package asgsync

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"regexp"
	"slices"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"
)

//go:generate go tool counterfeiter -generate
//counterfeiter:generate -o asgsyncfakes . Resolver
type Resolver interface {
	LookupNetIP(context.Context, string, string) ([]netip.Addr, error)
}

type Policy struct {
	Defaults []Grant `yaml:"defaults"`
	Orgs     []Org   `yaml:"orgs"`
}

type Org struct {
	Name   string        `yaml:"name"`
	Allow  []Grant       `yaml:"allow"`
	Spaces []SpacePolicy `yaml:"spaces"`
}

type SpacePolicy struct {
	Name  string  `yaml:"name"`
	Allow []Grant `yaml:"allow"`
}

type Grant struct {
	Name        string   `yaml:"name"`
	Rules       []Grant  `yaml:"rules"`
	Hostname    string   `yaml:"hostname"`
	Destination string   `yaml:"destination"`
	Protocol    string   `yaml:"protocol"`
	Ports       PortSpec `yaml:"ports"`
	Type        *int     `yaml:"type"`
	Code        *int     `yaml:"code"`
	Log         bool     `yaml:"log"`
	Description string   `yaml:"description"`
	Lifecycles  []string `yaml:"lifecycles"`
}

type DNSOptions struct {
	IPv6         bool
	PrivateCIDRs []netip.Prefix
}

type Rule struct {
	Destination string
	Protocol    string
	Port        uint16
	PortEnd     uint16 `json:",omitempty"`
	Type        int    `json:",omitempty"`
	Code        int    `json:",omitempty"`
	Log         bool   `json:",omitempty"`
}

type ResolvedOrg struct {
	NamedDefaults   map[string]resolvedDefault
	Name            string
	Baseline        []Rule
	Extras          map[string][]Rule
	Descriptions    RuleDescriptions
	DNSFailures     map[string]error
	StagingBaseline []Rule
	StagingExtras   map[string][]Rule
}

// RuleDescriptions records comma-separated source hostnames independently of
// Rule, whose identity is the actual access it grants.
type RuleDescriptions map[Rule]string

func (o ResolvedOrg) RulesFor(space string) []Rule {
	return normalize(append(slices.Clone(o.Baseline), o.Extras[space]...))
}

func normalize(rules []Rule) []Rule {
	slices.SortFunc(rules, func(a, b Rule) int {
		if n := strings.Compare(a.Destination, b.Destination); n != 0 {
			return n
		}
		if n := strings.Compare(a.Protocol, b.Protocol); n != 0 {
			return n
		}
		for _, n := range []int{int(a.Port) - int(b.Port), int(a.PortEnd) - int(b.PortEnd), a.Type - b.Type, a.Code - b.Code} {
			if n != 0 {
				return n
			}
		}
		if a.Log != b.Log {
			if a.Log {
				return 1
			}
			return -1
		}
		return 0
	})
	return slices.Compact(rules)
}

var dnsLabel = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)

func ParsePolicy(r io.Reader) (Policy, error) {
	var policy Policy
	d := yaml.NewDecoder(r)
	d.KnownFields(true)
	if err := d.Decode(&policy); err != nil {
		return Policy{}, fmt.Errorf("decode policy: %w", err)
	}
	var extra any
	if err := d.Decode(&extra); !errors.Is(err, io.EOF) {
		return Policy{}, fmt.Errorf("policy must contain exactly one YAML document")
	}
	if len(policy.Orgs) == 0 && policy.Defaults == nil {
		return Policy{}, fmt.Errorf("policy must list at least one org or set defaults")
	}
	if _, _, err := splitDefaults(policy.Defaults); err != nil {
		return Policy{}, fmt.Errorf("defaults: %w", err)
	}
	orgNames := map[string]bool{}
	for i := range policy.Orgs {
		o := &policy.Orgs[i]
		if err := checkName(o.Name, orgNames); err != nil {
			return Policy{}, fmt.Errorf("org: %w", err)
		}
		if err := validateGrants(o.Allow); err != nil {
			return Policy{}, fmt.Errorf("org %q: %w", o.Name, err)
		}
		spaceNames := map[string]bool{}
		for i := range o.Spaces {
			s := &o.Spaces[i]
			if err := checkName(s.Name, spaceNames); err != nil {
				return Policy{}, fmt.Errorf("org %q space: %w", o.Name, err)
			}
			if err := validateGrants(s.Allow); err != nil {
				return Policy{}, fmt.Errorf("org %q space %q: %w", o.Name, s.Name, err)
			}
		}
	}
	return policy, nil
}

func checkName(name string, seen map[string]bool) error {
	if name == "" || strings.TrimSpace(name) != name || strings.Contains(name, ",") {
		return fmt.Errorf("invalid name %q", name)
	}
	if seen[name] {
		return fmt.Errorf("duplicate name %q", name)
	}
	seen[name] = true
	return nil
}

func validateGrants(grants []Grant) error {
	for _, g := range grants {
		if _, _, err := deriveGrant(g); err != nil {
			return err
		}
	}
	return nil
}

func deriveGrant(g Grant) (Grant, []Rule, error) {
	if g.Name != "" || g.Rules != nil {
		return g, nil, fmt.Errorf("named groups are only supported in defaults")
	}
	if g.Lifecycles == nil {
		g.Lifecycles = []string{"running", "staging"}
	}
	seen := map[string]bool{}
	for _, life := range g.Lifecycles {
		if (life != "running" && life != "staging") || seen[life] {
			return g, nil, fmt.Errorf("invalid or duplicate lifecycle %q", life)
		}
		seen[life] = true
	}
	if len(g.Lifecycles) == 0 {
		return g, nil, fmt.Errorf("lifecycles must not be empty")
	}
	if g.Destination != "" {
		if g.Hostname != "" {
			return g, nil, fmt.Errorf("specify hostname or destination, not both")
		}
		rules, err := destinationRules(g.Destination, g.Protocol, g.Ports, g.Type, g.Code, g.Log)
		return g, rules, err
	}
	h := strings.ToLower(strings.TrimSuffix(g.Hostname, "."))
	labels := strings.Split(h, ".")
	_, ipErr := netip.ParseAddr(h)
	if len(h) > 253 || len(labels) < 2 || ipErr == nil {
		return g, nil, fmt.Errorf("expected a fully qualified hostname, got %q", g.Hostname)
	}
	for _, label := range labels {
		if !dnsLabel.MatchString(label) {
			return g, nil, fmt.Errorf("invalid hostname %q", g.Hostname)
		}
	}
	g.Hostname = h + "."
	if g.Protocol != "tcp" && g.Protocol != "udp" {
		return g, nil, fmt.Errorf("%s: protocol must be tcp or udp", h)
	}
	if len(g.Ports) == 0 || g.Type != nil || g.Code != nil || g.Log || g.Description != "" {
		return g, nil, fmt.Errorf("%s: hostname rules require ports and use generated descriptions", h)
	}
	return g, nil, nil
}

func Resolve(ctx context.Context, policy Policy, resolver Resolver, opts DNSOptions) ([]ResolvedOrg, error) {
	flat, named, err := splitDefaults(policy.Defaults)
	if err != nil {
		return nil, fmt.Errorf("defaults: %w", err)
	}
	type lookup struct {
		ips []netip.Addr
		err error
	}
	cache := map[string]lookup{}
	resolve := func(org *ResolvedOrg, grants []Grant) (running, staging []Rule, err error) {
		for _, grant := range grants {
			if err := ctx.Err(); err != nil {
				return nil, nil, err
			}
			g, native, err := deriveGrant(grant)
			if err != nil {
				return nil, nil, err
			}
			add := func(rule Rule, description string) {
				if slices.Contains(g.Lifecycles, "running") {
					running = append(running, rule)
				}
				if slices.Contains(g.Lifecycles, "staging") {
					staging = append(staging, rule)
				}
				if description != "" {
					org.Descriptions[rule] = mergeDescriptions(org.Descriptions[rule], description)
				}
			}
			if g.Destination != "" {
				for _, rule := range native {
					add(rule, g.Description)
				}
				continue
			}
			result, ok := cache[g.Hostname]
			if !ok {
				family := "ip4"
				if opts.IPv6 {
					family = "ip"
				}
				lookupCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
				answers, err := resolver.LookupNetIP(lookupCtx, family, g.Hostname)
				cancel()
				if err := ctx.Err(); err != nil {
					return nil, nil, err
				}
				if err != nil {
					answers = nil
				} // Ignore partial answers on failure.
				result.err = err
				for _, addr := range answers {
					addr = addr.Unmap()
					if addr.Is6() && !opts.IPv6 {
						continue
					}
					if !addr.IsGlobalUnicast() || addr.Zone() != "" || (restricted(addr) && !slices.ContainsFunc(opts.PrivateCIDRs, func(p netip.Prefix) bool { return p.Contains(addr) })) {
						return nil, nil, fmt.Errorf("%s resolved to disallowed address %s", g.Hostname, addr)
					}
					result.ips = append(result.ips, addr)
				}
				if result.err == nil && len(result.ips) == 0 {
					result.err = errors.New("no usable addresses")
				}
				cache[g.Hostname] = result
			}
			if result.err != nil {
				org.DNSFailures[g.Hostname] = result.err
				continue
			}
			for _, ip := range result.ips {
				for _, port := range g.Ports {
					rule := Rule{Destination: ip.String(), Protocol: g.Protocol, Port: port.start, PortEnd: port.end}
					add(rule, strings.TrimSuffix(g.Hostname, "."))
				}
			}
		}
		return normalize(running), normalize(staging), nil
	}
	var orgs []ResolvedOrg
	for _, o := range policy.Orgs {
		org := ResolvedOrg{Name: o.Name, Extras: map[string][]Rule{}, StagingExtras: map[string][]Rule{}, Descriptions: RuleDescriptions{}, DNSFailures: map[string]error{}}
		grants := o.Allow
		if grants == nil {
			grants = flat
			org.NamedDefaults = map[string]resolvedDefault{}
			for _, group := range named {
				entry := ResolvedOrg{Descriptions: RuleDescriptions{}, DNSFailures: org.DNSFailures}
				running, staging, err := resolve(&entry, group.rules)
				if err != nil {
					return nil, fmt.Errorf("default ASG %q: %w", group.name, err)
				}
				org.NamedDefaults[group.name] = resolvedDefault{running, staging, entry.Descriptions}
			}
		}
		base, stage, err := resolve(&org, grants)
		if err != nil {
			return nil, fmt.Errorf("org %q: %w", o.Name, err)
		}
		org.Baseline = base
		org.StagingBaseline = stage
		for _, s := range o.Spaces {
			rules, stage, err := resolve(&org, s.Allow)
			if err != nil {
				return nil, fmt.Errorf("org %q space %q: %w", o.Name, s.Name, err)
			}
			org.Extras[s.Name] = rules
			org.StagingExtras[s.Name] = stage
		}
		if len(org.DNSFailures) > 0 {
			// No partial policy can be applied for this org.
			org.Baseline, org.Extras, org.Descriptions = nil, nil, nil
			org.StagingBaseline, org.StagingExtras = nil, nil
		}
		orgs = append(orgs, org)
	}
	return orgs, nil
}

func mergeDescriptions(a, b string) string {
	if a == "" {
		return b
	}
	if b == "" || a == b {
		return a
	}
	return strings.Join(sortedUnique(strings.Split(a+","+b, ",")), ",")
}

var carrierGradeNAT = netip.MustParsePrefix("100.64.0.0/10")

func restricted(addr netip.Addr) bool { return addr.IsPrivate() || carrierGradeNAT.Contains(addr) }
