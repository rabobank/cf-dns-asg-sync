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
	Orgs []Org `yaml:"orgs"`
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
	Hostname string   `yaml:"hostname"`
	Protocol string   `yaml:"protocol"`
	Ports    []uint16 `yaml:"ports"`
}

type DNSOptions struct {
	IPv6         bool
	PrivateCIDRs []netip.Prefix
}

type Rule struct {
	Destination string
	Protocol    string
	Port        uint16
}

type ResolvedOrg struct {
	Name     string
	Baseline []Rule
	Extras   map[string][]Rule
}

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
		return int(a.Port) - int(b.Port)
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
	if len(policy.Orgs) == 0 {
		return Policy{}, fmt.Errorf("policy must list at least one org")
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
	for i := range grants {
		g := &grants[i]
		h := strings.ToLower(strings.TrimSuffix(g.Hostname, "."))
		labels := strings.Split(h, ".")
		_, ipErr := netip.ParseAddr(h)
		if len(h) > 253 || len(labels) < 2 || ipErr == nil {
			return fmt.Errorf("expected a fully qualified hostname, got %q", g.Hostname)
		}
		for _, label := range labels {
			if !dnsLabel.MatchString(label) {
				return fmt.Errorf("invalid hostname %q", g.Hostname)
			}
		}
		g.Hostname = h + "."
		if g.Protocol != "tcp" && g.Protocol != "udp" {
			return fmt.Errorf("%s: protocol must be tcp or udp", h)
		}
		if len(g.Ports) == 0 || slices.Contains(g.Ports, 0) {
			return fmt.Errorf("%s: specify ports between 1 and 65535", h)
		}
	}
	return nil
}

func Resolve(ctx context.Context, policy Policy, resolver Resolver, opts DNSOptions) ([]ResolvedOrg, error) {
	cache := map[string][]netip.Addr{}
	resolve := func(grants []Grant) ([]Rule, error) {
		var rules []Rule
		for _, g := range grants {
			ips, ok := cache[g.Hostname]
			if !ok {
				family := "ip4"
				if opts.IPv6 {
					family = "ip"
				}
				lookupCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
				answers, err := resolver.LookupNetIP(lookupCtx, family, g.Hostname)
				cancel()
				if err != nil {
					return nil, fmt.Errorf("resolve %s: %w", g.Hostname, err)
				}
				for _, addr := range answers {
					addr = addr.Unmap()
					if addr.Is6() && !opts.IPv6 {
						continue
					}
					if !addr.IsGlobalUnicast() || addr.Zone() != "" || (restricted(addr) && !slices.ContainsFunc(opts.PrivateCIDRs, func(p netip.Prefix) bool { return p.Contains(addr) })) {
						return nil, fmt.Errorf("%s resolved to disallowed address %s", g.Hostname, addr)
					}
					ips = append(ips, addr)
				}
				if len(ips) == 0 {
					return nil, fmt.Errorf("%s returned no usable addresses", g.Hostname)
				}
				cache[g.Hostname] = ips
			}
			for _, ip := range ips {
				for _, port := range g.Ports {
					rules = append(rules, Rule{ip.String(), g.Protocol, port})
				}
			}
		}
		return normalize(rules), nil
	}
	var orgs []ResolvedOrg
	for _, o := range policy.Orgs {
		base, err := resolve(o.Allow)
		if err != nil {
			return nil, fmt.Errorf("org %q: %w", o.Name, err)
		}
		org := ResolvedOrg{o.Name, base, map[string][]Rule{}}
		for _, s := range o.Spaces {
			rules, err := resolve(s.Allow)
			if err != nil {
				return nil, fmt.Errorf("org %q space %q: %w", o.Name, s.Name, err)
			}
			org.Extras[s.Name] = rules
		}
		orgs = append(orgs, org)
	}
	return orgs, nil
}

var carrierGradeNAT = netip.MustParsePrefix("100.64.0.0/10")

func restricted(addr netip.Addr) bool { return addr.IsPrivate() || carrierGradeNAT.Contains(addr) }
