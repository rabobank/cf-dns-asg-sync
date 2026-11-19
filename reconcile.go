package asgsync

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"slices"
	"strings"
)

//counterfeiter:generate -o asgsyncfakes . Foundation
type Foundation interface {
	ListOrgNames(context.Context) ([]string, error)
	FindOrg(context.Context, string) (string, error)
	ListSpaces(context.Context, string) ([]Space, error)
	ListGroups(context.Context) ([]SecurityGroup, error)
	DisableGlobalGroup(context.Context, string, bool, bool) error
	CreateGroup(context.Context, string, []Rule, RuleDescriptions) (string, error)
	UpdateGroupDescriptions(context.Context, string, []Rule, RuleDescriptions) error
	BindRunning(context.Context, string, []string) error
	UnbindRunning(context.Context, string, string) error
	BindStaging(context.Context, string, []string) error
	UnbindStaging(context.Context, string, string) error
	DeleteGroup(context.Context, string) error
}

type Space struct{ Name, GUID string }
type SecurityGroup struct {
	GUID, Name                   string
	GlobalRunning, GlobalStaging bool
	Unsupported                  bool
	Rules                        []Rule
	Descriptions                 RuleDescriptions
	Running, Staging             []string
}

func (g SecurityGroup) global() bool { return g.GlobalRunning || g.GlobalStaging }

const namePrefix = "cf-dns-asg-sync-"

type targetGroup struct {
	name         string
	org          string
	rules        []Rule
	descriptions RuleDescriptions
	update       bool
	current      SecurityGroup
	bind, unbind []binding
	retire       bool
}

type binding struct {
	Space
	lifecycle string
}

func (b binding) key() string { return b.lifecycle + ":" + b.GUID }

func currentBindings(g SecurityGroup) []string {
	var result []string
	for _, id := range g.Running {
		result = append(result, "running:"+id)
	}
	for _, id := range g.Staging {
		result = append(result, "staging:"+id)
	}
	return sortedUnique(result)
}

// Sync discovers defaulted orgs only when explicitly opted in, then resolves
// and reconciles the complete policy.
func Sync(ctx context.Context, cf Foundation, policy Policy, resolver Resolver, opts DNSOptions, dryRun bool, out io.Writer) error {
	groups, err := loadGroups(ctx, cf)
	if err != nil {
		return err
	}
	global := globalGroups(groups)
	if len(global) > 0 && !matchesGlobalDefaults(policy.Defaults, global) {
		return reportGlobalGroups(global, out)
	}
	if policy.Defaults != nil {
		names, err := cf.ListOrgNames(ctx)
		if err != nil {
			return fmt.Errorf("discover orgs for defaults: %w", err)
		}
		policy.Orgs = slices.Clone(policy.Orgs)
		configured := map[string]bool{}
		for _, org := range policy.Orgs {
			configured[org.Name] = true
		}
		for _, name := range sortedUnique(names) {
			if !configured[name] {
				policy.Orgs = append(policy.Orgs, Org{Name: name})
			}
		}
	}
	orgs, err := Resolve(ctx, policy, resolver, opts)
	if err != nil {
		return err
	}
	if err := reconcile(ctx, cf, orgs, groups, dryRun, out); err != nil {
		return err
	}
	if len(global) == 0 {
		return nil
	}
	return retireGlobalGroups(ctx, cf, global, dryRun, out)
}

func ruleKey(rules []Rule) string {
	data, _ := json.Marshal(normalize(slices.Clone(rules)))
	return fmt.Sprintf("%x", sha256.Sum256(data))
}

func orgPrefix(guid string) string {
	return fmt.Sprintf("%s%x-", namePrefix, sha256.Sum256([]byte(guid)))
}

func Reconcile(ctx context.Context, cf Foundation, orgs []ResolvedOrg, dryRun bool, out io.Writer) error {
	groups, err := loadGroups(ctx, cf)
	if err != nil {
		return err
	}
	if global := globalGroups(groups); len(global) > 0 {
		return reportGlobalGroups(global, out)
	}
	return reconcile(ctx, cf, orgs, groups, dryRun, out)
}

func loadGroups(ctx context.Context, cf Foundation) ([]SecurityGroup, error) {
	groups, err := cf.ListGroups(ctx)
	if err != nil {
		return nil, fmt.Errorf("list ASGs: %w", err)
	}
	return groups, nil
}

func reconcile(ctx context.Context, cf Foundation, orgs []ResolvedOrg, groups []SecurityGroup, dryRun bool, out io.Writer) error {
	var actions []targetGroup
	var failures []error
	for _, org := range orgs {
		if len(org.DNSFailures) > 0 {
			failures = append(failures, describeDNSFailures(ctx, cf, org, groups))
			continue
		}
		plan, err := planOrg(ctx, cf, org, groups)
		if err != nil {
			return errors.Join(errors.Join(failures...), fmt.Errorf("org %q: %w", org.Name, err))
		}
		actions = append(actions, plan...)
	}
	dnsErr := errors.Join(failures...)
	return errors.Join(dnsErr, applyActions(ctx, cf, actions, dryRun, out, dnsErr != nil))
}

func describeDNSFailures(ctx context.Context, cf Foundation, org ResolvedOrg, groups []SecurityGroup) error {
	guid, err := cf.FindOrg(ctx, org.Name)
	if guid == "" && err == nil {
		err = errors.New("empty org GUID")
	}
	var spaces []Space
	if err == nil {
		spaces, err = cf.ListSpaces(ctx, guid)
	}
	inOrg := map[string]bool{}
	for _, space := range spaces {
		inOrg[space.GUID] = true
	}
	previous := map[string][]string{}
	var diagnostics []error
	if err != nil {
		diagnostics = append(diagnostics, fmt.Errorf("org %q: could not read DNS history: %w", org.Name, err))
	} else {
		prefix := orgPrefix(guid)
		for _, g := range groups {
			if !managedName(g.Name, prefix) || g.global() || g.Unsupported || len(g.Running)+len(g.Staging) == 0 || g.Name != prefix+ruleKey(g.Rules) || slices.ContainsFunc(g.Running, func(id string) bool { return !inOrg[id] }) || slices.ContainsFunc(g.Staging, func(id string) bool { return !inOrg[id] }) {
				continue
			}
			for _, rule := range g.Rules {
				for _, host := range strings.Split(g.Descriptions[rule], ",") {
					if _, failed := org.DNSFailures[host+"."]; failed {
						previous[host+"."] = append(previous[host+"."], rule.Destination)
					}
				}
			}
		}
	}
	for _, host := range slices.Sorted(maps.Keys(org.DNSFailures)) {
		ips := sortedUnique(previous[host])
		history := "no previously applied IPs recorded"
		if len(ips) > 0 {
			history = fmt.Sprintf("%d previously applied IPs: %s", len(ips), strings.Join(ips, ","))
		}
		diagnostics = append(diagnostics, fmt.Errorf("org %q: DNS lookup for %s failed: %w; existing ASGs retained (%s)", org.Name, host, org.DNSFailures[host], history))
	}
	return errors.Join(diagnostics...)
}

func applyActions(ctx context.Context, cf Foundation, actions []targetGroup, dryRun bool, out io.Writer, skipped bool) error {
	if len(actions) == 0 {
		if skipped {
			return nil
		}
		_, err := fmt.Fprintln(out, "ASGs already up to date")
		return err
	}
	for _, a := range actions {
		if a.update {
			if _, err := fmt.Fprintf(out, "%s update DNS descriptions for ASG %s\n", a.org, a.name); err != nil {
				return err
			}
		}
		if a.current.GUID == "" || a.retire {
			verb := "create"
			if a.retire {
				verb = "delete"
			}
			if _, err := fmt.Fprintf(out, "%s %s ASG %s (%d grants)\n", a.org, verb, a.name, len(a.rules)); err != nil {
				return err
			}
			for _, rule := range a.rules {
				if _, err := fmt.Fprintf(out, "  %s %s\n", rule.Protocol, rule.displayDestination()); err != nil {
					return err
				}
			}
		}
		for _, s := range a.bind {
			if _, err := fmt.Fprintf(out, "%s bind %s to %s (%s)\n", a.org, a.name, s.Name, s.lifecycle); err != nil {
				return err
			}
		}
		for _, s := range a.unbind {
			if _, err := fmt.Fprintf(out, "%s unbind %s from %s (%s)\n", a.org, a.name, s.Name, s.lifecycle); err != nil {
				return err
			}
		}
	}
	if dryRun {
		return nil
	}
	// Publish new coverage before removing old coverage. Content-addressed names
	// let the next run resume after an interruption without creating duplicates.
	for _, a := range actions {
		id := a.current.GUID
		if id == "" {
			var err error
			id, err = cf.CreateGroup(ctx, a.name, a.rules, a.descriptions)
			if err != nil {
				return fmt.Errorf("create %s: %w", a.name, err)
			}
			if id == "" {
				return fmt.Errorf("create %s: empty ASG GUID", a.name)
			}
		}
		if a.update {
			if err := cf.UpdateGroupDescriptions(ctx, id, a.rules, a.descriptions); err != nil {
				return fmt.Errorf("update descriptions for %s: %w", a.name, err)
			}
		}
		for _, lifecycle := range []string{"running", "staging"} {
			var ids []string
			for _, s := range a.bind {
				if s.lifecycle == lifecycle {
					ids = append(ids, s.GUID)
				}
			}
			if len(ids) == 0 {
				continue
			}
			bind := cf.BindRunning
			if lifecycle == "staging" {
				bind = cf.BindStaging
			}
			if err := bind(ctx, id, ids); err != nil {
				return fmt.Errorf("bind %s (%s): %w", a.name, lifecycle, err)
			}
		}
	}
	for _, a := range actions {
		for _, s := range a.unbind {
			unbind := cf.UnbindRunning
			if s.lifecycle == "staging" {
				unbind = cf.UnbindStaging
			}
			if err := unbind(ctx, a.current.GUID, s.GUID); err != nil {
				return fmt.Errorf("unbind %s from %s (%s): %w", a.name, s.Name, s.lifecycle, err)
			}
		}
		if a.retire {
			if err := cf.DeleteGroup(ctx, a.current.GUID); err != nil {
				return fmt.Errorf("delete %s: %w", a.name, err)
			}
		}
	}
	return nil
}

func planOrg(ctx context.Context, cf Foundation, org ResolvedOrg, groups []SecurityGroup) ([]targetGroup, error) {
	guid, err := cf.FindOrg(ctx, org.Name)
	if err != nil {
		return nil, err
	}
	if guid == "" {
		return nil, fmt.Errorf("empty org GUID")
	}
	spaces, err := cf.ListSpaces(ctx, guid)
	if err != nil {
		return nil, fmt.Errorf("list spaces: %w", err)
	}
	byGUID := map[string]Space{}
	byName := map[string]bool{}
	policies := map[string][]Rule{}
	bindings := map[string]binding{}
	for _, s := range spaces {
		if s.GUID == "" || s.Name == "" || byGUID[s.GUID].GUID != "" || byName[s.Name] {
			return nil, fmt.Errorf("invalid or duplicate space %q (%s)", s.Name, s.GUID)
		}
		byGUID[s.GUID] = s
		byName[s.Name] = true
		running, staging := binding{s, "running"}, binding{s, "staging"}
		bindings[running.key()], bindings[staging.key()] = running, staging
		policies[running.key()] = org.RulesFor(s.Name)
		policies[staging.key()] = normalize(append(slices.Clone(org.StagingBaseline), org.StagingExtras[s.Name]...))
	}
	for name := range org.Extras {
		if !byName[name] {
			return nil, fmt.Errorf("unknown space %q", name)
		}
	}
	prefix := orgPrefix(guid)
	managed := map[string]SecurityGroup{}
	var existing []Group
	ordered := slices.Clone(groups)
	slices.SortFunc(ordered, func(a, b SecurityGroup) int { return strings.Compare(a.Name, b.Name) })
	for _, g := range ordered {
		if !managedName(g.Name, prefix) {
			continue
		}
		if g.global() {
			return nil, fmt.Errorf("managed ASG %s is globally enabled", g.Name)
		}
		for _, id := range append(slices.Clone(g.Running), g.Staging...) {
			if _, ok := byGUID[id]; !ok {
				return nil, fmt.Errorf("managed ASG %s has a binding outside the org: %s", g.Name, id)
			}
		}
		if g.GUID == "" || managed[g.Name].GUID != "" || g.Unsupported || g.Name != prefix+ruleKey(g.Rules) {
			return nil, fmt.Errorf("managed ASG %s has invalid identity or rules", g.Name)
		}
		managed[g.Name] = g
		existing = append(existing, Group{Rules: normalize(slices.Clone(g.Rules)), Spaces: currentBindings(g)})
	}
	desired, err := Minimize(ctx, policies, existing)
	if err != nil {
		return nil, err
	}
	var actions []targetGroup
	for _, g := range desired {
		name := prefix + ruleKey(g.Rules)
		current := managed[name]
		delete(managed, name)
		a := targetGroup{name: name, org: org.Name, rules: g.Rules, current: current}
		a.descriptions = RuleDescriptions{}
		for _, r := range g.Rules {
			if d := org.Descriptions[r]; d != "" {
				a.descriptions[r] = d
			}
		}
		a.update = current.GUID != "" && !maps.Equal(a.descriptions, current.Descriptions)
		bound := currentBindings(current)
		for _, id := range g.Spaces {
			if !slices.Contains(bound, id) {
				a.bind = append(a.bind, bindings[id])
			}
		}
		for _, id := range bound {
			if !slices.Contains(g.Spaces, id) {
				a.unbind = append(a.unbind, bindings[id])
			}
		}
		if current.GUID == "" || a.update || len(a.bind)+len(a.unbind) > 0 {
			actions = append(actions, a)
		}
	}
	for _, g := range ordered {
		if _, ok := managed[g.Name]; !ok {
			continue
		}
		a := targetGroup{name: g.Name, org: org.Name, rules: g.Rules, current: g, retire: true}
		for _, id := range currentBindings(g) {
			a.unbind = append(a.unbind, bindings[id])
		}
		actions = append(actions, a)
	}
	return actions, nil
}

func managedName(name, prefix string) bool {
	suffix, ok := strings.CutPrefix(name, prefix)
	if !ok || len(suffix) != 64 {
		return false
	}
	_, err := hex.DecodeString(suffix)
	return err == nil
}

func sortedUnique(values []string) []string {
	copy := slices.Clone(values)
	slices.Sort(copy)
	return slices.Compact(copy)
}
