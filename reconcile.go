package asgsync

import (
	"context"
	"crypto/sha256"
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

type targetGroup struct {
	name         string
	rules        []Rule
	descriptions RuleDescriptions
	update       bool
	current      SecurityGroup
	bind, unbind []binding
	retire       bool
}

type binding struct {
	Space
	org       string
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
	var failures []error
	for _, org := range orgs {
		if len(org.DNSFailures) > 0 {
			failures = append(failures, describeDNSFailures(ctx, cf, org, groups))
			continue
		}
		guid, spaces, err := discoverOrg(ctx, cf, org)
		if err != nil {
			return errors.Join(errors.Join(failures...), fmt.Errorf("org %q: %w", org.Name, err))
	policies := map[string][]Rule{}
	bindings := map[string]binding{}
	provenance := map[string]RuleDescriptions{}
	legacyOwners := map[string]bool{}
	orgIDs := map[string]bool{}
		}
		if orgIDs[guid] {
			return fmt.Errorf("duplicate org GUID %s", guid)
		}
		orgIDs[guid] = true
		legacyOwners[legacyOrgKey(guid)] = true
		provenance[org.Name] = org.Descriptions
		for _, s := range spaces {
			running, staging := binding{s, org.Name, "running"}, binding{s, org.Name, "staging"}
			if _, ok := bindings[running.key()]; ok {
				return fmt.Errorf("duplicate space GUID %s", s.GUID)
			}
			bindings[running.key()], bindings[staging.key()] = running, staging
			policies[running.key()] = org.RulesFor(s.Name)
			policies[staging.key()] = normalize(append(slices.Clone(org.StagingBaseline), org.StagingExtras[s.Name]...))
		}
	}
	dnsErr := errors.Join(failures...)
	return errors.Join(dnsErr, applyActions(ctx, cf, actions, dryRun, out, dnsErr != nil))
}

func describeDNSFailures(ctx context.Context, cf Foundation, org ResolvedOrg, groups []SecurityGroup) error {
	guid, err := cf.FindOrg(ctx, org.Name)
	if guid == "" && err == nil {
		err = errors.New("empty org GUID")
	}
	actions, err := planFoundation(ctx, groups, policies, bindings, provenance, legacyOwners, dnsErr != nil)
	if err != nil {
		return errors.Join(dnsErr, err)
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
		for _, g := range groups {
			if !managedGroupName(g.Name) || !validManagedRules(g) || g.global() || g.Unsupported || !(slices.ContainsFunc(g.Running, func(id string) bool { return inOrg[id] }) || slices.ContainsFunc(g.Staging, func(id string) bool { return inOrg[id] })) {
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
			if _, err := fmt.Fprintf(out, "update DNS descriptions for ASG %s\n", a.name); err != nil {
				return err
			}
		}
		if a.current.GUID == "" || a.retire {
			verb := "create"
			if a.retire {
				verb = "delete"
			}
			if _, err := fmt.Fprintf(out, "%s ASG %s (%d grants)\n", verb, a.name, len(a.rules)); err != nil {
				return err
			}
			for _, rule := range a.rules {
				if _, err := fmt.Fprintf(out, "  %s %s\n", rule.Protocol, rule.displayDestination()); err != nil {
					return err
				}
			}
		}
		for _, s := range a.bind {
			if _, err := fmt.Fprintf(out, "%s bind %s to %s (%s)\n", s.org, a.name, s.Name, s.lifecycle); err != nil {
				return err
			}
		}
		for _, s := range a.unbind {
			if _, err := fmt.Fprintf(out, "%s unbind %s from %s (%s)\n", s.org, a.name, s.Name, s.lifecycle); err != nil {
				return err
			}
		}
	}
	if dryRun {
		return nil
	}
	// Publish coverage before removing it. An ambiguous create aborts this run;
	// the next run reads a fresh snapshot, including any unbound ASGs.
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

func discoverOrg(ctx context.Context, cf Foundation, org ResolvedOrg) (string, []Space, error) {
	guid, err := cf.FindOrg(ctx, org.Name)
	if err != nil {
		return "", nil, err
	}
	if guid == "" {
		return "", nil, fmt.Errorf("empty org GUID")
	}
	spaces, err := cf.ListSpaces(ctx, guid)
	if err != nil {
		return "", nil, fmt.Errorf("list spaces: %w", err)
	}
	byGUID := map[string]bool{}
	byName := map[string]bool{}
	for _, s := range spaces {
		if s.GUID == "" || s.Name == "" || byGUID[s.GUID] || byName[s.Name] {
			return "", nil, fmt.Errorf("invalid or duplicate space %q (%s)", s.Name, s.GUID)
		}
		byGUID[s.GUID] = true
		byName[s.Name] = true
	}
	for name := range org.Extras {
		if !byName[name] {
			return "", nil, fmt.Errorf("unknown space %q", name)
		}
	}
	return guid, spaces, nil
}

func sortedUnique(values []string) []string {
	copy := slices.Clone(values)
	slices.Sort(copy)
	return slices.Compact(copy)
}
