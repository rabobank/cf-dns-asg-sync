package asgsync

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"slices"
	"strings"
)

//counterfeiter:generate -o asgsyncfakes . Foundation
type Foundation interface {
	FindOrg(context.Context, string) (string, error)
	ListSpaces(context.Context, string) ([]Space, error)
	ListGroups(context.Context) ([]SecurityGroup, error)
	CreateGroup(context.Context, string, []Rule) (string, error)
	BindRunning(context.Context, string, []string) error
	UnbindRunning(context.Context, string, string) error
	DeleteGroup(context.Context, string) error
}

type Space struct{ Name, GUID string }
type SecurityGroup struct {
	GUID, Name       string
	Global           bool
	Unsupported      bool
	Rules            []Rule
	Running, Staging []string
}

const namePrefix = "cf-dns-asg-sync-"

type targetGroup struct {
	name         string
	org          string
	rules        []Rule
	current      SecurityGroup
	bind, unbind []Space
	retire       bool
}

func ruleKey(rules []Rule) string {
	data, _ := json.Marshal(normalize(slices.Clone(rules)))
	return fmt.Sprintf("%x", sha256.Sum256(data))
}

func orgPrefix(guid string) string {
	return fmt.Sprintf("%s%x-", namePrefix, sha256.Sum256([]byte(guid)))
}

func Reconcile(ctx context.Context, cf Foundation, orgs []ResolvedOrg, dryRun bool, out io.Writer) error {
	groups, err := cf.ListGroups(ctx)
	if err != nil {
		return fmt.Errorf("list ASGs: %w", err)
	}
	var actions []targetGroup
	for _, org := range orgs {
		plan, err := planOrg(ctx, cf, org, groups)
		if err != nil {
			return fmt.Errorf("org %q: %w", org.Name, err)
		}
		actions = append(actions, plan...)
	}
	if len(actions) == 0 {
		_, err := fmt.Fprintln(out, "ASGs already up to date")
		return err
	}
	for _, a := range actions {
		if a.current.GUID == "" || a.retire {
			verb := "create"
			if a.retire {
				verb = "delete"
			}
			if _, err := fmt.Fprintf(out, "%s %s ASG %s (%d grants)\n", a.org, verb, a.name, len(a.rules)); err != nil {
				return err
			}
			for _, rule := range a.rules {
				if _, err := fmt.Fprintf(out, "  %s %s:%d\n", rule.Protocol, rule.Destination, rule.Port); err != nil {
					return err
				}
			}
		}
		for _, s := range a.bind {
			if _, err := fmt.Fprintf(out, "%s bind %s to %s\n", a.org, a.name, s.Name); err != nil {
				return err
			}
		}
		for _, s := range a.unbind {
			if _, err := fmt.Fprintf(out, "%s unbind %s from %s\n", a.org, a.name, s.Name); err != nil {
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
			id, err = cf.CreateGroup(ctx, a.name, a.rules)
			if err != nil {
				return fmt.Errorf("create %s: %w", a.name, err)
			}
			if id == "" {
				return fmt.Errorf("create %s: empty ASG GUID", a.name)
			}
		}
		if len(a.bind) > 0 {
			var ids []string
			for _, s := range a.bind {
				ids = append(ids, s.GUID)
			}
			if err := cf.BindRunning(ctx, id, ids); err != nil {
				return fmt.Errorf("bind %s: %w", a.name, err)
			}
		}
	}
	for _, a := range actions {
		for _, s := range a.unbind {
			if err := cf.UnbindRunning(ctx, a.current.GUID, s.GUID); err != nil {
				return fmt.Errorf("unbind %s from %s: %w", a.name, s.Name, err)
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
	for _, s := range spaces {
		if s.GUID == "" || s.Name == "" || byGUID[s.GUID].GUID != "" || byName[s.Name] {
			return nil, fmt.Errorf("invalid or duplicate space %q (%s)", s.Name, s.GUID)
		}
		byGUID[s.GUID] = s
		byName[s.Name] = true
		policies[s.GUID] = org.RulesFor(s.Name)
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
		suffix, ok := strings.CutPrefix(g.Name, prefix)
		if !ok || len(suffix) != 64 {
			continue
		}
		if _, err := hex.DecodeString(suffix); err != nil {
			continue
		}
		if g.Global {
			return nil, fmt.Errorf("managed ASG %s is globally enabled", g.Name)
		}
		for _, id := range append(slices.Clone(g.Running), g.Staging...) {
			if _, ok := byGUID[id]; !ok {
				return nil, fmt.Errorf("managed ASG %s has a binding outside the org: %s", g.Name, id)
			}
		}
		if len(g.Staging) != 0 {
			return nil, fmt.Errorf("managed ASG %s has unexpected staging bindings", g.Name)
		}
		if g.GUID == "" || managed[g.Name].GUID != "" || g.Unsupported || suffix != ruleKey(g.Rules) {
			return nil, fmt.Errorf("managed ASG %s has invalid identity or rules", g.Name)
		}
		managed[g.Name] = g
		existing = append(existing, Group{Rules: normalize(slices.Clone(g.Rules)), Spaces: sortedUnique(g.Running)})
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
		for _, id := range g.Spaces {
			if !slices.Contains(current.Running, id) {
				a.bind = append(a.bind, byGUID[id])
			}
		}
		for _, id := range sortedUnique(current.Running) {
			if !slices.Contains(g.Spaces, id) {
				a.unbind = append(a.unbind, byGUID[id])
			}
		}
		if current.GUID == "" || len(a.bind)+len(a.unbind) > 0 {
			actions = append(actions, a)
		}
	}
	for _, g := range ordered {
		if _, ok := managed[g.Name]; !ok {
			continue
		}
		a := targetGroup{name: g.Name, org: org.Name, rules: g.Rules, current: g, retire: true}
		for _, id := range sortedUnique(g.Running) {
			a.unbind = append(a.unbind, byGUID[id])
		}
		actions = append(actions, a)
	}
	return actions, nil
}

func sortedUnique(values []string) []string {
	copy := slices.Clone(values)
	slices.Sort(copy)
	return slices.Compact(copy)
}
