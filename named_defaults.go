package asgsync

import (
	"fmt"
	"maps"
	"regexp"
	"slices"
)

type namedDefault struct {
	name  string
	rules []Grant
}

type resolvedDefault struct {
	running, staging []Rule
	descriptions     RuleDescriptions
}

var defaultName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]*$`)

func splitDefaults(defaults []Grant) ([]Grant, []namedDefault, error) {
	var flat []Grant
	var named []namedDefault
	seen := map[string]bool{}
	for _, g := range defaults {
		if g.Name == "" && g.Rules == nil {
			flat = append(flat, g)
			continue
		}
		if !defaultName.MatchString(g.Name) || len(g.Rules) == 0 || g.Hostname != "" || g.Destination != "" || g.Protocol != "" || g.Ports != nil || g.Type != nil || g.Code != nil || g.Log || g.Description != "" {
			return nil, nil, fmt.Errorf("invalid named default %q: specify name, rules and optional lifecycles", g.Name)
		}
		for _, r := range g.Rules {
			if r.Lifecycles != nil {
				return nil, nil, fmt.Errorf("default %q: specify lifecycles on the group", g.Name)
			}
		}
		phases := g.Lifecycles
		if phases == nil {
			phases = []string{""}
		}
		if len(phases) == 0 {
			return nil, nil, fmt.Errorf("default %q: lifecycles must not be empty", g.Name)
		}
		for _, phase := range phases {
			name := g.Name
			rules := slices.Clone(g.Rules)
			if g.Lifecycles != nil {
				if phase != "running" && phase != "staging" {
					return nil, nil, fmt.Errorf("default %q: invalid lifecycle %q", g.Name, phase)
				}
				name += "-" + phase
				for i := range rules {
					rules[i].Lifecycles = []string{phase}
				}
			}
			if len(name) > 250 || seen[name] || managedGroupName(name) || name == migrationCheckpointName {
				return nil, nil, fmt.Errorf("invalid, duplicate or reserved default ASG name %q", name)
			}
			seen[name] = true
			if err := validateGrants(rules); err != nil {
				return nil, nil, fmt.Errorf("default %q: %w", name, err)
			}
			named = append(named, namedDefault{name, rules})
		}
	}
	return flat, named, validateGrants(flat)
}

type namedTarget struct {
	rules        []Rule
	descriptions RuleDescriptions
	keys         []string
}

func planNamed(groups []SecurityGroup, targets map[string]*namedTarget, bindings map[string]binding) ([]targetGroup, error) {
	var actions []targetGroup
	for _, name := range slices.Sorted(maps.Keys(targets)) {
		want := targets[name]
		var current SecurityGroup
		for _, g := range groups {
			if g.Name != name {
				continue
			}
			if current.GUID != "" || g.GUID == "" || g.Unsupported {
				return nil, fmt.Errorf("invalid existing named ASG %q", name)
			}
			current = g
		}
		// A declared group with no healthy inheritors still has to lose any
		// bindings in scope (for example after an org opts out).
		if want == nil {
			want = &namedTarget{rules: current.Rules, descriptions: current.Descriptions}
		}
		a := targetGroup{name: name, current: current, rules: want.rules, descriptions: want.descriptions}
		var active []string
		protected := false
		for _, key := range currentBindings(current) {
			if _, ok := bindings[key]; ok {
				active = append(active, key)
			} else {
				protected = true
			}
		}
		setBindings(&a, active, sortedUnique(want.keys), bindings)
		if current.GUID != "" {
			changed := ruleKey(current.Rules) != ruleKey(want.rules)
			if changed && (current.global() || protected || len(a.unbind) > 0) {
				return nil, fmt.Errorf("named ASG %q has conflicting rules and cannot be changed while it serves other bindings", name)
			}
			a.update = !protected && !current.global() && (changed || !maps.Equal(current.Descriptions, want.descriptions))
		}
		if (current.GUID == "" && len(want.keys) > 0) || a.update || len(a.bind)+len(a.unbind) > 0 {
			actions = append(actions, a)
		}
	}
	return actions, nil
}
