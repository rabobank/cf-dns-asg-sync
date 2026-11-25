package asgsync

import (
	"fmt"
	"io"
	"slices"
	"strings"
)

func planCleanup(groups []SecurityGroup, named map[string]*namedTarget, bindings map[string]binding, prune, dnsFailed bool, out io.Writer) ([]targetGroup, error) {
	ordered := slices.Clone(groups)
	slices.SortFunc(ordered, func(a, b SecurityGroup) int { return strings.Compare(a.Name, b.Name) })
	var actions []targetGroup
	for _, g := range ordered {
		if _, ok := named[g.Name]; ok || g.global() || managedGroupName(g.Name) || g.Name == migrationCheckpointName {
			continue
		}
		bound := currentBindings(g)
		a := targetGroup{name: g.Name, current: g, rules: g.Rules}
		if prune && !g.Unsupported && g.GUID != "" {
			for _, key := range bound {
				if b, ok := bindings[key]; ok {
					a.unbind = append(a.unbind, b)
				}
			}
			a.retire = len(a.unbind) == len(bound) && (!dnsFailed || len(bound) > 0)
		}
		if a.retire || len(a.unbind) > 0 {
			actions = append(actions, a)
		}
		if !a.retire {
			if _, err := fmt.Fprintf(out, "warning: existing ASG %q is not selected by the policy (running: %v; staging: %v)\n", g.Name, g.Running, g.Staging); err != nil {
				return nil, err
			}
		}
	}
	return actions, nil
}
