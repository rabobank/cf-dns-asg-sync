package asgsync

import (
	"context"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"

	"go.yaml.in/yaml/v3"
)

type migrationGrant struct {
	Destination string   `yaml:"destination"`
	Protocol    string   `yaml:"protocol"`
	Ports       *string  `yaml:"ports,omitempty"`
	Type        *int     `yaml:"type,omitempty"`
	Code        *int     `yaml:"code,omitempty"`
	Log         *bool    `yaml:"log,omitempty"`
	Description *string  `yaml:"description,omitempty"`
	Lifecycles  []string `yaml:"lifecycles"`
}

func globalGroups(groups []SecurityGroup) []SecurityGroup {
	var result []SecurityGroup
	for _, g := range groups {
		if g.global() {
			result = append(result, g)
		}
	}
	slices.SortFunc(result, func(a, b SecurityGroup) int { return strings.Compare(a.Name, b.Name) })
	return result
}

type lifecycleRule struct {
	rule      Rule
	lifecycle string
}

func matchesGlobalDefaults(defaults []Grant, groups []SecurityGroup) bool {
	if defaults == nil {
		return false
	}
	expected, actual := map[lifecycleRule]bool{}, map[lifecycleRule]bool{}
	for _, g := range groups {
		if g.Unsupported || g.GUID == "" || strings.HasPrefix(g.Name, namePrefix) {
			return false
		}
		for _, rule := range g.Rules {
			if g.GlobalRunning {
				expected[lifecycleRule{rule, "running"}] = true
			}
			if g.GlobalStaging {
				expected[lifecycleRule{rule, "staging"}] = true
			}
		}
	}
	for _, grant := range defaults {
		if grant.Hostname != "" {
			return false
		}
		for _, rule := range grant.static {
			for _, lifecycle := range grant.Lifecycles {
				actual[lifecycleRule{rule, lifecycle}] = true
			}
		}
	}
	if len(expected) != len(actual) {
		return false
	}
	for rule := range expected {
		if !actual[rule] {
			return false
		}
	}
	return true
}

func retireGlobalGroups(ctx context.Context, cf Foundation, groups []SecurityGroup, dryRun bool, out io.Writer) error {
	if !dryRun {
		current, err := loadGroups(ctx, cf)
		if err != nil {
			return err
		}
		current = globalGroups(current)
		unchanged := slices.EqualFunc(groups, current, func(a, b SecurityGroup) bool {
			return !b.Unsupported && a.GUID == b.GUID && a.Name == b.Name && a.GlobalRunning == b.GlobalRunning && a.GlobalStaging == b.GlobalStaging && ruleKey(a.Rules) == ruleKey(b.Rules)
		})
		if !unchanged {
			return errors.New("global ASGs changed during migration; rerun before disabling global bindings")
		}
	}
	for _, g := range groups {
		var phases []string
		if g.GlobalRunning {
			phases = append(phases, "running")
		}
		if g.GlobalStaging {
			phases = append(phases, "staging")
		}
		if _, err := fmt.Fprintf(out, "disable global ASG bindings for %q (%s)\n", g.Name, strings.Join(phases, ", ")); err != nil {
			return err
		}
		if !dryRun {
			if err := cf.DisableGlobalGroup(ctx, g.GUID, g.GlobalRunning, g.GlobalStaging); err != nil {
				return fmt.Errorf("disable global ASG bindings for %q: %w", g.Name, err)
			}
		}
	}
	return nil
}

func reportGlobalGroups(groups []SecurityGroup, out io.Writer) error {
	var names, unsupported []string
	var rules []Rule
	descriptions := RuleDescriptions{}
	running, staging := map[Rule]bool{}, map[Rule]bool{}
	for _, g := range groups {
		if !g.global() {
			continue
		}
		names = append(names, fmt.Sprintf("%q", g.Name))
		if g.Unsupported {
			unsupported = append(unsupported, fmt.Sprintf("%q", g.Name))
			continue
		}
		for _, r := range g.Rules {
			rules = append(rules, r)
			running[r] = running[r] || g.GlobalRunning
			staging[r] = staging[r] || g.GlobalStaging
			descriptions[r] = mergeDescriptions(descriptions[r], g.Descriptions[r])
		}
	}
	if len(names) == 0 {
		return nil
	}
	slices.Sort(names)
	blocked := fmt.Errorf("global ASGs are enabled: %s", strings.Join(names, ", "))
	var report strings.Builder
	fmt.Fprintf(&report, "# Global ASGs are enabled: %s\n", strings.Join(names, ", "))
	if len(unsupported) > 0 {
		slices.Sort(unsupported)
		detail := fmt.Errorf("cannot generate complete defaults: unsupported global ASGs: %s", strings.Join(unsupported, ", "))
		fmt.Fprintf(&report, "# %s\n# Inspect these groups and translate their rules before migration.\n", detail)
		_, err := io.WriteString(out, report.String())
		return errors.Join(blocked, detail, err)
	}
	report.WriteString("# Use these defaults to match the current global grants. Explicit org allow\n" +
		"# lists replace defaults; include any global grants those orgs still need.\n" +
		"# Dry-run first. On apply, the sync installs replacement space bindings\n" +
		"# before disabling global bindings. ASGs and explicit bindings are retained.\n")
	defaults := make([]migrationGrant, 0)
	type phases struct{ running, staging bool }
	var byPhase = map[phases][]Rule{}
	for _, r := range normalize(rules) {
		p := phases{running[r], staging[r]}
		byPhase[p] = append(byPhase[p], r)
	}
	for _, p := range []phases{{true, false}, {false, true}, {true, true}} {
		var lifecycles []string
		if p.running {
			lifecycles = append(lifecycles, "running")
		}
		if p.staging {
			lifecycles = append(lifecycles, "staging")
		}
		for _, r := range securityGroupRules(byPhase[p], descriptions) {
			defaults = append(defaults, migrationGrant{Destination: r.Destination, Protocol: r.Protocol, Ports: r.Ports, Type: r.Type, Code: r.Code, Log: r.Log, Description: r.Description, Lifecycles: lifecycles})
		}
	}
	data, err := yaml.Marshal(struct {
		Defaults []migrationGrant `yaml:"defaults"`
	}{defaults})
	if err != nil {
		return errors.Join(blocked, fmt.Errorf("encode migration defaults: %w", err))
	}
	report.Write(data)
	_, err = io.WriteString(out, report.String())
	return errors.Join(blocked, err)
}
