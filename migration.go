package asgsync

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"

	"go.yaml.in/yaml/v3"
)

const migrationCheckpointName = "cdas-migration-baseline"

type checkpointRule struct {
	Running     bool   `json:"running"`
	Staging     bool   `json:"staging"`
	Description string `json:"description,omitempty"`
}

func migrationBaseline(groups []SecurityGroup, global []SecurityGroup) ([]SecurityGroup, string, error) {
	var baseline []SecurityGroup
	var id string
	for _, g := range groups {
		if g.Name != migrationCheckpointName {
			continue
		}
		if id != "" || g.GUID == "" || g.Unsupported || g.global() || len(g.Running)+len(g.Staging) > 0 {
			return nil, "", errors.New("invalid global ASG migration checkpoint")
		}
		id = g.GUID
		baseline = []SecurityGroup{{GUID: id, Name: "original running baseline", GlobalRunning: true, Descriptions: RuleDescriptions{}}, {GUID: id, Name: "original staging baseline", GlobalStaging: true, Descriptions: RuleDescriptions{}}}
		for _, r := range g.Rules {
			var state checkpointRule
			if err := json.Unmarshal([]byte(g.Descriptions[r]), &state); err != nil || (!state.Running && !state.Staging) {
				return nil, "", errors.New("invalid rule in global ASG migration checkpoint")
			}
			for i, include := range []bool{state.Running, state.Staging} {
				if include {
					baseline[i].Rules = append(baseline[i].Rules, r)
					baseline[i].Descriptions[r] = state.Description
				}
			}
		}
	}
	if id == "" {
		return global, "", nil
	}
	expected, ok := globalRuleSet(baseline)
	actual, valid := globalRuleSet(global)
	if !ok || !valid {
		return nil, "", errors.New("invalid global ASGs during migration")
	}
	for rule := range actual {
		if !expected[rule] {
			return nil, "", errors.New("global ASG grants changed since the migration checkpoint was recorded")
		}
	}
	return baseline, id, nil
}

func createMigrationCheckpoint(ctx context.Context, cf Foundation, groups []SecurityGroup) (string, error) {
	states := map[Rule]checkpointRule{}
	for _, g := range groups {
		for _, r := range g.Rules {
			s := states[r]
			s.Running = s.Running || g.GlobalRunning
			s.Staging = s.Staging || g.GlobalStaging
			s.Description = mergeDescriptions(s.Description, g.Descriptions[r])
			states[r] = s
		}
	}
	var rules []Rule
	descriptions := RuleDescriptions{}
	for r, s := range states {
		rules = append(rules, r)
		data, _ := json.Marshal(s)
		descriptions[r] = string(data)
	}
	id, err := cf.CreateGroup(ctx, migrationCheckpointName, normalize(rules), descriptions)
	if err != nil {
		return "", fmt.Errorf("record global ASG migration checkpoint: %w", err)
	}
	if id == "" {
		return "", errors.New("empty global ASG migration checkpoint GUID")
	}
	return id, nil
}

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

func globalRuleSet(groups []SecurityGroup) (map[lifecycleRule]bool, bool) {
	expected := map[lifecycleRule]bool{}
	for _, g := range groups {
		if g.Unsupported || g.GUID == "" || managedGroupName(g.Name) {
			return nil, false
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
	return expected, true
}

func matchesGlobalDefaults(defaults []Grant, groups []SecurityGroup) (bool, error) {
	expected, ok := globalRuleSet(groups)
	if defaults == nil || !ok {
		return false, nil
	}
	actual := map[lifecycleRule]bool{}
	for _, input := range defaults {
		grant, rules, err := deriveGrant(input)
		if err != nil {
			return false, fmt.Errorf("defaults: %w", err)
		}
		if grant.Hostname != "" {
			return false, nil
		}
		for _, rule := range rules {
			for _, lifecycle := range grant.Lifecycles {
				actual[lifecycleRule{rule, lifecycle}] = true
			}
		}
	}
	if len(expected) != len(actual) {
		return false, nil
	}
	for rule := range expected {
		if !actual[rule] {
			return false, nil
		}
	}
	return true, nil
}

func retireGlobalGroups(ctx context.Context, cf Foundation, groups []SecurityGroup, checkpoint string, dryRun bool, out io.Writer) error {
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
		if checkpoint == "" {
			checkpoint, err = createMigrationCheckpoint(ctx, cf, groups)
			if err != nil {
				return err
			}
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
	if !dryRun {
		if err := cf.DeleteGroup(ctx, checkpoint); err != nil {
			return fmt.Errorf("remove global ASG migration checkpoint: %w", err)
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
