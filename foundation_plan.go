package asgsync

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/hex"
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strings"
)

const shortPrefix = "cdas-"
const legacyPrefix = "cf-dns-asg-sync-"

var shortNamePattern = regexp.MustCompile(`^cdas-[a-z2-7]{13}$`)
var nameEncoding = base32.NewEncoding("abcdefghijklmnopqrstuvwxyz234567").WithPadding(base32.NoPadding)

func legacyOrgKey(guid string) string { return fmt.Sprintf("%x", sha256.Sum256([]byte(guid))) }

func legacyName(name string) (owner, fingerprint string, ok bool) {
	suffix, ok := strings.CutPrefix(name, legacyPrefix)
	if !ok || len(suffix) != 129 || suffix[64] != '-' {
		return "", "", false
	}
	owner, fingerprint = suffix[:64], suffix[65:]
	_, ownerErr := hex.DecodeString(owner)
	_, rulesErr := hex.DecodeString(fingerprint)
	return owner, fingerprint, ownerErr == nil && rulesErr == nil
}

func managedGroupName(name string) bool {
	_, _, legacy := legacyName(name)
	return legacy || shortNamePattern.MatchString(name)
}

func validManagedRules(g SecurityGroup) bool {
	_, fingerprint, legacy := legacyName(g.Name)
	return !legacy || fingerprint == ruleKey(g.Rules)
}

type snapshotGroup struct {
	SecurityGroup
	active    []string
	protected bool
}

func planFoundation(ctx context.Context, groups []SecurityGroup, policies map[string][]Rule, bindings map[string]binding, provenance map[string]RuleDescriptions, owners map[string]bool, namedCoverage []Group, dnsFailed bool) ([]targetGroup, error) {
	ordered := slices.Clone(groups)
	slices.SortFunc(ordered, func(a, b SecurityGroup) int { return strings.Compare(a.Name, b.Name) })
	taken := map[string]bool{}
	for _, g := range groups {
		taken[g.Name] = true
	}
	var inventory []snapshotGroup
	var existing []Group
	index := map[string][]snapshotGroup{}
	seenNames, seenIDs := map[string]bool{}, map[string]bool{}
	for _, g := range ordered {
		if !managedGroupName(g.Name) {
			continue
		}
		s := snapshotGroup{SecurityGroup: g}
		bound := currentBindings(g)
		for _, key := range bound {
			if _, ok := bindings[key]; ok {
				s.active = append(s.active, key)
			} else {
				s.protected = true
			}
		}
		owner, _, legacy := legacyName(g.Name)
		if len(s.active) == 0 && (legacy && !owners[owner] || !legacy && len(bound) == 0 && len(owners) == 0) {
			continue
		}
		// Invalid groups outside the active scope are never adopted or modified.
		if g.GUID == "" || g.global() || g.Unsupported || !validManagedRules(g) || seenNames[g.Name] || seenIDs[g.GUID] {
			if len(s.active) > 0 || (legacy && owners[owner]) {
				return nil, fmt.Errorf("managed ASG %s has invalid identity or rules", g.Name)
			}
			continue
		}
		seenNames[g.Name], seenIDs[g.GUID] = true, true
		s.Rules = normalize(slices.Clone(g.Rules))
		inventory = append(inventory, s)
		if s.protected {
			continue
		}
		fingerprint := ruleKey(s.Rules)
		index[fingerprint] = append(index[fingerprint], s)
		existing = append(existing, Group{s.Rules, s.active})
	}
	fixedTargets, fixed := selectProtectedBindings(inventory, policies)
	desired, err := minimize(ctx, policies, existing, append(namedCoverage, fixed...))
	if err != nil {
		return nil, err
	}
	var actions []targetGroup
	selected := map[string]bool{}
	for _, g := range desired {
		var current snapshotGroup
		best := -1
		for _, s := range index[ruleKey(g.Rules)] {
			if selected[s.GUID] || !slices.Equal(s.Rules, g.Rules) {
				continue
			}
			score := 0
			for _, key := range g.Spaces {
				if slices.Contains(s.active, key) {
					score++
				}
			}
			if score > best {
				best, current = score, s
			}
		}
		a := targetGroup{name: current.Name, rules: g.Rules, current: current.SecurityGroup, descriptions: RuleDescriptions{}}
		if current.GUID == "" {
			for a.name == "" || taken[a.name] {
				var nonce [8]byte
				rand.Read(nonce[:])
				a.name = shortPrefix + nameEncoding.EncodeToString(nonce[:])
			}
			taken[a.name] = true
		} else {
			selected[current.GUID] = true
		}
		orgs := map[string]bool{}
		for _, key := range g.Spaces {
			orgs[bindings[key].org] = true
		}
		for _, r := range g.Rules {
			for _, org := range slices.Sorted(maps.Keys(orgs)) {
				if d := provenance[org][r]; d != "" {
					a.descriptions[r] = mergeDescriptions(a.descriptions[r], d)
				}
			}
		}
		a.update = current.GUID != "" && !maps.Equal(a.descriptions, current.Descriptions)
		setBindings(&a, current.active, g.Spaces, bindings)
		if current.GUID == "" || a.update || len(a.bind)+len(a.unbind) > 0 {
			actions = append(actions, a)
		}
	}
	for _, s := range inventory {
		if selected[s.GUID] {
			continue
		}
		a := targetGroup{name: s.Name, rules: s.Rules, current: s.SecurityGroup}
		setBindings(&a, s.active, fixedTargets[s.GUID], bindings)
		// Leave unbound groups alone during DNS failure: an opaque name cannot
		// establish whether an interrupted create belonged to a failed org.
		a.retire = !s.protected && (!dnsFailed || len(s.active) > 0)
		if a.retire || len(a.bind)+len(a.unbind) > 0 {
			actions = append(actions, a)
		}
	}
	return actions, nil
}

func selectProtectedBindings(inventory []snapshotGroup, policies map[string][]Rule) (map[string][]string, []Group) {
	var protected []snapshotGroup
	for _, group := range inventory {
		if group.protected {
			protected = append(protected, group)
		}
	}
	targets := map[string][]string{}
	for _, key := range slices.Sorted(maps.Keys(policies)) {
		want := map[Rule]bool{}
		for _, rule := range policies[key] {
			want[rule] = true
		}
		covered := map[Rule]bool{}
		var candidates []snapshotGroup
		keep := func(group snapshotGroup) {
			targets[group.GUID] = append(targets[group.GUID], key)
			for _, rule := range group.Rules {
				covered[rule] = true
			}
		}
		for _, group := range protected {
			if !containsRules(want, group.Rules) {
				continue
			}
			if slices.Contains(group.active, key) {
				keep(group)
			} else {
				candidates = append(candidates, group)
			}
		}
		// Add the greatest missing coverage first. Inventory order breaks ties.
		for len(covered) < len(want) {
			best, gain := -1, 0
			for i, group := range candidates {
				missing := 0
				for _, rule := range group.Rules {
					if !covered[rule] {
						missing++
					}
				}
				if missing > gain {
					best, gain = i, missing
				}
			}
			if best < 0 {
				break
			}
			keep(candidates[best])
		}
	}
	var fixed []Group
	for _, group := range protected {
		if keys := targets[group.GUID]; len(keys) > 0 && len(group.Rules) > 0 {
			fixed = append(fixed, Group{group.Rules, keys})
		}
	}
	return targets, fixed
}

func containsRules(want map[Rule]bool, group []Rule) bool {
	for _, r := range group {
		if !want[r] {
			return false
		}
	}
	return true
}

func setBindings(a *targetGroup, active, want []string, bindings map[string]binding) {
	for _, key := range want {
		if !slices.Contains(active, key) {
			a.bind = append(a.bind, bindings[key])
		}
	}
	for _, key := range active {
		if !slices.Contains(want, key) {
			a.unbind = append(a.unbind, bindings[key])
		}
	}
}
