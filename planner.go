package asgsync

import (
	"context"
	"fmt"
	"maps"
	"math/big"
	"math/bits"
	"slices"
)

type Group struct {
	Rules  []Rule
	Spaces []string
}

const (
	maxIntersections   = 4096
	maxSearchNodes     = 100_000
	maxEdges           = 1_000_000
	maxCandidateChecks = 1_000_000
	maxMemoBytes       = 32 << 20
)

type candidate struct {
	group Group
	cover *big.Int
	cost  int
}

// Minimize covers the space × grant matrix with the fewest all-allowed rectangles.
// Every rectangle can be expanded to a maximal one without granting extra access,
// so all maximal rectangles suffice to prove the minimum. Valid existing rectangles
// are also candidates, so ties can preserve their bindings.
func Minimize(ctx context.Context, policies map[string][]Rule, existing []Group) ([]Group, error) {
	return minimize(ctx, policies, existing, nil)
}

// minimize takes coverage from protected groups as already paid for. Candidate
// generation still uses the full policies: a new group may also cover an edge
// served by a protected group if that lets it cover other spaces safely.
func minimize(ctx context.Context, policies map[string][]Rule, existing, fixed []Group) ([]Group, error) {
	spaces := slices.Sorted(maps.Keys(policies))
	spaceIDs := map[string]int{}
	var allRules []Rule
	for _, s := range spaces {
		allRules = append(allRules, policies[s]...)
	}
	allRules = normalize(allRules)
	if len(allRules) == 0 {
		return nil, nil
	}
	ids := map[Rule]int{}
	for i, r := range allRules {
		ids[r] = i
	}
	rows := make([]*big.Int, len(spaces))
	uniqueRows := map[string]bool{}
	var intersections []*big.Int
	seen := map[string]bool{}
	checks := 0
	for i, s := range spaces {
		spaceIDs[s] = i
		row := new(big.Int)
		for _, r := range policies[s] {
			row.SetBit(row, ids[r], 1)
		}
		rows[i] = row
		key := string(row.Bytes())
		if uniqueRows[key] || row.Sign() == 0 {
			continue
		}
		uniqueRows[key] = true
		add := func(mask *big.Int) {
			k := string(mask.Bytes())
			if mask.Sign() != 0 && !seen[k] {
				seen[k] = true
				intersections = append(intersections, mask)
			}
		}
		n := len(intersections)
		add(row)
		for _, other := range intersections[:n] {
			checks++
			if len(intersections) >= maxIntersections || checks > maxCandidateChecks {
				return nil, fmt.Errorf("ASG minimization exceeded candidate budget")
			}
			add(new(big.Int).And(other, row))
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
	}
	// Identical space policies have the same edges for the maximal candidates.
	// Keep individual rows so an existing group can retain any valid subset of bindings.
	edges := make([]map[int]int, len(rows))
	edgeCount := 0
	for i, row := range rows {
		edges[i] = map[int]int{}
		for _, j := range setBits(row) {
			edges[i][j] = edgeCount
			edgeCount++
		}
		if edgeCount > maxEdges {
			return nil, fmt.Errorf("ASG minimization exceeded grant budget")
		}
	}
	if len(intersections)+len(existing) > maxCandidateChecks/max(1, edgeCount) {
		return nil, fmt.Errorf("ASG minimization exceeded coverage budget")
	}
	var candidates []candidate
	current := map[string][]string{}
	for _, g := range existing {
		current[ruleKey(g.Rules)] = g.Spaces
	}
	// Take removal of all existing bindings as the baseline. Reusing an
	// existing binding avoids one removal; a new binding adds one operation.
	bindingCost := func(g Group) int {
		cost := len(g.Spaces)
		previous, ok := current[ruleKey(g.Rules)]
		if !ok {
			return cost + 1
		}
		for _, s := range g.Spaces {
			if slices.Contains(previous, s) {
				cost -= 2
			}
		}
		return cost - 1
	}
	cover := func(group Group, cost int) {
		mask := new(big.Int)
		for _, s := range group.Spaces {
			for _, r := range group.Rules {
				mask.SetBit(mask, edges[spaceIDs[s]][ids[r]], 1)
			}
		}
		candidates = append(candidates, candidate{group, mask, cost})
	}
	for _, set := range intersections {
		var group Group
		for _, j := range setBits(set) {
			group.Rules = append(group.Rules, allRules[j])
		}
		for i, row := range rows {
			if new(big.Int).And(row, set).Cmp(set) == 0 {
				group.Spaces = append(group.Spaces, spaces[i])
			}
		}
		cover(group, bindingCost(group))
	}
	for _, g := range existing {
		if len(g.Rules) == 0 || len(g.Spaces) == 0 {
			continue
		}
		valid := true
		for _, s := range g.Spaces {
			i, ok := spaceIDs[s]
			if !ok {
				valid = false
				break
			}
			for _, r := range g.Rules {
				j, ok := ids[r]
				if !ok || rows[i].Bit(j) == 0 {
					valid = false
					break
				}
			}
			if !valid {
				break
			}
		}
		if valid {
			cover(g, bindingCost(g))
		}
	}
	covered := new(big.Int)
	for _, g := range fixed {
		for _, s := range g.Spaces {
			for _, r := range g.Rules {
				covered.SetBit(covered, edges[spaceIDs[s]][ids[r]], 1)
			}
		}
	}
	return minimumCover(ctx, candidates, edgeCount, covered)
}

func setBits(mask *big.Int) []int {
	var result []int
	for i, w := range mask.Bits() {
		for w != 0 {
			result = append(result, i*bits.UintSize+bits.TrailingZeros(uint(w)))
			w &= w - 1
		}
	}
	return result
}

func minimumCover(ctx context.Context, candidates []candidate, count int, initial *big.Int) ([]Group, error) {
	byEdge := make([][]int, count)
	for i, c := range candidates {
		for _, edge := range setBits(c.cover) {
			byEdge[edge] = append(byEdge[edge], i)
		}
	}
	order := make([]int, count)
	for i := range order {
		order[i] = i
	}
	slices.SortStableFunc(order, func(a, b int) int { return len(byEdge[a]) - len(byEdge[b]) })
	var best []int
	bestCost := 0
	type score struct{ depth, cost int }
	memo := map[string]score{}
	memoBytes := 0
	nodes := 0
	var search func(*big.Int, []int, int) error
	search = func(covered *big.Int, path []int, cost int) error {
		nodes++
		if nodes > maxSearchNodes {
			return fmt.Errorf("ASG minimization exceeded search budget")
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if best != nil && len(path) > len(best) {
			return nil
		}
		edge := -1
		for _, e := range order {
			if covered.Bit(e) == 0 {
				edge = e
				break
			}
		}
		if edge == -1 {
			if best == nil || len(path) < len(best) || (len(path) == len(best) && cost < bestCost) {
				best = append(make([]int, 0, len(path)), path...)
				bestCost = cost
			}
			return nil
		}
		if best != nil && len(path) >= len(best) {
			return nil
		}
		key := string(covered.Bytes())
		if prev, ok := memo[key]; ok {
			if prev.depth < len(path) || (prev.depth == len(path) && prev.cost <= cost) {
				return nil
			}
			memo[key] = score{len(path), cost}
		} else if memoBytes+len(key) < maxMemoBytes {
			memo[key] = score{len(path), cost}
			memoBytes += len(key)
		}
		for _, i := range byEdge[edge] {
			c := candidates[i]
			if err := search(new(big.Int).Or(covered, c.cover), append(path, i), cost+c.cost); err != nil {
				return err
			}
		}
		return nil
	}
	if err := search(initial, nil, 0); err != nil {
		return nil, err
	}
	if best == nil {
		return nil, fmt.Errorf("no exact ASG cover found")
	}
	result := make([]Group, 0, len(best))
	for _, i := range best {
		result = append(result, candidates[i].group)
	}
	return result, nil
}
