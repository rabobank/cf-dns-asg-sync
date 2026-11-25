package asgsync_test

import (
	"context"
	"errors"
	"io"
	"net/netip"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	sync "github.com/rkoster/cf-dns-asg-sync"
	"github.com/rkoster/cf-dns-asg-sync/asgsyncfakes"
)

var _ = Describe("Named default coverage", func() {
	var cf *asgsyncfakes.FakeFoundation
	var resolver *asgsyncfakes.FakeResolver
	var a, b sync.Rule
	BeforeEach(func() {
		cf = &asgsyncfakes.FakeFoundation{}
		resolver = &asgsyncfakes.FakeResolver{}
		cf.ListOrgNamesReturns([]string{"inherited"}, nil)
		cf.FindOrgCalls(func(_ context.Context, name string) (string, error) { return name, nil })
		cf.ListSpacesCalls(func(_ context.Context, id string) ([]sync.Space, error) {
			return []sync.Space{{Name: "app", GUID: id + "-space"}}, nil
		})
		cf.CreateGroupCalls(func(_ context.Context, name string, _ []sync.Rule, _ sync.RuleDescriptions) (string, error) {
			return name, nil
		})
		a = sync.Rule{Destination: "192.0.2.1", Protocol: "tcp", Port: 443}
		b = sync.Rule{Destination: "192.0.2.2", Protocol: "tcp", Port: 443}
	})
	run := func(ctx context.Context, cf sync.Foundation, resolver sync.Resolver, text string) error {
		GinkgoHelper()
		policy, err := sync.ParsePolicy(strings.NewReader(text))
		Expect(err).NotTo(HaveOccurred())
		return sync.Sync(ctx, cf, policy, resolver, sync.DNSOptions{}, false, io.Discard)
	}
	const namedA = `defaults:
  - name: base
    lifecycles: [running]
    rules: [{destination: 192.0.2.1, protocol: tcp, ports: [443]}]
`
	It("keeps the old named grant if its replacement bind fails", func(ctx SpecContext) {
		cf.ListGroupsReturns([]sync.SecurityGroup{{GUID: "base", Name: "base-running", Rules: []sync.Rule{a, b}, Running: []string{"inherited-space"}}}, nil)
		cf.BindRunningReturns(errors.New("replacement bind failed"))
		Expect(run(ctx, cf, resolver, namedA+`  - {destination: 192.0.2.2, protocol: tcp, ports: [443], lifecycles: [running]}
`)).To(MatchError(ContainSubstring("replacement bind failed")))
		Expect(cf.UpdateGroupDescriptionsCallCount()).To(BeZero())
	})
	It("adds moved rules to their new named group before removing them from the old one", func(ctx SpecContext) {
		cf.ListGroupsReturns([]sync.SecurityGroup{
			{GUID: "base", Name: "base-running", Rules: []sync.Rule{a, b}, Running: []string{"inherited-space"}},
			{GUID: "next", Name: "next-running", Running: []string{"inherited-space"}},
		}, nil)
		Expect(run(ctx, cf, resolver, namedA+`  - name: next
    lifecycles: [running]
    rules: [{destination: 192.0.2.2, protocol: tcp, ports: [443]}]
`)).To(Succeed())
		Expect(cf.UpdateGroupDescriptionsCallCount()).To(Equal(2))
		_, id, rules, _ := cf.UpdateGroupDescriptionsArgsForCall(0)
		Expect(id).To(Equal("next"))
		Expect(rules).To(Equal([]sync.Rule{b}))
		_, id, rules, _ = cf.UpdateGroupDescriptionsArgsForCall(1)
		Expect(id).To(Equal("base"))
		Expect(rules).To(Equal([]sync.Rule{a}))
	})

	It("publishes the union when a named group gains and loses rules in the same run", func(ctx SpecContext) {
		removed := sync.Rule{Destination: "192.0.2.3", Protocol: "tcp", Port: 443}
		cf.ListGroupsReturns([]sync.SecurityGroup{{GUID: "base", Name: "base-running", Rules: []sync.Rule{a, removed}, Running: []string{"inherited-space"}}}, nil)
		cf.BindRunningCalls(func(_ context.Context, _ string, _ []string) error {
			Expect(cf.UpdateGroupDescriptionsCallCount()).To(Equal(1))
			_, id, rules, _ := cf.UpdateGroupDescriptionsArgsForCall(0)
			Expect(id).To(Equal("base"))
			Expect(rules).To(ConsistOf(a, b, removed))
			return nil
		})
		Expect(run(ctx, cf, resolver, `defaults:
  - name: base
    lifecycles: [running]
    rules:
      - {destination: 192.0.2.1, protocol: tcp, ports: [443]}
      - {destination: 192.0.2.2, protocol: tcp, ports: [443]}
  - {destination: 192.0.2.3, protocol: tcp, ports: [443], lifecycles: [running]}
`)).To(Succeed())
		Expect(cf.BindRunningCallCount()).To(Equal(1))
		Expect(cf.UpdateGroupDescriptionsCallCount()).To(Equal(2))
		_, _, rules, _ := cf.UpdateGroupDescriptionsArgsForCall(1)
		Expect(rules).To(ConsistOf(a, b))
	})
	It("retains DNS provenance for a space override covered by a named native grant", func(ctx SpecContext) {
		text := namedA + `orgs:
  - name: inherited
    spaces:
      - name: app
        allow: [{hostname: service.example.org, protocol: tcp, ports: [443], lifecycles: [running]}]
`
		resolver.LookupNetIPReturns([]netip.Addr{netip.MustParseAddr(a.Destination)}, nil)
		Expect(run(ctx, cf, resolver, text)).To(Succeed())
		Expect(cf.CreateGroupCallCount()).To(Equal(1))
		_, name, rules, descriptions := cf.CreateGroupArgsForCall(0)
		Expect(descriptions).To(HaveKeyWithValue(a, "service.example.org"))
		cf.ListGroupsReturns([]sync.SecurityGroup{{GUID: name, Name: name, Rules: rules, Descriptions: descriptions, Running: []string{"inherited-space"}}}, nil)
		resolver.LookupNetIPReturns(nil, nil)
		Expect(run(ctx, cf, resolver, text)).To(MatchError(ContainSubstring("1 previously applied IPs: 192.0.2.1")))
	})
	It("shares a superset group across inheriting and explicit orgs", func(ctx SpecContext) {
		Expect(run(ctx, cf, resolver, namedA+`  - {destination: 192.0.2.2, protocol: tcp, ports: [443], lifecycles: [running]}
orgs:
  - name: explicit
    allow:
      - {destination: 192.0.2.1, protocol: tcp, ports: [443], lifecycles: [running]}
      - {destination: 192.0.2.2, protocol: tcp, ports: [443], lifecycles: [running]}
`)).To(Succeed())
		Expect(cf.CreateGroupCallCount()).To(Equal(2))
		_, id, spaces := cf.BindRunningArgsForCall(1)
		Expect(id).NotTo(Equal("base-running"))
		Expect(spaces).To(ConsistOf("inherited-space", "explicit-space"))
	})
})
