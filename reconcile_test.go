package asgsync_test

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	sync "github.com/rkoster/cf-dns-asg-sync"
	"github.com/rkoster/cf-dns-asg-sync/asgsyncfakes"
)

var _ = Describe("ASG reconciliation", func() {
	var cf *asgsyncfakes.FakeFoundation
	var org sync.ResolvedOrg
	var existing []sync.SecurityGroup
	BeforeEach(func() {
		cf = &asgsyncfakes.FakeFoundation{}
		org = sync.ResolvedOrg{Name: "payments", Baseline: []sync.Rule{{Destination: "192.0.2.1", Protocol: "tcp", Port: 443}}}
		existing = nil
		cf.FindOrgReturns("payments-guid", nil)
		cf.ListSpacesReturns([]sync.Space{{Name: "dev", GUID: "dev-guid"}, {Name: "prod", GUID: "prod-guid"}}, nil)
		cf.ListGroupsCalls(func(context.Context) ([]sync.SecurityGroup, error) { return existing, nil })
		cf.CreateGroupCalls(func(_ context.Context, name string, rules []sync.Rule, descriptions sync.RuleDescriptions) (string, error) {
			id := fmt.Sprintf("group-%d", len(existing)+1)
			existing = append(existing, sync.SecurityGroup{GUID: id, Name: name, Rules: append([]sync.Rule(nil), rules...), Descriptions: descriptions})
			return id, nil
		})
		cf.BindRunningCalls(func(_ context.Context, id string, guids []string) error {
			for i := range existing {
				if existing[i].GUID == id {
					existing[i].Running = append(existing[i].Running, guids...)
					return nil
				}
			}
			return fmt.Errorf("unknown group %s", id)
		})
	})

	It("binds one group to all spaces for an org-only entry and picks up new spaces on the next sync", func(ctx SpecContext) {
		existing = append(existing, sync.SecurityGroup{GUID: "foreign", Name: "cf-dns-asg-sync-reporting-guid-other", Global: true, Running: []string{"foreign-space"}})
		Expect(sync.Reconcile(ctx, cf, []sync.ResolvedOrg{org}, false, io.Discard)).To(Succeed())
		Expect(cf.CreateGroupCallCount()).To(Equal(1))
		Expect(existing[1].Running).To(ConsistOf("dev-guid", "prod-guid"))
		Expect(sync.Reconcile(ctx, cf, []sync.ResolvedOrg{org}, false, io.Discard)).To(Succeed())
		Expect(cf.BindRunningCallCount()).To(Equal(1))
		cf.ListSpacesReturns([]sync.Space{{Name: "dev", GUID: "dev-guid"}, {Name: "prod", GUID: "prod-guid"}, {Name: "new", GUID: "new-guid"}}, nil)
		Expect(sync.Reconcile(ctx, cf, []sync.ResolvedOrg{org}, false, io.Discard)).To(Succeed())
		Expect(cf.CreateGroupCallCount()).To(Equal(1))
		_, _, bound := cf.BindRunningArgsForCall(1)
		Expect(bound).To(Equal([]string{"new-guid"}))
		Expect(cf.DeleteGroupCallCount()).To(BeZero())
	})

	It("keeps identical grants in separate groups across configured orgs", func(ctx SpecContext) {
		cf.FindOrgCalls(func(_ context.Context, name string) (string, error) { return name + "-guid", nil })
		cf.ListSpacesCalls(func(_ context.Context, org string) ([]sync.Space, error) {
			return []sync.Space{{Name: "dev", GUID: org + "-dev"}}, nil
		})
		other := org
		other.Name = "reporting"
		Expect(sync.Reconcile(ctx, cf, []sync.ResolvedOrg{org, other}, false, io.Discard)).To(Succeed())
		Expect(existing).To(HaveLen(2))
		Expect(existing[0].Name).NotTo(Equal(existing[1].Name))
		Expect(existing[0].Running).To(Equal([]string{"payments-guid-dev"}))
		Expect(existing[1].Running).To(Equal([]string{"reporting-guid-dev"}))
	})

	It("refuses to mutate a managed group bound outside its org", func(ctx SpecContext) {
		Expect(sync.Reconcile(ctx, cf, []sync.ResolvedOrg{org}, false, io.Discard)).To(Succeed())
		existing[0].Running = append(existing[0].Running, "foreign-space")
		Expect(sync.Reconcile(ctx, cf, []sync.ResolvedOrg{org}, false, io.Discard)).To(MatchError(ContainSubstring("foreign-space")))
		Expect(cf.BindRunningCallCount()).To(Equal(1))
		Expect(cf.UnbindRunningCallCount()).To(BeZero())
		Expect(cf.DeleteGroupCallCount()).To(BeZero())
	})

	It("previews changes and refuses unknown overrides before making writes", func(ctx SpecContext) {
		var out strings.Builder
		Expect(sync.Reconcile(ctx, cf, []sync.ResolvedOrg{org}, true, &out)).To(Succeed())
		Expect(out.String()).To(ContainSubstring("dev"))
		Expect(cf.CreateGroupCallCount()).To(BeZero())
		org.Extras = map[string][]sync.Rule{"missing": nil}
		Expect(sync.Reconcile(ctx, cf, []sync.ResolvedOrg{org}, false, io.Discard)).To(MatchError(ContainSubstring("missing")))
		Expect(cf.CreateGroupCallCount()).To(BeZero())
	})

	It("backfills descriptions on existing ASGs without changing their grants or bindings", func(ctx SpecContext) {
		Expect(sync.Reconcile(ctx, cf, []sync.ResolvedOrg{org}, false, io.Discard)).To(Succeed())
		org.Descriptions = sync.RuleDescriptions{org.Baseline[0]: "a.example.org,b.example.org"}
		Expect(sync.Reconcile(ctx, cf, []sync.ResolvedOrg{org}, true, io.Discard)).To(Succeed())
		Expect(cf.UpdateGroupDescriptionsCallCount()).To(BeZero())
		cf.UpdateGroupDescriptionsCalls(func(_ context.Context, id string, rules []sync.Rule, descriptions sync.RuleDescriptions) error {
			Expect(id).To(Equal(existing[0].GUID))
			Expect(rules).To(Equal(existing[0].Rules))
			existing[0].Descriptions = descriptions
			return nil
		})
		Expect(sync.Reconcile(ctx, cf, []sync.ResolvedOrg{org}, false, io.Discard)).To(Succeed())
		Expect(sync.Reconcile(ctx, cf, []sync.ResolvedOrg{org}, false, io.Discard)).To(Succeed())
		Expect(cf.UpdateGroupDescriptionsCallCount()).To(Equal(1))
		Expect(existing[0].Descriptions).To(Equal(org.Descriptions))
		Expect(cf.CreateGroupCallCount()).To(Equal(1))
		Expect(cf.BindRunningCallCount()).To(Equal(1))
		Expect(cf.UnbindRunningCallCount()).To(BeZero())
		Expect(cf.DeleteGroupCallCount()).To(BeZero())
	})

	It("does not grant access from a first-run empty answer and applies rules once DNS recovers", func(ctx SpecContext) {
		policy, err := sync.ParsePolicy(strings.NewReader(`orgs: [{name: payments, allow: [{hostname: payments.example.org, protocol: tcp, ports: [443]}]}]`))
		Expect(err).NotTo(HaveOccurred())
		resolver := &asgsyncfakes.FakeResolver{}
		orgs, err := sync.Resolve(ctx, policy, resolver, sync.DNSOptions{})
		Expect(err).NotTo(HaveOccurred())
		Expect(sync.Reconcile(ctx, cf, orgs, false, io.Discard)).To(MatchError(ContainSubstring("no previously applied IPs recorded")))
		Expect(cf.CreateGroupCallCount()).To(BeZero())
		Expect(cf.BindRunningCallCount()).To(BeZero())
		Expect(cf.UpdateGroupDescriptionsCallCount()).To(BeZero())
		Expect(cf.UnbindRunningCallCount()).To(BeZero())
		Expect(cf.DeleteGroupCallCount()).To(BeZero())
		resolver.LookupNetIPReturns([]netip.Addr{netip.MustParseAddr("192.0.2.1")}, nil)
		orgs, err = sync.Resolve(ctx, policy, resolver, sync.DNSOptions{})
		Expect(err).NotTo(HaveOccurred())
		Expect(sync.Reconcile(ctx, cf, orgs, false, io.Discard)).To(Succeed())
		Expect(existing).To(HaveLen(1))
		Expect(existing[0].Descriptions).To(Equal(sync.RuleDescriptions{org.Baseline[0]: "payments.example.org"}))
	})

	It("binds rotated grants before revoking old grants and recovers an interrupted create", func(ctx SpecContext) {
		Expect(sync.Reconcile(ctx, cf, []sync.ResolvedOrg{org}, false, io.Discard)).To(Succeed())
		org.Baseline[0].Destination = "192.0.2.2"
		cf.BindRunningReturnsOnCall(1, fmt.Errorf("interrupted"))
		Expect(sync.Reconcile(ctx, cf, []sync.ResolvedOrg{org}, false, io.Discard)).To(MatchError(ContainSubstring("interrupted")))
		Expect(cf.UnbindRunningCallCount()).To(BeZero())
		cf.BindRunningCalls(func(_ context.Context, id string, guids []string) error {
			if id != existing[1].GUID {
				return fmt.Errorf("wrong group %s", id)
			}
			existing[1].Running = append(existing[1].Running, guids...)
			return nil
		})
		cf.UnbindRunningCalls(func(_ context.Context, _ string, _ string) error {
			if len(existing[1].Running) != 2 {
				return fmt.Errorf("revoked before replacement was bound")
			}
			return nil
		})
		Expect(sync.Reconcile(ctx, cf, []sync.ResolvedOrg{org}, false, io.Discard)).To(Succeed())
		Expect(cf.CreateGroupCallCount()).To(Equal(2))
		Expect(cf.UnbindRunningCallCount()).To(Equal(2))
		Expect(cf.DeleteGroupCallCount()).To(Equal(1))
	})

	DescribeTable("retains an affected org on DNS failure and still syncs healthy orgs",
		func(ctx SpecContext, lookupErr error, problem string) {
			cf.FindOrgCalls(func(_ context.Context, name string) (string, error) { return name + "-guid", nil })
			cf.ListSpacesCalls(func(_ context.Context, org string) ([]sync.Space, error) {
				return []sync.Space{{Name: "dev", GUID: org + "-dev"}}, nil
			})
			policy, err := sync.ParsePolicy(strings.NewReader(`orgs:
  - name: payments
    allow: [{hostname: payments.example.org, protocol: tcp, ports: [443]}]
  - name: reporting
    allow: [{hostname: reports.example.org, protocol: tcp, ports: [443]}]
`))
			Expect(err).NotTo(HaveOccurred())
			resolver := &asgsyncfakes.FakeResolver{}
			resolver.LookupNetIPCalls(func(_ context.Context, _, host string) ([]netip.Addr, error) {
				if host == "payments.example.org." {
					return []netip.Addr{netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2")}, nil
				}
				return []netip.Addr{netip.MustParseAddr("192.0.2.3")}, nil
			})
			orgs, err := sync.Resolve(ctx, policy, resolver, sync.DNSOptions{})
			Expect(err).NotTo(HaveOccurred())
			Expect(sync.Reconcile(ctx, cf, orgs[:1], false, io.Discard)).To(Succeed())

			resolver.LookupNetIPCalls(func(_ context.Context, _, host string) ([]netip.Addr, error) {
				if host == "payments.example.org." {
					return nil, lookupErr
				}
				return []netip.Addr{netip.MustParseAddr("192.0.2.3")}, nil
			})
			orgs, err = sync.Resolve(ctx, policy, resolver, sync.DNSOptions{})
			Expect(err).NotTo(HaveOccurred())
			Expect(sync.Reconcile(ctx, cf, orgs, false, io.Discard)).To(MatchError(And(
				ContainSubstring("payments.example.org"), ContainSubstring(problem),
				ContainSubstring("2 previously applied IPs"), ContainSubstring("192.0.2.1,192.0.2.2"),
			)))
			Expect(existing).To(HaveLen(2))
			Expect(existing[0].Running).To(Equal([]string{"payments-guid-dev"}))
			Expect(existing[1].Running).To(Equal([]string{"reporting-guid-dev"}))
			Expect(cf.UnbindRunningCallCount()).To(BeZero())
			Expect(cf.DeleteGroupCallCount()).To(BeZero())
			Expect(cf.UpdateGroupDescriptionsCallCount()).To(BeZero())
		},
		Entry("empty answer", nil, "no usable addresses"),
		Entry("timeout", &net.DNSError{Err: "i/o timeout", IsTimeout: true}, "timeout"),
		Entry("SERVFAIL", &net.DNSError{Err: "server misbehaving", IsTemporary: true}, "server misbehaving"),
		Entry("NXDOMAIN", &net.DNSError{Err: "no such host", IsNotFound: true}, "no such host"),
	)
})
