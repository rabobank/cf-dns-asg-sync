package asgsync_test

import (
	"context"
	"fmt"
	"io"
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
		cf.CreateGroupCalls(func(_ context.Context, name string, rules []sync.Rule) (string, error) {
			id := fmt.Sprintf("group-%d", len(existing)+1)
			existing = append(existing, sync.SecurityGroup{GUID: id, Name: name, Rules: append([]sync.Rule(nil), rules...)})
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
})
