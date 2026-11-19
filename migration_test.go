package asgsync_test

import (
	"context"
	"errors"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	sync "github.com/rkoster/cf-dns-asg-sync"
	"github.com/rkoster/cf-dns-asg-sync/asgsyncfakes"
)

var _ = Describe("Global ASG migration", func() {
	DescribeTable("blocks writes and prints a usable defaults policy",
		func(ctx SpecContext, dryRun bool) {
			cf := &asgsyncfakes.FakeFoundation{}
			resolver := &asgsyncfakes.FakeResolver{}
			public := sync.Rule{Destination: "0.0.0.0-9.255.255.255", Protocol: "all"}
			dns := sync.Rule{Destination: "10.0.0.53", Protocol: "udp", Port: 53}
			staging := sync.Rule{Destination: "10.0.2.0/24", Protocol: "tcp", Port: 8000, PortEnd: 8100, Log: true}
			cf.ListGroupsReturns([]sync.SecurityGroup{
				{GUID: "public", Name: "public_networks", GlobalRunning: true, Rules: []sync.Rule{public, dns}},
				{GUID: "builder", Name: "builder", GlobalStaging: true, Rules: []sync.Rule{staging, dns}, Descriptions: sync.RuleDescriptions{staging: "Build API"}},
				{Name: "local", Rules: []sync.Rule{{Destination: "10.1.0.0/16", Protocol: "all"}}},
			}, nil)
			policy, err := sync.ParsePolicy(strings.NewReader(`defaults: [{destination: 192.0.2.1, protocol: all}]
orgs: [{name: payments, allow: [{hostname: payments.example.org, protocol: tcp, ports: [443]}]}]`))
			Expect(err).NotTo(HaveOccurred())
			var out strings.Builder
			Expect(sync.Sync(ctx, cf, policy, resolver, sync.DNSOptions{}, dryRun, &out)).To(MatchError(ContainSubstring("global ASGs")))
			Expect(cf.ListGroupsCallCount()).To(Equal(1))
			Expect(cf.ListOrgNamesCallCount()).To(BeZero())
			Expect(cf.CreateGroupCallCount()).To(BeZero())
			Expect(cf.BindRunningCallCount()).To(BeZero())
			Expect(cf.BindStagingCallCount()).To(BeZero())
			Expect(cf.DeleteGroupCallCount()).To(BeZero())
			Expect(cf.DisableGlobalGroupCallCount()).To(BeZero())
			Expect(resolver.LookupNetIPCallCount()).To(BeZero())
			Expect(out.String()).To(ContainSubstring("public_networks"))
			Expect(out.String()).To(ContainSubstring("Build API"))
			migrated, err := sync.ParsePolicy(strings.NewReader(out.String()))
			Expect(err).NotTo(HaveOccurred())
			migrated.Orgs = []sync.Org{{Name: "inherited"}}
			orgs, err := sync.Resolve(ctx, migrated, resolver, sync.DNSOptions{})
			Expect(err).NotTo(HaveOccurred())
			Expect(orgs[0].Baseline).To(ConsistOf(public, dns))
			Expect(orgs[0].StagingBaseline).To(ConsistOf(staging, dns))
		},
		Entry("on apply", false),
		Entry("on dry-run", true),
	)

	It("reports unsupported global rules without printing a partial defaults policy", func(ctx SpecContext) {
		cf := &asgsyncfakes.FakeFoundation{}
		cf.ListGroupsReturns([]sync.SecurityGroup{{Name: "unsupported", GlobalStaging: true, Unsupported: true}}, nil)
		var out strings.Builder
		Expect(sync.Reconcile(ctx, cf, nil, false, &out)).To(MatchError(ContainSubstring("unsupported")))
		Expect(out.String()).To(ContainSubstring("unsupported"))
		Expect(out.String()).NotTo(ContainSubstring("defaults:\n"))
	})

	DescribeTable("only disables global bindings after a successful replacement apply",
		func(ctx SpecContext, dryRun bool, bindErr error, drift bool, wantDisable bool) {
			cf := &asgsyncfakes.FakeFoundation{}
			global := sync.SecurityGroup{GUID: "public-guid", Name: "public_networks", GlobalRunning: true, GlobalStaging: true, Rules: []sync.Rule{{Destination: "192.0.2.0/24", Protocol: "all"}}}
			cf.ListGroupsReturns([]sync.SecurityGroup{global}, nil)
			if drift {
				changed := global
				changed.GlobalStaging = false
				cf.ListGroupsReturnsOnCall(1, []sync.SecurityGroup{changed}, nil)
			}
			cf.ListOrgNamesReturns([]string{"discovered"}, nil)
			cf.FindOrgReturns("discovered-guid", nil)
			cf.ListSpacesReturns([]sync.Space{{Name: "test", GUID: "space-guid"}}, nil)
			cf.CreateGroupReturns("replacement", nil)
			cf.BindStagingReturns(bindErr)
			cf.DisableGlobalGroupCalls(func(_ context.Context, id string, running, staging bool) error {
				Expect(id).To(Equal(global.GUID))
				Expect(running && staging).To(BeTrue())
				Expect(cf.BindRunningCallCount()).To(Equal(1))
				Expect(cf.BindStagingCallCount()).To(Equal(1))
				return nil
			})
			policy, err := sync.ParsePolicy(strings.NewReader(`defaults: [{destination: 192.0.2.0/24, protocol: all}]`))
			Expect(err).NotTo(HaveOccurred())
			var out strings.Builder
			err = sync.Sync(ctx, cf, policy, &asgsyncfakes.FakeResolver{}, sync.DNSOptions{}, dryRun, &out)
			switch {
			case bindErr != nil:
				Expect(err).To(MatchError(ContainSubstring(bindErr.Error())))
			case drift:
				Expect(err).To(MatchError(ContainSubstring("changed during migration")))
			default:
				Expect(err).NotTo(HaveOccurred())
				Expect(out.String()).To(ContainSubstring(`disable global ASG bindings for "public_networks"`))
			}
			if wantDisable {
				Expect(cf.DisableGlobalGroupCallCount()).To(Equal(1))
			} else {
				Expect(cf.DisableGlobalGroupCallCount()).To(BeZero())
			}
			Expect(cf.DeleteGroupCallCount()).To(BeZero())
			if dryRun {
				Expect(cf.CreateGroupCallCount()).To(BeZero())
			}
		},
		Entry("successful apply", false, nil, false, true),
		Entry("dry run", true, nil, false, false),
		Entry("staging bind failed", false, errors.New("bind failed"), false, false),
		Entry("global rules changed mid-run", false, nil, true, false),
	)

	It("does not disable global bindings when an explicit org has a DNS failure", func(ctx SpecContext) {
		cf := &asgsyncfakes.FakeFoundation{}
		cf.ListGroupsReturns([]sync.SecurityGroup{{GUID: "global", Name: "dns", GlobalRunning: true, Rules: []sync.Rule{{Destination: "192.0.2.53", Protocol: "udp", Port: 53}}}}, nil)
		cf.FindOrgReturns("payments-guid", nil)
		policy, err := sync.ParsePolicy(strings.NewReader(`defaults: [{destination: 192.0.2.53, protocol: udp, ports: "53", lifecycles: [running]}]
orgs: [{name: payments, allow: [{hostname: missing.example.org, protocol: tcp, ports: [443]}]}]`))
		Expect(err).NotTo(HaveOccurred())
		var out strings.Builder
		Expect(sync.Sync(ctx, cf, policy, &asgsyncfakes.FakeResolver{}, sync.DNSOptions{}, false, &out)).To(MatchError(ContainSubstring("DNS lookup")))
		Expect(cf.DisableGlobalGroupCallCount()).To(BeZero())
	})
})
