package asgsync_test

import (
	"context"
	"errors"
	"slices"
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
			if wantDisable {
				Expect(cf.DeleteGroupCallCount()).To(Equal(1))
			} else {
				Expect(cf.DeleteGroupCallCount()).To(BeZero())
			}
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

	It("retries a partial cutover using the full original defaults", func(ctx SpecContext) {
		cf := &asgsyncfakes.FakeFoundation{}
		first := sync.Rule{Destination: "192.0.2.0/24", Protocol: "all"}
		second := sync.Rule{Destination: "198.51.100.0/24", Protocol: "all"}
		groups := []sync.SecurityGroup{
			{GUID: "first", Name: "first", GlobalRunning: true, Rules: []sync.Rule{first}},
			{GUID: "second", Name: "second", GlobalStaging: true, Rules: []sync.Rule{second}},
		}
		cf.ListGroupsCalls(func(context.Context) ([]sync.SecurityGroup, error) { return groups, nil })
		cf.CreateGroupCalls(func(_ context.Context, name string, rules []sync.Rule, descriptions sync.RuleDescriptions) (string, error) {
			groups = append(groups, sync.SecurityGroup{GUID: name, Name: name, Rules: rules, Descriptions: descriptions})
			return name, nil
		})
		cf.BindRunningCalls(func(_ context.Context, id string, spaces []string) error {
			for i := range groups {
				if groups[i].GUID == id {
					groups[i].Running = spaces
				}
			}
			return nil
		})
		cf.BindStagingCalls(func(_ context.Context, id string, spaces []string) error {
			for i := range groups {
				if groups[i].GUID == id {
					groups[i].Staging = spaces
				}
			}
			return nil
		})
		fail := true
		cf.DeleteGroupCalls(func(_ context.Context, id string) error {
			Expect(groups[0].GlobalRunning || groups[1].GlobalStaging).To(BeFalse())
			groups = slices.DeleteFunc(groups, func(g sync.SecurityGroup) bool { return g.GUID == id })
			return nil
		})
		cf.DisableGlobalGroupCalls(func(_ context.Context, id string, _, _ bool) error {
			if id == "second" && fail {
				return errors.New("temporary failure")
			}
			for i := range groups {
				if groups[i].GUID == id {
					groups[i].GlobalRunning, groups[i].GlobalStaging = false, false
				}
			}
			return nil
		})
		cf.ListOrgNamesReturns([]string{"inherited"}, nil)
		cf.FindOrgReturns("org-guid", nil)
		cf.ListSpacesReturns([]sync.Space{{Name: "app", GUID: "space-guid"}}, nil)
		policy, err := sync.ParsePolicy(strings.NewReader(`defaults:
  - {destination: 192.0.2.0/24, protocol: all, lifecycles: [running]}
  - {destination: 198.51.100.0/24, protocol: all, lifecycles: [staging]}
`))
		Expect(err).NotTo(HaveOccurred())
		resolver := &asgsyncfakes.FakeResolver{}
		var out strings.Builder
		Expect(sync.Sync(ctx, cf, policy, resolver, sync.DNSOptions{}, false, &out)).To(MatchError(ContainSubstring("temporary failure")))
		Expect(groups[0].GlobalRunning).To(BeFalse())
		Expect(groups[1].GlobalStaging).To(BeTrue())
		Expect(cf.DeleteGroupCallCount()).To(BeZero())
		reduced, err := sync.ParsePolicy(strings.NewReader(`defaults: [{destination: 198.51.100.0/24, protocol: all, lifecycles: [staging]}]`))
		Expect(err).NotTo(HaveOccurred())
		out.Reset()
		Expect(sync.Sync(ctx, cf, reduced, resolver, sync.DNSOptions{}, false, &out)).NotTo(Succeed())
		Expect(out.String()).To(ContainSubstring(first.Destination))
		fail = false
		Expect(sync.Sync(ctx, cf, policy, resolver, sync.DNSOptions{}, false, &out)).To(Succeed())
		Expect(groups[1].GlobalStaging).To(BeFalse())
		Expect(cf.UnbindRunningCallCount()).To(BeZero())
		Expect(cf.BindRunningCallCount()).To(Equal(1))
		Expect(cf.BindStagingCallCount()).To(Equal(1))
	})
})
