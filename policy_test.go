package asgsync_test

import (
	"context"
	"net/netip"
	"strings"

	sync "github.com/rkoster/cf-dns-asg-sync"
	"github.com/rkoster/cf-dns-asg-sync/asgsyncfakes"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

const policyYAML = `orgs:
  - name: payments
    allow:
      - {hostname: API.example.org, protocol: tcp, ports: [443, 8443]}
    spaces:
      - name: dev
        allow:
          - {hostname: api.example.org., protocol: tcp, ports: [8443]}
          - {hostname: dev.example.org, protocol: tcp, ports: [443]}
`

var _ = Describe("DNS policy", func() {
	It("resolves native grants from current fields without relying on YAML parsing", func(ctx SpecContext) {
		policy := sync.Policy{Orgs: []sync.Org{{Name: "payments", Allow: []sync.Grant{{Destination: "192.0.2.1", Protocol: "all"}}}}}
		orgs, err := sync.Resolve(ctx, policy, nil, sync.DNSOptions{})
		Expect(err).NotTo(HaveOccurred())
		Expect(orgs[0].Baseline).To(Equal([]sync.Rule{{Destination: "192.0.2.1", Protocol: "all"}}))
		Expect(orgs[0].StagingBaseline).To(Equal(orgs[0].Baseline))
		Expect(policy.Orgs[0].Allow[0].Lifecycles).To(BeNil())
	})

	It("revalidates edited native grants", func(ctx SpecContext) {
		policy, err := sync.ParsePolicy(strings.NewReader(`orgs: [{name: payments, allow: [{destination: 192.0.2.1, protocol: all}]}]`))
		Expect(err).NotTo(HaveOccurred())
		policy.Orgs[0].Allow[0].Destination = "192.0.2.2"
		orgs, err := sync.Resolve(ctx, policy, nil, sync.DNSOptions{})
		Expect(err).NotTo(HaveOccurred())
		Expect(orgs[0].Baseline).To(Equal([]sync.Rule{{Destination: "192.0.2.2", Protocol: "all"}}))
		policy.Orgs[0].Allow[0].Destination = "invalid"
		_, err = sync.Resolve(ctx, policy, nil, sync.DNSOptions{})
		Expect(err).To(MatchError(ContainSubstring("invalid ASG destination")))
	})
	var resolver *asgsyncfakes.FakeResolver
	BeforeEach(func() { resolver = &asgsyncfakes.FakeResolver{} })

	It("resolves each FQDN once and adds space grants without duplicating baseline grants", func(ctx SpecContext) {
		policy, err := sync.ParsePolicy(strings.NewReader(policyYAML))
		Expect(err).NotTo(HaveOccurred())
		resolver.LookupNetIPCalls(func(_ context.Context, _, host string) ([]netip.Addr, error) {
			if host == "api.example.org." {
				return []netip.Addr{netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2")}, nil
			}
			return []netip.Addr{netip.MustParseAddr("192.0.2.3")}, nil
		})
		orgs, err := sync.Resolve(ctx, policy, resolver, sync.DNSOptions{})
		Expect(err).NotTo(HaveOccurred())
		Expect(resolver.LookupNetIPCallCount()).To(Equal(2))
		Expect(orgs[0].RulesFor("prod")).To(HaveLen(4))
		Expect(orgs[0].RulesFor("dev")).To(HaveLen(5))
	})

	It("rejects private DNS answers unless explicitly allowed", func(ctx SpecContext) {
		policy, err := sync.ParsePolicy(strings.NewReader(policyYAML))
		Expect(err).NotTo(HaveOccurred())
		resolver.LookupNetIPReturns([]netip.Addr{netip.MustParseAddr("10.0.0.1")}, nil)
		_, err = sync.Resolve(ctx, policy, resolver, sync.DNSOptions{})
		Expect(err).To(MatchError(ContainSubstring("10.0.0.1")))
		_, err = sync.Resolve(ctx, policy, resolver, sync.DNSOptions{PrivateCIDRs: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24")}})
		Expect(err).NotTo(HaveOccurred())
	})

	It("records both hostnames for a shared grant and caches shared failures across orgs", func(ctx SpecContext) {
		policy, err := sync.ParsePolicy(strings.NewReader(`orgs:
  - name: payments
    allow:
      - {hostname: z.example.org, protocol: tcp, ports: [443]}
      - {hostname: a.example.org, protocol: tcp, ports: [443, 8443]}
  - name: reporting
    allow: [{hostname: a.example.org, protocol: tcp, ports: [8443]}]
`))
		Expect(err).NotTo(HaveOccurred())
		resolver.LookupNetIPReturns([]netip.Addr{netip.MustParseAddr("192.0.2.1")}, nil)
		orgs, err := sync.Resolve(ctx, policy, resolver, sync.DNSOptions{})
		Expect(err).NotTo(HaveOccurred())
		Expect(orgs[0].Baseline).To(HaveLen(2))
		Expect(orgs[0].Descriptions).To(Equal(sync.RuleDescriptions{
			{Destination: "192.0.2.1", Protocol: "tcp", Port: 443}:  "a.example.org,z.example.org",
			{Destination: "192.0.2.1", Protocol: "tcp", Port: 8443}: "a.example.org",
		}))
		resolver.LookupNetIPReturns(nil, nil)
		orgs, err = sync.Resolve(ctx, policy, resolver, sync.DNSOptions{})
		Expect(err).NotTo(HaveOccurred())
		Expect(resolver.LookupNetIPCallCount()).To(Equal(4))
		for _, org := range orgs {
			Expect(org.DNSFailures).To(HaveKey("a.example.org."))
			Expect(org.Baseline).To(BeEmpty())
		}
	})

	DescribeTable("rejects invalid YAML before resolving names",
		func(yaml string) {
			_, err := sync.ParsePolicy(strings.NewReader(yaml))
			Expect(err).To(HaveOccurred())
		},
		Entry("duplicate org", "orgs: [{name: payments}, {name: payments}]"),
		Entry("duplicate space", "orgs: [{name: payments, spaces: [{name: dev}, {name: dev}]}]"),
		Entry("unknown field", "orgs: [{name: payments, alow: []}]"),
		Entry("multiple documents", "orgs: [{name: payments}]\n---\norgs: [{name: reporting}]"),
		Entry("invalid hostname and port", "orgs: [{name: payments, allow: [{hostname: '*.example.org', protocol: tcp, ports: [0]}]}]"),
		Entry("hostname and destination", "orgs: [{name: payments, allow: [{hostname: a.example.org, destination: 192.0.2.1, protocol: tcp, ports: [443]}]}]"),
		Entry("reversed range", "orgs: [{name: payments, allow: [{destination: 192.0.2.10-192.0.2.1, protocol: all}]}]"),
		Entry("ports on all", "orgs: [{name: payments, allow: [{destination: 192.0.2.0/24, protocol: all, ports: '443'}]}]"),
		Entry("missing ICMP code", "orgs: [{name: payments, allow: [{destination: 192.0.2.1, protocol: icmp, type: 0}]}]"),
		Entry("negative port", "orgs: [{name: payments, allow: [{destination: 192.0.2.1, protocol: tcp, ports: '-1'}]}]"),
		Entry("empty lifecycles", "defaults: [{destination: 192.0.2.1, protocol: all, lifecycles: []}]"),
		Entry("unknown lifecycle", "defaults: [{destination: 192.0.2.1, protocol: all, lifecycles: [build]}]"),
	)

	It("resolves native Cloud Foundry rules without a DNS lookup", func(ctx SpecContext) {
		policy, err := sync.ParsePolicy(strings.NewReader(`orgs:
  - name: payments
    allow:
      - {destination: 0.0.0.0-9.255.255.255, protocol: all}
      - {destination: '10.0.0.0/24,10.0.1.1', protocol: udp, ports: '53'}
      - {destination: 192.0.2.1, protocol: tcp, ports: '8000-8100', log: true, description: lab}
      - {destination: 192.0.2.1, protocol: icmp, type: 0, code: -1}
`))
		Expect(err).NotTo(HaveOccurred())
		orgs, err := sync.Resolve(ctx, policy, resolver, sync.DNSOptions{})
		Expect(err).NotTo(HaveOccurred())
		Expect(resolver.LookupNetIPCallCount()).To(BeZero())
		Expect(orgs[0].Baseline).To(HaveLen(5))
		Expect(orgs[0].Descriptions).To(HaveLen(1))
	})
})
