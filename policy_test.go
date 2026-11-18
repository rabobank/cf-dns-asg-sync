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
	)
})
