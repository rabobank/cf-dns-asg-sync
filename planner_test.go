package asgsync_test

import (
	sync "github.com/rkoster/cf-dns-asg-sync"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("ASG minimization", func() {
	It("covers exactly the requested grants using fewer groups than distinct space policies", func(ctx SpecContext) {
		base := sync.Rule{Destination: "192.0.2.1", Protocol: "tcp", Port: 443}
		a := sync.Rule{Destination: "192.0.2.2", Protocol: "tcp", Port: 443}
		b := sync.Rule{Destination: "192.0.2.3", Protocol: "tcp", Port: 443}
		policies := map[string][]sync.Rule{"dev": {base, a}, "qa": {base, b}, "prod": {base, a, b}}
		plan, err := sync.Minimize(ctx, policies, nil)
		Expect(err).NotTo(HaveOccurred())
		Expect(plan).To(HaveLen(2))
		for space, expected := range policies {
			actual := map[sync.Rule]bool{}
			for _, group := range plan {
				for _, bound := range group.Spaces {
					if bound == space {
						for _, rule := range group.Rules {
							actual[rule] = true
						}
					}
				}
			}
			Expect(actual).To(HaveLen(len(expected)), "space %s must have no extra grants", space)
			for _, rule := range expected {
				Expect(actual).To(HaveKey(rule))
			}
		}
	})
})
