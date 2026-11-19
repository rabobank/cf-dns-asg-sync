package asgsync

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Cloud Foundry client", func() {
	It("encodes native ASG rules for CAPI without changing their grants", func() {
		policy, err := ParsePolicy(strings.NewReader(`orgs:
  - name: payments
    allow:
      - {destination: 0.0.0.0-9.255.255.255, protocol: all}
      - {destination: '10.0.0.0/24,10.0.1.1', protocol: udp, ports: '53'}
      - {destination: 192.0.2.1, protocol: tcp, ports: '8000-8100', log: true, description: lab}
      - {destination: 192.0.2.1, protocol: icmp, type: 0, code: -1}
`))
		Expect(err).NotTo(HaveOccurred())
		orgs, err := Resolve(context.Background(), policy, nil, DNSOptions{})
		Expect(err).NotTo(HaveOccurred())
		org := orgs[0]
		data, err := json.Marshal(securityGroupRules(org.Baseline, org.Descriptions))
		Expect(err).NotTo(HaveOccurred())
		Expect(data).To(MatchJSON(`[
  {"destination":"0.0.0.0-9.255.255.255","protocol":"all"},
  {"destination":"10.0.0.0/24","protocol":"udp","ports":"53"},
  {"destination":"10.0.1.1","protocol":"udp","ports":"53"},
  {"destination":"192.0.2.1","protocol":"icmp","type":0,"code":-1},
  {"destination":"192.0.2.1","protocol":"tcp","ports":"8000-8100","log":true,"description":"lab"}
]`))
	})
	DescribeTable("uses SDK discovery and obtains the selected OAuth grant",
		func(ctx SpecContext, useClientCredentials bool) {
			var tokenCalls atomic.Int32
			var server *httptest.Server
			server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				switch r.Method + " " + r.URL.Path {
				case "GET /":
					fmt.Fprintf(w, `{"links":{"login":{"href":%q},"uaa":{"href":%q}}}`, server.URL, server.URL)
				case "POST /oauth/token":
					tokenCalls.Add(1)
					user, pass, _ := r.BasicAuth()
					if useClientCredentials {
						if r.FormValue("grant_type") != "client_credentials" || user != "sync" || pass != "secret" {
							http.Error(w, "incorrect client credentials", 400)
							return
						}
					} else if r.FormValue("grant_type") != "password" || user != "cf" || r.FormValue("username") != "sync" || r.FormValue("password") != "secret" {
						http.Error(w, "incorrect user credentials", 400)
						return
					}
					fmt.Fprint(w, `{"access_token":"mock-token","token_type":"Bearer","expires_in":3600}`)
				case "GET /v3/organizations":
					if r.Header.Get("Authorization") != "Bearer mock-token" || r.URL.Query().Get("names") != "payments" {
						http.Error(w, "unexpected org request", 400)
						return
					}
					fmt.Fprint(w, `{"pagination":{"total_pages":1},"resources":[{"name":"payments","guid":"org-guid"}]}`)
				case "GET /v3/spaces":
					if r.URL.Query().Get("organization_guids") != "org-guid" {
						http.Error(w, "unexpected space request", 400)
						return
					}
					fmt.Fprint(w, `{"pagination":{"total_pages":1},"resources":[{"name":"dev","guid":"dev-guid","relationships":{"organization":{"data":{"guid":"org-guid"}}}}]}`)
				case "POST /v3/security_groups", "PATCH /v3/security_groups/group-guid":
					var payload struct {
						Rules []struct{ Destination, Protocol, Ports, Description string }
					}
					if err := json.NewDecoder(r.Body).Decode(&payload); err != nil || len(payload.Rules) != 2 || payload.Rules[0].Destination != "192.0.2.1" || payload.Rules[0].Ports != "443,9443" || payload.Rules[0].Protocol != "tcp" || payload.Rules[0].Description != "a.example.org,b.example.org" || payload.Rules[1].Ports != "8443" || payload.Rules[1].Description != "a.example.org" {
						http.Error(w, "unexpected ASG rules", 400)
						return
					}
					if r.Method == http.MethodPost {
						w.WriteHeader(http.StatusCreated)
					}
					fmt.Fprint(w, `{"guid":"group-guid"}`)
				case "GET /v3/security_groups":
					fmt.Fprint(w, `{"pagination":{"total_pages":1},"resources":[{"guid":"group-guid","name":"cf-dns-asg-sync-example","globally_enabled":{"running":false,"staging":false},"relationships":{"running_spaces":{"data":[{"guid":"dev-guid"}]},"staging_spaces":{"data":[]}},"rules":[{"destination":"192.0.2.1","ports":"443,9443","protocol":"tcp","description":"a.example.org,b.example.org"},{"destination":"192.0.2.1","ports":"8443","protocol":"tcp","description":"a.example.org"}]},{"guid":"global-guid","name":"public_networks","globally_enabled":{"running":false,"staging":true},"rules":[{"destination":"0.0.0.0-9.255.255.255","protocol":"all"}]}]}`)
				case "PATCH /v3/security_groups/global-guid":
					var body map[string]map[string]bool
					if err := json.NewDecoder(r.Body).Decode(&body); err != nil || len(body) != 1 || len(body["globally_enabled"]) != 1 {
						http.Error(w, "expected only the global flag update", 400)
						return
					}
					if value, ok := body["globally_enabled"]["staging"]; !ok || value {
						http.Error(w, "expected staging false", 400)
						return
					}
					fmt.Fprint(w, `{"guid":"global-guid"}`)
				default:
					http.NotFound(w, r)
				}
			}))
			DeferCleanup(server.Close)
			getenv := func(key string) string {
				return map[string]string{"CF_API": server.URL, "CF_USERNAME": "sync", "CF_PASSWORD": "secret"}[key]
			}
			cf, err := newCloudFoundry(getenv, useClientCredentials, server.Client())
			Expect(err).NotTo(HaveOccurred())
			org, err := cf.FindOrg(ctx, "payments")
			Expect(err).NotTo(HaveOccurred())
			Expect(org).To(Equal("org-guid"))
			spaces, err := cf.ListSpaces(ctx, org)
			Expect(err).NotTo(HaveOccurred())
			Expect(spaces).To(Equal([]Space{{Name: "dev", GUID: "dev-guid"}}))
			a, b, c := Rule{Destination: "192.0.2.1", Protocol: "tcp", Port: 443}, Rule{Destination: "192.0.2.1", Protocol: "tcp", Port: 8443}, Rule{Destination: "192.0.2.1", Protocol: "tcp", Port: 9443}
			rules := []Rule{a, b, c, a}
			descriptions := RuleDescriptions{a: "a.example.org,b.example.org", b: "a.example.org", c: "a.example.org,b.example.org"}
			id, err := cf.CreateGroup(ctx, "example", rules, descriptions)
			Expect(err).NotTo(HaveOccurred())
			Expect(id).To(Equal("group-guid"))
			Expect(cf.UpdateGroupDescriptions(ctx, id, rules, descriptions)).To(Succeed())
			groups, err := cf.ListGroups(ctx)
			Expect(err).NotTo(HaveOccurred())
			Expect(groups).To(HaveLen(2))
			Expect(groups[0].Unsupported).To(BeFalse())
			Expect(groups[0].Running).To(Equal([]string{"dev-guid"}))
			Expect(groups[0].Rules).To(ConsistOf(a, b, c))
			Expect(groups[0].Descriptions).To(Equal(descriptions))
			Expect(groups[1].Name).To(Equal("public_networks"))
			Expect(groups[1].Unsupported).To(BeFalse())
			Expect(groups[1].GlobalStaging).To(BeTrue())
			Expect(groups[1].GlobalRunning).To(BeFalse())
			Expect(groups[1].Rules).To(Equal([]Rule{{Destination: "0.0.0.0-9.255.255.255", Protocol: "all"}}))
			Expect(cf.DisableGlobalGroup(ctx, groups[1].GUID, false, true)).To(Succeed())
			Expect(tokenCalls.Load()).To(Equal(int32(1)))
		},
		Entry("password grant", false),
		Entry("client credentials grant", true),
	)
})
