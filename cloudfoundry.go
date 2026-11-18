package asgsync

import (
	"context"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/cloudfoundry/go-cfclient/v3/client"
	"github.com/cloudfoundry/go-cfclient/v3/config"
	"github.com/cloudfoundry/go-cfclient/v3/resource"
)

type cloudFoundry struct{ client *client.Client }

func NewCloudFoundry(getenv func(string) string, clientCredentials bool) (Foundation, error) {
	return newCloudFoundry(getenv, clientCredentials, nil)
}

func newCloudFoundry(getenv func(string) string, clientCredentials bool, httpClient *http.Client) (Foundation, error) {
	api := getenv("CF_API")
	username, password := getenv("CF_USERNAME"), getenv("CF_PASSWORD")
	for _, v := range []struct{ key, value string }{{"CF_API", api}, {"CF_USERNAME", username}, {"CF_PASSWORD", password}} {
		if strings.TrimSpace(v.value) == "" {
			return nil, fmt.Errorf("%s is required", v.key)
		}
	}
	u, err := url.Parse(api)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return nil, fmt.Errorf("CF_API must be an HTTPS foundation API root URL")
	}
	auth := config.UserPassword(username, password)
	if clientCredentials {
		auth = config.ClientCredentials(username, password)
	}
	opts := []config.Option{auth, config.UserAgent("cf-dns-asg-sync")}
	if httpClient != nil {
		opts = append(opts, config.HttpClient(httpClient))
	}
	cfg, err := config.New(api, opts...)
	if err != nil {
		return nil, fmt.Errorf("configure CF API authentication: %w", err)
	}
	c, err := client.New(cfg)
	if err != nil {
		return nil, fmt.Errorf("initialize CF API client: %w", err)
	}
	return &cloudFoundry{c}, nil
}

func (c *cloudFoundry) FindOrg(ctx context.Context, name string) (string, error) {
	opts := client.NewOrganizationListOptions()
	opts.Names.EqualTo(name)
	orgs, err := c.client.Organizations.ListAll(ctx, opts)
	if err != nil {
		return "", fmt.Errorf("find org: %w", err)
	}
	var guid string
	for _, o := range orgs {
		if o != nil && o.Name == name {
			if guid != "" || o.GUID == "" {
				return "", fmt.Errorf("invalid or ambiguous org %q", name)
			}
			guid = o.GUID
		}
	}
	if guid == "" {
		return "", fmt.Errorf("unknown org %q", name)
	}
	return guid, nil
}

func (c *cloudFoundry) ListSpaces(ctx context.Context, org string) ([]Space, error) {
	opts := client.NewSpaceListOptions()
	opts.OrganizationGUIDs.EqualTo(org)
	spaces, err := c.client.Spaces.ListAll(ctx, opts)
	if err != nil {
		return nil, err
	}
	var result []Space
	for _, s := range spaces {
		if s == nil || s.Relationships == nil || s.Relationships.Organization == nil || s.Relationships.Organization.Data == nil || s.Relationships.Organization.Data.GUID != org {
			return nil, fmt.Errorf("CAPI returned a space outside org %s", org)
		}
		result = append(result, Space{Name: s.Name, GUID: s.GUID})
	}
	return result, nil
}

func (c *cloudFoundry) ListGroups(ctx context.Context) ([]SecurityGroup, error) {
	groups, err := c.client.SecurityGroups.ListAll(ctx, nil)
	if err != nil {
		return nil, err
	}
	var result []SecurityGroup
	for _, g := range groups {
		if g == nil || !strings.HasPrefix(g.Name, namePrefix) {
			continue
		}
		running, staging := g.GloballyEnabled.Running, g.GloballyEnabled.Staging
		group := SecurityGroup{GUID: g.GUID, Name: g.Name, Global: running != nil && *running || staging != nil && *staging}
		group.Unsupported = running == nil || staging == nil || g.Relationships.RunningSpaces.Data == nil || g.Relationships.StagingSpaces.Data == nil
		for _, s := range g.Relationships.RunningSpaces.Data {
			group.Running = append(group.Running, s.GUID)
		}
		for _, s := range g.Relationships.StagingSpaces.Data {
			group.Staging = append(group.Staging, s.GUID)
		}
		for _, r := range g.Rules {
			ip, err := netip.ParseAddr(r.Destination)
			if err != nil || ip.Zone() != "" || (r.Protocol != "tcp" && r.Protocol != "udp") || r.Ports == nil || r.Log != nil && *r.Log || r.Code != nil || r.Type != nil {
				group.Unsupported = true
				continue
			}
			for _, p := range strings.Split(*r.Ports, ",") {
				port, err := strconv.ParseUint(p, 10, 16)
				if err != nil || port == 0 {
					group.Unsupported = true
					continue
				}
				group.Rules = append(group.Rules, Rule{ip.Unmap().String(), r.Protocol, uint16(port)})
			}
		}
		result = append(result, group)
	}
	return result, nil
}

func (c *cloudFoundry) CreateGroup(ctx context.Context, name string, rules []Rule) (string, error) {
	no := false
	request := &resource.SecurityGroupCreate{Name: name, GloballyEnabled: &resource.SecurityGroupGloballyEnabled{Running: &no, Staging: &no}}
	// Consolidate ports for a destination and protocol, while keeping the
	// planner's unit of comparison a single grant.
	for _, r := range normalize(append([]Rule(nil), rules...)) {
		p := strconv.Itoa(int(r.Port))
		if n := len(request.Rules); n > 0 {
			last := request.Rules[n-1]
			if last.Destination == r.Destination && last.Protocol == r.Protocol {
				*last.Ports += "," + p
				continue
			}
		}
		request.Rules = append(request.Rules, &resource.SecurityGroupRule{Destination: r.Destination, Protocol: r.Protocol, Ports: &p})
	}
	g, err := c.client.SecurityGroups.Create(ctx, request)
	if err != nil {
		return "", err
	}
	return g.GUID, nil
}

func (c *cloudFoundry) BindRunning(ctx context.Context, group string, spaces []string) error {
	_, err := c.client.SecurityGroups.BindRunningSecurityGroup(ctx, group, spaces)
	return err
}

func (c *cloudFoundry) UnbindRunning(ctx context.Context, group, space string) error {
	return c.client.SecurityGroups.UnBindRunningSecurityGroup(ctx, group, space)
}

func (c *cloudFoundry) DeleteGroup(ctx context.Context, group string) error {
	job, err := c.client.SecurityGroups.Delete(ctx, group)
	if err != nil || job == "" {
		return err
	}
	pollCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	return c.client.Jobs.PollComplete(pollCtx, job, client.NewPollingOptions())
}
