package asgsync

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"slices"
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

func (c *cloudFoundry) ListOrgNames(ctx context.Context) ([]string, error) {
	orgs, err := c.client.Organizations.ListAll(ctx, nil)
	if err != nil {
		return nil, err
	}
	var names []string
	for _, org := range orgs {
		if org == nil || org.Name == "" {
			return nil, fmt.Errorf("invalid org returned by CAPI")
		}
		names = append(names, org.Name)
	}
	return names, nil
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
		if g == nil {
			continue
		}
		running, staging := g.GloballyEnabled.Running, g.GloballyEnabled.Staging
		group := SecurityGroup{GUID: g.GUID, Name: g.Name, GlobalRunning: running != nil && *running, GlobalStaging: staging != nil && *staging}
		if !group.global() && !managedGroupName(g.Name) && g.Name != migrationCheckpointName {
			continue
		}
		group.Unsupported = running == nil || staging == nil || (!group.global() && (g.Relationships.RunningSpaces.Data == nil || g.Relationships.StagingSpaces.Data == nil))
		for _, s := range g.Relationships.RunningSpaces.Data {
			group.Running = append(group.Running, s.GUID)
		}
		for _, s := range g.Relationships.StagingSpaces.Data {
			group.Staging = append(group.Staging, s.GUID)
		}
		for _, r := range g.Rules {
			var ports PortSpec
			if r.Ports != nil {
				var err error
				ports, err = parsePorts(*r.Ports)
				if err != nil {
					group.Unsupported = true
					continue
				}
			}
			rules, err := destinationRules(r.Destination, r.Protocol, ports, r.Type, r.Code, r.Log != nil && *r.Log)
			if err != nil {
				group.Unsupported = true
				continue
			}
			for _, rule := range rules {
				group.Rules = append(group.Rules, rule)
				if r.Description != nil && *r.Description != "" {
					if group.Descriptions == nil {
						group.Descriptions = RuleDescriptions{}
					}
					group.Descriptions[rule] = mergeDescriptions(group.Descriptions[rule], *r.Description)
				}
			}
		}
		result = append(result, group)
	}
	return result, nil
}

func (c *cloudFoundry) CreateGroup(ctx context.Context, name string, rules []Rule, descriptions RuleDescriptions) (string, error) {
	no := false
	request := &resource.SecurityGroupCreate{Name: name, GloballyEnabled: &resource.SecurityGroupGloballyEnabled{Running: &no, Staging: &no}, Rules: securityGroupRules(rules, descriptions)}
	g, err := c.client.SecurityGroups.Create(ctx, request)
	if err != nil {
		return "", err
	}
	return g.GUID, nil
}

func (c *cloudFoundry) UpdateGroupDescriptions(ctx context.Context, id string, rules []Rule, descriptions RuleDescriptions) error {
	_, err := c.client.SecurityGroups.Update(ctx, id, &resource.SecurityGroupUpdate{Rules: securityGroupRules(rules, descriptions)})
	return err
}

func (c *cloudFoundry) DisableGlobalGroup(ctx context.Context, id string, running, staging bool) error {
	flags := &resource.SecurityGroupGloballyEnabled{}
	if running {
		flags.Running = new(false)
	}
	if staging {
		flags.Staging = new(false)
	}
	_, err := c.client.SecurityGroups.Update(ctx, id, &resource.SecurityGroupUpdate{GloballyEnabled: flags})
	return err
}

func securityGroupRules(rules []Rule, descriptions RuleDescriptions) []*resource.SecurityGroupRule {
	type key struct {
		rule        Rule
		description string
	}
	byKey := map[key]*resource.SecurityGroupRule{}
	var result []*resource.SecurityGroupRule
	for _, r := range normalize(slices.Clone(rules)) {
		p := r.portString()
		d := descriptions[r]
		k := key{r, d}
		if r.PortEnd == 0 {
			k.rule.Port = 0
		}
		if current := byKey[k]; current != nil && p != "" && r.PortEnd == 0 {
			*current.Ports += "," + p
			continue
		}
		entry := &resource.SecurityGroupRule{Destination: r.Destination, Protocol: r.Protocol}
		if p != "" {
			entry.Ports = &p
		}
		if r.Log {
			entry.Log = new(true)
		}
		if r.Protocol == "icmp" || r.Protocol == "icmpv6" {
			entry.Type = &r.Type
			entry.Code = &r.Code
		}
		if d != "" {
			entry.Description = &d
		}
		byKey[k] = entry
		result = append(result, entry)
	}
	return result
}

func (c *cloudFoundry) BindRunning(ctx context.Context, group string, spaces []string) error {
	_, err := c.client.SecurityGroups.BindRunningSecurityGroup(ctx, group, spaces)
	return err
}

func (c *cloudFoundry) UnbindRunning(ctx context.Context, group, space string) error {
	return c.client.SecurityGroups.UnBindRunningSecurityGroup(ctx, group, space)
}

func (c *cloudFoundry) BindStaging(ctx context.Context, group string, spaces []string) error {
	_, err := c.client.SecurityGroups.BindStagingSecurityGroup(ctx, group, spaces)
	return err
}

func (c *cloudFoundry) UnbindStaging(ctx context.Context, group, space string) error {
	return c.client.SecurityGroups.UnBindStagingSecurityGroup(ctx, group, space)
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
