# cf-dns-asg-sync

Sync Cloud Foundry egress rules from DNS allowlists, one org at a time.

## Use it

Build with Go 1.26 or later: `go build ./cmd/cf-dns-asg-sync`. See
[`examples/policy.yml`](examples/policy.yml) for the policy format. Org and space
names match Cloud Foundry exactly. An org with no `spaces` list applies its rules
to all spaces in that org. Each named space gets any extra rules in addition to
the org's rules. `allow: []` with no space entries removes the org's managed rules;
omitting the org from the file leaves it alone.

Set `CF_API` to the foundation's HTTPS API root. Set `CF_USERNAME` and
`CF_PASSWORD` to a user and password, or to a UAA client ID and secret when using
`--client-credentials`. These credential names match `cf auth`. The UAA client
must be allowed the `client_credentials` grant and have `cloud_controller.admin`
authority. The utility uses `go-cfclient/v3` to discover UAA and call CAPI.

Preview with `./cf-dns-asg-sync --config policy.yml --client-credentials --dry-run`.
Run without `--dry-run` to apply the plan. Use `--ipv6` only on a foundation with
IPv6 ASG support. Use `--allow-private-cidr` (repeatable) for intended private
destinations. Loopback and link-local addresses are never permitted.

## Reconciliation

- The utility computes the **minimum** number of managed ASGs for each org's
  current spaces. A missing configured space or exhausted solver budget aborts
  before writing.
- A DNS error or empty answer leaves the affected org's existing ASGs and space
  bindings intact. Healthy orgs can still sync, and the command exits nonzero so
  Concourse reports the failure. A first-run failure adds no grants.
- Each managed rule's `description` stores the sorted, comma-separated names
  that produced its grant (destination IP, protocol, and port). Names sharing a
  grant are deduplicated; descriptions do not affect ASG minimization. On a DNS
  failure, the utility reports any previously applied IPs it can find in the
  org's currently bound managed ASGs. This records the applied rules, not a
  time series of DNS answers. Older ASGs get descriptions on a successful sync.
- Managed ASGs have content-addressed names under the reserved
  `cf-dns-asg-sync-` prefix. Do not edit or bind these groups manually. An ASG that
  is global or bound outside its owning org blocks reconciliation. Other groups
  and unlisted orgs are untouched. Bindings are for the running lifecycle.
- The sync adds replacement coverage before revoking old coverage. Changes are
  not atomic: a failed run can leave old grants until a later run completes.
- New spaces inherit the org policy on the next successful run. Already-running
  containers need Dynamic ASGs or a restart for changes to take effect.
- ASGs allow IPs and ports, not hostnames. DNS rotation, split-horizon answers,
  and shared IPs can change effective access. Other ASGs are additive.

## Concourse

Use [`ci/pipeline.yml`](ci/pipeline.yml) with `source_uri`, `source_branch`,
`policy_uri`, `policy_branch`, `sync_interval` (for example `5m`), and `dry_run`
(`"true"` initially). Put `policy.yml` at the root of the policy repo. Supply
`cf-api`, `cf-client-id`, and `cf-client-secret` through the credential manager.
Select workers whose task containers see the same DNS view as apps and can
reach CAPI and UAA. Run one writer per foundation and org. The example task uses
IPv4 and public destinations; add flags in `ci/sync.yml` for private or IPv6 use.

## Develop

Run `go generate ./...` after changing an interface with a Counterfeiter fake.
Run tests with `go run github.com/onsi/ginkgo/v2/ginkgo -r` or `devbox run test`.

Licensed under [Apache 2.0](LICENSE).
