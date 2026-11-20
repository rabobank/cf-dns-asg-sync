# cf-dns-asg-sync

Sync Cloud Foundry egress rules from DNS allowlists and share ASGs across managed spaces.

## Use it

Build with Go 1.26 or later: `go build ./cmd/cf-dns-asg-sync`. See
[`examples/policy.yml`](examples/policy.yml) for the policy format. Org and space
names match Cloud Foundry exactly. An org with no `spaces` list applies its rules
to all spaces in that org. Each named space gets any extra rules in addition to
the org's rules. **Omitting `lifecycles` applies a rule to both staging and
running.** Set `lifecycles: [running]` on existing rules that should remain
running-only when upgrading. Use `[staging]` for staging-only rules.

## Migrating global rules

[`examples/migration.yml`](examples/migration.yml) shows how to configure
`defaults`. When present, the utility discovers all orgs and applies the defaults
to unlisted orgs and to listed orgs that omit `allow`. An explicit org `allow`
replaces defaults for both lifecycles. `allow: []` opts out of the default
baseline; any space overrides still apply. Without `defaults`, unlisted orgs
are untouched.

Rules accept either `hostname` or `destination`. Native destinations support
IPs, CIDRs, ranges, and comma-separated lists (expanded into separate
destinations). TCP and UDP accept a port, a comma-separated port string, a port
range, or a YAML list of ports. Native rules also support `all`, `icmp`,
`icmpv6`, TCP logging, and descriptions. Explicit native destinations do not
require `--allow-private-cidr`; that guard applies to DNS answers.

If the foundation has global ASGs and `defaults` doesn't match their normalized
destination rules and lifecycle assignments, the utility exits nonzero and
prints a copyable `defaults:` block to stdout. Use that block for the cutover.
Add any global grants that explicit org `allow` lists still need, including
DNS and staging dependencies.

With matching defaults, dry-run previews the replacement and cutover. Apply
reconciles the replacement space bindings first and disables the old global
bindings only after reconciliation succeeds. The original ASGs and their
explicit space bindings remain. If disabling multiple global ASGs fails partway
through, rerun with the original defaults. The temporary, unbound
`cdas-migration-baseline` ASG records the original grants and is removed after
the cutover succeeds.

## Authentication and execution

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

- The utility computes the **minimum** number of ASGs needed across managed
  staging and running bindings, with protected groups treated as fixed. Groups
  can serve spaces in several orgs. Without `defaults`, unlisted orgs remain
  out of scope. A missing configured space or exhausted solver budget aborts
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
- New managed ASGs use short opaque `cdas-` names. The utility fingerprints
  rules in memory from the CAPI snapshot and compares normalized rules before
  reuse, including unbound groups left by interrupted runs. Existing
  `cf-dns-asg-sync-` groups can be reused under their original names, and
  redundant groups are retired once no bindings need them. Reserve both naming
  formats for the utility.
- A group with a binding outside the current healthy scope keeps that binding
  and its rules and descriptions. The utility may still adjust bindings in
  healthy managed spaces. Independently managed groups remain untouched except
  for disabling global bindings during a matching-defaults migration.
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
reach CAPI and UAA. Run one writer per foundation. The example task uses
IPv4 and public destinations; add flags in `ci/sync.yml` for private or IPv6 use.

## Develop

Run `go generate ./...` after changing an interface with a Counterfeiter fake.
Run tests with `go run github.com/onsi/ginkgo/v2/ginkgo -r` or `devbox run test`.

Licensed under [Apache 2.0](LICENSE).
