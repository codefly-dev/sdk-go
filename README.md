![workflow](https://github.com/codefly-dev/sdk-go/actions/workflows/go.yml/badge.svg)
[![Go Report Card](https://goreportcard.com/badge/github.com/codefly-dev/sdk-go)](https://goreportcard.com/report/github.com/codefly-dev/sdk-go)
[![Go Reference](https://pkg.go.dev/badge/github.com/codefly-dev/sdk-go.svg)](https://pkg.go.dev/github.com/codefly-dev/sdk-go)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)


![](docs/media/dragonfly.png)

# codefly + go = sdk-go

## Work Context: mint once, sealed, verified exactly

A module process obtains its credential once per execution, sealed to the build
it is and the installation it serves, and never announces itself again. The leaf
module `github.com/codefly-dev/sdk-go/workcontext` holds the mint client, the
signer and the verifier; it depends only on the shared `codefly/base/v0` proto
types, so a consumer that only verifies keeps a `go.sum` of a handful of entries
rather than inheriting core's transitive tail.

See [`workcontext/README.md`](workcontext/README.md) for the model, the sealed
fields, the four refusals a caller must tell apart, and what a consumer has to
stop doing — there is no heartbeat, no registration call, and no self-reported
build or installation.

## Authority-bearing configuration

A principal, binding or audience is read once, at boot, through
`codefly.ReadAuthority`, and the SDK refuses a runtime change to one: the host
is the authority for these values, and a value that drifts under a running
process is an error rather than a reload — the process has already minted a
credential sealed to the old one. `For(ctx).WorkspaceValue` answers from that
boot read for a pinned name, so the ordinary accessor is not a way around it.

## Tenant-scoped effect receipts

Services whose receipt table uses row-level security should construct their
Postgres receipt store with `receipts.WithTenantScope`. The hook binds the
verified tenant with transaction-local settings before `Lookup`,
`Held.Lookup`, or `SweepTenant` runs; a failed binding fails the call.
`Record` continues to use the caller's already-bound effect transaction.

Use `SweepTenant` for tenant-by-tenant retention. `Sweep` remains an unscoped,
all-tenant operation and needs a role the table's policies admit. See the
[receipts package documentation](receipts/doc.go) for the binding example
and retention requirements.
