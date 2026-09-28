![workflow](https://github.com/codefly-dev/sdk-go/actions/workflows/go.yml/badge.svg)
[![Go Report Card](https://goreportcard.com/badge/github.com/codefly-dev/sdk-go)](https://goreportcard.com/report/github.com/codefly-dev/sdk-go)
[![Go Reference](https://pkg.go.dev/badge/github.com/codefly-dev/sdk-go.svg)](https://pkg.go.dev/github.com/codefly-dev/sdk-go)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)


![](docs/media/dragonfly.png)

# codefly + go = sdk-go

## Work Context verifier

Services that only need to verify Codefly Work Contexts can import the leaf
module `github.com/codefly-dev/sdk-go/workcontext` instead of the full SDK. It
depends only on the shared `codefly/base/v0` proto types, so a consumer's
`go.sum` stays a handful of entries rather than inheriting core's transitive
tail.

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
