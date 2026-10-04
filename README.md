![workflow](https://github.com/codefly-dev/sdk-go/actions/workflows/go.yml/badge.svg)
[![Go Report Card](https://goreportcard.com/badge/github.com/codefly-dev/sdk-go)](https://goreportcard.com/report/github.com/codefly-dev/sdk-go)
[![Go Reference](https://pkg.go.dev/badge/github.com/codefly-dev/sdk-go.svg)](https://pkg.go.dev/github.com/codefly-dev/sdk-go)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)


![](docs/media/dragonfly.png)

# codefly + go = sdk-go

## Work Context: mint once, sealed, one implementation

A module process obtains its credential once per execution, sealed to the build
it is and the installation it serves, and never announces itself again. The leaf
module `github.com/codefly-dev/sdk-go/workcontext` holds the mint-once client,
the carriers that take a credential to a callee, the cache partition and the
stream guard.

**It mints nothing and verifies nothing.** The Work Context is a core proto, and
`github.com/codefly-dev/core/workcontext` is its only implementation: the only
code that signs a capability, the only code that checks a signature, the only
encoding of either. What this module exports as a verification entry point *is*
core's, by type alias, and two tests hold it that way —
`TestNoSecondWorkContextImplementation` refuses a signing primitive, a
JSON-encoded capability or a `WorkContext*` type of our own anywhere in the
module, and `TestWorkContextConformance` drives core's own fixtures through the
entry point we export.

That rule is written down because it was broken here, and the cost of breaking
it is a specific misdiagnosis: two encodings of one message both look like
`<payload>.<signature>` with an Ed25519 signature, so a token from one fails
*signature* verification in the other, and "signature does not verify under key
X" sends everyone to look at keys.

See [`workcontext/README.md`](workcontext/README.md) for the model, the sealed
fields, the refusals a caller must tell apart, the four sources core's verifier
requires, and what a consumer has to stop doing — there is no heartbeat, no
registration call, and no self-reported build or installation.

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
