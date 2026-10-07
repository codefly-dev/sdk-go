![workflow](https://github.com/codefly-dev/sdk-go/actions/workflows/go.yml/badge.svg)
[![Go Report Card](https://goreportcard.com/badge/github.com/codefly-dev/sdk-go)](https://goreportcard.com/report/github.com/codefly-dev/sdk-go)
[![Go Reference](https://pkg.go.dev/badge/github.com/codefly-dev/sdk-go.svg)](https://pkg.go.dev/github.com/codefly-dev/sdk-go)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)


![](docs/media/dragonfly.png)

# codefly + go = sdk-go

## Endpoint resolution with core v0.13.0

Both SDK modules pin the core **v0.13.0** release tag (`f2423c9c`). Endpoint
visibility is `private`, `internal`, or `public`; an endpoint outside the system
declares `location: external` independently of its visibility.

`For(ctx).Module(...).Service(...).Endpoint(...).ResolveNetworkInstance()` uses
core selection before looking up a runtime-injected address wherever the
workspace is on disk. In `local` or with no environment selected, it can fall
back to core's deterministic native map. Core's `Endpoint.External()` predicate
refuses that fallback for an external location. A public endpoint without an
external location still resolves locally, even though public visibility also
allocates an external instance.

With a workspace on disk, every query resolves its name and API through core's
typed selector on the producer's declarations before reading the injected
carrier, including queries with an explicit API. Ambiguous, forbidden, and
API-mismatched references are refused even if a matching carrier exists.

A deployed process has no workspace: the builder image ships the binary alone.
In every environment, with no workspace on disk, the carriers the composition
injected are the composition's judgement — the CLI's join decided at render
which endpoints the consumer may reach, and the mesh enforces it on the cell.
Such a process resolves from the carrier keyed by the query's canonical
identity (module, service, name, API; a name that is a supported API serves
that API, as core reads a declaration) and refuses only an absent carrier, with
`ErrEndpointCarrierAbsent`, or a malformed one. It never computes a native
address. This includes Kubernetes pods in a `local` environment: the environment
name does not mean the workspace is shipped in their image. A process that does
ship its workspace keeps selection first. The workspace's presence determines
the path; native fallback requires a workspace and a `local` or unset environment.
A reference to an endpoint not named after its API must qualify the
API with `.API(...)` there, since no declaration is on disk to supply it.

Call `codefly.Init(ctx)` at boot to pin the calling module from the runtime
identity. `Init` refuses a process whose runtime identity carrier is unset or
blank with `ErrConsumerNotIdentified`. Every codefly-managed flow sets that
carrier, and a process that fails `Init` must not serve, so the refusal gates
configuration and secret reads as well as endpoints. Endpoint queries before
initialization are refused. `.Module(...)` selects the producer and cannot
change the consumer. Each resolution checks the live identity against the boot
pin and returns `ErrAuthorityValueChanged` on drift, including for queries
created before the change. Reloading the snapshot or calling `Init` again
cannot adopt a different identity. Core loads the producer's module-adjusted
declarations and `SelectEndpointForReference` checks visibility, internal
allowlists, exact names, API qualifiers, and ambiguity. Its refusal is returned
to the caller, including `ErrEndpointNotReachable` for a private endpoint
queried across modules.

`ResolveNetworkInstance` returns resolution errors with no instance, and
`NetworkInstance` returns nil on those errors. No entrypoint ever substitutes
an address for an unavailable, external, forbidden, or invalid endpoint.
After selection, core's key/value lookup distinguishes an absent carrier from
a present value under the selected declaration's key. In unset or `local`
environments with a workspace only absence permits native fallback; without
a workspace or outside `local`, absence is refused with
`ErrEndpointCarrierAbsent`. A carrier keyed differently from the
selected declaration — another API, or another spelling — is not found under
that key and reads as absent, so in `local` the native fallback runs in its
place until the declaration-aware carrier validator (core#716) lands with the
v0.14.0 re-pin. A present value is parsed by core; malformed or empty addresses
are refused with no instance, even when a native address could be computed.

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

Core validates each marked operation when the receipts interceptor is built.
Operation declarations must specify a completion mode; synchronous operations
declare `COMPLETION_CALL`. An omitted mode is refused, not defaulted.
