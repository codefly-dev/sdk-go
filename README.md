![workflow](https://github.com/codefly-dev/sdk-go/actions/workflows/go.yml/badge.svg)
[![Go Report Card](https://goreportcard.com/badge/github.com/codefly-dev/sdk-go)](https://goreportcard.com/report/github.com/codefly-dev/sdk-go)
[![Go Reference](https://pkg.go.dev/badge/github.com/codefly-dev/sdk-go.svg)](https://pkg.go.dev/github.com/codefly-dev/sdk-go)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)


![](docs/media/dragonfly.png)

# codefly + go = sdk-go

## Endpoint resolution

Each module's `go.mod` owns its core pin: `workcontext` is on the **v0.19.1**
release tag (`7f78302f`); the root is on core's candidate `835460f1`, a candidate
pin and not release qualification. Endpoint visibility is `private`, `internal`,
or `public`; an endpoint outside the system declares `location: external`
independently of its visibility.

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

A workspace found above the process counts only if it is the process's
composition. The runtime names the composition: every service `codefly run`
starts carries it as the injected workspace identity. A composed module run from
its own checkout, a released tag resolved into `CODEFLY_MODULE_CACHE`, or a
solution's tag finds its producer's own `workspace.codefly.yaml` first. That file
declares another name (`saas-starter-dev`, not `platform-core`), so it is treated
as no workspace at all. It is never loaded, which matters for a solution's tag
whose workspace imports its platform by release and cannot be composed outside
the CLI. Even when the producer names the module exactly as the composition does
(`robin` in its own repository and in `platform-core`), the process resolves
from its injected carriers, refuses an absent one with
`ErrEndpointCarrierAbsent`, and never selects against the producer's
declarations or computes a native address from its name. A workspace that does
match must also carry the queried module, by core's `Workspace.Member`: modules
it composes through `workspaces:` or `solutions:` count, and the native address
is computed under the composition's name. A module it does not carry is
answered from the carriers, and an absent carrier's refusal names the modules
the workspace does carry.

The composition's own workspace is sometimes one only the host can compose: a
solution run natively from its root imports its platform by release
(`workspaces:` with `source` and `version`), and composing that means acquiring
the release, which the CLI does — it hands core a `WorkspaceResolver` — and this
SDK never does. The SDK hands core a resolver that refuses, so core's own loader
says when that acquisition is all that stands between the file and a
composition, and the file then counts as none (`enclosing.HostComposed`): the
carriers the run injected answer, the process's own endpoint included, and an
absent carrier's `ErrEndpointCarrierAbsent` says why no declaration was judged
here and names the import. Nothing is recomposed and no native address is
computed from a workspace that was not composed. Before this, the load failure
(`requires host resolution`) was the answer, and `NetworkInstance()` hid it as
nil while the run's carrier sat in the environment.

`codefly run` and `codefly test` both inject that identity. With none injected,
no composition started the process (a local tool, a plain `go test` or `go
run`), and the workspace found is the only one there is: it is used as found.

A workspace file that cannot be decoded cannot name itself, so under an
injected identity it does not count and the injected carrier still answers. If
no carrier was injected either, the refusal carries the decode error, since that
file may have been the composition's own. With no identity injected, the decode
error is returned as it always was.

The same rule decides every other read that falls back to the workspace on
disk: the local configuration and secret files behind `Configuration` and
`Secret`, the packages `fixture.Selected().Principal` resolves, and the name
`codefly.Workspace` reports when no identity is injected. That name is read from
the file, without composing it.

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

`Init` also enables the OTLP trace exporter when the process was handed an
intake: Codefly delivers `OTEL_EXPORTER_OTLP_ENDPOINT` (a URL whose scheme
fixes the transport), `OTEL_SERVICE_NAME` and `OTEL_RESOURCE_ATTRIBUTES` to
every service it runs or renders, from the environment's `telemetry:` block. A
service declares no configuration group and dials no address for this; one
started with no endpoint exports nothing. An exporter that cannot be built is
logged, never fatal. Call `codefly.ShutdownTelemetry(ctx)` on the way down so
the last spans are flushed.

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
place. Core has shipped the declaration-aware carrier validator
(`resources.ValidateEndpointCarriers`, core#716) since v0.14.0; this SDK does
not call it yet, so that gap is open here, not in core. A present value is parsed by core; malformed or empty addresses
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
A pinned value whose live delivery breaks is refused with
`ErrAuthorityValueChanged` wrapping the reason, by `WorkspaceValue`,
`WorkspaceValueIfSet` and `Authority.Recheck` alike.

## Workspace values

`WorkspaceValue` and `WorkspaceValueIfSet` read a name that may sit in either
the public or the secret workspace namespace, and it must sit in exactly one:

- a name carried in **both** namespaces is refused with
  `ErrWorkspaceValueInBothNamespaces`, as two sources for one value, the same
  way a value delivered both inline and by file is refused;
- a delivery that **cannot be read** (a missing file, an empty file, a value
  delivered both inline and by file) is refused with that reason
  (`resources.ErrFileCarrier`). The other namespace never answers in its place.

An **empty delivered file** is a broken delivery, not absence. Codefly
delivers a value by file only when it is too large for the process
environment, so an empty file is a truncated write or a mount race. Every
accessor refuses it, and so does `LoadEnvironmentVariables`. An empty
*inline* value is still absent.

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
