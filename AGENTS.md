# Working in codefly-dev/sdk-go

`github.com/codefly-dev/sdk-go` (Go 1.27) is the Go SDK a *product service*
imports. It owns the boundary between product code and the Codefly runtime:
resolving endpoints, configuration, secrets, fixtures and runtime-injected
values, plus workload TLS and Work Context signing/verification.

It does **not** own: the resource model, the proto schema or the environment
variable encoding itself — those are `codefly-dev/core`, which this module
depends on. It does not own the `codefly` CLI, any agent implementation, or the
services that import it. The one thing it exists to guarantee is that **product
code never spells a Codefly carrier**. Every `os.Getenv("CODEFLY__…")` in this
repo is deliberate and encapsulated; a new one anywhere else is the bug.

## How to behave

Fleet standard — [handbook#68](https://github.com/obin-ai/handbook/issues/68).
They land hard here: this is a *library*, so its defects are observed in someone
else's service, where hand-assembling the value the SDK failed to resolve always
looks like the faster path.

- **A gap in the tooling is a bug in the tooling — never a reason to reach
  around it.** When a service cannot get a value out of the SDK, the answer is
  an accessor added here, or a capability fixed in whichever tool owns it, named
  in the PR. It is never a hand-written env var in the consumer — not as a
  "workaround", not "just this once", not "until the accessor lands".
- **Never hack. Provide the best fix, even when it spans repos.** The fix living
  in `codefly-dev/core` or `codefly-dev/cli` is not a reason to work around it
  here. Open the PR there and consume the reviewed result. When it genuinely
  cannot be fixed now, the deliverable is a precise issue against that owner
  plus an explicitly labelled stopgap — never an unlabelled one.
- **Classify every change that makes something work**, in the PR body: a *fix*
  at the place that owns the behaviour, or a *hack*. A hack does not become a
  fix by working, by being small, by being local, or by the real fix belonging
  elsewhere.
- **Never hardcode what the system resolves** — injected environment, derived
  ports, service addresses, credentials copied out of another component. This
  module is the resolution: addresses come from
  `codefly.For(ctx)…ResolveNetworkInstance()`, configuration and secrets from
  the `For` accessors, direct runtime values from `codefly.RuntimeValue`. Typing
  one encodes something true only on one machine for ten minutes, and it fails
  *quietly* — a runtime missing a credential can skip registration silently, so
  the service boots, serves, and is simply absent.
- **Diagnose, do not pattern-match.** "It started working when I set X" is not a
  diagnosis — set X back and confirm it breaks. Do not trust an error message
  before checking its claim: an unknown-fixture error here has meant a *pinned*
  module the SDK never read, not a wrong name, which is why `Principal` says so
  explicitly.
- **Say what you did not verify.** Unverified is not the same as working. A unit
  run is not a service booting against a real runtime; if you could not exercise
  something, the PR says so.

## Build and test

Two modules, both Go 1.27.0. Derived from `.github/workflows/go.yml`, which runs
every job against the matrix `[".", "workcontext"]` except coverage.

```bash
go test ./...                                             # the suite
CODEFLY_TEST_POSTGRES_DSN=postgres://… go test ./receipts/...  # the receipts store
go test -race ./...                                       # CI runs this separately
go mod tidy && git diff --exit-code -- go.mod go.sum      # module consistency
golangci-lint run                                         # v2.13.2, config .golangci.yaml
go test ./... -coverprofile=cover.out -covermode=atomic -coverpkg=./...
```

The receipts store's tests **skip** without `CODEFLY_TEST_POSTGRES_DSN`, and a
skipped test is green. CI's `coverage` and `race` jobs run a Postgres service
and set it; a local run that does not is not the gate.

Run each of those a second time from `workcontext/` — it is a separate module
with its own `go.mod` and `go.sum`, so nothing at the root covers it. Lint finds
the root `.golangci.yaml` by walking up, so it needs no config of its own.

Coverage thresholds differ by module and are not interchangeable:

| Module | Gate | Where |
| --- | --- | --- |
| root | total ≥ 75%, per-file and per-package 0 | `.testcoverage.yaml` |
| `workcontext` | module total ≥ 75%, via `awk` in CI | `go.yml`, `coverage` job |

The `workcontext` gate is on the **module total** across both its packages, so
`grpctransport` sitting low is carried by the verifier. Read the total, not a
package line.

## Where things live

| Path | Owns |
| --- | --- |
| `codefly.go` | `Init`, the immutable env snapshot, `Inject*`, process-level accessors |
| `for.go` | the `For(ctx)` query: endpoints, configuration, secrets, workspace values |
| `authority.go` | authority-bearing values, read once at boot; a drift is refused, never reloaded |
| `runtime_value.go` | `RuntimeValue`, for values the runtime injects directly |
| `runtime_environment_file.go` | loading a runtime-written env file |
| `fixture.go` | the selected fixture, and resolving its principals by role |
| `tls.go` | workload leaf certificates, reloaded on rotation |
| `receipts/` | effect receipts: the store, the digest, the replay/conflict interceptor |
| `receipts/grpctransport/`, `receipts/connecttransport/` | the two transport adapters, split so neither drags the other's dependency in |
| `workcontext/` | **separate leaf module**: the mint-once client, the carriers, the cache partition, the stream guard, and typed access to core's one implementation. Its own `AGENTS.md` holds what the two gates refuse |
| `workcontext/grpctransport/` | the gRPC carrier, so a consumer that makes no gRPC call never compiles grpc |

`workcontext` mints nothing and verifies nothing: `core/workcontext` is the only
implementation of the capability, and this module re-exports core's verifier by
type alias. Adding a dependency to it is still a design change, not a detail —
see the skill below.

## Rules that bite

- **Core is pinned to the v0.12.0 tag in both modules.** Endpoint visibility is
  exactly `private`/`internal`/`public`; `external` is a location. Local fallback
  uses core's `Endpoint.External()` predicate and still resolves public
  endpoints without an external location. Do not recreate removed visibility names.
- **`CODEFLY__` is spelled in this repo, nowhere else.** A consumer needing a
  value gets a typed accessor here; the prefix constant lives in
  `runtime_value.go` for that reason.
- **Env state is global and the snapshot is explicit.** `LoadEnvironmentVariables`
  rebuilds it; a test that sets a carrier and forgets the reload asserts against
  the previous snapshot and passes for the wrong reason. Tests are
  `package codefly_test` and use `t.Setenv`.
- **An empty injected value is not a value.** A composition templating an unset
  variable ships the name with an empty string; `RuntimeValue` reports `false`
  so it cannot shadow the configuration a caller falls back to. Keep that.
- **The Work Context has exactly one implementation and it is not here.**
  `core/workcontext` signs, verifies, and answers the *structural* question
  through `Inspect`. Nothing here may sign, check a signature, encode a
  capability **or decide what a capability is** — a local seal rule is a second
  implementation even when it signs nothing, and ours disagreed with core's own
  fixtures about which sentinel three refusals earn. **Four gates hold that, and
  all four read both modules**: a **deny-by-default import allowlist per
  module** and a **`go/types`-decided codec rule** (both via
  `x/tools/go/packages`), the syntactic AST gate, and
  `scripts/check-one-implementation.sh` over every published ref, which reads
  imports with `go/parser` because a regex cannot — `import "\x63rypto/ed25519"`
  compiles. The allowlist replaced a denylist of names that was behind by one
  entry every round for ten rounds, the last being `crypto/mldsa` signing a
  `WorkContextV1` that `encoding/json/v2` had encoded in the deleted format,
  with both gates green. `testdata` is walked and `import "C"` is refused.
  **Published TAGS cannot be fixed, only retracted**: nineteen of them carry the
  deleted implementation and `go.mod` retracts them.
  **`workcontext/AGENTS.md` is what each one refuses and why** — read it before
  touching that module, the gate, or the sweep.
- **An authority-bearing value is read once.** A principal, binding or audience
  comes from `ReadAuthority` at boot. `WorkspaceValue` answers from that pin for
  a pinned name, so a drift is an error rather than a reload — the process has
  already minted a credential sealed to the old value.
- **A receipt is written inside the transaction that commits its effect.** A
  receipt written after the commit leaves a window where the effect exists and
  the receipt does not, and a recovery landing there reads "no receipt" for an
  effect that already happened. That is why `receipts.Record` takes a `Tx`.
- **Every published ref is held to these rules, not exempted from them.** A
  consumer can pin any branch, so the sweep covers every one rather than a
  `compat/*` name glob: measured, 22 of 25 remote branches still carried the
  deleted implementation, so retiring the three NAMED compat refs would have
  turned the gate green with 19 copies published. A line that cannot meet a
  rule is **retired** by the owner, never granted a period during which the
  rule is false here. A bullet forbidding the back-port of a breaking deletion
  used to live here; it is what kept the implementation alive on refs CI
  builds, so it is deleted.

## Procedures

Loaded on demand rather than carried here — `.claude/skills/`:

- `dual-module-change` — a change touches both modules, or `workcontext` alone,
  and you need the leaf-module contract and the per-module gates.
- `runtime-carrier-accessor` — a consumer needs a value it currently reads from
  the environment by hand, and the answer is a new accessor.

## Workflow

- Branch and PR; never commit to `main`. Conventional Commits for the title.
- The PR template asks for the fix-or-hack classification and for what you did
  not verify. Both are rules above; answer them there rather than omitting them.
- `agentcontext_test.go` holds this file's length budget and each skill's
  frontmatter contract. It runs under `go test ./...`, so CI enforces it with no
  workflow change.
- Keep this file under ~150 lines (hard cap 200). Push depth into a nested
  `AGENTS.md` beside what it describes, or into `.claude/skills/`.
- `CLAUDE.md` is a pointer to this file. Keep one canonical source.
- Treat this file as code: the PR that changes a process updates it.
