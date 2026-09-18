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
| `runtime_value.go` | `RuntimeValue`, for values the runtime injects directly |
| `runtime_environment_file.go` | loading a runtime-written env file |
| `fixture.go` | the selected fixture, and resolving its principals by role |
| `tls.go` | workload leaf certificates, reloaded on rotation |
| `receipts/` | effect receipts: the store, the digest, the replay/conflict interceptor |
| `receipts/grpctransport/`, `receipts/connecttransport/` | the two transport adapters, split so neither drags the other's dependency in |
| `workcontext/` | **separate leaf module**: Work Context signing and verification |
| `workcontext/grpctransport/` | the gRPC carrier, so verify-only consumers never compile grpc |

`workcontext` exists to keep a verify-only consumer's `go.sum` small. Adding a
dependency to it is a design change, not a detail — see the skill below.

## Rules that bite

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
- **A receipt is written inside the transaction that commits its effect.** A
  receipt written after the commit leaves a window where the effect exists and
  the receipt does not, and a recovery landing there reads "no receipt" for an
  effect that already happened. That is why `receipts.Record` takes a `Tx`.
- **`compat/**` branches are published artifacts.** Consumers pin them when
  `main` holds an unreleased breaking change, so CI builds them like `main`.

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
