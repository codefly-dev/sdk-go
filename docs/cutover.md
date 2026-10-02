# Retiring the release lines that still carry the deleted implementation

The Work Context has exactly one implementation, `codefly-dev/core/workcontext`.
On `main` that is enforced by `TestNoSecondWorkContextImplementation` and by
core's conformance kit, both in `workcontext/`. This page is about the branches
those tests cannot reach.

## Why there is anything left to retire

`compat/**` branches are published artifacts: a consumer pins one when `main`
holds an unreleased breaking change, and CI builds them like `main`
(`AGENTS.md`). The one-implementation change is exactly such a breaking change,
so the release lines still carry the root JSON signer, verifier and JWKS
verifier — in full, and deliberately. **Back-porting the deletion is the wrong
move**: it would break the consumer the line exists for.

A branch's CI run uses that branch's own tree and workflow, so no test added on
`main` executes there. `scripts/check-one-implementation.sh`, run by the
`one implementation` workflow, reads every ref out of the object database
instead, and is **red by design** while any of them still carries an
implementation. That is a visible countdown, not a failure to fix.

## The refs, and the one consumer pinned to them

| Ref | Head at the time of writing | Carries |
| --- | --- | --- |
| `origin/compat/v0.1.65` | `8157d3a` (2026-09-27) | `work_context.go`, `work_context_jwks.go`, root `execution_context_grpc.go` |
| `origin/compat/v0.1.65-tls` | `eabe9b8` (2026-09-17) | the same |
| `origin/feat/file-carriers-compat` | `0fbc3ce` (2026-09-27) | the same |

`feat/file-carriers-compat` is not under `compat/**`, so no published-artifact
rule names it; the sweep covers it anyway, because CI builds it.

**One known consumer**, `obin-ai/module-robin`, pins
`github.com/codefly-dev/sdk-go v0.1.66-0.20260927165945-8157d3a…` — a commit on
`compat/v0.1.65`. That is why it still compiles `codefly.WorkContextVerifier`
and the other root identifiers, which left `main` on 2026-09-03 in `cd3613b`.

## Precondition

**Every consumer pinned to these refs has repinned to a release carrying the
one-implementation change.** For `module-robin` that is one move, not two: the
mint-once client has never existed on the `v0.1.65` line, so leaving the compat
line and adopting `workcontext.MintClient` happen together.

Re-enumerate rather than trusting the table above — new pins and new branches
appear:

```bash
git fetch --no-tags origin '+refs/heads/*:refs/remotes/origin/*'
./scripts/check-one-implementation.sh          # names every ref still carrying one
```

## The retirement

Performed by the repository owner at the cold cutover, once the precondition
holds. **Never by an agent, and never automatically** — deleting a published ref
breaks every build still pinned to it, and whether that moment has arrived is a
judgement about consumers rather than a property of this repository.

```bash
git push --delete origin compat/v0.1.65
git push --delete origin compat/v0.1.65-tls
git push --delete origin feat/file-carriers-compat
```

The `one implementation` workflow goes green on the next run, and the rule is
then true of the repository rather than of one branch. If it stays red, it is
naming a ref the commands above did not cover, which is the point of running the
script rather than the list.
