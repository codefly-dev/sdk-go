---
name: dual-module-change
description: Use when a change touches workcontext/ — the leaf module — or both it and the root SDK. Covers the dependency budget that is the module's whole reason to exist, the two go.mod/go.sum pairs that must be tidied independently, the two different coverage gates, and how a consumer resolves a version of a Go submodule. Reach for it when a root-module command reports "ok" but workcontext was never compiled, when `go mod tidy` at the root leaves workcontext dirty, or before adding any import to workcontext.
---

# Changing the two modules

`workcontext/` is a separate Go module, not a package of the SDK. It exists so a
service whose only need is to verify Work Contexts can import
`github.com/codefly-dev/sdk-go/workcontext` without inheriting the root SDK's
transitive tail — which is `codefly-dev/core` and everything under it.

That is the contract. Everything below follows from it.

## The dependency budget

`workcontext/go.mod` currently has three direct requirements — `core` (for the
`codefly/base/v0` proto types), `testify`, `grpc` — and five indirect ones. The
root SDK's indirect list is roughly fifty.

**Adding an import to `workcontext` is a design change.** Before you do:

- Can the type come from `codefly/base/v0`, which the module already has?
- Does it belong in `workcontext/grpctransport/` instead? That subpackage exists
  so a verify-only consumer never compiles grpc. Anything transport-shaped goes
  there, not beside the verifier.
- Does it belong in the root SDK, with `workcontext` left alone?

If none of those work, say in the PR body what the consumer's `go.sum` now
costs. Growth is a decision someone makes, not a side effect of an import line.

The root module must never import `workcontext` to reach shared code. That would
make the leaf module a dependency of the thing it was split out of, and a
consumer taking the leaf would be back to the full tail.

## Running the gates

Every CI job except coverage runs the matrix `[".", "workcontext"]`. A command
run only at the root proves nothing about the leaf: `go test ./...` at the root
does not descend into another module, and reports `ok` having never compiled it.

```bash
go test ./... && (cd workcontext && go test ./...)
go test -race ./... && (cd workcontext && go test -race ./...)
golangci-lint run && (cd workcontext && golangci-lint run)

go mod tidy && git diff --exit-code -- go.mod go.sum
(cd workcontext && go mod tidy && cd .. && git diff --exit-code -- workcontext/go.mod workcontext/go.sum)
```

`go mod tidy` operates on one module. Tidying the root leaves `workcontext`
untouched and CI's `module-consistency` job fails on the second matrix leg.

`golangci-lint` walks up for its config, so running it from `workcontext/`
picks up the root `.golangci.yaml`. Do not add a second config file.

## Coverage, which is two different gates

| Module | Gate | Enforced by |
| --- | --- | --- |
| root | total ≥ 75%, file and package thresholds 0 | `.testcoverage.yaml`, go-test-coverage action |
| `workcontext` | module total ≥ 75% | an `awk` line in the `coverage` job of `go.yml` |

The `workcontext` check is inline in the workflow, not in `.testcoverage.yaml`,
and it reads the **module total** across both packages:

```bash
cd workcontext
go test ./... -coverprofile=cover.out -covermode=atomic -coverpkg=./...
go tool cover -func=cover.out | awk '/^total:/ {print $3}'
```

`-coverpkg=./...` is what makes `grpctransport` count toward that total even
though the verifier's tests are what exercise it. Reading a single package's
percentage will mislead you in both directions.

## Versioning

A Go submodule is released under its own tag path — `workcontext/vX.Y.Z`, not
the root's `vX.Y.Z`. This repo publishes root tags (`v0.1.66` and below) and no
`workcontext/*` tag, so a consumer today resolves the leaf module to a
pseudo-version of a commit rather than to a release.

If you are asked to cut a release of `workcontext`, that is the first thing to
establish, and it is a question for whoever owns the release process — not
something to infer from the root tags. Do not hand-tag to find out.
