---
name: runtime-carrier-accessor
description: Use when a consuming service needs a value the Codefly runtime provides and is reading it — or is about to read it — from the environment by hand, e.g. os.Getenv("CODEFLY__…"), a pinned port, or a credential path copied from another component. Covers choosing between the For query, RuntimeValue and a process-level accessor, the three-source lookup order every accessor follows, the compatibility spellings, and the global snapshot that makes a forgotten LoadEnvironmentVariables pass a test for the wrong reason.
---

# Adding an accessor for a runtime-provided value

This module exists so product code never spells a Codefly carrier. When a
service is reading `CODEFLY__SOMETHING` directly, the deliverable is an accessor
here — not a documented env var, and never a suggestion that the consumer keep
reading it "for now". That is the fleet's *gap in the tooling is a bug in the
tooling* rule in its most literal form.

## Pick the right surface first

| The value is… | Goes on | Example |
| --- | --- | --- |
| provisioned to a **service** (its own or another's) | `For(ctx)` | `Configuration`, `Secret` |
| provisioned to the **workspace** | `For(ctx)` | `WorkspaceConfiguration`, `WorkspaceSecret`, `WorkspaceValue` |
| an **endpoint address** | `For(ctx)` | `ResolveNetworkInstance` |
| injected **directly into the process**, addressed by name | `RuntimeValue` | `RuntimeValue("MODULE_IDENTITY_PREFIX")` |
| **process identity** the runtime selects | a package function | `Environment`, `Workspace`, `Fixture`, `ServiceVersion` |

Prefer an existing accessor. A new one is warranted when the value's *shape* is
new, not when its name is. `RuntimeValue` in particular is the generic escape
hatch for injected values and usually removes the need for a bespoke function.

Do not export a new `CODEFLY__…` constant. The prefix is declared once, in
`runtime_value.go`, and the whole point is that it is not part of the API.

## The lookup order every accessor follows

Three sources, in this order, and the first non-empty wins:

1. the in-process injected carrier (`injectedEnvironmentValue`) — what
   `InjectConfigurations` / `InjectEndpoints` populate for an embedded flow;
2. the process environment (`os.LookupEnv`);
3. `resources.FindValueInEnvironmentVariables` over the SDK's snapshot.

Follow it. An accessor that only reads `os.Getenv` is invisible to an embedded
host that injected the value, and the failure is silent — the host resolved the
configuration correctly and the service still behaves as if nothing was
provisioned.

**Empty is absent.** `RuntimeValue` trims and reports `false` for whitespace,
because a composition templating an unset variable ships the name with an empty
value; treating that as present would shadow the fallback a caller relies on.
New accessors do the same.

**Two spellings, exact first.** Capability and configuration names historically
preserved `-` while newer emitters normalize it to `_`. `For`'s accessors try
the canonical key, then the legacy one, so an SDK user is independent of the
runtime agent's version. If your value can carry a `-`, do the same rather than
picking one spelling and requiring everyone to upgrade.

## Testing it

Tests are `package codefly_test` — the external test package — so they exercise
the public surface exactly as a consumer does. Keep it that way; a test that
needs internals is usually testing the wrong boundary.

The env snapshot is **global and explicitly rebuilt**:

```go
t.Setenv("CODEFLY__WORKSPACE_CONFIGURATION__SECURITY__TOKEN", "value")
requireNoError(t, codefly.LoadEnvironmentVariables())
```

Set a carrier without that reload and the accessor reads the *previous*
snapshot. The test can pass for the wrong reason — it asserts against whatever a
neighbouring test left behind. When a new assertion passes immediately, take the
value back out and confirm it fails; a snapshot bug looks exactly like success.

Cover both the injected path (`InjectConfigurations` / `InjectEndpoints`, no
process env) and the process-env path. They are different sources and a single
test exercises only one of them.

Then run the gates the root module is held to:

```bash
go test ./...
go test -race ./...
golangci-lint run
```

If the value is one the runtime *should* provide and does not, the accessor is
still only half the work: the other half is the issue against the runtime or CLI
that owns the injection. Name it in the PR.
