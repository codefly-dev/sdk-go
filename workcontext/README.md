# `workcontext`

Signing and verification of Codefly Work Contexts, and the client a module
process uses to obtain the one credential it runs on.

It is a separate Go module so a service whose only need is to verify can import
`github.com/codefly-dev/sdk-go/workcontext` without inheriting the root SDK's
transitive tail. Three direct dependencies: `codefly-dev/core` (for the
`codefly/base/v0` proto types), `testify`, `grpc`. The gRPC carrier lives in
`workcontext/grpctransport` so a verify-only consumer never compiles grpc.

## The model: mint once, sealed, verified exactly

A module process obtains its credential **once per execution**, bound to the
build it is and the installation it serves, and never again announces itself.

```
boot ──▶ read the projected service-account token
     ──▶ present it to the host's mint endpoint
     ──▶ receive a credential sealed to
             (principal id + epoch, installation id + revision, build incarnation)
     ──▶ serve
     ──▶ at expiry: re-read the rotated projection, re-check the boot authority, mint again
```

Three properties follow, and each replaces something that used to be true:

**Nothing runs on a timer that is not the credential's own expiry.** There is no
heartbeat and no registration call. A fifteen-minute credential renewed three
minutes before expiry costs **one mint and five renewals in an hour**. The
heartbeat this replaces burned a single-use token per surface every fifteen
seconds — 240 mints an hour, each one an audit event recording that nothing had
changed.

**The process self-reports nothing.** The mint request carries the audience it
wants and the audience its projection was minted for. That is all. Principal,
installation and build are the host's to establish, from the projected token and
its own records; a field for any of them would be a field a process could lie
in. There is no self-reported upstream and no manifest.

**A credential is sealed or it is not a credential.** Every sealed field is
required. A token missing one does not verify, and `AttachWorkContext` refuses
to put it on a request at all — there is no request on which an unsealed
credential is better than no credential.

## Obtaining the credential

```go
// At boot, in the root SDK: read the authority-bearing values once.
authority, err := codefly.ReadAuthority(ctx,
    codefly.AuthorityValueName{Name: "platform", Key: "work-context-audience"},
    codefly.AuthorityValueName{Name: "platform", Key: "mint-url"},
)
if err != nil {
    return err // a process that cannot establish its identity must not serve
}
audience, _ := authority.Value("platform", "work-context-audience")
mintURL, _ := authority.Value("platform", "mint-url")

client, err := workcontext.NewMintClient(workcontext.MintOptions{
    URL:                mintURL,
    Audience:           audience,
    ProjectedToken:     workcontext.ProjectedTokenFile("/var/run/secrets/codefly/token"),
    ProjectionAudience: projectionAudience,
    Authority:          authority, // rechecked before every renewal
})
```

Then, on every outbound request:

```go
credential, err := client.Credential(ctx) // mints once; renews only at expiry
if err != nil {
    return err
}
if err := credential.Attach(request); err != nil {
    return err
}
```

`Credential` is the only way to reach the credential, so there is no path on
which a stale one is used. It re-reads the projected token and rechecks the
boot-read authority before each renewal: a projection rotated under the running
process is picked up without a restart, and an authority value that has drifted
refuses the renewal instead of being sealed into a new credential.

`Attach` sets `x-codefly-work-context` and, beside it,
`x-codefly-installation-id` / `x-codefly-installation-revision`. The gRPC
transport sets the same names as metadata. Those two carriers are a **pre-check
the host may refuse on cheaply, and never authority**: the installation that
governs a call is the sealed one. On the incoming side the SDK refuses when a
carrier disagrees with the sealed claim rather than preferring either side.

## Verifying

`VerifyWorkContext` is the only verification entry point, on both the static
verifier and the JWKS one. It returns `VerifiedWorkContext`, which is the only
thing that can produce verified claims — so code holding claims cannot be
holding a hand-built protobuf, a token that was parsed and never verified, or a
credential nobody held to an installation.

```go
verified, err := verifier.VerifyWorkContext(token, workcontext.WorkContextExpectations{
    Issuer:   issuer,
    Audience: myAudience,

    // The delegating principal.
    OwnerPrincipalID:   ownerID,
    OwnerPrincipalKind: ownerKind,

    // The calling principal, checked separately. nil accepts direct owner
    // calls ONLY: a credential carrying an actor chain is refused.
    Delegation: &workcontext.DelegationExpectations{PrincipalKind: "agent"},

    // Required. A verifier that does not state where it is cannot refuse a
    // credential from somewhere else.
    Seal: workcontext.SealExpectations{
        PrincipalEpoch:       epoch,
        InstallationID:       installationID,
        InstallationRevision: revision,
        BuildIncarnation:     build,
    },

    // Required for an operation context; nil refuses a credential that seals one.
    OperationBinding: &workcontext.OperationBindingExpectations{
        BindingID: bindingID, BindingRevision: bindingRevision, BindingIncarnation: incarnation,
    },
})
```

Scope comes last, from the verified credential:

```go
err = workcontext.RequireWorkContextScope(verified, workcontext.WorkContextScopeRequirement{
    ResourceKind: "evidence", Action: "append", ResourceID: recordID,
})
```

### Exact binding, not scope search

An operation credential names one binding, at one revision, in one incarnation,
and verification resolves that identity. It never searches for a binding whose
scopes would admit the call. A credential sealed to binding X presented as
binding Y is refused **even when Y's scopes are a superset of X's** — scope
containment is not binding identity, and a revoked narrow credential must not
validate through a wider binding.

### The four refusals, and why they are four

| Sentinel | Means | What the caller does |
| --- | --- | --- |
| `ErrWorkContextInvalid` | the credential is wrong and cannot become right — bad signature, another installation, another build, another binding id | refuse the call; 401 |
| `ErrWorkContextSuperseded` | it was sound when minted and has been overtaken — principal epoch, installation revision or binding revision moved | mint again, then retry once |
| `ErrWorkContextDenied` | the credential is good and its scope does not cover this | refuse the call; 403 |
| `ErrWorkContextUnavailable` | the key set is unreachable (transport failure, issuer 5xx/429) | retry; 503, never 401 |

`ErrWorkContextSuperseded` is separate from the other three on purpose. Mapped
onto the retryable-outage path, every installation revision bump becomes a retry
storm against a credential that is guaranteed to keep failing. Mapped onto a
plain denial, a condition one mint would fix becomes a user-visible error.

## Streams

A stream authorized when it opened is not authorized forever. `StreamGuard`
re-presents the credential on the host's re-check cadence and terminates on
refusal, rather than draining a snapshot computed under authority that has since
been replaced — the failure mode it exists to prevent is the silent one, where
nothing errors and the data keeps arriving.

```go
guard, err := workcontext.NewStreamGuard(workcontext.StreamGuardOptions{
    Interval: hostRecheckCadence,
    Recheck: func(ctx context.Context) error {
        _, err := verifier.VerifyWorkContext(token, expectationsRightNow())
        return err
    },
})
for message := range messages {
    if err := guard.BeforeSend(ctx); err != nil {
        return err // terminate; do not resume
    }
    if err := stream.Send(message); err != nil {
        return err
    }
}
```

It guards emission rather than running a timer: an idle stream discloses
nothing, so there is nothing to refuse. Termination is sticky — a caller that
loops past the first refusal is not handed a second chance to emit, and the
authority coming back does not resurrect the stream.

## Cache partitions

`DeriveCachePartition` keys on the tenant **and the sealed installation at its
sealed revision**, always. An answer computed while the host held revision N was
computed under the authority of revision N, so the move to N+1 lands every
caller in a fresh partition. That is a cache miss by design and never a stale
hit.

- `ByAuthorizationView()` adds a digest of the effective scopes and the
  authorization revision. Safe only when the result depends on scopes alone.
- `ByViewer()` adds the effective actor — the last actor, or the owner for a
  direct call. Use it for anything whose content varies by who is asking: every
  reader of a wiki holds `documents:[read]`, and a revision is a number they
  share.

The key prefix is `wc2:`. It changed with the installation revision going into
the key, so a shared cache that outlives the deploy — Redis, a warehouse table —
cannot be reached under the `wc1:` keys it still holds.

## What a consumer must stop doing

- **Stop heartbeating, and delete the client that did it.** No periodic mint, no
  registration call, no deregistration. The host establishes presence from
  delivery, not from processes announcing themselves.
- **Stop reporting your own identity.** Do not send a build digest, an image
  reference, an installation, an upstream address or a manifest with a mint
  request. The host reads your build from the pod; anything you send instead is
  something you could get wrong, and the version it could get wrong is the one
  an attacker would choose.
- **Stop caching the projected token.** Read it again before every renewal. The
  projection is rotated under the running process, so the copy read at boot
  expires long before the process does.
- **Stop re-reading authority-bearing configuration.** A principal, binding or
  audience is read once, at boot, through `codefly.ReadAuthority`. The SDK
  refuses a runtime change to one: the host is the authority, and a value that
  drifts under a running process is an error, not a reload. `WorkspaceValue`
  answers from the pin for a pinned name, so there is no way around it.
- **Stop verifying without a seal.** `Verify` is gone; `VerifyWorkContext` takes
  required `SealExpectations`. A verifier that does not state which installation
  revision and build it is on cannot refuse a credential from an earlier one.
- **Stop searching bindings.** Resolve the sealed binding identity. A superset
  of scopes is not a licence to act as a different binding.
- **Stop authorizing from bare claims.** `RequireWorkContextScope` takes a
  `VerifiedWorkContext`. Claims that were never verified, or were mutated after
  verification, can no longer reach an authorization decision.

## Running the gates

This is a separate module. Commands run at the repository root do not compile
it, and report `ok` having never tried.

```bash
go test ./...                     && (cd workcontext && go test ./...)
go test -race ./...               && (cd workcontext && go test -race ./...)
golangci-lint run                 && (cd workcontext && golangci-lint run)
go mod tidy                       && (cd workcontext && go mod tidy)
```

Coverage for this module is gated on the **module total** across both its
packages (≥ 75%, an `awk` line in the `coverage` job of `.github/workflows/go.yml`),
not per package — `grpctransport` is carried by the verifier, so read the total:

```bash
cd workcontext
go test ./... -coverprofile=cover.out -covermode=atomic -coverpkg=./...
go tool cover -func=cover.out | awk '/^total:/ {print $3}'
```

## The wire, and the other implementation

The signed payload is `base64url(JSON payload) + "." + base64url(Ed25519
signature)`, with one fixed snake_case field order. Revisions and epochs travel
as decimal strings so the complete `uint64` domain survives a JavaScript
verifier. Decoding rejects unknown fields and trailing JSON.

`codefly-dev/core` also has a `workcontext` package. It signs **deterministic
binary protobuf**, not this JSON, so a token from one fails *signature*
verification in the other — the error reads like a key-rotation problem and is
not one. The host (`accounts`, `auth-gateway`) imports this module, so this is
the production wire; core's package is not on any live path. Anything that adds
a claim must add it to the payload struct pair in `work_context.go`, because a
field present only in the proto is dropped at mint and absent at verify.

The golden tokens in `work_context_test.go` are shared byte-for-byte with
sdk-js. A change to the payload changes them, and sdk-js must be regenerated in
the same round.
