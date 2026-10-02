# `workcontext`

The client side of the Work Context capability: the mint-once client a module
process obtains its one credential with, the carriers that take it to a callee,
and typed access to the one implementation of the capability itself.

**This module mints nothing and verifies nothing.** The Work Context is a core
proto, and `github.com/codefly-dev/core/workcontext` is its only
implementation — the only code that signs one, the only code that checks a
signature, the only encoding of either. What this module exports as a
verification entry point *is* core's, by type alias.

It is a separate Go module so a consumer can import
`github.com/codefly-dev/sdk-go/workcontext` without inheriting the root SDK's
transitive tail. Four direct dependencies: `codefly-dev/core` (the
`codefly/base/v0` proto types **and** `core/workcontext`), `protobuf`,
`testify`, `grpc`. The gRPC carrier lives in `workcontext/grpctransport` so a
consumer that never makes a gRPC call does not compile grpc.

Importing `core/workcontext` pulls `protovalidate` → `cel-go` → `antlr`, which
this module used to avoid. That was a deliberate trade and it was made the
other way on purpose: the dependency budget existed to keep a verify-only
consumer's `go.sum` small, and a second implementation of a signed credential
is not a price worth paying for it.

## One implementation, and the gate that keeps it that way

A wire contract has exactly one implementation, in the repository that owns the
type. Nothing outside `core/workcontext` may sign, verify or re-encode a Work
Context.

That is written down because it was broken. A second implementation lived in
this module and signed a **hand-written JSON payload** while core signed the
**deterministic protobuf encoding** of the same message. Both forms are
`<base64url payload>.<base64url signature>` with an Ed25519 signature, so a
token from either looked well-formed to the other and then failed **signature**
verification. "Signature does not verify under key X" reads like a rotated key
or a wrong trust root, so keys are what everyone investigated, while the actual
problem was two encodings of one message. The host signed with this module's
format, so a field added only to core's proto was dropped at mint and absent at
verify on every live path.

A comment would not have stopped that, and did not. Two tests do.

**`TestNoSecondWorkContextImplementation`** parses every non-test file in this
module and fails if any of them:

- imports `crypto/ed25519` or `crypto/ecdsa` — this module neither signs nor
  checks a signature, so nothing here needs a signing primitive;
- imports `encoding/json` outside the one allowlisted file, `mint.go`, which
  speaks the mint endpoint's HTTP bodies and never encodes a capability;
- declares a json-tagged struct other than the mint endpoint's request and
  response — a struct whose tags enumerate a capability's fields by hand is
  exactly the deleted implementation, and is how a field present in the proto
  came to be missing on the wire;
- declares a type or func named `WorkContext*` that is not an alias of core's.

It also pins the aliases by assignment (`var _ *corework.Verifier =
(*Verifier)(nil)`), which compiles only while `Verifier` is core's type and not
a local copy with the same fields.

**`TestWorkContextConformance`** runs `core/workcontext/conformance.RunWith`
against the verification entry point this module exports. The kit drives **21
fixtures** through it — every token form (session, operation, delegated,
delegated-operation, grant) and every negative case, including a stale and a
*future* installation revision, because the seal is compared for exact equality
and there is no legitimate way to hold a capability sealed ahead of live — and
fails the build if any outcome or any named sentinel differs. The single-use
grant fixture is presented twice against one replay store, so a verifier
without a working one passes the other twenty and fails exactly there. The decisive fixture is the foreign encoding: a JSON-shaped
token that must be refused **before** its signature is checked, with
`ErrNotACoreToken`. A second implementation refuses that token too — as a
signature failure, which is the misdiagnosis the whole rule exists to prevent.
That is why the gate lives here, in the consumer: core cannot see who
re-implements it.

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
required. A capability missing one does not verify, and `Attach` refuses to put
it on a request at all — there is no request on which an unsealed credential is
better than no credential.

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

Verification is core's, and what this module exports is core's:

```go
// workcontext.Verifier IS github.com/codefly-dev/core/workcontext.Verifier.
verified, err := verifier.Verify(ctx, token) // *workcontext.Verified, or a refusal
```

```go
verifier := &workcontext.Verifier{
    Issuer:    issuer,
    Audience:  myAudience,
    Keys:      publicKeysByKeyID,

    // All four are required. A verifier missing one refuses everything rather
    // than skipping that check, because a verifier that silently skipped the
    // seal check would make the strongest check in the model the easiest one
    // to omit.
    Revisions: revisions, // the issuer's authorization revision
    Replay:    replay,    // consumes single-use capabilities
    Grants:    grants,    // resolves an approval a grant capability claims
    Seals:     seals,     // the live installation, epoch, build and binding state
}
```

**That shape is issuer-shaped, and it is a real cost for a consumer.** A
component that holds those four locally — the host — supplies them from its own
state. A verify-only module does not hold them, and must back them with calls
to whoever does: `RevisionSource`, `GrantSource` and `SealSource` are narrow
interfaces for exactly that reason, so an implementation can be an RPC.
`ReplayStore` has to be durable and shared when more than one process verifies,
or single-use is not single use.

Core ships `FixedRevision`, `MemoryReplayStore` and `MemorySealSource` as real
implementations for tests and single-process cases. **`FixedRevision` is not a
production stand-in**: it answers one number forever, so it accepts a
superseded capability. A consumer that reaches for it in a deployment has
turned revocation off.

Scope comes last, from the verified capability, through core's scope algebra:

```go
if !workcontext.ScopeContained(
    &basev0.WorkScopeV1{ResourceKind: "record", Actions: []string{"append"}, ResourceIds: []string{recordID}},
    verified.EffectiveScopes(),
) {
    return errRefused // the capability is good and does not cover this call
}
```

`verified.EffectiveScopes()` is the current actor's hop, or the owner's
delegated authority when no hop has narrowed it. Asking core rather than
walking the actor chain is what keeps one answer to "what does this caller
hold".

### Exact binding, not scope search

An operation capability names one binding, at one revision, in one incarnation,
and verification resolves that identity against the seal source. It never
searches for a binding whose scopes would admit the call: a capability sealed to
binding X presented as binding Y is refused **even when Y's scopes are a
superset of X's**. Scope containment is not binding identity, and a revoked
narrow capability must not validate through a wider binding.

Core's `SealSource` deliberately has no method that lists bindings or finds one
matching a set of scopes. Making the search unexpressible through the interface
is what keeps it out: a search is a predicate somebody writes, and a predicate
one case too generous grants authority nobody reviewed.

### The refusals

They are core's, re-exported here so `errors.Is` answers the same through
either import path.

| Sentinel | Means | What the caller does |
| --- | --- | --- |
| `ErrInvalid` | wrong and cannot become right — bad signature, another audience, another installation, another build, another binding id, a malformed capability | refuse; 401 |
| `ErrRevoked` | sound when minted, overtaken since — the principal's epoch, the installation revision, the build incarnation, a binding revision or incarnation, a revoked binding, or the authorization revision moved | mint again, retry once |
| `ErrUnsealed` | the capability carries no seal, or names no installation | refuse; it is not a credential |
| `ErrNotACoreToken` | the payload is not this encoding at all — most usefully, a JSON one | refuse, and do **not** report a signature problem |
| `ErrReplayed` | a single-use capability was presented twice | refuse; this is the resume contract, not a forgery |

Two of those deserve a note, because getting either wrong costs an outage.

**`ErrRevoked` is one sentinel for six reasons, deliberately.** In every one of
them the capability was sound when it was minted and the state moved under it,
so the holder's response is identical: mint again. A caller needs to tell "mint
again" from "this caller is not authorized" — those read differently. It does
not need the six reasons for a re-mint to read differently from each other, and
a caller branching on them would be writing a policy nobody reviewed. **This
module no longer defines a `superseded` sentinel of its own**; `ErrRevoked` is
it.

**`ErrNotACoreToken` does not wrap `ErrInvalid`.** `errors.Is(err,
ErrInvalid)` is false for it, on purpose, so "this is another format" and "this
capability is bad" are not reachable from one branch. A gateway should log the
reason by name: the symptom this prevents is a token that looks valid and fails
signature, and it cannot recur if the look-alike never reaches the signature
check.

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
        // The same verification an ordinary call performs, against the
        // issuer's state as it is NOW — not the state the stream opened with.
        _, err := verifier.Verify(ctx, token)
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
- `ByViewer()` adds the effective actor — core's `Verified.Actor()`, or the
  owner for a direct call — with its kind, agent identity and organization. Use
  it for anything whose content varies by who is asking: every reader of a
  collection holds the same read scope, and a revision is a number they share.

`WriteAround` is true for a capability carrying an approval **grant hop**. That
hop is the one audited exception to the attenuation rule, so the answer was
computed under authority nobody else holds: caching it would serve an approved
call's result to callers who were never approved, and reading from the cache
would answer the approved call from an unapproved computation.

The key prefix is `wc3:`. It moves whenever the key's composition does — this
time, because the digest preimage became length-prefixed binary rather than
JSON — so a shared cache that outlives the deploy (Redis, a warehouse table)
cannot be reached under the keys it still holds. Those digests are framed field
by field, so no tenant, installation or scope can contain a delimiter and spell
another partition's key.

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
- **Stop verifying through this module.** `WorkContextSigner`,
  `WorkContextVerifier`, `WorkContextJWKSVerifier`, `VerifyWorkContext`,
  `WorkContextExpectations`, `RequireWorkContextScope` and the token type are
  **deleted**, not deprecated. Use `core/workcontext`'s `Verifier`, which this
  module re-exports; a consumer that was verifying here owes the four sources
  above, and that is the honest price of there being one implementation.
- **Stop searching bindings.** Resolve the sealed binding identity. A superset
  of scopes is not a licence to act as a different binding.
- **Stop authorizing from bare claims.** Read claims off a `*Verified` and
  nowhere else. Claims that were never verified, or were mutated after
  verification, cannot reach an authorization decision.
- **Stop writing a second encoder.** If a claim is missing from the wire, it is
  added to the proto in core and mints from there. Nothing in this repository
  assembles, re-encodes or re-signs a capability — the gate above will say so
  before review does.

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
not per package — `grpctransport` is carried by the rest, so read the total:

```bash
cd workcontext
go test ./... -coverprofile=cover.out -covermode=atomic -coverpkg=./...
go tool cover -func=cover.out | awk '/^total:/ {print $3}'
```

Until core#691 is released, this module is pinned to a **pseudo-version of
core's branch** (`go get github.com/codefly-dev/core@<sha>`), not a local
`replace`: a pseudo-version is reproducible for anyone who checks the branch
out, and a `replace` to a worktree is not mergeable. Move it to the release when
there is one.

## The wire

`base64url(deterministic protobuf of codefly.base.v0.WorkContextV1) + "." +
base64url(Ed25519 signature)`, signed by `core/workcontext` and by nothing
else. The sealed fields are proto fields — `seal.principal_epoch`,
`seal.installation_id`, `seal.installation_revision`,
`seal.build_incarnation`, and for an operation capability
`operation_binding.binding_id` / `.revision` / `.incarnation`, all three
together or none.

This module reads a capability's seal and lifetime in one place (`carrier.go`,
`claimsOf`): core's `CheckEncoding` on the decoded payload, then
`proto.Unmarshal` into core's generated type, and **no signature check**. That
is sound only because nothing trusts the result — it fills the pre-check
carriers, and it tells the mint client when its own freshly issued credential
expires. A receiver that preferred a carrier over the sealed claim would have
made a caller-controlled header into authority, which is why the incoming side
refuses a disagreement instead.

`CheckEncoding` is core's and is called rather than reimplemented, so a token in
another format is named `ErrNotACoreToken` **here too**. Two decoders giving an
operator two different messages for one condition is the same diagnostic
fragmentation as the two encodings, in miniature.

There are no cross-language golden tokens in this module any more. They went
with the implementation that produced them: core mints its conformance fixtures
fresh on every call, because a committed token carries a validity window and
would eventually fail for the wrong reason.

**Adding a claim**: add the field to the proto in `codefly-dev/core`, mint it
from `core/workcontext`, and add a fixture for it there. There is nothing to
change in this module, which is the point — the failure that made this rule was
a field that existed in the proto and in nobody's encoder.
