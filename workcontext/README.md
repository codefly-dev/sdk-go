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
module and refuses it **by what the code can do, not by what it is called**.
That distinction is the whole of it: the first version listed two package paths
and a case-sensitive name prefix, and a faithful clone of core's signer —
`proto.MarshalOptions{Deterministic: true}` plus `golang.org/x/crypto/ed25519`
— was green, as were `crypto/rsa`, `crypto/hmac`, the bare `crypto` package
(whose `crypto.Signer` signs Ed25519 with no ed25519 import), `protojson`, and
the deleted implementation's own type name `workContextPayload`.

It fails a file that:

- imports **any** signature, MAC or key-agreement primitive, anything under
  `golang.org/x/crypto/`, or any JOSE/JWT/token library, whatever the paths are.
  `crypto/sha256` is deliberately fine — a hash is not a signature;
- imports `crypto/tls` or `crypto/x509` anywhere but `mint.go`, which builds the
  mint client's own transport — **and uses only the symbols a transport needs**,
  so `x509.ParsePKCS8PrivateKey` followed by a `crypto.Signer` assertion, the
  shortest signer that imports no primitive at all, is a finding;
- imports `encoding/json` outside `mint.go` — matched by **exact path relative
  to the module root**, since a base-name match let any nested `mint.go` inherit
  the allowance;
- calls `proto.Marshal` or `proto.MarshalOptions` outside the one file that
  encodes a scope for a cache digest. Encoding the message is half a signer;
- declares a json-tagged struct other than the mint endpoint's two bodies,
  **anywhere in the file** including an anonymous struct or a type inside a
  function;
- declares anything — func, method, var, const or type — whose name begins with
  `workcontext` **case-insensitively**, unless it is in a named allowlist with a
  reason, or is a type alias **whose target resolves into
  `github.com/codefly-dev/core`**.

It also pins the aliases by assignment (`var _ *corework.Verifier =
(*Verifier)(nil)`), which compiles only while `Verifier` is core's type and not
a local copy with the same fields.

**`TestTheGateCatchesItsOwnBypasses`** drives twenty-one hostile sources through
the checker and two that must stay allowed, so the gate is held to its claim
rather than trusted about it. Each of the standard bypasses above was measured
to pass the previous version and fail this one.

**`TestWorkContextConformance`** runs `core/workcontext/conformance.RunWith`
against a verifier built **field by field from the kit's settings as this
module's exported `Verifier`** — not through `conformance.Settings.Verifier()`,
which returns core's own and would have passed unchanged beside the
implementation this module deleted. The kit drives every fixture it carries
through it (the count moves as core adds cases; read it, never pin it) — every token form (session, operation, delegated,
delegated-operation, grant) and every negative case, including a stale and a
*future* installation revision, because the seal is compared for exact equality
and there is no legitimate way to hold a capability sealed ahead of live — and
fails the build if any outcome or any named sentinel differs. The single-use
grant fixture is presented twice against one replay store, so a verifier
without a working one passes everything else and fails exactly there. The
decisive fixture is the foreign encoding: a JSON-shaped token that must be
refused **before** its signature is checked, with `ErrNotACoreToken`. A second
implementation refuses that token too — but only after reading a key id out of a
payload it cannot read, so it refuses as "unknown key" or "signature does not
verify", which is the misdiagnosis the whole rule exists to prevent. The
signatures were never the problem: each implementation signed and verified the
bytes it handled. The key id is a field *inside* the payload, which is why
naming the format before any key lookup is the only diagnosis that points at the
format. That is why the gate lives here,
in the consumer: core cannot see who re-implements it.

**One field in that build is load-bearing and easy to miss.**
`TrustTheConformanceFixtureKey` must be copied from the settings: the fixture
key's private half is derivable from core's source, so a verifier refuses it
unless it says in as many words that it is a test. Leaving it out made all 35
fixtures fail with *"key `conformance-1` is the conformance fixture key"* — a
consumer doing exactly the right thing refusing everything.

Which is the argument **for** building the verifier field by field rather than
calling `settings.Verifier()`: a field core adds to the contract lands here as
a failing test. Through the constructor it would have been inherited silently
and this module would have learned nothing.

What the kit proves is **behavioural**: this entry point reaches core's
accept/refuse decision with core's named reason on every fixture. It does not
prove identity — an equivalent second implementation would pass the same
fixtures. Identity is the compile-time assertions (`var _ *corework.Verifier =
(*Verifier)(nil)`) and the static gate. Two halves, claimed separately.

**`TestTheSDKParsePathsAgreeWithCore`** drives every fixture in core's kit
through **this module's own parse paths** and requires core's declared sentinel
for each.

This is the test the conformance run is not. Driving fixtures through
`&Verifier{}` exercises core, because `Verifier` is an alias of core's type —
and the module's real decisions are in `SealedInstallation`, `FromHeaders`,
`Attach` and `credentialFrom`. Three divergences lived exactly there, and all
three are now core's answer rather than a local one:

| fixture | core | this module, before |
| --- | --- | --- |
| `seal-without-installation` | `ErrInvalid` (the schema reaches it first) | `ErrUnsealed`, with a test pinning the divergence |
| `actor-without-epoch` | `ErrInvalid` | **accepted** — the actor chain was never read, so a principal nobody can revoke went on the wire |
| zero epoch / revision / incarnation, partial binding | `ErrInvalid` | `ErrUnsealed` |

**The seal is four fields, and `ImageDigest` is one of them.** `WorkSealV1`
gained `image_digest` as a **required** field: a seal names the approved build
for its installation, and a mint attests the execution it is actually running
against it (`StartInput.Execution{ImageDigest, BuildIncarnation}`). A seal that
names no digest names no execution to match a caller against, so core refuses
to record one. `Credential.Seal()` returns the carried seal as core's own
message, which is why that field arriving needed no code change here — see
`SealedValues`.

**`ErrUnsealed` no longer exists, and that is the end of this class of defect.**
`WorkContextV1.seal` and `WorkActorV1.principal_epoch` are schema-**required**
now, so `protovalidate` refuses a missing seal or a missing actor epoch inside
core's decode before any branch that could have produced `ErrUnsealed` runs. A
sentinel no branch can produce is worse than none — you write a handler and the
handler never runs — so it is deleted, and **every structural seal defect is
`ErrInvalid`**. One sentinel, one branch.

This module needed no edit for that change, which is the argument for reading
sentinels off core's kit rather than writing them down: three fixtures changed
sentinel and the tests that assert `declared.Err` did not move.

The fix was not to sync the rule. **`corework.Decode` now owns every
structural decision** — shape, encoding, schema, attenuation, grant shape, a
seal naming an installation, an epoch on every actor hop — and this module's
`readClaims` runs after it, reads two values, and decides nothing. Core added
`Inspect` for this, when asked; the twelve structural refusals must reach core's
sentinel here, and every other fixture must **pass**, because an unverified
inspection that refused a signature or a live-state failure would be claiming to
have verified something it cannot see. `Inspect` checks no signature at all —
core's own test asserts a token re-signed with a key nobody holds passes it — so
nil means *shaped right*, never *permitted*.

**And one sweep, because the test above walks from this module's root.** The
implementation this repository deleted lived at the REPOSITORY root, in package
`codefly` — exactly where that walk does not reach.
`scripts/check-one-implementation.sh` sweeps every tracked Go file in both
modules, as a job in `go.yml` — the workflow that builds every ref this
repository publishes — and it is **required on `main` by an active ruleset**.

It sweeps **every other ref this repository publishes** too, through
`scripts/sweep-published-refs.sh` — a script rather than inline shell because
the inline version was wrong for weeks and nothing could test it. It listed
refs with `git for-each-ref 'refs/remotes/origin/*'`, and **`*` does not cross
a slash**, so every namespaced branch was silently dropped. CI printed
`sweeping 1 other published ref(s)` / `ok origin/badges` and the required check
went green while `origin/dependabot/go_modules/gomod-06d3dc2861` published
`workcontext/work_context.go` importing `crypto/ed25519`.

Two things follow, and the second matters more. Refs are listed **by prefix**,
so a namespaced ref is included. And **swept is asserted against what the
remote publishes**: a gate that sweeps a subset and reports success is worse
than no gate, because the green is the evidence somebody acts on. A mismatch
fails. Both properties have tests —
`TestTheRefSweepSeesNamespacedBranches` and
`TestTheRefSweepRefusesWhenItCanSeeFewerRefsThanExist` — because listing
correctly is a property somebody can break again.

**That step fails today**, on `origin/dependabot/go_modules/gomod-06d3dc2861`,
which still carries the deleted implementation. Under "legacy means delete" a
published ref that cannot meet the rule is **deleted by the owner**, and `main`
does not move while the rule is false of something this repository publishes.
The base ref and the ref under review are excluded: sweeping the branch a pull
request merges into is circular, since `main` carries the implementation until
this change deletes it, and `main` is covered by the working-tree sweep of its
own push build.

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
mintURL, _ := authority.Value("platform", "mint-url")

client, err := workcontext.NewMintClient(workcontext.MintOptions{
    URL:       mintURL,
    Authority: authority, // REQUIRED: rechecked before every mint, including the first
    // The audience is NAMED, not passed. It is read from the pin on every
    // mint, so the value that reaches the host is the pinned value.
    Audience: workcontext.AuthorityValue{
        Name: "platform", Key: "work-context-audience",
    },
    ProjectedToken:     workcontext.ProjectedTokenFile("/var/run/secrets/codefly/token"),
    ProjectionAudience: projectionAudience,
    // REQUIRED: sources of current trust roots, workload X.509-SVID,
    // and admitted mint endpoint SPIFFE IDs. Re-read per handshake.
    TrustAnchor:       readPlatformRoots,     // func() (*x509.CertPool, error)
    ClientCertificate: readWorkloadSVID,      // func() (*tls.Certificate, error)
    AdmittedPeers:     readAdmittedMintPeers, // func() ([]string, error)
})
```

**`Authority` is required and the audience is read from it.** A free-string
audience beside an optional pin made the drift check guard a value the mint did
not use: `Recheck` could pass while the credential was minted for whatever
string the caller had typed. Reading it through `Value` on every mint is what
makes the pin load-bearing, and `credentialFrom` then requires the audience the
host SIGNED to be the audience the pin answered.

`URL` must be **absolute https** with no userinfo, query or fragment: the
projected service-account token travels on that request as a bearer credential,
so plaintext is a disclosure the configuration must not be able to choose.

**The SDK owns the mint transport.** Callers provide `TrustAnchor`,
`ClientCertificate` and `AdmittedPeers` sources; all three functions are
required. `NewMintClient` returns `ErrInvalid` for a missing source and reads
no sources. Every source answer is validated during dialing.

Every mint, renewal and refresh opens a **new TLS 1.3 connection**. The SDK
reads the current anchor for the handshake, presents the workload's current
X.509-SVID through `GetClientCertificate`, and reads the current admitted peer
set in `VerifyConnection`, **after Go has verified the chain and hostname**.
After the handshake, it reads the anchor and peers again, re-verifies the
certificate chains and hostname against those roots, and repeats admission
before handing the connection to HTTP. The endpoint must request a client
certificate. There is no system-root fallback, connection reuse, TLS session
resumption, compression, proxy or followed redirect. HTTP/1.1 keeps requests
on separate connections without HTTP/2 multiplexing. Callers cannot supply an
HTTP client or reach its transport.

Before reading admission, the SDK checks the parsed leaf's X.509-SVID purpose:
it must not be a CA, its KeyUsage must include digitalSignature and exclude
keyCertSign and cRLSign, and any present ExtendedKeyUsage extension must
explicitly include serverAuth. Ordinary Go certificate verification accepts
some of these forbidden purposes, so chain and hostname verification alone
are insufficient. An absent EKU is allowed; an empty EKU or anyExtendedKeyUsage
without serverAuth is refused.

The leaf must carry **exactly one URI SAN**, a valid admitted SPIFFE ID. The
SDK validates its original bytes from the signed SAN extension: Go's parsed
URL loses an empty fragment delimiter, so serializing that URL is unsafe here.
IDs must have the form `spiffe://<trust-domain>/<path>`; the trust domain uses
ASCII letters, digits, dots, hyphens and underscores, with no empty labels.
Scheme and trust-domain case are ignored, but paths are compared
**byte-for-byte**. Empty segments, trailing
slashes, dot segments, userinfo, ports, queries, fragments and percent-escapes
are refused, never normalized into admitted identities. Any malformed admitted
entry is `ErrInvalid`, checked at the handshake even alongside a valid entry.

An unreadable anchor or client certificate, nil anchor, empty or unreadable
peer set, invalid admitted identity, or failed TLS verification refuses the
request with **`ErrMintUnavailable`** (also wrapping `ErrInvalid` for malformed
admitted identities). A leaf with a forbidden SVID purpose or an invalid,
ambiguous or unadmitted SPIFFE ID also wraps **`ErrMintPeerNotAdmitted`**,
available through `errors.Is`.
These failures never latch and deliver no HTTP headers or body, including
the projected token in `Authorization`.

Source waits honor the dial and request contexts. Cancellation closes the raw
connection even if a source or private-key operation is blocked. The three
transport sources and the TLS operations they trigger share **one outstanding
worker per client**, retaining its slot through the entire handshake and
post-handshake checks. Retries check the occupied slot before dialing and
refuse immediately without a connection attempt while it is occupied. An
arbitrary callback or signer cannot itself be interrupted; cancellation bounds
the wait, and the slot is released only when the worker returns. Late answers
are discarded. Subsequent attempts read fresh values and can recover.

A root or peer withdrawal during the handshake is caught by the
post-handshake check. Each source value's residual freshness interval begins
when that value is sampled and ends at the transport's first HTTP write. The
recheck shortens it to the **re-read-to-write window**, including later source
waits: the second anchor is sampled before the second peer callback, which may
block while that anchor is withdrawn. Independent sources do not provide a
coordinated snapshot; stronger consistency requires a shared snapshot/version
check. Withdrawal in this interval cannot retract an in-flight request.
Every new mint, renewal and refresh repeats both checks. Tests capture
HTTP disclosure at the server, withdraw peers and rotate roots inside the
handshake, and verify deadlines, connection closure, bounded reads and recovery.

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

`Credential` mints the first credential and renews one that has reached its
renewal point, so no caller obtains a credential the client knows to be past
that point. It is **not** a guarantee about a credential a caller already holds:
`Credential` is a value, so one read out and kept can be attached after the host
has moved the state under it. That is what `Refresh` is for, and it is why a
receiver verifies rather than trusting that a caller re-asked.

Every mint re-reads the projected token and rechecks the pinned authority — the
first one included, because a client constructed at boot may not be asked for a
credential until an hour later and the value can have moved in between. A
drifted value refuses the mint instead of being sealed into a new credential.
`Authority` is optional; without it there is no pin for the client to check,
which is why a process that resolved its audience through `ReadAuthority` should
pass it.

A credential is also checked against **its own window** before it is installed:
an expired or not-yet-valid response, or one whose whole lifetime sits inside
the renewal lead, is refused rather than held and counted as a mint that
worked. The window tested is
**`not_before`** — the claim core's verifier tests; testing `issued_at` was
testing a different window from the one the credential would be judged against
— and the tolerance is `core/workcontext.DefaultSkew`, so the client is not
stricter than the verifier that will accept the credential.

### A failed renewal is not an outage

**A held credential that is still valid is served even when a renewal fails.**
Entering the renewal lead and getting a 503 used to return an error to every
caller while the credential in hand had minutes left — an outage manufactured
out of a credential that still worked. A renewal failure is only an error once
the credential has actually expired.

One mint at a time, and **the wait is cancellable**: callers wait on a channel
rather than on the client's mutex, so a caller whose `ctx` is cancelled stops
waiting instead of blocking on a request it is not making. After a failure the
next attempt is **held off**, doubling to a minute. Without that, a host
answering 503 received one request per caller per call — the heartbeat under
another name, arriving exactly when the host was least able to serve it.

**The request itself is detached from the caller that started it,** bounded by
`RequestTimeout`. It used to run on the leader's own context, and a cancelled
leader was then a case of its own — no failure, so no hold-off, and *never
served the credential it was holding*. Three consequences, all measured:

- one mint request per caller deadline. A reviewer ran a host at 250 ms latency
  against callers with 20 ms deadlines and counted **94 requests in two
  seconds, all 94 completed host-side** — single-flight caps concurrency, not
  rate — each one minted, audited, and discarded. With eight concurrent callers
  it was 752 calls and the same 94 requests.
- a refusal arriving just after its caller gave up was discarded, so the next
  caller presented the projected token to a host that had already refused it.
- **20 of 20 callers failed in the renewal window while holding a credential
  with two minutes left.** A cancelled *waiter* was served that credential, so
  the two paths disagreed about the same credential.

Detached, there is no leader: whoever takes the slot waits on the same channel
as everybody else and is answered by the same `servableLocked`. The request
completes once, is classified once, and installs for everybody.

**Latching is the enumerated case, not the default.** `ErrMintRefused` is
terminal — a process that sees one must stop serving — so the rule for which
HTTP statuses earn it used to be inverted: 429 and 5xx were retryable and
*everything else* was a permanent stop. Measured: a **408 from a proxy**, with a
valid credential in hand, refused, did not serve, and latched for the life of
the process. A 425, a 404 from an ingress mid-rollout, or a 502 rendered as 400
by a sidecar would each do the same. Only **401** (the projected token is not
acceptable) and **403** (the host authenticated this process and refused it)
latch now; every other status is an outage. The cost of being wrong is
asymmetric — a wrong "retryable" costs one request per hold-off, and a wrong
"terminal" costs the process. A refusal this client decides for *itself* — an
audience that does not match the pin, a seal the host contradicted, a refused
redirect, a certificate that did not verify — still latches, because those are
its own verdicts rather than a status somebody in the middle chose.

**`Refresh` has its own rate limit, and it decays.** The generation check does
not bound it: a receiver whose live state lags refuses each FRESH credential, so
every refusal is a new generation. The bound is a token bucket — a burst of
three, refilling one per minute — which bounds the steady state to one mint a
minute while answering an honest revocation at once. It used to be the failure
backoff computed from the lifetime refresh count, which never decayed: after a
few legitimate refreshes the bound was a minute *permanently*, so a refresh days
later still waited for a receiver that had lagged that morning. That is a tax,
not a rate limit.

**The lifetime bound is CORE'S, in the one decode path, and this client's
option is a deployment policy.** Core's `MaxTTLCeiling` (24h) is absolute:
`Authority.maxTTL` clamps to it, `Start` refuses a TTL beyond it, and — since
core `67ee7220` — `decodeClaims` refuses a capability whose window is wider,
so `Verify`, `Authenticate` **and `Inspect`** all refuse it with one message.

That last one is what matters here, and it is the third place core put this
bound. The argument this module made twice for keeping a client-side ceiling was
that **a mint client never verifies a signature** — it is the party the
credential is minted *for*, not a receiver — so it reads its own window through
`corework.Decode`, which was structural and checked no lifetime. Core's first
two attempts bounded `Authority.Start` and then `Verify` alone, neither of which
this client can see. A thirty-day capability that every `Verify` refuses was
reported to its **holder** as thirty days of validity: an absent bound tells a
caller nothing, and that one told it something false about the only field it
calls `Inspect` to read.

With the bound in `decodeClaims`, an over-ceiling lifetime is refused in this
client's own read path before `checkWindow` runs. So the net is core's.
`MintOptions.MaxCredentialLifetime` survives as a **deployment policy** — a
process that will hold a credential for at most five minutes says so — and it
defaults to `corework.MaxTTLCeiling`, read from core, so there is no second
number to drift. A value above core's ceiling is refused at construction, and a
credential at *exactly* the ceiling is accepted, which this module pins with its
own test rather than taking on trust: the default is core's constant, so a
second of slack either way would refuse every credential a host mints at the
maximum.

**The ceiling's effect on #47's arithmetic:** at `Authority.MaxTTL`'s default
of **one hour**, a process that runs for an hour costs one mint and one renewal
— so the issue's "one audit event per hour" criterion is not reachable by
holding a credential longer unless the host raises `MaxTTL`, within core's 24h
absolute ceiling. That is the host's configuration decision and this module
cannot make it; it is named in the pull request as an open question for the
issue's owner rather than silently satisfied.

**That ceiling changes #47's acceptance arithmetic, so read it before sizing.**
One mint across an hour of calls needs a lifetime of at least
`run / (1 - lead)` — 75 minutes at the default 0.2 lead — so **at core's
default one-hour cap, "exactly one mint for an hour's run" is not reachable**:
an hour of calls costs one mint and one renewal. That is the ceiling working.
The heartbeat this replaced made 240 requests an hour per surface; two is not
one, and it is also not 240. Both shapes are asserted
(`TestAnHourOfCallsCostsOneMintAndOneRenewalAtCoresDefaultCeiling` and
`…WhenTheHostMintsLongerThanTheRun`), because a consumer sizing this needs to
know which one its host has chosen.

### When the host refuses the credential you hold

`ErrRevoked` from the far end means the credential was sound when it was minted
and the state moved under it. Hand the refused credential back:

```go
credential, err := client.Credential(ctx)
// ... the call is refused with ErrRevoked ...
credential, err = client.Refresh(ctx, credential)
```

`Refresh` is tied to the credential that was refused, not to the clock. If the
client has already replaced that one, the replacement is returned and nothing is
minted — so a burst of concurrent refusals on one credential produces exactly
one replacement mint, and a caller holding a credential two generations old
cannot roll the client backwards. It rechecks the pin and re-reads the
projection like any other mint, and a refused replacement leaves the credential
already held in place rather than clearing it.

`client.Counts()` returns `MintCounts{Mints, Renewals, Refreshes}`. A correct
execution reports exactly one mint.

`Attach` sets `x-codefly-work-context` and, beside it,
`x-codefly-installation-id` / `x-codefly-installation-revision`. The gRPC
transport sets the same names as metadata. Those two carriers are a **pre-check
the host may refuse on cheaply, and never authority**: the installation that
governs a call is the sealed one. On the incoming side the SDK refuses when a
carrier disagrees with the sealed claim rather than preferring either side.

**Both carriers are required, exactly once each, on both transports.** Carrying
neither used to be allowed on HTTP, which was the optional-carrier escape hatch
surviving there after it was deleted on gRPC — "one contract for both
transports" was false, and a sender that attached nothing skipped the pre-check
entirely. Cardinality is checked before agreement, because `Header.Get` reads
only the first value: `[sealed-id, something-else]` compared equal to the seal
while the request carried two contradictory installations.

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
| `ErrInvalid` | wrong and cannot become right — bad signature, another issuer, another audience, a schema violation, **no seal at all**, a seal naming no installation or no image digest, a zero epoch/revision/incarnation, a partial binding, **an actor hop with no epoch**, **an unknown field or a non-canonical encoding**, a malformed capability, an expired or not-yet-valid window | refuse; 401 |
| `ErrRevoked` | sound when minted, overtaken since — the principal's epoch, an actor hop's epoch, the installation revision, the build incarnation, a binding revision or incarnation, a revoked binding, **a binding granted to another principal or in another installation**, an installation the principal no longer holds, or the authorization revision moved | mint again, retry once |
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
re-presents the credential **before every message** and terminates on refusal,
rather than draining a snapshot computed under authority that has since been
replaced — the failure mode it exists to prevent is the silent one, where
nothing errors and the data keeps arriving.

There was a re-check cadence here, and it was a weakening of the rule rather
than an implementation of it: revoke the installation one second after a
successful check and every message for the next interval still left, with expiry
and source unavailability equally invisible for that whole window. The condition
is per emission, so the check is per emission.

**Use `RecheckWith`, never `Verify`.** The recipe this README carried called
`verifier.Verify` on every emission. Core's `Verify` **consumes** a single-use
nonce and every grant capability is single-use, so a grant-opened stream died
with `ErrReplayed` at its **first** message — and the error read like a replay
attack rather than like the guard eating its own credential. Core added
`(*Verifier).Recheck` for this: it re-reads the window, the authorization
revision, the seal, every actor hop's epoch, the operation binding and the
issuer's grant record, and it never touches the replay store. It takes a
`*Verified`, so it cannot be anybody's first check.

```go
// verified came from verifier.Verify once, when the stream opened.
guard, err := workcontext.NewStreamGuard(workcontext.StreamGuardOptions{
    Recheck: workcontext.RecheckWith(verifier, verified),
})

// And let the SERVER enforce it, rather than each handler remembering to.
//
// DECLARED at construction: every method whose streams carry a capability. A
// method in this list is guarded or its stream is refused; a method outside it
// reaches the handler UNGUARDED, which is why the validation below is not
// optional and is not skippable.
bearing := []string{"/codefly.example.Streamer/Emit"}

streams := grpctransport.GuardStreams(bearing,
    func(ctx context.Context, info *grpc.StreamServerInfo) (*workcontext.StreamGuard, error) {
        verified := verifiedFor(ctx) // from the server's own stream setup
        return workcontext.NewStreamGuard(workcontext.StreamGuardOptions{
            Recheck: workcontext.RecheckWith(verifier, verified),
        })
    })

server := grpc.NewServer(grpc.StreamInterceptor(streams.Intercept))
pb.RegisterStreamerServer(server, impl)

// REQUIRED, after registering and before Serve. Until this passes, Intercept
// REFUSES EVERY STREAM — because an earlier revision of this recipe left the
// call out, and a consumer following it kept the fail-open the call exists to
// close. grpc forces the ordering (the interceptor is built before
// registration, the served set exists only after), so the gap is made loud
// instead of silent.
//
// It asks the server three things the interceptor cannot see from inside one
// request:
//
//   - a declared name the server does not serve is a typo, and guards nothing;
//   - a declared name that is unary guards nothing and makes the set non-empty;
//   - a SERVED stream that is neither declared nor named below is a decision
//     nobody made.
//
// A stream that genuinely carries no authority is named here, so the decision
// lives in the source rather than in somebody's memory.
if err := streams.Validate(
    server.GetServiceInfo(),
    "/codefly.example.Streamer/Health", // deliberately unguarded
); err != nil {
    return err
}

// The handler then just sends. It is handed the wrapper, it has no route to
// the raw stream, and the interceptor calls Finish.
func (s *server) Emit(_ *pb.Request, stream pb.Streamer_EmitServer) error {
    for message := range messages {
        if err := stream.Send(message); err != nil {
            return err // terminated; do not resume
        }
    }
    return nil
}
```

**The method set is declared, not learned.** The previous revision asked
`guardFor` per request and took the FIRST answer for a method as binding —
trust on first use, and it failed the way trust on first use always fails. A
first request arriving without a capability (a client mid-deploy, a health
probe, a retry that lost its metadata) got `(nil, nil)`, **was handed the raw
stream**, recorded the method as unguarded, and every later legitimate request
was refused `codes.Internal` until the process restarted. One early request
both bypassed the guard and took the method down. A server that cannot
enumerate its capability-bearing methods does not know which of its streams
carry authority, which is the thing to fix before installing an interceptor.

**Use the interceptor, not `Guard` directly.** This README's previous recipe
called `Guard` in the handler, which leaves the original stream in scope, never
calls `Finish` — so every trailer the handler set was silently dropped — and
cannot replace the context, so the package-level `grpc.SetHeader`,
`grpc.SendHeader` and `grpc.SetTrailer` still wrote straight to the transport.
`Guard` remains exported for a server doing its own wrapping; if you use it,
you must call `Finish` and must pass the wrapper's `Context` to anything that
writes metadata.

`grpctransport.Guard` wraps a `grpc.ServerStream` so `SendMsg` **is** the
re-check followed by the send. A guard on its own is advice: `BeforeSend` has to
be called, and "before each emission" was therefore something each author had
to remember — the same shape as the optional carrier this PR deleted, a rule
that holds wherever somebody thought of it. A handler writing through the
wrapper cannot emit without the check. `Guard` refuses a nil guard rather than
treating it as "no guarding wanted", because a wrapper that silently did
nothing would be worse than none: the call site would read as guarded.

It guards emission rather than running a timer: an idle stream discloses
nothing, so there is nothing to refuse. **Any** error from `Recheck` terminates,
including one that is neither `ErrRevoked` nor `ErrInvalid` — a live source that
could not be reached has not said the credential is good, and treating "I could
not ask" as a pass is how a stream outlives its authority with clean logs.
Termination is sticky: a caller that loops past the first refusal is not handed
a second chance to emit, and the authority coming back does not resurrect the
stream.

### There are three routes out of a stream, not one

Each of these was a live bypass of the wrapper, and each was found only after
the previous one was closed. They are listed together because the lesson is that
"the handler calls our method" was never the only way metadata leaves.

| Route | What happened | What closes it |
| --- | --- | --- |
| the embedded field | the wrapper embedded `grpc.ServerStream` publicly, so `stream.(*GuardedServerStream).ServerStream` sent with **no check at all** — a real gRPC probe delivered a message under revoked authority with zero re-checks | the stream is a private field and every interface method is forwarded by hand |
| when gRPC sends | gRPC sends trailers, and flushes a pending header, when the **handler returns** — so a handler could queue, have authority revoked, return, and the client received it. Measured over bufconn: a header queued under authority arrived at the client *after* `Finish` had refused | headers **and** trailers are held in the wrapper and released only by `Finish`, after one last check |
| the context | `grpc.SetHeader`, `grpc.SendHeader` and `grpc.SetTrailer` are package-level functions that resolve a `grpc.ServerTransportStream` out of the context and write to the transport. Measured over bufconn with the guard revoked for the whole call: both a header and a trailer reached the client, and the guard was **never asked** | the wrapper owns the transport stream in the context it hands out, so those three functions route back through the checks |

What stays deliberately open: a server that keeps the original stream from
outside the interceptor, and `SendHeader`'s own flush — once a header frame is
on the wire no later revocation recalls it, which is what `SendHeader` means.

**A refusal reaches the client as a gRPC status it can act on.** Returning the
plain Go error made every refusal arrive as `codes.Unknown` with internal text,
so a receiver could not tell "mint again" from "the server broke" — which is the
only decision the table above asks a caller to make. `ErrRevoked`,
`ErrReplayed`, `ErrNotACoreToken` and `ErrInvalid` become
`codes.Unauthenticated`; a termination for a source that could not be reached
becomes `codes.Unavailable`; and this server's own misuse — a nil guard, a
finished stream, a re-check that tried to write to the stream whose liveness it
was deciding — becomes `codes.Internal`, because the client did nothing it can
correct.

That last split matters more than it looks. `ErrInvalid` was mapped to
`codes.Internal` wholesale on the argument that it covers misuse as well as a
broken capability, and telling a client "mint again" about a server bug makes it
loop. The argument is right and it was applied to the wrong side: core answers
an **expired** capability with `ErrInvalid`, and a stream that outlives its
credential is the ordinary case, not a rare malformed one — it is exactly the
refusal a client answers by minting again. The misuse errors are this package's
own and are constructed here, so they carry their own sentinel and keep the
`codes.Internal` the argument asked for. The sentinel chain is kept alongside
the code, so `errors.Is` still works inside the server that produced it.

What this costs is one live authorization check per message — against an
RPC-backed `SealSource`, one round trip per emitted item. That is the price of
the guarantee, and it is why the guard is for streams whose messages carry
authority rather than for every stream. **Decide it explicitly rather than
discovering it from a latency graph**: per emission catches a revocation at the
next message, per stream catches one only at the start, and core deliberately
does not choose for you. A stream that cannot pay per-emission does not get the
per-emission guarantee; what it must not get is a cadence that reads like one.

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
  of scopes is not a licence to act as a different binding. Note the two types:
  `SealedOperationBinding` is what a capability CARRIES (id, revision,
  incarnation) and `OperationBinding` is the LIVE state an issuer holds (those
  three plus the principal it is granted to, the installation it is granted
  within, and whether it is revoked). They are deliberately different, because a
  client filling the live type from a token would hand a reader an empty
  `PrincipalID` that reads as "granted to nobody" rather than as "the wire does
  not say".
- **Stop extracting attribution optionally.**
  `GRPCExecutionContextFromIncomingIfPresent` is **deleted**. A
  capability-bearing path requires the capability, so a call carrying no
  carriers at all is refused exactly like one carrying half of them. A consumer
  that relied on `present=false` now fails to compile rather than silently
  keeping its old path, which is the point.
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

The `one implementation` sweep is a required check and runs at the repository
root:

```bash
./scripts/check-one-implementation.sh
```

### Core release dependency

Both `workcontext/go.mod` and the root SDK pin **core v0.13.0**, the release
tag at `f2423c9c7f71481952e246dcda0652e1fe97f2f4`. This tag supplies the sealed
Work Context implementation, `Inspect`, verification and re-check entrypoints,
the lifetime ceiling, and the conformance kit exercised by this module. No
unreleased core pin is required.

The core dependency version is separate from the SDK leaf's own version:
Go releases this module with a `workcontext/vX.Y.Z` tag. A root SDK tag does not
release the leaf. Release through `codefly publish`, which owns the tags and
pre-flight gates; use the resulting leaf tag or its resolved pseudo-version
when pinning a consumer.

## The wire

`base64url(deterministic protobuf of codefly.base.v0.WorkContextV1) + "." +
base64url(Ed25519 signature)`, signed by `core/workcontext` and by nothing
else. The sealed fields are proto fields — `seal.installation_id`,
`seal.installation_revision`, and `seal.image_digest` /
`seal.build_incarnation` as a **pair or neither**; plus, for an operation
capability, `operation_binding.binding_id` / `.revision` / `.incarnation`, all
three together or none. Each actor hop carries its own epoch.

**The execution pair is optional, and absent is a real answer.** Core
`4cb260d3` moved the approved build out of the live `Seal` and into
`SealSource.ApprovedBuild`, keyed on the **principal**: reading it from the
owner's installation record made a derived capability's execution describe the
owner's workload however many hops had been added, and a hop's principal does
not hold the owner's installation at all. So every hop now attests its own, and
a principal that bears no execution — a person at a terminal — seals none
rather than having a value invented for it.

**If you read the execution off `Credential.Seal()`, mind the zero.**
`GetImageDigest()` answers `""` and `GetBuildIncarnation()` answers `0` both for
"this principal bears no execution" and for a value core says is never
legitimate, since an incarnation starts at 1. Treating zero as "missing or
invalid" is a bug: it is an answer. This module hit it in its own mint-response
cross-check, where a host echoing `"0"` matched a capability that sealed no
execution at all — a host asserting an execution the issuer does not hold,
passing the check whose job is to catch exactly that. Ask about presence before
comparing.

This module no longer reads a capability itself. `corework.Decode` runs the
size bound, the envelope, `CheckEncoding`, `proto.Unmarshal`, **protovalidate**
and the full structural seal check, and returns the claims it decoded;
`readClaims` (`carrier.go`) calls it and clones the result. There is no second
decode, no local rule, and **no signature check** — core's own test asserts a
token re-signed with a key nobody holds passes `Inspect`, so nil means "shaped
like a sealed capability" and never "permitted". That is sound only because
nothing trusts it: it fills the pre-check carriers and tells the mint client
when its own freshly issued credential expires, and a receiver that preferred a
carrier over the sealed claim would have made a caller-controlled header into
authority, which is why the incoming side refuses a disagreement instead.

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
