# Working in `workcontext/`

A separate leaf module (`github.com/codefly-dev/sdk-go/workcontext`, Go 1.27,
its own `go.mod`/`go.sum` and its own coverage gate). It mints nothing and
verifies nothing: `codefly-dev/core/workcontext` is the only implementation of
the capability and this module re-exports core's verifier by type alias, in
`core.go`. Adding a dependency here is a design change — see
`.claude/skills/dual-module-change`.

Depth that used to live in the root `AGENTS.md` and does not fit its 200-line
budget. The root file carries the rule; this carries what the gates refuse.

## What the two gates refuse, and why each rule exists

**There are four gates and they read BOTH modules.** Two are type-checked with
`x/tools/go/packages`: `TestEveryImportIsOnItsModulesAllowlist` is a
**deny-by-default import allowlist per module**, and
`TestNoCodecTouchesACapabilityByType` decides the codec rule with `go/types`.
`TestNoSecondWorkContextImplementation` is the syntactic gate that remains.
`scripts/check-one-implementation.sh` sweeps every published ref, reading
imports with `go/parser`.

**Deny by default is the spine, and it replaces an argument that lost ten
times.** Every revision banned a LIST OF NAMES and every review found the next
name — `hkdf`, then `sha512`, then `protoiface`, and finally `crypto/mldsa`
signing a `WorkContextV1` that `encoding/json/v2` had encoded as snake_case
JSON, which is the exact format this repository deleted, with both gates green
and lint clean. The list was not behind by one entry; it was behind by a design.
Each module now declares the imports it HAS, measured from the tree, and
anything else is a finding — so `protodelim`, the gRPC codec registry,
`prototext`, `jsontext` and `hpke` are refused by one rule, and so is the one
nobody has thought of. `import "C"` is refused by name, because a MAC built
through CommonCrypto names no Go package at all.

**go/types is necessary and not sufficient**, which is why both halves exist. A
syntactic resolver answers with a SPELLING where the question is a KIND: six
compiled probes decoded a real capability through `func into[M proto.Message]`,
an embedded interface, an alias of `proto.Message`, a `reflect.Call`, a closure
taking `proto.Unmarshal`, and a descriptor-built message. `types.IsInterface`
and object identity answer all of them, and the indirection allowlist is keyed
on `*types.Func` — so a second method named `Handle` on a new type is a
different object. **The irreducible residue** is a hand-written implementation
that imports nothing: a base64url decoder is twenty lines and a wire walk is
fifty. That is closed by review, and saying so is part of the rule.

The syntactic gate used to walk this module only, which was a hole with nothing
behind it: the deleted implementation lived at the repository root, and the
sweep bans *imports* rather than reading code. A reviewer built the consequence
— a root file with a **hand-written base64url decoder**, so no banned import at
all, and `proto.Unmarshal` into `basev0.WorkContextV1` — and it compiled, linted
clean and swept green.

The two modules are held to different rules, deliberately. **In here the
capability is the subject**, so every codec use is allowlisted by name. **Outside
it the subject is everything else** — receipts, configuration, runtime documents
— so enumerating the legitimate types would be noise that rots; the rule there
is the decisive one on its own: **no codec may be applied to a Work Context
message**, recognised as a type under core's module whose name begins with
`Work`. A prefix, so a message core adds later is covered the day it exists.

Type names resolve to the imported **package PATH**, never to the local
qualifier, because the qualifier is the author's choice.

- **By capability, never by name.** A signature, MAC or JOSE/JWT primitive,
  anything under `x/crypto`, `protojson`/`protowire`/`anypb`. The bare `crypto`
  is included: `crypto.Signer` signs Ed25519 with no `ed25519` import anywhere.
  The predicate used to be "imports a primitive AND mentions WorkContext",
  which a second implementation defeats by putting the signer in one file and
  the wrapper in another.
- **An allowlisted import is held to FILES and SYMBOLS.** `crypto/tls`,
  `crypto/x509`, `mime`, `crypto/sha256` and `encoding/base64` each have an
  honest use in exactly one file. Whole-file is allowed-for-everything — which
  is how `x509.ParsePKCS8PrivateKey`, a signer getting a key without naming
  `ed25519`, would be a permitted use of an allowed import.
- **base64 may ENCODE and never DECODE.** `cache_partition.go` builds a cache
  key. base64 decoding plus `proto.Unmarshal` is the entire second parser this
  module deleted, and the symbol rule alone cannot see it: `base64.StdEncoding`
  is the permitted symbol and `DecodeString` is a method on the value it names.
- **A codec is held to (file, codec, type).** Not to a file — a whole-file
  exemption is an exemption for every type in it — and not to an operation
  name, because `Marshal` is an operation name shared by every codec, so
  `mint.go`'s `encoding/json` row also permitted `proto.Unmarshal` on anything
  *named* `mintResponse`. Types resolve package-qualified (`basev0.WorkScopeV1`,
  not `WorkScopeV1` from anywhere), in the scope of the use, before the use, and
  an ambiguous identifier is refused rather than guessed.
- **No function-local type, and no second local name for core's types outside
  `core.go`** — alias or defined type, through a pointer or a slice, and a local
  name is CHASED to what it names. Either one hands a type-name allowlist
  whatever name it asks for: `type WorkScopeV1 = basev0.WorkContextV1` makes a
  capability marshal as an allowed scope, and a declaration inside a function
  body is invisible to every rule reading a file's declarations. One `*` walked
  past both halves for three rounds — `type carrier = *basev0.WorkContextV1`
  resolved to `"carrier"`, neither a capability nor unresolvable, so the root
  module's one rule permitted a `proto.Unmarshal` into it.
- **A codec-allowed struct's field set is FROZEN, embedded fields included.**
  The codec rule names the top-level type, so a new field is a new thing encoded
  through a row written for the fields listed. An embedded field has no `Names`,
  so a loop over `field.Names` skipped every one — and `encoding/json` promotes
  an embedded struct's exported fields into the enclosing object.
- **No `encoding/json` outside `mint.go` by exact path, and no json-tagged
  struct elsewhere.** The deleted implementation signed a hand-written JSON
  payload. The path is exact because matching the base name let any new
  `mint.go` inherit the allowance — an allowlist undone by `touch`.
- **No declaration named `workcontext*`** (case-insensitively, every
  declaration kind) unless it aliases into core's module.
- **The sweep reads imports with GO'S OWN PARSER** (`scripts/importsof`), not a
  regex. Its awk extractor was rewritten three times for this class and five
  more shapes walked past it, the decisive one being `import
  "\x63rypto/ed25519"` — which compiles, IS `crypto/ed25519` to the compiler,
  and is not that string to anything matching text. No regex closes that. A
  file that does not parse is a failure, not a file with no imports.
- **ONE import policy, `scripts/allowed-imports.txt`,** read by the Go gate and
  by the sweep. There were two and they disagreed in both directions, which was
  a blocker twice: the sweep is the only thing that runs over a published ref
  and is the whole of the required check, so a branch carrying `crypto/mldsa`
  and `encoding/json/v2` swept clean while the allowlist in `go test` refused
  it. A line may name the FILES that may have an import; `legacy` lines apply
  to published refs only, because deny-by-default describes today's tree and
  sweeping two years of tags with it flagged 33 clean versions.
- **The gates must READ every shipped file, asserted against `git ls-files`.**
  `packages.Load` builds one configuration, so a build-constrained file, a cgo
  file under `CGO_ENABLED=0`, a `_`-prefixed directory, a nested module or a
  vendor tree is invisible to every semantic rule. The sweep still reads them
  (go/parser ignores build tags), so an import ban holds and nothing else does
  — and assembly, object code and C are refused outright, because no rule here
  can read them.
- **A gate that could not look must not report success.** Four fail-opens, three
  inside the assertion added the round before: a swallowed `git ls-remote`
  failure skipped the comparison entirely, the comparison was between COUNTS
  rather than ref sets, an entry `git cat-file` could not read swept clean, and
  the fix for that `exit`ed a command substitution's subshell — printing `FAIL`
  and then `ok`. Every enumeration's exit status is read.

**What no import ban catches:** a hand-rolled HMAC over `crypto/sha256` builds a
MAC out of parts that are not MACs. `crypto/cipher` and the block ciphers are
banned in both gates now; the hash cannot be, because two digests here need it.
So in this module the symbol rule bounds that residue to one file, and in the
root module it is closed by review. "Any MAC is a finding" was a list of names;
this is what the list reaches.

`TestTheGateCatchesItsOwnBypasses`,
`TestTheRepositorySweepCatchesItsOwnBypasses`,
`TestTheImportScannerReadsOneLineOnce` and
`TestTheSweepRefusesWhenItCouldNotLook` hold both gates to these claims: every
case is a bypass reported against a previous revision, and every one worked. `TestTheSDKParsePathsAgreeWithCore` drives every core conformance
fixture through this module's own parse paths and requires core's sentinel —
read a refusal's sentinel off the fixture, never off a constant here, because
three fixtures changed sentinel under us and the tests that did that needed no
edit.

## A credential is sealed or it is not a credential, and core says what that means

The seal and each actor hop's epoch are schema-required, so a missing one is a
`protovalidate` refusal inside core's decode. The **execution** —
`image_digest` and `build_incarnation` — is a PAIR OR NEITHER: it lives in
`SealSource.ApprovedBuild` keyed on the principal, every hop attests its own,
and a principal that bears none (a person at a terminal) seals none rather than
inventing a value. An operation binding carries its id, revision and
incarnation or none of them; and core refuses an unknown field or a
non-canonical encoding, so nothing here may ever marshal a capability.

**Zero is an answer, not a gap.** `GetBuildIncarnation()` returns 0 both for
"bears no execution" and for a value core says is never legitimate, since an
incarnation starts at 1. `mint.go`'s echo cross-check asks about PRESENCE
before comparing, because a host echoing `"0"` otherwise matched a capability
sealing no execution — a host asserting an execution the issuer does not hold,
passing the check that exists to catch that. `Attach` refuses an unsealed
capability with `corework.Inspect`'s answer — false for a while precisely
because we answered it ourselves and never read the actor chain.

**One sentinel for every structural seal defect, `ErrInvalid`.** `ErrUnsealed`
is deleted: once the schema requires the seal, no branch can produce it, and a
sentinel no branch produces invites a handler that never runs.

**`Credential.Seal()` returns core's own wire message**, cloned. That is why
core making `ImageDigest` a required seal field cost this module no code: a
hand-filled struct would have needed a new field everywhere it was built.

## Metadata leaves a stream by three routes, not one

The embedded field; gRPC's own flush when the handler RETURNS; and the
package-level `grpc.SetHeader`/`SendHeader`/`SetTrailer`, which resolve a
`grpc.ServerTransportStream` out of the context and write to the transport.
Each was a live bypass found only after the previous one was closed, and the
last two were measured over bufconn with the guard revoked for the whole call
and never asked.

So `GuardedServerStream` keeps the stream private and forwards every interface
method by hand, HOLDS headers and trailers until `Finish` re-checks and releases
them, and owns the transport stream in the context it hands out.
`GuardStreams` — not `Guard`, and not a bare interceptor — is the recipe,
because it does the
wrapping, the context and the `Finish`, and because its `Intercept` REFUSES
EVERY STREAM until `Validate(server.GetServiceInfo(), …)` has passed. The
interceptor constructor is unexported for that reason: exporting it beside the
validation meant the correct wiring took two calls and only one was reachable
from the type system, so a consumer could install the enforcement and skip the
check — which the README recipe itself did for several revisions. Whether a method is guarded is a
property of the METHOD and the first answer binds; a per-request `(nil, nil)` is
the optional-carrier shape this module deleted.

A refusal reaches the client as a gRPC status: core's sentinels become
`codes.Unauthenticated`, an unreachable re-check source becomes
`codes.Unavailable`, and the Go error chain is kept alongside the code so
`errors.Is` still works in the server that produced it. **`ErrInvalid` is
`Unauthenticated` and this package's own misuse is `Internal`** — two sentinels,
because they were one: core answers an EXPIRED capability with `ErrInvalid`, so
mapping every `ErrInvalid` to `Internal` told a client not to mint again about
the most ordinary mid-stream refusal there is. `errStreamMisuse` wraps
`ErrInvalid` and is checked first.

## The mint client holds a credential it cannot verify

It is the party the credential is minted FOR, not a receiver, so it reads the
window through `corework.Inspect` and checks no signature. Three consequences
that are easy to get backwards:

- **The lifetime bound is CORE'S**, in `decodeClaims`, so `Inspect` carries it
  — and `Inspect` is this client's read path. Core's first two attempts bounded
  `Authority.Start` and then `Verify` alone, neither of which a holder can see,
  so a thirty-day capability every `Verify` refuses was reported to its holder
  as thirty days of validity. `MaxCredentialLifetime` survives as a DEPLOYMENT
  POLICY below core's ceiling, defaulting to `corework.MaxTTLCeiling` so there
  is no second number; exactly-at-ceiling is accepted and this module pins that
  with its own test, because the default IS that constant.
- **The sentinel says what RECOVERY is possible.** `ErrMintRefused` is latched
  and terminal — a process seeing one must stop serving — so anything transient
  classified that way permanently stops a process holding a good credential: an
  interrupted response read, a projected-token `EMFILE`, a momentarily empty
  projection, a 408. All of those are `ErrMintUnavailable`. TLS verification
  and peer-admission failures are also retryable: the handshake refuses them
  before any projected token leaves, and rotation or admission can recover.
  Local misuse is `ErrInvalid`, never `ErrMintRefused`, or `Refused()` and
  `errors.Is` disagree.
- **The shared request is detached from whoever started it**, bounded by
  `RequestTimeout`. On the caller's context, a cancelled leader counted as no
  failure, so twenty callers with deadlines shorter than a degraded host's
  latency produced twenty mint requests — each of which the host may complete
  and audit while this process discards it.

## The mint transport admits the peer before disclosing the projection

`MintOptions` requires three sources: `TrustAnchor`, `ClientCertificate` and
`AdmittedPeers`. The SDK owns its HTTP client and transport; a caller can
supply neither. The private TLS dialer reads the current anchor for each
handshake with normal chain and hostname verification enabled, and
`GetClientCertificate` reads the workload's current X.509-SVID. The endpoint
must request the client certificate. `VerifyConnection` reads the admitted
SPIFFE IDs only after chain verification, then compares them against the
leaf's URI SANs. Both sides lower-case the scheme and trust domain and remove
empty path segments and trailing slashes; path case is significant. Anything
outside `spiffe://<trust-domain>/<path>` is refused, including userinfo, ports,
queries, fragments, escapes and dot segments.

Every mint, renewal and refresh dials fresh: TLS 1.3 minimum, no connection or
TLS session reuse, no compression, proxy or redirect. HTTP/1.1 prevents
multiplexing across admission decisions. A withdrawal takes effect on the next
request. The handshake-to-write window remains, normally microseconds subject
to scheduling; no HTTP headers or body leave before `VerifyConnection` returns.

A missing source or malformed currently readable admitted identity is
`ErrInvalid` at construction. Unavailable projections are enforced at the
handshake so a client can recover: unreadable or nil anchors, unreadable or
empty certificates, empty or unreadable peer sets, malformed live peer IDs and
TLS verification failures return `ErrMintUnavailable`. A verified leaf without
an admitted SPIFFE ID additionally wraps `ErrMintPeerNotAdmitted`. These errors
never latch. `mint_transport_test.go` captures server-side authorization
headers, tests withdrawal and rotation across requests, proves client
certificate presentation, and requires recovery after source failures.
