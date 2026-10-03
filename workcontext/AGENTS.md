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

`TestNoSecondWorkContextImplementation` walks this module's AST.
`scripts/check-one-implementation.sh` sweeps every tracked Go file in BOTH
modules, because that test walks from this module's root and the implementation
this repository deleted lived at the repository root, in package `codefly`.

- **By capability, never by name.** A signature, MAC or JOSE/JWT primitive,
  anything under `x/crypto`, `protojson`/`protowire`/`anypb`. The bare `crypto`
  is included: `crypto.Signer` signs Ed25519 with no `ed25519` import anywhere.
  The predicate used to be "imports a primitive AND mentions WorkContext",
  which a second implementation defeats by putting the signer in one file and
  the wrapper in another.
- **Allowed imports are held to FILES and SYMBOLS.** `crypto/tls`,
  `crypto/x509`, `mime`, `crypto/sha256` and `encoding/base64` each have an
  honest use in exactly one file. An import allowed whole-file is allowed for
  everything in that package — which is how `x509.ParsePKCS8PrivateKey`, a
  signer getting a key without naming `ed25519`, would be a permitted use of an
  allowed import rather than a finding.
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
- **No function-local type, and no alias to core's types outside `core.go`.**
  Either one hands a type-name allowlist whatever name it asks for: `type
  WorkScopeV1 = basev0.WorkContextV1` makes a capability marshal as an allowed
  scope, and a declaration inside a function body is invisible to every rule
  that reads a file's declarations.
- **No `encoding/json` outside `mint.go` by exact path, and no json-tagged
  struct elsewhere.** The deleted implementation signed a hand-written JSON
  payload. The path is exact because matching the base name let any new
  `mint.go` inherit the allowance — an allowlist undone by `touch`.
- **No declaration named `workcontext*`** (case-insensitively, every
  declaration kind) unless it aliases into core's module.
- **The sweep tests import PATHS**, taken from inside the quotes, and never a
  line's shape. Its previous regex tried to recognise an import and was walked
  past by a non-ASCII alias (`ψ "crypto/ed25519"`) and a comment-prefixed line
  (`/* x */ "crypto/ed25519"`) — in the root module, where it is the only gate.

**What no import ban catches:** a hand-rolled HMAC over `crypto/sha256`, or a
GMAC assembled from `crypto/cipher`, builds a MAC out of parts that are not
MACs. `crypto/cipher` and the block ciphers are banned; the hash cannot be,
because two digests here need it. So in this module the symbol rule bounds that
residue to one file, and in the root module it is closed by review rather than
by the script. "Any MAC is a finding" was a list of names; this is what the
list reaches.

`TestTheGateCatchesItsOwnBypasses` and
`TestTheRepositorySweepCatchesItsOwnBypasses` hold both gates to these claims:
every case is a bypass that was reported against a previous revision and
worked. `TestTheSDKParsePathsAgreeWithCore` drives every core conformance
fixture through this module's own parse paths and requires core's sentinel —
read a refusal's sentinel off the fixture, never off a constant here, because
three fixtures changed sentinel under us and the tests that did that needed no
edit.

## A credential is sealed or it is not a credential, and core says what that means

The seal, each actor hop's epoch and the seal's **image digest** are
schema-required, so a missing one is a `protovalidate` refusal inside core's
decode; an operation binding carries its id, revision and incarnation or none
of them; and core refuses an unknown field or a non-canonical encoding, so
nothing here may ever marshal a capability. `Attach` refuses an unsealed
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
`StreamServerInterceptor` — not `Guard` — is the recipe, because it does the
wrapping, the context and the `Finish`. Whether a method is guarded is a
property of the METHOD and the first answer binds; a per-request `(nil, nil)` is
the optional-carrier shape this module deleted.

A refusal reaches the client as a gRPC status: the sentinels become
`codes.Unauthenticated`, an unreachable re-check source becomes
`codes.Unavailable`, and the Go error chain is kept alongside the code so
`errors.Is` still works in the server that produced it.

## The mint client holds a credential it cannot verify

It is the party the credential is minted FOR, not a receiver, so it reads the
window through `corework.Inspect` — structural, no signature. Three
consequences that are easy to get backwards:

- **`MaxCredentialLifetime` defaults to `corework.MaxTTLCeiling`**, core's own
  constant, so there is one number rather than two to keep in step. Core's
  `Start` bounds an honest minter and core's `Verify` bounds a receiver on a
  current core; what this process holds in memory and presents for its whole
  life is bounded here or nowhere.
- **The sentinel says what RECOVERY is possible.** `ErrMintRefused` is latched
  and terminal — a process seeing one must stop serving — so anything transient
  classified that way permanently stops a process holding a good credential: an
  interrupted response read, a projected-token `EMFILE`, a momentarily empty
  projection, a 408. All of those are `ErrMintUnavailable`. A TLS verification
  failure is the opposite: not an outage but the one thing this transport
  exists to refuse, so it latches. Local misuse is `ErrInvalid`, never
  `ErrMintRefused`, or `Refused()` and `errors.Is` disagree.
- **The shared request is detached from whoever started it**, bounded by
  `RequestTimeout`. On the caller's context, a cancelled leader counted as no
  failure, so twenty callers with deadlines shorter than a degraded host's
  latency produced twenty mint requests — each of which the host may complete
  and audit while this process discards it.
