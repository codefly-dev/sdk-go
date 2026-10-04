// Package workcontext is the client side of the Work Context capability: it
// obtains one credential per execution from the host's mint endpoint, carries
// it on outbound calls, and gives typed access to the one implementation of
// the capability itself.
//
// It mints nothing and it verifies nothing. The Work Context is a core type
// (codefly.base.v0.WorkContextV1) and github.com/codefly-dev/core/workcontext
// is its only implementation: the only code that signs a capability, the only
// code that checks a signature, and the only encoding of either. This package
// re-exports core's verification entry point rather than offering one of its
// own, so a consumer that verifies through this module is verifying through
// core.
//
// That is a rule and not a preference, because the alternative was tried. A
// second implementation here once signed a hand-written JSON payload while
// core signed the deterministic protobuf encoding of the same message. Both
// forms are "<base64url payload>.<base64url signature>" with an Ed25519
// signature, so a token from either looked well-formed to the other and then
// failed to resolve a key id read out of a payload in the other format — a message that reads like a rotated key or a
// wrong trust root, and sends everyone to look at keys. The gate test in this
// package is what stops it coming back; see README.md, "One implementation, and
// the gate that keeps it that way".
//
// What this package does own:
//
//   - MintClient: one credential per execution, obtained from the projected
//     service-account token, renewed only at expiry. No heartbeat, no
//     registration, nothing a process reports about itself.
//   - The carriers: the capability's header, and the sealed installation
//     beside it as a pre-check the far end may refuse on cheaply.
//   - CachePartition: the identity partition a cache stack scopes entries to,
//     which never spans an installation revision.
//   - StreamGuard: a stream re-presents its credential before every message
//     and terminates on refusal.
package workcontext
