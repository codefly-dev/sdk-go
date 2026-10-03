package workcontext

import (
	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
	corework "github.com/codefly-dev/core/workcontext"
)

// Everything below is core's, named here so product code can reach it through
// the package it already imports. They are aliases and not wrappers: a wrapper
// is a place a second behaviour grows, and the whole point of this file is that
// there is nowhere for one to grow.

// Verifier is the verification entry point — core's, unmodified. A consumer
// that verifies a capability constructs one of these.
//
// It is issuer-shaped by design, and that is load-bearing rather than
// inconvenient: it refuses everything unless it is given the authorization
// revision, replay, grant and seal sources, because a verifier that silently
// skipped the seal check would make the strongest check in the model the
// easiest one to omit. A service that cannot answer those four is not in a
// position to verify a capability itself; it presents its own and lets the
// component that holds them decide.
type Verifier = corework.Verifier

// Verified is a capability that passed every check. Only Verifier.Verify
// constructs one, so a value of this type cannot be a hand-built protobuf or a
// token that was parsed and never verified.
type Verified = corework.Verified

// Seal is the live binding of a principal's authority to one installation and
// one execution, as the issuer holds it. A Verifier compares a capability's
// sealed values against it for exact equality.
type Seal = corework.Seal

// OperationBinding is the LIVE state of one unit of authority, as the issuer
// holds it: resolved by its opaque id — never searched for by the scopes it
// contains — and carrying the principal it is granted to and the installation
// it is granted within, because an id that exists is not an id somebody holds.
//
// It is what a verifier's seal source answers, not what a capability carries.
// SealedOperationBinding is the carried half, and the two are deliberately
// different types: the capability names three fields, the live state names six,
// and a client that filled the live type from a token would be handing a reader
// an empty PrincipalID and InstallationID that read as "granted to nobody,
// nowhere" rather than as "the wire does not say".
type OperationBinding = corework.OperationBinding

// SealedOperationBinding is the operation binding a capability carries: the
// binding's id, and its revision and incarnation at mint time. It is core's own
// message for that, so there is no second spelling of what travels.
type SealedOperationBinding = basev0.WorkOperationBindingV1

// SealSource answers the live values a seal is compared against.
type SealSource = corework.SealSource

// RevisionSource, ReplayStore and GrantSource are the other three sources a
// Verifier requires.
type (
	RevisionSource = corework.RevisionSource
	ReplayStore    = corework.ReplayStore
	GrantSource    = corework.GrantSource
)

// MemorySealSource and MemoryReplayStore are core's in-memory implementations,
// for a test or a single-process deployment.
type (
	MemorySealSource  = corework.MemorySealSource
	MemoryReplayStore = corework.MemoryReplayStore
	FixedRevision     = corework.FixedRevision
)

// Claims are the capability's fields. Read them off a Verified, never off the
// wire.
type Claims = basev0.WorkContextV1

// Core's verify-only Authenticator and Authenticated are deliberately not
// aliased either. They require the issuer's revision and seal sources, which is
// precisely what a client does not hold; a client that could supply them is not
// a client. Re-exporting them here would put the weaker of two strengths in the
// same namespace as the stronger, one import away from each other, which is the
// silent downgrade core objected to when it was first asked for that path.

// The refusals, core's. This module defines no second taxonomy of them: a
// caller writes errors.Is against these and gets the same answer whichever
// package it names them through.
var (
	// ErrInvalid covers every rejection that is a property of the capability
	// itself — signature, window, audience, attenuation, grant shape — and
	// every refusal this package makes about a capability it is asked to
	// carry.
	ErrInvalid = corework.ErrInvalid

	// ErrNotACoreToken is a token whose payload is not this encoding at all,
	// most usefully one carrying a JSON payload. It is refused before the
	// signature is checked and with its own error, so a token from another
	// format is never diagnosed as a bad key.
	ErrNotACoreToken = corework.ErrNotACoreToken

	// ErrRevoked is every sealed mismatch: principal epoch, installation
	// revision, build incarnation, binding revision or incarnation, a revoked
	// binding, or an installation the principal no longer holds — and an
	// authorization revision the issuer has moved past.
	//
	// One sentinel for all of them is core's decision and the right one: in
	// every case the capability was sound when it was minted and the state
	// moved under it, so the holder's response is the same — mint again. A
	// caller that needs to tell "mint again" from "this caller is not
	// authorized" needs those two to read differently, which they do; it does
	// not need the six reasons a re-mint is due to read differently from each
	// other.
	ErrRevoked = corework.ErrRevoked

	// ErrReplayed is a single-use capability presented twice.
	ErrReplayed = corework.ErrReplayed

	// ErrUnsealed is GONE, and its absence is the point. It was aliased here
	// for a while, which is worse than not having it: WorkContextV1.seal and
	// WorkActorV1.principal_epoch are now schema-REQUIRED, so protovalidate
	// refuses a missing seal or a missing actor epoch inside core's decode
	// before any branch that could have produced ErrUnsealed runs. A sentinel
	// no branch can produce invites a handler that never executes, and an
	// unreachable handler reads as cover.
	//
	// Every structural seal defect is therefore ErrInvalid: no seal, a seal
	// naming no installation, a zero epoch, revision or incarnation, a partial
	// binding, an actor hop with no epoch. One sentinel, one branch.

	// Core exports three more sentinels that are deliberately NOT aliased here,
	// on core's own instruction when asked:
	//
	//   - ErrNeedsIssuer comes only from core's verify-only Authenticator, when
	//     a capability carries a grant hop. Verifier.Verify never returns it, so
	//     a client matching it would be writing a branch nothing reaches.
	//   - ErrNoSeal and ErrNoBinding are what a SealSource IMPLEMENTATION
	//     returns, not what a client matches.
	//
	// Aliasing them would widen this module's surface to a shape its consumers
	// cannot reach, which reads as "this is available here" about three things
	// that are not. A consumer that implements a seal source, or adopts the
	// verify-only entrypoint, imports core/workcontext directly for them — and
	// at that point it is not a client of the capability but a participant in
	// it.
)

// ScopeContained and ScopesAttenuate are core's scope algebra. A service
// deciding whether a verified capability covers a call asks these rather than
// comparing scope structs, because "contains" over a wildcard resource set is
// not an equality.
var (
	ScopeContained  = corework.ScopeContained
	ScopesAttenuate = corework.ScopesAttenuate
)
