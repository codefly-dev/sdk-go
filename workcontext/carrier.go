package workcontext

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"

	corework "github.com/codefly-dev/core/workcontext"
	"google.golang.org/protobuf/proto"
)

const (
	// HeaderName is the only HTTP carrier for a signed capability. Product code
	// calls Attach instead of naming it. It is spelled in lower case because
	// gRPC metadata keys must be, and an HTTP header name is case-insensitive:
	// one spelling for one fact, rather than two that drift.
	HeaderName = "x-codefly-work-context"

	// InstallationIDHeaderName and InstallationRevisionHeaderName carry the
	// installation a capability is sealed to, beside the capability.
	//
	// They exist so the far end can refuse a call before it decodes a token,
	// and for no other reason: the installation that governs a call is the one
	// inside the signature. A receiver that finds a carrier disagreeing with
	// the seal refuses the call rather than preferring either, because a header
	// is caller-controlled and a seal is not.
	InstallationIDHeaderName       = "x-codefly-installation-id"
	InstallationRevisionHeaderName = "x-codefly-installation-revision"

	// MaxTokenBytes bounds a capability this module will carry or read. It IS
	// core's bound, not a number of ours that happens to agree: this module
	// invented one because core declared none, which is one more rule kept in
	// sync by hand. Core declares it now, so this is a re-export.
	MaxTokenBytes = corework.MaxTokenSize
)

// Attach installs a capability on an outbound request: the signed capability
// and, beside it, the installation it is sealed to.
//
// It refuses an unsealed capability outright. A credential is sealed or it is
// not a credential, and the moment to find that out is before a call is made on
// it rather than at the far end, where the refusal names an installation
// mismatch for a capability that never named an installation at all.
func Attach(request *http.Request, encoded string) error {
	if request == nil {
		return fmt.Errorf("%w: nil request", ErrInvalid)
	}
	if request.Header == nil {
		request.Header = make(http.Header)
	}
	id, revision, err := SealedInstallation(encoded)
	if err != nil {
		return err
	}
	request.Header.Set(HeaderName, encoded)
	request.Header.Set(InstallationIDHeaderName, id)
	request.Header.Set(InstallationRevisionHeaderName, revision)
	return nil
}

// FromHeaders reads the capability a request carries. It returns the encoded
// token and nothing else: a token is a string until a Verifier has had it, and
// an accessor that handed back claims here would be an accessor somebody
// authorizes from.
func FromHeaders(headers http.Header) (string, error) {
	if headers == nil {
		return "", fmt.Errorf("%w: no headers", ErrInvalid)
	}
	values := headers.Values(HeaderName)
	if len(values) == 0 || strings.TrimSpace(values[0]) == "" {
		return "", fmt.Errorf("%w: no %s header", ErrInvalid, HeaderName)
	}
	if len(values) > 1 {
		return "", fmt.Errorf("%w: %s appears %d times", ErrInvalid, HeaderName, len(values))
	}
	encoded := values[0]
	if err := checkCarriedInstallation(headers, encoded); err != nil {
		return "", err
	}
	return encoded, nil
}

// checkCarriedInstallation requires BOTH installation carriers, exactly once
// each, and holds them to the seal.
//
// Carrying neither used to be allowed, and that was the optional-carrier escape
// hatch surviving on HTTP after it was deleted on gRPC: gRPC requires exactly
// one of each, so "one contract for both transports" was false, and a sender
// that attached nothing skipped the seal check entirely. Attach always sets
// both, so any sender using this SDK already satisfies it; one that does not is
// a sender whose pre-check nobody can perform.
//
// Cardinality is checked before agreement, which Header.Get made impossible: it
// reads the FIRST value, so `[sealed-id, something-else]` compared equal to the
// seal and the call was accepted while carrying two contradictory
// installations. Whether a later intermediary reads the first or the second is
// not something this module can decide, so an ambiguous carrier is refused.
func checkCarriedInstallation(headers http.Header, encoded string) error {
	for _, carrier := range []struct {
		name   string
		values []string
	}{
		{InstallationIDHeaderName, headers.Values(InstallationIDHeaderName)},
		{InstallationRevisionHeaderName, headers.Values(InstallationRevisionHeaderName)},
	} {
		if len(carrier.values) != 1 {
			return fmt.Errorf(
				"%w: %s requires exactly one value and carries %d",
				ErrInvalid, carrier.name, len(carrier.values),
			)
		}
	}
	sealedID, sealedRevision, err := SealedInstallation(encoded)
	if err != nil {
		return err
	}
	if id := headers.Get(InstallationIDHeaderName); id != sealedID {
		return fmt.Errorf(
			"%w: %s carries %q and the capability is sealed to %q",
			ErrInvalid, InstallationIDHeaderName, id, sealedID,
		)
	}
	if revision := headers.Get(InstallationRevisionHeaderName); revision != sealedRevision {
		return fmt.Errorf(
			"%w: %s carries %q and the capability is sealed to %q",
			ErrInvalid, InstallationRevisionHeaderName, revision, sealedRevision,
		)
	}
	return nil
}

// SealedInstallation reads the installation a capability is sealed to, for a
// transport that names it beside the capability.
//
// It is CORE'S whole structural check and not an installation check. It used to
// read just the installation id and revision, which made "Attach refuses an
// unsealed capability" true of two fields out of four; then it grew a local
// rule, which disagreed with core's fixtures about which sentinel each refusal
// earns. Now it asks corework.Decode, so there is one answer to "is this
// sealed" for every carrier in this module — HTTP attach, HTTP read, outgoing
// gRPC metadata, incoming gRPC metadata — and that answer is core's.
//
// It reads the capability's own content without checking the signature, which
// is sound only because nothing trusts the result: the carrier it fills is a
// pre-check, and a receiver that preferred it over the sealed claim would have
// made the carrier into authority.
func SealedInstallation(encoded string) (id string, revision string, err error) {
	_, seal, _, err := sealOf(encoded)
	if err != nil {
		return "", "", err
	}
	return seal.GetInstallationId(), strconv.FormatUint(seal.GetInstallationRevision(), 10), nil
}

// readClaims asks core what a capability is, and reads the claims core has
// already decoded. There is no second decode and no rule of this module's.
//
// This is all that is left of a parser that had become a second
// implementation. It hand-parsed the envelope and then applied its own
// structural seal rule, and that rule DISAGREED with core's own fixtures:
// seal-without-installation was ErrUnsealed here and ErrInvalid there, a zero
// epoch, revision or incarnation was ErrUnsealed here and ErrInvalid there, and
// the actor chain was never read at all — so core's actor-without-epoch
// fixture, a principal nobody can revoke, was attached and carried. One
// condition with two messages is the fragmentation the one-implementation rule
// exists to end, and it had been relocated from the signature to the seal.
//
// Core's Decode is the one answer now. It runs the size bound, the envelope,
// CheckEncoding, proto.Unmarshal, protovalidate — which is where the seal and
// every actor epoch are REQUIRED by the schema — and the structural seal
// check, and Verify runs the same decode, so an early refusal here and core's
// verification cannot disagree about what a token is.
//
// Nothing here trusts the result. Decode checks NO signature, and core has a
// test asserting that a token re-signed with a key nobody holds passes it, so
// nil means "shaped like a sealed capability" and never "permitted". The
// carriers this fills are a pre-check; the receiver verifies.
//
// The claims are CLONED. Decoded.Context hands back core's own pointer, so a
// caller that mutated what it was given would be mutating core's value.
func readClaims(encoded string) (*Claims, error) {
	decoded, err := corework.Decode(encoded)
	if err != nil {
		return nil, err
	}
	claims, ok := proto.Clone(decoded.Context()).(*Claims)
	if !ok {
		return nil, fmt.Errorf("%w: decoded claims are not a WorkContextV1", ErrInvalid)
	}
	return claims, nil
}

// sealOf reads the seal and the sealed operation binding of a capability whose
// structure core has approved. Both come back as core's own WIRE messages,
// already cloned by readClaims.
//
// It applies no rule and copies no field. It used to build core's LIVE Seal
// type by hand from three wire fields, which is the same conflation this
// module fixed for OperationBinding and left in place for the seal: a client
// cannot answer what the issuer holds, and a field core adds to the seal —
// image_digest is next — would have been silently zero in a value that reads
// as the issuer's.
//
// Every refusal a capability's own bytes can earn — another encoding, a bad
// envelope, a schema violation, no seal, a seal naming no installation, a zero
// epoch, revision or incarnation, a partial binding, a widening hop, an actor
// hop with no epoch — is corework.Decode's answer, with corework's sentinel.
// TestTheSDKParsePathsAgreeWithCore drives every fixture in core's kit through
// this path and requires core's declared sentinel for each, so the agreement is
// tested rather than described.
func sealOf(encoded string) (*Claims, *SealedValues, *SealedOperationBinding, error) {
	claims, err := readClaims(encoded)
	if err != nil {
		return nil, nil, nil, err
	}
	return claims, claims.GetSeal(), claims.GetOperationBinding(), nil
}

// cloneSealedBinding copies the message, so a caller that mutates what it is
// handed cannot change what a credential reports it is bound to.
func cloneSealedBinding(bound *SealedOperationBinding) *SealedOperationBinding {
	if bound == nil {
		return nil
	}
	copied, ok := proto.Clone(bound).(*SealedOperationBinding)
	if !ok {
		return nil
	}
	return copied
}
