package workcontext

import (
	"encoding/base64"
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

	// MaxTokenBytes bounds a capability this module will carry or read.
	MaxTokenBytes = 32 * 1024
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

// checkCarriedInstallation refuses a request whose installation carriers
// disagree with the seal, or whose carriers are stated more than once.
//
// Cardinality is checked before agreement, which Header.Get made impossible:
// it reads the FIRST value, so `[sealed-id, something-else]` compared equal to
// the seal and the call was accepted while carrying two contradictory
// installations. Whether a later intermediary reads the first or the second is
// not something this module can decide, so an ambiguous carrier is refused
// here — the same contract gRPC already held, now stated once for both.
func checkCarriedInstallation(headers http.Header, encoded string) error {
	ids := headers.Values(InstallationIDHeaderName)
	revisions := headers.Values(InstallationRevisionHeaderName)
	if len(ids) == 0 && len(revisions) == 0 {
		return nil
	}
	for _, carrier := range []struct {
		name   string
		values []string
	}{
		{InstallationIDHeaderName, ids},
		{InstallationRevisionHeaderName, revisions},
	} {
		if len(carrier.values) == 0 {
			return fmt.Errorf(
				"%w: %s and %s travel together; one was presented without the other",
				ErrInvalid, InstallationIDHeaderName, InstallationRevisionHeaderName,
			)
		}
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
	if ids[0] != sealedID {
		return fmt.Errorf(
			"%w: %s carries %q and the capability is sealed to %q",
			ErrInvalid, InstallationIDHeaderName, ids[0], sealedID,
		)
	}
	if revisions[0] != sealedRevision {
		return fmt.Errorf(
			"%w: %s carries %q and the capability is sealed to %q",
			ErrInvalid, InstallationRevisionHeaderName, revisions[0], sealedRevision,
		)
	}
	return nil
}

// SealedInstallation reads the installation a capability is sealed to, for a
// transport that names it beside the capability.
//
// It is the WHOLE seal check and not an installation check. It used to read
// just the installation id and revision, which made "Attach refuses an unsealed
// capability" true of two fields out of four: a capability with no principal
// epoch, no build incarnation, or a binding naming an id at no revision was
// attached and travelled, and the missing field is the one an attacker would
// choose to leave out. Every carrier in this module — HTTP attach, HTTP read,
// outgoing gRPC metadata, incoming gRPC metadata — goes through here, so there
// is one answer to "is this sealed" rather than one per transport.
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
	return seal.InstallationID, strconv.FormatUint(seal.InstallationRevision, 10), nil
}

// claimsOf decodes a capability's claims WITHOUT establishing any trust in
// them. Nothing in this module authorizes from what it returns: its one caller
// is sealOf, which the pre-check carriers and the mint client reach it through.
//
// It decodes core's encoding with core's generated type, so there is no second
// reading of the wire here. The one thing it must not become is a verification:
// there is no signature check in it and there must never be one, because a
// second place that checks a signature is a second implementation whatever it
// is called.
func claimsOf(encoded string) (*Claims, error) {
	if strings.TrimSpace(encoded) == "" {
		return nil, fmt.Errorf("%w: empty capability", ErrInvalid)
	}
	if len(encoded) > MaxTokenBytes {
		return nil, fmt.Errorf("%w: capability exceeds %d bytes", ErrInvalid, MaxTokenBytes)
	}
	payload, signature, found := strings.Cut(encoded, ".")
	if !found || payload == "" || signature == "" {
		return nil, fmt.Errorf("%w: capability is not <payload>.<signature>", ErrInvalid)
	}
	raw, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil {
		return nil, fmt.Errorf("%w: payload is not base64url: %v", ErrInvalid, err)
	}
	if _, err := base64.RawURLEncoding.DecodeString(signature); err != nil {
		return nil, fmt.Errorf("%w: signature is not base64url: %v", ErrInvalid, err)
	}
	// Before unmarshalling: is this even this encoding? Core's check, not a
	// second one — so a token in another format is named here exactly as the
	// verifier would name it (ErrNotACoreToken), rather than reported as a
	// payload that failed to unmarshal. Two different messages for one
	// condition is the diagnostic fragmentation that produced this rule.
	//
	// A nil return means only that the payload is not visibly another format.
	// Nothing here checks a signature, and nothing that follows trusts the
	// result.
	if err := corework.CheckEncoding(raw); err != nil {
		return nil, err
	}
	claims := &Claims{}
	if err := proto.Unmarshal(raw, claims); err != nil {
		return nil, fmt.Errorf("%w: payload is not a WorkContextV1: %v", ErrInvalid, err)
	}
	return claims, nil
}

// sealOf reads the claims, the seal and the sealed operation binding of a
// capability, and is the one structural seal check in this module.
//
// It requires a whole seal: every field of it, and for an operation binding all
// three of its fields or none of them. A partial seal is refused here and not
// carried, because a capability sealed to an installation with no revision, or
// to a binding id at no revision, names an authority nobody approved — and the
// field that is missing is the one an attacker would choose to leave out.
//
// Refusing it here is a preflight and not the authorization: core's verifier
// refuses the same capability at the far end. The preflight is what makes the
// refusal legible — it names the field that is missing, in the process that
// holds the credential, rather than arriving as a mismatch in a service that
// cannot do anything about it.
func sealOf(encoded string) (*Claims, Seal, *SealedOperationBinding, error) {
	claims, err := claimsOf(encoded)
	if err != nil {
		return nil, Seal{}, nil, err
	}
	sealed := claims.GetSeal()
	if sealed == nil {
		return nil, Seal{}, nil, fmt.Errorf("%w: capability carries no seal", ErrUnsealed)
	}
	seal := Seal{
		PrincipalEpoch:       sealed.GetPrincipalEpoch(),
		InstallationID:       sealed.GetInstallationId(),
		InstallationRevision: sealed.GetInstallationRevision(),
		BuildIncarnation:     sealed.GetBuildIncarnation(),
	}
	switch {
	case seal.PrincipalEpoch == 0:
		return nil, Seal{}, nil, fmt.Errorf("%w: the seal names no principal epoch", ErrUnsealed)
	case seal.InstallationID == "":
		return nil, Seal{}, nil, fmt.Errorf("%w: the seal names no installation", ErrUnsealed)
	case seal.InstallationRevision == 0:
		return nil, Seal{}, nil, fmt.Errorf("%w: the seal names no installation revision", ErrUnsealed)
	case seal.BuildIncarnation == 0:
		return nil, Seal{}, nil, fmt.Errorf("%w: the seal names no build incarnation", ErrUnsealed)
	}
	bound := claims.GetOperationBinding()
	if bound == nil {
		return claims, seal, nil, nil
	}
	if bound.GetBindingId() == "" || bound.GetRevision() == 0 || bound.GetIncarnation() == 0 {
		return nil, Seal{}, nil, fmt.Errorf(
			"%w: an operation binding carries its id, revision and incarnation or none of them",
			ErrUnsealed,
		)
	}
	return claims, seal, cloneSealedBinding(bound), nil
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
