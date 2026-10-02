package workcontext

import (
	"fmt"
	"strconv"
)

// Carrier names for the sealed installation. They exist so a host can refuse a
// request before it decodes a token, and for no other reason: the installation
// that governs the call is the one sealed inside the signature. A verifier that
// disagrees with these headers refuses the call rather than preferring either
// side, because a header is caller-controlled and the seal is not.
const (
	InstallationIDHeaderName       = "x-codefly-installation-id"
	InstallationRevisionHeaderName = "x-codefly-installation-revision"
)

// Seal binds one credential to the execution it was issued to: the principal
// the host authenticated and the epoch it authenticated at, the installation
// the process serves and the revision of that installation, and the build
// incarnation the process is running.
//
// Every field is required. A credential missing any of them does not verify —
// there is no shape in which part of a seal is a seal, because each field is
// the only thing standing between a credential and its reuse somewhere it was
// never issued for.
type Seal struct {
	// PrincipalEpoch is the host's epoch for the owner principal. It moves when
	// the principal's authority changes, so a credential sealed to an older
	// epoch is refused rather than carried across the change.
	PrincipalEpoch uint64
	// InstallationID is the installation the process serves. It is the
	// immutable, non-reused installation identity, never a reusable route alias
	// or registry key: an alias can be released and taken by something else,
	// and a credential must not inherit the grants of whatever held it before.
	InstallationID string
	// InstallationRevision is that installation's revision at mint time. A
	// verifier holding a later revision refuses the credential.
	InstallationRevision uint64
	// BuildIncarnation identifies the exact build the process is running, as
	// the host established it — never as the process reported it.
	BuildIncarnation string
}

// OperationBinding seals an operation context to exactly one binding, at one
// revision, in one incarnation. Verification resolves the binding identity
// rather than searching for a binding whose scopes would admit the call: a
// superset of scopes is not a licence to act as a different binding.
type OperationBinding struct {
	BindingID          string
	BindingRevision    uint64
	BindingIncarnation string
}

// SealedInstallation reads the installation a token is sealed to, for a
// transport that names it beside the capability. It reads the token's own
// content without checking the signature, which is sound only because nothing
// trusts the result: the carrier it fills is a pre-check, and a verifier that
// prefers it over the sealed claim has made the carrier into authority.
//
// A token with no readable seal is an error here, so no transport can attach a
// capability while leaving the installation blank.
func SealedInstallation(token WorkContextToken) (id string, revision string, err error) {
	_, seal, _, err := readSealedToken(token)
	if err != nil {
		return "", "", err
	}
	return seal.InstallationID, decimal(seal.InstallationRevision), nil
}

func (s Seal) validate() error {
	if s.PrincipalEpoch == 0 {
		return fmt.Errorf("%w: seal principal_epoch is required", ErrWorkContextInvalid)
	}
	if err := validateBounded("seal installation_id", s.InstallationID, workContextMaxIDBytes, true); err != nil {
		return err
	}
	if s.InstallationRevision == 0 {
		return fmt.Errorf("%w: seal installation_revision is required", ErrWorkContextInvalid)
	}
	if err := validateBounded("seal build_incarnation", s.BuildIncarnation, workContextMaxIDBytes, true); err != nil {
		return err
	}
	return nil
}

func (b OperationBinding) validate() error {
	if err := validateBounded("operation_binding_id", b.BindingID, workContextMaxIDBytes, true); err != nil {
		return err
	}
	if b.BindingRevision == 0 {
		return fmt.Errorf("%w: operation_binding_revision is required", ErrWorkContextInvalid)
	}
	if err := validateBounded("operation_binding_incarnation", b.BindingIncarnation, workContextMaxIDBytes, true); err != nil {
		return err
	}
	return nil
}

// SealExpectations are the sealed values a verifier holds as current. Every
// field is required: a verifier that does not know which installation revision
// it is on cannot refuse a credential from an older one, so leaving a field
// unset is refused instead of being read as "any".
type SealExpectations struct {
	PrincipalEpoch       uint64
	InstallationID       string
	InstallationRevision uint64
	BuildIncarnation     string
}

// OperationBindingExpectations identify the one binding a verifier will accept
// an operation context for. Pass it when the call is an operation context;
// leave it nil and a credential carrying an operation binding is refused,
// because a credential issued to act through one binding must not be presented
// where no binding was named.
type OperationBindingExpectations struct {
	BindingID          string
	BindingRevision    uint64
	BindingIncarnation string
}

func (e SealExpectations) validate() error {
	if e.PrincipalEpoch == 0 {
		return fmt.Errorf("%w: expected principal_epoch is required", ErrWorkContextInvalid)
	}
	if err := validateBounded("expected installation_id", e.InstallationID, workContextMaxIDBytes, true); err != nil {
		return err
	}
	if e.InstallationRevision == 0 {
		return fmt.Errorf("%w: expected installation_revision is required", ErrWorkContextInvalid)
	}
	if err := validateBounded("expected build_incarnation", e.BuildIncarnation, workContextMaxIDBytes, true); err != nil {
		return err
	}
	return nil
}

func (e OperationBindingExpectations) validate() error {
	if err := validateBounded("expected operation_binding_id", e.BindingID, workContextMaxIDBytes, true); err != nil {
		return err
	}
	if e.BindingRevision == 0 {
		return fmt.Errorf("%w: expected operation_binding_revision is required", ErrWorkContextInvalid)
	}
	if err := validateBounded("expected operation_binding_incarnation", e.BindingIncarnation, workContextMaxIDBytes, true); err != nil {
		return err
	}
	return nil
}

// matchSeal compares a credential's seal with what the verifier holds. Each
// field is a separate refusal so the reason a call failed is the reason, not a
// single opaque mismatch: a stale installation revision is re-mintable and a
// wrong installation is not, and a caller that cannot tell them apart either
// retries what will never succeed or fails what one mint would fix.
func matchSeal(seal Seal, expected SealExpectations) error {
	if err := expected.validate(); err != nil {
		return err
	}
	if seal.InstallationID != expected.InstallationID {
		return fmt.Errorf(
			"%w: credential is sealed to installation %q, presented to %q",
			ErrWorkContextInvalid, seal.InstallationID, expected.InstallationID,
		)
	}
	if seal.BuildIncarnation != expected.BuildIncarnation {
		return fmt.Errorf(
			"%w: credential is sealed to build incarnation %q, presented to %q",
			ErrWorkContextInvalid, seal.BuildIncarnation, expected.BuildIncarnation,
		)
	}
	if seal.PrincipalEpoch != expected.PrincipalEpoch {
		return fmt.Errorf(
			"%w: credential is sealed to principal epoch %d, issuer is at %d",
			ErrWorkContextSuperseded, seal.PrincipalEpoch, expected.PrincipalEpoch,
		)
	}
	if seal.InstallationRevision != expected.InstallationRevision {
		return fmt.Errorf(
			"%w: credential is sealed to installation revision %d, verifier holds %d",
			ErrWorkContextSuperseded, seal.InstallationRevision, expected.InstallationRevision,
		)
	}
	return nil
}

// matchOperationBinding resolves the sealed binding identity against the one
// binding the verifier will accept. All three values must agree: a binding id
// at a different revision is a different authorization, and the same revision
// in a different incarnation is a different deployment of it.
func matchOperationBinding(binding *OperationBinding, expected *OperationBindingExpectations) error {
	switch {
	case expected == nil && binding == nil:
		return nil
	case expected == nil:
		return fmt.Errorf(
			"%w: credential is sealed to operation binding %q, presented where no binding was named",
			ErrWorkContextInvalid, binding.BindingID,
		)
	case binding == nil:
		return fmt.Errorf(
			"%w: operation binding %q expected, credential seals none",
			ErrWorkContextInvalid, expected.BindingID,
		)
	}
	if err := expected.validate(); err != nil {
		return err
	}
	if binding.BindingID != expected.BindingID {
		return fmt.Errorf(
			"%w: credential is sealed to operation binding %q, presented to %q",
			ErrWorkContextInvalid, binding.BindingID, expected.BindingID,
		)
	}
	if binding.BindingIncarnation != expected.BindingIncarnation {
		return fmt.Errorf(
			"%w: operation binding %q is sealed to incarnation %q, verifier holds %q",
			ErrWorkContextInvalid, binding.BindingID, binding.BindingIncarnation, expected.BindingIncarnation,
		)
	}
	if binding.BindingRevision != expected.BindingRevision {
		return fmt.Errorf(
			"%w: operation binding %q is sealed to revision %d, verifier holds %d",
			ErrWorkContextSuperseded, binding.BindingID, binding.BindingRevision, expected.BindingRevision,
		)
	}
	return nil
}

// decimal encodes a uint64 for the wire. Revisions and epochs travel as decimal
// strings for the same reason authorization_revision does: a JSON number loses
// the top of the uint64 domain in any JavaScript verifier, and a credential
// that verifies in Go and not in the browser is worse than one that verifies
// nowhere.
func decimal(value uint64) string {
	return strconv.FormatUint(value, 10)
}

func parseDecimal(name string, encoded string) (uint64, error) {
	value, err := strconv.ParseUint(encoded, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("%w: %s must be a uint64 decimal string", ErrWorkContextInvalid, name)
	}
	return value, nil
}
