package workcontext

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
)

const (
	// WorkContextHeaderName is the only HTTP carrier for a signed Work Context.
	// Product code should call AttachWorkContext instead of naming this header.
	WorkContextHeaderName = "x-codefly-work-context"

	WorkContextType      = "codefly.work-context/v1"
	WorkContextAlgorithm = "Ed25519"

	WorkContextReplayIdempotent = "idempotent"
	WorkContextReplaySingleUse  = "single-use"

	WorkContextMaxActorDepth = 16
	WorkContextMaxTokenBytes = 32 * 1024
)

const (
	workContextMaxIDBytes      = 512
	workContextMaxKindBytes    = 128
	workContextMaxScopes       = 64
	workContextMaxScopeEntries = 256
)

var (
	WorkContextDefaultTTL = 5 * time.Minute
	WorkContextMaxTTL     = 15 * time.Minute
	WorkContextClockSkew  = time.Minute

	ErrWorkContextInvalid = errors.New("invalid Codefly Work Context")
	// ErrWorkContextUnavailable marks a fail-closed rejection caused by the key
	// set being unreachable (transport failure or an issuer 5xx/429) rather than
	// by the token itself. Callers should treat it as retryable — HTTP 503, not
	// 401 — since an otherwise-valid context must not be dropped during an outage.
	ErrWorkContextUnavailable = errors.New("Codefly Work Context verification unavailable")
	ErrWorkContextDenied      = errors.New("Codefly Work Context scope denied")
	// ErrWorkContextSuperseded marks a credential that was sound when it was
	// minted and has been overtaken since: the principal epoch, the
	// installation revision or the binding revision has moved on. It is
	// distinct from ErrWorkContextInvalid because the two need opposite
	// responses — a superseded credential is replaced by minting again, and
	// the holder can do that unaided, while an invalid one never becomes
	// valid. It is equally distinct from ErrWorkContextUnavailable: nothing is
	// unreachable, so retrying the same credential is guaranteed to fail and a
	// retry loop is the one thing a caller must not do.
	ErrWorkContextSuperseded = errors.New("Codefly Work Context superseded")
)

// WorkContextToken is an opaque signed capability. Its encoded representation
// is exposed only for storage and transport adapters; use AttachWorkContext for
// HTTP requests and WorkContextVerifier for trust decisions.
type WorkContextToken struct {
	encoded string
}

// Encoded returns the signed wire value for persistence or a non-HTTP transport.
func (t WorkContextToken) Encoded() string {
	return t.encoded
}

func (t WorkContextToken) empty() bool {
	return t.encoded == ""
}

// ParseWorkContextToken validates only the bounded two-segment wire shape. It
// does not establish trust; call WorkContextVerifier.Verify before using claims.
func ParseWorkContextToken(encoded string) (WorkContextToken, error) {
	if err := validateTokenShape(encoded); err != nil {
		return WorkContextToken{}, err
	}
	return WorkContextToken{encoded: encoded}, nil
}

// AttachWorkContext installs a credential on an outbound request without
// exposing the carrier names to application code. It sets the signed
// capability and, beside it, the installation the capability is sealed to, so
// every outbound request carries the installation the host will re-check the
// call against.
//
// The installation headers are a pre-check the host may refuse on cheaply.
// They are not authority and no verifier may prefer them: they are read out of
// the token here without checking its signature, which is sound only because
// nothing downstream trusts them. The installation that governs a call is the
// sealed one.
//
// A token with no readable seal is refused rather than attached bare. There is
// no request on which an unsealed credential is better than no credential.
func AttachWorkContext(request *http.Request, token WorkContextToken) error {
	if request == nil {
		return fmt.Errorf("%w: nil HTTP request", ErrWorkContextInvalid)
	}
	if token.empty() {
		return fmt.Errorf("%w: empty token", ErrWorkContextInvalid)
	}
	_, seal, _, err := readSealedToken(token)
	if err != nil {
		return err
	}
	request.Header.Set(WorkContextHeaderName, token.encoded)
	request.Header.Set(InstallationIDHeaderName, seal.InstallationID)
	request.Header.Set(InstallationRevisionHeaderName, decimal(seal.InstallationRevision))
	return nil
}

// readSealedToken reads a token's own content without checking its signature.
// It exists for the two jobs a holder has to do with a credential it was just
// handed: know when to renew it, and name its installation on the way out.
// Neither is a trust decision, and nothing in this package authorizes from its
// result — VerifyWorkContext is the only thing that does that, and it checks
// the signature first.
func readSealedToken(token WorkContextToken) (*basev0.WorkContextV1, Seal, *OperationBinding, error) {
	payload, _, err := decodeWorkContextToken(token.encoded)
	if err != nil {
		return nil, Seal{}, nil, err
	}
	sealed, err := unmarshalWorkContext(payload)
	if err != nil {
		return nil, Seal{}, nil, err
	}
	if err := validateSealedContext(sealed); err != nil {
		return nil, Seal{}, nil, err
	}
	return sealed.context, sealed.seal, sealed.binding, nil
}

// WorkContextFromHeaders extracts an opaque token. It does not verify it.
func WorkContextFromHeaders(headers http.Header) (WorkContextToken, error) {
	if headers == nil {
		return WorkContextToken{}, fmt.Errorf("%w: missing HTTP headers", ErrWorkContextInvalid)
	}
	return ParseWorkContextToken(headers.Get(WorkContextHeaderName))
}

// WorkContextSigner is an authority-side capability. Product applications
// should receive tokens from an authority/exchange endpoint, not receive this
// signer or its private key.
type WorkContextSigner struct {
	issuer     string
	keyID      string
	privateKey ed25519.PrivateKey
	now        func() time.Time
	nonce      func() (string, error)
}

type WorkContextSignerOptions struct {
	Issuer     string
	KeyID      string
	PrivateKey ed25519.PrivateKey
	Now        func() time.Time
	Nonce      func() (string, error)
}

func NewWorkContextSigner(options WorkContextSignerOptions) (*WorkContextSigner, error) {
	if err := validateBounded("issuer", options.Issuer, workContextMaxIDBytes, true); err != nil {
		return nil, err
	}
	if err := validateBounded("key_id", options.KeyID, workContextMaxKindBytes, true); err != nil {
		return nil, err
	}
	if len(options.PrivateKey) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("%w: Ed25519 private key must be %d bytes", ErrWorkContextInvalid, ed25519.PrivateKeySize)
	}
	now := options.Now
	if now == nil {
		now = time.Now
	}
	nonce := options.Nonce
	if nonce == nil {
		nonce = randomWorkContextNonce
	}
	return &WorkContextSigner{
		issuer:     options.Issuer,
		keyID:      options.KeyID,
		privateKey: append(ed25519.PrivateKey(nil), options.PrivateKey...),
		now:        now,
		nonce:      nonce,
	}, nil
}

// StartTaskInput creates a Task and its first root Session capability.
type StartTaskInput struct {
	Audience         string
	TenantID         string
	OwnerPrincipalID string
	// OwnerPrincipalKind is the sort of principal the owner is. It is required:
	// the principal id namespaces are independent, so a user and an agent may
	// share an id string without being the same caller, and a verifier that
	// cannot tell them apart cannot check the delegating principal at all.
	OwnerPrincipalKind string
	// OwnerAgentID is the owner's agent manifest identity. Required when
	// OwnerPrincipalKind is "agent" and refused otherwise.
	OwnerAgentID string
	// Seal binds this credential to the execution it is minted for. Required.
	Seal Seal
	// OperationBinding seals the credential to exactly one binding. Set it only
	// for an operation context.
	OperationBinding      *OperationBinding
	TaskID                string
	SessionID             string
	AuthorizationRevision uint64
	ReplayPolicy          string
	AuthorityScopes       []*basev0.WorkScopeV1
	ActorChain            []*basev0.WorkActorV1
	AttributionTeamIDs    []string
	WorkspaceID           string
	ProjectID             string
	TTL                   time.Duration
	NotBefore             time.Time
}

// StartTask constructs and signs an immutable Task/root-Session context.
func (s *WorkContextSigner) StartTask(input StartTaskInput) (WorkContextToken, *basev0.WorkContextV1, error) {
	if s == nil {
		return WorkContextToken{}, nil, fmt.Errorf("%w: nil signer", ErrWorkContextInvalid)
	}
	now := s.now().UTC().Truncate(time.Second)
	ttl := input.TTL
	if ttl == 0 {
		ttl = WorkContextDefaultTTL
	}
	notBefore := input.NotBefore
	if notBefore.IsZero() {
		notBefore = now
	}
	nonce, err := s.nonce()
	if err != nil {
		return WorkContextToken{}, nil, fmt.Errorf("%w: generate nonce: %v", ErrWorkContextInvalid, err)
	}
	replayPolicy := input.ReplayPolicy
	if replayPolicy == "" {
		replayPolicy = WorkContextReplayIdempotent
	}
	context := &basev0.WorkContextV1{
		Typ:                   WorkContextType,
		Algorithm:             WorkContextAlgorithm,
		KeyId:                 s.keyID,
		Issuer:                s.issuer,
		Audience:              input.Audience,
		NotBeforeUnix:         notBefore.UTC().Truncate(time.Second).Unix(),
		IssuedAtUnix:          now.Unix(),
		ExpiresAtUnix:         now.Add(ttl).Unix(),
		Nonce:                 nonce,
		AuthorizationRevision: input.AuthorizationRevision,
		ReplayPolicy:          replayPolicy,
		TenantId:              input.TenantID,
		OwnerPrincipalId:      input.OwnerPrincipalID,
		TaskId:                input.TaskID,
		SessionId:             input.SessionID,
		AuthorityScopes:       cloneScopes(input.AuthorityScopes),
		ActorChain:            cloneActors(input.ActorChain),
		AttributionTeamIds:    append([]string(nil), input.AttributionTeamIDs...),
	}
	if input.OwnerPrincipalKind != "" {
		context.OwnerPrincipalKind = stringPointer(input.OwnerPrincipalKind)
	}
	if input.OwnerAgentID != "" {
		context.OwnerAgentId = stringPointer(input.OwnerAgentID)
	}
	if input.WorkspaceID != "" {
		context.WorkspaceId = stringPointer(input.WorkspaceID)
	}
	if input.ProjectID != "" {
		context.ProjectId = stringPointer(input.ProjectID)
	}
	binding := input.OperationBinding
	if binding != nil {
		copied := *binding
		binding = &copied
	}
	return s.sign(sealedContext{context: context, seal: input.Seal, binding: binding})
}

// StartRootSessionInput exchanges a valid capability for another root Session
// under the same Task. Identity, owner, scopes, actors, and attribution cannot
// be changed by the caller.
type StartRootSessionInput struct {
	SessionID    string
	Audience     string
	ReplayPolicy string
	TTL          time.Duration
}

// ExchangeWorkContextAudienceInput reissues one verified Work Context for a
// different consumer. Immutable work and delegation identity is preserved.
// AttenuatedScopes, when non-nil, replaces the effective scopes and must be a
// subset of the parent's effective scopes.
type ExchangeWorkContextAudienceInput struct {
	Audience         string
	ReplayPolicy     string
	TTL              time.Duration
	AttenuatedScopes []*basev0.WorkScopeV1
}

// ExchangeWorkContextAudience reissues a capability for another audience
// without creating a new Task, Session, actor, or delegation. Authorities use
// this when one logical execution crosses service trust boundaries. An
// exchange may reduce effective authority but can never widen it.
func (s *WorkContextSigner) ExchangeWorkContextAudience(
	parent WorkContextToken,
	input ExchangeWorkContextAudienceInput,
) (WorkContextToken, *basev0.WorkContextV1, error) {
	verified, err := s.verifyOwn(parent)
	if err != nil {
		return WorkContextToken{}, nil, err
	}
	next := verified.clone()
	if input.AttenuatedScopes != nil {
		attenuated := cloneScopes(input.AttenuatedScopes)
		canonicalizeScopes(attenuated)
		effective := verified.context.GetAuthorityScopes()
		if actors := verified.context.GetActorChain(); len(actors) > 0 {
			effective = actors[len(actors)-1].GetGrantedScopes()
		}
		if !scopesAttenuate(effective, attenuated) {
			return WorkContextToken{}, nil, fmt.Errorf(
				"%w: audience exchange widens authority",
				ErrWorkContextInvalid,
			)
		}
		if actors := next.context.GetActorChain(); len(actors) > 0 {
			actors[len(actors)-1].GrantedScopes = attenuated
		} else {
			next.context.AuthorityScopes = attenuated
		}
	}
	return s.exchange(
		next,
		input.Audience,
		input.ReplayPolicy,
		input.TTL,
	)
}

func (s *WorkContextSigner) StartSession(parent WorkContextToken, input StartRootSessionInput) (WorkContextToken, *basev0.WorkContextV1, error) {
	verified, err := s.verifyOwn(parent)
	if err != nil {
		return WorkContextToken{}, nil, err
	}
	next := verified.clone()
	next.context.SessionId = input.SessionID
	next.context.ParentSessionId = nil
	return s.exchange(next, input.Audience, input.ReplayPolicy, input.TTL)
}

// StartChildSessionInput appends exactly one verified Actor and creates a child
// Session. The new actor's scopes must attenuate the parent's effective scope.
type StartChildSessionInput struct {
	SessionID    string
	Audience     string
	Actor        *basev0.WorkActorV1
	ReplayPolicy string
	TTL          time.Duration
}

func (s *WorkContextSigner) StartChildSession(parent WorkContextToken, input StartChildSessionInput) (WorkContextToken, *basev0.WorkContextV1, error) {
	verified, err := s.verifyOwn(parent)
	if err != nil {
		return WorkContextToken{}, nil, err
	}
	next := verified.clone()
	next.context.ParentSessionId = stringPointer(verified.context.SessionId)
	next.context.SessionId = input.SessionID
	next.context.ActorChain = append(next.context.ActorChain, cloneActor(input.Actor))
	return s.exchange(next, input.Audience, input.ReplayPolicy, input.TTL)
}

// exchange re-signs a verified credential for another audience, session or
// actor. The seal travels unchanged: an exchange moves authority between
// boundaries inside one execution, and the execution is exactly what the seal
// names. A hop that could restate the seal would be a hop that could move a
// credential onto another build or another installation.
func (s *WorkContextSigner) exchange(sealed sealedContext, audience, replayPolicy string, ttl time.Duration) (WorkContextToken, *basev0.WorkContextV1, error) {
	context := sealed.context
	now := s.now().UTC().Truncate(time.Second)
	if ttl == 0 {
		ttl = WorkContextDefaultTTL
	}
	if audience == "" {
		audience = context.Audience
	}
	if replayPolicy == "" {
		replayPolicy = context.ReplayPolicy
	}
	nonce, err := s.nonce()
	if err != nil {
		return WorkContextToken{}, nil, fmt.Errorf("%w: generate nonce: %v", ErrWorkContextInvalid, err)
	}
	context.Typ = WorkContextType
	context.Algorithm = WorkContextAlgorithm
	context.KeyId = s.keyID
	context.Issuer = s.issuer
	context.Audience = audience
	context.NotBeforeUnix = now.Unix()
	context.IssuedAtUnix = now.Unix()
	context.ExpiresAtUnix = now.Add(ttl).Unix()
	context.Nonce = nonce
	context.ReplayPolicy = replayPolicy
	return s.sign(sealed)
}

// verifyOwn re-reads a credential this signer issued before deriving from it.
// It checks the signature and shape, deliberately not the seal: the authority
// re-signing its own credential is not the party that holds the installation
// revision, and refusing here would make an exchange fail for a reason the
// exchanging authority cannot act on. The seal is what travels, and the
// verifier at the far end is where it is held to the current revision.
func (s *WorkContextSigner) verifyOwn(token WorkContextToken) (sealedContext, error) {
	publicKey, ok := s.privateKey.Public().(ed25519.PublicKey)
	if !ok {
		return sealedContext{}, fmt.Errorf("%w: signer has no Ed25519 public key", ErrWorkContextInvalid)
	}
	verifier, err := NewWorkContextVerifier(WorkContextVerifierOptions{
		PublicKeys: map[string]ed25519.PublicKey{s.keyID: publicKey},
		Now:        s.now,
	})
	if err != nil {
		return sealedContext{}, err
	}
	sealed, err := verifier.decode(token)
	if err != nil {
		return sealedContext{}, err
	}
	if sealed.context.GetIssuer() != s.issuer {
		return sealedContext{}, fmt.Errorf("%w: issuer mismatch", ErrWorkContextInvalid)
	}
	return sealed, nil
}

func (s *WorkContextSigner) sign(sealed sealedContext) (WorkContextToken, *basev0.WorkContextV1, error) {
	canonical := sealed.clone()
	canonicalizeWorkContext(canonical.context)
	if err := validateSealedContext(canonical); err != nil {
		return WorkContextToken{}, nil, err
	}
	payload, err := marshalWorkContext(canonical.context, canonical.seal, canonical.binding)
	if err != nil {
		return WorkContextToken{}, nil, err
	}
	signature := ed25519.Sign(s.privateKey, payload)
	encoded := base64.RawURLEncoding.EncodeToString(payload) + "." +
		base64.RawURLEncoding.EncodeToString(signature)
	if len(encoded) > WorkContextMaxTokenBytes {
		return WorkContextToken{}, nil, fmt.Errorf("%w: token exceeds %d bytes", ErrWorkContextInvalid, WorkContextMaxTokenBytes)
	}
	return WorkContextToken{encoded: encoded}, canonical.context, nil
}

type WorkContextVerifier struct {
	publicKeys map[string]ed25519.PublicKey
	now        func() time.Time
	clockSkew  time.Duration
}

type WorkContextVerifierOptions struct {
	PublicKeys map[string]ed25519.PublicKey
	Now        func() time.Time
	ClockSkew  time.Duration
}

func NewWorkContextVerifier(options WorkContextVerifierOptions) (*WorkContextVerifier, error) {
	if len(options.PublicKeys) == 0 {
		return nil, fmt.Errorf("%w: no public verification keys", ErrWorkContextInvalid)
	}
	keys := make(map[string]ed25519.PublicKey, len(options.PublicKeys))
	for keyID, publicKey := range options.PublicKeys {
		if err := validateBounded("key_id", keyID, workContextMaxKindBytes, true); err != nil {
			return nil, err
		}
		if len(publicKey) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("%w: public key %q must be %d bytes", ErrWorkContextInvalid, keyID, ed25519.PublicKeySize)
		}
		keys[keyID] = append(ed25519.PublicKey(nil), publicKey...)
	}
	now := options.Now
	if now == nil {
		now = time.Now
	}
	clockSkew := options.ClockSkew
	if clockSkew == 0 {
		clockSkew = WorkContextClockSkew
	}
	if clockSkew < 0 || clockSkew > WorkContextClockSkew {
		return nil, fmt.Errorf("%w: clock skew must be between zero and %s", ErrWorkContextInvalid, WorkContextClockSkew)
	}
	return &WorkContextVerifier{publicKeys: keys, now: now, clockSkew: clockSkew}, nil
}

// WorkContextExpectations is what a verifier holds as current. Identity
// expectations that are left empty are not checked, as before. The seal is
// different: it is required, because a verifier that does not state which
// installation revision and build it is on cannot refuse a credential from an
// earlier one, and a credential nobody holds to an installation is a bearer
// token.
type WorkContextExpectations struct {
	Issuer                string
	Audience              string
	TenantID              string
	TaskID                string
	SessionID             string
	ParentSessionID       *string
	AuthorizationRevision *uint64

	// The delegating principal. OwnerPrincipalKind is checked separately from
	// OwnerPrincipalID: the two id namespaces are independent, so matching an
	// id without its kind matches a different principal that happens to spell
	// the same string.
	OwnerPrincipalID   string
	OwnerPrincipalKind string

	// Delegation describes the calling principal — the final actor of a
	// delegated credential — and is checked separately from the owner above.
	//
	// nil means this verifier accepts direct owner calls only, and a credential
	// carrying an actor chain is refused. That is deliberate: a service that
	// never considered delegation would otherwise accept a delegated caller
	// silently, having checked only the principal that delegated rather than
	// the one that is actually calling.
	Delegation *DelegationExpectations

	// Seal is required. See SealExpectations.
	Seal SealExpectations

	// OperationBinding names the one binding an operation context may be
	// presented for. nil means no binding was named, and a credential sealed
	// to one is refused rather than accepted as if it were an ordinary
	// credential that happens to carry extra fields.
	OperationBinding *OperationBindingExpectations
}

// DelegationExpectations is what a verifier holds about the calling principal.
// Empty fields are not checked; the presence of the struct is itself the
// statement that a delegated credential is acceptable here.
type DelegationExpectations struct {
	PrincipalID   string
	PrincipalKind string
	DelegationID  string
}

// WorkContextScopeRequirement identifies one exact capability a verified Work
// Context must grant. An empty ResourceID asks whether the effective scope
// grants every resource of ResourceKind; it never ignores explicit resource
// restrictions.
type WorkContextScopeRequirement struct {
	ResourceKind            string
	Action                  string
	ResourceID              string
	RequireExplicitResource bool
}

// RequireWorkContextScope evaluates the current actor's effective scope. The
// authority scopes apply to a direct owner call; when actors are present, only
// the final actor's monotonically attenuated granted scopes are effective.
//
// It takes a verified credential rather than claims. Taking claims meant a
// caller could authorize from a hand-constructed protobuf or from a token that
// was parsed and never verified, and the defensive re-validation that used to
// stand here could not tell those apart from a real one — it checked the shape
// of the claims, not where they came from.
//
// Scope is the last question, not the first: the credential has already been
// held to its seal and its binding by the time this runs. A scope that would
// admit the call never widens the binding it was granted under.
func RequireWorkContextScope(
	verified VerifiedWorkContext,
	requirement WorkContextScopeRequirement,
) error {
	claims := verified.sealed.context
	if claims == nil {
		return fmt.Errorf("%w: scope check requires a verified Work Context", ErrWorkContextInvalid)
	}
	if err := validateBounded(
		"required resource_kind",
		requirement.ResourceKind,
		workContextMaxKindBytes,
		true,
	); err != nil {
		return err
	}
	if err := validateBounded(
		"required action",
		requirement.Action,
		workContextMaxKindBytes,
		true,
	); err != nil {
		return err
	}
	if err := validateBounded(
		"required resource_id",
		requirement.ResourceID,
		workContextMaxIDBytes,
		requirement.RequireExplicitResource,
	); err != nil {
		return err
	}

	effective := claims.GetAuthorityScopes()
	if actors := claims.GetActorChain(); len(actors) > 0 {
		effective = actors[len(actors)-1].GetGrantedScopes()
	}
	for _, scope := range effective {
		if scope.GetResourceKind() != requirement.ResourceKind ||
			!sortedStringsContain(scope.GetActions(), requirement.Action) {
			continue
		}
		resourceIDs := scope.GetResourceIds()
		switch {
		case len(resourceIDs) == 0 && !requirement.RequireExplicitResource:
			return nil
		case requirement.ResourceID != "" &&
			sortedStringsContain(resourceIDs, requirement.ResourceID):
			return nil
		}
	}
	return fmt.Errorf(
		"%w: %s:%s:%s",
		ErrWorkContextDenied,
		requirement.ResourceKind,
		requirement.Action,
		requirement.ResourceID,
	)
}

// decode checks the signature, the structural rules and the lifetime, and
// returns the sealed content. It is not verification: nothing here holds the
// credential to an installation, a build or a caller, so its result must not
// escape this package except through VerifyWorkContext.
func (v *WorkContextVerifier) decode(token WorkContextToken) (sealedContext, error) {
	if v == nil {
		return sealedContext{}, fmt.Errorf("%w: nil verifier", ErrWorkContextInvalid)
	}
	payload, signature, err := decodeWorkContextToken(token.encoded)
	if err != nil {
		return sealedContext{}, err
	}
	probe := struct {
		KeyID string `json:"key_id"`
	}{}
	if decodeErr := json.Unmarshal(payload, &probe); decodeErr != nil {
		return sealedContext{}, fmt.Errorf("%w: decode key id: %v", ErrWorkContextInvalid, decodeErr)
	}
	publicKey, ok := v.publicKeys[probe.KeyID]
	if !ok {
		return sealedContext{}, fmt.Errorf("%w: unknown key id %q", ErrWorkContextInvalid, probe.KeyID)
	}
	// ed25519.Verify panics on a key that is not PublicKeySize bytes. The key
	// is selected by the untrusted token's key id, so one malformed entry would
	// turn every token naming it into a crash of this process, on demand for
	// anyone who learns that key id. NewWorkContextVerifier rejects such a key,
	// which is what makes this a belt rather than the only guard.
	if len(publicKey) != ed25519.PublicKeySize {
		return sealedContext{}, fmt.Errorf(
			"%w: verification key %q is %d bytes, not %d",
			ErrWorkContextInvalid, probe.KeyID, len(publicKey), ed25519.PublicKeySize,
		)
	}
	if !ed25519.Verify(publicKey, payload, signature) {
		return sealedContext{}, fmt.Errorf("%w: signature verification failed", ErrWorkContextInvalid)
	}
	sealed, err := unmarshalWorkContext(payload)
	if err != nil {
		return sealedContext{}, err
	}
	if err := validateSealedContext(sealed); err != nil {
		return sealedContext{}, err
	}
	if err := v.validateTime(sealed.context); err != nil {
		return sealedContext{}, err
	}
	return sealed, nil
}

func (v *WorkContextVerifier) validateTime(context *basev0.WorkContextV1) error {
	now := v.now().UTC()
	notBefore := time.Unix(context.NotBeforeUnix, 0)
	issuedAt := time.Unix(context.IssuedAtUnix, 0)
	expiresAt := time.Unix(context.ExpiresAtUnix, 0)
	if now.Before(notBefore.Add(-v.clockSkew)) {
		return fmt.Errorf("%w: token is not active yet", ErrWorkContextInvalid)
	}
	if issuedAt.After(now.Add(v.clockSkew)) {
		return fmt.Errorf("%w: token was issued in the future", ErrWorkContextInvalid)
	}
	if now.After(expiresAt.Add(v.clockSkew)) {
		return fmt.Errorf("%w: token expired", ErrWorkContextInvalid)
	}
	return nil
}

func matchWorkContext(sealed sealedContext, expected WorkContextExpectations) error {
	context := sealed.context
	checks := []struct {
		name string
		got  string
		want string
	}{
		{"issuer", context.Issuer, expected.Issuer},
		{"audience", context.Audience, expected.Audience},
		{"tenant", context.TenantId, expected.TenantID},
		{"owner", context.OwnerPrincipalId, expected.OwnerPrincipalID},
		{"owner kind", context.GetOwnerPrincipalKind(), expected.OwnerPrincipalKind},
		{"task", context.TaskId, expected.TaskID},
		{"session", context.SessionId, expected.SessionID},
	}
	for _, check := range checks {
		if check.want != "" && check.got != check.want {
			return fmt.Errorf("%w: %s mismatch", ErrWorkContextInvalid, check.name)
		}
	}
	if expected.ParentSessionID != nil && context.GetParentSessionId() != *expected.ParentSessionID {
		return fmt.Errorf("%w: parent session mismatch", ErrWorkContextInvalid)
	}
	if expected.AuthorizationRevision != nil && context.AuthorizationRevision != *expected.AuthorizationRevision {
		return fmt.Errorf("%w: authorization revision mismatch", ErrWorkContextInvalid)
	}
	if err := matchDelegation(context, expected.Delegation); err != nil {
		return err
	}
	if err := matchSeal(sealed.seal, expected.Seal); err != nil {
		return err
	}
	return matchOperationBinding(sealed.binding, expected.OperationBinding)
}

// matchDelegation checks the calling principal. The owner was already checked
// above; this is the separate check, and the two are not interchangeable — a
// credential whose owner is the one this verifier expects may still be
// presented by a delegate it does not.
func matchDelegation(context *basev0.WorkContextV1, expected *DelegationExpectations) error {
	actors := context.GetActorChain()
	if expected == nil {
		if len(actors) > 0 {
			return fmt.Errorf(
				"%w: credential is delegated through %d actor(s) where only a direct owner call is accepted",
				ErrWorkContextInvalid, len(actors),
			)
		}
		return nil
	}
	if len(actors) == 0 {
		return fmt.Errorf("%w: a delegated credential was expected and this one carries no actor", ErrWorkContextInvalid)
	}
	caller := actors[len(actors)-1]
	for _, check := range []struct {
		name string
		got  string
		want string
	}{
		{"caller", caller.GetPrincipalId(), expected.PrincipalID},
		{"caller kind", caller.GetPrincipalKind(), expected.PrincipalKind},
		{"delegation", caller.GetDelegationId(), expected.DelegationID},
	} {
		if check.want != "" && check.got != check.want {
			return fmt.Errorf("%w: %s mismatch", ErrWorkContextInvalid, check.name)
		}
	}
	return nil
}

// The token payload uses one fixed snake_case JSON layout. authorization_revision
// is a decimal string so Go and JavaScript preserve the complete uint64 domain.
type workContextPayload struct {
	Typ                   string             `json:"typ"`
	Algorithm             string             `json:"algorithm"`
	KeyID                 string             `json:"key_id"`
	Issuer                string             `json:"issuer"`
	Audience              string             `json:"audience"`
	NotBeforeUnix         int64              `json:"not_before_unix"`
	IssuedAtUnix          int64              `json:"issued_at_unix"`
	ExpiresAtUnix         int64              `json:"expires_at_unix"`
	Nonce                 string             `json:"nonce"`
	AuthorizationRevision string             `json:"authorization_revision"`
	ReplayPolicy          string             `json:"replay_policy"`
	TenantID              string             `json:"tenant_id"`
	OwnerPrincipalID      string             `json:"owner_principal_id"`
	TaskID                string             `json:"task_id"`
	SessionID             string             `json:"session_id"`
	ParentSessionID       *string            `json:"parent_session_id,omitempty"`
	AuthorityScopes       []workContextScope `json:"authority_scopes"`
	ActorChain            []workContextActor `json:"actor_chain"`
	AttributionTeamIDs    []string           `json:"attribution_team_ids"`
	WorkspaceID           *string            `json:"workspace_id,omitempty"`
	ProjectID             *string            `json:"project_id,omitempty"`
	OwnerPrincipalKind    string             `json:"owner_principal_kind"`
	OwnerAgentID          *string            `json:"owner_agent_id,omitempty"`

	// The seal. These are not claims the owner delegated; they are the binding
	// between this credential and the one execution it was issued to, and
	// every one of them is required.
	PrincipalEpoch       string `json:"owner_principal_epoch"`
	InstallationID       string `json:"installation_id"`
	InstallationRevision string `json:"installation_revision"`
	BuildIncarnation     string `json:"build_incarnation"`

	// The operation binding. Present together or absent together: a partial
	// binding would resolve to a binding identity the verifier never approved.
	OperationBindingID          *string `json:"operation_binding_id,omitempty"`
	OperationBindingRevision    *string `json:"operation_binding_revision,omitempty"`
	OperationBindingIncarnation *string `json:"operation_binding_incarnation,omitempty"`
}

type workContextScope struct {
	ResourceKind string   `json:"resource_kind"`
	Actions      []string `json:"actions"`
	ResourceIDs  []string `json:"resource_ids"`
}

type workContextActor struct {
	PrincipalID   string             `json:"principal_id"`
	PrincipalKind string             `json:"principal_kind"`
	DelegationID  string             `json:"delegation_id"`
	GrantedScopes []workContextScope `json:"granted_scopes"`
}

// sealedContext is the complete signed content of one credential: the
// delegation claims, the seal binding them to a single execution, and the
// operation binding when the credential is an operation context.
//
// Nothing constructs one without a seal. The seal is not an addition to a Work
// Context that may be left out — it is the half that says which process, build
// and installation the other half was issued to, and a credential carrying
// only the other half is a bearer token for anything that holds it.
type sealedContext struct {
	context *basev0.WorkContextV1
	seal    Seal
	binding *OperationBinding
}

func (c sealedContext) clone() sealedContext {
	cloned := sealedContext{context: cloneContext(c.context), seal: c.seal}
	if c.binding != nil {
		binding := *c.binding
		cloned.binding = &binding
	}
	return cloned
}

func marshalWorkContext(context *basev0.WorkContextV1, seal Seal, binding *OperationBinding) ([]byte, error) {
	payload := payloadFromContext(context, seal, binding)
	encoded, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("%w: encode payload: %v", ErrWorkContextInvalid, err)
	}
	return encoded, nil
}

func unmarshalWorkContext(encoded []byte) (sealedContext, error) {
	var payload workContextPayload
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&payload); err != nil {
		return sealedContext{}, fmt.Errorf("%w: decode payload: %v", ErrWorkContextInvalid, err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return sealedContext{}, fmt.Errorf("%w: trailing JSON value", ErrWorkContextInvalid)
		}
		return sealedContext{}, fmt.Errorf("%w: trailing JSON: %v", ErrWorkContextInvalid, err)
	}
	revision, err := strconv.ParseUint(payload.AuthorizationRevision, 10, 64)
	if err != nil {
		return sealedContext{}, fmt.Errorf("%w: authorization_revision must be uint64 decimal", ErrWorkContextInvalid)
	}
	seal, binding, err := sealFromPayload(payload)
	if err != nil {
		return sealedContext{}, err
	}
	return sealedContext{
		context: contextFromPayload(payload, revision),
		seal:    seal,
		binding: binding,
	}, nil
}

// sealFromPayload reads the seal off the wire. A credential whose seal cannot
// be read is rejected here rather than treated as unsealed: "no seal" and
// "a seal I could not parse" must reach the same refusal, because the second
// is what an attacker produces when trying to reach the first.
func sealFromPayload(payload workContextPayload) (Seal, *OperationBinding, error) {
	epoch, err := parseDecimal("owner_principal_epoch", payload.PrincipalEpoch)
	if err != nil {
		return Seal{}, nil, err
	}
	installationRevision, err := parseDecimal("installation_revision", payload.InstallationRevision)
	if err != nil {
		return Seal{}, nil, err
	}
	seal := Seal{
		PrincipalEpoch:       epoch,
		InstallationID:       payload.InstallationID,
		InstallationRevision: installationRevision,
		BuildIncarnation:     payload.BuildIncarnation,
	}
	present := 0
	for _, field := range []*string{
		payload.OperationBindingID,
		payload.OperationBindingRevision,
		payload.OperationBindingIncarnation,
	} {
		if field != nil {
			present++
		}
	}
	switch present {
	case 0:
		return seal, nil, nil
	case 3:
	default:
		return Seal{}, nil, fmt.Errorf(
			"%w: an operation binding needs its id, revision and incarnation together",
			ErrWorkContextInvalid,
		)
	}
	bindingRevision, err := parseDecimal("operation_binding_revision", *payload.OperationBindingRevision)
	if err != nil {
		return Seal{}, nil, err
	}
	return seal, &OperationBinding{
		BindingID:          *payload.OperationBindingID,
		BindingRevision:    bindingRevision,
		BindingIncarnation: *payload.OperationBindingIncarnation,
	}, nil
}

func payloadFromContext(context *basev0.WorkContextV1, seal Seal, binding *OperationBinding) workContextPayload {
	payload := workContextPayload{
		Typ:                   context.Typ,
		Algorithm:             context.Algorithm,
		KeyID:                 context.KeyId,
		Issuer:                context.Issuer,
		Audience:              context.Audience,
		NotBeforeUnix:         context.NotBeforeUnix,
		IssuedAtUnix:          context.IssuedAtUnix,
		ExpiresAtUnix:         context.ExpiresAtUnix,
		Nonce:                 context.Nonce,
		AuthorizationRevision: strconv.FormatUint(context.AuthorizationRevision, 10),
		ReplayPolicy:          context.ReplayPolicy,
		TenantID:              context.TenantId,
		OwnerPrincipalID:      context.OwnerPrincipalId,
		TaskID:                context.TaskId,
		SessionID:             context.SessionId,
		ParentSessionID:       cloneStringPointer(context.ParentSessionId),
		AuthorityScopes:       payloadScopes(context.AuthorityScopes),
		ActorChain:            payloadActors(context.ActorChain),
		AttributionTeamIDs:    append([]string{}, context.AttributionTeamIds...),
		WorkspaceID:           cloneStringPointer(context.WorkspaceId),
		ProjectID:             cloneStringPointer(context.ProjectId),
		OwnerPrincipalKind:    context.GetOwnerPrincipalKind(),
		OwnerAgentID:          cloneStringPointer(context.OwnerAgentId),
		PrincipalEpoch:        decimal(seal.PrincipalEpoch),
		InstallationID:        seal.InstallationID,
		InstallationRevision:  decimal(seal.InstallationRevision),
		BuildIncarnation:      seal.BuildIncarnation,
	}
	if binding != nil {
		payload.OperationBindingID = stringPointer(binding.BindingID)
		payload.OperationBindingRevision = stringPointer(decimal(binding.BindingRevision))
		payload.OperationBindingIncarnation = stringPointer(binding.BindingIncarnation)
	}
	return payload
}

func payloadScopes(scopes []*basev0.WorkScopeV1) []workContextScope {
	out := make([]workContextScope, 0, len(scopes))
	for _, scope := range scopes {
		if scope == nil {
			out = append(out, workContextScope{})
			continue
		}
		out = append(out, workContextScope{
			ResourceKind: scope.ResourceKind,
			Actions:      append([]string{}, scope.Actions...),
			ResourceIDs:  append([]string{}, scope.ResourceIds...),
		})
	}
	return out
}

func payloadActors(actors []*basev0.WorkActorV1) []workContextActor {
	out := make([]workContextActor, 0, len(actors))
	for _, actor := range actors {
		if actor == nil {
			out = append(out, workContextActor{})
			continue
		}
		out = append(out, workContextActor{
			PrincipalID:   actor.PrincipalId,
			PrincipalKind: actor.PrincipalKind,
			DelegationID:  actor.DelegationId,
			GrantedScopes: payloadScopes(actor.GrantedScopes),
		})
	}
	return out
}

func contextFromPayload(payload workContextPayload, revision uint64) *basev0.WorkContextV1 {
	context := &basev0.WorkContextV1{
		Typ:                   payload.Typ,
		Algorithm:             payload.Algorithm,
		KeyId:                 payload.KeyID,
		Issuer:                payload.Issuer,
		Audience:              payload.Audience,
		NotBeforeUnix:         payload.NotBeforeUnix,
		IssuedAtUnix:          payload.IssuedAtUnix,
		ExpiresAtUnix:         payload.ExpiresAtUnix,
		Nonce:                 payload.Nonce,
		AuthorizationRevision: revision,
		ReplayPolicy:          payload.ReplayPolicy,
		TenantId:              payload.TenantID,
		OwnerPrincipalId:      payload.OwnerPrincipalID,
		TaskId:                payload.TaskID,
		SessionId:             payload.SessionID,
		ParentSessionId:       cloneStringPointer(payload.ParentSessionID),
		AuthorityScopes:       contextScopes(payload.AuthorityScopes),
		ActorChain:            contextActors(payload.ActorChain),
		AttributionTeamIds:    append([]string(nil), payload.AttributionTeamIDs...),
		WorkspaceId:           cloneStringPointer(payload.WorkspaceID),
		ProjectId:             cloneStringPointer(payload.ProjectID),
		OwnerPrincipalKind:    stringPointer(payload.OwnerPrincipalKind),
		OwnerAgentId:          cloneStringPointer(payload.OwnerAgentID),
	}
	return context
}

func contextScopes(scopes []workContextScope) []*basev0.WorkScopeV1 {
	out := make([]*basev0.WorkScopeV1, 0, len(scopes))
	for _, scope := range scopes {
		out = append(out, &basev0.WorkScopeV1{
			ResourceKind: scope.ResourceKind,
			Actions:      append([]string(nil), scope.Actions...),
			ResourceIds:  append([]string(nil), scope.ResourceIDs...),
		})
	}
	return out
}

func contextActors(actors []workContextActor) []*basev0.WorkActorV1 {
	out := make([]*basev0.WorkActorV1, 0, len(actors))
	for _, actor := range actors {
		out = append(out, &basev0.WorkActorV1{
			PrincipalId:   actor.PrincipalID,
			PrincipalKind: actor.PrincipalKind,
			DelegationId:  actor.DelegationID,
			GrantedScopes: contextScopes(actor.GrantedScopes),
		})
	}
	return out
}

// PrincipalKindAgent is the owner kind that requires an agent manifest
// identity beside the principal id.
const PrincipalKindAgent = "agent"

// validateSealedContext is the whole structural rule for a credential: the
// delegation claims, the seal, and the operation binding when there is one.
// Signing and verification both go through it, so a credential this module
// would refuse is never one it hands out.
func validateSealedContext(sealed sealedContext) error {
	if err := validateWorkContext(sealed.context); err != nil {
		return err
	}
	if err := sealed.seal.validate(); err != nil {
		return err
	}
	if sealed.binding != nil {
		if err := sealed.binding.validate(); err != nil {
			return err
		}
	}
	return nil
}

func validateWorkContext(context *basev0.WorkContextV1) error {
	if context == nil {
		return fmt.Errorf("%w: nil claims", ErrWorkContextInvalid)
	}
	if context.Typ != WorkContextType {
		return fmt.Errorf("%w: unsupported typ %q", ErrWorkContextInvalid, context.Typ)
	}
	if context.Algorithm != WorkContextAlgorithm {
		return fmt.Errorf("%w: unsupported algorithm %q", ErrWorkContextInvalid, context.Algorithm)
	}
	fields := []struct {
		name  string
		value string
		max   int
	}{
		{"key_id", context.KeyId, workContextMaxKindBytes},
		{"issuer", context.Issuer, workContextMaxIDBytes},
		{"audience", context.Audience, workContextMaxIDBytes},
		{"nonce", context.Nonce, workContextMaxIDBytes},
		{"tenant_id", context.TenantId, workContextMaxIDBytes},
		{"owner_principal_id", context.OwnerPrincipalId, workContextMaxIDBytes},
		{"task_id", context.TaskId, workContextMaxIDBytes},
		{"session_id", context.SessionId, workContextMaxIDBytes},
	}
	for _, field := range fields {
		if err := validateBounded(field.name, field.value, field.max, true); err != nil {
			return err
		}
	}
	// These proto fields are optional, but each declares min_len=1: absent is
	// allowed, present-but-empty is not. min_len is a length rule, so the guard
	// is emptiness, not whitespace-trimming — a proto-generated verifier in
	// another language accepts a one-character value, and this one must agree on
	// the same wire bytes.
	for name, value := range map[string]*string{
		"parent_session_id": context.ParentSessionId,
		"workspace_id":      context.WorkspaceId,
		"project_id":        context.ProjectId,
	} {
		if value == nil {
			continue
		}
		if *value == "" {
			return fmt.Errorf("%w: %s must not be empty when present", ErrWorkContextInvalid, name)
		}
		if err := validateBounded(name, *value, workContextMaxIDBytes, false); err != nil {
			return err
		}
	}
	if context.ParentSessionId != nil && context.GetParentSessionId() == context.SessionId {
		return fmt.Errorf("%w: parent session equals session", ErrWorkContextInvalid)
	}
	if err := validateBounded(
		"owner_principal_kind",
		context.GetOwnerPrincipalKind(),
		workContextMaxKindBytes,
		true,
	); err != nil {
		return err
	}
	// The agent manifest identity and the agent kind are one fact stated twice.
	// Allowing either without the other admits a credential that claims to be
	// an agent nothing can name, or names an agent while presenting as a user.
	switch {
	case context.GetOwnerPrincipalKind() == PrincipalKindAgent:
		if err := validateBounded("owner_agent_id", context.GetOwnerAgentId(), workContextMaxIDBytes, true); err != nil {
			return err
		}
	case context.OwnerAgentId != nil:
		return fmt.Errorf(
			"%w: owner_agent_id is set on a %q owner",
			ErrWorkContextInvalid, context.GetOwnerPrincipalKind(),
		)
	}
	if context.ReplayPolicy != WorkContextReplayIdempotent && context.ReplayPolicy != WorkContextReplaySingleUse {
		return fmt.Errorf("%w: unsupported replay policy %q", ErrWorkContextInvalid, context.ReplayPolicy)
	}
	if context.NotBeforeUnix > context.ExpiresAtUnix {
		return fmt.Errorf("%w: not-before is after expiry", ErrWorkContextInvalid)
	}
	if context.IssuedAtUnix > context.ExpiresAtUnix {
		return fmt.Errorf("%w: issued-at is after expiry", ErrWorkContextInvalid)
	}
	if ttl := time.Duration(context.ExpiresAtUnix-context.IssuedAtUnix) * time.Second; ttl <= 0 || ttl > WorkContextMaxTTL {
		return fmt.Errorf("%w: lifetime must be positive and at most %s", ErrWorkContextInvalid, WorkContextMaxTTL)
	}
	if len(context.ActorChain) > WorkContextMaxActorDepth {
		return fmt.Errorf("%w: actor chain exceeds depth %d", ErrWorkContextInvalid, WorkContextMaxActorDepth)
	}
	if len(context.AttributionTeamIds) > workContextMaxScopeEntries {
		return fmt.Errorf("%w: too many attribution teams", ErrWorkContextInvalid)
	}
	if err := validateSortedUniqueStrings("attribution_team_ids", context.AttributionTeamIds, workContextMaxIDBytes, true); err != nil {
		return err
	}
	if err := validateScopes("authority_scopes", context.AuthorityScopes); err != nil {
		return err
	}
	previous := context.AuthorityScopes
	for index, actor := range context.ActorChain {
		if actor == nil {
			return fmt.Errorf("%w: actor_chain[%d] is nil", ErrWorkContextInvalid, index)
		}
		if err := validateBounded("actor principal_id", actor.PrincipalId, workContextMaxIDBytes, true); err != nil {
			return err
		}
		if err := validateBounded("actor principal_kind", actor.PrincipalKind, workContextMaxKindBytes, true); err != nil {
			return err
		}
		if err := validateBounded("actor delegation_id", actor.DelegationId, workContextMaxIDBytes, true); err != nil {
			return err
		}
		if err := validateScopes(fmt.Sprintf("actor_chain[%d].granted_scopes", index), actor.GrantedScopes); err != nil {
			return err
		}
		if !scopesAttenuate(previous, actor.GrantedScopes) {
			return fmt.Errorf("%w: actor_chain[%d] widens authority", ErrWorkContextInvalid, index)
		}
		previous = actor.GrantedScopes
	}
	return nil
}

func validateScopes(name string, scopes []*basev0.WorkScopeV1) error {
	if len(scopes) > workContextMaxScopes {
		return fmt.Errorf("%w: %s exceeds %d scopes", ErrWorkContextInvalid, name, workContextMaxScopes)
	}
	previousKind := ""
	for index, scope := range scopes {
		if scope == nil {
			return fmt.Errorf("%w: %s[%d] is nil", ErrWorkContextInvalid, name, index)
		}
		if err := validateBounded(name+" resource_kind", scope.ResourceKind, workContextMaxKindBytes, true); err != nil {
			return err
		}
		if previousKind >= scope.ResourceKind {
			return fmt.Errorf("%w: %s resource kinds must be sorted and unique", ErrWorkContextInvalid, name)
		}
		previousKind = scope.ResourceKind
		if len(scope.Actions) == 0 || len(scope.Actions) > workContextMaxScopeEntries {
			return fmt.Errorf("%w: %s[%d] actions must contain 1..%d entries", ErrWorkContextInvalid, name, index, workContextMaxScopeEntries)
		}
		if err := validateSortedUniqueStrings(name+" actions", scope.Actions, workContextMaxKindBytes, true); err != nil {
			return err
		}
		if len(scope.ResourceIds) > workContextMaxScopeEntries {
			return fmt.Errorf("%w: %s[%d] has too many resource IDs", ErrWorkContextInvalid, name, index)
		}
		if err := validateSortedUniqueStrings(name+" resource_ids", scope.ResourceIds, workContextMaxIDBytes, true); err != nil {
			return err
		}
	}
	return nil
}

func scopesAttenuate(parent, child []*basev0.WorkScopeV1) bool {
	parentByKind := make(map[string]*basev0.WorkScopeV1, len(parent))
	for _, scope := range parent {
		parentByKind[scope.ResourceKind] = scope
	}
	for _, scope := range child {
		ancestor, ok := parentByKind[scope.ResourceKind]
		if !ok || !stringSubset(scope.Actions, ancestor.Actions) {
			return false
		}
		if len(ancestor.ResourceIds) > 0 {
			// Empty means wildcard, so an explicit parent set may only be
			// narrowed to another non-empty subset.
			if len(scope.ResourceIds) == 0 || !stringSubset(scope.ResourceIds, ancestor.ResourceIds) {
				return false
			}
		}
	}
	return true
}

func stringSubset(child, parent []string) bool {
	parentSet := make(map[string]struct{}, len(parent))
	for _, value := range parent {
		parentSet[value] = struct{}{}
	}
	for _, value := range child {
		if _, ok := parentSet[value]; !ok {
			return false
		}
	}
	return true
}

func sortedStringsContain(values []string, wanted string) bool {
	index := sort.SearchStrings(values, wanted)
	return index < len(values) && values[index] == wanted
}

func canonicalizeWorkContext(context *basev0.WorkContextV1) {
	context.AttributionTeamIds = sortedUnique(context.AttributionTeamIds)
	canonicalizeScopes(context.AuthorityScopes)
	for _, actor := range context.ActorChain {
		if actor != nil {
			canonicalizeScopes(actor.GrantedScopes)
		}
	}
}

func canonicalizeScopes(scopes []*basev0.WorkScopeV1) {
	for _, scope := range scopes {
		if scope == nil {
			continue
		}
		scope.Actions = sortedUnique(scope.Actions)
		scope.ResourceIds = sortedUnique(scope.ResourceIds)
	}
	sort.SliceStable(scopes, func(i, j int) bool {
		if scopes[i] == nil {
			return scopes[j] != nil
		}
		if scopes[j] == nil {
			return false
		}
		return scopes[i].ResourceKind < scopes[j].ResourceKind
	})
}

func sortedUnique(values []string) []string {
	out := append([]string(nil), values...)
	sort.Strings(out)
	if len(out) < 2 {
		return out
	}
	write := 1
	for read := 1; read < len(out); read++ {
		if out[read] == out[write-1] {
			continue
		}
		out[write] = out[read]
		write++
	}
	return out[:write]
}

func validateSortedUniqueStrings(name string, values []string, max int, nonEmpty bool) error {
	previous := ""
	for index, value := range values {
		if err := validateBounded(name, value, max, nonEmpty); err != nil {
			return err
		}
		if index > 0 && previous >= value {
			return fmt.Errorf("%w: %s must be sorted and unique", ErrWorkContextInvalid, name)
		}
		previous = value
	}
	return nil
}

func validateBounded(name, value string, max int, required bool) error {
	if required && strings.TrimSpace(value) == "" {
		return fmt.Errorf("%w: %s is required", ErrWorkContextInvalid, name)
	}
	if len(value) > max {
		return fmt.Errorf("%w: %s exceeds %d bytes", ErrWorkContextInvalid, name, max)
	}
	return nil
}

func validateTokenShape(encoded string) error {
	if encoded == "" {
		return fmt.Errorf("%w: empty token", ErrWorkContextInvalid)
	}
	if len(encoded) > WorkContextMaxTokenBytes {
		return fmt.Errorf("%w: token exceeds %d bytes", ErrWorkContextInvalid, WorkContextMaxTokenBytes)
	}
	if strings.Count(encoded, ".") != 1 {
		return fmt.Errorf("%w: token must have exactly two segments", ErrWorkContextInvalid)
	}
	return nil
}

func decodeWorkContextToken(encoded string) ([]byte, []byte, error) {
	if err := validateTokenShape(encoded); err != nil {
		return nil, nil, err
	}
	segments := strings.SplitN(encoded, ".", 2)
	payload, err := base64.RawURLEncoding.DecodeString(segments[0])
	if err != nil {
		return nil, nil, fmt.Errorf("%w: payload base64: %v", ErrWorkContextInvalid, err)
	}
	if base64.RawURLEncoding.EncodeToString(payload) != segments[0] {
		return nil, nil, fmt.Errorf("%w: payload is not canonical base64url", ErrWorkContextInvalid)
	}
	signature, err := base64.RawURLEncoding.DecodeString(segments[1])
	if err != nil {
		return nil, nil, fmt.Errorf("%w: signature base64: %v", ErrWorkContextInvalid, err)
	}
	if base64.RawURLEncoding.EncodeToString(signature) != segments[1] {
		return nil, nil, fmt.Errorf("%w: signature is not canonical base64url", ErrWorkContextInvalid)
	}
	if len(signature) != ed25519.SignatureSize {
		return nil, nil, fmt.Errorf("%w: signature must be %d bytes", ErrWorkContextInvalid, ed25519.SignatureSize)
	}
	return payload, signature, nil
}

func randomWorkContextNonce() (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw[:]), nil
}

func cloneContext(context *basev0.WorkContextV1) *basev0.WorkContextV1 {
	if context == nil {
		return nil
	}
	return &basev0.WorkContextV1{
		Typ:                   context.Typ,
		Algorithm:             context.Algorithm,
		KeyId:                 context.KeyId,
		Issuer:                context.Issuer,
		Audience:              context.Audience,
		NotBeforeUnix:         context.NotBeforeUnix,
		IssuedAtUnix:          context.IssuedAtUnix,
		ExpiresAtUnix:         context.ExpiresAtUnix,
		Nonce:                 context.Nonce,
		AuthorizationRevision: context.AuthorizationRevision,
		ReplayPolicy:          context.ReplayPolicy,
		TenantId:              context.TenantId,
		OwnerPrincipalId:      context.OwnerPrincipalId,
		TaskId:                context.TaskId,
		SessionId:             context.SessionId,
		ParentSessionId:       cloneStringPointer(context.ParentSessionId),
		AuthorityScopes:       cloneScopes(context.AuthorityScopes),
		ActorChain:            cloneActors(context.ActorChain),
		AttributionTeamIds:    append([]string(nil), context.AttributionTeamIds...),
		WorkspaceId:           cloneStringPointer(context.WorkspaceId),
		ProjectId:             cloneStringPointer(context.ProjectId),
		OwnerPrincipalKind:    cloneStringPointer(context.OwnerPrincipalKind),
		OwnerAgentId:          cloneStringPointer(context.OwnerAgentId),
	}
}

func cloneScopes(scopes []*basev0.WorkScopeV1) []*basev0.WorkScopeV1 {
	out := make([]*basev0.WorkScopeV1, 0, len(scopes))
	for _, scope := range scopes {
		if scope == nil {
			out = append(out, nil)
			continue
		}
		out = append(out, &basev0.WorkScopeV1{
			ResourceKind: scope.ResourceKind,
			Actions:      append([]string(nil), scope.Actions...),
			ResourceIds:  append([]string(nil), scope.ResourceIds...),
		})
	}
	return out
}

func cloneActor(actor *basev0.WorkActorV1) *basev0.WorkActorV1 {
	if actor == nil {
		return nil
	}
	return &basev0.WorkActorV1{
		PrincipalId:   actor.PrincipalId,
		PrincipalKind: actor.PrincipalKind,
		DelegationId:  actor.DelegationId,
		GrantedScopes: cloneScopes(actor.GrantedScopes),
	}
}

func cloneActors(actors []*basev0.WorkActorV1) []*basev0.WorkActorV1 {
	out := make([]*basev0.WorkActorV1, 0, len(actors))
	for _, actor := range actors {
		out = append(out, cloneActor(actor))
	}
	return out
}

func stringPointer(value string) *string {
	return &value
}

func cloneStringPointer(value *string) *string {
	if value == nil {
		return nil
	}
	copy := *value
	return &copy
}
