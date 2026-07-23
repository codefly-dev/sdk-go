package codefly

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
	ErrWorkContextDenied  = errors.New("Codefly Work Context scope denied")
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

// AttachWorkContext installs a token without exposing the carrier name to
// application code.
func AttachWorkContext(request *http.Request, token WorkContextToken) error {
	if request == nil {
		return fmt.Errorf("%w: nil HTTP request", ErrWorkContextInvalid)
	}
	if token.empty() {
		return fmt.Errorf("%w: empty token", ErrWorkContextInvalid)
	}
	request.Header.Set(WorkContextHeaderName, token.encoded)
	return nil
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
	Audience              string
	TenantID              string
	OwnerPrincipalID      string
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
	if input.WorkspaceID != "" {
		context.WorkspaceId = stringPointer(input.WorkspaceID)
	}
	if input.ProjectID != "" {
		context.ProjectId = stringPointer(input.ProjectID)
	}
	return s.sign(context)
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

func (s *WorkContextSigner) StartSession(parent WorkContextToken, input StartRootSessionInput) (WorkContextToken, *basev0.WorkContextV1, error) {
	verified, err := s.verifyOwn(parent)
	if err != nil {
		return WorkContextToken{}, nil, err
	}
	next := cloneContext(verified)
	next.SessionId = input.SessionID
	next.ParentSessionId = nil
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
	next := cloneContext(verified)
	next.ParentSessionId = stringPointer(verified.SessionId)
	next.SessionId = input.SessionID
	next.ActorChain = append(next.ActorChain, cloneActor(input.Actor))
	return s.exchange(next, input.Audience, input.ReplayPolicy, input.TTL)
}

func (s *WorkContextSigner) exchange(context *basev0.WorkContextV1, audience, replayPolicy string, ttl time.Duration) (WorkContextToken, *basev0.WorkContextV1, error) {
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
	return s.sign(context)
}

func (s *WorkContextSigner) verifyOwn(token WorkContextToken) (*basev0.WorkContextV1, error) {
	publicKey, ok := s.privateKey.Public().(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("%w: signer has no Ed25519 public key", ErrWorkContextInvalid)
	}
	verifier, err := NewWorkContextVerifier(WorkContextVerifierOptions{
		PublicKeys: map[string]ed25519.PublicKey{s.keyID: publicKey},
		Now:        s.now,
	})
	if err != nil {
		return nil, err
	}
	return verifier.Verify(token, WorkContextExpectations{Issuer: s.issuer})
}

func (s *WorkContextSigner) sign(context *basev0.WorkContextV1) (WorkContextToken, *basev0.WorkContextV1, error) {
	canonical := cloneContext(context)
	canonicalizeWorkContext(canonical)
	if err := validateWorkContext(canonical); err != nil {
		return WorkContextToken{}, nil, err
	}
	payload, err := marshalWorkContext(canonical)
	if err != nil {
		return WorkContextToken{}, nil, err
	}
	signature := ed25519.Sign(s.privateKey, payload)
	encoded := base64.RawURLEncoding.EncodeToString(payload) + "." +
		base64.RawURLEncoding.EncodeToString(signature)
	if len(encoded) > WorkContextMaxTokenBytes {
		return WorkContextToken{}, nil, fmt.Errorf("%w: token exceeds %d bytes", ErrWorkContextInvalid, WorkContextMaxTokenBytes)
	}
	return WorkContextToken{encoded: encoded}, canonical, nil
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

type WorkContextExpectations struct {
	Issuer                string
	Audience              string
	TenantID              string
	OwnerPrincipalID      string
	TaskID                string
	SessionID             string
	ParentSessionID       *string
	AuthorizationRevision *uint64
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
// Call this only after signature, time, issuer, and audience verification.
// The claims are structurally validated again so a caller cannot accidentally
// authorize from a hand-constructed or mutated protobuf.
func RequireWorkContextScope(
	claims *basev0.WorkContextV1,
	requirement WorkContextScopeRequirement,
) error {
	if err := validateWorkContext(claims); err != nil {
		return err
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

func (v *WorkContextVerifier) Verify(token WorkContextToken, expected WorkContextExpectations) (*basev0.WorkContextV1, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: nil verifier", ErrWorkContextInvalid)
	}
	payload, signature, err := decodeWorkContextToken(token.encoded)
	if err != nil {
		return nil, err
	}
	probe := struct {
		KeyID string `json:"key_id"`
	}{}
	if err := json.Unmarshal(payload, &probe); err != nil {
		return nil, fmt.Errorf("%w: decode key id: %v", ErrWorkContextInvalid, err)
	}
	publicKey, ok := v.publicKeys[probe.KeyID]
	if !ok {
		return nil, fmt.Errorf("%w: unknown key id %q", ErrWorkContextInvalid, probe.KeyID)
	}
	if !ed25519.Verify(publicKey, payload, signature) {
		return nil, fmt.Errorf("%w: signature verification failed", ErrWorkContextInvalid)
	}
	context, err := unmarshalWorkContext(payload)
	if err != nil {
		return nil, err
	}
	if err := validateWorkContext(context); err != nil {
		return nil, err
	}
	if err := v.validateTime(context); err != nil {
		return nil, err
	}
	if err := matchWorkContext(context, expected); err != nil {
		return nil, err
	}
	return context, nil
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

func matchWorkContext(context *basev0.WorkContextV1, expected WorkContextExpectations) error {
	checks := []struct {
		name string
		got  string
		want string
	}{
		{"issuer", context.Issuer, expected.Issuer},
		{"audience", context.Audience, expected.Audience},
		{"tenant", context.TenantId, expected.TenantID},
		{"owner", context.OwnerPrincipalId, expected.OwnerPrincipalID},
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

func marshalWorkContext(context *basev0.WorkContextV1) ([]byte, error) {
	payload := payloadFromContext(context)
	encoded, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("%w: encode payload: %v", ErrWorkContextInvalid, err)
	}
	return encoded, nil
}

func unmarshalWorkContext(encoded []byte) (*basev0.WorkContextV1, error) {
	var payload workContextPayload
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&payload); err != nil {
		return nil, fmt.Errorf("%w: decode payload: %v", ErrWorkContextInvalid, err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return nil, fmt.Errorf("%w: trailing JSON value", ErrWorkContextInvalid)
		}
		return nil, fmt.Errorf("%w: trailing JSON: %v", ErrWorkContextInvalid, err)
	}
	revision, err := strconv.ParseUint(payload.AuthorizationRevision, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("%w: authorization_revision must be uint64 decimal", ErrWorkContextInvalid)
	}
	return contextFromPayload(payload, revision), nil
}

func payloadFromContext(context *basev0.WorkContextV1) workContextPayload {
	return workContextPayload{
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
	}
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
	for name, value := range map[string]string{
		"parent_session_id": context.GetParentSessionId(),
		"workspace_id":      context.GetWorkspaceId(),
		"project_id":        context.GetProjectId(),
	} {
		if err := validateBounded(name, value, workContextMaxIDBytes, false); err != nil {
			return err
		}
	}
	if context.ParentSessionId != nil && context.GetParentSessionId() == context.SessionId {
		return fmt.Errorf("%w: parent session equals session", ErrWorkContextInvalid)
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
