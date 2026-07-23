package codefly

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
)

const (
	defaultWorkContextJWKSCacheTTL       = 5 * time.Minute
	defaultWorkContextJWKSRequestTimeout = 2 * time.Second
	maxWorkContextJWKSCacheTTL           = 24 * time.Hour
	maxWorkContextJWKSRequestTimeout     = 30 * time.Second
	maxWorkContextJWKSBytes              = 256 * 1024
	maxWorkContextJWKSKeys               = 64
)

// WorkContextJWKSVerifierOptions configures rotation-aware public Work Context
// verification. The verifier caches only public keys and never stores bearer
// tokens or private material.
type WorkContextJWKSVerifierOptions struct {
	URL            string
	HTTPClient     *http.Client
	CacheTTL       time.Duration
	RequestTimeout time.Duration
	Now            func() time.Time
	ClockSkew      time.Duration
}

// WorkContextJWKSVerifier verifies signed Work Contexts against a bounded,
// cached Ed25519 JWKS. An unknown key ID forces one generation-aware refresh,
// so rotation is picked up immediately without a request stampede.
type WorkContextJWKSVerifier struct {
	mu                       sync.Mutex
	url                      string
	httpClient               *http.Client
	cacheTTL                 time.Duration
	requestTimeout           time.Duration
	now                      func() time.Time
	clockSkew                time.Duration
	verifier                 *WorkContextVerifier
	keyIDs                   map[string]struct{}
	expiresAt                time.Time
	generation               uint64
	unknownRefreshGeneration uint64
}

// NewWorkContextJWKSVerifier validates configuration without performing
// network I/O. The first Verify call fetches the JWKS.
func NewWorkContextJWKSVerifier(
	options WorkContextJWKSVerifierOptions,
) (*WorkContextJWKSVerifier, error) {
	endpoint, err := validateWorkContextJWKSURL(options.URL)
	if err != nil {
		return nil, err
	}
	cacheTTL := options.CacheTTL
	if cacheTTL == 0 {
		cacheTTL = defaultWorkContextJWKSCacheTTL
	}
	if cacheTTL < time.Second || cacheTTL > maxWorkContextJWKSCacheTTL {
		return nil, fmt.Errorf(
			"%w: JWKS cache TTL must be between 1s and %s",
			ErrWorkContextInvalid,
			maxWorkContextJWKSCacheTTL,
		)
	}
	requestTimeout := options.RequestTimeout
	if requestTimeout == 0 {
		requestTimeout = defaultWorkContextJWKSRequestTimeout
	}
	if requestTimeout < time.Millisecond || requestTimeout > maxWorkContextJWKSRequestTimeout {
		return nil, fmt.Errorf(
			"%w: JWKS request timeout must be between 1ms and %s",
			ErrWorkContextInvalid,
			maxWorkContextJWKSRequestTimeout,
		)
	}
	now := options.Now
	if now == nil {
		now = time.Now
	}
	client := options.HTTPClient
	if client == nil {
		client = &http.Client{
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
	}
	return &WorkContextJWKSVerifier{
		url: endpoint, httpClient: client, cacheTTL: cacheTTL,
		requestTimeout: requestTimeout, now: now, clockSkew: options.ClockSkew,
	}, nil
}

// Verify establishes Work Context trust using the current cached JWKS.
func (v *WorkContextJWKSVerifier) Verify(
	ctx context.Context,
	token WorkContextToken,
	expected WorkContextExpectations,
) (*basev0.WorkContextV1, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: nil JWKS verifier", ErrWorkContextInvalid)
	}
	if ctx == nil {
		return nil, fmt.Errorf("%w: nil context", ErrWorkContextInvalid)
	}
	keyID, err := workContextTokenKeyID(token)
	if err != nil {
		return nil, err
	}
	verifier, keyIDs, generation, err := v.current(ctx)
	if err != nil {
		return nil, err
	}
	if _, known := keyIDs[keyID]; known {
		return verifier.Verify(token, expected)
	}

	// A different caller may already have refreshed this generation. Passing
	// the observed generation lets that refresh satisfy every waiter.
	verifier, _, _, err = v.refreshUnknown(ctx, generation)
	if err != nil {
		return nil, err
	}
	return verifier.Verify(token, expected)
}

func (v *WorkContextJWKSVerifier) current(
	ctx context.Context,
) (*WorkContextVerifier, map[string]struct{}, uint64, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.verifier != nil && v.now().UTC().Before(v.expiresAt) {
		return v.verifier, cloneKeyIDs(v.keyIDs), v.generation, nil
	}
	verifier, keyIDs, generation, err := v.refreshLocked(ctx)
	if err == nil {
		// A scheduled cache refresh starts a fresh generation in which one
		// unknown key may force an early refresh for normal key rotation.
		v.unknownRefreshGeneration = 0
	}
	return verifier, keyIDs, generation, err
}

func (v *WorkContextJWKSVerifier) refreshUnknown(
	ctx context.Context,
	observedGeneration uint64,
) (*WorkContextVerifier, map[string]struct{}, uint64, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.verifier != nil && v.generation != observedGeneration {
		return v.verifier, cloneKeyIDs(v.keyIDs), v.generation, nil
	}
	if v.verifier != nil && v.unknownRefreshGeneration == v.generation {
		return v.verifier, cloneKeyIDs(v.keyIDs), v.generation, nil
	}

	// Reserve this generation before network I/O. A failed rotation refresh
	// must not let attacker-controlled key IDs turn verification into an
	// unbounded JWKS request loop. The normal TTL refresh opens a new window.
	v.unknownRefreshGeneration = v.generation
	verifier, keyIDs, generation, err := v.refreshLocked(ctx)
	if err != nil {
		return nil, nil, generation, err
	}
	v.unknownRefreshGeneration = generation
	return verifier, keyIDs, generation, nil
}

func (v *WorkContextJWKSVerifier) refreshLocked(
	ctx context.Context,
) (*WorkContextVerifier, map[string]struct{}, uint64, error) {
	keys, err := v.fetch(ctx)
	if err != nil {
		return nil, nil, v.generation, err
	}
	verifier, err := NewWorkContextVerifier(WorkContextVerifierOptions{
		PublicKeys: keys,
		Now:        v.now,
		ClockSkew:  v.clockSkew,
	})
	if err != nil {
		return nil, nil, v.generation, err
	}
	keyIDs := make(map[string]struct{}, len(keys))
	for keyID := range keys {
		keyIDs[keyID] = struct{}{}
	}
	if v.generation == ^uint64(0) {
		return nil, nil, v.generation, fmt.Errorf("%w: JWKS generation exhausted", ErrWorkContextInvalid)
	}
	v.verifier = verifier
	v.keyIDs = keyIDs
	v.expiresAt = v.now().UTC().Add(v.cacheTTL)
	v.generation++
	return verifier, cloneKeyIDs(keyIDs), v.generation, nil
}

func (v *WorkContextJWKSVerifier) fetch(ctx context.Context) (map[string]ed25519.PublicKey, error) {
	requestContext, cancel := context.WithTimeout(ctx, v.requestTimeout)
	defer cancel()
	request, err := http.NewRequestWithContext(requestContext, http.MethodGet, v.url, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: create JWKS request: %v", ErrWorkContextInvalid, err)
	}
	request.Header.Set("Accept", "application/json")
	response, err := v.httpClient.Do(request)
	if err != nil {
		return nil, fmt.Errorf("%w: fetch Work Context JWKS: %v", ErrWorkContextInvalid, err)
	}
	defer response.Body.Close()
	if response.Request != nil && response.Request.URL != nil &&
		response.Request.URL.String() != v.url {
		return nil, fmt.Errorf("%w: Work Context JWKS redirected", ErrWorkContextInvalid)
	}
	if response.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4*1024))
		return nil, fmt.Errorf(
			"%w: Work Context JWKS returned HTTP %d",
			ErrWorkContextInvalid,
			response.StatusCode,
		)
	}
	if contentType := response.Header.Get("Content-Type"); contentType != "" {
		mediaType, _, parseErr := mime.ParseMediaType(contentType)
		if parseErr != nil || mediaType != "application/json" {
			return nil, fmt.Errorf("%w: Work Context JWKS is not application/json", ErrWorkContextInvalid)
		}
	}
	payload, err := io.ReadAll(io.LimitReader(response.Body, maxWorkContextJWKSBytes+1))
	if err != nil {
		return nil, fmt.Errorf("%w: read Work Context JWKS: %v", ErrWorkContextInvalid, err)
	}
	if len(payload) > maxWorkContextJWKSBytes {
		return nil, fmt.Errorf(
			"%w: Work Context JWKS exceeds %d bytes",
			ErrWorkContextInvalid,
			maxWorkContextJWKSBytes,
		)
	}
	return parseWorkContextJWKS(payload)
}

type workContextJWKS struct {
	Keys []workContextJWK `json:"keys"`
}

type workContextJWK struct {
	KeyType string `json:"kty"`
	Curve   string `json:"crv"`
	Use     string `json:"use"`
	Alg     string `json:"alg"`
	KeyID   string `json:"kid"`
	X       string `json:"x"`
}

func parseWorkContextJWKS(payload []byte) (map[string]ed25519.PublicKey, error) {
	var document workContextJWKS
	if err := json.Unmarshal(payload, &document); err != nil {
		return nil, fmt.Errorf("%w: decode Work Context JWKS: %v", ErrWorkContextInvalid, err)
	}
	if len(document.Keys) == 0 || len(document.Keys) > maxWorkContextJWKSKeys {
		return nil, fmt.Errorf(
			"%w: Work Context JWKS must contain between 1 and %d keys",
			ErrWorkContextInvalid,
			maxWorkContextJWKSKeys,
		)
	}
	keys := make(map[string]ed25519.PublicKey, len(document.Keys))
	for _, key := range document.Keys {
		if key.KeyType != "OKP" || key.Curve != "Ed25519" ||
			key.Alg != "" && key.Alg != "EdDSA" ||
			key.Use != "" && key.Use != "sig" {
			return nil, fmt.Errorf("%w: JWKS contains a non-Ed25519 signing key", ErrWorkContextInvalid)
		}
		if err := validateBounded("key_id", key.KeyID, workContextMaxKindBytes, true); err != nil {
			return nil, err
		}
		decoded, err := base64.RawURLEncoding.DecodeString(key.X)
		if err != nil || len(decoded) != ed25519.PublicKeySize {
			return nil, fmt.Errorf(
				"%w: JWKS key %q has an invalid Ed25519 public key",
				ErrWorkContextInvalid,
				key.KeyID,
			)
		}
		if _, duplicate := keys[key.KeyID]; duplicate {
			return nil, fmt.Errorf("%w: JWKS has duplicate key ID %q", ErrWorkContextInvalid, key.KeyID)
		}
		keys[key.KeyID] = append(ed25519.PublicKey(nil), decoded...)
	}
	return keys, nil
}

func workContextTokenKeyID(token WorkContextToken) (string, error) {
	if token.empty() {
		return "", fmt.Errorf("%w: empty token", ErrWorkContextInvalid)
	}
	payloadSegment, _, found := strings.Cut(token.encoded, ".")
	if !found {
		return "", fmt.Errorf("%w: malformed token", ErrWorkContextInvalid)
	}
	payload, err := base64.RawURLEncoding.DecodeString(payloadSegment)
	if err != nil {
		return "", fmt.Errorf("%w: malformed token payload", ErrWorkContextInvalid)
	}
	probe := struct {
		KeyID string `json:"key_id"`
	}{}
	if err := json.Unmarshal(payload, &probe); err != nil {
		return "", fmt.Errorf("%w: decode key id: %v", ErrWorkContextInvalid, err)
	}
	if err := validateBounded("key_id", probe.KeyID, workContextMaxKindBytes, true); err != nil {
		return "", err
	}
	return probe.KeyID, nil
}

func validateWorkContextJWKSURL(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Host == "" || parsed.User != nil ||
		parsed.Fragment != "" || parsed.RawQuery != "" ||
		parsed.Scheme != "http" && parsed.Scheme != "https" {
		return "", fmt.Errorf("%w: Work Context JWKS URL must be an absolute HTTP(S) URL without credentials, query, or fragment", ErrWorkContextInvalid)
	}
	return parsed.String(), nil
}

func cloneKeyIDs(source map[string]struct{}) map[string]struct{} {
	cloned := make(map[string]struct{}, len(source))
	for keyID := range source {
		cloned[keyID] = struct{}{}
	}
	return cloned
}
