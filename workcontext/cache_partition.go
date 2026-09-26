package workcontext

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"

	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
)

// cachePartitionViewDomain separates the view digest from every other SHA-256
// a Codefly component computes, so no other structure can be made to collide
// with it.
const cachePartitionViewDomain = "codefly.work-context.cache-partition.view.v1\n"

// VerifiedWorkContext is a Work Context whose signature, lifetime and
// expectations a verifier has checked. Only VerifyWorkContext on a verifier
// constructs one, so code holding it cannot be holding a hand-built protobuf or
// a token that was parsed but never verified. Its zero value is not verified
// and every consumer rejects it.
type VerifiedWorkContext struct {
	claims *basev0.WorkContextV1
}

// Claims returns a copy of the verified claims. Mutating the copy changes
// nothing this value derives.
func (v VerifiedWorkContext) Claims() *basev0.WorkContextV1 {
	return cloneContext(v.claims)
}

// VerifyWorkContext is Verify, returning a value that can only have come from
// verification. Use it wherever the result feeds a trust-sensitive derivation
// such as DeriveCachePartition.
func (v *WorkContextVerifier) VerifyWorkContext(
	token WorkContextToken,
	expected WorkContextExpectations,
) (VerifiedWorkContext, error) {
	claims, err := v.Verify(token, expected)
	if err != nil {
		return VerifiedWorkContext{}, err
	}
	return VerifiedWorkContext{claims: claims}, nil
}

// VerifyWorkContext is Verify, returning a value that can only have come from
// verification. Use it wherever the result feeds a trust-sensitive derivation
// such as DeriveCachePartition.
func (v *WorkContextJWKSVerifier) VerifyWorkContext(
	ctx context.Context,
	token WorkContextToken,
	expected WorkContextExpectations,
) (VerifiedWorkContext, error) {
	claims, err := v.Verify(ctx, token, expected)
	if err != nil {
		return VerifiedWorkContext{}, err
	}
	return VerifiedWorkContext{claims: claims}, nil
}

// CachePartition is the identity partition a cache stack scopes its entries
// to. It is plain data on purpose: the cache takes it as an opaque value built
// from these two fields and never learns what a Work Context is.
type CachePartition struct {
	// Key is stable for one tenant (and, with ByAuthorizationView, one
	// effective authorization view). It contains only base64url, hex and ':'.
	Key string
	// WriteAround asks the stack to bypass cached reads and writes for this
	// call. It is always false today: the approval-grant hop that should set it
	// does not exist in WorkContextV1 yet (codefly-dev/core#658).
	WriteAround bool
}

// CachePartitionOption refines the partition DeriveCachePartition computes.
type CachePartitionOption func(*cachePartitionOptions)

type cachePartitionOptions struct {
	byAuthorizationView bool
}

// ByAuthorizationView partitions by what the caller is allowed to see as well
// as by tenant: the key adds a digest of the effective scopes and the
// authorization revision. Use it for data whose content varies by viewer; a
// tenant-only partition would serve one viewer's entries to another.
func ByAuthorizationView() CachePartitionOption {
	return func(options *cachePartitionOptions) {
		options.byAuthorizationView = true
	}
}

// DeriveCachePartition computes the cache partition for a verified Work
// Context. The key always carries the tenant. It never carries the session,
// task, nonce or audience: those identify an execution, not an authorization,
// so a child session or an audience exchange with the same effective view
// shares its parent's partition instead of fragmenting the cache per hop.
func DeriveCachePartition(
	verified VerifiedWorkContext,
	options ...CachePartitionOption,
) (CachePartition, error) {
	claims := verified.claims
	if claims == nil {
		return CachePartition{}, fmt.Errorf("%w: cache partition requires a verified Work Context", ErrWorkContextInvalid)
	}
	var settings cachePartitionOptions
	for _, option := range options {
		if option != nil {
			option(&settings)
		}
	}
	// Tenant IDs are free-form, so the key encodes rather than embeds them: no
	// tenant can contain the delimiter and spell another tenant's view key.
	key := "wc1:t:" + base64.RawURLEncoding.EncodeToString([]byte(claims.TenantId))
	if settings.byAuthorizationView {
		digest, err := authorizationViewDigest(claims)
		if err != nil {
			return CachePartition{}, err
		}
		key += ":v:" + digest
	}
	return CachePartition{Key: key}, nil
}

// authorizationViewDigest hashes the effective scopes — the final actor's
// granted scopes, or the authority scopes for a direct owner call, exactly as
// RequireWorkContextScope reads them — together with the authorization
// revision. The scopes are canonicalized first so the order a signer was
// handed them in never changes the digest.
func authorizationViewDigest(claims *basev0.WorkContextV1) (string, error) {
	effective := claims.GetAuthorityScopes()
	if actors := claims.GetActorChain(); len(actors) > 0 {
		effective = actors[len(actors)-1].GetGrantedScopes()
	}
	scopes := cloneScopes(effective)
	canonicalizeScopes(scopes)
	view := struct {
		AuthorizationRevision string             `json:"authorization_revision"`
		Scopes                []workContextScope `json:"scopes"`
	}{
		AuthorizationRevision: strconv.FormatUint(claims.AuthorizationRevision, 10),
		Scopes:                payloadScopes(scopes),
	}
	encoded, err := json.Marshal(view)
	if err != nil {
		return "", fmt.Errorf("%w: encode authorization view: %v", ErrWorkContextInvalid, err)
	}
	sum := sha256.Sum256(append([]byte(cachePartitionViewDomain), encoded...))
	return hex.EncodeToString(sum[:]), nil
}
