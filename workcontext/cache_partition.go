package workcontext

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"slices"
	"strconv"

	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
	"google.golang.org/protobuf/proto"
)

// cachePartitionViewDomain separates the view digest from every other SHA-256 a
// component computes, so no other structure can be made to collide with it.
const cachePartitionViewDomain = "codefly.work-context.cache-partition.view.v2\n"

// cachePartitionViewerDomain does the same for the viewer digest, so a subject
// can never be made to spell a view.
const cachePartitionViewerDomain = "codefly.work-context.cache-partition.viewer.v2\n"

// CachePartition is the identity partition a cache stack scopes its entries to.
// It is plain data on purpose: the cache takes it as an opaque value built from
// these two fields and never learns what a Work Context is.
type CachePartition struct {
	// Key is stable for one tenant on one installation revision (and, with
	// ByAuthorizationView, one effective authorization view). It contains only
	// base64url, hex and ':'.
	Key string

	// WriteAround asks the stack to bypass cached reads and writes for this
	// call. It is true for a capability carrying an approval grant hop: that
	// hop is the one audited exception to the attenuation rule, so the answer
	// was computed under authority nobody else holds — caching it would serve
	// an approved call's result to callers who were never approved, and reading
	// from the cache would answer the approved call from an unapproved
	// computation.
	WriteAround bool
}

// CachePartitionOption refines the partition DeriveCachePartition computes.
type CachePartitionOption func(*cachePartitionOptions)

type cachePartitionOptions struct {
	byAuthorizationView bool
	byViewer            bool
}

// ByAuthorizationView partitions by what the caller may do as well as by
// tenant: the key adds a digest of the effective scopes and the authorization
// revision.
//
// It is only safe when the result depends on scopes alone. Scopes are not the
// viewer: a service that authorizes per subject — per-subject resource grants,
// or a row predicate over the caller's identity — gives every caller with the
// same scopes the same partition, so one caller's entries are served to
// another. Every reader of a collection holds the same read scope, and a
// revision is a number they share. Use ByViewer for anything whose content
// varies by who is asking.
func ByAuthorizationView() CachePartitionOption {
	return func(options *cachePartitionOptions) {
		options.byAuthorizationView = true
	}
}

// ByViewer partitions by the identity authorization is evaluated as, on top of
// the authorization view: the key adds a digest of the effective actor — the
// current actor's hop, or the owner principal for a direct owner call, which is
// the same identity core's Verified.Actor reports.
//
// This is the option for a result that varies by who is asking, which is any
// result a service computes by authorizing the caller rather than by reading
// their scopes. It implies the authorization view rather than replacing it:
// without the revision in the key, a caller whose grants were revoked would
// keep being served the partition they held before, so a subject digest alone
// would trade a cross-caller leak for a stale-authority one.
func ByViewer() CachePartitionOption {
	return func(options *cachePartitionOptions) {
		options.byViewer = true
	}
}

// DeriveCachePartition computes the cache partition for a verified capability.
// The key always carries the tenant and the sealed installation at its sealed
// revision. It never carries the session, task, nonce or audience: those
// identify an execution, not an authorization, so a child session or an
// audience exchange with the same effective view shares its parent's partition
// instead of fragmenting the cache per hop.
//
// It takes core's *Verified and nothing else, so there is no way to derive a
// partition from a capability nobody verified. The installation revision is in
// the key, not optional, and that is the whole point of it being there: an
// answer computed while the host held revision N was computed under the
// authority of revision N, and nothing about it survives the host moving to
// N+1. A revision bump therefore lands every caller in a fresh partition,
// which is a cache miss by design and never a stale hit. The installation id
// travels with the revision because revision numbers are per-installation and
// two installations share their small integers.
func DeriveCachePartition(
	verified *Verified,
	options ...CachePartitionOption,
) (CachePartition, error) {
	if verified == nil || verified.Context() == nil {
		return CachePartition{}, fmt.Errorf("%w: a cache partition requires a verified Work Context", ErrInvalid)
	}
	claims := verified.Context()
	seal := claims.GetSeal()
	if seal.GetInstallationId() == "" || seal.GetInstallationRevision() == 0 {
		return CachePartition{}, fmt.Errorf("%w: a cache partition requires the sealed installation", ErrUnsealed)
	}
	var settings cachePartitionOptions
	for _, option := range options {
		if option != nil {
			option(&settings)
		}
	}
	// Tenant and installation IDs are free-form, so the key encodes rather than
	// embeds them: no tenant or installation can contain the delimiter and
	// spell another one's view key.
	//
	// The "wc3" prefix is not decoration. A shared cache that outlives the
	// deploy — Redis, a warehouse table — still holds keys computed under an
	// earlier scheme, and those keys would otherwise be reachable by a process
	// that now partitions correctly. Changing the prefix orphans them instead.
	key := "wc3:t:" + base64.RawURLEncoding.EncodeToString([]byte(claims.GetTenantId())) +
		":i:" + base64.RawURLEncoding.EncodeToString([]byte(seal.GetInstallationId())) +
		":r:" + strconv.FormatUint(seal.GetInstallationRevision(), 10)
	if settings.byAuthorizationView || settings.byViewer {
		digest, err := authorizationViewDigest(verified)
		if err != nil {
			return CachePartition{}, err
		}
		key += ":v:" + digest
	}
	if settings.byViewer {
		key += ":s:" + viewerDigest(verified)
	}
	return CachePartition{Key: key, WriteAround: claims.GetGrantHop() != nil}, nil
}

// viewerDigest hashes the effective actor. The kind travels with the id because
// the two namespaces are independent: an owner whose id is "x" and a delegated
// agent whose id is "x" are different callers. The agent identity and the
// organization travel with them for the same reason — authorization is
// evaluated per organization, so two organizations' callers must never share a
// partition even when one principal acts in both.
func viewerDigest(verified *Verified) string {
	claims := verified.Context()
	principalID := claims.GetOwnerPrincipalId()
	kind := claims.GetOwnerPrincipalKind()
	agentID := claims.GetOwnerAgentId()
	organization := claims.GetOrganizationId()
	if actor := verified.Actor(); actor != nil {
		principalID = actor.GetPrincipalId()
		kind = actor.GetPrincipalKind()
		agentID = actor.GetAgentId()
		if actor.GetOrganizationId() != "" {
			organization = actor.GetOrganizationId()
		}
	}
	preimage := []byte(cachePartitionViewerDomain)
	for _, field := range []string{principalID, kind, agentID, organization} {
		preimage = appendField(preimage, []byte(field))
	}
	sum := sha256.Sum256(preimage)
	return hex.EncodeToString(sum[:])
}

// authorizationViewDigest hashes the effective scopes — core's
// Verified.EffectiveScopes, so this module never decides for itself which hop a
// caller's authority comes from — together with the authorization revision.
//
// The preimage is length-prefixed binary rather than a text encoding: every
// field is framed by its own length, so no scope can contain a delimiter and
// spell another view. The scopes are canonicalized first, so the order a minter
// was handed them in never changes the digest.
func authorizationViewDigest(verified *Verified) (string, error) {
	scopes, err := canonicalScopes(verified.EffectiveScopes())
	if err != nil {
		return "", err
	}
	preimage := binary.BigEndian.AppendUint64(
		[]byte(cachePartitionViewDomain), verified.Context().GetAuthorizationRevision(),
	)
	preimage = binary.BigEndian.AppendUint32(preimage, uint32(len(scopes)))
	for _, scope := range scopes {
		preimage = appendField(preimage, scope)
	}
	sum := sha256.Sum256(preimage)
	return hex.EncodeToString(sum[:]), nil
}

// canonicalScopes encodes each scope deterministically and sorts the
// encodings, which puts a set of scopes in one order without this module
// defining what "first" means for a scope. Each scope's own repeated fields are
// sorted before encoding, for the same reason.
func canonicalScopes(scopes []*basev0.WorkScopeV1) ([][]byte, error) {
	encoded := make([][]byte, 0, len(scopes))
	for _, scope := range scopes {
		if scope == nil {
			continue
		}
		clone, ok := proto.Clone(scope).(*basev0.WorkScopeV1)
		if !ok {
			return nil, fmt.Errorf("%w: scope clone is not a scope", ErrInvalid)
		}
		slices.Sort(clone.Actions)
		clone.Actions = slices.Compact(clone.Actions)
		slices.Sort(clone.ResourceIds)
		clone.ResourceIds = slices.Compact(clone.ResourceIds)
		raw, err := proto.MarshalOptions{Deterministic: true}.Marshal(clone)
		if err != nil {
			return nil, fmt.Errorf("%w: encode scope: %v", ErrInvalid, err)
		}
		encoded = append(encoded, raw)
	}
	slices.SortFunc(encoded, bytes.Compare)
	return encoded, nil
}

// appendField frames one value by its length, so a digest preimage cannot be
// read two ways.
func appendField(preimage []byte, field []byte) []byte {
	preimage = binary.BigEndian.AppendUint32(preimage, uint32(len(field)))
	return append(preimage, field...)
}
