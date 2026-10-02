package workcontext

import (
	"context"
	"encoding/base64"
	"fmt"
	"math/rand/v2"
	"strconv"
	"strings"
	"testing"
	"time"

	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
	corework "github.com/codefly-dev/core/workcontext"
	"github.com/codefly-dev/core/workcontext/conformance"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

const partitionPropertyIterations = 50

// verified mints a capability and verifies it, because a partition is only
// ever derived from what verification produced.
func (a *authority) verified(t *testing.T, input mintInput) *Verified {
	t.Helper()
	verified, err := a.verifier(t).Verify(context.Background(), a.start(t, input))
	require.NoError(t, err)
	return verified
}

func partition(t *testing.T, verified *Verified, options ...CachePartitionOption) CachePartition {
	t.Helper()
	derived, err := DeriveCachePartition(verified, options...)
	require.NoError(t, err)
	return derived
}

// partitionKeyPrefix is the tenant-and-installation half of every key. The
// installation and its revision are always present, so a test that spells the
// prefix by hand spells all three.
func partitionKeyPrefix(tenant string, revision uint64) string {
	return "wc3:t:" + base64.RawURLEncoding.EncodeToString([]byte(tenant)) +
		":i:" + base64.RawURLEncoding.EncodeToString([]byte(testInstallation)) +
		":r:" + strconv.FormatUint(revision, 10)
}

// A child session with the same effective view shares its parent's partition.
// A session, task or nonce identifies an execution rather than an
// authorization, so putting one in the key would fragment the cache per hop and
// buy nothing: the two calls may read the same entries because they may read
// the same data.
func TestCachePartitionIsStableAcrossHopsWithTheSameView(t *testing.T) {
	a := newAuthority(t)
	scopes := []*basev0.WorkScopeV1{scope("document", "read", "write")}
	owner := a.verified(t, mintInput{scopes: scopes})
	delegated, err := a.verifier(t).Verify(
		context.Background(), a.child(t, a.start(t, mintInput{scopes: scopes}), "actor-1", scopes),
	)
	require.NoError(t, err)

	require.NotEqual(t, owner.Context().GetSessionId(), delegated.Context().GetSessionId())
	require.Equal(t,
		partition(t, owner, ByAuthorizationView()).Key,
		partition(t, delegated, ByAuthorizationView()).Key,
		"the same authority through a delegation hop is the same authorization view",
	)
}

// Tenant, installation revision and effective view each separate partitions on
// their own, and the plain partition carries the first two whether or not a
// caller asks for a view.
func TestCachePartitionSeparatesTenantRevisionAndView(t *testing.T) {
	a := newAuthority(t)
	read := []*basev0.WorkScopeV1{scope("document", "read")}
	write := []*basev0.WorkScopeV1{scope("document", "read", "write")}

	base := a.verified(t, mintInput{scopes: read})
	require.Equal(t, partitionKeyPrefix(testTenant, 3), partition(t, base).Key)

	other := a.verified(t, mintInput{tenant: "tenant-2", scopes: read})
	require.NotEqual(t, partition(t, base).Key, partition(t, other).Key)

	wider := a.verified(t, mintInput{scopes: write})
	require.Equal(t, partition(t, base).Key, partition(t, wider).Key,
		"without ByAuthorizationView the key carries the tenant and installation only")
	require.NotEqual(t,
		partition(t, base, ByAuthorizationView()).Key,
		partition(t, wider, ByAuthorizationView()).Key,
		"a wider scope set is a different authorization view",
	)
}

// The installation revision is in every key, and that is the whole point of it
// being there: an answer computed while the host held revision N was computed
// under the authority of revision N, and nothing about it survives the host
// moving to N+1.
func TestCachePartitionNeverSpansAnInstallationRevision(t *testing.T) {
	a := newAuthority(t)
	before := partition(t, a.verified(t, mintInput{}), ByViewer())

	moved := testSeal
	moved.InstallationRevision++
	require.NoError(t, a.seals.Put(testPrincipal, moved))

	after := partition(t, a.verified(t, mintInput{}), ByViewer())
	require.NotEqual(t, before.Key, after.Key)
	require.True(t, strings.HasPrefix(after.Key, partitionKeyPrefix(testTenant, moved.InstallationRevision)))
}

// A tenant is free-form, so the key encodes it rather than embedding it. A
// tenant that spells the delimiters of another tenant's key must not produce
// that key.
func TestCachePartitionTenantEncodingCannotSpellAnotherView(t *testing.T) {
	a := newAuthority(t)
	honest := a.verified(t, mintInput{tenant: "tenant-1"})
	forged := a.verified(t, mintInput{tenant: "tenant-1:i:" + testInstallation + ":r:3"})
	require.NotEqual(t, partition(t, honest).Key, partition(t, forged).Key)
	require.NotContains(t, partition(t, forged).Key, ":i:"+testInstallation+":r:3:i:")
}

// A partition is derived from a verified capability or not at all. There is no
// accessor that produces one from claims nobody verified, because a caller
// holding one would eventually authorize from it.
func TestCachePartitionRequiresAVerifiedCapability(t *testing.T) {
	_, err := DeriveCachePartition(nil)
	require.ErrorIs(t, err, ErrInvalid)

	var absent *Verified
	_, err = DeriveCachePartition(absent)
	require.ErrorIs(t, err, ErrInvalid)
}

// The order a minter was handed its scopes in must not change the view. The
// digest canonicalizes, so the same authority spelled in any order — with
// duplicate actions and resource ids — is one partition.
func TestAuthorizationViewDigestCanonicalizesScopeOrder(t *testing.T) {
	a := newAuthority(t)
	random := rand.New(rand.NewPCG(1, 2))
	for iteration := range partitionPropertyIterations {
		scopes := randomScopes(random)
		canonical := partition(t, a.verified(t, mintInput{scopes: scopes}), ByAuthorizationView()).Key
		shuffled := partition(t, a.verified(t, mintInput{scopes: shuffledScopes(random, scopes)}), ByAuthorizationView()).Key
		require.Equal(t, canonical, shuffled, "iteration %d: the same authority in another order", iteration)
	}
}

// randomScopes returns a valid, non-empty scope set in a random order with
// duplicated entries, so canonicalization is always exercised.
func randomScopes(random *rand.Rand) []*basev0.WorkScopeV1 {
	kinds := []string{"repository", "record", "document", "profile", "account"}
	random.Shuffle(len(kinds), func(i, j int) { kinds[i], kinds[j] = kinds[j], kinds[i] })
	scopes := make([]*basev0.WorkScopeV1, 0, len(kinds))
	for _, kind := range kinds[:1+random.IntN(len(kinds))] {
		actions := []string{"read", "write", "append", "invoke"}
		random.Shuffle(len(actions), func(i, j int) { actions[i], actions[j] = actions[j], actions[i] })
		actions = actions[:1+random.IntN(len(actions))]
		actions = append(actions, actions[0])
		var resourceIDs []string
		for index := range random.IntN(4) {
			resourceIDs = append(resourceIDs, fmt.Sprintf("%s-%d", kind, index))
		}
		scopes = append(scopes, &basev0.WorkScopeV1{
			ResourceKind: kind, Actions: actions, ResourceIds: resourceIDs,
		})
	}
	return scopes
}

// shuffledScopes is the same authority in a different order.
func shuffledScopes(random *rand.Rand, scopes []*basev0.WorkScopeV1) []*basev0.WorkScopeV1 {
	out := make([]*basev0.WorkScopeV1, 0, len(scopes))
	for _, source := range scopes {
		clone, ok := proto.Clone(source).(*basev0.WorkScopeV1)
		if !ok {
			continue
		}
		random.Shuffle(len(clone.Actions), func(i, j int) {
			clone.Actions[i], clone.Actions[j] = clone.Actions[j], clone.Actions[i]
		})
		random.Shuffle(len(clone.ResourceIds), func(i, j int) {
			clone.ResourceIds[i], clone.ResourceIds[j] = clone.ResourceIds[j], clone.ResourceIds[i]
		})
		out = append(out, clone)
	}
	random.Shuffle(len(out), func(i, j int) { out[i], out[j] = out[j], out[i] })
	return out
}

// Two callers holding the same scopes are not the same viewer. ByViewer is for
// a result that varies by who is asking, which is any result a service computes
// by authorizing the caller rather than by reading their scopes.
func TestCachePartitionByViewerSeparatesSubjectsSharingAView(t *testing.T) {
	a := newAuthority(t)
	scopes := []*basev0.WorkScopeV1{scope("document", "read")}
	parent := a.start(t, mintInput{scopes: scopes})

	first, err := a.verifier(t).Verify(context.Background(), a.child(t, parent, "actor-1", scopes))
	require.NoError(t, err)
	second, err := a.verifier(t).Verify(context.Background(), a.child(t, parent, "actor-2", scopes))
	require.NoError(t, err)

	require.Equal(t,
		partition(t, first, ByAuthorizationView()).Key,
		partition(t, second, ByAuthorizationView()).Key,
		"the two callers hold the same scopes, so they share an authorization view",
	)
	require.NotEqual(t,
		partition(t, first, ByViewer()).Key,
		partition(t, second, ByViewer()).Key,
		"and they are still different callers, which is what ByViewer is for",
	)
	require.Contains(t, partition(t, first, ByViewer()).Key, partition(t, first, ByAuthorizationView()).Key,
		"ByViewer implies the authorization view rather than replacing it",
	)
}

// The viewer is the effective actor — the current hop, or the owner when the
// owner acts directly — which is the identity core's Verified.Actor reports.
func TestCachePartitionByViewerFollowsTheEffectiveActor(t *testing.T) {
	a := newAuthority(t)
	scopes := []*basev0.WorkScopeV1{scope("document", "read")}
	owner := a.verified(t, mintInput{scopes: scopes})
	delegated, err := a.verifier(t).Verify(
		context.Background(), a.child(t, a.start(t, mintInput{scopes: scopes}), "actor-1", scopes),
	)
	require.NoError(t, err)
	require.NotEqual(t,
		partition(t, owner, ByViewer()).Key,
		partition(t, delegated, ByViewer()).Key,
		"an owner acting directly and an actor acting on its authority are different viewers",
	)
}

// A capability carrying an approval grant hop is written around. The hop is the
// one audited exception to the attenuation rule, so the answer was computed
// under authority nobody else holds: caching it would serve an approved call's
// result to callers who were never approved.
//
// The capability comes from core's own conformance kit, so the shape under test
// is the shape core mints rather than one this test invented.
func TestCachePartitionWritesAroundAnApprovalGrant(t *testing.T) {
	now := time.Now()
	settings := conformance.New(now)
	verifier := settings.Verifier()
	fixtures, err := corework.Fixtures(now)
	require.NoError(t, err)

	var seen int
	for _, fixture := range fixtures {
		if fixture.Outcome != corework.OutcomeAccepted {
			continue
		}
		if fixture.Form != corework.FormGrant && fixture.Form != corework.FormSession {
			continue
		}
		verified, verifyErr := verifier.Verify(context.Background(), fixture.Token)
		require.NoError(t, verifyErr, fixture.Name)
		derived, deriveErr := DeriveCachePartition(verified)
		require.NoError(t, deriveErr, fixture.Name)
		require.Equal(t, fixture.Form == corework.FormGrant, derived.WriteAround,
			"fixture %q (%s): a grant hop is written around and an ordinary session is not",
			fixture.Name, fixture.Form)
		seen++
	}
	require.Equal(t, 2, seen, "the kit must have offered one session and one grant capability")
}
