package workcontext

import (
	"crypto/ed25519"
	"fmt"
	"math/rand/v2"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
)

const partitionPropertyIterations = 200

// partitionWorld is one real signer and the verifier trusting it. Every token
// a property test derives from goes through both, so the partition is only
// ever computed from what verification produced.
type partitionWorld struct {
	t        *testing.T
	signer   *WorkContextSigner
	verifier *WorkContextVerifier
	nonces   int
}

func newPartitionWorld(t *testing.T) *partitionWorld {
	t.Helper()
	publicKey, privateKey := workContextTestKeys()
	world := &partitionWorld{t: t}
	signer, err := NewWorkContextSigner(WorkContextSignerOptions{
		Issuer: "https://accounts.codefly.dev/work-context", KeyID: "partition-key",
		PrivateKey: privateKey, Now: func() time.Time { return workContextTestTime },
		Nonce: func() (string, error) {
			world.nonces++
			return fmt.Sprintf("nonce-%d", world.nonces), nil
		},
	})
	require.NoError(t, err)
	verifier, err := NewWorkContextVerifier(WorkContextVerifierOptions{
		PublicKeys: map[string]ed25519.PublicKey{"partition-key": publicKey},
		Now:        func() time.Time { return workContextTestTime },
	})
	require.NoError(t, err)
	world.signer, world.verifier = signer, verifier
	return world
}

func (w *partitionWorld) verify(token WorkContextToken) VerifiedWorkContext {
	w.t.Helper()
	verified, err := w.verifier.VerifyWorkContext(token, WorkContextExpectations{})
	require.NoError(w.t, err)
	return verified
}

func (w *partitionWorld) partitions(token WorkContextToken) (tenant, view CachePartition) {
	w.t.Helper()
	verified := w.verify(token)
	tenant, err := DeriveCachePartition(verified)
	require.NoError(w.t, err)
	view, err = DeriveCachePartition(verified, ByAuthorizationView())
	require.NoError(w.t, err)
	require.False(w.t, tenant.WriteAround)
	require.False(w.t, view.WriteAround)
	return tenant, view
}

// randomScopes returns a valid, non-empty scope set in a random order with
// duplicated entries, so the signer's canonicalization is always exercised.
func randomScopes(random *rand.Rand) []*basev0.WorkScopeV1 {
	kinds := []string{"repository", "evidence", "document", "profile", "billing"}
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
	out := cloneScopes(scopes)
	random.Shuffle(len(out), func(i, j int) { out[i], out[j] = out[j], out[i] })
	for _, scope := range out {
		random.Shuffle(len(scope.Actions), func(i, j int) {
			scope.Actions[i], scope.Actions[j] = scope.Actions[j], scope.Actions[i]
		})
		random.Shuffle(len(scope.ResourceIds), func(i, j int) {
			scope.ResourceIds[i], scope.ResourceIds[j] = scope.ResourceIds[j], scope.ResourceIds[i]
		})
	}
	return out
}

// narrowedScopes strictly attenuates a canonical scope set: it drops a kind
// when there are several, else an action, else pins a wildcard to one ID or
// drops one explicit ID. ok is false when nothing can be narrowed.
func narrowedScopes(scopes []*basev0.WorkScopeV1) (out []*basev0.WorkScopeV1, ok bool) {
	out = cloneScopes(scopes)
	canonicalizeScopes(out)
	if len(out) > 1 {
		return out[1:], true
	}
	scope := out[0]
	switch {
	case len(scope.Actions) > 1:
		scope.Actions = scope.Actions[1:]
	case len(scope.ResourceIds) == 0:
		scope.ResourceIds = []string{"pinned"}
	case len(scope.ResourceIds) > 1:
		scope.ResourceIds = scope.ResourceIds[1:]
	default:
		return nil, false
	}
	return out, true
}

func partitionStartInput(random *rand.Rand, tenant string, revision uint64, scopes []*basev0.WorkScopeV1) StartTaskInput {
	return StartTaskInput{
		Audience:              fmt.Sprintf("service-%d", random.IntN(1000)),
		TenantID:              tenant,
		OwnerPrincipalID:      fmt.Sprintf("principal-%d", random.IntN(1000)),
		TaskID:                fmt.Sprintf("task-%d", random.Uint64()),
		SessionID:             fmt.Sprintf("session-%d", random.Uint64()),
		AuthorizationRevision: revision,
		AuthorityScopes:       scopes,
	}
}

func TestDeriveCachePartitionIsStableAcrossHopsWithTheSameView(t *testing.T) {
	world := newPartitionWorld(t)
	random := rand.New(rand.NewPCG(39, 658))
	for iteration := range partitionPropertyIterations {
		tenant := fmt.Sprintf("tenant-%d", random.IntN(50))
		revision := random.Uint64()
		scopes := randomScopes(random)
		root, _, err := world.signer.StartTask(partitionStartInput(random, tenant, revision, scopes))
		require.NoError(t, err)
		rootTenant, rootView := world.partitions(root)

		// A different task, session, owner, audience and nonce under the same
		// tenant, revision and authority — handed to the signer in another
		// order — is the same view.
		other, _, err := world.signer.StartTask(
			partitionStartInput(random, tenant, revision, shuffledScopes(random, scopes)),
		)
		require.NoError(t, err)
		otherTenant, otherView := world.partitions(other)
		require.Equal(t, rootTenant, otherTenant, "iteration %d", iteration)
		require.Equal(t, rootView, otherView, "iteration %d", iteration)

		// A child session whose actor keeps the whole effective authority.
		child, _, err := world.signer.StartChildSession(root, StartChildSessionInput{
			SessionID: fmt.Sprintf("child-%d", iteration),
			Audience:  "service-child",
			Actor: &basev0.WorkActorV1{
				PrincipalId: "agent", PrincipalKind: "agent", DelegationId: "delegation",
				GrantedScopes: shuffledScopes(random, scopes),
			},
		})
		require.NoError(t, err)
		childTenant, childView := world.partitions(child)
		require.Equal(t, rootTenant, childTenant, "iteration %d", iteration)
		require.Equal(t, rootView, childView, "iteration %d", iteration)

		// Audience exchanges, with no attenuation and with an attenuation equal
		// to the effective scopes, from the child's actor-scoped view.
		for _, attenuated := range [][]*basev0.WorkScopeV1{nil, shuffledScopes(random, scopes)} {
			exchanged, _, err := world.signer.ExchangeWorkContextAudience(child, ExchangeWorkContextAudienceInput{
				Audience: "service-next", AttenuatedScopes: attenuated,
			})
			require.NoError(t, err)
			exchangedTenant, exchangedView := world.partitions(exchanged)
			require.Equal(t, rootTenant, exchangedTenant, "iteration %d", iteration)
			require.Equal(t, rootView, exchangedView, "iteration %d", iteration)
		}
	}
}

func TestDeriveCachePartitionSeparatesTenantViewAndRevision(t *testing.T) {
	world := newPartitionWorld(t)
	random := rand.New(rand.NewPCG(7, 5))
	for iteration := range partitionPropertyIterations {
		tenant := fmt.Sprintf("tenant-%d", iteration)
		revision := random.Uint64()
		scopes := randomScopes(random)
		base, _, err := world.signer.StartTask(partitionStartInput(random, tenant, revision, scopes))
		require.NoError(t, err)
		baseTenant, baseView := world.partitions(base)

		otherTenant, _, err := world.signer.StartTask(
			partitionStartInput(random, tenant+"-other", revision, scopes),
		)
		require.NoError(t, err)
		tenantPartition, viewPartition := world.partitions(otherTenant)
		require.NotEqual(t, baseTenant.Key, tenantPartition.Key, "iteration %d", iteration)
		require.NotEqual(t, baseView.Key, viewPartition.Key, "iteration %d", iteration)

		otherRevision, _, err := world.signer.StartTask(
			partitionStartInput(random, tenant, revision+1, scopes),
		)
		require.NoError(t, err)
		tenantPartition, viewPartition = world.partitions(otherRevision)
		require.Equal(t, baseTenant.Key, tenantPartition.Key, "iteration %d", iteration)
		require.NotEqual(t, baseView.Key, viewPartition.Key, "iteration %d", iteration)

		narrowed, ok := narrowedScopes(scopes)
		if !ok {
			continue
		}
		// A narrower view reached every way the protocol allows: an audience
		// exchange that attenuates, and a child actor granted less.
		exchanged, _, err := world.signer.ExchangeWorkContextAudience(base, ExchangeWorkContextAudienceInput{
			Audience: "service-next", AttenuatedScopes: narrowed,
		})
		require.NoError(t, err)
		tenantPartition, viewPartition = world.partitions(exchanged)
		require.Equal(t, baseTenant.Key, tenantPartition.Key, "iteration %d", iteration)
		require.NotEqual(t, baseView.Key, viewPartition.Key, "iteration %d", iteration)

		child, _, err := world.signer.StartChildSession(base, StartChildSessionInput{
			SessionID: "child",
			Actor: &basev0.WorkActorV1{
				PrincipalId: "agent", PrincipalKind: "agent", DelegationId: "delegation",
				GrantedScopes: narrowed,
			},
		})
		require.NoError(t, err)
		_, childView := world.partitions(child)
		require.Equal(t, viewPartition.Key, childView.Key, "iteration %d", iteration)
	}
}

func TestDeriveCachePartitionNeverCarriesExecutionIdentity(t *testing.T) {
	world := newPartitionWorld(t)
	input := workContextTestInput()
	input.TaskID = "task-must-not-leak"
	input.SessionID = "session-must-not-leak"
	input.Audience = "audience-must-not-leak"
	token, _, err := world.signer.StartTask(input)
	require.NoError(t, err)
	tenant, view := world.partitions(token)
	for _, partition := range []CachePartition{tenant, view} {
		for _, secret := range []string{"must-not-leak", "nonce-", "principal-antoine"} {
			require.NotContains(t, partition.Key, secret)
		}
		require.True(t, strings.HasPrefix(partition.Key, tenant.Key))
	}
	require.Equal(t, "wc1:t:dGVuYW50LWNvZGVmbHk", tenant.Key)
	require.Regexp(t, `^wc1:t:dGVuYW50LWNvZGVmbHk:v:[0-9a-f]{64}$`, view.Key)
}

func TestDeriveCachePartitionTenantEncodingCannotSpellAnotherView(t *testing.T) {
	world := newPartitionWorld(t)
	random := rand.New(rand.NewPCG(1, 2))
	scopes := randomScopes(random)
	victim, _, err := world.signer.StartTask(partitionStartInput(random, "tenant-a", 1, scopes))
	require.NoError(t, err)
	_, victimView := world.partitions(victim)

	// A tenant ID made of the victim's view key suffix must not produce the
	// victim's key under tenant-only partitioning.
	suffix := strings.TrimPrefix(victimView.Key, "wc1:t:")
	forger, _, err := world.signer.StartTask(partitionStartInput(random, "tenant-a:v:"+suffix, 1, scopes))
	require.NoError(t, err)
	forgerTenant, _ := world.partitions(forger)
	require.NotEqual(t, victimView.Key, forgerTenant.Key)
}

func TestDeriveCachePartitionAcceptsOnlyVerifiedContexts(t *testing.T) {
	_, err := DeriveCachePartition(VerifiedWorkContext{}, ByAuthorizationView())
	require.ErrorIs(t, err, ErrWorkContextInvalid)

	world := newPartitionWorld(t)
	token, claims, err := world.signer.StartTask(workContextTestInput())
	require.NoError(t, err)

	// A token that parses is still not usable: re-signing the same claims for
	// another tenant with a key the verifier does not trust fails before any
	// partition can be derived.
	_, untrustedKey := workContextJWKSKey(9)
	forger, err := NewWorkContextSigner(WorkContextSignerOptions{
		Issuer: claims.GetIssuer(), KeyID: "partition-key", PrivateKey: untrustedKey,
		Now: func() time.Time { return workContextTestTime },
	})
	require.NoError(t, err)
	forgedInput := workContextTestInput()
	forgedInput.TenantID = "tenant-victim"
	forged, _, err := forger.StartTask(forgedInput)
	require.NoError(t, err)
	parsed, err := ParseWorkContextToken(forged.Encoded())
	require.NoError(t, err)
	_, err = world.verifier.VerifyWorkContext(parsed, WorkContextExpectations{})
	require.ErrorIs(t, err, ErrWorkContextInvalid)

	// Expectations still apply: a context for another audience is rejected.
	_, err = world.verifier.VerifyWorkContext(token, WorkContextExpectations{Audience: "someone-else"})
	require.ErrorIs(t, err, ErrWorkContextInvalid)

	// Claims hands out a copy; mutating it cannot move the partition.
	verified := world.verify(token)
	before, err := DeriveCachePartition(verified, ByAuthorizationView())
	require.NoError(t, err)
	copied := verified.Claims()
	copied.TenantId = "tenant-victim"
	copied.AuthorizationRevision = 0
	copied.ActorChain = nil
	after, err := DeriveCachePartition(verified, ByAuthorizationView())
	require.NoError(t, err)
	require.Equal(t, before, after)
	require.Equal(t, claims.GetTenantId(), verified.Claims().GetTenantId())
}

func TestJWKSVerifierVerifyWorkContextFeedsThePartition(t *testing.T) {
	publicKey, privateKey := workContextJWKSKey(1)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write(workContextJWKSJSON(t, map[string]ed25519.PublicKey{"key-1": publicKey}))
	}))
	t.Cleanup(server.Close)
	verifier, err := NewWorkContextJWKSVerifier(WorkContextJWKSVerifierOptions{
		URL: server.URL, Now: func() time.Time { return workContextTestTime },
	})
	require.NoError(t, err)

	verified, err := verifier.VerifyWorkContext(t.Context(), workContextJWKSToken(t, "key-1", privateKey), WorkContextExpectations{})
	require.NoError(t, err)
	partition, err := DeriveCachePartition(verified)
	require.NoError(t, err)
	require.Equal(t, "wc1:t:dGVuYW50LWNvZGVmbHk", partition.Key)

	_, err = verifier.VerifyWorkContext(t.Context(), workContextJWKSToken(t, "key-2", privateKey), WorkContextExpectations{})
	require.ErrorIs(t, err, ErrWorkContextInvalid)
}

func TestAuthorizationViewDigestCanonicalizesScopeOrder(t *testing.T) {
	ordered := &basev0.WorkContextV1{
		AuthorizationRevision: 3,
		AuthorityScopes: []*basev0.WorkScopeV1{
			{ResourceKind: "document", Actions: []string{"read", "write"}, ResourceIds: []string{"a", "b"}},
			{ResourceKind: "evidence", Actions: []string{"append"}},
		},
	}
	shuffled := &basev0.WorkContextV1{
		AuthorizationRevision: 3,
		AuthorityScopes: []*basev0.WorkScopeV1{
			{ResourceKind: "evidence", Actions: []string{"append", "append"}, ResourceIds: []string{}},
			{ResourceKind: "document", Actions: []string{"write", "read"}, ResourceIds: []string{"b", "a", "b"}},
		},
	}
	first, err := authorizationViewDigest(ordered)
	require.NoError(t, err)
	second, err := authorizationViewDigest(shuffled)
	require.NoError(t, err)
	require.Equal(t, first, second)
	// Digesting never reorders the caller's claims.
	require.Equal(t, "evidence", shuffled.AuthorityScopes[0].ResourceKind)
	require.True(t, slices.Equal([]string{"write", "read"}, shuffled.AuthorityScopes[1].Actions))

	// With actors, only the final actor's scopes are the view.
	ordered.ActorChain = []*basev0.WorkActorV1{{GrantedScopes: ordered.AuthorityScopes[1:]}}
	actorView, err := authorizationViewDigest(ordered)
	require.NoError(t, err)
	require.NotEqual(t, first, actorView)

	// A nil option is ignored rather than dereferenced.
	_, err = DeriveCachePartition(VerifiedWorkContext{claims: ordered}, nil, ByAuthorizationView())
	require.NoError(t, err)
}
