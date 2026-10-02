package workcontext

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"testing"
	"time"

	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
	corework "github.com/codefly-dev/core/workcontext"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

// Every capability in this package's tests is minted by core's Authority,
// because that is the only minter there is. A test that assembled a token
// another way would be testing a format nothing issues, which is how this
// module came to hold a second implementation in the first place.

// testClock is the instant every capability in these tests is minted at, and
// testSeal is the live sealed state the authority holds.
var (
	testClock = time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	testSeal  = Seal{
		InstallationID:       testInstallation,
		InstallationRevision: 3,
		BuildIncarnation:     11,
	}
	// testLiveBinding is the binding as the ISSUER holds it: granted to one
	// principal, within one installation. A capability carries only the first,
	// third and fourth of these — see SealedOperationBinding.
	testLiveBinding = OperationBinding{
		ID:             testBinding,
		PrincipalID:    testPrincipal,
		InstallationID: testInstallation,
		Revision:       2,
		Incarnation:    1,
	}
)

const (
	testIssuer       = "codefly.test-authority"
	testAudience     = "codefly.test-audience"
	testKeyID        = "test-key-1"
	testTenant       = "tenant-1"
	testPrincipal    = "principal-1"
	testInstallation = "installation-1"
	testBinding      = "binding-1"
	// testPrincipalEpoch is the owner's live epoch, which the seal source
	// answers rather than the seal carrying it.
	testPrincipalEpoch = 7
)

type authority struct {
	core  *corework.Authority
	seals *corework.MemorySealSource
	now   func() time.Time
}

// newAuthority stands up core's minter over an in-memory seal source, holding
// the live values a fresh capability is sealed to.
func newAuthority(t *testing.T) *authority {
	t.Helper()
	seals := corework.NewMemorySealSource()
	require.NoError(t, seals.Put(testPrincipal, testSeal))
	// The owner's epoch is recorded through PutEpoch like any other
	// principal's. Seal no longer carries it: it had two sources, and
	// revocation could be UNDONE — advancing the epoch left stored seals
	// untouched, and storing a seal for an unrelated installation lowered it
	// back. One source, owners and actors alike.
	require.NoError(t, seals.PutEpoch(testPrincipal, testPrincipalEpoch))
	require.NoError(t, seals.PutBinding(testLiveBinding))
	return newAuthorityOver(t, seals)
}

func newAuthorityOver(t *testing.T, seals *corework.MemorySealSource) *authority {
	t.Helper()
	_, private := corework.FixtureKeyPair()
	now := func() time.Time { return testClock }
	return &authority{
		core: &corework.Authority{
			Issuer:    testIssuer,
			KeyID:     testKeyID,
			Key:       private,
			Revisions: corework.FixedRevision(5),
			Seals:     seals,
			Now:       now,
		},
		seals: seals,
		now:   now,
	}
}

// verifier is core's verifier configured for this authority — the module's only
// verification entry point, reached through the alias in core.go.
func (a *authority) verifier(t *testing.T) *Verifier {
	t.Helper()
	public, _ := corework.FixtureKeyPair()
	return &Verifier{
		Issuer:    testIssuer,
		Audience:  testAudience,
		Keys:      map[string]ed25519.PublicKey{testKeyID: public},
		Revisions: corework.FixedRevision(5),
		Replay:    corework.NewMemoryReplayStore(),
		Grants:    noGrants{},
		Seals:     a.seals,
		Now:       a.now,
	}
}

// noGrants is a grant source for tests that mint no grant capability. A
// Verifier requires one even so: a verifier that treated a missing source as
// "no grants to check" would skip the check for a capability that carried one.
type noGrants struct{}

func (noGrants) Grant(context.Context, string) (*corework.Grant, error) {
	return nil, corework.ErrInvalid
}

// resealWithout rewrites a capability core has just minted, blanking exactly
// one field of its seal, and re-signs it with core's fixture key.
//
// It has to be done this way, and it is not a second implementation. Core's
// minter REFUSES to seal a capability to a zero epoch, revision or incarnation
// — protovalidate rejects the message — which is correct of an issuer and means
// a partial seal cannot be obtained by configuring one. Core's own conformance
// kit builds its `missing-seal` fixture by exactly this move, for exactly this
// reason. Nothing here invents a format: the message is core's, the
// deterministic marshal is core's, the key is core's fixture key, so the
// signature is genuine and the rule under test is the one that refuses the
// token.
//
// The durable home for these is core's conformance kit, since "every field of
// the seal is required" is core's rule and not this module's — see the PR
// discussion.
func resealWithout(t *testing.T, token string, field string) string {
	t.Helper()
	claims, err := readClaims(token)
	require.NoError(t, err)
	require.NotNil(t, claims.GetSeal())
	switch field {
	case "PrincipalEpoch":
		claims.Seal.PrincipalEpoch = 0
	case "ActorEpoch":
		require.NotEmpty(t, claims.GetActorChain(), "no hop to blank")
		claims.ActorChain[len(claims.ActorChain)-1].PrincipalEpoch = nil
	case "InstallationID":
		claims.Seal.InstallationId = ""
	case "InstallationRevision":
		claims.Seal.InstallationRevision = 0
	case "BuildIncarnation":
		claims.Seal.BuildIncarnation = 0
	case "Binding.ID":
		require.NotNil(t, claims.GetOperationBinding())
		claims.OperationBinding.BindingId = ""
	case "Binding.Revision":
		require.NotNil(t, claims.GetOperationBinding())
		claims.OperationBinding.Revision = 0
	case "Binding.Incarnation":
		require.NotNil(t, claims.GetOperationBinding())
		claims.OperationBinding.Incarnation = 0
	default:
		t.Fatalf("resealWithout has no case for %q, so the field is not being covered", field)
	}
	payload, err := proto.MarshalOptions{Deterministic: true}.Marshal(claims)
	require.NoError(t, err)
	_, private := corework.FixtureKeyPair()
	return base64.RawURLEncoding.EncodeToString(payload) + "." +
		base64.RawURLEncoding.EncodeToString(ed25519.Sign(private, payload))
}

type mintInput struct {
	tenant       string
	audience     string
	scopes       []*basev0.WorkScopeV1
	binding      string
	taskID       string
	organization string
}

// start mints a session capability, sealed to the live values above.
func (a *authority) start(t *testing.T, input mintInput) string {
	t.Helper()
	return a.startAt(t, a.now(), input, 15*time.Minute)
}

// startAt mints at a given instant for a given lifetime, which is what a mint
// endpoint under a moving test clock needs.
func (a *authority) startAt(t *testing.T, now time.Time, input mintInput, lifetime time.Duration) string {
	t.Helper()
	minter := *a.core
	minter.Now = func() time.Time { return now }
	if input.tenant == "" {
		input.tenant = testTenant
	}
	if input.audience == "" {
		input.audience = testAudience
	}
	if input.taskID == "" {
		input.taskID = "task-1"
	}
	if input.scopes == nil {
		input.scopes = []*basev0.WorkScopeV1{scope("document", "read")}
	}
	token, _, err := minter.Start(context.Background(), corework.StartInput{
		TenantID:           input.tenant,
		OwnerPrincipalID:   testPrincipal,
		OwnerPrincipalKind: "service",
		TaskID:             input.taskID,
		Audience:           input.audience,
		AuthorityScopes:    input.scopes,
		OrganizationID:     input.organization,
		InstallationID:     testInstallation,
		OperationBindingID: input.binding,
		TTL:                lifetime,
	})
	require.NoError(t, err)
	return token
}

// child delegates a verified capability one hop, which is how a test obtains a
// capability whose effective actor is not its owner.
//
// The actor principal needs a live epoch of its own: an actor's authority is
// narrowed independently of the owner's, so core seals the actor's epoch per
// hop and refuses a hop that carries none. A test that delegates without
// recording one fails at the mint, which is the right place for it to fail.
func (a *authority) child(t *testing.T, parent string, principal string, scopes []*basev0.WorkScopeV1) string {
	t.Helper()
	require.NotNil(t, a.seals, "delegation needs a seal source this test can record an actor epoch in")
	require.NoError(t, a.seals.PutEpoch(principal, 1))
	verified, err := a.verifier(t).Verify(context.Background(), parent)
	require.NoError(t, err)
	token, _, err := a.core.Child(context.Background(), verified, corework.ChildInput{
		PrincipalID:   principal,
		PrincipalKind: "service",
		DelegationID:  "delegation-" + principal,
		GrantedScopes: scopes,
		Audience:      testAudience,
		TTL:           10 * time.Minute,
	})
	require.NoError(t, err)
	return token
}

func scope(kind string, actions ...string) *basev0.WorkScopeV1 {
	return &basev0.WorkScopeV1{ResourceKind: kind, Actions: actions}
}
