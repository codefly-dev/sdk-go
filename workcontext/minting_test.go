package workcontext

import (
	"context"
	"crypto/ed25519"
	"testing"
	"time"

	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
	corework "github.com/codefly-dev/core/workcontext"
	"github.com/stretchr/testify/require"
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
		PrincipalEpoch:       7,
		InstallationID:       testInstallation,
		InstallationRevision: 3,
		BuildIncarnation:     11,
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
	_, private := corework.FixtureKeyPair()
	seals := corework.NewMemorySealSource()
	require.NoError(t, seals.Put(testPrincipal, testSeal))
	require.NoError(t, seals.PutBinding(OperationBinding{ID: testBinding, Revision: 2, Incarnation: 1}))
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
func (a *authority) child(t *testing.T, parent string, principal string, scopes []*basev0.WorkScopeV1) string {
	t.Helper()
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
