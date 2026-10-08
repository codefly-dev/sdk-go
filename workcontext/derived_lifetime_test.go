package workcontext

import (
	"fmt"
	"testing"
	"time"

	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
	corework "github.com/codefly-dev/core/workcontext"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

// SP-WC-01 — a context derived from another, by exchange, child session or
// renewal, expires no later than its parent and never refreshes a lifetime past
// the root's.
//
// The rule holds for EVERY derivation, so it is asserted over a matrix rather
// than at one pair of numbers: an assertion at a single pair does not state a
// property.
//
// It is tested HERE, in a module that derives nothing, on purpose. Derivation is
// core's and core's alone, and a test living only in core would hold core to the
// rule; this one holds the version of core THIS module resolves to it, so the
// rule is required of whatever this module depends on rather than of core in
// general.
//
// Two halves of the invariant are not reachable from here, and saying so is part
// of the test:
//
//   - At VERIFICATION, a verifier holds the capability and not its parent, and
//     codefly.base.v0.WorkContextV1 carries no absolute-deadline claim and no
//     per-hop timestamp — so "no later than its parent" is not a question the
//     wire lets a verifier ask. That claim, and the check that reads it, are
//     core's to add. What a verifier DOES enforce today is the chain's
//     attenuation, in core's checkStructure.
//   - A RENEWAL in this module is not a derivation at all. MintClient renews by
//     presenting the projected service-account token for a fresh mint, never the
//     credential it holds, so each renewal is a root the host re-authorizes
//     rather than a window extended from the last one. mintLocked sends the
//     audience and the projection audience and nothing else.

// deriveChild is childAs with the TTL as a parameter, which is the dimension
// this property varies and the shared helper fixes.
func (a *authority) deriveChild(
	t *testing.T, parent string, principal string, scopes []*basev0.WorkScopeV1, ttl time.Duration,
) (string, *basev0.WorkContextV1, error) {
	t.Helper()
	require.NoError(t, a.seals.PutEpoch(principal, 1))
	require.NoError(t, a.seals.PutApprovedBuild(
		principal, testApprovedBuild.digest, testApprovedBuild.incarnation))
	verified, err := a.verifier(t).Verify(t.Context(), parent)
	require.NoError(t, err)
	token, claims, err := a.core.Child(t.Context(), verified, corework.ChildInput{
		Execution: corework.Execution{
			ImageDigest:      testApprovedBuild.digest,
			BuildIncarnation: testApprovedBuild.incarnation,
		},
		PrincipalID:   principal,
		PrincipalKind: "service",
		DelegationID:  "delegation-" + principal,
		GrantedScopes: scopes,
		Audience:      testAudience,
		TTL:           ttl,
	})
	return token, claims, err
}

func expiryOf(t *testing.T, a *authority, token string) time.Time {
	t.Helper()
	verified, err := a.verifier(t).Verify(t.Context(), token)
	require.NoError(t, err)
	return time.Unix(verified.Context().GetExpiresAtUnix(), 0)
}

func TestDerivedContextNeverOutlivesParent(t *testing.T) {
	parentScopes := []*basev0.WorkScopeV1{scope("document", "read", "write")}
	childScopes := []*basev0.WorkScopeV1{scope("document", "read")}

	// The matrix. Every parent lifetime against every requested child window,
	// including the ones that ask for more than the parent has left — which is
	// the only interesting direction and the one an uncapped derivation gets
	// wrong.
	t.Run("a child expires no later than its parent, for every window", func(t *testing.T) {
		lifetimes := []time.Duration{
			time.Minute, 5 * time.Minute, 15 * time.Minute, 30 * time.Minute, time.Hour,
		}
		for _, parentLifetime := range lifetimes {
			for _, requested := range lifetimes {
				name := fmt.Sprintf("parent %s, child asks %s", parentLifetime, requested)
				t.Run(name, func(t *testing.T) {
					a := newAuthority(t)
					parent := a.startAt(t, a.now(), mintInput{scopes: parentScopes}, parentLifetime)
					parentExpiry := expiryOf(t, a, parent)

					_, claims, err := a.deriveChild(t, parent, "principal-child", childScopes, requested)
					require.NoError(t, err)
					childExpiry := time.Unix(claims.GetExpiresAtUnix(), 0)

					require.False(t, childExpiry.After(parentExpiry),
						"a child expiring at %s outlives a parent expiring at %s", childExpiry, parentExpiry)
					// And it is the MINIMUM, not merely bounded: a derivation
					// that always took the parent's expiry would satisfy the
					// bound while ignoring the requested window.
					wanted := a.now().Add(requested)
					if wanted.After(parentExpiry) {
						wanted = parentExpiry
					}
					require.Equal(t, wanted.Unix(), claims.GetExpiresAtUnix())
				})
			}
		}
	})

	// A chain, which is where "never refreshes a lifetime past the root's"
	// lives. Each hop asks for the longest window the authority mints, so the
	// root's expiry is the only thing that can be holding the chain.
	t.Run("a chain of derivations never outlives the root", func(t *testing.T) {
		a := newAuthority(t)
		root := a.startAt(t, a.now(), mintInput{scopes: parentScopes}, 2*time.Minute)
		rootExpiry := expiryOf(t, a, root)

		token, previous := root, rootExpiry
		for hop := 1; hop <= 4; hop++ {
			derived, claims, err := a.deriveChild(
				t, token, fmt.Sprintf("principal-hop-%d", hop), childScopes, time.Hour)
			require.NoError(t, err)
			expiry := time.Unix(claims.GetExpiresAtUnix(), 0)

			require.False(t, expiry.After(previous), "hop %d outlives the hop before it", hop)
			require.False(t, expiry.After(rootExpiry), "hop %d outlives the root", hop)
			require.Equal(t, rootExpiry.Unix(), claims.GetExpiresAtUnix(),
				"every hop is clamped to the root's expiry once the root is the shortest window")
			token, previous = derived, expiry
		}
	})

	// A grant capability is the other derivation core mints, and it takes a
	// different route to its expiry — bounded by the approval's own window
	// first. The parent still wins when the parent is shorter.
	t.Run("a grant capability expires no later than its parent", func(t *testing.T) {
		a := newAuthority(t)
		parent := a.startAt(t, a.now(), mintInput{scopes: parentScopes}, 2*time.Minute)
		parentExpiry := expiryOf(t, a, parent)
		verified, err := a.verifier(t).Verify(t.Context(), parent)
		require.NoError(t, err)

		_, claims, err := a.core.Grant(t.Context(), verified, corework.GrantInput{
			Execution: corework.Execution{
				ImageDigest:      testApprovedBuild.digest,
				BuildIncarnation: testApprovedBuild.incarnation,
			},
			// An approval whose own window closes long after the parent
			// session does, asking for a window longer than either.
			Grant: &corework.Grant{
				ID:                    "grant-1",
				Approvers:             []corework.Approver{{PrincipalID: testHumanPrincipal, Kind: "human"}},
				Scope:                 &basev0.WorkScopeV1{ResourceKind: "document", Actions: []string{"read"}, ResourceIds: []string{"document-1"}},
				Subject:               "subject-1",
				RequestDigest:         "digest-1",
				Audience:              testAudience,
				NotAfter:              a.now().Add(12 * time.Hour),
				AuthorizationRevision: 5,
			},
			TTL: time.Hour,
		})
		require.NoError(t, err)

		require.Equal(t, parentExpiry.Unix(), claims.GetExpiresAtUnix(),
			"a grant capability outlives the session it was approved within")
	})

	// A parent already past its expiry derives NOTHING. The window here is
	// inside core's skew, so the parent still verifies: that is a state a
	// legitimate holder can be in, and the rule has to hold in it rather than
	// only where the parent fails verification anyway.
	t.Run("a parent past its expiry derives nothing", func(t *testing.T) {
		a := newAuthority(t)
		lifetime := 15 * time.Minute
		parent := a.startAt(
			t, a.now().Add(-lifetime-10*time.Second), mintInput{scopes: parentScopes}, lifetime)
		require.True(t, expiryOf(t, a, parent).Before(a.now()),
			"this case needs a parent that verifies and is already past its expiry")

		_, _, err := a.deriveChild(t, parent, "principal-child", childScopes, time.Hour)

		require.ErrorIs(t, err, ErrInvalid)
		require.ErrorContains(t, err, "parent session expired")
	})

	// The chain never widens, and never grows by more than the hop being added.
	// The parent is the bound in both dimensions: a derived context carries no
	// authority its parent did not hold, and no hop its parent did not.
	t.Run("a child never widens or lengthens the chain beyond one hop", func(t *testing.T) {
		a := newAuthority(t)
		parent := a.startAt(t, a.now(), mintInput{scopes: parentScopes}, 30*time.Minute)

		_, _, err := a.deriveChild(t, parent, "principal-wider",
			[]*basev0.WorkScopeV1{scope("document", "read", "write", "delete")}, time.Minute)
		require.ErrorIs(t, err, ErrInvalid)
		require.ErrorContains(t, err, "widens authority beyond its parent")

		_, _, err = a.deriveChild(t, parent, "principal-other-kind",
			[]*basev0.WorkScopeV1{scope("secret", "read")}, time.Minute)
		require.ErrorIs(t, err, ErrInvalid)
		require.ErrorContains(t, err, "widens authority beyond its parent")

		// One hop per derivation, and the hops before it carried through
		// unchanged: a derivation that rewrote an earlier hop would be a
		// chain whose earlier authority is whatever the last deriver said.
		first, firstClaims, err := a.deriveChild(t, parent, "principal-first", childScopes, time.Minute)
		require.NoError(t, err)
		require.Len(t, firstClaims.GetActorChain(), 1)

		_, secondClaims, err := a.deriveChild(t, first, "principal-second", childScopes, time.Minute)
		require.NoError(t, err)
		require.Len(t, secondClaims.GetActorChain(), 2)
		require.True(t,
			proto.Equal(firstClaims.GetActorChain()[0], secondClaims.GetActorChain()[0]),
			"deriving rewrote the hop it inherited")
	})
}
