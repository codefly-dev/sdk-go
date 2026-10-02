package workcontext

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	corework "github.com/codefly-dev/core/workcontext"
	"github.com/stretchr/testify/require"
)

// structurallyRefused is every fixture in core's kit whose refusal this module
// MUST reach on its own, because it is a property of the capability's own bytes
// rather than of the issuer's live state or of a signature.
//
// Naming them explicitly is the point. Without this list the test below would
// pass by refusing nothing at all: "no disagreement" is satisfied by an
// inspection that accepts everything, and that is exactly how the actor-epoch
// hole survived — sealOf never read the actor chain, so a capability core
// refuses as unsealed went on the wire.
var structurallyRefused = map[string]bool{
	"missing-seal":              true, // ErrUnsealed: carries no seal at all
	"actor-without-epoch":       true, // ErrUnsealed: a hop nobody can revoke
	"seal-without-installation": true, // ErrInvalid: the schema refuses it first
	"foreign-encoding":          true, // ErrNotACoreToken: another format entirely
	"empty-token":               true, // ErrInvalid: no envelope
	"no-separator":              true, // ErrInvalid: no envelope
	"separator-only":            true, // ErrInvalid: empty segments
	"payload-not-b64":           true, // ErrInvalid: the envelope does not decode
}

// TestTheSDKParsePathsAgreeWithCore drives every fixture in core's kit through
// THIS MODULE's parse paths and requires core's declared sentinel for each one.
//
// The eight above are the ones a capability's own bytes earn, so this module
// must reach them with no network and no key. The other seventeen are
// signature, audience or live-state refusals, which an unverified inspection
// cannot see and must therefore PASS: a structural check that refused them
// would be claiming to have verified something it cannot.
//
// This is the test the conformance test is not. Driving fixtures through
// `&Verifier{}` exercises core, because Verifier is an alias of core's type —
// it is core testing core, and it would have passed unchanged beside the
// implementation this PR deletes. The SDK's own decision paths are
// claimsOf/sealOf, SealedInstallation, FromHeaders and credentialFrom, and that
// is where a divergence from core can actually live. Three did:
//
//   - seal-without-installation: core answers ErrInvalid, because protovalidate
//     reaches it before the structural check. This module answered ErrUnsealed,
//     and its own test pinned that divergence as if it were correct.
//   - actor-without-epoch: core answers ErrUnsealed. This module never read the
//     actor chain and accepted it.
//   - a zero epoch, revision or incarnation: core answers ErrInvalid from the
//     schema. This module answered ErrUnsealed.
//
// Each of those is "one condition, two messages" — the fragmentation the
// one-implementation rule exists to end — relocated from the signature to the
// seal. The agreement is now TESTED against core's own declarations rather than
// described in a comment, so core changing its order breaks this test here
// rather than surfacing as a mismatched sentinel in somebody's gateway.
//
// It does not make this module's parser correct by construction. One exported
// unverified inspection entry point in core would; that is asked for in
// core#691 and said plainly in the PR body.
func TestTheSDKParsePathsAgreeWithCore(t *testing.T) {
	fixtures, err := corework.Fixtures(time.Now())
	require.NoError(t, err)
	require.NotEmpty(t, fixtures)

	seen := map[string]bool{}
	for _, fixture := range fixtures {
		seen[fixture.Name] = true
		t.Run(fixture.Name, func(t *testing.T) {
			_, _, _, sealErr := sealOf(fixture.Token)

			if fixture.Outcome == corework.OutcomeAccepted {
				require.NoError(t, sealErr,
					"core accepts %q, so this module must not refuse it on its own bytes", fixture.Name)
				return
			}

			if structurallyRefused[fixture.Name] {
				require.Error(t, sealErr,
					"%q is refused on its own bytes, so this module must refuse it too:\n"+
						"  core's reason: %s", fixture.Name, fixture.Reason)
			}
			if sealErr == nil {
				// A refusal that needs the issuer's live state, a key, or the
				// replay store is not this module's to reach. Accepting it here
				// is correct, and nothing authorizes from the result.
				require.False(t, structurallyRefused[fixture.Name])
				return
			}
			// But WHEN this module refuses, it must refuse for core's reason.
			require.ErrorIs(t, sealErr, fixture.Err,
				"this module refuses %q as %v; core declares %v.\n"+
					"  core's reason: %s\n"+
					"  One condition with two messages is the fragmentation this rule exists to end.",
				fixture.Name, sealErr, fixture.Err, fixture.Reason)
		})
	}

	for name := range structurallyRefused {
		require.True(t, seen[name],
			"the list names %q, which is not a fixture in core's kit any more — "+
				"a stale entry is a case nobody is covering", name)
	}
}

// And the agreement holds on every carrier, not only in sealOf: the carriers
// are the reason this module parses at all, so a capability core refuses on its
// own bytes must not reach a request through any of them.
func TestNoCarrierAcceptsWhatCoreRefusesOnItsOwnBytes(t *testing.T) {
	fixtures, err := corework.Fixtures(time.Now())
	require.NoError(t, err)

	for _, fixture := range fixtures {
		if !structurallyRefused[fixture.Name] {
			continue
		}
		t.Run(fixture.Name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, "/records", nil)
			attachErr := Attach(request, fixture.Token)
			require.ErrorIs(t, attachErr, fixture.Err)
			require.Empty(t, request.Header.Get(HeaderName),
				"a refused capability must not be left on the request")

			_, _, installationErr := SealedInstallation(fixture.Token)
			require.ErrorIs(t, installationErr, fixture.Err,
				"SealedInstallation is the one function every carrier goes through")

			headers := http.Header{}
			headers.Set(HeaderName, fixture.Token)
			headers.Set(InstallationIDHeaderName, corework.FixtureInstallation)
			headers.Set(InstallationRevisionHeaderName, "1")
			_, headerErr := FromHeaders(headers)
			require.Error(t, headerErr)
			require.True(t,
				errors.Is(headerErr, fixture.Err) || errors.Is(headerErr, ErrInvalid),
				"FromHeaders refused %q as %v, which is neither core's %v nor a carrier mismatch",
				fixture.Name, headerErr, fixture.Err)
		})
	}
}
