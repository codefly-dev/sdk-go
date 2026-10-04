package workcontext

import (
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
	// The envelope.
	"empty-token":      true, // ErrInvalid: nothing at all
	"no-separator":     true, // ErrInvalid: not <payload>.<signature>
	"separator-only":   true, // ErrInvalid: empty segments
	"payload-not-b64":  true, // ErrInvalid: the envelope does not decode
	"foreign-encoding": true, // ErrNotACoreToken: another format entirely

	// The seal, every part of which the schema requires now.
	"missing-seal":               true, // ErrInvalid: no seal
	"seal-without-installation":  true, // ErrInvalid: a seal bound to nothing
	"zero-principal-epoch":       true, // ErrInvalid: zero is not an epoch
	"zero-installation-revision": true, // ErrInvalid: zero is not a revision
	"zero-build-incarnation":     true, // ErrInvalid: zero is not an incarnation
	// The execution is a PAIR, set together or absent together: a digest with
	// no incarnation, or an incarnation with no digest, is a seal that names a
	// build nothing can supersede. This fixture arrived with core's per-hop
	// execution change and the suite caught it by comparing against core's own
	// list rather than against a constant here — which is the whole reason the
	// comparison is written that way.
	"seal-half-execution":       true, // ErrInvalid: half an execution is not one
	"partial-operation-binding": true, // ErrInvalid: an id at no revision
	"actor-without-epoch":       true, // ErrInvalid: a principal nobody can revoke

	// The encoding itself. Core's Verify now refuses unknown fields
	// recursively and non-canonical encodings, and Inspect reaches the same
	// answer — so a capability with a field appended and re-signed is refused
	// here too, with no key and no network. This fixture arrived with the
	// settled surface and the exactness assertion below is what found it,
	// which is the reason that assertion exists.
	"unknown-field": true, // ErrInvalid: an appended field, re-signed
}

// TestTheSDKParsePathsAgreeWithCore drives every fixture in core's kit through
// THIS MODULE's parse paths and requires core's declared sentinel for each one.
//
// The twelve above are the ones a capability's own bytes earn, so this module
// must reach them with no network and no key. Every other fixture — signature,
// issuer, audience, WINDOW and live-state refusals — must PASS: a structural
// check that refused them would be claiming to have verified something it
// cannot see. Expired and not-yet-valid are in that second group, which is
// worth stating because it surprises: Inspect checks no window at all, and the
// mint client's own checkWindow is what refuses a credential that arrives
// unusable.
//
// The list is not derived from Inspect's behaviour, deliberately — that would
// be a tautology. It is written down, and the test requires every name on it to
// be a fixture that exists, so a fixture core renames or retires fails here
// rather than quietly dropping out of coverage.
//
// This is the test the conformance test is not. Driving fixtures through
// `&Verifier{}` exercises core, because Verifier is an alias of core's type —
// it is core testing core, and it would have passed unchanged beside the
// implementation this PR deletes. The SDK's own decision paths are
// readClaims/sealOf, SealedInstallation, FromHeaders and credentialFrom, and that
// is where a divergence from core can actually live. Three did:
//
//   - seal-without-installation: core answers ErrInvalid, because protovalidate
//     reaches it before the structural check. This module answered ErrUnsealed,
//     and its own test pinned that divergence as if it were correct.
//   - actor-without-epoch: this module never read the actor chain and accepted
//     the capability outright, so a principal nobody can revoke went on the
//     wire.
//   - a zero epoch, revision or incarnation: core answers ErrInvalid from the
//     schema. This module answered ErrUnsealed.
//
// Every one of those is ErrInvalid at core today — the seal and each actor
// epoch are schema-required, so protovalidate reaches all of them and
// ErrUnsealed is deleted. This test needed no edit for that, which is the
// argument for reading sentinels off the kit rather than writing them down:
// three of core's fixtures changed sentinel and nothing here had to move.
//
// Each of those is "one condition, two messages" — the fragmentation the
// one-implementation rule exists to end — relocated from the signature to the
// seal. The agreement is now TESTED against core's own declarations rather than
// described in a comment, so core changing its order breaks this test here
// rather than surfacing as a mismatched sentinel in somebody's gateway.
//
// It does not make this module's reading correct by construction — core's
// Inspect does that, and this test is what holds the two in agreement. Core
// built Inspect when it was asked for; this module applies no structural rule
// of its own any more.
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

	// The list is EXACT, not a lower bound. A fixture this module refuses
	// structurally but nobody listed would otherwise drift into coverage
	// silently, and one it stops refusing would drift out — and the second is
	// the direction that matters, because it is how the actor-epoch hole
	// existed in the first place. Core adding a structural fixture should land
	// here as a failing test asking to be acknowledged.
	refused := map[string]bool{}
	for _, fixture := range fixtures {
		if _, _, _, err := sealOf(fixture.Token); err != nil {
			refused[fixture.Name] = true
		}
	}
	require.Equal(t, structurallyRefused, refused,
		"the fixtures this module refuses on their own bytes are not the ones the list names")
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
			// Core's sentinel, with no alternative: the `|| ErrInvalid` this
			// used to allow made the assertion vacuous for the eleven of
			// twelve fixtures whose sentinel IS ErrInvalid.
			_, headerErr := FromHeaders(headers)
			require.ErrorIs(t, headerErr, fixture.Err,
				"FromHeaders refused %q as %v; core declares %v", fixture.Name, headerErr, fixture.Err)
		})
	}
}
