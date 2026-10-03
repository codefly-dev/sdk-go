package workcontext

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	corework "github.com/codefly-dev/core/workcontext"
	"github.com/stretchr/testify/require"
)

// fixture returns one of core's conformance tokens by name, so a negative case
// here is the same token core's own verifier is held to rather than one this
// test invented.
func fixture(t *testing.T, name string) corework.Fixture {
	t.Helper()
	fixtures, err := corework.Fixtures(time.Now())
	require.NoError(t, err)
	for _, candidate := range fixtures {
		if candidate.Name == name {
			return candidate
		}
	}
	t.Fatalf("core's conformance kit has no fixture %q", name)
	return corework.Fixture{}
}

// A capability travels with the installation it is sealed to, so the far end
// can refuse the call before it decodes anything.
func TestAttachCarriesTheCapabilityAndTheSealedInstallation(t *testing.T) {
	a := newAuthority(t)
	token := a.start(t, mintInput{})
	request := httptest.NewRequest(http.MethodGet, "/records", nil)
	require.NoError(t, Attach(request, token))

	require.Equal(t, token, request.Header.Get(HeaderName))
	require.Equal(t, testInstallation, request.Header.Get(InstallationIDHeaderName))
	require.Equal(t, "3", request.Header.Get(InstallationRevisionHeaderName))

	// And it comes back off the request, with the carriers held to the seal.
	carried, err := FromHeaders(request.Header)
	require.NoError(t, err)
	require.Equal(t, token, carried)
}

// A credential is sealed or it is not a credential. Finding that out before the
// call is made is the point: at the far end the refusal names an installation
// mismatch for a capability that named no installation at all.
//
// The sentinel is CORE'S, taken from core's own fixture rather than written
// here. This test used to assert ErrUnsealed for all of them, which was wrong
// for seal-without-installation even then — core answered ErrInvalid there,
// because the schema reaches it before the structural check — and pinning a
// sentinel of one's own is how the divergence stayed invisible. It is now
// ErrInvalid for every one of them, because the seal and the actor epoch are
// schema-required and ErrUnsealed is deleted; reading the sentinel off the
// fixture is what made this change a no-op here instead of a rewrite.
func TestAttachRefusesAnUnsealedCapability(t *testing.T) {
	for _, name := range []string{"missing-seal", "seal-without-installation", "actor-without-epoch"} {
		t.Run(name, func(t *testing.T) {
			declared := fixture(t, name)
			request := httptest.NewRequest(http.MethodGet, "/records", nil)
			err := Attach(request, declared.Token)
			require.ErrorIs(t, err, declared.Err,
				"core declares %v for %q: %s", declared.Err, name, declared.Reason)
			require.Empty(t, request.Header.Get(HeaderName),
				"a refused capability must not be left on the request")
		})
	}
}

func TestAttachRefusesWhatIsNotACapability(t *testing.T) {
	for name, encoded := range map[string]string{
		"empty":             "",
		"whitespace":        "   ",
		"one segment":       "not-a-token",
		"empty payload":     ".c2lnbmF0dXJl",
		"empty signature":   "cGF5bG9hZA.",
		"payload not b64":   "not!base64.c2lnbmF0dXJl",
		"signature not b64": "cGF5bG9hZA.not!base64",
		"payload not proto": "bm90LWEtcHJvdG8tbWVzc2FnZS1hdC1hbGw.c2lnbmF0dXJl",
		"oversized":         strings.Repeat("a", MaxTokenBytes+1) + ".sig",
	} {
		t.Run(name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, "/records", nil)
			require.ErrorIs(t, Attach(request, encoded), ErrInvalid)
		})
	}
	require.ErrorIs(t, Attach(nil, "irrelevant"), ErrInvalid)
}

// The carriers are a pre-check and never authority. A receiver that found them
// disagreeing with the seal and preferred either side would have made a
// caller-controlled header into authority.
func TestIncomingCarriersAreHeldToTheSeal(t *testing.T) {
	a := newAuthority(t)
	token := a.start(t, mintInput{})

	for name, carriers := range map[string]map[string]string{
		"another installation": {
			InstallationIDHeaderName:       "installation-the-caller-preferred",
			InstallationRevisionHeaderName: "3",
		},
		"another revision": {
			InstallationIDHeaderName:       testInstallation,
			InstallationRevisionHeaderName: "4",
		},
		"id without revision": {
			InstallationIDHeaderName: testInstallation,
		},
		"revision without id": {
			InstallationRevisionHeaderName: "3",
		},
	} {
		t.Run(name, func(t *testing.T) {
			headers := http.Header{}
			headers.Set(HeaderName, token)
			for carrier, value := range carriers {
				headers.Set(carrier, value)
			}
			_, err := FromHeaders(headers)
			require.ErrorIs(t, err, ErrInvalid)
		})
	}

	// Carrying NEITHER is refused too, which it was not: that was the
	// optional-carrier escape hatch surviving on HTTP after it was deleted on
	// gRPC, and it skipped the seal check altogether. Attach always sets both,
	// so a sender using this SDK satisfies it.
	bare := http.Header{}
	bare.Set(HeaderName, token)
	_, err := FromHeaders(bare)
	require.ErrorIs(t, err, ErrInvalid)
	require.ErrorContains(t, err, "requires exactly one value")

	// And what Attach produces round-trips.
	attached := httptest.NewRequest(http.MethodGet, "/records", nil)
	require.NoError(t, Attach(attached, token))
	carried, err := FromHeaders(attached.Header)
	require.NoError(t, err)
	require.Equal(t, token, carried)
}

func TestFromHeadersRequiresExactlyOneCapability(t *testing.T) {
	_, err := FromHeaders(nil)
	require.ErrorIs(t, err, ErrInvalid)

	_, err = FromHeaders(http.Header{})
	require.ErrorIs(t, err, ErrInvalid)

	blank := http.Header{}
	blank.Set(HeaderName, "   ")
	_, err = FromHeaders(blank)
	require.ErrorIs(t, err, ErrInvalid)

	a := newAuthority(t)
	twice := http.Header{}
	twice.Add(HeaderName, a.start(t, mintInput{}))
	twice.Add(HeaderName, a.start(t, mintInput{}))
	_, err = FromHeaders(twice)
	require.ErrorIs(t, err, ErrInvalid)
	require.ErrorContains(t, err, "appears 2 times")
}

// An operation binding carries its id, revision and incarnation or none of
// them: a capability sealed to a binding id at no revision names an authority
// nobody approved, and the field that is missing is the one an attacker would
// choose to leave out.
//
// The partial case is CORE'S fixture now. This test used to build it by
// re-signing a minted capability with core's fixture key, because core's kit
// had no such fixture and core's minter correctly refuses to mint one. Core
// added `partial-operation-binding` when asked, so the local signer is gone —
// and an `ed25519.Sign` in a test file was the gate's weakest edge, since the
// gate exempts test files.
func TestSealedOperationBindingIsWholeOrAbsent(t *testing.T) {
	a := newAuthority(t)
	_, _, binding, err := sealOf(a.start(t, mintInput{binding: testBinding}))
	require.NoError(t, err)
	require.NotNil(t, binding)
	require.Equal(t, testBinding, binding.GetBindingId())
	require.EqualValues(t, 2, binding.GetRevision())
	require.EqualValues(t, 1, binding.GetIncarnation())

	_, _, none, err := sealOf(a.start(t, mintInput{}))
	require.NoError(t, err)
	require.Nil(t, none, "a session that exercises no binding seals none")

	// A binding carrying an id and nothing else is refused, with core's own
	// sentinel, and never reaches a request on any carrier.
	declared := fixture(t, "partial-operation-binding")
	_, _, _, err = sealOf(declared.Token)
	require.ErrorIs(t, err, declared.Err)

	request := httptest.NewRequest(http.MethodGet, "/records", nil)
	require.ErrorIs(t, Attach(request, declared.Token), declared.Err)
	require.Empty(t, request.Header.Get(HeaderName))
	_, _, err = SealedInstallation(declared.Token)
	require.ErrorIs(t, err, declared.Err)
}

// Every field of the seal is required, and the check is the SAME check for
// every carrier. SealedInstallation used to read only the installation id and
// revision, which made "Attach refuses an unsealed capability" true of two
// fields out of four: a capability with no principal epoch or no build
// incarnation was attached and travelled.
//
// Each case is one of CORE'S fixtures and each sentinel is read off the
// fixture rather than written here. That is what made the schema change a
// no-op for this test: the seal became required, three fixtures changed from
// ErrUnsealed to ErrInvalid, and nothing below had to move.
func TestEverySealedFieldIsRequiredOnEveryCarrier(t *testing.T) {
	for _, name := range []string{
		"missing-seal",
		"seal-without-installation",
		"zero-principal-epoch",
		"zero-installation-revision",
		"zero-build-incarnation",
	} {
		t.Run(name, func(t *testing.T) {
			declared := fixture(t, name)
			require.ErrorIs(t, declared.Err, ErrInvalid,
				"every structural seal defect is one sentinel now: %s", declared.Reason)

			_, _, _, err := sealOf(declared.Token)
			require.ErrorIs(t, err, declared.Err)

			// The outbound HTTP carrier.
			request := httptest.NewRequest(http.MethodGet, "/records", nil)
			require.ErrorIs(t, Attach(request, declared.Token), declared.Err)
			require.Empty(t, request.Header.Get(HeaderName),
				"a refused capability must not be left on the request")

			// The inbound HTTP carrier. Both carriers are stated, because both
			// are required — and the seal check runs whether or not they are.
			headers := http.Header{}
			headers.Set(HeaderName, declared.Token)
			headers.Set(InstallationIDHeaderName, corework.FixtureInstallation)
			headers.Set(InstallationRevisionHeaderName, "1")
			_, err = FromHeaders(headers)
			require.ErrorIs(t, err, declared.Err)

			// And the one function both gRPC directions go through.
			_, _, err = SealedInstallation(declared.Token)
			require.ErrorIs(t, err, declared.Err)
		})
	}
}

// An installation carrier stated twice is ambiguous, and ambiguous is refused.
//
// Header.Get reads the FIRST value, so [sealed-id, something-else] compared
// equal to the seal and the call was accepted while carrying two contradictory
// installations. Whether a later intermediary reads the first or the second is
// not something this module can decide — gRPC already required exactly one, and
// now both transports do.
func TestDuplicateInstallationCarriersAreRefused(t *testing.T) {
	a := newAuthority(t)
	token := a.start(t, mintInput{})

	for name, build := range map[string]func(http.Header){
		"id stated twice, the second disagreeing": func(headers http.Header) {
			headers.Add(InstallationIDHeaderName, testInstallation)
			headers.Add(InstallationIDHeaderName, "installation-the-caller-added")
			headers.Set(InstallationRevisionHeaderName, "3")
		},
		"id stated twice, both agreeing": func(headers http.Header) {
			headers.Add(InstallationIDHeaderName, testInstallation)
			headers.Add(InstallationIDHeaderName, testInstallation)
			headers.Set(InstallationRevisionHeaderName, "3")
		},
		"revision stated twice": func(headers http.Header) {
			headers.Set(InstallationIDHeaderName, testInstallation)
			headers.Add(InstallationRevisionHeaderName, "3")
			headers.Add(InstallationRevisionHeaderName, "4")
		},
	} {
		t.Run(name, func(t *testing.T) {
			headers := http.Header{}
			headers.Set(HeaderName, token)
			build(headers)
			_, err := FromHeaders(headers)
			require.ErrorIs(t, err, ErrInvalid)
			require.ErrorContains(t, err, "exactly one value")
		})
	}
}

// A token in another encoding is refused as that, by name, in the one place
// this module decodes — using core's own discrimination, so an operator does
// not get two different messages for one condition. It is never reported as a
// signature problem, which is the misdiagnosis the whole rule exists to end.
func TestAForeignEncodingIsNamedAsOne(t *testing.T) {
	request := httptest.NewRequest(http.MethodGet, "/records", nil)
	err := Attach(request, fixture(t, "foreign-encoding").Token)
	require.ErrorIs(t, err, ErrNotACoreToken)
	require.NotErrorIs(t, err, ErrInvalid,
		"ErrNotACoreToken does not wrap ErrInvalid: the two diagnoses must not be reachable from one branch")
	require.NotContains(t, err.Error(), "signature")

	// An empty payload is NOT that error, here or in core: it is a malformed
	// token of no format at all. Widening "not a core token" to cover it would
	// make it mean "something was wrong early", which is the vagueness it
	// exists to remove.
	empty := httptest.NewRequest(http.MethodGet, "/records", nil)
	err = Attach(empty, ".c2lnbmF0dXJl")
	require.ErrorIs(t, err, ErrInvalid)
	require.NotErrorIs(t, err, ErrNotACoreToken)
}
