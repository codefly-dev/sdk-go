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
func TestAttachRefusesAnUnsealedCapability(t *testing.T) {
	for _, name := range []string{"missing-seal", "seal-without-installation"} {
		t.Run(name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, "/records", nil)
			err := Attach(request, fixture(t, name).Token)
			require.ErrorIs(t, err, ErrUnsealed)
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

	// Carrying neither is allowed: a sender that attaches nothing beside the
	// capability has stated nothing to disagree with, and the seal governs
	// regardless.
	headers := http.Header{}
	headers.Set(HeaderName, token)
	carried, err := FromHeaders(headers)
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
// nobody approved.
func TestSealedOperationBindingIsWholeOrAbsent(t *testing.T) {
	a := newAuthority(t)
	_, _, binding, err := sealOf(a.start(t, mintInput{binding: testBinding}))
	require.NoError(t, err)
	require.NotNil(t, binding)
	require.Equal(t, OperationBinding{ID: testBinding, Revision: 2, Incarnation: 1}, *binding)

	_, _, none, err := sealOf(a.start(t, mintInput{}))
	require.NoError(t, err)
	require.Nil(t, none, "a session that exercises no binding seals none")
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
