package workcontext

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"go/ast"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	corework "github.com/codefly-dev/core/workcontext"
	"github.com/stretchr/testify/require"
)

// SP-WC-05 — a verifier accepts a capability only when it carries the configured
// issuer and this module's own audience; it reads its key set only over
// mesh-protected transport, and fails closed BY NAME when the issuer or the key
// set is unset.
//
// Verification is core's. What is required here is that no verifier exists
// without that configuration, that each missing part is refused by its own name,
// and that the keys a verifier holds are the keys an admitted endpoint served.

// ---------------------------------------------------------------------------
// The transport source: the composition's assertion and the runtime.
// ---------------------------------------------------------------------------

type transport struct {
	assertion string
	set       bool
	failure   error
	local     bool
}

func (t transport) WorkspaceValueIfSet(name string, key string) (string, bool, error) {
	if name != MeshTransportGroup || key != MeshTransportKey {
		return "", false, nil
	}
	if t.failure != nil {
		return "", false, t.failure
	}
	return t.assertion, t.set, nil
}

func (t transport) IsLocalRun() bool { return t.local }

var (
	meshed      = transport{assertion: "true", set: true}
	unasserted  = transport{}
	localRun    = transport{local: true}
	meshedLocal = transport{assertion: "true", set: true, local: true}
)

// ---------------------------------------------------------------------------
// A real endpoint, because the binding under test is that the keys came from one.
// ---------------------------------------------------------------------------

// decodeKeySet is a consumer's decoder. Reading a key set means naming a
// signature primitive, which is why the decoding is the caller's and the keys
// cross this module's boundary as plain bytes.
func decodeKeySet(payload []byte) (map[string][]byte, error) {
	keys := map[string][]byte{}
	for _, line := range strings.Split(strings.TrimSpace(string(payload)), "\n") {
		id, encoded, found := strings.Cut(line, " ")
		if !found {
			return nil, errors.New("not a key set")
		}
		key, err := hex.DecodeString(encoded)
		if err != nil {
			return nil, err
		}
		keys[id] = key
	}
	return keys, nil
}

// servedKeySet stands up a loopback endpoint serving body, and returns the
// admitted endpoint for it.
func servedKeySet(t *testing.T, body string) KeySetEndpoint {
	t.Helper()
	return servedBy(t, func(writer http.ResponseWriter, _ *http.Request) {
		_, _ = writer.Write([]byte(body))
	})
}

func servedBy(t *testing.T, handler http.HandlerFunc) KeySetEndpoint {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	endpoint, err := ResolveKeySetEndpoint(server.URL+"/keys", localRun)
	require.NoError(t, err)
	return endpoint
}

func keySetLine(id string, key []byte) string { return id + " " + hex.EncodeToString(key) }

// acquired is a usable key set holding one key of the right length.
func acquired(t *testing.T, key ed25519.PublicKey) KeySet {
	t.Helper()
	set, err := AcquireKeySet(t.Context(), servedKeySet(t, keySetLine(testKeyID, key)), decodeKeySet)
	require.NoError(t, err)
	return set
}

func mustKey(t *testing.T) ed25519.PublicKey {
	t.Helper()
	public, _, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	return public
}

// signingAuthority is core's minter with a REAL signing key: a verifier built
// the only way this package allows holds whatever key the endpoint served, so a
// test needs a key whose private half it has.
type signingAuthority struct {
	*authority
	public ed25519.PublicKey
}

func newSigningAuthority(t *testing.T) signingAuthority {
	t.Helper()
	over := newAuthority(t)
	public, private, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	minter := *over.core
	minter.Key = private
	return signingAuthority{
		authority: &authority{core: &minter, seals: over.seals, now: over.now},
		public:    public,
	}
}

func settingsFor(a *authority) VerifierSettings {
	return VerifierSettings{
		Issuer:    testIssuer,
		Audience:  testAudience,
		Revisions: corework.FixedRevision(5),
		Replay:    corework.NewMemoryReplayStore(),
		Grants:    noGrants{},
		Seals:     a.seals,
		Now:       a.now,
	}
}

// pinnedFor wraps a raw verifier for the in-package tests that build one from
// core's conformance kit. It exists only here: there is no exported way to make
// one, which is the property TestEveryVerificationPathIsPinned holds.
func pinnedFor(v *verifier) *PinnedVerifier { return &PinnedVerifier{verifier: v} }

// ---------------------------------------------------------------------------
// The number this module states and core calls for.
// ---------------------------------------------------------------------------

func TestTheVerificationKeySizeAgreesWithCore(t *testing.T) {
	require.Equal(t, ed25519.PublicKeySize, verificationKeySize,
		"verificationKeySize is this module's copy of the length core's resolveKey requires; "+
			"if core changed it, this number changes with it or every usable key set is refused")
}

// ---------------------------------------------------------------------------
// The mesh assertion: literal, three-valued, and never echoed.
// ---------------------------------------------------------------------------

// ONLY THE LITERAL VALUE asserts the mesh. A value carrying any whitespace is
// not that value, and is an error rather than either answer.
func TestMeshProtectedComparesTheAssertionLiterally(t *testing.T) {
	protected, err := MeshProtected(transport{assertion: "true", set: true})
	require.NoError(t, err)
	require.True(t, protected)

	for _, value := range []string{
		" true", "true ", "\ttrue", "true\n", "true\r\n", " true", "true ",
		"TRUE", "True", "1", "yes", "0", "no", "FALSE", "tru", "true false",
	} {
		t.Run(fmt.Sprintf("refuses %q", value), func(t *testing.T) {
			_, err := MeshProtected(transport{assertion: value, set: true})

			require.ErrorIs(t, err, ErrInvalid)
			require.ErrorContains(t, err, MeshTransportGroup+"/"+MeshTransportKey)
		})
	}
}

// The refusal names the setting and the permitted values and nothing else.
// WorkspaceValueIfSet reads the secret namespace too, so the value may be a
// credential, and a configuration error reaches boot-time logging.
func TestTheAssertionRefusalDoesNotEchoTheValue(t *testing.T) {
	const marker = "zzsecretzz"
	for _, value := range []string{marker, "true " + marker, "AKIA" + marker, "hunter2-" + marker} {
		_, err := MeshProtected(transport{assertion: value, set: true})

		require.Error(t, err)
		require.NotContains(t, err.Error(), marker,
			"the refusal for %q echoes the configured value", value)
	}
}

// Unset, and the literal "false", keep plaintext refused without stopping the
// process. An empty value is "not asserted" rather than a misspelling.
func TestMeshProtectedTreatsUnsetAndFalseAsNotAsserted(t *testing.T) {
	for name, source := range map[string]transport{
		"nothing carries it": {},
		"an empty value":     {assertion: "", set: true},
		"false":              {assertion: "false", set: true},
	} {
		t.Run(name, func(t *testing.T) {
			protected, err := MeshProtected(source)

			require.NoError(t, err)
			require.False(t, protected)
		})
	}
}

// A LOOKUP FAILURE IS NOT ABSENCE. An unreadable delivery, or an
// authority-bearing value that has drifted since boot, is a refusal — reading it
// as "not asserted" is a failed read quietly deciding a posture question.
func TestMeshProtectedRefusesALookupFailureRatherThanReadingItAsAbsence(t *testing.T) {
	const marker = "zzsecretzz"
	failure := fmt.Errorf("the pinned value changed from %q", marker)

	_, err := MeshProtected(transport{failure: failure})

	require.ErrorIs(t, err, ErrInvalid)
	require.ErrorIs(t, err, failure, "the source's error stays in the chain for errors.Is")
	require.ErrorContains(t, err, "could not be read")
	require.NotContains(t, err.Error(), marker, "the refusal echoes the value the lookup named")
}

// And the failure reaches every admission decision, including an https one: a
// declaration that cannot be read must not leave the process admitting.
func TestALookupFailureRefusesEveryKeySetEndpoint(t *testing.T) {
	source := transport{failure: errors.New("unreadable")}
	for _, raw := range []string{
		"https://authority.example/keys",
		"http://authority.platform.svc/keys",
		"http://127.0.0.1:8080/keys",
	} {
		_, err := ResolveKeySetEndpoint(raw, source)

		require.ErrorIs(t, err, ErrInvalid, "admitting %q after a failed declaration read", raw)
		require.ErrorContains(t, err, "could not be read")
	}
}

func TestResolveKeySetEndpointNeedsATransportSource(t *testing.T) {
	_, err := ResolveKeySetEndpoint("https://authority.example/keys", nil)

	require.ErrorIs(t, err, ErrInvalid)
	require.ErrorContains(t, err, "needs a transport source")
}

// The assertion is read whatever the URL's scheme, so a misspelling cannot sit
// unread behind an https URL until the day somebody changes one.
func TestAMisspelledAssertionIsRefusedEvenForAnHTTPSKeySet(t *testing.T) {
	_, err := ResolveKeySetEndpoint("https://authority.example/keys", transport{assertion: "True", set: true})

	require.ErrorIs(t, err, ErrInvalid)
	require.ErrorContains(t, err, MeshTransportKey)
}

// ---------------------------------------------------------------------------
// The address rule.
// ---------------------------------------------------------------------------

func TestResolveKeySetEndpointAdmitsOnlyTheMeshContract(t *testing.T) {
	accepted := map[string]struct {
		url    string
		source TransportSource
	}{
		"https to any host":                    {"https://authority.example/keys", unasserted},
		"https with a port and a path":         {"https://authority.example:8443/.well-known/keys", unasserted},
		"https needs no assertion":             {"https://authority.svc.cluster.local/keys", unasserted},
		"https is admitted with the assertion": {"https://authority.example/keys", meshed},
		"plaintext to an in-cluster Service":   {"http://authority.platform.svc/keys", meshed},
		"plaintext with the cluster domain":    {"http://authority.platform.svc.cluster.local/keys", meshed},
		"plaintext in-cluster with a port":     {"http://authority.platform.svc:8080/keys", meshed},
		"a trailing dot on the cluster domain": {"http://authority.platform.svc.cluster.local./keys", meshed},
		"labels with digits and hyphens":       {"http://auth-1.platform-2.svc/keys", meshed},
		"a loopback name on a local run":       {"http://localhost:8080/keys", localRun},
		"a loopback literal on a local run":    {"http://127.0.0.1:8080/keys", localRun},
		"a loopback v6 literal on a local run": {"http://[::1]:8080/keys", localRun},
		"an uppercase loopback name locally":   {"http://LOCALHOST:8080/keys", localRun},
		"an uppercase scheme is still https":   {"HTTPS://authority.example/keys", unasserted},
	}
	for name, test := range accepted {
		t.Run("accepts "+name, func(t *testing.T) {
			endpoint, err := ResolveKeySetEndpoint(test.url, test.source)

			require.NoError(t, err)
			require.NotEmpty(t, endpoint.URL())
			require.Equal(t, endpoint.URL(), endpoint.String())
		})
	}

	refused := map[string]struct {
		url    string
		source TransportSource
		names  string
	}{
		// Neither half of the contract admits on its own.
		"an in-cluster Service without the assertion": {
			"http://authority.platform.svc/keys", unasserted, "is not asserted",
		},
		"an in-cluster Service with the assertion false": {
			"http://authority.platform.svc/keys", transport{assertion: "false", set: true}, "is not asserted",
		},
		"an external host with the assertion set": {
			"http://authority.example/keys", meshed, "not an in-cluster Service address",
		},
		// The suffix is matched literally.
		"an svc label in another domain": {
			"http://authority.platform.svc.example.com/keys", meshed, "not an in-cluster Service address",
		},
		"the cluster domain with something after it": {
			"http://authority.platform.svc.cluster.local.example.com/keys", meshed,
			"not an in-cluster Service address",
		},
		"an extra prefix label": {
			"http://extra.authority.platform.svc/keys", meshed, "not an in-cluster Service address",
		},
		"only two labels": {"http://authority.svc/keys", meshed, "not an in-cluster Service address"},
		"four labels":     {"http://authority.platform.svc.cluster/keys", meshed, "not an in-cluster Service address"},
		"svc in the wrong position": {
			"http://svc.authority.platform/keys", meshed, "not an in-cluster Service address",
		},
		"a bare IP with the assertion set": {
			"http://10.4.1.9:8080/keys", meshed, "not an in-cluster Service address",
		},
		"a short name with the assertion set": {
			"http://authority/keys", meshed, "not an in-cluster Service address",
		},
		// DNS-1123 on both labels before svc.
		"an empty service label":           {"http://.platform.svc/keys", meshed, "not an in-cluster Service"},
		"an empty namespace label":         {"http://authority..svc/keys", meshed, "not an in-cluster Service"},
		"a leading hyphen":                 {"http://-authority.platform.svc/keys", meshed, "not an in-cluster Service"},
		"a trailing hyphen":                {"http://authority-.platform.svc/keys", meshed, "not an in-cluster Service"},
		"an underscore":                    {"http://authority_1.platform.svc/keys", meshed, "not an in-cluster Service"},
		"a label of sixty-four characters": {"http://" + strings.Repeat("a", 64) + ".platform.svc/keys", meshed, "not an in-cluster Service"},
		// Loopback is the local shape only.
		"loopback off a local run": {
			"http://127.0.0.1:8080/keys", unasserted, "not a local run",
		},
		"loopback off a local run with the assertion set": {
			"http://127.0.0.1:8080/keys", meshed, "not a local run",
		},
		"a loopback name off a local run": {
			"http://localhost:8080/keys", meshed, "not a local run",
		},
		// A name that merely contains a loopback spelling is a different host.
		"a host containing localhost":     {"http://localhost.example.invalid/keys", meshedLocal, "not an in-cluster Service"},
		"a host containing a v4 loopback": {"http://127.0.0.1.example.invalid/keys", meshedLocal, "not an in-cluster Service"},
		"notlocalhost":                    {"http://notlocalhost/keys", meshedLocal, "not an in-cluster Service"},
		// Not http and not https.
		"ftp":             {"ftp://authority.example/keys", unasserted, "scheme is not https"},
		"ws":              {"ws://authority.example/keys", unasserted, "scheme is not https"},
		"scheme relative": {"//authority.example/keys", unasserted, "scheme is not https"},
		// No host to authenticate.
		"a file URL":          {"file:///etc/keys.json", unasserted, "absolute URL naming a host"},
		"a port with no host": {"https://:443/keys", unasserted, "absolute URL naming a host"},
		"a path only":         {"/well-known/keys", unasserted, "absolute URL naming a host"},
		"a bare host":         {"authority.example/keys", unasserted, "absolute URL naming a host"},
		"an opaque URL":       {"mailto:keys@example.test", unasserted, "absolute URL naming a host"},
		// Malformed: refused, and NOT a panic.
		"a malformed port":    {"https://authority.example:ht/keys", unasserted, "absolute URL naming a host"},
		"a malformed escape":  {"https://authority.example/%zz", unasserted, "absolute URL naming a host"},
		"an unclosed bracket": {"https://[::1/keys", unasserted, "absolute URL naming a host"},
		"a control character": {"https://authority.example/\x7f", unasserted, "absolute URL naming a host"},
		// A value that leaks into a log or carries a credential.
		"userinfo":       {"https://user:pass@authority.example/keys", unasserted, "no credentials, query or fragment"},
		"a query":        {"https://authority.example/keys?token=abc", unasserted, "no credentials, query or fragment"},
		"an empty query": {"https://authority.example/keys?", unasserted, "no credentials, query or fragment"},
		"a fragment":     {"https://authority.example/keys#frag", unasserted, "no credentials, query or fragment"},
		// Unset.
		"empty":      {"", unasserted, "the key set is unset"},
		"whitespace": {"   ", unasserted, "the key set is unset"},
	}
	for name, test := range refused {
		t.Run("refuses "+name, func(t *testing.T) {
			endpoint, err := ResolveKeySetEndpoint(test.url, test.source)

			require.ErrorIs(t, err, ErrInvalid)
			require.ErrorContains(t, err, test.names)
			require.Empty(t, endpoint.URL())
		})
	}
}

func TestEveryPlaintextRefusalCarriesTheRemedy(t *testing.T) {
	for _, test := range []struct {
		url    string
		source TransportSource
	}{
		{"http://authority.platform.svc/keys", unasserted},
		{"http://authority.example/keys", meshed},
		{"http://127.0.0.1/keys", meshed},
		{"ftp://authority.example/keys", unasserted},
	} {
		_, err := ResolveKeySetEndpoint(test.url, test.source)

		require.ErrorContains(t, err, MeshTransportRemedy, "refusing %q", test.url)
	}
}

// No refusal echoes any part of the URL, the parser's own message included.
func TestNoRefusalEchoesTheURL(t *testing.T) {
	const marker = "zzmarkerzz"
	for _, raw := range []string{
		"https://user:" + marker + "@authority.example/keys",
		"https://authority.example/keys?token=" + marker,
		"https://authority.example/keys#" + marker,
		"https://authority.example:" + marker + "/keys",
		"https://authority.example/%zz" + marker,
		"https://[::1" + marker + "/keys",
		"ftp://" + marker + ".example/keys",
		"http://" + marker + ".example/keys",
		"http://127.0.0.1/" + marker,
		marker + "/keys",
	} {
		_, err := ResolveKeySetEndpoint(raw, meshed)

		require.Error(t, err, "%q must be refused", raw)
		require.NotContains(t, err.Error(), marker, "the refusal for %q echoes part of the URL", raw)
	}
}

func TestKeySetEndpointCarriesTheAdmittedURL(t *testing.T) {
	endpoint, err := ResolveKeySetEndpoint(" https://authority.example/keys ", unasserted)
	require.NoError(t, err)
	require.Equal(t, "https://authority.example/keys", endpoint.URL())

	require.Empty(t, KeySetEndpoint{}.URL(), "a zero value names no location")
	require.Empty(t, KeySetEndpoint{}.String())
}

// ---------------------------------------------------------------------------
// Acquisition: the keys a verifier holds are the keys an admitted endpoint served.
// ---------------------------------------------------------------------------

func TestAcquireKeySetFetchesFromTheAdmittedEndpoint(t *testing.T) {
	key := mustKey(t)
	endpoint := servedKeySet(t, keySetLine(testKeyID, key))

	set, err := AcquireKeySet(t.Context(), endpoint, decodeKeySet)

	require.NoError(t, err)
	require.Equal(t, endpoint.URL(), set.Endpoint())
	require.Equal(t, []string{testKeyID}, set.KeyIDs())
}

func TestAcquireKeySetRefusesWhatItCannotUse(t *testing.T) {
	t.Run("a zero endpoint", func(t *testing.T) {
		_, err := AcquireKeySet(t.Context(), KeySetEndpoint{}, decodeKeySet)

		require.ErrorIs(t, err, ErrInvalid)
		require.ErrorContains(t, err, "needs an admitted endpoint")
	})

	t.Run("no decoder", func(t *testing.T) {
		_, err := AcquireKeySet(t.Context(), servedKeySet(t, ""), nil)

		require.ErrorIs(t, err, ErrInvalid)
		require.ErrorContains(t, err, "needs a decoder")
	})

	t.Run("a redirect, which leaves the admitted address", func(t *testing.T) {
		elsewhere := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(keySetLine(testKeyID, mustKey(t))))
		}))
		t.Cleanup(elsewhere.Close)
		endpoint := servedBy(t, func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, elsewhere.URL, http.StatusFound)
		})

		_, err := AcquireKeySet(t.Context(), endpoint, decodeKeySet)

		require.ErrorIs(t, err, ErrKeySetUnavailable)
		require.ErrorContains(t, err, "redirected")
	})

	t.Run("a status", func(t *testing.T) {
		endpoint := servedBy(t, func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusServiceUnavailable)
		})

		_, err := AcquireKeySet(t.Context(), endpoint, decodeKeySet)

		require.ErrorIs(t, err, ErrKeySetUnavailable)
		require.ErrorContains(t, err, "503")
	})

	t.Run("a body larger than this module reads", func(t *testing.T) {
		endpoint := servedBy(t, func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write(make([]byte, maxKeySetBytes+1))
		})

		_, err := AcquireKeySet(t.Context(), endpoint, decodeKeySet)

		require.ErrorIs(t, err, ErrKeySetUnavailable)
		require.ErrorContains(t, err, "larger than")
	})

	t.Run("an endpoint that does not answer", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
		endpoint, err := ResolveKeySetEndpoint(server.URL+"/keys", localRun)
		require.NoError(t, err)
		server.Close()

		_, err = AcquireKeySet(t.Context(), endpoint, decodeKeySet)

		require.ErrorIs(t, err, ErrKeySetUnavailable)
	})

	t.Run("a decoder error, whose text is the caller's", func(t *testing.T) {
		const marker = "zzdecoderzz"
		endpoint := servedKeySet(t, "whatever")

		_, err := AcquireKeySet(t.Context(), endpoint, func([]byte) (map[string][]byte, error) {
			return nil, errors.New(marker)
		})

		require.ErrorIs(t, err, ErrInvalid)
		require.NotContains(t, err.Error(), marker, "a decoder's text may name the bytes it read")
	})

	t.Run("no key at all", func(t *testing.T) {
		endpoint := servedKeySet(t, "")

		_, err := AcquireKeySet(t.Context(), endpoint, func([]byte) (map[string][]byte, error) {
			return map[string][]byte{}, nil
		})

		require.ErrorIs(t, err, ErrInvalid)
		require.ErrorContains(t, err, "served no key")
	})

	t.Run("more keys than a verifier holds", func(t *testing.T) {
		lines := make([]string, 0, maxKeySetKeys+1)
		for index := range maxKeySetKeys + 1 {
			lines = append(lines, keySetLine(fmt.Sprintf("key-%d", index), mustKey(t)))
		}

		_, err := AcquireKeySet(t.Context(), servedKeySet(t, strings.Join(lines, "\n")), decodeKeySet)

		require.ErrorIs(t, err, ErrInvalid)
		require.ErrorContains(t, err, "at most")
	})

	t.Run("a key with no id", func(t *testing.T) {
		endpoint := servedKeySet(t, "whatever")

		_, err := AcquireKeySet(t.Context(), endpoint, func([]byte) (map[string][]byte, error) {
			return map[string][]byte{"": make([]byte, verificationKeySize)}, nil
		})

		require.ErrorIs(t, err, ErrInvalid)
		require.ErrorContains(t, err, "no id")
	})

	t.Run("no context", func(t *testing.T) {
		//nolint:staticcheck // a nil context is exactly what this refuses.
		_, err := AcquireKeySet(nil, servedKeySet(t, ""), decodeKeySet)

		require.ErrorIs(t, err, ErrInvalid)
		require.ErrorContains(t, err, "needs a context")
	})
}

// ---------------------------------------------------------------------------
// Settling the verifier.
// ---------------------------------------------------------------------------

func TestNewVerifierRefusesAnIncompleteConfigurationByName(t *testing.T) {
	cases := map[string]struct {
		settings func(VerifierSettings) VerifierSettings
		keys     func(*testing.T) KeySet
		names    string
	}{
		"no issuer": {
			settings: func(s VerifierSettings) VerifierSettings { s.Issuer = ""; return s },
			names:    "no issuer is pinned",
		},
		"no audience": {
			settings: func(s VerifierSettings) VerifierSettings { s.Audience = ""; return s },
			names:    "no audience is pinned",
		},
		"issuer carrying whitespace": {
			settings: func(s VerifierSettings) VerifierSettings { s.Issuer = " " + testIssuer; return s },
			names:    "issuer carries surrounding whitespace",
		},
		"audience carrying whitespace": {
			settings: func(s VerifierSettings) VerifierSettings { s.Audience = testAudience + "\n"; return s },
			names:    "audience carries surrounding whitespace",
		},
		"a key set that was never acquired": {
			keys:  func(*testing.T) KeySet { return KeySet{} },
			names: "no key set from an admitted endpoint",
		},
		"no revision source": {
			settings: func(s VerifierSettings) VerifierSettings { s.Revisions = nil; return s },
			names:    "no revision source",
		},
		"no replay store": {
			settings: func(s VerifierSettings) VerifierSettings { s.Replay = nil; return s },
			names:    "no replay store",
		},
		"no grant source": {
			settings: func(s VerifierSettings) VerifierSettings { s.Grants = nil; return s },
			names:    "no grant source",
		},
		"no seal source": {
			settings: func(s VerifierSettings) VerifierSettings { s.Seals = nil; return s },
			names:    "no seal source",
		},
	}
	for name, test := range cases {
		t.Run(name, func(t *testing.T) {
			a := newAuthority(t)
			settings := settingsFor(a)
			if test.settings != nil {
				settings = test.settings(settings)
			}
			keys := acquired(t, mustKey(t))
			if test.keys != nil {
				keys = test.keys(t)
			}

			pinned, err := NewVerifier(settings, keys)

			require.ErrorIs(t, err, ErrInvalid)
			require.ErrorContains(t, err, test.names)
			require.Nil(t, pinned, "a refused configuration hands back nothing to verify with")
		})
	}
}

// Key material of the wrong length is refused when the verifier is settled,
// naming the key id. Core refuses it per request; a configuration fault belongs
// in a refusal before anything is served.
func TestNewVerifierRefusesUnusableKeyMaterial(t *testing.T) {
	for _, size := range []int{0, 1, 16, 31, 33, 64} {
		t.Run(fmt.Sprintf("%d bytes", size), func(t *testing.T) {
			set, err := AcquireKeySet(t.Context(), servedKeySet(t, "whatever"),
				func([]byte) (map[string][]byte, error) {
					return map[string][]byte{testKeyID: make([]byte, size)}, nil
				})
			require.NoError(t, err)

			pinned, err := NewVerifier(settingsFor(newAuthority(t)), set)

			require.ErrorIs(t, err, ErrInvalid)
			require.ErrorContains(t, err, fmt.Sprintf("verification key %q is %d bytes", testKeyID, size))
			require.Nil(t, pinned)
		})
	}

	// The id named is stable across runs: two unusable entries must not produce
	// a different message each time.
	t.Run("two unusable keys name the first id in order", func(t *testing.T) {
		set, err := AcquireKeySet(t.Context(), servedKeySet(t, "whatever"),
			func([]byte) (map[string][]byte, error) {
				return map[string][]byte{"key-z": make([]byte, 7), "key-a": make([]byte, 9)}, nil
			})
		require.NoError(t, err)

		for range 20 {
			_, err := NewVerifier(settingsFor(newAuthority(t)), set)
			require.ErrorContains(t, err, `verification key "key-a" is 9 bytes`)
		}
	})
}

// The whole path, end to end: admit the endpoint, fetch the keys from it, settle
// the verifier, verify a capability the authority minted.
func TestAVerifierSettledFromAnAdmittedEndpointVerifies(t *testing.T) {
	signing := newSigningAuthority(t)

	pinned, err := NewVerifier(settingsFor(signing.authority), acquired(t, signing.public))
	require.NoError(t, err)
	require.Equal(t, testIssuer, pinned.Issuer())
	require.Equal(t, testAudience, pinned.Audience())
	require.NotEmpty(t, pinned.KeySetEndpoint())

	token := signing.startAt(t, signing.now(), mintInput{}, 15*time.Minute)

	verified, err := pinned.Verify(t.Context(), token)

	require.NoError(t, err)
	require.Equal(t, testAudience, verified.Context().GetAudience())
	require.NoError(t, pinned.Recheck(t.Context(), verified))
}

// A verifier accepts a capability only when it carries the configured issuer.
func TestASettledVerifierRefusesAnotherIssuer(t *testing.T) {
	signing := newSigningAuthority(t)
	signing.core.Issuer = "codefly.other-authority"
	token := signing.startAt(t, signing.now(), mintInput{}, 15*time.Minute)

	pinned, err := NewVerifier(settingsFor(signing.authority), acquired(t, signing.public))
	require.NoError(t, err)

	_, err = pinned.Verify(t.Context(), token)

	require.ErrorIs(t, err, ErrInvalid)
	require.ErrorContains(t, err, "codefly.other-authority")
}

// A verifier holds the keys the endpoint served and nothing else: a capability
// signed under a key that endpoint did not serve is refused.
func TestAVerifierHoldsOnlyTheKeysItsEndpointServed(t *testing.T) {
	signing := newSigningAuthority(t)
	token := signing.startAt(t, signing.now(), mintInput{}, 15*time.Minute)

	// An endpoint serving a DIFFERENT key under the same id.
	pinned, err := NewVerifier(settingsFor(signing.authority), acquired(t, mustKey(t)))
	require.NoError(t, err)

	_, err = pinned.Verify(t.Context(), token)

	require.ErrorIs(t, err, ErrInvalid)
}

func TestANilPinnedVerifierRefuses(t *testing.T) {
	var pinned *PinnedVerifier

	_, err := pinned.Verify(t.Context(), "")
	require.ErrorIs(t, err, ErrInvalid)
	require.ErrorIs(t, pinned.Recheck(t.Context(), nil), ErrInvalid)
}

// Nothing in the settings permits plaintext or an unset issuer. The shape is
// frozen by an UNKEYED literal, which stops compiling the moment a field is
// added or reordered, so a field admitting something on its own say-so could not
// arrive unnoticed.
func TestNothingInTheVerifierSettingsTurnsACheckOff(t *testing.T) {
	a := newAuthority(t)
	settings := VerifierSettings{
		testIssuer, testAudience,
		corework.FixedRevision(5), corework.NewMemoryReplayStore(), noGrants{}, a.seals,
		a.now, 0,
	}

	pinned, err := NewVerifier(settings, acquired(t, mustKey(t)))

	require.NoError(t, err)
	require.Equal(t, testIssuer, pinned.Issuer())
}

// ---------------------------------------------------------------------------
// The gate: there is no verification path here that was not settled.
// ---------------------------------------------------------------------------

// THE CHECK SP-WC-05 IS RE-AUDITED BY, in this repository.
//
// A verifier whose issuer, audience and key set are required is only a
// requirement if there is no second way to get one. Core's verifier is a struct
// whose every field has a usable zero value, so re-exporting it was a path that
// skipped every check in this file — the same shape GuardStreams exists to
// avoid, where the correct wiring took two calls and only one was reachable from
// the type system.
//
// So: nothing this package EXPORTS may name core's Verifier, and the only
// exported Verify and Recheck methods are PinnedVerifier's. Violate either and
// this test fails, which is what makes it a check rather than a description.
func TestEveryVerificationPathIsPinned(t *testing.T) {
	const coreVerifier = coreModulePath + "/workcontext#Verifier"
	var findings []string

	for _, file := range repositoryFiles(t) {
		if filepath.Dir(file.path) != "workcontext" || strings.HasSuffix(file.path, "_test.go") {
			continue
		}
		for _, declaration := range file.syntax.Decls {
			switch declared := declaration.(type) {
			case *ast.GenDecl:
				for _, spec := range declared.Specs {
					typed, ok := spec.(*ast.TypeSpec)
					if !ok || !typed.Name.IsExported() {
						continue
					}
					if typeName(file, typed.Type) == coreVerifier {
						findings = append(findings, fmt.Sprintf(
							"%s exports %s, which names core's Verifier.\n"+
								"Core's verifier is constructible with every check unset, so exporting it "+
								"is a second way in that skips the configuration NewVerifier requires.",
							file.path, typed.Name.Name))
					}
				}
			case *ast.FuncDecl:
				if !declared.Name.IsExported() {
					continue
				}
				if receiver := receiverTypeName(declared); receiver != "" {
					if (declared.Name.Name == "Verify" || declared.Name.Name == "Recheck") &&
						receiver != "PinnedVerifier" {
						findings = append(findings, fmt.Sprintf(
							"%s declares (%s).%s.\n"+
								"PinnedVerifier is the only type here that verifies, because it is the only "+
								"one that cannot exist without an issuer, an audience and an acquired key set.",
							file.path, receiver, declared.Name.Name))
					}
					continue
				}
				if declared.Type.Results == nil {
					continue
				}
				for _, result := range declared.Type.Results.List {
					if typeName(file, result.Type) == coreVerifier {
						findings = append(findings, fmt.Sprintf(
							"%s exports func %s returning core's Verifier.\n"+
								"A caller holding one can verify without any of the configuration this "+
								"package requires.",
							file.path, declared.Name.Name))
					}
				}
			}
		}
	}

	require.Empty(t, findings, "%s", strings.Join(findings, "\n\n"))
}

// receiverTypeName is the bare type name a method is declared on, through a
// pointer, and "" for a function.
func receiverTypeName(declared *ast.FuncDecl) string {
	if declared.Recv == nil || len(declared.Recv.List) == 0 {
		return ""
	}
	expression := declared.Recv.List[0].Type
	if star, ok := expression.(*ast.StarExpr); ok {
		expression = star.X
	}
	if identifier, ok := expression.(*ast.Ident); ok {
		return identifier.Name
	}
	return ""
}
