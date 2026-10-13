package workcontext

import (
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// The mint URL is admitted by the SAME function as the key-set URL, not by a
// mint-shaped copy of it. Driving every branch of the rule through both doors
// and requiring the same answer — and the same words, once the subject is
// swapped — is how that is held rather than documented.
func TestTheMintURLIsAdmittedByTheSameRuleAsTheKeySet(t *testing.T) {
	for name, test := range map[string]struct {
		url    string
		source TransportSource
		names  string // "" admits; otherwise the rule the refusal must name
	}{
		"https to any host":                      {"https://mint.example/platform/_mint", unasserted, ""},
		"https under the assertion":              {"https://mint.example/platform/_mint", meshed, ""},
		"plaintext to an in-cluster Service":     {"http://gateway.platform.svc/_mint", meshed, ""},
		"plaintext with the cluster domain":      {"http://gateway.platform.svc.cluster.local:8081/_mint", meshed, ""},
		"plaintext to loopback on a local run":   {"http://127.0.0.1:8081/_mint", localRun, ""},
		"plaintext to a v6 loopback locally":     {"http://[::1]:8081/_mint", localRun, ""},
		"plaintext to localhost on a local run":  {"http://localhost:8081/_mint", localRun, ""},
		"an in-cluster Service unasserted":       {"http://gateway.platform.svc/_mint", unasserted, "is not asserted"},
		"an in-cluster Service asserted false":   {"http://gateway.platform.svc/_mint", transport{assertion: "false", set: true}, "is not asserted"},
		"an external host under the assertion":   {"http://mint.example/_mint", meshed, "not an in-cluster Service address"},
		"an svc label in another domain":         {"http://gateway.platform.svc.example.com/_mint", meshed, "not an in-cluster Service address"},
		"a bare IP under the assertion":          {"http://10.4.1.9:8081/_mint", meshed, "not an in-cluster Service address"},
		"loopback off a local run":               {"http://127.0.0.1:8081/_mint", unasserted, "not a local run"},
		"loopback off a local run with the mesh": {"http://127.0.0.1:8081/_mint", meshed, "not a local run"},
		"a host containing localhost":            {"http://localhost.example.invalid/_mint", meshedLocal, "not an in-cluster Service address"},
		"another scheme":                         {"ftp://mint.example/_mint", meshed, "scheme is not https"},
		"a misspelled assertion behind https":    {"https://mint.example/_mint", transport{assertion: "True", set: true}, MeshTransportKey},
		"an unreadable assertion behind https":   {"https://mint.example/_mint", transport{failure: fmt.Errorf("unreadable")}, "could not be read"},
		"userinfo":                               {"https://user:pass@mint.example/_mint", unasserted, "no credentials, query or fragment"},
		"a query":                                {"https://mint.example/_mint?as=root", unasserted, "no credentials, query or fragment"},
		"an empty query":                         {"https://mint.example/_mint?", unasserted, "no credentials, query or fragment"},
		"a fragment":                             {"https://mint.example/_mint#f", unasserted, "no credentials, query or fragment"},
		"no host":                                {"/platform/_mint", unasserted, "absolute URL naming a host"},
		"empty":                                  {"   ", unasserted, "is unset"},
	} {
		t.Run(name, func(t *testing.T) {
			endpoint, plaintext, mintErr := validateMintURL(test.url, test.source)
			keySet, keySetErr := ResolveKeySetEndpoint(test.url, test.source)

			if test.names == "" {
				require.NoError(t, mintErr)
				require.NoError(t, keySetErr)
				require.Equal(t, keySet.URL(), endpoint, "both doors admit the same canonical URL")
				require.Equal(t, strings.HasPrefix(test.url, "http://"), plaintext)
				return
			}
			require.ErrorIs(t, mintErr, ErrInvalid)
			require.ErrorContains(t, mintErr, test.names)
			require.NotErrorIs(t, mintErr, ErrMintRefused, "a misconfiguration must not read as a host's verdict")
			require.Error(t, keySetErr)
			require.Equal(t,
				strings.ReplaceAll(keySetErr.Error(), "key set", "mint endpoint"), mintErr.Error(),
				"the two doors refuse in the same words")
			if strings.HasPrefix(test.url, "http://") || strings.HasPrefix(test.url, "ftp://") {
				require.ErrorContains(t, mintErr, MeshTransportRemedy)
			}
		})
	}
}

// With no Transport, nothing can read the composition's assertion or the
// environment, so the client admits https alone — the default every existing
// caller already has. Both plaintext shapes are refused by the half of the rule
// that cannot be satisfied, never admitted on the strength of the address.
func TestANilTransportKeepsTheMintURLHTTPSOnly(t *testing.T) {
	endpoint, plaintext, err := validateMintURL("https://mint.example/platform/_mint", nil)
	require.NoError(t, err)
	require.Equal(t, "https://mint.example/platform/_mint", endpoint)
	require.False(t, plaintext)

	_, _, err = validateMintURL("http://gateway.platform.svc/_mint", nil)
	require.ErrorIs(t, err, ErrInvalid)
	require.ErrorContains(t, err, "is not asserted")

	_, _, err = validateMintURL("http://127.0.0.1:8081/_mint", nil)
	require.ErrorIs(t, err, ErrInvalid)
	require.ErrorContains(t, err, "not a local run")
}

// No construction-time refusal echoes any part of the mint URL: a URL is a place
// a credential gets written by mistake, and a refusal reaches boot-time logging.
func TestNoMintRefusalEchoesTheURL(t *testing.T) {
	const marker = "zzmarkerzz"
	for _, raw := range []string{
		"https://user:" + marker + "@mint.example/_mint",
		"https://mint.example/_mint?token=" + marker,
		"https://mint.example/_mint#" + marker,
		"https://mint.example:" + marker + "/_mint",
		"https://mint.example/%zz" + marker,
		"http://" + marker + ".example/_mint",
		"http://" + marker + ".platform.svc/_mint",
		"http://127.0.0.1/" + marker,
		marker + "/_mint",
	} {
		for _, source := range []TransportSource{nil, meshed, localRun} {
			options := validMintOptions()
			options.URL, options.Transport = raw, source
			_, err := NewMintClient(options)

			require.Error(t, err, "%q must be refused", raw)
			require.NotContains(t, err.Error(), marker, "the refusal for %q echoes part of the URL", raw)
		}
	}
}

// An admitted plaintext endpoint has no handshake, so the three handshake sources
// are not required — and TestNewMintClientValidatesItsConfiguration holds that
// one set beside it is refused.
func TestAPlaintextMintClientNeedsNoHandshakeSource(t *testing.T) {
	for name, test := range map[string]struct {
		url    string
		source TransportSource
	}{
		"loopback on a local run":     {"http://127.0.0.1:8081/_mint", localRun},
		"an in-cluster Service":       {"http://gateway.platform.svc/_mint", meshed},
		"with the cluster domain":     {"http://gateway.platform.svc.cluster.local/_mint", meshed},
		"https still reads all three": {"https://mint.example/_mint", meshed},
	} {
		t.Run(name, func(t *testing.T) {
			options := validMintOptions()
			options.URL, options.Transport = test.url, test.source
			if strings.HasPrefix(test.url, "http://") {
				options.TrustAnchor, options.ClientCertificate, options.AdmittedPeers = nil, nil, nil
			}

			client, err := NewMintClient(options)

			require.NoError(t, err)
			require.Equal(t, test.url, client.options.URL)
		})
	}
}

// countingProjection answers a different token on every read, so a host can tell
// which read each request carried.
type countingProjection struct{ reads atomic.Uint64 }

func (p *countingProjection) ProjectedToken() (string, error) {
	return fmt.Sprintf("projected-%d", p.reads.Add(1)), nil
}

// The host spends a projected token on the mint it is presented for, so a token
// read once and presented twice earns a 401 that latches. Every mint — the first,
// a renewal, a refresh — reads the projection again and presents what it read,
// over plaintext exactly as over TLS: the request goes through DialContext to a
// plain listener, on its own HTTP/1.1 connection, with no TLS state at the host.
func TestEveryPlaintextMintPresentsTheProjectionReadForIt(t *testing.T) {
	clock := testClock
	now := func() time.Time { return clock }
	host := newPlaintextMintHost(t, now)
	projection := &countingProjection{}
	client := newTestMintClient(t, host, "", now, plaintextMint, func(o *MintOptions) {
		o.ProjectedToken = projection
	})
	require.True(t, strings.HasPrefix(client.options.URL, "http://127.0.0.1:"), client.options.URL)

	held, err := client.Credential(t.Context())
	require.NoError(t, err)

	clock = testClock.Add(14 * time.Minute)
	renewed, err := client.Credential(t.Context())
	require.NoError(t, err)
	require.NotEqual(t, held.Token(), renewed.Token(), "the renewal is a new mint")

	refreshed, err := client.Refresh(t.Context(), renewed)
	require.NoError(t, err)
	require.NotEqual(t, renewed.Token(), refreshed.Token(), "the refresh is a new mint")

	require.Equal(t, MintCounts{Mints: 1, Renewals: 1, Refreshes: 1}, client.Counts())
	require.EqualValues(t, 3, projection.reads.Load(), "one read per mint, never a cached token")
	require.EqualValues(t, 3, host.requests.Load())
	for want := 1; want <= 3; want++ {
		arrival := <-host.arrivals
		require.Equal(t, fmt.Sprintf("Bearer projected-%d", want), arrival.authorization,
			"mint %d presents the token read for it, in order", want)
		require.False(t, arrival.tls.HandshakeComplete, "the hop is plaintext; the mesh carries it")
		require.Equal(t, 1, arrival.protocol, "HTTP/1.1, one request per connection")
		require.True(t, arrival.close, "no connection is reused across mints")
	}
}
