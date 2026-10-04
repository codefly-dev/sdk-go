package workcontext

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

const (
	testMintPeer       = "spiffe://test.example/mint/issuer"
	testMintClientPeer = "spiffe://test.example/workload/client"
)

func testMintPeers() ([]string, error) { return []string{testMintPeer}, nil }

// Construction-only tests need a source without exercising the handshake.
func unusedMintCertificate() (*tls.Certificate, error) {
	return nil, errors.New("this test must not request a client certificate")
}

type mintTestCA struct {
	root *x509.Certificate
	key  ed25519.PrivateKey
	pool *x509.CertPool
}

// Each CA has a distinct key so changing the root pool cannot accidentally
// trust the old leaf through a reused test signing key.
func newMintTestCA(t *testing.T) *mintTestCA {
	t.Helper()
	public, key, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "mint test root"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, public, key)
	require.NoError(t, err)
	root, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	pool := x509.NewCertPool()
	pool.AddCert(root)
	return &mintTestCA{root: root, key: key, pool: pool}
}

func (ca *mintTestCA) certificate(t *testing.T, peers []string, configure ...func(*x509.Certificate)) *tls.Certificate {
	t.Helper()
	public, key, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber: serial,
		NotBefore:    time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}
	for _, peer := range peers {
		identity, parseErr := url.Parse(peer)
		require.NoError(t, parseErr)
		template.URIs = append(template.URIs, identity)
	}
	for _, option := range configure {
		option(template)
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca.root, public, ca.key)
	require.NoError(t, err)
	leaf, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}
}

func newMintTLSServer(t *testing.T, handler http.Handler, ca *mintTestCA, configure ...func(*tls.Config)) *httptest.Server {
	t.Helper()
	server := &httptest.Server{Listener: newMintMemoryListener(t), Config: &http.Server{Handler: handler}}
	server.EnableHTTP2 = true // The client must still use a dedicated HTTP/1.1 connection.
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.TLS = &tls.Config{
		MinVersion:   tls.VersionTLS13,
		NextProtos:   []string{"h2", "http/1.1"},
		Certificates: []tls.Certificate{*ca.certificate(t, []string{testMintPeer})},
		ClientCAs:    ca.pool, ClientAuth: tls.RequireAndVerifyClientCert,
	}
	for _, option := range configure {
		option(server.TLS)
	}
	server.StartTLS()
	t.Cleanup(server.Close)
	return server
}

type mintArrival struct {
	authorization string
	remote        string
	close         bool
	protocol      int
	encoding      string
	tls           tls.ConnectionState
}

func requireNoMintDisclosure(t *testing.T, host *mintHost, requests uint64) {
	t.Helper()
	require.Equal(t, requests, host.requests.Load(), "a refused handshake must deliver no HTTP request")
	require.Empty(t, host.arrivals, "the server captured an unexpected authorization header")
	if requests == 0 {
		require.Nil(t, host.presented.Load(), "the projected bearer must never reach the server")
		require.Empty(t, host.bodies, "no request body may reach the server")
	}
}

func requireMintRetryable(t *testing.T, client *MintClient, err error) {
	t.Helper()
	require.ErrorIs(t, err, ErrMintUnavailable)
	require.NotErrorIs(t, err, ErrMintRefused)
	require.NoError(t, client.Refused(), "transport admission failures must not latch")
}

func TestMintPeerAdmissionPrecedesAnyHTTPDisclosure(t *testing.T) {
	for name, identities := range map[string][]string{
		"same root, different workload": {"spiffe://test.example/workload/other"},
		"path case is significant":      {"spiffe://test.example/mint/Issuer"},
		"no URI SAN":                    nil,
		"non SPIFFE URI SAN":            {"https://test.example/mint/issuer"},
	} {
		t.Run(name, func(t *testing.T) {
			host := newMintHost(t, func() time.Time { return testClock })
			certificate := host.tlsCA.certificate(t, identities)
			_, err := certificate.Leaf.Verify(x509.VerifyOptions{Roots: host.tlsCA.pool, DNSName: "127.0.0.1"})
			require.NoError(t, err, "the anchor and hostname must verify so only admission can refuse this peer")
			config := host.tlsConfig.Load().Clone()
			config.Certificates = []tls.Certificate{*certificate}
			host.tlsConfig.Store(config)
			client := newTestMintClient(t, host, projectedFile(t, "secret-projection"), host.now)

			_, err = client.Credential(t.Context())
			requireNoMintDisclosure(t, host, 0)
			requireMintRetryable(t, client, err)
			require.ErrorIs(t, err, ErrMintPeerNotAdmitted)
		})
	}
}

func TestMintPeerWithdrawalAppliesToTheNextMint(t *testing.T) {
	clock := &movableClock{at: testClock}
	host := newMintHost(t, clock.now)
	var peers atomic.Value
	peers.Store([]string{testMintPeer})
	client := newTestMintClient(t, host, projectedFile(t, "secret-projection"), clock.now, func(options *MintOptions) {
		options.AdmittedPeers = func() ([]string, error) { return peers.Load().([]string), nil }
	})
	first, err := client.Credential(t.Context())
	require.NoError(t, err)
	arrival := <-host.arrivals
	require.Equal(t, "Bearer secret-projection", arrival.authorization)

	// The chain still verifies against the same anchor. Only admission changes.
	peers.Store([]string{"spiffe://test.example/mint/replacement"})
	clock.set(first.ExpiresAt().Add(time.Second))
	_, err = client.Credential(t.Context())
	requireNoMintDisclosure(t, host, 1)
	requireMintRetryable(t, client, err)
	require.ErrorIs(t, err, ErrMintPeerNotAdmitted)

	peers.Store([]string{testMintPeer})
	clock.set(clock.now().Add(2 * time.Second))
	_, err = client.Credential(t.Context())
	require.NoError(t, err, "re-admission must recover after backoff")
	require.EqualValues(t, 2, host.requests.Load())
	require.NotEqual(t, arrival.remote, (<-host.arrivals).remote)
}

func TestMintAnchorRotationAppliesToTheNextMint(t *testing.T) {
	clock := &movableClock{at: testClock}
	host := newMintHost(t, clock.now)
	var roots atomic.Pointer[x509.CertPool]
	roots.Store(host.tlsCA.pool)
	var reads atomic.Uint64
	client := newTestMintClient(t, host, projectedFile(t, "secret-projection"), clock.now, func(options *MintOptions) {
		options.TrustAnchor = func() (*x509.CertPool, error) { reads.Add(1); return roots.Load(), nil }
	})
	require.Zero(t, reads.Load(), "construction must not pin the anchor")
	first, err := client.Credential(t.Context())
	require.NoError(t, err)
	<-host.arrivals

	newCA := newMintTestCA(t)
	roots.Store(newCA.pool)
	clock.set(first.ExpiresAt().Add(time.Second))
	_, err = client.Credential(t.Context())
	requireNoMintDisclosure(t, host, 1)
	requireMintRetryable(t, client, err)
	require.ErrorContains(t, err, "certificate did not verify")
	require.NotErrorIs(t, err, ErrMintPeerNotAdmitted, "chain verification precedes admission")

	// The URL and admitted identity stay fixed; the endpoint switches roots.
	config := host.tlsConfig.Load().Clone()
	config.Certificates = []tls.Certificate{*newCA.certificate(t, []string{testMintPeer})}
	host.tlsConfig.Store(config)
	clock.set(clock.now().Add(2 * time.Second))
	_, err = client.Credential(t.Context())
	require.NoError(t, err)
	require.EqualValues(t, 2, host.requests.Load())
	require.EqualValues(t, 3, reads.Load(), "each attempt must read the current anchor")
}

func TestMintTransportSourcesFailClosedAndRecover(t *testing.T) {
	fault := errors.New("transport projection unreadable")
	for _, source := range []string{
		"anchor unreadable", "anchor nil", "peers unreadable", "peers empty", "peers malformed",
		"client certificate unreadable", "client certificate nil", "client certificate empty", "client key missing",
	} {
		t.Run(source, func(t *testing.T) {
			clock := &movableClock{at: testClock}
			host := newMintHost(t, clock.now)
			var failing atomic.Bool
			client := newTestMintClient(t, host, projectedFile(t, "secret-projection"), clock.now, func(options *MintOptions) {
				options.TrustAnchor = func() (*x509.CertPool, error) {
					if failing.Load() {
						switch source {
						case "anchor unreadable":
							return nil, fault
						case "anchor nil":
							return nil, nil
						}
					}
					return host.tlsCA.pool, nil
				}
				options.AdmittedPeers = func() ([]string, error) {
					if failing.Load() {
						switch source {
						case "peers unreadable":
							return nil, fault
						case "peers empty":
							return nil, nil
						case "peers malformed":
							return []string{testMintPeer, "https://test.example/mint/issuer"}, nil
						}
					}
					return testMintPeers()
				}
				options.ClientCertificate = func() (*tls.Certificate, error) {
					if failing.Load() {
						switch source {
						case "client certificate unreadable":
							return nil, fault
						case "client certificate nil":
							return nil, nil
						case "client certificate empty":
							return &tls.Certificate{}, nil
						case "client key missing":
							return &tls.Certificate{Certificate: host.clientCertificate.Certificate}, nil
						}
					}
					return host.clientCertificate, nil
				}
			})
			failing.Store(true)
			_, err := client.Credential(t.Context())
			requireNoMintDisclosure(t, host, 0)
			requireMintRetryable(t, client, err)
			if source == "anchor nil" {
				require.ErrorContains(t, err, "mint trust anchor is nil", "a nil anchor must not attempt system-root verification")
			}
			if source == "anchor unreadable" || source == "peers unreadable" || source == "client certificate unreadable" {
				require.ErrorIs(t, err, fault, "retain the source error in the retryable chain")
			}

			failing.Store(false)
			clock.set(clock.now().Add(2 * time.Second))
			_, err = client.Credential(t.Context())
			require.NoError(t, err)
			require.EqualValues(t, 1, host.requests.Load())
			require.Equal(t, "Bearer secret-projection", (<-host.arrivals).authorization)
		})
	}
}

func TestMintPresentsTheCurrentClientCertificateWithoutConnectionReuse(t *testing.T) {
	clock := &movableClock{at: testClock}
	host := newMintHost(t, clock.now)
	var certificate atomic.Pointer[tls.Certificate]
	certificate.Store(host.clientCertificate)
	var reads atomic.Uint64
	client := newTestMintClient(t, host, projectedFile(t, "secret-projection"), clock.now, func(options *MintOptions) {
		options.ClientCertificate = func() (*tls.Certificate, error) { reads.Add(1); return certificate.Load(), nil }
	})
	first, err := client.Credential(t.Context())
	require.NoError(t, err)
	arrival := <-host.arrivals
	require.Equal(t, host.clientCertificate.Certificate[0], arrival.tls.PeerCertificates[0].Raw)
	require.NotEmpty(t, arrival.tls.VerifiedChains, "the server requires and verifies the client certificate")

	replacement := host.tlsCA.certificate(t, []string{testMintClientPeer})
	certificate.Store(replacement)
	clock.set(first.ExpiresAt().Add(-time.Minute))
	second, err := client.Credential(t.Context())
	require.NoError(t, err)
	renewal := <-host.arrivals
	require.Equal(t, replacement.Certificate[0], renewal.tls.PeerCertificates[0].Raw)
	require.NotEqual(t, arrival.remote, renewal.remote, "renewal must establish a new connection")
	clock.set(clock.now().Add(time.Second))
	_, err = client.Refresh(t.Context(), second)
	require.NoError(t, err)
	refresh := <-host.arrivals
	require.NotEqual(t, renewal.remote, refresh.remote, "refresh must establish a new connection")
	require.EqualValues(t, 3, reads.Load(), "client identity is read at every handshake")
	for _, request := range []mintArrival{arrival, renewal, refresh} {
		require.True(t, request.close, "Connection: close makes mint requests non-reusable")
		require.Equal(t, 1, request.protocol, "HTTP/2 multiplexing is disabled")
		require.Empty(t, request.encoding, "the mint client disables compression")
		require.EqualValues(t, tls.VersionTLS13, request.tls.Version)
		require.False(t, request.tls.DidResume, "every connection verifies the full chain")
	}
}

func TestMintCanonicalSPIFFEAdmission(t *testing.T) {
	for _, spelling := range []struct{ leaf, admitted string }{
		{testMintPeer, "SPIFFE://TEST.Example//mint///issuer/"},
		{"SPIFFE://TEST.Example//mint///issuer/", testMintPeer},
		{"spiffe://Test.Example/mint//issuer/", "SpIfFe://TEST.EXAMPLE//mint/issuer///"},
	} {
		t.Run(spelling.leaf+" against "+spelling.admitted, func(t *testing.T) {
			host := newMintHost(t, func() time.Time { return testClock })
			config := host.tlsConfig.Load().Clone()
			config.Certificates = []tls.Certificate{*host.tlsCA.certificate(t, []string{spelling.leaf})}
			host.tlsConfig.Store(config)
			client := newTestMintClient(t, host, projectedFile(t, "projected"), host.now, func(options *MintOptions) {
				options.AdmittedPeers = func() ([]string, error) { return []string{spelling.admitted}, nil }
			})
			_, err := client.Credential(t.Context())
			require.NoError(t, err)
			require.Equal(t, "Bearer projected", (<-host.arrivals).authorization)
		})
	}
}

func TestMintRejectsMalformedAdmittedIdentitiesAtConstruction(t *testing.T) {
	host := newMintHost(t, func() time.Time { return testClock })
	valid := newTestMintClient(t, host, projectedFile(t, "projected"), host.now).options
	for _, identity := range []string{
		"", "https://test.example/mint/issuer", "spiffe:test.example/mint", "/mint/issuer",
		"spiffe:///mint", "spiffe://test.example", "spiffe://test.example///",
		"spiffe://user@test.example/mint", "spiffe://test.example:443/mint",
		"spiffe://test.example/mint?query", "spiffe://test.example/mint?",
		"spiffe://test.example/mint#fragment", "spiffe://test.example/mint#",
		"spiffe://test.example/mint/%69ssuer", "spiffe://test.example/mint/../issuer",
		"spiffe://test.example/mint/./issuer", "spiffe://test.example/mint/%2Fissuer",
		"spiffe://test.example/mint/issuer ", "spiffe://test.example/mint\\issuer",
		"spiffe://test.example/mint/%zz", "spiffe://[::1]/mint",
	} {
		t.Run(identity, func(t *testing.T) {
			options := valid
			options.AdmittedPeers = func() ([]string, error) { return []string{testMintPeer, identity}, nil }
			_, err := NewMintClient(options)
			require.ErrorIs(t, err, ErrInvalid, "one valid entry must not hide a malformed one")
			require.NotErrorIs(t, err, ErrMintRefused)
		})
	}
	requireNoMintDisclosure(t, host, 0)
}

func TestMintUnavailablePeersAtConstructionAreRetriedAtTheHandshake(t *testing.T) {
	for _, fault := range []error{nil, errors.New("peer projection unreadable")} {
		t.Run("empty or unreadable", func(t *testing.T) {
			host := newMintHost(t, func() time.Time { return testClock })
			var ready atomic.Bool
			client := newTestMintClient(t, host, projectedFile(t, "projected"), host.now, func(options *MintOptions) {
				options.AdmittedPeers = func() ([]string, error) {
					if !ready.Load() {
						return nil, fault
					}
					return testMintPeers()
				}
			})
			ready.Store(true)
			_, err := client.Credential(t.Context())
			require.NoError(t, err, "construction must not cache an unavailable projection")
		})
	}
}

func TestMintTransportKeepsTLSVerificationAndMutualAuthentication(t *testing.T) {
	for _, refusal := range []string{"TLS 1.2", "wrong hostname", "untrusted root", "no client certificate request"} {
		t.Run(refusal, func(t *testing.T) {
			host := newMintHost(t, func() time.Time { return testClock })
			config := host.tlsConfig.Load().Clone()
			switch refusal {
			case "TLS 1.2":
				config.MinVersion, config.MaxVersion = tls.VersionTLS12, tls.VersionTLS12
			case "wrong hostname":
				config.Certificates = []tls.Certificate{*host.tlsCA.certificate(t, []string{testMintPeer}, func(leaf *x509.Certificate) {
					leaf.IPAddresses = nil
					leaf.DNSNames = []string{"different.example"}
				})}
			case "untrusted root":
				config.Certificates = []tls.Certificate{*newMintTestCA(t).certificate(t, []string{testMintPeer})}
			case "no client certificate request":
				config.ClientAuth = tls.NoClientCert
			}
			host.tlsConfig.Store(config)
			var peerReads atomic.Uint64
			client := newTestMintClient(t, host, projectedFile(t, "projected"), host.now, func(options *MintOptions) {
				options.AdmittedPeers = func() ([]string, error) { peerReads.Add(1); return testMintPeers() }
			})
			_, err := client.Credential(t.Context())
			requireNoMintDisclosure(t, host, 0)
			requireMintRetryable(t, client, err)
			if refusal != "no client certificate request" {
				require.EqualValues(t, 1, peerReads.Load(), "only construction reads peers before chain verification succeeds")
			}
		})
	}
}
