package workcontext

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"runtime"
	"strings"
	"sync"
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

// ExtraExtensions signs the URI bytes verbatim. Parsing peers before signing
// would erase the trailing '#' that this fixture exists to exercise.
func mintRawSAN(t *testing.T, peers []string) func(*x509.Certificate) {
	t.Helper()
	names := []asn1.RawValue{
		{Class: asn1.ClassContextSpecific, Tag: 2, Bytes: []byte("mint.test.example")},
		{Class: asn1.ClassContextSpecific, Tag: 7, Bytes: []byte{127, 0, 0, 1}},
	}
	for _, peer := range peers {
		names = append(names, asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 6, Bytes: []byte(peer)})
	}
	der, err := asn1.Marshal(names)
	require.NoError(t, err)
	return func(leaf *x509.Certificate) {
		leaf.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 17}, Value: der}}
	}
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
		"same root, different workload":     {"spiffe://test.example/workload/other"},
		"path case is significant":          {"spiffe://test.example/mint/Issuer"},
		"no URI SAN":                        nil,
		"non SPIFFE URI SAN":                {"https://test.example/mint/issuer"},
		"empty first segment":               {"spiffe://test.example//mint/issuer"},
		"empty middle segment":              {"spiffe://test.example/mint//issuer"},
		"trailing slash":                    {testMintPeer + "/"},
		"empty segments and trailing slash": {"spiffe://test.example//mint/issuer/"},
		"dot segment":                       {"spiffe://test.example/mint/./issuer"},
		"parent segment":                    {"spiffe://test.example/mint/../issuer"},
		"escaped segment":                   {"spiffe://test.example/mint/%69ssuer"},
		"invalid trust domain":              {"spiffe://test+example/mint/issuer"},
		"multiple SPIFFE IDs":               {testMintPeer, "spiffe://test.example/workload/other"},
		"matching second SPIFFE ID":         {"spiffe://test.example/workload/other", testMintPeer},
		"duplicate SPIFFE IDs":              {testMintPeer, testMintPeer},
		"extra non SPIFFE URI":              {testMintPeer, "https://test.example/mint/issuer"},
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

func TestMintPeerLeafPurposePrecedesAnyHTTPDisclosure(t *testing.T) {
	for name, fixture := range map[string]struct {
		configure func(*x509.Certificate)
		accepted  bool
	}{
		"authentication leaf": {func(*x509.Certificate) {}, true},
		"explicit non CA": {func(leaf *x509.Certificate) {
			leaf.BasicConstraintsValid = true
		}, true},
		"EKU absent": {func(leaf *x509.Certificate) {
			leaf.ExtKeyUsage = nil
		}, true},
		"serverAuth only": {func(leaf *x509.Certificate) {
			leaf.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		}, true},
		"CA with certSign": {func(leaf *x509.Certificate) {
			leaf.BasicConstraintsValid, leaf.IsCA = true, true
			leaf.KeyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign
		}, false},
		"CA without certSign": {func(leaf *x509.Certificate) {
			leaf.BasicConstraintsValid, leaf.IsCA = true, true
		}, false},
		"non CA certSign": {func(leaf *x509.Certificate) {
			leaf.KeyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign
		}, false},
		"CRLSign only": {func(leaf *x509.Certificate) {
			leaf.KeyUsage = x509.KeyUsageCRLSign
		}, false},
		"digitalSignature with CRLSign": {func(leaf *x509.Certificate) {
			leaf.KeyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageCRLSign
		}, false},
		"no digitalSignature": {func(leaf *x509.Certificate) {
			leaf.KeyUsage = x509.KeyUsageKeyEncipherment
		}, false},
		"key usage absent": {func(leaf *x509.Certificate) {
			leaf.KeyUsage = 0
		}, false},
		// anyExtendedKeyUsage passes Go's ordinary server verification but
		// does not explicitly grant the serverAuth required on this hop.
		"EKU any without serverAuth": {func(leaf *x509.Certificate) {
			leaf.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageAny}
		}, false},
		// Presence is determined from Extensions: an empty EKU sequence has
		// no parsed usages, but it is not the same as an absent extension.
		"EKU present but empty": {func(leaf *x509.Certificate) {
			leaf.ExtraExtensions = append(leaf.ExtraExtensions, pkix.Extension{
				Id: asn1.ObjectIdentifier{2, 5, 29, 37}, Value: []byte{0x30, 0x00},
			})
		}, false},
	} {
		t.Run(name, func(t *testing.T) {
			host := newMintHost(t, func() time.Time { return testClock })
			certificate := host.tlsCA.certificate(t, nil, mintRawSAN(t, []string{testMintPeer}), fixture.configure)
			for _, hostname := range []string{"127.0.0.1", "mint.test.example"} {
				_, err := certificate.Leaf.Verify(x509.VerifyOptions{Roots: host.tlsCA.pool, DNSName: hostname})
				require.NoError(t, err, "ordinary chain, hostname and server-purpose verification must pass independently")
			}
			config := host.tlsConfig.Load().Clone()
			config.Certificates = []tls.Certificate{*certificate}
			host.tlsConfig.Store(config)
			var peerReads atomic.Uint64
			client := newTestMintClient(t, host, projectedFile(t, "secret-projection"), host.now, func(options *MintOptions) {
				options.AdmittedPeers = func() ([]string, error) { peerReads.Add(1); return testMintPeers() }
			})
			written := observeMintHTTPWrites(t, client)
			_, err := client.Credential(t.Context())
			if fixture.accepted {
				require.NoError(t, err)
				require.Positive(t, written.Load(), "the observer must see a successful mint's HTTP bytes")
				require.EqualValues(t, 1, host.requests.Load())
				require.Equal(t, "Bearer secret-projection", (<-host.arrivals).authorization)
				require.NotEmpty(t, <-host.bodies)
				return
			}
			require.Zero(t, written.Load(), "no request line, header or body may be written to TLS")
			requireNoMintDisclosure(t, host, 0)
			requireMintRetryable(t, client, err)
			require.ErrorIs(t, err, ErrMintPeerNotAdmitted)
			require.Zero(t, peerReads.Load(), "leaf purpose must be checked before consulting admission")
		})
	}
}

func TestMintRawURISANAdmission(t *testing.T) {
	for name, fixture := range map[string]struct {
		peers    []string
		accepted bool
	}{
		"valid":                  {[]string{testMintPeer}, true},
		"empty fragment":         {[]string{testMintPeer + "#"}, false},
		"fragment":               {[]string{testMintPeer + "#part"}, false},
		"empty query":            {[]string{testMintPeer + "?"}, false},
		"query":                  {[]string{testMintPeer + "?key=value"}, false},
		"percent escape":         {[]string{"spiffe://test.example/mint/%69ssuer"}, false},
		"no URI":                 {nil, false},
		"two identical URIs":     {[]string{testMintPeer, testMintPeer}, false},
		"valid beside lossy URI": {[]string{testMintPeer, testMintPeer + "#"}, false},
	} {
		t.Run(name, func(t *testing.T) {
			host := newMintHost(t, func() time.Time { return testClock })
			certificate := host.tlsCA.certificate(t, nil, mintRawSAN(t, fixture.peers))
			for _, hostname := range []string{"127.0.0.1", "mint.test.example"} {
				_, err := certificate.Leaf.Verify(x509.VerifyOptions{Roots: host.tlsCA.pool, DNSName: hostname})
				require.NoError(t, err, "the raw SAN fixture must verify independently of admission")
			}
			if name == "empty fragment" {
				require.Len(t, certificate.Leaf.URIs, 1)
				require.Equal(t, testMintPeer, certificate.Leaf.URIs[0].String(), "prove x509 lost the forbidden delimiter")
			}
			config := host.tlsConfig.Load().Clone()
			config.Certificates = []tls.Certificate{*certificate}
			host.tlsConfig.Store(config)
			client := newTestMintClient(t, host, projectedFile(t, "secret-projection"), host.now)
			_, err := client.Credential(t.Context())
			if fixture.accepted {
				require.NoError(t, err)
				require.Equal(t, "Bearer secret-projection", (<-host.arrivals).authorization)
				return
			}
			requireNoMintDisclosure(t, host, 0)
			requireMintRetryable(t, client, err)
			require.ErrorIs(t, err, ErrMintPeerNotAdmitted)
		})
	}
}

func TestMintRawSANRequiresCompleteGeneralNames(t *testing.T) {
	validURI := asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 6, Bytes: []byte(testMintPeer)}
	valid, err := asn1.Marshal([]asn1.RawValue{validURI})
	require.NoError(t, err)
	compoundURI := validURI
	compoundURI.IsCompound = true
	compound, err := asn1.Marshal([]asn1.RawValue{compoundURI})
	require.NoError(t, err)
	wrongClassURI := validURI
	wrongClassURI.Class = asn1.ClassApplication
	wrongClass, err := asn1.Marshal([]asn1.RawValue{wrongClassURI})
	require.NoError(t, err)
	for name, raw := range map[string][]byte{
		"truncated sequence": valid[:len(valid)-1],
		"trailing data":      append(append([]byte{}, valid...), 0),
		"compound URI":       compound,
		"wrong class":        wrongClass,
	} {
		t.Run(name, func(t *testing.T) {
			state := tls.ConnectionState{PeerCertificates: []*x509.Certificate{{
				Extensions: []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 17}, Value: raw}},
			}}}
			_, ok := mintPeerURI(state)
			require.False(t, ok, "only a complete GeneralNames sequence with one primitive URI supplies an identity")
		})
	}
	_, ok := mintPeerURI(tls.ConnectionState{})
	require.False(t, ok)
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
	require.EqualValues(t, 5, reads.Load(), "successful handshakes re-read the anchor; the rejected handshake reads it once")
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
		{testMintPeer, "SPIFFE://TEST.Example/mint/issuer"},
		{"SPIFFE://TEST.Example/mint/issuer", testMintPeer},
		{"spiffe://Test.Example/mint/issuer", "SpIfFe://TEST.EXAMPLE/mint/issuer"},
		{"spiffe://test_domain.example/mint/issuer", "SPIFFE://TEST_DOMAIN.EXAMPLE/mint/issuer"},
		{"SPIFFE://TEST_DOMAIN.EXAMPLE/mint/issuer", "spiffe://test_domain.example/mint/issuer"},
		{"spiffe://test_example/mint/issuer", "spiffe://test_example/mint/issuer"},
		{"spiffe://example.org/workload", "spiffe://example.org/workload"},
		{"spiffe://example.com/workload", "spiffe://example.com/workload"},
		{"spiffe://prod-1.example/work_load.v2", "spiffe://prod-1.example/work_load.v2"},
	} {
		t.Run(spelling.leaf+" against "+spelling.admitted, func(t *testing.T) {
			clock := &movableClock{at: testClock}
			host := newMintHost(t, clock.now)
			config := host.tlsConfig.Load().Clone()
			config.Certificates = []tls.Certificate{*host.tlsCA.certificate(t, nil, mintRawSAN(t, []string{spelling.leaf}))}
			host.tlsConfig.Store(config)
			var admitted atomic.Value
			// Appending a valid path character changes the identity without
			// invoking malformed-ID rejection instead of membership checking.
			admitted.Store(spelling.admitted + "_other")
			client := newTestMintClient(t, host, projectedFile(t, "projected"), host.now, func(options *MintOptions) {
				options.AdmittedPeers = func() ([]string, error) { return []string{admitted.Load().(string)}, nil }
			})
			_, err := client.Credential(t.Context())
			requireNoMintDisclosure(t, host, 0)
			requireMintRetryable(t, client, err)
			require.ErrorIs(t, err, ErrMintPeerNotAdmitted)

			admitted.Store(spelling.admitted)
			clock.set(clock.now().Add(2 * time.Second))
			_, err = client.Credential(t.Context())
			require.NoError(t, err)
			require.Equal(t, "Bearer projected", (<-host.arrivals).authorization)
		})
	}
}

func TestMintRejectsMalformedAdmittedIdentitiesAtHandshake(t *testing.T) {
	for _, identity := range []string{
		"", "https://test.example/mint/issuer", "spiffe:test.example/mint", "/mint/issuer",
		"spiffe:///mint", "spiffe://test.example", "spiffe://test.example///",
		"spiffe://test.example//mint/issuer", "spiffe://test.example/mint//issuer", testMintPeer + "/",
		"spiffe://test+example/mint/issuer", "spiffe://test.K/mint/issuer",
		"spiffe://.test.example/mint/issuer", "spiffe://test..example/mint/issuer", "spiffe://test.example./mint/issuer",
		"spiffe://" + strings.Repeat("a", 256) + "/mint/issuer",
		"spiffe://user@test.example/mint", "spiffe://test.example:443/mint",
		"spiffe://test.example/mint?query", "spiffe://test.example/mint?",
		"spiffe://test.example/mint#fragment", "spiffe://test.example/mint#",
		"spiffe://test.example/mint/%69ssuer", "spiffe://test.example/mint/../issuer",
		"spiffe://test.example/mint/./issuer", "spiffe://test.example/mint/%2Fissuer",
		"spiffe://test.example/mint/issuer ", "spiffe://test.example/mint\\issuer",
		"spiffe://test.example/mint/%zz", "spiffe://[::1]/mint",
	} {
		t.Run(identity, func(t *testing.T) {
			host := newMintHost(t, func() time.Time { return testClock })
			client := newTestMintClient(t, host, projectedFile(t, "projected"), host.now, func(options *MintOptions) {
				options.AdmittedPeers = func() ([]string, error) { return []string{testMintPeer, identity}, nil }
			})
			_, err := client.Credential(t.Context())
			require.ErrorIs(t, err, ErrInvalid, "one valid entry must not hide a malformed one")
			requireMintRetryable(t, client, err)
			requireNoMintDisclosure(t, host, 0)
		})
	}
}

func TestMintUnavailablePeersAtConstructionAreRetriedAtTheHandshake(t *testing.T) {
	for name, fault := range map[string]error{"empty": nil, "unreadable": errors.New("peer projection unreadable")} {
		t.Run(name, func(t *testing.T) {
			clock := &movableClock{at: testClock}
			host := newMintHost(t, clock.now)
			var ready atomic.Bool
			var reads atomic.Uint64
			client := newTestMintClient(t, host, projectedFile(t, "projected"), host.now, func(options *MintOptions) {
				options.AdmittedPeers = func() ([]string, error) {
					reads.Add(1)
					if !ready.Load() {
						return nil, fault
					}
					return testMintPeers()
				}
			})
			require.Zero(t, reads.Load(), "construction must not read an unavailable source")
			_, err := client.Credential(t.Context())
			requireNoMintDisclosure(t, host, 0)
			requireMintRetryable(t, client, err)
			require.EqualValues(t, 1, reads.Load(), "the first mint must actually read the unavailable source")
			if fault != nil {
				require.ErrorIs(t, err, fault)
			} else {
				require.ErrorContains(t, err, "no admitted mint peers")
			}

			ready.Store(true)
			clock.set(clock.now().Add(2 * time.Second))
			_, err = client.Credential(t.Context())
			require.NoError(t, err, "construction must not cache an unavailable projection")
			require.EqualValues(t, 3, reads.Load(), "recovery re-reads peers at both admission passes")
			require.EqualValues(t, 1, host.requests.Load())
			require.Equal(t, "Bearer projected", (<-host.arrivals).authorization)
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
				require.Zero(t, peerReads.Load(), "peers must not be read before chain verification succeeds")
			}
		})
	}
}

func TestNewMintClientReadsNoSources(t *testing.T) {
	host := newMintHost(t, func() time.Time { return testClock })
	options := newTestMintClient(t, host, projectedFile(t, "projected"), host.now).options
	release := make(chan struct{})
	defer close(release)
	var reads atomic.Uint64
	block := func() { reads.Add(1); <-release }
	options.TrustAnchor = func() (*x509.CertPool, error) { block(); return host.tlsCA.pool, nil }
	options.ClientCertificate = func() (*tls.Certificate, error) { block(); return host.clientCertificate, nil }
	options.AdmittedPeers = func() ([]string, error) { block(); return testMintPeers() }
	done := make(chan error, 1)
	go func() { _, err := NewMintClient(options); done <- err }()
	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(time.Second):
		t.Fatal("construction blocked on a source")
	}
	require.Zero(t, reads.Load(), "construction must not even start a source read")
	requireNoMintDisclosure(t, host, 0)
}

// Preserve httptest's connection bookkeeping while observing server-side closes.
func mintConnectionClosures(host *mintHost) <-chan net.Conn {
	closed := make(chan net.Conn, 16)
	previous := host.server.Config.ConnState
	host.server.Config.ConnState = func(connection net.Conn, state http.ConnState) {
		if previous != nil {
			previous(connection, state)
		}
		if state == http.StateClosed {
			closed <- connection
		}
	}
	return closed
}

func mintGoroutineStackContains(function string) bool {
	stack := make([]byte, 1024*1024)
	n := runtime.Stack(stack, true)
	return strings.Contains(string(stack[:n]), function)
}

// A source can return an arbitrary signer. Public works in the Sign case, so
// the stall happens in TLS 1.3's actual CertificateVerify signing operation.
type mintBlockingSigner struct {
	crypto.Signer
	block func(string)
}

func (s mintBlockingSigner) Public() crypto.PublicKey {
	s.block("signer Public")
	return s.Signer.Public()
}

func (s mintBlockingSigner) Sign(random io.Reader, digest []byte, options crypto.SignerOpts) ([]byte, error) {
	s.block("signer Sign")
	return s.Signer.Sign(random, digest, options)
}

func TestMintTransportSourceReadsAreBoundedAndRecover(t *testing.T) {
	for _, stage := range []string{"anchor", "peers", "certificate", "signer Public", "signer Sign", "post-handshake anchor", "post-handshake peers"} {
		t.Run(stage, func(t *testing.T) {
			source := strings.TrimPrefix(stage, "post-handshake ")
			blockAt := uint64(1)
			if source != stage {
				blockAt = 2
			}
			var sourceReads atomic.Uint64
			clock := &movableClock{at: testClock}
			host := newMintHost(t, clock.now)
			certificate := *host.clientCertificate
			key, ok := certificate.PrivateKey.(crypto.Signer)
			require.True(t, ok)
			closed := mintConnectionClosures(host)
			entered := make(chan struct{}, 16)
			release := make(chan struct{})
			var once sync.Once
			unblock := func() { once.Do(func() { close(release) }) }
			defer unblock()
			var blocking atomic.Bool
			blocking.Store(true)
			var reads atomic.Uint64
			read := func(name string) {
				reads.Add(1)
				if name == source && sourceReads.Add(1) >= blockAt && blocking.Load() {
					entered <- struct{}{}
					<-release
				}
			}
			certificate.PrivateKey = mintBlockingSigner{Signer: key, block: read}
			const timeout = 500 * time.Millisecond
			client := newTestMintClient(t, host, projectedFile(t, "secret-projection"), clock.now, func(options *MintOptions) {
				options.RequestTimeout = timeout
				options.TrustAnchor = func() (*x509.CertPool, error) { read("anchor"); return host.tlsCA.pool, nil }
				options.AdmittedPeers = func() ([]string, error) { read("peers"); return testMintPeers() }
				options.ClientCertificate = func() (*tls.Certificate, error) { read("certificate"); return &certificate, nil }
			})
			transport, ok := client.httpClient.Transport.(*http.Transport)
			require.True(t, ok)
			var dialAttempts atomic.Uint64
			transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
				if dialAttempts.Add(1) > 1 && blocking.Load() {
					// A retry reaching an unreachable endpoint consumes the
					// budget unless the occupied slot is checked before dialing.
					<-ctx.Done()
					return nil, ctx.Err()
				}
				return dialMintMemory(ctx, network, address)
			}
			done := make(chan error, 1)
			started := time.Now()
			go func() { _, err := client.Credential(t.Context()); done <- err }()
			select {
			case <-entered:
			case <-time.After(2 * time.Second):
				t.Fatal("the handshake never reached the blocked source")
			}
			initialReads := reads.Load()
			refuseAttempt := func() {
				t.Helper()
				began := time.Now()
				// Exercise a separate transport attempt while Credential's
				// detached single-flight request may still be waiting.
				_, err := client.mintOnce(t.Context())
				require.EqualValues(t, 1, dialAttempts.Load(), "an occupied slot must refuse without any connection attempt")
				requireMintRetryable(t, client, err)
				require.ErrorContains(t, err, "source read is still outstanding")
				require.Less(t, time.Since(began), timeout/2, "a second attempt must refuse immediately")
				require.Equal(t, initialReads, reads.Load(), "all sources share one outstanding read slot")
			}
			refuseAttempt()
			select {
			case err := <-done:
				requireMintRetryable(t, client, err)
				require.ErrorIs(t, err, context.DeadlineExceeded)
			case <-time.After(timeout + 250*time.Millisecond):
				t.Fatal("the request outlived its deadline while a source was blocked")
			}
			require.Less(t, time.Since(started), timeout+250*time.Millisecond)
			// Only the first attempt connected. Every opened raw connection
			// must still close before the blocked worker is released.
			for range dialAttempts.Load() {
				select {
				case <-closed:
				case <-time.After(250 * time.Millisecond):
					t.Fatal("the server did not see the raw connection close before the source was released")
				}
			}
			require.Eventually(t, func() bool {
				return !mintGoroutineStackContains(".mintHTTPClient.func")
			}, 250*time.Millisecond, time.Millisecond, "the dial goroutine must exit while the source is still blocked")
			for range 3 {
				refuseAttempt()
			}
			requireNoMintDisclosure(t, host, 0)
			blocking.Store(false)
			unblock()
			require.Eventually(t, func() bool {
				return !mintGoroutineStackContains(".readMintSource[")
			}, time.Second, time.Millisecond, "no source worker may survive release")
			clock.set(clock.now().Add(2 * time.Second))
			_, err := client.Credential(t.Context())
			require.NoError(t, err, "a later attempt must read fresh sources and recover")
			require.EqualValues(t, 2, dialAttempts.Load(), "recovery must dial again after the worker releases its slot")
			require.Greater(t, reads.Load(), initialReads)
			require.EqualValues(t, 1, host.requests.Load())
			require.Equal(t, "Bearer secret-projection", (<-host.arrivals).authorization)
		})
	}
}

func TestMintWithdrawalDuringHandshakePreventsHTTPDisclosure(t *testing.T) {
	for _, withdrawal := range []string{"peers", "anchor"} {
		t.Run(withdrawal, func(t *testing.T) {
			clock := &movableClock{at: testClock}
			host := newMintHost(t, clock.now)
			closed := mintConnectionClosures(host)
			replacement := newMintTestCA(t)
			var roots atomic.Pointer[x509.CertPool]
			roots.Store(host.tlsCA.pool)
			var peers atomic.Value
			peers.Store([]string{testMintPeer})
			var anchorReads, peerReads atomic.Uint64
			entered, release := make(chan struct{}), make(chan struct{})
			var once sync.Once
			unblock := func() { once.Do(func() { close(release) }) }
			defer unblock()
			var withdraw atomic.Bool
			withdraw.Store(true)
			client := newTestMintClient(t, host, projectedFile(t, "secret-projection"), clock.now, func(options *MintOptions) {
				options.TrustAnchor = func() (*x509.CertPool, error) { anchorReads.Add(1); return roots.Load(), nil }
				options.AdmittedPeers = func() ([]string, error) { peerReads.Add(1); return peers.Load().([]string), nil }
				options.ClientCertificate = func() (*tls.Certificate, error) {
					if withdraw.CompareAndSwap(true, false) {
						close(entered)
						<-release
						if withdrawal == "peers" {
							peers.Store([]string{"spiffe://test.example/mint/replacement"})
						} else {
							roots.Store(replacement.pool)
						}
					}
					return host.clientCertificate, nil
				}
			})
			done := make(chan error, 1)
			go func() { _, err := client.Credential(t.Context()); done <- err }()
			select {
			case <-entered:
			case <-time.After(time.Second):
				t.Fatal("the handshake never reached the client-certificate barrier")
			}
			require.EqualValues(t, 1, anchorReads.Load())
			require.EqualValues(t, 1, peerReads.Load(), "initial admission must precede the withdrawal")
			requireNoMintDisclosure(t, host, 0)
			unblock()
			select {
			case err := <-done:
				requireMintRetryable(t, client, err)
				if withdrawal == "peers" {
					require.ErrorIs(t, err, ErrMintPeerNotAdmitted)
				} else {
					require.ErrorContains(t, err, "certificate did not verify")
					require.NotErrorIs(t, err, ErrMintPeerNotAdmitted)
				}
			case <-time.After(time.Second):
				t.Fatal("post-handshake withdrawal did not finish")
			}
			select {
			case <-closed:
			case <-time.After(time.Second):
				t.Fatal("the refused connection was not closed")
			}
			requireNoMintDisclosure(t, host, 0)
			roots.Store(host.tlsCA.pool)
			peers.Store([]string{testMintPeer})
			clock.set(clock.now().Add(2 * time.Second))
			_, err := client.Credential(t.Context())
			require.NoError(t, err)
			require.Equal(t, "Bearer secret-projection", (<-host.arrivals).authorization)
		})
	}
}

func TestMintTransportSourcesHonorTheRequestContext(t *testing.T) {
	for _, cancellation := range []string{"deadline", "cancel"} {
		t.Run(cancellation, func(t *testing.T) {
			host := newMintHost(t, func() time.Time { return testClock })
			closed := mintConnectionClosures(host)
			entered, release := make(chan struct{}), make(chan struct{})
			defer close(release)
			client := newTestMintClient(t, host, projectedFile(t, "projected"), host.now, func(options *MintOptions) {
				options.RequestTimeout = 5 * time.Second
				options.TrustAnchor = func() (*x509.CertPool, error) {
					close(entered)
					<-release
					return host.tlsCA.pool, nil
				}
			})
			// The request has less time left than the dialer's configured cap.
			ctx, cancel := context.WithTimeout(t.Context(), 500*time.Millisecond)
			defer cancel()
			done := make(chan error, 1)
			go func() { _, err := client.mintOnce(ctx); done <- err }()
			select {
			case <-entered:
			case <-time.After(time.Second):
				t.Fatal("the anchor read never started")
			}
			expected := context.DeadlineExceeded
			if cancellation == "cancel" {
				expected = context.Canceled
				cancel()
			}
			select {
			case err := <-done:
				requireMintRetryable(t, client, err)
				require.ErrorIs(t, err, expected)
			case <-time.After(time.Second):
				t.Fatal("the mint ignored request cancellation")
			}
			select {
			case <-closed:
			case <-time.After(250 * time.Millisecond):
				t.Fatal("the detached HTTP dial retained its raw connection after request cancellation")
			}
			requireNoMintDisclosure(t, host, 0)
		})
	}
}

func TestMintTransportSlotIsReleasedOnlyByItsWorker(t *testing.T) {
	var reading atomic.Bool
	var calls atomic.Uint64
	for range 2 {
		entered, release, finished := make(chan struct{}), make(chan struct{}), make(chan struct{})
		var once sync.Once
		unblock := func() { once.Do(func() { close(release) }) }
		t.Cleanup(unblock)
		ctx, cancel := context.WithCancel(t.Context())
		done := make(chan error, 1)
		go func() {
			_, err := readMintSource(ctx, &reading, func() (int, error) {
				calls.Add(1)
				close(entered)
				<-release
				close(finished)
				return 1, nil
			})
			done <- err
		}()
		select {
		case <-entered:
		case <-time.After(time.Second):
			t.Fatal("the released slot was not available to the next worker")
		}
		cancel()
		select {
		case err := <-done:
			require.ErrorIs(t, err, context.Canceled)
		case <-time.After(time.Second):
			t.Fatal("cancellation did not bound the wait")
		}
		require.True(t, reading.Load(), "the canceled waiter must not release its live worker's slot")
		before := calls.Load()
		_, err := readMintSource(t.Context(), &reading, func() (int, error) { calls.Add(1); return 2, nil })
		require.ErrorIs(t, err, ErrMintUnavailable)
		require.Equal(t, before, calls.Load(), "only one callback may run, including after a previous slot release")
		unblock()
		select {
		case <-finished:
		case <-time.After(time.Second):
			t.Fatal("the released callback did not return")
		}
		require.Eventually(t, func() bool { return !reading.Load() }, time.Second, time.Millisecond,
			"the worker must release its slot exactly once after returning")
	}
	require.EqualValues(t, 2, calls.Load())
}

func TestMintSourceValueDiscardsCanceledReads(t *testing.T) {
	for _, cancellation := range []string{"before", "during"} {
		t.Run(cancellation, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			if cancellation == "before" {
				cancel()
			}
			calls := 0
			value, err := mintSourceValue(ctx, func() (string, error) {
				calls++
				cancel()
				return "late projection", nil
			})
			require.ErrorIs(t, err, context.Canceled)
			require.Empty(t, value, "late projections must not reach TLS signing or another source")
			if cancellation == "before" {
				require.Zero(t, calls, "a canceled worker must not start another source")
			} else {
				require.Equal(t, 1, calls)
			}
		})
	}
}

// This exercises the documented consistency limit, not an atomic-snapshot
// guarantee: an anchor may be withdrawn while the later peer read is waiting.
func TestMintSourceFreshnessWindowIncludesLaterCallbacks(t *testing.T) {
	clock := &movableClock{at: testClock}
	host := newMintHost(t, clock.now)
	var roots atomic.Pointer[x509.CertPool]
	roots.Store(host.tlsCA.pool)
	var anchorReads, peerReads atomic.Uint64
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	defer unblock()
	client := newTestMintClient(t, host, projectedFile(t, "projected"), clock.now, func(options *MintOptions) {
		options.TrustAnchor = func() (*x509.CertPool, error) { anchorReads.Add(1); return roots.Load(), nil }
		options.AdmittedPeers = func() ([]string, error) {
			if peerReads.Add(1) == 2 {
				close(entered)
				<-release
			}
			return testMintPeers()
		}
	})
	done := make(chan error, 1)
	go func() { _, err := client.mintOnce(t.Context()); done <- err }()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("the second peer read did not start")
	}
	require.EqualValues(t, 2, anchorReads.Load(), "the second anchor has already been sampled")
	requireNoMintDisclosure(t, host, 0)
	roots.Store(newMintTestCA(t).pool)
	unblock()
	select {
	case err := <-done:
		require.NoError(t, err, "independent sources cannot observe a withdrawal after their own sampling")
	case <-time.After(time.Second):
		t.Fatal("the peer read did not finish")
	}
	require.Equal(t, "Bearer projected", (<-host.arrivals).authorization)
	_, err := client.mintOnce(t.Context())
	requireMintRetryable(t, client, err)
	require.ErrorContains(t, err, "certificate did not verify")
	requireNoMintDisclosure(t, host, 1)
}
