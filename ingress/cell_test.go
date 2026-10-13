package ingress

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"github.com/codefly-dev/sdk-go/workload"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The fixtures below are the solution runtime's (boot_test.go), moved with the
// code they exercise: one anchor per cell, every identity issued under it, a
// leaf whose only identity is the SPIFFE ID in its URI SAN.
const (
	testPrincipal        = "spiffe://codefly.test/ns/modules/sa/widgets"
	testGatewayPrincipal = "spiffe://codefly.test/ns/platform/sa/gateway"
	testNeighbour        = "spiffe://codefly.test/ns/modules/sa/neighbour"
)

type cell struct {
	anchorPEM []byte
	anchor    *x509.Certificate
	anchorKey ed25519.PrivateKey
	roots     *x509.CertPool
}

func newCell(t *testing.T) *cell {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "codefly.test workload CA"},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, public, private)
	if err != nil {
		t.Fatal(err)
	}
	anchor, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(anchor)
	return &cell{anchorPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), anchor: anchor, anchorKey: private, roots: roots}
}

// leaf issues one workload identity naming the given URIs.
func (c *cell) leaf(t *testing.T, uris ...string) (certPEM, keyPEM []byte) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var parsed []*url.URL
	for _, raw := range uris {
		u, err := url.Parse(raw)
		if err != nil {
			t.Fatal(err)
		}
		parsed = append(parsed, u)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: strings.Join(uris, ",")},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		URIs:         parsed,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, c.anchor, public, c.anchorKey)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
}

// identity is a TLS certificate for one SPIFFE ID, for a party that serves or
// dials rather than reading projected files.
func (c *cell) identity(t *testing.T, spiffeID string) *tls.Certificate {
	t.Helper()
	certPEM, keyPEM := c.leaf(t, spiffeID)
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	return &pair
}

// files writes the projection a platform would: this workload's pair, the
// anchor, and the admitted-caller set naming the gateway.
func (c *cell) files(t *testing.T, principal string) workload.Files {
	t.Helper()
	dir := t.TempDir()
	certPEM, keyPEM := c.leaf(t, principal)
	files := workload.Files{
		Cert:           filepath.Join(dir, "tls.crt"),
		Key:            filepath.Join(dir, "tls.key"),
		TrustBundle:    filepath.Join(dir, "ca.crt"),
		AllowedCallers: filepath.Join(dir, "allowed-callers"),
		MintPeers:      filepath.Join(dir, "mint-peers"),
		GatewayPeers:   filepath.Join(dir, "gateway-peers"),
		Token:          filepath.Join(dir, "token"),
	}
	writeFile(t, files.Cert, string(certPEM))
	writeFile(t, files.Key, string(keyPEM))
	writeFile(t, files.TrustBundle, string(c.anchorPEM))
	writeFile(t, files.AllowedCallers, testGatewayPrincipal+"\n")
	writeFile(t, files.MintPeers, testGatewayPrincipal+"\n")
	writeFile(t, files.GatewayPeers, testGatewayPrincipal+"\n")
	writeFile(t, files.Token, "projected-token\n")
	return files
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	// Through a rename, as a projection is swapped, so a reader never sees a
	// half-written file.
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, path); err != nil {
		t.Fatal(err)
	}
}

// caller is an HTTPS client presenting identity and trusting the cell, with no
// connection reuse unless keepAlive.
func (c *cell) caller(identity *tls.Certificate, keepAlive bool) *http.Client {
	transport := &http.Transport{
		TLSClientConfig:   &tls.Config{RootCAs: c.roots, Certificates: []tls.Certificate{*identity}, MinVersion: tls.VersionTLS13},
		DisableKeepAlives: !keepAlive,
	}
	return &http.Client{Transport: transport, Timeout: 5 * time.Second}
}
