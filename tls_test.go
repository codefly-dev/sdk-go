package codefly_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	codefly "github.com/codefly-dev/sdk-go"
)

// writeLeaf writes a fresh self-signed leaf to certFile/keyFile, returns its DER
// and a cert pool trusting it (usable as both a server leaf and a client CA).
func writeLeaf(t *testing.T, certFile, keyFile string, serial int64) ([]byte, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(serial),
		Subject:               pkix.Name{CommonName: fmt.Sprintf("reload-test-%d", serial)},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		IsCA:                  true,
		BasicConstraintsValid: true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8}), 0600); err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(parsed)
	return der, pool
}

// bump advances a file's modification time so a reload triggers even when the
// rewrite lands in the same filesystem timestamp tick as the first write.
func bump(t *testing.T, path string) {
	t.Helper()
	future := time.Now().Add(time.Minute)
	if err := os.Chtimes(path, future, future); err != nil {
		t.Fatal(err)
	}
}

func TestCertificateReloaderServesRotatedLeaf(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile := filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key")
	first, _ := writeLeaf(t, certFile, keyFile, 1)

	r, err := codefly.NewCertificateReloader(certFile, keyFile)
	if err != nil {
		t.Fatal(err)
	}
	if string(r.Certificate().Certificate[0]) != string(first) {
		t.Fatal("initial leaf not served")
	}

	second, _ := writeLeaf(t, certFile, keyFile, 2)
	bump(t, certFile)
	bump(t, keyFile)
	if string(r.Certificate().Certificate[0]) != string(second) {
		t.Fatal("rotated leaf not served after file change")
	}
}

func TestCertificateReloaderKeepsLastGoodOnMalformedReplacement(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile := filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key")
	good, _ := writeLeaf(t, certFile, keyFile, 1)

	r, err := codefly.NewCertificateReloader(certFile, keyFile)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(certFile, []byte("not a certificate"), 0600); err != nil {
		t.Fatal(err)
	}
	bump(t, certFile)
	if string(r.Certificate().Certificate[0]) != string(good) {
		t.Fatal("malformed replacement served instead of last good leaf")
	}

	third, _ := writeLeaf(t, certFile, keyFile, 3)
	bump(t, certFile)
	bump(t, keyFile)
	if string(r.Certificate().Certificate[0]) != string(third) {
		t.Fatal("reloader did not recover after a valid pair landed")
	}
}

func TestNewCertificateReloaderRejectsMissingFilesAtStartup(t *testing.T) {
	dir := t.TempDir()
	if _, err := codefly.NewCertificateReloader(filepath.Join(dir, "absent.crt"), filepath.Join(dir, "absent.key")); err == nil {
		t.Fatal("reloader started without an initial leaf")
	}
}

// TestServerAndClientTLSConfigServeRotatedLeaf drives a real mTLS handshake
// through ServerTLSConfig/ClientTLSConfig and proves the certificate the server
// presents changes after the mounted files rotate, with no new config built.
func TestServerAndClientTLSConfigServeRotatedLeaf(t *testing.T) {
	dir := t.TempDir()
	serverCert, serverKey := filepath.Join(dir, "s.crt"), filepath.Join(dir, "s.key")
	clientCert, clientKey := filepath.Join(dir, "c.crt"), filepath.Join(dir, "c.key")
	_, serverCA := writeLeaf(t, serverCert, serverKey, 1)
	_, clientCA := writeLeaf(t, clientCert, clientKey, 100)

	serverConfig, err := codefly.ServerTLSConfig(serverCert, serverKey, clientCA)
	if err != nil {
		t.Fatal(err)
	}
	clientConfig, err := codefly.ClientTLSConfig(clientCert, clientKey, serverCA)
	if err != nil {
		t.Fatal(err)
	}

	// served returns the DER the server presents on one handshake. serverCA is
	// re-read from the file each call so the client keeps trusting a rotated
	// server leaf signed anew (each writeLeaf is its own self-signed root).
	served := func(trust *x509.CertPool) []byte {
		listener, err := tls.Listen("tcp", "127.0.0.1:0", serverConfig)
		if err != nil {
			t.Fatal(err)
		}
		defer listener.Close()
		done := make(chan struct{})
		go func() {
			defer close(done)
			conn, aerr := listener.Accept()
			if aerr != nil {
				return
			}
			_ = conn.(*tls.Conn).Handshake()
			conn.Close()
		}()
		cc := clientConfig.Clone()
		cc.RootCAs = trust
		conn, err := tls.Dial("tcp", listener.Addr().String(), cc)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		<-done
		return conn.ConnectionState().PeerCertificates[0].Raw
	}

	first := served(serverCA)

	// Rotate the server leaf in place (a new self-signed root); trust it and prove
	// the served certificate changed with no new server config constructed.
	_, rotatedCA := writeLeaf(t, serverCert, serverKey, 2)
	bump(t, serverCert)
	bump(t, serverKey)
	second := served(rotatedCA)

	if string(first) == string(second) {
		t.Fatal("server served the same leaf after rotation")
	}
}

// TestWithFileReaderReValidatesEveryReload proves the caller's reader, not
// os.ReadFile, sees both the boot-time pair and every rotated pair: a rotation
// the reader rejects keeps the last good leaf serving, and once the reader
// accepts the files the rotated leaf is served.
func TestWithFileReaderReValidatesEveryReload(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile := filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key")
	first, _ := writeLeaf(t, certFile, keyFile, 1)

	var reads []string
	// privateOnly mirrors a projected-file reader: it refuses a file readable
	// beyond the owner, and records every path it is asked for.
	privateOnly := func(path string) ([]byte, error) {
		reads = append(reads, filepath.Base(path))
		info, err := os.Stat(path)
		if err != nil {
			return nil, err
		}
		if info.Mode().Perm()&0o077 != 0 {
			return nil, fmt.Errorf("%s: not private", filepath.Base(path))
		}
		return os.ReadFile(path)
	}

	r, err := codefly.NewCertificateReloader(certFile, keyFile, codefly.WithFileReader(privateOnly))
	if err != nil {
		t.Fatal(err)
	}
	if len(reads) != 2 {
		t.Fatalf("boot-time pair read through the caller's reader %d times, want 2", len(reads))
	}
	if string(r.Certificate().Certificate[0]) != string(first) {
		t.Fatal("boot-time leaf not served")
	}

	// A rotation that lands world-readable is refused by the reader; the reader
	// was consulted (stat saw the change) and the last good leaf keeps serving.
	second, _ := writeLeaf(t, certFile, keyFile, 2)
	for _, path := range []string{certFile, keyFile} {
		if err := os.Chmod(path, 0o644); err != nil {
			t.Fatal(err)
		}
		bump(t, path)
	}
	before := len(reads)
	if string(r.Certificate().Certificate[0]) != string(first) {
		t.Fatal("a pair the reader rejected was served")
	}
	if len(reads) == before {
		t.Fatal("rotation was not offered to the caller's reader")
	}

	// Once the files satisfy the reader, the rotated leaf is served.
	for _, path := range []string{certFile, keyFile} {
		if err := os.Chmod(path, 0o600); err != nil {
			t.Fatal(err)
		}
		bump(t, path)
	}
	if string(r.Certificate().Certificate[0]) != string(second) {
		t.Fatal("accepted rotation not served")
	}

	// The reader also gates startup.
	if err := os.Chmod(keyFile, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := codefly.NewCertificateReloader(certFile, keyFile, codefly.WithFileReader(privateOnly)); err == nil {
		t.Fatal("startup accepted a pair the reader rejects")
	}
	if _, err := codefly.ServerTLSConfig(certFile, keyFile, nil, codefly.WithFileReader(privateOnly)); err == nil {
		t.Fatal("ServerTLSConfig accepted a pair the reader rejects")
	}
}
