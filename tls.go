package codefly

import (
	"crypto/tls"
	"crypto/x509"
	"os"
	"sync"
	"time"
)

// CertificateReloader serves a rotated TLS leaf without a process restart.
//
// A service that terminates or initiates TLS is handed a certificate/key pair as
// files projected into the container (for example a cert-manager Certificate
// written to a Kubernetes Secret). The usual pattern loads that pair once at
// startup with tls.LoadX509KeyPair and then presents the boot-time leaf for the
// life of the process. When the issuer rotates the leaf — short-lived workload
// leaves are rotated well before expiry — the files on disk are fresh but the
// running process keeps presenting the stale leaf, and once it expires every
// handshake fails even though a valid certificate is already mounted. Issuance
// signals stay green throughout; only the served certificate is stale.
//
// A CertificateReloader re-reads the mounted files when their content changes and
// serves the new leaf on the next handshake, via tls.Config.GetCertificate and
// GetClientCertificate. A malformed or half-written replacement is rejected and
// the last good leaf keeps serving, so a rotation in progress never fails a
// handshake the process could otherwise complete.
type CertificateReloader struct {
	certFile, keyFile string
	read              func(string) ([]byte, error)

	mu      sync.RWMutex
	current *tls.Certificate
	certMod time.Time
	keyMod  time.Time

	checkMu sync.Mutex
}

// ReloaderOption adjusts how a CertificateReloader reads its mounted pair.
type ReloaderOption func(*CertificateReloader)

// WithFileReader reads the certificate and key files through read instead of
// os.ReadFile, at startup and on every reload. A service whose projected files
// must satisfy checks beyond "parses as a key pair" (permission bits, a size
// bound, the path's shape) passes the reader it already applies at startup, so a
// rotated pair is re-validated exactly as the boot-time pair was; a replacement
// the reader rejects is treated like a malformed one and the last good pair keeps
// serving. Rotation is still detected by stat, so read is called only when a
// file's modification time advanced.
func WithFileReader(read func(string) ([]byte, error)) ReloaderOption {
	return func(r *CertificateReloader) {
		if read != nil {
			r.read = read
		}
	}
}

// NewCertificateReloader loads the initial pair once. A startup failure is
// returned to the caller: a listener or dialer must never come up without a
// valid leaf.
func NewCertificateReloader(certFile, keyFile string, options ...ReloaderOption) (*CertificateReloader, error) {
	r := &CertificateReloader{certFile: certFile, keyFile: keyFile, read: os.ReadFile}
	for _, option := range options {
		option(r)
	}
	if err := r.load(); err != nil {
		return nil, err
	}
	return r, nil
}

func (r *CertificateReloader) load() error {
	certPEM, err := r.read(r.certFile)
	if err != nil {
		return err
	}
	keyPEM, err := r.read(r.keyFile)
	if err != nil {
		return err
	}
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return err
	}
	certInfo, err := os.Stat(r.certFile)
	if err != nil {
		return err
	}
	keyInfo, err := os.Stat(r.keyFile)
	if err != nil {
		return err
	}
	r.mu.Lock()
	r.current = &pair
	r.certMod = certInfo.ModTime()
	r.keyMod = keyInfo.ModTime()
	r.mu.Unlock()
	return nil
}

// refresh re-reads the pair only when a file's modification time advanced past
// the loaded copy. os.Stat follows the atomic symlink swap a Kubernetes projected
// Secret uses on update, so a rotation is observed. Any stat, read or parse
// failure is swallowed so the last good pair keeps serving; a half-written
// replacement is picked up on a later handshake once both files settle.
func (r *CertificateReloader) refresh() {
	r.checkMu.Lock()
	defer r.checkMu.Unlock()
	certInfo, err := os.Stat(r.certFile)
	if err != nil {
		return
	}
	keyInfo, err := os.Stat(r.keyFile)
	if err != nil {
		return
	}
	r.mu.RLock()
	changed := certInfo.ModTime().After(r.certMod) || keyInfo.ModTime().After(r.keyMod)
	r.mu.RUnlock()
	if changed {
		_ = r.load()
	}
}

// Certificate returns the leaf a handshake would serve now, refreshing first.
func (r *CertificateReloader) Certificate() *tls.Certificate {
	r.refresh()
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.current
}

// GetCertificate is a tls.Config.GetCertificate callback: it serves the current
// leaf to every inbound handshake.
func (r *CertificateReloader) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	return r.Certificate(), nil
}

// GetClientCertificate is a tls.Config.GetClientCertificate callback: a
// reconnecting client presents the current leaf, so a rotated client identity
// reaches the server on the next dial without a restart.
func (r *CertificateReloader) GetClientCertificate(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
	return r.Certificate(), nil
}

// ServerTLSConfig returns a *tls.Config for a server listener whose leaf reloads
// in-process from the mounted certFile/keyFile. When clientCAs is non-nil the
// server requires and verifies a client certificate against it (mutual TLS);
// when nil it performs server-authenticated TLS only. The floor is TLS 1.3; a
// caller needing different settings can instead build its own config around a
// CertificateReloader. options apply to that reloader (see WithFileReader).
//
// Only GetCertificate is set, deliberately: a server that also populates
// Certificates would have Go consult GetCertificate only when the client sent an
// SNI name (see (*tls.Config).getCertificate). Peers addressed by IP send no
// SNI, so a config carrying both would silently serve the static boot-time leaf
// to them and defeat the reload. GetCertificate alone is always consulted.
func ServerTLSConfig(certFile, keyFile string, clientCAs *x509.CertPool, options ...ReloaderOption) (*tls.Config, error) {
	reloader, err := NewCertificateReloader(certFile, keyFile, options...)
	if err != nil {
		return nil, err
	}
	config := &tls.Config{
		MinVersion:     tls.VersionTLS13,
		GetCertificate: reloader.GetCertificate,
	}
	if clientCAs != nil {
		config.ClientCAs = clientCAs
		config.ClientAuth = tls.RequireAndVerifyClientCert
	}
	return config, nil
}

// ClientTLSConfig returns a *tls.Config for a client that presents a leaf which
// reloads in-process from the mounted certFile/keyFile and verifies the server
// against roots (nil uses the system roots). The floor is TLS 1.3. Only
// GetClientCertificate is set, so the current leaf is presented on every
// (re)dial without a static copy shadowing it.
func ClientTLSConfig(certFile, keyFile string, roots *x509.CertPool, options ...ReloaderOption) (*tls.Config, error) {
	reloader, err := NewCertificateReloader(certFile, keyFile, options...)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		MinVersion:           tls.VersionTLS13,
		RootCAs:              roots,
		GetClientCertificate: reloader.GetClientCertificate,
	}, nil
}
