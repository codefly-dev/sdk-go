package workload

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"
)

// Projected is the default IdentitySource: the X.509-SVID the platform projects
// for this workload as files, and the anchor its peers are verified against.
// An empty path is refused when the listener is built, naming the override and
// the group that provision it.
func Projected(files Files) IdentitySource {
	return projectedIdentity{certFile: files.Cert, keyFile: files.Key, trustBundleFile: files.TrustBundle}
}

// PrincipalOf reads the identity a source serves under: the SPIFFE ID in the
// single URI SAN of the certificate it would present to a peer addressing this
// workload by IP (an empty hello).
//
// Read once, at boot, and then held: the listener and the client refuse any
// later certificate that names something else, so a rotation that lands a
// neighbouring workload's pair is refused as it is served rather than adopted.
// The certificate is parsed from the DER that would be sent, never from
// tls.Certificate.Leaf, which is a cache its holder fills in.
func PrincipalOf(source IdentitySource) (string, error) {
	if source == nil {
		return "", fmt.Errorf("no identity source: a workload with no X.509-SVID has no principal to be held to")
	}
	config, err := source.ServerTLSConfig()
	if err != nil {
		return "", err
	}
	if config == nil {
		return "", fmt.Errorf("the identity source returned no TLS configuration, so this workload has no certificate to read its principal from")
	}
	if refused := oneCertificateToChooseFrom(config, "this workload"); refused != nil {
		return "", refused
	}
	var pair *tls.Certificate
	switch {
	case len(config.Certificates) == 1:
		pair = &config.Certificates[0]
	case config.GetCertificate != nil:
		if pair, err = config.GetCertificate(&tls.ClientHelloInfo{}); err != nil {
			return "", fmt.Errorf("the identity source could not produce the certificate this workload serves under: %w", err)
		}
	}
	if pair == nil || len(pair.Certificate) == 0 {
		return "", fmt.Errorf("the identity source produces no certificate for a peer addressing this workload, so it has no principal to be held to")
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return "", fmt.Errorf("the certificate this workload serves under cannot be parsed: %w", err)
	}
	return oneURIIdentity([]*x509.Certificate{leaf}, "workload")
}

// Listener is this workload's identity, held to the posture every rule in this
// package states, for the listener its callers reach it on and the client it
// dials the platform with.
type Listener struct {
	source    IdentitySource
	principal string
	admitted  func() ([]string, error)
	// config is the one configuration everything is served under, built once:
	// the boot and the listener are the same identity rather than two
	// resolutions that could differ.
	config *tls.Config
	// handshakeTimeout bounds one outbound handshake; zero is the default.
	// Settable only inside this package, for tests.
	handshakeTimeout time.Duration
}

// NewListener resolves this workload's identity once and holds it to every
// posture rule.
//
// principal is the SPIFFE ID the served certificate must name, read before any
// outbound act (PrincipalOf); admitted is who may call, resolved per handshake
// and failing closed (IdentitySet). Building it before the first outbound act is
// the ordering half of a real bug: a leaf issued for a neighbouring workload
// must be refused before it, and the projected token beside it, have been
// presented to anyone.
func NewListener(source IdentitySource, principal string, admitted func() ([]string, error)) (*Listener, error) {
	if source == nil {
		return nil, fmt.Errorf("no identity source: this listener presents this workload's X.509-SVID and there is no plain-HTTP listener to fall back to")
	}
	if admitted == nil {
		return nil, fmt.Errorf("no admitted-caller set: every workload in the trust domain holds a certificate from the anchor, so a listener that admits whoever verifies serves the whole cell. Provision %s/%s, or set %s",
			Group, AllowedCallersFileKey, AllowedCallersFileOverride)
	}
	answered, err := source.ServerTLSConfig()
	if err != nil {
		return nil, err
	}
	if err := usableServerIdentity(answered); err != nil {
		return nil, err
	}
	// A source that resolves anything per handshake has to be askable, and
	// carrying a base pool as well does not make it so: that pool is one object
	// fixed when the source built it, so the rechecks and every outbound dial
	// would be judged by it while the callback went on resolving a fresh one.
	if answered.GetConfigForClient != nil {
		if _, askable := source.(PeerAnchorSource); !askable {
			return nil, fmt.Errorf("the identity source resolves its configuration per handshake (GetConfigForClient is set) and does not implement PeerAnchorSource, so this workload cannot obtain the anchor it re-verifies established peers against — or verifies the platform it dials against — except through a handshake nobody made. Implement PeerAnchor() (*x509.CertPool, error)")
		}
	}
	// On a clone, because everything below writes to it, and a source is under
	// no obligation to hand back a fresh configuration.
	config := answered.Clone()
	refuseResumption(config)
	if err := holdServedCertificate(config, principal); err != nil {
		return nil, err
	}
	admitOnly(config, admitted)
	holdPerConnectionPosture(config, principal, admitted)
	return &Listener{source: source, principal: principal, admitted: admitted, config: config}, nil
}

// Principal is the SPIFFE ID this workload is held to.
func (l *Listener) Principal() string { return l.principal }

// Listen wraps ln in this workload's identity. There is no plain path.
func (l *Listener) Listen(ln net.Listener) net.Listener {
	return tls.NewListener(ln, l.config)
}

// PeerAnchor is the anchor this workload verifies its peers against, now, in
// either direction: one resolution for both because it is one anchor, which is
// what makes a removed root take effect on both halves at once.
func (l *Listener) PeerAnchor() (*x509.CertPool, error) {
	anchor, err := peerAnchorFrom(l.source, l.config)
	if err != nil {
		return nil, fmt.Errorf("resolve the anchor this workload verifies its peers against: %w", err)
	}
	return anchor, nil
}

// Server is an http.Server for handler on this listener: the handshake and
// header deadline bounded, idle keep-alives dropped, and every served
// connection held to trust as it is now rather than as it was at its handshake.
// It negotiates no HTTP/2: net/http skips the hook that records the identity a
// connection was admitted as for h2, so enabling it means moving that record
// first.
func (l *Listener) Server(handler http.Handler) *http.Server {
	return &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: inboundHandshakeTimeout,
		IdleTimeout:       inboundIdleTimeout,
		ConnState:         l.connState(),
	}
}

// connState re-verifies every served connection's caller against current trust
// for as long as the connection lives, and closes it when it stops verifying.
//
// Re-reading trust per *handshake* bounds nothing about a connection that has
// already had its handshake: a caller whose identity was removed from the
// admitted set, or whose issuing root was pulled from the bundle, kept the
// keep-alive connection it already had and kept being served on it.
//
// Installed through http.Server.ConnState so the connection stays the
// *tls.Conn net/http requires it to be.
func (l *Listener) connState() func(net.Conn, http.ConnState) {
	trust := l.PeerAnchor
	admitted := l.admitted
	var watching sync.Map
	return func(conn net.Conn, state http.ConnState) {
		switch state {
		// StateNew, not StateActive: the watch begins when the connection is
		// accepted, so it covers the connection from the moment it is
		// authenticated. The recheck loop waits for the handshake itself.
		case http.StateNew:
			tlsConn, ok := conn.(*tls.Conn)
			if !ok {
				return
			}
			watched := &watchedCaller{done: make(chan struct{})}
			if _, already := watching.LoadOrStore(conn, watched); already {
				return
			}
			go recheckCaller(tlsConn, watched, trust, admitted)
		case http.StateActive:
			// The identity is recorded HERE, synchronously, before the handler
			// runs — not on the recheck's first tick. A handler is handed
			// r.TLS, and tls.ConnectionState shares its certificates with the
			// connection: one rewriting PeerCertificates[0].Raw inside a
			// one-second window had the pin record the rewritten identity, and
			// a de-admitted caller was served 465 requests over 10 seconds on
			// one connection. net/http calls this hook after readRequest and
			// before ServeHTTP, so this runs ahead of any handler.
			if stored, ok := watching.Load(conn); ok {
				watched, isWatched := stored.(*watchedCaller)
				tlsConn, isTLS := conn.(*tls.Conn)
				if isWatched && isTLS {
					watched.pin(tlsConn.ConnectionState())
				}
			}
		case http.StateClosed, http.StateHijacked:
			if stored, ok := watching.LoadAndDelete(conn); ok {
				if watched, isWatched := stored.(*watchedCaller); isWatched {
					watched.stop()
				}
			}
		}
	}
}
