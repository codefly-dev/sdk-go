package workload

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"slices"
	"sync"
	"time"

	codefly "github.com/codefly-dev/sdk-go"
)

// newPlatformTransport is the default transport with proxying dropped.
func newPlatformTransport() *http.Transport {
	base, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		// Something replaced the process-wide default with another kind of
		// RoundTripper; start from Go's own defaults rather than from it.
		base = &http.Transport{}
	}
	transport := base.Clone()
	transport.Proxy = nil
	return transport
}

// Client is the client this workload makes platform requests with, under the
// identity its listener serves: the same pair and the same anchor, which is the
// point — one identity, used in both directions.
//
// peersAt is the authorization set for each address dialled: who may answer
// there. An address it has no set for is refused rather than held to some
// union. bootAddress is dialled at no point; the configuration for it is built
// once at boot so an unbuildable one refuses the boot rather than the first
// request.
//
// It is the other half of refusing a plaintext destination. An https URL says
// only that the scheme is https: without a trust anchor the connection is
// verified against whatever the image's system roots happen to contain, and
// without a client certificate the far end cannot tell this workload from
// anything else that reached it. So the client presents this workload's
// X.509-SVID and verifies the far end against the anchor the platform
// projected — the same pair and the same anchor the listener uses, which is the
// point: one identity, used in both directions.
//
// It refuses to follow redirects. net/http strips only Authorization,
// WWW-Authenticate and Cookie when a redirect crosses hosts; every other header
// — the projected token on a mint, a viewer's capability on a module read — is
// copied to the new target verbatim, and a 307/308 re-sends the body with them.
// So anything able to answer with a Location would be handed the credentials
// that prove who this workload is, and the theft would look like an ordinary
// successful request.
func (l *Listener) Client(peersAt func(addr string) func() ([]string, error), bootAddress string) (*http.Client, error) {
	if peersAt == nil {
		return nil, fmt.Errorf("a platform client needs the set of identities allowed to answer at each address it dials: with none, a workload holding a certificate for the address would be handed this workload's credentials")
	}
	// A fresh configuration per connection, so the anchor this workload judges
	// the platform by is re-read rather than snapshotted at boot.
	//
	// Judging by a stale anchor admits whoever should be refused, which is not
	// symmetric with serving a stale leaf — the inbound argument, and it
	// applies outbound with more force, not less. The two destinations on the
	// other side of this
	// client are the mint and the gateway — they receive the projected
	// service-account token, the viewer's bearer and this workload's own
	// credential — so a root removed from the bundle because it was compromised
	// kept authenticating exactly the parties that are handed everything.
	//
	// Reloading per connection is the whole story only if connections do not
	// outlive the reload, so established connections are re-verified too (see
	// below).
	//
	// What is *not* rebuilt per connection is this workload's own leaf source.
	// Building a whole new SDK reloader per dial, and again per recheck of
	// every connection, looks like "nothing is snapshotted" and is a
	// regression: NewCertificateReloader loads
	// eagerly and returns the error, where a long-lived reloader swallows a
	// failed re-read and keeps serving the last good pair. So a cert rotated
	// non-atomically — the certificate written, the key a moment behind —
	// failed every new dial, and failed every recheck, which closed
	// established connections whose peers were still perfectly trusted. A
	// half-written copy of this workload's own key is not a judgement about
	// the peer, and the two must not share a failure path.
	leaf, err := l.outboundLeaf()
	if err != nil {
		return nil, err
	}
	trust := l.PeerAnchor
	// Per destination, not per "platform": the authorization set is chosen by
	// the address being dialled, so the mint's identity is not accepted at the
	// gateway's address or the other way round, and a third address has no set
	// and is refused.
	newConfig := func(addr string) (*tls.Config, error) {
		anchor, err := trust()
		if err != nil {
			return nil, err
		}
		config := &tls.Config{
			MinVersion:           tls.VersionTLS13,
			RootCAs:              anchor,
			GetClientCertificate: leaf,
		}
		// Held to the frozen principal at presentation, and pointed at the one
		// identity allowed to answer at this address. Both apply to a
		// consumer's source and to the projected pair: one of the two paths
		// carrying a check is not the check.
		if err := holdPresentedCertificate(config, l.principal); err != nil {
			return nil, err
		}
		admitOnlyPlatform(config, peersAt(addr))
		return config, nil
	}
	// Refused at boot rather than at the first dial: a configuration this
	// runtime cannot build is a boot failure, not a mint that fails later.
	if _, err := newConfig(bootAddress); err != nil {
		return nil, err
	}

	transport := newPlatformTransport()
	// No TLSClientConfig: every connection builds its own below, and leaving a
	// snapshot here would be the bug this function exists to avoid.
	transport.TLSClientConfig = nil
	transport.DialTLSContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		config, err := newConfig(addr)
		if err != nil {
			return nil, err
		}
		host, _, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}
		config = config.Clone()
		config.ServerName = host
		raw, err := (&net.Dialer{Timeout: platformRequestTimeout}).DialContext(ctx, network, addr)
		if err != nil {
			return nil, err
		}
		// The handshake carries its own deadline, independent of whatever the
		// caller's context says.
		//
		// A custom DialTLSContext takes net/http out of the handshake entirely:
		// it calls customDialTLS and never reaches addTLS, so
		// Transport.TLSHandshakeTimeout — inherited as 10s from
		// DefaultTransport — silently does nothing, and the only bound left is
		// the request context's. That is adequate for an ordinary request and
		// wrong exactly where it matters: Gateway.HTTPClient carries streams
		// and therefore sets no client timeout on purpose, so a dial made for
		// a stream was bounded by the method's declared MaxStreamDuration (up
		// to thirty minutes) or by nothing at all. A handshake is not a
		// stream: it completes in milliseconds or the peer is not answering.
		bound := l.handshakeTimeout
		if bound == 0 {
			bound = platformHandshakeTimeout
		}
		handshake, cancelHandshake := context.WithTimeout(ctx, bound)
		defer cancelHandshake()
		conn := tls.Client(raw, config)
		if err := conn.HandshakeContext(handshake); err != nil {
			_ = raw.Close()
			return nil, err
		}
		// Watched on the two inputs that are a judgement about the peer — the
		// anchor and the admitted set — and on nothing else.
		return watchOutboundTrust(conn, host, trust, peersAt(addr)), nil
	}
	// Pool hygiene, not the trust bound: a connection nothing sends on is
	// dropped rather than held open indefinitely. What bounds the trust
	// decision is the recheck above, because an inactivity timeout cannot.
	transport.IdleConnTimeout = outboundTrustReloadBound
	return &http.Client{
		Timeout:       platformRequestTimeout,
		Transport:     transport,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}, nil
}

// outboundLeaf is the certificate this workload presents to the platform,
// resolved once and re-read by whatever produces it.
//
// Once, because the thing that keeps a rotated leaf presented is the reloader's
// own re-read, not a new reloader: the SDK's swallows a failed or half-written
// re-read and keeps serving the last good pair (sdk-go tls.go, refresh), which
// is the property that makes a rotation invisible to a caller. Building a new
// one per dial threw exactly that away, because the constructor loads eagerly
// and reports the error instead.
func (l *Listener) outboundLeaf() (func(*tls.CertificateRequestInfo) (*tls.Certificate, error), error) {
	projected, isProjected := l.source.(projectedIdentity)
	if !isProjected {
		// A consumer's source: the identity it returned, in both directions,
		// rather than projected files it never said it uses. Its own callback
		// is what gets asked, so a source that rotates is followed.
		client, err := clientTLSFrom(l.source, l.config)
		if err != nil {
			return nil, fmt.Errorf("configure this workload's outbound identity from the supplied identity source: %w", err)
		}
		if client.GetClientCertificate != nil {
			return client.GetClientCertificate, nil
		}
		pairs := client.Certificates
		return func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			if len(pairs) == 0 {
				return nil, fmt.Errorf("the identity source produces no certificate this workload can present to the platform")
			}
			return &pairs[0], nil
		}, nil
	}
	reloader, err := codefly.NewCertificateReloader(projected.certFile, projected.keyFile)
	if err != nil {
		return nil, fmt.Errorf("configure this workload's outbound identity from %q/%q: %w — the same pair the listener presents is what names this workload to the platform it calls",
			projected.certFile, projected.keyFile, err)
	}
	return reloader.GetClientCertificate, nil
}

// outboundTrustReloadBound is how long a connection nobody is using is kept in
// the pool. Pool hygiene, nothing more.
//
// It used to be described as the bound on outbound trust staleness, and it was
// not one: an inactivity timeout bounds only a connection that goes inactive,
// so a connection carrying traffic was never dropped and the documented window
// held for a quiet process only. What bounds the trust decision is
// outboundTrustRecheckInterval below.
const outboundTrustReloadBound = 30 * time.Second

// outboundTrustRecheckInterval bounds how long an established platform
// connection may outlive the trust that authenticated it.
//
// It is the number the reload bound above could not deliver on its own. Peer
// trust is re-read on every dial, and that was documented as a 30-second
// window on the strength of IdleConnTimeout — but an *inactivity* timeout
// bounds only a connection nobody is using. A connection carrying a request
// every 100ms never becomes idle, and one was demonstrated still answering 31
// seconds after the server's trust root was removed, over a single handshake:
// traffic kept the connection, and the trust decision behind it, alive for as
// long as it kept arriving. A stream is the same shape by construction, held
// open for as long as its declared duration allows (up to
// MaxStreamDurationLimit).
//
// A second, not the idle bound's thirty: the recheck is a file read and a chain
// verification against a chain already in hand, a few hundred microseconds on a
// handful of platform connections, so the window is set by what the guarantee
// should be rather than by what the work costs. It is also what makes the
// busy-connection case testable in about a second instead of half a minute.
const outboundTrustRecheckInterval = time.Second

// watchOutboundTrust re-verifies an established connection's peer against
// current trust, and closes the connection when it stops verifying.
//
// Re-verifying rather than imposing a maximum connection age, which was the
// other way to bound this. A maximum age cuts whatever is in flight when it
// expires, and a declared 30-minute stream over a peer that is still perfectly
// trusted would be cut every bound — the runtime would be ending conforming
// streams to answer a question it can answer without ending them. The chain the
// peer presented is already in hand, so the anchor and the allowed-peer set can
// be re-read and applied to it: a connection whose peer still verifies is left
// alone, and one whose peer no longer does is closed, busy or idle, stream or
// request.
//
// A closed connection surfaces as a failed request or a cut stream, which is
// the intended outcome: the alternative is continuing to present this
// workload's credentials — and the viewer's — to a destination this cell has
// stopped vouching for.
func watchOutboundTrust(conn *tls.Conn, host string, trust func() (*x509.CertPool, error), peers func() ([]string, error)) net.Conn {
	watched := &recheckedConn{Conn: conn, done: make(chan struct{})}
	go func() {
		ticker := time.NewTicker(outboundTrustRecheckInterval)
		defer ticker.Stop()
		for {
			select {
			case <-watched.done:
				return
			case <-ticker.C:
				if err := peerStillTrusted(conn.ConnectionState(), host, trust, peers); err != nil {
					_ = watched.Close()
					return
				}
			}
		}
	}()
	return watched
}

// recheckedConn is the connection the transport holds, so the recheck stops
// when net/http drops it.
type recheckedConn struct {
	net.Conn
	stop sync.Once
	done chan struct{}
}

func (c *recheckedConn) Close() error {
	c.stop.Do(func() { close(c.done) })
	return c.Conn.Close()
}

// peerStillTrusted holds the chain this connection was authenticated by to
// trust as it is now: the current anchor, the current allowed-peer set, and the
// current time, which is also how a peer certificate that expired mid-stream
// stops being accepted.
// It takes the anchor and the admitted set, not a whole configuration to
// rebuild: a recheck that also resolved this workload's own leaf would close a
// trusted connection over a half-written copy of this process's own key, which
// is not a statement about the peer at all.
func peerStillTrusted(state tls.ConnectionState, host string, trust func() (*x509.CertPool, error), peers func() ([]string, error)) error {
	anchor, err := trust()
	if err != nil {
		return err
	}
	// The private chain, for the reason immutableChain records: the objects in
	// a ConnectionState are shared, and this runs for as long as the
	// connection lives.
	chain, err := immutableChain(state)
	if err != nil {
		return err
	}
	if len(chain) == 0 {
		return fmt.Errorf("the established platform connection presents no peer certificate to re-verify")
	}
	intermediates := x509.NewCertPool()
	for _, cert := range chain[1:] {
		intermediates.AddCert(cert)
	}
	if _, verifyErr := chain[0].Verify(x509.VerifyOptions{
		Roots:         anchor,
		Intermediates: intermediates,
		DNSName:       host,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}); verifyErr != nil {
		return fmt.Errorf("the platform destination this connection was authenticated against no longer verifies: %w", verifyErr)
	}
	// And the same identity check a dial makes, since the allowed-peer set is
	// read per dial and a connection older than a change to it would otherwise
	// keep a de-authorised destination.
	admitted, err := peers()
	if err != nil {
		return err
	}
	identity, err := oneURIIdentity(chain, "platform destination")
	if err != nil {
		return err
	}
	if !slices.Contains(admitted, identity) {
		return fmt.Errorf("the established connection's destination %q is no longer one this workload presents its credentials to", identity)
	}
	return nil
}

// platformHandshakeTimeout bounds one outbound TLS handshake, on its own,
// because the custom dialler means nothing else does. It is deliberately not
// derived from platformRequestTimeout: a request may legitimately be long (a
// declared stream), and a handshake never is.
const platformHandshakeTimeout = 10 * time.Second

// platformRequestTimeout bounds one request this workload makes on its own
// behalf, end to end, so a host that accepts a request and never answers
// surfaces as a failure rather than a goroutine parked in Do forever.
const platformRequestTimeout = 10 * time.Second

// DialAddress is the host:port a URL is dialled at, with the scheme's default
// port made explicit so it compares equal to what the dialler is handed.
//
// Host and port together, because the two destinations may well share a host
// and differ only by port — the mint has lived on the gateway's host — and a
// comparison on the host alone would then hold both to whichever set matched
// first, which is the merge this split exists to undo.
func DialAddress(raw string) string {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Host == "" {
		return ""
	}
	if parsed.Port() != "" {
		return parsed.Host
	}
	if parsed.Scheme == "http" {
		return parsed.Host + ":80"
	}
	return parsed.Host + ":443"
}
