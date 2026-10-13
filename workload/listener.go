package workload

import (
	"crypto/tls"
	"crypto/x509"
	"sync"
	"time"
)

// inboundHandshakeTimeout bounds the TLS handshake and the request headers of
// an accepted connection.
//
// http.Server derives its handshake deadline from the smallest of
// ReadHeaderTimeout, ReadTimeout and WriteTimeout, so this one value bounds
// both. With all three unset, as they were, any peer that completes a TCP
// connect and then sends a partial ClientHello — or a header line at a byte a
// minute — holds a goroutine and a file descriptor indefinitely, and every
// ClientHello costs a read of the trust bundle, so the cheap half of that is
// the attacker's. Neither ReadTimeout nor WriteTimeout is set, deliberately:
// they bound the whole body, and a declared long-running stream (up to
// MaxStreamDurationLimit) is a conforming request, not a slow one.
const inboundHandshakeTimeout = 10 * time.Second

// inboundIdleTimeout bounds a keep-alive connection nobody is using. It is pool
// hygiene, not the trust bound — what bounds the trust decision is the recheck,
// because an inactivity timeout cannot bound a connection that is never
// inactive, which is the finding this runtime already answered outbound.
const inboundIdleTimeout = 30 * time.Second

// watchedCaller is one watched connection's lifetime and the identity it was
// admitted as.
//
// The identity is recorded once, by whichever of the two reaches it first: the
// ConnState hook at the first request, or the recheck's own first tick for a
// connection that handshakes and then sends nothing. Both read it from a
// private parse (see immutableChain); the difference is that the hook runs
// before any handler, and the tick does not.
type watchedCaller struct {
	done     chan struct{}
	stopOnce sync.Once
	mu       sync.Mutex
	identity string
	leaf     []byte
	refused  error
}

// pin records the identity this connection was authenticated as, if nothing has
// yet.
func (w *watchedCaller) pin(state tls.ConnectionState) {
	if !state.HandshakeComplete {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.identity != "" || w.refused != nil {
		return
	}
	identity, leaf, err := admittedIdentity(state)
	if err != nil {
		w.refused = err
		return
	}
	w.identity, w.leaf = identity, leaf
}

// pinned is what was recorded, and any error that recording it produced.
func (w *watchedCaller) pinned() (string, []byte, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.identity, w.leaf, w.refused
}

func (w *watchedCaller) stop() {
	w.stopOnce.Do(func() { close(w.done) })
}

// recheckCaller re-verifies one established caller until the connection ends.
func recheckCaller(conn *tls.Conn, watched *watchedCaller, trust func() (*x509.CertPool, error), admitted func() ([]string, error)) {
	ticker := time.NewTicker(inboundTrustRecheckInterval)
	defer ticker.Stop()
	for {
		select {
		case <-watched.done:
			return
		case <-ticker.C:
			// Until the handshake completes there is no peer chain to judge,
			// and an unhandshaken connection is not a caller who should be
			// refused — it is bounded by the handshake deadline instead. This
			// is why the watch can start at accept: it waits for
			// authentication rather than for the first request.
			state := conn.ConnectionState()
			if !state.HandshakeComplete {
				continue
			}
			// For a connection that handshook and has sent nothing, no request
			// has reached StateActive, so nothing has pinned it yet and no
			// handler has run either. Pinning here is then reading the chain
			// as the handshake left it.
			watched.pin(state)
			pinned, leaf, err := watched.pinned()
			if err != nil {
				_ = conn.Close()
				return
			}
			if err := callerStillAdmitted(state, trust, admitted, pinned, leaf); err != nil {
				_ = conn.Close()
				return
			}
		}
	}
}

// inboundTrustRecheckInterval bounds how long an accepted connection may
// outlive the trust that admitted it. The outbound interval's reasoning, in the
// direction where being wrong means serving a caller who should be refused.
const inboundTrustRecheckInterval = time.Second
