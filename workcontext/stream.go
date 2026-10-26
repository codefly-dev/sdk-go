package workcontext

import (
	"context"
	"errors"
	"fmt"
	"sync"
)

// ErrStreamTerminated marks a stream that a re-check refused. It is returned to
// every later call on the same guard, including after the refusal that caused
// it: a stream is terminated once, and a caller that loops past the first
// refusal must not be handed a second chance to emit.
var ErrStreamTerminated = errors.New("Codefly Work Context stream terminated")

// StreamGuardOptions configures one stream's hold on its credential.
type StreamGuardOptions struct {
	// Recheck re-reads the issuer's live state for a capability that is ALREADY
	// verified, and returns the host's answer.
	//
	// Use (*PinnedVerifier).Recheck. Do NOT use Verify: it consumes a
	// single-use nonce, and every grant capability is single-use, so a stream
	// opened with one died with ErrReplayed at its first message. This
	// module's own README recommended exactly that for a while. Re-checking
	// liveness and spending a nonce are two operations and only one of them
	// belongs in a loop; core added Recheck for this, and it takes a *Verified
	// so it cannot be anybody's first check.
	//
	// Any error terminates the stream, and that includes an error that is
	// neither ErrRevoked nor ErrInvalid. A live source that cannot be reached
	// has not said the credential is good; treating "I could not ask" as a
	// pass is how a stream outlives the authority it was opened under while
	// every log line stays clean.
	Recheck func(context.Context) error
}

// RecheckWith builds the per-emission check from a verifier and a capability
// that has already been verified, so the right call is the easy one.
//
// It exists because the wrong call compiles and reads fine: Verify is the name
// everybody knows, and a guard built on it works in every test that does not
// use a single-use capability and then kills the first grant-opened stream in
// production.
func RecheckWith(verifier *PinnedVerifier, verified *Verified) func(context.Context) error {
	return func(ctx context.Context) error {
		if verifier == nil || verified == nil {
			return fmt.Errorf("%w: a stream re-check needs a verifier and a verified capability", ErrInvalid)
		}
		return verifier.Recheck(ctx, verified)
	}
}

// StreamGuard holds a stream to its credential for the stream's whole life.
//
// A stream authorized when it opened is not authorized forever. The failure it
// exists to prevent is the quiet one: a long-running stream that was opened
// under an installation revision the host has since replaced, continuing to
// drain a snapshot computed under authority that no longer exists. Nothing in
// the stream fails, no error is logged, and the data keeps arriving.
//
// It guards EVERY emission. There was a re-check cadence here, bounded at
// fifteen minutes, and it was a weakening of the rule rather than an
// implementation of it: revoke the installation one second after a successful
// check and every message for the next fifteen minutes still left, with expiry
// and source unavailability equally invisible for that interval. The condition
// is per emission, so the check is per emission.
//
// What that costs is one live authorization check per message, which is the
// price of the guarantee and is why the guard is for streams whose messages
// carry authority rather than for every stream. A stream that cannot pay it
// does not get the guarantee; it does not get a cadence instead.
//
// An idle stream discloses nothing, so there is nothing to refuse: the guard
// does no work until something is about to be sent.
type StreamGuard struct {
	mu         sync.Mutex
	recheck    func(context.Context) error
	terminated error
}

// NewStreamGuard validates its configuration and performs no I/O. The first
// BeforeSend re-checks, so a stream never emits its first message on the
// strength of the check that opened it.
func NewStreamGuard(options StreamGuardOptions) (*StreamGuard, error) {
	if options.Recheck == nil {
		return nil, fmt.Errorf("%w: a stream guard needs a re-check", ErrInvalid)
	}
	return &StreamGuard{recheck: options.Recheck}, nil
}

// BeforeSend is called before every message a stream emits, and re-presents the
// credential every time. A non-nil error terminates the stream: the message
// must not be sent, and nothing after it may be either.
//
// A refusal is returned wrapped, so a caller can tell a credential the state
// moved under (ErrRevoked — a fresh credential would be accepted) from one that
// never becomes valid (ErrInvalid) from a live source that could not be reached
// at all. None of the three resumes this stream. The distinction is for the
// caller's decision about whether to open another, which is a decision about
// one new stream and not a licence to keep this one alive.
//
// It holds the guard's lock across the check, so a stream emitting from several
// goroutines cannot have one of them send on the strength of a check another
// goroutine is still waiting on.
func (g *StreamGuard) BeforeSend(ctx context.Context) error {
	if g == nil {
		return fmt.Errorf("%w: nil stream guard", ErrInvalid)
	}
	if ctx == nil {
		return fmt.Errorf("%w: nil context", ErrInvalid)
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.terminated != nil {
		return g.terminated
	}
	if err := g.recheck(ctx); err != nil {
		// Both sentinels stay in the chain: the caller needs to know the stream
		// is over AND whether a fresh credential would be accepted, and
		// flattening the refusal to text would leave it guessing.
		g.terminated = fmt.Errorf("%w: %w", ErrStreamTerminated, err)
		return g.terminated
	}
	return nil
}

// Terminated reports the refusal that ended the stream, or nil while it is
// still authorized.
func (g *StreamGuard) Terminated() error {
	if g == nil {
		return nil
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.terminated
}
