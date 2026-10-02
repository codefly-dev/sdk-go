package workcontext

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"
)

// Bounds on the re-check cadence. A cadence longer than a credential's own
// lifetime would never fire inside one stream, and one shorter than a second
// would re-present a credential faster than any authority changes its mind.
const minStreamRecheckInterval = time.Second

// maxStreamRecheckInterval tracks WorkContextMaxTTL, which is a variable a
// consumer may lower, so it is read rather than copied.
func maxStreamRecheckInterval() time.Duration { return WorkContextMaxTTL }

// ErrStreamTerminated marks a stream that a re-check refused. It is returned to
// every later call on the same guard, including after the refusal that caused
// it: a stream is terminated once, and a caller that loops past the first
// refusal must not be handed a second chance to emit.
var ErrStreamTerminated = errors.New("Codefly Work Context stream terminated")

// StreamGuardOptions configures one stream's hold on its credential.
type StreamGuardOptions struct {
	// Interval is the host's re-check cadence. It is the host's, not a number
	// chosen here: the host is what decides how long an authorization answer
	// stays true, and a stream that re-checks more slowly than that is a stream
	// serving from a snapshot the host has already revised.
	Interval time.Duration

	// Recheck re-presents the credential and returns the host's answer. It is
	// the same verification an ordinary call performs, against expectations
	// read at the moment of the check — not against the expectations the stream
	// opened with, which is the whole point.
	Recheck func(context.Context) error

	// Now is the clock, for tests.
	Now func() time.Time
}

// StreamGuard holds a stream to its credential for the stream's whole life.
//
// A stream authorized when it opened is not authorized forever. The failure it
// exists to prevent is the quiet one: a long-running stream that was opened
// under an installation revision the host has since replaced, continuing to
// drain a snapshot computed under authority that no longer exists. Nothing in
// the stream fails, no error is logged, and the data keeps arriving.
//
// It guards emission rather than running a timer. An idle stream discloses
// nothing, so there is nothing to refuse; a stream that keeps emitting is
// re-checked on the cadence and terminates the moment the answer changes.
type StreamGuard struct {
	mu         sync.Mutex
	interval   time.Duration
	recheck    func(context.Context) error
	now        func() time.Time
	checkedAt  time.Time
	terminated error
}

// NewStreamGuard validates the cadence and performs no I/O. The first
// BeforeSend re-checks, so a stream never emits its first message on the
// strength of the check that opened it.
func NewStreamGuard(options StreamGuardOptions) (*StreamGuard, error) {
	if options.Recheck == nil {
		return nil, fmt.Errorf("%w: a stream guard needs a re-check", ErrWorkContextInvalid)
	}
	if options.Interval < minStreamRecheckInterval || options.Interval > maxStreamRecheckInterval() {
		return nil, fmt.Errorf(
			"%w: stream re-check interval must be between %s and %s",
			ErrWorkContextInvalid, minStreamRecheckInterval, maxStreamRecheckInterval(),
		)
	}
	now := options.Now
	if now == nil {
		now = time.Now
	}
	return &StreamGuard{interval: options.Interval, recheck: options.Recheck, now: now}, nil
}

// BeforeSend is called before every message a stream emits. It re-presents the
// credential when the cadence has elapsed and returns the refusal when the
// host gives one. A non-nil error terminates the stream: the message must not
// be sent, and nothing after it may be either.
//
// A refusal is returned wrapped so a caller can tell a superseded credential
// (ErrWorkContextSuperseded — the installation or binding revision moved, and
// a fresh credential would be accepted) from an invalid one. Neither resumes
// this stream. The distinction is for the caller's decision about whether to
// open another, which is a decision about one new stream and not a licence to
// keep this one alive.
func (g *StreamGuard) BeforeSend(ctx context.Context) error {
	if g == nil {
		return fmt.Errorf("%w: nil stream guard", ErrWorkContextInvalid)
	}
	if ctx == nil {
		return fmt.Errorf("%w: nil context", ErrWorkContextInvalid)
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.terminated != nil {
		return g.terminated
	}
	now := g.now().UTC()
	if !g.checkedAt.IsZero() && now.Sub(g.checkedAt) < g.interval {
		return nil
	}
	if err := g.recheck(ctx); err != nil {
		// Both sentinels stay in the chain: the caller needs to know the stream
		// is over AND whether a fresh credential would be accepted, and
		// flattening the refusal to text would leave it guessing.
		g.terminated = fmt.Errorf("%w: %w", ErrStreamTerminated, err)
		return g.terminated
	}
	g.checkedAt = now
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
