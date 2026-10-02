package grpctransport

import (
	"fmt"

	"google.golang.org/grpc"

	"github.com/codefly-dev/sdk-go/workcontext"
)

// GuardedServerStream re-presents a stream's credential before every message
// the stream sends, by being the thing that sends them.
//
// A StreamGuard on its own is advice. BeforeSend has to be called, and whether
// it is called before each emission depends on each author remembering to call
// it — which is the same shape as the optional carrier this PR deleted: a rule
// that holds wherever somebody thought of it. Wrapping the stream makes the
// check structural. A handler that writes through this cannot emit without the
// re-check, because Send IS the re-check followed by the send.
//
// It wraps grpc.ServerStream, so it also serves the generated per-service
// stream types: a generated server stream embeds grpc.ServerStream, and
// handing it one of these makes every SendMsg go through the guard.
type GuardedServerStream struct {
	grpc.ServerStream
	guard *workcontext.StreamGuard
}

// Guard wraps a server stream so every message it sends is preceded by a live
// re-check. A nil guard is refused rather than treated as "no guarding
// wanted": a wrapper that silently did nothing would be worse than no wrapper,
// because the call site would read as guarded.
func Guard(stream grpc.ServerStream, guard *workcontext.StreamGuard) (*GuardedServerStream, error) {
	if stream == nil {
		return nil, fmt.Errorf("%w: no stream to guard", workcontext.ErrInvalid)
	}
	if guard == nil {
		return nil, fmt.Errorf("%w: no stream guard", workcontext.ErrInvalid)
	}
	return &GuardedServerStream{ServerStream: stream, guard: guard}, nil
}

// SendMsg re-checks, then sends. A refusal is returned and the message is NOT
// sent: the whole point is that a message computed under withdrawn authority
// does not leave.
//
// The error is the guard's, wrapped, so a caller can tell a terminated stream
// from a transport failure — and ErrStreamTerminated is sticky, so a handler
// that loops past the first refusal keeps being refused rather than getting a
// second chance to emit.
func (s *GuardedServerStream) SendMsg(message any) error {
	if s == nil || s.guard == nil {
		return fmt.Errorf("%w: unguarded stream", workcontext.ErrInvalid)
	}
	if err := s.guard.BeforeSend(s.Context()); err != nil {
		return err
	}
	return s.ServerStream.SendMsg(message)
}

// Terminated reports the refusal that ended the stream, or nil.
func (s *GuardedServerStream) Terminated() error {
	if s == nil {
		return nil
	}
	return s.guard.Terminated()
}
