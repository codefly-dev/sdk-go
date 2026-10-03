package grpctransport

import (
	"context"
	"fmt"

	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"

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

// SendHeader, SetHeader and SetTrailer are guarded too. They were not, and
// metadata is a channel out: a handler that could not send a message could
// still send a trailer describing it. Everything that leaves goes through the
// re-check.
func (s *GuardedServerStream) SendHeader(metadata metadata.MD) error {
	if err := s.guarded(); err != nil {
		return err
	}
	return s.ServerStream.SendHeader(metadata)
}

func (s *GuardedServerStream) SetHeader(metadata metadata.MD) error {
	if err := s.guarded(); err != nil {
		return err
	}
	return s.ServerStream.SetHeader(metadata)
}

// SetTrailer has no error to return, so a refusal can only be withheld: a
// terminated stream sets no trailer rather than setting one nobody checked.
func (s *GuardedServerStream) SetTrailer(trailer metadata.MD) {
	if s.guarded() != nil {
		return
	}
	s.ServerStream.SetTrailer(trailer)
}

func (s *GuardedServerStream) guarded() error {
	if s == nil || s.guard == nil {
		return fmt.Errorf("%w: unguarded stream", workcontext.ErrInvalid)
	}
	return s.guard.BeforeSend(s.Context())
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
	if err := s.guarded(); err != nil {
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

// StreamServerInterceptor guards every stream a server opens, so enforcement is
// WIRING rather than something each handler author remembers.
//
// Guard on its own leaves the original stream in the handler's scope, so the
// rule held wherever somebody thought of it — the same shape as the optional
// carrier this module deleted. An interceptor is installed once, at the server,
// and the handler receives a stream it cannot write around because the
// unguarded one never reaches it.
//
// guardFor builds the guard for one stream, from whatever the server
// established when the stream opened: typically the capability it verified, so
// the re-check is workcontext.RecheckWith(verifier, verified). Returning a nil
// guard with a nil error means this stream carries no capability and needs
// none; returning an error refuses the stream before the handler runs, which is
// the right outcome for a capability-bearing method whose capability did not
// verify.
func StreamServerInterceptor(
	guardFor func(ctx context.Context, info *grpc.StreamServerInfo) (*workcontext.StreamGuard, error),
) grpc.StreamServerInterceptor {
	return func(
		server any,
		stream grpc.ServerStream,
		info *grpc.StreamServerInfo,
		handler grpc.StreamHandler,
	) error {
		if guardFor == nil {
			return fmt.Errorf(
				"%w: a stream interceptor needs a guard for each stream",
				workcontext.ErrInvalid,
			)
		}
		guard, err := guardFor(stream.Context(), info)
		if err != nil {
			return err
		}
		if guard == nil {
			// Explicitly unguarded, by the server's own decision, at the
			// server rather than inside a handler.
			return handler(server, stream)
		}
		guarded, err := Guard(stream, guard)
		if err != nil {
			return err
		}
		return handler(server, guarded)
	}
}
