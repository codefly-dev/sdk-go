package grpctransport

import (
	"context"
	"fmt"
	"sync"

	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"

	"github.com/codefly-dev/sdk-go/workcontext"
)

// GuardedServerStream re-presents a stream's credential before anything leaves
// it, by being the thing that sends.
//
// A StreamGuard on its own is advice. BeforeSend has to be called, and whether
// it is called before each emission depends on each author remembering — the
// same shape as the optional carrier this module deleted: a rule that holds
// wherever somebody thought of it. Wrapping the stream makes the check
// structural, and StreamServerInterceptor makes the wrapping structural too.
//
// # It does not embed the stream, and that is load-bearing
//
// This type used to embed grpc.ServerStream as a public field, so a handler
// given only the intercepted stream could write `stream.(*GuardedServerStream).
// ServerStream` and send whatever it liked with no check at all. A real gRPC
// probe delivered a message under revoked authority with zero checks that way.
// A guard reachable past is not a guard, so the underlying stream is private
// and every method of the interface is forwarded by hand.
//
// # Trailers are held, not queued
//
// gRPC sends trailers when the handler RETURNS, not when SetTrailer is called.
// Checking authority at SetTrailer time and handing the metadata straight to
// gRPC meant a handler could queue a trailer, have authority revoked, return,
// and the client received it — through the ordinary guarded API, no unwrapping
// needed. So pending trailers stay in this wrapper, and Finish is what releases
// them, after one more check.
type GuardedServerStream struct {
	stream grpc.ServerStream
	guard  *workcontext.StreamGuard

	mu       sync.Mutex
	trailers metadata.MD
	finished bool
}

// Guard wraps a server stream so everything it sends is preceded by a live
// re-check. A nil guard is refused rather than treated as "no guarding
// wanted": a wrapper that silently did nothing would be worse than no wrapper,
// because the call site would read as guarded.
//
// A caller using Guard directly MUST call Finish when its handler is done, or
// trailers it set are never sent. StreamServerInterceptor does that for you,
// which is the reason to prefer it.
func Guard(stream grpc.ServerStream, guard *workcontext.StreamGuard) (*GuardedServerStream, error) {
	if stream == nil {
		return nil, fmt.Errorf("%w: no stream to guard", workcontext.ErrInvalid)
	}
	if guard == nil {
		return nil, fmt.Errorf("%w: no stream guard", workcontext.ErrInvalid)
	}
	return &GuardedServerStream{stream: stream, guard: guard, trailers: metadata.MD{}}, nil
}

// Context is the stream's context, forwarded. It is not guarded: reading the
// context sends nothing.
func (s *GuardedServerStream) Context() context.Context {
	if s == nil || s.stream == nil {
		return context.Background()
	}
	return s.stream.Context()
}

// RecvMsg is forwarded unguarded. Receiving is not emitting, and a handler that
// cannot read its own request cannot decide anything about it; the guard is
// about what leaves.
func (s *GuardedServerStream) RecvMsg(message any) error {
	if s == nil || s.stream == nil {
		return fmt.Errorf("%w: unguarded stream", workcontext.ErrInvalid)
	}
	return s.stream.RecvMsg(message)
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
	if err := s.recheck(); err != nil {
		return err
	}
	return s.stream.SendMsg(message)
}

// SendHeader re-checks and sends. gRPC flushes headers immediately, so the
// check at this moment is the check that matters.
func (s *GuardedServerStream) SendHeader(headers metadata.MD) error {
	if err := s.recheck(); err != nil {
		return err
	}
	return s.stream.SendHeader(headers)
}

// SetHeader re-checks and queues with gRPC. Headers queued this way are
// flushed by the first SendMsg or SendHeader, both of which re-check — so
// unlike a trailer, a queued header cannot outlive its authorization.
func (s *GuardedServerStream) SetHeader(headers metadata.MD) error {
	if err := s.recheck(); err != nil {
		return err
	}
	return s.stream.SetHeader(headers)
}

// SetTrailer re-checks and HOLDS the metadata in this wrapper. Nothing reaches
// gRPC until Finish releases it, because gRPC would otherwise send it when the
// handler returns — which is after any revocation that happened in between.
func (s *GuardedServerStream) SetTrailer(trailer metadata.MD) {
	if s == nil {
		return
	}
	if err := s.recheck(); err != nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.finished {
		// Past the last check there is nothing left to authorize against.
		return
	}
	for key, values := range trailer {
		s.trailers[key] = append(s.trailers[key], values...)
	}
}

// Finish performs the LAST re-check and releases the trailers the handler set,
// or discards them. It is called once, after the handler returns, and
// StreamServerInterceptor calls it.
//
// It returns the handler's own error unchanged when authority still holds, and
// the termination error when it does not — so a handler that completed under
// authority that has since been withdrawn fails the RPC rather than succeeding
// with a trailer nobody authorized.
func (s *GuardedServerStream) Finish(handlerErr error) error {
	if s == nil {
		return handlerErr
	}
	err := s.recheck()
	s.mu.Lock()
	pending := s.trailers
	s.trailers = metadata.MD{}
	s.finished = true
	s.mu.Unlock()
	if err != nil {
		// Discarded. A trailer describes the result of work the authority has
		// since been withdrawn from, and it is the last thing to leave.
		return err
	}
	if len(pending) > 0 {
		s.stream.SetTrailer(pending)
	}
	return handlerErr
}

// Terminated reports the refusal that ended the stream, or nil.
func (s *GuardedServerStream) Terminated() error {
	if s == nil {
		return nil
	}
	return s.guard.Terminated()
}

func (s *GuardedServerStream) recheck() error {
	if s == nil || s.guard == nil || s.stream == nil {
		return fmt.Errorf("%w: unguarded stream", workcontext.ErrInvalid)
	}
	return s.guard.BeforeSend(s.Context())
}

// StreamServerInterceptor guards every stream a server opens, so enforcement is
// WIRING rather than something each handler author remembers.
//
// Guard on its own leaves the original stream in the caller's scope, so the
// rule held wherever somebody thought of it. An interceptor is installed once,
// at the server, and the handler receives a stream it cannot write around: the
// unguarded one never reaches it, and the wrapper does not expose it.
//
// It also calls Finish, which is where the handler's queued trailers are
// re-checked and released. A handler that returns successfully under authority
// that was withdrawn while it ran fails the RPC.
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
		return guarded.Finish(handler(server, guarded))
	}
}
