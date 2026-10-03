package grpctransport

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

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
// # Three routes out of a stream, not one
//
// Each of the following was a live bypass, and each was found after the
// previous one was fixed. They are listed together because the lesson is that
// "the handler calls our method" was never the only way metadata leaves.
//
//  1. THE EMBEDDED FIELD. This type used to embed grpc.ServerStream as a
//     public field, so a handler could write
//     `stream.(*GuardedServerStream).ServerStream` and send with no check at
//     all. The underlying stream is private now and every interface method is
//     forwarded by hand.
//
//  2. WHEN gRPC SENDS. gRPC sends trailers, and flushes any pending header,
//     when the HANDLER RETURNS — not when SetTrailer or SetHeader is called.
//     Checking at queue time and handing the metadata straight to gRPC meant a
//     handler could queue, have authority revoked, return, and the client
//     received it. Measured over bufconn at the previous revision: a header
//     queued under authority arrived at the client after Finish had refused.
//     So headers AND trailers are held in this wrapper and released by Finish.
//
//  3. THE CONTEXT. grpc.SetHeader, grpc.SendHeader and grpc.SetTrailer are
//     package-level functions that resolve a grpc.ServerTransportStream out of
//     the context and write to the TRANSPORT stream. They never touch this
//     type. Measured over bufconn at the previous revision: with the guard
//     revoked for the whole call and zero re-checks performed, both a
//     context-route header and a context-route trailer reached the client. So
//     this wrapper owns the transport stream in the context it hands out, and
//     those three functions route back through the checks.
//
// What remains deliberately unguarded: a handler that already holds the
// ORIGINAL stream from outside the interceptor, and SendHeader's own flush —
// once a header frame is on the wire no later revocation recalls it, which is
// what SendHeader means.
type GuardedServerStream struct {
	stream grpc.ServerStream
	guard  *workcontext.StreamGuard
	// ctx carries THIS wrapper as the context's transport stream, so the
	// package-level grpc.SetHeader/SendHeader/SetTrailer reach the checks
	// instead of reaching around them.
	ctx context.Context

	mu       sync.Mutex
	headers  metadata.MD
	trailers metadata.MD
	flushed  bool
	finished bool
}

// Guard wraps a server stream so everything it sends is preceded by a live
// re-check. A nil guard is refused rather than treated as "no guarding
// wanted": a wrapper that silently did nothing would be worse than no wrapper,
// because the call site would read as guarded.
//
// A caller using Guard directly MUST call Finish when its handler is done, or
// the headers and trailers it set are never sent, and MUST pass this wrapper's
// Context to anything that writes metadata. StreamServerInterceptor does both,
// which is the reason to prefer it — and the reason the README's recipe is the
// interceptor and not this.
func Guard(stream grpc.ServerStream, guard *workcontext.StreamGuard) (*GuardedServerStream, error) {
	if stream == nil {
		return nil, fmt.Errorf("%w: no stream to guard", workcontext.ErrInvalid)
	}
	if guard == nil {
		return nil, fmt.Errorf("%w: no stream guard", workcontext.ErrInvalid)
	}
	guarded := &GuardedServerStream{
		stream:   stream,
		guard:    guard,
		headers:  metadata.MD{},
		trailers: metadata.MD{},
	}
	// The handler's context carries this wrapper as its transport stream. The
	// inherited one is kept for Method(), which is the one thing a transport
	// stream answers that is not a write.
	guarded.ctx = grpc.NewContextWithServerTransportStream(
		stream.Context(),
		&guardedTransportStream{
			guarded:   guarded,
			inherited: grpc.ServerTransportStreamFromContext(stream.Context()),
		},
	)
	return guarded, nil
}

// Context is the stream's context with this wrapper installed as its transport
// stream. Reading it sends nothing, so it is not itself guarded — but what a
// caller can reach THROUGH it is.
func (s *GuardedServerStream) Context() context.Context {
	if s == nil || s.stream == nil {
		return context.Background()
	}
	if s.ctx != nil {
		return s.ctx
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
// Headers held by SetHeader are released onto the real stream first, under this
// same check, because a message flushes them anyway and they must not reach the
// wire unchecked.
//
// The error is the guard's, wrapped, so a caller can tell a terminated stream
// from a transport failure — and ErrStreamTerminated is sticky, so a handler
// that loops past the first refusal keeps being refused rather than getting a
// second chance to emit.
func (s *GuardedServerStream) SendMsg(message any) error {
	if err := s.recheck(); err != nil {
		return err
	}
	if err := s.releaseHeaders(); err != nil {
		return err
	}
	return s.stream.SendMsg(message)
}

// SendHeader re-checks and sends immediately, together with anything SetHeader
// had queued. gRPC flushes on this call, so the check at this moment is the
// check that matters and no later revocation can recall the frame.
func (s *GuardedServerStream) SendHeader(headers metadata.MD) error {
	if err := s.recheck(); err != nil {
		return err
	}
	s.mu.Lock()
	if s.finished {
		s.mu.Unlock()
		return fmt.Errorf("%w: the stream is finished", workcontext.ErrInvalid)
	}
	pending := s.headers
	s.headers = metadata.MD{}
	s.flushed = true
	s.mu.Unlock()
	merged := metadata.Join(pending, headers)
	return s.stream.SendHeader(merged)
}

// SetHeader re-checks and HOLDS the metadata in this wrapper.
//
// It used to hand the metadata straight to gRPC on the strength of "a queued
// header is flushed by the first SendMsg or SendHeader, both of which
// re-check". That was false, and measured so: when a handler returns without
// having sent, gRPC's WriteStatus writes the pending header frame before the
// status, so a header queued under authority reached the client after Finish
// had already refused. Held here, it reaches gRPC only through a check.
func (s *GuardedServerStream) SetHeader(headers metadata.MD) error {
	if err := s.recheck(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.finished {
		return fmt.Errorf("%w: the stream is finished", workcontext.ErrInvalid)
	}
	if s.flushed {
		// gRPC's own contract: headers are sent once. Forward so the caller
		// gets gRPC's answer rather than a silent hold that never leaves.
		return s.stream.SetHeader(headers)
	}
	for key, values := range headers {
		s.headers[key] = append(s.headers[key], values...)
	}
	return nil
}

// SetTrailer re-checks and HOLDS the metadata in this wrapper. Nothing reaches
// gRPC until Finish releases it, because gRPC would otherwise send it when the
// handler returns — which is after any revocation that happened in between.
func (s *GuardedServerStream) SetTrailer(trailer metadata.MD) {
	_ = s.setTrailer(trailer)
}

// setTrailer is SetTrailer with the refusal kept, for the context route: the
// package-level grpc.SetTrailer returns an error, so there a refusal can be
// reported instead of being dropped on the floor by an interface that has
// nowhere to put it.
func (s *GuardedServerStream) setTrailer(trailer metadata.MD) error {
	if s == nil {
		return fmt.Errorf("%w: unguarded stream", workcontext.ErrInvalid)
	}
	if err := s.recheck(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.finished {
		// Past the last check there is nothing left to authorize against.
		return fmt.Errorf("%w: the stream is finished", workcontext.ErrInvalid)
	}
	for key, values := range trailer {
		s.trailers[key] = append(s.trailers[key], values...)
	}
	return nil
}

// Finish performs the LAST re-check and releases the headers and trailers the
// handler set, or discards them. It is called once, after the handler returns,
// and StreamServerInterceptor calls it.
//
// It returns the handler's own error unchanged when authority still holds, and
// a gRPC status when it does not — so a handler that completed under authority
// that has since been withdrawn fails the RPC rather than succeeding with
// metadata nobody authorized.
func (s *GuardedServerStream) Finish(handlerErr error) error {
	if s == nil {
		return handlerErr
	}
	err := s.recheck()
	s.mu.Lock()
	pendingHeaders := s.headers
	pendingTrailers := s.trailers
	s.headers = metadata.MD{}
	s.trailers = metadata.MD{}
	flushed := s.flushed
	s.finished = true
	s.mu.Unlock()
	if err != nil {
		// Discarded, both of them. Metadata describes the result of work the
		// authority has since been withdrawn from, and it is the last thing to
		// leave.
		return statusFor(err)
	}
	if len(pendingHeaders) > 0 && !flushed {
		_ = s.stream.SetHeader(pendingHeaders)
	}
	if len(pendingTrailers) > 0 {
		s.stream.SetTrailer(pendingTrailers)
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

// releaseHeaders hands held headers to the real stream. The caller has just
// re-checked, and a SendMsg flushes whatever is queued there, so this is the
// one moment they may cross.
func (s *GuardedServerStream) releaseHeaders() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.flushed || len(s.headers) == 0 {
		return nil
	}
	pending := s.headers
	s.headers = metadata.MD{}
	s.flushed = true
	return s.stream.SetHeader(pending)
}

// guardedTransportStream is what the handler's context answers with, so the
// package-level grpc.SetHeader, grpc.SendHeader and grpc.SetTrailer write
// through the wrapper's checks instead of straight to the transport.
//
// It exists because those three functions were a complete bypass: they take a
// context, resolve the transport stream out of it, and write. Measured over
// bufconn with the guard revoked for the whole call: a header and a trailer
// both reached the client, and the guard was never asked.
type guardedTransportStream struct {
	guarded *GuardedServerStream
	// inherited is gRPC's own transport stream, kept only for Method. It is
	// never written to: every write goes through guarded.
	inherited grpc.ServerTransportStream
}

// Method is the only question a transport stream answers that is not a write,
// so it is the only one forwarded to gRPC's own.
func (t *guardedTransportStream) Method() string {
	if t.inherited == nil {
		return ""
	}
	return t.inherited.Method()
}

func (t *guardedTransportStream) SetHeader(md metadata.MD) error {
	return t.guarded.SetHeader(md)
}

func (t *guardedTransportStream) SendHeader(md metadata.MD) error {
	return t.guarded.SendHeader(md)
}

func (t *guardedTransportStream) SetTrailer(md metadata.MD) error {
	return t.guarded.setTrailer(md)
}

// statusFor turns a guard refusal into a gRPC status a client can act on.
//
// Returning the plain Go error made every refusal arrive as codes.Unknown with
// internal text in the message, so a receiver could not tell "mint again" from
// "the server broke" — which is the whole decision the README's table asks a
// caller to make. The sentinel is what carries that, so it is what the code is
// read off.
func statusFor(err error) error {
	code := codes.Unknown
	switch {
	case err == nil:
		return nil
	case errors.Is(err, workcontext.ErrRevoked),
		errors.Is(err, workcontext.ErrReplayed),
		errors.Is(err, workcontext.ErrInvalid),
		errors.Is(err, workcontext.ErrNotACoreToken):
		// The capability no longer authenticates. Unauthenticated is the code
		// a client answers by presenting a new one, which is exactly the
		// README's "mint again".
		code = codes.Unauthenticated
	case errors.Is(err, context.Canceled):
		code = codes.Canceled
	case errors.Is(err, context.DeadlineExceeded):
		code = codes.DeadlineExceeded
	case errors.Is(err, workcontext.ErrStreamTerminated):
		// Terminated for a reason that is not one of core's sentinels: the
		// re-check's own source failed. Retryable at the far end, which
		// Unavailable is how to say.
		code = codes.Unavailable
	default:
		return err
	}
	return statusError{err: err, code: code}
}

// statusError carries a gRPC code to the wire AND keeps the sentinel chain for
// the process that produced it.
//
// status.Error would do the first and lose the second: it builds a fresh error
// with the text flattened in, so errors.Is(err, ErrStreamTerminated) in the
// server's own code — including its tests — stops being true the moment a code
// is attached. grpc-go reads the status off any error implementing
// GRPCStatus(), so implementing that beside Unwrap keeps both.
type statusError struct {
	err  error
	code codes.Code
}

func (e statusError) Error() string { return e.err.Error() }

func (e statusError) Unwrap() error { return e.err }

// GRPCStatus is what grpc-go reads the code and message off.
func (e statusError) GRPCStatus() *status.Status {
	return status.New(e.code, e.err.Error())
}

// StreamServerInterceptor guards every stream a server opens, so enforcement is
// WIRING rather than something each handler author remembers.
//
// Guard on its own leaves the original stream in the caller's scope, so the
// rule held wherever somebody thought of it. An interceptor is installed once,
// at the server, and the handler receives a stream it cannot write around: the
// unguarded one never reaches it, the wrapper does not expose it, and the
// context it hands out routes the package-level metadata functions back through
// the checks.
//
// It also calls Finish, which is where the handler's held headers and trailers
// are re-checked and released. A handler that returns successfully under
// authority that was withdrawn while it ran fails the RPC.
//
// guardFor builds the guard for one stream, from whatever the server
// established when the stream opened: typically the capability it verified, so
// the re-check is workcontext.RecheckWith(verifier, verified). Returning a nil
// guard with a nil error means this METHOD carries no capability and needs
// none.
//
// # Unguarded is a property of a method, not of a request
//
// That decision is remembered per info.FullMethod and the FIRST answer is
// binding: a later disagreement about the same method refuses the stream. A
// per-request (nil, nil) is the optional-carrier shape this module deleted —
// "guarded wherever the callback felt like it", where one buggy branch, or one
// request whose own metadata was missing, hands a handler the unguarded stream.
// Whether a method is capability-bearing is static; if a server needs it to
// vary, that is two methods.
func StreamServerInterceptor(
	guardFor func(ctx context.Context, info *grpc.StreamServerInfo) (*workcontext.StreamGuard, error),
) grpc.StreamServerInterceptor {
	var (
		mu      sync.Mutex
		decided = map[string]bool{}
	)
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
			return statusFor(err)
		}
		method := ""
		if info != nil {
			method = info.FullMethod
		}
		mu.Lock()
		wasGuarded, seen := decided[method]
		if !seen {
			decided[method] = guard != nil
		}
		mu.Unlock()
		if seen && wasGuarded != (guard != nil) {
			// The method's own answer changed under us. Refusing is the only
			// safe reading: if it was guarded once it is capability-bearing,
			// and if it was not, something now thinks it is.
			return status.Errorf(codes.Internal,
				"%s: whether this method is Work Context guarded changed between requests; that is a property of the method",
				method,
			)
		}
		if guard == nil {
			// Explicitly unguarded, for this METHOD, by the server's own
			// decision, at the server rather than inside a handler.
			return handler(server, stream)
		}
		guarded, err := Guard(stream, guard)
		if err != nil {
			return err
		}
		return guarded.Finish(handler(server, guarded))
	}
}
