package grpctransport

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"sync/atomic"

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
// structural, and streamServerInterceptor makes the wrapping structural too.
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
//
// # What does not work inside a guarded stream
//
// grpc.SetSendCompressor and grpc.ClientSupportedCompressors type-assert the
// context's transport stream to gRPC's own unexported implementation, so they
// FAIL here rather than being guarded. That is a real limitation and not a
// safety property: nothing leaks, a handler that needs per-call compression
// cannot have it. Fixing it means implementing an interface gRPC does not
// export, so it is written down instead.
type GuardedServerStream struct {
	stream grpc.ServerStream
	guard  *workcontext.StreamGuard
	// ctx carries THIS wrapper as the context's transport stream, so the
	// package-level grpc.SetHeader/SendHeader/SetTrailer reach the checks
	// instead of reaching around them.
	ctx context.Context

	// transport is this wrapper as the context's transport stream, kept so the
	// re-check's own context can answer the method without being able to write.
	transport *guardedTransportStream

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
// Context to anything that writes metadata. streamServerInterceptor does both,
// which is the reason to prefer it — and the reason the README's recipe is the
// interceptor and not this.
func Guard(stream grpc.ServerStream, guard *workcontext.StreamGuard) (*GuardedServerStream, error) {
	if stream == nil {
		return nil, fmt.Errorf("%w: no stream to guard", errStreamMisuse)
	}
	if guard == nil {
		return nil, fmt.Errorf("%w: no stream guard", errStreamMisuse)
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
	guarded.transport = &guardedTransportStream{
		guarded:   guarded,
		inherited: grpc.ServerTransportStreamFromContext(stream.Context()),
	}
	guarded.ctx = grpc.NewContextWithServerTransportStream(stream.Context(), guarded.transport)
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
		return fmt.Errorf("%w: unguarded stream", errStreamMisuse)
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
		return fmt.Errorf("%w: the stream is finished", errStreamMisuse)
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
		return fmt.Errorf("%w: the stream is finished", errStreamMisuse)
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
		return fmt.Errorf("%w: unguarded stream", errStreamMisuse)
	}
	if err := s.recheck(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.finished {
		// Past the last check there is nothing left to authorize against.
		return fmt.Errorf("%w: the stream is finished", errStreamMisuse)
	}
	for key, values := range trailer {
		s.trailers[key] = append(s.trailers[key], values...)
	}
	return nil
}

// Finish performs the LAST re-check and releases the headers and trailers the
// handler set, or discards them. It is called once, after the handler returns,
// and streamServerInterceptor calls it.
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
		return fmt.Errorf("%w: unguarded stream", errStreamMisuse)
	}
	// THE RE-CHECK'S CONTEXT REFUSES WRITES, and that is what stops a
	// deadlock rather than a convention asking people not to.
	//
	// Measured: a Recheck that emitted an audit header with
	// grpc.SetHeader(ctx, …) hung the handler FOREVER. The write resolved this
	// wrapper out of the context, called SetHeader, which called recheck,
	// which called BeforeSend — and BeforeSend holds the guard's mutex across
	// the re-check, so the nested call blocked on a sync.Mutex its own
	// goroutine held. SendMsg never returned.
	//
	// Releasing that mutex would turn the hang into unbounded recursion, which
	// is not better. The honest fix is that a liveness check must not write to
	// the stream whose liveness it is deciding — that is circular — so the
	// context it runs under answers every write with a refusal naming why.
	return s.guard.BeforeSend(grpc.NewContextWithServerTransportStream(
		s.Context(), refusingTransportStream{method: s.method()},
	))
}

// method is the full method name, for the refusing transport stream's answer.
func (s *GuardedServerStream) method() string {
	if s == nil || s.transport == nil {
		return ""
	}
	return s.transport.Method()
}

// refusingTransportStream is what a re-check's context answers with: it reads
// the method and refuses every write.
//
// A re-check deciding whether the stream may still emit must not emit, and a
// re-check that tries gets an error saying so instead of a deadlock.
type refusingTransportStream struct{ method string }

func (t refusingTransportStream) Method() string { return t.method }

func (t refusingTransportStream) SetHeader(metadata.MD) error { return errRecheckMustNotWrite }

func (t refusingTransportStream) SendHeader(metadata.MD) error { return errRecheckMustNotWrite }

func (t refusingTransportStream) SetTrailer(metadata.MD) error { return errRecheckMustNotWrite }

var errRecheckMustNotWrite = fmt.Errorf(
	"%w: a Work Context liveness re-check must not write to the stream whose liveness it is deciding",
	errStreamMisuse,
)

// errStreamMisuse is THIS PACKAGE'S OWN misuse, distinct from a capability that
// does not authenticate, and it exists because the two were the same sentinel.
//
// core returns ErrInvalid for an EXPIRED capability (verify.go: "expired at
// …") and for one that is not yet valid. statusFor mapped ErrInvalid to
// codes.Internal on the argument that ErrInvalid also covers misuse — a nil
// guard, a finished stream, an unguarded wrapper — and that telling a client
// "mint again" about a server bug makes it loop. The argument is sound and the
// conclusion was still wrong, because it applied to the WRONG SIDE: expiry is
// not the rare malformed case, it is the ordinary mid-stream refusal on a
// stream that outlives its credential, and it is precisely the one a client
// answers by minting again. Measured: an expired capability arrived as
// Internal.
//
// The distinction the old comment said was unavailable was available all along.
// Every misuse error here is CONSTRUCTED here, so it can say so; what arrives
// from core says nothing extra and is read as a capability refusal. It still
// wraps ErrInvalid, so errors.Is(err, workcontext.ErrInvalid) is unchanged for
// anything that was relying on it.
var errStreamMisuse = fmt.Errorf("%w: guarded stream misuse", workcontext.ErrInvalid)

// releaseHeaders hands held headers to the real stream. The caller has just
// re-checked, and a SendMsg flushes whatever is queued there, so this is the
// one moment they may cross.
func (s *GuardedServerStream) releaseHeaders() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.flushed {
		return nil
	}
	// FLUSHED IS ABOUT THE SEND, NOT ABOUT THE QUEUE. Returning early when
	// nothing was queued left flushed false after a message had gone out —
	// and gRPC sends the header frame with the first message whether the
	// handler queued anything or not. So a SetHeader AFTER the first SendMsg
	// was held in this wrapper, found !flushed, and was handed to
	// stream.SetHeader by Finish, which gRPC ignores because the headers are
	// already on the wire. Measured over bufconn: SetHeader returned nil, the
	// header never reached the client, and the handler was told nothing.
	//
	// With flushed set here, that SetHeader forwards to gRPC instead and the
	// handler gets gRPC's own answer, which is the behaviour SetHeader
	// documents for a stream whose headers have been sent.
	s.flushed = true
	if len(s.headers) == 0 {
		return nil
	}
	pending := s.headers
	s.headers = metadata.MD{}
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
		errors.Is(err, workcontext.ErrNotACoreToken):
		// The capability no longer authenticates. Unauthenticated is the code
		// a client answers by presenting a new one, which is exactly the
		// README's "mint again".
		code = codes.Unauthenticated
	case errors.Is(err, errStreamMisuse):
		// THIS SERVER'S OWN MISUSE: a nil guard, a finished stream, an
		// unguarded wrapper, a re-check that tried to write. Internal, because
		// the client did nothing it can correct and minting again cannot fix a
		// server bug.
		//
		// Checked BEFORE ErrInvalid, which it wraps, so the order of these two
		// cases is the whole of the distinction.
		code = codes.Internal
	case errors.Is(err, workcontext.ErrInvalid):
		// A CAPABILITY THAT DOES NOT AUTHENTICATE, which from core includes
		// the ordinary one: expired. core answers an expired or not-yet-valid
		// capability with ErrInvalid, and a stream that outlives its
		// credential is the common case rather than a rare malformed one — so
		// Unauthenticated, which is the README's "mint again".
		//
		// The previous revision mapped every ErrInvalid to Internal to avoid
		// telling a client to mint again about a server bug. That cost was
		// real and this keeps it: the server's own misuse is a separate
		// sentinel above, constructed here, where the difference is known.
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

// streamServerInterceptor guards every stream a server opens, so enforcement is
// WIRING rather than something each handler author remembers.
//
// UNEXPORTED, and that is the last of the validate/enforce mismatch. It was
// public beside ValidateMethodSet, so the correct way to install this took two
// calls and only one of them was reachable from the type system: a consumer
// wiring the interceptor alone got a server where an undeclared stream reaches
// the handler unguarded, which is exactly what the README recipe did for
// several revisions. GuardStreams is the only way in now, and its Intercept
// refuses every stream until Validate has passed, so there is no public path
// that skips the check.
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
// # The capability-bearing method set is DECLARED, not learned
//
// capabilityBearing names every method whose streams carry a capability. It is
// fixed at construction, and guardFor is asked only about those — so a method
// in the set always gets a guard, and a method outside it never does.
//
// The previous revision learned it instead: guardFor was asked per request and
// the FIRST answer for a method was binding. That is trust on first use, and
// it fails the way trust on first use always fails. If the first request to a
// capability-bearing method arrived without a capability — a client mid-deploy,
// a health probe, a retry that lost its metadata — guardFor answered
// (nil, nil), THAT REQUEST GOT THE RAW STREAM, the method was recorded
// unguarded, and every later legitimate request was refused codes.Internal
// until the process restarted. One early request could both bypass the guard
// and disable the method.
//
// Declaring the set removes the learning. A server that cannot enumerate its
// capability-bearing methods does not know which of its streams carry
// authority, which is the thing to fix before installing an interceptor.
func streamServerInterceptor(
	capabilityBearing []string,
	guardFor func(ctx context.Context, info *grpc.StreamServerInfo) (*workcontext.StreamGuard, error),
) grpc.StreamServerInterceptor {
	guarded := make(map[string]bool, len(capabilityBearing))
	for _, method := range capabilityBearing {
		guarded[method] = true
	}
	return func(
		server any,
		stream grpc.ServerStream,
		info *grpc.StreamServerInfo,
		handler grpc.StreamHandler,
	) error {
		if guardFor == nil {
			return statusFor(fmt.Errorf(
				"%w: a stream interceptor needs a guard for each stream",
				errStreamMisuse,
			))
		}
		if len(guarded) == 0 {
			// AN EMPTY SET GUARDS NOTHING, so it refuses everything instead.
			//
			// streamServerInterceptor(nil, guardFor) read as "no method carries
			// a capability" and passed every stream through unguarded —
			// measured, a message delivered under revoked authority with zero
			// re-checks. An interceptor installed to enforce something, that
			// enforces nothing, is the worst available outcome: the wiring is
			// there, so nobody looks again.
			//
			// "Guard no method" is not a thing to say by omission. A server
			// with no capability-bearing streams installs no interceptor.
			// Through statusFor, like every other refusal here: returned bare,
			// a misconfiguration arrived as codes.Unknown with internal text,
			// which is the thing statusFor exists to stop.
			return statusFor(fmt.Errorf(
				"%w: a stream interceptor was installed with an empty capability-bearing "+
					"method set, which would guard nothing; name the methods, or install no "+
					"interceptor",
				errStreamMisuse,
			))
		}
		method := ""
		if info != nil {
			method = info.FullMethod
		}
		if !guarded[method] {
			// Declared as carrying no capability. The decision was made at
			// construction, where a reviewer can read it, rather than inferred
			// from whichever request happened to arrive first.
			//
			// A METHOD MISSING FROM THE SET IS STILL UNGUARDED HERE, and that
			// is what the set means — but a NAME that matches nothing the
			// server serves is a typo, not a decision, and this cannot tell
			// the difference from inside one request. ValidateMethodSet is how
			// a server catches it at startup, and the README says to call it.
			return handler(server, stream)
		}
		guard, err := guardFor(stream.Context(), info)
		if err != nil {
			return statusFor(err)
		}
		if guard == nil {
			// The method IS declared capability-bearing and guardFor produced
			// no guard. That is a refusal, not a passthrough: the previous
			// revision handed this request the raw stream.
			return status.Errorf(codes.Unauthenticated,
				"%s carries a Work Context and no guard could be built for this stream",
				method,
			)
		}
		guarded, err := Guard(stream, guard)
		if err != nil {
			return err
		}
		return guarded.Finish(handler(server, guarded))
	}
}

// ValidateMethodSet refuses a declared method name the server does not serve.
//
// It exists because a TYPO SILENTLY UNGUARDS A METHOD. The capability-bearing
// set is matched against grpc's full method name, so
// "/codefly.Streamer/Emmit" guards nothing at all and looks exactly like a
// method that was considered and declared — measured, a message delivered
// under revoked authority with zero re-checks, and nothing anywhere said so.
//
// The interceptor cannot catch this from inside a request: "this method is not
// in the set" and "this method is in the set under another spelling" are the
// same observation there. The server knows, so the server is asked, once, at
// startup:
//
//	streams := grpctransport.GuardStreams(bearing, guardFor)
//	server := grpc.NewServer(grpc.StreamInterceptor(streams.Intercept))
//	pb.RegisterStreamerServer(server, impl)
//	if err := streams.Validate(server.GetServiceInfo(), unguarded...); err != nil {
//	    return err
//	}
//
// Call it AFTER registering services and BEFORE Serve. It is a function rather
// than something the interceptor does because grpc hands the interceptor no
// server, and inventing a registration hook to reach one would be a bigger
// surface than a call a server makes.
func ValidateMethodSet(
	served map[string]grpc.ServiceInfo,
	capabilityBearing []string,
	deliberatelyUnguarded ...string,
) error {
	// STREAMING METHODS ONLY. Every grpc.MethodInfo went into this map,
	// ignoring IsClientStream and IsServerStream — so for a service with a
	// unary Read and a streaming Emit, declaring only "/Service/Read" passed
	// validation, produced a non-empty guarded set, and let Emit reach the raw
	// handler without guardFor ever being called. That is precisely the
	// installed-interceptor-that-guards-nothing configuration the empty-set
	// refusal exists to reject, reached by naming a method that cannot stream.
	known := map[string]bool{}
	unary := map[string]bool{}
	for service, info := range served {
		for _, method := range info.Methods {
			full := "/" + service + "/" + method.Name
			if method.IsClientStream || method.IsServerStream {
				known[full] = true
				continue
			}
			unary[full] = true
		}
	}
	var unknown, notStreaming []string
	for _, method := range capabilityBearing {
		switch {
		case known[method]:
		case unary[method]:
			notStreaming = append(notStreaming, method)
		default:
			unknown = append(unknown, method)
		}
	}

	// AND THE OTHER DIRECTION, which is the fail-open this validation did not
	// reach: a STREAMING method the server serves and the set does not name
	// gets the raw handler, with guardFor never called. The set was checked
	// against the server and the server was never checked against the set.
	//
	// Deny by default, as everywhere else here: every served streaming method
	// is either capability-bearing or NAMED as deliberately unguarded. A
	// stream that carries no authority is a real thing and this does not force
	// it to be guarded — it forces somebody to have said so, once, where a
	// reader sees it, instead of a method being unguarded because nobody
	// thought about it.
	declared := map[string]bool{}
	for _, method := range capabilityBearing {
		declared[method] = true
	}
	for _, method := range deliberatelyUnguarded {
		declared[method] = true
	}
	var unconsidered []string
	for method := range known {
		if !declared[method] {
			unconsidered = append(unconsidered, method)
		}
	}

	// ALL THREE AT ONCE. Returning on the first meant a server with both a
	// typo and an unconsidered stream was told about one of them, fixed it,
	// and met the other on the next run — and a test that asserted the typo's
	// message started failing because a different true finding came out first.
	sort.Strings(unknown)
	sort.Strings(notStreaming)
	sort.Strings(unconsidered)
	var problems []string
	if len(unknown) > 0 {
		problems = append(problems, fmt.Sprintf(
			"these methods are declared capability-bearing and this server does not serve "+
				"them: %v (a name that matches nothing guards nothing, and reads exactly like "+
				"a method that was considered)", unknown))
	}
	if len(notStreaming) > 0 {
		problems = append(problems, fmt.Sprintf(
			"these are declared capability-bearing for a STREAM interceptor and are unary on "+
				"this server: %v (a unary name makes the set non-empty and guards nothing)",
			notStreaming))
	}
	if len(unconsidered) > 0 {
		problems = append(problems, fmt.Sprintf(
			"this server serves these streaming methods and nothing names them: %v (a stream "+
				"missing from the set reaches the handler UNGUARDED; name it as "+
				"capability-bearing, or pass it as deliberately unguarded — the decision is "+
				"what has to exist, not the guard)", unconsidered))
	}
	if len(known) == 0 {
		problems = append(problems, "this server registers no streaming method at all, so a "+
			"stream interceptor has nothing to guard")
	}
	if len(capabilityBearing) == 0 {
		problems = append(problems, "no method is declared capability-bearing, so the "+
			"interceptor would guard nothing")
	}
	if len(problems) > 0 {
		return fmt.Errorf("%w: %s", errStreamMisuse, strings.Join(problems, "; "))
	}
	return nil
}

// GuardedStreams is the stream interceptor with its validation MADE MANDATORY.
//
// streamServerInterceptor plus ValidateMethodSet was correct and optional, and
// optional is the whole of the finding: the README recipe did not call the
// validation for several revisions, so a consumer following it kept the
// fail-open the validation exists to close, and nothing anywhere said so. A
// safety check a caller may skip is a safety check for whoever remembers it.
//
// So it is not skippable here. Intercept REFUSES EVERY STREAM until Validate
// has been called and passed:
//
//	streams := grpctransport.GuardStreams(bearing, guardFor)
//	server := grpc.NewServer(grpc.StreamInterceptor(streams.Intercept))
//	pb.RegisterStreamerServer(server, impl)
//	if err := streams.Validate(server.GetServiceInfo(), unguarded...); err != nil {
//	    return err
//	}
//	// only now does the server serve
//
// The ordering is forced by grpc itself — the interceptor is built before
// registration and the served method set exists only after it — so the one
// thing a library can do is make the gap LOUD instead of silent. A server that
// forgets refuses every stream on the first request, which is a failure found
// in the first test rather than a method that was never guarded.
//
// There is no longer a public way to build the interceptor WITHOUT this: the
// previous revision exported both and a consumer could wire the interceptor
// alone, which is the mismatch a review kept naming. One entry point, and the
// validation is part of it.
type GuardedStreams struct {
	bearing   []string
	intercept grpc.StreamServerInterceptor
	validated atomic.Bool
}

// GuardStreams builds the interceptor and the validation together.
func GuardStreams(
	capabilityBearing []string,
	guardFor func(ctx context.Context, info *grpc.StreamServerInfo) (*workcontext.StreamGuard, error),
) *GuardedStreams {
	return &GuardedStreams{
		bearing:   capabilityBearing,
		intercept: streamServerInterceptor(capabilityBearing, guardFor),
	}
}

// Validate asks the server what it serves and records that the answer held.
func (g *GuardedStreams) Validate(
	served map[string]grpc.ServiceInfo,
	deliberatelyUnguarded ...string,
) error {
	if err := ValidateMethodSet(served, g.bearing, deliberatelyUnguarded...); err != nil {
		return err
	}
	g.validated.Store(true)
	return nil
}

// Intercept is the interceptor, and it refuses every stream until Validate has
// passed.
func (g *GuardedStreams) Intercept(
	server any,
	stream grpc.ServerStream,
	info *grpc.StreamServerInfo,
	handler grpc.StreamHandler,
) error {
	if !g.validated.Load() {
		return statusFor(fmt.Errorf(
			"%w: this stream interceptor has not been validated against the server's method "+
				"set, so it does not know whether any stream it is not guarding was meant to "+
				"be unguarded. Call Validate(server.GetServiceInfo(), …) after registering "+
				"services and before Serve",
			errStreamMisuse,
		))
	}
	return g.intercept(server, stream, info, handler)
}
