package grpctransport

import (
	"context"
	"errors"
	"fmt"
	"io"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/codefly-dev/sdk-go/workcontext"
)

// The round-four review's two blockers, as the bufconn probes it could not run.
//
// Both were predicted statically and both reproduced on the first attempt at
// the previous revision (ffaa5c0):
//
//	PROBE 1  header=[secret]  — a header queued with SetHeader under authority
//	         reached the client after Finish had refused.
//	PROBE 2  transport stream in ctx: true; SendHeader err=<nil>;
//	         header=[leaked] trailer=[leaked] — the package-level functions on
//	         stream.Context() delivered both, with the guard revoked for the
//	         whole call and NOT ONE re-check performed.
//
// They live here rather than beside the happy-path tests because what they
// assert is about gRPC's behaviour, not the wrapper's: only a real client can
// say what left.

// clientSaw runs the stream to completion and reports the headers AND the
// trailers the client received, which is the thing the previous round's tests
// never read.
func clientSaw(t *testing.T, connection *grpc.ClientConn) (received int, header metadata.MD, trailer metadata.MD, err error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	stream, streamErr := connection.NewStream(ctx,
		&grpc.StreamDesc{StreamName: "Emit", ServerStreams: true}, streamMethod)
	require.NoError(t, streamErr)
	require.NoError(t, stream.CloseSend())
	var recvErr error
	for {
		recvErr = stream.RecvMsg(&wrapperspb.StringValue{})
		if recvErr != nil {
			break
		}
		// COUNTED, and that is the whole of a review finding: this helper
		// dropped every message it received, so the one test that cared wrote
		// `received := 0` beside it and asserted require.Zero on its own
		// literal. A tautology in the place where "no message left under
		// revoked authority" was supposed to be established.
		received++
	}
	if errors.Is(recvErr, io.EOF) {
		recvErr = nil
	}
	// Header() blocks until headers arrive or the stream ends, so it is read
	// after the receive loop has finished.
	header, _ = stream.Header()
	return received, header, stream.Trailer(), recvErr
}

// handlerFaults collects what a handler observed, so nothing calls require on
// the server's goroutine.
//
// The review was right about this: require.IsType inside the handler calls
// FailNow off the test goroutine, which Go's testing package documents as
// undefined — it stops that goroutine and the test keeps going, so a failed
// assertion in a handler could pass the test.
type handlerFaults struct {
	mu     sync.Mutex
	faults []string
}

func (f *handlerFaults) record(format string, args ...any) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.faults = append(f.faults, fmt.Sprintf(format, args...))
}

func (f *handlerFaults) assert(t *testing.T) {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	require.Empty(t, f.faults, "the handler observed something it should not have")
}

// (1) A header QUEUED with SetHeader must not reach the client when authority
// is withdrawn before the handler returns.
//
// gRPC flushes a pending header frame from WriteStatus when the handler
// returns, which is after any revocation in between. The wrapper's comment
// used to argue the opposite — that only SendMsg and SendHeader flush, and
// both re-check. Measured: [secret] arrived.
func TestARealClientNeverReceivesAHeaderAuthorityWasWithdrawnFrom(t *testing.T) {
	authority := &revocableGuard{}
	faults := &handlerFaults{}
	connection := serveGuarded(t, authority.guard(t), func(stream grpc.ServerStream) error {
		if err := stream.SetHeader(metadata.Pairs("queued-header", "secret")); err != nil {
			faults.record("SetHeader under authority was refused: %v", err)
		}
		authority.revoked.Store(true)
		return nil
	})

	_, header, trailer, err := clientSaw(t, connection)
	faults.assert(t)
	require.Error(t, err, "a handler that completed under withdrawn authority must fail the RPC")
	require.Empty(t, header.Get("queued-header"),
		"the client received a header whose authority had been withdrawn")
	require.Empty(t, trailer.Get("queued-header"))
}

// And a queued header DOES arrive when authority holds all the way through, so
// holding it is not quietly dropping it.
func TestARealClientReceivesTheQueuedHeaderWhenAuthorityHolds(t *testing.T) {
	authority := &revocableGuard{}
	connection := serveGuarded(t, authority.guard(t), func(stream grpc.ServerStream) error {
		return stream.SetHeader(metadata.Pairs("queued-header", "fine"))
	})

	_, header, _, err := clientSaw(t, connection)
	require.NoError(t, err)
	require.Equal(t, []string{"fine"}, header.Get("queued-header"))
}

// (2) The package-level grpc.SetHeader, grpc.SendHeader and grpc.SetTrailer,
// called on the stream's context, must route through the checks.
//
// They resolve a grpc.ServerTransportStream out of the context and write to
// the transport. Measured at the previous revision: with the guard revoked for
// the whole call, grpc.SendHeader returned nil, and both the header and the
// trailer reached the client having been checked zero times.
func TestTheContextRouteCannotWriteUnderRevokedAuthority(t *testing.T) {
	authority := &revocableGuard{}
	authority.revoked.Store(true)
	faults := &handlerFaults{}
	connection := serveGuarded(t, authority.guard(t), func(stream grpc.ServerStream) error {
		ctx := stream.Context()
		if grpc.ServerTransportStreamFromContext(ctx) == nil {
			faults.record("no transport stream in the handler's context: the probe proves nothing")
		}
		if err := grpc.SetTrailer(ctx, metadata.Pairs("ctx-trailer", "leaked")); err == nil {
			faults.record("grpc.SetTrailer was accepted under revoked authority")
		}
		if err := grpc.SetHeader(ctx, metadata.Pairs("ctx-set-header", "leaked")); err == nil {
			faults.record("grpc.SetHeader was accepted under revoked authority")
		}
		if err := grpc.SendHeader(ctx, metadata.Pairs("ctx-header", "leaked")); err == nil {
			faults.record("grpc.SendHeader was accepted under revoked authority")
		}
		return nil
	})

	_, header, trailer, err := clientSaw(t, connection)
	faults.assert(t)
	require.Error(t, err)
	require.Empty(t, trailer.Get("ctx-trailer"), "a context-route trailer reached the client")
	require.Empty(t, header.Get("ctx-header"), "a context-route header reached the client")
	require.Empty(t, header.Get("ctx-set-header"), "a context-route queued header reached the client")
	require.Positive(t, int(authority.checks.Load()),
		"the context route performed no re-check at all")
}

// The context route works normally under authority — it is guarded, not
// disabled. A handler using the package-level functions is an ordinary handler.
func TestTheContextRouteDeliversUnderAuthority(t *testing.T) {
	authority := &revocableGuard{}
	faults := &handlerFaults{}
	connection := serveGuarded(t, authority.guard(t), func(stream grpc.ServerStream) error {
		ctx := stream.Context()
		if err := grpc.SetHeader(ctx, metadata.Pairs("ctx-header", "ok")); err != nil {
			faults.record("grpc.SetHeader under authority: %v", err)
		}
		if err := grpc.SetTrailer(ctx, metadata.Pairs("ctx-trailer", "ok")); err != nil {
			faults.record("grpc.SetTrailer under authority: %v", err)
		}
		return stream.SendMsg(wrapperspb.String("one"))
	})

	_, header, trailer, err := clientSaw(t, connection)
	faults.assert(t)
	require.NoError(t, err)
	require.Equal(t, []string{"ok"}, header.Get("ctx-header"))
	require.Equal(t, []string{"ok"}, trailer.Get("ctx-trailer"))
}

// grpc.Method still answers, so replacing the context's transport stream did
// not take away the one thing it answers that is not a write.
func TestTheGuardedContextStillAnswersTheMethod(t *testing.T) {
	authority := &revocableGuard{}
	observed := make(chan string, 1)
	connection := serveGuarded(t, authority.guard(t), func(stream grpc.ServerStream) error {
		method, _ := grpc.Method(stream.Context())
		observed <- method
		return nil
	})

	_, _, _, err := clientSaw(t, connection)
	require.NoError(t, err)
	require.Equal(t, streamMethod, <-observed)
}

// A revoked stream reaches the client as codes.Unauthenticated, which is the
// code a client answers by minting again — not codes.Unknown, which is what a
// plain Go error returned from an interceptor becomes.
func TestRevocationReachesTheClientAsUnauthenticated(t *testing.T) {
	authority := &revocableGuard{}
	authority.revoked.Store(true)
	connection := serveGuarded(t, authority.guard(t), func(stream grpc.ServerStream) error {
		return stream.SendMsg(wrapperspb.String("never"))
	})

	_, _, _, err := clientSaw(t, connection)
	require.Error(t, err)
	require.Equal(t, codes.Unauthenticated, status.Code(err),
		"a client cannot tell 'mint again' from 'the server broke' out of codes.Unknown")
}

// N-C: the capability-bearing method set is DECLARED, so a first request
// without a capability never gets the raw stream and never disables the method.
//
// The previous revision learned the set: guardFor was asked per request and the
// FIRST answer for a method was binding. That is trust on first use. If the
// first request to a capability-bearing method arrived without a capability — a
// client mid-deploy, a health probe, a retry that lost its metadata —
// guardFor answered (nil, nil), THAT request was handed the raw stream, the
// method was recorded unguarded, and every later legitimate request was
// refused codes.Internal until the process restarted. One early request both
// bypassed the guard and took the method down.
func TestAFirstRequestWithoutACapabilityNeitherBypassesNorDisablesTheMethod(t *testing.T) {
	var asked int
	var mu sync.Mutex
	var handedRaw bool
	interceptor := streamServerInterceptor(
		// DECLARED: this method carries a capability, whatever any one request
		// looks like.
		[]string{streamMethod},
		func(context.Context, *grpc.StreamServerInfo) (*workcontext.StreamGuard, error) {
			mu.Lock()
			defer mu.Unlock()
			asked++
			if asked == 1 {
				// The first request has no capability.
				return nil, nil
			}
			return (&revocableGuard{}).guard(t), nil
		})

	connection := serveWith(t, interceptor, func(stream grpc.ServerStream) error {
		if _, ok := stream.(*GuardedServerStream); !ok {
			mu.Lock()
			handedRaw = true
			mu.Unlock()
		}
		return nil
	})

	// The first request is REFUSED rather than handed the raw stream.
	_, _, _, first := clientSaw(t, connection)
	require.Error(t, first, "a capability-bearing method ran with no guard")
	require.Equal(t, codes.Unauthenticated, status.Code(first))
	mu.Lock()
	require.False(t, handedRaw, "the handler was handed the raw stream")
	mu.Unlock()

	// And the method still WORKS afterwards: nothing was learned, so nothing
	// is stuck. This is the half that used to be codes.Internal until restart.
	_, _, _, second := clientSaw(t, connection)
	require.NoError(t, second, "one early request without a capability disabled the method")
}

// The three survivors the layer-4 mutation pass found in this package: no test
// sent a header through SendHeader under revoked authority, SetTrailer after
// Finish could still append, and the shape test survives an Unwrap accessor.

// SendHeader is refused under revoked authority, and nothing reaches the
// client. The whole suite stayed green with SendHeader's re-check deleted,
// because every header test went through SetHeader.
func TestSendHeaderIsRefusedUnderRevokedAuthority(t *testing.T) {
	authority := &revocableGuard{}
	authority.revoked.Store(true)
	faults := &handlerFaults{}
	connection := serveGuarded(t, authority.guard(t), func(stream grpc.ServerStream) error {
		if err := stream.SendHeader(metadata.Pairs("sent-header", "leaked")); err == nil {
			faults.record("SendHeader was accepted under revoked authority")
		}
		return nil
	})

	_, header, _, err := clientSaw(t, connection)
	faults.assert(t)
	require.Error(t, err)
	require.Empty(t, header.Get("sent-header"))
	require.Positive(t, int(authority.checks.Load()), "SendHeader performed no re-check")
}

// A trailer set AFTER Finish is not appended, so it cannot ride out on a
// subsequent release. Past the last check there is nothing left to authorize
// against, and the wrapper says so rather than silently keeping it.
func TestATrailerSetAfterFinishIsRefused(t *testing.T) {
	guard, err := workcontext.NewStreamGuard(workcontext.StreamGuardOptions{
		Recheck: func(context.Context) error { return nil },
	})
	require.NoError(t, err)
	underlying := &recordingStream{ctx: context.Background()}
	guarded, err := Guard(underlying, guard)
	require.NoError(t, err)

	require.NoError(t, guarded.Finish(nil))
	released := underlying.trailers

	for range 3 {
		guarded.SetTrailer(metadata.Pairs("after-finish", "late"))
	}
	require.Equal(t, released, underlying.trailers,
		"a trailer set after the last check reached gRPC")

	// And the context route reports it rather than dropping it, because
	// grpc.SetTrailer has somewhere to put an error.
	require.Error(t, grpc.SetTrailer(guarded.Context(), metadata.Pairs("after-finish", "late")))
}

// The wrapper exposes no METHOD that returns the underlying stream either.
//
// The shape test checked fields and the interface's own methods, so it survived
// an `Unwrap() any` accessor — the embedded field with one more step. This
// asserts the property the shape test was reaching for: nothing on this type
// hands back something satisfying grpc.ServerStream, and nothing returns a
// bare `any`, which would carry the raw stream past every shape check.
func TestNoMethodOfTheWrapperReturnsTheRawStream(t *testing.T) {
	guard, err := workcontext.NewStreamGuard(workcontext.StreamGuardOptions{
		Recheck: func(context.Context) error { return nil },
	})
	require.NoError(t, err)
	underlying := &recordingStream{ctx: context.Background()}
	guarded, err := Guard(underlying, guard)
	require.NoError(t, err)

	streamInterface := reflect.TypeOf((*grpc.ServerStream)(nil)).Elem()
	wrapper := reflect.TypeOf(guarded)
	for index := range wrapper.NumMethod() {
		method := wrapper.Method(index)
		for result := range method.Type.NumOut() {
			out := method.Type.Out(result)
			if out == reflect.TypeOf((*error)(nil)).Elem() {
				continue
			}
			require.False(t, out.Implements(streamInterface),
				"%s returns %s, which satisfies grpc.ServerStream: that is the embedded field again",
				method.Name, out)
			if out.Kind() == reflect.Interface && out.NumMethod() == 0 {
				require.Failf(t, "an empty interface escapes the wrapper",
					"%s returns %s; an `any` result can carry the raw stream past every shape check",
					method.Name, out)
			}
		}
	}
}

// N-P: a Recheck that writes to the stream must get an ERROR, not a deadlock.
//
// Measured before the fix: a Recheck emitting an audit header with
// grpc.SetHeader(ctx, …) hung the handler FOREVER. The write resolved the
// wrapper out of the context, called SetHeader, which called recheck, which
// called BeforeSend — and BeforeSend holds the guard's mutex across the
// re-check, so the nested call blocked on a sync.Mutex its own goroutine held.
// SendMsg never returned.
//
// Releasing that mutex would turn the hang into unbounded recursion. A liveness
// check deciding whether the stream may emit must not emit, so the context it
// runs under refuses every write and names why.
func TestARecheckThatWritesToTheStreamIsRefusedRatherThanDeadlocking(t *testing.T) {
	var wrote error
	guard, err := workcontext.NewStreamGuard(workcontext.StreamGuardOptions{
		Recheck: func(ctx context.Context) error {
			wrote = grpc.SetHeader(ctx, metadata.Pairs("audited", "yes"))
			return nil
		},
	})
	require.NoError(t, err)
	guarded, err := Guard(&recordingStream{ctx: context.Background()}, guard)
	require.NoError(t, err)

	sent := make(chan error, 1)
	go func() { sent <- guarded.SendMsg("x") }()
	select {
	case sendErr := <-sent:
		require.NoError(t, sendErr, "the send itself is fine; the write inside the re-check is not")
	case <-time.After(10 * time.Second):
		t.Fatal("SendMsg never returned: the re-check re-entered BeforeSend under its own mutex")
	}

	require.ErrorIs(t, wrote, workcontext.ErrInvalid)
	require.ErrorContains(t, wrote, "must not write to the stream whose liveness it is deciding")

	// And the method is still readable from inside a re-check, because reading
	// is not writing.
	var seen string
	readOnly, err := workcontext.NewStreamGuard(workcontext.StreamGuardOptions{
		Recheck: func(ctx context.Context) error {
			seen, _ = grpc.Method(ctx)
			return nil
		},
	})
	require.NoError(t, err)
	reader, err := Guard(&recordingStream{ctx: context.Background()}, readOnly)
	require.NoError(t, err)
	require.NoError(t, reader.SendMsg("x"))
	require.Empty(t, seen, "a bare recordingStream carries no transport stream, so there is no method to read")
}

// Round five's two survivors in this package.

// The UNAVAILABLE mapping (guarded_stream.go). "Mutation-verified both ways"
// did not hold for this branch: a termination whose re-check SOURCE failed —
// neither revoked nor replayed nor malformed, just unreachable — must reach the
// client as codes.Unavailable, because that is the one case where retrying the
// same capability is the right answer. Mapped to Unknown, a client cannot tell
// it from a server bug.
func TestARecheckSourceFailureReachesTheClientAsUnavailable(t *testing.T) {
	unreachable := errors.New("the seal source did not answer")
	guard, err := workcontext.NewStreamGuard(workcontext.StreamGuardOptions{
		Recheck: func(context.Context) error { return unreachable },
	})
	require.NoError(t, err)

	connection := serveWith(t, streamServerInterceptor(
		[]string{streamMethod},
		func(context.Context, *grpc.StreamServerInfo) (*workcontext.StreamGuard, error) {
			return guard, nil
		}), func(stream grpc.ServerStream) error {
		return stream.SendMsg(wrapperspb.String("never"))
	})

	_, _, _, err = clientSaw(t, connection)
	require.Error(t, err)
	require.Equal(t, codes.Unavailable, status.Code(err),
		"a re-check source that could not be reached is the one retryable termination")
}

// SendHeader must CARRY what SetHeader queued, not drop it. The wrapper holds
// queued headers, so a SendHeader that sent only its own argument would
// silently discard everything a handler had set — and no test noticed.
func TestSendHeaderCarriesWhatSetHeaderQueued(t *testing.T) {
	authority := &revocableGuard{}
	faults := &handlerFaults{}
	connection := serveGuarded(t, authority.guard(t), func(stream grpc.ServerStream) error {
		if err := stream.SetHeader(metadata.Pairs("queued", "one")); err != nil {
			faults.record("SetHeader: %v", err)
		}
		if err := stream.SetHeader(metadata.Pairs("queued-two", "two")); err != nil {
			faults.record("SetHeader: %v", err)
		}
		// SendHeader flushes, and must include both of the above.
		if err := stream.SendHeader(metadata.Pairs("sent", "three")); err != nil {
			faults.record("SendHeader: %v", err)
		}
		return nil
	})

	_, header, _, err := clientSaw(t, connection)
	faults.assert(t)
	require.NoError(t, err)
	require.Equal(t, []string{"one"}, header.Get("queued"),
		"SendHeader dropped a header SetHeader had queued")
	require.Equal(t, []string{"two"}, header.Get("queued-two"))
	require.Equal(t, []string{"three"}, header.Get("sent"))
}
