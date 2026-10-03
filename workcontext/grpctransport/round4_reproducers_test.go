package grpctransport

import (
	"context"
	"errors"
	"fmt"
	"io"
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
func clientSaw(t *testing.T, connection *grpc.ClientConn) (header metadata.MD, trailer metadata.MD, err error) {
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
	}
	if errors.Is(recvErr, io.EOF) {
		recvErr = nil
	}
	// Header() blocks until headers arrive or the stream ends, so it is read
	// after the receive loop has finished.
	header, _ = stream.Header()
	return header, stream.Trailer(), recvErr
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

	header, trailer, err := clientSaw(t, connection)
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

	header, _, err := clientSaw(t, connection)
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

	header, trailer, err := clientSaw(t, connection)
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

	header, trailer, err := clientSaw(t, connection)
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

	_, _, err := clientSaw(t, connection)
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

	_, _, err := clientSaw(t, connection)
	require.Error(t, err)
	require.Equal(t, codes.Unauthenticated, status.Code(err),
		"a client cannot tell 'mint again' from 'the server broke' out of codes.Unknown")
}

// Whether a method is guarded is a property of the METHOD. A guardFor that
// answers (nil, nil) for a method it guarded before is refused rather than
// handing that request the raw stream.
func TestGuardingIsDecidedPerMethodAndNotPerRequest(t *testing.T) {
	authority := &revocableGuard{}
	var calls int
	var mu sync.Mutex
	interceptor := StreamServerInterceptor(
		func(context.Context, *grpc.StreamServerInfo) (*workcontext.StreamGuard, error) {
			mu.Lock()
			defer mu.Unlock()
			calls++
			if calls == 1 {
				return authority.guard(t), nil
			}
			// The optional-carrier shape: this request happens to have found
			// no capability, so the handler would get the unguarded stream.
			return nil, nil
		})

	connection := serveWith(t, interceptor, func(stream grpc.ServerStream) error {
		if _, ok := stream.(*GuardedServerStream); !ok {
			return errors.New("the handler was handed a stream that is not the wrapper")
		}
		return nil
	})

	_, _, first := clientSaw(t, connection)
	require.NoError(t, first, "the first request establishes the method as guarded")

	_, _, second := clientSaw(t, connection)
	require.Error(t, second)
	require.Equal(t, codes.Internal, status.Code(second))
	require.Contains(t, status.Convert(second).Message(), "property of the method")
}
