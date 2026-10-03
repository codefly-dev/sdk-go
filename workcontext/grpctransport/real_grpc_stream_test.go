package grpctransport

import (
	"context"
	"net"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/codefly-dev/sdk-go/workcontext"
)

// A REAL gRPC server and client, over bufconn, with the interceptor installed.
//
// The dynamic review was right that a recording stream's call count is not
// evidence here: what a trailer does is decided by gRPC, not by the wrapper.
// gRPC sends trailers when the HANDLER RETURNS, so a handler could set one
// under authority, have authority revoked, return, and the client received it
// — through the ordinary guarded API, with the interceptor installed and
// nothing unwrapped. Only a real client can show that.

const (
	streamService = "codefly.test.Streamer"
	streamMethod  = "/codefly.test.Streamer/Emit"
)

// revocableGuard is a stream guard whose authority a test can withdraw at an
// exact moment, counting the checks it performs.
type revocableGuard struct {
	revoked atomic.Bool
	checks  atomic.Uint64
}

func (g *revocableGuard) guard(t *testing.T) *workcontext.StreamGuard {
	t.Helper()
	built, err := workcontext.NewStreamGuard(workcontext.StreamGuardOptions{
		Recheck: func(context.Context) error {
			g.checks.Add(1)
			if g.revoked.Load() {
				return workcontext.ErrRevoked
			}
			return nil
		},
	})
	require.NoError(t, err)
	return built
}

// serveGuarded stands up a real gRPC server whose one streaming method runs
// handler behind StreamServerInterceptor, and returns a client connection.
func serveGuarded(
	t *testing.T,
	guard *workcontext.StreamGuard,
	handler func(stream grpc.ServerStream) error,
) *grpc.ClientConn {
	t.Helper()
	return serveWith(t, StreamServerInterceptor(
		[]string{streamMethod},
		func(context.Context, *grpc.StreamServerInfo) (*workcontext.StreamGuard, error) {
			return guard, nil
		}), handler)
}

// serveWith is serveGuarded with the interceptor supplied, so a test can drive
// the interceptor's own decisions rather than only the wrapper's.
func serveWith(
	t *testing.T,
	interceptor grpc.StreamServerInterceptor,
	handler func(stream grpc.ServerStream) error,
) *grpc.ClientConn {
	t.Helper()
	listener := bufconn.Listen(1024 * 1024)
	server := grpc.NewServer(grpc.StreamInterceptor(interceptor))
	server.RegisterService(&grpc.ServiceDesc{
		ServiceName: streamService,
		HandlerType: (*any)(nil),
		Streams: []grpc.StreamDesc{{
			StreamName:    "Emit",
			ServerStreams: true,
			Handler: func(_ any, stream grpc.ServerStream) error {
				return handler(stream)
			},
		}},
	}, new(any))

	served := make(chan struct{})
	go func() {
		defer close(served)
		_ = server.Serve(listener)
	}()
	t.Cleanup(func() {
		server.Stop()
		<-served
	})

	connection, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return listener.DialContext(ctx)
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = connection.Close() })
	return connection
}

// drain runs the stream to completion and reports the message count, the
// trailer and the client's error.
//
// It delegates to clientSaw rather than opening the stream a second way. There
// were two helpers doing this, each with its own hand-built StreamDesc and its
// own receive loop, and they disagreed: this one counted messages and never
// read the header, clientSaw read the header and dropped the count. A test
// needing both got one of them and a local variable, which is how
// `received := 0; require.Zero(received)` came to stand where the file's
// central assertion belongs.
//
// WHAT THESE TESTS ESTABLISH, since the count was not the only claim running
// ahead of its evidence: the TRANSPORT's behaviour — what gRPC does with
// messages, headers and trailers when the guard refuses, with the interceptor
// installed and nothing unwrapped. The authority is a revocableGuard, a Recheck
// closure a test flips; so these do NOT establish that core's own refusals
// reach the guard, which is what TestWorkContextConformance drives through
// core's fixtures. And the stream is server-streaming with CloseSend called at
// once, so nothing here says anything about the client-streaming direction.
func drain(t *testing.T, connection *grpc.ClientConn) (received int, trailer metadata.MD, err error) {
	t.Helper()
	received, _, trailer, err = clientSaw(t, connection)
	return received, trailer, err
}

// (1) A trailer queued under authority must NOT reach the client when
// authority is withdrawn before the handler returns.
func TestARealClientNeverReceivesATrailerAuthorityWasWithdrawnFrom(t *testing.T) {
	authority := &revocableGuard{}
	connection := serveGuarded(t, authority.guard(t), func(stream grpc.ServerStream) error {
		// Queued under authority, which holds at this instant.
		stream.SetTrailer(metadata.Pairs("confidential-result", "tenant-data"))
		// And withdrawn before the handler returns, which is when gRPC would
		// otherwise send it.
		authority.revoked.Store(true)
		return nil
	})

	received, trailer, err := drain(t, connection)
	require.Error(t, err, "a handler that completed under withdrawn authority must fail the RPC")
	require.Zero(t, received)
	require.Empty(t, trailer.Get("confidential-result"),
		"the client received a trailer whose authority had been withdrawn")
}

// And the same trailer DOES arrive when authority holds all the way through,
// so the guard is not simply swallowing everything.
func TestARealClientReceivesTheTrailerWhenAuthorityHolds(t *testing.T) {
	authority := &revocableGuard{}
	connection := serveGuarded(t, authority.guard(t), func(stream grpc.ServerStream) error {
		stream.SetTrailer(metadata.Pairs("result", "ok"))
		return stream.SendMsg(wrapperspb.String("one"))
	})

	received, trailer, err := drain(t, connection)
	require.NoError(t, err)
	require.Equal(t, 1, received)
	require.Equal(t, []string{"ok"}, trailer.Get("result"))
	require.Positive(t, int(authority.checks.Load()))
}

// (2) A handler holding only the intercepted stream has no route to the raw
// one, so a message sent under revoked authority does not reach the client.
//
// The probe that found this recovered the embedded field and delivered
// `message under revoked authority` with ZERO checks. There is no embedded
// field now, so what the handler can attempt is the guarded API — and every
// attempt is refused.
func TestARealHandlerCannotSendUnderRevokedAuthority(t *testing.T) {
	authority := &revocableGuard{}
	authority.revoked.Store(true)

	var attempts, refusals int
	faults := &handlerFaults{}
	connection := serveGuarded(t, authority.guard(t), func(stream grpc.ServerStream) error {
		// Whatever this handler reaches for, it is the wrapper. Recorded
		// rather than asserted: require inside a handler calls FailNow on the
		// SERVER's goroutine, which stops that goroutine and lets the test
		// carry on, so a failed assertion here could pass the test.
		if _, ok := stream.(*GuardedServerStream); !ok {
			faults.record("the handler was handed %T, not the wrapper", stream)
		}
		for range 3 {
			attempts++
			if err := stream.SendMsg(wrapperspb.String("message under revoked authority")); err != nil {
				refusals++
			}
		}
		// Every route out, not only SendMsg: a queued header and a queued
		// trailer under revoked authority.
		if err := stream.SetHeader(metadata.Pairs("leaked-header", "yes")); err == nil {
			faults.record("SetHeader was accepted under revoked authority")
		}
		stream.SetTrailer(metadata.Pairs("leaked", "yes"))
		return nil
	})

	received, header, trailer, err := clientSaw(t, connection)
	faults.assert(t)
	require.Error(t, err)
	require.Empty(t, header.Get("leaked-header"))
	// THE MESSAGE COUNT THE CLIENT ACTUALLY RECEIVED. This read
	// `received := 0; require.Zero(received)` — the assertion that mattered
	// most in this file, against a literal the line above it had just written.
	require.Zero(t, received, "a message left under revoked authority")
	require.Empty(t, trailer.Get("leaked"))
	require.Equal(t, attempts, refusals, "every send under revoked authority was refused")
	require.Positive(t, int(authority.checks.Load()), "and every one of them was checked")
}

// Revocation mid-stream stops the stream at the next message, over a real
// connection: the first messages arrive, the rest do not.
func TestARealStreamStopsAtTheMessageAfterRevocation(t *testing.T) {
	authority := &revocableGuard{}
	connection := serveGuarded(t, authority.guard(t), func(stream grpc.ServerStream) error {
		for message := range 10 {
			if message == 3 {
				authority.revoked.Store(true)
			}
			if err := stream.SendMsg(wrapperspb.String("payload")); err != nil {
				return err
			}
		}
		return nil
	})

	received, _, err := drain(t, connection)
	require.Error(t, err)
	require.Equal(t, 3, received,
		"three messages were sent under authority and the fourth was refused")
}
