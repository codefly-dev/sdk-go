package grpctransport

import (
	"context"
	"errors"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

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
	listener := bufconn.Listen(1024 * 1024)
	server := grpc.NewServer(grpc.StreamInterceptor(
		StreamServerInterceptor(
			func(context.Context, *grpc.StreamServerInfo) (*workcontext.StreamGuard, error) {
				return guard, nil
			}),
	))
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

// drain runs the stream to completion and reports what the client saw.
func drain(t *testing.T, connection *grpc.ClientConn) (received int, trailer metadata.MD, err error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	stream, err := connection.NewStream(ctx,
		&grpc.StreamDesc{StreamName: "Emit", ServerStreams: true}, streamMethod)
	require.NoError(t, err)
	require.NoError(t, stream.CloseSend())
	for {
		message := &wrapperspb.StringValue{}
		recvErr := stream.RecvMsg(message)
		if errors.Is(recvErr, io.EOF) {
			return received, stream.Trailer(), nil
		}
		if recvErr != nil {
			return received, stream.Trailer(), recvErr
		}
		received++
	}
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
	connection := serveGuarded(t, authority.guard(t), func(stream grpc.ServerStream) error {
		// Whatever this handler reaches for, it is the wrapper.
		require.IsType(t, &GuardedServerStream{}, stream)
		for range 3 {
			attempts++
			if err := stream.SendMsg(wrapperspb.String("message under revoked authority")); err != nil {
				refusals++
			}
		}
		stream.SetTrailer(metadata.Pairs("leaked", "yes"))
		return nil
	})

	received, trailer, err := drain(t, connection)
	require.Error(t, err)
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
