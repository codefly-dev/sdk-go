package grpctransport

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"

	"github.com/codefly-dev/sdk-go/workcontext"
)

// recordingStream is a grpc.ServerStream that records what was sent, so a test
// can assert that a message did NOT leave.
type recordingStream struct {
	grpc.ServerStream
	ctx      context.Context
	sent     []any
	headers  int
	trailers int
}

func (s *recordingStream) Context() context.Context { return s.ctx }

func (s *recordingStream) SendMsg(message any) error {
	s.sent = append(s.sent, message)
	return nil
}

func (s *recordingStream) SetHeader(metadata.MD) error {
	s.headers++
	return nil
}

func (s *recordingStream) SendHeader(metadata.MD) error {
	s.headers++
	return nil
}

func (s *recordingStream) SetTrailer(metadata.MD) { s.trailers++ }
func (s *recordingStream) RecvMsg(any) error      { return nil }

// A guarded stream re-checks before EVERY message, and a refused message does
// not leave.
//
// This is the half a StreamGuard on its own cannot provide. BeforeSend has to
// be called, and "before each emission" was therefore something each author
// had to remember — the same shape as the optional carrier this PR deleted, a
// rule that holds wherever somebody thought of it. Here Send IS the re-check
// followed by the send, so a handler cannot emit without it.
func TestAGuardedStreamRechecksBeforeEveryMessage(t *testing.T) {
	rechecks := 0
	refuse := false
	guard, err := workcontext.NewStreamGuard(workcontext.StreamGuardOptions{
		Recheck: func(context.Context) error {
			rechecks++
			if refuse {
				return workcontext.ErrRevoked
			}
			return nil
		},
	})
	require.NoError(t, err)

	underlying := &recordingStream{ctx: context.Background()}
	guarded, err := Guard(underlying, guard)
	require.NoError(t, err)

	for message := 1; message <= 3; message++ {
		require.NoError(t, guarded.SendMsg(message))
		require.Equal(t, message, rechecks, "message %d re-presented the credential", message)
		require.Len(t, underlying.sent, message)
	}

	// The authority is withdrawn with no time passing at all. The very next
	// message is refused AND NOT SENT.
	refuse = true
	err = guarded.SendMsg("the message that must not leave")
	require.ErrorIs(t, err, workcontext.ErrStreamTerminated)
	require.ErrorIs(t, err, workcontext.ErrRevoked)
	require.Len(t, underlying.sent, 3,
		"a message computed under withdrawn authority must not reach the wire")

	// And it stays terminated: a handler looping past the first refusal does
	// not get a second chance to emit, and the authority coming back does not
	// resurrect the stream.
	refuse = false
	for range 3 {
		require.ErrorIs(t, guarded.SendMsg("still refused"), workcontext.ErrStreamTerminated)
	}
	require.Len(t, underlying.sent, 3)
	require.Equal(t, 4, rechecks, "a terminated stream asks nothing further")
	require.ErrorIs(t, guarded.Terminated(), workcontext.ErrStreamTerminated)
}

// An unreachable live source terminates the stream too. "I could not ask" is
// not "the credential is good", and a stream that treated it as one would
// outlive its authority with clean logs.
func TestAGuardedStreamTerminatesWhenTheLiveSourceIsUnavailable(t *testing.T) {
	unavailable := errors.New("installation state store unreachable")
	guard, err := workcontext.NewStreamGuard(workcontext.StreamGuardOptions{
		Recheck: func(context.Context) error { return unavailable },
	})
	require.NoError(t, err)

	underlying := &recordingStream{ctx: context.Background()}
	guarded, err := Guard(underlying, guard)
	require.NoError(t, err)

	err = guarded.SendMsg("anything")
	require.ErrorIs(t, err, workcontext.ErrStreamTerminated)
	require.ErrorIs(t, err, unavailable)
	require.Empty(t, underlying.sent)
}

// A wrapper that silently did nothing would be worse than no wrapper, because
// the call site would read as guarded.
func TestGuardRefusesToWrapNothing(t *testing.T) {
	guard, err := workcontext.NewStreamGuard(workcontext.StreamGuardOptions{
		Recheck: func(context.Context) error { return nil },
	})
	require.NoError(t, err)

	_, err = Guard(nil, guard)
	require.ErrorIs(t, err, workcontext.ErrInvalid)

	_, err = Guard(&recordingStream{ctx: context.Background()}, nil)
	require.ErrorIs(t, err, workcontext.ErrInvalid)

	var absent *GuardedServerStream
	require.ErrorIs(t, absent.SendMsg("x"), workcontext.ErrInvalid)
	require.NoError(t, absent.Terminated())
}

// Metadata is a channel out too, and a TRAILER leaves when the handler returns
// rather than when SetTrailer is called — so it is held in the wrapper until
// Finish re-checks and releases it.
func TestAGuardedStreamHoldsTrailersUntilFinishRechecks(t *testing.T) {
	refuse := false
	guard, err := workcontext.NewStreamGuard(workcontext.StreamGuardOptions{
		Recheck: func(context.Context) error {
			if refuse {
				return workcontext.ErrRevoked
			}
			return nil
		},
	})
	require.NoError(t, err)

	underlying := &recordingStream{ctx: context.Background()}
	guarded, err := Guard(underlying, guard)
	require.NoError(t, err)

	// SetHeader HOLDS: gRPC flushes a pending header frame when the handler
	// returns, so handing it over at queue time let a header leave after a
	// revocation that happened in between. Only SendHeader reaches gRPC, and
	// it carries what SetHeader queued.
	require.NoError(t, guarded.SetHeader(metadata.Pairs("a", "1")))
	require.Zero(t, underlying.headers, "a queued header must not reach gRPC before a check")
	require.NoError(t, guarded.SendHeader(metadata.Pairs("b", "2")))
	require.Equal(t, 1, underlying.headers)

	// Set under authority, and NOT yet handed to gRPC: gRPC would send it when
	// the handler returned, which is after any revocation in between.
	guarded.SetTrailer(metadata.Pairs("c", "3"))
	require.Zero(t, underlying.trailers,
		"a trailer must not reach gRPC before the last check")

	// Authority is withdrawn after the handler queued it. Finish discards.
	refuse = true
	require.ErrorIs(t, guarded.Finish(nil), workcontext.ErrStreamTerminated)
	require.Zero(t, underlying.trailers,
		"a trailer describes work whose authority was withdrawn; it is dropped")
	require.ErrorIs(t, guarded.SetHeader(metadata.Pairs("d", "4")), workcontext.ErrStreamTerminated)
}

// And when authority holds, Finish releases them and returns the handler's own
// error unchanged.
func TestFinishReleasesTrailersWhenAuthorityHolds(t *testing.T) {
	guard, err := workcontext.NewStreamGuard(workcontext.StreamGuardOptions{
		Recheck: func(context.Context) error { return nil },
	})
	require.NoError(t, err)
	underlying := &recordingStream{ctx: context.Background()}
	guarded, err := Guard(underlying, guard)
	require.NoError(t, err)

	guarded.SetTrailer(metadata.Pairs("c", "3"))
	guarded.SetTrailer(metadata.Pairs("d", "4"))
	handlerErr := errors.New("the handler's own failure")
	require.ErrorIs(t, guarded.Finish(handlerErr), handlerErr,
		"Finish reports the handler's result, not its own")
	require.Equal(t, 1, underlying.trailers,
		"the pending trailers are released together, once")
}

// The wrapper must expose NO route to the stream it wraps.
//
// It used to embed grpc.ServerStream as a public field, so a handler given only
// the intercepted stream could write stream.(*GuardedServerStream).ServerStream
// and send with no check at all. This asserts the shape rather than the
// behaviour, because the behaviour it prevents would not compile: no exported
// field, and nothing exported that hands back a grpc.ServerStream.
func TestTheWrapperExposesNoRouteToTheRawStream(t *testing.T) {
	wrapper := reflect.TypeOf(GuardedServerStream{})
	serverStream := reflect.TypeOf((*grpc.ServerStream)(nil)).Elem()

	for field := range wrapper.NumField() {
		declared := wrapper.Field(field)
		require.False(t, declared.IsExported(),
			"%s is exported; a handler can reach it and bypass the guard", declared.Name)
		require.False(t, declared.Anonymous && declared.Type == serverStream,
			"the stream must not be embedded: embedding is what made it reachable")
	}

	pointer := reflect.TypeOf(&GuardedServerStream{})
	for method := range pointer.NumMethod() {
		declared := pointer.Method(method)
		for result := range declared.Type.NumOut() {
			require.NotEqual(t, serverStream, declared.Type.Out(result),
				"%s returns a grpc.ServerStream, which is a route around the guard",
				declared.Name)
		}
	}

	// And it still satisfies the interface it replaces, by forwarding rather
	// than embedding.
	require.Implements(t, (*grpc.ServerStream)(nil), &GuardedServerStream{})
}

// The interceptor is the half a wrapper cannot provide: enforcement as wiring.
//
// Guard leaves the original stream in the handler's scope, so "guard your
// stream" was advice. Installed at the server, the handler receives a stream it
// cannot write around, because the unguarded one never reaches it.
func TestTheStreamInterceptorHandsTheHandlerAGuardedStream(t *testing.T) {
	refuse := false
	guard, err := workcontext.NewStreamGuard(workcontext.StreamGuardOptions{
		Recheck: func(context.Context) error {
			if refuse {
				return workcontext.ErrRevoked
			}
			return nil
		},
	})
	require.NoError(t, err)

	underlying := &recordingStream{ctx: context.Background()}
	interceptor := StreamServerInterceptor(
		func(context.Context, *grpc.StreamServerInfo) (*workcontext.StreamGuard, error) {
			return guard, nil
		})

	var handed grpc.ServerStream
	err = interceptor(nil, underlying, &grpc.StreamServerInfo{FullMethod: "/x/Y"},
		func(_ any, stream grpc.ServerStream) error {
			handed = stream
			require.NoError(t, stream.SendMsg("first"))
			refuse = true
			return stream.SendMsg("the one that must not leave")
		})
	require.ErrorIs(t, err, workcontext.ErrStreamTerminated)
	require.IsType(t, &GuardedServerStream{}, handed,
		"the handler must not be able to receive the unguarded stream")
	require.Len(t, underlying.sent, 1)
	require.NotImplements(t, (*interface{ ServerStream() grpc.ServerStream })(nil), handed)
}

// A server may declare a stream unguarded, but it does so AT THE SERVER where
// a reviewer sees it, not inside a handler.
func TestTheStreamInterceptorRefusesWhenItCannotBuildAGuard(t *testing.T) {
	underlying := &recordingStream{ctx: context.Background()}
	refused := errors.New("this capability did not verify")

	err := StreamServerInterceptor(
		func(context.Context, *grpc.StreamServerInfo) (*workcontext.StreamGuard, error) {
			return nil, refused
		})(nil, underlying, &grpc.StreamServerInfo{}, func(any, grpc.ServerStream) error {
		t.Fatal("the handler must not run when the stream could not be guarded")
		return nil
	})
	require.ErrorIs(t, err, refused)

	// Explicitly unguarded: allowed, and the handler gets the raw stream.
	var handed grpc.ServerStream
	err = StreamServerInterceptor(
		func(context.Context, *grpc.StreamServerInfo) (*workcontext.StreamGuard, error) {
			return nil, nil
		})(nil, underlying, &grpc.StreamServerInfo{}, func(_ any, stream grpc.ServerStream) error {
		handed = stream
		return nil
	})
	require.NoError(t, err)
	require.Same(t, underlying, handed)

	// And no guard-builder at all is a configuration error, not a pass.
	err = StreamServerInterceptor(nil)(nil, underlying, &grpc.StreamServerInfo{},
		func(any, grpc.ServerStream) error { return nil })
	require.ErrorIs(t, err, workcontext.ErrInvalid)
}
