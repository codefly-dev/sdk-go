package grpctransport

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/codefly-dev/sdk-go/workcontext"
)

// B7. EXPIRY IS THE ORDINARY REFUSAL AND IT ARRIVED AS Internal.
//
// core answers an expired capability with ErrInvalid — verify.go returns
// "%w: expired at …" — and statusFor mapped every ErrInvalid to codes.Internal.
// The argument for that was sound and applied to the wrong side: ErrInvalid
// also covers this package's own misuse, and telling a client "mint again"
// about a server bug makes it loop. But a stream outliving its credential is
// the COMMON case, not a rare malformed one, and minting again is exactly the
// right answer to it. Measured: Internal.
//
// The distinction the old comment called unavailable was available all along,
// because every misuse error here is constructed here and can say so.
func TestAnExpiredCapabilityTellsTheClientToMintAgain(t *testing.T) {
	// The sentinel core actually returns for expiry, with core's own wording.
	expired := fmt.Errorf("%w: expired at 2026-10-02T12:00:00Z", workcontext.ErrInvalid)

	require.Equal(t, codes.Unauthenticated, status.Code(statusFor(expired)),
		"an expired capability is answered by presenting a new one, which is what "+
			"Unauthenticated means to a client")

	// And this server's own misuse is still Internal, which is the cost the
	// previous mapping was protecting and this keeps.
	for name, misuse := range map[string]error{
		"a re-check that tried to write": errRecheckMustNotWrite,
		"a finished stream":              fmt.Errorf("%w: the stream is finished", errStreamMisuse),
		"an unguarded wrapper":           (*GuardedServerStream)(nil).SetHeader(metadata.MD{}),
	} {
		t.Run(name, func(t *testing.T) {
			require.Equal(t, codes.Internal, status.Code(statusFor(misuse)),
				"the client did nothing it can correct, and minting again cannot fix a server bug")
			require.ErrorIs(t, misuse, workcontext.ErrInvalid,
				"misuse still wraps ErrInvalid, so anything relying on that is unchanged")
		})
	}

	// The sentinels that were already Unauthenticated stay there, so this is
	// not green by mapping everything one way.
	require.Equal(t, codes.Unauthenticated, status.Code(statusFor(workcontext.ErrRevoked)))
	require.Equal(t, codes.Unavailable, status.Code(statusFor(workcontext.ErrStreamTerminated)))
}

// B8. THE FIRST SEND LEFT THE HEADER STATE WRONG WHEN NOTHING WAS QUEUED.
//
// releaseHeaders returned early on an empty queue without marking flushed, and
// gRPC sends the header frame with the first message whether the handler queued
// anything or not. So a SetHeader after the first SendMsg was held in the
// wrapper, found !flushed, and was handed to stream.SetHeader by Finish — which
// gRPC ignores, because the headers are already on the wire.
//
// Measured over bufconn: SetHeader returned nil, the header never reached the
// client, and the handler was told nothing. A handler cannot act on an error it
// is not given.
func TestAHeaderSetAfterTheFirstMessageIsNotSilentlyDropped(t *testing.T) {
	faults := &handlerFaults{}
	answered := make(chan error, 1)
	connection := serveGuarded(t, (&revocableGuard{}).guard(t), func(stream grpc.ServerStream) error {
		// NOTHING QUEUED before the first send: that is the whole case. With a
		// header queued first, flushed was set and this all worked.
		if err := stream.SendMsg(wrapperspb.String("first")); err != nil {
			faults.record("the first send failed: %v", err)
		}
		answered <- stream.SetHeader(metadata.Pairs("late-header", "yes"))
		return nil
	})

	received, header, _, err := clientSaw(t, connection)
	faults.assert(t)
	require.NoError(t, err)
	require.Equal(t, 1, received, "the message itself must still arrive")

	setHeaderErr := <-answered
	require.Error(t, setHeaderErr,
		"the headers went out with the first message, so this SetHeader cannot be honoured — "+
			"and a handler that is told nothing cannot act on it")
	require.Empty(t, header.Get("late-header"),
		"and it must not arrive either: an error plus delivery would be worse than silence")
}
