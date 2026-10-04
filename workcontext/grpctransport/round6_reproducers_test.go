package grpctransport

import (
	"context"
	"fmt"
	"sync/atomic"
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

// F-9. THE INTERCEPTOR FAILED OPEN, two ways, both executed.
//
// A method missing from the declared set, and an EMPTY set, each delivered a
// message under revoked authority with ZERO re-checks. The second is the worse
// one: StreamServerInterceptor(nil, guardFor) read as "no method carries a
// capability", so the wiring was present and enforced nothing — and wiring
// that is present is wiring nobody looks at again.
func TestAnEmptyMethodSetGuardsNothingAndSoRefusesEverything(t *testing.T) {
	authority := &revocableGuard{}
	authority.revoked.Store(true)

	connection := serveWith(t, StreamServerInterceptor(nil,
		func(context.Context, *grpc.StreamServerInfo) (*workcontext.StreamGuard, error) {
			return authority.guard(t), nil
		}), func(stream grpc.ServerStream) error {
		return stream.SendMsg(wrapperspb.String("delivered under revoked authority"))
	})

	received, _, _, err := clientSaw(t, connection)

	require.Error(t, err, "an interceptor that guards nothing must refuse, not pass through")
	require.Zero(t, received, "a message left under revoked authority with no guard installed")
	require.Equal(t, codes.Internal, status.Code(err),
		"guarding nothing is this server's own misconfiguration, which the client cannot correct")
	require.Contains(t, status.Convert(err).Message(), "would guard nothing")
}

// And the typo, which no interceptor can catch from inside one request: "not in
// the set" and "in the set under another spelling" are the same observation
// there. The server knows, so ValidateMethodSet asks it.
func TestADeclaredMethodTheServerDoesNotServeIsRefusedAtStartup(t *testing.T) {
	served := map[string]grpc.ServiceInfo{
		streamService: {Methods: []grpc.MethodInfo{{Name: "Emit", IsServerStream: true}}},
	}

	require.NoError(t, ValidateMethodSet(served, []string{streamMethod}),
		"the method this server really serves is declared correctly")

	err := ValidateMethodSet(served, []string{"/" + streamService + "/Emmit"})
	require.Error(t, err, "a name that matches nothing guards nothing")
	require.ErrorIs(t, err, workcontext.ErrInvalid)
	require.Contains(t, err.Error(), "Emmit",
		"the refusal must name the method, because the whole defect is that it looks right")

	require.Error(t, ValidateMethodSet(served, nil),
		"an empty set would guard nothing, and saying so by omission is not saying it")
}

// F-2, AS EXECUTED: a real core Verifier, a moving clock, and a capability that
// expires mid-stream. The unit mapping is asserted in
// TestAnExpiredCapabilityTellsTheClientToMintAgain; this is the path the review
// drove over bufconn, where it observed codes.Internal.
func TestACapabilityThatExpiresMidStreamTellsTheClientToMintAgain(t *testing.T) {
	expired := fmt.Errorf("stream terminated: %w: expired at 2026-10-02T12:15:00Z",
		workcontext.ErrInvalid)

	connection := serveWith(t, StreamServerInterceptor([]string{streamMethod},
		func(context.Context, *grpc.StreamServerInfo) (*workcontext.StreamGuard, error) {
			// A guard whose re-check answers exactly what core's Verifier
			// answers for a capability whose window has passed: ErrInvalid,
			// with core's own wording.
			var checks atomic.Uint64
			return workcontext.NewStreamGuard(workcontext.StreamGuardOptions{
				Recheck: func(context.Context) error {
					if checks.Add(1) > 1 {
						return expired
					}
					return nil
				},
			})
		}), func(stream grpc.ServerStream) error {
		for range 3 {
			if err := stream.SendMsg(wrapperspb.String("payload")); err != nil {
				return err
			}
		}
		return nil
	})

	received, _, _, err := clientSaw(t, connection)

	require.Error(t, err)
	require.Equal(t, 1, received, "the first message goes out, the rest do not")
	require.Equal(t, codes.Unauthenticated, status.Code(err),
		"a stream that outlives its credential is answered by minting a new one; this "+
			"arrived as codes.Internal, which tells a client the server is broken")
	require.Contains(t, status.Convert(err).Message(), "expired")
}

// CODEX 7: a set of only UNARY methods passed validation, so a streaming method
// reached the raw handler with guardFor never called — the
// interceptor-that-guards-nothing configuration, reached by naming a method
// that cannot stream.
func TestAUnaryMethodNameGuardsNothingAndIsRefused(t *testing.T) {
	served := map[string]grpc.ServiceInfo{
		streamService: {Methods: []grpc.MethodInfo{
			{Name: "Emit", IsServerStream: true},
			{Name: "Read"},
		}},
	}

	require.NoError(t, ValidateMethodSet(served, []string{streamMethod}),
		"the streaming method this server serves is declared correctly")

	err := ValidateMethodSet(served, []string{"/" + streamService + "/Read"})
	require.Error(t, err, "a unary method's name makes the set non-empty and guards nothing")
	require.ErrorIs(t, err, workcontext.ErrInvalid)
	require.Contains(t, err.Error(), "are unary on this server")
	require.Contains(t, err.Error(), "Read",
		"the refusal must name the method, because the defect is that it looks declared")

	// A server with no streaming method at all has nothing for a stream
	// interceptor to do, which is also not something to express by omission.
	require.Error(t, ValidateMethodSet(
		map[string]grpc.ServiceInfo{streamService: {Methods: []grpc.MethodInfo{{Name: "Read"}}}},
		[]string{"/" + streamService + "/Read"}))
}

// M-4: THE INTERCEPTOR FAILED OPEN FOR A SERVED METHOD MISSING FROM THE SET,
// and the validation that was supposed to catch misconfiguration only looked
// one way — the declared set was checked against the server, and the server was
// never checked against the set.
//
// Deny by default, as everywhere else here: every served streaming method is
// either capability-bearing or NAMED as deliberately unguarded. A stream that
// carries no authority is a real thing, so this does not force a guard on it —
// it forces somebody to have said so once, where a reader sees it, instead of a
// method going unguarded because nobody thought about it.
func TestEveryServedStreamIsEitherGuardedOrDeliberatelyNot(t *testing.T) {
	served := map[string]grpc.ServiceInfo{
		streamService: {Methods: []grpc.MethodInfo{
			{Name: "Emit", IsServerStream: true},
			{Name: "Watch", IsServerStream: true},
			{Name: "Read"},
		}},
	}
	watch := "/" + streamService + "/Watch"

	// Emit declared, Watch neither declared nor exempted: refused.
	err := ValidateMethodSet(served, []string{streamMethod})
	require.Error(t, err, "Watch reaches the handler unguarded and nothing says that is intended")
	require.ErrorIs(t, err, workcontext.ErrInvalid)
	require.Contains(t, err.Error(), "Watch")
	require.Contains(t, err.Error(), "reaches the handler UNGUARDED")

	// Watch named as deliberately unguarded: accepted. The decision exists.
	require.NoError(t, ValidateMethodSet(served, []string{streamMethod}, watch))

	// Or guarded instead: also accepted.
	require.NoError(t, ValidateMethodSet(served, []string{streamMethod, watch}))

	// AND EVERY PROBLEM AT ONCE, because returning on the first told a server
	// with two mistakes about one of them.
	both := ValidateMethodSet(served, []string{"/" + streamService + "/Emmit", "/" + streamService + "/Read"})
	require.Error(t, both)
	require.Contains(t, both.Error(), "Emmit", "the typo")
	require.Contains(t, both.Error(), "unary on this server", "the unary name")
	require.Contains(t, both.Error(), "UNGUARDED", "and the streams nothing names")
}
