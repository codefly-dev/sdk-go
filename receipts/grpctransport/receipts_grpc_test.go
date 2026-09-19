package grpctransport_test

import (
	"context"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/codefly-dev/sdk-go/receipts"
	"github.com/codefly-dev/sdk-go/receipts/grpctransport"
	"github.com/codefly-dev/sdk-go/receipts/internal/fixture"
)

const testTenant = "tenant-a"

type harness struct {
	fixture fixture.Registry
	store   *receipts.MemoryStore
	guard   *receipts.Interceptor
	calls   atomic.Int64
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	built, err := fixture.New(fixture.Operation())
	require.NoError(t, err)
	store := receipts.NewMemoryStore()
	guard, err := receipts.New(receipts.Options{
		Store:  store,
		Tenant: func(context.Context) (string, error) { return testTenant, nil },
		Files:  built.Files,
		Types:  built.Types,
	})
	require.NoError(t, err)
	return &harness{fixture: built, store: store, guard: guard}
}

func (h *harness) message(t *testing.T, name, value string) proto.Message {
	t.Helper()
	built, err := h.fixture.Message(protoreflect.FullName(name), value)
	require.NoError(t, err)
	return built
}

// handler commits its answer the way a real one does, inside the call.
func (h *harness) handler(t *testing.T, value string) grpc.UnaryHandler {
	t.Helper()
	return func(ctx context.Context, _ any) (any, error) {
		h.calls.Add(1)
		committed := h.message(t, fixture.AnswerMessage, value)
		if err := receipts.Record(ctx, h.store, receipts.NoTx{}, committed); err != nil {
			return nil, err
		}
		return committed, nil
	}
}

func incoming(t *testing.T, pairs ...string) context.Context {
	t.Helper()
	return metadata.NewIncomingContext(t.Context(), metadata.Pairs(pairs...))
}

func TestBothEffectIDSpellingsAreAccepted(t *testing.T) {
	for _, header := range []string{receipts.EffectIDHeaderName, receipts.IdempotencyKeyHeaderName} {
		t.Run(header, func(t *testing.T) {
			h := newHarness(t)
			intercept := grpctransport.UnaryServerInterceptor(h.guard)
			info := &grpc.UnaryServerInfo{FullMethod: fixture.OperationMethod}
			ctx := incoming(t, header, "effect-1")

			first, err := intercept(ctx, h.message(t, fixture.RequestMessage, "in"), info, h.handler(t, "out"))
			require.NoError(t, err)
			replayed, err := intercept(ctx, h.message(t, fixture.RequestMessage, "in"), info, h.handler(t, "other"))
			require.NoError(t, err)

			require.Equal(t, int64(1), h.calls.Load())
			require.True(t, proto.Equal(first.(proto.Message), replayed.(proto.Message)))
		})
	}
}

func TestGRPCRefusalsCarryTheirStatusCode(t *testing.T) {
	h := newHarness(t)
	intercept := grpctransport.UnaryServerInterceptor(h.guard)
	info := &grpc.UnaryServerInfo{FullMethod: fixture.OperationMethod}

	_, err := intercept(t.Context(), h.message(t, fixture.RequestMessage, "in"), info, h.handler(t, "out"))
	require.Equal(t, codes.InvalidArgument, status.Code(err), "a call with no metadata at all")

	_, err = intercept(incoming(t, "unrelated", "value"),
		h.message(t, fixture.RequestMessage, "in"), info, h.handler(t, "out"))
	require.Equal(t, codes.InvalidArgument, status.Code(err))

	_, err = intercept(
		incoming(t, receipts.EffectIDHeaderName, "effect-1", receipts.IdempotencyKeyHeaderName, "effect-2"),
		h.message(t, fixture.RequestMessage, "in"), info, h.handler(t, "out"))
	require.Equal(t, codes.InvalidArgument, status.Code(err), "two effect ids are ambiguous, not lenient")

	ctx := incoming(t, receipts.EffectIDHeaderName, "effect-1")
	_, err = intercept(ctx, h.message(t, fixture.RequestMessage, "in"), info, h.handler(t, "out"))
	require.NoError(t, err)
	_, err = intercept(ctx, h.message(t, fixture.RequestMessage, "different"), info, h.handler(t, "out"))
	require.Equal(t, codes.FailedPrecondition, status.Code(err))

	require.Equal(t, int64(1), h.calls.Load())
}

func TestAHandlerErrorIsReportedUnchanged(t *testing.T) {
	h := newHarness(t)
	intercept := grpctransport.UnaryServerInterceptor(h.guard)
	info := &grpc.UnaryServerInfo{FullMethod: fixture.OperationMethod}

	_, err := intercept(incoming(t, receipts.EffectIDHeaderName, "effect-1"),
		h.message(t, fixture.RequestMessage, "in"), info,
		func(context.Context, any) (any, error) { return nil, status.Error(codes.ResourceExhausted, "busy") })
	require.Equal(t, codes.ResourceExhausted, status.Code(err))

	// The refused attempt recorded nothing, so the effect id is still spendable.
	answered, err := intercept(incoming(t, receipts.EffectIDHeaderName, "effect-1"),
		h.message(t, fixture.RequestMessage, "in"), info, h.handler(t, "out"))
	require.NoError(t, err)
	require.NotNil(t, answered)
}

func TestAnUnmarkedMethodPassesThrough(t *testing.T) {
	h := newHarness(t)
	intercept := grpctransport.UnaryServerInterceptor(h.guard)

	answered, err := intercept(t.Context(), h.message(t, fixture.RequestMessage, "in"),
		&grpc.UnaryServerInfo{FullMethod: fixture.PlainMethod},
		func(ctx context.Context, _ any) (any, error) {
			h.calls.Add(1)
			_, admitted := receipts.EffectFromContext(ctx)
			require.False(t, admitted, "an unmarked method was admitted as an effect")
			return h.message(t, fixture.AnswerMessage, "out"), nil
		})
	require.NoError(t, err)
	require.NotNil(t, answered)
	require.Equal(t, int64(1), h.calls.Load())
}

func TestANonProtoRequestOnAnOperationIsInternal(t *testing.T) {
	h := newHarness(t)
	intercept := grpctransport.UnaryServerInterceptor(h.guard)

	_, err := intercept(incoming(t, receipts.EffectIDHeaderName, "effect-1"), "not a message",
		&grpc.UnaryServerInfo{FullMethod: fixture.OperationMethod}, h.handler(t, "out"))
	require.Equal(t, codes.Internal, status.Code(err))
}
