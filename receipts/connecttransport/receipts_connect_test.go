package connecttransport_test

import (
	"context"
	"sync/atomic"
	"testing"

	"connectrpc.com/connect"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/dynamicpb"

	"github.com/codefly-dev/sdk-go/receipts"
	"github.com/codefly-dev/sdk-go/receipts/connecttransport"
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

func (h *harness) message(t *testing.T, name, value string) *dynamicpb.Message {
	t.Helper()
	built, err := h.fixture.Message(protoreflect.FullName(name), value)
	require.NoError(t, err)
	dynamic, isDynamic := built.(*dynamicpb.Message)
	require.True(t, isDynamic)
	return dynamic
}

func (h *harness) request(t *testing.T, value, effectHeader, effectID string) *connect.Request[dynamicpb.Message] {
	t.Helper()
	built := connect.NewRequest(h.message(t, fixture.RequestMessage, value))
	if effectHeader != "" {
		built.Header().Set(effectHeader, effectID)
	}
	return built
}

func (h *harness) handler(t *testing.T, value string) func(context.Context, *connect.Request[dynamicpb.Message]) (*connect.Response[dynamicpb.Message], error) {
	t.Helper()
	return func(ctx context.Context, _ *connect.Request[dynamicpb.Message]) (*connect.Response[dynamicpb.Message], error) {
		h.calls.Add(1)
		committed := h.message(t, fixture.AnswerMessage, value)
		if err := receipts.Record(ctx, h.store, receipts.NoTx{}, committed); err != nil {
			return nil, err
		}
		return connect.NewResponse(committed), nil
	}
}

func TestConnectReplaysFromTheReceipt(t *testing.T) {
	for _, header := range []string{receipts.EffectIDHeaderName, receipts.IdempotencyKeyHeaderName} {
		t.Run(header, func(t *testing.T) {
			h := newHarness(t)
			guarded := connecttransport.WrapUnary(h.guard, fixture.OperationMethod, h.handler(t, "out"))

			first, err := guarded(t.Context(), h.request(t, "in", header, "effect-1"))
			require.NoError(t, err)
			replayed, err := connecttransport.
				WrapUnary(h.guard, fixture.OperationMethod, h.handler(t, "other"))(
				t.Context(), h.request(t, "in", header, "effect-1"))
			require.NoError(t, err)

			require.Equal(t, int64(1), h.calls.Load())
			require.True(t, proto.Equal(first.Msg, replayed.Msg))
		})
	}
}

func TestConnectRefusalsCarryTheirCode(t *testing.T) {
	h := newHarness(t)
	guarded := connecttransport.WrapUnary(h.guard, fixture.OperationMethod, h.handler(t, "out"))

	_, err := guarded(t.Context(), h.request(t, "in", "", ""))
	require.Equal(t, connect.CodeInvalidArgument, connect.CodeOf(err))

	ambiguous := h.request(t, "in", receipts.EffectIDHeaderName, "effect-1")
	ambiguous.Header().Set(receipts.IdempotencyKeyHeaderName, "effect-2")
	_, err = guarded(t.Context(), ambiguous)
	require.Equal(t, connect.CodeInvalidArgument, connect.CodeOf(err))

	_, err = guarded(t.Context(), h.request(t, "in", receipts.EffectIDHeaderName, "effect-1"))
	require.NoError(t, err)
	_, err = guarded(t.Context(), h.request(t, "different", receipts.EffectIDHeaderName, "effect-1"))
	require.Equal(t, connect.CodeFailedPrecondition, connect.CodeOf(err))

	require.Equal(t, int64(1), h.calls.Load())
}

// A handler that ran owns its response headers, so the wrapper returns its own
// answer rather than one rebuilt from the recorded message.
func TestConnectKeepsTheHandlersOwnResponse(t *testing.T) {
	h := newHarness(t)
	guarded := connecttransport.WrapUnary(h.guard, fixture.OperationMethod,
		func(ctx context.Context, request *connect.Request[dynamicpb.Message]) (*connect.Response[dynamicpb.Message], error) {
			answered, err := h.handler(t, "out")(ctx, request)
			if err != nil {
				return nil, err
			}
			answered.Header().Set("x-fixture", "handled")
			return answered, nil
		})

	answered, err := guarded(t.Context(), h.request(t, "in", receipts.EffectIDHeaderName, "effect-1"))
	require.NoError(t, err)
	require.Equal(t, "handled", answered.Header().Get("x-fixture"))
}

func TestConnectLeavesAnUnmarkedMethodAlone(t *testing.T) {
	h := newHarness(t)
	guarded := connecttransport.WrapUnary(h.guard, fixture.PlainMethod,
		func(context.Context, *connect.Request[dynamicpb.Message]) (*connect.Response[dynamicpb.Message], error) {
			h.calls.Add(1)
			return connect.NewResponse(h.message(t, fixture.AnswerMessage, "out")), nil
		})

	answered, err := guarded(t.Context(), h.request(t, "in", "", ""))
	require.NoError(t, err)
	require.NotNil(t, answered)
	require.Equal(t, int64(1), h.calls.Load())
}

func TestConnectReportsAHandlerErrorUnchanged(t *testing.T) {
	h := newHarness(t)
	guarded := connecttransport.WrapUnary(h.guard, fixture.OperationMethod,
		func(context.Context, *connect.Request[dynamicpb.Message]) (*connect.Response[dynamicpb.Message], error) {
			return nil, connect.NewError(connect.CodeResourceExhausted, context.DeadlineExceeded)
		})

	_, err := guarded(t.Context(), h.request(t, "in", receipts.EffectIDHeaderName, "effect-1"))
	require.Equal(t, connect.CodeResourceExhausted, connect.CodeOf(err))
}
