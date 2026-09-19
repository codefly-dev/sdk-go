package receipts_test

import (
	"context"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	runnablev0 "github.com/codefly-dev/core/generated/go/codefly/runnable/v0"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/codefly-dev/sdk-go/receipts"
	"github.com/codefly-dev/sdk-go/receipts/internal/fixture"
)

const testTenant = "tenant-a"

func registry(t *testing.T, declared *runnablev0.Operation) fixture.Registry {
	t.Helper()
	built, err := fixture.New(declared)
	require.NoError(t, err)
	return built
}

func request(t *testing.T, built fixture.Registry, value string) proto.Message {
	t.Helper()
	message, err := built.Message(protoreflect.FullName(fixture.RequestMessage), value)
	require.NoError(t, err)
	return message
}

func answer(t *testing.T, built fixture.Registry, value string) proto.Message {
	t.Helper()
	message, err := built.Message(protoreflect.FullName(fixture.AnswerMessage), value)
	require.NoError(t, err)
	return message
}

func interceptor(t *testing.T, built fixture.Registry, store receipts.Store) *receipts.Interceptor {
	t.Helper()
	guard, err := receipts.New(receipts.Options{
		Store:  store,
		Tenant: func(context.Context) (string, error) { return testTenant, nil },
		Files:  built.Files,
		Types:  built.Types,
	})
	require.NoError(t, err)
	return guard
}

// recordingHandler commits its answer the way a real handler does: inside the
// call, through Record, against the effect the interceptor admitted.
func recordingHandler(t *testing.T, built fixture.Registry, store receipts.Store, value string, calls *atomic.Int64) func(context.Context) (proto.Message, error) {
	t.Helper()
	return func(ctx context.Context) (proto.Message, error) {
		calls.Add(1)
		committed := answer(t, built, value)
		if err := receipts.Record(ctx, store, receipts.NoTx{}, committed); err != nil {
			return nil, err
		}
		return committed, nil
	}
}

func TestReplayAnswersFromTheReceiptWithoutCallingTheHandler(t *testing.T) {
	built := registry(t, fixture.Operation())
	store := receipts.NewMemoryStore()
	guard := interceptor(t, built, store)
	calls := &atomic.Int64{}

	first, err := guard.Handle(t.Context(), fixture.OperationMethod, "effect-1",
		request(t, built, "in"), recordingHandler(t, built, store, "out", calls))
	require.NoError(t, err)
	require.Equal(t, int64(1), calls.Load())

	replayed, err := guard.Handle(t.Context(), fixture.OperationMethod, "effect-1",
		request(t, built, "in"), recordingHandler(t, built, store, "other", calls))
	require.NoError(t, err)
	require.Equal(t, int64(1), calls.Load(), "the handler ran again instead of the receipt being replayed")
	require.True(t, proto.Equal(first, replayed))
}

func TestEffectIDReusedForADifferentRequestIsRefused(t *testing.T) {
	built := registry(t, fixture.Operation())
	store := receipts.NewMemoryStore()
	guard := interceptor(t, built, store)
	calls := &atomic.Int64{}

	_, err := guard.Handle(t.Context(), fixture.OperationMethod, "effect-1",
		request(t, built, "in"), recordingHandler(t, built, store, "out", calls))
	require.NoError(t, err)

	_, err = guard.Handle(t.Context(), fixture.OperationMethod, "effect-1",
		request(t, built, "different"), recordingHandler(t, built, store, "out", calls))
	require.ErrorIs(t, err, receipts.ErrEffectIDReused)
	require.Equal(t, receipts.RefusalFailedPrecondition, receipts.RefusalFor(err))
	require.Equal(t, int64(1), calls.Load(), "the refused call still ran the handler")
}

func TestAnOperationRequiresAnEffectID(t *testing.T) {
	built := registry(t, fixture.Operation())
	guard := interceptor(t, built, receipts.NewMemoryStore())
	calls := &atomic.Int64{}

	_, err := guard.Handle(t.Context(), fixture.OperationMethod, "",
		request(t, built, "in"), recordingHandler(t, built, receipts.NewMemoryStore(), "out", calls))
	require.ErrorIs(t, err, receipts.ErrEffectIDMissing)
	require.Equal(t, receipts.RefusalInvalidArgument, receipts.RefusalFor(err))
	require.Zero(t, calls.Load())
}

func TestAnEffectIDIsBounded(t *testing.T) {
	built := registry(t, fixture.Operation())
	guard := interceptor(t, built, receipts.NewMemoryStore())
	calls := &atomic.Int64{}

	for name, effectID := range map[string]string{
		"not canonical":         " effect-1",
		"control character":     "effect\n1",
		"longer than the bound": strings.Repeat("a", 200),
	} {
		t.Run(name, func(t *testing.T) {
			_, err := guard.Handle(t.Context(), fixture.OperationMethod, effectID,
				request(t, built, "in"), recordingHandler(t, built, receipts.NewMemoryStore(), "out", calls))
			require.ErrorIs(t, err, receipts.ErrInvalid)
			require.Equal(t, receipts.RefusalInvalidArgument, receipts.RefusalFor(err))
		})
	}
	require.Zero(t, calls.Load())
}

func TestAMethodWithoutTheOperationOptionIsUntouched(t *testing.T) {
	built := registry(t, fixture.Operation())
	guard := interceptor(t, built, receipts.NewMemoryStore())

	require.True(t, guard.IsOperation(fixture.OperationMethod))
	require.False(t, guard.IsOperation(fixture.PlainMethod))

	answered, err := guard.Handle(t.Context(), fixture.PlainMethod, "",
		request(t, built, "in"), func(ctx context.Context) (proto.Message, error) {
			_, admitted := receipts.EffectFromContext(ctx)
			require.False(t, admitted, "an unmarked method was admitted as an effect")
			return answer(t, built, "out"), nil
		})
	require.NoError(t, err)
	require.NotNil(t, answered)
}

// Two first attempts of one effect must not both read no receipt and both run
// the handler; the store's admission is what makes exactly one of them run.
func TestConcurrentFirstAttemptsRunTheHandlerOnce(t *testing.T) {
	built := registry(t, fixture.Operation())
	store := receipts.NewMemoryStore()
	guard := interceptor(t, built, store)
	calls := &atomic.Int64{}

	const attempts = 8
	answers := make([]proto.Message, attempts)
	start := make(chan struct{})
	group := sync.WaitGroup{}
	group.Add(attempts)
	for index := range attempts {
		go func() {
			defer group.Done()
			<-start
			answered, err := guard.Handle(t.Context(), fixture.OperationMethod, "effect-1",
				request(t, built, "in"), recordingHandler(t, built, store, "out", calls))
			require.NoError(t, err)
			answers[index] = answered
		}()
	}
	close(start)
	group.Wait()

	require.Equal(t, int64(1), calls.Load(), "the effect ran more than once")
	for _, answered := range answers {
		require.True(t, proto.Equal(answers[0], answered))
	}
}

func TestAnInterceptorNeedsAStoreAndATenant(t *testing.T) {
	built := registry(t, fixture.Operation())

	_, err := receipts.New(receipts.Options{
		Tenant: func(context.Context) (string, error) { return testTenant, nil },
		Files:  built.Files, Types: built.Types,
	})
	require.ErrorIs(t, err, receipts.ErrInvalid)

	_, err = receipts.New(receipts.Options{
		Store: receipts.NewMemoryStore(),
		Files: built.Files, Types: built.Types,
	})
	require.ErrorIs(t, err, receipts.ErrInvalid)
}

// A policy the runtime would refuse to install is refused when the server
// starts rather than leaving the method unguarded.
func TestAnUninstallableOperationIsRefusedAtConstruction(t *testing.T) {
	declared := fixture.Operation()
	declared.MaxAttempts = 99

	built := registry(t, declared)
	_, err := receipts.New(receipts.Options{
		Store:  receipts.NewMemoryStore(),
		Tenant: func(context.Context) (string, error) { return testTenant, nil },
		Files:  built.Files,
		Types:  built.Types,
	})
	require.ErrorContains(t, err, "max_attempts")
}

func TestRecordNeedsAnAdmittedEffectAndATransaction(t *testing.T) {
	built := registry(t, fixture.Operation())
	store := receipts.NewMemoryStore()
	committed := answer(t, built, "out")

	require.ErrorIs(t, receipts.Record(t.Context(), store, receipts.NoTx{}, committed), receipts.ErrNoEffect)
	require.Equal(t, receipts.RefusalInternal,
		receipts.RefusalFor(receipts.Record(t.Context(), store, receipts.NoTx{}, committed)))

	admitted := receipts.WithEffect(t.Context(), receipts.Effect{
		ID: "effect-1", Tenant: testTenant, Method: fixture.OperationMethod, RequestDigest: []byte{1},
	})
	require.ErrorIs(t, receipts.Record(admitted, store, nil, committed), receipts.ErrInvalid)
	require.ErrorIs(t, receipts.Record(admitted, nil, receipts.NoTx{}, committed), receipts.ErrInvalid)
	require.NoError(t, receipts.Record(admitted, store, receipts.NoTx{}, committed))
}

func TestRequestDigestSeparatesRequestsAndSurvivesReencoding(t *testing.T) {
	built := registry(t, fixture.Operation())

	one, err := receipts.RequestDigest(request(t, built, "in"))
	require.NoError(t, err)
	again, err := receipts.RequestDigest(request(t, built, "in"))
	require.NoError(t, err)
	other, err := receipts.RequestDigest(request(t, built, "different"))
	require.NoError(t, err)

	require.Equal(t, one, again)
	require.NotEqual(t, one, other)

	_, err = receipts.RequestDigest(nil)
	require.ErrorIs(t, err, receipts.ErrInvalid)
}

func TestMemoryStoreSweepsByCutoff(t *testing.T) {
	store := receipts.NewMemoryStore()
	now := time.Now().UTC()
	for index, committedAt := range []time.Time{now.Add(-8 * 24 * time.Hour), now} {
		require.NoError(t, store.Record(t.Context(), receipts.NoTx{}, receipts.Receipt{
			EffectID: "effect-" + string(rune('a'+index)), Tenant: testTenant,
			Method: fixture.OperationMethod, RequestDigest: []byte{byte(index)},
			Response: []byte{byte(index)}, CommittedAt: committedAt,
		}))
	}

	swept, err := store.Sweep(t.Context(), now.Add(-receipts.DefaultRetention))
	require.NoError(t, err)
	require.Equal(t, int64(1), swept)

	_, found, err := store.Lookup(t.Context(), testTenant, "effect-a", fixture.OperationMethod)
	require.NoError(t, err)
	require.False(t, found, "a swept receipt is still readable")

	_, found, err = store.Lookup(t.Context(), testTenant, "effect-b", fixture.OperationMethod)
	require.NoError(t, err)
	require.True(t, found)
}

func TestMemoryStoreRefusesAnIncompleteReceipt(t *testing.T) {
	store := receipts.NewMemoryStore()
	complete := receipts.Receipt{
		EffectID: "effect-1", Tenant: testTenant, Method: fixture.OperationMethod,
		RequestDigest: []byte{1}, Response: []byte{2}, CommittedAt: time.Now().UTC(),
	}

	require.ErrorIs(t, store.Record(t.Context(), nil, complete), receipts.ErrInvalid)

	for name, mutate := range map[string]func(*receipts.Receipt){
		"no tenant": func(r *receipts.Receipt) { r.Tenant = "" },
		"no effect": func(r *receipts.Receipt) { r.EffectID = "" },
		"no method": func(r *receipts.Receipt) { r.Method = "" },
		"no digest": func(r *receipts.Receipt) { r.RequestDigest = nil },
		"no time":   func(r *receipts.Receipt) { r.CommittedAt = time.Time{} },
	} {
		t.Run(name, func(t *testing.T) {
			incomplete := complete
			mutate(&incomplete)
			require.ErrorIs(t, store.Record(t.Context(), receipts.NoTx{}, incomplete), receipts.ErrInvalid)
		})
	}

	_, _, err := store.Lookup(t.Context(), "", "effect-1", fixture.OperationMethod)
	require.ErrorIs(t, err, receipts.ErrInvalid)
	_, err = store.Serialize(t.Context(), "", "effect-1", fixture.OperationMethod)
	require.ErrorIs(t, err, receipts.ErrInvalid)
}

// A caller whose deadline passes while another attempt holds the effect reports
// that rather than queueing behind an attempt whose answer it can no longer use.
func TestSerializeStopsWaitingWhenTheCallerGivesUp(t *testing.T) {
	store := receipts.NewMemoryStore()
	release, err := store.Serialize(t.Context(), testTenant, "effect-1", fixture.OperationMethod)
	require.NoError(t, err)
	defer release()

	waiting, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
	defer cancel()
	_, err = store.Serialize(waiting, testTenant, "effect-1", fixture.OperationMethod)
	require.ErrorIs(t, err, context.DeadlineExceeded)
}

func TestATenantThatCannotBeResolvedRefusesTheCall(t *testing.T) {
	built := registry(t, fixture.Operation())
	guard, err := receipts.New(receipts.Options{
		Store:  receipts.NewMemoryStore(),
		Tenant: func(context.Context) (string, error) { return "", nil },
		Files:  built.Files,
		Types:  built.Types,
	})
	require.NoError(t, err)

	_, err = guard.Handle(t.Context(), fixture.OperationMethod, "effect-1", request(t, built, "in"),
		func(context.Context) (proto.Message, error) { return nil, nil })
	require.ErrorIs(t, err, receipts.ErrInvalid)
}
