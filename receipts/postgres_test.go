package receipts_test

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"

	"github.com/codefly-dev/sdk-go/receipts"
	"github.com/codefly-dev/sdk-go/receipts/internal/fixture"
)

// The store is the half of this package that only a database can exercise: the
// receipt is written in the caller's transaction, the admission is a Postgres
// advisory lock, and idempotence is a primary key. A fake would assert the
// behaviour of the fake.
const postgresDSNVariable = "CODEFLY_TEST_POSTGRES_DSN"

func postgres(t *testing.T) (*receipts.PostgresStore, *sql.DB) {
	t.Helper()
	dsn := os.Getenv(postgresDSNVariable)
	if dsn == "" {
		t.Skipf("%s is not set, so the receipts store has no database to run against", postgresDSNVariable)
	}
	db, err := sql.Open("pgx", dsn)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, db.Close()) })
	require.NoError(t, db.PingContext(t.Context()))
	require.NoError(t, receipts.Migrate(t.Context(), db))

	store, err := receipts.NewPostgresStore(db)
	require.NoError(t, err)
	return store, db
}

// testRun makes each run's tenants its own. A tenant named after the test alone
// is stable across runs, so the second run of the suite against one database
// reads the first run's receipts and replays instead of running its handler.
var testRun = func() string {
	drawn := make([]byte, 8)
	if _, err := rand.Read(drawn); err != nil {
		panic(err)
	}
	return hex.EncodeToString(drawn)
}()

// Each test owns a tenant, which is also the column every index leads with, so
// the suite needs no truncation.
func tenantOf(t *testing.T) string {
	t.Helper()
	return "tenant/" + testRun + "/" + t.Name()
}

func receiptFor(tenant, effectID string, digest, response []byte) receipts.Receipt {
	return receipts.Receipt{
		EffectID:      effectID,
		Tenant:        tenant,
		Method:        fixture.OperationMethod,
		RequestDigest: digest,
		Response:      response,
		CommittedAt:   time.Now().UTC().Truncate(time.Microsecond),
	}
}

func TestPostgresMigrationIsRepeatable(t *testing.T) {
	_, db := postgres(t)
	require.NoError(t, receipts.Migrate(t.Context(), db))
	require.NoError(t, receipts.Migrate(t.Context(), db))
}

func TestPostgresRecordsAndReadsBackOneReceipt(t *testing.T) {
	store, db := postgres(t)
	tenant := tenantOf(t)
	written := receiptFor(tenant, "effect-1", []byte("digest"), []byte("response"))

	tx, err := db.BeginTx(t.Context(), nil)
	require.NoError(t, err)
	require.NoError(t, store.Record(t.Context(), tx, written))
	require.NoError(t, tx.Commit())

	read, found, err := store.Lookup(t.Context(), tenant, "effect-1", fixture.OperationMethod)
	require.NoError(t, err)
	require.True(t, found)
	require.Equal(t, written.RequestDigest, read.RequestDigest)
	require.Equal(t, written.Response, read.Response)
	require.WithinDuration(t, written.CommittedAt, read.CommittedAt, time.Millisecond)

	_, found, err = store.Lookup(t.Context(), tenant, "effect-absent", fixture.OperationMethod)
	require.NoError(t, err)
	require.False(t, found)
}

// A receipt written in a transaction that rolls back is not a receipt. This is
// the property the Tx parameter exists for, and the only one a store without a
// database cannot show.
func TestPostgresReceiptIsPartOfTheCommit(t *testing.T) {
	store, db := postgres(t)
	tenant := tenantOf(t)

	tx, err := db.BeginTx(t.Context(), nil)
	require.NoError(t, err)
	require.NoError(t, store.Record(t.Context(), tx, receiptFor(tenant, "effect-1", []byte("d"), []byte("r"))))
	require.NoError(t, tx.Rollback())

	_, found, err := store.Lookup(t.Context(), tenant, "effect-1", fixture.OperationMethod)
	require.NoError(t, err)
	require.False(t, found, "a rolled-back effect left a receipt behind")
}

func TestPostgresRefusesAnAlreadyFinishedTransaction(t *testing.T) {
	store, db := postgres(t)
	tenant := tenantOf(t)

	tx, err := db.BeginTx(t.Context(), nil)
	require.NoError(t, err)
	require.NoError(t, tx.Commit())

	err = store.Record(t.Context(), tx, receiptFor(tenant, "effect-1", []byte("d"), []byte("r")))
	require.ErrorIs(t, err, sql.ErrTxDone)
}

// Re-recording one effect is the normal outcome of a retried attempt, so it is
// idempotent rather than a conflict — and the first answer is the one kept.
func TestPostgresRecordIsIdempotent(t *testing.T) {
	store, db := postgres(t)
	tenant := tenantOf(t)

	for _, response := range [][]byte{[]byte("first"), []byte("second")} {
		tx, err := db.BeginTx(t.Context(), nil)
		require.NoError(t, err)
		require.NoError(t, store.Record(t.Context(), tx, receiptFor(tenant, "effect-1", []byte("d"), response)))
		require.NoError(t, tx.Commit())
	}

	read, found, err := store.Lookup(t.Context(), tenant, "effect-1", fixture.OperationMethod)
	require.NoError(t, err)
	require.True(t, found)
	require.Equal(t, []byte("first"), read.Response)
}

func TestPostgresKeepsTenantsApart(t *testing.T) {
	store, db := postgres(t)
	tenant := tenantOf(t)

	tx, err := db.BeginTx(t.Context(), nil)
	require.NoError(t, err)
	require.NoError(t, store.Record(t.Context(), tx, receiptFor(tenant, "effect-1", []byte("d"), []byte("r"))))
	require.NoError(t, tx.Commit())

	_, found, err := store.Lookup(t.Context(), tenant+"-other", "effect-1", fixture.OperationMethod)
	require.NoError(t, err)
	require.False(t, found, "one tenant read another's outcome")
}

func TestPostgresSweepRemovesReceiptsPastTheCutoff(t *testing.T) {
	store, db := postgres(t)
	tenant := tenantOf(t)
	now := time.Now().UTC()

	for effectID, committedAt := range map[string]time.Time{
		"effect-old":    now.Add(-8 * 24 * time.Hour),
		"effect-recent": now,
	} {
		written := receiptFor(tenant, effectID, []byte("d"), []byte("r"))
		written.CommittedAt = committedAt
		tx, err := db.BeginTx(t.Context(), nil)
		require.NoError(t, err)
		require.NoError(t, store.Record(t.Context(), tx, written))
		require.NoError(t, tx.Commit())
	}

	swept, err := store.Sweep(t.Context(), now.Add(-receipts.DefaultRetention))
	require.NoError(t, err)
	require.GreaterOrEqual(t, swept, int64(1))

	_, found, err := store.Lookup(t.Context(), tenant, "effect-old", fixture.OperationMethod)
	require.NoError(t, err)
	require.False(t, found, "a swept receipt is still readable")

	_, found, err = store.Lookup(t.Context(), tenant, "effect-recent", fixture.OperationMethod)
	require.NoError(t, err)
	require.True(t, found)

	_, err = store.Sweep(t.Context(), time.Time{})
	require.ErrorIs(t, err, receipts.ErrInvalid)
}

// Concurrent first attempts of one effect must not both read no receipt and
// both run the handler: the advisory lock is the admission that makes exactly
// one of them run, and the rest replay what it committed.
func TestPostgresSerializesConcurrentFirstAttempts(t *testing.T) {
	store, db := postgres(t)
	built := registry(t, fixture.Operation())
	tenant := tenantOf(t)
	guard, err := receipts.New(receipts.Options{
		Store:  store,
		Tenant: func(context.Context) (string, error) { return tenant, nil },
		Files:  built.Files,
		Types:  built.Types,
	})
	require.NoError(t, err)

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
			answered, handleErr := guard.Handle(t.Context(), fixture.OperationMethod, "effect-1",
				request(t, built, "in"), committingHandler(t, built, store, db, calls))
			require.NoError(t, handleErr)
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

// A process that dies after its transaction commits but before its caller sees
// the answer still leaves a receipt, because the receipt was in that commit.
// The next attempt therefore replays instead of running the effect again.
func TestPostgresReceiptSurvivesACrashAfterTheCommit(t *testing.T) {
	store, db := postgres(t)
	built := registry(t, fixture.Operation())
	tenant := tenantOf(t)
	guard, err := receipts.New(receipts.Options{
		Store:  store,
		Tenant: func(context.Context) (string, error) { return tenant, nil },
		Files:  built.Files,
		Types:  built.Types,
	})
	require.NoError(t, err)

	crash := errors.New("the process died after the commit")
	calls := &atomic.Int64{}
	_, err = guard.Handle(t.Context(), fixture.OperationMethod, "effect-1", request(t, built, "in"),
		func(ctx context.Context) (proto.Message, error) {
			if _, commitErr := committingHandler(t, built, store, db, calls)(ctx); commitErr != nil {
				return nil, commitErr
			}
			return nil, crash
		})
	require.ErrorIs(t, err, crash)
	require.Equal(t, int64(1), calls.Load())

	replayed, err := guard.Handle(t.Context(), fixture.OperationMethod, "effect-1", request(t, built, "in"),
		committingHandler(t, built, store, db, calls))
	require.NoError(t, err)
	require.Equal(t, int64(1), calls.Load(), "the effect ran a second time after a crash")
	require.True(t, proto.Equal(answer(t, built, "out"), replayed))
}

// committingHandler is what a real handler does: it records the receipt on the
// very transaction it commits with.
func committingHandler(
	t *testing.T,
	built fixture.Registry,
	store receipts.Store,
	db *sql.DB,
	calls *atomic.Int64,
) func(context.Context) (proto.Message, error) {
	t.Helper()
	return func(ctx context.Context) (proto.Message, error) {
		calls.Add(1)
		committed := answer(t, built, "out")
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			return nil, err
		}
		if err = receipts.Record(ctx, store, tx, committed); err != nil {
			return nil, errors.Join(err, tx.Rollback())
		}
		if err = tx.Commit(); err != nil {
			return nil, err
		}
		return committed, nil
	}
}
