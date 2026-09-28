package receipts_test

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"

	"github.com/codefly-dev/sdk-go/receipts"
	"github.com/codefly-dev/sdk-go/receipts/internal/fixture"
)

// A module that isolates its tenants with row-level security binds the tenant
// in a transaction-local setting its policies read. These tests put the
// receipts table under such a policy and run the store as a role the policy
// applies to — never the DSN's own role, which in CI is a superuser, and a
// superuser bypasses every policy, forced or not.
const tenantSetting = "app.current_tenant"

func bindTenant(ctx context.Context, tx *sql.Tx, tenant string) error {
	_, err := tx.ExecContext(ctx, `SELECT set_config('`+tenantSetting+`', $1, true)`, tenant)
	return err
}

var rowLevelSecuredDatabases atomic.Int64

// rowLevelSecured gives one test its own schema holding the receipts table
// under a forced tenant-isolation policy, and a pool whose connections run as
// a role that policy applies to. The schema is the test's own because the
// policy would otherwise hide every other test's receipts.
func rowLevelSecured(t *testing.T) *sql.DB {
	t.Helper()
	dsn := os.Getenv(postgresDSNVariable)
	if dsn == "" {
		t.Skipf("%s is not set, so the receipts store has no database to run against", postgresDSNVariable)
	}
	name := fmt.Sprintf("receipts_rls_%s_%d", testRun, rowLevelSecuredDatabases.Add(1))
	identifier := pgx.Identifier{name}.Sanitize()

	owner := openInSchema(t, dsn, name)
	t.Cleanup(func() {
		// t.Context is already cancelled when cleanups run.
		ctx := context.Background()
		_, dropSchemaErr := owner.ExecContext(ctx, `DROP SCHEMA IF EXISTS `+identifier+` CASCADE`)
		_, dropRoleErr := owner.ExecContext(ctx, `DROP ROLE IF EXISTS `+identifier)
		require.NoError(t, errors.Join(dropSchemaErr, dropRoleErr, owner.Close()))
	})
	for _, statement := range []string{
		`CREATE ROLE ` + identifier + ` NOLOGIN`,
		`CREATE SCHEMA ` + identifier,
		`GRANT USAGE ON SCHEMA ` + identifier + ` TO ` + identifier,
	} {
		_, err := owner.ExecContext(t.Context(), statement)
		require.NoError(t, err, statement)
	}
	require.NoError(t, receipts.Migrate(t.Context(), owner))
	for _, statement := range []string{
		`ALTER TABLE codefly_effect_receipts ENABLE ROW LEVEL SECURITY`,
		`ALTER TABLE codefly_effect_receipts FORCE ROW LEVEL SECURITY`,
		`CREATE POLICY tenant_isolation ON codefly_effect_receipts TO ` + identifier +
			` USING (tenant = NULLIF(current_setting('` + tenantSetting + `', true), ''))`,
		`GRANT SELECT, INSERT, DELETE ON codefly_effect_receipts TO ` + identifier,
	} {
		_, err := owner.ExecContext(t.Context(), statement)
		require.NoError(t, err, statement)
	}

	secured := openInSchema(t, dsn, name, stdlib.OptionAfterConnect(func(ctx context.Context, connection *pgx.Conn) error {
		_, err := connection.Exec(ctx, `SET ROLE `+identifier)
		return err
	}))
	t.Cleanup(func() { require.NoError(t, secured.Close()) })
	var superuser string
	require.NoError(t, secured.QueryRowContext(t.Context(), `SELECT current_setting('is_superuser')`).Scan(&superuser))
	require.Equal(t, "off", superuser, "the policy under test does not apply to a superuser")
	return secured
}

func openInSchema(t *testing.T, dsn, schema string, options ...stdlib.OptionOpenDB) *sql.DB {
	t.Helper()
	config, err := pgx.ParseConfig(dsn)
	require.NoError(t, err)
	config.RuntimeParams["search_path"] = schema
	db := stdlib.OpenDB(*config, options...)
	require.NoError(t, db.PingContext(t.Context()))
	return db
}

func scopedStore(t *testing.T, db *sql.DB) *receipts.PostgresStore {
	t.Helper()
	store, err := receipts.NewPostgresStore(db, receipts.WithTenantScope(bindTenant))
	require.NoError(t, err)
	return store
}

// recordAs writes a receipt the way a module under row-level security does:
// in its own transaction, which it has bound to the effect's tenant.
func recordAs(t *testing.T, store *receipts.PostgresStore, db *sql.DB, receipt receipts.Receipt) {
	t.Helper()
	tx, err := db.BeginTx(t.Context(), nil)
	require.NoError(t, err)
	require.NoError(t, bindTenant(t.Context(), tx, receipt.Tenant))
	require.NoError(t, store.Record(t.Context(), tx, receipt))
	require.NoError(t, tx.Commit())
}

// boundTenantHandler commits its answer in a transaction bound to the tenant
// of the effect it was admitted under, as a handler in such a module does.
func boundTenantHandler(
	t *testing.T,
	built fixture.Registry,
	store receipts.Store,
	db *sql.DB,
	calls *atomic.Int64,
) func(context.Context) (proto.Message, error) {
	t.Helper()
	return func(ctx context.Context) (proto.Message, error) {
		calls.Add(1)
		effect, admitted := receipts.EffectFromContext(ctx)
		if !admitted {
			return nil, receipts.ErrNoEffect
		}
		committed := answer(t, built, "out")
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			return nil, err
		}
		if err = bindTenant(ctx, tx, effect.Tenant); err != nil {
			return nil, errors.Join(err, tx.Rollback())
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

func TestNewPostgresStoreRefusesAMissingTenantScope(t *testing.T) {
	db, err := sql.Open("pgx", "postgres://localhost/never-dialled")
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, db.Close()) })

	_, err = receipts.NewPostgresStore(db, receipts.WithTenantScope(nil))
	require.ErrorIs(t, err, receipts.ErrInvalid)
	_, err = receipts.NewPostgresStore(db, nil)
	require.ErrorIs(t, err, receipts.ErrInvalid)

	_, err = receipts.NewPostgresStore(db, receipts.WithTenantScope(bindTenant))
	require.NoError(t, err)
}

func TestSweepTenantRefusesAMissingTenantOrCutoff(t *testing.T) {
	db, err := sql.Open("pgx", "postgres://localhost/never-dialled")
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, db.Close()) })
	store := scopedStore(t, db)

	_, err = store.SweepTenant(t.Context(), "", time.Now())
	require.ErrorIs(t, err, receipts.ErrInvalid)
	_, err = store.SweepTenant(t.Context(), " padded ", time.Now())
	require.ErrorIs(t, err, receipts.ErrInvalid)
	_, err = store.SweepTenant(t.Context(), "tenant-a", time.Time{})
	require.ErrorIs(t, err, receipts.ErrInvalid)
}

// The gap the tenant scope closes. Every query the store issues on its own
// connections filters by tenant, but under a policy that admits only the bound
// tenant, a store with nothing bound reads no receipt at all — and a recovery
// that reads "no receipt" for an effect that committed runs it again.
func TestPostgresRowLevelSecurityHidesReceiptsFromAnUnscopedStore(t *testing.T) {
	secured := rowLevelSecured(t)
	unscoped, err := receipts.NewPostgresStore(secured)
	require.NoError(t, err)
	tenant := tenantOf(t)
	recordAs(t, unscoped, secured, receiptFor(tenant, "effect-1", []byte("d"), []byte("r")))

	_, found, err := scopedStore(t, secured).Lookup(t.Context(), tenant, "effect-1", fixture.OperationMethod)
	require.NoError(t, err)
	require.True(t, found, "the receipt was never committed, so its absence below proves nothing")

	_, found, err = unscoped.Lookup(t.Context(), tenant, "effect-1", fixture.OperationMethod)
	require.NoError(t, err)
	require.False(t, found)

	held, err := unscoped.Serialize(t.Context(), tenant, "effect-1", fixture.OperationMethod)
	require.NoError(t, err)
	_, found, err = held.Lookup(t.Context())
	held.Release()
	require.NoError(t, err)
	require.False(t, found)

	built := registry(t, fixture.Operation())
	guard, err := receipts.New(receipts.Options{
		Store:  unscoped,
		Tenant: func(context.Context) (string, error) { return tenant, nil },
		Files:  built.Files,
		Types:  built.Types,
	})
	require.NoError(t, err)
	calls := &atomic.Int64{}
	for range 2 {
		_, err = guard.Handle(t.Context(), fixture.OperationMethod, "effect-2", request(t, built, "in"),
			boundTenantHandler(t, built, unscoped, secured, calls))
		require.NoError(t, err)
	}
	require.Equal(t, int64(2), calls.Load(), "an unscoped store under row-level security replayed")
}

func TestPostgresTenantScopeReplaysUnderRowLevelSecurity(t *testing.T) {
	secured := rowLevelSecured(t)
	store := scopedStore(t, secured)
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
	for range 2 {
		answered, handleErr := guard.Handle(t.Context(), fixture.OperationMethod, "effect-1", request(t, built, "in"),
			boundTenantHandler(t, built, store, secured, calls))
		require.NoError(t, handleErr)
		require.True(t, proto.Equal(answer(t, built, "out"), answered))
	}
	require.Equal(t, int64(1), calls.Load(), "the effect ran a second time")
}

func TestPostgresTenantScopeReadsOnlyTheBoundTenant(t *testing.T) {
	secured := rowLevelSecured(t)
	store := scopedStore(t, secured)
	tenantA, tenantB := tenantOf(t)+"/a", tenantOf(t)+"/b"
	recordAs(t, store, secured, receiptFor(tenantA, "effect-1", []byte("d"), []byte("answer-a")))
	recordAs(t, store, secured, receiptFor(tenantB, "effect-1", []byte("d"), []byte("answer-b")))
	recordAs(t, store, secured, receiptFor(tenantB, "effect-only-b", []byte("d"), []byte("answer-b")))

	for tenant, response := range map[string]string{tenantA: "answer-a", tenantB: "answer-b"} {
		read, found, err := store.Lookup(t.Context(), tenant, "effect-1", fixture.OperationMethod)
		require.NoError(t, err)
		require.True(t, found, tenant)
		require.Equal(t, []byte(response), read.Response, tenant)
	}
	_, found, err := store.Lookup(t.Context(), tenantA, "effect-only-b", fixture.OperationMethod)
	require.NoError(t, err)
	require.False(t, found, "one tenant read another's outcome")

	// The policy, not only the query's own tenant filter, decides what the read
	// sees: a scope bound to the wrong tenant finds nothing even though the
	// statement asks for tenant A by name.
	misbound, err := receipts.NewPostgresStore(secured, receipts.WithTenantScope(
		func(ctx context.Context, tx *sql.Tx, _ string) error { return bindTenant(ctx, tx, tenantB) }))
	require.NoError(t, err)
	_, found, err = misbound.Lookup(t.Context(), tenantA, "effect-1", fixture.OperationMethod)
	require.NoError(t, err)
	require.False(t, found, "the read did not run under the scope's binding")
}

// The lock stays session-level while each read under it is its own scoped
// transaction: committing a read must not give the lock up.
func TestPostgresTenantScopeReadsUnderAHold(t *testing.T) {
	secured := rowLevelSecured(t)
	store := scopedStore(t, secured)
	tenantA, tenantB := tenantOf(t)+"/a", tenantOf(t)+"/b"
	recordAs(t, store, secured, receiptFor(tenantA, "effect-1", []byte("d"), []byte("answer-a")))
	recordAs(t, store, secured, receiptFor(tenantB, "effect-1", []byte("d"), []byte("answer-b")))
	recordAs(t, store, secured, receiptFor(tenantB, "effect-only-b", []byte("d"), []byte("answer-b")))

	held, err := store.Serialize(t.Context(), tenantA, "effect-1", fixture.OperationMethod)
	require.NoError(t, err)
	for range 2 {
		read, found, lookupErr := held.Lookup(t.Context())
		require.NoError(t, lookupErr)
		require.True(t, found)
		require.Equal(t, []byte("answer-a"), read.Response)
	}

	waiting, cancel := context.WithTimeout(t.Context(), 300*time.Millisecond)
	defer cancel()
	_, err = store.Serialize(waiting, tenantA, "effect-1", fixture.OperationMethod)
	require.ErrorIs(t, err, context.DeadlineExceeded, "a scoped read under the hold released its lock")

	held.Release()
	reacquired, err := store.Serialize(t.Context(), tenantA, "effect-1", fixture.OperationMethod)
	require.NoError(t, err)
	reacquired.Release()

	elsewhere, err := store.Serialize(t.Context(), tenantA, "effect-only-b", fixture.OperationMethod)
	require.NoError(t, err)
	defer elsewhere.Release()
	_, found, err := elsewhere.Lookup(t.Context())
	require.NoError(t, err)
	require.False(t, found, "one tenant read another's outcome under a hold")
}

// The binding ends with the call. The pool has one connection, so every check
// below reads the very connection the store just used — which the control at
// the end proves, with a scope that binds at session level and leaks.
func TestPostgresTenantScopeDoesNotOutliveTheCall(t *testing.T) {
	secured := rowLevelSecured(t)
	secured.SetMaxOpenConns(1)
	store := scopedStore(t, secured)
	tenant := tenantOf(t)
	recordAs(t, store, secured, receiptFor(tenant, "effect-1", []byte("d"), []byte("r")))

	bound := func() (string, int) {
		t.Helper()
		var setting string
		var visible int
		require.NoError(t, secured.QueryRowContext(t.Context(),
			`SELECT coalesce(current_setting('`+tenantSetting+`', true), '')`).Scan(&setting))
		require.NoError(t, secured.QueryRowContext(t.Context(),
			`SELECT count(*) FROM codefly_effect_receipts`).Scan(&visible))
		return setting, visible
	}
	unbound := func(after string) {
		t.Helper()
		setting, visible := bound()
		require.Empty(t, setting, "the tenant stayed bound on the connection after %s", after)
		require.Zero(t, visible, "the connection still saw receipts after %s", after)
	}

	_, found, err := store.Lookup(t.Context(), tenant, "effect-1", fixture.OperationMethod)
	require.NoError(t, err)
	require.True(t, found)
	unbound("Lookup")

	held, err := store.Serialize(t.Context(), tenant, "effect-1", fixture.OperationMethod)
	require.NoError(t, err)
	_, found, err = held.Lookup(t.Context())
	require.NoError(t, err)
	require.True(t, found)
	held.Release()
	unbound("Held.Lookup")

	_, err = store.SweepTenant(t.Context(), tenant, time.Now().Add(-receipts.DefaultRetention))
	require.NoError(t, err)
	unbound("SweepTenant")

	leaky, err := receipts.NewPostgresStore(secured, receipts.WithTenantScope(
		func(ctx context.Context, tx *sql.Tx, tenant string) error {
			_, setErr := tx.ExecContext(ctx, `SELECT set_config('`+tenantSetting+`', $1, false)`, tenant)
			return setErr
		}))
	require.NoError(t, err)
	_, found, err = leaky.Lookup(t.Context(), tenant, "effect-1", fixture.OperationMethod)
	require.NoError(t, err)
	require.True(t, found)
	setting, visible := bound()
	require.Equal(t, tenant, setting, "the checks above did not read the connection the store used")
	require.Equal(t, 1, visible)
}

func TestPostgresSweepTenantRemovesOnlyThatTenantsExpiredReceipts(t *testing.T) {
	secured := rowLevelSecured(t)
	store := scopedStore(t, secured)
	tenantA, tenantB := tenantOf(t)+"/a", tenantOf(t)+"/b"
	now := time.Now().UTC()
	for _, tenant := range []string{tenantA, tenantB} {
		for effectID, committedAt := range map[string]time.Time{
			"effect-old":    now.Add(-8 * 24 * time.Hour),
			"effect-recent": now,
		} {
			written := receiptFor(tenant, effectID, []byte("d"), []byte("r"))
			written.CommittedAt = committedAt
			recordAs(t, store, secured, written)
		}
	}
	cutoff := now.Add(-receipts.DefaultRetention)

	// Sweep stays one unscoped statement, so under the policy, with no tenant
	// bound, it removes nothing.
	swept, err := store.Sweep(t.Context(), cutoff)
	require.NoError(t, err)
	require.Zero(t, swept)

	swept, err = store.SweepTenant(t.Context(), tenantA, cutoff)
	require.NoError(t, err)
	require.Equal(t, int64(1), swept)

	for _, expected := range []struct {
		tenant, effectID string
		present          bool
	}{
		{tenantA, "effect-old", false},
		{tenantA, "effect-recent", true},
		{tenantB, "effect-old", true},
		{tenantB, "effect-recent", true},
	} {
		_, found, lookupErr := store.Lookup(t.Context(), expected.tenant, expected.effectID, fixture.OperationMethod)
		require.NoError(t, lookupErr)
		require.Equal(t, expected.present, found, "%s %s", expected.tenant, expected.effectID)
	}

	swept, err = store.SweepTenant(t.Context(), tenantB, cutoff)
	require.NoError(t, err)
	require.Equal(t, int64(1), swept)
}

// Without a scope SweepTenant is still one tenant's sweep, for a module that
// keeps retention per tenant without row-level security.
func TestPostgresSweepTenantWithoutAScope(t *testing.T) {
	store, db := postgres(t)
	tenantA, tenantB := tenantOf(t)+"/a", tenantOf(t)+"/b"
	for _, tenant := range []string{tenantA, tenantB} {
		written := receiptFor(tenant, "effect-old", []byte("d"), []byte("r"))
		written.CommittedAt = time.Now().UTC().Add(-8 * 24 * time.Hour)
		tx, err := db.BeginTx(t.Context(), nil)
		require.NoError(t, err)
		require.NoError(t, store.Record(t.Context(), tx, written))
		require.NoError(t, tx.Commit())
	}

	swept, err := store.SweepTenant(t.Context(), tenantA, time.Now().Add(-receipts.DefaultRetention))
	require.NoError(t, err)
	require.Equal(t, int64(1), swept)

	_, found, err := store.Lookup(t.Context(), tenantB, "effect-old", fixture.OperationMethod)
	require.NoError(t, err)
	require.True(t, found, "sweeping one tenant removed another's receipt")
}

// A scope that cannot bind fails the call. Falling back to an unscoped
// statement would read "no receipt" under the policy, which is the one answer
// a recovery must never get for an effect that committed.
func TestPostgresTenantScopeErrorFailsTheCall(t *testing.T) {
	_, db := postgres(t)
	refused := errors.New("the tenant cannot be bound")
	store, err := receipts.NewPostgresStore(db, receipts.WithTenantScope(
		func(context.Context, *sql.Tx, string) error { return refused }))
	require.NoError(t, err)
	tenant := tenantOf(t)

	_, _, err = store.Lookup(t.Context(), tenant, "effect-1", fixture.OperationMethod)
	require.ErrorIs(t, err, refused)

	held, err := store.Serialize(t.Context(), tenant, "effect-1", fixture.OperationMethod)
	require.NoError(t, err)
	defer held.Release()
	_, _, err = held.Lookup(t.Context())
	require.ErrorIs(t, err, refused)

	_, err = store.SweepTenant(t.Context(), tenant, time.Now())
	require.ErrorIs(t, err, refused)
}
