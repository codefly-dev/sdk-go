package receipts

import (
	"context"
	"crypto/sha256"
	"database/sql"
	_ "embed"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
	"time"
)

// Schema is the table a module installs to hold its effect receipts. It is
// exported so a module can hand it to whichever migration tool it already runs;
// Migrate applies it directly for a module that has none.
//
//go:embed schema.sql
var Schema string

// PostgresStore keeps receipts in the module's own Postgres database, in the
// database the effects themselves commit to.
type PostgresStore struct {
	db    *sql.DB
	scope TenantScope
}

// TenantScope binds one tenant to a transaction the store opened for itself,
// before the store's own statement runs in it. It is how a module that
// enforces tenant isolation with row-level security admits the store's reads
// and sweeps to exactly the tenant they are for: the hook sets whatever the
// module's policies read, typically
//
//	_, err := tx.ExecContext(ctx, `SELECT set_config('app.current_tenant', $1, true)`, tenant)
//
// The hook must set only transaction-local state — set_config with is_local
// true, or SET LOCAL. The store runs it on pooled connections and on the one
// connection a hold pins, so session-level state would outlive the call and
// the next statement on that connection, for another tenant, would run under
// this tenant's binding. Transaction-local state ends with the transaction the
// store opened, and the store opens one per call.
//
// The transactions a lookup opens are read-only. An error from the hook fails
// the call; the store never falls back to an unscoped statement.
type TenantScope func(ctx context.Context, tx *sql.Tx, tenant string) error

// PostgresOption configures a PostgresStore.
type PostgresOption func(*PostgresStore) error

// WithTenantScope makes the store bind the receipt's tenant before it reads or
// deletes receipts on its own connections: Lookup, each Held.Lookup and
// SweepTenant then run inside a transaction scope has bound to that tenant.
// Without it they run unscoped, as they always have.
//
// Record needs no scope: it writes in the caller's transaction, which the
// caller binds as it binds the effect's own statements. Serialize's advisory
// lock reads no table, so it is still taken at session level on the pinned
// connection and outlives each scoped read under it. Sweep is one statement
// across every tenant and stays unscoped; see SweepTenant.
func WithTenantScope(scope TenantScope) PostgresOption {
	return func(store *PostgresStore) error {
		if scope == nil {
			return fmt.Errorf("%w: tenant scope is required", ErrInvalid)
		}
		store.scope = scope
		return nil
	}
}

// NewPostgresStore binds the store to the pool the module's effects commit
// through. The pool must reach the same database as those effects: a receipt
// written to another one could not be written in their transaction.
func NewPostgresStore(db *sql.DB, options ...PostgresOption) (*PostgresStore, error) {
	if db == nil {
		return nil, fmt.Errorf("%w: database handle is required", ErrInvalid)
	}
	store := &PostgresStore{db: db}
	for _, option := range options {
		if option == nil {
			return nil, fmt.Errorf("%w: store option is nil", ErrInvalid)
		}
		if err := option(store); err != nil {
			return nil, err
		}
	}
	return store, nil
}

// Migrate creates the receipts table if it is absent.
func Migrate(ctx context.Context, db *sql.DB) error {
	if db == nil {
		return fmt.Errorf("%w: database handle is required", ErrInvalid)
	}
	if _, err := db.ExecContext(ctx, Schema); err != nil {
		return fmt.Errorf("install the Codefly effect receipts table: %w", err)
	}
	return nil
}

const recordReceiptStatement = `
INSERT INTO codefly_effect_receipts
    (tenant, effect_id, method, request_digest, response, committed_at)
VALUES ($1, $2, $3, $4, $5, $6)
ON CONFLICT (tenant, effect_id, method) DO NOTHING`

func (s *PostgresStore) Record(ctx context.Context, tx Tx, receipt Receipt) error {
	if tx == nil {
		return fmt.Errorf("%w: the transaction committing the effect is required", ErrInvalid)
	}
	if err := receipt.validate(); err != nil {
		return err
	}
	_, err := tx.ExecContext(ctx, recordReceiptStatement,
		receipt.Tenant,
		receipt.EffectID,
		receipt.Method,
		receipt.RequestDigest,
		receipt.Response,
		receipt.CommittedAt.UTC(),
	)
	if err != nil {
		return fmt.Errorf("record the Codefly effect receipt: %w", err)
	}
	return nil
}

const lookupReceiptStatement = `
SELECT request_digest, response, committed_at
FROM codefly_effect_receipts
WHERE tenant = $1 AND effect_id = $2 AND method = $3`

func (s *PostgresStore) Lookup(ctx context.Context, tenant, effectID, method string) (*Receipt, bool, error) {
	if err := validateEffectKey(tenant, effectID, method); err != nil {
		return nil, false, err
	}
	return scopedLookup(ctx, s.db, s.scope, tenant, effectID, method)
}

// queryer is what a receipt is read through: the store's pool, the one
// connection a hold pins, or a transaction opened on either.
type queryer interface {
	QueryRowContext(ctx context.Context, query string, arguments ...any) *sql.Row
}

// session is where the store opens its own statements: the store's pool, or
// the one connection a hold pins.
type session interface {
	queryer
	BeginTx(ctx context.Context, options *sql.TxOptions) (*sql.Tx, error)
}

// scopedLookup reads a receipt on the session directly when the store has no
// tenant scope, and otherwise inside a read-only transaction the scope has
// bound to the tenant, so the read is admitted by the module's row-level
// security policies and the binding ends with it.
func scopedLookup(ctx context.Context, on session, scope TenantScope, tenant, effectID, method string) (*Receipt, bool, error) {
	if scope == nil {
		return lookupReceipt(ctx, on, tenant, effectID, method)
	}
	var (
		receipt *Receipt
		found   bool
	)
	err := inTenantTransaction(ctx, on, &sql.TxOptions{ReadOnly: true}, scope, tenant, func(tx *sql.Tx) error {
		var err error
		receipt, found, err = lookupReceipt(ctx, tx, tenant, effectID, method)
		return err
	})
	if err != nil {
		return nil, false, err
	}
	return receipt, found, nil
}

// inTenantTransaction runs work in a transaction on the session, bound to the
// tenant by scope first when there is one, and commits it.
func inTenantTransaction(
	ctx context.Context,
	on session,
	options *sql.TxOptions,
	scope TenantScope,
	tenant string,
	work func(tx *sql.Tx) error,
) error {
	tx, err := on.BeginTx(ctx, options)
	if err != nil {
		return fmt.Errorf("begin a Codefly effect receipts transaction: %w", err)
	}
	if scope != nil {
		if err = scope(ctx, tx, tenant); err != nil {
			return errors.Join(fmt.Errorf("scope the Codefly effect receipts transaction to its tenant: %w", err), rollback(tx))
		}
	}
	if err = work(tx); err != nil {
		return errors.Join(err, rollback(tx))
	}
	if err = tx.Commit(); err != nil {
		return fmt.Errorf("commit a Codefly effect receipts transaction: %w", err)
	}
	return nil
}

// rollback ends a failed transaction. A transaction the driver already ended —
// its context was cancelled — has nothing left to roll back, and reporting
// that would bury the error that ended it.
func rollback(tx *sql.Tx) error {
	if err := tx.Rollback(); err != nil && !errors.Is(err, sql.ErrTxDone) {
		return fmt.Errorf("roll back a Codefly effect receipts transaction: %w", err)
	}
	return nil
}

func lookupReceipt(ctx context.Context, q queryer, tenant, effectID, method string) (*Receipt, bool, error) {
	receipt := Receipt{Tenant: tenant, EffectID: effectID, Method: method}
	err := q.QueryRowContext(ctx, lookupReceiptStatement, tenant, effectID, method).
		Scan(&receipt.RequestDigest, &receipt.Response, &receipt.CommittedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("read the Codefly effect receipt: %w", err)
	}
	return &receipt, true, nil
}

// Serialize takes a session-level advisory lock on the effect's key, the same
// admission the runtime takes on its own work. Two first attempts of one effect
// therefore do not both read no receipt and both run the handler: the second
// waits, and finds the first one's receipt.
//
// The lock is held on one pinned connection because an advisory lock belongs to
// the session that took it. A process that dies mid-attempt drops that
// connection, and the lock goes with it.
//
// A waiter holds no connection. It tries the lock and, when another attempt
// holds it, gives its connection back before it waits to try again. Blocking in
// pg_advisory_lock instead would pin a connection per waiter, and waiters alone
// could then exhaust a bounded pool that the holder's own handler needs to
// commit: every attempt would wait on the others until its deadline.
//
// With a tenant scope the lock is still session-level, because it must outlive
// the reads under it; each Held.Lookup is its own scoped transaction on the
// pinned connection, so the tenant binding never outlives the read.
func (s *PostgresStore) Serialize(ctx context.Context, tenant, effectID, method string) (Held, error) {
	if err := validateEffectKey(tenant, effectID, method); err != nil {
		return nil, err
	}
	key := advisoryLockKey(tenant, effectID, method)
	wait := serializeFirstWait
	var connection *sql.Conn
	for {
		taken, err := s.db.Conn(ctx)
		if err != nil {
			return nil, fmt.Errorf("take a connection for the Codefly effect lock: %w", err)
		}
		var acquired bool
		if err = taken.QueryRowContext(ctx, `SELECT pg_try_advisory_lock($1)`, key).Scan(&acquired); err != nil {
			return nil, errors.Join(fmt.Errorf("take the Codefly effect lock: %w", err), taken.Close())
		}
		if acquired {
			connection = taken
			break
		}
		if err = taken.Close(); err != nil {
			return nil, fmt.Errorf("give back the connection while the Codefly effect lock is held elsewhere: %w", err)
		}
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("take the Codefly effect lock: %w", ctx.Err())
		case <-time.After(wait):
		}
		wait = min(wait*2, serializeMaxWait)
	}
	return &postgresHold{connection: connection, scope: s.scope, key: key, tenant: tenant, effectID: effectID, method: method,
		release: sync.OnceFunc(func() {
			// Unlocking is best effort by construction: the caller is finished
			// with the attempt either way, and closing the connection releases
			// the lock even when the unlock itself cannot be sent.
			_, _ = connection.ExecContext(context.WithoutCancel(ctx), `SELECT pg_advisory_unlock($1)`, key)
			_ = connection.Close()
		})}, nil
}

// A waiter's retry interval: short at first, because contention on one effect
// is a redelivery racing its original and usually ends quickly, and bounded so
// a long-held effect costs a waiter one query per interval.
const (
	serializeFirstWait = 10 * time.Millisecond
	serializeMaxWait   = 250 * time.Millisecond
)

// postgresHold reads under the lock on the connection that holds it, so an
// attempt occupies exactly one of the store's connections from Serialize to
// Release.
type postgresHold struct {
	connection               *sql.Conn
	scope                    TenantScope
	key                      int64
	tenant, effectID, method string
	release                  func()
}

func (h *postgresHold) Lookup(ctx context.Context) (*Receipt, bool, error) {
	return scopedLookup(ctx, h.connection, h.scope, h.tenant, h.effectID, h.method)
}

func (h *postgresHold) Release() { h.release() }

// Sweep removes every tenant's receipts committed before the cutoff, in one
// statement on the store's pool. It is never tenant-scoped: under row-level
// security it removes only the rows the connection's own role is admitted to,
// which with no tenant bound is usually none. A module whose receipts table is
// under row-level security either calls SweepTenant for each of its tenants,
// or runs Sweep through a store whose pool connects as a role its policies
// admit to every tenant's receipts.
func (s *PostgresStore) Sweep(ctx context.Context, olderThan time.Time) (int64, error) {
	if olderThan.IsZero() {
		return 0, fmt.Errorf("%w: sweep cutoff is required", ErrInvalid)
	}
	result, err := s.db.ExecContext(ctx,
		`DELETE FROM codefly_effect_receipts WHERE committed_at < $1`, olderThan.UTC())
	if err != nil {
		return 0, fmt.Errorf("sweep Codefly effect receipts: %w", err)
	}
	swept, err := result.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("sweep Codefly effect receipts: %w", err)
	}
	return swept, nil
}

// SweepTenant removes one tenant's receipts committed before the cutoff and
// reports how many it removed, in a transaction bound to that tenant by the
// store's tenant scope when it has one. It is Sweep for a module whose
// receipts table is under row-level security: the module enumerates its own
// tenants — the store cannot, since the tenants it may see are the policies'
// to decide — and sweeps each. See the package documentation before choosing
// a cutoff.
func (s *PostgresStore) SweepTenant(ctx context.Context, tenant string, olderThan time.Time) (int64, error) {
	if err := validateBounded("tenant", tenant, maxTenantBytes); err != nil {
		return 0, err
	}
	if olderThan.IsZero() {
		return 0, fmt.Errorf("%w: sweep cutoff is required", ErrInvalid)
	}
	var swept int64
	err := inTenantTransaction(ctx, s.db, nil, s.scope, tenant, func(tx *sql.Tx) error {
		result, err := tx.ExecContext(ctx,
			`DELETE FROM codefly_effect_receipts WHERE tenant = $1 AND committed_at < $2`, tenant, olderThan.UTC())
		if err != nil {
			return err
		}
		swept, err = result.RowsAffected()
		return err
	})
	if err != nil {
		return 0, fmt.Errorf("sweep one tenant's Codefly effect receipts: %w", err)
	}
	return swept, nil
}

// advisoryLockKey folds the effect's identity into the one bigint an advisory
// lock is taken on. The lock is an admission gate, not a correctness boundary:
// the primary key is what keeps two effects apart, so a collision here costs
// one unrelated attempt a wait and nothing else.
func advisoryLockKey(tenant, effectID, method string) int64 {
	digest := sha256.New()
	for _, part := range []string{tenant, effectID, method} {
		digest.Write([]byte(part))
		digest.Write([]byte{0})
	}
	return int64(binary.BigEndian.Uint64(digest.Sum(nil)[:8]))
}
