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
	db *sql.DB
}

// NewPostgresStore binds the store to the pool the module's effects commit
// through. The pool must reach the same database as those effects: a receipt
// written to another one could not be written in their transaction.
func NewPostgresStore(db *sql.DB) (*PostgresStore, error) {
	if db == nil {
		return nil, fmt.Errorf("%w: database handle is required", ErrInvalid)
	}
	return &PostgresStore{db: db}, nil
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
	return lookupReceipt(ctx, s.db, tenant, effectID, method)
}

// queryer is what a receipt is read through: the store's pool, or the one
// connection a hold pins.
type queryer interface {
	QueryRowContext(ctx context.Context, query string, arguments ...any) *sql.Row
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
	return &postgresHold{connection: connection, key: key, tenant: tenant, effectID: effectID, method: method,
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
	key                      int64
	tenant, effectID, method string
	release                  func()
}

func (h *postgresHold) Lookup(ctx context.Context) (*Receipt, bool, error) {
	return lookupReceipt(ctx, h.connection, h.tenant, h.effectID, h.method)
}

func (h *postgresHold) Release() { h.release() }

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
