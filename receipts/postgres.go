package receipts

import (
	"context"
	"crypto/sha256"
	"database/sql"
	_ "embed"
	"encoding/binary"
	"errors"
	"fmt"
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
	receipt := Receipt{Tenant: tenant, EffectID: effectID, Method: method}
	err := s.db.QueryRowContext(ctx, lookupReceiptStatement, tenant, effectID, method).
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
func (s *PostgresStore) Serialize(ctx context.Context, tenant, effectID, method string) (func(), error) {
	if err := validateEffectKey(tenant, effectID, method); err != nil {
		return nil, err
	}
	key := advisoryLockKey(tenant, effectID, method)
	connection, err := s.db.Conn(ctx)
	if err != nil {
		return nil, fmt.Errorf("take a connection for the Codefly effect lock: %w", err)
	}
	if _, err = connection.ExecContext(ctx, `SELECT pg_advisory_lock($1)`, key); err != nil {
		return nil, errors.Join(
			fmt.Errorf("take the Codefly effect lock: %w", err),
			connection.Close(),
		)
	}
	return func() {
		// Unlocking is best effort by construction: the caller is finished with
		// the attempt either way, and closing the connection releases the lock
		// even when the unlock itself cannot be sent.
		_, _ = connection.ExecContext(context.WithoutCancel(ctx), `SELECT pg_advisory_unlock($1)`, key)
		_ = connection.Close()
	}, nil
}

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
