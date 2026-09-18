package receipts

import (
	"bytes"
	"context"
	"database/sql"
	"fmt"
	"sync"
	"time"
)

// MemoryStore keeps receipts in the process. It is for tests: it has no
// transaction of its own, so a receipt it records is visible the moment Record
// returns rather than when the caller's transaction commits. That is the one
// property a real store has and this one cannot model, which is why a module
// takes the Postgres store.
type MemoryStore struct {
	mutex    sync.Mutex
	receipts map[effectKey]Receipt
	held     map[effectKey]chan struct{}
}

type effectKey struct {
	tenant   string
	effectID string
	method   string
}

// NewMemoryStore returns an empty in-process store.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		receipts: make(map[effectKey]Receipt),
		held:     make(map[effectKey]chan struct{}),
	}
}

func (s *MemoryStore) Record(_ context.Context, tx Tx, receipt Receipt) error {
	if tx == nil {
		return fmt.Errorf("%w: the transaction committing the effect is required", ErrInvalid)
	}
	if err := receipt.validate(); err != nil {
		return err
	}
	stored := receipt
	stored.RequestDigest = bytes.Clone(receipt.RequestDigest)
	stored.Response = bytes.Clone(receipt.Response)

	s.mutex.Lock()
	defer s.mutex.Unlock()
	key := effectKey{tenant: receipt.Tenant, effectID: receipt.EffectID, method: receipt.Method}
	if _, recorded := s.receipts[key]; recorded {
		return nil
	}
	s.receipts[key] = stored
	return nil
}

func (s *MemoryStore) Lookup(_ context.Context, tenant, effectID, method string) (*Receipt, bool, error) {
	if err := validateEffectKey(tenant, effectID, method); err != nil {
		return nil, false, err
	}
	s.mutex.Lock()
	defer s.mutex.Unlock()
	stored, found := s.receipts[effectKey{tenant: tenant, effectID: effectID, method: method}]
	if !found {
		return nil, false, nil
	}
	answer := stored
	answer.RequestDigest = bytes.Clone(stored.RequestDigest)
	answer.Response = bytes.Clone(stored.Response)
	return &answer, true, nil
}

// Serialize hands out the right to attempt one effect, waiting for the holder
// to release it. Waiting is interruptible so a caller whose deadline passes
// reports that rather than queueing behind an attempt it can no longer use.
func (s *MemoryStore) Serialize(ctx context.Context, tenant, effectID, method string) (func(), error) {
	if err := validateEffectKey(tenant, effectID, method); err != nil {
		return nil, err
	}
	key := effectKey{tenant: tenant, effectID: effectID, method: method}
	for {
		s.mutex.Lock()
		waiting, taken := s.held[key]
		if !taken {
			released := make(chan struct{})
			s.held[key] = released
			s.mutex.Unlock()
			return sync.OnceFunc(func() {
				s.mutex.Lock()
				delete(s.held, key)
				s.mutex.Unlock()
				close(released)
			}), nil
		}
		s.mutex.Unlock()
		select {
		case <-waiting:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}

func (s *MemoryStore) Sweep(_ context.Context, olderThan time.Time) (int64, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	swept := int64(0)
	for key, stored := range s.receipts {
		if stored.CommittedAt.Before(olderThan) {
			delete(s.receipts, key)
			swept++
		}
	}
	return swept, nil
}

// NoTx is the transaction stand-in a test passes to the in-memory store. It
// commits nothing: it exists so a test of the interceptor need not open a
// database, never so production code can satisfy Record without a transaction.
type NoTx struct{}

func (NoTx) ExecContext(context.Context, string, ...any) (sql.Result, error) {
	return noRows{}, nil
}

type noRows struct{}

func (noRows) LastInsertId() (int64, error) { return 0, nil }
func (noRows) RowsAffected() (int64, error) { return 0, nil }
