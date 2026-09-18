package receipts

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

const (
	// EffectIDHeaderName carries the effect id an operation is attempted under.
	// Every attempt of one invocation presents the same value, which is what
	// makes a second attempt a replay rather than a second effect.
	EffectIDHeaderName = "x-codefly-effect-id"
	// IdempotencyKeyHeaderName is the HTTP twin of EffectIDHeaderName, accepted
	// so a module already taking Idempotency-Key on its REST surface keeps one
	// spelling for its callers.
	IdempotencyKeyHeaderName = "Idempotency-Key"

	// DefaultRetention is how long a receipt is kept before Sweep may remove it.
	// See the package documentation: this is only safe while it exceeds the
	// runtime's maximum recovery horizon.
	DefaultRetention = 7 * 24 * time.Hour

	maxEffectIDBytes = 128
	maxMethodBytes   = 512
	maxTenantBytes   = 512
)

var (
	// ErrEffectIDMissing marks a call on an operation method that presented no
	// effect id. Without one there is nothing to replay against, so the call is
	// refused rather than run as a fresh effect.
	ErrEffectIDMissing = errors.New("codefly effect id is required")
	// ErrEffectIDReused marks an effect id already recorded against a different
	// request. Answering with the stored response would attribute one caller's
	// outcome to another's request, and running the handler would give one
	// effect id two effects.
	ErrEffectIDReused = errors.New("codefly effect id reused for a different request")
	// ErrNoEffect marks a Record call from a handler the interceptor never
	// admitted, so there is no effect id to record the receipt under.
	ErrNoEffect = errors.New("no Codefly effect in context")
	// ErrInvalid marks a receipt, identifier or configuration the store refuses.
	ErrInvalid = errors.New("invalid Codefly effect receipt")
)

// Receipt is what an operation committed, kept so a later attempt can be
// answered without running the effect again.
type Receipt struct {
	// EffectID is the identity every attempt of one invocation presents.
	EffectID string
	// Tenant is the tenant of the verified Work Context the effect ran under.
	// It is part of the receipt's identity so one tenant can never read, or
	// collide with, another's outcome.
	Tenant string
	// Method is the full gRPC method name, "/package.Service/Method".
	Method string
	// RequestDigest fingerprints the request the effect was committed for.
	RequestDigest []byte
	// Response is the committed response, in protobuf wire encoding.
	Response []byte
	// CommittedAt is when the effect committed.
	CommittedAt time.Time
}

func (r Receipt) validate() error {
	if err := validateEffectKey(r.Tenant, r.EffectID, r.Method); err != nil {
		return err
	}
	if len(r.RequestDigest) == 0 {
		return fmt.Errorf("%w: request digest is required", ErrInvalid)
	}
	if r.CommittedAt.IsZero() {
		return fmt.Errorf("%w: committed_at is required", ErrInvalid)
	}
	return nil
}

// Tx is the transaction an effect commits in. *sql.Tx satisfies it, and so
// does any wrapper a module already uses, so the receipt is written by the
// statement handle that is about to commit rather than beside it.
type Tx interface {
	ExecContext(ctx context.Context, query string, arguments ...any) (sql.Result, error)
}

// Store keeps the receipts of one module's operations.
//
// A module normally takes the Postgres implementation; the in-memory one is for
// tests. Implementing it elsewhere means implementing all four: Serialize is
// what makes concurrent first attempts run the handler exactly once, and is not
// an optimization a store may skip.
type Store interface {
	// Record writes a receipt inside the caller's transaction. It is idempotent
	// on (tenant, effect id, method): re-recording the same effect is the
	// normal outcome of a retried attempt, not a conflict.
	Record(ctx context.Context, tx Tx, receipt Receipt) error
	// Lookup reads the receipt of one effect.
	Lookup(ctx context.Context, tenant, effectID, method string) (*Receipt, bool, error)
	// Serialize blocks until this process holds the right to attempt one
	// effect, and returns the release to call once the attempt has finished.
	// Two concurrent first attempts of one effect therefore do not both find no
	// receipt and both run the handler.
	Serialize(ctx context.Context, tenant, effectID, method string) (release func(), err error)
	// Sweep removes receipts committed before the cutoff and reports how many
	// it removed. See the package documentation before choosing a cutoff.
	Sweep(ctx context.Context, olderThan time.Time) (int64, error)
}

func validateEffectKey(tenant, effectID, method string) error {
	if err := validateBounded("tenant", tenant, maxTenantBytes); err != nil {
		return err
	}
	if err := validateBounded("effect id", effectID, maxEffectIDBytes); err != nil {
		return err
	}
	return validateBounded("method", method, maxMethodBytes)
}

func validateBounded(name, value string, max int) error {
	switch {
	case value == "":
		return fmt.Errorf("%w: %s is required", ErrInvalid, name)
	case len(value) > max:
		return fmt.Errorf("%w: %s exceeds %d bytes", ErrInvalid, name, max)
	case strings.TrimSpace(value) != value:
		return fmt.Errorf("%w: %s is not canonical", ErrInvalid, name)
	case strings.ContainsAny(value, "\x00\r\n\t"):
		return fmt.Errorf("%w: %s contains control characters", ErrInvalid, name)
	}
	return nil
}
