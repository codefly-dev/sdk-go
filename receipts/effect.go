package receipts

import (
	"context"
	"fmt"
	"time"

	"google.golang.org/protobuf/proto"
)

// Effect is the admitted attempt a handler is running under: the identity its
// receipt is recorded against, placed in the context by the interceptor.
type Effect struct {
	ID            string
	Tenant        string
	Method        string
	RequestDigest []byte
}

type effectContextKey struct{}

// WithEffect carries one admitted attempt to the handler. The interceptor calls
// it; a caller constructing one by hand is asserting an admission that never
// happened.
func WithEffect(ctx context.Context, effect Effect) context.Context {
	return context.WithValue(ctx, effectContextKey{}, effect)
}

// EffectFromContext returns the attempt the handler is running under.
func EffectFromContext(ctx context.Context) (Effect, bool) {
	effect, ok := ctx.Value(effectContextKey{}).(Effect)
	return effect, ok
}

// Record writes the receipt of the effect the handler is committing, inside the
// transaction it is about to commit with. It is the one line the SDK cannot
// write for a handler — see the package documentation.
func Record(ctx context.Context, store Store, tx Tx, response proto.Message) error {
	if store == nil {
		return fmt.Errorf("%w: store is required", ErrInvalid)
	}
	if tx == nil {
		return fmt.Errorf("%w: the transaction committing the effect is required", ErrInvalid)
	}
	effect, ok := EffectFromContext(ctx)
	if !ok {
		return ErrNoEffect
	}
	if response == nil {
		return fmt.Errorf("%w: response is required", ErrInvalid)
	}
	encoded, err := proto.Marshal(response)
	if err != nil {
		return fmt.Errorf("%w: encode response: %v", ErrInvalid, err)
	}
	return store.Record(ctx, tx, Receipt{
		EffectID:      effect.ID,
		Tenant:        effect.Tenant,
		Method:        effect.Method,
		RequestDigest: effect.RequestDigest,
		Response:      encoded,
		CommittedAt:   time.Now().UTC(),
	})
}
