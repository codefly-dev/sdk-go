package receipts

import "errors"

// Refusal is how one of this package's refusals is reported on the wire,
// spelled as a gRPC status code name so the gRPC and Connect adapters answer a
// caller identically.
type Refusal int

const (
	// RefusalNone means the error is not one of this package's refusals and is
	// the handler's or the store's to report.
	RefusalNone Refusal = iota
	// RefusalInvalidArgument is INVALID_ARGUMENT: the call cannot be attempted
	// as presented.
	RefusalInvalidArgument
	// RefusalFailedPrecondition is FAILED_PRECONDITION: the effect id is
	// already spent on a different request, which no retry of this call will
	// change.
	RefusalFailedPrecondition
	// RefusalInternal is INTERNAL: a handler recorded, or failed to record, a
	// receipt for an attempt that was never admitted.
	RefusalInternal
)

// RefusalFor classifies an error a transport adapter is about to report.
func RefusalFor(err error) Refusal {
	switch {
	case errors.Is(err, ErrEffectIDMissing), errors.Is(err, ErrInvalid):
		return RefusalInvalidArgument
	case errors.Is(err, ErrEffectIDReused):
		return RefusalFailedPrecondition
	case errors.Is(err, ErrNoEffect):
		return RefusalInternal
	default:
		return RefusalNone
	}
}
