package codefly

import (
	"context"
	"fmt"
	"strings"

	"google.golang.org/grpc/metadata"
)

const (
	workContextGRPCMetadataName = WorkContextHeaderName
	operationIDGRPCMetadataName = "x-codefly-operation-id"
	maxOperationIDBytes         = 128
)

// ExecutionContext is the opaque authority and stable logical-operation
// identity carried to a Codefly execution boundary.
//
// Callers construct it through NewExecutionContext and attach it through
// WithGRPCExecutionContext. Carrier names remain SDK-owned.
type ExecutionContext struct {
	workContext WorkContextToken
	operationID string
}

// NewExecutionContext validates and freezes one Work Context/operation pair.
func NewExecutionContext(
	workContext WorkContextToken,
	operationID string,
) (ExecutionContext, error) {
	if workContext.empty() {
		return ExecutionContext{}, fmt.Errorf("%w: empty Work Context", ErrWorkContextInvalid)
	}
	if err := validateOperationID(operationID); err != nil {
		return ExecutionContext{}, err
	}
	return ExecutionContext{
		workContext: workContext,
		operationID: operationID,
	}, nil
}

// WorkContext returns the opaque signed capability. Trust decisions still
// require WorkContextVerifier.
func (execution ExecutionContext) WorkContext() WorkContextToken {
	return execution.workContext
}

// OperationID returns the caller-stable logical operation identifier.
func (execution ExecutionContext) OperationID() string {
	return execution.operationID
}

// WithGRPCExecutionContext attaches one execution context to outgoing gRPC
// metadata while preserving unrelated metadata. Existing carrier values are
// rejected rather than overwritten or joined.
func WithGRPCExecutionContext(
	ctx context.Context,
	execution ExecutionContext,
) (context.Context, error) {
	if ctx == nil {
		return nil, fmt.Errorf("%w: nil gRPC context", ErrWorkContextInvalid)
	}
	validated, err := NewExecutionContext(execution.workContext, execution.operationID)
	if err != nil {
		return nil, err
	}
	existing, _ := metadata.FromOutgoingContext(ctx)
	if len(existing.Get(workContextGRPCMetadataName)) != 0 {
		return nil, fmt.Errorf("%w: outgoing gRPC Work Context already set", ErrWorkContextInvalid)
	}
	if len(existing.Get(operationIDGRPCMetadataName)) != 0 {
		return nil, fmt.Errorf("%w: outgoing gRPC operation ID already set", ErrWorkContextInvalid)
	}
	return metadata.AppendToOutgoingContext(
		ctx,
		workContextGRPCMetadataName,
		validated.workContext.encoded,
		operationIDGRPCMetadataName,
		validated.operationID,
	), nil
}

// GRPCExecutionContextFromIncoming extracts an opaque execution context from
// incoming gRPC metadata. It validates carrier cardinality and wire shape but
// does not verify Work Context trust.
func GRPCExecutionContextFromIncoming(ctx context.Context) (ExecutionContext, error) {
	if ctx == nil {
		return ExecutionContext{}, fmt.Errorf("%w: nil gRPC context", ErrWorkContextInvalid)
	}
	values, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return ExecutionContext{}, fmt.Errorf("%w: missing incoming gRPC metadata", ErrWorkContextInvalid)
	}
	workContexts := values.Get(workContextGRPCMetadataName)
	if len(workContexts) != 1 {
		return ExecutionContext{}, fmt.Errorf(
			"%w: incoming gRPC Work Context requires exactly one value",
			ErrWorkContextInvalid,
		)
	}
	operationIDs := values.Get(operationIDGRPCMetadataName)
	if len(operationIDs) != 1 {
		return ExecutionContext{}, fmt.Errorf(
			"%w: incoming gRPC operation ID requires exactly one value",
			ErrWorkContextInvalid,
		)
	}
	workContext, err := ParseWorkContextToken(workContexts[0])
	if err != nil {
		return ExecutionContext{}, err
	}
	return NewExecutionContext(workContext, operationIDs[0])
}

// GRPCExecutionContextFromIncomingIfPresent supports compatibility boundaries
// where execution attribution is optional. No carrier returns present=false;
// a partial or duplicate carrier is still an error.
func GRPCExecutionContextFromIncomingIfPresent(
	ctx context.Context,
) (execution ExecutionContext, present bool, err error) {
	if ctx == nil {
		return ExecutionContext{}, false, fmt.Errorf("%w: nil gRPC context", ErrWorkContextInvalid)
	}
	values, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return ExecutionContext{}, false, nil
	}
	workContexts := values.Get(workContextGRPCMetadataName)
	operationIDs := values.Get(operationIDGRPCMetadataName)
	if len(workContexts) == 0 && len(operationIDs) == 0 {
		return ExecutionContext{}, false, nil
	}
	execution, err = GRPCExecutionContextFromIncoming(ctx)
	if err != nil {
		return ExecutionContext{}, false, err
	}
	return execution, true, nil
}

func validateOperationID(operationID string) error {
	if operationID == "" {
		return fmt.Errorf("%w: operation ID is required", ErrWorkContextInvalid)
	}
	if strings.TrimSpace(operationID) != operationID {
		return fmt.Errorf("%w: operation ID is not canonical", ErrWorkContextInvalid)
	}
	if len(operationID) > maxOperationIDBytes {
		return fmt.Errorf(
			"%w: operation ID exceeds %d bytes",
			ErrWorkContextInvalid,
			maxOperationIDBytes,
		)
	}
	for _, character := range operationID {
		if character >= 'a' && character <= 'z' ||
			character >= 'A' && character <= 'Z' ||
			character >= '0' && character <= '9' {
			continue
		}
		switch character {
		case '-', '_', '.', ':':
			continue
		default:
			return fmt.Errorf("%w: operation ID contains unsupported characters", ErrWorkContextInvalid)
		}
	}
	return nil
}
