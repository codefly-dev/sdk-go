package grpctransport

import (
	"context"
	"fmt"
	"strings"

	"google.golang.org/grpc/metadata"

	"github.com/codefly-dev/sdk-go/workcontext"
)

const (
	workContextGRPCMetadataName = workcontext.HeaderName
	// The installation carriers are the same names as on HTTP, because they
	// are the same fact: gRPC metadata keys and HTTP header names are one
	// namespace, and spelling them twice is how they drift.
	installationIDGRPCMetadataName       = workcontext.InstallationIDHeaderName
	installationRevisionGRPCMetadataName = workcontext.InstallationRevisionHeaderName
	operationIDGRPCMetadataName          = "x-codefly-operation-id"
	maxOperationIDBytes                  = 128
)

// ExecutionContext is the opaque authority and stable logical-operation
// identity carried to a Codefly execution boundary.
//
// Callers construct it through NewExecutionContext and attach it through
// WithGRPCExecutionContext. Carrier names remain SDK-owned.
type ExecutionContext struct {
	workContext string
	operationID string
}

// NewExecutionContext validates and freezes one Work Context/operation pair.
func NewExecutionContext(
	workContext string,
	operationID string,
) (ExecutionContext, error) {
	if workContext == "" {
		return ExecutionContext{}, fmt.Errorf("%w: empty Work Context", workcontext.ErrInvalid)
	}
	if err := validateOperationID(operationID); err != nil {
		return ExecutionContext{}, err
	}
	return ExecutionContext{
		workContext: workContext,
		operationID: operationID,
	}, nil
}

// Capability returns the opaque signed capability. It is a string, and a trust
// decision still requires core's verifier: nothing a transport hands back has
// been verified by being transported.
func (execution ExecutionContext) Capability() string {
	return execution.workContext
}

// OperationID returns the caller-stable logical operation identifier.
func (execution ExecutionContext) OperationID() string {
	return execution.operationID
}

// WithGRPCExecutionContext attaches one execution context to outgoing gRPC
// metadata while preserving unrelated metadata. Existing carrier values are
// rejected rather than overwritten or joined.
//
// The sealed installation travels beside the capability on every call, so the
// callee can re-check the installation the call is being made under without
// decoding the token first. It is a pre-check and not authority: the
// installation that governs the call is the sealed one, and a callee that finds
// the two disagreeing refuses rather than choosing between them.
//
// A Work Context is bound to one audience. A service calling another service
// attaches a capability the authority minted for the callee's audience, never
// the one it received: the callee's audience check rejects a forwarded
// capability. Nothing here reads incoming metadata, so this helper never
// forwards on its own.
func WithGRPCExecutionContext(
	ctx context.Context,
	execution ExecutionContext,
) (context.Context, error) {
	if ctx == nil {
		return nil, fmt.Errorf("%w: nil gRPC context", workcontext.ErrInvalid)
	}
	validated, err := NewExecutionContext(execution.workContext, execution.operationID)
	if err != nil {
		return nil, err
	}
	installationID, installationRevision, err := workcontext.SealedInstallation(validated.workContext)
	if err != nil {
		return nil, err
	}
	existing, _ := metadata.FromOutgoingContext(ctx)
	for _, carrier := range []string{
		workContextGRPCMetadataName,
		operationIDGRPCMetadataName,
		installationIDGRPCMetadataName,
		installationRevisionGRPCMetadataName,
	} {
		if len(existing.Get(carrier)) != 0 {
			return nil, fmt.Errorf(
				"%w: outgoing gRPC metadata %q is already set",
				workcontext.ErrInvalid, carrier,
			)
		}
	}
	return metadata.AppendToOutgoingContext(
		ctx,
		workContextGRPCMetadataName,
		validated.workContext,
		operationIDGRPCMetadataName,
		validated.operationID,
		installationIDGRPCMetadataName,
		installationID,
		installationRevisionGRPCMetadataName,
		installationRevision,
	), nil
}

// GRPCExecutionContextFromIncoming extracts an opaque execution context from
// incoming gRPC metadata. It validates carrier cardinality and wire shape but
// does not verify Work Context trust.
func GRPCExecutionContextFromIncoming(ctx context.Context) (ExecutionContext, error) {
	if ctx == nil {
		return ExecutionContext{}, fmt.Errorf("%w: nil gRPC context", workcontext.ErrInvalid)
	}
	values, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return ExecutionContext{}, fmt.Errorf("%w: missing incoming gRPC metadata", workcontext.ErrInvalid)
	}
	workContexts := values.Get(workContextGRPCMetadataName)
	if len(workContexts) != 1 {
		return ExecutionContext{}, fmt.Errorf(
			"%w: incoming gRPC Work Context requires exactly one value",
			workcontext.ErrInvalid,
		)
	}
	operationIDs := values.Get(operationIDGRPCMetadataName)
	if len(operationIDs) != 1 {
		return ExecutionContext{}, fmt.Errorf(
			"%w: incoming gRPC operation ID requires exactly one value",
			workcontext.ErrInvalid,
		)
	}
	workContext := workContexts[0]
	if err := checkIncomingInstallation(values, workContext); err != nil {
		return ExecutionContext{}, err
	}
	return NewExecutionContext(workContext, operationIDs[0])
}

// checkIncomingInstallation holds the installation carriers to the sealed
// claim. The carriers exist so a callee can refuse cheaply; they are caller-
// controlled, so the only two acceptable outcomes are "they agree with the
// seal" and "the call is refused". Preferring the carrier would let a caller
// name any installation it liked, and ignoring a disagreement would make the
// carriers decoration that a reader would nonetheless log and believe.
func checkIncomingInstallation(
	values metadata.MD,
	token string,
) error {
	sealedID, sealedRevision, err := workcontext.SealedInstallation(token)
	if err != nil {
		return err
	}
	for _, carrier := range []struct {
		name   string
		sealed string
	}{
		{installationIDGRPCMetadataName, sealedID},
		{installationRevisionGRPCMetadataName, sealedRevision},
	} {
		presented := values.Get(carrier.name)
		if len(presented) != 1 {
			return fmt.Errorf(
				"%w: incoming gRPC %s requires exactly one value",
				workcontext.ErrInvalid, carrier.name,
			)
		}
		if presented[0] != carrier.sealed {
			return fmt.Errorf(
				"%w: incoming gRPC %s is %q and the credential seals %q",
				workcontext.ErrInvalid, carrier.name, presented[0], carrier.sealed,
			)
		}
	}
	return nil
}

// GRPCExecutionContextFromIncomingIfPresent supports compatibility boundaries
// where execution attribution is optional. No carrier returns present=false;
// a partial or duplicate carrier is still an error.
func GRPCExecutionContextFromIncomingIfPresent(
	ctx context.Context,
) (execution ExecutionContext, present bool, err error) {
	if ctx == nil {
		return ExecutionContext{}, false, fmt.Errorf("%w: nil gRPC context", workcontext.ErrInvalid)
	}
	values, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return ExecutionContext{}, false, nil
	}
	carried := 0
	for _, carrier := range []string{
		workContextGRPCMetadataName,
		operationIDGRPCMetadataName,
		installationIDGRPCMetadataName,
		installationRevisionGRPCMetadataName,
	} {
		carried += len(values.Get(carrier))
	}
	if carried == 0 {
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
		return fmt.Errorf("%w: operation ID is required", workcontext.ErrInvalid)
	}
	if strings.TrimSpace(operationID) != operationID {
		return fmt.Errorf("%w: operation ID is not canonical", workcontext.ErrInvalid)
	}
	if len(operationID) > maxOperationIDBytes {
		return fmt.Errorf(
			"%w: operation ID exceeds %d bytes",
			workcontext.ErrInvalid,
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
			return fmt.Errorf("%w: operation ID contains unsupported characters", workcontext.ErrInvalid)
		}
	}
	return nil
}
