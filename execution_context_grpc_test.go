package codefly

import (
	"context"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/metadata"
)

func opaqueTestWorkContext(t *testing.T) WorkContextToken {
	t.Helper()
	signature := base64.RawURLEncoding.EncodeToString(make([]byte, 64))
	token, err := ParseWorkContextToken("e30." + signature)
	require.NoError(t, err)
	return token
}

func TestGRPCExecutionContextRoundTripPreservesOtherMetadata(t *testing.T) {
	original := metadata.NewOutgoingContext(
		context.Background(),
		metadata.Pairs("authorization", "Bearer gateway-token"),
	)
	execution, err := NewExecutionContext(
		opaqueTestWorkContext(t),
		"operation-019f8fc1",
	)
	require.NoError(t, err)

	outgoing, err := WithGRPCExecutionContext(original, execution)
	require.NoError(t, err)
	outgoingMetadata, ok := metadata.FromOutgoingContext(outgoing)
	require.True(t, ok)
	require.Equal(t, []string{"Bearer gateway-token"}, outgoingMetadata.Get("authorization"))

	incoming := metadata.NewIncomingContext(context.Background(), outgoingMetadata)
	received, err := GRPCExecutionContextFromIncoming(incoming)
	require.NoError(t, err)
	require.Equal(t, execution.WorkContext().Encoded(), received.WorkContext().Encoded())
	require.Equal(t, execution.OperationID(), received.OperationID())
}

func TestGRPCExecutionContextRejectsExistingOrDuplicateCarriers(t *testing.T) {
	execution, err := NewExecutionContext(opaqueTestWorkContext(t), "operation-1")
	require.NoError(t, err)

	outgoing := metadata.NewOutgoingContext(
		context.Background(),
		metadata.Pairs(workContextGRPCMetadataName, execution.WorkContext().Encoded()),
	)
	_, err = WithGRPCExecutionContext(outgoing, execution)
	require.ErrorContains(t, err, "already set")

	incoming := metadata.NewIncomingContext(
		context.Background(),
		metadata.Pairs(
			workContextGRPCMetadataName,
			execution.WorkContext().Encoded(),
			workContextGRPCMetadataName,
			execution.WorkContext().Encoded(),
			operationIDGRPCMetadataName,
			execution.OperationID(),
		),
	)
	_, err = GRPCExecutionContextFromIncoming(incoming)
	require.ErrorContains(t, err, "exactly one value")
}

func TestGRPCExecutionContextRejectsMissingOrNonCanonicalOperationID(t *testing.T) {
	workContext := opaqueTestWorkContext(t)
	for _, operationID := range []string{
		"",
		" operation-1",
		"operation 1",
		"operation/1",
		strings.Repeat("a", maxOperationIDBytes+1),
	} {
		_, err := NewExecutionContext(workContext, operationID)
		require.Error(t, err, operationID)
	}

	incoming := metadata.NewIncomingContext(
		context.Background(),
		metadata.Pairs(workContextGRPCMetadataName, workContext.Encoded()),
	)
	_, err := GRPCExecutionContextFromIncoming(incoming)
	require.ErrorContains(t, err, "operation ID requires exactly one value")
}

func TestGRPCExecutionContextOptionalExtractionDistinguishesAbsentFromPartial(t *testing.T) {
	execution, present, err := GRPCExecutionContextFromIncomingIfPresent(context.Background())
	require.NoError(t, err)
	require.False(t, present)
	require.Empty(t, execution.OperationID())

	partial := metadata.NewIncomingContext(
		context.Background(),
		metadata.Pairs(operationIDGRPCMetadataName, "operation-1"),
	)
	_, present, err = GRPCExecutionContextFromIncomingIfPresent(partial)
	require.ErrorContains(t, err, "Work Context requires exactly one value")
	require.False(t, present)
}
