package grpctransport

import (
	"context"
	"strconv"
	"strings"
	"testing"
	"time"

	corework "github.com/codefly-dev/core/workcontext"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/metadata"

	"github.com/codefly-dev/sdk-go/workcontext"
)

// opaqueTestCapability is a real sealed capability rather than a shaped
// placeholder. It has to be: the transport reads the installation out of the
// capability so every call carries it, so one with no seal cannot be attached
// at all — which is the behaviour, and a placeholder here would hide it.
//
// It comes from core's conformance kit, which is the only minter. A test that
// assembled a token here would be asserting against a format nothing issues.
func opaqueTestCapability(t *testing.T) string {
	t.Helper()
	fixtures, err := corework.Fixtures(time.Now())
	require.NoError(t, err)
	for _, fixture := range fixtures {
		if fixture.Form == corework.FormSession && fixture.Outcome == corework.OutcomeAccepted {
			return fixture.Token
		}
	}
	t.Fatalf("core's conformance kit offered no accepted session capability")
	return ""
}

// The installation every capability above is sealed to, as the kit holds it.
var (
	sealedInstallationID       = corework.FixtureInstallation
	sealedInstallationRevision = strconv.Itoa(corework.FixtureInstallationRevision)
)

func TestGRPCExecutionContextRoundTripPreservesOtherMetadata(t *testing.T) {
	original := metadata.NewOutgoingContext(
		context.Background(),
		metadata.Pairs("authorization", "Bearer gateway-token"),
	)
	execution, err := NewExecutionContext(
		opaqueTestCapability(t),
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
	require.Equal(t, execution.Capability(), received.Capability())
	require.Equal(t, execution.OperationID(), received.OperationID())
}

func TestGRPCExecutionContextRejectsExistingOrDuplicateCarriers(t *testing.T) {
	execution, err := NewExecutionContext(opaqueTestCapability(t), "operation-1")
	require.NoError(t, err)

	outgoing := metadata.NewOutgoingContext(
		context.Background(),
		metadata.Pairs(workContextGRPCMetadataName, execution.Capability()),
	)
	_, err = WithGRPCExecutionContext(outgoing, execution)
	require.ErrorContains(t, err, "already set")

	incoming := metadata.NewIncomingContext(
		context.Background(),
		metadata.Pairs(
			workContextGRPCMetadataName,
			execution.Capability(),
			workContextGRPCMetadataName,
			execution.Capability(),
			operationIDGRPCMetadataName,
			execution.OperationID(),
		),
	)
	_, err = GRPCExecutionContextFromIncoming(incoming)
	require.ErrorContains(t, err, "exactly one value")
}

func TestGRPCExecutionContextRejectsMissingOrNonCanonicalOperationID(t *testing.T) {
	workContext := opaqueTestCapability(t)
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
		metadata.Pairs(workContextGRPCMetadataName, workContext),
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

// Deliverable 3 on the gRPC side: the sealed installation travels beside the
// capability on every call, under the same names HTTP uses, so a callee can
// refuse before it decodes anything.
func TestGRPCCallsCarryTheSealedInstallation(t *testing.T) {
	execution, err := NewExecutionContext(opaqueTestCapability(t), "operation-019f8fc1")
	require.NoError(t, err)
	outgoing, err := WithGRPCExecutionContext(context.Background(), execution)
	require.NoError(t, err)
	carried, ok := metadata.FromOutgoingContext(outgoing)
	require.True(t, ok)

	require.Equal(t, []string{sealedInstallationID}, carried.Get(workcontext.InstallationIDHeaderName))
	require.Equal(t, []string{sealedInstallationRevision}, carried.Get(workcontext.InstallationRevisionHeaderName))
}

// The carriers are caller-controlled, so the only two acceptable outcomes are
// "they agree with the seal" and "the call is refused". Preferring the carrier
// would let a caller name any installation it liked; ignoring a disagreement
// would make them decoration that a reader would nonetheless log and believe.
func TestIncomingInstallationCarriersAreHeldToTheSeal(t *testing.T) {
	execution, err := NewExecutionContext(opaqueTestCapability(t), "operation-019f8fc1")
	require.NoError(t, err)
	outgoing, err := WithGRPCExecutionContext(context.Background(), execution)
	require.NoError(t, err)
	honest, ok := metadata.FromOutgoingContext(outgoing)
	require.True(t, ok)

	_, err = GRPCExecutionContextFromIncoming(metadata.NewIncomingContext(context.Background(), honest))
	require.NoError(t, err)

	for name, mutate := range map[string]func(metadata.MD){
		"another installation": func(values metadata.MD) {
			values.Set(workcontext.InstallationIDHeaderName, "installation-somebody-elses")
		},
		"another revision": func(values metadata.MD) {
			values.Set(workcontext.InstallationRevisionHeaderName, "6")
		},
		"installation removed": func(values metadata.MD) {
			values.Delete(workcontext.InstallationIDHeaderName)
		},
		"revision removed": func(values metadata.MD) {
			values.Delete(workcontext.InstallationRevisionHeaderName)
		},
		"duplicate revision": func(values metadata.MD) {
			values.Append(workcontext.InstallationRevisionHeaderName, sealedInstallationRevision)
		},
	} {
		t.Run(name, func(t *testing.T) {
			tampered := honest.Copy()
			mutate(tampered)
			_, err := GRPCExecutionContextFromIncoming(metadata.NewIncomingContext(context.Background(), tampered))
			require.ErrorIs(t, err, workcontext.ErrInvalid)
		})
	}
}

// A partial carrier set is an error rather than an absence: the optional-
// attribution boundary exists for a call that carries nothing at all, not for
// one that carries half of an authority.
func TestIfPresentTreatsAPartialInstallationCarrierAsAnError(t *testing.T) {
	_, present, err := GRPCExecutionContextFromIncomingIfPresent(
		metadata.NewIncomingContext(context.Background(), metadata.MD{}),
	)
	require.NoError(t, err)
	require.False(t, present)

	_, _, err = GRPCExecutionContextFromIncomingIfPresent(metadata.NewIncomingContext(
		context.Background(),
		metadata.Pairs(workcontext.InstallationIDHeaderName, sealedInstallationID),
	))
	require.ErrorIs(t, err, workcontext.ErrInvalid)
}
