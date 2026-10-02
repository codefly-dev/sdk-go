package grpctransport

import (
	"context"
	"crypto/ed25519"
	"strings"
	"testing"

	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/metadata"

	"github.com/codefly-dev/sdk-go/workcontext"
)

// opaqueTestWorkContext is a real signed credential rather than a shaped
// placeholder. It has to be: the transport reads the installation out of the
// token so every call carries it, so a token with no seal cannot be attached
// at all — which is the behaviour, and a placeholder here would hide it.
func opaqueTestWorkContext(t *testing.T) workcontext.WorkContextToken {
	t.Helper()
	seed := make([]byte, ed25519.SeedSize)
	for index := range seed {
		seed[index] = byte(index)
	}
	signer, err := workcontext.NewWorkContextSigner(workcontext.WorkContextSignerOptions{
		Issuer:     "https://accounts.codefly.dev/work-context",
		KeyID:      "transport-test",
		PrivateKey: ed25519.NewKeyFromSeed(seed),
	})
	require.NoError(t, err)
	token, _, err := signer.StartTask(workcontext.StartTaskInput{
		Audience: "warden.transport", TenantID: "tenant-codefly",
		OwnerPrincipalID: "principal-owner", OwnerPrincipalKind: "user",
		TaskID: "task-transport", SessionID: "session-transport",
		AuthorizationRevision: 1,
		Seal: workcontext.Seal{
			PrincipalEpoch:       2,
			InstallationID:       "installation-transport",
			InstallationRevision: 5,
			BuildIncarnation:     "build-incarnation-transport",
		},
		AuthorityScopes: []*basev0.WorkScopeV1{
			{ResourceKind: "evidence", Actions: []string{"append"}},
		},
	})
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

// Deliverable 3 on the gRPC side: the sealed installation travels beside the
// capability on every call, under the same names HTTP uses, so a callee can
// refuse before it decodes anything.
func TestGRPCCallsCarryTheSealedInstallation(t *testing.T) {
	execution, err := NewExecutionContext(opaqueTestWorkContext(t), "operation-019f8fc1")
	require.NoError(t, err)
	outgoing, err := WithGRPCExecutionContext(context.Background(), execution)
	require.NoError(t, err)
	carried, ok := metadata.FromOutgoingContext(outgoing)
	require.True(t, ok)

	require.Equal(t, []string{"installation-transport"}, carried.Get(workcontext.InstallationIDHeaderName))
	require.Equal(t, []string{"5"}, carried.Get(workcontext.InstallationRevisionHeaderName))
}

// The carriers are caller-controlled, so the only two acceptable outcomes are
// "they agree with the seal" and "the call is refused". Preferring the carrier
// would let a caller name any installation it liked; ignoring a disagreement
// would make them decoration that a reader would nonetheless log and believe.
func TestIncomingInstallationCarriersAreHeldToTheSeal(t *testing.T) {
	execution, err := NewExecutionContext(opaqueTestWorkContext(t), "operation-019f8fc1")
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
			values.Append(workcontext.InstallationRevisionHeaderName, "5")
		},
	} {
		t.Run(name, func(t *testing.T) {
			tampered := honest.Copy()
			mutate(tampered)
			_, err := GRPCExecutionContextFromIncoming(metadata.NewIncomingContext(context.Background(), tampered))
			require.ErrorIs(t, err, workcontext.ErrWorkContextInvalid)
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
		metadata.Pairs(workcontext.InstallationIDHeaderName, "installation-transport"),
	))
	require.ErrorIs(t, err, workcontext.ErrWorkContextInvalid)
}
