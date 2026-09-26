package grpctransport_test

import (
	"context"
	"crypto/ed25519"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	healthv1 "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/status"

	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"

	"github.com/codefly-dev/sdk-go/workcontext"
	"github.com/codefly-dev/sdk-go/workcontext/grpctransport"
)

// Two real gRPC services on loopback listeners, a real Ed25519 authority, and
// a real verifier in each service. Service A is called by a client holding a
// Work Context for A's audience, and calls service B on the same logical
// operation. The request's Service field names how A reaches B.
const (
	hopIssuer    = "https://accounts.codefly.dev/work-context"
	hopKeyID     = "hop-key"
	audienceA    = "codefly.test.service-a"
	audienceB    = "codefly.test.service-b"
	hopMethod    = "/codefly.test.Hop/Call"
	hopForward   = "forward"
	hopExchange  = "exchange"
	hopAttenuate = "exchange-attenuated"
	hopWiden     = "exchange-widened"
)

var hopNow = time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC)

var hopScopes = []*basev0.WorkScopeV1{
	{ResourceKind: "document", Actions: []string{"read", "write"}},
	{ResourceKind: "evidence", Actions: []string{"append"}},
}

// hopService is the handler both services register under one ServiceDesc. It
// reuses the grpc module's health messages so the test needs no generated code
// and no dependency the module does not already have.
type hopService interface {
	call(ctx context.Context, request *healthv1.HealthCheckRequest) (*healthv1.HealthCheckResponse, error)
}

var hopServiceDesc = grpc.ServiceDesc{
	ServiceName: "codefly.test.Hop",
	HandlerType: (*hopService)(nil),
	Methods: []grpc.MethodDesc{{
		MethodName: "Call",
		Handler: func(server any, ctx context.Context, decode func(any) error, _ grpc.UnaryServerInterceptor) (any, error) {
			request := new(healthv1.HealthCheckRequest)
			if err := decode(request); err != nil {
				return nil, err
			}
			return server.(hopService).call(ctx, request)
		},
	}},
}

// hopAuthority stands in for the exchange endpoint a service calls: it holds
// the signer, which services never do.
type hopAuthority struct {
	signer    *workcontext.WorkContextSigner
	publicKey ed25519.PublicKey
}

func newHopAuthority(t *testing.T) *hopAuthority {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	signer, err := workcontext.NewWorkContextSigner(workcontext.WorkContextSignerOptions{
		Issuer: hopIssuer, KeyID: hopKeyID, PrivateKey: privateKey,
		Now: func() time.Time { return hopNow },
	})
	require.NoError(t, err)
	return &hopAuthority{signer: signer, publicKey: publicKey}
}

func (a *hopAuthority) verifier(t *testing.T) *workcontext.WorkContextVerifier {
	t.Helper()
	verifier, err := workcontext.NewWorkContextVerifier(workcontext.WorkContextVerifierOptions{
		PublicKeys: map[string]ed25519.PublicKey{hopKeyID: a.publicKey},
		Now:        func() time.Time { return hopNow },
	})
	require.NoError(t, err)
	return verifier
}

// verifyIncoming is the authentication a service runs on every call: the
// carrier from gRPC metadata, verified for this service's own audience.
func verifyIncoming(
	ctx context.Context,
	verifier *workcontext.WorkContextVerifier,
	audience string,
) (grpctransport.ExecutionContext, workcontext.VerifiedWorkContext, error) {
	execution, err := grpctransport.GRPCExecutionContextFromIncoming(ctx)
	if err != nil {
		return grpctransport.ExecutionContext{}, workcontext.VerifiedWorkContext{}, status.Error(codes.Unauthenticated, err.Error())
	}
	verified, err := verifier.VerifyWorkContext(execution.WorkContext(), workcontext.WorkContextExpectations{
		Issuer: hopIssuer, Audience: audience,
	})
	if err != nil {
		return grpctransport.ExecutionContext{}, workcontext.VerifiedWorkContext{}, status.Error(codes.Unauthenticated, err.Error())
	}
	return execution, verified, nil
}

type serviceB struct {
	verifier *workcontext.WorkContextVerifier
	accepted chan workcontext.VerifiedWorkContext
}

func (s *serviceB) call(ctx context.Context, _ *healthv1.HealthCheckRequest) (*healthv1.HealthCheckResponse, error) {
	_, verified, err := verifyIncoming(ctx, s.verifier, audienceB)
	if err != nil {
		return nil, err
	}
	s.accepted <- verified
	return &healthv1.HealthCheckResponse{Status: healthv1.HealthCheckResponse_SERVING}, nil
}

type serviceA struct {
	verifier  *workcontext.WorkContextVerifier
	authority *hopAuthority
	b         grpc.ClientConnInterface
	accepted  chan workcontext.VerifiedWorkContext
}

func (s *serviceA) call(ctx context.Context, request *healthv1.HealthCheckRequest) (*healthv1.HealthCheckResponse, error) {
	incoming, verified, err := verifyIncoming(ctx, s.verifier, audienceA)
	if err != nil {
		return nil, err
	}
	s.accepted <- verified

	outgoing := incoming
	if request.GetService() != hopForward {
		input := workcontext.ExchangeWorkContextAudienceInput{Audience: audienceB}
		switch request.GetService() {
		case hopAttenuate:
			input.AttenuatedScopes = hopScopes[1:]
		case hopWiden:
			input.AttenuatedScopes = append(cloneHopScopes(), &basev0.WorkScopeV1{
				ResourceKind: "profile", Actions: []string{"read"},
			})
		}
		exchanged, _, err := s.authority.signer.ExchangeWorkContextAudience(incoming.WorkContext(), input)
		if err != nil {
			return nil, status.Error(codes.PermissionDenied, err.Error())
		}
		outgoing, err = grpctransport.NewExecutionContext(exchanged, incoming.OperationID())
		if err != nil {
			return nil, status.Error(codes.Internal, err.Error())
		}
	}
	callCtx, err := grpctransport.WithGRPCExecutionContext(ctx, outgoing)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	response := new(healthv1.HealthCheckResponse)
	if err := s.b.Invoke(callCtx, hopMethod, &healthv1.HealthCheckRequest{}, response); err != nil {
		return nil, err
	}
	return response, nil
}

func cloneHopScopes() []*basev0.WorkScopeV1 {
	out := make([]*basev0.WorkScopeV1, 0, len(hopScopes))
	for _, scope := range hopScopes {
		out = append(out, &basev0.WorkScopeV1{
			ResourceKind: scope.GetResourceKind(),
			Actions:      append([]string(nil), scope.GetActions()...),
			ResourceIds:  append([]string(nil), scope.GetResourceIds()...),
		})
	}
	return out
}

func serveHop(t *testing.T, service hopService) *grpc.ClientConn {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	server := grpc.NewServer()
	server.RegisterService(&hopServiceDesc, service)
	served := make(chan error, 1)
	go func() { served <- server.Serve(listener) }()
	t.Cleanup(func() {
		server.Stop()
		if err := <-served; err != nil && !errors.Is(err, grpc.ErrServerStopped) {
			t.Errorf("serve: %v", err)
		}
	})
	connection, err := grpc.NewClient(listener.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	t.Cleanup(func() { _ = connection.Close() })
	return connection
}

type hopTopology struct {
	authority *hopAuthority
	a         *grpc.ClientConn
	b         *grpc.ClientConn
	atA       chan workcontext.VerifiedWorkContext
	atB       chan workcontext.VerifiedWorkContext
}

func newHopTopology(t *testing.T) *hopTopology {
	t.Helper()
	authority := newHopAuthority(t)
	topology := &hopTopology{
		authority: authority,
		atA:       make(chan workcontext.VerifiedWorkContext, 1),
		atB:       make(chan workcontext.VerifiedWorkContext, 1),
	}
	topology.b = serveHop(t, &serviceB{verifier: authority.verifier(t), accepted: topology.atB})
	topology.a = serveHop(t, &serviceA{
		verifier: authority.verifier(t), authority: authority, b: topology.b, accepted: topology.atA,
	})
	return topology
}

// startTask issues the context the external caller holds: for service A only.
func (h *hopTopology) startTask(t *testing.T) workcontext.WorkContextToken {
	t.Helper()
	token, _, err := h.authority.signer.StartTask(workcontext.StartTaskInput{
		Audience: audienceA, TenantID: "tenant-codefly", OwnerPrincipalID: "principal-owner",
		TaskID: "task-hop", SessionID: "session-hop", AuthorizationRevision: 7,
		AuthorityScopes: cloneHopScopes(),
	})
	require.NoError(t, err)
	return token
}

func (h *hopTopology) call(t *testing.T, connection *grpc.ClientConn, token workcontext.WorkContextToken, mode string) error {
	t.Helper()
	execution, err := grpctransport.NewExecutionContext(token, "operation-hop")
	require.NoError(t, err)
	ctx, err := grpctransport.WithGRPCExecutionContext(t.Context(), execution)
	require.NoError(t, err)
	return connection.Invoke(ctx, hopMethod, &healthv1.HealthCheckRequest{Service: mode}, new(healthv1.HealthCheckResponse))
}

func effectiveScopes(claims *basev0.WorkContextV1) []*basev0.WorkScopeV1 {
	if actors := claims.GetActorChain(); len(actors) > 0 {
		return actors[len(actors)-1].GetGrantedScopes()
	}
	return claims.GetAuthorityScopes()
}

func TestServiceHopRejectsAWorkContextForwardedToAnotherAudience(t *testing.T) {
	topology := newHopTopology(t)
	token := topology.startTask(t)

	err := topology.call(t, topology.a, token, hopForward)
	require.Equal(t, codes.Unauthenticated, status.Code(err), err)
	require.ErrorContains(t, err, "audience mismatch")
	require.Len(t, topology.atA, 1, "A accepted its own context before forwarding it")
	require.Empty(t, topology.atB, "B must not accept a context minted for A")

	// The same token presented to B directly, with no intermediary, is
	// rejected identically: the refusal is B's audience check, not A's doing.
	err = topology.call(t, topology.b, token, "")
	require.Equal(t, codes.Unauthenticated, status.Code(err), err)
	require.Empty(t, topology.atB)
}

func TestServiceHopExchangeThenCallSucceedsWithoutWideningScopes(t *testing.T) {
	topology := newHopTopology(t)
	token := topology.startTask(t)

	require.NoError(t, topology.call(t, topology.a, token, hopExchange))
	atA := (<-topology.atA).Claims()
	verifiedB := <-topology.atB
	atB := verifiedB.Claims()

	require.Equal(t, audienceA, atA.GetAudience())
	require.Equal(t, audienceB, atB.GetAudience())
	for _, pair := range [][2]string{
		{atA.GetTenantId(), atB.GetTenantId()},
		{atA.GetOwnerPrincipalId(), atB.GetOwnerPrincipalId()},
		{atA.GetTaskId(), atB.GetTaskId()},
		{atA.GetSessionId(), atB.GetSessionId()},
	} {
		require.Equal(t, pair[0], pair[1])
	}
	require.Equal(t, atA.GetAuthorizationRevision(), atB.GetAuthorizationRevision())
	require.Equal(t, len(effectiveScopes(atA)), len(effectiveScopes(atB)))
	for index, scope := range effectiveScopes(atB) {
		want := effectiveScopes(atA)[index]
		require.Equal(t, want.GetResourceKind(), scope.GetResourceKind())
		require.Equal(t, want.GetActions(), scope.GetActions())
		require.Equal(t, want.GetResourceIds(), scope.GetResourceIds())
	}

	// B's exchanged context is itself bound to B: sent back to A it fails.
	exchangedToA := topology.call(t, topology.a, mustReissueForB(t, topology.authority, token), hopExchange)
	require.Equal(t, codes.Unauthenticated, status.Code(exchangedToA), exchangedToA)

	// The hop keeps the cache partition: same tenant, same view.
	verifiedA, err := topology.authority.verifier(t).VerifyWorkContext(token, workcontext.WorkContextExpectations{Audience: audienceA})
	require.NoError(t, err)
	for _, options := range [][]workcontext.CachePartitionOption{nil, {workcontext.ByAuthorizationView()}} {
		partitionA, err := workcontext.DeriveCachePartition(verifiedA, options...)
		require.NoError(t, err)
		partitionB, err := workcontext.DeriveCachePartition(verifiedB, options...)
		require.NoError(t, err)
		require.Equal(t, partitionA, partitionB)
	}
}

func TestServiceHopExchangeMayAttenuateButNeverWiden(t *testing.T) {
	topology := newHopTopology(t)

	require.NoError(t, topology.call(t, topology.a, topology.startTask(t), hopAttenuate))
	<-topology.atA
	atB := (<-topology.atB).Claims()
	require.NoError(t, workcontext.RequireWorkContextScope(atB, workcontext.WorkContextScopeRequirement{
		ResourceKind: "evidence", Action: "append",
	}))
	err := workcontext.RequireWorkContextScope(atB, workcontext.WorkContextScopeRequirement{
		ResourceKind: "document", Action: "read",
	})
	require.ErrorIs(t, err, workcontext.ErrWorkContextDenied)

	err = topology.call(t, topology.a, topology.startTask(t), hopWiden)
	require.Equal(t, codes.PermissionDenied, status.Code(err), err)
	require.ErrorContains(t, err, "widens authority")
	<-topology.atA
	require.Empty(t, topology.atB, "a widening exchange must never reach B")
}

func mustReissueForB(t *testing.T, authority *hopAuthority, token workcontext.WorkContextToken) workcontext.WorkContextToken {
	t.Helper()
	exchanged, _, err := authority.signer.ExchangeWorkContextAudience(token, workcontext.ExchangeWorkContextAudienceInput{
		Audience: audienceB,
	})
	require.NoError(t, err)
	return exchanged
}
