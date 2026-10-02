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
	corework "github.com/codefly-dev/core/workcontext"

	"github.com/codefly-dev/sdk-go/workcontext"
	"github.com/codefly-dev/sdk-go/workcontext/grpctransport"
)

// Two real gRPC services on loopback listeners, core's authority holding the
// one signing key, and core's verifier in each service. Service A is called by
// a client holding a capability for A's audience, and calls service B on the
// same logical operation. The request's Service field names how A reaches B.
//
// Everything that mints or verifies here is core's. The transport under test is
// this module's, and that is the whole shape of the module: it carries a
// capability it did not make to a verifier it does not own.
const (
	hopIssuer    = "https://authority.codefly.test/work-context"
	hopKeyID     = "hop-key"
	hopTenant    = "tenant-hop"
	hopPrincipal = "principal-owner"
	hopActor     = "principal-service-a"
	hopRevision  = 7
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
	{ResourceKind: "record", Actions: []string{"append"}},
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

// hopAuthority is the exchange endpoint a service calls: it holds the signing
// key, which a service never does.
type hopAuthority struct {
	minter    *corework.Authority
	seals     *corework.MemorySealSource
	replay    corework.ReplayStore
	publicKey ed25519.PublicKey
}

func newHopAuthority(t *testing.T) *hopAuthority {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	seals := corework.NewMemorySealSource()
	require.NoError(t, seals.Put(hopPrincipal, hopSeal()))
	return &hopAuthority{
		minter: &corework.Authority{
			Issuer: hopIssuer, KeyID: hopKeyID, Key: privateKey,
			Revisions: corework.FixedRevision(hopRevision),
			Seals:     seals,
			Now:       func() time.Time { return hopNow },
		},
		seals:     seals,
		replay:    corework.NewMemoryReplayStore(),
		publicKey: publicKey,
	}
}

// verifier is core's, configured for one service's audience. A verifier is
// given all four of core's sources because a verifier missing one refuses
// everything rather than skipping that check.
func (a *hopAuthority) verifier(audience string) *workcontext.Verifier {
	return &workcontext.Verifier{
		Issuer:    hopIssuer,
		Audience:  audience,
		Keys:      map[string]ed25519.PublicKey{hopKeyID: a.publicKey},
		Revisions: corework.FixedRevision(hopRevision),
		Replay:    a.replay,
		Grants:    hopNoGrants{},
		Seals:     a.seals,
		Now:       func() time.Time { return hopNow },
	}
}

type hopNoGrants struct{}

func (hopNoGrants) Grant(context.Context, string) (*corework.Grant, error) {
	return nil, corework.ErrInvalid
}

// verifyIncoming is the authentication a service runs on every call: the
// carrier from gRPC metadata, verified for this service's own audience.
func verifyIncoming(
	ctx context.Context,
	verifier *workcontext.Verifier,
) (grpctransport.ExecutionContext, *workcontext.Verified, error) {
	execution, err := grpctransport.GRPCExecutionContextFromIncoming(ctx)
	if err != nil {
		return grpctransport.ExecutionContext{}, nil, status.Error(codes.Unauthenticated, err.Error())
	}
	verified, err := verifier.Verify(ctx, execution.Capability())
	if err != nil {
		return grpctransport.ExecutionContext{}, nil, status.Error(codes.Unauthenticated, err.Error())
	}
	return execution, verified, nil
}

type serviceB struct {
	verifier *workcontext.Verifier
	accepted chan *workcontext.Verified
}

func (s *serviceB) call(ctx context.Context, _ *healthv1.HealthCheckRequest) (*healthv1.HealthCheckResponse, error) {
	_, verified, err := verifyIncoming(ctx, s.verifier)
	if err != nil {
		return nil, err
	}
	s.accepted <- verified
	return &healthv1.HealthCheckResponse{Status: healthv1.HealthCheckResponse_SERVING}, nil
}

type serviceA struct {
	verifier  *workcontext.Verifier
	authority *hopAuthority
	b         grpc.ClientConnInterface
	accepted  chan *workcontext.Verified
}

func (s *serviceA) call(ctx context.Context, request *healthv1.HealthCheckRequest) (*healthv1.HealthCheckResponse, error) {
	incoming, verified, err := verifyIncoming(ctx, s.verifier)
	if err != nil {
		return nil, err
	}
	s.accepted <- verified

	outgoing := incoming
	if request.GetService() != hopForward {
		// A hop across an audience boundary is a delegation minted by the
		// authority for the callee's audience, never the capability A was
		// handed: B's audience check refuses a forwarded one.
		scopes := cloneHopScopes()
		switch request.GetService() {
		case hopAttenuate:
			scopes = cloneHopScopes()[1:]
		case hopWiden:
			scopes = append(cloneHopScopes(), &basev0.WorkScopeV1{
				ResourceKind: "profile", Actions: []string{"read"},
			})
		}
		exchanged, _, err := s.authority.minter.Child(ctx, verified, corework.ChildInput{
			PrincipalID:   hopActor,
			PrincipalKind: "service",
			DelegationID:  "delegation-hop",
			GrantedScopes: scopes,
			Audience:      audienceB,
			TTL:           5 * time.Minute,
		})
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
	atA       chan *workcontext.Verified
	atB       chan *workcontext.Verified
}

func newHopTopology(t *testing.T) *hopTopology {
	t.Helper()
	authority := newHopAuthority(t)
	topology := &hopTopology{
		authority: authority,
		atA:       make(chan *workcontext.Verified, 1),
		atB:       make(chan *workcontext.Verified, 1),
	}
	topology.b = serveHop(t, &serviceB{verifier: authority.verifier(audienceB), accepted: topology.atB})
	topology.a = serveHop(t, &serviceA{
		verifier: authority.verifier(audienceA), authority: authority, b: topology.b, accepted: topology.atA,
	})
	return topology
}

// hopSeal is the execution both services in the hop run as: one installation,
// one revision, one build. A hop crosses an audience boundary inside one
// execution, so the seal is the same on both sides of it.
func hopSeal() workcontext.Seal {
	return workcontext.Seal{
		PrincipalEpoch:       3,
		InstallationID:       "installation-hop",
		InstallationRevision: 12,
		BuildIncarnation:     9,
	}
}

// startTask issues the capability the external caller holds: for service A
// only.
func (h *hopTopology) startTask(t *testing.T) string {
	t.Helper()
	token, _, err := h.authority.minter.Start(context.Background(), corework.StartInput{
		Audience: audienceA, TenantID: hopTenant, OwnerPrincipalID: hopPrincipal,
		OwnerPrincipalKind: "service", TaskID: "task-hop",
		InstallationID:  hopSeal().InstallationID,
		AuthorityScopes: cloneHopScopes(),
		TTL:             10 * time.Minute,
	})
	require.NoError(t, err)
	return token
}

func (h *hopTopology) call(t *testing.T, connection *grpc.ClientConn, token string, mode string) error {
	t.Helper()
	execution, err := grpctransport.NewExecutionContext(token, "operation-hop")
	require.NoError(t, err)
	ctx, err := grpctransport.WithGRPCExecutionContext(t.Context(), execution)
	require.NoError(t, err)
	return connection.Invoke(ctx, hopMethod, &healthv1.HealthCheckRequest{Service: mode}, new(healthv1.HealthCheckResponse))
}

func TestServiceHopRejectsACapabilityForwardedToAnotherAudience(t *testing.T) {
	topology := newHopTopology(t)
	token := topology.startTask(t)

	err := topology.call(t, topology.a, token, hopForward)
	require.Equal(t, codes.Unauthenticated, status.Code(err), err)
	require.ErrorContains(t, err, "presented to")
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
	verifiedA := <-topology.atA
	atA := verifiedA.Context()
	verifiedB := <-topology.atB
	atB := verifiedB.Context()

	require.Equal(t, audienceA, atA.GetAudience())
	require.Equal(t, audienceB, atB.GetAudience())
	for _, pair := range [][2]string{
		{atA.GetTenantId(), atB.GetTenantId()},
		{atA.GetOwnerPrincipalId(), atB.GetOwnerPrincipalId()},
		{atA.GetTaskId(), atB.GetTaskId()},
	} {
		require.Equal(t, pair[0], pair[1])
	}
	// A hop is a child session of the same task, not the same session: the
	// task is what survives a delegation, and the parent is named rather than
	// impersonated.
	require.NotEqual(t, atA.GetSessionId(), atB.GetSessionId())
	require.Equal(t, atA.GetSessionId(), atB.GetParentSessionId())
	require.Equal(t, atA.GetAuthorizationRevision(), atB.GetAuthorizationRevision())
	require.Equal(t, len(verifiedA.EffectiveScopes()), len(verifiedB.EffectiveScopes()))
	for index, scope := range verifiedB.EffectiveScopes() {
		want := verifiedA.EffectiveScopes()[index]
		require.Equal(t, want.GetResourceKind(), scope.GetResourceKind())
		require.Equal(t, want.GetActions(), scope.GetActions())
		require.Equal(t, want.GetResourceIds(), scope.GetResourceIds())
	}

	// The seal survives the hop unchanged: a hop crosses an audience boundary
	// inside one execution, so both sides are sealed to one installation at one
	// revision on one build.
	require.Equal(t, atA.GetSeal().GetInstallationId(), atB.GetSeal().GetInstallationId())
	require.Equal(t, atA.GetSeal().GetInstallationRevision(), atB.GetSeal().GetInstallationRevision())
	require.Equal(t, atA.GetSeal().GetBuildIncarnation(), atB.GetSeal().GetBuildIncarnation())

	// B's delegated capability is itself bound to B: sent back to A it fails.
	exchangedToA := topology.call(t, topology.a, mustReissueForB(t, topology.authority, verifiedA), hopExchange)
	require.Equal(t, codes.Unauthenticated, status.Code(exchangedToA), exchangedToA)

	// The hop keeps the cache partition: same tenant, same installation, same
	// view.
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
	atB := <-topology.atB

	// Whether the delegated capability covers a call is core's scope algebra,
	// asked of the scopes core says are effective. This module answers no part
	// of that question.
	require.True(t, workcontext.ScopeContained(
		&basev0.WorkScopeV1{ResourceKind: "record", Actions: []string{"append"}},
		atB.EffectiveScopes(),
	))
	require.False(t, workcontext.ScopeContained(
		&basev0.WorkScopeV1{ResourceKind: "document", Actions: []string{"read"}},
		atB.EffectiveScopes(),
	), "the hop attenuated the document scope away, so it is no longer covered")

	err := topology.call(t, topology.a, topology.startTask(t), hopWiden)
	require.Equal(t, codes.PermissionDenied, status.Code(err), err)
	require.ErrorContains(t, err, "widens authority")
	<-topology.atA
	require.Empty(t, topology.atB, "a widening exchange must never reach B")
}

func mustReissueForB(t *testing.T, authority *hopAuthority, parent *workcontext.Verified) string {
	t.Helper()
	exchanged, _, err := authority.minter.Child(context.Background(), parent, corework.ChildInput{
		PrincipalID:   hopActor,
		PrincipalKind: "service",
		DelegationID:  "delegation-hop",
		GrantedScopes: cloneHopScopes(),
		Audience:      audienceB,
		TTL:           5 * time.Minute,
	})
	require.NoError(t, err)
	return exchanged
}
