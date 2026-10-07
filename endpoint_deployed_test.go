package codefly_test

import (
	"context"
	"os"
	"testing"

	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
	"github.com/codefly-dev/core/resources"
	codefly "github.com/codefly-dev/sdk-go"
	"github.com/stretchr/testify/require"
)

// A deployed process is composed and started by the runtime, and the builder
// image ships the binary alone: there is no workspace on disk. Its carriers are
// the composition's judgement — the CLI's join decided at render which
// endpoints this consumer may reach, and the mesh enforces it on the cell — so
// the SDK resolves from the carrier keyed by the query's canonical identity and
// refuses only an absent carrier or a malformed one. The environment and the
// presence of a workspace decide the path; no flag does.

var carriedEndpoint = resources.EndpointInformation{
	Module: "platform", Service: "location-records", Name: "rest", API: "rest",
}

func carrierFor(name, api, address string) *resources.EndpointAccess {
	return &resources.EndpointAccess{
		Endpoint:        &basev0.Endpoint{Module: carriedEndpoint.Module, Service: carriedEndpoint.Service, Name: name, Api: api, Visibility: resources.VisibilityPublic},
		NetworkInstance: &basev0.NetworkInstance{Address: address},
	}
}

// prepareProcessWithoutWorkspace boots the process as the consumer "client" in
// the given environment, from a directory with no workspace above it. The
// canonical carrier for platform/location-records/rest is removed from the
// environment and the snapshot reloaded, so each test injects exactly what it
// means to.
func prepareProcessWithoutWorkspace(t *testing.T, environment string) {
	t.Helper()
	initEndpointConsumer(t, "client")
	t.Cleanup(func() { require.NoError(t, codefly.LoadEnvironmentVariables()) })
	t.Setenv("CODEFLY__ENVIRONMENT", environment)
	key := resources.EndpointAsEnvironmentVariableKey(&carriedEndpoint)
	t.Setenv(key, "") // register cleanup before removing the carrier entirely
	require.NoError(t, os.Unsetenv(key))
	require.NoError(t, codefly.LoadEnvironmentVariables())
	t.Chdir(t.TempDir())
	workspace, err := resources.FindWorkspaceUp(context.Background())
	require.NoError(t, err)
	require.Nil(t, workspace, "a workspace above the temporary directory would make a test about a process without one prove nothing")
}

func queryCarriedService() *codefly.Query {
	return codefly.For(context.Background()).Module(carriedEndpoint.Module).Service(carriedEndpoint.Service)
}

// Every spelling of the reference that names platform/location-records/rest.
var referenceForms = []struct {
	name  string
	query func(*codefly.Query) *codefly.Query
}{
	{"name and API", func(q *codefly.Query) *codefly.Query { return q.Endpoint("rest").API("rest") }},
	{"API only", func(q *codefly.Query) *codefly.Query { return q.API("rest") }},
	{"name only", func(q *codefly.Query) *codefly.Query { return q.Endpoint("rest") }},
}

func TestDeployedProcessResolvesItsCarrierWithoutAWorkspace(t *testing.T) {
	for _, environment := range []string{"production", "staging"} {
		for _, source := range []string{"runtime", "embedded"} {
			for _, form := range referenceForms {
				t.Run("environment="+environment+"/source="+source+"/"+form.name, func(t *testing.T) {
					prepareProcessWithoutWorkspace(t, environment)
					access := carrierFor("rest", "rest", "https://upstream.example:9443")
					injectEndpointForTest(t, source, access)
					query := form.query(queryCarriedService())
					instance, err := query.ResolveNetworkInstance()
					require.NoError(t, err)
					require.NotNil(t, instance)
					require.Equal(t, access.NetworkInstance.Address, instance.Address)
					require.Equal(t, "upstream.example", instance.Hostname)
					require.Equal(t, uint16(9443), instance.Port)
					require.NotNil(t, query.NetworkInstance())
				})
			}
		}
	}
}

func TestDeployedProcessRefusesAnAbsentCarrierWithTheSentinel(t *testing.T) {
	for _, environment := range []string{"production", "staging"} {
		for _, form := range referenceForms {
			t.Run("environment="+environment+"/"+form.name, func(t *testing.T) {
				prepareProcessWithoutWorkspace(t, environment)
				query := form.query(queryCarriedService())
				t.Run("ResolveNetworkInstance", func(t *testing.T) {
					instance, err := query.ResolveNetworkInstance()
					require.ErrorIs(t, err, codefly.ErrEndpointCarrierAbsent)
					require.ErrorContains(t, err, "platform/location-records/rest")
					require.Nil(t, instance)
				})
				t.Run("NetworkInstance", func(t *testing.T) { require.Nil(t, query.NetworkInstance()) })
			})
		}
	}
}

// The carrier is keyed by the whole identity. One carried under the same name
// for another API does not answer a reference to this one, and nothing native
// is computed in its place.
func TestDeployedProcessCarrierIsKeyedByTheWholeIdentity(t *testing.T) {
	for _, source := range []string{"runtime", "embedded"} {
		t.Run("source="+source, func(t *testing.T) {
			prepareProcessWithoutWorkspace(t, "production")
			injectEndpointForTest(t, source, carrierFor("rest", "grpc", "grpc.example:9090"))
			query := queryCarriedService().Endpoint("rest").API("rest")
			instance, err := query.ResolveNetworkInstance()
			require.ErrorIs(t, err, codefly.ErrEndpointCarrierAbsent)
			require.Nil(t, instance)
			require.Nil(t, query.NetworkInstance())
		})
	}
}

// Only a declaration could say which API an endpoint not named after one
// serves, and there is none on disk: the reference cannot key a carrier until
// it qualifies the API itself.
func TestDeployedProcessNeedsTheAPIOfAnEndpointNotNamedAfterOne(t *testing.T) {
	prepareProcessWithoutWorkspace(t, "production")
	injectEndpointForTest(t, "embedded", carrierFor("health", "rest", "https://health.example:9443"))
	instance, err := queryCarriedService().Endpoint("health").ResolveNetworkInstance()
	require.ErrorIs(t, err, codefly.ErrEndpointCarrierAbsent)
	require.ErrorContains(t, err, "API(...)")
	require.Nil(t, instance)
	instance, err = queryCarriedService().Endpoint("health").API("rest").ResolveNetworkInstance()
	require.NoError(t, err)
	require.Equal(t, "https://health.example:9443", instance.Address)
}

func TestDeployedProcessRefusesAMalformedCarrier(t *testing.T) {
	for _, tc := range []struct{ source, address string }{
		{"runtime", "not-an-address"}, {"embedded", "not-an-address"},
		{"runtime", "localhost:not-a-port"}, {"embedded", "localhost:not-a-port"},
		// InjectEndpoints refuses an empty address, so an empty carrier can only
		// arrive from the process environment.
		{"runtime", ""},
	} {
		t.Run("source="+tc.source+"/address="+tc.address, func(t *testing.T) {
			prepareProcessWithoutWorkspace(t, "production")
			if tc.address == "" {
				t.Setenv(resources.EndpointAsEnvironmentVariableKey(&carriedEndpoint), "")
				require.NoError(t, codefly.LoadEnvironmentVariables())
			} else {
				injectEndpointForTest(t, tc.source, carrierFor("rest", "rest", tc.address))
			}
			query := queryCarriedService().Endpoint("rest").API("rest")
			t.Run("ResolveNetworkInstance", func(t *testing.T) {
				instance, err := query.ResolveNetworkInstance()
				require.Error(t, err)
				require.NotErrorIs(t, err, codefly.ErrEndpointCarrierAbsent, "a present carrier is never reported absent")
				require.ErrorContains(t, err, "malformed address", "the refusal names the carrier, not an unrelated cause")
				require.Nil(t, instance, "core's partial instance beside a parse error must not leak")
			})
			t.Run("NetworkInstance", func(t *testing.T) { require.Nil(t, query.NetworkInstance()) })
		})
	}
}

// A consumer that ships its workspace keeps the stronger check outside local:
// selection judges the reference before any carrier is read.
func TestDeployedProcessWithAWorkspaceStillSelectsFirst(t *testing.T) {
	for _, tc := range []struct {
		name, declaration string
		refusal           error
	}{
		{"private across modules", "visibility: private", resources.ErrEndpointNotReachable},
		// This table holds refusals. The case that stood here asserted an authored
		// allow-list excluding a consumer, a rule core deleted: an endpoint
		// names no consumer and `internal` reaches whatever composes the
		// module, so a deployed process selects it rather than refusing. The
		// refusals that remain are private, above, and the API mismatch below.
		{"API mismatch", "visibility: public\n    api: grpc\n    exposure: none", resources.ErrEndpointAPIMismatch},
	} {
		for _, source := range []string{"runtime", "embedded"} {
			t.Run(tc.name+"/source="+source, func(t *testing.T) {
				prepareEndpointSelectionWorkspace(t, "client", tc.declaration, "")
				t.Setenv("CODEFLY__ENVIRONMENT", "production")
				require.NoError(t, codefly.LoadEnvironmentVariables())
				injectEndpointForTest(t, source, &resources.EndpointAccess{
					Endpoint:        &basev0.Endpoint{Module: "producer", Service: "records", Name: "rest", Api: "rest"},
					NetworkInstance: &basev0.NetworkInstance{Address: "https://upstream.example:9443"},
				})
				query := codefly.For(context.Background()).Module("producer").Service("records").Endpoint("rest").API("rest")
				instance, err := query.ResolveNetworkInstance()
				require.ErrorIs(t, err, tc.refusal)
				require.Nil(t, instance)
				require.Nil(t, query.NetworkInstance())
			})
		}
	}
}

// Outside local, an absent carrier is the same refusal with or without a
// workspace: the typed sentinel, and no native address.
func TestNonlocalProcessWithAWorkspaceRefusesAbsenceWithTheSentinel(t *testing.T) {
	prepareEndpointLocationWorkspace(t, "production", "")
	query := codefly.For(context.Background()).Module("platform").Service("location-records").Endpoint("rest")
	instance, err := query.ResolveNetworkInstance()
	require.ErrorIs(t, err, codefly.ErrEndpointCarrierAbsent)
	require.Nil(t, instance)
}

// In local, or before an environment is selected, the declarations are the
// authority and a process without them is refused as #57 built it. A carrier
// alone establishes nothing there.
func TestLocalProcessWithoutAWorkspaceStillRequiresDeclarations(t *testing.T) {
	for _, environment := range []string{"", "local"} {
		for _, form := range referenceForms {
			t.Run("environment="+environment+"/"+form.name, func(t *testing.T) {
				prepareProcessWithoutWorkspace(t, environment)
				injectEndpointForTest(t, "embedded", carrierFor("rest", "rest", "https://upstream.example:9443"))
				query := form.query(queryCarriedService())
				instance, err := query.ResolveNetworkInstance()
				require.ErrorIs(t, err, resources.ErrNoDeclaredEndpoints)
				require.Nil(t, instance)
				require.Nil(t, query.NetworkInstance())
			})
		}
	}
}
