package codefly_test

import (
	"context"
	"testing"

	basev1 "github.com/codefly-dev/core/generated/go/codefly/base/v1"
	"github.com/codefly-dev/core/network"
	"github.com/codefly-dev/core/resources"
	codefly "github.com/codefly-dev/sdk-go"
	"github.com/stretchr/testify/require"
)

// runScope is a naming scope a run was started under (`--naming-scope`, or the
// one `--temporary-ports` generates): the run injects it into every service it
// starts, beside the address of each endpoint it delivers that service.
const runScope = "invk3v9q2x"

// prepareScopedRun runs the consumer `client` in the composition root as a
// service of a run started under runScope.
func prepareScopedRun(t *testing.T) {
	t.Helper()
	prepareCompositionRoot(t, compositionRoot)
	t.Setenv(resources.NamingScopePrefix, runScope)
	require.NoError(t, codefly.LoadEnvironmentVariables())
}

func healthQuery(ctx context.Context) *codefly.Query {
	return codefly.For(ctx).Module("producer").Service("records").Endpoint("health").API("rest")
}

// A run under a naming scope hands a service the address of every endpoint it
// delivers it, and none for a dependency the service declared `kind:
// external`, which the run neither starts nor orders. Asked for such an
// endpoint, the SDK answered the native map's address for NO scope: a port
// where nothing of this run listens (a seed dialled [::1]:1193 while the
// scoped hop listened elsewhere, on every attempt). Under a scope the native
// map is no answer at all, since a scoped run's ports may be probed rather
// than derived; the endpoint is refused, naming the run and what was asked.
func TestAScopedRunRefusesAnEndpointItDidNotDeliver(t *testing.T) {
	prepareScopedRun(t)
	ctx := context.Background()

	instance, err := healthQuery(ctx).ResolveNetworkInstance()
	require.Nil(t, instance, "an address was answered for an endpoint the run did not deliver")
	require.ErrorIs(t, err, codefly.ErrEndpointCarrierAbsent)
	require.ErrorContains(t, err, "producer/records")
	require.ErrorContains(t, err, `naming scope "`+runScope+`"`)
	require.ErrorContains(t, err, "kind: external", "the refusal says which declaration a run delivers nothing for")
	require.Nil(t, healthQuery(ctx).NetworkInstance())
}

// What the run did deliver is answered as before: the carrier is the address.
func TestAScopedRunAnswersTheEndpointItDelivered(t *testing.T) {
	prepareScopedRun(t)
	t.Setenv(resources.EndpointAsEnvironmentVariableKey(&resources.EndpointInformation{
		Module: "producer", Service: "records", Name: "health", API: "rest"}), "http://localhost:41873")
	require.NoError(t, codefly.LoadEnvironmentVariables())

	instance, err := healthQuery(context.Background()).ResolveNetworkInstance()
	require.NoError(t, err)
	require.Equal(t, uint16(41873), instance.Port)
}

// A query that names the scope itself (a tool reaching a run it did not start)
// still gets that scope's native address: it asked for the map by name.
func TestAQueryNamingAScopeStillReadsThatScopesNativeMap(t *testing.T) {
	prepareScopedRun(t)
	ctx := context.Background()

	instance, err := healthQuery(ctx).NamingScope("other-run").ResolveNetworkInstance()
	require.NoError(t, err)
	expected := network.NativeFor(ctx, compositionRoot, "producer", "records", "other-run", &basev1.Endpoint{Name: "health", Api: "rest"})
	require.Equal(t, expected.Address, instance.Address)
}
