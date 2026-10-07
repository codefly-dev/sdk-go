package codefly_test

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/codefly-dev/core/resources"
	codefly "github.com/codefly-dev/sdk-go"
	"github.com/stretchr/testify/require"
)

func TestConsumerIdentityDriftIsRefused(t *testing.T) {
	prepareEndpointSelectionWorkspace(t, "client", "visibility: private", "")
	_, err := codefly.Init(context.Background())
	require.NoError(t, err)
	original := codefly.For(context.Background()).Module("producer").Service("records").Endpoint("rest").API("rest")
	_, err = original.ResolveNetworkInstance()
	require.ErrorIs(t, err, resources.ErrEndpointNotReachable)
	t.Setenv(resources.ModulePrefix, "producer")
	for _, query := range []*codefly.Query{original, codefly.For(context.Background()).Module("producer").Service("records").Endpoint("rest").API("rest")} {
		t.Run("ResolveNetworkInstance", func(t *testing.T) {
			instance, err := query.ResolveNetworkInstance()
			require.ErrorIs(t, err, codefly.ErrAuthorityValueChanged)
			require.Nil(t, instance)
		})
		t.Run("NetworkInstance", func(t *testing.T) { require.Nil(t, query.NetworkInstance()) })
	}
}

func initEndpointConsumer(t *testing.T, identity string) {
	t.Helper()
	codefly.IsolateConsumerIdentityForTest(t)
	t.Cleanup(func() { require.NoError(t, codefly.LoadEnvironmentVariables()) })
	t.Setenv(resources.ModulePrefix, identity)
	if strings.TrimSpace(identity) != "" {
		_, err := codefly.Init(context.Background())
		require.NoError(t, err)
	}
}

func TestConsumerIdentityCannotBeReinitialized(t *testing.T) {
	prepareEndpointSelectionWorkspace(t, "client", "visibility: private", "")
	_, err := codefly.Init(context.Background())
	require.NoError(t, err, "reinitializing the same identity is allowed")
	t.Setenv(resources.ModulePrefix, "producer")
	require.NoError(t, codefly.LoadEnvironmentVariables())
	_, err = codefly.Init(context.Background())
	require.ErrorIs(t, err, codefly.ErrAuthorityValueChanged)
	instance, err := codefly.For(context.Background()).Module("producer").Service("records").Endpoint("rest").ResolveNetworkInstance()
	require.ErrorIs(t, err, codefly.ErrAuthorityValueChanged)
	require.Nil(t, instance)
	t.Setenv(resources.ModulePrefix, "client")
	instance, err = codefly.For(context.Background()).Module("producer").Service("records").Endpoint("rest").ResolveNetworkInstance()
	require.ErrorIs(t, err, resources.ErrEndpointNotReachable, "the original consumer remains pinned")
	require.Nil(t, instance)
}

func TestEndpointConsumerMustBeInitialized(t *testing.T) {
	prepareEndpointSelectionWorkspace(t, "client", "visibility: public", "")
	codefly.IsolateConsumerIdentityForTest(t)
	query := codefly.For(context.Background()).Module("producer").Service("records").Endpoint("rest")
	instance, err := query.ResolveNetworkInstance()
	require.ErrorIs(t, err, resources.ErrConsumerNotIdentified)
	require.Nil(t, instance)
	require.Nil(t, query.NetworkInstance())
}

// Init alone establishes the consumer, and a process the runtime did not
// identify has no consumer to establish: it is refused at boot rather than
// left to resolve references for nobody. Every codefly-managed flow sets the
// identity carrier; a bare `go run` does not, and this is the error it sees.
func TestInitRefusesAnUnidentifiedProcess(t *testing.T) {
	for name, identity := range map[string]*string{"unset": nil, "empty": new(string), "whitespace": ptr("  ")} {
		t.Run(name, func(t *testing.T) {
			codefly.IsolateConsumerIdentityForTest(t)
			t.Cleanup(func() { require.NoError(t, codefly.LoadEnvironmentVariables()) })
			t.Setenv(resources.ModulePrefix, "") // register the restore before unsetting
			if identity == nil {
				require.NoError(t, os.Unsetenv(resources.ModulePrefix))
			} else {
				t.Setenv(resources.ModulePrefix, *identity)
			}
			provider, err := codefly.Init(context.Background())
			require.ErrorIs(t, err, resources.ErrConsumerNotIdentified)
			require.Nil(t, provider)
			// Nothing was pinned: a later query is refused for the same reason,
			// not reported as a drift from an identity that was never adopted.
			query := codefly.For(context.Background()).Module("producer").Service("records").Endpoint("rest")
			instance, err := query.ResolveNetworkInstance()
			require.ErrorIs(t, err, resources.ErrConsumerNotIdentified)
			require.Nil(t, instance)
			require.Nil(t, query.NetworkInstance())
		})
	}
}

func ptr(s string) *string { return &s }
