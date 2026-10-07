package codefly_test

import (
	"context"
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
