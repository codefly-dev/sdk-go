package codefly_test

import (
	"context"
	"testing"

	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
	"github.com/codefly-dev/core/resources"
	codefly "github.com/codefly-dev/sdk-go"
	"github.com/stretchr/testify/require"
)

func TestMalformedInjectedEndpointCannotFallBack(t *testing.T) {
	for _, environment := range []string{"", "local"} {
		for _, source := range []string{"runtime", "embedded"} {
			for _, api := range []string{"", "rest"} {
				t.Run("environment="+environment+"/source="+source+"/api="+api, func(t *testing.T) {
					prepareEndpointLocationWorkspace(t, environment, "")
					injectEndpointForTest(t, source, &resources.EndpointAccess{
						Endpoint:        &basev0.Endpoint{Module: "platform", Service: "location-records", Name: "rest", Api: "rest"},
						NetworkInstance: &basev0.NetworkInstance{Address: "not-an-address"},
					})
					query := codefly.For(context.Background()).Module("platform").Service("location-records").Endpoint("rest").API(api)
					t.Run("ResolveNetworkInstance", func(t *testing.T) {
						instance, err := query.ResolveNetworkInstance()
						require.Error(t, err)
						require.Nil(t, instance)
					})
					t.Run("NetworkInstance", func(t *testing.T) { require.Nil(t, query.NetworkInstance()) })
				})
			}
		}
	}
}

func TestInjectedParseFailureNeverReturnsPartialInstance(t *testing.T) {
	prepareEndpointLocationWorkspace(t, "local", "")
	// Core returns a partial instance alongside this parse error; the SDK must
	// discard it so neither public entrypoint can return that address.
	partial, parseErr := resources.ParseAddress("localhost:not-a-port")
	require.Error(t, parseErr)
	require.NotNil(t, partial)
	injectEndpointForTest(t, "embedded", &resources.EndpointAccess{
		Endpoint:        &basev0.Endpoint{Module: "platform", Service: "location-records", Name: "rest", Api: "rest"},
		NetworkInstance: &basev0.NetworkInstance{Address: "localhost:not-a-port"},
	})
	query := codefly.For(context.Background()).Module("platform").Service("location-records").Endpoint("rest")
	instance, err := query.ResolveNetworkInstance()
	require.Error(t, err)
	require.Nil(t, instance)
	require.Nil(t, query.NetworkInstance())
}

func TestPresentEmptyEndpointCarrierIsNotAbsence(t *testing.T) {
	prepareEndpointLocationWorkspace(t, "local", "")
	key := resources.EndpointAsEnvironmentVariableKey(&resources.EndpointInformation{
		Module: "platform", Service: "location-records", Name: "rest", API: "rest",
	})
	t.Setenv(key, "")
	require.NoError(t, codefly.LoadEnvironmentVariables())
	query := codefly.For(context.Background()).Module("platform").Service("location-records").Endpoint("rest")
	instance, err := query.ResolveNetworkInstance()
	require.Error(t, err)
	require.Nil(t, instance)
	require.Nil(t, query.NetworkInstance())
}
