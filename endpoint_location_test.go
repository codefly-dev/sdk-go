package codefly_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
	"github.com/codefly-dev/core/network"
	"github.com/codefly-dev/core/resources"
	codefly "github.com/codefly-dev/sdk-go"
	"github.com/stretchr/testify/require"
)

func TestExternalLocationRefusesLocalResolution(t *testing.T) {
	for _, environment := range []string{"", "local"} {
		t.Run("environment="+environment, func(t *testing.T) {
			prepareEndpointLocationWorkspace(t, environment, resources.LocationExternal)
			instance, err := codefly.For(context.Background()).
				Module("platform").Service("location-records").Endpoint("rest").
				ResolveNetworkInstance()
			require.ErrorContains(t, err, "external endpoint cannot be resolved from the local native map")
			require.Nil(t, instance)
		})
	}
}

func TestPublicEndpointResolvesLocally(t *testing.T) {
	for _, environment := range []string{"", "local"} {
		t.Run("environment="+environment, func(t *testing.T) {
			prepareEndpointLocationWorkspace(t, environment, "")
			ctx := context.Background()
			instance, err := codefly.For(ctx).
				Module("platform").Service("location-records").Endpoint("rest").
				ResolveNetworkInstance()
			require.NoError(t, err)
			require.NotNil(t, instance)
			expected := network.NativeFor(ctx, "sdk-location-test", "platform", "location-records", "",
				&basev0.Endpoint{Name: "rest", Api: "rest", Visibility: resources.VisibilityPublic})
			require.Equal(t, expected.Address, instance.Address)
			require.Equal(t, expected.Hostname, instance.Hostname)
			require.Equal(t, expected.Host, instance.Host)
			require.Equal(t, uint16(expected.Port), instance.Port)
		})
	}
}

func TestNonlocalMissingEndpointCarrierRefusesNativeFallback(t *testing.T) {
	for _, environment := range []string{"production", "staging"} {
		for _, api := range []string{"", "rest"} {
			t.Run("environment="+environment+"/api="+api, func(t *testing.T) {
				// Boot as client with a public, locally resolvable declaration.
				// The helper removes the canonical carrier (not an empty value),
				// reloads the snapshot, and registers environment/snapshot cleanup.
				prepareEndpointLocationWorkspace(t, environment, "")
				query := codefly.For(context.Background()).Module("platform").Service("location-records").Endpoint("rest")
				if api != "" {
					query = query.API(api)
				}
				t.Run("ResolveNetworkInstance", func(t *testing.T) {
					instance, err := query.ResolveNetworkInstance()
					require.Error(t, err)
					require.Nil(t, instance)
				})
				t.Run("NetworkInstance", func(t *testing.T) {
					require.Nil(t, query.NetworkInstance())
				})
			})
		}
	}
}

// Both endpoints are public: only their location decides local resolvability.
func prepareEndpointLocationWorkspace(t *testing.T, environment, location string) {
	t.Helper()
	initEndpointConsumer(t, "client")
	t.Cleanup(func() { require.NoError(t, codefly.LoadEnvironmentVariables()) })
	t.Setenv("CODEFLY__ENVIRONMENT", environment)
	key := resources.EndpointAsEnvironmentVariableKey(&resources.EndpointInformation{
		Module: "platform", Service: "location-records", Name: "rest", API: "rest",
	})
	t.Setenv(key, "") // register cleanup before removing the carrier entirely
	require.NoError(t, os.Unsetenv(key))
	require.NoError(t, codefly.LoadEnvironmentVariables())
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "workspace.codefly.yaml"), `name: sdk-location-test
layout: modules
modules:
  - name: platform
`)
	writeFile(t, filepath.Join(root, "modules", "platform", "module.codefly.yaml"), `kind: module
name: platform
services:
  - name: location-records
`)
	writeFile(t, filepath.Join(root, "modules", "platform", "services", "location-records", "service.codefly.yaml"), `kind: service
name: location-records
version: 0.0.0
agent:
  kind: codefly:service
  name: rust
  version: 0.0.20
  publisher: codefly.dev
endpoints:
  - name: rest
    visibility: public
    exposure: none
    location: "`+location+`"
`)
	t.Chdir(root)
}

func TestEndpointOnlyLookupUsesInjectedAddress(t *testing.T) {
	for _, location := range []string{"", resources.LocationExternal} {
		for _, environment := range []string{"", "local", "production"} {
			for _, source := range []string{"runtime", "embedded"} {
				t.Run("location="+location+"/environment="+environment+"/source="+source, func(t *testing.T) {
					prepareEndpointLocationWorkspace(t, environment, location)
					access := &resources.EndpointAccess{
						Endpoint:        &basev0.Endpoint{Module: "platform", Service: "location-records", Name: "rest", Api: "rest", Visibility: resources.VisibilityPublic, Location: location},
						NetworkInstance: &basev0.NetworkInstance{Address: "https://upstream.example:9443"},
					}
					injectEndpointForTest(t, source, access)
					instance, err := codefly.For(context.Background()).Module("platform").Service("location-records").Endpoint("rest").ResolveNetworkInstance()
					require.NoError(t, err)
					require.NotNil(t, instance)
					require.Equal(t, access.NetworkInstance.Address, instance.Address)
				})
			}
		}
	}
}

// Both choices exist: an injected runtime address and a resolvable native one.
// An explicit API also exercises the direct carrier lookup, before selection.
func TestInjectedAddressPrecedesLocalNativeAddress(t *testing.T) {
	for _, environment := range []string{"", "local"} {
		for _, source := range []string{"runtime", "embedded"} {
			t.Run("environment="+environment+"/source="+source, func(t *testing.T) {
				prepareEndpointLocationWorkspace(t, environment, "")
				access := &resources.EndpointAccess{
					Endpoint:        &basev0.Endpoint{Module: "platform", Service: "location-records", Name: "rest", Api: "rest", Visibility: resources.VisibilityPublic},
					NetworkInstance: &basev0.NetworkInstance{Address: "http://runtime.example:43210"},
				}
				injectEndpointForTest(t, source, access)
				instance, err := codefly.For(context.Background()).Module("platform").Service("location-records").Endpoint("rest").API("rest").ResolveNetworkInstance()
				require.NoError(t, err)
				require.NotNil(t, instance)
				require.Equal(t, access.NetworkInstance.Address, instance.Address)
			})
		}
	}
}

func injectEndpointForTest(t *testing.T, source string, access *resources.EndpointAccess) {
	t.Helper()
	if source == "embedded" {
		require.NoError(t, codefly.InjectEndpoints(access))
		t.Cleanup(func() { require.NoError(t, codefly.InjectEndpoints()) })
	} else {
		variable := resources.EndpointAsEnvironmentVariable(access)
		t.Setenv(variable.Key, variable.ValueAsString())
		require.NoError(t, codefly.LoadEnvironmentVariables())
	}
}
