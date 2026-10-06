package codefly_test

import (
	"context"
	"os"
	"strings"

	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
	"path/filepath"
	"testing"

	"github.com/codefly-dev/core/resources"
	codefly "github.com/codefly-dev/sdk-go"
	"github.com/stretchr/testify/require"
)

func TestLocalEndpointSelectionUsesConsumerBoundary(t *testing.T) {
	for _, tc := range []struct {
		name, consumer, declaration, moduleInterface string
		refusal                                      error
	}{
		{name: "private foreign consumer", consumer: "client", declaration: "visibility: private", refusal: resources.ErrEndpointNotReachable},
		{name: "unidentified", declaration: "visibility: public", refusal: resources.ErrConsumerNotIdentified},
		{name: "whitespace consumer", consumer: " ", declaration: "visibility: public", refusal: resources.ErrConsumerNotIdentified},
		{name: "private same module", consumer: "producer", declaration: "visibility: private"},
		{name: "internal unlisted", consumer: "client", declaration: "visibility: internal\n    allow-modules: [other]", refusal: resources.ErrEndpointNotReachable},
		{name: "internal listed", consumer: "client", declaration: "visibility: internal\n    allow-modules: [client]"},
		{name: "module hides public", consumer: "client", declaration: "visibility: public", moduleInterface: "interface:\n  endpoints:\n    - service: records\n      endpoint: health\n      visibility: public\n", refusal: resources.ErrEndpointNotReachable},
		{name: "module exports private", consumer: "client", declaration: "visibility: private", moduleInterface: "interface:\n  endpoints:\n    - service: records\n      endpoint: rest\n      visibility: internal\n      allow-modules: [client]\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			prepareEndpointSelectionWorkspace(t, tc.consumer, tc.declaration, tc.moduleInterface)
			instance, err := codefly.For(context.Background()).Module("producer").Service("records").Endpoint("rest").API("rest").ResolveNetworkInstance()
			if tc.refusal != nil {
				require.ErrorIs(t, err, tc.refusal)
				require.Nil(t, instance)
			} else {
				require.NoError(t, err)
				require.NotNil(t, instance)
			}
		})
	}
}

func prepareEndpointSelectionWorkspace(t *testing.T, consumer, declaration, moduleInterface string) {
	t.Helper()
	t.Cleanup(func() { require.NoError(t, codefly.LoadEnvironmentVariables()) })
	t.Setenv(resources.ModulePrefix, consumer)
	t.Setenv("CODEFLY__ENVIRONMENT", "local")
	require.NoError(t, codefly.LoadEnvironmentVariables())
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "workspace.codefly.yaml"), "name: selection-test\nlayout: modules\nmodules:\n  - name: producer\n")
	writeFile(t, filepath.Join(root, "modules", "producer", "module.codefly.yaml"), "kind: module\nname: producer\nservices:\n  - name: records\n"+moduleInterface)
	writeFile(t, filepath.Join(root, "modules", "producer", "services", "records", "service.codefly.yaml"), `kind: service
name: records
version: 0.0.0
agent:
  kind: codefly:service
  name: rust
  version: 0.0.20
  publisher: codefly.dev
endpoints:
  - name: rest
    `+declaration+"\n  - name: health\n    api: rest\n    visibility: public\n")
	t.Chdir(root)
}

func TestDefaultNetworkCannotBypassEndpointRefusals(t *testing.T) {
	for _, tc := range []struct {
		name, declaration string
		refusal           error
	}{
		{name: "external", declaration: "visibility: public\n    location: external"},
		{name: "invalid visibility", declaration: "visibility: external", refusal: resources.ErrInvalidEndpointDeclaration},
		{name: "private", declaration: "visibility: private", refusal: resources.ErrEndpointNotReachable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			prepareEndpointSelectionWorkspace(t, "client", tc.declaration, "")
			query := codefly.For(context.Background()).Module("producer").Service("records").Endpoint("rest").API("rest").WithDefaultNetwork()
			t.Run("ResolveNetworkInstance", func(t *testing.T) {
				instance, err := query.ResolveNetworkInstance()
				if tc.refusal != nil {
					require.ErrorIs(t, err, tc.refusal)
				} else {
					require.ErrorContains(t, err, "external endpoint cannot be resolved from the local native map")
				}
				require.Nil(t, instance)
			})
			t.Run("NetworkInstance", func(t *testing.T) {
				require.Nil(t, query.NetworkInstance(), "the convenience entrypoint must also refuse")
			})
		})
	}
}

func TestEndpointOnlySelectionRefusesAmbiguityBeforeInjection(t *testing.T) {
	prepareEndpointSelectionWorkspace(t, "client", "api: rest\n    visibility: public", "")
	path := filepath.Join("modules", "producer", "services", "records", "service.codefly.yaml")
	declaration, err := os.ReadFile(path)
	require.NoError(t, err)
	writeFile(t, path, strings.Replace(string(declaration), "name: rest", "name: primary", 1))
	require.NoError(t, codefly.InjectEndpoints(&resources.EndpointAccess{
		Endpoint:        &basev0.Endpoint{Module: "producer", Service: "records", Name: "primary", Api: "rest"},
		NetworkInstance: &basev0.NetworkInstance{Address: "https://upstream.example:9443"},
	}))
	t.Cleanup(func() { require.NoError(t, codefly.InjectEndpoints()) })
	instance, err := codefly.For(context.Background()).Module("producer").Service("records").Endpoint("rest").ResolveNetworkInstance()
	require.ErrorIs(t, err, resources.ErrAmbiguousEndpointReference)
	require.Nil(t, instance)
}

func TestEndpointOnlySelectionUsesDeclaredAPI(t *testing.T) {
	prepareEndpointSelectionWorkspace(t, "client", "visibility: public", "")
	// health serves REST; its name is not its protocol. Exact name takes precedence
	// over its REST sibling, and the selected declaration supplies the carrier API.
	require.NoError(t, codefly.InjectEndpoints(&resources.EndpointAccess{
		Endpoint:        &basev0.Endpoint{Module: "producer", Service: "records", Name: "health", Api: "rest"},
		NetworkInstance: &basev0.NetworkInstance{Address: "https://health.example:9443"},
	}))
	t.Cleanup(func() { require.NoError(t, codefly.InjectEndpoints()) })
	instance, err := codefly.For(context.Background()).Module("producer").Service("records").Endpoint("health").ResolveNetworkInstance()
	require.NoError(t, err)
	require.Equal(t, "https://health.example:9443", instance.Address)
}
