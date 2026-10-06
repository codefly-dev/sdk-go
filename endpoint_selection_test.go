package codefly_test

import (
	"context"
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
