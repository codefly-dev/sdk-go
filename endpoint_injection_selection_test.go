package codefly_test

import (
	"context"
	"testing"

	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
	"github.com/codefly-dev/core/resources"
	codefly "github.com/codefly-dev/sdk-go"
	"github.com/stretchr/testify/require"
)

func TestInjectedEndpointMustPassCoreSelection(t *testing.T) {
	for _, tc := range []struct {
		name, declaration, api string
		refusal                error
	}{
		{"excluded consumer", "visibility: internal\n    allow-modules: [other]", "rest", resources.ErrEndpointNotReachable},
		{"API mismatch", "visibility: public", "grpc", resources.ErrEndpointAPIMismatch},
	} {
		for _, source := range []string{"runtime", "embedded"} {
			t.Run(tc.name+"/"+source, func(t *testing.T) {
				prepareEndpointSelectionWorkspace(t, "client", tc.declaration, "")
				injectEndpointForTest(t, source, &resources.EndpointAccess{
					Endpoint:        &basev0.Endpoint{Module: "producer", Service: "records", Name: "rest", Api: tc.api},
					NetworkInstance: &basev0.NetworkInstance{Address: "http://runtime.example:43210"},
				})
				query := codefly.For(context.Background()).Module("producer").Service("records").Endpoint("rest").API(tc.api)
				t.Run("ResolveNetworkInstance", func(t *testing.T) {
					instance, err := query.ResolveNetworkInstance()
					require.ErrorIs(t, err, tc.refusal)
					require.Nil(t, instance)
				})
				t.Run("NetworkInstance", func(t *testing.T) { require.Nil(t, query.NetworkInstance()) })
			})
		}
	}
}
