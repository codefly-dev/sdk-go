package codefly_test

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/codefly-dev/core/resources"
	codefly "github.com/codefly-dev/sdk-go"
	"github.com/stretchr/testify/require"
)

// A composition names the modules it composes; the module's own repository
// names it too, and the two need not agree. platform-core composes
// module-saas-starter as `saas`, while the repository's workspace knows it as
// `saas-starter` in `saas-starter-dev`. A process run from that repository —
// its checkout, or a released tag resolved into the module cache, which ships
// the same workspace file — finds the producer's workspace above it. That
// workspace does not carry the module the composition queries, so it is not
// the process's composition and the process is answered from the carriers the
// composition's CLI injected, exactly as a process with no workspace is.

// producerWorkspace is the workspace module-saas-starter ships, scaled down: it
// declares the module under the repository's own name, never the composition's.
const producerWorkspace = "name: platform-starter-dev\nlayout: modules\nmodules:\n  - name: platform-starter\n"

// foreignWorkspaceLayouts are the two places a composed module's process runs
// from with the producer's workspace above it. Each returns the directory the
// process runs in.
var foreignWorkspaceLayouts = []struct {
	name   string
	layout func(t *testing.T) string
}{
	{"module checkout", func(t *testing.T) string {
		checkout := t.TempDir()
		writeProducerModule(t, checkout)
		return filepath.Join(checkout, "module", "services", carriedEndpoint.Service, "code")
	}},
	{"module cache tag", func(t *testing.T) string {
		tag := filepath.Join(t.TempDir(), "codefly-dev", "module-platform-starter", "v0.0.94")
		writeProducerModule(t, tag)
		return filepath.Join(tag, "module", "services", carriedEndpoint.Service, "code")
	}},
}

func writeProducerModule(t *testing.T, root string) {
	t.Helper()
	writeFile(t, filepath.Join(root, "workspace.codefly.yaml"), producerWorkspace)
	writeFile(t, filepath.Join(root, "module", "module.codefly.yaml"),
		"kind: module\nname: platform-starter\nservices:\n  - name: "+carriedEndpoint.Service+"\n")
	writeFile(t, filepath.Join(root, "module", "services", carriedEndpoint.Service, "service.codefly.yaml"),
		"kind: service\nname: "+carriedEndpoint.Service+"\nversion: 0.0.0\nendpoints:\n  - name: rest\n    api: rest\n    visibility: public\n")
	writeFile(t, filepath.Join(root, "module", "services", carriedEndpoint.Service, "code", "main.go"), "package main\n")
}

// prepareProcessUnderAForeignWorkspace boots the process as a workspace-free
// one, then moves it under the producer's workspace, and holds the premise: the
// workspace is found, and it would refuse the query by module name.
func prepareProcessUnderAForeignWorkspace(t *testing.T, environment string, layout func(*testing.T) string) {
	t.Helper()
	prepareProcessWithoutWorkspace(t, environment)
	t.Chdir(layout(t))
	workspace, err := resources.FindWorkspaceUp(context.Background())
	require.NoError(t, err)
	require.NotNil(t, workspace, "the test needs the producer's workspace above the process")
	_, err = workspace.LoadModuleFromName(context.Background(), carriedEndpoint.Module)
	require.ErrorContains(t, err, "cannot find module", "the producer's workspace must not carry the composition's module name")
}

func TestAComposedModuleUnderItsOwnWorkspaceResolvesItsCarrier(t *testing.T) {
	for _, layout := range foreignWorkspaceLayouts {
		for _, environment := range []string{"local", "", "production"} {
			for _, source := range []string{"runtime", "embedded"} {
				for _, form := range referenceForms {
					t.Run(layout.name+"/environment="+environment+"/source="+source+"/"+form.name, func(t *testing.T) {
						prepareProcessUnderAForeignWorkspace(t, environment, layout.layout)
						access := carrierFor("rest", "rest", "http://localhost:24601")
						injectEndpointForTest(t, source, access)
						query := form.query(queryCarriedService())
						instance, err := query.ResolveNetworkInstance()
						require.NoError(t, err)
						require.Equal(t, access.NetworkInstance.Address, instance.Address)
						require.Equal(t, uint16(24601), instance.Port)
						require.NotNil(t, query.NetworkInstance())
					})
				}
			}
		}
	}
}

// Neither the composition's workspace nor a carrier: the typed refusal, never
// the producer workspace's declarations and never a native address computed
// from it — even in local, where a carrying workspace would fall back.
func TestAComposedModuleUnderItsOwnWorkspaceRefusesAnAbsentCarrier(t *testing.T) {
	for _, layout := range foreignWorkspaceLayouts {
		for _, environment := range []string{"local", "", "production"} {
			for _, form := range referenceForms {
				t.Run(layout.name+"/environment="+environment+"/"+form.name, func(t *testing.T) {
					prepareProcessUnderAForeignWorkspace(t, environment, layout.layout)
					query := form.query(queryCarriedService())
					instance, err := query.ResolveNetworkInstance()
					require.ErrorIs(t, err, codefly.ErrEndpointCarrierAbsent)
					require.ErrorContains(t, err, "platform/location-records/rest")
					require.Nil(t, instance)
					require.Nil(t, query.NetworkInstance())
				})
			}
		}
	}
}

// A malformed carrier is refused as one, not hidden behind the producer
// workspace's "cannot find module".
func TestAComposedModuleUnderItsOwnWorkspaceRefusesAMalformedCarrier(t *testing.T) {
	for _, layout := range foreignWorkspaceLayouts {
		t.Run(layout.name, func(t *testing.T) {
			prepareProcessUnderAForeignWorkspace(t, "local", layout.layout)
			injectEndpointForTest(t, "runtime", carrierFor("rest", "rest", "localhost:not-a-port"))
			instance, err := queryCarriedService().Endpoint("rest").API("rest").ResolveNetworkInstance()
			require.ErrorContains(t, err, "malformed address")
			require.NotErrorIs(t, err, codefly.ErrEndpointCarrierAbsent)
			require.Nil(t, instance)
		})
	}
}
