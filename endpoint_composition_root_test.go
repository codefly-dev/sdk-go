package codefly_test

import (
	"context"
	"fmt"
	"path/filepath"
	"testing"

	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
	"github.com/codefly-dev/core/network"
	"github.com/codefly-dev/core/resources"
	codefly "github.com/codefly-dev/sdk-go"
	"github.com/stretchr/testify/require"
)

// A composition root carries modules it does not author: a platform it imports
// through `workspaces:` and a solution it adds through `solutions:`. That root
// IS the process's composition — the runtime names it — so selection judges
// every query against it first, and the native map is computed from its name.
// This is the platform-obin topology: platform-core imported, core-solutions'
// solutions added.

const compositionRoot = "platform-obin"

const rootServiceDeclaration = `kind: service
name: %s
version: 0.0.0
agent:
  kind: codefly:service
  name: go-grpc
  version: 0.0.1
  publisher: codefly.dev
endpoints:
  - name: rest
    api: rest
    visibility: private
  - name: health
    api: rest
    visibility: public
    exposure: none
`

func writeRootModule(t *testing.T, dir, module, service string) {
	t.Helper()
	writeFile(t, filepath.Join(dir, "module.codefly.yaml"), "kind: module\nname: "+module+"\nservices:\n  - name: "+service+"\n")
	writeFile(t, filepath.Join(dir, "services", service, "service.codefly.yaml"),
		fmt.Sprintf(rootServiceDeclaration, service))
}

// prepareCompositionRoot lays out platform-obin importing platform-core by path
// (which carries `producer`) and adding the solution `wiki`, and runs the
// consumer `client` at its root in local, with the given injected composition.
func prepareCompositionRoot(t *testing.T, injected string) {
	t.Helper()
	initEndpointConsumer(t, "client")
	t.Setenv("CODEFLY__ENVIRONMENT", "local")
	t.Setenv(resources.WorkspacePrefix, injected)
	require.NoError(t, codefly.LoadEnvironmentVariables())
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "workspace.codefly.yaml"),
		"name: "+compositionRoot+"\nlayout: modules\nworkspaces:\n  - name: platform-core\n    path: platform-core\nsolutions:\n  - name: wiki\n")
	writeFile(t, filepath.Join(root, "platform-core", "workspace.codefly.yaml"),
		"name: platform-core\nlayout: modules\nmodules:\n  - name: producer\n")
	writeRootModule(t, filepath.Join(root, "platform-core", "modules", "producer"), "producer", "records")
	writeRootModule(t, filepath.Join(root, "modules", "wiki"), "wiki", "backend")
	t.Chdir(root)
	workspace, err := resources.FindWorkspaceUp(context.Background())
	require.NoError(t, err)
	producer, carried := workspace.Member("producer")
	require.True(t, carried)
	require.Equal(t, "platform-core", producer.Workspace, "producer is carried through the import, not authored by the root")
	wiki, carried := workspace.Member("wiki")
	require.True(t, carried)
	require.Equal(t, resources.MemberRoleSolution, wiki.Role, "wiki is carried as a solution")
}

func TestACompositionRootSelectsModulesItComposes(t *testing.T) {
	for _, injected := range []string{compositionRoot, ""} {
		for _, carried := range []struct{ module, service string }{
			{"producer", "records"}, // through `workspaces:`
			{"wiki", "backend"},     // through `solutions:`
		} {
			t.Run("composition="+injected+"/"+carried.module, func(t *testing.T) {
				prepareCompositionRoot(t, injected)
				// A carrier is present: only selection can refuse the query, so a
				// refusal proves the root's declarations were judged first.
				injectEndpointForTest(t, "runtime", &resources.EndpointAccess{
					Endpoint:        &basev0.Endpoint{Module: carried.module, Service: carried.service, Name: "rest", Api: "rest"},
					NetworkInstance: &basev0.NetworkInstance{Address: "http://localhost:24601"},
				})
				instance, err := codefly.For(context.Background()).Module(carried.module).Service(carried.service).
					Endpoint("rest").API("rest").ResolveNetworkInstance()
				require.ErrorIs(t, err, resources.ErrEndpointNotReachable)
				require.Nil(t, instance)
			})
		}
	}
}

// In local with no carrier, the native address is the composition's: computed
// from the root's name, not from the imported workspace that authored the
// module.
func TestACompositionRootComputesTheNativeAddressUnderItsOwnName(t *testing.T) {
	prepareCompositionRoot(t, compositionRoot)
	ctx := context.Background()
	instance, err := codefly.For(ctx).Module("producer").Service("records").Endpoint("health").API("rest").ResolveNetworkInstance()
	require.NoError(t, err)
	require.NotNil(t, instance)
	expected := network.NativeFor(ctx, compositionRoot, "producer", "records", "", &basev0.Endpoint{Name: "health", Api: "rest"})
	require.Equal(t, expected.Address, instance.Address)
	require.NotEqual(t, network.NativeFor(ctx, "platform-core", "producer", "records", "", &basev0.Endpoint{Name: "health", Api: "rest"}).Address,
		instance.Address, "the premise: the imported workspace's name derives another address")
}

// A module the composition does not carry — a typo at the root — is refused,
// and the refusal still says which modules the root does carry.
func TestACompositionRootNamesWhatItCarriesWhenAModuleIsUnknown(t *testing.T) {
	for _, injected := range []string{compositionRoot, ""} {
		t.Run("composition="+injected, func(t *testing.T) {
			prepareCompositionRoot(t, injected)
			instance, err := codefly.For(context.Background()).Module("prodcuer").Service("records").
				Endpoint("rest").API("rest").ResolveNetworkInstance()
			require.ErrorIs(t, err, codefly.ErrEndpointCarrierAbsent)
			require.ErrorContains(t, err, "does not compose module <prodcuer>")
			require.ErrorContains(t, err, "present: [")
			require.ErrorContains(t, err, "producer")
			require.ErrorContains(t, err, "wiki")
			require.Nil(t, instance)
		})
	}
}

// The injected name is compared as written. A workspace whose name differs from
// it only in case is another workspace: it is not judged, and the injected
// carrier answers, where the composition's own declarations would refuse.
func TestACompositionRootCountsOnlyUnderTheExactInjectedName(t *testing.T) {
	prepareCompositionRoot(t, "PLATFORM-OBIN")
	injectEndpointForTest(t, "runtime", &resources.EndpointAccess{
		Endpoint:        &basev0.Endpoint{Module: "producer", Service: "records", Name: "rest", Api: "rest"},
		NetworkInstance: &basev0.NetworkInstance{Address: "http://localhost:24601"},
	})
	instance, err := codefly.For(context.Background()).Module("producer").Service("records").
		Endpoint("rest").API("rest").ResolveNetworkInstance()
	require.NoError(t, err, "a case-folded match would have judged the private endpoint and refused it")
	require.Equal(t, "http://localhost:24601", instance.Address)
}
