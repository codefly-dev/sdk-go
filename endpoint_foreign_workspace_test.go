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
// workspace is not the process's composition: the runtime names the
// composition (CODEFLY__WORKSPACE), and the producer's workspace declares
// another name. The process is answered from the carriers the composition's
// CLI injected, exactly as a process with no workspace is.

// composition is the name the runtime injects, as platform-core's run does.
const composition = "platform-core"

type foreignLayout struct {
	name string
	// layout writes the producer's tree and returns the directory the process
	// runs in.
	layout func(t *testing.T) string
	// premise holds what makes the layout a case worth testing: what trusting
	// the found workspace would do.
	premise func(t *testing.T)
	// identified lists the injected compositions the layout is answered from
	// carriers under. A layout listed only with an injected name is one that,
	// with nothing injected, is the only workspace there is (see
	// TestAProcessNoCompositionStartedUsesTheWorkspaceAsFound).
	identified []string
}

// premiseRefusesTheModule: the producer's workspace does not carry the
// composition's module name, so trusting it refuses every query (#66).
func premiseRefusesTheModule(t *testing.T) {
	t.Helper()
	workspace := foundWorkspace(t)
	_, err := workspace.LoadModuleFromName(context.Background(), carriedEndpoint.Module)
	require.ErrorContains(t, err, "cannot find module", "the producer's workspace must not carry the composition's module name")
}

// premiseCarriesTheModule: the producer's workspace names the module exactly as
// the composition does (robin, annotations, documents, model and runtime in
// platform-core), so trusting it selects against the producer's declarations
// and computes a native address from the producer's workspace name.
func premiseCarriesTheModule(t *testing.T) {
	t.Helper()
	workspace := foundWorkspace(t)
	_, carried := workspace.Member(carriedEndpoint.Module)
	require.True(t, carried, "the producer's workspace must carry the composition's module name")
	require.NotEqual(t, composition, workspace.Name)
}

// premiseCannotLoad: a solution's tag imports its platform by release, which
// only the CLI can resolve, so loading the workspace fails before any carrier
// is read.
func premiseCannotLoad(t *testing.T) {
	t.Helper()
	_, err := resources.FindWorkspaceUp(context.Background())
	require.ErrorContains(t, err, "requires host resolution")
}

func foundWorkspace(t *testing.T) *resources.Workspace {
	t.Helper()
	workspace, err := resources.FindWorkspaceUp(context.Background())
	require.NoError(t, err)
	require.NotNil(t, workspace, "the test needs the producer's workspace above the process")
	return workspace
}

var foreignLayouts = []foreignLayout{
	{"module checkout", func(t *testing.T) string {
		return writeRenamedProducer(t, t.TempDir())
	}, premiseRefusesTheModule, []string{composition, ""}},
	{"module cache tag", func(t *testing.T) string {
		return writeRenamedProducer(t, filepath.Join(t.TempDir(), "codefly-dev", "module-platform-starter", "v0.0.94"))
	}, premiseRefusesTheModule, []string{composition, ""}},
	{"same-name producer tag", func(t *testing.T) string {
		root := filepath.Join(t.TempDir(), "obin-ai", "module-platform", "v0.1.22")
		writeFile(t, filepath.Join(root, "workspace.codefly.yaml"),
			"name: platform-dev\nlayout: modules\nmodules:\n  - name: "+carriedEndpoint.Module+"\n")
		return writeProducerModule(t, filepath.Join(root, "modules", carriedEndpoint.Module), carriedEndpoint.Module)
	}, premiseCarriesTheModule, []string{composition}},
	{"solution tag importing its platform by release", func(t *testing.T) string {
		root := filepath.Join(t.TempDir(), "obin-ai", "core-solutions", "v0.0.17", "solutions", "proposals")
		writeFile(t, filepath.Join(root, "workspace.codefly.yaml"),
			"name: proposals\nlayout: modules\nworkspaces:\n  - name: platform-core\n    source: obin-ai/platform-core\n    version: \"0.0.3\"\nmodules:\n  - name: proposals\n    path: .\n")
		return writeProducerModule(t, root, "proposals")
	}, premiseCannotLoad, []string{"platform-obin"}},
}

// writeRenamedProducer lays out the workspace module-saas-starter ships, scaled
// down: it declares the module under the repository's own name, never the
// composition's.
func writeRenamedProducer(t *testing.T, root string) string {
	t.Helper()
	writeFile(t, filepath.Join(root, "workspace.codefly.yaml"),
		"name: platform-starter-dev\nlayout: modules\nmodules:\n  - name: platform-starter\n    path: module\n")
	return writeProducerModule(t, filepath.Join(root, "module"), "platform-starter")
}

// writeProducerModule writes a module declaring the carried service with a
// public rest endpoint, and returns the service's code directory.
func writeProducerModule(t *testing.T, dir, name string) string {
	t.Helper()
	writeFile(t, filepath.Join(dir, "module.codefly.yaml"),
		"kind: module\nname: "+name+"\nservices:\n  - name: "+carriedEndpoint.Service+"\n")
	service := filepath.Join(dir, "services", carriedEndpoint.Service)
	writeFile(t, filepath.Join(service, "service.codefly.yaml"),
		"kind: service\nname: "+carriedEndpoint.Service+"\nversion: 0.0.0\nendpoints:\n  - name: rest\n    api: rest\n    visibility: public\n    exposure: public\n")
	writeFile(t, filepath.Join(service, "configurations", "local", "api.env"), "URL=the-producers-own-value\n")
	writeFile(t, filepath.Join(service, "code", "main.go"), "package main\n")
	return filepath.Join(service, "code")
}

// prepareProcessUnderAForeignWorkspace boots the process as a workspace-free
// one in the composition the runtime names, then moves it under the producer's
// workspace, and holds the layout's premise.
func prepareProcessUnderAForeignWorkspace(t *testing.T, environment, injected string, layout foreignLayout) {
	t.Helper()
	prepareProcessWithoutWorkspace(t, environment)
	t.Setenv(resources.WorkspacePrefix, injected)
	t.Chdir(layout.layout(t))
	layout.premise(t)
}

func forEachForeignLayout(t *testing.T, run func(t *testing.T, injected string, layout foreignLayout)) {
	for _, layout := range foreignLayouts {
		for _, injected := range layout.identified {
			t.Run(layout.name+"/composition="+injected, func(t *testing.T) { run(t, injected, layout) })
		}
	}
}

func TestAComposedModuleUnderItsOwnWorkspaceResolvesItsCarrier(t *testing.T) {
	forEachForeignLayout(t, func(t *testing.T, injected string, layout foreignLayout) {
		for _, environment := range []string{"local", "", "production"} {
			for _, source := range []string{"runtime", "embedded"} {
				for _, form := range referenceForms {
					t.Run("environment="+environment+"/source="+source+"/"+form.name, func(t *testing.T) {
						prepareProcessUnderAForeignWorkspace(t, environment, injected, layout)
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
	})
}

// Neither the composition's workspace nor a carrier: the typed refusal, never
// the producer workspace's declarations, its load failure, or a native address
// computed from its name — even in local, where the composition's own
// workspace would fall back.
func TestAComposedModuleUnderItsOwnWorkspaceRefusesAnAbsentCarrier(t *testing.T) {
	forEachForeignLayout(t, func(t *testing.T, injected string, layout foreignLayout) {
		for _, environment := range []string{"local", "", "production"} {
			for _, form := range referenceForms {
				t.Run("environment="+environment+"/"+form.name, func(t *testing.T) {
					prepareProcessUnderAForeignWorkspace(t, environment, injected, layout)
					query := form.query(queryCarriedService())
					instance, err := query.ResolveNetworkInstance()
					require.ErrorIs(t, err, codefly.ErrEndpointCarrierAbsent)
					require.ErrorContains(t, err, "platform/location-records/rest")
					require.Nil(t, instance)
					require.Nil(t, query.NetworkInstance())
				})
			}
		}
	})
}

// A malformed carrier is refused as one, not hidden behind anything the
// producer's workspace would have said.
func TestAComposedModuleUnderItsOwnWorkspaceRefusesAMalformedCarrier(t *testing.T) {
	forEachForeignLayout(t, func(t *testing.T, injected string, layout foreignLayout) {
		prepareProcessUnderAForeignWorkspace(t, "local", injected, layout)
		injectEndpointForTest(t, "runtime", carrierFor("rest", "rest", "localhost:not-a-port"))
		instance, err := queryCarriedService().Endpoint("rest").API("rest").ResolveNetworkInstance()
		require.ErrorContains(t, err, "malformed address")
		require.NotErrorIs(t, err, codefly.ErrEndpointCarrierAbsent)
		require.Nil(t, instance)
	})
}

// The producer's local configuration files are the producer's: a composed
// module's process never reads them, even when the producer names the module
// as the composition does.
func TestAComposedModuleUnderItsOwnWorkspaceReadsNoProducerConfiguration(t *testing.T) {
	forEachForeignLayout(t, func(t *testing.T, injected string, layout foreignLayout) {
		prepareProcessUnderAForeignWorkspace(t, "local", injected, layout)
		value, err := queryCarriedService().Configuration("api", "url")
		require.Error(t, err)
		require.NotContains(t, err.Error(), "cannot find module", "absence, not the producer's module list")
		require.NotContains(t, err.Error(), "requires host resolution", "absence, not the producer's load failure")
		require.Empty(t, value)
	})
}

// With nothing injected, no composition started the process, and the workspace
// above it is the only one there is: a local tool under a same-name producer
// reads that producer's declarations, as it did before composition identity
// was consulted. This is the boundary F1's rule draws, held so a change to it
// is a decision rather than a drift.
func TestAProcessNoCompositionStartedUsesTheWorkspaceAsFound(t *testing.T) {
	layout := foreignLayouts[2]
	require.Equal(t, "same-name producer tag", layout.name)
	prepareProcessUnderAForeignWorkspace(t, "local", "", layout)
	instance, err := queryCarriedService().Endpoint("rest").API("rest").ResolveNetworkInstance()
	require.NoError(t, err, "selection and the native map answer from the workspace found")
	require.NotNil(t, instance)
	value, err := queryCarriedService().Configuration("api", "url")
	require.NoError(t, err)
	require.Equal(t, "the-producers-own-value", value)
}

// A workspace file that does not decode names nothing, so under an injected
// composition it does not count and the injected carrier answers. When nothing
// was injected for the query either, that file may have been the composition's
// own, and the refusal carries its decode error rather than dropping it. With
// no composition injected, the decode error is the answer, as it always was.
func TestAnUndecodableWorkspaceFileIsReportedNotTrusted(t *testing.T) {
	const yamlError = "did not find expected node content"
	prepare := func(t *testing.T, injected string) {
		t.Helper()
		prepareProcessWithoutWorkspace(t, "local")
		t.Setenv(resources.WorkspacePrefix, injected)
		root := t.TempDir()
		writeFile(t, filepath.Join(root, "workspace.codefly.yaml"), "name: "+composition+"\nmodules: [\n")
		t.Chdir(root)
	}
	query := func() *codefly.Query { return queryCarriedService().Endpoint("rest").API("rest") }

	t.Run("injected, carrier present", func(t *testing.T) {
		prepare(t, composition)
		injectEndpointForTest(t, "runtime", carrierFor("rest", "rest", "http://localhost:24601"))
		instance, err := query().ResolveNetworkInstance()
		require.NoError(t, err, "an unreadable file is not loaded, so it cannot stop the carrier")
		require.Equal(t, "http://localhost:24601", instance.Address)
	})
	t.Run("injected, carrier absent", func(t *testing.T) {
		prepare(t, composition)
		instance, err := query().ResolveNetworkInstance()
		require.ErrorIs(t, err, codefly.ErrEndpointCarrierAbsent)
		require.ErrorContains(t, err, "could not be read")
		require.ErrorContains(t, err, yamlError)
		require.Nil(t, instance)
		_, err = queryCarriedService().Configuration("api", "url")
		require.ErrorContains(t, err, yamlError, "the configuration fallback says why too")
	})
	t.Run("nothing injected", func(t *testing.T) {
		prepare(t, "")
		instance, err := query().ResolveNetworkInstance()
		require.ErrorContains(t, err, yamlError)
		require.NotErrorIs(t, err, codefly.ErrEndpointCarrierAbsent)
		require.Nil(t, instance)
	})
}
