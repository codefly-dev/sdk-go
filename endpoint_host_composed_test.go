package codefly_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/codefly-dev/core/resources"
	codefly "github.com/codefly-dev/sdk-go"
	"github.com/stretchr/testify/require"
)

// A solution run natively from its own root is its own composition, and its
// workspace imports the platform by release:
//
//	workspaces:
//	  - name: platform-core
//	    source: example-org/platform-core
//	    version: "0.0.10"
//
// Only the CLI can compose that: it acquires the release and registers core's
// WorkspaceResolver, and this SDK acquires nothing. The run injects the
// composition's name (CODEFLY__WORKSPACE) and a carrier for every endpoint it
// grants, the process's own included. Resolving the own endpoint used to load
// that workspace, fail at the import ("requires host resolution") and return
// the failure; NetworkInstance() hid it as nil, and the runtime refused to
// start for want of its own port while the carrier sat in its environment.
//
// The composition's own workspace that only the host can compose is not
// loaded. The composition's carriers answer, as they do for a process with no
// workspace, and an absent carrier says why no declaration was judged here.
func writeSolutionImportingItsPlatformByRelease(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "workspace.codefly.yaml"),
		"name: lastlogin-go\nlayout: modules\nworkspaces:\n  - name: platform-core\n    source: example-org/platform-core\n    version: \"0.0.10\"\nmodules:\n  - name: lastlogin-go\n    path: .\n")
	writeFile(t, filepath.Join(root, "module.codefly.yaml"),
		"kind: module\nname: lastlogin-go\nservice-entry: backend\nservices:\n  - name: backend\n")
	backend := filepath.Join(root, "services", "backend")
	writeFile(t, filepath.Join(backend, "service.codefly.yaml"),
		"kind: service\nmodule-identity: true\nname: backend\nversion: 0.0.1\nendpoints:\n  - name: http\n    visibility: public\n    exposure: none\n    api: http\n")
	return backend
}

var ownEndpoint = resources.EndpointInformation{Module: "lastlogin-go", Service: "backend", Name: "http", API: "http"}

// prepareOwnSolutionProcess boots the process as the solution's own backend,
// in the given composition and environment, from the service's directory under
// the solution root, and holds the premise: composing that workspace here fails
// at the import.
func prepareOwnSolutionProcess(t *testing.T, injected, environment string) {
	t.Helper()
	initEndpointConsumer(t, ownEndpoint.Module)
	t.Setenv(resources.ServicePrefix, ownEndpoint.Service)
	t.Setenv("CODEFLY__ENVIRONMENT", environment)
	t.Setenv(resources.WorkspacePrefix, injected)
	key := resources.EndpointAsEnvironmentVariableKey(&ownEndpoint)
	t.Setenv(key, "") // register cleanup before removing the carrier entirely
	require.NoError(t, os.Unsetenv(key))
	require.NoError(t, codefly.LoadEnvironmentVariables())
	t.Chdir(writeSolutionImportingItsPlatformByRelease(t))
	_, err := resources.FindWorkspaceUp(context.Background())
	require.ErrorContains(t, err, "requires host resolution", "the premise: only the host can compose this workspace")
}

func forEachOwnSolutionRun(t *testing.T, run func(t *testing.T, injected, environment string)) {
	// The runtime injects the composition's name; a local tool injects nothing.
	for _, injected := range []string{ownEndpoint.Module, ""} {
		for _, environment := range []string{"local", ""} {
			t.Run("composition="+injected+"/environment="+environment, func(t *testing.T) { run(t, injected, environment) })
		}
	}
}

func TestASolutionsOwnWorkspaceOnlyTheHostCanComposeAnswersFromTheRunsCarriers(t *testing.T) {
	forEachOwnSolutionRun(t, func(t *testing.T, injected, environment string) {
		prepareOwnSolutionProcess(t, injected, environment)
		t.Setenv(resources.EndpointAsEnvironmentVariableKey(&ownEndpoint), "http://localhost:52382")
		require.NoError(t, codefly.LoadEnvironmentVariables())

		// The runtime's own query: module and service from the identity, the endpoint by name.
		instance, err := codefly.For(context.Background()).Endpoint("http").ResolveNetworkInstance()
		require.NoError(t, err, "the run's carrier answers; the import it never needed does not refuse it")
		require.Equal(t, "http://localhost:52382", instance.Address)
		require.Equal(t, uint16(52382), instance.Port)
		require.NotNil(t, codefly.For(context.Background()).Endpoint("http").NetworkInstance())

		// And the fully qualified spelling.
		instance, err = codefly.For(context.Background()).Module(ownEndpoint.Module).Service(ownEndpoint.Service).Endpoint("http").API("http").ResolveNetworkInstance()
		require.NoError(t, err)
		require.Equal(t, "http://localhost:52382", instance.Address)
	})
}

// No carrier, no declaration judged here, and no native address computed from
// a workspace that was not composed — the typed refusal, naming the import
// that kept this SDK from composing it.
func TestASolutionsOwnWorkspaceOnlyTheHostCanComposeRefusesAnAbsentCarrierSayingWhy(t *testing.T) {
	forEachOwnSolutionRun(t, func(t *testing.T, injected, environment string) {
		prepareOwnSolutionProcess(t, injected, environment)
		instance, err := codefly.For(context.Background()).Endpoint("http").ResolveNetworkInstance()
		require.ErrorIs(t, err, codefly.ErrEndpointCarrierAbsent)
		require.ErrorContains(t, err, "only the host can compose")
		require.ErrorContains(t, err, "platform-core")
		require.Nil(t, instance)
		require.Nil(t, codefly.For(context.Background()).Endpoint("http").NetworkInstance())
	})
}
