package codefly_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/codefly-dev/core/resources"
	"github.com/codefly-dev/core/solutionhost"
	codefly "github.com/codefly-dev/sdk-go"
	"github.com/stretchr/testify/require"
)

func TestDeliveredEndpointsChangeWithoutReloadAndNeverResurrectBootCarriers(t *testing.T) {
	initEndpointConsumer(t, "platform")
	dir := t.TempDir()
	t.Setenv(resources.EndpointDeliveryDirectoryKey, dir)
	raw, err := solutionhost.FixtureDocument(solutionhost.DocumentTypePresence, "valid")
	require.NoError(t, err)
	applied, err := solutionhost.Parse(raw)
	require.NoError(t, err)
	endpoint := applied.Endpoints[0]
	key := resources.EndpointAsEnvironmentVariableKey(&resources.EndpointInformation{
		Module: endpoint.Module, Service: endpoint.Service, Name: endpoint.Name, API: endpoint.API,
	})
	t.Setenv(key, "http://stale.example:9000")
	require.NoError(t, codefly.LoadEnvironmentVariables())
	query := codefly.For(t.Context()).Module(endpoint.Module).Service(endpoint.Service).Endpoint(endpoint.Name).API(endpoint.API)
	filename, err := solutionhost.EndpointDeliveryFilename(applied)
	require.NoError(t, err)
	path := filepath.Join(dir, filename)
	write := func(document *solutionhost.SolutionHostBinding, carriers map[string]string) {
		t.Helper()
		data, err := solutionhost.MarshalEndpointDelivery(document, carriers)
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(path+".tmp", data, 0o600))
		require.NoError(t, os.Rename(path+".tmp", path))
	}
	_, err = query.ResolveDeliveredNetworkInstance(applied)
	require.ErrorIs(t, err, codefly.ErrEndpointDeliveryUnavailable)
	write(applied, map[string]string{key: "http://first.example:8080"})
	first, err := query.ResolveDeliveredNetworkInstance(applied)
	require.NoError(t, err)
	require.Contains(t, first.Address, "first.example")
	next := *applied
	next.Generation++
	write(&next, map[string]string{key: "http://second.example:8081"})
	_, err = query.ResolveDeliveredNetworkInstance(applied)
	require.ErrorIs(t, err, codefly.ErrEndpointDeliveryUnavailable, "new delivery cannot serve old applied authority")
	second, err := query.ResolveDeliveredNetworkInstance(&next)
	require.NoError(t, err)
	require.Contains(t, second.Address, "second.example")
	write(&next, nil)
	_, err = query.ResolveDeliveredNetworkInstance(&next)
	require.ErrorIs(t, err, codefly.ErrEndpointDeliveryUnavailable, "empty projection cannot fall back to the boot carrier")
	require.NoError(t, os.Remove(path))
	_, err = query.ResolveDeliveredNetworkInstance(&next)
	require.ErrorIs(t, err, codefly.ErrEndpointDeliveryUnavailable, "withdrawal cannot resurrect the boot carrier")
	require.NoError(t, os.WriteFile(path, []byte("not a projection"), 0o600))
	_, err = query.ResolveDeliveredNetworkInstance(&next)
	require.ErrorIs(t, err, codefly.ErrEndpointDeliveryUnavailable)
}
