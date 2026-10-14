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
	presence, err := solutionhost.FixtureDocument(solutionhost.DocumentTypePresence, "valid")
	require.NoError(t, err)
	applied, err := solutionhost.Parse(presence)
	require.NoError(t, err)
	endpoint := applied.Endpoints[0]
	key := resources.EndpointAsEnvironmentVariableKey(&resources.EndpointInformation{
		Module: endpoint.Module, Service: endpoint.Service, Name: endpoint.Name, API: endpoint.API,
	})
	// A boot carrier for the same endpoint, and a projection file in a delivery
	// directory the environment names: neither may ever answer this query.
	t.Setenv(key, "http://stale.example:9000")
	directory := t.TempDir()
	t.Setenv(resources.EndpointDeliveryDirectoryKey, directory)
	require.NoError(t, codefly.LoadEnvironmentVariables())
	query := codefly.For(t.Context()).Module(endpoint.Module).Service(endpoint.Service).Endpoint(endpoint.Name).API(endpoint.API)
	deliver := func(document *solutionhost.SolutionHostBinding, carriers map[string]string) []byte {
		t.Helper()
		data, err := solutionhost.MarshalEndpointDelivery(document, carriers)
		require.NoError(t, err)
		return data
	}
	filename, err := solutionhost.EndpointDeliveryFilename(applied)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(directory, filename),
		deliver(applied, map[string]string{key: "http://mounted.example:7000"}), 0o600))

	_, err = query.ResolveDeliveredNetworkInstance(applied, nil)
	require.ErrorIs(t, err, codefly.ErrEndpointDeliveryUnavailable,
		"no value: neither the boot carrier nor a file in the named directory may answer")
	first, err := query.ResolveDeliveredNetworkInstance(applied, deliver(applied, map[string]string{key: "http://first.example:8080"}))
	require.NoError(t, err)
	require.Contains(t, first.Address, "first.example")

	next := *applied
	next.Generation++
	newer := deliver(&next, map[string]string{key: "http://second.example:8081"})
	_, err = query.ResolveDeliveredNetworkInstance(applied, newer)
	require.ErrorIs(t, err, codefly.ErrEndpointDeliveryUnavailable, "new delivery cannot serve old applied authority")
	_, err = query.ResolveDeliveredNetworkInstance(&next, deliver(applied, map[string]string{key: "http://first.example:8080"}))
	require.ErrorIs(t, err, codefly.ErrEndpointDeliveryUnavailable, "old delivery cannot serve the new applied authority")
	second, err := query.ResolveDeliveredNetworkInstance(&next, newer)
	require.NoError(t, err)
	require.Contains(t, second.Address, "second.example")

	_, err = query.ResolveDeliveredNetworkInstance(&next, deliver(&next, nil))
	require.ErrorIs(t, err, codefly.ErrEndpointDeliveryUnavailable, "a delivery without this endpoint cannot fall back to the boot carrier")
	_, err = query.ResolveDeliveredNetworkInstance(&next, []byte{})
	require.ErrorIs(t, err, codefly.ErrEndpointDeliveryUnavailable, "withdrawal cannot resurrect the boot carrier")
	_, err = query.ResolveDeliveredNetworkInstance(&next, []byte("not a projection"))
	require.ErrorIs(t, err, codefly.ErrEndpointDeliveryUnavailable)
	_, err = query.ResolveDeliveredNetworkInstance(nil, newer)
	require.ErrorIs(t, err, codefly.ErrEndpointDeliveryUnavailable, "no applied document, no route")
	oversized := make([]byte, solutionhost.EndpointDeliveryMaxBytes+1)
	_, err = query.ResolveDeliveredNetworkInstance(&next, oversized)
	require.ErrorIs(t, err, codefly.ErrEndpointDeliveryUnavailable, "over the bound is refused before decoding")
}
