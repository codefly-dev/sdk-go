package codefly_test

import (
	"errors"
	"os"
	"testing"

	codefly "github.com/codefly-dev/sdk-go"
	"github.com/stretchr/testify/require"
)

// The advertised address is its own carrier: a rendered cell localizes a
// service's own endpoint carrier to the address it binds, so reading that one
// would tell a peer to dial its own loopback.
func TestTheAdvertisedAddressIsItsOwnCarrier(t *testing.T) {
	t.Setenv("CODEFLY__MODULE", "widgets")
	t.Setenv("CODEFLY__SERVICE", "api")
	t.Setenv("CODEFLY__ENDPOINT__WIDGETS__API__INGRESS__HTTP", "http://localhost:8443")
	t.Setenv("CODEFLY__SELF_ENDPOINT__WIDGETS__API__INGRESS__HTTP", "http://api.widgets.svc:8443")
	require.NoError(t, codefly.LoadEnvironmentVariables())

	instance, err := codefly.For(t.Context()).Endpoint("ingress").API("http").AdvertisedNetworkInstance()
	require.NoError(t, err)
	require.Equal(t, "api.widgets.svc", instance.Hostname)
	require.Equal(t, uint16(8443), uint16(instance.Port))
	require.Equal(t, "widgets", codefly.Module())

	require.NoError(t, os.Unsetenv("CODEFLY__SELF_ENDPOINT__WIDGETS__API__INGRESS__HTTP"))
	require.NoError(t, codefly.LoadEnvironmentVariables())
	_, err = codefly.For(t.Context()).Endpoint("ingress").API("http").AdvertisedNetworkInstance()
	require.True(t, errors.Is(err, codefly.ErrEndpointCarrierAbsent), "absence is reported as absence: %v", err)

	t.Setenv("CODEFLY__SELF_ENDPOINT__WIDGETS__API__INGRESS__HTTP", "not an address")
	require.NoError(t, codefly.LoadEnvironmentVariables())
	_, err = codefly.For(t.Context()).Endpoint("ingress").API("http").AdvertisedNetworkInstance()
	require.Error(t, err)
	require.False(t, errors.Is(err, codefly.ErrEndpointCarrierAbsent), "a malformed carrier is never absence")

	_, err = codefly.For(t.Context()).Endpoint("ingress").AdvertisedNetworkInstance()
	require.Error(t, err, "an advertised endpoint is named by its endpoint and its API")
}
