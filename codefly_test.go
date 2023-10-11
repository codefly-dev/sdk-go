package codefly_test

import (
	codefly "github.com/codefly-dev/sdk-go"
	"github.com/stretchr/testify/assert"
	"os"
	"testing"
)

//	func TestEndpointParsing(t *testing.T) {
//		tcs := []struct {
//			name     string
//			endpoint string
//			host     string
//			port     string
//		}{
//			{name: "regular", endpoint: "CODEFLY_NETWORK_GUESTBOOK-GO_DEFAULT"},
//		}
//		for _, tc := range tcs {
//			t.Run(tc.name, func(t *testing.T) {
//				e := codefly.NetworkEndpoint{Value: tc.endpoint}
//				assert.Equal(t, tc.host, e.Host())
//			}
//		}
//	}

func TestFromEnv(t *testing.T) {
	err := os.Setenv("CODEFLY-NETWORK_GUESTBOOK-GO_DEFAULT", ":8080")
	codefly.Load()
	assert.NoError(t, err)
	assert.Equal(t, ":8080", codefly.Endpoint("guestbook-go.default").PortAddress())

	err = os.Setenv("CODEFLY-NETWORK_GUESTBOOK-GO_DEFAULT_WRITE", ":8080")
	codefly.Load()
	assert.NoError(t, err)
	assert.Equal(t, ":8080", codefly.Endpoint("guestbook-go.default::write").PortAddress())

	err = os.Setenv("CODEFLY-NETWORK_GUESTBOOK-GO_DEFAULT_WRITE", "service.namespace:8080")
	codefly.Load()
	assert.NoError(t, err)
	assert.Equal(t, "service.namespace:8080", codefly.Endpoint("guestbook-go.default::write").Host())
}
