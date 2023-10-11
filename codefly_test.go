package codefly_test

import (
	codefly "github.com/codefly-dev/sdk-go"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestEndpointParsing(t *testing.T) {
	tcs := []struct {
		name     string
		endpoint string
		host     string
		port     string
	}{
		{name: "regular", endpoint: "CODEFLY_NETWORK_GUESTBOOK-GO_DEFAULT"},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			e := codefly.NetworkEndpoint{Value: tc.endpoint}
			assert.Equal(t, tc.host, e.Host())
		}
	}
}
