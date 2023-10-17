package codefly_test

import (
	"github.com/codefly-dev/core/configurations"
	codefly "github.com/codefly-dev/sdk-go"
	"github.com/stretchr/testify/assert"
	"os"
	"testing"
)

func TestFromEnv(t *testing.T) {
	err := os.Setenv("CODEFLY-NETWORK_GUESTBOOK-GO_DEFAULT", ":8080")

	codefly.WithRoot(configurations.SolveDir("testdata"))
	codefly.LoadService()

	codefly.LoadEnvironmentVariables()
	assert.NoError(t, err)

	assert.Equal(t, ":8080", codefly.Endpoint("guestbook-go.default").PortAddress())
	assert.Equal(t, ":8080", codefly.Endpoint("self").PortAddress())

	err = os.Setenv("CODEFLY-NETWORK_GUESTBOOK-GO_DEFAULT_WRITE", ":8080")

	codefly.LoadEnvironmentVariables()
	assert.NoError(t, err)

	assert.Equal(t, ":8080", codefly.Endpoint("guestbook-go.default::write").PortAddress())
	assert.Equal(t, ":8080", codefly.Endpoint("self::write").PortAddress())

	err = os.Setenv("CODEFLY-NETWORK_GUESTBOOK-GO_DEFAULT_WRITE", "service.namespace:8080")
	codefly.LoadEnvironmentVariables()

	assert.NoError(t, err)
	assert.Equal(t, "service.namespace:8080", codefly.Endpoint("guestbook-go.default::write").Host())
	assert.Equal(t, "service.namespace:8080", codefly.Endpoint("self::write").Host())
}
