package codefly_test

import (
	"github.com/codefly-dev/core/configurations"
	codefly "github.com/codefly-dev/sdk-go"
	"github.com/stretchr/testify/assert"
	"os"
	"testing"
)

func TestEndpoint(t *testing.T) {
	env := configurations.AsEndpointEnvironmentVariableKey("app", "svc", &configurations.Endpoint{})
	err := os.Setenv(env, ":1234")

	codefly.WithRoot(configurations.SolveDir("testdata/regular"))
	err = codefly.LoadService()
	assert.NoError(t, err)

	codefly.LoadEnvironmentVariables()
	assert.NoError(t, err)

	assert.Equal(t, ":1234", codefly.Endpoint("app/svc").PortAddress())
	assert.Equal(t, ":1234", codefly.Endpoint("self").PortAddress())

	err = os.Setenv("CODEFLY_ENDPOINT__APP__SVC___WRITE", ":12345")

	codefly.LoadEnvironmentVariables()
	assert.NoError(t, err)

	assert.Equal(t, ":12345", codefly.Endpoint("app/svc/write").PortAddress())
	assert.Equal(t, ":12345", codefly.Endpoint("self/write").PortAddress())

	err = os.Setenv("CODEFLY_ENDPOINT__APP__SVC___WRITE", "service.namespace:23456")
	codefly.LoadEnvironmentVariables()

	assert.NoError(t, err)
	assert.Equal(t, "service.namespace:23456", codefly.Endpoint("app/svc/write").Host())
	assert.Equal(t, "service.namespace:23456", codefly.Endpoint("self/write").Host())
}

func TestEndpointWithOverride(t *testing.T) {
	codefly.WithTrace()

	codefly.WithRoot(configurations.SolveDir("testdata/with_overrides"))
	err := codefly.LoadService()
	assert.NoError(t, err)
	codefly.LoadOverrides()

	assert.Equal(t, ":11886", codefly.Endpoint("app/svc::write").PortAddress())
	assert.Equal(t, ":11886", codefly.Endpoint("self::write").PortAddress())
	assert.Equal(t, "localhost:11886", codefly.Endpoint("app/svc::write").Host())
	assert.Equal(t, "localhost:11886", codefly.Endpoint("self::write").Host())
}
