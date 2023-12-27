package codefly_test

import (
	"context"
	"github.com/codefly-dev/core/configurations"
	codefly "github.com/codefly-dev/sdk-go"
	"github.com/stretchr/testify/assert"
	"os"
	"testing"
)

func TestEndpoint(t *testing.T) {
	ctx := context.Background()

	err := os.Setenv("CODEFLY_SDK__LOGLEVEL", "trace")
	assert.NoError(t, err)

	env := configurations.AsEndpointEnvironmentVariableKey(&configurations.Endpoint{Application: "app", Service: "svc"})
	t.Log(env)
	err = os.Setenv(env, ":1234")
	assert.NoError(t, err)

	codefly.WithRoot("testdata/regular")
	_, err = codefly.Init(ctx)
	assert.NoError(t, err)

	assert.Equal(t, ":1234", codefly.Endpoint(ctx, "app/svc").PortAddress())
	assert.Equal(t, ":1234", codefly.Endpoint(ctx, "self").PortAddress())

	err = os.Setenv("CODEFLY_ENDPOINT__APP__SVC___WRITE", ":12345")
	assert.NoError(t, err)

	err = codefly.LoadNetworkEndpointFromEnvironmentVariables(ctx)
	assert.NoError(t, err)

	assert.Equal(t, ":12345", codefly.Endpoint(ctx, "app/svc/write").PortAddress())
	assert.Equal(t, ":12345", codefly.Endpoint(ctx, "self/write").PortAddress())

	err = os.Setenv("CODEFLY_ENDPOINT__APP__SVC___WRITE", "service.namespace:23456")
	assert.NoError(t, err)

	err = codefly.LoadNetworkEndpointFromEnvironmentVariables(ctx)
	assert.NoError(t, err)

	assert.Equal(t, "service.namespace:23456", codefly.Endpoint(ctx, "app/svc/write").Host())
	assert.Equal(t, "service.namespace:23456", codefly.Endpoint(ctx, "self/write").Host())
}

func TestEndpointWithOverride(t *testing.T) {
	ctx := context.Background()

	err := os.Setenv("CODEFLY_SDK__LOGLEVEL", "trace")
	assert.NoError(t, err)

	err = os.Setenv("CODEFLY_SDK__WITHOVERRIDE", "true")
	assert.NoError(t, err)

	codefly.WithRoot("testdata/with_overrides")
	_, err = codefly.Init(ctx)
	assert.NoError(t, err)

	assert.Equal(t, ":11886", codefly.Endpoint(ctx, "app/svc::write").PortAddress())
	assert.Equal(t, ":11886", codefly.Endpoint(ctx, "self::write").PortAddress())
	assert.Equal(t, "localhost:11886", codefly.Endpoint(ctx, "app/svc::write").Host())
	assert.Equal(t, "localhost:11886", codefly.Endpoint(ctx, "self::write").Host())
}
