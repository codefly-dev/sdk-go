package codefly_test

import (
	"context"
	"github.com/codefly-dev/core/configurations"
	codefly "github.com/codefly-dev/sdk-go"
	"github.com/stretchr/testify/assert"
	"os"
	"testing"
)

func Must[T any](obj T, err error) T {
	if err != nil {
		panic(err.Error())
	}
	return obj
}

func TestEndpoint(t *testing.T) {
	ctx := context.Background()

	err := os.Setenv("CODEFLY_SDK__LOGLEVEL", "trace")
	assert.NoError(t, err)

	env := configurations.EndpointEnvironmentVariableKey(&configurations.Endpoint{Application: "app", Service: "svc"})
	t.Log(env)
	err = os.Setenv(env, ":1234")
	assert.NoError(t, err)

	codefly.WithRoot("testdata/regular")

	_, err = codefly.Init(ctx)
	assert.NoError(t, err)

	assert.Equal(t, ":1234", Must(Must(codefly.GetEndpoint(ctx, "app/svc")).PortAddress()))
	assert.Equal(t, ":1234", Must(Must(codefly.GetEndpoint(ctx, "app/svc")).PortAddress()))

	env = configurations.EndpointEnvironmentVariableKey(&configurations.Endpoint{Application: "app", Service: "svc", Name: "write"})
	err = os.Setenv(env, ":12345")
	assert.NoError(t, err)

	err = codefly.LoadFromEnvironmentVariables(ctx)
	assert.NoError(t, err)

	assert.Equal(t, ":12345", Must(Must(codefly.GetEndpoint(ctx, "app/svc/write")).PortAddress()))
	assert.Equal(t, ":12345", Must(Must(codefly.GetEndpoint(ctx, "self/write")).PortAddress()))

	err = os.Setenv(env, "service.namespace:23456")
	assert.NoError(t, err)

	err = codefly.LoadFromEnvironmentVariables(ctx)
	assert.NoError(t, err)

	assert.Equal(t, "service.namespace:23456", Must(Must(codefly.GetEndpoint(ctx, "app/svc/write")).Address()))
	assert.Equal(t, "service.namespace:23456", Must(Must(codefly.GetEndpoint(ctx, "self/write")).Address()))
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

	assert.Equal(t, ":11886", Must(Must(codefly.GetEndpoint(ctx, "app/svc/write")).PortAddress()))
	assert.Equal(t, ":11886", Must(Must(codefly.GetEndpoint(ctx, "self/write")).PortAddress()))
	assert.Equal(t, "localhost:11886", Must(Must(codefly.GetEndpoint(ctx, "app/svc/write")).Address()))
	assert.Equal(t, "localhost:11886", Must(Must(codefly.GetEndpoint(ctx, "self/write")).Address()))
}
