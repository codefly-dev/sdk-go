package codefly_test

import (
	"context"
	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
	"github.com/codefly-dev/core/resources"
	"github.com/codefly-dev/core/standards"
	"github.com/codefly-dev/core/wool"
	codefly "github.com/codefly-dev/sdk-go"
	"github.com/stretchr/testify/assert"
	"os"
	"path"
	"testing"
)

func Must[T any](obj T, err error) T {
	if err != nil {
		panic(err.Error())
	}
	return obj
}

func TestServiceLoad(t *testing.T) {
	cur, err := os.Getwd()
	wool.SetGlobalLogLevel(wool.TRACE)
	assert.NoError(t, err)
	err = os.Chdir(path.Join(cur, "testdata/regular/services/src"))
	assert.NoError(t, err)
	defer func() {
		err = os.Chdir(cur)
		assert.NoError(t, err)
	}()
	_, err = codefly.Init(context.Background())
	assert.NoError(t, err)
	assert.NotNil(t, codefly.Service())
}

func TestServiceLoadUp(t *testing.T) {
	cur, err := os.Getwd()
	assert.NoError(t, err)
	err = os.Chdir(path.Join(cur, "testdata/regular/services/src"))
	assert.NoError(t, err)
	defer func() {
		err = os.Chdir(cur)
		assert.NoError(t, err)
	}()
	_, err = codefly.Init(context.Background())
	assert.NoError(t, err)
	assert.NotNil(t, codefly.Service())
}

func TestEnvironmentVariables(t *testing.T) {
	ctx := context.Background()
	wool.SetGlobalLogLevel(wool.TRACE)

	cur, err := os.Getwd()
	assert.NoError(t, err)
	err = os.Chdir(path.Join(cur, "testdata/regular/services/src"))
	assert.NoError(t, err)
	defer func() {
		err = os.Chdir(cur)
		assert.NoError(t, err)
	}()
	_, err = codefly.Init(context.Background())
	assert.NoError(t, err)

	err = os.Setenv("CODEFLY_SDK__LOGLEVEL", "trace")
	assert.NoError(t, err)

	// No default
	net := codefly.For(ctx).API(standards.REST).NetworkInstance()
	assert.Nil(t, net)

	// With default
	net = codefly.For(ctx).API(standards.REST).WithDefaultNetwork().NetworkInstance()
	assert.NotNil(t, net)
	assert.Equal(t, "localhost", net.Hostname)
	assert.Equal(t, uint16(8080), net.Port)
	assert.Equal(t, "http://localhost:8080", net.Address)

	// With API and no name
	env := resources.EndpointAsEnvironmentVariableKey(&resources.EndpointInformation{Module: "mod", Service: "svc", Name: standards.HTTP, API: standards.HTTP})
	err = os.Setenv(env, "http://localhost:1234")
	assert.NoError(t, err)
	err = codefly.LoadEnvironmentVariables()
	assert.NoError(t, err)

	net = codefly.For(ctx).API(standards.HTTP).NetworkInstance()
	assert.Equal(t, "localhost", net.Hostname)
	assert.Equal(t, uint16(1234), net.Port)
	assert.Equal(t, "http://localhost:1234", net.Address)

	outputConf := &basev0.Configuration{
		Origin:         "mod/store",
		RuntimeContext: resources.NewRuntimeContextNative(),
		Infos: []*basev0.ConfigurationInformation{
			{Name: "postgres",
				ConfigurationValues: []*basev0.ConfigurationValue{
					{Key: "connection", Value: "secret", Secret: true},
					{Key: "connection", Value: "plain"},
				},
			},
		},
	}
	secretEnvs := resources.ConfigurationAsEnvironmentVariables(outputConf, true)
	envs := resources.ConfigurationAsEnvironmentVariables(outputConf, false)

	for _, e := range secretEnvs {
		err = os.Setenv(e.Key, e.ValueAsString())
		assert.NoError(t, err)
	}
	for _, e := range envs {
		err = os.Setenv(e.Key, e.ValueAsString())
		assert.NoError(t, err)
	}
	err = codefly.LoadEnvironmentVariables()
	assert.NoError(t, err)

	value, err := codefly.For(ctx).Service("store").Configuration("postgres", "connection")
	assert.NoError(t, err)
	assert.Equal(t, "plain", value)

	value, err = codefly.For(ctx).Service("store").Secret("postgres", "connection")
	assert.NoError(t, err)
	assert.Equal(t, "secret", value)
}
