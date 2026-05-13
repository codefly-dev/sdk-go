package codefly_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
	"github.com/codefly-dev/core/resources"
	"github.com/codefly-dev/core/standards"
	"github.com/codefly-dev/core/wool"
	codefly "github.com/codefly-dev/sdk-go"
	"github.com/stretchr/testify/assert"
)

func init() {
	_ = os.Setenv("CODEFLY__SERVICE", "svc")
	_ = os.Setenv("CODEFLY__MODULE", "mod")
}

func Must[T any](obj T, err error) T {
	if err != nil {
		panic(err.Error())
	}
	return obj
}

func TestEnvironmentVariables(t *testing.T) {
	ctx := context.Background()
	wool.SetGlobalLogLevel(wool.TRACE)

	_, err := codefly.Init(context.Background())
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

func TestConfigurationFallsBackToLocalFiles(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()

	writeFile(t, filepath.Join(root, "workspace.codefly.yaml"), `name: sdk-test
layout: modules
modules:
  - name: mod
`)
	writeFile(t, filepath.Join(root, "modules", "mod", "module.codefly.yaml"), `kind: module
name: mod
services:
  - name: file-svc
`)
	serviceDir := filepath.Join(root, "modules", "mod", "services", "file-svc")
	writeFile(t, filepath.Join(serviceDir, "service.codefly.yaml"), `kind: service
name: file-svc
version: 0.0.0
agent:
  kind: runtime::service
  name: go-grpc
  version: 0.0.1
  publisher: codefly.ai
`)
	writeFile(t, filepath.Join(serviceDir, "configurations", "local", "api.secret.env"), "TOKEN=file-secret\n")
	writeFile(t, filepath.Join(serviceDir, "configurations", "local", "api.env"), "URL=file-plain\n")

	codeDir := filepath.Join(serviceDir, "code")
	requireNoError(t, os.MkdirAll(codeDir, 0o755))
	t.Chdir(codeDir)

	secret, err := codefly.For(ctx).Module("mod").Service("file-svc").Secret("api", "token")
	assert.NoError(t, err)
	assert.Equal(t, "file-secret", secret)

	plain, err := codefly.For(ctx).Module("mod").Service("file-svc").Configuration("api", "url")
	assert.NoError(t, err)
	assert.Equal(t, "file-plain", plain)
}

func writeFile(t *testing.T, path string, content string) {
	t.Helper()
	requireNoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
	requireNoError(t, os.WriteFile(path, []byte(content), 0o644))
}

func requireNoError(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
