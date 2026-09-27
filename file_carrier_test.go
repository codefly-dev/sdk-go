package codefly_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
	"github.com/codefly-dev/core/resources"
	codefly "github.com/codefly-dev/sdk-go"
	"github.com/stretchr/testify/require"
)

// deliver emits configuration the way a Codefly runner does — values above
// the threshold written to files, the environment carrying their paths — and
// sets that environment on the test process.
func deliver(t *testing.T, configuration *basev0.Configuration) {
	t.Helper()
	var envs []*resources.EnvironmentVariable
	for _, secret := range []bool{false, true} {
		emitted, err := resources.ConfigurationAsEnvironmentVariables(configuration, "", secret)
		require.NoError(t, err)
		envs = append(envs, emitted...)
	}
	dir := filepath.Join(t.TempDir(), "carriers")
	delivered, err := resources.MaterializeFileCarriers(dir, dir, envs)
	require.NoError(t, err)
	require.NoError(t, resources.CheckProcessEnvironment(delivered))
	for _, env := range delivered {
		t.Setenv(env.Key, env.ValueAsString())
	}
}

func workspaceGroup(name string, values ...*basev0.ConfigurationValue) *basev0.Configuration {
	return &basev0.Configuration{Origin: resources.ConfigurationWorkspace, Infos: []*basev0.ConfigurationInformation{{Name: name, ConfigurationValues: values}}}
}

// A value delivered by file reads exactly as one delivered inline, through
// the snapshot and through a direct lookup, and in both namespaces.
func TestAFileDeliveredValueReadsThroughTheSDK(t *testing.T) {
	t.Cleanup(func() { require.NoError(t, codefly.LoadEnvironmentVariables()) })
	large := strings.Repeat("descriptor-bytes ", resources.FileCarrierThreshold/16+64)
	secret := strings.Repeat("s", resources.FileCarrierThreshold+1)
	deliver(t, workspaceGroup("runnable-bindings",
		&basev0.ConfigurationValue{Key: "ACME__OPERATION", Value: `{"schema":"small"}`},
		&basev0.ConfigurationValue{Key: "DESCRIPTOR_SET__AB", Value: large},
		&basev0.ConfigurationValue{Key: "BUNDLE", Value: secret, Secret: true},
	))
	carrier := resources.WorkspaceConfigurationPrefix + "__RUNNABLE_BINDINGS__DESCRIPTOR_SET__AB"
	_, inline := os.LookupEnv(carrier)
	require.False(t, inline, "the large value is not in the environment")
	require.NotEmpty(t, os.Getenv(resources.FileCarrierKey(carrier)))

	query := codefly.For(context.Background())
	// Before any snapshot: a direct lookup reads through the file.
	value, err := query.WorkspaceValue("runnable-bindings", "DESCRIPTOR_SET__AB")
	require.NoError(t, err)
	require.Equal(t, large, value)

	require.NoError(t, codefly.LoadEnvironmentVariables())
	value, err = query.WorkspaceValue("runnable-bindings", "DESCRIPTOR_SET__AB")
	require.NoError(t, err)
	require.Equal(t, large, value)
	value, err = query.WorkspaceValue("runnable-bindings", "ACME__OPERATION")
	require.NoError(t, err)
	require.Equal(t, `{"schema":"small"}`, value)
	value, err = query.WorkspaceSecret("runnable-bindings", "BUNDLE")
	require.NoError(t, err)
	require.Equal(t, secret, value)
}

// A carrier is fixed at process start: a file changed under a running
// process does not change what it reads.
func TestAFileCarrierIsReadOnce(t *testing.T) {
	t.Cleanup(func() { require.NoError(t, codefly.LoadEnvironmentVariables()) })
	path := filepath.Join(t.TempDir(), "value")
	require.NoError(t, os.WriteFile(path, []byte("first"), 0o600))
	key := resources.WorkspaceConfigurationPrefix + "__ONCE__VALUE"
	t.Setenv(resources.FileCarrierKey(key), path)
	query := codefly.For(context.Background())
	value, err := query.WorkspaceConfiguration("once", "value")
	require.NoError(t, err)
	require.Equal(t, "first", value)
	require.NoError(t, os.WriteFile(path, []byte("second"), 0o600))
	require.NoError(t, codefly.LoadEnvironmentVariables())
	value, err = query.WorkspaceConfiguration("once", "value")
	require.NoError(t, err)
	require.Equal(t, "first", value)
}

// A carrier the SDK cannot read as its value is an error, never an absent
// value, and the error never carries the content.
func TestAnUnreadableFileCarrierFailsClosed(t *testing.T) {
	t.Cleanup(func() {
		for _, entry := range os.Environ() {
			if key, _, _ := strings.Cut(entry, "="); resources.IsFileCarrierKey(key) {
				_ = os.Unsetenv(key)
			}
		}
		require.NoError(t, codefly.LoadEnvironmentVariables())
	})
	dir := t.TempDir()
	query := codefly.For(context.Background())

	missing := resources.WorkspaceConfigurationPrefix + "__GONE__VALUE"
	t.Setenv(resources.FileCarrierKey(missing), filepath.Join(dir, "absent"))
	_, err := query.WorkspaceConfiguration("gone", "value")
	require.ErrorIs(t, err, resources.ErrFileCarrier)
	require.Error(t, codefly.LoadEnvironmentVariables())
	require.NoError(t, os.Unsetenv(resources.FileCarrierKey(missing)))

	exposed := filepath.Join(dir, "exposed")
	require.NoError(t, os.WriteFile(exposed, []byte("private-sentinel"), 0o644))
	secret := resources.WorkspaceSecretConfigurationPrefix + "__VAULT__TOKEN"
	t.Setenv(resources.FileCarrierKey(secret), exposed)
	_, err = query.WorkspaceSecret("vault", "token")
	require.ErrorIs(t, err, resources.ErrFileCarrier)
	require.NotContains(t, err.Error(), "private-sentinel")
	require.NoError(t, os.Unsetenv(resources.FileCarrierKey(secret)))

	both := resources.WorkspaceConfigurationPrefix + "__BOTH__VALUE"
	file := filepath.Join(dir, "both")
	require.NoError(t, os.WriteFile(file, []byte("from-file"), 0o600))
	t.Setenv(both, "inline")
	t.Setenv(resources.FileCarrierKey(both), file)
	_, err = query.WorkspaceConfiguration("both", "value")
	require.ErrorIs(t, err, resources.ErrFileCarrier)
	require.Error(t, codefly.LoadEnvironmentVariables())
}
