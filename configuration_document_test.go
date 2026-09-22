package codefly_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/codefly-dev/core/configurations"
	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
	"github.com/codefly-dev/core/resources"
	codefly "github.com/codefly-dev/sdk-go"
	"github.com/stretchr/testify/require"
)

func TestConfigurationDocumentsReachSDKFromFilesAndRuntimeCarrier(t *testing.T) {
	ctx := context.Background()
	t.Setenv(resources.EnvironmentPrefix, "staging")
	t.Setenv(resources.ModulePrefix, "app")
	t.Setenv(resources.ServicePrefix, "api")
	dir := t.TempDir()
	public := `{"nested":{"list":[true,null,9007199254740993],"name":"00123"}}`
	secret := `{"credentials":{"token":"private-sentinel"}}`
	require.NoError(t, os.WriteFile(filepath.Join(dir, "settings.yaml"), []byte(public), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "credentials.secret.yaml"), []byte(secret), 0o600))
	infos, err := configurations.LoadConfigurationInformationsFromFiles(ctx, dir)
	require.NoError(t, err)
	require.Len(t, infos, 2)
	manager := resources.NewEnvironmentVariableManager()
	manager.SetEnvironment(&basev0.Environment{Name: "staging"})
	require.NoError(t, manager.AddConfigurations(ctx, &basev0.Configuration{Origin: "app/api", Infos: infos}))
	variables, err := manager.All()
	require.NoError(t, err)
	for _, variable := range variables {
		t.Setenv(variable.Key, variable.ValueAsString())
	}
	require.NoError(t, codefly.LoadEnvironmentVariables())
	t.Cleanup(func() { require.NoError(t, codefly.InjectConfigurations()) })
	query := codefly.For(ctx)
	data, err := query.ConfigurationDocument("settings")
	require.NoError(t, err)
	require.Equal(t, public, string(data))
	data[0] = '['
	data, err = query.ConfigurationDocument("settings")
	require.NoError(t, err)
	require.Equal(t, public, string(data), "returned documents must not alias a retained snapshot")
	data, err = query.SecretDocument("credentials")
	require.NoError(t, err)
	require.Equal(t, secret, string(data))
	_, err = query.ConfigurationDocument("credentials")
	require.Error(t, err)
	var generic map[string]any
	require.NoError(t, query.DecodeConfigurationDocument("settings", &generic))
	require.Equal(t, json.Number("9007199254740993"), generic["nested"].(map[string]any)["list"].([]any)[2])
	var incompatible struct {
		Credentials int `json:"credentials"`
	}
	err = query.DecodeSecretDocument("credentials", &incompatible)
	require.Error(t, err)
	require.NotContains(t, err.Error(), "private-sentinel")
	_, err = codefly.For(ctx).Service("other").ConfigurationDocument("settings")
	require.Error(t, err)
	t.Setenv(resources.EnvironmentPrefix, "production")
	_, err = query.ConfigurationDocument("settings")
	require.Error(t, err)
}

func TestInjectConfigurationDocumentsIsAtomicAndSeparatesWorkspaceScope(t *testing.T) {
	t.Setenv(resources.EnvironmentPrefix, "staging")
	t.Cleanup(func() { require.NoError(t, codefly.InjectConfigurations()) })
	conf := &basev0.Configuration{Origin: resources.ConfigurationWorkspace, Infos: []*basev0.ConfigurationInformation{{
		Name: "policy", Data: &basev0.ConfigurationData{Kind: "json", Content: []byte(`{"enabled":true}`)},
	}}}
	require.NoError(t, codefly.InjectConfigurations(conf))
	query := codefly.For(context.Background()).Module("app").Service("api")
	data, err := query.WorkspaceConfigurationDocument("policy")
	require.NoError(t, err)
	require.Equal(t, `{"enabled":true}`, string(data))
	var policy struct {
		Enabled bool `json:"enabled"`
	}
	require.NoError(t, query.DecodeWorkspaceConfigurationDocument("policy", &policy))
	require.True(t, policy.Enabled)
	_, err = query.ConfigurationDocument("policy")
	require.Error(t, err)
	conf.Infos[0].Data.Content = []byte(`{"private-sentinel":`)
	err = codefly.InjectConfigurations(conf)
	require.Error(t, err)
	require.NotContains(t, err.Error(), "private-sentinel")
	data, err = query.WorkspaceConfigurationDocument("policy")
	require.NoError(t, err)
	require.Equal(t, `{"enabled":true}`, string(data))
	require.NoError(t, codefly.InjectConfigurations())
	_, err = query.WorkspaceConfigurationDocument("policy")
	require.Error(t, err)
}

func TestWorkspaceSecretDocumentHasIndependentTypedScope(t *testing.T) {
	t.Setenv(resources.EnvironmentPrefix, "staging")
	t.Cleanup(func() { require.NoError(t, codefly.InjectConfigurations()) })
	conf := &basev0.Configuration{Origin: resources.ConfigurationWorkspace, Infos: []*basev0.ConfigurationInformation{{
		Name: "credentials", Data: &basev0.ConfigurationData{Kind: "json", Secret: true, Content: []byte(`{"token":"private-sentinel"}`)},
	}}}
	require.NoError(t, codefly.InjectConfigurations(conf))
	query := codefly.For(context.Background())
	var credentials struct {
		Token string `json:"token"`
	}
	require.NoError(t, query.DecodeWorkspaceSecretDocument("credentials", &credentials))
	require.Equal(t, "private-sentinel", credentials.Token)
	_, err := query.WorkspaceConfigurationDocument("credentials")
	require.Error(t, err)
	var incompatible int
	err = query.DecodeWorkspaceSecretDocument("credentials", &incompatible)
	require.Error(t, err)
	require.NotContains(t, err.Error(), "private-sentinel")
}
