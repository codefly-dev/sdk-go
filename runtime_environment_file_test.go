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

func TestLoadRuntimeEnvironmentFilePreservesOpaqueValues(t *testing.T) {
	path := writeRuntimeEnvironmentFile(
		t,
		"CODEFLY__MODULE=platform\n"+
			"CODEFLY__OPAQUE=value with spaces=$HOME;$(touch nope)\n"+
			"CODEFLY__MODULE=platform\n",
		0o600,
	)
	t.Setenv("CODEFLY__MODULE", "")
	t.Setenv("CODEFLY__OPAQUE", "")

	require.NoError(t, codefly.LoadRuntimeEnvironmentFile(path))
	require.Equal(t, "platform", os.Getenv("CODEFLY__MODULE"))
	require.Equal(t, "value with spaces=$HOME;$(touch nope)", os.Getenv("CODEFLY__OPAQUE"))
	require.NoFileExists(t, filepath.Join(filepath.Dir(path), "nope"))
}

func TestLoadRuntimeEnvironmentFileRejectsMalformedOrForeignEntriesAtomically(t *testing.T) {
	path := writeRuntimeEnvironmentFile(
		t,
		"CODEFLY__MODULE=platform\nNOT_CODEFLY=must-not-load\n",
		0o600,
	)
	t.Setenv("CODEFLY__MODULE", "unchanged")

	require.Error(t, codefly.LoadRuntimeEnvironmentFile(path))
	require.Equal(t, "unchanged", os.Getenv("CODEFLY__MODULE"))
	require.Empty(t, os.Getenv("NOT_CODEFLY"))
}

func TestLoadRuntimeEnvironmentFileRejectsUnsafeFile(t *testing.T) {
	path := writeRuntimeEnvironmentFile(t, "CODEFLY__MODULE=platform\n", 0o644)
	require.Error(t, codefly.LoadRuntimeEnvironmentFile(path))

	target := writeRuntimeEnvironmentFile(t, "CODEFLY__MODULE=platform\n", 0o600)
	link := filepath.Join(t.TempDir(), "runtime.env")
	require.NoError(t, os.Symlink(target, link))
	require.Error(t, codefly.LoadRuntimeEnvironmentFile(link))
}

// TestLoadRuntimeEnvironmentFileCarriesAConfigurationDocument: core names a
// structured configuration document's carrier with a lowercase hex digest
// (resources.ConfigurationDocumentKey), and an artifact exporting one — a
// composition's workspace fixture-composition document — was refused whole.
// The document's carrier now loads, and the SDK reads the document from it.
func TestLoadRuntimeEnvironmentFileCarriesAConfigurationDocument(t *testing.T) {
	t.Cleanup(func() { require.NoError(t, codefly.LoadEnvironmentVariables()) })
	t.Setenv(resources.EnvironmentPrefix, "local")
	manager := resources.NewEnvironmentVariableManager()
	manager.SetEnvironment(&basev0.Environment{Name: "local"})
	require.NoError(t, manager.AddConfigurations(context.Background(), &basev0.Configuration{
		Origin: resources.ConfigurationWorkspace,
		Infos: []*basev0.ConfigurationInformation{{
			Name: "fixture-composition",
			Data: &basev0.ConfigurationData{Kind: "json", Content: []byte(`{"roles":[]}`)},
		}},
	}))
	variables, err := manager.All()
	require.NoError(t, err)
	key := resources.ConfigurationDocumentKey(resources.ConfigurationWorkspace, "fixture-composition", "local", false)
	var body strings.Builder
	for _, variable := range variables {
		if variable.Key == key {
			body.WriteString(variable.Key + "=" + variable.ValueAsString() + "\n")
		}
	}
	require.NotEmpty(t, body.String(), "core delivers the document under the key it names")
	t.Setenv(key, "")

	require.NoError(t, codefly.LoadRuntimeEnvironmentFile(writeRuntimeEnvironmentFile(t, body.String(), 0o600)))
	require.NoError(t, codefly.LoadEnvironmentVariables())
	document, err := codefly.For(context.Background()).WorkspaceConfigurationDocument("fixture-composition")
	require.NoError(t, err)
	require.JSONEq(t, `{"roles":[]}`, string(document))
}

// TestLoadRuntimeEnvironmentFileAdmitsOnlyTheDocumentDigestInLowerCase holds
// the exception to exactly the shape core mints.
func TestLoadRuntimeEnvironmentFileAdmitsOnlyTheDocumentDigestInLowerCase(t *testing.T) {
	digest := strings.Repeat("0a", 32)
	for name, admitted := range map[string]bool{
		resources.ConfigurationDocumentPrefix + digest:                  true,
		resources.SecretConfigurationDocumentPrefix + digest:            true,
		resources.ConfigurationDocumentPrefix + strings.ToUpper(digest): true,
		resources.ConfigurationDocumentPrefix + digest[1:]:              false,
		resources.ConfigurationDocumentPrefix + digest + "a":            false,
		resources.ConfigurationDocumentPrefix + strings.Repeat("g", 64): false,
		"CODEFLY__CONFIGURATION_DOCUMENT_V2__" + digest:                 false,
		"CODEFLY__WORKSPACE_CONFIGURATION__" + digest:                   false,
		"CODEFLY__lower": false,
		"codefly__CONFIGURATION_DOCUMENT_V1__" + digest: false,
	} {
		path := writeRuntimeEnvironmentFile(t, name+"=value\n", 0o600)
		t.Setenv(name, "")
		err := codefly.LoadRuntimeEnvironmentFile(path)
		if admitted {
			require.NoError(t, err, name)
		} else {
			require.Error(t, err, name)
		}
	}
}

func writeRuntimeEnvironmentFile(
	t *testing.T,
	body string,
	mode os.FileMode,
) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "runtime.env")
	require.NoError(t, os.WriteFile(path, []byte(body), mode))
	return path
}
