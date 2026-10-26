package codefly_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
	"github.com/codefly-dev/core/resources"
	codefly "github.com/codefly-dev/sdk-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// setWorkspaceCarriers sets process carriers and rebuilds the snapshot, and
// rebuilds it again once t.Setenv has restored them, so no neighbouring test
// reads a group this one left behind.
func setWorkspaceCarriers(t *testing.T, carriers map[string]string) {
	t.Helper()
	t.Cleanup(func() { _ = codefly.LoadEnvironmentVariables() })
	for key, value := range carriers {
		t.Setenv(key, value)
	}
	require.NoError(t, codefly.LoadEnvironmentVariables())
}

// A group keyed by generated names — runnable-bindings, keyed
// <MODULE>__<OPERATION> — is enumerated through the SDK, sorted, and each key
// it lists reads its value through the per-key accessor. Neighbouring groups,
// a group whose name merely extends this one, and the secret namespace are
// not part of it.
func TestWorkspaceConfigurationKeysListsOneGroupInItsReadableSpelling(t *testing.T) {
	ctx := t.Context()
	setWorkspaceCarriers(t, map[string]string{
		"CODEFLY__WORKSPACE_CONFIGURATION__KEYS_BINDINGS__DOCUMENTS__COUNT_DOCUMENTS": `{"operation":"count"}`,
		"CODEFLY__WORKSPACE_CONFIGURATION__KEYS_BINDINGS__ACCOUNTS__WHO_AM_I":         `{"operation":"whoami"}`,
		"CODEFLY__WORKSPACE_CONFIGURATION__KEYS_BINDINGS__EMPTY":                      "",
		"CODEFLY__WORKSPACE_CONFIGURATION__KEYS_BINDINGS__lower":                      "not a spelling the accessor reads",
		"CODEFLY__WORKSPACE_CONFIGURATION__KEYS_BINDINGS_EXTRA__OTHER":                "another group",
		"CODEFLY__WORKSPACE_CONFIGURATION__KEYS_OTHER__DOCUMENTS__COUNT_DOCUMENTS":    "another group",
		"CODEFLY__WORKSPACE_SECRET_CONFIGURATION__KEYS_BINDINGS__HIDDEN":              "secret",
	})

	keys, err := codefly.For(ctx).WorkspaceConfigurationKeys("keys-bindings")

	require.NoError(t, err)
	assert.Equal(t, []string{"ACCOUNTS__WHO_AM_I", "DOCUMENTS__COUNT_DOCUMENTS"}, keys)
	value, err := codefly.For(ctx).WorkspaceConfiguration("keys-bindings", keys[1])
	require.NoError(t, err)
	assert.Equal(t, `{"operation":"count"}`, value)

	secrets, err := codefly.For(ctx).WorkspaceSecretKeys("keys-bindings")
	require.NoError(t, err)
	assert.Equal(t, []string{"HIDDEN"}, secrets)
	value, err = codefly.For(ctx).WorkspaceSecret("keys-bindings", secrets[0])
	require.NoError(t, err)
	assert.Equal(t, "secret", value)
}

// The group is read under both spellings the per-key accessor reads: the
// exact name and the '-'-normalized one.
func TestWorkspaceConfigurationKeysReadsBothGroupSpellings(t *testing.T) {
	setWorkspaceCarriers(t, map[string]string{
		"CODEFLY__WORKSPACE_CONFIGURATION__KEYS-SPELLING__EXACT":      "exact",
		"CODEFLY__WORKSPACE_CONFIGURATION__KEYS_SPELLING__NORMALIZED": "normalized",
	})

	keys, err := codefly.For(t.Context()).WorkspaceConfigurationKeys("keys-spelling")

	require.NoError(t, err)
	assert.Equal(t, []string{"EXACT", "NORMALIZED"}, keys)
}

// A prepared binding is large enough to be delivered by file. Its key is
// listed under the key it carries, never under the carrier's own name, and its
// value reads through the file.
func TestWorkspaceConfigurationKeysListsAFileDeliveredKey(t *testing.T) {
	key := "CODEFLY__WORKSPACE_CONFIGURATION__KEYS_FILED__DOCUMENTS__COUNT_DOCUMENTS"
	content := strings.Repeat("x", resources.FileCarrierThreshold+1)
	path := filepath.Join(t.TempDir(), "binding")
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
	setWorkspaceCarriers(t, map[string]string{resources.FileCarrierKey(key): path})

	keys, err := codefly.For(t.Context()).WorkspaceConfigurationKeys("keys-filed")

	require.NoError(t, err)
	assert.Equal(t, []string{"DOCUMENTS__COUNT_DOCUMENTS"}, keys)
	value, err := codefly.For(t.Context()).WorkspaceConfiguration("keys-filed", keys[0])
	require.NoError(t, err)
	assert.Equal(t, content, value)
}

// An embedded host injects configuration without touching the process
// environment; the listing sees what the per-key accessor sees.
func TestWorkspaceConfigurationKeysListsInjectedConfiguration(t *testing.T) {
	t.Cleanup(func() { require.NoError(t, codefly.InjectConfigurations()) })
	require.NoError(t, codefly.InjectConfigurations(&basev0.Configuration{
		Origin: resources.ConfigurationWorkspace,
		Infos: []*basev0.ConfigurationInformation{{
			Name: "keys-injected",
			ConfigurationValues: []*basev0.ConfigurationValue{
				{Key: "documents__count-documents", Value: "count"},
				{Key: "credential", Value: "secret", Secret: true},
			},
		}},
	}))

	keys, err := codefly.For(t.Context()).WorkspaceConfigurationKeys("keys-injected")

	require.NoError(t, err)
	assert.Equal(t, []string{"DOCUMENTS__COUNT_DOCUMENTS"}, keys)
	secrets, err := codefly.For(t.Context()).WorkspaceSecretKeys("keys-injected")
	require.NoError(t, err)
	assert.Equal(t, []string{"CREDENTIAL"}, secrets)
}

// Listing a secret group opens no secret file and caches no secret value:
// the value read after the listing is what the file holds then, so the listing
// did not keep a copy of it.
func TestWorkspaceSecretKeysReadsNoSecretValue(t *testing.T) {
	key := "CODEFLY__WORKSPACE_SECRET_CONFIGURATION__KEYS_SECRET_FILED__CREDENTIAL"
	path := filepath.Join(t.TempDir(), "credential")
	require.NoError(t, os.WriteFile(path, []byte("before listing"), 0o600))
	t.Cleanup(func() { _ = codefly.LoadEnvironmentVariables() })
	t.Setenv(resources.FileCarrierKey(key), path)

	keys, err := codefly.For(t.Context()).WorkspaceSecretKeys("keys-secret-filed")

	require.NoError(t, err)
	assert.Equal(t, []string{"CREDENTIAL"}, keys)
	require.NoError(t, os.WriteFile(path, []byte("after listing"), 0o600))
	value, err := codefly.For(t.Context()).WorkspaceSecret("keys-secret-filed", keys[0])
	require.NoError(t, err)
	assert.Equal(t, "after listing", value, "the listing must not have read or cached the secret")
}

// Absence is an answer and a failed read is not: an absent group (or one
// whose only carrier is empty) is an empty list with the error the per-key
// accessor gives an absent key, and a delivery that cannot be read is listed
// (never silently dropped) and fails where its value is read, with an error
// that is not absence.
func TestWorkspaceConfigurationKeysSeparatesAbsenceFromFailure(t *testing.T) {
	ctx := t.Context()

	t.Run("a group nothing carries", func(t *testing.T) {
		keys, err := codefly.For(ctx).WorkspaceConfigurationKeys("keys-absent")

		assert.ErrorIs(t, err, codefly.ErrWorkspaceConfigurationAbsent)
		assert.NotNil(t, keys)
		assert.Empty(t, keys)
		_, err = codefly.For(ctx).WorkspaceConfiguration("keys-absent", "any")
		assert.ErrorIs(t, err, codefly.ErrWorkspaceConfigurationAbsent, "one classification for an absent key and an absent group")
	})

	t.Run("a group whose only carrier is empty", func(t *testing.T) {
		setWorkspaceCarriers(t, map[string]string{"CODEFLY__WORKSPACE_CONFIGURATION__KEYS_BLANK__KEY": ""})

		keys, err := codefly.For(ctx).WorkspaceConfigurationKeys("keys-blank")

		assert.ErrorIs(t, err, codefly.ErrWorkspaceConfigurationAbsent)
		assert.Empty(t, keys)
	})

	t.Run("a delivery that cannot be read", func(t *testing.T) {
		key := "CODEFLY__WORKSPACE_CONFIGURATION__KEYS_UNREADABLE__BINDING"
		t.Setenv("CODEFLY__WORKSPACE_CONFIGURATION__KEYS_UNREADABLE__READABLE", "value")
		t.Setenv(resources.FileCarrierKey(key), filepath.Join(t.TempDir(), "absent"))

		keys, err := codefly.For(ctx).WorkspaceConfigurationKeys("keys-unreadable")

		require.NoError(t, err)
		assert.Equal(t, []string{"BINDING", "READABLE"}, keys, "an unreadable delivery is listed, never silently omitted")
		_, err = codefly.For(ctx).WorkspaceConfiguration("keys-unreadable", "BINDING")
		require.Error(t, err)
		assert.NotErrorIs(t, err, codefly.ErrWorkspaceConfigurationAbsent, "an unreadable delivery is not absence")
		assert.ErrorIs(t, err, resources.ErrFileCarrier)
	})

	t.Run("a file carrier naming an empty file", func(t *testing.T) {
		key := "CODEFLY__WORKSPACE_CONFIGURATION__KEYS_EMPTY_FILE__BINDING"
		path := filepath.Join(t.TempDir(), "empty")
		require.NoError(t, os.WriteFile(path, nil, 0o600))
		t.Setenv(resources.FileCarrierKey(key), path)

		keys, err := codefly.For(ctx).WorkspaceConfigurationKeys("keys-empty-file")

		require.NoError(t, err)
		assert.Equal(t, []string{"BINDING"}, keys, "listing opens no file, so the carrier's path is what it sees")
		_, err = codefly.For(ctx).WorkspaceConfiguration("keys-empty-file", "BINDING")
		assert.ErrorIs(t, err, codefly.ErrWorkspaceConfigurationAbsent, "an empty file reads as absent")
	})

	t.Run("a value delivered both inline and by file", func(t *testing.T) {
		key := "CODEFLY__WORKSPACE_CONFIGURATION__KEYS_TWICE__BINDING"
		path := filepath.Join(t.TempDir(), "binding")
		require.NoError(t, os.WriteFile(path, []byte("by file"), 0o600))
		t.Setenv(key, "inline")
		t.Setenv(resources.FileCarrierKey(key), path)

		keys, err := codefly.For(ctx).WorkspaceConfigurationKeys("keys-twice")

		require.NoError(t, err)
		assert.Equal(t, []string{"BINDING"}, keys)
		_, err = codefly.For(ctx).WorkspaceConfiguration("keys-twice", "BINDING")
		require.Error(t, err)
		assert.NotErrorIs(t, err, codefly.ErrWorkspaceConfigurationAbsent, "two sources for one fact is not absence")
		assert.ErrorIs(t, err, resources.ErrFileCarrier)
		assert.ErrorContains(t, err, "delivered both inline and by file")
	})
}
