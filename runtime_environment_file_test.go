package codefly_test

import (
	"os"
	"path/filepath"
	"testing"

	codefly "github.com/codefly-dev/sdk-go"
	"github.com/stretchr/testify/require"
)

func TestLoadRuntimeEnvironmentFilePreservesOpaqueValues(t *testing.T) {
	path := writeRuntimeEnvironmentFile(
		t,
		"CODEFLY__MODULE=saas\n"+
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
		"CODEFLY__MODULE=saas\nNOT_CODEFLY=must-not-load\n",
		0o600,
	)
	t.Setenv("CODEFLY__MODULE", "unchanged")

	require.Error(t, codefly.LoadRuntimeEnvironmentFile(path))
	require.Equal(t, "unchanged", os.Getenv("CODEFLY__MODULE"))
	require.Empty(t, os.Getenv("NOT_CODEFLY"))
}

func TestLoadRuntimeEnvironmentFileRejectsUnsafeFile(t *testing.T) {
	path := writeRuntimeEnvironmentFile(t, "CODEFLY__MODULE=saas\n", 0o644)
	require.Error(t, codefly.LoadRuntimeEnvironmentFile(path))

	target := writeRuntimeEnvironmentFile(t, "CODEFLY__MODULE=saas\n", 0o600)
	link := filepath.Join(t.TempDir(), "runtime.env")
	require.NoError(t, os.Symlink(target, link))
	require.Error(t, codefly.LoadRuntimeEnvironmentFile(link))
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
