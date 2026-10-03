package codefly_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// The repository-wide sweep, held to its own claim.
//
// scripts/check-one-implementation.sh is the ONLY one-implementation gate the
// root module has: TestNoSecondWorkContextImplementation walks from the
// workcontext module root, and the implementation this repository deleted lived
// at the root, in package codefly. So a bypass here is a bypass with nothing
// behind it — which is why these cases exist. Each one was reported as a
// bypass of the previous revision and each one worked:
//
//   - a non-ASCII import alias and a comment-prefixed import line both walked
//     past a regex that tried to recognise an import's SHAPE. The sweep now
//     reads the path out of the quotes and never looks at the alias.
//   - encoding/pem decodes a base64 body and mime.WordDecoder decodes base64,
//     so "base64 is banned" was a ban on one spelling.
//   - a GMAC through crypto/cipher is a MAC that names no MAC.
//
// Each case is a throwaway git repository, because the sweep's subject is
// "every tracked Go file" and git is how it enumerates them.
func TestTheRepositorySweepCatchesItsOwnBypasses(t *testing.T) {
	script, err := filepath.Abs("scripts/check-one-implementation.sh")
	require.NoError(t, err)

	for name, probe := range map[string]struct {
		source string
		says   string
	}{
		"a non-ASCII import alias": {
			source: "package x\n\nimport ψ \"crypto/ed25519\"\n\nvar _ = ψ.Sign\n",
			says:   "crypto/ed25519",
		},
		"a comment-prefixed import line": {
			source: "package x\n\nimport (\n\t/* innocuous */ \"crypto/ed25519\"\n)\n",
			says:   "crypto/ed25519",
		},
		"a dot-imported signer": {
			source: "package x\n\nimport . \"crypto/ed25519\"\n",
			says:   "crypto/ed25519",
		},
		"encoding/pem as a base64 decoder": {
			source: "package x\n\nimport \"encoding/pem\"\n\nvar _ = pem.Decode\n",
			says:   "encoding/pem",
		},
		"mime as a base64 decoder": {
			source: "package x\n\nimport \"mime\"\n\nvar _ = mime.WordDecoder{}\n",
			says:   "mime",
		},
		"a GMAC through crypto/cipher": {
			source: "package x\n\nimport \"crypto/cipher\"\n\nvar _ = cipher.NewGCM\n",
			says:   "crypto/cipher",
		},
		"a raw-string import path": {
			source: "package x\n\nimport `crypto/ed25519`\n",
			says:   "crypto/ed25519",
		},
		"an alias that is neither ASCII nor a single word": {
			source: "package x\n\nimport (\n\tédd \"crypto/ed25519\"\n)\n",
			says:   "crypto/ed25519",
		},
		"a comment-prefixed single-line import": {
			source: "package x\n\nimport /* x */ \"crypto/ed25519\"\n",
			says:   "crypto/ed25519",
		},
		"base32 as an alternative envelope": {
			source: "package x\n\nimport \"encoding/base32\"\n\nvar _ = base32.StdEncoding\n",
			says:   "encoding/base32",
		},
		"a root-module JSON credential decoder": {
			source: "package x\n\nimport \"encoding/json\"\n\nvar _ = json.Unmarshal\n",
			says:   "encoding/json",
		},
	} {
		t.Run(name, func(t *testing.T) {
			out, err := sweepOf(t, script, "second.go", probe.source)
			require.Error(t, err, "the sweep passed this file:\n%s", out)
			require.Contains(t, out, probe.says)
			require.Contains(t, out, "second.go")
		})
	}

	// And an ordinary file passes, so the sweep is not simply failing.
	out, err := sweepOf(t, script, "ordinary.go",
		"package x\n\nimport (\n\t\"fmt\"\n\t\"strings\"\n)\n\nvar _ = fmt.Sprint\nvar _ = strings.TrimSpace\n")
	require.NoError(t, err, out)
	require.Contains(t, out, "ok")

	// A tracked file with no Go source at all must FAIL rather than pass: a
	// sweep that reports "ok" for an empty repository is a sweep that reports
	// ok for a repository whose checkout went wrong.
	_, err = sweepOf(t, script, "README.md", "nothing to sweep\n")
	require.Error(t, err, "an empty sweep must not be a green sweep")
}

// sweepOf runs the sweep over a throwaway repository containing one file.
func sweepOf(t *testing.T, script string, name string, source string) (string, error) {
	t.Helper()
	repository := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(repository, name), []byte(source), 0o600))
	for _, command := range [][]string{
		{"git", "init", "--quiet"},
		{"git", "add", "."},
	} {
		run := exec.Command(command[0], command[1:]...)
		run.Dir = repository
		output, err := run.CombinedOutput()
		require.NoError(t, err, "%s: %s", command, output)
	}
	sweep := exec.Command("bash", script)
	sweep.Dir = repository
	output, err := sweep.CombinedOutput()
	return string(output), err
}
