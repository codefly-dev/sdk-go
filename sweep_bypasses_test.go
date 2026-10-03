package codefly_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
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

// The REF-LISTING step itself, which was wrong for weeks because nothing could
// test it.
//
// go.yml listed refs with `git for-each-ref 'refs/remotes/origin/*'`. That
// glob does not cross a slash, so every namespaced branch — compat/*, feat/*,
// dependabot/* — was silently dropped. CI printed "sweeping 1 other published
// ref(s)" and "ok origin/badges" and the required check went GREEN while a
// dependabot branch published workcontext/work_context.go importing
// crypto/ed25519.
//
// The step is a script now so these cases exist. The second one is the point:
// listing correctly is a property somebody can break again, and a sweep over a
// subset that reports success is worse than no sweep, because the green is
// what a reader acts on.
func TestTheRefSweepSeesNamespacedBranches(t *testing.T) {
	script, err := filepath.Abs("scripts/sweep-published-refs.sh")
	require.NoError(t, err)
	checker, err := filepath.Abs("scripts/check-one-implementation.sh")
	require.NoError(t, err)

	// A throwaway "remote" with namespaced branches, cloned so the clone has
	// real remote-tracking refs to list.
	remote := t.TempDir()
	runIn(t, remote, "git", "init", "--quiet", "--bare")

	seed := t.TempDir()
	runIn(t, seed, "git", "init", "--quiet")
	require.NoError(t, os.WriteFile(filepath.Join(seed, "ordinary.go"),
		[]byte("package x\n\nimport \"fmt\"\n\nvar _ = fmt.Sprint\n"), 0o600))
	runIn(t, seed, "git", "add", ".")
	runIn(t, seed, "git", "-c", "user.email=t@t", "-c", "user.name=t", "commit", "--quiet", "-m", "seed")
	runIn(t, seed, "git", "branch", "-M", "main")
	runIn(t, seed, "git", "remote", "add", "origin", remote)
	runIn(t, seed, "git", "push", "--quiet", "origin", "main")
	// Namespaced, exactly the shape the glob dropped.
	for _, branch := range []string{"badges", "connectory/welcome", "dependabot/go_modules/gomod-abc"} {
		runIn(t, seed, "git", "push", "--quiet", "origin", "main:refs/heads/"+branch)
	}

	clone := t.TempDir()
	runIn(t, clone, "git", "clone", "--quiet", remote, ".")
	runIn(t, clone, "git", "fetch", "--prune", "--quiet", "origin", "+refs/heads/*:refs/remotes/origin/*")
	require.NoError(t, os.MkdirAll(filepath.Join(clone, "scripts"), 0o755))
	copyFile(t, script, filepath.Join(clone, "scripts", "sweep-published-refs.sh"))
	copyFile(t, checker, filepath.Join(clone, "scripts", "check-one-implementation.sh"))

	listed := listRefs(t, clone, "main", "")
	require.Contains(t, listed, "origin/connectory/welcome",
		"a namespaced branch was dropped: this is the defect the glob had")
	require.Contains(t, listed, "origin/dependabot/go_modules/gomod-abc",
		"a doubly namespaced branch was dropped")
	require.Contains(t, listed, "origin/badges")
	require.NotContains(t, listed, "origin/main", "the base ref is swept by its own push build")

	// And the head ref is excluded while everything else stays.
	withHead := listRefs(t, clone, "main", "badges")
	require.NotContains(t, withHead, "origin/badges")
	require.Contains(t, withHead, "origin/connectory/welcome")
}

// And the sweep REFUSES when it can see fewer refs than the remote publishes,
// which is what turns "I swept a subset" from a silent pass into a failure.
func TestTheRefSweepRefusesWhenItCanSeeFewerRefsThanExist(t *testing.T) {
	script, err := filepath.Abs("scripts/sweep-published-refs.sh")
	require.NoError(t, err)
	checker, err := filepath.Abs("scripts/check-one-implementation.sh")
	require.NoError(t, err)

	remote := t.TempDir()
	runIn(t, remote, "git", "init", "--quiet", "--bare")
	seed := t.TempDir()
	runIn(t, seed, "git", "init", "--quiet")
	require.NoError(t, os.WriteFile(filepath.Join(seed, "ordinary.go"),
		[]byte("package x\n\nimport \"fmt\"\n\nvar _ = fmt.Sprint\n"), 0o600))
	runIn(t, seed, "git", "add", ".")
	runIn(t, seed, "git", "-c", "user.email=t@t", "-c", "user.name=t", "commit", "--quiet", "-m", "seed")
	runIn(t, seed, "git", "branch", "-M", "main")
	runIn(t, seed, "git", "remote", "add", "origin", remote)
	runIn(t, seed, "git", "push", "--quiet", "origin", "main")
	runIn(t, seed, "git", "push", "--quiet", "origin", "main:refs/heads/kept")

	clone := t.TempDir()
	runIn(t, clone, "git", "clone", "--quiet", remote, ".")
	require.NoError(t, os.MkdirAll(filepath.Join(clone, "scripts"), 0o755))
	copyFile(t, script, filepath.Join(clone, "scripts", "sweep-published-refs.sh"))
	copyFile(t, checker, filepath.Join(clone, "scripts", "check-one-implementation.sh"))
	// A branch appears on the remote AFTER the clone, so the local view is a
	// strict subset — the shallow/stale-fetch case.
	runIn(t, seed, "git", "push", "--quiet", "origin", "main:refs/heads/appeared/later")

	run := exec.Command("bash", "scripts/sweep-published-refs.sh")
	run.Dir = clone
	run.Env = append(os.Environ(), "SWEEP_BASE=main", "SWEEP_HEAD=")
	output, err := run.CombinedOutput()
	require.Error(t, err, "a sweep that can see fewer refs than exist must fail:\n%s", output)
	require.Contains(t, string(output), "worse than no sweep")
}

func listRefs(t *testing.T, dir string, base string, head string) []string {
	t.Helper()
	run := exec.Command("bash", "scripts/sweep-published-refs.sh")
	run.Dir = dir
	run.Env = append(os.Environ(), "SWEEP_LIST_ONLY=1", "SWEEP_BASE="+base, "SWEEP_HEAD="+head)
	output, err := run.CombinedOutput()
	require.NoError(t, err, "%s", output)
	var refs []string
	for _, line := range strings.Split(strings.TrimSpace(string(output)), "\n") {
		if line != "" {
			refs = append(refs, line)
		}
	}
	return refs
}

func runIn(t *testing.T, dir string, command string, args ...string) {
	t.Helper()
	run := exec.Command(command, args...)
	run.Dir = dir
	output, err := run.CombinedOutput()
	require.NoError(t, err, "%s %v: %s", command, args, output)
}

func copyFile(t *testing.T, from string, to string) {
	t.Helper()
	content, err := os.ReadFile(from)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(to, content, 0o755))
}
