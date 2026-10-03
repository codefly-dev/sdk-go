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

// Round six, layer 2: THE AUDIT FAILED OPEN, in four separate places, and three
// of them were inside the assertion added for round five's blocker.
//
// A gate that reports success when it could not look is worse than no gate, and
// each of these reported success: the ref-listing guard skipped itself when
// git failed, the comparison was between COUNTS, an unreadable blob was swept
// as a clean one, and the fix for that last one exited a subshell.
func TestTheSweepRefusesWhenItCouldNotLook(t *testing.T) {
	sweep, err := filepath.Abs("scripts/sweep-published-refs.sh")
	require.NoError(t, err)
	checker, err := filepath.Abs("scripts/check-one-implementation.sh")
	require.NoError(t, err)

	// AN UNREACHABLE REMOTE. `git ls-remote … 2>/dev/null` swallowed the
	// failure and `[ ${#published[@]} -gt 0 ]` skipped the comparison, so a
	// checkout with one ref fetched printed "the remote publishes 0 ref(s);
	// sweeping 0 of them", "this repository publishes no ref other than main",
	// and exited 0 — the same false green the glob produced, through the guard
	// added to stop it.
	t.Run("an unreachable remote", func(t *testing.T) {
		clone := clonedRemote(t, sweep, checker, "kept")
		runIn(t, clone, "git", "remote", "set-url", "origin", filepath.Join(t.TempDir(), "gone.git"))

		output, err := runSweep(clone)

		require.Error(t, err, "a sweep with no denominator must not report success:\n%s", output)
		require.Contains(t, output, "cannot list the refs this repository publishes")
	})

	// COUNTS AGREEING IS NOT THE SAME REFS. A remote that deleted one branch
	// and published another left the local view holding a stale ref and
	// missing the new one: two each side, assertion green, and the branch that
	// carried the implementation was never opened.
	t.Run("the same number of different refs", func(t *testing.T) {
		clone := clonedRemote(t, sweep, checker, "kept")
		remote := strings.TrimSpace(runOut(t, clone, "git", "remote", "get-url", "origin"))
		// The remote moves on; this checkout does not refetch.
		//
		// Pushed from origin/main BY NAME, never from HEAD: a clone's HEAD is
		// the remote's, and a bare repository's HEAD follows whoever ran
		// `git init` — so `HEAD:refs/heads/…` resolved here and failed on a
		// runner whose init.defaultBranch is master with "src refspec HEAD
		// does not match any". Green locally, red in CI, which is the class
		// this whole file is about.
		seed := t.TempDir()
		runIn(t, seed, "git", "clone", "--quiet", remote, ".")
		runIn(t, seed, "git", "push", "--quiet", "origin", ":refs/heads/kept")
		runIn(t, seed, "git", "push", "--quiet", "origin",
			"refs/remotes/origin/main:refs/heads/appeared/later")

		output, err := runSweep(clone)

		require.Error(t, err, "the same count of different refs must not pass:\n%s", output)
		require.Contains(t, output, "appeared/later",
			"and the refusal must name the ref that was never swept")
	})

	// AN UNREADABLE ENTRY AT A REF. `git ls-tree -r` names gitlinks as well as
	// blobs, so a submodule whose path ends in .go is listed and `git cat-file
	// blob` cannot read it. The error was swallowed, the source emptied, and
	// the ref announced `ok` with exit 0.
	//
	// The first fix for this failed open too: the `exit 1` ran inside the
	// command substitution `"$(carrying_in_ref "$ref")"`, so the script printed
	// FAIL, carried on, found no findings, and printed `ok` directly underneath
	// — measured. Both halves are asserted here, the exit status as well as the
	// message.
	t.Run("an entry the sweep cannot read", func(t *testing.T) {
		repository := t.TempDir()
		runIn(t, repository, "git", "init", "--quiet", ".")
		require.NoError(t, os.WriteFile(filepath.Join(repository, "ordinary.go"),
			[]byte("package x\n\nimport \"fmt\"\n\nvar _ = fmt.Sprint\n"), 0o600))
		runIn(t, repository, "git", "add", ".")
		runIn(t, repository, "git", "-c", "user.email=t@t", "-c", "user.name=t",
			"commit", "--quiet", "-m", "seed")
		commit := strings.TrimSpace(runOut(t, repository, "git", "rev-parse", "HEAD"))
		// A gitlink whose path ends in .go.
		runIn(t, repository, "git", "update-index", "--add", "--cacheinfo",
			"160000,"+commit+",vendored.go")
		runIn(t, repository, "git", "-c", "user.email=t@t", "-c", "user.name=t",
			"commit", "--quiet", "-m", "a gitlink named like a Go file")
		runIn(t, repository, "git", "branch", "gitlinked")
		require.NoError(t, os.MkdirAll(filepath.Join(repository, "scripts"), 0o755))
		copyFile(t, checker, filepath.Join(repository, "scripts", "check-one-implementation.sh"))

		run := exec.Command("bash", "scripts/check-one-implementation.sh", "gitlinked")
		run.Dir = repository
		raw, err := run.CombinedOutput()
		output := string(raw)

		require.Error(t, err, "a ref this sweep could not open must not be reported ok:\n%s", output)
		require.Contains(t, output, "has not been swept")
		require.NotContains(t, output, "ok   gitlinked",
			"the first fix printed FAIL and then ok, because exit 1 inside a command "+
				"substitution exits the subshell")
	})
}

// And the two SCANNER bypasses, both of which compile and pass `go vet`.
//
// The import extractor was rewritten in round four for exactly this class and
// these two shapes walked past the rewrite: it read the closing paren off the
// RAW line, so a `)` inside a comment closed the block early; and it scanned
// for double-quoted paths and backquoted paths in two sequential passes, so a
// raw path BEFORE a quoted one on the same line was dropped. Both measured at
// exit 0 against the previous revision.
func TestTheImportScannerReadsOneLineOnce(t *testing.T) {
	script, err := filepath.Abs("scripts/check-one-implementation.sh")
	require.NoError(t, err)

	for name, probe := range map[string]string{
		"a closing paren inside a comment": "package x\n\nimport (\n\t// )\n\t\"crypto/ed25519\"\n)\n\nvar _ = ed25519.Sign\n",
		"a block comment holding a paren":  "package x\n\nimport (\n\t/* ) */\n\t\"crypto/ed25519\"\n)\n\nvar _ = ed25519.Sign\n",
		"a raw path before a quoted one":   "package x\n\nimport (`crypto/ed25519`; \"fmt\")\n\nvar _ = ed25519.Sign\nvar _ = fmt.Sprint\n",
	} {
		t.Run(name, func(t *testing.T) {
			out, err := sweepOf(t, script, "second.go", probe)
			require.Error(t, err, "the sweep passed this file:\n%s", out)
			require.Contains(t, out, "crypto/ed25519")
		})
	}

	// THE BANS THE AST GATE HAS AND THIS ONE DID NOT. Four import paths the
	// AST gate refuses passed here with `ok working tree (4 Go files)`, exit 0
	// — in the root module, where this script is the only gate.
	for name, probe := range map[string]struct{ source, says string }{
		"the legacy protobuf module": {
			source: "package x\n\nimport _ \"github.com/golang/protobuf/proto\"\n",
			says:   "github.com/golang/protobuf/proto",
		},
		"the low-level protobuf runtime": {
			source: "package x\n\nimport _ \"google.golang.org/protobuf/runtime/protoiface\"\n",
			says:   "runtime/protoiface",
		},
		"protoimpl": {
			source: "package x\n\nimport _ \"google.golang.org/protobuf/runtime/protoimpl\"\n",
			says:   "runtime/protoimpl",
		},
		"a vendored ed25519": {
			source: "package x\n\nimport _ \"github.com/some/vendor/ed25519\"\n",
			says:   "ed25519",
		},
	} {
		t.Run(name, func(t *testing.T) {
			out, err := sweepOf(t, script, "second.go", probe.source)
			require.Error(t, err, "the sweep passed this file:\n%s", out)
			require.Contains(t, out, probe.says)
		})
	}
}

// clonedRemote builds a throwaway remote with one extra branch and returns a
// clone of it carrying both scripts.
func clonedRemote(t *testing.T, sweep string, checker string, branch string) string {
	t.Helper()
	// -b main on both: these repositories' branch names are part of what the
	// sweep is asserted against, so they are stated here rather than inherited
	// from whatever init.defaultBranch the machine happens to set.
	remote := t.TempDir()
	runIn(t, remote, "git", "init", "--quiet", "--bare", "-b", "main")
	seed := t.TempDir()
	runIn(t, seed, "git", "init", "--quiet", "-b", "main")
	require.NoError(t, os.WriteFile(filepath.Join(seed, "ordinary.go"),
		[]byte("package x\n\nimport \"fmt\"\n\nvar _ = fmt.Sprint\n"), 0o600))
	runIn(t, seed, "git", "add", ".")
	runIn(t, seed, "git", "-c", "user.email=t@t", "-c", "user.name=t", "commit", "--quiet", "-m", "seed")
	runIn(t, seed, "git", "remote", "add", "origin", remote)
	runIn(t, seed, "git", "push", "--quiet", "origin", "main")
	runIn(t, seed, "git", "push", "--quiet", "origin", "main:refs/heads/"+branch)

	clone := t.TempDir()
	runIn(t, clone, "git", "clone", "--quiet", remote, ".")
	runIn(t, clone, "git", "fetch", "--prune", "--quiet", "origin", "+refs/heads/*:refs/remotes/origin/*")
	require.NoError(t, os.MkdirAll(filepath.Join(clone, "scripts"), 0o755))
	copyFile(t, sweep, filepath.Join(clone, "scripts", "sweep-published-refs.sh"))
	copyFile(t, checker, filepath.Join(clone, "scripts", "check-one-implementation.sh"))
	return clone
}

func runSweep(dir string) (string, error) {
	run := exec.Command("bash", "scripts/sweep-published-refs.sh")
	run.Dir = dir
	run.Env = append(os.Environ(), "SWEEP_BASE=main", "SWEEP_HEAD=")
	output, err := run.CombinedOutput()
	return string(output), err
}

func runOut(t *testing.T, dir string, command string, args ...string) string {
	t.Helper()
	run := exec.Command(command, args...)
	run.Dir = dir
	output, err := run.Output()
	require.NoError(t, err, "%s %v", command, args)
	return string(output)
}
