package codefly_test

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

// The repository-wide sweep, held to its own claim.
//
// scripts/check-one-implementation.sh is the only one-implementation gate that
// reads a PUBLISHED REF. The Go gates type-check both modules from a checkout;
// a ref has no checkout, so the sweep reads blobs out of `git cat-file` and
// this script is all there is behind it. (It was the only gate reading the root
// module at all until the import allowlist and the type-checked codec rule
// landed; that half of the claim is no longer true.) A bypass here is still a
// bypass of the required check for any branch a consumer can pin, which is why
// these cases exist. Each one was reported as a
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

// importReader builds scripts/importsof once per run and returns its path.
//
// Every harness here runs the sweep in a throwaway repository, where the script
// cannot find the reader beside itself — so it is built once and passed in
// through IMPORTSOF_BIN. Thirty `go build` invocations was the alternative.
func importReader(t *testing.T) string {
	t.Helper()
	readerOnce.Do(func() {
		source, err := filepath.Abs(filepath.Join("scripts", "importsof"))
		if err != nil {
			readerErr = err
			return
		}
		binary := filepath.Join(os.TempDir(), fmt.Sprintf("importsof-%d", os.Getpid()))
		build := exec.Command("go", "build", "-o", binary, source)
		if output, err := build.CombinedOutput(); err != nil {
			readerErr = fmt.Errorf("build the import reader: %v: %s", err, output)
			return
		}
		readerPath = binary
	})
	require.NoError(t, readerErr)
	require.NotEmpty(t, readerPath)
	return readerPath
}

var (
	readerOnce sync.Once
	readerPath string
	readerErr  error
)

// sweepEnv is the environment every sweep invocation runs with.
func sweepEnv(t *testing.T) []string {
	t.Helper()
	return append(os.Environ(), "IMPORTSOF_BIN="+importReader(t))
}

// sweepRefOf runs the sweep in REF MODE over a committed blob.
//
// A different path through the script from the working tree: the ref arm reads
// blobs out of `git cat-file` into a temporary directory and maps them back,
// and it applies the historical `legacy` allowance. Both arms were measured
// passing the old denylist's gaps, so both are probed.
func sweepRefOf(t *testing.T, script string, name string, source string) (string, error) {
	t.Helper()
	repository := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Dir(filepath.Join(repository, name)), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(repository, name), []byte(source), 0o600))
	require.NoError(t, os.MkdirAll(filepath.Join(repository, "scripts"), 0o755))
	copyFile(t, script, filepath.Join(repository, "scripts", "check-one-implementation.sh"))
	copyPolicy(t, filepath.Dir(script), filepath.Join(repository, "scripts"))
	for _, command := range [][]string{
		{"git", "init", "--quiet", "-b", "main"},
		{"git", "add", "."},
		{"git", "-c", "user.email=t@t", "-c", "user.name=t", "commit", "--quiet", "-m", "probe"},
	} {
		run := exec.Command(command[0], command[1:]...)
		run.Dir = repository
		output, err := run.CombinedOutput()
		require.NoError(t, err, "%s: %s", command, output)
	}
	run := exec.Command("bash", "scripts/check-one-implementation.sh", "main")
	run.Dir = repository
	run.Env = sweepEnv(t)
	output, err := run.CombinedOutput()
	return string(output), err
}

// sweepOf runs the sweep over a throwaway repository containing one file.
func sweepOf(t *testing.T, script string, name string, source string) (string, error) {
	t.Helper()
	repository := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Dir(filepath.Join(repository, name)), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(repository, name), []byte(source), 0o600))
	require.NoError(t, os.MkdirAll(filepath.Join(repository, "scripts"), 0o755))
	for _, command := range [][]string{
		{"git", "init", "--quiet"},
		{"git", "add", "."},
	} {
		run := exec.Command(command[0], command[1:]...)
		run.Dir = repository
		output, err := run.CombinedOutput()
		require.NoError(t, err, "%s: %s", command, output)
	}
	// THE POLICY TRAVELS WITH THE SCRIPT. The sweep reads
	// scripts/allowed-imports.txt beside itself, so a throwaway repository with
	// only the script in it would fail for want of a policy rather than on the
	// probe — which is a test passing for the wrong reason in the file whose
	// subject is exactly that.
	copyPolicy(t, filepath.Dir(script), filepath.Join(repository, "scripts"))
	sweep := exec.Command("bash", script)
	sweep.Dir = repository
	sweep.Env = sweepEnv(t)
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
	// Namespaced, exactly the shape the glob dropped. The names are SYNTHETIC:
	// these were copied off the live remote, where one of them is a
	// third-party bot's branch, and a fixture that names something outside
	// this repository is a fixture that goes stale when that thing does.
	for _, branch := range []string{"badges", "team/welcome", "dependabot/go_modules/gomod-abc"} {
		runIn(t, seed, "git", "push", "--quiet", "origin", "main:refs/heads/"+branch)
	}

	clone := t.TempDir()
	runIn(t, clone, "git", "clone", "--quiet", remote, ".")
	runIn(t, clone, "git", "fetch", "--prune", "--quiet", "origin", "+refs/heads/*:refs/remotes/origin/*")
	require.NoError(t, os.MkdirAll(filepath.Join(clone, "scripts"), 0o755))
	copyFile(t, script, filepath.Join(clone, "scripts", "sweep-published-refs.sh"))
	copyFile(t, checker, filepath.Join(clone, "scripts", "check-one-implementation.sh"))

	listed := listRefs(t, clone, "main", "")
	require.Contains(t, listed, "origin/team/welcome",
		"a namespaced branch was dropped: this is the defect the glob had")
	require.Contains(t, listed, "origin/dependabot/go_modules/gomod-abc",
		"a doubly namespaced branch was dropped")
	require.Contains(t, listed, "origin/badges")
	require.NotContains(t, listed, "origin/main", "the base ref is swept by its own push build")

	// And the head ref is excluded while everything else stays.
	withHead := listRefs(t, clone, "main", "badges")
	require.NotContains(t, withHead, "origin/badges")
	require.Contains(t, withHead, "origin/team/welcome")
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
	run.Env = append(sweepEnv(t), "SWEEP_BASE=main", "SWEEP_HEAD=")
	output, err := run.CombinedOutput()
	require.Error(t, err, "a sweep that can see fewer refs than exist must fail:\n%s", output)
	require.Contains(t, string(output), "worse than no sweep")
}

func listRefs(t *testing.T, dir string, base string, head string) []string {
	t.Helper()
	run := exec.Command("bash", "scripts/sweep-published-refs.sh")
	run.Dir = dir
	run.Env = append(sweepEnv(t), "SWEEP_LIST_ONLY=1", "SWEEP_BASE="+base, "SWEEP_HEAD="+head)
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

// copyPolicy puts the real import policy beside a throwaway copy of the script.
func copyPolicy(t *testing.T, fromDir string, toDir string) {
	t.Helper()
	require.NoError(t, os.MkdirAll(toDir, 0o755))
	copyFile(t, filepath.Join(fromDir, "allowed-imports.txt"),
		filepath.Join(toDir, "allowed-imports.txt"))
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

		output, err := runSweep(t, clone)

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

		output, err := runSweep(t, clone)

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
		copyPolicy(t, filepath.Dir(checker), filepath.Join(repository, "scripts"))

		run := exec.Command("bash", "scripts/check-one-implementation.sh", "gitlinked")
		run.Dir = repository
		run.Env = sweepEnv(t)
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
		// The shapes the awk extractor still passed after three rewrites, each
		// compiled by the reviewer who found them. The last one is the whole
		// argument for deleting the extractor: `"\x63rypto/ed25519"` IS
		// crypto/ed25519 to the compiler, and is not that string to anything
		// matching text. No regex closes it; go/parser closes all of them.
		"the keyword, then a newline, then the path": "package x\n\nimport\n\t\"crypto/ed25519\"\n\nvar _ = ed25519.Sign\n",
		"a comment spanning lines before the path":   "package x\n\nimport /*\n*/ \"crypto/ed25519\"\n\nvar _ = ed25519.Sign\n",
		"an escaped import path":                     "package x\n\nimport \"\\x63rypto/ed25519\"\n",
		"a grouped escaped path":                     "package x\n\nimport (\n\t\"\\x63rypto/ed25519\"\n)\n",
	} {
		t.Run(name, func(t *testing.T) {
			out, err := sweepOf(t, script, "second.go", probe)
			require.Error(t, err, "the sweep passed this file:\n%s", out)
			require.Contains(t, out, "crypto/ed25519")
		})
	}

	// THE DENY-BY-DEFAULT POLICY, THROUGH THE SCRIPT, IN TREE AND REF MODE.
	//
	// This is what had no test. The policy file is asserted not to LIST these
	// paths, and the Go gates refuse them in a checkout — but nothing ran the
	// SWEEP over them, which is the only thing that reads a published ref and
	// is the whole of the required check. A reviewer pointed out that
	// restoring the entire old denylist script left every test green, and that
	// was true.
	//
	// Ref mode is checked separately from tree mode because they take
	// different paths through the script: the tree reads files from disk, a ref
	// reads blobs out of `git cat-file` into a temporary directory. The old
	// `ok` was measured in both.
	for name, spec := range map[string]string{
		"json/v2, which is not encoding/json":  "encoding/json/v2",
		"mldsa, a signature nobody had listed": "crypto/mldsa",
		"protodelim, a codec by another name":  "google.golang.org/protobuf/encoding/protodelim",
		"the gRPC codec registry":              "google.golang.org/grpc/encoding",
		"prototext":                            "google.golang.org/protobuf/encoding/prototext",
		"jsontext":                             "encoding/json/jsontext",
		"hpke, an AEAD and so MAC-capable":     "crypto/hpke",
		"unsafe, which can forge anything":     "unsafe",
	} {
		// BOTH MODULES, because the policy is per module and the sweep picks
		// the list by PATH. Probing only a root-level file left the leaf list
		// untested: a mutation that allowlisted `crypto/mldsa` for the leaf
		// changed nothing, because no probe ever asked the leaf list anything.
		for module, path := range map[string]string{
			"root": "second.go",
			"leaf": "workcontext/second.go",
		} {
			source := "package x\n\nimport _ \"" + spec + "\"\n"
			t.Run(name+", in the "+module+" module's working tree", func(t *testing.T) {
				out, err := sweepOf(t, script, path, source)
				require.Error(t, err, "the sweep passed this file:\n%s", out)
				require.Contains(t, out, spec)
				require.Contains(t, out, path)
			})
			t.Run(name+", in the "+module+" module at a ref", func(t *testing.T) {
				out, err := sweepRefOf(t, script, path, source)
				require.Error(t, err, "the sweep passed this blob at a ref:\n%s", out)
				require.Contains(t, out, spec)
			})
		}
	}

	// `import "C"` is not an import path, so it is refused by name — in both
	// modes, and with the diagnosis that says why rather than "not listed".
	t.Run("cgo, in the working tree", func(t *testing.T) {
		out, err := sweepOf(t, script, "cgo.go", "package x\n\n/*\n*/\nimport \"C\"\n")
		require.Error(t, err, out)
		require.Contains(t, out, "cgo.go imports C")
		require.Contains(t, out, "cgo is not a package name to add to a list",
			"and the diagnosis says WHY, because a reader told only \"not listed\" would "+
				"reasonably try adding it")
	})
	t.Run("cgo, at a ref", func(t *testing.T) {
		out, err := sweepRefOf(t, script, "cgo.go", "package x\n\n/*\n*/\nimport \"C\"\n")
		require.Error(t, err, out)
		require.Contains(t, out, "cgo.go imports C")
		require.Contains(t, out, "cgo is not a package name to add to a list")
	})

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
	copyPolicy(t, filepath.Dir(checker), filepath.Join(clone, "scripts"))
	return clone
}

func runSweep(t *testing.T, dir string) (string, error) {
	t.Helper()
	run := exec.Command("bash", "scripts/sweep-published-refs.sh")
	run.Dir = dir
	run.Env = append(sweepEnv(t), "SWEEP_BASE=main", "SWEEP_HEAD=")
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

// AND A FILE THAT DOES NOT PARSE IS A FAILURE, not a file with no imports.
//
// This is the fail-open class one more time, in the new reader: `awk` produced
// an empty list for anything it could not make sense of, and an empty list is
// indistinguishable from "imports nothing". The reader returns a non-zero exit
// instead, and the script stops.
func TestAFileTheSweepCannotParseIsNotAFileItHasCleared(t *testing.T) {
	script, err := filepath.Abs("scripts/check-one-implementation.sh")
	require.NoError(t, err)

	out, err := sweepOf(t, script, "broken.go", "package x\n\nimport (\n\t\"crypto/ed25519\"\n// never closed\n")
	require.Error(t, err, "a file that does not parse must not be swept as clean:\n%s", out)
	require.Contains(t, out, "cannot read the imports")
}

// The import reader is Go, so it is held to the same question directly: what
// does Go think this file imports?
func TestTheImportReaderAnswersWithWhatGoSees(t *testing.T) {
	reader := importReader(t)
	directory := t.TempDir()
	path := filepath.Join(directory, "probe.go")
	require.NoError(t, os.WriteFile(path, []byte(
		"package x\n\nimport (\n\t// )\n\t\"\\x63rypto/ed25519\"\n\t`encoding/base64`\n)\n"), 0o600))

	run := exec.Command(reader)
	run.Dir = directory
	run.Stdin = strings.NewReader(path + "\n")
	output, err := run.Output()
	require.NoError(t, err, "%s", output)

	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	var paths []string
	for _, line := range lines {
		_, imported, found := strings.Cut(line, "\t")
		require.True(t, found, "each line is path<TAB>import: %q", line)
		paths = append(paths, imported)
	}
	require.ElementsMatch(t, []string{"crypto/ed25519", "encoding/base64"}, paths,
		"the escape is unquoted to the path the compiler sees, the raw string is read, "+
			"and the \")\" in the comment does not end the block")
}

// NO GATE HERE CAN READ ASSEMBLY OR C, so the sweep refuses them — at every
// published ref, where no Go test runs.
//
// Every rule in this repository is about Go: `go/parser` for the imports,
// `go/types` for the codec rule. A `.s` file can implement anything at all, a
// `.syso` is already-compiled object code linked in whole, and a `.c` reached
// through cgo is outside the language. `import "C"` is refused by name and this
// is the other half of it: the import ban is meaningless if the implementation
// can arrive as an object file.
func TestTheSweepRefusesSourcesNoGateCanRead(t *testing.T) {
	script, err := filepath.Abs("scripts/check-one-implementation.sh")
	require.NoError(t, err)

	for name, probe := range map[string]struct{ file, source string }{
		"hand-written assembly": {"sign_amd64.s", "TEXT sign(SB),$0\n\tRET\n"},
		"a compiled object":     {"libsign.syso", "\x7fELF not really\n"},
		"a C source":            {"sign.c", "int sign(void) { return 0; }\n"},
		"a C header":            {"sign.h", "int sign(void);\n"},
	} {
		t.Run(name, func(t *testing.T) {
			repository := t.TempDir()
			require.NoError(t, os.WriteFile(filepath.Join(repository, "ordinary.go"),
				[]byte("package x\n\nimport \"fmt\"\n\nvar _ = fmt.Sprint\n"), 0o600))
			require.NoError(t, os.WriteFile(filepath.Join(repository, probe.file),
				[]byte(probe.source), 0o600))
			require.NoError(t, os.MkdirAll(filepath.Join(repository, "scripts"), 0o755))
			copyFile(t, script, filepath.Join(repository, "scripts", "check-one-implementation.sh"))
			copyPolicy(t, filepath.Dir(script), filepath.Join(repository, "scripts"))
			for _, command := range [][]string{{"git", "init", "--quiet"}, {"git", "add", "."}} {
				run := exec.Command(command[0], command[1:]...)
				run.Dir = repository
				output, err := run.CombinedOutput()
				require.NoError(t, err, "%s: %s", command, output)
			}

			run := exec.Command("bash", "scripts/check-one-implementation.sh")
			run.Dir = repository
			run.Env = sweepEnv(t)
			raw, err := run.CombinedOutput()

			require.Error(t, err, "a source no gate can read must not sweep clean:\n%s", raw)
			require.Contains(t, string(raw), probe.file)
			require.Contains(t, string(raw), "no gate here can read")
		})
	}

	// And a repository of ordinary Go still passes, so this is not simply
	// failing — the mutation guard for every case above.
	out, err := sweepOf(t, script, "ordinary.go",
		"package x\n\nimport \"fmt\"\n\nvar _ = fmt.Sprint\n")
	require.NoError(t, err, out)
}

// THE SAME CHECK MUST ANSWER THE SAME WAY WHICHEVER EVENT RAN IT.
//
// The base ref — the one this change merges into, excluded because sweeping it
// is circular — fell through to GITHUB_REF_NAME when GITHUB_BASE_REF was empty.
// That is empty on a PUSH build, so:
//
//	pull_request  GITHUB_BASE_REF=main      -> main excluded, check green
//	push          GITHUB_BASE_REF empty     -> base became the pushed branch,
//	                                           main swept, check RED
//
// Measured in CI, run 37208615216: `FAIL origin/main carries a Work Context
// implementation`, listing the files this PR deletes. Both triggers report
// under one required check name, so the answer depended on which event landed
// last — and a check that is right half the time is worse than one that is
// wrong, because the green is what somebody acts on.
//
// Nothing covered this: every test here set SWEEP_BASE explicitly, which is
// precisely the variable CI was not setting on a push.
func TestTheBaseRefIsTheDefaultBranchWhicheverEventRan(t *testing.T) {
	sweep, err := filepath.Abs("scripts/sweep-published-refs.sh")
	require.NoError(t, err)
	checker, err := filepath.Abs("scripts/check-one-implementation.sh")
	require.NoError(t, err)
	clone := clonedRemote(t, sweep, checker, "feature/work")
	// A third published ref, so "everything else is still swept" is an
	// assertion rather than an empty list: excluding the base and the head
	// from a two-branch remote leaves nothing, and nil contains nothing.
	runIn(t, clone, "git", "push", "--quiet", "origin",
		"refs/remotes/origin/main:refs/heads/badges")
	runIn(t, clone, "git", "fetch", "--prune", "--quiet", "origin",
		"+refs/heads/*:refs/remotes/origin/*")

	listWith := func(environment ...string) []string {
		t.Helper()
		run := exec.Command("bash", "scripts/sweep-published-refs.sh")
		run.Dir = clone
		run.Env = append(sweepEnv(t), append([]string{"SWEEP_LIST_ONLY=1"}, environment...)...)
		output, err := run.Output()
		require.NoError(t, err, "%s", output)
		var refs []string
		for _, line := range strings.Split(strings.TrimSpace(string(output)), "\n") {
			if line != "" {
				refs = append(refs, line)
			}
		}
		return refs
	}

	// A PUSH build: no GITHUB_BASE_REF, GITHUB_REF_NAME is the pushed branch.
	// This is the shape that was red.
	push := listWith("GITHUB_BASE_REF=", "GITHUB_REF_NAME=feature/work", "GITHUB_HEAD_REF=")
	require.NotContains(t, push, "origin/main",
		"a push build swept the default branch, which carries the implementation until "+
			"this change merges — the circular case the exclusion exists for")
	require.NotContains(t, push, "origin/feature/work",
		"and the ref being built is covered by the working-tree sweep")
	require.Contains(t, push, "origin/badges", "while every other published ref is still swept")

	// A PULL_REQUEST build: GITHUB_BASE_REF names the base.
	pull := listWith("GITHUB_BASE_REF=main", "GITHUB_REF_NAME=feature/work",
		"GITHUB_HEAD_REF=feature/work")
	require.NotContains(t, pull, "origin/main")
	require.NotContains(t, pull, "origin/feature/work")

	// THE TWO MUST AGREE. That is the property; the individual exclusions are
	// how it is reached.
	require.ElementsMatch(t, push, pull,
		"the same required check swept a different set depending on which event ran it")

	// And an explicit SWEEP_BASE still wins, which is what the workflow passes.
	explicit := listWith("SWEEP_BASE=badges", "GITHUB_BASE_REF=", "GITHUB_REF_NAME=feature/work")
	require.NotContains(t, explicit, "origin/badges")
	require.Contains(t, explicit, "origin/main",
		"with badges named as the base, main is an ordinary published ref again")
}
