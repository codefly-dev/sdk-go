package workcontext

import (
	"fmt"
	"go/ast"
	"go/types"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/tools/go/packages"
)

// DENY BY DEFAULT. This is the gate's spine, and it replaces an argument that
// lost ten times running.
//
// Every previous revision banned a LIST OF NAMES and every review found the
// next name: `hkdf`, then `sha512`, then `protoiface`, then — in the round that
// prompted this file — `crypto/mldsa` signing a `WorkContextV1` that
// `encoding/json/v2` had encoded as snake_case JSON, which is the exact format
// this repository deleted. Both gates were green. `golangci-lint` reported 0
// issues. The denylist was not behind by one entry; it was behind by a design.
//
// So the question is inverted. Each module declares the imports it HAS, and
// anything else is a finding until somebody adds it here with a reason. The
// next name costs a reviewed line in this file rather than a round of review:
// `protodelim`, `grpc/encoding`, `json/v2`, `mldsa`, `prototext`, `jsontext`
// and `hpke` are all refused by the same rule, and so is the one nobody has
// thought of.
//
// Three things this does NOT reach, stated rather than implied:
//
//   - A hand-written implementation that imports nothing. A base64url decoder
//     is twenty lines, a protobuf wire walk is fifty, and neither names a
//     package. That is the irreducible residue, the same class as a hand-rolled
//     HMAC over an allowed hash, and it is closed by review.
//   - Test files, which are exempt: `minting_test.go` imports `crypto/ed25519`
//     to hold the verifier's public-key map, and that is the right thing for a
//     test of a verifier to do. A `_test.go` cannot be imported by shipped
//     code, so a second implementation there ships to nobody.
//   - Anything a dependency does. This is a rule about what THIS repository
//     spells.

// allowedImports is every import path a module's non-test code may use, READ
// FROM scripts/allowed-imports.txt.
//
// It was a map in this file, and that was the hole: the ref sweep is the only
// thing that runs over a published ref, and it had its own denylist — so a
// branch carrying `crypto/mldsa` and `encoding/json/v2`, which is the round-six
// second implementation, swept `ok` in the job that is a required check. Two
// policies is one policy and one hole. One file now, read by both.
//
// The test below fails in BOTH directions: an import not in the file is a
// finding, and a line nothing imports is deleted, because a permission nobody
// uses is precedent for the next reader.
func allowedImportsFor(t *testing.T, module string) []string {
	t.Helper()
	policy := loadImportPolicy(t)
	require.Contains(t, policy, module, "the policy file lists no module %q", module)
	return policy[module]
}

// loadImportPolicy parses the shared policy file.
func loadImportPolicy(t *testing.T) map[string][]string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "scripts", "allowed-imports.txt"))
	require.NoError(t, err, "the import policy is the gate; a gate with no policy is not one")

	policy := map[string][]string{}
	for index, line := range strings.Split(string(raw), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		module, rest, found := strings.Cut(trimmed, " ")
		require.True(t, found, "line %d is not `<module> <importpath> [file …]`: %q", index+1, line)
		// A line may name the FILES that may have the import. This package
		// checks module membership; the file list is what keeps the ref sweep
		// as strict as the denylist it replaced, and the Go gate's own
		// narrowedImports holds the same imports to files AND symbols.
		path, _, _ := strings.Cut(rest, " ")
		require.Contains(t, []string{"root", "leaf", "legacy"}, module,
			"line %d names %q, which is not root, leaf or legacy", index+1, module)
		// `legacy` is the historical allowance, applied by the sweep to
		// published refs only — never to the working tree, which is what this
		// package checks. It is kept out of the module lists deliberately: a
		// path in it must not become permitted in a checkout, and
		// TestTheHistoricalImportAllowanceCarriesNothingCapabilityShaped is
		// what holds it to being benign.
		policy[module] = append(policy[module], strings.TrimSpace(path))
	}
	require.NotEmpty(t, policy["root"])
	require.NotEmpty(t, policy["leaf"])
	return policy
}

// TestEveryImportIsOnItsModulesAllowlist is the deny-by-default rule.
func TestEveryImportIsOnItsModulesAllowlist(t *testing.T) {
	for _, module := range loadModules(t) {
		allowed := allowedImportsFor(t, module.name)
		require.NotEmpty(t, allowed)

		for _, finding := range unallowedImports(module.name, allowed, importsOfModule(t, module)) {
			t.Error(finding)
		}

	}
}

// An entry nothing imports is a permission in force for nobody, which the next
// reader takes as precedent. The allowlist is measured from the tree, so it
// stays measured.
func TestTheAllowlistHasNoUnusedPermission(t *testing.T) {
	for _, module := range loadModules(t) {
		used := importsOfModule(t, module)
		for _, spec := range allowedImportsFor(t, module.name) {
			require.Contains(t, used, spec,
				"allowedImports[%q] permits %q and no file in that module imports it. "+
					"An unused permission is precedent; delete the line.", module.name, spec)
		}
	}
}

// TESTDATA IS SHIPPED CODE. The go tool excludes a `testdata` directory from
// WILDCARD matching, not from importing — so a package there is compiled into
// anything that imports it by path, and no `./...` ever mentions it. A reviewer
// put a complete Ed25519 signer under receipts/testdata/ and imported it from a
// root file; the syntactic walk skipped the directory by name and both gates
// were green.
//
// This asserts the loader's patterns reach such a package, because the rule
// above is only as wide as what it was handed.
func TestTestdataIsNotAHidingPlace(t *testing.T) {
	// IN A TEMPORARY DIRECTORY, NOT IN THE REPOSITORY. The first version of
	// this test created receipts/testdata/gateprobe and its cleanup removed
	// receipts/testdata — the PARENT. Nothing lives there today, so it did no
	// harm here, but a test that deletes a directory it did not create will
	// delete somebody's fixtures the day they add some, and running the suite
	// is not supposed to be a destructive act. A reviewer was right to call
	// that a major finding rather than a nit.
	//
	// What is actually being asserted is a property of testdataPatterns, which
	// takes a directory — so it is handed one that belongs to this test.
	root := t.TempDir()
	probe := filepath.Join(root, "receipts", "testdata", "gateprobe")
	require.NoError(t, os.MkdirAll(probe, 0o750))
	require.NoError(t, os.WriteFile(filepath.Join(probe, "signer.go"),
		[]byte("package gateprobe\n\nimport \"crypto/ed25519\"\n\n"+
			"func Sign(key ed25519.PrivateKey, payload []byte) []byte {\n"+
			"\treturn ed25519.Sign(key, payload)\n}\n"), 0o600))

	require.Contains(t, testdataPatterns(t, root), "./receipts/testdata/...",
		"the loader must be given the testdata packages explicitly; ./... does not match them, "+
			"and a reviewer imported a complete Ed25519 signer from one")

	// A directory with no testdata in it yields no patterns, so the walk is
	// not simply returning everything.
	require.Empty(t, testdataPatterns(t, t.TempDir()))

	// And the rule refuses what is in there, which is the point of reaching it.
	require.NotEmpty(t, unallowedImports("root", allowedImportsFor(t, "root"), map[string][]string{
		"crypto/ed25519": {"receipts/testdata/gateprobe/signer.go"},
	}), "a signer under testdata is still a signer")
}

// A package that does not type-check is a package this gate has not read, and
// passing what it could not read is the fail-open this repository has fixed
// four times in three rounds. The loader fails on it rather than skipping it.
func TestTheGateRefusesAPackageItCannotTypeCheck(t *testing.T) {
	// Asserted on the loader's own contract rather than by breaking the tree:
	// every package loaded here carries zero errors, so if the check below
	// were removed nothing would notice until something was already broken.
	for _, module := range loadModules(t) {
		for _, loaded := range module.packages {
			require.Empty(t, loaded.Errors,
				"%s did not type-check; the type-based rules cannot run on it", loaded.PkgPath)
			require.NotNil(t, loaded.TypesInfo,
				"%s carries no type information, so every go/types rule read nothing there",
				loaded.PkgPath)
		}
	}
}

// importsOfModule is what a module's non-test files import, by path.
func importsOfModule(t *testing.T, module loadedModule) map[string][]string {
	t.Helper()
	used := map[string][]string{}
	for _, loaded := range module.packages {
		for _, file := range loaded.Syntax {
			path := module.relative(loaded, file)
			if path == "" || strings.HasSuffix(path, "_test.go") {
				continue
			}
			for _, imported := range file.Imports {
				spec, err := strconv.Unquote(imported.Path.Value)
				require.NoError(t, err)
				used[spec] = append(used[spec], path)
			}
		}
	}
	return used
}

// unallowedImports is the rule itself, over a module name and what its files
// import, returning findings rather than calling require.
//
// Separated so a probe can drive it: the test above reads the real tree, so the
// only way to ask "would this refuse crypto/mldsa?" through it is to commit
// crypto/mldsa. A rule that cannot be probed is a rule nobody has tested, which
// is the finding that prompted this whole file.
func unallowedImports(module string, allowed []string, used map[string][]string) []string {
	var findings []string
	for _, spec := range sortedKeys(used) {
		files := strings.Join(used[spec], ", ")
		// `import "C"` IS NOT AN IMPORT PATH, it is an escape from Go
		// entirely: a reviewer MACed a capability through CommonCrypto's
		// CCHmac and checked it against RFC 4231, and no rule written about Go
		// imports could see it. There is no honest use for cgo in an SDK whose
		// job is resolving values.
		if spec == "C" {
			findings = append(findings, fmt.Sprintf("%s imports \"C\".\n"+
				"cgo is not an import path, it is an exit from every rule here: a MAC built with\n"+
				"the host's crypto library names no Go package at all. Nothing in this repository\n"+
				"needs it.", files))
			continue
		}
		if slices.Contains(allowed, spec) {
			continue
		}
		findings = append(findings, fmt.Sprintf(
			"%s (module %s) imports %q, which is not on that module's allowlist.\n"+
				"THIS LIST IS DENY-BY-DEFAULT, and that is the point. A denylist of names was\n"+
				"behind by one entry every round — hkdf, then sha512, then protoiface, then\n"+
				"crypto/mldsa signing a WorkContextV1 that encoding/json/v2 had encoded in the\n"+
				"deleted format, with both gates green. If this import is honest, add it to\n"+
				"allowedImports[%q] WITH A REASON, in a reviewed diff. That is the cost, and it is\n"+
				"one line instead of a round of review.",
			files, module, spec, module))
	}
	return findings
}

func sortedKeys(from map[string][]string) []string {
	keys := make([]string, 0, len(from))
	for key := range from {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

// THE PROBES, every one of them a shape a reviewer compiled and ran as a
// decoder, a signer or a MAC of a real WorkContextV1 minted by core's
// Authority, against the previous revision of this gate. Every one passed.
func TestTheImportAllowlistRefusesTheNextName(t *testing.T) {
	for name, probe := range map[string]struct {
		module string
		spec   string
	}{
		// The two halves of the complete second implementation: json/v2
		// encoded a real capability as snake_case JSON — the deleted format —
		// and mldsa signed it, 2420 bytes, verified. Both gates green.
		"encoding/json/v2, which is not encoding/json":    {"leaf", "encoding/json/v2"},
		"crypto/mldsa, a signature nobody had listed":     {"leaf", "crypto/mldsa"},
		"protodelim, a codec with different method names": {"leaf", "google.golang.org/protobuf/encoding/protodelim"},
		"the gRPC codec registry":                         {"leaf", "google.golang.org/grpc/encoding"},
		// Named in the review as inferred, never compiled. They cost nothing
		// here, which is the whole argument for inverting the question.
		"prototext":                        {"leaf", "google.golang.org/protobuf/encoding/prototext"},
		"jsontext":                         {"leaf", "encoding/json/jsontext"},
		"hpke, an AEAD and so MAC-capable": {"leaf", "crypto/hpke"},
		// And in the root module, where the shell sweep is the only other gate.
		"json/v2 in the root module":    {"root", "encoding/json/v2"},
		"protodelim in the root module": {"root", "google.golang.org/protobuf/encoding/protodelim"},
		// cgo, which is not an import path at all.
		"cgo": {"leaf", "C"},
	} {
		t.Run(name, func(t *testing.T) {
			findings := unallowedImports(probe.module, allowedImportsFor(t, probe.module),
				map[string][]string{probe.spec: {"second_implementation.go"}})
			require.NotEmpty(t, findings,
				"%q is not on the %s allowlist and must be a finding", probe.spec, probe.module)
			if probe.spec == "C" {
				// THE DIAGNOSIS, not only the refusal. `"C"` is refused by the
				// allowlist anyway — a mutation of the cgo branch changed
				// nothing — so what that branch is for is saying WHY: cgo is
				// not a package whose name a reviewer can add to a list, it is
				// an exit from every rule here, and a reader told "not on the
				// allowlist" would reasonably try adding it.
				require.Contains(t, strings.Join(findings, "\n"), "cgo is not an import path")
			}
		})
	}

	// And every import the tree really has stays allowed, so this is not green
	// by refusing everything — which is also the mutation guard for the cases
	// above.
	for _, module := range []string{"root", "leaf"} {
		allowed := allowedImportsFor(t, module)
		used := map[string][]string{}
		for _, spec := range allowed {
			used[spec] = []string{"real.go"}
		}
		require.Empty(t, unallowedImports(module, allowed, used),
			"module %s refuses an import it actually has", module)
	}
}

// loadedModule is one module's type-checked packages.
type loadedModule struct {
	name     string
	dir      string
	packages []*packages.Package
}

// relative is a file's path relative to the REPOSITORY root, so a finding reads
// the same way whichever module it is in.
func (m loadedModule) relative(loaded *packages.Package, file *ast.File) string {
	position := loaded.Fset.Position(file.Pos())
	if position.Filename == "" {
		return ""
	}
	repository, err := filepath.Abs("..")
	if err != nil {
		return ""
	}
	path, err := filepath.Rel(repository, position.Filename)
	if err != nil || strings.HasPrefix(path, "..") {
		return ""
	}
	return filepath.ToSlash(path)
}

// loadModules type-checks both modules with x/tools/go/packages.
//
// TESTDATA IS INCLUDED, which a syntactic walk had skipped: a reviewer put a
// complete Ed25519 signer under receipts/testdata/ and imported it from a root
// file. The go tool excludes `testdata` from WILDCARD matching, not from
// importing, so a package there is shipped code that no `./...` ever mentions.
// It is loaded by explicit pattern for that reason.
// loadModules type-checks both modules ONCE per test binary.
//
// Cached because it is not cheap: the leaf suite went from 60s to 247s when the
// type-checked gates arrived, and every one of them was re-running the same
// load. The result is read-only — findings are computed from it, nothing
// mutates it — so one load serves every test, and the gates stay fast enough
// that nobody is tempted to skip them.
func loadModules(t *testing.T) []loadedModule {
	t.Helper()
	loadOnce.Do(func() { loadedModules, loadErr = loadBothModules() })
	require.NoError(t, loadErr)
	require.NotEmpty(t, loadedModules)
	return loadedModules
}

var (
	loadOnce      sync.Once
	loadedModules []loadedModule
	loadErr       error
)

func loadBothModules() ([]loadedModule, error) {
	repository, err := filepath.Abs("..")
	if err != nil {
		return nil, fmt.Errorf("resolve the repository root: %w", err)
	}

	modules := []loadedModule{
		{name: "root", dir: repository},
		{name: "leaf", dir: filepath.Join(repository, "workcontext")},
	}
	for index := range modules {
		found, err := testdataPackages(modules[index].dir)
		if err != nil {
			return nil, err
		}
		patterns := append([]string{"./..."}, found...)
		loaded, err := packages.Load(&packages.Config{
			Mode: packages.NeedName | packages.NeedFiles | packages.NeedSyntax |
				packages.NeedTypes | packages.NeedTypesInfo | packages.NeedDeps |
				packages.NeedImports,
			Dir:   modules[index].dir,
			Tests: true,
		}, patterns...)
		if err != nil {
			return nil, fmt.Errorf("loading module %s: %w", modules[index].name, err)
		}
		if len(loaded) == 0 {
			return nil, fmt.Errorf("module %s loaded no packages", modules[index].name)
		}
		for _, one := range loaded {
			// A package that does not type-check is a package this gate has not
			// read, and a gate that passes what it could not read is the
			// fail-open this repository has now fixed five times.
			for _, problem := range one.Errors {
				return nil, fmt.Errorf(
					"module %s: %s did not type-check: %s. The type-based rules cannot run on a "+
						"package that does not compile, and skipping it would be a gate reporting "+
						"success for code it never read",
					modules[index].name, one.PkgPath, problem)
			}
		}
		modules[index].packages = loaded
	}
	return modules, nil
}

// testdataPatterns names every package under a testdata directory, which
// `./...` deliberately does not match.
func testdataPatterns(t *testing.T, dir string) []string {
	t.Helper()
	patterns, err := testdataPackages(dir)
	require.NoError(t, err)
	return patterns
}

func testdataPackages(dir string) ([]string, error) {
	var patterns []string
	walkErr := filepath.WalkDir(dir, func(path string, entry os.DirEntry, err error) error {
		if err != nil || !entry.IsDir() {
			return err //nolint:wrapcheck // the walk's own error, returned as-is
		}
		switch entry.Name() {
		case ".git", ".github", ".claude", "node_modules":
			return filepath.SkipDir
		}
		if entry.Name() != "testdata" {
			return nil
		}
		relative, relErr := filepath.Rel(dir, path)
		if relErr != nil {
			return relErr //nolint:wrapcheck // the walk's own error
		}
		patterns = append(patterns, "./"+filepath.ToSlash(relative)+"/...")
		return filepath.SkipDir
	})
	if walkErr != nil {
		return nil, fmt.Errorf("walk %s for testdata: %w", dir, walkErr)
	}
	sort.Strings(patterns)
	return patterns, nil
}

// typesAreAvailable is a guard on the loader itself: if NeedTypes ever stops
// being requested, every type-based rule below silently answers "nothing to
// see" and the gate goes green by reading nothing.
func TestTheGateActuallyHasTypeInformation(t *testing.T) {
	var checked int
	for _, module := range loadModules(t) {
		for _, loaded := range module.packages {
			if loaded.TypesInfo == nil || loaded.Types == nil {
				continue
			}
			for expression, kind := range loaded.TypesInfo.Types {
				if kind.Type != nil && expression != nil {
					checked++
					break
				}
			}
		}
	}
	require.Positive(t, checked,
		"no package carried type information, so every go/types rule in this gate "+
			"was deciding nothing. A gate with no inputs passes everything.")
	var _ types.Type = types.Typ[types.Bool] // the import is load-bearing above
}

// THE GATE READS EVERY SHIPPED FILE, asserted against git rather than assumed.
//
// This is the half of the one-implementation rule that the shared policy file
// did not close. `packages.Load` builds for ONE configuration, so a file the
// current build does not select is a file the type-checked gates never see:
// GOOS/GOARCH or custom build tags, cgo under CGO_ENABLED=0, a directory
// beginning with `_` or `.`, a nested module, a `vendor/` tree. The sweep reads
// every tracked file regardless of tags (go/parser ignores them), so a
// prohibited IMPORT there is still caught — what is not caught is every
// semantic rule: the codec rule, the capability walk, the envelope rule.
//
// "Every source file is checked regardless of build tags" was true of the
// syntactic scanners and stopped being true when the type-checked gates
// arrived. So the claim is now a test: what the loader read must equal what the
// repository ships. Today they are equal; the day somebody adds a
// build-constrained file this fails, and the answer is to load that
// configuration too or to refuse the file — not to let it through unread.
//
// It also subsumes the testdata claim. A reviewer struck
// TestTestdataIsNotAHidingPlace for checking the helper and never that the gate
// LOADS a testdata package: `git ls-files` lists one, so this is what would
// fail if the loader skipped it.
func TestTheGateReadsEveryShippedFile(t *testing.T) {
	tracked := trackedGoFiles(t)
	require.NotEmpty(t, tracked, "git listed no Go files, so this asserted nothing")

	read := map[string]bool{}
	for _, module := range loadModules(t) {
		for _, loaded := range module.packages {
			for _, file := range loaded.Syntax {
				path := module.relative(loaded, file)
				if path != "" && !strings.HasSuffix(path, "_test.go") {
					read[path] = true
				}
			}
		}
	}

	var unread []string
	for _, path := range tracked {
		if !read[path] {
			unread = append(unread, path)
		}
	}
	require.Empty(t, unread,
		"these files are shipped and the type-checked gates never read them: %v.\n"+
			"packages.Load builds for ONE configuration, so a build-constrained file, a cgo\n"+
			"file under CGO_ENABLED=0, a `_`-prefixed directory, a nested module or a vendor\n"+
			"tree is invisible to every semantic rule here — the codec rule, the capability\n"+
			"walk, the envelope rule. The import sweep still reads them, so an import ban\n"+
			"holds; nothing else does. Load that configuration too, or refuse the file.",
		unread)

	// And the loader must not be reading files git does not track, which would
	// mean it is answering about something other than what ships.
	trackedSet := map[string]bool{}
	for _, path := range tracked {
		trackedSet[path] = true
	}
	var untracked []string
	for path := range read {
		if !trackedSet[path] {
			untracked = append(untracked, path)
		}
	}
	require.Empty(t, untracked,
		"the gates read files this repository does not track: %v", untracked)
}

// NO GATE HERE READS ASSEMBLY OR C, so none may be shipped.
//
// Every rule in this repository is about Go: `go/parser` for the sweep,
// `go/types` for the codec rule. A `.s` file can implement anything at all, a
// `.syso` is already-compiled object code linked in whole, and a `.c` compiled
// through cgo is outside the language. There is no honest need for any of them
// in an SDK whose job is resolving values — and `import "C"` is already refused
// by name, so this is the other half of that.
func TestNoSourceNoGateCanReadIsShipped(t *testing.T) {
	run := exec.Command("git", "ls-files", "--",
		"*.s", "*.S", "*.syso", "*.a", "*.o", "*.c", "*.cc", "*.cpp", "*.cxx",
		"*.h", "*.hh", "*.hpp", "*.m", "*.mm")
	run.Dir = ".."
	output, err := run.Output()
	require.NoError(t, err)

	var shipped []string
	for _, line := range strings.Split(strings.TrimSpace(string(output)), "\n") {
		if trimmed := strings.TrimSpace(line); trimmed != "" {
			shipped = append(shipped, trimmed)
		}
	}
	require.Empty(t, shipped,
		"these files are shipped and no gate in this repository can read them: %v.\n"+
			"Every rule here is about Go — go/parser for the import sweep, go/types for the\n"+
			"codec rule — so assembly, object code and C are outside all of them. A .s file\n"+
			"can implement anything; a .syso is compiled code linked in whole. `import \"C\"`\n"+
			"is already refused by name and this is the other half of it.",
		shipped)
}

// trackedGoFiles is every non-test Go file this repository ships, from git.
func trackedGoFiles(t *testing.T) []string {
	t.Helper()
	run := exec.Command("git", "ls-files", "--", "*.go")
	run.Dir = ".."
	output, err := run.Output()
	require.NoError(t, err)

	var files []string
	for _, line := range strings.Split(strings.TrimSpace(string(output)), "\n") {
		path := strings.TrimSpace(line)
		if path == "" || strings.HasSuffix(path, "_test.go") {
			continue
		}
		files = append(files, path)
	}
	return files
}
