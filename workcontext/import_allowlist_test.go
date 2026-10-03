package workcontext

import (
	"fmt"
	"go/ast"
	"go/types"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
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

// allowedImports is every import path a module's non-test code may use.
//
// Measured from the tree with `go list`, not written from memory, and the test
// below fails in BOTH directions: an import that is not here is a finding, and
// an entry here that nothing imports is deleted, because a permission nobody
// uses is precedent for the next reader.
var allowedImports = map[string][]string{
	"root": {
		"bufio", "bytes", "context", "database/sql", "embed",
		"encoding/binary", "encoding/json", "errors", "fmt", "io", "os",
		"path/filepath", "runtime/debug", "sort", "strconv", "strings",
		"sync", "time",
		// scripts/importsof reads a Go file's imports WITH GO'S OWN PARSER,
		// because the sweep's awk extractor was walked past five more times —
		// `import "\x63rypto/ed25519"` compiles, is crypto/ed25519 to the
		// compiler, and is not that string to anything matching text. It is a
		// main package that ships to nobody; being here is what makes it
		// visible rather than exempt.
		"go/parser", "go/token",
		// The ONE hash, for three digests. A hand-rolled HMAC over it is the
		// residue named above.
		"crypto/sha256",
		// The workload's own TLS, which is this module's job.
		"crypto/tls", "crypto/x509",
		"connectrpc.com/connect",
		"github.com/codefly-dev/core/composition",
		"github.com/codefly-dev/core/configurations",
		"github.com/codefly-dev/core/generated/go/codefly/base/v0",
		"github.com/codefly-dev/core/generated/go/codefly/runnable/v0",
		"github.com/codefly-dev/core/network",
		"github.com/codefly-dev/core/resources",
		"github.com/codefly-dev/core/runnable",
		"github.com/codefly-dev/core/standards",
		"github.com/codefly-dev/core/wool",
		"github.com/codefly-dev/sdk-go/receipts",
		"google.golang.org/grpc",
		"google.golang.org/grpc/codes",
		"google.golang.org/grpc/metadata",
		"google.golang.org/grpc/status",
		// The receipts digest canonicalises a receipt REQUEST, never a
		// capability, and the replay path resolves a response type at runtime.
		// Each is held to files and symbols by the rules in
		// one_implementation_test.go; being on this list is necessary and not
		// sufficient.
		"google.golang.org/protobuf/encoding/protojson",
		"google.golang.org/protobuf/proto",
		"google.golang.org/protobuf/reflect/protodesc",
		"google.golang.org/protobuf/reflect/protoreflect",
		"google.golang.org/protobuf/reflect/protoregistry",
		"google.golang.org/protobuf/types/descriptorpb",
		"google.golang.org/protobuf/types/dynamicpb",
		"google.golang.org/protobuf/types/known/durationpb",
	},
	"leaf": {
		"bytes", "context", "encoding/binary", "encoding/hex", "errors",
		"fmt", "io", "mime", "net/http", "net/url", "os", "slices",
		"strconv", "strings", "sync", "sync/atomic", "time",
		"crypto/sha256",
		"crypto/tls", "crypto/x509",
		// Held to ENCODE-only in one file, and to two types in one file,
		// by the rules in one_implementation_test.go.
		"encoding/base64", "encoding/json",
		"github.com/codefly-dev/core/generated/go/codefly/base/v0",
		"github.com/codefly-dev/core/workcontext",
		"github.com/codefly-dev/sdk-go/workcontext",
		"google.golang.org/grpc",
		"google.golang.org/grpc/codes",
		"google.golang.org/grpc/metadata",
		"google.golang.org/grpc/status",
		"google.golang.org/protobuf/proto",
	},
}

// TestEveryImportIsOnItsModulesAllowlist is the deny-by-default rule.
func TestEveryImportIsOnItsModulesAllowlist(t *testing.T) {
	for _, module := range loadModules(t) {
		_, ok := allowedImports[module.name]
		require.True(t, ok, "no allowlist for module %q", module.name)

		for _, finding := range unallowedImports(module.name, importsOfModule(t, module)) {
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
		for _, spec := range allowedImports[module.name] {
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
	repository, err := filepath.Abs("..")
	require.NoError(t, err)
	// A real package under testdata, created for this test and removed with it.
	directory := filepath.Join(repository, "receipts", "testdata", "gateprobe")
	require.NoError(t, os.MkdirAll(directory, 0o750))
	t.Cleanup(func() {
		_ = os.RemoveAll(filepath.Join(repository, "receipts", "testdata"))
	})
	require.NoError(t, os.WriteFile(filepath.Join(directory, "signer.go"),
		[]byte(`package gateprobe

import "crypto/ed25519"

// Sign is the shape a reviewer imported from a root file.
func Sign(key ed25519.PrivateKey, payload []byte) []byte {
	return ed25519.Sign(key, payload)
}
`), 0o600))

	patterns := testdataPatterns(t, repository)
	require.Contains(t, patterns, "./receipts/testdata/...",
		"the loader must be given the testdata packages explicitly; ./... does not match them")

	// And the rule refuses it, which is the point of reaching it.
	findings := unallowedImports("root", map[string][]string{
		"crypto/ed25519": {"receipts/testdata/gateprobe/signer.go"},
	})
	require.NotEmpty(t, findings, "a signer under testdata is still a signer")
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
func unallowedImports(module string, used map[string][]string) []string {
	allowed := allowedImports[module]
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
			findings := unallowedImports(probe.module, map[string][]string{
				probe.spec: {"second_implementation.go"},
			})
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
		used := map[string][]string{}
		for _, spec := range allowedImports[module] {
			used[spec] = []string{"real.go"}
		}
		require.Empty(t, unallowedImports(module, used),
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
func loadModules(t *testing.T) []loadedModule {
	t.Helper()
	repository, err := filepath.Abs("..")
	require.NoError(t, err)

	modules := []loadedModule{
		{name: "root", dir: repository},
		{name: "leaf", dir: filepath.Join(repository, "workcontext")},
	}
	for index := range modules {
		patterns := append([]string{"./..."}, testdataPatterns(t, modules[index].dir)...)
		loaded, err := packages.Load(&packages.Config{
			Mode: packages.NeedName | packages.NeedFiles | packages.NeedSyntax |
				packages.NeedTypes | packages.NeedTypesInfo | packages.NeedDeps |
				packages.NeedImports,
			Dir:   modules[index].dir,
			Tests: true,
		}, patterns...)
		require.NoError(t, err, "loading module %s", modules[index].name)
		require.NotEmpty(t, loaded, "module %s loaded no packages", modules[index].name)
		for _, one := range loaded {
			// A package that does not type-check is a package this gate has not
			// read, and a gate that passes what it could not read is the
			// fail-open this repository has now fixed four times.
			for _, problem := range one.Errors {
				t.Fatalf("module %s: %s did not type-check: %s.\n"+
					"The type-based rules cannot run on a package that does not compile, and "+
					"skipping it would be a gate reporting success for code it never read.",
					modules[index].name, one.PkgPath, problem)
			}
		}
		modules[index].packages = loaded
	}
	return modules
}

// testdataPatterns names every package under a testdata directory, which
// `./...` deliberately does not match.
func testdataPatterns(t *testing.T, dir string) []string {
	t.Helper()
	var patterns []string
	require.NoError(t, filepath.WalkDir(dir, func(path string, entry os.DirEntry, err error) error {
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
		patterns = append(patterns, "./"+filepath.ToSlash(mustRel(t, dir, path))+"/...")
		return filepath.SkipDir
	}))
	sort.Strings(patterns)
	return patterns
}

func mustRel(t *testing.T, base string, path string) string {
	t.Helper()
	relative, err := filepath.Rel(base, path)
	require.NoError(t, err)
	return relative
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
