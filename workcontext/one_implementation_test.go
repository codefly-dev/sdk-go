package workcontext

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	corework "github.com/codefly-dev/core/workcontext"
	"github.com/codefly-dev/core/workcontext/conformance"
	"github.com/stretchr/testify/require"
)

// The aliases in core.go are core's types and not this module's copies of
// them. These declarations compile only while that is true: a named type
// declared here, however identical its fields, would not be assignable to
// core's pointer type, and the gate below would be guarding a surface that had
// already forked.
var (
	_ *corework.Verifier        = (*Verifier)(nil)
	_ *corework.Verified        = (*Verified)(nil)
	_ corework.Seal             = Seal{}
	_ corework.OperationBinding = OperationBinding{}
)

// cryptoImplementationPackages are the packages a second implementation would
// have to reach for. Neither may be imported by anything in this module: this
// module presents capabilities and reads the sealed values off ones the host
// issued it, and it neither signs nor checks a signature.
var cryptoImplementationPackages = []string{"crypto/ed25519", "crypto/ecdsa"}

// jsonAllowlist is every non-test file that may import encoding/json, and why.
//
// The ban exists because the second implementation this module used to hold
// signed a hand-written JSON payload. The one remaining use is not a token at
// all: it is the body of the host's mint endpoint, an ordinary HTTP API whose
// request is two strings and whose response hands back an opaque capability.
// The capability itself never passes through a JSON codec here — it arrives as
// a string and is read with core's generated type — and the second assertion
// below is what holds that apart from the first, by refusing a JSON-tagged
// struct anywhere in the module except that request and that response.
var jsonAllowlist = map[string]string{
	"mint.go": "the mint endpoint's HTTP request and response bodies, which carry the capability as an opaque string",
}

// mintEndpointJSONTypes are the only structs in this module that may carry
// json tags. They are the mint endpoint's two bodies. A payload struct pair for
// a capability — the shape of the implementation this module deleted — is a
// third entry here, which is a failing test rather than a review comment
// somebody might not leave.
var mintEndpointJSONTypes = []string{"mintRequest", "mintResponse"}

// TestNoSecondWorkContextImplementation is the gate.
//
// A wire contract has exactly one implementation, in the repository that owns
// the type. The Work Context is a core proto, so core's workcontext package is
// the only mint and the only verify, and this module is a client of it. That
// rule was broken once: a second implementation here signed a hand-written
// JSON payload while core signed the deterministic protobuf encoding of the
// same message, and because both forms are "<payload>.<signature>" with
// Ed25519, a token from either looked well-formed to the other and then failed
// SIGNATURE verification. "Signature does not verify under key X" reads like a
// rotated key, so keys are what everyone investigated.
//
// A comment would not have stopped that and did not. This does, structurally,
// in four parts: nothing here may reach for a signing primitive, nothing may
// JSON-encode a capability, nothing may declare a type or function that reads
// as a second WorkContext surface, and the verification entrypoint this module
// exports is driven by core's own conformance fixtures.
//
// It guards the tree it runs in, which is all a test can do: a branch's CI run
// uses that branch's own tree, so this file never executes on the release lines
// that still carry the deleted implementation.
// scripts/check-one-implementation.sh is the other half — it reads every ref CI
// builds out of the object database — and docs/cutover.md says when those refs
// are retired and by whom.
func TestNoSecondWorkContextImplementation(t *testing.T) {
	files := moduleFiles(t)
	require.NotEmpty(t, files, "the gate scanned no files, so it would pass for an empty module")

	packages := map[string]bool{}
	jsonImporters := []string{}
	for _, file := range files {
		packages[filepath.Dir(file.path)] = true
		for _, path := range importsOf(file.syntax) {
			if slices.Contains(cryptoImplementationPackages, path) {
				t.Errorf(
					"%s imports %q.\n"+
						"This module signs nothing and verifies nothing: core's workcontext is the only\n"+
						"implementation of the capability. If a signature has to be checked, it is checked\n"+
						"by core's Verifier, reached through the alias in core.go.",
					file.path, path,
				)
			}
			if path == "encoding/json" {
				jsonImporters = append(jsonImporters, filepath.Base(file.path))
			}
		}
		checkDeclarations(t, file)
	}

	for _, importer := range jsonImporters {
		reason, allowed := jsonAllowlist[importer]
		require.True(t, allowed,
			"%s imports encoding/json.\n"+
				"A capability is a protobuf message, signed by core over its deterministic encoding.\n"+
				"The only JSON in this module is %v — the mint endpoint's HTTP bodies. If a capability\n"+
				"is being JSON-encoded here, that is the second implementation coming back.",
			importer, allowedJSONFiles())
		require.NotEmpty(t, reason)
	}

	require.GreaterOrEqual(t, len(packages), 2,
		"the gate found %d package(s) in this module; it is meant to scan every one, "+
			"so a package it cannot see is a package the rule does not reach", len(packages))
}

// checkDeclarations refuses a declaration that reads as a second WorkContext
// surface, and a json tag outside the mint endpoint's two bodies.
func checkDeclarations(t *testing.T, file sourceFile) {
	t.Helper()
	for _, declaration := range file.syntax.Decls {
		switch declared := declaration.(type) {
		case *ast.FuncDecl:
			if declared.Recv == nil && strings.HasPrefix(declared.Name.Name, "WorkContext") {
				t.Errorf(
					"%s declares func %s.\n"+
						"A WorkContext-named function here is how the second implementation looked. The\n"+
						"capability's own operations are core's; this module names what it does to one\n"+
						"(Attach, FromHeaders, SealedInstallation) and re-exports core's for the rest.",
					file.path, declared.Name.Name,
				)
			}
		case *ast.GenDecl:
			for _, spec := range declared.Specs {
				typed, ok := spec.(*ast.TypeSpec)
				if !ok {
					continue
				}
				if typed.Assign == 0 && strings.HasPrefix(typed.Name.Name, "WorkContext") {
					t.Errorf(
						"%s declares type %s, which is not an alias of core's.\n"+
							"The capability's types are core's. Alias them (type X = corework.X) so there is\n"+
							"one definition, or name what this module adds without naming the capability.",
						file.path, typed.Name.Name,
					)
				}
				checkJSONTags(t, file, typed)
			}
		}
	}
}

// checkJSONTags refuses a json-tagged struct outside the mint endpoint. The
// deleted implementation's signed payload was exactly this: a struct whose
// tags enumerated a capability's fields by hand, which is why a field present
// in the proto and absent from the struct was dropped at mint and missing at
// verify.
func checkJSONTags(t *testing.T, file sourceFile, typed *ast.TypeSpec) {
	t.Helper()
	structure, ok := typed.Type.(*ast.StructType)
	if !ok || structure.Fields == nil {
		return
	}
	for _, field := range structure.Fields.List {
		if field.Tag == nil {
			continue
		}
		tag, err := strconv.Unquote(field.Tag.Value)
		if err != nil || !strings.Contains(tag, `json:"`) {
			continue
		}
		if reflect.StructTag(tag).Get("json") == "" {
			continue
		}
		require.Contains(t, mintEndpointJSONTypes, typed.Name.Name,
			"%s declares type %s with json tags.\n"+
				"Only the mint endpoint's bodies (%v) are JSON here. A JSON-tagged struct describing a\n"+
				"capability's fields is the second implementation: core signs the deterministic protobuf\n"+
				"encoding, and a field enumerated by hand is a field dropped at mint and absent at verify.",
			file.path, typed.Name.Name, mintEndpointJSONTypes)
		return
	}
}

// TestWorkContextConformance drives core's own fixtures against the
// verification entrypoint this module exports, which is core's Verifier.
//
// It is the half of the gate the static checks cannot make: a module could
// import no signing primitive and still hand a consumer a verifier that
// answered differently from core's. The decisive fixture is the foreign
// encoding — a JSON-shaped token that must be refused BEFORE its signature is
// checked, with ErrNotACoreToken. A second implementation refuses that token
// too, but as a signature failure, which is the misdiagnosis this whole rule
// exists to prevent.
func TestWorkContextConformance(t *testing.T) {
	settings := conformance.New(time.Now())
	verifier := settings.Verifier()
	conformance.RunWith(t, settings, func(ctx context.Context, token string) error {
		_, err := verifier.Verify(ctx, token)
		return err
	})
}

type sourceFile struct {
	path   string
	syntax *ast.File
}

// moduleFiles parses every non-test Go file in this module. The walk starts at
// the module root, which is this package's directory, so a new package added
// beside grpctransport is scanned without anyone remembering to list it.
func moduleFiles(t *testing.T) []sourceFile {
	t.Helper()
	var files []sourceFile
	fileSet := token.NewFileSet()
	require.NoError(t, filepath.WalkDir(".", func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			if entry.Name() == "testdata" {
				return fs.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		syntax, parseErr := parser.ParseFile(fileSet, path, nil, parser.SkipObjectResolution)
		if parseErr != nil {
			return parseErr
		}
		files = append(files, sourceFile{path: path, syntax: syntax})
		return nil
	}))
	return files
}

func importsOf(file *ast.File) []string {
	paths := make([]string, 0, len(file.Imports))
	for _, imported := range file.Imports {
		path, err := strconv.Unquote(imported.Path.Value)
		if err != nil {
			continue
		}
		paths = append(paths, path)
	}
	return paths
}

func allowedJSONFiles() []string {
	names := make([]string, 0, len(jsonAllowlist))
	for name := range jsonAllowlist {
		names = append(names, name)
	}
	slices.Sort(names)
	return names
}
