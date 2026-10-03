package workcontext

import (
	"context"
	"fmt"
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

// bannedImports, bannedImportPrefixes and bannedImportSubstrings are every way
// into a signature or a second encoding of the message. An import matching any
// of them is refused OUTRIGHT — with no "and the file also mentions WorkContext"
// conjunction, because a conjunction is satisfied by putting the signer in one
// file and the wrapper in another.
//
// The previous version of this gate listed exactly "crypto/ed25519" and
// "crypto/ecdsa", which made it a gate about two strings. All of these passed
// it: golang.org/x/crypto/ed25519; crypto/rsa and crypto/hmac; the bare crypto
// package, whose crypto.Signer signs Ed25519 with no ed25519 import anywhere;
// and protojson, which is a second encoding of the message by itself. A
// faithful clone of core's signer — proto.MarshalOptions{Deterministic: true}
// plus x/crypto — was green.
var (
	bannedImports = []string{
		// The bare package: crypto.Signer and crypto.Hash are all a signer
		// needs once a key has been parsed out of a PKCS#8 blob.
		"crypto",
		"crypto/ed25519", "crypto/ecdsa", "crypto/rsa", "crypto/dsa",
		"crypto/hmac", "crypto/ecdh", "crypto/elliptic", "crypto/subtle",
		// Second encodings of the message. encoding/json is handled separately
		// because one file is allowed it for the mint endpoint's HTTP bodies.
		"google.golang.org/protobuf/encoding/protojson",
		"google.golang.org/protobuf/encoding/protowire",
		"google.golang.org/protobuf/types/known/anypb",
		"encoding/gob", "encoding/asn1", "encoding/xml",
	}

	// envelopeDecoders are banned EXCEPT where a file is allowlisted below. A
	// second parser applying its own seal rule was the last blocker here, and
	// it needed exactly this: base64 to open the envelope by hand, and
	// proto.Unmarshal to read it. corework.Inspect does both now and hands back
	// the claims, so opening an envelope here has no honest use.
	envelopeDecoders = []string{"encoding/base64"}

	// envelopeDecoderAllowlist is every file that may reach for one, and what
	// it does with it — which is never a capability.
	envelopeDecoderAllowlist = map[string]string{
		"cache_partition.go": "ENCODES a tenant and installation id into a cache key; it opens no envelope",
	}
	bannedImportPrefixes = []string{"golang.org/x/crypto/"}
	// Any JOSE, JWT or token-library path, whoever publishes it. A capability
	// here is core's protobuf envelope; a library that mints bearer tokens has
	// no honest use in this module.
	bannedImportSubstrings = []string{"jose", "jwt", "jwx", "paseto", "macaroon", "branca"}
)

// tlsPlumbing is the narrow exception: the mint client builds and owns its own
// transport, which needs crypto/tls for the configuration and crypto/x509 for
// the caller's root pool. Both are refused everywhere else, and even there only
// these SYMBOLS may be used — so x509.ParsePKCS8PrivateKey, which is how a
// signer gets a key without importing ed25519, is a finding rather than a
// permitted use of an allowed import.
//
// crypto/sha256 is deliberately absent from every list: a hash is not a
// signature, and the cache partition's digest preimage needs one.
var tlsPlumbing = map[string]struct {
	files   []string
	symbols []string
}{
	"crypto/tls": {
		files:   []string{"mint.go"},
		symbols: []string{"Config", "VersionTLS12", "VersionTLS13"},
	},
	"crypto/x509": {
		files:   []string{"mint.go"},
		symbols: []string{"CertPool", "NewCertPool", "SystemCertPool"},
	},
}

// codecAllowlist is the only codec use in this module: a file, the codec
// operation, and THE TYPE it may be applied to.
//
// The type is the part that was missing. The exemptions used to be per FILE, so
// cache_partition.go — allowed proto.Marshal for a scope — could marshal a
// *Claims, and mint.go — allowed encoding/json for two tagged structs — could
// json.Marshal a map[string]any holding a capability's fields, needing no tags
// at all. Both were reproduced as AST probes that produced zero findings. A
// whole-file exemption is an exemption for every type in the file.
var codecAllowlist = []codecUse{
	{file: "mint.go", operations: jsonOperations, types: mintEndpointJSONTypes,
		reason: "the mint endpoint's two HTTP bodies, which carry the capability as an opaque string"},
	{file: "mint.go", operations: jsonValueOperations,
		types: append(append([]string{}, mintEndpointJSONTypes...), "RawMessage"),
		reason: "the same two bodies, plus a RawMessage the response decoder reads into to " +
			"require EOF — it holds nothing and is discarded"},
	{file: "cache_partition.go", operations: protoOperations, types: []string{"WorkScopeV1"},
		reason: "one scope, for the cache digest preimage — never a capability"},
}

type codecUse struct {
	file       string
	operations []string
	types      []string
	reason     string
}

var (
	// The operations that take the VALUE. NewDecoder and NewEncoder are not
	// among them: they take a reader or a writer and encode nothing, and the
	// type that matters is the one handed to Decode or Encode afterwards —
	// which is checked separately, because its receiver is a local variable
	// rather than the package.
	jsonOperations      = []string{"Marshal", "Unmarshal"}
	jsonValueOperations = []string{"Decode", "Encode"}
	protoOperations     = []string{"Marshal", "MarshalOptions", "Unmarshal", "UnmarshalOptions"}
)

// permittedCodecTypes is the set of type names a codec operation may be applied
// to in this file, or nil when the file may use no codec at all.
func permittedCodecTypes(path string, operation string) []string {
	for _, use := range codecAllowlist {
		if use.file == path && slices.Contains(use.operations, operation) {
			return use.types
		}
	}
	return nil
}

// workContextNameAllowlist is this module's own declarations whose names begin
// with the capability's, with the reason each is not a second surface. The name
// check is case-insensitive and covers every declaration kind, so the module's
// legitimate carrier constants have to be named here rather than slipping
// through on capitalisation.
var workContextNameAllowlist = map[string]string{
	"workContextGRPCMetadataName": "the gRPC metadata key, which is workcontext.HeaderName and not a second name",
	"workContext":                 "the opaque capability string a transport carries",
	"workContexts":                "the metadata values read for that key",
	"WorkContext":                 "the mint response body's JSON field for the capability string",
}

// jsonAllowlist is every non-test file that may import encoding/json, keyed by
// its path RELATIVE TO THE MODULE ROOT, and why.
//
// The path is exact on purpose. It used to be matched on the base name, so any
// file called mint.go anywhere in the tree — grpctransport/mint.go, a new
// package's mint.go — inherited the allowance, which is the whole allowlist
// undone by `touch`.
//
// The ban exists because the second implementation this module used to hold
// signed a hand-written JSON payload. The one remaining use is not a token at
// all: it is the body of the host's mint endpoint, an ordinary HTTP API whose
// request is two strings and whose response hands back an opaque capability.
// The capability itself never passes through a JSON codec here — it arrives as
// a string and is read with core's generated type — and the json-tag check
// below is what holds that apart, by refusing a json-tagged struct anywhere in
// the module except that request and that response.
var jsonAllowlist = map[string]string{
	"mint.go": "the mint endpoint's HTTP request and response bodies, which carry the capability as an opaque string",
}

// mintEndpointJSONTypes are the only structs in this module that may carry
// json tags, and mintEndpointJSONFile is the only file they may be declared in.
//
// The pair matters. Allowing them by NAME alone let any file declare a type
// called mintRequest or mintResponse and inherit the exemption — so
// `extra/payload.go` could hold a json-tagged `mintRequest` enumerating a
// capability's fields by hand, which is precisely the deleted implementation,
// and the gate would be green. The exemption is a property of one file's two
// declarations, not of two identifiers.
//
// A payload struct pair for a capability is a third entry here, which is a
// failing test rather than a review comment somebody might not leave.
var (
	mintEndpointJSONTypes = []string{"mintRequest", "mintResponse"}
	mintEndpointJSONFile  = "mint.go"
)

// coreModulePath is the module whose types this one aliases. An alias has to
// resolve into it, or it is a local type wearing core's name.
const coreModulePath = "github.com/codefly-dev/core"

// TestNoSecondWorkContextImplementation is the gate.
//
// A wire contract has exactly one implementation, in the repository that owns
// the type. The Work Context is a core proto, so core's workcontext package is
// the only mint and the only verify, and this module is a client of it. That
// rule was broken once: a second implementation here signed a hand-written
// JSON payload while core signed the deterministic protobuf encoding of the
// same message, and because both forms are "<payload>.<signature>" with
// Ed25519, a token from either looked well-formed to the other.
//
// The signature itself was sound — each side signed the bytes it sent, and each
// side verified the bytes it received. What broke was READING the payload before
// verifying it: the key id is a field inside the payload, so a protobuf payload
// read as JSON (or the reverse) yielded no key id or a wrong one, and the
// failure surfaced as "unknown key" or "signature does not verify under key X".
// Both read like a rotated key, so keys are what everyone investigated, for
// days. That is also why ErrNotACoreToken has to be returned BEFORE any key
// lookup: naming the format is the only diagnosis that points at the format.
//
// A comment would not have stopped that and did not. This does, structurally,
// in four parts: nothing here may reach for a signing primitive, nothing may
// JSON-encode a capability, nothing may declare a type or function that reads
// as a second WorkContext surface — including inside a function body, and
// including an alias whose target is not core's — and the verification
// entrypoint this module exports is driven by core's own conformance fixtures.
//
// It guards the tree it runs in, which is all a test can do, and it walks from
// this module's root — so the rest of the repository, where the deleted
// implementation actually lived, is swept by
// scripts/check-one-implementation.sh instead. That sweep is a required check
// and it is green.
func TestNoSecondWorkContextImplementation(t *testing.T) {
	files := moduleFiles(t)
	require.NotEmpty(t, files, "the gate scanned no files, so it would pass for an empty module")

	packages := map[string]bool{}
	var findings []string
	for _, file := range files {
		packages[filepath.Dir(file.path)] = true
		findings = append(findings, inspectForSecondImplementation(file)...)
	}
	require.Empty(t, findings, "%s", strings.Join(findings, "\n\n"))

	require.GreaterOrEqual(t, len(packages), 2,
		"the gate found %d package(s) in this module; it is meant to scan every one, "+
			"so a package it cannot see is a package the rule does not reach", len(packages))

	// The allowlist must describe files that exist. An entry for a file that
	// has been renamed or deleted is a permission nobody is using and the next
	// person reads as precedent.
	paths := map[string]bool{}
	for _, file := range files {
		paths[file.path] = true
	}
	for allowed := range jsonAllowlist {
		require.True(t, paths[allowed],
			"the json allowlist names %q, which is not a file in this module", allowed)
	}
	require.Contains(t, jsonAllowlist, mintEndpointJSONFile,
		"the file allowed to carry json TAGS must be the file allowed to IMPORT encoding/json; "+
			"two lists that can drift are two lists")
}

// inspectForSecondImplementation is the whole check over one parsed file,
// separated out so the bypasses it is supposed to catch can be driven through
// it directly rather than asserted about by eye.
func inspectForSecondImplementation(file sourceFile) []string {
	var findings []string
	coreImports := map[string]bool{}
	plumbing := map[string]string{} // local name -> allowed import path
	protoNames := map[string]bool{} // every local name google.golang.org/protobuf is reachable under
	jsonNames := map[string]bool{}  // and encoding/json
	for _, imported := range importsOf(file.syntax) {
		if imported.name == "." {
			// A dot import makes every one of a package's identifiers
			// unqualified, which defeats every symbol rule below and collided
			// in the map this used to build. Nothing here needs one.
			findings = append(findings, fmt.Sprintf(
				"%s dot-imports %q.\n"+
					"A dot import makes a package's identifiers unqualified, so every rule in this gate\n"+
					"that reasons about a qualifier stops applying — and two dot imports collided in the\n"+
					"map this check used to build, which hid whichever came first.",
				file.path, imported.path))
		}
		findings = append(findings, inspectImport(file, imported.name, imported.path, plumbing)...)
		if imported.path == coreModulePath || strings.HasPrefix(imported.path, coreModulePath+"/") {
			coreImports[imported.name] = true
		}
		if strings.HasPrefix(imported.path, "google.golang.org/protobuf") {
			protoNames[imported.name] = true
		}
		if imported.path == "encoding/json" {
			jsonNames[imported.name] = true
		}
	}
	findings = append(findings, inspectPlumbingSymbols(file, plumbing)...)
	findings = append(findings, inspectProtoEncoding(file, protoNames)...)
	findings = append(findings, inspectDeclarations(file, coreImports)...)
	findings = append(findings, inspectJSONTags(file)...)
	findings = append(findings, inspectJSONCalls(file, jsonNames)...)
	findings = append(findings, inspectJSONValueCalls(file, len(jsonNames) > 0)...)
	return findings
}

// inspectImport refuses an import by what it can DO, not by whether its path is
// one of two strings.
func inspectImport(file sourceFile, name string, path string, plumbing map[string]string) []string {
	if allowed, ok := tlsPlumbing[path]; ok {
		if slices.Contains(allowed.files, file.path) {
			plumbing[name] = path
			return nil
		}
		return []string{fmt.Sprintf(
			"%s imports %q, which only %v may: it is the mint client's own transport plumbing.",
			file.path, path, allowed.files)}
	}
	if slices.Contains(envelopeDecoders, path) {
		if reason, allowed := envelopeDecoderAllowlist[file.path]; allowed {
			_ = reason
			return nil
		}
		return []string{fmt.Sprintf(
			"%s imports %q.\n"+
				"Opening a capability's envelope by hand is the beginning of a second parser, which\n"+
				"is what this module last had to delete — its own seal rule disagreed with core's\n"+
				"fixtures about three refusals. corework.Inspect opens the envelope and returns the\n"+
				"claims. Only %v may reach for this, and only because %v.",
			file.path, path, allowedEnvelopeDecoderFiles(), envelopeDecoderReasons())}
	}
	banned := slices.Contains(bannedImports, path)
	for _, prefix := range bannedImportPrefixes {
		banned = banned || strings.HasPrefix(path, prefix)
	}
	for _, fragment := range bannedImportSubstrings {
		banned = banned || strings.Contains(strings.ToLower(path), fragment)
	}
	if banned {
		return []string{fmt.Sprintf(
			"%s imports %q.\n"+
				"This module signs nothing, verifies nothing and encodes no capability: core's\n"+
				"workcontext is the only implementation. The ban is on what a package can do rather\n"+
				"than on two package names, because crypto.Signer, x/crypto and protojson each build a\n"+
				"complete second implementation without naming ed25519 anywhere.",
			file.path, path)}
	}
	if path == "encoding/json" {
		if _, allowed := jsonAllowlist[file.path]; !allowed {
			return []string{fmt.Sprintf(
				"%s imports encoding/json.\n"+
					"A capability is a protobuf message, signed by core over its deterministic encoding.\n"+
					"The only JSON in this module is %v — the mint endpoint's HTTP bodies, named by exact\n"+
					"path. If a capability is being JSON-encoded here, that is the second implementation\n"+
					"coming back.",
				file.path, allowedJSONFiles())}
		}
	}
	return nil
}

// inspectPlumbingSymbols holds crypto/tls and crypto/x509 to the symbols the
// transport actually needs. An allowed import is not an allowed package: the
// shortest route to a signer that imports no signing primitive is
// x509.ParsePKCS8PrivateKey followed by a crypto.Signer assertion, and the
// first half of that lives in a package this module legitimately imports.
func inspectPlumbingSymbols(file sourceFile, plumbing map[string]string) []string {
	if len(plumbing) == 0 {
		return nil
	}
	var findings []string
	ast.Inspect(file.syntax, func(node ast.Node) bool {
		selector, ok := node.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		qualifier, ok := selector.X.(*ast.Ident)
		if !ok {
			return true
		}
		path, isPlumbing := plumbing[qualifier.Name]
		if !isPlumbing {
			return true
		}
		if slices.Contains(tlsPlumbing[path].symbols, selector.Sel.Name) {
			return true
		}
		findings = append(findings, fmt.Sprintf(
			"%s uses %s.%s. Only %v may be used from %q here.\n"+
				"The import is allowed for the mint client's transport, not as a way into the package:\n"+
				"x509.ParsePKCS8PrivateKey plus a crypto.Signer assertion is a complete signer that\n"+
				"imports no signing primitive at all.",
			file.path, qualifier.Name, selector.Sel.Name, tlsPlumbing[path].symbols, path))
		return true
	})
	return findings
}

// inspectProtoEncoding refuses a protobuf MARSHAL outside the one file that
// encodes something which is not a capability. Unmarshal and Clone are not
// restricted: reading a capability the host issued is this module's job, and
// writing one is core's.
func inspectProtoEncoding(file sourceFile, protoNames map[string]bool) []string {
	var findings []string
	ast.Inspect(file.syntax, func(node ast.Node) bool {
		selector, ok := node.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		qualifier, ok := selector.X.(*ast.Ident)
		// The qualifier is resolved from the IMPORT MAP rather than compared
		// against the literal "proto". An aliased import — pb.Marshal — passed
		// the identifier check, which made this a rule about a name in a gate
		// whose whole point is not to be one.
		if !ok || !protoNames[qualifier.Name] {
			return true
		}
		switch selector.Sel.Name {
		case "Marshal", "MarshalOptions":
			if codecArgumentIsPermitted(file, node, "Marshal") {
				return true
			}
		case "Unmarshal", "UnmarshalOptions":
			// Unrestricted until now, and it is half of the defect that was the
			// last blocker: a second unverified parser needs base64 to open the
			// envelope and Unmarshal to read it. corework.Inspect does both, and
			// hands back the claims, so nothing here needs either.
			if codecArgumentIsPermitted(file, node, "Unmarshal") {
				return true
			}
			findings = append(findings, fmt.Sprintf(
				"%s calls %s.%s.\n"+
					"Reading a capability off the wire is corework.Inspect's job, and it returns the\n"+
					"claims it decoded. A decode here is the beginning of a second parser — which is\n"+
					"what this module last had to delete, and its own seal rule disagreed with core's\n"+
					"fixtures about three refusals.",
				file.path, qualifier.Name, selector.Sel.Name))
			return true
		default:
			return true
		}
		findings = append(findings, fmt.Sprintf(
			"%s calls %s.%s on a type it is not allowed to.\n"+
				"Encoding the message is half of a signer: core signs the deterministic protobuf\n"+
				"encoding, so MarshalOptions{Deterministic: true} over a capability is the deleted\n"+
				"implementation with a different import list. The exemption names a FILE AND A TYPE\n"+
				"(%v), because a whole-file exemption is an exemption for every type in the file —\n"+
				"which is how a *Claims could be marshalled through the one meant for a scope.",
			file.path, qualifier.Name, selector.Sel.Name, codecAllowlist))
		return true
	})
	return findings
}

// inspectDeclarations refuses a declaration that reads as a second WorkContext
// surface, ANYWHERE in the file and WHATEVER ITS CAPITALISATION.
//
// Three things the previous version missed. It walked file.Decls, so a
// declaration inside a function body passed untouched. It accepted any alias at
// all, so `type WorkContextVerifier = mylocal.Verifier` satisfied "it is an
// alias" while aliasing nothing of core's. And it matched a case-sensitive
// "WorkContext" prefix on free functions and types only — so the deleted
// implementation's own type name, `workContextPayload`, passed it, as did a
// method, a `var WorkContextSign = func…` and a const.
//
// This is a heuristic and is NOT the load-bearing half of the gate: a name
// proves nothing, which is why the import, symbol and encoding rules above
// refuse the CAPABILITY to sign or encode whatever anything is called. It is
// kept because it catches the lazy case cheaply, and tightened so that this
// module's own carrier names must be allowlisted with a reason rather than pass
// on capitalisation.
func inspectDeclarations(file sourceFile, coreImports map[string]bool) []string {
	var findings []string
	named := func(name string) bool {
		if _, allowed := workContextNameAllowlist[name]; allowed {
			return false
		}
		return strings.HasPrefix(strings.ToLower(name), "workcontext")
	}
	report := func(kind string, name string) {
		if !named(name) {
			return
		}
		findings = append(findings, fmt.Sprintf(
			"%s declares %s %s.\n"+
				"A WorkContext-named declaration here is how the second implementation looked, and its\n"+
				"own payload type was spelled workContextPayload. The capability's operations and types\n"+
				"are core's; this module names what it DOES to one (Attach, FromHeaders,\n"+
				"SealedInstallation) and re-exports core's for the rest. If this is a legitimate\n"+
				"carrier name, add it to workContextNameAllowlist with the reason.",
			file.path, kind, name))
	}
	ast.Inspect(file.syntax, func(node ast.Node) bool {
		switch declared := node.(type) {
		case *ast.FuncDecl:
			kind := "func"
			if declared.Recv != nil {
				kind = "method"
			}
			report(kind, declared.Name.Name)
		case *ast.ValueSpec:
			for _, name := range declared.Names {
				report("var/const", name.Name)
			}
		case *ast.TypeSpec:
			if !named(declared.Name.Name) {
				return true
			}
			if declared.Assign == 0 {
				findings = append(findings, fmt.Sprintf(
					"%s declares type %s, which is not an alias of core's.\n"+
						"The capability's types are core's. Alias them (type X = corework.X) so there is\n"+
						"one definition, or name what this module adds without naming the capability.",
					file.path, declared.Name.Name))
				return true
			}
			if !aliasesCore(declared.Type, coreImports) {
				findings = append(findings, fmt.Sprintf(
					"%s declares type %s as an alias of something that is not core's.\n"+
						"Being an alias is not the guarantee; aliasing CORE'S type is. An alias of a local\n"+
						"type is a second definition with core's name on it, which is worse than a plainly\n"+
						"named one because it reads as a re-export.",
					file.path, declared.Name.Name))
			}
		}
		return true
	})
	return findings
}

// aliasesCore reports whether an alias's right-hand side names a type in core's
// module, through one of this file's imports of it.
func aliasesCore(target ast.Expr, coreImports map[string]bool) bool {
	for {
		switch typed := target.(type) {
		case *ast.StarExpr:
			target = typed.X
		case *ast.SelectorExpr:
			qualifier, ok := typed.X.(*ast.Ident)
			return ok && coreImports[qualifier.Name]
		default:
			return false
		}
	}
}

// inspectJSONTags refuses a json-tagged struct outside the mint endpoint's two
// bodies, wherever the struct appears.
//
// The deleted implementation's signed payload was exactly this: a struct whose
// tags enumerated a capability's fields by hand, which is why a field present
// in the proto and absent from the struct was dropped at mint and missing at
// verify. The earlier version only looked at top-level named types, so an
// anonymous struct literal or a type declared inside a function carried json
// tags freely. This walks every struct type in the file and allows exactly the
// two the mint endpoint declares — identified by node, so a THIRD type cannot
// borrow the allowance by being declared beside them.
func inspectJSONTags(file sourceFile) []string {
	allowed := map[ast.Node]bool{}
	// Only the mint endpoint's own file may hold them. Elsewhere the names earn
	// nothing, so the walk below finds the tags and refuses them.
	if file.path == mintEndpointJSONFile {
		allowed = allowedMintBodies(file)
	}
	var findings []string
	ast.Inspect(file.syntax, func(node ast.Node) bool {
		structure, ok := node.(*ast.StructType)
		if !ok || structure.Fields == nil || allowed[structure] {
			return true
		}
		for _, field := range structure.Fields.List {
			if field.Tag == nil {
				continue
			}
			tag, err := strconv.Unquote(field.Tag.Value)
			if err != nil || reflect.StructTag(tag).Get("json") == "" {
				continue
			}
			findings = append(findings, fmt.Sprintf(
				"%s declares a struct with json tags. Only %v in %s may.\n"+
					"A JSON-tagged struct describing a capability's fields is the second\n"+
					"implementation: core signs the deterministic protobuf encoding, and a field\n"+
					"enumerated by hand is a field dropped at mint and absent at verify. Naming a type\n"+
					"mintRequest somewhere else does not inherit the endpoint's exemption — the\n"+
					"exemption is that file's, not the identifier's.",
				file.path, mintEndpointJSONTypes, mintEndpointJSONFile))
			return true
		}
		return true
	})
	return findings
}

// allowedMintBodies returns the struct nodes of the mint endpoint's two bodies,
// identified by node so a THIRD json-tagged type declared beside them cannot
// borrow the allowance.
func allowedMintBodies(file sourceFile) map[ast.Node]bool {
	allowed := map[ast.Node]bool{}
	for _, declaration := range file.syntax.Decls {
		general, ok := declaration.(*ast.GenDecl)
		if !ok {
			continue
		}
		for _, spec := range general.Specs {
			typed, ok := spec.(*ast.TypeSpec)
			if !ok || !slices.Contains(mintEndpointJSONTypes, typed.Name.Name) {
				continue
			}
			if structure, ok := typed.Type.(*ast.StructType); ok {
				allowed[structure] = true
			}
		}
	}
	return allowed
}

// inspectJSONCalls refuses a json codec call applied to anything but the mint
// endpoint's two bodies.
//
// The TAG rule above is not enough on its own, and that was a reproduced gap:
// json.Marshal of a map[string]any holding a capability's fields needs no tags
// at all, so it produced zero findings in the one file allowed to import
// encoding/json. Tags describe a struct; this describes what is encoded.
func inspectJSONCalls(file sourceFile, jsonNames map[string]bool) []string {
	if len(jsonNames) == 0 {
		return nil
	}
	var findings []string
	ast.Inspect(file.syntax, func(node ast.Node) bool {
		selector, ok := node.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		qualifier, ok := selector.X.(*ast.Ident)
		if !ok || !jsonNames[qualifier.Name] {
			return true
		}
		if !slices.Contains(jsonOperations, selector.Sel.Name) {
			return true
		}
		if codecArgumentIsPermitted(file, node, selector.Sel.Name) {
			return true
		}
		findings = append(findings, fmt.Sprintf(
			"%s calls %s.%s on a type it is not allowed to.\n"+
				"Only %v may be JSON-encoded here, by name and by type. A map[string]any holding a\n"+
				"capability's fields needs no json tags, so the tag rule alone let it through — and a\n"+
				"hand-enumerated capability is exactly the implementation this module deleted.",
			file.path, qualifier.Name, selector.Sel.Name, mintEndpointJSONTypes))
		return true
	})
	return findings
}

// inspectJSONValueCalls checks what a json decoder or encoder is pointed AT.
//
// json.NewDecoder takes a reader, so the type that matters is the one handed to
// Decode — and its receiver is a local variable, not the package, so the
// package-qualified rule above cannot see it.
func inspectJSONValueCalls(file sourceFile, importsJSON bool) []string {
	if !importsJSON {
		return nil
	}
	var findings []string
	ast.Inspect(file.syntax, func(node ast.Node) bool {
		selector, ok := node.(*ast.SelectorExpr)
		if !ok || !slices.Contains(jsonValueOperations, selector.Sel.Name) {
			return true
		}
		// A method call on something, in a file that speaks JSON. The
		// allowlist row for Decode/Encode is what it may be pointed at, which
		// is a DIFFERENT row from Marshal/Unmarshal's — so the operation's own
		// name is what selects it.
		if codecArgumentIsPermitted(file, node, selector.Sel.Name) {
			return true
		}
		findings = append(findings, fmt.Sprintf(
			"%s calls %s on a type it is not allowed to.\n"+
				"Only %v may be JSON-decoded or encoded here, by type. A decoder takes a reader, so\n"+
				"the type that matters is what it is pointed at.",
			file.path, selector.Sel.Name, mintEndpointJSONTypes))
		return true
	})
	return findings
}

// TestTheGateCatchesItsOwnBypasses drives the checks over source written to
// slip past them.
//
// Every case here passed the earlier version of the gate. They are not
// hypothetical readings of it: the base-name allowlist, the top-level-only
// declaration walk, the top-level-only tag walk and the unchecked alias target
// were each a way to reintroduce the deleted implementation with the gate
// green, which is worse than no gate because it is evidence nobody re-reads.
func TestTheGateCatchesItsOwnBypasses(t *testing.T) {
	for name, bypass := range map[string]struct {
		path   string
		source string
		says   string
	}{
		"a nested file inheriting the mint.go allowance": {
			path: "grpctransport/mint.go",
			source: `package grpctransport
import "encoding/json"
var _ = json.Marshal`,
			says: "imports encoding/json",
		},
		"an anonymous struct carrying json tags": {
			path: "carrier.go",
			source: `package workcontext
func payload() any {
	return struct {
		Scopes []string ` + "`json:\"scopes\"`" + `
	}{}
}`,
			says: "struct with json tags",
		},
		"a json-tagged type declared inside a function": {
			path: "carrier.go",
			source: `package workcontext
func payload() any {
	type sealedClaims struct {
		Installation string ` + "`json:\"installation_id\"`" + `
	}
	return sealedClaims{}
}`,
			says: "struct with json tags",
		},
		"a WorkContext type declared inside a function": {
			path: "carrier.go",
			source: `package workcontext
func build() any {
	type WorkContextToken struct{ Payload string }
	return WorkContextToken{}
}`,
			says: "is not an alias of core's",
		},
		"a WorkContext function declared below the imports": {
			path: "carrier.go",
			source: `package workcontext
func WorkContextSign(payload []byte) []byte { return payload }`,
			says: "declares func WorkContextSign",
		},
		"an alias of a type that is not core's": {
			path: "core.go",
			source: `package workcontext
import local "github.com/codefly-dev/sdk-go/workcontext/internal/legacy"
type WorkContextVerifier = local.Verifier`,
			says: "alias of something that is not core's",
		},
		"an alias of a bare local type": {
			path: "core.go",
			source: `package workcontext
type verifier struct{}
type WorkContextVerifier = verifier`,
			says: "alias of something that is not core's",
		},
		"a signing primitive": {
			path: "carrier.go",
			source: `package workcontext
import "crypto/ed25519"
var _ = ed25519.Sign`,
			says: `imports "crypto/ed25519"`,
		},

		// Below: the STANDARD bypasses. Each one is a complete second
		// implementation that the previous gate — a list of two package paths
		// and a case-sensitive name prefix — reported as green.
		"the same primitive from x/crypto": {
			path: "carrier.go",
			source: `package workcontext
import "golang.org/x/crypto/ed25519"
var _ = ed25519.Sign`,
			says: `imports "golang.org/x/crypto/ed25519"`,
		},
		"a different algorithm": {
			path: "carrier.go",
			source: `package workcontext
import "crypto/rsa"
var _ = rsa.SignPKCS1v15`,
			says: `imports "crypto/rsa"`,
		},
		"a MAC instead of a signature": {
			path: "carrier.go",
			source: `package workcontext
import "crypto/hmac"
var _ = hmac.New`,
			says: `imports "crypto/hmac"`,
		},
		"the bare crypto package, whose Signer needs no algorithm import": {
			path: "carrier.go",
			source: `package workcontext
import "crypto"
func sign(key crypto.Signer, payload []byte) ([]byte, error) {
	return key.Sign(nil, payload, crypto.Hash(0))
}`,
			says: `imports "crypto"`,
		},
		"a key parsed out of PKCS#8 through an allowed import": {
			path: "mint.go",
			source: `package workcontext
import "crypto/x509"
func key(der []byte) (any, error) { return x509.ParsePKCS8PrivateKey(der) }`,
			says: "uses x509.ParsePKCS8PrivateKey",
		},
		"the TLS plumbing imported somewhere that is not the mint client": {
			path: "carrier.go",
			source: `package workcontext
import "crypto/tls"
var _ = tls.Config{}`,
			says: `imports "crypto/tls", which only`,
		},
		"a second encoding of the message, in JSON, without encoding/json": {
			path: "carrier.go",
			source: `package workcontext
import "google.golang.org/protobuf/encoding/protojson"
var _ = protojson.Marshal`,
			says: "protobuf/encoding/protojson",
		},
		"core's own signing encoding, reproduced": {
			path: "carrier.go",
			source: `package workcontext
import "google.golang.org/protobuf/proto"
func encode(claims *Claims) ([]byte, error) {
	return proto.MarshalOptions{Deterministic: true}.Marshal(claims)
}`,
			says: "calls proto.MarshalOptions",
		},
		"a JOSE library": {
			path: "carrier.go",
			source: `package workcontext
import "github.com/go-jose/go-jose/v4"
var _ = jose.NewSigner`,
			says: "go-jose",
		},
		"the deleted implementation's own type name, uncapitalised": {
			path: "carrier.go",
			source: `package workcontext
type workContextPayload struct {
	Audience string
}`,
			says: "declares type workContextPayload",
		},
		"a WorkContext method rather than a free function": {
			path: "carrier.go",
			source: `package workcontext
type thing struct{}
func (thing) WorkContextSign(payload []byte) []byte { return payload }`,
			says: "declares method WorkContextSign",
		},
		// Below: the bypasses round three found. Each defeated the gate as it
		// stood after round two, which is the pattern worth noticing — every
		// round the gate was tightened, and every round the next reviewer
		// found the thing the tightening did not reach.
		"a dot-import collision hiding a signing primitive": {
			path: "carrier.go",
			source: `package workcontext
import (
	. "crypto/ed25519"
	. "strings"
)
var _ = Sign
var _ = TrimSpace`,
			says: `dot-imports "crypto/ed25519"`,
		},
		"a single dot import": {
			path: "carrier.go",
			source: `package workcontext
import . "crypto/ed25519"
var _ = Sign`,
			says: "dot-imports",
		},
		"an ALIASED protobuf marshal": {
			path: "carrier.go",
			source: `package workcontext
import pb "google.golang.org/protobuf/proto"
func encode(claims *Claims) ([]byte, error) {
	return pb.MarshalOptions{Deterministic: true}.Marshal(claims)
}`,
			says: "calls pb.MarshalOptions",
		},
		"a hand parser: base64 plus Unmarshal": {
			path: "carrier.go",
			source: `package workcontext
import (
	"encoding/base64"
	"google.golang.org/protobuf/proto"
)
func parse(encoded string) (*Claims, error) {
	raw, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return nil, err
	}
	claims := &Claims{}
	return claims, proto.Unmarshal(raw, claims)
}`,
			says: `imports "encoding/base64"`,
		},
		"proto.Unmarshal on its own": {
			path: "carrier.go",
			source: `package workcontext
import "google.golang.org/protobuf/proto"
func read(raw []byte) (*Claims, error) {
	claims := &Claims{}
	return claims, proto.Unmarshal(raw, claims)
}`,
			says: "calls proto.Unmarshal",
		},
		"the wire encoder": {
			path: "carrier.go",
			source: `package workcontext
import "google.golang.org/protobuf/encoding/protowire"
var _ = protowire.AppendTag`,
			says: "encoding/protowire",
		},
		"anypb, which marshals anything": {
			path: "carrier.go",
			source: `package workcontext
import "google.golang.org/protobuf/types/known/anypb"
var _ = anypb.New`,
			says: "types/known/anypb",
		},
		// Round-three dynamic: both of these produced ZERO findings, because
		// the codec exemptions were per FILE. A whole-file exemption is an
		// exemption for every type in the file.
		"a capability JSON-encoded as a map, needing no tags": {
			path: "mint.go",
			source: `package workcontext
import "encoding/json"
func leak(c *Claims) ([]byte, error) {
	return json.Marshal(map[string]any{
		"installation_id": c.GetSeal().GetInstallationId(),
		"audience":        c.GetAudience(),
	})
}`,
			says: "calls json.Marshal on a type it is not allowed to",
		},
		"a capability decoded into, in the file allowed JSON": {
			path: "mint.go",
			source: `package workcontext
import (
	"bytes"
	"encoding/json"
)
func parse(raw []byte) (*Claims, error) {
	claims := &Claims{}
	return claims, json.NewDecoder(bytes.NewReader(raw)).Decode(claims)
}`,
			says: "calls Decode on a type it is not allowed to",
		},
		"a capability proto-marshalled through the scope exemption": {
			path: "cache_partition.go",
			source: `package workcontext
import "google.golang.org/protobuf/proto"
func sign(c *Claims) ([]byte, error) {
	return proto.MarshalOptions{Deterministic: true}.Marshal(c)
}`,
			says: "on a type it is not allowed to",
		},
		"a WorkContext func bound to a var": {
			path: "carrier.go",
			source: `package workcontext
var WorkContextSign = func(payload []byte) []byte { return payload }`,
			says: "declares var/const WorkContextSign",
		},
	} {
		t.Run(name, func(t *testing.T) {
			findings := inspectForSecondImplementation(parseSource(t, bypass.path, bypass.source))
			require.NotEmpty(t, findings, "the gate accepted source it must refuse")
			require.Contains(t, strings.Join(findings, "\n"), bypass.says)
		})
	}

	// And the two things that ARE allowed stay allowed, so the gate is not
	// green by refusing everything.
	for name, allowed := range map[string]struct {
		path   string
		source string
	}{
		"the mint endpoint's own bodies": {
			path: "mint.go",
			source: `package workcontext
import "encoding/json"
type mintRequest struct {
	Audience string ` + "`json:\"audience\"`" + `
}
type mintResponse struct {
	WorkContext string ` + "`json:\"work_context\"`" + `
}
func encode(audience string) ([]byte, error) {
	return json.Marshal(mintRequest{Audience: audience})
}
func decode(raw []byte) (mintResponse, error) {
	var body mintResponse
	return body, json.Unmarshal(raw, &body)
}`,
		},
		"an alias of core's type": {
			path: "core.go",
			source: `package workcontext
import corework "github.com/codefly-dev/core/workcontext"
type WorkContextVerifier = corework.Verifier`,
		},
	} {
		t.Run(name, func(t *testing.T) {
			require.Empty(t, inspectForSecondImplementation(parseSource(t, allowed.path, allowed.source)))
		})
	}
}

func parseSource(t *testing.T, path string, source string) sourceFile {
	t.Helper()
	syntax, err := parser.ParseFile(token.NewFileSet(), path, source, parser.SkipObjectResolution)
	require.NoError(t, err)
	return sourceFile{path: path, syntax: syntax}
}

// TestWorkContextConformance drives core's own fixtures against the
// verification entrypoint THIS MODULE exports.
//
// It is built field by field from the kit's settings rather than through
// conformance.Settings.Verifier(), which returns core's own verifier: running
// the fixtures against that tests core, which core already tests, and would
// have passed unchanged beside the second implementation this PR deletes. The
// verifier under test is constructed as `&Verifier{...}` — this module's
// exported name — so the thing a consumer reaches for is the thing the
// fixtures are driven through.
//
// What it proves is BEHAVIOURAL conformance: this entrypoint reaches core's
// accept/refuse decision with core's named reason on every fixture. Because
// Verifier is a true alias the identity follows, but the kit cannot see that —
// an equivalent second implementation would pass the same fixtures. The
// identity half is the compile-time assertion at the top of this file plus the
// static gate above; the fixtures are the cheaper half of the guarantee, not
// the whole of it.
//
// The decisive fixture is the foreign encoding — a JSON-shaped token that must
// be refused BEFORE its signature is checked, with ErrNotACoreToken. A second
// implementation refuses that token too, but as a signature failure, which is
// the misdiagnosis this whole rule exists to prevent.
func TestWorkContextConformance(t *testing.T) {
	settings := conformance.New(time.Now())
	exported := &Verifier{
		Issuer:   settings.Issuer,
		Audience: settings.Audience,
		// Settings.Keys is map[string][]byte so holding settings needs no
		// signing import; PublicKeys() is the typed form the verifier takes.
		Keys:      settings.PublicKeys(),
		Revisions: settings.Revisions,
		// One replay store for the whole run: the kit presents the single-use
		// grant fixture twice and requires ErrReplayed, which a fresh store per
		// call would turn into a pass on everything else and a failure there.
		Replay: settings.Replay,
		Grants: settings.Grants,
		Seals:  settings.Seals,
		Now:    settings.Now,
		// Copied from the kit rather than written here, and it is REQUIRED: the
		// fixture key's private half is derivable from core's source, so a
		// verifier refuses it unless it says in as many words that it is a
		// test. Leaving it out made every one of the 35 fixtures fail with
		// "key \"conformance-1\" is the conformance fixture key" — a consumer
		// doing exactly the right thing refusing everything.
		//
		// Which is the argument FOR building this field by field rather than
		// calling settings.Verifier(): a new field core adds to the contract
		// lands here as a failing test. Through the constructor it would have
		// been inherited silently and this module would have learned nothing.
		TrustTheConformanceFixtureKey: settings.TrustTheConformanceFixtureKey,
	}
	conformance.RunWith(t, settings, func(ctx context.Context, token string) error {
		_, err := exported.Verify(ctx, token)
		return err
	})
}

type sourceFile struct {
	path   string
	syntax *ast.File
}

// moduleFiles parses every non-test Go file in this module. The walk starts at
// the module root, which is this package's directory, so a new package added
// beside grpctransport is scanned without anyone remembering to list it. Paths
// are slash-separated and relative to that root, which is what the allowlist is
// keyed by.
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
		files = append(files, sourceFile{path: filepath.ToSlash(path), syntax: syntax})
		return nil
	}))
	return files
}

// importsOf returns this file's imports as (local name, path) PAIRS.
//
// It used to return a map keyed by local name, which two imports can collide
// in: `import ( . "crypto/ed25519"; . "strings" )` maps "." twice, the second
// wins, and the signing primitive is never inspected at all. A gate whose
// coverage depends on import order is not a gate. Pairs cannot collide.
func importsOf(file *ast.File) []importedPackage {
	imports := make([]importedPackage, 0, len(file.Imports))
	for _, imported := range file.Imports {
		path, err := strconv.Unquote(imported.Path.Value)
		if err != nil {
			continue
		}
		name := path[strings.LastIndex(path, "/")+1:]
		if imported.Name != nil {
			name = imported.Name.Name
		}
		imports = append(imports, importedPackage{name: name, path: path})
	}
	return imports
}

type importedPackage struct {
	name string
	path string
}

func allowedEnvelopeDecoderFiles() []string {
	names := make([]string, 0, len(envelopeDecoderAllowlist))
	for name := range envelopeDecoderAllowlist {
		names = append(names, name)
	}
	slices.Sort(names)
	return names
}

func envelopeDecoderReasons() []string {
	reasons := make([]string, 0, len(envelopeDecoderAllowlist))
	for _, reason := range envelopeDecoderAllowlist {
		reasons = append(reasons, reason)
	}
	slices.Sort(reasons)
	return reasons
}

// codecArgumentIsPermitted reports whether this codec call is applied to a
// type the file is allowed to apply it to.
//
// It resolves the argument's type SYNTACTICALLY, from the file alone: a
// composite literal names its own type, a type assertion names the asserted
// type, an address-of or a star defers to what it wraps, and an identifier is
// looked up among the file's var declarations, short declarations and function
// parameters. There is no go/types here and so no cross-file inference, which
// is a stated limit rather than a claim: what it has to catch is a codec
// applied to something the allowlist did not name, and both reproduced probes
// — a map[string]any and a *Claims — are named locally in the file that uses
// them.
//
// An argument it cannot resolve is NOT permitted. A gate that passed what it
// could not read would be a gate about what is easy to parse.
func codecArgumentIsPermitted(file sourceFile, call ast.Node, operation string) bool {
	permitted := permittedCodecTypes(file.path, operation)
	if len(permitted) == 0 {
		return false
	}
	arguments := codecArguments(file, call)
	if len(arguments) == 0 {
		// A codec reference with no call to read — json.Marshal passed as a
		// value, say. Nothing names a type, so nothing is permitted.
		return false
	}
	// Only the argument carrying the VALUE is checked. An Unmarshal or Decode
	// takes the bytes first and the destination last; a Marshal or Encode takes
	// the value first. Requiring every argument to be an allowlisted type
	// refused `json.Unmarshal(raw, &body)` on account of raw being []byte,
	// which is not what the rule is about.
	value := arguments[0]
	if operation == "Unmarshal" || operation == "Decode" {
		value = arguments[len(arguments)-1]
	}
	named := resolveTypeName(file, value)
	return named != "" && slices.Contains(permitted, named)
}

// codecArguments finds the call this codec selector belongs to and returns the
// arguments whose types matter. For a MarshalOptions{...}.Marshal(x) chain the
// selector sits inside the outer call, so the whole file is walked for the call
// whose function expression contains this node.
func codecArguments(file sourceFile, target ast.Node) []ast.Expr {
	var arguments []ast.Expr
	ast.Inspect(file.syntax, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		contains := false
		ast.Inspect(call.Fun, func(inner ast.Node) bool {
			if inner == target {
				contains = true
			}
			return true
		})
		if contains && len(call.Args) > 0 {
			arguments = call.Args
		}
		return true
	})
	return arguments
}

// resolveTypeName names the type of an expression, syntactically, or returns ""
// when it cannot.
func resolveTypeName(file sourceFile, expression ast.Expr) string {
	switch typed := expression.(type) {
	case *ast.UnaryExpr:
		return resolveTypeName(file, typed.X)
	case *ast.CompositeLit:
		return typeName(typed.Type)
	case *ast.TypeAssertExpr:
		return typeName(typed.Type)
	case *ast.CallExpr:
		// new(T) names T, not "new".
		if function, ok := typed.Fun.(*ast.Ident); ok && function.Name == "new" && len(typed.Args) == 1 {
			return typeName(typed.Args[0])
		}
		// A conversion: T(x) names T; anything else is unknown.
		return typeName(typed.Fun)
	case *ast.Ident:
		return declaredTypeName(file, typed.Name)
	}
	return ""
}

// typeName reduces a type expression to its bare name: *pkg.T, pkg.T, []T and
// map[K]V all answer what a reader would call them.
func typeName(expression ast.Expr) string {
	switch typed := expression.(type) {
	case *ast.StarExpr:
		return typeName(typed.X)
	case *ast.SelectorExpr:
		return typed.Sel.Name
	case *ast.Ident:
		return typed.Name
	case *ast.ArrayType:
		return "[]" + typeName(typed.Elt)
	case *ast.MapType:
		// Deliberately not reduced to its value type: a map is never an
		// allowlisted codec type, and naming it as one is how the json probe
		// would have passed.
		return "map"
	}
	return ""
}

// declaredTypeName looks an identifier up among this file's declarations: var
// specs, short variable declarations, and function parameters and results.
func declaredTypeName(file sourceFile, name string) string {
	found := ""
	ast.Inspect(file.syntax, func(node ast.Node) bool {
		switch declared := node.(type) {
		case *ast.ValueSpec:
			for index, declaredName := range declared.Names {
				if declaredName.Name != name {
					continue
				}
				if declared.Type != nil {
					found = typeName(declared.Type)
					return false
				}
				if index < len(declared.Values) {
					found = resolveTypeName(file, declared.Values[index])
					return false
				}
			}
		case *ast.AssignStmt:
			if declared.Tok != token.DEFINE {
				return true
			}
			for index, left := range declared.Lhs {
				ident, ok := left.(*ast.Ident)
				if !ok || ident.Name != name || index >= len(declared.Rhs) {
					continue
				}
				found = resolveTypeName(file, declared.Rhs[index])
				return false
			}
		case *ast.FuncDecl:
			for _, list := range fieldLists(declared.Type) {
				for _, field := range list {
					for _, declaredName := range field.Names {
						if declaredName.Name == name {
							found = typeName(field.Type)
							return false
						}
					}
				}
			}
		}
		return true
	})
	return found
}

func fieldLists(signature *ast.FuncType) [][]*ast.Field {
	var lists [][]*ast.Field
	if signature.Params != nil {
		lists = append(lists, signature.Params.List)
	}
	if signature.Results != nil {
		lists = append(lists, signature.Results.List)
	}
	return lists
}

func allowedJSONFiles() []string {
	names := make([]string, 0, len(jsonAllowlist))
	for name := range jsonAllowlist {
		names = append(names, name)
	}
	slices.Sort(names)
	return names
}
