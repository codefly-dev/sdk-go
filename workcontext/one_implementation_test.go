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
		// The LOW-LEVEL protobuf runtime. protoiface and protoimpl expose a
		// message's own marshal and unmarshal methods, so
		// c.ProtoReflect().ProtoMethods().Unmarshal(...) is a complete decode
		// that mentions no codec package at all — a route neither gate
		// inspected. Nothing here has any use for them.
		"google.golang.org/protobuf/runtime/protoiface",
		"google.golang.org/protobuf/runtime/protoimpl",
		// dynamicpb and protoregistry are NOT here: the receipts replay path
		// genuinely resolves a response type at runtime. They are held to
		// files and symbols in narrowedImports instead.
		// The LEGACY protobuf module, whose proto.Marshal and proto.Unmarshal
		// are the same capability under a different path. Uncovered by every
		// rule that named the new one.
		"github.com/golang/protobuf/proto",
		// Hashes that nothing here uses, and that a hand-rolled HMAC needs one
		// of. crypto/sha256 is the exception and is held to named files and
		// symbols; these have no use at all, so they are simply refused rather
		// than left "not a signature, therefore fine".
		"crypto/sha512", "crypto/sha1", "crypto/sha3", "crypto/md5",
		// HKDF is HMAC with a label on it, and PBKDF2 is HMAC in a loop. Both
		// were reproduced taking sha512.New as the hash, which is why the
		// sha* family is refused rather than waved through as "not a
		// signature".
		"crypto/hkdf", "crypto/pbkdf2",
		// THE CIPHER FAMILY, which the shell sweep has banned since the GMAC
		// probe and this list did not. A GMAC or a CMAC is a MAC assembled out
		// of a block cipher and names no MAC, so the two gates disagreed in
		// the WORSE direction: the shell caught it in the root module and this
		// gate — the one that reads the module the capability actually lives
		// in — did not. Nothing in either module encrypts anything.
		"crypto/cipher", "crypto/aes", "crypto/des", "crypto/rc4",
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
		"workcontext/cache_partition.go": "ENCODES a tenant and installation id into a cache key; it opens no envelope",
	}
	bannedImportPrefixes = []string{"golang.org/x/crypto/"}
	// Any JOSE, JWT or token-library path, whoever publishes it. A capability
	// here is core's protobuf envelope; a library that mints bearer tokens has
	// no honest use in this module.
	// Any path CONTAINING one of these. ed25519 is here as well as in the
	// exact list because a third-party path ending /ed25519 — a vendored
	// copy, a re-export, a fork — passed both gates while naming the one
	// primitive this module must never reach for.
	bannedImportSubstrings = []string{
		"jose", "jwt", "jwx", "paseto", "macaroon", "branca", "ed25519",
	}
)

// narrowedImports are the imports some file here genuinely needs, held to the
// FILES that may have them and the SYMBOLS they may use. An import allowed
// whole-file is an import allowed for everything in that package: this is why
// x509.ParsePKCS8PrivateKey — how a signer gets a key without naming ed25519 —
// is a finding rather than a permitted use of an allowed import.
//
// It was called tlsPlumbing when crypto/tls and crypto/x509 were the only two.
// They are not: crypto/sha256 is not a signature but a hand-written HMAC is two
// of them and an xor, mime.WordDecoder decodes base64 with no base64 import,
// and base64 itself is allowed in one file to ENCODE a cache key.
var narrowedImports = map[string]struct {
	files   []string
	symbols []string
}{
	"crypto/tls": {
		files: []string{"workcontext/mint.go", "tls.go"},
		// Config and the version floor, plus the two error types the client
		// classifies on. Reading an error TYPE is not using a primitive, and
		// the alternative was matching on error text — which is how a
		// certificate failure quietly became an outage again the next time the
		// standard library reworded one.
		symbols: []string{
			"Config", "VersionTLS13",
			"CertificateVerificationError", "RecordHeaderError",
			// tls.go's workload leaf certificates, reloaded on rotation.
			// Measured from the tree, so the list is what is used and no more.
			"Certificate", "X509KeyPair", "LoadX509KeyPair",
			"ClientHelloInfo", "CertificateRequestInfo",
			"RequireAndVerifyClientCert",
		},
	},
	// mime, for one call: the mint response's Content-Type must be declared
	// and must be application/json. A WordDecoder in this package decodes
	// base64 with no base64 import, so the symbols matter here as much as
	// anywhere.
	"mime": {
		files:   []string{"workcontext/mint.go"},
		symbols: []string{"ParseMediaType"},
	},
	// crypto/sha256 is not a signature and the cache digest needs it, but a
	// hand-written HMAC is two hashes and an xor — so the symbols and the
	// files are named, which bounds that to the one file that hashes.
	"crypto/sha256": {
		files: []string{
			"workcontext/cache_partition.go",
			// The root module's two digests: a receipt request's canonical
			// digest and the store's row digest. Neither is a capability and
			// neither is a MAC.
			"receipts/digest.go", "receipts/postgres.go",
		},
		symbols: []string{"Sum256", "New", "Size"},
	},
	// DYNAMIC MESSAGES AND THE TYPE REGISTRY, which the receipts replay path
	// genuinely needs: a recorded response is decoded into whatever type the
	// method answers with, resolved at runtime.
	//
	// They are also how a capability is decoded with its Go type appearing
	// nowhere. dynamicpb.NewMessage(desc) builds a message from a descriptor,
	// and protoregistry resolves one by NAME — and the name can be assembled
	// from pieces ("codefly.base.v0.Work" + "ContextV1"), so no string
	// matches either. Both were reproduced against a real WorkContextV1 in
	// the root module.
	//
	// So: the receipts files may resolve DESCRIPTORS and the method's own
	// type, and nothing may build a message from a name it chose. The symbols
	// are measured from the tree.
	"google.golang.org/protobuf/reflect/protoregistry": {
		files: []string{
			"receipts/interceptor.go",
			"receipts/internal/fixture/fixture.go",
		},
		symbols: []string{"Files", "GlobalFiles", "Types", "GlobalTypes"},
	},
	"google.golang.org/protobuf/types/dynamicpb": {
		// One file, and only NewMessageType — which needs a descriptor the
		// caller already holds. NewMessage, the route the probe used, is
		// refused everywhere.
		files:   []string{"receipts/internal/fixture/fixture.go"},
		symbols: []string{"NewMessageType"},
	},
	// The receipts digest canonicalises a receipt REQUEST — never a capability
	// — and protojson is how it reaches a stable field order. The capability
	// rule is what keeps it off a Work Context message.
	"google.golang.org/protobuf/encoding/protojson": {
		files:   []string{"receipts/digest.go"},
		symbols: []string{"MarshalOptions", "Marshal"},
	},
	// encoding/base64 ENCODES a cache key here and must never DECODE: base64
	// decoding plus proto.Unmarshal is the whole of a second parser, and the
	// exemption used to be per file, so DecodeString was available in the one
	// file that had it.
	"encoding/base64": {
		files:   []string{"workcontext/cache_partition.go"},
		symbols: []string{"RawURLEncoding", "URLEncoding", "StdEncoding"},
	},
	"crypto/x509": {
		files: []string{"workcontext/mint.go", "tls.go"},
		// CertPool for the caller's roots, and the three verification error
		// types for the same reason as above. Notably still refused:
		// ParsePKCS8PrivateKey, which is how a signer gets a key without
		// importing ed25519.
		symbols: []string{
			"CertPool", "NewCertPool", "SystemCertPool",
			"UnknownAuthorityError", "HostnameError", "CertificateInvalidError",
		},
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
	{file: "workcontext/mint.go", codec: codecJSON, operations: jsonOperations, types: mintEndpointJSONTypes,
		reason: "the mint endpoint's two HTTP bodies, which carry the capability as an opaque string"},
	{file: "workcontext/mint.go", codec: codecJSON, operations: jsonValueOperations,
		types: append(append([]string{}, mintEndpointJSONTypes...), "encoding/json#RawMessage"),
		reason: "the same two bodies, plus a RawMessage the response decoder reads into to " +
			"require EOF — it holds nothing and is discarded"},
	{file: "workcontext/cache_partition.go", codec: codecProto, operations: protoOperations,
		types:  []string{basev0Path + "#WorkScopeV1"},
		reason: "one scope, for the cache digest preimage — never a capability"},
}

// The codecs a row can be about. A row used to be keyed on the file and the
// OPERATION NAME, and "Marshal" is an operation name shared by every codec —
// so mint.go's row for encoding/json, whose two allowed types are the HTTP
// bodies, also permitted proto.Marshal and proto.Unmarshal on anything NAMED
// mintRequest or mintResponse. A row has to say which codec it is about.
const (
	codecJSON  = "encoding/json"
	codecProto = "google.golang.org/protobuf/proto"
)

type codecUse struct {
	file       string
	codec      string
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

// permittedCodecTypes is the set of type names THIS CODEC's operation may be
// applied to in this file, or nil when it may not be used here at all.
func permittedCodecTypes(path string, codec string, operation string) []string {
	for _, use := range codecAllowlist {
		if use.file == path && use.codec == codec && slices.Contains(use.operations, operation) {
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
	"workcontext/mint.go": "the mint endpoint's HTTP request and response bodies, which carry the capability as an opaque string",
	// The root module's own JSON, named here now that the gate reads both
	// modules — and MEASURED from the tree, not guessed: these are the only
	// two files outside the leaf module that import encoding/json. Neither is
	// a capability, and the capability rule refuses a codec on a Work Context
	// message in any file whatever this list says.
	"configuration_document.go": "the runtime's own configuration document, which is not a capability",
	"receipts/digest.go":        "canonicalising a receipt REQUEST for its digest: protojson, then a stable re-encode",
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
	mintEndpointJSONFile  = "workcontext/mint.go"
)

// coreModulePath is the module whose types this one aliases. An alias has to
// resolve into it, or it is a local type wearing core's name.
const coreModulePath = "github.com/codefly-dev/core"

// basev0Path is the generated package holding the capability's messages, so an
// allowlist row can say which package it means.
const basev0Path = coreModulePath + "/generated/go/codefly/base/v0"

// leafModulePrefix is the leaf module's directory, as repositoryFiles names it.
// Inside it the capability IS the subject, so every codec use is allowlisted by
// name; outside it the module's subject is everything else, so the rule is the
// decisive one instead — no codec on a capability type, whatever else the file
// legitimately encodes. See codecArgumentIsPermitted.
const leafModulePrefix = "workcontext/"

// capabilityTypePrefix recognises a Work Context message: a type under core's
// module whose name begins with "Work". A PREFIX rather than a list, so a
// message core adds later is covered the day it exists rather than the day
// somebody remembers it here.
const capabilityTypePrefix = "Work"

// coreAliasFile is the one file whose job is re-exporting core's surface, so it
// is the one file where an alias to one of core's types is the point rather
// than a second local name for a capability.
const coreAliasFile = "workcontext/core.go"

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
	files := repositoryFiles(t)
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
	assertFrozenStructShapes(t, files)

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
	plumbing := map[string]string{}  // local name -> allowed import path
	protoNames := map[string]bool{}  // every local name google.golang.org/protobuf is reachable under
	jsonNames := map[string]bool{}   // and encoding/json
	base64Names := map[string]bool{} // and encoding/base64, which may only ENCODE
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
		if imported.path == "encoding/base64" {
			base64Names[imported.name] = true
		}
	}
	findings = append(findings, inspectPlumbingSymbols(file, plumbing)...)
	findings = append(findings, inspectProtoEncoding(file, protoNames)...)
	findings = append(findings, inspectDeclarations(file, coreImports)...)
	findings = append(findings, inspectJSONTags(file)...)
	findings = append(findings, inspectJSONCalls(file, jsonNames)...)
	findings = append(findings, inspectJSONValueCalls(file, len(jsonNames) > 0)...)
	findings = append(findings, inspectLocalTypes(file)...)
	findings = append(findings, inspectCoreAliases(file, coreImports)...)
	findings = append(findings, inspectEnvelopeDecoding(file, base64Names)...)
	findings = append(findings, inspectProtoMethodsRoute(file)...)
	findings = append(findings, inspectCapabilityFields(file)...)
	return findings
}

// frozenStructFields is the EXACT field set of each struct a codec is allowed
// to touch, by file and type name.
//
// The codec rule checks the TOP-LEVEL type only, which is the original defect
// class coming back one level down: adding
//
//	Echo *Claims `json:"echo,omitempty"`
//
// to mintRequest made json.Marshal(mintRequest{Echo: claims}) encode a whole
// capability through the row that exists for two strings — reproduced, and
// green. The same went for a *Claims field on mintResponse.
//
// Freezing the field sets is stronger than chasing field types, and it is
// honest about what these two structs are: an HTTP wire contract with a host.
// A field added to either is a change to that contract and belongs in a
// reviewed diff, not in a struct literal.
var frozenStructFields = map[string]map[string][]string{
	"workcontext/mint.go": {
		"mintRequest":  {"Audience string", "ProjectionAudience string"},
		"mintResponse": {"WorkContext string", "InstallationID string", "BuildIncarnation string"},
	},
}

// inspectCapabilityFields refuses any struct carrying a field whose type is
// one of core's Work messages.
//
// A codec reaching the struct then reaches the capability through it, whatever
// the allowlist said about the outer type — which is the hand-enumerated
// payload this module deleted, one level down.
func inspectCapabilityFields(file sourceFile) []string {
	var findings []string
	ast.Inspect(file.syntax, func(node ast.Node) bool {
		spec, ok := node.(*ast.TypeSpec)
		if !ok {
			return true
		}
		structure, ok := spec.Type.(*ast.StructType)
		if !ok || structure.Fields == nil {
			return true
		}
		// THE GENERAL RULE: no struct anywhere in this module carries a
		// capability as a field. A codec reaching the struct then reaches the
		// capability, whatever the allowlist said about the outer type.
		for _, field := range structure.Fields.List {
			named := typeName(file, field.Type)
			if isCapabilityType(named) {
				findings = append(findings, fmt.Sprintf(
					"%s declares %s with a field of type %s.\n"+
						"A struct carrying one of core's Work messages is a capability wearing another\n"+
						"type's name: a codec allowed to touch the struct reaches the capability through\n"+
						"it, which is the hand-enumerated payload this module deleted, one level down.",
					file.path, spec.Name.Name, named))
			}
		}
		return true
	})
	return findings
}

// assertFrozenStructShapes holds this repository's two codec-allowed structs to
// their exact field sets.
//
// It is a claim about THIS TREE rather than a rule for arbitrary source, so it
// runs over the repository's own files and not inside the per-file inspector
// the bypass probes drive — a synthetic probe naming itself mintRequest is not
// a change to the wire contract.
func assertFrozenStructShapes(t *testing.T, files []sourceFile) {
	t.Helper()
	require.Empty(t, frozenStructViolations(files),
		"%s", strings.Join(frozenStructViolations(files), "\n\n"))
}

// frozenStructViolations is the check itself, returning findings rather than
// calling require.
//
// Separated for one reason: a probe cannot drive a require-based assertion.
// Passing a fresh testing.T to one makes FailNow call runtime.Goexit on the
// probe's own goroutine, so "did the freeze catch this?" could only be answered
// by eye — which is how the embedded-field hole went three rounds unnoticed. A
// rule that cannot be probed is a rule nobody has tested.
func frozenStructViolations(files []sourceFile) []string {
	var findings []string
	seen := map[string]map[string][]string{}
	for _, file := range files {
		frozen, ok := frozenStructFields[file.path]
		if !ok {
			continue
		}
		seen[file.path] = map[string][]string{}
		ast.Inspect(file.syntax, func(node ast.Node) bool {
			spec, ok := node.(*ast.TypeSpec)
			if !ok {
				return true
			}
			structure, ok := spec.Type.(*ast.StructType)
			if !ok || structure.Fields == nil {
				return true
			}
			if _, isFrozen := frozen[spec.Name.Name]; !isFrozen {
				return true
			}
			var actual []string
			for _, field := range structure.Fields.List {
				if len(field.Names) == 0 {
					// AN EMBEDDED FIELD IS A FIELD, and this loop over
					// field.Names skipped every one of them — an embedded
					// field has no Names at all. Measured: adding
					//
					//	type smuggled struct { Echo string }
					//
					// to mint.go and embedding it in mintRequest left the
					// frozen set byte-identical, produced no finding anywhere
					// in the gate, and put a new field on the wire, because
					// encoding/json promotes an embedded struct's exported
					// fields into the enclosing object. The freeze exists for
					// exactly that, one level sideways.
					actual = append(actual, "embedded "+typeName(file, field.Type))
					continue
				}
				for _, name := range field.Names {
					actual = append(actual, name.Name+" "+typeName(file, field.Type))
				}
			}
			seen[file.path][spec.Name.Name] = actual
			return true
		})
	}
	for path, frozen := range frozenStructFields {
		for name, expected := range frozen {
			if slices.Equal(expected, seen[path][name]) {
				continue
			}
			findings = append(findings, fmt.Sprintf(
				"%s: %s is a codec-allowed struct and its field set is FROZEN.\n"+
					"The codec rule names the TYPE, so a new field is a new thing encoded through a\n"+
					"row that exists for the fields listed — adding `Echo *Claims` to mintRequest\n"+
					"encoded a whole capability through a row for two strings, and was green. These\n"+
					"two structs are an HTTP wire contract with the mint host: a change to them is a\n"+
					"change to that contract, and belongs in a reviewed diff with\n"+
					"frozenStructFields updated in it.\n"+
					"  frozen: %v\n"+
					"  found:  %v",
				path, name, expected, seen[path][name]))
		}
	}
	return findings
}

// inspectProtoMethodsRoute refuses a message's own marshal and unmarshal
// methods, reached through protobuf reflection.
//
// c.ProtoReflect().ProtoMethods().Unmarshal(...) is a complete decode of a
// capability that names no codec package, no banned import and no allowlisted
// type — so the import ban could not see it and the codec rule had nothing to
// key on. Banning the protoiface and protoimpl imports closes the typed route;
// this closes the reflective one, which needs no import at all because
// ProtoReflect is a method on every generated message.
func inspectProtoMethodsRoute(file sourceFile) []string {
	var findings []string
	ast.Inspect(file.syntax, func(node ast.Node) bool {
		selector, ok := node.(*ast.SelectorExpr)
		if !ok || selector.Sel.Name != "ProtoMethods" {
			return true
		}
		findings = append(findings, fmt.Sprintf(
			"%s reaches ProtoMethods.\n"+
				"A message's own marshal and unmarshal methods are a complete codec that names no\n"+
				"codec package: ProtoReflect().ProtoMethods().Unmarshal(...) decodes a capability\n"+
				"with no banned import and no type for an allowlist to key on. Reading a capability\n"+
				"off the wire is corework.Inspect's job.",
			file.path))
		return true
	})
	return findings
}

// envelopeEncodeOnly are the methods an allowlisted base64 import may call on
// an encoding. Everything else — DecodeString, Decode, NewDecoder, AppendDecode
// — is the first half of a second parser.
var envelopeEncodeOnly = []string{"EncodeToString", "Encode", "EncodedLen", "AppendEncode"}

// inspectEnvelopeDecoding refuses DECODING in the one file allowed to encode.
//
// The symbol allowlist cannot see this on its own: base64.StdEncoding is the
// permitted symbol and DecodeString is a method on the *value* it names, so
// `base64.StdEncoding.DecodeString(payload)` passed a package-level symbol
// check completely. The exemption was per file, so the file allowed to encode a
// cache key could decode a capability's envelope — and with proto.Unmarshal
// that is a whole parser.
func inspectEnvelopeDecoding(file sourceFile, base64Names map[string]bool) []string {
	if len(base64Names) == 0 {
		return nil
	}
	var findings []string
	ast.Inspect(file.syntax, func(node ast.Node) bool {
		method, ok := node.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		// The receiver must itself be base64.<something>, which is what makes
		// this a base64 encoding rather than any other value's method.
		receiver, ok := method.X.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		qualifier, ok := receiver.X.(*ast.Ident)
		if !ok || !base64Names[qualifier.Name] {
			return true
		}
		if slices.Contains(envelopeEncodeOnly, method.Sel.Name) {
			return true
		}
		findings = append(findings, fmt.Sprintf(
			"%s calls %s.%s.%s.\n"+
				"This file may ENCODE with base64 — it builds a cache key — and may never DECODE.\n"+
				"base64 decoding plus proto.Unmarshal is the entire second parser this module\n"+
				"deleted; corework.Inspect opens the envelope and hands back the claims. Only %v\n"+
				"may be called here.",
			file.path, qualifier.Name, receiver.Sel.Name, method.Sel.Name, envelopeEncodeOnly))
		return true
	})
	return findings
}

// inspectLocalTypes refuses a type declared INSIDE a function.
//
// This is the alias bypass's other half. A function-local declaration is
// invisible to every rule that reads a file's declarations, and `type X =
// basev0.WorkContextV1` inside a function body is enough to give a codec row
// whatever type name it asks for. It is also something this module has no use
// for: a type worth declaring here is worth declaring where a reader finds it.
func inspectLocalTypes(file sourceFile) []string {
	var findings []string
	for _, declaration := range file.syntax.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if !ok || function.Body == nil {
			continue
		}
		ast.Inspect(function.Body, func(node ast.Node) bool {
			spec, ok := node.(*ast.TypeSpec)
			if !ok {
				return true
			}
			findings = append(findings, fmt.Sprintf(
				"%s declares the type %q inside a function.\n"+
					"A function-local type is invisible to every rule here that reads a file's\n"+
					"declarations, and a local alias is all it takes to hand a codec row a type name it\n"+
					"permits — `type WorkScopeV1 = basev0.WorkContextV1` makes a capability marshal as\n"+
					"an allowed scope. Declare it at file level, where it is read.",
				file.path, spec.Name.Name))
			return true
		})
	}
	return findings
}

// inspectCoreAliases refuses an alias to one of core's types outside the one
// file whose job is aliasing core.
//
// core.go exists so this module's surface IS core's surface: an alias there is
// the re-export the one-implementation rule asks for. An alias anywhere else
// renames core's type locally, which is how a capability acquires a second
// name — and the name rule cannot catch it, because a reader chooses the name.
func inspectCoreAliases(file sourceFile, coreImports map[string]bool) []string {
	if file.path == coreAliasFile || len(coreImports) == 0 {
		return nil
	}
	var findings []string
	ast.Inspect(file.syntax, func(node ast.Node) bool {
		spec, ok := node.(*ast.TypeSpec)
		if !ok {
			return true
		}
		// BOTH SPELLINGS. This required spec.Assign.IsValid(), so only
		// `type A = corework.B` was a finding and `type A corework.B` was
		// silent. The defined form cannot reach a codec — it inherits no
		// methods, so it is not a proto.Message — but it is still a second
		// declaration of core's shape under a local name, and a rule true for
		// one spelling and silent for the other is a rule a reader has to test
		// to know.
		kind := "aliases"
		if !spec.Assign.IsValid() {
			kind = "declares a local type over"
		}
		// THROUGH A POINTER OR A SLICE. The check read spec.Type as a bare
		// selector, so `type carrier = basev0.WorkContextV1` was a finding and
		// `type carrier = *basev0.WorkContextV1` was not — and the pointer
		// form is the one a codec takes.
		selector, ok := unwrapTypeExpr(spec.Type).(*ast.SelectorExpr)
		if !ok {
			return true
		}
		qualifier, ok := selector.X.(*ast.Ident)
		if !ok || !coreImports[qualifier.Name] {
			return true
		}
		findings = append(findings, fmt.Sprintf(
			"%s %s core's %s.%s as %q.\n"+
				"Aliases to core's types belong in %s, which is this module's re-export of core's\n"+
				"surface. A second local name elsewhere is precisely what a codec allowlist keyed by\n"+
				"type name cannot see through.",
			file.path, kind, qualifier.Name, selector.Sel.Name, spec.Name.Name, coreAliasFile))
		return true
	})
	return findings
}

// unwrapTypeExpr strips the pointers, slices and parentheses a type expression
// wears, so a rule written for a named type reaches it however it is dressed.
func unwrapTypeExpr(expression ast.Expr) ast.Expr {
	for hops := 0; hops < maxAliasHops; hops++ {
		switch typed := expression.(type) {
		case *ast.StarExpr:
			expression = typed.X
		case *ast.ArrayType:
			expression = typed.Elt
		case *ast.ParenExpr:
			expression = typed.X
		default:
			return expression
		}
	}
	return expression
}

// inspectImport refuses an import by what it can DO, not by whether its path is
// one of two strings.
func inspectImport(file sourceFile, name string, path string, plumbing map[string]string) []string {
	if allowed, ok := narrowedImports[path]; ok {
		if slices.Contains(allowed.files, file.path) {
			plumbing[name] = path
			return nil
		}
		return []string{fmt.Sprintf(
			"%s imports %q, which only %v may, and only for named symbols.",
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
		if slices.Contains(narrowedImports[path].symbols, selector.Sel.Name) {
			return true
		}
		findings = append(findings, fmt.Sprintf(
			"%s uses %s.%s. Only %v may be used from %q here.\n"+
				"The import is allowed for the mint client's transport, not as a way into the package:\n"+
				"x509.ParsePKCS8PrivateKey plus a crypto.Signer assertion is a complete signer that\n"+
				"imports no signing primitive at all.",
			file.path, qualifier.Name, selector.Sel.Name, narrowedImports[path].symbols, path))
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
			if codecArgumentIsPermitted(file, node, codecProto, "Marshal") {
				return true
			}
		case "Unmarshal", "UnmarshalOptions":
			// Unrestricted until now, and it is half of the defect that was the
			// last blocker: a second unverified parser needs base64 to open the
			// envelope and Unmarshal to read it. corework.Inspect does both, and
			// hands back the claims, so nothing here needs either.
			if codecArgumentIsPermitted(file, node, codecProto, "Unmarshal") {
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
		if codecArgumentIsPermitted(file, node, codecJSON, selector.Sel.Name) {
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
		if codecArgumentIsPermitted(file, node, codecJSON, selector.Sel.Name) {
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
		// ---- Round four, layer 4: EXECUTED probes, plus every ban entry and
		// rule the review's mutation pass found had no probe at all.
		//
		// THE ROOT MODULE. A reviewer wrote the first of these, compiled it,
		// ran golangci-lint over it (0 issues) and ran the shell sweep (ok, 58
		// Go files): a second parser whose base64url decoder is HAND-WRITTEN,
		// so it imports nothing a sweep can ban. Only reading the code sees
		// it, which is why this gate now walks both modules.
		"a root-module parser with a hand-written decoder": {
			path: "work_context_reader.go",
			source: `package codefly
import (
	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
	"google.golang.org/protobuf/proto"
)
func decodeBase64URL(text string) []byte { return []byte(text) }
func ReadWorkContextTenant(token string) (string, error) {
	claims := &basev0.WorkContextV1{}
	if err := proto.Unmarshal(decodeBase64URL(token), claims); err != nil {
		return "", err
	}
	return claims.GetTenantId(), nil
}`,
			says: "calls proto.Unmarshal",
		},
		"a root-module encoder of the capability": {
			path: "work_context_writer.go",
			source: `package codefly
import (
	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
	"google.golang.org/protobuf/proto"
)
func encodeClaims(claims *basev0.WorkContextV1) ([]byte, error) {
	return proto.MarshalOptions{Deterministic: true}.Marshal(claims)
}`,
			says: "on a type it is not allowed to",
		},
		// THE IMPORT NAME IS THE AUTHOR'S CHOICE, so a row compared against a
		// LOCAL qualifier is satisfied by aliasing any package to the expected
		// name. Rows name package PATHS.
		"a foreign package aliased to core's own local name": {
			path: "workcontext/cache_partition.go",
			source: `package workcontext
import (
	basev0 "google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/proto"
)
func encode() ([]byte, error) {
	return proto.Marshal(&basev0.WorkScopeV1{})
}`,
			says: "on a type it is not allowed to",
		},
		// "An argument it cannot resolve is NOT permitted" had no probe, so in
		// the leaf module the claim was untested.
		"a codec on a value the gate cannot resolve": {
			path: "workcontext/mint.go",
			source: `package workcontext
import "encoding/json"
func write(anything any) ([]byte, error) {
	return json.Marshal(anything)
}`,
			says: "on a type it is not allowed to",
		},
		// The json-TAG exemption is a property of ONE file's TWO declarations,
		// never of two identifiers anywhere.
		"a json-tagged mintRequest in another file": {
			path: "workcontext/carrier.go",
			source: `package workcontext
type mintRequest struct {
	Audience string "json:\"audience\""
}`,
			says: "struct with json tags",
		},
		"a nested package declaring the allowlisted json types": {
			path: "workcontext/grpctransport/bodies.go",
			source: `package grpctransport
type mintResponse struct {
	WorkContext string "json:\"work_context\""
}`,
			says: "struct with json tags",
		},
		// The thirteen ban entries that had no probe. Each is a complete
		// second implementation or a second encoding of the message, and each
		// was previously asserted only by appearing in a list.
		"crypto/ecdsa": {
			path: "workcontext/carrier.go",
			source: `package workcontext
import "crypto/ecdsa"
var _ = ecdsa.SignASN1`,
			says: "imports \"crypto/ecdsa\"",
		},
		"crypto/dsa": {
			path: "workcontext/carrier.go",
			source: `package workcontext
import "crypto/dsa"
var _ = dsa.Sign`,
			says: "imports \"crypto/dsa\"",
		},
		"crypto/ecdh": {
			path: "workcontext/carrier.go",
			source: `package workcontext
import "crypto/ecdh"
var _ = ecdh.P256`,
			says: "imports \"crypto/ecdh\"",
		},
		"crypto/elliptic": {
			path: "workcontext/carrier.go",
			source: `package workcontext
import "crypto/elliptic"
var _ = elliptic.P256`,
			says: "imports \"crypto/elliptic\"",
		},
		"crypto/subtle": {
			path: "workcontext/carrier.go",
			source: `package workcontext
import "crypto/subtle"
var _ = subtle.ConstantTimeCompare`,
			says: "imports \"crypto/subtle\"",
		},
		"encoding/gob": {
			path: "workcontext/carrier.go",
			source: `package workcontext
import "encoding/gob"
var _ = gob.NewEncoder`,
			says: "imports \"encoding/gob\"",
		},
		"encoding/asn1": {
			path: "workcontext/carrier.go",
			source: `package workcontext
import "encoding/asn1"
var _ = asn1.Marshal`,
			says: "imports \"encoding/asn1\"",
		},
		"encoding/xml": {
			path: "workcontext/carrier.go",
			source: `package workcontext
import "encoding/xml"
var _ = xml.Marshal`,
			says: "imports \"encoding/xml\"",
		},
		"a jwt library": {
			path: "workcontext/carrier.go",
			source: `package workcontext
import "github.com/golang-jwt/jwt/v5"
var _ = jwt.New`,
			says: "jwt",
		},
		"a jwx library": {
			path: "workcontext/carrier.go",
			source: `package workcontext
import "github.com/lestrrat-go/jwx/v2/jws"
var _ = jws.Sign`,
			says: "jwx",
		},
		"a paseto library": {
			path: "workcontext/carrier.go",
			source: `package workcontext
import "aidanwoods.dev/go-paseto"
var _ = paseto.NewToken`,
			says: "paseto",
		},
		"a macaroon library": {
			path: "workcontext/carrier.go",
			source: `package workcontext
import "gopkg.in/macaroon.v2"
var _ = macaroon.New`,
			says: "macaroon",
		},
		"a branca library": {
			path: "workcontext/carrier.go",
			source: `package workcontext
import "github.com/essentialkaos/branca"
var _ = branca.NewBranca`,
			says: "branca",
		},
		// ---- Round four: the shapes the review found this gate blind to.
		//
		// Each is a complete second parser or encoder that COMPILED and
		// produced zero findings at the previous revision. The common thread
		// is that the codec rule was about names: a type name with no package,
		// an identifier resolved to whichever same-named declaration came
		// last, and a row keyed on an operation name shared by every codec.
		"a local alias giving a capability an allowlisted type name": {
			path: "workcontext/cache_partition.go",
			source: `package workcontext
import (
	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
	"google.golang.org/protobuf/proto"
)
func encode(wc *basev0.WorkContextV1) ([]byte, error) {
	type WorkScopeV1 = basev0.WorkContextV1
	return proto.MarshalOptions{Deterministic: true}.Marshal((*WorkScopeV1)(wc))
}`,
			says: "inside a function",
		},
		"a file-level alias giving a capability an allowlisted type name": {
			path: "workcontext/cache_partition.go",
			source: `package workcontext
import (
	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
	"google.golang.org/protobuf/proto"
)
type WorkScopeV1 = basev0.WorkContextV1
func encode(wc *WorkScopeV1) ([]byte, error) {
	return proto.Marshal(wc)
}`,
			says: "aliases core's",
		},
		// The qualifier is the whole point: the allowlist row exists for ONE
		// core message, and the resolver used to answer "WorkScopeV1" for
		// every type whose final name was that, from any package.
		"a marshal of a foreign package's WorkScopeV1": {
			path: "workcontext/cache_partition.go",
			source: `package workcontext
import (
	"google.golang.org/protobuf/proto"
	elsewhere "example.test/other"
)
func encode(scope *elsewhere.WorkScopeV1) ([]byte, error) {
	return proto.Marshal(scope)
}`,
			says: "on a type it is not allowed to",
		},
		"a marshal of another package's identically named type": {
			path: "workcontext/cache_partition.go",
			source: `package workcontext
import (
	"google.golang.org/protobuf/proto"
	elsewhere "google.golang.org/protobuf/types/known/structpb"
)
type WorkScopeV1 = elsewhere.Struct
func encode() ([]byte, error) {
	return proto.Marshal(&WorkScopeV1{})
}`,
			says: "on a type it is not allowed to",
		},
		"base64 DECODING in the file allowed to encode": {
			path: "workcontext/cache_partition.go",
			source: `package workcontext
import "encoding/base64"
func open(token string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(token)
}`,
			says: "may never DECODE",
		},
		"a proto codec riding mint.go's encoding/json row": {
			path: "workcontext/mint.go",
			source: `package workcontext
import "google.golang.org/protobuf/proto"
type mintResponse struct{ WorkContext string }
func read(raw []byte) error {
	var body mintResponse
	return proto.Unmarshal(raw, &body)
}`,
			says: "calls proto.Unmarshal",
		},
		"an identifier resolved to a later same-named declaration": {
			path: "workcontext/mint.go",
			source: `package workcontext
import (
	"encoding/json"
	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
)
func leak(claims *basev0.WorkContextV1) ([]byte, error) {
	body := claims
	return json.Marshal(body)
}
type mintResponse struct{ WorkContext string }
func decode() {
	var body mintResponse
	_ = body
}`,
			says: "on a type it is not allowed to",
		},
		"an identifier an ambiguous file cannot resolve": {
			path: "workcontext/mint.go",
			source: `package workcontext
import "encoding/json"
type mintRequest struct{ Audience string }
func one() { body := mintRequest{}; _ = body }
func two(raw []byte) error {
	body := map[string]any{}
	return json.Unmarshal(raw, &body)
}`,
			says: "on a type it is not allowed to",
		},
		"mime as a base64 decoder": {
			path: "workcontext/carrier.go",
			source: `package workcontext
import "mime"
func open(header string) (string, error) {
	kind, _, err := mime.ParseMediaType(header)
	return kind, err
}`,
			says: "imports \"mime\"",
		},
		"sha256 outside the file that hashes": {
			path: "workcontext/carrier.go",
			source: `package workcontext
import "crypto/sha256"
func mac(key, message []byte) []byte {
	inner := sha256.Sum256(append(key, message...))
	return inner[:]
}`,
			says: "imports \"crypto/sha256\"",
		},
		"a nested package reaching for the cache partition's base64": {
			path: "workcontext/grpctransport/partition.go",
			source: `package grpctransport
import "encoding/base64"
var _ = base64.RawURLEncoding`,
			says: "imports \"encoding/base64\"",
		},
		"a nested file inheriting the mint.go allowance": {
			path: "workcontext/grpctransport/mint.go",
			source: `package grpctransport
import "encoding/json"
var _ = json.Marshal`,
			says: "imports encoding/json",
		},
		"an anonymous struct carrying json tags": {
			path: "workcontext/carrier.go",
			source: `package workcontext
func payload() any {
	return struct {
		Scopes []string ` + "`json:\"scopes\"`" + `
	}{}
}`,
			says: "struct with json tags",
		},
		"a json-tagged type declared inside a function": {
			path: "workcontext/carrier.go",
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
			path: "workcontext/carrier.go",
			source: `package workcontext
func build() any {
	type WorkContextToken struct{ Payload string }
	return WorkContextToken{}
}`,
			says: "is not an alias of core's",
		},
		"a WorkContext function declared below the imports": {
			path: "workcontext/carrier.go",
			source: `package workcontext
func WorkContextSign(payload []byte) []byte { return payload }`,
			says: "declares func WorkContextSign",
		},
		"an alias of a type that is not core's": {
			path: "workcontext/core.go",
			source: `package workcontext
import local "github.com/codefly-dev/sdk-go/workcontext/internal/legacy"
type WorkContextVerifier = local.Verifier`,
			says: "alias of something that is not core's",
		},
		"an alias of a bare local type": {
			path: "workcontext/core.go",
			source: `package workcontext
type verifier struct{}
type WorkContextVerifier = verifier`,
			says: "alias of something that is not core's",
		},
		"a signing primitive": {
			path: "workcontext/carrier.go",
			source: `package workcontext
import "crypto/ed25519"
var _ = ed25519.Sign`,
			says: `imports "crypto/ed25519"`,
		},

		// Below: the STANDARD bypasses. Each one is a complete second
		// implementation that the previous gate — a list of two package paths
		// and a case-sensitive name prefix — reported as green.
		"the same primitive from x/crypto": {
			path: "workcontext/carrier.go",
			source: `package workcontext
import "golang.org/x/crypto/ed25519"
var _ = ed25519.Sign`,
			says: `imports "golang.org/x/crypto/ed25519"`,
		},
		"a different algorithm": {
			path: "workcontext/carrier.go",
			source: `package workcontext
import "crypto/rsa"
var _ = rsa.SignPKCS1v15`,
			says: `imports "crypto/rsa"`,
		},
		"a MAC instead of a signature": {
			path: "workcontext/carrier.go",
			source: `package workcontext
import "crypto/hmac"
var _ = hmac.New`,
			says: `imports "crypto/hmac"`,
		},
		"the bare crypto package, whose Signer needs no algorithm import": {
			path: "workcontext/carrier.go",
			source: `package workcontext
import "crypto"
func sign(key crypto.Signer, payload []byte) ([]byte, error) {
	return key.Sign(nil, payload, crypto.Hash(0))
}`,
			says: `imports "crypto"`,
		},
		"a key parsed out of PKCS#8 through an allowed import": {
			path: "workcontext/mint.go",
			source: `package workcontext
import "crypto/x509"
func key(der []byte) (any, error) { return x509.ParsePKCS8PrivateKey(der) }`,
			says: "uses x509.ParsePKCS8PrivateKey",
		},
		"the TLS plumbing imported somewhere that is not the mint client": {
			path: "workcontext/carrier.go",
			source: `package workcontext
import "crypto/tls"
var _ = tls.Config{}`,
			says: `imports "crypto/tls", which only`,
		},
		"a second encoding of the message, in JSON, without encoding/json": {
			path: "workcontext/carrier.go",
			source: `package workcontext
import "google.golang.org/protobuf/encoding/protojson"
var _ = protojson.Marshal`,
			says: "protobuf/encoding/protojson",
		},
		"core's own signing encoding, reproduced": {
			path: "workcontext/carrier.go",
			source: `package workcontext
import "google.golang.org/protobuf/proto"
func encode(claims *Claims) ([]byte, error) {
	return proto.MarshalOptions{Deterministic: true}.Marshal(claims)
}`,
			says: "calls proto.MarshalOptions",
		},
		"a JOSE library": {
			path: "workcontext/carrier.go",
			source: `package workcontext
import "github.com/go-jose/go-jose/v4"
var _ = jose.NewSigner`,
			says: "go-jose",
		},
		"the deleted implementation's own type name, uncapitalised": {
			path: "workcontext/carrier.go",
			source: `package workcontext
type workContextPayload struct {
	Audience string
}`,
			says: "declares type workContextPayload",
		},
		"a WorkContext method rather than a free function": {
			path: "workcontext/carrier.go",
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
			path: "workcontext/carrier.go",
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
			path: "workcontext/carrier.go",
			source: `package workcontext
import . "crypto/ed25519"
var _ = Sign`,
			says: "dot-imports",
		},
		"an ALIASED protobuf marshal": {
			path: "workcontext/carrier.go",
			source: `package workcontext
import pb "google.golang.org/protobuf/proto"
func encode(claims *Claims) ([]byte, error) {
	return pb.MarshalOptions{Deterministic: true}.Marshal(claims)
}`,
			says: "calls pb.MarshalOptions",
		},
		"a hand parser: base64 plus Unmarshal": {
			path: "workcontext/carrier.go",
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
			path: "workcontext/carrier.go",
			source: `package workcontext
import "google.golang.org/protobuf/proto"
func read(raw []byte) (*Claims, error) {
	claims := &Claims{}
	return claims, proto.Unmarshal(raw, claims)
}`,
			says: "calls proto.Unmarshal",
		},
		"the wire encoder": {
			path: "workcontext/carrier.go",
			source: `package workcontext
import "google.golang.org/protobuf/encoding/protowire"
var _ = protowire.AppendTag`,
			says: "encoding/protowire",
		},
		"anypb, which marshals anything": {
			path: "workcontext/carrier.go",
			source: `package workcontext
import "google.golang.org/protobuf/types/known/anypb"
var _ = anypb.New`,
			says: "types/known/anypb",
		},
		// Round-three dynamic: both of these produced ZERO findings, because
		// the codec exemptions were per FILE. A whole-file exemption is an
		// exemption for every type in the file.
		"a capability JSON-encoded as a map, needing no tags": {
			path: "workcontext/mint.go",
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
			path: "workcontext/mint.go",
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
			path: "workcontext/cache_partition.go",
			source: `package workcontext
import "google.golang.org/protobuf/proto"
func sign(c *Claims) ([]byte, error) {
	return proto.MarshalOptions{Deterministic: true}.Marshal(c)
}`,
			says: "on a type it is not allowed to",
		},
		"a WorkContext func bound to a var": {
			path: "workcontext/carrier.go",
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
			path: "workcontext/mint.go",
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
			path: "workcontext/core.go",
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
// repositoryFiles parses every non-test Go file in the WHOLE REPOSITORY, both
// modules, naming each by its path relative to the repository root.
//
// It used to walk only this module, which was a hole with nothing behind it:
// the implementation this repository deleted lived at the repository ROOT, in
// package codefly, and the shell sweep — the root's only gate — bans imports
// rather than reading code. A reviewer built the consequence and ran it: a root
// file with a HAND-WRITTEN base64url decoder, so no banned import at all, and
// proto.Unmarshal into basev0.WorkContextV1, compiled, passed golangci-lint
// with zero issues and passed the sweep as "ok working tree (58 Go files)".
// Reading the AST is what sees that, so the AST gate reads both modules.
func repositoryFiles(t *testing.T) []sourceFile {
	t.Helper()
	root, err := filepath.Abs("..")
	require.NoError(t, err)
	var files []sourceFile
	fileSet := token.NewFileSet()
	require.NoError(t, filepath.WalkDir(root, func(absolute string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		path, relErr := filepath.Rel(root, absolute)
		if relErr != nil {
			return relErr
		}
		path = filepath.ToSlash(path)
		if entry.IsDir() {
			switch entry.Name() {
			case "testdata", ".git", ".github", ".claude":
				return fs.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		syntax, parseErr := parser.ParseFile(fileSet, absolute, nil, parser.SkipObjectResolution)
		if parseErr != nil {
			return parseErr
		}
		files = append(files, sourceFile{path: path, syntax: syntax})
		return nil
	}))
	return files
}

// moduleFiles is the same walk restricted to this module.
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

// isCapabilityType reports whether a resolved type name is one of core's Work
// Context messages. The name is package-PATH qualified, so neither a local
// alias nor an import aliased to core's own local name can answer yes by
// spelling.
func isCapabilityType(resolved string) bool {
	path, bare, found := strings.Cut(resolved, "#")
	if !found {
		return false
	}
	if path != coreModulePath && !strings.HasPrefix(path, coreModulePath+"/") {
		return false
	}
	return strings.HasPrefix(bare, capabilityTypePrefix)
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
func codecArgumentIsPermitted(file sourceFile, call ast.Node, codec string, operation string) bool {
	permitted := permittedCodecTypes(file.path, codec, operation)
	inLeaf := strings.HasPrefix(file.path, leafModulePrefix)
	if len(permitted) == 0 && inLeaf {
		// Inside the leaf module an unlisted codec use is a finding on its
		// own: the capability is that module's subject, so every codec it
		// performs is named.
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
	named := resolveTypeName(file, value, value.Pos())
	if named == "" {
		// UNRESOLVABLE IS A FINDING EVERYWHERE NOW, with the root module's
		// genuine indirections named one by one.
		//
		// "Allowed outside the leaf module" was a hatch wide enough to drive
		// the whole gate through, and it was exercised: a reviewer wrote
		//
		//	func into(raw []byte, m proto.Message) error {
		//	    return proto.Unmarshal(raw, m)
		//	}
		//
		// in the root module, called it with &basev0.WorkContextV1{}, and the
		// gate was green. One interface-typed parameter defeated the decisive
		// rule, because the codec's argument is then an interface and names no
		// type at all.
		//
		// Closing it needs the legitimate indirections enumerated, which they
		// now are — there are three, all in receipts, all taking a
		// proto.Message by design. A new one is a finding and has to be argued
		// here, which is the point.
		//
		// WHAT THIS STILL DOES NOT CATCH, stated rather than implied: a
		// capability passed INTO one of those three allowlisted functions.
		// Following a value across a call needs go/types, and this gate is
		// syntactic by choice — see the limit stated on codecArgumentIsPermitted.
		return codecIndirectionIsPermitted(file, call)
	}
	if isCapabilityType(named) {
		// THE DECISIVE RULE, and it holds in BOTH modules: a Work Context
		// message passes through a codec only where a row names it. This is
		// the whole of the root module's rule, and it is why the gate reading
		// that module closes a bypass the shell sweep cannot — a hand-written
		// base64url decoder imports nothing, so only reading the code sees
		// proto.Unmarshal into basev0.WorkContextV1.
		return slices.Contains(permitted, named)
	}
	if isCodecInterfaceType(named) {
		// AN INTERFACE CAN CARRY A CAPABILITY, so resolving the argument's
		// type is not enough when the type is one of the codec's own
		// interfaces. This is the hatch a reviewer drove the whole gate
		// through:
		//
		//	func into(raw []byte, m proto.Message) error {
		//	    return proto.Unmarshal(raw, m)
		//	}
		//
		// called with &basev0.WorkContextV1{}. The argument resolves perfectly
		// — to proto.Message — which is neither a capability nor unresolvable,
		// so both of the checks above said yes. One interface-typed parameter,
		// and the decisive rule was gone.
		//
		// The legitimate indirections are enumerated instead. A new one is a
		// finding and has to be argued in codecIndirections.
		return codecIndirectionIsPermitted(file, call)
	}
	if !inLeaf {
		return true
	}
	return slices.Contains(permitted, named)
}

// codecInterfaceTypes are the interface types a codec takes, through which a
// capability can reach it without ever being named.
//
// A list of names, and deliberately a short closed one: these are the
// parameter types of the codecs themselves, so an indirection has to go
// through one of them. `any` and a literal `interface{}` are here for
// encoding/json, whose Marshal takes one.
var codecInterfaceTypes = []string{
	"google.golang.org/protobuf/proto#Message",
	"google.golang.org/protobuf/reflect/protoreflect#ProtoMessage",
	"google.golang.org/protobuf/runtime/protoiface#MessageV1",
	"github.com/golang/protobuf/proto#Message",
	"any",
	"interface{}",
}

func isCodecInterfaceType(resolved string) bool {
	return slices.Contains(codecInterfaceTypes, resolved)
}

// codecIndirections are the functions that legitimately apply a codec to an
// interface-typed parameter, by file and by function name.
//
// Three, all in receipts, all taking a proto.Message because that is what the
// receipts contract is about: a caller's own request and response messages,
// never a capability. Keyed on the enclosing function rather than the file,
// because a file-wide exemption is what let the type rule be bypassed twice
// already.
var codecIndirections = map[string][]string{
	"receipts/digest.go":      {"RequestDigest"},
	"receipts/effect.go":      {"Record"},
	"receipts/interceptor.go": {"Handle"},
	// The runtime's own documents, decoded into a caller's destination. The
	// destination is the CALLER's type and the content is a configuration
	// document, never a capability — a capability arrives as an opaque string
	// and is read with corework.Inspect.
	"configuration_document.go": {"decodeDocument"},
}

// codecIndirectionIsPermitted reports whether an unresolvable codec argument is
// one of the named indirections.
func codecIndirectionIsPermitted(file sourceFile, call ast.Node) bool {
	permitted, named := codecIndirections[file.path]
	if !named {
		return false
	}
	enclosing := enclosingFuncName(file, call.Pos())
	return enclosing != "" && slices.Contains(permitted, enclosing)
}

// enclosingFuncName names the function containing pos, or "" at file level.
func enclosingFuncName(file sourceFile, pos token.Pos) string {
	for _, declaration := range file.syntax.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if !ok || function.Body == nil {
			continue
		}
		if function.Body.Pos() <= pos && pos <= function.Body.End() {
			return function.Name.Name
		}
	}
	return ""
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
func resolveTypeName(file sourceFile, expression ast.Expr, use token.Pos) string {
	switch typed := expression.(type) {
	case *ast.UnaryExpr:
		return resolveTypeName(file, typed.X, use)
	case *ast.CompositeLit:
		return typeName(file, typed.Type)
	case *ast.TypeAssertExpr:
		return typeName(file, typed.Type)
	case *ast.CallExpr:
		// new(T) names T, not "new".
		if function, ok := typed.Fun.(*ast.Ident); ok && function.Name == "new" && len(typed.Args) == 1 {
			return typeName(file, typed.Args[0])
		}
		// EVERY OTHER CALL IS UNKNOWN, and this used to return the function's
		// own name as though it were a type.
		//
		// That lie was a bypass: dynamicpb.NewMessage(desc) resolved to
		// "…/dynamicpb#NewMessage", which is neither a capability nor an
		// interface nor empty, so the root module's check said yes — and a
		// reviewer unmarshalled a real WorkContextV1 through it. The same went
		// for protoregistry.GlobalTypes.FindMessageByName(...).New().
		//
		// A conversion T(x) is lost with it. That is the right trade: a
		// conversion at a codec call site now needs the indirection
		// allowlist, and there are none in this repository.
		return ""
	case *ast.Ident:
		return declaredTypeName(file, typed.Name, use)
	}
	return ""
}

// typeName reduces a type expression to its name, KEEPING THE PACKAGE
// QUALIFIER: *pkg.T and pkg.T are "pkg.T", []T is "[]T", a map is "map".
//
// It used to return Sel.Name and drop the qualifier, so basev0.WorkScopeV1 and
// anything.WorkScopeV1 were the same string — and cache_partition.go's row,
// which exists for ONE core scope message, permitted a proto.Marshal of any
// type whose final name happened to be WorkScopeV1, including a local alias to
// the capability itself.
func typeName(file sourceFile, expression ast.Expr) string {
	return typeNameThroughAliases(file, expression, 0)
}

// maxAliasHops bounds the alias chase. Go rejects a cycle, but this gate parses
// source that has not been compiled — every probe here is uncompiled by
// construction — so the bound is what stops a cycle in source nobody built.
const maxAliasHops = 8

func typeNameThroughAliases(file sourceFile, expression ast.Expr, hops int) string {
	switch typed := expression.(type) {
	case *ast.StarExpr:
		return typeNameThroughAliases(file, typed.X, hops)
	case *ast.SelectorExpr:
		qualifier, ok := typed.X.(*ast.Ident)
		if !ok {
			return ""
		}
		// Resolved to the imported PACKAGE PATH, never to the local name. The
		// local name is the author's choice, so `basev0 "some/other/pkg"`
		// would otherwise let a foreign type answer to a row written for one
		// of core's — the same defect as dropping the qualifier altogether.
		path := importPathOf(file, qualifier.Name)
		if path == "" {
			return ""
		}
		return path + "#" + typed.Sel.Name
	case *ast.Ident:
		// A LOCAL NAME IS CHASED TO WHAT IT NAMES, which is the hole the
		// qualifier fix left behind. Returning the identifier as written meant
		//
		//	type carrier = *basev0.WorkContextV1
		//	var c carrier = &basev0.WorkContextV1{}
		//	proto.Unmarshal(raw, c)
		//
		// resolved to "carrier" — not a capability, not a codec interface, not
		// unresolvable — so the root module's decisive rule returned true.
		// Reproduced against this gate: green. The VALUE alias was caught, but
		// only by inspectCoreAliases and only because its right-hand side was
		// a bare selector; one `*` walked past both.
		if hops < maxAliasHops {
			if target := localTypeTarget(file, typed.Name); target != nil {
				if named := typeNameThroughAliases(file, target, hops+1); named != "" && named != typed.Name {
					return named
				}
			}
		}
		return typed.Name
	case *ast.ArrayType:
		return "[]" + typeNameThroughAliases(file, typed.Elt, hops)
	case *ast.MapType:
		// Deliberately not reduced to its value type: a map is never an
		// allowlisted codec type, and naming it as one is how the json probe
		// would have passed.
		return "map"
	}
	return ""
}

// localTypeTarget is the right-hand side of a file-level `type X = T` or
// `type X T`, or nil.
//
// BOTH forms, and the defined form deliberately: `type X basev0.WorkContextV1`
// is a second declaration of a capability's shape under a local name. It cannot
// reach proto.Unmarshal, because a defined type inherits no methods and so is
// not a proto.Message — but a rule that is true for one spelling and silent for
// the other is a rule a reader has to test to know, and the gate's whole
// subject is names chosen locally for core's types.
func localTypeTarget(file sourceFile, name string) ast.Expr {
	for _, declaration := range file.syntax.Decls {
		generic, ok := declaration.(*ast.GenDecl)
		if !ok || generic.Tok != token.TYPE {
			continue
		}
		for _, spec := range generic.Specs {
			typeSpec, ok := spec.(*ast.TypeSpec)
			if !ok || typeSpec.Name.Name != name {
				continue
			}
			return typeSpec.Type
		}
	}
	return nil
}

// declaredTypeName looks an identifier up among the declarations that are
// actually IN SCOPE at the use, and refuses to answer when more than one
// distinct declaration could be the one.
//
// Two defects it used to have, both reported and both reproducible:
//
//   - IT RETURNED THE LAST MATCH. ast.Inspect's false return prunes a subtree
//     and then carries on over the siblings, so `found` was overwritten by
//     every later declaration of the same name — and a function placed BEFORE
//     mint.go's credentialFrom could write `body := claims` and have `body`
//     resolve to the mintResponse declared further down.
//   - IT IGNORED SCOPE. A name declared in one function resolved a name used
//     in another.
//
// Now the search is restricted to the function enclosing the use (plus
// file-level declarations), the candidate must be declared BEFORE the use, and
// two candidates that disagree resolve to "" — which is not permitted, because
// a gate that guesses between two readings is not a gate.
func declaredTypeName(file sourceFile, name string, use token.Pos) string {
	scope := enclosingBody(file, use)
	var candidates []string
	consider := func(node ast.Node, resolved string) {
		if node.Pos() > use || resolved == "" {
			return
		}
		if !slices.Contains(candidates, resolved) {
			candidates = append(candidates, resolved)
		}
	}
	inspect := func(root ast.Node) {
		ast.Inspect(root, func(node ast.Node) bool {
			switch declared := node.(type) {
			case *ast.ValueSpec:
				for index, declaredName := range declared.Names {
					if declaredName.Name != name {
						continue
					}
					if declared.Type != nil {
						consider(declared, typeName(file, declared.Type))
						continue
					}
					if index < len(declared.Values) {
						consider(declared, resolveTypeName(file, declared.Values[index], use))
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
					consider(declared, resolveTypeName(file, declared.Rhs[index], use))
				}
			case *ast.FuncDecl:
				// Parameters and results are in scope only inside their own
				// function, which is what scope here means.
				if scope == nil || declared.Body != scope {
					return true
				}
				for _, list := range fieldLists(declared.Type) {
					for _, field := range list {
						for _, declaredName := range field.Names {
							if declaredName.Name == name {
								consider(field, typeName(file, field.Type))
							}
						}
					}
				}
			}
			return true
		})
	}
	// File-level declarations, then the enclosing function's own body.
	for _, declaration := range file.syntax.Decls {
		if function, ok := declaration.(*ast.FuncDecl); ok {
			if scope != nil && function.Body == scope {
				inspect(function)
			}
			continue
		}
		inspect(declaration)
	}
	if len(candidates) != 1 {
		// Nothing, or an ambiguity. Either way nothing is permitted.
		return ""
	}
	return candidates[0]
}

// enclosingBody is the body of the function containing pos, or nil at file
// level. It is what makes the lookup above scoped rather than file-wide.
func enclosingBody(file sourceFile, pos token.Pos) *ast.BlockStmt {
	var found *ast.BlockStmt
	for _, declaration := range file.syntax.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if !ok || function.Body == nil {
			continue
		}
		if function.Body.Pos() <= pos && pos <= function.Body.End() {
			found = function.Body
		}
	}
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

// importPathOf resolves a file-local package name to the path it was imported
// from, or "" when nothing imported it.
//
// It is what makes a type name mean a type rather than a spelling: the local
// name in `basev0 "…/base/v0"` is chosen by whoever wrote the import, so an
// allowlist compared against local names is one anybody satisfies by aliasing
// a different package to the expected name.
func importPathOf(file sourceFile, local string) string {
	for _, imported := range importsOf(file.syntax) {
		if imported.name == local {
			return imported.path
		}
	}
	return ""
}
