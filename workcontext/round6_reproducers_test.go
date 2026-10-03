package workcontext

import (
	"context"
	"go/ast"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// Round six, layer 2: the findings a static reviewer executed the EXTRACTED
// logic of, each reproduced here against the real thing.
//
// The pattern this round repeats, named because it is now four rounds old: the
// defects are in the code written to fix the previous review. B1's fail-open
// lives inside the assertion added for round five's blocker; B3's pointer alias
// walks past the qualifier fix from round four; B4's embedded field walks past
// the field freeze from round five.

// B3. A POINTER ALIAS DEFEATED THE ROOT MODULE'S DECISIVE RULE.
//
// The root module has exactly one codec rule — a Work Context message passes
// through a codec only where a row names it — and typeName returned a local
// identifier as written. So
//
//	type carrier = *basev0.WorkContextV1
//	var c carrier = &basev0.WorkContextV1{}
//	proto.Unmarshal(raw, c)
//
// resolved to "carrier": not a capability, not a codec interface, not
// unresolvable, and therefore permitted. Measured against this gate: green.
//
// The VALUE alias was caught, and only by inspectCoreAliases, whose check read
// spec.Type as a bare selector — so one `*` walked past the alias rule and the
// codec rule at the same time. Both are fixed: local names are chased to what
// they name, and the alias rule unwraps pointers and slices.
func TestAPointerAliasDoesNotRenameACapability(t *testing.T) {
	for name, source := range map[string]string{
		"a pointer alias in the root module": `package codefly
import (
	"google.golang.org/protobuf/proto"
	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
)
type carrier = *basev0.WorkContextV1
func readit(raw []byte) (*basev0.WorkContextV1, error) {
	var c carrier = &basev0.WorkContextV1{}
	return c, proto.Unmarshal(raw, c)
}`,
		"a chain of aliases": `package codefly
import (
	"google.golang.org/protobuf/proto"
	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
)
type inner = basev0.WorkContextV1
type carrier = *inner
func readit(raw []byte) (*inner, error) {
	var c carrier = &inner{}
	return c, proto.Unmarshal(raw, c)
}`,
		"a slice alias": `package codefly
import (
	"google.golang.org/protobuf/proto"
	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
)
type batch = []*basev0.WorkContextV1
func readit(raw []byte, all batch) error { return proto.Unmarshal(raw, all[0]) }`,
		// A DEFINED type cannot reach proto.Unmarshal — it inherits no methods
		// — but a rule true for one spelling and silent for the other is a
		// rule a reader has to test to know.
		"a defined type over a capability": `package codefly
import basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
type carrier basev0.WorkContextV1
var _ = carrier{}`,
	} {
		t.Run(name, func(t *testing.T) {
			findings := inspectForSecondImplementation(parseSource(t, "second_parser.go", source))
			require.NotEmpty(t, findings,
				"a capability under a local name is still a capability")
		})
	}

	// And the alias the rule exists to permit stays permitted, so this is not
	// green by refusing everything.
	require.Empty(t, inspectForSecondImplementation(parseSource(t, coreAliasFile, `package workcontext
import corework "github.com/codefly-dev/core/workcontext"
type Verifier = corework.Verifier
type Claims = corework.Claims`)))
}

// EACH OF THE TWO RULES, SEPARATELY, because driving them together is how two
// mutations survived.
//
// The fix for the pointer alias was two coupled edits — typeName chases a local
// name to what it names, and inspectCoreAliases unwraps a pointer — and a probe
// through inspectForSecondImplementation is satisfied by EITHER of them. Both
// mutations survived the test above, which is the same shape that survived in
// round four and for the same reason. So each rule is asserted at the rule.
func TestTypeNameChasesALocalNameToWhatItNames(t *testing.T) {
	file := parseSource(t, "second_parser.go", `package codefly
import basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
type carrier = *basev0.WorkContextV1
type chained = carrier
var direct *basev0.WorkContextV1
var aliased carrier
var twice chained`)

	// THIS is what the root module's decisive rule reads, and the whole of
	// B3: a local name must resolve to the capability, not to itself.
	for _, name := range []string{"direct", "aliased", "twice"} {
		resolved := resolveTypeName(file, ast.NewIdent(name), file.syntax.End())
		require.True(t, isCapabilityType(resolved),
			"%s resolved to %q; the codec rule keys on this string, so a local name that "+
				"answers to itself is a capability the rule cannot see", name, resolved)
	}

	// And a name that is not an alias still answers as itself, so the chase
	// does not invent resolutions.
	plain := parseSource(t, "second_parser.go", `package codefly
var count int`)
	require.Equal(t, "int", resolveTypeName(plain, ast.NewIdent("count"), plain.syntax.End()))
}

func TestTheCoreAliasRuleSeesThroughAPointer(t *testing.T) {
	core := map[string]bool{"basev0": true}
	for name, declaration := range map[string]string{
		"a value alias":   "type carrier = basev0.WorkContextV1",
		"a pointer alias": "type carrier = *basev0.WorkContextV1",
		"a slice alias":   "type batch = []*basev0.WorkContextV1",
		"a defined type":  "type carrier basev0.WorkContextV1",
	} {
		t.Run(name, func(t *testing.T) {
			file := parseSource(t, "second_parser.go", `package codefly
import basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
`+declaration)
			require.NotEmpty(t, inspectCoreAliases(file, core),
				"a second local name for one of core's types belongs in %s", coreAliasFile)
		})
	}

	// The one file whose job is aliasing core is still exempt.
	exempt := parseSource(t, coreAliasFile, `package workcontext
import corework "github.com/codefly-dev/core/workcontext"
type Verifier = corework.Verifier`)
	require.Empty(t, inspectCoreAliases(exempt, map[string]bool{"corework": true}))
}

// B4. AN EMBEDDED FIELD WAS NOT A FIELD.
//
// assertFrozenStructShapes walked field.Names, and an embedded field has none —
// so an embedded struct added to mintRequest left the frozen set
// byte-identical. Measured: no finding anywhere in the gate, and
// encoding/json promotes an embedded struct's exported fields into the
// enclosing object, so it is a new field on the wire. That is the defect class
// the freeze was added for, one level sideways from where it was added.
func TestAnEmbeddedFieldIsAFieldOfAFrozenStruct(t *testing.T) {
	mintFile := func(extra string) sourceFile {
		return parseSource(t, "workcontext/mint.go", `package workcontext
import "encoding/json"
type smuggled struct {
	Echo string
}
type mintRequest struct {
	Audience           string `+"`json:\"audience\"`"+`
	ProjectionAudience string `+"`json:\"projection_audience\"`"+`
`+extra+`
}
type mintResponse struct {
	WorkContext      string `+"`json:\"work_context\"`"+`
	InstallationID   string `+"`json:\"installation_id\"`"+`
	BuildIncarnation string `+"`json:\"build_incarnation\"`"+`
}
func encode(a string) ([]byte, error) { return json.Marshal(mintRequest{Audience: a}) }`)
	}

	require.NotEmpty(t, frozenStructViolations([]sourceFile{mintFile("\tsmuggled")}),
		"an embedded struct carries fields onto the wire and the freeze must see it")
	require.NotEmpty(t, frozenStructViolations([]sourceFile{mintFile("\t*smuggled")}),
		"and so does an embedded pointer")

	// The shape as it actually is passes, so the assertion is not simply
	// failing — and this is the mutation guard for the two above.
	require.Empty(t, frozenStructViolations([]sourceFile{mintFile("")}),
		"the frozen field sets must match the structs this repository really has")
}

// B2. THE TWO GATES' BAN LISTS DISAGREED, in both directions.
//
// Measured: four import paths the AST gate bans — the legacy protobuf module,
// protoiface, protoimpl, and a vendored path ending /ed25519 — passed the shell
// sweep with `ok working tree (4 Go files)`, exit 0. That is the ROOT module,
// where the sweep is the only gate. And in the other direction the shell banned
// crypto/cipher, crypto/aes, crypto/des and crypto/rc4 — a GMAC or a CMAC is a
// MAC assembled from a block cipher and names no MAC — while this gate, the one
// that reads the module the capability lives in, did not.
//
// Both lists are now entry-for-entry, and THIS is what keeps them that way: two
// lists a person maintains by hand are two lists, and the only thing that makes
// them one is a test that fails when they differ.
func TestTheShellSweepBansEverythingTheASTGateBans(t *testing.T) {
	script, err := os.ReadFile(filepath.Join("..", "scripts", "check-one-implementation.sh"))
	require.NoError(t, err)

	shell := shellBanPatterns(t, string(script))

	for _, path := range bannedImports {
		require.True(t, shell.matches(path),
			"the AST gate bans %q and the shell sweep does not. The sweep is the ONLY gate in "+
				"the root module, so a ban that lives only here does not hold where the deleted "+
				"implementation actually lived.", path)
	}
	for _, fragment := range bannedImportSubstrings {
		require.True(t, shell.matches("github.com/vendored/"+fragment),
			"the AST gate bans any path containing %q and the shell sweep does not match "+
				"a vendored one", fragment)
	}
	for _, prefix := range bannedImportPrefixes {
		require.True(t, shell.matches(prefix+"ed25519"),
			"the AST gate bans the prefix %q and the shell sweep does not", prefix)
	}
	for _, path := range envelopeDecoders {
		require.True(t, shell.matches(path),
			"the AST gate bans the envelope decoder %q and the shell sweep does not", path)
	}

	// AND THE REVERSE, which is the direction that was wrong for the cipher
	// family. Anything the sweep refuses repository-wide must be refused here
	// too, unless this gate holds it to named files and symbols instead —
	// which is strictly stronger, not weaker.
	for _, path := range []string{
		"crypto", "crypto/ed25519", "crypto/ecdsa", "crypto/rsa", "crypto/dsa",
		"crypto/hmac", "crypto/ecdh", "crypto/elliptic", "crypto/subtle",
		"crypto/cipher", "crypto/aes", "crypto/des", "crypto/rc4",
		"crypto/sha512", "crypto/sha1", "crypto/sha3", "crypto/md5",
		"crypto/hkdf", "crypto/pbkdf2",
		"encoding/gob", "encoding/asn1", "encoding/xml",
		"google.golang.org/protobuf/encoding/protojson",
		"google.golang.org/protobuf/encoding/protowire",
	} {
		if !shell.matches(path) {
			continue
		}
		_, narrowed := narrowedImports[path]
		require.True(t, slices.Contains(bannedImports, path) || narrowed,
			"the shell sweep refuses %q repository-wide and this gate neither bans it nor "+
				"holds it to named files and symbols — so the module the capability lives in "+
				"is the one with the weaker rule", path)
	}
}

// shellBans is the sweep's three regexes, compiled.
type shellBans struct{ patterns []*regexp.Regexp }

func (b shellBans) matches(path string) bool {
	for _, pattern := range b.patterns {
		if pattern.MatchString(path) {
			return true
		}
	}
	return false
}

// shellBanPatterns reads primitives=, encoders= and envelope= out of the script
// itself, so the test cannot drift from the file it is about by being updated
// alongside a copy of it.
func shellBanPatterns(t *testing.T, script string) shellBans {
	t.Helper()
	var bans shellBans
	for _, name := range []string{"primitives", "encoders", "envelope"} {
		found := false
		for _, line := range strings.Split(script, "\n") {
			prefix := name + "='"
			if !strings.HasPrefix(line, prefix) || !strings.HasSuffix(line, "'") {
				continue
			}
			expression := strings.TrimSuffix(strings.TrimPrefix(line, prefix), "'")
			compiled, err := regexp.Compile(expression)
			require.NoError(t, err, "%s= is not a usable expression: %s", name, expression)
			bans.patterns = append(bans.patterns, compiled)
			found = true
			break
		}
		require.True(t, found,
			"no %s= assignment in check-one-implementation.sh; this test reads the script's own "+
				"lists and cannot check a list it cannot find", name)
	}
	// encoding/json is handled by exact name in the sweep rather than by one of
	// the three expressions, so it is added here to match.
	bans.patterns = append(bans.patterns, regexp.MustCompile(`^encoding/json$`))
	return bans
}

// B5. RequestTimeout DID NOT BOUND THE DETACHED ATTEMPT.
//
// ProjectedTokenSource is a caller's interface and takes no context, so the
// read in front of the HTTP request was bounded by nothing. Measured with a
// source that blocks and RequestTimeout at 150ms: Credential returned after
// 3.0s, bounded by the CALLER's deadline — and with no caller deadline it does
// not return at all, because the detached goroutine never closes `done`, so
// every later caller waits on an attempt that will not finish and no hold-off
// is ever installed. mintInto's own comment said RequestTimeout was "what makes
// the request terminate".
func TestRequestTimeoutBoundsTheTokenSourceRead(t *testing.T) {
	clock := &movableClock{at: testClock}
	host := newMintHost(t, clock.now)
	source := &blockingSource{released: make(chan struct{})}
	t.Cleanup(func() { close(source.released) })
	client := newTestMintClient(t, host, projectedFile(t, "projected"), clock.now,
		func(options *MintOptions) {
			options.ProjectedToken = source
			options.RequestTimeout = 150 * time.Millisecond
		})

	// A caller whose own deadline is twenty times RequestTimeout, so what
	// bounds the attempt is observable rather than inferred.
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	started := time.Now()
	_, err := client.Credential(ctx)
	elapsed := time.Since(started)

	require.ErrorIs(t, err, ErrMintUnavailable,
		"a slow projection is a mount under load, which clears: held off, never latched")
	require.NoError(t, client.Refused(), "and it must not latch")
	require.ErrorContains(t, err, "reading the projected token did not finish")
	require.Less(t, elapsed, time.Second,
		"RequestTimeout is 150ms; an attempt that runs %s is bounded by the caller instead", elapsed)
}

// blockingSource is a token source that does not return — a hung mount, a
// source holding a lock, an implementation with a bug in it.
type blockingSource struct{ released chan struct{} }

func (s *blockingSource) ProjectedToken() (string, error) {
	<-s.released
	return "projected", nil
}

// B6. ENDPOINT TRUST WAS OPTIONAL, AND SILENTLY THE SYSTEM POOL.
//
// Every other route to a weak transport here was closed — no caller-supplied
// client, no reachable Transport, a TLS 1.3 floor, no followed redirect — and
// the trust anchor defaulted to whatever the image shipped. A mis-issued
// certificate for the host name, or a corporate interception root, receives the
// projected service-account token. It is a deployment decision, so it is stated
// or construction refuses; TrustSystemRoots is how a deployment that means the
// host's pool says so.
func TestTheMintEndpointsTrustAnchorMustBeStated(t *testing.T) {
	base := MintOptions{
		URL:                "https://mint.example/platform/_mint",
		Authority:          newTestPin(),
		Audience:           testAudienceName,
		ProjectedToken:     ProjectedTokenFile("/var/run/secrets/token"),
		ProjectionAudience: "projection-audience",
	}

	_, err := NewMintClient(base)
	require.ErrorIs(t, err, ErrInvalid)
	require.ErrorContains(t, err, "no trust anchor")
	require.ErrorContains(t, err, "https://mint.example/platform/_mint",
		"the refusal must name the endpoint the projection would have been sent to")

	stated := base
	stated.TrustSystemRoots = true
	_, err = NewMintClient(stated)
	require.NoError(t, err, "a deployment that says it means the host's pool is configured")

	named := base
	named.RootCAs = certPoolOf()
	_, err = NewMintClient(named)
	require.NoError(t, err, "and so is one that names the roots")

	both := named
	both.TrustSystemRoots = true
	_, err = NewMintClient(both)
	require.ErrorIs(t, err, ErrInvalid)
	require.ErrorContains(t, err, "not both",
		"two anchors is not a stronger statement than one; it is an unanswered question")
}
