package workcontext

import (
	"context"
	"errors"
	"fmt"
	"go/ast"
	"net/http"
	"sync/atomic"
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

// ROUND SEVEN, BLOCKER: THE PUBLISHED-REF SWEEP WAS STILL A DENYLIST.
//
// The deny-by-default rule lived in this package, which reads a CHECKOUT. The
// ref sweep is the only thing that runs over a published ref — and it is the
// whole of the required check — and it had its own three regexes. A reviewer
// ran that predicate over the round-six second implementation:
//
//	encoding/json/v2    permitted
//	crypto/mldsa        permitted
//	protodelim          permitted
//	grpc/encoding       permitted
//	C                   permitted
//	crypto/ed25519      rejected
//
// So the pair that encodes a WorkContextV1 in the deleted format and signs it
// could sit on any branch with the required check green. Two policies is one
// policy and one hole.
//
// There is one policy file now, scripts/allowed-imports.txt, read by this
// package and by the sweep. This test is what makes "one" true: it asserts the
// file describes the tree, and the sweep's own tests assert the sweep enforces
// the file.
func TestOneImportPolicyGovernsTheTreeAndEveryPublishedRef(t *testing.T) {
	policy := loadImportPolicy(t)

	// THE SHAPES THE OLD DENYLIST PERMITTED. Each is absent from both module
	// lists, so each is a finding wherever it appears — checkout or ref.
	for _, spec := range []string{
		"encoding/json/v2", "crypto/mldsa",
		"google.golang.org/protobuf/encoding/protodelim",
		"google.golang.org/grpc/encoding",
		"google.golang.org/protobuf/encoding/prototext",
		"encoding/json/jsontext", "crypto/hpke",
	} {
		for _, module := range []string{"root", "leaf"} {
			require.NotContains(t, policy[module], spec,
				"%q is on the %s allowlist, so the sweep permits it on every published ref",
				spec, module)
		}
	}

	// And `C` is never on a list, because it is not a path. The sweep refuses
	// it by name; adding it here would be a line somebody could write.
	for _, module := range []string{"root", "leaf"} {
		require.NotContains(t, policy[module], "C")
	}
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
func TestTheMintEndpointsTrustAnchorIsRequired(t *testing.T) {
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
	require.ErrorContains(t, err, "x509.SystemCertPool",
		"and must name the two lines a deployment that really means the host's pool writes, "+
			"because a refusal with no way forward gets worked around")

	named := base
	named.RootCAs = certPoolOf()
	_, err = NewMintClient(named)
	require.NoError(t, err, "naming the roots is the whole of the requirement")
}

// F-5 and F-6. EVERY 200 THAT IS NOT A CAPABILITY LATCHED FOREVER, and so did
// every redirect. Executed over httptest-TLS: `{}`, `null`,
// `{"work_context":"not-a-capability"}`, a 307 to another host and a 308 to the
// same host with a trailing slash each became ErrMintRefused and stayed refused
// through the host recovering and the clock passing every hold-off.
//
// They are the same class as the text/html 200 and the oversized 200 beside
// them, both already retryable: something that is not the host is answering.
// ErrMintRefused is documented as "the host will give the same answer again",
// and a mesh mid-rollout is the shape least likely to.
//
// This also covers the classifications F-6 named as untested, because the table
// drives each one and then drives RECOVERY, which is the half that makes
// "retryable" mean anything.
func TestNoAnswerFromSomethingThatIsNotTheHostLatches(t *testing.T) {
	for name, answer := range map[string]struct {
		status  int
		headers map[string]string
		body    string
	}{
		"an empty JSON object": {status: http.StatusOK, body: `{}`},
		"a JSON null":          {status: http.StatusOK, body: `null`},
		"a work_context that is not a capability": {status: http.StatusOK, body: `{"work_context":"not-a-capability"}`},
		"an empty work_context":                   {status: http.StatusOK, body: `{"work_context":""}`},
		// The two F-6 named as untested, beside the new ones so one table
		// drives the whole 200 path.
		"a 200 carrying text/html": {
			status:  http.StatusOK,
			headers: map[string]string{"Content-Type": "text/html; charset=utf-8"},
			body:    "<html>gateway</html>",
		},
		"a 200 that does not decode": {status: http.StatusOK, body: `{"work_context":`},
		"a 200 with no Content-Type at all": {
			status:  http.StatusOK,
			headers: map[string]string{"Content-Type": ""},
			body:    `{"work_context":"x"}`,
		},
	} {
		t.Run(name, func(t *testing.T) {
			clock := &movableClock{at: testClock}
			host := newMintHost(t, clock.now)
			host.answer = &cannedAnswer{status: answer.status, headers: answer.headers, body: answer.body}
			client := newTestMintClient(t, host, projectedFile(t, "projected"), clock.now)

			_, err := client.Credential(context.Background())

			require.ErrorIs(t, err, ErrMintUnavailable,
				"something that is not the host answered; that is not a verdict")
			require.NotErrorIs(t, err, ErrMintRefused)
			require.NoError(t, client.Refused(),
				"this latched and stayed refused forever through the host recovering")

			// AND IT RECOVERS, which is the half that makes "retryable" a
			// claim rather than a label.
			host.answer = nil
			clock.set(clock.at.Add(time.Minute))
			credential, err := client.Credential(context.Background())
			require.NoError(t, err, "the host recovered and the client did not")
			require.NotEmpty(t, credential.Token())
		})
	}
}

// F-6. THE ONE LATCH RULE, asserted. Reverting it to its negation — "anything
// that is not an outage latches" — survived every test in this suite.
//
// The rule is one sentence: only ErrMintRefused is terminal. Its negation is
// also one sentence and is the previous revision, under which every error this
// client had not thought about became a permanent stop. So it is driven over
// the error CLASSES rather than over one of them.
func TestOnlyAHostRefusalIsTerminal(t *testing.T) {
	for name, source := range map[string]struct {
		err     error
		latches bool
	}{
		// ErrInvalid says in its own comment that it is not latched, and the
		// negation latched it.
		"a misconfiguration from the token source": {
			err: fmt.Errorf("%w: no projected token path", ErrInvalid),
		},
		// An error from a caller's own reader carrying NO sentinel. Under the
		// negation this latched, so errors.Is(client.Refused(), ErrMintRefused)
		// was false while the client was permanently refused — the two ways of
		// asking disagreed.
		"an unlabelled error from a caller's source": {
			err: errors.New("the caller's own reader failed"),
		},
		"an outage from the token source": {
			err: fmt.Errorf("%w: read projected token: EIO", ErrMintUnavailable),
		},
		// And the one that does latch, so this is not green by never latching.
		"a refusal from the token source": {
			err: fmt.Errorf("%w: the host said no", ErrMintRefused), latches: true,
		},
	} {
		t.Run(name, func(t *testing.T) {
			clock := &movableClock{at: testClock}
			host := newMintHost(t, clock.now)
			faulty := &faultySource{err: source.err}
			client := newTestMintClient(t, host, projectedFile(t, "projected"), clock.now,
				func(options *MintOptions) { options.ProjectedToken = faulty })

			_, err := client.Credential(context.Background())
			require.Error(t, err)

			if source.latches {
				require.ErrorIs(t, client.Refused(), ErrMintRefused,
					"a host refusal is terminal and Refused() must say so")
				return
			}
			require.NoError(t, client.Refused(),
				"only ErrMintRefused is terminal; this stopped the process for good")

			// THE RECOVERY, which is what "not terminal" means.
			faulty.err = nil
			faulty.token = "projected"
			clock.set(clock.at.Add(time.Minute))
			credential, err := client.Credential(context.Background())
			require.NoError(t, err)
			require.NotEmpty(t, credential.Token())
		})
	}
}

// F-6. THE DETACHED REQUEST CARRIES THE CALLER'S VALUES. Reverting
// context.WithoutCancel(caller) to context.Background() survived, because
// nothing read anything off the request's context.
//
// What that costs is invisible and real: a trace span, a request id, whatever
// an http.RoundTripper in the caller's stack reads. Background() dropped all of
// it silently while the comment said the detaching was about cancellation.
func TestTheDetachedMintRequestKeepsTheCallersValues(t *testing.T) {
	type key struct{}
	clock := &movableClock{at: testClock}
	host := newMintHost(t, clock.now)
	client := newTestMintClient(t, host, projectedFile(t, "projected"), clock.now)

	carried := make(chan any, 1)
	client.httpClient.Transport = &valueReadingTransport{
		inner: client.httpClient.Transport,
		key:   key{},
		seen:  carried,
	}

	_, err := client.Credential(context.WithValue(context.Background(), key{}, "trace-42"))
	require.NoError(t, err)

	select {
	case value := <-carried:
		require.Equal(t, "trace-42", value,
			"the detached request dropped the caller's context values; detaching from "+
				"CANCELLATION is the point, not from everything")
	default:
		t.Fatal("the transport was never reached, so this asserted nothing")
	}
}

// valueReadingTransport reports the caller's context value as the request saw
// it.
type valueReadingTransport struct {
	inner http.RoundTripper
	key   any
	seen  chan any
}

func (t *valueReadingTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	select {
	case t.seen <- request.Context().Value(t.key):
	default:
	}
	return t.inner.RoundTrip(request) //nolint:wrapcheck // a transport returns the inner error
}

// THE LATCH SITES, AUDITED, with the one candidate examined and REJECTED.
//
// Reading the one-latch rule against mintOnce, Authority.Recheck looked like
// the projected-token defect one layer up: any failure to re-resolve a pinned
// value latches, so a momentary configuration read failure would permanently
// stop a healthy process. I changed it, and the root module's
// TestAuthorityValueWithdrawnIsAChange rejected the change — correctly.
//
// A withdrawn value and an unreadable one arrive identically (withdrawing an
// injected variable makes the live read FAIL, it does not return empty), and
// the asymmetry runs the other way here: a held credential keeps being served
// through an outage, so a withdrawn audience classed as an outage means serving
// under authority somebody removed, until expiry.
//
// What this asserts is the classification as it stands, so the next audit finds
// the argument instead of repeating the attempt.
func TestThePinnedAuthorityLatchesAndTheRestDoNot(t *testing.T) {
	for name, probe := range map[string]struct {
		install func(*mintHost, *MintClient)
		latches bool
	}{
		// The pin: terminal, deliberately, and argued above.
		"the pinned authority did not re-check": {
			install: func(host *mintHost, _ *MintClient) {
				host.pin.set(testAudience, errors.New("audience changed under a running process"))
			},
			latches: true,
		},
		// Everything a host or a middlebox does that is not 401/403: an outage.
		"a 200 with no capability in it": {
			install: func(host *mintHost, _ *MintClient) {
				host.answer = &cannedAnswer{status: http.StatusOK, body: `{}`}
			},
		},
		"a 503": {
			install: func(host *mintHost, _ *MintClient) { host.refuseWith = http.StatusServiceUnavailable },
		},
		// And the two enumerated refusals, so this is not green by never
		// latching.
		"a 401": {
			install: func(host *mintHost, _ *MintClient) { host.refuseWith = http.StatusUnauthorized },
			latches: true,
		},
		"a 403": {
			install: func(host *mintHost, _ *MintClient) { host.refuseWith = http.StatusForbidden },
			latches: true,
		},
	} {
		t.Run(name, func(t *testing.T) {
			clock := &movableClock{at: testClock}
			host := newMintHost(t, clock.now)
			client := newTestMintClient(t, host, projectedFile(t, "projected"), clock.now)
			probe.install(host, client)

			_, err := client.Credential(context.Background())
			require.Error(t, err)

			if probe.latches {
				require.ErrorIs(t, client.Refused(), ErrMintRefused,
					"this is an enumerated refusal and Refused() must say so")
				return
			}
			require.NoError(t, client.Refused(), "only an enumerated refusal is terminal")

			host.answer = nil
			host.refuseWith = 0
			clock.set(clock.at.Add(time.Minute))
			credential, err := client.Credential(context.Background())
			require.NoError(t, err, "the host recovered and the client did not")
			require.NotEmpty(t, credential.Token())
		})
	}
}

// CODEX 6: the timeout fix left an UNBOUNDED population of abandoned readers.
//
// ProjectedTokenSource takes no context, so a read cannot be cancelled and a
// blocked source leaves its goroutine blocked. One goroutine per ATTEMPT is not
// a bound on outstanding goroutines: against a source that never returns they
// accumulate forever, at the maximum-backoff rate, and a source that
// single-flight had been protecting gets concurrent calls. The committed test
// proved one caller returns promptly and said nothing about the second.
func TestABlockedTokenSourceIsReadOnceNoMatterHowManyAttempts(t *testing.T) {
	clock := &movableClock{at: testClock}
	host := newMintHost(t, clock.now)
	source := &countingBlockedSource{released: make(chan struct{})}
	t.Cleanup(func() { close(source.released) })
	client := newTestMintClient(t, host, projectedFile(t, "projected"), clock.now,
		func(options *MintOptions) {
			options.ProjectedToken = source
			options.RequestTimeout = 60 * time.Millisecond
		})

	// SIX attempts, each timing out, with the clock moved past every hold-off
	// so each one really starts.
	for attempt := range 6 {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		_, err := client.Credential(ctx)
		cancel()
		require.ErrorIs(t, err, ErrMintUnavailable, "attempt %d", attempt)
		clock.set(clock.at.Add(10 * time.Minute))
	}

	require.EqualValues(t, 1, source.calls.Load(),
		"six attempts against a blocked source started %d reads; a source that cannot be "+
			"cancelled must be read once and waited on, or the readers accumulate without "+
			"limit and a source single-flight was protecting gets concurrent calls",
		source.calls.Load())
	require.NoError(t, client.Refused(), "and none of it latches")
}

// countingBlockedSource blocks and counts how many times it was entered.
type countingBlockedSource struct {
	calls    atomic.Int64
	released chan struct{}
}

func (s *countingBlockedSource) ProjectedToken() (string, error) {
	s.calls.Add(1)
	<-s.released
	return "projected", nil
}
