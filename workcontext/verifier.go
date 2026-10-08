package workcontext

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"
)

// MeshTransportGroup and MeshTransportKey name the workspace setting a
// composition asserts the cell's mesh with.
//
// In-cell transport security is the mesh's: every hop between workloads on a
// cell is authenticated and encrypted by the platform mesh, so a service
// terminates no TLS of its own for an in-cell peer. A composition states that
// out loud, and a service accepts plaintext to an in-cluster Service address
// exactly under that assertion and refuses it otherwise, by name.
//
// This is the same group, key and remedy sentence the host and the composed
// modules apply to their own in-cluster hops. It is reimplemented here rather
// than imported — a module never imports another module's internals — so the
// shared thing is the contract and each side owns its copy of the check. This
// copy is the SDK's, which is what lets a consumer route every plaintext hop it
// has through one check instead of writing a fourth.
const (
	MeshTransportGroup = "internal-transport"
	MeshTransportKey   = "mesh-protected"
)

// MeshTransportAssertion is the one value that asserts the mesh. It is compared
// LITERALLY: see MeshProtected.
const MeshTransportAssertion = "true"

// MeshTransportRemedy is the sentence every plaintext refusal ends with, so an
// operator reads the one supported way through off the error rather than off a
// document.
const MeshTransportRemedy = "use https, or — only for an in-cluster Service address " +
	"(<service>.<namespace>.svc, optionally followed by cluster.local) when every in-cluster hop " +
	"is carried by a mutually authenticated mesh (mTLS) — assert it with the workspace setting " +
	MeshTransportGroup + "/" + MeshTransportKey + ", whose value must be exactly " +
	MeshTransportAssertion + " with nothing around it"

// TransportSource answers the two things an admission decision needs, and
// answers both from the runtime rather than from an argument a caller chooses:
// the composition's mesh assertion, and whether this is a local run.
//
// `codefly.For(ctx)` satisfies it. That is the point of its being an interface
// of two accessors rather than two parameters: a boolean parameter is a
// per-service opt-in that no address has to qualify for, which is the shape the
// host deleted. Here the only way to say plaintext is permitted is for the
// composition to have said it.
//
// WorkspaceValueIfSet rather than WorkspaceValue, because the three answers
// have to stay three. A setting that is NOT CONFIGURED is an answer — the mesh
// is not asserted. A setting whose delivery could not be read, or whose
// authority-bearing value has drifted since it was pinned at boot, is not an
// answer at all, and reading it as "not asserted" would be a lookup failure
// quietly deciding a posture question.
type TransportSource interface {
	// WorkspaceValueIfSet resolves a workspace setting: the value and true when
	// it is set, ("", false, nil) when nothing carries it, and an error when the
	// lookup failed.
	WorkspaceValueIfSet(name string, key string) (string, bool, error)

	// IsLocalRun reports whether the Codefly environment is local.
	IsLocalRun() bool
}

// MeshProtected reports whether the composition asserted that the cell's mesh
// protects plaintext in-cluster hops.
//
// Fail-closed on three counts.
//
// ONLY THE LITERAL VALUE "true" ASSERTS IT. Not " true", not "true\n", not a
// value carrying any other whitespace: the comparison is byte for byte. An
// earlier revision trimmed first, on the reasoning that a value delivered by
// file carries the newline the file ends with — but TrimSpace trims every
// Unicode space, so values that are not the assertion asserted it, and the
// delivery's own shape is the delivery's problem to fix rather than this
// check's to absorb.
//
// Unset and "false" keep plaintext refused. ANY OTHER VALUE IS AN ERROR rather
// than being read as either answer, because a misspelled assertion must not pass
// for an absent one nor for a present one.
//
// A LOOKUP FAILURE IS NOT ABSENCE. An unreadable delivery, or a value that has
// drifted from the one pinned at boot, is returned as an error; only a setting
// nothing carries is "not asserted".
//
// No refusal here echoes the value. WorkspaceValueIfSet reads the public
// namespace and then the secret one, so the value may be a credential, and a
// configuration error reaches boot-time logging.
func MeshProtected(source TransportSource) (bool, error) {
	if source == nil {
		return false, fmt.Errorf("%w: admission needs a transport source", ErrInvalid)
	}
	value, set, err := source.WorkspaceValueIfSet(MeshTransportGroup, MeshTransportKey)
	if err != nil {
		return false, fmt.Errorf(
			"%w: %s/%s could not be read, which is not the same as not being asserted: %w",
			ErrInvalid, MeshTransportGroup, MeshTransportKey, redactedLookupFailure(err))
	}
	if !set {
		return false, nil
	}
	switch value {
	case MeshTransportAssertion:
		return true, nil
	case "", "false":
		// An empty value is "not asserted", like an absent one. It is the one
		// value that is not a misspelling: nothing was said.
		return false, nil
	default:
		return false, fmt.Errorf(
			"%w: %s/%s is set to something other than %q or %q, and is compared byte for byte; "+
				"its value is not reported because this setting is read from the secret namespace too",
			ErrInvalid, MeshTransportGroup, MeshTransportKey, MeshTransportAssertion, "false")
	}
}

// redactedLookupFailure keeps a source's error in the chain for errors.Is while
// keeping its text out of the message, because a lookup error may name the value
// it could not use.
func redactedLookupFailure(err error) error {
	return lookupFailure{err: err}
}

type lookupFailure struct{ err error }

func (f lookupFailure) Error() string { return "the workspace lookup failed" }
func (f lookupFailure) Unwrap() error { return f.err }

// ClusterServiceHost reports whether hostname names a Kubernetes Service inside
// this cluster. It accepts exactly two shapes:
//
//	<service>.<namespace>.svc
//	<service>.<namespace>.svc.cluster.local
//
// and nothing else. Both labels before `svc` must be valid DNS-1123 labels.
//
// The suffix is matched against `cluster.local` literally rather than accepted
// as "whatever follows svc", because an arbitrary suffix is not evidence of a
// cluster domain: a name like `<service>.<namespace>.svc.example.com` is an
// ordinary public name that happens to carry an `svc` label, and admitting it
// would let the mesh assertion cover a destination the mesh does not. Nothing
// in the platform supplies an authoritative cluster-domain value to compare
// against, so the trusted suffix is Kubernetes' default and only that; a cell
// with a custom cluster domain uses the unqualified `<service>.<namespace>.svc`
// form, which resolves in-cluster under any domain. If a configuration seam for
// the cluster domain ever exists, this is where it is read — until then,
// inferring one is the bug.
//
// It takes a HOSTNAME and not a host: a port is the caller's to strip, which
// url.URL.Hostname does, so there is no second parse of an authority here.
func ClusterServiceHost(hostname string) bool {
	labels := strings.Split(strings.TrimSuffix(strings.ToLower(hostname), "."), ".")
	switch len(labels) {
	case 3:
	case 5:
		if labels[3] != "cluster" || labels[4] != "local" {
			return false
		}
	default:
		return false
	}
	if labels[2] != "svc" {
		return false
	}
	return dnsLabel(labels[0]) && dnsLabel(labels[1])
}

// dnsLabel reports whether label is a valid DNS-1123 label, so an empty or
// malformed component cannot ride through on the shape of the name alone.
func dnsLabel(label string) bool {
	if len(label) == 0 || len(label) > 63 {
		return false
	}
	for index := range len(label) {
		character := label[index]
		switch {
		case character >= 'a' && character <= 'z', character >= '0' && character <= '9':
		case character == '-' && index != 0 && index != len(label)-1:
		default:
			return false
		}
	}
	return true
}

// keySetLoopbackHosts are the hosts a local run may name over plaintext.
//
// An EXACT set, by spelling, because what a name resolves to is a
// resolution-time question this cannot ask. `localhost` is reserved to the
// loopback interface by RFC 6761, so that is a property of the name; a name
// that merely contains one of these spellings is a different host.
var keySetLoopbackHosts = []string{"127.0.0.1", "::1", "localhost"}

// KeySetEndpoint is a key-set location whose transport has been admitted.
//
// It is an opaque value with an unexported field and exactly one constructor,
// so the location a key set is fetched from is the location that was admitted.
type KeySetEndpoint struct {
	url string
}

// URL is the location the key set is fetched from. It is empty on a zero value,
// which is not an endpoint.
func (e KeySetEndpoint) URL() string { return e.url }

// String implements fmt.Stringer.
func (e KeySetEndpoint) String() string { return e.url }

// ResolveKeySetEndpoint admits a key-set location, or refuses it by name.
//
// A verifier's key set decides which signatures it accepts, so the hop it
// arrives over is part of the verifier's configuration rather than a detail of
// how it was fetched. This is the one place that decision is made; a consumer
// that writes its own is a second copy of a rule whose whole value is that there
// is one.
//
// What is admitted:
//
//   - https to any host.
//   - plaintext http to an in-cluster Service address, exactly under the
//     composition's mesh assertion. Neither half admits on its own: the
//     assertion covers only what a mesh can cover, so a plaintext URL to any
//     other host stays refused with it set, and an in-cluster address without it
//     is refused too.
//   - plaintext http to a loopback host, on a local run only. A deployed runtime
//     has one admission rule and loopback is not an exception to it, not even
//     with the assertion set: a mesh does not carry a hop that never leaves the
//     pod, so nothing the composition said covers it.
//
// The assertion is read and validated FIRST, whatever the URL's scheme, so a
// misspelled or unreadable assertion stops the process rather than sitting
// unread behind an https URL until the day somebody changes one.
//
// No refusal here echoes any part of the URL, the parser's message included. A
// configuration error reaches boot-time logging, and a URL is a place a
// credential or a token gets written by mistake; every refusal names the setting
// and the remedy instead.
func ResolveKeySetEndpoint(raw string, source TransportSource) (KeySetEndpoint, error) {
	protected, err := MeshProtected(source)
	if err != nil {
		return KeySetEndpoint{}, err
	}
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return KeySetEndpoint{}, fmt.Errorf(
			"%w: no key-set URL is configured, so the key set is unset", ErrInvalid)
	}
	parsed, err := url.Parse(trimmed)
	if err != nil || parsed.Opaque != "" || parsed.Hostname() == "" {
		// The parser's error text embeds the input, so it is not reported.
		return KeySetEndpoint{}, fmt.Errorf(
			"%w: the key-set URL is not an absolute URL naming a host", ErrInvalid)
	}
	if parsed.User != nil || parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" {
		return KeySetEndpoint{}, fmt.Errorf(
			"%w: the key-set URL must carry no credentials, query or fragment", ErrInvalid)
	}
	if parsed.Scheme == "https" {
		return KeySetEndpoint{url: parsed.String()}, nil
	}
	if parsed.Scheme != "http" {
		return KeySetEndpoint{}, fmt.Errorf(
			"%w: the key-set URL scheme is not https; %s", ErrInvalid, MeshTransportRemedy)
	}
	if slices.Contains(keySetLoopbackHosts, strings.ToLower(parsed.Hostname())) {
		if source.IsLocalRun() {
			return KeySetEndpoint{url: parsed.String()}, nil
		}
		return KeySetEndpoint{}, fmt.Errorf(
			"%w: the key-set URL is plaintext to a loopback host and this is not a local run; "+
				"a mesh carries no hop that never leaves the pod, so the assertion cannot cover it. %s",
			ErrInvalid, MeshTransportRemedy)
	}
	if !protected {
		return KeySetEndpoint{}, fmt.Errorf(
			"%w: the key-set URL is plaintext and %s/%s is not asserted. %s",
			ErrInvalid, MeshTransportGroup, MeshTransportKey, MeshTransportRemedy)
	}
	if !ClusterServiceHost(parsed.Hostname()) {
		return KeySetEndpoint{}, fmt.Errorf(
			"%w: %s/%s is asserted and the key-set URL is plaintext to a host that is not an "+
				"in-cluster Service address, which the assertion does not cover. %s",
			ErrInvalid, MeshTransportGroup, MeshTransportKey, MeshTransportRemedy)
	}
	return KeySetEndpoint{url: parsed.String()}, nil
}

// ErrKeySetUnavailable is a key set that could not be fetched: the endpoint did
// not answer, answered with a status, or answered with more than this module
// reads. It is retryable, and it is a different condition from ErrInvalid,
// which is a configuration this process will produce again.
var ErrKeySetUnavailable = errors.New("Codefly Work Context key set unavailable")

const (
	// maxKeySetBytes bounds what is read from the endpoint. A key set is a few
	// kilobytes; anything larger is not one, and reading it unbounded makes the
	// endpoint able to exhaust this process.
	maxKeySetBytes = 256 * 1024

	// maxKeySetKeys bounds how many keys a verifier will hold.
	maxKeySetKeys = 64

	// keySetRequestTimeout bounds one fetch. The caller's context bounds it too;
	// this is the ceiling when the caller supplies none.
	keySetRequestTimeout = 10 * time.Second
)

// KeySetDecoder turns the bytes the endpoint served into verification keys by
// key id.
//
// The decoding is the CALLER'S and the keys come back as plain bytes,
// deliberately: a key set's encoding is the issuer's format, and reading one
// means naming a signature primitive, which is the one thing this module may
// never do — see workcontext/AGENTS.md. What this module owns is the part a
// decoder cannot: that the bytes came from an admitted endpoint, and that
// nothing but those bytes reaches a verifier.
type KeySetDecoder func(payload []byte) (map[string][]byte, error)

// KeySet is verification key material that was fetched from an admitted
// endpoint. It is opaque with exactly one constructor, so the keys a verifier
// holds are the keys that endpoint served — the endpoint check and the fetch are
// one operation rather than two a caller could do separately and then ignore.
type KeySet struct {
	endpoint string
	keys     map[string][]byte
}

// Endpoint is the admitted location the keys were fetched from. It is empty on a
// zero value, which is not a key set.
func (s KeySet) Endpoint() string { return s.endpoint }

// KeyIDs are the ids the endpoint served, sorted.
func (s KeySet) KeyIDs() []string {
	ids := make([]string, 0, len(s.keys))
	for id := range s.keys {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	return ids
}

// AcquireKeySet fetches the key set from an admitted endpoint and decodes it
// through the caller's decoder.
//
// It is the only way to obtain a KeySet, and NewVerifier takes nothing else, so
// a verifier's keys cannot be supplied beside an endpoint that was checked and
// then not used. The endpoint check answering "this location is permitted" while
// the keys came from somewhere else is two facts presented as one.
//
// The HTTP client is this module's and a caller supplies none, on the same terms
// as the mint client's: a redirect is refused rather than followed, because
// following one leaves the address that was admitted; the body is bounded; and
// nothing is sent but the request.
func AcquireKeySet(ctx context.Context, endpoint KeySetEndpoint, decode KeySetDecoder) (KeySet, error) {
	if ctx == nil {
		return KeySet{}, fmt.Errorf("%w: acquiring a key set needs a context", ErrInvalid)
	}
	if endpoint.URL() == "" {
		return KeySet{}, fmt.Errorf(
			"%w: acquiring a key set needs an admitted endpoint; resolve one with ResolveKeySetEndpoint",
			ErrInvalid)
	}
	if decode == nil {
		return KeySet{}, fmt.Errorf("%w: acquiring a key set needs a decoder", ErrInvalid)
	}
	requestContext, cancel := context.WithTimeout(ctx, keySetRequestTimeout)
	defer cancel()
	request, err := http.NewRequestWithContext(requestContext, http.MethodGet, endpoint.URL(), nil)
	if err != nil {
		return KeySet{}, fmt.Errorf("%w: the key-set endpoint could not be requested", ErrInvalid)
	}
	client := &http.Client{
		Timeout:       keySetRequestTimeout,
		CheckRedirect: refuseKeySetRedirect,
	}
	response, err := client.Do(request)
	if err != nil {
		// A refused redirect arrives here already classed, wrapped in a
		// *url.Error whose text is the address; it is named here rather than
		// reported through.
		if errors.Is(err, errKeySetRedirected) {
			return KeySet{}, fmt.Errorf(
				"%w: the key-set endpoint redirected, which leaves the admitted address",
				ErrKeySetUnavailable)
		}
		// Every other transport error names the URL it was given too, so it is
		// kept in the chain and out of the message.
		return KeySet{}, fmt.Errorf("%w: the key-set endpoint did not answer: %w",
			ErrKeySetUnavailable, redactedLookupFailure(err))
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK {
		return KeySet{}, fmt.Errorf("%w: the key-set endpoint answered %d",
			ErrKeySetUnavailable, response.StatusCode)
	}
	payload, err := io.ReadAll(io.LimitReader(response.Body, maxKeySetBytes+1))
	if err != nil {
		return KeySet{}, fmt.Errorf("%w: the key set could not be read", ErrKeySetUnavailable)
	}
	if len(payload) > maxKeySetBytes {
		return KeySet{}, fmt.Errorf("%w: the key set is larger than %d bytes",
			ErrKeySetUnavailable, maxKeySetBytes)
	}
	decoded, err := decode(payload)
	if err != nil {
		// A decoder is the caller's code and its error is the caller's text, so
		// it stays in the chain rather than in the message.
		return KeySet{}, fmt.Errorf("%w: the key set could not be decoded: %w",
			ErrInvalid, redactedLookupFailure(err))
	}
	if len(decoded) == 0 {
		return KeySet{}, fmt.Errorf("%w: the key-set endpoint served no key", ErrInvalid)
	}
	if len(decoded) > maxKeySetKeys {
		return KeySet{}, fmt.Errorf("%w: the key set holds %d keys and a verifier holds at most %d",
			ErrInvalid, len(decoded), maxKeySetKeys)
	}
	keys := make(map[string][]byte, len(decoded))
	for id, key := range decoded {
		if id == "" {
			return KeySet{}, fmt.Errorf("%w: the key set holds a key with no id", ErrInvalid)
		}
		keys[id] = key
	}
	return KeySet{endpoint: endpoint.URL(), keys: keys}, nil
}

// errKeySetRedirected is how a refused redirect travels back out of the HTTP
// client, which wraps it in a *url.Error whose text is the URL. It is matched
// rather than reported, so the refusal names the condition and not the address.
var errKeySetRedirected = fmt.Errorf("%w: redirected", ErrKeySetUnavailable)

// refuseKeySetRedirect stops a fetch that would leave the admitted address. A
// redirect is the endpoint choosing where the key set comes from, which is the
// decision ResolveKeySetEndpoint exists to make.
func refuseKeySetRedirect(*http.Request, []*http.Request) error {
	return errKeySetRedirected
}

// verificationKeySize is the length core requires of a verification key.
//
// It is a NUMBER here and a call in core — resolveKey compares against
// ed25519.PublicKeySize — which is a duplication this module would rather not
// have. It has it because naming a signature primitive is the one thing this
// module may never do, and core exports no key-configuration validator to call
// instead. So the number is stated once and TestTheVerificationKeySizeAgreesWithCore
// holds it to core's own constant from a _test.go, where the import is
// legitimate. If core grows the validator this becomes a call and the number
// goes. The same arrangement, for the same reason, as sealCarriesAnExecution.
const verificationKeySize = 32

// VerifierSettings are everything a verifier is, besides its key set.
//
// Every field of core's verifier has a usable zero value, so an incomplete
// configuration is expressible and the invariant requires it to be refused, and
// refused BY NAME. Failing closed and failing closed by name are two different
// properties and this is the second.
//
// Nothing here is optional except the clock and the skew, which are core's own
// test seams, and nothing here turns a check off.
type VerifierSettings struct {
	// Issuer is the authority this verifier trusts. A capability from any other
	// issuer is not a credential here, whatever its signature checks out
	// against.
	//
	// It is compared byte for byte by core, so it is taken byte for byte here:
	// a value with surrounding whitespace is refused rather than trimmed, since
	// the two spellings are two pins.
	Issuer string

	// Audience is this service or trust boundary, on the same terms.
	Audience string

	// Revisions answers the issuer's current authorization revision.
	Revisions RevisionSource

	// Replay consumes single-use capabilities.
	Replay ReplayStore

	// Grants resolves the approval a grant capability claims.
	Grants GrantSource

	// Seals answers the live installation, epoch, build and binding state.
	Seals SealSource

	// Now is the clock. nil means time.Now.
	Now func() time.Time

	// Skew is the tolerance applied to a capability's window. Zero means core's
	// DefaultSkew.
	Skew time.Duration
}

// PinnedVerifier is a verifier whose issuer, audience and key set are settled.
// It is the only thing this package hands out with a Verify method.
//
// It holds core's verifier and adds nothing to verification — Verify and Recheck
// are one line each and must stay that way. The type exists so that the
// configuration cannot be skipped, not so that behaviour can be added: there is
// exactly one implementation of the capability and it is core's.
type PinnedVerifier struct {
	verifier *verifier
	keySet   KeySet
}

// NewVerifier settles a verifier's configuration or refuses it by name.
//
// What it refuses, each one named in the error:
//
//   - no issuer, no audience, or either carrying surrounding whitespace;
//   - a key set that was not acquired from an admitted endpoint (a zero KeySet);
//   - a key set holding no key, or key material of the wrong length, which core
//     refuses per request and which belongs in a refusal at boot;
//   - a missing revision source, replay store, grant source or seal source, each
//     by its own name, where core names all four in one message.
//
// There is no way to hand it a key set from anywhere but AcquireKeySet, and no
// way to reach core's verifier through this package, so "the endpoint was
// admitted" and "these are the keys in use" are one fact rather than two.
func NewVerifier(settings VerifierSettings, keys KeySet) (*PinnedVerifier, error) {
	issuer, err := pinnedValue("issuer", settings.Issuer)
	if err != nil {
		return nil, err
	}
	audience, err := pinnedValue("audience", settings.Audience)
	if err != nil {
		return nil, err
	}
	if keys.Endpoint() == "" {
		return nil, fmt.Errorf(
			"%w: this verifier has no key set from an admitted endpoint; acquire one with "+
				"ResolveKeySetEndpoint and AcquireKeySet", ErrInvalid)
	}
	if len(keys.keys) == 0 {
		return nil, fmt.Errorf("%w: the key set holds no verification key", ErrInvalid)
	}
	for _, id := range keys.KeyIDs() {
		if size := len(keys.keys[id]); size != verificationKeySize {
			return nil, fmt.Errorf(
				"%w: verification key %q is %d bytes and a verification key is %d; "+
					"a key set carrying unusable material is refused here rather than per request",
				ErrInvalid, id, size, verificationKeySize)
		}
	}
	for _, source := range []struct {
		what    string
		missing bool
	}{
		{"revision source", settings.Revisions == nil},
		{"replay store", settings.Replay == nil},
		{"grant source", settings.Grants == nil},
		{"seal source", settings.Seals == nil},
	} {
		if source.missing {
			return nil, fmt.Errorf("%w: this verifier has no %s", ErrInvalid, source.what)
		}
	}
	pinned := &PinnedVerifier{
		verifier: &verifier{
			Issuer:    issuer,
			Audience:  audience,
			Revisions: settings.Revisions,
			Replay:    settings.Replay,
			Grants:    settings.Grants,
			Seals:     settings.Seals,
			Now:       settings.Now,
			Skew:      settings.Skew,
		},
		keySet: keys,
	}
	fillVerificationKeys(&pinned.verifier.Keys, keys.keys)
	return pinned, nil
}

// fillVerificationKeys moves the acquired bytes into the verifier's key map.
//
// It is generic so the element type is INFERRED from the field it fills: this
// module may not name the signature primitive that type is, and a conversion
// through a type parameter whose core type is []byte names nothing.
func fillVerificationKeys[K ~[]byte](into *map[string]K, acquired map[string][]byte) {
	keys := make(map[string]K, len(acquired))
	for id, key := range acquired {
		keys[id] = K(key)
	}
	*into = keys
}

// Verify checks a presented capability. It is core's Verify and nothing else;
// this method adds no check and must never.
func (p *PinnedVerifier) Verify(ctx context.Context, encoded string) (*Verified, error) {
	if p == nil {
		return nil, fmt.Errorf("%w: nil verifier", ErrInvalid)
	}
	return p.verifier.Verify(ctx, encoded)
}

// Recheck re-reads the issuer's live state for a capability that is already
// verified. It is core's Recheck and nothing else.
func (p *PinnedVerifier) Recheck(ctx context.Context, verified *Verified) error {
	if p == nil {
		return fmt.Errorf("%w: nil verifier", ErrInvalid)
	}
	return p.verifier.Recheck(ctx, verified)
}

// Issuer, Audience and KeySetEndpoint report what this verifier was settled
// with, for a diagnostic or a readiness check.
func (p *PinnedVerifier) Issuer() string   { return p.verifier.Issuer }
func (p *PinnedVerifier) Audience() string { return p.verifier.Audience }

// KeySetEndpoint is the admitted location this verifier's keys came from.
func (p *PinnedVerifier) KeySetEndpoint() string { return p.keySet.Endpoint() }

// pinnedValue refuses an unset pin, and a pin whose spelling is not the
// spelling it will be compared under.
func pinnedValue(what string, value string) (string, error) {
	if value == "" {
		return "", fmt.Errorf("%w: no %s is pinned", ErrInvalid, what)
	}
	if strings.TrimSpace(value) != value {
		return "", fmt.Errorf(
			"%w: the pinned %s carries surrounding whitespace; it is compared byte for byte",
			ErrInvalid, what)
	}
	return value, nil
}
