package workcontext

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	corework "github.com/codefly-dev/core/workcontext"
	"google.golang.org/protobuf/proto"
)

// Bounds on everything the mint endpoint can hand back. A credential is the
// one thing a process will trust for the rest of its life, so nothing about
// the response is allowed to be unbounded.
const (
	defaultMintRequestTimeout = 5 * time.Second
	maxMintRequestTimeout     = 30 * time.Second
	maxMintResponseBytes      = 64 * 1024
	maxProjectedTokenBytes    = 64 * 1024

	// defaultRenewalLead is how far before expiry a renewal is attempted, as a
	// fraction of the credential's whole lifetime. It is not a heartbeat: at
	// 0.2 a fifteen-minute credential is renewed once, three minutes before it
	// expires, and a process that runs for an hour renews four times rather
	// than announcing itself two hundred and forty times.
	defaultRenewalLead = 0.2

	// minRenewalLeadTime floors the lead so a very short credential still
	// leaves room for one request and one retry.
	minRenewalLeadTime = 5 * time.Second

	// defaultMaxCredentialLifetime is the longest credential this client will
	// hold, and it is CORE'S OWN CONSTANT so there is one number rather than
	// two to keep in step.
	//
	// WHAT THIS IS NOW FOR, because it is not what it was for. The argument
	// that kept this check was that a mint client NEVER VERIFIES A SIGNATURE —
	// it is the party the credential is minted FOR, not a receiver — so it
	// reads its own window through corework.Inspect, which was structural and
	// bounded no lifetime. Core's first two attempts bounded Authority.Start
	// and then Verify alone, neither of which a holder can reach: a thirty-day
	// capability that every Verify refuses was reported to its HOLDER as
	// thirty days of validity.
	//
	// Core 67ee7220 moved the bound into decodeClaims, which Inspect uses, so
	// an over-ceiling lifetime is refused IN THIS CLIENT'S OWN READ PATH —
	// inside sealOf, before checkWindow runs at all.
	//
	// So the safety net is core's and this is no longer one. What remains is a
	// DEPLOYMENT POLICY: a process that will hold a credential for at most
	// five minutes says so here, and the check fires below core's ceiling
	// where core has nothing to say. That is the only case it can reach, and
	// it is the case its test exercises — describing it as a safety net would
	// be claiming a branch nothing can enter.
	defaultMaxCredentialLifetime = corework.MaxTTLCeiling

	// Backoff after a mint that failed. A failed renewal used to return an
	// error to every caller while the held credential still had minutes left,
	// and each caller then retried serially under the client's lock: one mint
	// request per caller, which is the heartbeat under another name.
	minMintBackoff = time.Second
	maxMintBackoff = time.Minute

	// The refresh bucket. A refresh is not a failure, so it is not held off by
	// the failure backoff; it is rate-limited in its own right because a
	// receiver whose live state lags refuses every FRESH credential too, and
	// each refusal is a new generation that the generation check cannot stop.
	//
	// One per minute in the steady state, with a burst of three so the honest
	// case — a revocation, then a second one shortly after — is not delayed.
	refreshInterval = time.Minute
	maxRefreshBurst = 3.0
)

// Errors a mint caller distinguishes.
var (
	// ErrMintRefused marks a refusal the host will give again: the projected
	// token is not acceptable, the build does not match what the host approved,
	// the installation is not one this process may serve. Minting again changes
	// nothing, so a process that sees it must not serve.
	ErrMintRefused = errors.New("Codefly credential mint refused")

	// ErrMintUnavailable marks a refusal caused by the endpoint being
	// unreachable or answering 5xx/429. It is retryable, and it is the only
	// mint outcome that is.
	ErrMintUnavailable = errors.New("Codefly credential mint unavailable")
)

// ProjectedTokenSource reads the service-account token the platform projects
// into the process. It is an interface with one implementation so a test can
// rotate the token without a filesystem, and so the only thing that ever holds
// a path to it is this package.
type ProjectedTokenSource interface {
	// ProjectedToken returns the token as it is on disk right now. It is called
	// again before every renewal rather than cached, because the projection is
	// rotated under the running process and the copy read at boot is expired
	// long before the process is.
	ProjectedToken() (string, error)
}

// ProjectedTokenFile reads the projection from its mounted path.
type ProjectedTokenFile string

// ProjectedToken reads and trims the file. An empty or whitespace-only file is
// an error and never an empty token: a projection that has been unmounted or
// not yet written must not be presented as a credential request, because the
// host would refuse it and the refusal would read as "this build is not
// approved" rather than "the token is missing".
func (path ProjectedTokenFile) ProjectedToken() (string, error) {
	if strings.TrimSpace(string(path)) == "" {
		// Misconfiguration, not a host decision: no request was made and
		// retrying changes nothing. ErrInvalid rather than ErrMintRefused,
		// which is latched and means "the host refused you".
		return "", fmt.Errorf("%w: no projected token path", ErrInvalid)
	}
	file, err := os.Open(string(path))
	if err != nil {
		// A LOCAL TRANSIENT FAULT, so an outage and not a refusal. EMFILE
		// under load, EIO on the mount, or the projection being replaced
		// between unlink and create are all momentary — and classifying them
		// ErrMintRefused made them TERMINAL once refusals latched: one
		// exhausted file-descriptor table permanently stopped a process that
		// was holding a perfectly good credential, and it stayed stopped. This
		// is the same defect the response-body read had, on the local side.
		return "", fmt.Errorf("%w: open projected token: %w", ErrMintUnavailable, err)
	}
	defer func() {
		_ = file.Close()
	}()
	raw, err := io.ReadAll(io.LimitReader(file, maxProjectedTokenBytes+1))
	if err != nil {
		return "", fmt.Errorf("%w: read projected token: %w", ErrMintUnavailable, err)
	}
	if len(raw) > maxProjectedTokenBytes {
		// Retryable. "The file is there and is the wrong thing" was the reason
		// for latching this, and it is not a reason: latching buys nothing
		// here — the host would refuse an oversized bearer anyway — while a
		// projection caught mid-write is exactly the shape that produces it.
		return "", fmt.Errorf("%w: projected token exceeds %d bytes", ErrMintUnavailable, maxProjectedTokenBytes)
	}
	token := strings.TrimSpace(string(raw))
	if token == "" {
		// The projection is rewritten under the running process, so an empty
		// read is a moment in the middle of a rotation. Retryable.
		return "", fmt.Errorf("%w: projected token is empty", ErrMintUnavailable)
	}
	return token, nil
}

// AuthorityPin is the boot-read authority every mint reads its audience from
// and is checked against. The root SDK's *codefly.Authority satisfies it.
//
// It is REQUIRED, and it answers the audience rather than merely agreeing with
// one. A free-string Audience beside an optional pin was a drift check guarding
// a value the mint did not use: Recheck could pass while the credential was
// minted for whatever string the caller had typed. Reading the audience through
// Value on every mint is what makes the pin load-bearing — the value that
// reaches the host is the pinned value, or the mint fails.
//
// Value's contract is the pin's: it answers from what was frozen at boot, and a
// name the process did not declare is an error rather than a live lookup.
type AuthorityPin interface {
	// Recheck re-resolves every pinned value and refuses on the first that
	// moved. A value that drifts under a running process is an error, never a
	// reload: the process has already minted a credential sealed to the old
	// one.
	Recheck(ctx context.Context) error

	// Value answers one pinned value, by the name and key the workspace
	// accessors take.
	Value(name string, key string) (string, error)
}

// AuthorityValue addresses one pinned workspace value, by the name and key
// ReadAuthority declared it under. It is how MintOptions names the audience
// without the audience being a string a caller can type.
type AuthorityValue struct {
	Name string
	Key  string
}

func (v AuthorityValue) String() string { return v.Name + "/" + v.Key }

// MintOptions configures the one credential a process obtains per execution.
type MintOptions struct {
	// URL is the host's mint endpoint: absolute HTTPS, no query, no fragment,
	// no userinfo. Plain HTTP is refused — the projected service-account token
	// travels on this request as a bearer credential.
	URL string

	// Authority is the process's boot-read authority. REQUIRED: it answers the
	// audience on every mint and it is rechecked before every mint, including
	// the first.
	Authority AuthorityPin

	// Audience names the pinned value the Work Context audience is read from.
	// REQUIRED. The audience is never a string passed in beside the pin — that
	// made the drift check guard a value the mint did not use.
	Audience AuthorityValue

	// ProjectedToken reads the platform's projection of this process's
	// service-account token. Required.
	ProjectedToken ProjectedTokenSource

	// ProjectionAudience is the audience the projected token itself was minted
	// for, which the host states. Sent so the host can refuse a projection
	// aimed at something else rather than reviewing whatever it is handed.
	ProjectionAudience string

	// RootCAs is the only thing a caller may say about the transport: the roots
	// that may sign the mint endpoint's certificate.
	//
	// Set this, or set TrustSystemRoots. Nil used to mean the system pool
	// SILENTLY, which left the one remaining hole in a transport built to have
	// none: every other way of weakening it was closed — no caller-supplied
	// client, no reachable Transport, a TLS 1.3 floor, no followed redirect —
	// and the trust anchor was still whatever the image happened to ship. A
	// mint endpoint is platform infrastructure, so a public CA has no business
	// vouching for it; a mis-issued certificate for the host name, or a
	// corporate interception root in the image, receives the projected
	// service-account token. Construction refuses silence now, because the
	// choice is a deployment decision and a default is not a decision.
	//
	// It replaces an *http.Client, and that is the point. A client is a hole:
	// its Transport may be nil (so the global, mutable http.DefaultTransport),
	// a wrapper this package cannot inspect, or one with a DialTLSContext that
	// bypasses TLSClientConfig entirely — and a caller holding the same
	// *http.Transport pointer can turn verification off after construction,
	// because a copied http.Client shares it. Inspecting a supplied client
	// could not close any of that. So the client builds and owns its transport.
	// What that transport is, is stated once, at mintHTTPClient — not restated
	// here, because a field comment and a constructor comment saying the same
	// thing is how this one came to claim a TLS 1.2 floor for three revisions
	// after the floor became 1.3.
	RootCAs *x509.CertPool

	// TrustSystemRoots says, in as many words, that the host's own root pool is
	// the right trust anchor for this endpoint. It is the alternative to
	// RootCAs and never a companion to it: exactly one of the two is set, or
	// construction refuses.
	//
	// It exists so that using the system pool is a sentence somebody wrote
	// rather than a field somebody left alone. There are deployments where it
	// is correct — a mint endpoint behind a certificate from the same public
	// CA the image already trusts — and this says so out loud.
	TrustSystemRoots bool

	// RequestTimeout bounds one mint request.
	RequestTimeout time.Duration

	// RenewalLead overrides the fraction of a credential's lifetime at which
	// renewal is attempted. Zero takes the default.
	RenewalLead float64

	// MaxCredentialLifetime refuses a credential valid for longer than this
	// process will hold one. Zero takes defaultMaxCredentialLifetime, which is
	// core's own MaxTTLCeiling.
	//
	// It is a DEPLOYMENT POLICY below core's absolute ceiling, and what that
	// means is argued once at defaultMaxCredentialLifetime rather than again
	// here. This comment claimed to be the only thing between a misconfigured
	// host and a month-long credential, which stopped being true when core put
	// the bound in its one decode path — and it went on claiming it because
	// the argument was written down twice.
	MaxCredentialLifetime time.Duration

	// Now is the clock, for tests.
	Now func() time.Time
}

// Credential is the sealed capability a process holds for its execution. It is
// obtained once by Mint and replaced only by renewal at expiry or by Refresh
// after the host has refused it.
type Credential struct {
	token     string
	seal      *SealedValues
	binding   *SealedOperationBinding
	notBefore time.Time
	issuedAt  time.Time
	expiresAt time.Time

	// generation identifies which credential of this client's life this is. It
	// is what Refresh is told about, so a caller holding a credential the host
	// has refused asks for a replacement for THAT one — and two callers
	// refused on the same credential get one replacement rather than two
	// mints. It is deliberately not exported: it means nothing outside the
	// client that issued it.
	generation uint64

	// origin is which client issued it, because generation means nothing
	// outside that one. Two clients in a process each count from one, so a
	// credential from client B presented to client A's Refresh named a
	// generation A had issued to somebody else — and A would compare it,
	// believe it, and mint. Checked rather than documented.
	origin uint64
}

// Token returns the opaque signed capability, as it travels. It is a string and
// not a type of this module's: a capability is an opaque string until a Verifier
// has had it, and a typed wrapper here would offer the reassurance of a check
// nobody performed.
func (c Credential) Token() string { return c.token }

// Seal returns the execution this credential is bound to, as the capability
// CARRIES it — core's own WorkSealV1, cloned.
//
// It used to return core's Seal, which core documents as the live binding as
// the ISSUER holds it, filled by hand from three wire fields. A client cannot
// answer what the issuer holds, and a field core adds to the seal would have
// been silently zero in a value that reads as the issuer's. Same conflation
// this module already fixed for OperationBinding.
func (c Credential) Seal() *SealedValues {
	if c.seal == nil {
		return nil
	}
	copied, ok := proto.Clone(c.seal).(*SealedValues)
	if !ok {
		return nil
	}
	return copied
}

// OperationBinding returns the one binding this credential may act through, or
// nil. It is the binding AS SEALED — the three fields the capability carries —
// and not the live state of that binding, which only the issuer holds and which
// core's OperationBinding describes.
func (c Credential) OperationBinding() *SealedOperationBinding {
	return cloneSealedBinding(c.binding)
}

// NotBefore reports when the credential starts being accepted. It is a
// separate claim from IssuedAt, and it is the one a verifier tests, so a client
// that checked only issued_at was checking a different window from the one its
// credential would be judged against.
func (c Credential) NotBefore() time.Time { return c.notBefore }

// IssuedAt reports when the host minted it.
func (c Credential) IssuedAt() time.Time { return c.issuedAt }

// ExpiresAt reports when the credential stops being accepted.
func (c Credential) ExpiresAt() time.Time { return c.expiresAt }

// Attach installs the credential on an outbound HTTP request: the signed
// capability and, beside it, the installation it is sealed to.
func (c Credential) Attach(request *http.Request) error {
	return Attach(request, c.token)
}

// MintCounts is what a process's credential life cost: one first mint, a
// renewal per expiry reached, and a refresh per distinct credential the host
// refused. A correct execution reports exactly one mint.
type MintCounts struct {
	Mints     uint64
	Renewals  uint64
	Refreshes uint64
}

// MintClient obtains and renews one credential for one execution.
//
// What it does not do is the point of it. There is no heartbeat: nothing here
// runs on a timer that is not the credential's own expiry. There is no
// registration call: the process announces nothing about itself, because
// everything the host needs to know — which build, which installation, which
// principal — the host establishes from the projected token and its own
// records, and anything the process could report instead is something it could
// misreport. There is no self-reported upstream or manifest for the same
// reason.
type MintClient struct {
	mu         sync.Mutex
	options    MintOptions
	httpClient *http.Client
	now        func() time.Time
	credential *Credential
	generation uint64
	counts     MintCounts

	// inflight is non-nil while one goroutine is minting, and is closed when it
	// finishes. Concurrent callers wait on the channel rather than on the mutex
	// so the wait is cancellable: holding the lock across the request made
	// every caller's ctx meaningless and serialised N callers into N requests
	// when the mint kept failing.
	inflight chan struct{}

	// backoff holds off the next attempt after an OUTAGE, and failures counts
	// consecutive ones so the hold-off grows. Without it, a host answering 503
	// received one request per caller per call — the heartbeat under another
	// name, arriving exactly when the host is least able to serve it.
	backoffUntil time.Time
	failures     int

	// refused latches a refusal. ErrMintRefused means the host will say the
	// same thing again — the projection is not acceptable, the build is not
	// approved, the installation is not one this process may serve, an
	// authority value drifted — and this package's own documentation says a
	// process that sees it MUST NOT SERVE. So it is terminal: once latched,
	// every later call returns it rather than handing out the credential in
	// hand.
	//
	// This exists because the previous revision got it exactly backwards. The
	// "serve the held credential rather than manufacture an outage" fix was
	// applied to EVERY error, so a refusal, an authority drift and the
	// final-URL disclosure check all returned the held credential with a nil
	// error — and a test was adjusted to assert that as correct. Serving
	// through an outage and serving through a refusal are opposite decisions
	// and the error type is what tells them apart.
	refused error

	// The refresh rate limit, as a token bucket that REFILLS.
	//
	// It was a hold-off computed from the lifetime count —
	// mintBackoff(Refreshes) — which never decayed: after a few legitimate
	// refreshes the bound was a minute, permanently, so a refresh days later
	// waited for a receiver that had lagged that morning. A bucket bounds the
	// steady-state rate, which is what the limit is for, and forgets: it
	// refills one token per refreshInterval to a burst of maxRefreshBurst, so
	// an idle client refreshes at once and a receiver refusing every fresh
	// credential is held to one mint per interval.
	refreshTokens float64
	refreshFilled time.Time

	// lastFailure is the most recent outage, kept so a caller held off by it
	// learns WHY rather than only that minting is held off. The detached
	// request has no caller to return its error to, so without this the
	// transport's own words — a refused connection, a certificate, a 503 —
	// reached nobody.
	lastFailure error

	// refreshWanted records that the in-flight request was started BY a
	// refresh, so the detached goroutine can count it correctly. It cannot read
	// the reason off its caller any more, which is the point: there may be no
	// caller left.
	refreshWanted bool

	// id distinguishes this client from any other in the process, so a
	// Credential can say which one issued it.
	id uint64
}

// mintClientIDs numbers clients so a Credential's generation can be held to the
// client that issued it.
var mintClientIDs atomic.Uint64

// NewMintClient validates configuration without performing any I/O.
func NewMintClient(options MintOptions) (*MintClient, error) {
	endpoint, err := validateMintURL(options.URL)
	if err != nil {
		return nil, err
	}
	if options.Authority == nil {
		return nil, fmt.Errorf(
			"%w: a mint client needs the process's boot-read authority; the audience is read from it",
			ErrInvalid,
		)
	}
	audience := AuthorityValue{
		Name: strings.TrimSpace(options.Audience.Name),
		Key:  strings.TrimSpace(options.Audience.Key),
	}
	if audience.Name == "" || audience.Key == "" {
		return nil, fmt.Errorf(
			"%w: name the pinned value the audience is read from", ErrInvalid,
		)
	}
	if options.ProjectedToken == nil {
		return nil, fmt.Errorf("%w: no projected token source", ErrInvalid)
	}
	if strings.TrimSpace(options.ProjectionAudience) == "" {
		return nil, fmt.Errorf("%w: no projection audience", ErrInvalid)
	}
	switch {
	case options.RootCAs != nil && options.TrustSystemRoots:
		return nil, fmt.Errorf(
			"%w: name the roots that may sign the mint endpoint's certificate, or say TrustSystemRoots; not both",
			ErrInvalid,
		)
	case options.RootCAs == nil && !options.TrustSystemRoots:
		return nil, fmt.Errorf(
			"%w: no trust anchor for the mint endpoint; set RootCAs to the roots that may sign its certificate, "+
				"or TrustSystemRoots to use the host's pool. The projected service-account token is sent to "+
				"whatever answers at %s, so which certificates are acceptable there is a deployment decision "+
				"and there is no safe default to fall back to",
			ErrInvalid, endpoint,
		)
	}
	timeout := options.RequestTimeout
	if timeout == 0 {
		timeout = defaultMintRequestTimeout
	}
	if timeout < time.Millisecond || timeout > maxMintRequestTimeout {
		return nil, fmt.Errorf(
			"%w: mint request timeout must be between 1ms and %s",
			ErrInvalid, maxMintRequestTimeout,
		)
	}
	lead := options.RenewalLead
	if lead == 0 {
		lead = defaultRenewalLead
	}
	if lead <= 0 || lead >= 1 {
		return nil, fmt.Errorf("%w: renewal lead must be between zero and one", ErrInvalid)
	}
	ceiling := options.MaxCredentialLifetime
	if ceiling == 0 {
		ceiling = defaultMaxCredentialLifetime
	}
	if ceiling <= 0 {
		return nil, fmt.Errorf("%w: maximum credential lifetime must be positive", ErrInvalid)
	}
	if ceiling > corework.MaxTTLCeiling {
		// Refused rather than clamped, so a deployment that configured a
		// window nothing will mint finds out at construction instead of at the
		// first mint. Core refuses the same thing on its own side.
		return nil, fmt.Errorf(
			"%w: maximum credential lifetime of %s is above core's absolute ceiling of %s, which no authority mints beyond",
			ErrInvalid, ceiling, corework.MaxTTLCeiling,
		)
	}
	now := options.Now
	if now == nil {
		now = time.Now
	}
	options.URL = endpoint
	options.MaxCredentialLifetime = ceiling
	options.Audience = audience
	options.RequestTimeout = timeout
	options.RenewalLead = lead
	return &MintClient{
		options:    options,
		httpClient: mintHTTPClient(options.RootCAs), // nil here means TrustSystemRoots, checked above
		now:        now,
		id:         mintClientIDs.Add(1),
	}, nil
}

// mintHTTPClient builds the client every mint request is made with. The client
// owns it: there is no way for a caller to supply one.
//
// Inspecting a caller's client could not make this safe, which is why the
// option is gone. A nil Transport means the global, mutable
// http.DefaultTransport; a wrapping RoundTripper is opaque; a DialTLSContext
// bypasses TLSClientConfig altogether; and a caller that keeps the
// *http.Transport pointer can turn verification off after construction, because
// copying an http.Client shares its Transport. All four sent the projected
// service-account token over a channel nobody authenticated. So the only thing
// a caller says about the transport is which roots may sign the endpoint's
// certificate.
func mintHTTPClient(roots *x509.CertPool) *http.Client {
	return &http.Client{
		CheckRedirect: refuseMintRedirect,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				// Nil reaches here only when the caller said TrustSystemRoots:
				// NewMintClient refuses an unstated anchor, so this nil is a
				// decision rather than an omission.
				RootCAs: roots,
				// TLS 1.3 FLOOR. The projected service-account token is the
				// one secret this process hands to anybody, and 1.2 permits
				// cipher suites and a renegotiation surface that 1.3 removes.
				// A mint endpoint is infrastructure this platform runs, not an
				// arbitrary third party, so there is no long tail of old
				// servers to accommodate — a host that cannot speak 1.3 is a
				// host to upgrade.
				MinVersion: tls.VersionTLS13,
			},
			ForceAttemptHTTP2:   true,
			DisableCompression:  true,
			MaxIdleConnsPerHost: 2,
			TLSHandshakeTimeout: maxMintRequestTimeout,
		},
	}
}

// refuseMintRedirect is called by net/http BEFORE the redirected request is
// sent, and returning an error means it is never sent. That is the whole
// requirement: the destination of a redirect must receive no request at all,
// because the first one carried the projected service-account token and the
// second would carry it to an address nothing configured.
//
// It refuses rather than returning http.ErrUseLastResponse so the outcome is a
// named refusal instead of a 3xx that later checks have to recognise, and it
// carries ErrMintRefused rather than ErrMintUnavailable: retrying would send
// the projection again.
func refuseMintRedirect(request *http.Request, via []*http.Request) error {
	return fmt.Errorf(
		"%w: the mint endpoint redirected to %s after %d request(s); a credential request is not followed to an address the configuration did not name",
		ErrMintRefused, request.URL.Redacted(), len(via),
	)
}

// Credential returns the credential to use now: the first one is minted, and
// one that has reached its renewal point is renewed.
//
// It is NOT a guarantee about a credential a caller already holds. A Credential
// is a value, so one read out of here and kept can be attached after the host
// has moved the state under it; that is what Refresh is for, and it is why a
// receiver verifies rather than trusting that a caller re-asked.
//
// **A held credential that is still valid is served through an OUTAGE, and
// never through a refusal.** Entering the renewal lead and failing used to
// return an error to every caller while the credential in hand had minutes of
// validity left — an outage this client manufactured out of a credential that
// still worked. But the fix was then applied to every error, so a refusal
// served the held credential too, which is the opposite decision: ErrMintRefused
// means the host will say the same thing again and a process seeing it must
// stop serving. So an unreachable host serves what is in hand until it
// expires, and a refusal is TERMINAL for this client — Refused reports it, and
// every later call returns it.
//
// One mint at a time, and the wait is cancellable. Concurrent callers wait on a
// channel rather than on the mutex, so a caller whose ctx is cancelled stops
// waiting, and a failing mint produces one request rather than one per caller.
// After a failure the next attempt is held off, growing to a minute: a process
// obtains one credential per execution, and a process that answered a 503 with
// a request per call would be the heartbeat again under another name.
func (c *MintClient) Credential(ctx context.Context) (Credential, error) {
	if c == nil {
		return Credential{}, fmt.Errorf("%w: nil mint client", ErrInvalid)
	}
	if ctx == nil {
		return Credential{}, fmt.Errorf("%w: nil context", ErrInvalid)
	}
	return c.obtain(ctx, mintReasonRenewal, nil)
}

// Refresh replaces a credential the host has refused — ErrRevoked from a
// verifier at the far end, which means the credential was sound when it was
// minted and the state moved under it.
//
// Without it there was no way back: Credential answers from the credential it
// holds until that credential's own renewal point, so a process whose
// installation revision changed served refusals until a lead the host chooses
// had elapsed.
//
// It is tied to the credential that was refused, not to the clock. A caller
// passes back the Credential it was refused on; if this client has already
// replaced that one, the replacement is returned and nothing is minted. So a
// burst of concurrent refusals on one credential produces exactly one
// replacement mint, and a caller holding a credential two generations old
// cannot roll the client backwards by asking about it.
//
// It has its OWN rate limit, which matters for the case a generation check
// alone does not cover: a receiver whose seal source lags refuses each FRESH
// credential too, and every refusal is a new generation, so the generation
// check never fires. The limit is a token bucket — a burst of three, refilling
// one per minute — so a lagging receiver costs one mint a minute in the steady
// state while an honest revocation is answered at once. It refills with elapsed
// time, so a client that refreshed this morning is not held off tonight.
//
// A credential this client did not issue is refused with ErrInvalid: the
// generation it names belongs to whichever client minted it, and comparing it
// here would let a credential from one client in the process drive another
// client's mint.
func (c *MintClient) Refresh(ctx context.Context, refused Credential) (Credential, error) {
	if c == nil {
		return Credential{}, fmt.Errorf("%w: nil mint client", ErrInvalid)
	}
	if ctx == nil {
		return Credential{}, fmt.Errorf("%w: nil context", ErrInvalid)
	}
	// Local misuse carries ErrInvalid, not ErrMintRefused. The two were the
	// same sentinel, which made errors.Is(err, ErrMintRefused) true for a
	// caller that passed a zero Credential while Refused() was nil — so the
	// two ways of asking "is this client refused" disagreed, and the sentinel
	// whose documented meaning is "do not serve" was returned for a programmer
	// error nobody should stop serving over.
	if refused.generation == 0 {
		return Credential{}, fmt.Errorf(
			"%w: refresh needs the credential that was refused, as this client issued it",
			ErrInvalid,
		)
	}
	if refused.origin != c.id {
		return Credential{}, fmt.Errorf(
			"%w: that credential was issued by another mint client; its generation means nothing here",
			ErrInvalid,
		)
	}
	// There is deliberately no "this client has issued nothing" check. The
	// origin check above subsumes it: a credential whose origin is this
	// client's id was issued BY this client, so there is one to replace. A
	// branch no input reaches is the ErrUnsealed mistake again — a handler
	// that never runs, read by everyone as a case that can happen.
	return c.obtain(ctx, mintReasonRefresh, func(held *Credential) bool {
		// The credential that was refused is still the one being held, so it
		// has to be replaced. If it is NOT — somebody else was refused on the
		// same credential and has already replaced it — this asks for nothing,
		// and obtain's own freshness check decides whether the replacement can
		// be handed over as it stands.
		return held.generation == refused.generation
	})
}

// mintReason says which counter a successful mint belongs to. The FIRST mint is
// always counted as a mint whatever asked for it.
type mintReason int

const (
	mintReasonRenewal mintReason = iota
	mintReasonRefresh
)

// obtain is the one path that mints.
//
// wanted is an EXTRA reason to mint, asked of the credential currently held and
// called under the lock; nil means "no reason beyond freshness". Freshness
// itself is checked here for every caller, which is the point: Refresh used to
// return the held credential whenever its generation had already moved on,
// without looking at whether that replacement was still usable — so a caller
// refused on an old generation was handed a replacement that had since
// EXPIRED. A credential leaves this function only if it is not due for
// renewal, whoever asked and for whatever reason.
func (c *MintClient) obtain(
	ctx context.Context, reason mintReason, wanted func(held *Credential) bool,
) (Credential, error) {
	for {
		c.mu.Lock()
		if c.refused != nil {
			// Terminal. A refusal is not something a later call outlives.
			c.mu.Unlock()
			return Credential{}, c.refused
		}
		held := c.credential
		if held != nil && !c.dueForRenewalLocked(*held) &&
			(wanted == nil || !wanted(held)) {
			credential := *held
			c.mu.Unlock()
			return credential, nil
		}
		if reason == mintReasonRefresh && held != nil && wanted != nil && !wanted(held) &&
			c.now().UTC().Before(held.expiresAt) {
			// A refresh asking about a generation this client has ALREADY
			// replaced, where the replacement is the credential in hand. It is
			// answered even when that credential has entered its renewal lead:
			// the caller asked for something newer than what it was refused
			// on, and this is it. The renewal is Credential's business and
			// happens on its own schedule.
			//
			// Falling through here instead minted — and when the bucket was
			// empty it returned a held-off ErrMintUnavailable, so the one
			// credential that WAS the requested replacement was the one thing
			// this would not hand over.
			credential := *held
			c.mu.Unlock()
			return credential, nil
		}
		// servable is the credential this call may fall back on when minting is
		// UNAVAILABLE. A refresh has none: its caller was refused on the
		// credential being held, so handing that same credential back would
		// report a replacement that did not happen. It is recomputed rather
		// than captured wherever the clock may have moved since.
		servable := c.servableLocked(reason, wanted)
		if waiting := c.inflight; waiting != nil {
			// Another goroutine is minting. Wait for it rather than queueing a
			// second request, and let ctx cancel the wait.
			c.mu.Unlock()
			select {
			case <-waiting:
				continue
			case <-ctx.Done():
				return c.answerCancelled(ctx, reason, wanted)
			}
		}
		if until, holding := c.holdOffLocked(reason); holding {
			if servable != nil {
				credential := *servable
				c.mu.Unlock()
				return credential, nil
			}
			failure := c.lastFailure
			c.mu.Unlock()
			if failure != nil {
				// The transport's own words, plus when the next attempt may
				// happen. A caller held off by a failure it cannot see has no
				// way to tell a 503 from a certificate it must fix.
				return Credential{}, fmt.Errorf("%w (held off until %s)", failure, until)
			}
			return Credential{}, fmt.Errorf(
				"%w: minting is held off until %s", ErrMintUnavailable, until,
			)
		}
		// This caller takes the slot and STARTS the request, then waits for
		// it exactly as any other waiter does. It does not run the request on
		// its own context.
		//
		// It used to, and the cancelled leader was then a case of its own:
		// counted as no failure, so no hold-off. Under callers whose deadlines
		// are shorter than a degraded host's latency, every call became the
		// new leader, sent one request, cancelled it and learned nothing —
		// roughly one mint request per caller deadline, each of which the host
		// may well complete, and audit, while this process throws it away. A
		// refusal arriving just after the leader gave up was discarded too, so
		// the next caller presented the projected token again.
		//
		// Detached and bounded by RequestTimeout, the request outlives whoever
		// asked for it: it completes once, is classified once, and the result
		// is installed for everybody. However many callers give up, the host
		// sees one request per hold-off.
		done := make(chan struct{})
		c.inflight = done
		if reason == mintReasonRefresh {
			c.refreshWanted = true
		}
		c.mu.Unlock()
		go c.mintInto(ctx, done)

		select {
		case <-done:
			// Re-read the state the request installed, under the lock, at the
			// top of the loop: a credential, a latched refusal, or a hold-off.
			continue
		case <-ctx.Done():
			return c.answerCancelled(ctx, reason, wanted)
		}
	}
}

// mintInto performs the one detached request and installs whatever it learned.
//
// Its context is NOT any caller's. It is bounded by RequestTimeout, which is
// what makes the request terminate, and detached from the caller that started
// it, which is what makes the result arrive whether or not that caller is still
// interested.
func (c *MintClient) mintInto(caller context.Context, done chan struct{}) {
	// WithoutCancel(caller), not Background(). Detaching from the caller's
	// CANCELLATION is the whole point; detaching from its VALUES throws away
	// anything the caller put there for the request to carry — a trace span, a
	// request id, whatever an http.RoundTripper in the caller's stack reads.
	// Background() dropped all of it silently, which is a different thing from
	// what the comment said this was doing.
	ctx, cancel := context.WithTimeout(
		context.WithoutCancel(caller), c.options.RequestTimeout,
	)
	defer cancel()
	credential, err := c.mintOnce(ctx)

	c.mu.Lock()
	defer func() {
		c.mu.Unlock()
		close(done)
	}()
	c.inflight = nil
	refresh := c.refreshWanted
	c.refreshWanted = false
	renewal := c.credential != nil
	if err != nil {
		// ONE LATCH RULE: only ErrMintRefused is terminal, and nothing else is.
		//
		// It used to be the negation — anything that was not an outage latched
		// — which made every error this client had not thought about into a
		// permanent stop. An ErrInvalid from a caller's own token source
		// latched while Refused() reported something errors.Is(…,
		// ErrMintRefused) said false about, so the two ways of asking "is this
		// client refused" disagreed; and the misconfiguration sentinels said
		// in their own comments that they were NOT latched, while this branch
		// latched them.
		//
		// Everything that is not an enumerated refusal is held off and
		// retried, with the error kept so a caller can see it. The asymmetry
		// is the whole argument: a wrong "retryable" costs one request per
		// hold-off, and a wrong "terminal" costs the process.
		if errors.Is(err, ErrMintRefused) {
			c.refused = err
			return
		}
		c.failures++
		c.backoffUntil = c.now().UTC().Add(mintBackoff(c.failures))
		c.lastFailure = err
		return
	}
	if renewal && credential.token == c.credential.token {
		// The host handed back the credential it was asked to replace. That is
		// not a replacement: installing it would count a refresh or a renewal
		// for a credential that did not change, and it would come due again
		// immediately. An idempotent mint endpoint does exactly this.
		c.failures++
		c.backoffUntil = c.now().UTC().Add(mintBackoff(c.failures))
		c.lastFailure = fmt.Errorf(
			"%w: the mint returned the credential it was asked to replace", ErrMintUnavailable,
		)
		return
	}
	c.failures = 0
	c.backoffUntil = time.Time{}
	c.lastFailure = nil
	c.generation++
	credential.generation = c.generation
	credential.origin = c.id
	c.credential = &credential
	switch {
	case !renewal:
		c.counts.Mints++
	case refresh:
		c.counts.Refreshes++
		c.spendRefreshTokenLocked()
	default:
		c.counts.Renewals++
	}
}

// answerCancelled is what a caller gets when it stops waiting: the credential
// in hand if one is servable FOR THIS KIND OF CALL at the clock as it is now,
// or its own cancellation.
//
// Re-evaluated under the lock rather than from a snapshot taken before the
// wait. The snapshot version handed an EXPIRED credential, with a nil error, to
// a waiter that entered one second before expiry and gave up one second after
// it — and two seconds fits easily inside the default five-second timeout.
func (c *MintClient) answerCancelled(
	ctx context.Context, reason mintReason, wanted func(held *Credential) bool,
) (Credential, error) {
	c.mu.Lock()
	terminal := c.refused
	servable := c.servableLocked(reason, wanted)
	snapshot := Credential{}
	if servable != nil {
		snapshot = *servable
	}
	c.mu.Unlock()
	if terminal != nil {
		return Credential{}, terminal
	}
	if servable != nil {
		return snapshot, nil
	}
	// Both stay in the chain: a caller that cancelled wants to see its own
	// cancellation, not only that minting was unavailable.
	return Credential{}, fmt.Errorf("%w: %w", ErrMintUnavailable, ctx.Err())
}

// holdOffLocked reports whether minting is held off for this kind of call, and
// until when. A renewal is held off by consecutive failures; a refresh is held
// off by its own rate limit as well, which a successful mint does not reset.
func (c *MintClient) holdOffLocked(reason mintReason) (time.Time, bool) {
	now := c.now().UTC()
	if !c.backoffUntil.IsZero() && now.Before(c.backoffUntil) {
		return c.backoffUntil, true
	}
	if reason == mintReasonRefresh {
		if available := c.refreshTokensLocked(); available < 1 {
			// When the next token lands, which is a real instant rather than a
			// growing penalty: the bucket refills whether or not anybody asks.
			return now.Add(time.Duration((1 - available) * float64(refreshInterval))), true
		}
	}
	return time.Time{}, false
}

// refreshTokensLocked refills the refresh bucket to now and reports what is in
// it. It is a function of ELAPSED TIME, so the limit forgets: a client that
// refreshed three times this morning is not still paying for it tonight.
//
// The previous bound was mintBackoff(Refreshes), computed from the LIFETIME
// count, so after a few legitimate refreshes it was a minute — permanently.
// "One refresh per minute, forever" is not a rate limit, it is a tax.
func (c *MintClient) refreshTokensLocked() float64 {
	now := c.now().UTC()
	if c.refreshFilled.IsZero() {
		c.refreshTokens = maxRefreshBurst
		c.refreshFilled = now
		return c.refreshTokens
	}
	if elapsed := now.Sub(c.refreshFilled); elapsed > 0 {
		c.refreshTokens += elapsed.Seconds() / refreshInterval.Seconds()
		if c.refreshTokens > maxRefreshBurst {
			c.refreshTokens = maxRefreshBurst
		}
		c.refreshFilled = now
	}
	return c.refreshTokens
}

// spendRefreshTokenLocked charges one SUCCESSFUL refresh to the bucket. A
// failure is charged to the failure backoff instead, which is the thing that
// grows.
func (c *MintClient) spendRefreshTokenLocked() {
	if available := c.refreshTokensLocked(); available >= 1 {
		c.refreshTokens = available - 1
		return
	}
	c.refreshTokens = 0
}

// servableLocked is the credential a caller may be handed when minting is
// unavailable: one that is held, unexpired, and not the one a refresh was
// refused on.
func (c *MintClient) servableLocked(reason mintReason, wanted func(held *Credential) bool) *Credential {
	if c.credential == nil {
		return nil
	}
	if reason == mintReasonRefresh && (wanted == nil || wanted(c.credential)) {
		// The credential being held IS the one this refresh was refused on, so
		// handing it back would report a replacement that did not happen.
		//
		// When it is NOT — the client has already moved on and this caller is
		// asking about a generation that has been replaced — the credential in
		// hand is exactly the replacement being asked for. Returning nil there
		// was a defect of its own: a stale-generation refresh arriving while
		// the current credential sat inside its renewal lead got a held-off
		// ErrMintUnavailable instead of the perfectly good credential the
		// client was holding.
		return nil
	}
	if !c.now().UTC().Before(c.credential.expiresAt) {
		return nil
	}
	return c.credential
}

// Refused reports the refusal that stopped this client, or nil.
//
// It is exported because a refusal is the one mint outcome a process must act
// on by not serving, and a process cannot act on something it has to infer
// from the error of whichever call happened to be first.
func (c *MintClient) Refused() error {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.refused
}

// mintOnce rechecks the pinned authority, reads the audience from it and mints.
// It performs no locking: obtain holds the single-flight slot across it, so the
// request is made without the client's mutex held and a caller's ctx still
// means something.
func (c *MintClient) mintOnce(ctx context.Context) (Credential, error) {
	if err := c.options.Authority.Recheck(ctx); err != nil {
		return Credential{}, fmt.Errorf("%w: %v", ErrMintRefused, err)
	}
	audience, err := c.options.Authority.Value(c.options.Audience.Name, c.options.Audience.Key)
	if err != nil {
		return Credential{}, fmt.Errorf(
			"%w: read the audience from %s: %v", ErrMintRefused, c.options.Audience, err,
		)
	}
	if strings.TrimSpace(audience) == "" {
		return Credential{}, fmt.Errorf(
			"%w: %s is pinned to an empty audience", ErrMintRefused, c.options.Audience,
		)
	}
	return c.mintLocked(ctx, audience)
}

// mintBackoff grows the hold-off with consecutive failures, to a minute.
func mintBackoff(failures int) time.Duration {
	hold := minMintBackoff
	for range failures - 1 {
		hold *= 2
		if hold >= maxMintBackoff {
			return maxMintBackoff
		}
	}
	return hold
}

// Counts reports what this process's credential life cost. A correct execution
// reports exactly one mint; renewals are expected and bounded by the
// credential's lifetime, not by a beat, and a refresh happens only when the
// host has refused the credential being held.
func (c *MintClient) Counts() MintCounts {
	if c == nil {
		return MintCounts{}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.counts
}

// projectedRead is one answer from a token source, at file level because the
// gate refuses a function-local type — a local declaration is invisible to every
// rule that reads a file's declarations, and that is true of this one too.
type projectedRead struct {
	token string
	err   error
}

// projectedToken reads the token source UNDER THE DEADLINE.
//
// ProjectedTokenSource is a caller's interface and takes no context, so nothing
// about it can be interrupted: ProjectedTokenFile does os.Open and io.ReadAll,
// neither of which a context reaches, and a caller's own implementation may do
// anything at all. RequestTimeout bounded the HTTP request and the comment on
// mintInto said it bounded "the one detached request" — measured with a source
// that blocks and RequestTimeout at 150ms, Credential returned after 3.0s,
// bounded only by the CALLER's deadline. With no caller deadline it does not
// return: the detached goroutine never closes `done`, so every later caller
// waits on an attempt that will not finish, and no hold-off is ever installed.
//
// The read runs on its own goroutine and the deadline is waited on instead. The
// goroutine outlives the timeout — there is no way to interrupt a blocking read
// behind an interface that takes no context — so the channel is buffered and
// the value it eventually sends is dropped. That leak is bounded by one
// goroutine per attempt and attempts are single-flighted and held off; a
// permanently wedged client is not.
func (c *MintClient) projectedToken(ctx context.Context) (string, error) {
	// Buffered, so the goroutine is not held open by a receiver that left.
	answers := make(chan projectedRead, 1)
	go func() {
		token, err := c.options.ProjectedToken.ProjectedToken()
		answers <- projectedRead{token: token, err: err}
	}()
	select {
	case answer := <-answers:
		return answer.token, answer.err
	case <-ctx.Done():
		// AN OUTAGE, under the one latch rule: a projection that is slow is a
		// mount under load or a source holding a lock, and both clear.
		return "", fmt.Errorf(
			"%w: reading the projected token did not finish within %s: %w",
			ErrMintUnavailable, c.options.RequestTimeout, ctx.Err(),
		)
	}
}

// dueForRenewalLocked is true once the credential has entered its renewal lead.
// An already-expired credential is also due, and is never returned to a caller:
// handing one out would turn a renewal failure into an authorization failure at
// the far end, where nothing can act on it.
func (c *MintClient) dueForRenewalLocked(credential Credential) bool {
	now := c.now().UTC()
	remaining := credential.expiresAt.Sub(now)
	if remaining <= 0 {
		return true
	}
	lifetime := credential.expiresAt.Sub(credential.notBefore)
	lead := time.Duration(float64(lifetime) * c.options.RenewalLead)
	if lead < minRenewalLeadTime {
		lead = minRenewalLeadTime
	}
	if lead > lifetime {
		lead = lifetime
	}
	return remaining <= lead
}

func (c *MintClient) mintLocked(ctx context.Context, audience string) (Credential, error) {
	projected, err := c.projectedToken(ctx)
	if err != nil {
		// A source is a caller's code. An error from one that carries neither
		// sentinel was returned as it stood and then LATCHED as terminal, so
		// errors.Is(Refused(), ErrMintRefused) was false while the client was
		// refused — and a transient local fault in somebody's own reader
		// stopped the process for good. An unlabelled source failure is a
		// local fault: retryable.
		if errors.Is(err, ErrMintRefused) || errors.Is(err, ErrMintUnavailable) ||
			errors.Is(err, ErrInvalid) {
			return Credential{}, err
		}
		return Credential{}, fmt.Errorf("%w: read the projected token: %w", ErrMintUnavailable, err)
	}
	body, err := json.Marshal(mintRequest{
		Audience:           audience,
		ProjectionAudience: c.options.ProjectionAudience,
	})
	if err != nil {
		return Credential{}, fmt.Errorf("%w: encode mint request: %v", ErrMintRefused, err)
	}
	requestContext, cancel := context.WithTimeout(ctx, c.options.RequestTimeout)
	defer cancel()
	request, err := http.NewRequestWithContext(
		requestContext, http.MethodPost, c.options.URL, bytes.NewReader(body),
	)
	if err != nil {
		return Credential{}, fmt.Errorf("%w: create mint request: %v", ErrMintRefused, err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Authorization", "Bearer "+projected)
	response, err := c.httpClient.Do(request)
	if err != nil {
		// A refused redirect arrives here already named. It is a refusal and
		// not an outage: retrying it would send the projection again.
		if errors.Is(err, ErrMintRefused) {
			return Credential{}, err
		}
		if reason := tlsVerificationFailure(err); reason != "" {
			// AN OUTAGE, and the previous revision had this backwards for a
			// reason that does not survive being stated precisely.
			//
			// It latched, on the argument that "the projected token is not
			// presented to an endpoint that cannot prove who it is". But the
			// HANDSHAKE FAILS BEFORE ANY REQUEST BYTES LEAVE: the token was
			// never sent and a retry would not send it either, so latching
			// buys no confidentiality at all. What it does buy is a permanent
			// stop on a certificate ROTATION — the endpoint's new leaf not yet
			// trusted, a root pool updated a minute later — which is the most
			// ordinary cause of this error in a running system.
			//
			// So it is retryable, and named distinctly in the message because
			// a certificate that does not verify is still the thing an
			// operator must look at first.
			return Credential{}, fmt.Errorf(
				"%w: the mint endpoint's certificate did not verify (%s); nothing was sent, and this retries",
				ErrMintUnavailable, reason,
			)
		}
		return Credential{}, fmt.Errorf("%w: %w", ErrMintUnavailable, err)
	}
	defer func() {
		_ = response.Body.Close()
	}()
	if elsewhere := answeredFromElsewhere(response, c.options.URL); elsewhere != "" {
		// An ASSERTION on the transport-ownership invariant, and deliberately
		// kept although nothing can currently reach it: CheckRedirect refuses
		// first, and the client owns its transport so no RoundTripper can
		// follow a redirect internally. A reviewer measured that deleting it
		// changes no test, which is true and is not the same as it being
		// pointless — what it holds is that those two facts stay true. If the
		// answer came from anywhere but the configured URL, the projected
		// token has already been seen by something nothing configured, and
		// stopping the process is the only safe outcome.
		//
		// It is a FUNCTION rather than an inline condition so the check itself
		// is testable without having to manufacture a transport that cannot
		// exist. A branch that can only be asserted by its own absence is the
		// ErrUnsealed mistake; a named predicate with a unit test is not.
		return Credential{}, fmt.Errorf(
			"%w: the mint response came from %s, not the configured endpoint",
			ErrMintRefused, elsewhere,
		)
	}
	if response.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4*1024))
		return Credential{}, fmt.Errorf(
			"%w: mint returned HTTP %d", sentinelForStatus(response.StatusCode), response.StatusCode,
		)
	}
	// Content-Type is REQUIRED, not checked when present. An absent header used
	// to be accepted, which made "the response is JSON" something the host
	// could decline to state about the one response this process trusts for its
	// whole life.
	mediaType, _, parseErr := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if parseErr != nil || mediaType != "application/json" {
		// RETRYABLE. A 200 carrying text/html is an ingress or a service mesh
		// answering instead of the host — a default page, a captive error
		// page, a misrouted rollout — and every one of those is a moment
		// rather than a verdict. Latched, one of them stopped the process for
		// good.
		return Credential{}, fmt.Errorf(
			"%w: mint response must declare Content-Type: application/json and declared %q",
			ErrMintUnavailable, response.Header.Get("Content-Type"),
		)
	}
	payload, err := io.ReadAll(io.LimitReader(response.Body, maxMintResponseBytes+1))
	if err != nil {
		// An OUTAGE, not a refusal. A body that stops mid-read is a connection
		// interrupted after the headers — the host said 200 and the network
		// went away — and classifying it ErrMintRefused made it TERMINAL once
		// refusals started latching: one interrupted read permanently stopped
		// a process holding a perfectly good credential, and it stayed stopped
		// after the endpoint recovered.
		//
		// The underlying error stays in the chain so a caller can see what the
		// transport did, rather than only that minting was unavailable.
		return Credential{}, fmt.Errorf("%w: read mint response: %w", ErrMintUnavailable, err)
	}
	if len(payload) > maxMintResponseBytes {
		// Terminal, unlike the read failure above: the host answered, and
		// answered with something this client will not accept. Retrying gets
		// the same answer.
		// Retryable for the same reason: an oversized body on a 200 is
		// something in the middle answering, not the host refusing.
		return Credential{}, fmt.Errorf(
			"%w: mint response exceeds %d bytes", ErrMintUnavailable, maxMintResponseBytes,
		)
	}
	return c.credentialFrom(payload, audience)
}

// credentialFrom reads the credential out of the response and takes its sealed
// values from the token, not from the response body. The host may echo them for
// a log, and an echo that disagrees with the signature is a refusal: the only
// installation, build and epoch that mean anything are the signed ones.
func (c *MintClient) credentialFrom(payload []byte, audience string) (Credential, error) {
	var body mintResponse
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&body); err != nil {
		// Retryable: an undecodable body on a 200 is the same class as a wrong
		// Content-Type — something answered that is not the host.
		return Credential{}, fmt.Errorf("%w: decode mint response: %v", ErrMintUnavailable, err)
	}
	// DisallowUnknownFields applies to the value just decoded and says nothing
	// about what follows it, so a valid response with a second JSON value
	// appended was accepted — strict parsing that stopped at the first value.
	// The response is ONE object and nothing after it.
	if err := decoder.Decode(new(json.RawMessage)); !errors.Is(err, io.EOF) {
		return Credential{}, fmt.Errorf(
			"%w: mint response carries more than one JSON value", ErrMintUnavailable,
		)
	}
	token := body.WorkContext
	claims, seal, binding, err := sealOf(token)
	if err != nil {
		return Credential{}, fmt.Errorf("%w: %v", ErrMintRefused, err)
	}
	if body.InstallationID != "" && body.InstallationID != seal.GetInstallationId() {
		return Credential{}, fmt.Errorf(
			"%w: mint reported installation %q and sealed %q",
			ErrMintRefused, body.InstallationID, seal.GetInstallationId(),
		)
	}
	if body.BuildIncarnation != "" {
		// PRESENCE, not value. The sealed execution became OPTIONAL in core
		// 4cb260d3, because a principal that bears no approved build — a
		// person at a terminal — must not have one invented for it. So a
		// capability can legitimately carry no incarnation, and
		// GetBuildIncarnation() answers 0 for both "absent" and a value core
		// says is never legitimate (an incarnation starts at 1).
		//
		// Comparing the echo against that zero would have accepted a host
		// echoing "0" against a capability bearing no execution at all, which
		// is a host asserting an execution the issuer does not hold. The echo
		// is only for catching a host and a signature that disagree, but
		// "disagree" has to include "one of them says nothing".
		if !sealCarriesAnExecution(seal) {
			return Credential{}, fmt.Errorf(
				"%w: mint reported build incarnation %q and the capability seals no execution at all",
				ErrMintRefused, body.BuildIncarnation,
			)
		}
		if body.BuildIncarnation != strconv.FormatUint(seal.GetBuildIncarnation(), 10) {
			return Credential{}, fmt.Errorf(
				"%w: mint reported build incarnation %q and sealed %d",
				ErrMintRefused, body.BuildIncarnation, seal.GetBuildIncarnation(),
			)
		}
	}
	// The audience the host signed must be the audience read from the pin.
	// This is the check an optional pin beside a free-string Audience could not
	// make: Recheck passing told nobody that the credential in hand was minted
	// for the pinned value rather than for whatever a caller had typed.
	if claims.GetAudience() != audience {
		return Credential{}, fmt.Errorf(
			"%w: credential was minted for audience %q, and %s is pinned to %q",
			ErrMintRefused, claims.GetAudience(), c.options.Audience, audience,
		)
	}
	credential := Credential{
		token:     token,
		seal:      seal,
		binding:   binding,
		notBefore: time.Unix(claims.GetNotBeforeUnix(), 0).UTC(),
		issuedAt:  time.Unix(claims.GetIssuedAtUnix(), 0).UTC(),
		expiresAt: time.Unix(claims.GetExpiresAtUnix(), 0).UTC(),
	}
	if err := c.checkWindow(credential); err != nil {
		return Credential{}, err
	}
	return credential, nil
}

// checkWindow refuses a credential that is unusable the moment it arrives, and
// one valid for longer than this process will hold a credential.
//
// Two things it gets right that the first version did not. It tests
// **not_before**, which is the claim core's verifier tests; testing issued_at
// was testing a different window from the one the credential would be judged
// against, and a host that sets them apart would have had a credential accepted
// here and refused everywhere. And it bounds the lifetime to what this
// DEPLOYMENT chose to hold — below core's absolute ceiling, which core refuses
// inside Inspect, the call sealOf already makes.
//
// The tolerance is core's own skew, so this client is never stricter than the
// verifier that will accept the credential.
func (c *MintClient) checkWindow(credential Credential) error {
	if !credential.expiresAt.After(credential.notBefore) {
		return fmt.Errorf(
			"%w: the minted credential expires at or before it becomes valid (%s to %s)",
			ErrMintRefused, credential.notBefore, credential.expiresAt,
		)
	}
	if lifetime := credential.expiresAt.Sub(credential.notBefore); lifetime > c.options.MaxCredentialLifetime {
		// A DEPLOYMENT POLICY, below core's absolute ceiling. Anything above
		// that ceiling was refused by corework.Inspect before this ran, in
		// sealOf — so what is reachable here is a process that chose to hold a
		// credential for less time than the platform permits.
		return fmt.Errorf(
			"%w: the minted credential is valid for %s, and this process holds one for at most %s",
			ErrMintRefused, lifetime, c.options.MaxCredentialLifetime,
		)
	}
	now := c.now().UTC()
	if now.Before(credential.notBefore.Add(-corework.DefaultSkew)) {
		// Not yet valid: the clocks are further apart than core's own skew.
		// RETRYABLE, because the thing that most often causes it does fix
		// itself — ntpd stepping a clock that drifted, a VM resuming. Latched,
		// a process that happened to boot inside that window never recovered.
		return fmt.Errorf(
			"%w: the minted credential is not valid until %s, and it is %s",
			ErrMintUnavailable, credential.notBefore, now,
		)
	}
	if !now.Before(credential.expiresAt) {
		// Already expired on arrival. This is what a DELAYED response looks
		// like, which the next attempt may well not hit, so it is an outage
		// and not a refusal — and the backoff is what stops the next attempt
		// being immediate.
		return fmt.Errorf(
			"%w: the minted credential expired at %s, and it is %s",
			ErrMintUnavailable, credential.expiresAt, now,
		)
	}
	if c.dueForRenewalLocked(credential) {
		// Installing it would put the client straight back into a renewal and
		// the next response would be the same one: a mint loop, one audit event
		// per iteration, which is the heartbeat this client replaced.
		//
		// ErrMintUnavailable rather than ErrMintRefused, which is the sentinel
		// this carried first and got wrong: a merely delayed response produces
		// exactly this, and ErrMintRefused means "the host will say the same
		// thing again, do not serve". A caller must not stop serving because
		// one response arrived late.
		return fmt.Errorf(
			"%w: the minted credential's whole remaining lifetime is inside the renewal lead (%s to %s)",
			ErrMintUnavailable, credential.notBefore, credential.expiresAt,
		)
	}
	return nil
}

// answeredFromElsewhere reports the redacted URL a response actually came from
// when that is not the configured endpoint, and "" when it is.
func answeredFromElsewhere(response *http.Response, configured string) string {
	if response == nil || response.Request == nil || response.Request.URL == nil {
		return ""
	}
	if response.Request.URL.String() == configured {
		return ""
	}
	return response.Request.URL.Redacted()
}

// sealCarriesAnExecution is CORE'S OWN TEST, copied expression for expression
// from checkExecutionAgainst (core workcontext/seal.go):
//
//	carried := sealed.GetImageDigest() != "" || sealed.GetBuildIncarnation() != 0
//
// This module had a second definition — it tested PRESENCE
// (seal.BuildIncarnation == nil) while core tests VALUES — and two definitions
// of "carries an execution" is one too many whether or not they currently
// agree. They agree for anything that survives Inspect, because the schema
// requires the pair; they would disagree about a seal carrying a digest with
// no incarnation, which is exactly the kind of case a protovalidate rule gets
// relaxed out from under.
//
// Core exports no predicate for this, so adopting its expression is the
// closest thing to calling it. Core has been asked for one; if it lands, this
// becomes a call and the duplication goes.
func sealCarriesAnExecution(seal *SealedValues) bool {
	return seal.GetImageDigest() != "" || seal.GetBuildIncarnation() != 0
}

// refusalStatuses are the ONLY statuses that latch this client.
//
// The rule used to be the other way round — 429 and 5xx were retryable and
// EVERYTHING ELSE was a terminal refusal — which made every status a host or
// anything between it and this process might invent into a permanent stop. It
// was measured: a 408 from a proxy, with a valid credential in hand, refused,
// did not serve, and latched for the life of the process. A 425, a 404 from an
// ingress mid-rollout and a 502 rendered as 400 by a sidecar would each do the
// same.
//
// So the default is now "retryable", and latching is the enumerated case:
//
//	401  the projected token is not acceptable. Presenting it again is the
//	     thing this client must not do.
//	403  the host authenticated the process and refused it — the build is not
//	     approved, the installation is not one it may serve.
//
// Everything else is an outage: the held credential keeps being served while it
// is valid, the next attempt is held off, and the process does not stop. That is
// the right default because the cost of being wrong is asymmetric — a wrong
// "retryable" costs one request per hold-off, and a wrong "terminal" costs the
// process.
//
// A refusal this client decides for ITSELF — an audience that does not match
// the pin, a seal the host contradicted, a refused redirect, a certificate that
// did not verify — still latches, because those are this client's own verdicts
// and not a status somebody in the middle chose.
var refusalStatuses = []int{
	http.StatusUnauthorized,
	http.StatusForbidden,
}

// sentinelForStatus classifies the host's status code.
func sentinelForStatus(status int) error {
	if slices.Contains(refusalStatuses, status) {
		return ErrMintRefused
	}
	return ErrMintUnavailable
}

// mintRequest is everything the client tells the host, which is only what it
// wants — never who it is. Principal, installation and build are established
// by the host from the projected token and its own records; a field here for
// any of them would be a field a process could lie in.
type mintRequest struct {
	Audience           string `json:"audience"`
	ProjectionAudience string `json:"projection_audience"`
}

// mintResponse is the host's answer. The echoed fields are for logs and for
// catching a host and a signature that disagree; nothing authorizes from them.
type mintResponse struct {
	WorkContext      string `json:"work_context"`
	InstallationID   string `json:"installation_id,omitempty"`
	BuildIncarnation string `json:"build_incarnation,omitempty"`
}

// validateMintURL requires absolute HTTPS with no userinfo, query or fragment.
//
// Its refusal is ErrInvalid, like every other construction-time check: nothing
// has been asked of a host, so "the mint refused you" is the wrong thing to
// tell a caller — and ErrMintRefused is the sentinel this package documents as
// meaning a process must stop serving.
//
// Plaintext HTTP used to be accepted here, which made the strongest reason this
// endpoint exists — that the projected service-account token is presented to it
// and nothing else — contingent on a configuration value. A credential request
// goes over an authenticated channel or it does not go.
func validateMintURL(raw string) (string, error) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed.Host == "" || parsed.User != nil ||
		parsed.Fragment != "" || parsed.RawQuery != "" || parsed.Scheme != "https" {
		return "", fmt.Errorf(
			"%w: mint URL must be an absolute https URL without credentials, query, or fragment",
			ErrInvalid,
		)
	}
	return parsed.String(), nil
}

// tlsVerificationFailure names the reason when err is a failure to
// AUTHENTICATE the endpoint, and returns "" for every other transport error.
//
// The distinction is the one this client's whole transport is about. A dial
// timeout, a reset, a closed connection: the endpoint is not answering, which
// is an outage and is retryable. A certificate that does not chain to the
// configured roots, is for another name, or has expired: something answered and
// could not prove it is the endpoint — so the next attempt would present the
// projected service-account token to it again.
func tlsVerificationFailure(err error) string {
	var verification *tls.CertificateVerificationError
	if errors.As(err, &verification) {
		return "certificate verification failed"
	}
	var unknownAuthority x509.UnknownAuthorityError
	if errors.As(err, &unknownAuthority) {
		return "certificate is not signed by a configured root"
	}
	var hostname x509.HostnameError
	if errors.As(err, &hostname) {
		return "certificate is for another name"
	}
	var invalid x509.CertificateInvalidError
	if errors.As(err, &invalid) {
		return "certificate is not valid"
	}
	var recordHeader tls.RecordHeaderError
	if errors.As(err, &recordHeader) {
		// The endpoint answered something that is not TLS at all on a URL this
		// client required to be https.
		return "the endpoint did not answer with TLS"
	}
	return ""
}
