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
	"strconv"
	"strings"
	"sync"
	"time"

	corework "github.com/codefly-dev/core/workcontext"
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
	// hold. Core checks only that a TTL is positive, so without a ceiling a
	// misconfigured host minting a month-long credential is accepted in
	// silence. It is generous enough for the lifetimes the mint-once model
	// wants — an hour's run needs about 75 minutes at the default lead — and
	// short enough that a month is not one of them.
	defaultMaxCredentialLifetime = 24 * time.Hour

	// Backoff after a mint that failed. A failed renewal used to return an
	// error to every caller while the held credential still had minutes left,
	// and each caller then retried serially under the client's lock: one mint
	// request per caller, which is the heartbeat under another name.
	minMintBackoff = time.Second
	maxMintBackoff = time.Minute
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
		return "", fmt.Errorf("%w: no projected token path", ErrMintRefused)
	}
	file, err := os.Open(string(path))
	if err != nil {
		return "", fmt.Errorf("%w: open projected token: %v", ErrMintRefused, err)
	}
	defer func() {
		_ = file.Close()
	}()
	raw, err := io.ReadAll(io.LimitReader(file, maxProjectedTokenBytes+1))
	if err != nil {
		return "", fmt.Errorf("%w: read projected token: %v", ErrMintRefused, err)
	}
	if len(raw) > maxProjectedTokenBytes {
		return "", fmt.Errorf("%w: projected token exceeds %d bytes", ErrMintRefused, maxProjectedTokenBytes)
	}
	token := strings.TrimSpace(string(raw))
	if token == "" {
		return "", fmt.Errorf("%w: projected token is empty", ErrMintRefused)
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
	// that may sign the mint endpoint's certificate. Nil means the system pool.
	//
	// It replaces an *http.Client, and that is the point. A client is a hole:
	// its Transport may be nil (so the global, mutable http.DefaultTransport),
	// a wrapper this package cannot inspect, or one with a DialTLSContext that
	// bypasses TLSClientConfig entirely — and a caller holding the same
	// *http.Transport pointer can turn verification off after construction,
	// because a copied http.Client shares it. Inspecting a supplied client
	// could not close any of that. So the client builds and owns its transport:
	// TLS 1.2 minimum, verification on, no custom dialer, redirects refused.
	RootCAs *x509.CertPool

	// RequestTimeout bounds one mint request.
	RequestTimeout time.Duration

	// RenewalLead overrides the fraction of a credential's lifetime at which
	// renewal is attempted. Zero takes the default.
	RenewalLead float64

	// MaxCredentialLifetime refuses a credential the host minted for longer
	// than this. Zero takes defaultMaxCredentialLifetime.
	//
	// The ceiling is here because there is none at the minter: core checks only
	// that the TTL is positive, so a misconfigured host can mint a credential
	// valid for a month and every verifier will accept it. A ceiling in the
	// client is the weaker half of that fix — it bounds what THIS process will
	// hold, not what the host will issue — and the cap belongs at the minter.
	MaxCredentialLifetime time.Duration

	// Now is the clock, for tests.
	Now func() time.Time
}

// Credential is the sealed capability a process holds for its execution. It is
// obtained once by Mint and replaced only by renewal at expiry or by Refresh
// after the host has refused it.
type Credential struct {
	token     string
	seal      Seal
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
}

// Token returns the opaque signed capability, as it travels. It is a string and
// not a type of this module's: a capability is an opaque string until a Verifier
// has had it, and a typed wrapper here would offer the reassurance of a check
// nobody performed.
func (c Credential) Token() string { return c.token }

// Seal returns the execution this credential is bound to.
func (c Credential) Seal() Seal { return c.seal }

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

	// backoff holds off the next attempt after a failure, and failures counts
	// consecutive ones so the hold-off grows. Without it, a host answering 503
	// received one request per caller per call — the heartbeat under another
	// name, arriving exactly when the host is least able to serve it.
	backoffUntil time.Time
	failures     int
}

// NewMintClient validates configuration without performing any I/O.
func NewMintClient(options MintOptions) (*MintClient, error) {
	endpoint, err := validateMintURL(options.URL)
	if err != nil {
		return nil, err
	}
	if options.Authority == nil {
		return nil, fmt.Errorf(
			"%w: a mint client needs the process's boot-read authority; the audience is read from it",
			ErrMintRefused,
		)
	}
	audience := AuthorityValue{
		Name: strings.TrimSpace(options.Audience.Name),
		Key:  strings.TrimSpace(options.Audience.Key),
	}
	if audience.Name == "" || audience.Key == "" {
		return nil, fmt.Errorf(
			"%w: name the pinned value the audience is read from", ErrMintRefused,
		)
	}
	if options.ProjectedToken == nil {
		return nil, fmt.Errorf("%w: no projected token source", ErrMintRefused)
	}
	if strings.TrimSpace(options.ProjectionAudience) == "" {
		return nil, fmt.Errorf("%w: no projection audience", ErrMintRefused)
	}
	timeout := options.RequestTimeout
	if timeout == 0 {
		timeout = defaultMintRequestTimeout
	}
	if timeout < time.Millisecond || timeout > maxMintRequestTimeout {
		return nil, fmt.Errorf(
			"%w: mint request timeout must be between 1ms and %s",
			ErrMintRefused, maxMintRequestTimeout,
		)
	}
	lead := options.RenewalLead
	if lead == 0 {
		lead = defaultRenewalLead
	}
	if lead <= 0 || lead >= 1 {
		return nil, fmt.Errorf("%w: renewal lead must be between zero and one", ErrMintRefused)
	}
	ceiling := options.MaxCredentialLifetime
	if ceiling == 0 {
		ceiling = defaultMaxCredentialLifetime
	}
	if ceiling <= 0 {
		return nil, fmt.Errorf("%w: maximum credential lifetime must be positive", ErrMintRefused)
	}
	now := options.Now
	if now == nil {
		now = time.Now
	}
	options.URL = endpoint
	options.Audience = audience
	options.RequestTimeout = timeout
	options.RenewalLead = lead
	options.MaxCredentialLifetime = ceiling
	return &MintClient{
		options:    options,
		httpClient: mintHTTPClient(options.RootCAs),
		now:        now,
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
				RootCAs:    roots, // nil means the system pool
				MinVersion: tls.VersionTLS12,
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
// **A held credential that is still valid is served even when a renewal
// fails.** Entering the renewal lead and failing used to return an error to
// every caller while the credential in hand had minutes of validity left — an
// outage this client manufactured out of a credential that still worked. A
// renewal failure is only an error once the credential has actually expired.
//
// One mint at a time, and the wait is cancellable. Concurrent callers wait on a
// channel rather than on the mutex, so a caller whose ctx is cancelled stops
// waiting, and a failing mint produces one request rather than one per caller.
// After a failure the next attempt is held off, growing to a minute: a process
// obtains one credential per execution, and a process that answered a 503 with
// a request per call would be the heartbeat again under another name.
func (c *MintClient) Credential(ctx context.Context) (Credential, error) {
	if c == nil {
		return Credential{}, fmt.Errorf("%w: nil mint client", ErrMintRefused)
	}
	if ctx == nil {
		return Credential{}, fmt.Errorf("%w: nil context", ErrMintRefused)
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
// It is held to the same backoff as a renewal, which matters for the case a
// generation check alone does not cover: a receiver whose seal source lags
// refuses each FRESH credential too, and every refusal is a new generation. The
// backoff is what bounds that into one mint per hold-off rather than one per
// call.
func (c *MintClient) Refresh(ctx context.Context, refused Credential) (Credential, error) {
	if c == nil {
		return Credential{}, fmt.Errorf("%w: nil mint client", ErrMintRefused)
	}
	if ctx == nil {
		return Credential{}, fmt.Errorf("%w: nil context", ErrMintRefused)
	}
	if refused.generation == 0 {
		return Credential{}, fmt.Errorf(
			"%w: refresh needs the credential that was refused, as this client issued it",
			ErrMintRefused,
		)
	}
	c.mu.Lock()
	issued := c.credential != nil
	c.mu.Unlock()
	if !issued {
		return Credential{}, fmt.Errorf(
			"%w: this client has issued no credential to refresh", ErrMintRefused,
		)
	}
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
		held := c.credential
		if held != nil && !c.dueForRenewalLocked(*held) &&
			(wanted == nil || !wanted(held)) {
			credential := *held
			c.mu.Unlock()
			return credential, nil
		}
		usable := held != nil && c.now().UTC().Before(held.expiresAt)
		if waiting := c.inflight; waiting != nil {
			// Another goroutine is minting. Wait for it rather than queueing a
			// second request, and let ctx cancel the wait.
			snapshot := Credential{}
			if held != nil {
				snapshot = *held
			}
			c.mu.Unlock()
			select {
			case <-waiting:
				continue
			case <-ctx.Done():
				if usable {
					return snapshot, nil
				}
				// Both stay in the chain: a caller that cancelled wants to see
				// its own cancellation, not only that minting was unavailable.
				return Credential{}, fmt.Errorf("%w: %w", ErrMintUnavailable, ctx.Err())
			}
		}
		if until := c.backoffUntil; !until.IsZero() && c.now().UTC().Before(until) {
			// Held off after a failure. Serving the credential in hand is the
			// whole point of the hold-off; only an expired one is an error.
			if usable {
				credential := *held
				c.mu.Unlock()
				return credential, nil
			}
			c.mu.Unlock()
			return Credential{}, fmt.Errorf(
				"%w: the last mint failed and the next attempt is held off until %s",
				ErrMintUnavailable, until,
			)
		}
		done := make(chan struct{})
		c.inflight = done
		renewal := held != nil
		c.mu.Unlock()

		credential, err := c.mintOnce(ctx)

		c.mu.Lock()
		c.inflight = nil
		if err != nil {
			c.failures++
			c.backoffUntil = c.now().UTC().Add(mintBackoff(c.failures))
			stillUsable := c.credential != nil && c.now().UTC().Before(c.credential.expiresAt)
			snapshot := Credential{}
			if stillUsable {
				snapshot = *c.credential
			}
			c.mu.Unlock()
			close(done)
			if stillUsable {
				// The credential in hand still works. A renewal that failed is
				// not an outage until the thing it was renewing has expired.
				return snapshot, nil
			}
			return Credential{}, err
		}
		c.failures = 0
		c.backoffUntil = time.Time{}
		c.generation++
		credential.generation = c.generation
		c.credential = &credential
		switch {
		case !renewal:
			c.counts.Mints++
		case reason == mintReasonRefresh:
			c.counts.Refreshes++
		default:
			c.counts.Renewals++
		}
		c.mu.Unlock()
		close(done)
		return credential, nil
	}
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
	projected, err := c.options.ProjectedToken.ProjectedToken()
	if err != nil {
		return Credential{}, err
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
		return Credential{}, fmt.Errorf("%w: %v", ErrMintUnavailable, err)
	}
	defer func() {
		_ = response.Body.Close()
	}()
	if response.Request != nil && response.Request.URL != nil &&
		response.Request.URL.String() != c.options.URL {
		// The redirect refusal above is what prevents a second request, and a
		// transport that redirects inside itself never calls it. If the answer
		// came from anywhere other than the configured URL, the projected token
		// has already been seen by something nothing configured, and stopping
		// the process is the only safe outcome.
		return Credential{}, fmt.Errorf(
			"%w: the mint response came from %s, not the configured endpoint",
			ErrMintRefused, response.Request.URL.Redacted(),
		)
	}
	if response.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4*1024))
		sentinel := ErrMintRefused
		if response.StatusCode == http.StatusTooManyRequests || response.StatusCode >= 500 {
			sentinel = ErrMintUnavailable
		}
		return Credential{}, fmt.Errorf("%w: mint returned HTTP %d", sentinel, response.StatusCode)
	}
	// Content-Type is REQUIRED, not checked when present. An absent header used
	// to be accepted, which made "the response is JSON" something the host
	// could decline to state about the one response this process trusts for its
	// whole life.
	mediaType, _, parseErr := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if parseErr != nil || mediaType != "application/json" {
		return Credential{}, fmt.Errorf(
			"%w: mint response must declare Content-Type: application/json", ErrMintRefused,
		)
	}
	payload, err := io.ReadAll(io.LimitReader(response.Body, maxMintResponseBytes+1))
	if err != nil {
		return Credential{}, fmt.Errorf("%w: read mint response: %v", ErrMintRefused, err)
	}
	if len(payload) > maxMintResponseBytes {
		return Credential{}, fmt.Errorf(
			"%w: mint response exceeds %d bytes", ErrMintRefused, maxMintResponseBytes,
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
		return Credential{}, fmt.Errorf("%w: decode mint response: %v", ErrMintRefused, err)
	}
	token := body.WorkContext
	claims, seal, binding, err := sealOf(token)
	if err != nil {
		return Credential{}, fmt.Errorf("%w: %v", ErrMintRefused, err)
	}
	if body.InstallationID != "" && body.InstallationID != seal.InstallationID {
		return Credential{}, fmt.Errorf(
			"%w: mint reported installation %q and sealed %q",
			ErrMintRefused, body.InstallationID, seal.InstallationID,
		)
	}
	if body.BuildIncarnation != "" &&
		body.BuildIncarnation != strconv.FormatUint(seal.BuildIncarnation, 10) {
		return Credential{}, fmt.Errorf(
			"%w: mint reported build incarnation %q and sealed %d",
			ErrMintRefused, body.BuildIncarnation, seal.BuildIncarnation,
		)
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
// here and refused everywhere. And it bounds the lifetime: core checks only
// that a TTL is positive, so a misconfigured host minting a month-long
// credential was installed in silence.
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
		return fmt.Errorf(
			"%w: the minted credential is valid for %s, and this process holds a credential for at most %s",
			ErrMintRefused, lifetime, c.options.MaxCredentialLifetime,
		)
	}
	now := c.now().UTC()
	if now.Before(credential.notBefore.Add(-corework.DefaultSkew)) {
		// Not yet valid. A clock this far apart is a configuration error on one
		// side or the other and will not fix itself, so it is a refusal.
		return fmt.Errorf(
			"%w: the minted credential is not valid until %s, and it is %s",
			ErrMintRefused, credential.notBefore, now,
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
			ErrMintRefused,
		)
	}
	return parsed.String(), nil
}
