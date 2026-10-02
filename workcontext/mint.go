package workcontext

import (
	"bytes"
	"context"
	"crypto/tls"
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

// AuthorityPin is the boot-read authority every mint is checked against. The
// root SDK's *codefly.Authority satisfies it.
//
// It exists so a mint cannot seal a credential to a value that drifted after
// boot. The host is the authority for the audience and the binding a process
// mints against; a value that changes under a running process is an error, and
// a mint is exactly the moment that error would otherwise be laundered into a
// new, differently-sealed credential.
//
// It is checked before the FIRST mint too, and not only before a renewal: a
// process may construct its client at boot and make its first call an hour
// later, and the value can have moved in between.
type AuthorityPin interface {
	Recheck(ctx context.Context) error
}

// MintOptions configures the one credential a process obtains per execution.
type MintOptions struct {
	// URL is the host's mint endpoint: absolute HTTPS, no query, no fragment,
	// no userinfo. Plain HTTP is refused — the projected service-account token
	// travels on this request as a bearer credential.
	URL string
	// Audience is the Work Context audience to mint for, as the host names it.
	// It is read from the process's boot-read authority, never typed.
	Audience string
	// ProjectedToken reads the platform's projection of this process's
	// service-account token. Required.
	ProjectedToken ProjectedTokenSource
	// ProjectionAudience is the audience the projected token itself was minted
	// for, which the host states. Sent so the host can refuse a projection
	// aimed at something else rather than reviewing whatever it is handed.
	ProjectionAudience string
	// Authority, when set, is rechecked before every mint, including the first.
	// A process that resolved its audience or binding through ReadAuthority
	// passes it here; without it there is no pin for this client to check and
	// the drift refusal is not available to it.
	Authority AuthorityPin
	// HTTPClient is used as given except that redirects are refused on a copy
	// of it, whatever it was configured to do. A redirected mint request is a
	// credential request sent somewhere the configuration did not name.
	HTTPClient *http.Client
	// RequestTimeout bounds one mint request.
	RequestTimeout time.Duration
	// RenewalLead overrides the fraction of a credential's lifetime at which
	// renewal is attempted. Zero takes the default.
	RenewalLead float64
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
}

// NewMintClient validates configuration without performing any I/O.
func NewMintClient(options MintOptions) (*MintClient, error) {
	endpoint, err := validateMintURL(options.URL)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(options.Audience) == "" {
		return nil, fmt.Errorf("%w: no audience to mint for", ErrMintRefused)
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
	now := options.Now
	if now == nil {
		now = time.Now
	}
	client, err := secureMintClient(options.HTTPClient)
	if err != nil {
		return nil, err
	}
	options.URL = endpoint
	options.RequestTimeout = timeout
	options.RenewalLead = lead
	return &MintClient{options: options, httpClient: client, now: now}, nil
}

// secureMintClient returns the client every mint request is made with:
// the caller's, copied, with redirects refused on the copy.
//
// Refusing them on a client of our own was not enough. The projection is on the
// request as a bearer token, and Go's own client forwards Authorization across a
// redirect to the same host — so a caller that supplied an ordinary
// &http.Client{} disclosed the projection to whatever that host redirected to,
// before anything here could classify the answer. The refusal is therefore
// installed on EVERY client, before any request leaves. It is installed on a
// copy so a caller that uses its client elsewhere keeps its own redirect
// behaviour there.
func secureMintClient(supplied *http.Client) (*http.Client, error) {
	client := &http.Client{}
	if supplied != nil {
		copied := *supplied
		client = &copied
	}
	if err := checkTransportAuthenticates(client.Transport); err != nil {
		return nil, err
	}
	client.CheckRedirect = refuseMintRedirect
	return client, nil
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

// checkTransportAuthenticates refuses a transport configured not to verify the
// endpoint's certificate. HTTPS whose certificate nobody checks is plaintext
// with extra steps, and this is the one request that carries the projection.
//
// A RoundTripper this package cannot inspect is not refused — it cannot be —
// but it cannot downgrade the scheme either, and the URL check above requires
// https.
func checkTransportAuthenticates(transport http.RoundTripper) error {
	settings, ok := transport.(*http.Transport)
	if !ok {
		return nil
	}
	if settings.TLSClientConfig != nil && settings.TLSClientConfig.InsecureSkipVerify {
		return fmt.Errorf(
			"%w: the mint client's transport does not verify the endpoint's certificate",
			ErrMintRefused,
		)
	}
	if settings.TLSClientConfig != nil &&
		settings.TLSClientConfig.MinVersion != 0 &&
		settings.TLSClientConfig.MinVersion < tls.VersionTLS12 {
		return fmt.Errorf(
			"%w: the mint client's transport permits TLS below 1.2",
			ErrMintRefused,
		)
	}
	return nil
}

// Credential returns the credential for this moment, minting the first one and
// renewing a credential that has reached its renewal point. Every caller goes
// through it, so no caller obtains a credential this client knows to be past
// its renewal point.
//
// It is not a guarantee about a credential a caller already holds: a Credential
// is a value, so one read out of here and kept can be attached after the host
// has moved the state under it. That is what Refresh is for, and it is why a
// receiver verifies rather than trusting that a caller re-asked.
//
// It holds one lock across the mint request, so concurrent callers wait rather
// than each minting their own. That is the point: a process obtains one
// credential per execution, and a process whose first request burst produced
// one mint per goroutine would be the heartbeat again under another name. The
// request timeout bounds the wait.
//
// Every mint re-reads the projected token and rechecks the boot-read authority
// first. A projection rotated under the running process is therefore picked up
// without a restart, and an authority value that drifted refuses the mint
// instead of being sealed into a new credential.
func (c *MintClient) Credential(ctx context.Context) (Credential, error) {
	if c == nil {
		return Credential{}, fmt.Errorf("%w: nil mint client", ErrMintRefused)
	}
	if ctx == nil {
		return Credential{}, fmt.Errorf("%w: nil context", ErrMintRefused)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.credential != nil && !c.dueForRenewalLocked(*c.credential) {
		return *c.credential, nil
	}
	renewal := c.credential != nil
	credential, err := c.obtainLocked(ctx)
	if err != nil {
		return Credential{}, err
	}
	if renewal {
		c.counts.Renewals++
	} else {
		c.counts.Mints++
	}
	return credential, nil
}

// Refresh replaces a credential the host has refused — ErrRevoked from a
// verifier at the far end, which means the credential was sound when it was
// minted and the state moved under it.
//
// Without it there was no way back: Credential answers from the credential it
// holds until that credential's own renewal point, so a process whose
// installation revision changed served refusals until a lead that the host
// chooses — hours, for a long-lived credential — had elapsed.
//
// It is tied to the credential that was refused, not to the clock. A caller
// passes back the Credential it was refused on; if this client has already
// replaced that one, the replacement is returned and nothing is minted. So a
// burst of concurrent refusals on one credential produces exactly one
// replacement mint, and a caller holding a credential two generations old
// cannot roll the client backwards by asking about it.
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
	defer c.mu.Unlock()
	if c.credential == nil {
		return Credential{}, fmt.Errorf(
			"%w: this client has issued no credential to refresh", ErrMintRefused,
		)
	}
	if c.credential.generation != refused.generation {
		// Somebody else was refused on the same credential and has already
		// replaced it. Minting again here would be the second mint for one
		// revocation, which is the thing this client exists not to do.
		return *c.credential, nil
	}
	credential, err := c.obtainLocked(ctx)
	if err != nil {
		return Credential{}, err
	}
	c.counts.Refreshes++
	return credential, nil
}

// obtainLocked rechecks the pinned authority, mints, and installs the result as
// the credential this client holds. It is the one path that writes
// c.credential, so a mint that is refused leaves the previous credential in
// place rather than clearing it: a refused renewal must not turn into "this
// process holds nothing", which reads as a boot failure somewhere it is not.
func (c *MintClient) obtainLocked(ctx context.Context) (Credential, error) {
	if c.options.Authority != nil {
		if err := c.options.Authority.Recheck(ctx); err != nil {
			return Credential{}, fmt.Errorf("%w: %v", ErrMintRefused, err)
		}
	}
	credential, err := c.mintLocked(ctx)
	if err != nil {
		return Credential{}, err
	}
	c.generation++
	credential.generation = c.generation
	c.credential = &credential
	return credential, nil
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
	lifetime := credential.expiresAt.Sub(credential.issuedAt)
	lead := time.Duration(float64(lifetime) * c.options.RenewalLead)
	if lead < minRenewalLeadTime {
		lead = minRenewalLeadTime
	}
	if lead > lifetime {
		lead = lifetime
	}
	return remaining <= lead
}

func (c *MintClient) mintLocked(ctx context.Context) (Credential, error) {
	projected, err := c.options.ProjectedToken.ProjectedToken()
	if err != nil {
		return Credential{}, err
	}
	body, err := json.Marshal(mintRequest{
		Audience:           c.options.Audience,
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
	if contentType := response.Header.Get("Content-Type"); contentType != "" {
		mediaType, _, parseErr := mime.ParseMediaType(contentType)
		if parseErr != nil || mediaType != "application/json" {
			return Credential{}, fmt.Errorf("%w: mint response is not application/json", ErrMintRefused)
		}
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
	return c.credentialFrom(payload)
}

// credentialFrom reads the credential out of the response and takes its sealed
// values from the token, not from the response body. The host may echo them for
// a log, and an echo that disagrees with the signature is a refusal: the only
// installation, build and epoch that mean anything are the signed ones.
func (c *MintClient) credentialFrom(payload []byte) (Credential, error) {
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
	if claims.GetAudience() != c.options.Audience {
		return Credential{}, fmt.Errorf(
			"%w: credential was minted for audience %q, not %q",
			ErrMintRefused, claims.GetAudience(), c.options.Audience,
		)
	}
	credential := Credential{
		token:     token,
		seal:      seal,
		binding:   binding,
		issuedAt:  time.Unix(claims.GetIssuedAtUnix(), 0).UTC(),
		expiresAt: time.Unix(claims.GetExpiresAtUnix(), 0).UTC(),
	}
	if err := c.checkWindow(credential); err != nil {
		return Credential{}, err
	}
	return credential, nil
}

// checkWindow refuses a credential that is unusable the moment it arrives.
//
// The renewal check only ever looked at the credential already held, so a
// response that was delayed, or minted against a clock well behind this
// process's, was installed as a success and then refused by every receiver —
// with the mint counted as having worked. A credential is checked against its
// own window before it is installed, with core's own skew so the tolerance here
// is the verifier's and not a second number.
func (c *MintClient) checkWindow(credential Credential) error {
	if !credential.expiresAt.After(credential.issuedAt) {
		return fmt.Errorf(
			"%w: the minted credential expires at or before it was issued (%s to %s)",
			ErrMintRefused, credential.issuedAt, credential.expiresAt,
		)
	}
	now := c.now().UTC()
	if now.Before(credential.issuedAt.Add(-corework.DefaultSkew)) {
		return fmt.Errorf(
			"%w: the minted credential is not valid until %s, and it is %s",
			ErrMintRefused, credential.issuedAt, now,
		)
	}
	if !now.Before(credential.expiresAt) {
		return fmt.Errorf(
			"%w: the minted credential expired at %s, and it is %s",
			ErrMintRefused, credential.expiresAt, now,
		)
	}
	if c.dueForRenewalLocked(credential) {
		// Installing it would put the client straight back into a renewal, and
		// the next response would be the same one: a mint loop, one audit event
		// per iteration, which is the heartbeat this client replaced.
		return fmt.Errorf(
			"%w: the minted credential's whole lifetime is inside the renewal lead (%s to %s)",
			ErrMintRefused, credential.issuedAt, credential.expiresAt,
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
