package workcontext

import (
	"bytes"
	"context"
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

// AuthorityPin is the boot-read authority a renewal is checked against. The
// root SDK's *codefly.Authority satisfies it.
//
// It exists so a renewal cannot re-seal a credential to a value that drifted
// after boot. The host is the authority for the audience and the binding a
// process mints against; a value that changes under a running process is an
// error, and the renewal is exactly the moment that error would otherwise be
// laundered into a new, differently-sealed credential.
type AuthorityPin interface {
	Recheck(ctx context.Context) error
}

// MintOptions configures the one credential a process obtains per execution.
type MintOptions struct {
	// URL is the host's mint endpoint, absolute, no query and no fragment.
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
	// Authority, when set, is rechecked before every renewal.
	Authority AuthorityPin
	// HTTPClient defaults to a client that refuses to follow redirects: a
	// redirected mint request is a credential request sent somewhere the
	// configuration did not name.
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
// obtained once by Mint and replaced only by renewal at expiry.
type Credential struct {
	token     string
	seal      Seal
	binding   *OperationBinding
	issuedAt  time.Time
	expiresAt time.Time
}

// Token returns the opaque signed capability, as it travels. It is a string and
// not a type of this module's: a capability is an opaque string until a Verifier
// has had it, and a typed wrapper here would offer the reassurance of a check
// nobody performed.
func (c Credential) Token() string { return c.token }

// Seal returns the execution this credential is bound to.
func (c Credential) Seal() Seal { return c.seal }

// OperationBinding returns the one binding this credential may act through, or
// nil.
func (c Credential) OperationBinding() *OperationBinding {
	if c.binding == nil {
		return nil
	}
	binding := *c.binding
	return &binding
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
	mints      uint64
	renewals   uint64
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
	client := options.HTTPClient
	if client == nil {
		client = &http.Client{
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
	}
	options.URL = endpoint
	options.RequestTimeout = timeout
	options.RenewalLead = lead
	return &MintClient{options: options, httpClient: client, now: now}, nil
}

// Credential returns the credential for this moment, minting the first one and
// renewing a credential that has reached its renewal point. Every caller goes
// through it, so there is no path on which a stale credential is used.
//
// It holds one lock across the mint request, so concurrent callers wait rather
// than each minting their own. That is the point: a process obtains one
// credential per execution, and a process whose first request burst produced
// one mint per goroutine would be the heartbeat again under another name. The
// request timeout bounds the wait.
//
// Renewal re-reads the projected token and rechecks the boot-read authority
// first. A projection rotated under the running process is therefore picked up
// without a restart, and an authority value that drifted refuses the renewal
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
	if renewal && c.options.Authority != nil {
		if err := c.options.Authority.Recheck(ctx); err != nil {
			return Credential{}, fmt.Errorf("%w: %v", ErrMintRefused, err)
		}
	}
	credential, err := c.mintLocked(ctx)
	if err != nil {
		return Credential{}, err
	}
	c.credential = &credential
	if renewal {
		c.renewals++
	} else {
		c.mints++
	}
	return credential, nil
}

// Counts reports how many first mints and how many renewals this process has
// performed. A correct execution reports exactly one mint; renewals are
// expected and bounded by the credential's lifetime, not by a beat.
func (c *MintClient) Counts() (mints uint64, renewals uint64) {
	if c == nil {
		return 0, 0
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.mints, c.renewals
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
		return Credential{}, fmt.Errorf("%w: %v", ErrMintUnavailable, err)
	}
	defer func() {
		_ = response.Body.Close()
	}()
	if response.Request != nil && response.Request.URL != nil &&
		response.Request.URL.String() != c.options.URL {
		// The projected token was already sent to whatever answered. Treating a
		// redirect as retryable would send it again; treating it as a refusal
		// stops the process, which is the only safe outcome once a credential
		// request has left for an address nothing configured.
		return Credential{}, fmt.Errorf("%w: mint request was redirected", ErrMintRefused)
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
	return Credential{
		token:     token,
		seal:      seal,
		binding:   binding,
		issuedAt:  time.Unix(claims.GetIssuedAtUnix(), 0).UTC(),
		expiresAt: time.Unix(claims.GetExpiresAtUnix(), 0).UTC(),
	}, nil
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

func validateMintURL(raw string) (string, error) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed.Host == "" || parsed.User != nil ||
		parsed.Fragment != "" || parsed.RawQuery != "" ||
		parsed.Scheme != "http" && parsed.Scheme != "https" {
		return "", fmt.Errorf(
			"%w: mint URL must be an absolute HTTP(S) URL without credentials, query, or fragment",
			ErrMintRefused,
		)
	}
	return parsed.String(), nil
}
