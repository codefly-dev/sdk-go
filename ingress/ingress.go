// Package ingress serves a module's gateway ingress: a TLS-only listener under
// the module's own X.509-SVID that admits only the callers the platform
// provisions (the host's gateway), and the report that tells the host where it
// serves.
//
// The gateway reaches a composed module at /v1/<alias>/* only once three things
// hold: the module's presence is applied, its origin has been reported by a
// workload that proved its identity, and the destination presents the SVID the
// applied presence names. This package does the module's half of the last two
// with the workload package's listener and client, so a module's ingress is
// held to the same posture as a solution's listener — the same rules, moved
// rather than copied.
//
// It is a second listener beside the module's own endpoints, not a replacement
// for them: what other modules call stays as it is. The ingress serves whatever
// handler the module hands it, which is normally the handler of the surface the
// gateway forwards /v1/<alias>/* to.
package ingress

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/codefly-dev/core/wool"
	codefly "github.com/codefly-dev/sdk-go"
	"github.com/codefly-dev/sdk-go/workload"
)

// EndpointName and EndpointAPI name the endpoint a module declares for its
// gateway ingress: the composition assigns its port and advertises its address
// like any other endpoint's.
const (
	EndpointName = "ingress"
	EndpointAPI  = "http"
)

// ReportPath is the host's workload endpoint a module reports its origin at,
// on the same origin it mints at (the credential mint URL).
const ReportPath = "/modules/_upstream"

// CredentialMintURL is the runtime value naming the host endpoint this workload
// mints at; the report goes to its origin.
const CredentialMintURL = "CREDENTIAL_MINT_URL"

// Option adjusts Serve.
type Option func(*options)

type options struct {
	prefix     string
	files      *workload.Files
	source     workload.IdentitySource
	listener   net.Listener
	reportURL  string
	advertised string
	backoff    backoff
}

// WithPrefix reports under prefix instead of this process's module name. The
// prefix is the module's route alias, which is its name unless a composition
// aliased it.
func WithPrefix(prefix string) Option { return func(o *options) { o.prefix = prefix } }

// WithFiles uses files instead of the projection resolved from the runtime.
func WithFiles(files workload.Files) Option { return func(o *options) { o.files = &files } }

// WithIdentity serves under source instead of the projected X.509-SVID, for a
// platform that hands out identities another way. It is held to the same
// posture; see workload.IdentitySource.
func WithIdentity(source workload.IdentitySource) Option {
	return func(o *options) { o.source = source }
}

// WithListener serves on ln instead of binding the ingress endpoint's port.
func WithListener(ln net.Listener) Option { return func(o *options) { o.listener = ln } }

// WithReportURL reports to url (an https URL ending in ReportPath) instead of
// the origin of the credential mint URL.
func WithReportURL(url string) Option { return func(o *options) { o.reportURL = url } }

// WithAdvertisedOrigin reports origin instead of the address the composition
// advertises for the ingress endpoint.
func WithAdvertisedOrigin(origin string) Option {
	return func(o *options) { o.advertised = origin }
}

// Ingress is a serving gateway ingress and its report.
type Ingress struct {
	server   *http.Server
	listener net.Listener
	origin   string
	prefix   string
	reported chan struct{}
	cancel   context.CancelFunc
	done     chan struct{}
	closing  sync.Once
	served   error
}

// Serve starts the gateway ingress for this workload and reports where it
// serves.
//
// Everything is resolved before anything is bound or dialled, and a boot that
// cannot produce an identity, an admitted set, an advertised origin or a report
// destination is refused naming the missing material: there is no plain
// listener and no fallback, because an ingress the gateway cannot verify is one
// it refuses for a reason only the gateway can see.
//
// The report runs until the host records it (204) and then stops; Reported is
// closed then. A refusal is retried slowly and logged by name, since the cause
// is usually a delivery or an envelope an operator is about to fix; an outage
// is retried with a jittered backoff. Cancelling ctx, or Close, stops both.
func Serve(ctx context.Context, handler http.Handler, opts ...Option) (*Ingress, error) {
	if handler == nil {
		return nil, errors.New("ingress: no handler to serve")
	}
	o := options{backoff: defaultBackoff}
	for _, opt := range opts {
		opt(&o)
	}
	files := workload.ProjectedFiles(ctx)
	if o.files != nil {
		files = *o.files
	}
	source := o.source
	if source == nil {
		source = workload.Projected(files)
	}
	principal, err := workload.PrincipalOf(source)
	if err != nil {
		return nil, fmt.Errorf("ingress: %w", err)
	}
	admitted := workload.IdentitySet(files.AllowedCallers, fmt.Sprintf(
		"whom the gateway ingress admits could not be resolved, so the handshake is refused rather than served against the set this process booted with. Provision %s/%s, or set %s",
		workload.Group, workload.AllowedCallersFileKey, workload.AllowedCallersFileOverride))
	if _, unresolved := admitted(); unresolved != nil {
		return nil, fmt.Errorf("ingress: %w", unresolved)
	}
	identity, err := workload.NewListener(source, principal, admitted)
	if err != nil {
		return nil, fmt.Errorf("ingress: %w", err)
	}

	prefix := strings.TrimSpace(o.prefix)
	if prefix == "" {
		prefix = codefly.Module()
	}
	if prefix == "" {
		return nil, errors.New("ingress: no module name to report under: the runtime names the module this process belongs to, or WithPrefix does")
	}
	reportURL, err := resolveReportURL(o.reportURL)
	if err != nil {
		return nil, fmt.Errorf("ingress: %w", err)
	}
	destination := workload.DialAddress(reportURL)
	// The report carries the projected ServiceAccount token, and the host
	// serves it beside the credential mint on one address: a dial to a shared
	// address cannot be attributed to one role, so only an identity both
	// provisioned sets admit may answer there.
	peers := workload.Intersect(
		workload.IdentitySet(files.GatewayPeers, fmt.Sprintf(
			"which identity answers for the gateway could not be resolved, and the report goes to it with this workload's projected token, so the dial is refused. Provision %s/%s, or set %s",
			workload.Group, workload.GatewayPeersFileKey, workload.GatewayPeersFileOverride)),
		workload.IdentitySet(files.MintPeers, fmt.Sprintf(
			"which identity answers for the credential mint could not be resolved, and the report goes to its address with this workload's projected token, so the dial is refused. Provision %s/%s, or set %s",
			workload.Group, workload.MintPeersFileKey, workload.MintPeersFileOverride)),
		destination)
	if _, unresolved := peers(); unresolved != nil {
		return nil, fmt.Errorf("ingress: %w", unresolved)
	}
	client, err := identity.Client(func(addr string) func() ([]string, error) {
		if addr == destination {
			return peers
		}
		return func() ([]string, error) {
			return nil, fmt.Errorf("refusing to present this workload's credentials at %s: the ingress dials the host's report endpoint (%s) and nothing else", addr, destination)
		}
	}, destination)
	if err != nil {
		return nil, fmt.Errorf("ingress: %w", err)
	}
	if strings.TrimSpace(files.Token) == "" {
		return nil, fmt.Errorf("ingress: no projected ServiceAccount token resolved: the host establishes who reports an origin from it. Provision %s/%s, or set %s",
			workload.Group, workload.TokenFileKey, workload.TokenFileOverride)
	}

	ln := o.listener
	if ln == nil {
		instance, resolveErr := codefly.For(ctx).Endpoint(EndpointName).API(EndpointAPI).ResolveNetworkInstance()
		if resolveErr != nil {
			return nil, fmt.Errorf("ingress: resolve the %q endpoint's port: %w — the module declares an %q endpoint (api %s) and the composition assigns it", EndpointName, resolveErr, EndpointName, EndpointAPI)
		}
		if ln, err = net.Listen("tcp", ":"+strconv.Itoa(int(instance.Port))); err != nil {
			return nil, fmt.Errorf("ingress: bind %d: %w", instance.Port, err)
		}
	}
	origin := strings.TrimSpace(o.advertised)
	if origin == "" {
		if origin, err = advertisedOrigin(ctx, ln.Addr()); err != nil {
			_ = ln.Close()
			return nil, fmt.Errorf("ingress: %w", err)
		}
	} else if origin, err = httpsOrigin(origin); err != nil {
		_ = ln.Close()
		return nil, fmt.Errorf("ingress: the advertised origin is not one a peer can dial: %w", err)
	}

	serving, cancel := context.WithCancel(ctx)
	in := &Ingress{
		server:   identity.Server(handler),
		listener: identity.Listen(ln),
		origin:   origin,
		prefix:   prefix,
		reported: make(chan struct{}),
		cancel:   cancel,
		done:     make(chan struct{}),
	}
	go func() {
		defer close(in.done)
		if err := in.server.Serve(in.listener); !errors.Is(err, http.ErrServerClosed) {
			in.served = err
		}
	}()
	go func() {
		<-serving.Done()
		_ = in.server.Close()
	}()
	r := &reporter{client: client, url: reportURL, tokenFile: files.Token, prefix: prefix, origin: origin, backoff: o.backoff}
	go r.run(serving, in.reported)
	return in, nil
}

// Origin is the https origin this ingress reports to the host.
func (i *Ingress) Origin() string { return i.origin }

// Addr is the address the ingress listens on.
func (i *Ingress) Addr() net.Addr { return i.listener.Addr() }

// Reported is closed once the host has recorded the origin.
func (i *Ingress) Reported() <-chan struct{} { return i.reported }

// Close stops the report and the listener, and waits for serving to end.
func (i *Ingress) Close() error {
	i.closing.Do(func() {
		i.cancel()
		_ = i.server.Close()
	})
	<-i.done
	return i.served
}

// resolveReportURL is the host's report endpoint: an explicit one, or the
// origin of the credential mint URL the runtime injects. https only, with
// nothing beside a host, a port and the path: the request carries this
// workload's projected token.
func resolveReportURL(explicit string) (string, error) {
	raw := strings.TrimSpace(explicit)
	if raw == "" {
		mint, ok := codefly.RuntimeValue(CredentialMintURL)
		if !ok {
			return "", fmt.Errorf("no report destination: the runtime names the host's credential mint (%s) and the report goes to its origin, at %s", CredentialMintURL, ReportPath)
		}
		u, err := url.Parse(mint)
		if err != nil || u.Host == "" {
			return "", fmt.Errorf("the credential mint URL (%s) is not a URL with a host", CredentialMintURL)
		}
		raw = (&url.URL{Scheme: u.Scheme, Host: u.Host, Path: ReportPath}).String()
	}
	u, err := url.Parse(raw)
	switch {
	case err != nil || u.Host == "":
		return "", errors.New("the report destination is not a URL with a host")
	case u.Scheme != "https":
		return "", errors.New("the report destination is not https: the report carries this workload's projected token, which is not sent in the clear")
	case u.User != nil || u.RawQuery != "" || u.Fragment != "":
		return "", errors.New("the report destination carries userinfo, a query or a fragment: name the host and the path, and nothing else")
	case u.Path != ReportPath:
		return "", fmt.Errorf("the report destination must name the host's report endpoint %s", ReportPath)
	}
	return u.String(), nil
}

// advertisedOrigin is the https origin the composition advertises for the
// ingress endpoint. Without that carrier, a local run reports the loopback port
// it actually listens on, because the gateway beside it reaches it there; a
// deployed one has no such answer, because its listen address is a loopback no
// peer can dial.
func advertisedOrigin(ctx context.Context, listening net.Addr) (string, error) {
	instance, err := codefly.For(ctx).Endpoint(EndpointName).API(EndpointAPI).AdvertisedNetworkInstance()
	switch {
	case err == nil:
		origin, unusable := httpsOrigin(instance.Address)
		if unusable != nil {
			return "", fmt.Errorf("the advertised address of the %q endpoint is not one a peer can dial: %w", EndpointName, unusable)
		}
		return origin, nil
	case !errors.Is(err, codefly.ErrEndpointCarrierAbsent):
		return "", err
	case !codefly.IsLocal():
		return "", fmt.Errorf("%w — a deployed workload reports the address its composition advertises, and this one advertises none", err)
	}
	_, port, splitErr := net.SplitHostPort(listening.String())
	if splitErr != nil {
		return "", fmt.Errorf("the listen address %q has no port", listening)
	}
	return httpsOrigin(net.JoinHostPort("localhost", port))
}

// httpsOrigin is "https://host:port" for an address written as host:port or as
// a URL, and an error for anything that is not exactly a host and a port.
//
// Strict, because this value is handed to another component to dial. A path, a
// query, userinfo, a missing port, a port that is not one, and a host that
// names no machine (the unspecified address a listener binds) are all refused
// rather than trimmed: each is a destination that is not the one somebody
// meant. The scheme is always https: the listener is TLS-only, whatever scheme
// the carrier's value was written with.
func httpsOrigin(raw string) (string, error) {
	hostport := strings.TrimSpace(raw)
	if strings.Contains(hostport, "://") {
		u, err := url.Parse(hostport)
		if err != nil {
			return "", errors.New("it does not parse as a URL")
		}
		if u.User != nil || u.RawQuery != "" || u.Fragment != "" || strings.Trim(u.Path, "/") != "" {
			return "", errors.New("it carries more than a host and a port")
		}
		hostport = u.Host
	}
	host, port, err := net.SplitHostPort(hostport)
	if err != nil {
		return "", errors.New("it is not a host and a port")
	}
	if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
		return "", errors.New("its port is not a port")
	}
	if host == "" || strings.ContainsAny(host, "/@?# ") {
		return "", errors.New("it names no host")
	}
	if ip := net.ParseIP(host); ip != nil && ip.IsUnspecified() {
		return "", errors.New("it is the unspecified address, which names no machine")
	}
	return "https://" + net.JoinHostPort(host, port), nil
}

// backoff is the wait before each retry.
type backoff struct {
	first, ceiling, refused time.Duration
}

var defaultBackoff = backoff{first: time.Second, ceiling: 30 * time.Second, refused: 60 * time.Second}

// maxTokenBytes bounds the projected token read; a projected ServiceAccount
// token is a few KiB.
const maxTokenBytes = 64 << 10

// maxAnswerBytes bounds what is read of the host's answer: only its status
// decides anything, and the rest is logged.
const maxAnswerBytes = 4 << 10

// upstreamReport is the report endpoint's request body: the module's route
// alias and the origin it serves at. It carries no capability.
type upstreamReport struct {
	Prefix   string `json:"prefix"`
	Upstream string `json:"upstream"`
}

type reporter struct {
	client    *http.Client
	url       string
	tokenFile string
	prefix    string
	origin    string
	backoff   backoff
}

// outcome is what one attempt established.
type outcome int

const (
	recorded outcome = iota
	refused
	unavailable
)

func (r *reporter) run(ctx context.Context, reported chan<- struct{}) {
	w := wool.Get(ctx).In("ingress.report")
	wait := r.backoff.first
	for {
		result, detail := r.once(ctx)
		var next time.Duration
		switch result {
		case recorded:
			close(reported)
			return
		case refused:
			// A verdict, not an outage: the host established something about
			// this workload. It is retried slowly because the usual cause — a
			// presence not yet delivered, an envelope that does not approve
			// this build — is one an operator fixes without restarting this.
			w.Warn("the host refused this ingress's origin", wool.Field("prefix", r.prefix), wool.Field("origin", r.origin), wool.Field("answer", detail))
			next = r.backoff.refused
		default:
			w.Debug("the host could not record this ingress's origin yet", wool.Field("prefix", r.prefix), wool.Field("answer", detail))
			next = jittered(wait)
			if wait *= 2; wait > r.backoff.ceiling {
				wait = r.backoff.ceiling
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(next):
		}
	}
}

// jittered is d with up to a quarter of it taken off at random, so replicas
// restarted together do not report in lockstep.
func jittered(d time.Duration) time.Duration {
	if d <= 0 {
		return d
	}
	return d - time.Duration(rand.Int64N(int64(d)/4+1))
}

func (r *reporter) once(ctx context.Context) (outcome, string) {
	token, err := readToken(r.tokenFile)
	if err != nil {
		// The kubelet rewrites the projection under the running process; an
		// unreadable one is waited out rather than reported as a refusal.
		return unavailable, err.Error()
	}
	body, err := json.Marshal(upstreamReport{Prefix: r.prefix, Upstream: r.origin})
	if err != nil {
		return unavailable, err.Error()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, r.url, bytes.NewReader(body))
	if err != nil {
		return unavailable, err.Error()
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := r.client.Do(req)
	if err != nil {
		return unavailable, err.Error()
	}
	defer func() { _ = resp.Body.Close() }()
	answer, _ := io.ReadAll(io.LimitReader(resp.Body, maxAnswerBytes))
	detail := fmt.Sprintf("%d %s", resp.StatusCode, strings.TrimSpace(string(answer)))
	switch resp.StatusCode {
	case http.StatusNoContent:
		return recorded, detail
	case http.StatusBadRequest, http.StatusUnauthorized, http.StatusForbidden:
		return refused, detail
	}
	return unavailable, detail
}

// readToken reads the projected token fresh, bounded: the kubelet rotates it
// under the running process.
func readToken(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("read the projected token: %w", err)
	}
	defer func() { _ = file.Close() }()
	raw, err := io.ReadAll(io.LimitReader(file, maxTokenBytes+1))
	if err != nil {
		return "", fmt.Errorf("read the projected token: %w", err)
	}
	if len(raw) > maxTokenBytes {
		return "", fmt.Errorf("the projected token file is larger than %d bytes", maxTokenBytes)
	}
	token := strings.TrimSpace(string(raw))
	if token == "" {
		return "", errors.New("the projected token file is empty")
	}
	return token, nil
}
