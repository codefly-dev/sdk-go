package workcontext

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// mintHost is the host's mint endpoint, counting what it is asked for. The
// count is the acceptance criterion: a process that runs for an hour must not
// have announced itself every fifteen seconds.
type mintHost struct {
	t          *testing.T
	server     *httptest.Server
	requests   atomic.Uint64
	presented  atomic.Value // the last projected token the host was shown
	now        func() time.Time
	lifetime   time.Duration
	audience   string
	seal       Seal
	echoWrong  bool
	refuseWith int
	// mintAudience, when set, makes the host answer with a credential for an
	// audience other than the one asked for.
	mintAudience string
}

func newMintHost(t *testing.T, now func() time.Time) *mintHost {
	t.Helper()
	host := &mintHost{
		t: t, now: now, lifetime: 15 * time.Minute,
		audience: "warden.evidence", seal: workContextTestSeal(),
	}
	host.server = httptest.NewServer(http.HandlerFunc(host.handle))
	t.Cleanup(host.server.Close)
	return host
}

func (h *mintHost) handle(writer http.ResponseWriter, request *http.Request) {
	h.requests.Add(1)
	h.presented.Store(request.Header.Get("Authorization"))
	if h.refuseWith != 0 {
		writer.WriteHeader(h.refuseWith)
		return
	}
	var body mintRequest
	if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
		writer.WriteHeader(http.StatusBadRequest)
		return
	}
	input := workContextTestInput()
	input.Audience = body.Audience
	if h.mintAudience != "" {
		input.Audience = h.mintAudience
	}
	input.Seal = h.seal
	input.TTL = h.lifetime
	token, _, err := workContextTestSigner(h.t, h.now()).StartTask(input)
	require.NoError(h.t, err)
	response := mintResponse{WorkContext: token.Encoded(), InstallationID: h.seal.InstallationID}
	if h.echoWrong {
		response.InstallationID = "installation-the-host-did-not-seal"
	}
	writer.Header().Set("Content-Type", "application/json")
	require.NoError(h.t, json.NewEncoder(writer).Encode(response))
}

// projectedFile writes a rotating projected token and hands back its path.
func projectedFile(t *testing.T, contents string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "token")
	require.NoError(t, os.WriteFile(path, []byte(contents), 0o600))
	return path
}

func newTestMintClient(t *testing.T, host *mintHost, path string, now func() time.Time, options ...func(*MintOptions)) *MintClient {
	t.Helper()
	settings := MintOptions{
		URL:                host.server.URL,
		Audience:           "warden.evidence",
		ProjectedToken:     ProjectedTokenFile(path),
		ProjectionAudience: "accounts",
		Now:                now,
	}
	for _, option := range options {
		option(&settings)
	}
	client, err := NewMintClient(settings)
	require.NoError(t, err)
	return client
}

// The acceptance criterion, as arithmetic rather than as a hope. A process
// that runs for an hour holding a credential it renews only at expiry mints
// once and renews on the credential's own clock. The heartbeat it replaces
// minted once per surface every fifteen seconds — 240 times an hour, each one
// an audit event recording that nothing had changed.
func TestMintOncePerExecutionAndRenewOnlyAtExpiry(t *testing.T) {
	clock := workContextTestTime
	now := func() time.Time { return clock }
	host := newMintHost(t, now)
	client := newTestMintClient(t, host, projectedFile(t, "projected-token-1"), now)

	first, err := client.Credential(t.Context())
	require.NoError(t, err)
	require.Equal(t, workContextTestSeal(), first.Seal())
	require.EqualValues(t, 1, host.requests.Load())

	// Every call for the next twelve minutes is answered from the credential
	// already held. Nothing reaches the host.
	for minute := range 12 {
		clock = workContextTestTime.Add(time.Duration(minute) * time.Minute)
		again, err := client.Credential(t.Context())
		require.NoError(t, err)
		require.Equal(t, first.Token().Encoded(), again.Token().Encoded())
	}
	require.EqualValues(t, 1, host.requests.Load(), "holding a credential must not talk to the host")

	mints, renewals := client.Counts()
	require.EqualValues(t, 1, mints)
	require.EqualValues(t, 0, renewals)

	// An hour of a fifteen-minute credential, renewed three minutes before each
	// expiry: one mint and five renewals, six requests in total. The heartbeat
	// this replaces made 240 in the same hour, one per surface every fifteen
	// seconds, each recording that nothing had changed.
	for minute := 12; minute <= 60; minute++ {
		clock = workContextTestTime.Add(time.Duration(minute) * time.Minute)
		_, err := client.Credential(t.Context())
		require.NoError(t, err)
	}
	mints, renewals = client.Counts()
	require.EqualValues(t, 1, mints, "exactly one first mint per execution")
	require.EqualValues(t, 5, renewals)
	require.EqualValues(t, 6, host.requests.Load())
}

// The projection is rotated under the running process, so the copy read at
// boot is expired long before the process is. Re-reading it before every
// renewal is what makes the rotation a non-event; caching it would make the
// process fail at its first renewal and need a restart to recover.
func TestRenewalRereadsTheRotatedProjectedToken(t *testing.T) {
	clock := workContextTestTime
	now := func() time.Time { return clock }
	host := newMintHost(t, now)
	path := projectedFile(t, "projected-token-before-rotation")
	client := newTestMintClient(t, host, path, now)

	_, err := client.Credential(t.Context())
	require.NoError(t, err)
	require.Equal(t, "Bearer projected-token-before-rotation", host.presented.Load())

	require.NoError(t, os.WriteFile(path, []byte("projected-token-after-rotation"), 0o600))
	clock = workContextTestTime.Add(14 * time.Minute)
	_, err = client.Credential(t.Context())
	require.NoError(t, err)
	require.Equal(t, "Bearer projected-token-after-rotation", host.presented.Load(),
		"the renewal must present the rotated projection, not the one read at boot")

	mints, renewals := client.Counts()
	require.EqualValues(t, 1, mints)
	require.EqualValues(t, 1, renewals)
}

// An authority value that drifted under the running process refuses the
// renewal. This is the moment the drift would otherwise be laundered: the
// process would mint a new credential sealed to a value the host never
// approved for it, and nothing downstream could tell.
func TestRenewalRefusesWhenTheBootReadAuthorityHasDrifted(t *testing.T) {
	clock := workContextTestTime
	now := func() time.Time { return clock }
	host := newMintHost(t, now)
	drifted := errors.New("audience changed under a running process")
	pin := &stubAuthority{}
	client := newTestMintClient(t, host, projectedFile(t, "projected"), now, func(options *MintOptions) {
		options.Authority = pin
	})

	_, err := client.Credential(t.Context())
	require.NoError(t, err, "the first mint is the boot read, so there is nothing to have drifted from")
	require.EqualValues(t, 0, pin.checks.Load(), "the first mint is not a renewal")

	pin.err = drifted
	clock = workContextTestTime.Add(14 * time.Minute)
	_, err = client.Credential(t.Context())
	require.ErrorIs(t, err, ErrMintRefused)
	require.ErrorContains(t, err, "audience changed")
	require.EqualValues(t, 1, pin.checks.Load())
	require.EqualValues(t, 1, host.requests.Load(), "a drifted authority must not reach the mint endpoint")
}

type stubAuthority struct {
	checks atomic.Uint64
	err    error
}

func (s *stubAuthority) Recheck(context.Context) error {
	s.checks.Add(1)
	return s.err
}

// The host may echo the sealed values for a log. An echo that disagrees with
// the signature is a refusal: the only installation that means anything is the
// signed one, and a client that preferred the echo would hold a credential
// whose installation it had been told wrongly.
func TestMintRefusesAnEchoThatDisagreesWithTheSignature(t *testing.T) {
	now := func() time.Time { return workContextTestTime }
	host := newMintHost(t, now)
	host.echoWrong = true
	client := newTestMintClient(t, host, projectedFile(t, "projected"), now)

	_, err := client.Credential(t.Context())
	require.ErrorIs(t, err, ErrMintRefused)
	require.ErrorContains(t, err, "reported installation")
}

// A credential minted for another audience is refused rather than held. The
// far end would refuse it anyway; refusing it here makes the failure a boot
// error in the process that is wrong rather than an authorization error in the
// service it calls.
func TestMintRefusesACredentialForAnotherAudience(t *testing.T) {
	now := func() time.Time { return workContextTestTime }
	host := newMintHost(t, now)
	host.mintAudience = "warden.other"
	client := newTestMintClient(t, host, projectedFile(t, "projected"), now)

	_, err := client.Credential(t.Context())
	require.ErrorIs(t, err, ErrMintRefused)
	require.ErrorContains(t, err, "minted for audience")
}

// A refusal the host will give again is not retryable, and an outage is. A
// client that confused them would either spin against a permanent refusal or
// give up on a transient one.
func TestMintSeparatesARefusalFromAnOutage(t *testing.T) {
	now := func() time.Time { return workContextTestTime }
	for status, sentinel := range map[int]error{
		http.StatusForbidden:           ErrMintRefused,
		http.StatusUnauthorized:        ErrMintRefused,
		http.StatusTooManyRequests:     ErrMintUnavailable,
		http.StatusInternalServerError: ErrMintUnavailable,
		http.StatusBadGateway:          ErrMintUnavailable,
	} {
		t.Run(fmt.Sprintf("http %d", status), func(t *testing.T) {
			host := newMintHost(t, now)
			host.refuseWith = status
			client := newTestMintClient(t, host, projectedFile(t, "projected"), now)
			_, err := client.Credential(t.Context())
			require.ErrorIs(t, err, sentinel)
		})
	}
}

// The projection is the one thing the client presents, so an unreadable one is
// a refusal rather than an empty bearer token. Sending the request anyway would
// turn "the token is missing" into the host's "this build is not approved",
// which is the wrong thing to go looking for.
func TestProjectedTokenFileRefusesWhatIsNotAToken(t *testing.T) {
	for name, path := range map[string]ProjectedTokenFile{
		"no path":     "",
		"absent file": ProjectedTokenFile(filepath.Join(t.TempDir(), "missing")),
		"empty file":  ProjectedTokenFile(projectedFile(t, "")),
		"whitespace":  ProjectedTokenFile(projectedFile(t, "   \n\t ")),
	} {
		t.Run(name, func(t *testing.T) {
			_, err := path.ProjectedToken()
			require.ErrorIs(t, err, ErrMintRefused)
		})
	}

	token, err := ProjectedTokenFile(projectedFile(t, "  projected-with-trailing-newline\n")).ProjectedToken()
	require.NoError(t, err)
	require.Equal(t, "projected-with-trailing-newline", token)
}

// A mint request carries what the process wants and nothing about who it is.
// Principal, installation and build are the host's to establish; a field for
// any of them would be a field a process could lie in.
func TestMintRequestSelfReportsNoIdentity(t *testing.T) {
	encoded, err := json.Marshal(mintRequest{Audience: "warden.evidence", ProjectionAudience: "accounts"})
	require.NoError(t, err)
	var fields map[string]any
	require.NoError(t, json.Unmarshal(encoded, &fields))
	require.Equal(t, []string{"audience", "projection_audience"}, sortedUnique(keysOf(fields)))
}

func keysOf(fields map[string]any) []string {
	names := make([]string, 0, len(fields))
	for name := range fields {
		names = append(names, name)
	}
	return names
}

// A credential request that was answered by an address nothing configured has
// already left with the projected token attached. Retrying would send it again,
// so a redirect is a permanent refusal and the process must not serve.
func TestMintRefusesARedirectedRequest(t *testing.T) {
	now := func() time.Time { return workContextTestTime }
	elsewhere := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(elsewhere.Close)
	redirector := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		http.Redirect(writer, request, elsewhere.URL, http.StatusTemporaryRedirect)
	}))
	t.Cleanup(redirector.Close)

	client, err := NewMintClient(MintOptions{
		URL:                redirector.URL,
		Audience:           "warden.evidence",
		ProjectedToken:     ProjectedTokenFile(projectedFile(t, "projected")),
		ProjectionAudience: "accounts",
		Now:                now,
		HTTPClient:         &http.Client{},
	})
	require.NoError(t, err)
	_, err = client.Credential(t.Context())
	require.ErrorIs(t, err, ErrMintRefused)
	require.NotErrorIs(t, err, ErrMintUnavailable)
}

func TestNewMintClientValidatesItsConfiguration(t *testing.T) {
	valid := MintOptions{
		URL:                "https://accounts.internal/platform/_mint",
		Audience:           "warden.evidence",
		ProjectedToken:     ProjectedTokenFile("/var/run/secrets/token"),
		ProjectionAudience: "accounts",
	}
	_, err := NewMintClient(valid)
	require.NoError(t, err)

	for name, mutate := range map[string]func(*MintOptions){
		"no url":                 func(o *MintOptions) { o.URL = "" },
		"url with query":         func(o *MintOptions) { o.URL = "https://accounts.internal/_mint?as=root" },
		"url with credentials":   func(o *MintOptions) { o.URL = "https://user:pass@accounts.internal/_mint" },
		"no audience":            func(o *MintOptions) { o.Audience = "" },
		"no projection":          func(o *MintOptions) { o.ProjectedToken = nil },
		"no projection audience": func(o *MintOptions) { o.ProjectionAudience = "" },
		"timeout too long":       func(o *MintOptions) { o.RequestTimeout = time.Hour },
		"renewal lead at one":    func(o *MintOptions) { o.RenewalLead = 1 },
		"negative renewal lead":  func(o *MintOptions) { o.RenewalLead = -0.5 },
	} {
		t.Run(name, func(t *testing.T) {
			options := valid
			mutate(&options)
			_, err := NewMintClient(options)
			require.ErrorIs(t, err, ErrMintRefused)
		})
	}
}
