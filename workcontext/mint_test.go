package workcontext

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	corework "github.com/codefly-dev/core/workcontext"
	"github.com/stretchr/testify/require"
)

// mintHost is the host's mint endpoint, counting what it is asked for. The
// count is the acceptance criterion: a process that runs for an hour must not
// have announced itself every fifteen seconds.
//
// It is served over TLS, because that is the only way the client will talk to
// it: the projected service-account token is a bearer credential on this
// request, and MintOptions.URL refuses anything but https.
type mintHost struct {
	t         *testing.T
	server    *httptest.Server
	requests  atomic.Uint64
	presented atomic.Value // the last projected token the host was shown
	bodies    chan []byte  // every request body, as the client actually sent it
	now       func() time.Time
	lifetime  time.Duration
	audience  string
	authority *authority
	echoWrong bool
	// binding, when set, makes the host mint an operation capability sealed to
	// that binding.
	binding    string
	refuseWith int
	// mintAudience, when set, makes the host answer with a credential for an
	// audience other than the one asked for.
	mintAudience string
	// mintedAt and mintedFor override when and for how long the host mints, so
	// a test can be handed a credential that is already expired, not yet valid,
	// or shorter-lived than the renewal lead.
	mintedAt  *time.Time
	mintedFor *time.Duration
}

func newMintHost(t *testing.T, now func() time.Time) *mintHost {
	t.Helper()
	host := &mintHost{
		t: t, now: now, lifetime: 15 * time.Minute,
		audience: testAudience, authority: newAuthority(t),
		bodies: make(chan []byte, 64),
	}
	host.server = httptest.NewTLSServer(http.HandlerFunc(host.handle))
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
	raw, err := readAll(request)
	if err != nil {
		writer.WriteHeader(http.StatusBadRequest)
		return
	}
	select {
	case h.bodies <- raw:
	default:
	}
	var body mintRequest
	if err := json.Unmarshal(raw, &body); err != nil {
		writer.WriteHeader(http.StatusBadRequest)
		return
	}
	audience := body.Audience
	if h.mintAudience != "" {
		audience = h.mintAudience
	}
	mintedAt := h.now()
	if h.mintedAt != nil {
		mintedAt = *h.mintedAt
	}
	lifetime := h.lifetime
	if h.mintedFor != nil {
		lifetime = *h.mintedFor
	}
	// The host mints with core's Authority, because that is what the host does.
	// A test endpoint that assembled a token itself would be a second
	// implementation wearing a test's clothes.
	token := h.authority.startAt(h.t, mintedAt, mintInput{audience: audience, binding: h.binding}, lifetime)
	response := mintResponse{WorkContext: token, InstallationID: testInstallation}
	if h.echoWrong {
		response.InstallationID = "installation-the-host-did-not-seal"
	}
	writer.Header().Set("Content-Type", "application/json")
	require.NoError(h.t, json.NewEncoder(writer).Encode(response))
}

func readAll(request *http.Request) ([]byte, error) {
	defer func() {
		_ = request.Body.Close()
	}()
	return io.ReadAll(io.LimitReader(request.Body, maxMintResponseBytes))
}

// certPoolOf trusts exactly these test servers and nothing else, so a request
// that reaches the wrong one fails the assertion rather than the handshake.
func certPoolOf(servers ...*httptest.Server) *x509.CertPool {
	pool := x509.NewCertPool()
	for _, server := range servers {
		pool.AddCert(server.Certificate())
	}
	return pool
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
		Audience:           testAudience,
		ProjectedToken:     ProjectedTokenFile(path),
		ProjectionAudience: "accounts",
		Now:                now,
		// The test server's own client, which trusts the server's certificate
		// and nothing else. It is a SUPPLIED client, so every test here also
		// exercises the path where the caller brought its own.
		HTTPClient: host.server.Client(),
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
	clock := testClock
	now := func() time.Time { return clock }
	host := newMintHost(t, now)
	client := newTestMintClient(t, host, projectedFile(t, "projected-token-1"), now)

	first, err := client.Credential(t.Context())
	require.NoError(t, err)
	require.Equal(t, testSeal, first.Seal())
	require.EqualValues(t, 1, host.requests.Load())

	// Every call for the next twelve minutes is answered from the credential
	// already held. Nothing reaches the host.
	for minute := range 12 {
		clock = testClock.Add(time.Duration(minute) * time.Minute)
		again, err := client.Credential(t.Context())
		require.NoError(t, err)
		require.Equal(t, first.Token(), again.Token())
	}
	require.EqualValues(t, 1, host.requests.Load(), "holding a credential must not talk to the host")
	require.Equal(t, MintCounts{Mints: 1}, client.Counts())

	// An hour of a fifteen-minute credential, renewed three minutes before each
	// expiry: one mint and five renewals, six requests in total. The heartbeat
	// this replaces made 240 in the same hour, one per surface every fifteen
	// seconds, each recording that nothing had changed.
	//
	// Six endpoint requests is what this test can observe. Whether the host
	// records one mint audit event or six is the host's accounting and not
	// something an SDK test can assert — see the PR body.
	for minute := 12; minute <= 60; minute++ {
		clock = testClock.Add(time.Duration(minute) * time.Minute)
		_, err := client.Credential(t.Context())
		require.NoError(t, err)
	}
	require.Equal(t, MintCounts{Mints: 1, Renewals: 5}, client.Counts())
	require.EqualValues(t, 6, host.requests.Load())
}

// A process whose first request burst is concurrent still mints once. A client
// that minted per goroutine would be the heartbeat again under another name,
// and "one credential per execution" would hold only for a process that
// happened to make its first call from one goroutine.
func TestTheFirstMintIsOneMintUnderConcurrentFirstCalls(t *testing.T) {
	now := func() time.Time { return testClock }
	host := newMintHost(t, now)
	client := newTestMintClient(t, host, projectedFile(t, "projected"), now)

	const callers = 24
	tokens := make([]string, callers)
	var waiting sync.WaitGroup
	for caller := range callers {
		waiting.Add(1)
		go func() {
			defer waiting.Done()
			credential, err := client.Credential(t.Context())
			require.NoError(t, err)
			tokens[caller] = credential.Token()
		}()
	}
	waiting.Wait()

	require.EqualValues(t, 1, host.requests.Load(),
		"%d concurrent first calls must produce one mint", callers)
	require.Equal(t, MintCounts{Mints: 1}, client.Counts())
	for caller := range callers {
		require.Equal(t, tokens[0], tokens[caller], "every caller holds the same credential")
	}
}

// The projection is rotated under the running process, so the copy read at
// boot is expired long before the process is. Re-reading it before every
// renewal is what makes the rotation a non-event; caching it would make the
// process fail at its first renewal and need a restart to recover.
func TestRenewalRereadsTheRotatedProjectedToken(t *testing.T) {
	clock := testClock
	now := func() time.Time { return clock }
	host := newMintHost(t, now)
	path := projectedFile(t, "projected-token-before-rotation")
	client := newTestMintClient(t, host, path, now)

	_, err := client.Credential(t.Context())
	require.NoError(t, err)
	require.Equal(t, "Bearer projected-token-before-rotation", host.presented.Load())

	require.NoError(t, os.WriteFile(path, []byte("projected-token-after-rotation"), 0o600))
	clock = testClock.Add(14 * time.Minute)
	_, err = client.Credential(t.Context())
	require.NoError(t, err)
	require.Equal(t, "Bearer projected-token-after-rotation", host.presented.Load(),
		"the renewal must present the rotated projection, not the one read at boot")
	require.Equal(t, MintCounts{Mints: 1, Renewals: 1}, client.Counts())
}

// An authority value that drifted under the running process refuses the mint.
// This is the moment the drift would otherwise be laundered: the process would
// mint a credential sealed to a value the host never approved for it, and
// nothing downstream could tell.
//
// It is checked before the FIRST mint too. A process can construct its client
// at boot and make its first call an hour later, and the value can have moved
// in between; a check that began at the first renewal left exactly that window
// open.
func TestEveryMintRefusesWhenTheBootReadAuthorityHasDrifted(t *testing.T) {
	clock := testClock
	now := func() time.Time { return clock }
	host := newMintHost(t, now)
	pin := &stubAuthority{}
	client := newTestMintClient(t, host, projectedFile(t, "projected"), now, func(options *MintOptions) {
		options.Authority = pin
	})

	_, err := client.Credential(t.Context())
	require.NoError(t, err)
	require.EqualValues(t, 1, pin.checks.Load(), "the first mint checks the pin too")

	pin.err = errors.New("audience changed under a running process")
	clock = testClock.Add(14 * time.Minute)
	_, err = client.Credential(t.Context())
	require.ErrorIs(t, err, ErrMintRefused)
	require.ErrorContains(t, err, "audience changed")
	require.EqualValues(t, 2, pin.checks.Load())
	require.EqualValues(t, 1, host.requests.Load(), "a drifted authority must not reach the mint endpoint")
}

// The first mint, specifically: a client constructed at boot whose pin has
// already moved by the time anything asks for a credential must not mint.
func TestTheFirstMintRefusesAnAlreadyDriftedAuthority(t *testing.T) {
	now := func() time.Time { return testClock }
	host := newMintHost(t, now)
	pin := &stubAuthority{err: errors.New("binding changed before the first call")}
	client := newTestMintClient(t, host, projectedFile(t, "projected"), now, func(options *MintOptions) {
		options.Authority = pin
	})

	_, err := client.Credential(t.Context())
	require.ErrorIs(t, err, ErrMintRefused)
	require.ErrorContains(t, err, "binding changed")
	require.EqualValues(t, 0, host.requests.Load(),
		"the pin is checked before the projection is presented to anything")
}

type stubAuthority struct {
	checks atomic.Uint64
	err    error
}

func (s *stubAuthority) Recheck(context.Context) error {
	s.checks.Add(1)
	return s.err
}

// A credential the host has refused is replaced on demand, not when its own
// renewal lead arrives. Without this there was no way back: the client answered
// from the credential it held until a lead the HOST chooses had elapsed, so an
// installation revision that moved under a long-lived credential meant hours of
// refusals with nothing a process could do about it.
func TestARefusedCredentialIsReplacedOnDemand(t *testing.T) {
	now := func() time.Time { return testClock }
	host := newMintHost(t, now)
	client := newTestMintClient(t, host, projectedFile(t, "projected"), now)

	held, err := client.Credential(t.Context())
	require.NoError(t, err)
	require.EqualValues(t, 1, host.requests.Load())

	// Nothing about the clock has changed, so Credential would answer from the
	// credential already held — which is the one the far end refused.
	same, err := client.Credential(t.Context())
	require.NoError(t, err)
	require.Equal(t, held.Token(), same.Token())
	require.EqualValues(t, 1, host.requests.Load())

	replaced, err := client.Refresh(t.Context(), held)
	require.NoError(t, err)
	require.NotEqual(t, held.Token(), replaced.Token())
	require.EqualValues(t, 2, host.requests.Load())
	require.Equal(t, MintCounts{Mints: 1, Refreshes: 1}, client.Counts())

	// And the replacement is what every later caller gets.
	after, err := client.Credential(t.Context())
	require.NoError(t, err)
	require.Equal(t, replaced.Token(), after.Token())
}

// Concurrent refusals on ONE credential produce ONE replacement mint. A
// refresh that minted per caller would turn a single revocation into a burst of
// audit events, which is the failure this whole client replaced.
func TestConcurrentRefusalsOnOneCredentialMintOnce(t *testing.T) {
	now := func() time.Time { return testClock }
	host := newMintHost(t, now)
	client := newTestMintClient(t, host, projectedFile(t, "projected"), now)

	held, err := client.Credential(t.Context())
	require.NoError(t, err)

	const callers = 16
	replaced := make([]string, callers)
	var waiting sync.WaitGroup
	for caller := range callers {
		waiting.Add(1)
		go func() {
			defer waiting.Done()
			credential, err := client.Refresh(t.Context(), held)
			require.NoError(t, err)
			replaced[caller] = credential.Token()
		}()
	}
	waiting.Wait()

	require.EqualValues(t, 2, host.requests.Load(),
		"one first mint and one replacement for %d refusals on the same credential", callers)
	require.Equal(t, MintCounts{Mints: 1, Refreshes: 1}, client.Counts())
	for caller := range callers {
		require.Equal(t, replaced[0], replaced[caller])
		require.NotEqual(t, held.Token(), replaced[caller])
	}
}

// A refresh is tied to the credential that was refused, so a caller holding a
// stale one cannot roll the client backwards by asking about it.
func TestRefreshIsTiedToTheRefusedCredential(t *testing.T) {
	now := func() time.Time { return testClock }
	host := newMintHost(t, now)
	client := newTestMintClient(t, host, projectedFile(t, "projected"), now)

	first, err := client.Credential(t.Context())
	require.NoError(t, err)
	second, err := client.Refresh(t.Context(), first)
	require.NoError(t, err)
	require.EqualValues(t, 2, host.requests.Load())

	// Asking again about the credential that was already replaced returns the
	// replacement and mints nothing.
	again, err := client.Refresh(t.Context(), first)
	require.NoError(t, err)
	require.Equal(t, second.Token(), again.Token())
	require.EqualValues(t, 2, host.requests.Load())
	require.Equal(t, MintCounts{Mints: 1, Refreshes: 1}, client.Counts())

	// A Credential this client never issued is not something to refresh
	// against: it names no generation of this client's life.
	_, err = client.Refresh(t.Context(), Credential{})
	require.ErrorIs(t, err, ErrMintRefused)
	require.ErrorContains(t, err, "the credential that was refused")

	fresh := newTestMintClient(t, host, projectedFile(t, "projected"), now)
	_, err = fresh.Refresh(t.Context(), second)
	require.ErrorIs(t, err, ErrMintRefused)
	require.ErrorContains(t, err, "issued no credential")
}

// A refresh rechecks the pin and re-reads the projection, exactly as a renewal
// does: it is a mint, and every mint goes through the same door.
func TestRefreshRechecksThePinAndRereadsTheProjection(t *testing.T) {
	now := func() time.Time { return testClock }
	host := newMintHost(t, now)
	path := projectedFile(t, "projected-before")
	pin := &stubAuthority{}
	client := newTestMintClient(t, host, path, now, func(options *MintOptions) {
		options.Authority = pin
	})

	held, err := client.Credential(t.Context())
	require.NoError(t, err)
	require.EqualValues(t, 1, pin.checks.Load())

	require.NoError(t, os.WriteFile(path, []byte("projected-after"), 0o600))
	replaced, err := client.Refresh(t.Context(), held)
	require.NoError(t, err)
	require.EqualValues(t, 2, pin.checks.Load())
	require.Equal(t, "Bearer projected-after", host.presented.Load())

	// A drifted pin refuses the refresh, and the credential already held stays
	// held: a refused replacement must not leave the process holding nothing,
	// which would read as a boot failure somewhere it is not.
	pin.err = errors.New("audience changed under a running process")
	_, err = client.Refresh(t.Context(), replaced)
	require.ErrorIs(t, err, ErrMintRefused)
	require.ErrorContains(t, err, "audience changed")

	pin.err = nil
	still, err := client.Credential(t.Context())
	require.NoError(t, err)
	require.Equal(t, replaced.Token(), still.Token(),
		"a refused replacement leaves the credential the process already holds")
}

// The host may echo the sealed values for a log. An echo that disagrees with
// the signature is a refusal: the only installation that means anything is the
// signed one, and a client that preferred the echo would hold a credential
// whose installation it had been told wrongly.
func TestMintRefusesAnEchoThatDisagreesWithTheSignature(t *testing.T) {
	now := func() time.Time { return testClock }
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
	now := func() time.Time { return testClock }
	host := newMintHost(t, now)
	host.mintAudience = "codefly.other-audience"
	client := newTestMintClient(t, host, projectedFile(t, "projected"), now)

	_, err := client.Credential(t.Context())
	require.ErrorIs(t, err, ErrMintRefused)
	require.ErrorContains(t, err, "minted for audience")
}

// A credential is checked against its OWN window before it is installed.
//
// The renewal check only ever looked at the credential already held, so a
// response that was delayed, or minted against a clock well behind this
// process's, was installed as a success — counted as a working mint — and then
// refused by every receiver. The three cases are the three ways that happens.
func TestMintRefusesACredentialThatIsUnusableOnArrival(t *testing.T) {
	now := func() time.Time { return testClock }
	short := 4 * time.Second

	for name, arrange := range map[string]struct {
		mintedAt  time.Time
		mintedFor time.Duration
		says      string
	}{
		"already expired": {
			mintedAt: testClock.Add(-time.Hour), mintedFor: 15 * time.Minute,
			says: "expired at",
		},
		"not yet valid": {
			mintedAt: testClock.Add(time.Hour), mintedFor: 15 * time.Minute,
			says: "not valid until",
		},
		"whole lifetime inside the renewal lead": {
			mintedAt: testClock, mintedFor: short,
			says: "inside the renewal lead",
		},
	} {
		t.Run(name, func(t *testing.T) {
			host := newMintHost(t, now)
			mintedAt, mintedFor := arrange.mintedAt, arrange.mintedFor
			host.mintedAt, host.mintedFor = &mintedAt, &mintedFor
			client := newTestMintClient(t, host, projectedFile(t, "projected"), now)

			_, err := client.Credential(t.Context())
			require.ErrorIs(t, err, ErrMintRefused)
			require.ErrorContains(t, err, arrange.says)
			require.Equal(t, MintCounts{}, client.Counts(),
				"a credential that was never usable is not a mint that worked")
		})
	}

	// A response minted inside core's own clock skew is NOT refused: the
	// tolerance here is the verifier's, so a client stricter than the thing
	// that will accept the credential would refuse credentials that work.
	host := newMintHost(t, now)
	within := testClock.Add(corework.DefaultSkew / 2)
	lifetime := 15 * time.Minute
	host.mintedAt, host.mintedFor = &within, &lifetime
	client := newTestMintClient(t, host, projectedFile(t, "projected"), now)
	_, err := client.Credential(t.Context())
	require.NoError(t, err, "a credential minted inside core's skew is usable")
}

// A refusal the host will give again is not retryable, and an outage is. A
// client that confused them would either spin against a permanent refusal or
// give up on a transient one.
func TestMintSeparatesARefusalFromAnOutage(t *testing.T) {
	now := func() time.Time { return testClock }
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
//
// It reads the body the HOST received, not a struct this test marshalled. The
// earlier version marshalled mintRequest itself, which proved only that the
// struct has two fields — it would have passed while the client added a
// self-reported principal to the request on its way out.
func TestMintRequestSelfReportsNoIdentity(t *testing.T) {
	now := func() time.Time { return testClock }
	host := newMintHost(t, now)
	client := newTestMintClient(t, host, projectedFile(t, "projected"), now)

	_, err := client.Credential(t.Context())
	require.NoError(t, err)

	var sent []byte
	select {
	case sent = <-host.bodies:
	default:
		t.Fatal("the host received no request body")
	}
	var fields map[string]any
	require.NoError(t, json.Unmarshal(sent, &fields))
	require.Equal(t, []string{"audience", "projection_audience"}, keysOf(fields))
	require.Equal(t, testAudience, fields["audience"])
	require.Equal(t, "accounts", fields["projection_audience"])
}

func keysOf(fields map[string]any) []string {
	names := make([]string, 0, len(fields))
	for name := range fields {
		names = append(names, name)
	}
	slices.Sort(names)
	return slices.Compact(names)
}

// The redirect target must receive NO REQUEST AT ALL.
//
// The old test asserted the returned classification after the redirect had
// already been followed, which is the wrong thing entirely: by then the
// projected service-account token had been sent to an address nothing
// configured, and naming the outcome afterwards changes nothing. What this
// asserts is containment — zero requests at the destination — and it asserts it
// for a SUPPLIED client, which is where the hole was: Go's own client forwards
// Authorization across a redirect to the same host, so a caller that brought an
// ordinary &http.Client{} disclosed the projection before this package could
// classify anything.
func TestARedirectedMintSendsNothingToTheDestination(t *testing.T) {
	now := func() time.Time { return testClock }
	var elsewhereRequests atomic.Uint64
	elsewhere := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		elsewhereRequests.Add(1)
		writer.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(elsewhere.Close)

	redirector := httptest.NewTLSServer(http.HandlerFunc(
		func(writer http.ResponseWriter, request *http.Request) {
			http.Redirect(writer, request, elsewhere.URL, http.StatusTemporaryRedirect)
		}))
	t.Cleanup(redirector.Close)

	// One TLS configuration that trusts BOTH servers, so nothing but the
	// refusal stops the second request. A client that could not verify the
	// destination's certificate would pass this test for the wrong reason.
	trusted := &tls.Config{
		RootCAs:    certPoolOf(redirector, elsewhere),
		MinVersion: tls.VersionTLS12,
	}

	for name, supplied := range map[string]*http.Client{
		// The case that disclosed the projection: a caller-supplied client with
		// no redirect policy of its own, so net/http's default applied.
		"no redirect policy of its own": {
			Transport: &http.Transport{TLSClientConfig: trusted},
		},
		// And a caller that explicitly decided to follow redirects. For a
		// credential request that decision is not the caller's to make.
		"a policy that follows redirects": {
			Transport:     &http.Transport{TLSClientConfig: trusted},
			CheckRedirect: func(*http.Request, []*http.Request) error { return nil },
		},
	} {
		t.Run(name, func(t *testing.T) {
			elsewhereRequests.Store(0)
			client, err := NewMintClient(MintOptions{
				URL:                redirector.URL,
				Audience:           testAudience,
				ProjectedToken:     ProjectedTokenFile(projectedFile(t, "projected")),
				ProjectionAudience: "accounts",
				Now:                now,
				HTTPClient:         supplied,
			})
			require.NoError(t, err)

			_, err = client.Credential(t.Context())

			// Containment first, and on its own line: this is the assertion
			// that matters. A test that checked the returned error before the
			// request count would report the classification of a disclosure
			// that had already happened.
			require.EqualValues(t, 0, elsewhereRequests.Load(),
				"the redirect destination must receive no request: the first one carried the projection")
			require.ErrorIs(t, err, ErrMintRefused)
			require.NotErrorIs(t, err, ErrMintUnavailable,
				"a redirected credential request is not something to retry")
			require.ErrorContains(t, err, "redirected")
			require.Equal(t, MintCounts{}, client.Counts())
		})
	}

	// The client the SDK builds when the caller supplies none cannot reach a
	// test server's certificate, so its refusal is asserted on the policy
	// itself rather than over the wire.
	byDefault, err := secureMintClient(nil)
	require.NoError(t, err)
	request, err := http.NewRequest(http.MethodGet, elsewhere.URL, nil)
	require.NoError(t, err)
	require.ErrorIs(t, byDefault.CheckRedirect(request, nil), ErrMintRefused)
}

// A supplied client keeps its own redirect behaviour everywhere else. The
// refusal is installed on a copy, so a caller that shares one client between
// the mint endpoint and its ordinary traffic does not have the rest of its
// traffic silently stop following redirects.
func TestSecuringTheMintClientDoesNotMutateTheCallersClient(t *testing.T) {
	supplied := &http.Client{}
	secured, err := secureMintClient(supplied)
	require.NoError(t, err)
	require.NotNil(t, secured.CheckRedirect)
	require.Nil(t, supplied.CheckRedirect,
		"the caller's client must not be reconfigured out from under it")

	// And a client that had its own redirect policy loses it HERE and only
	// here: a credential request is not followed, whatever the caller decided
	// for its other traffic.
	followed := false
	opinionated := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		followed = true
		return nil
	}}
	secured, err = secureMintClient(opinionated)
	require.NoError(t, err)
	request, err := http.NewRequest(http.MethodGet, "https://example.invalid/_mint", nil)
	require.NoError(t, err)
	require.ErrorIs(t, secured.CheckRedirect(request, nil), ErrMintRefused)
	require.False(t, followed)
}

func TestNewMintClientValidatesItsConfiguration(t *testing.T) {
	valid := MintOptions{
		URL:                "https://accounts.internal/platform/_mint",
		Audience:           testAudience,
		ProjectedToken:     ProjectedTokenFile("/var/run/secrets/token"),
		ProjectionAudience: "accounts",
	}
	_, err := NewMintClient(valid)
	require.NoError(t, err)

	for name, mutate := range map[string]func(*MintOptions){
		"no url": func(o *MintOptions) { o.URL = "" },
		// Plaintext is the one that mattered: the projection travels on this
		// request as a bearer credential, so http was a disclosure the
		// configuration could choose.
		"plaintext http":         func(o *MintOptions) { o.URL = "http://accounts.internal/_mint" },
		"url with query":         func(o *MintOptions) { o.URL = "https://accounts.internal/_mint?as=root" },
		"url with credentials":   func(o *MintOptions) { o.URL = "https://user:pass@accounts.internal/_mint" },
		"url with fragment":      func(o *MintOptions) { o.URL = "https://accounts.internal/_mint#f" },
		"no audience":            func(o *MintOptions) { o.Audience = "" },
		"no projection":          func(o *MintOptions) { o.ProjectedToken = nil },
		"no projection audience": func(o *MintOptions) { o.ProjectionAudience = "" },
		"timeout too long":       func(o *MintOptions) { o.RequestTimeout = time.Hour },
		"renewal lead at one":    func(o *MintOptions) { o.RenewalLead = 1 },
		"negative renewal lead":  func(o *MintOptions) { o.RenewalLead = -0.5 },
		// HTTPS nobody authenticates is plaintext with extra steps, and this is
		// the one request that carries the projection.
		"transport that skips certificate verification": func(o *MintOptions) {
			o.HTTPClient = &http.Client{Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // the point of the test
			}}
		},
		"transport permitting TLS below 1.2": func(o *MintOptions) {
			o.HTTPClient = &http.Client{Transport: &http.Transport{
				TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS10},
			}}
		},
	} {
		t.Run(name, func(t *testing.T) {
			options := valid
			mutate(&options)
			_, err := NewMintClient(options)
			require.ErrorIs(t, err, ErrMintRefused)
		})
	}
}

// The credential a process holds, and what it puts on a call. The sealed
// values come off the signature rather than the response body, so what a
// caller reads here is what a verifier will compare against.
func TestCredentialSurfaceComesFromTheSignedCapability(t *testing.T) {
	now := func() time.Time { return testClock }
	host := newMintHost(t, now)
	host.binding = testBinding
	client := newTestMintClient(t, host, projectedFile(t, "projected"), now)

	credential, err := client.Credential(t.Context())
	require.NoError(t, err)
	require.Equal(t, testSeal, credential.Seal())

	// The binding AS SEALED: the three fields the capability carries. The live
	// binding has three more — the principal it is granted to, the installation
	// it is granted within, and whether it is revoked — and none of them is on
	// the wire, which is why this is a different type from OperationBinding.
	bound := credential.OperationBinding()
	require.NotNil(t, bound)
	require.Equal(t, testBinding, bound.GetBindingId())
	require.EqualValues(t, 2, bound.GetRevision())
	require.EqualValues(t, 1, bound.GetIncarnation())
	require.Equal(t, testClock, credential.IssuedAt())
	require.Equal(t, testClock.Add(15*time.Minute), credential.ExpiresAt())

	// OperationBinding hands back a copy: a caller that mutated it must not be
	// able to change what the credential reports it is bound to.
	bound.BindingId = "binding-the-caller-preferred"
	require.Equal(t, testBinding, credential.OperationBinding().GetBindingId())

	request := httptest.NewRequest(http.MethodPost, "/records", nil)
	require.NoError(t, credential.Attach(request))
	require.Equal(t, credential.Token(), request.Header.Get(HeaderName))
	require.Equal(t, testInstallation, request.Header.Get(InstallationIDHeaderName))
}
