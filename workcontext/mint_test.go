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
	// pin is the process's boot-read authority, which answers the audience.
	pin *testPin
	// before runs at the top of every request, so a test can hold one open.
	before func()
}

func newMintHost(t *testing.T, now func() time.Time) *mintHost {
	t.Helper()
	host := &mintHost{
		t: t, now: now, lifetime: 15 * time.Minute,
		audience: testAudience, authority: newAuthority(t),
		bodies: make(chan []byte, 64), pin: newTestPin(),
	}
	host.server = httptest.NewTLSServer(http.HandlerFunc(host.handle))
	t.Cleanup(host.server.Close)
	return host
}

func (h *mintHost) handle(writer http.ResponseWriter, request *http.Request) {
	h.requests.Add(1)
	if h.before != nil {
		h.before()
	}
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
		Authority:          host.pin,
		Audience:           testAudienceName,
		ProjectedToken:     ProjectedTokenFile(path),
		ProjectionAudience: "projection-audience",
		Now:                now,
		// The only thing a caller may say about the transport: which roots may
		// sign the endpoint's certificate. The client builds the rest.
		RootCAs: certPoolOf(host.server),
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
	// The seal as the capability CARRIES it — core's wire message, which also
	// carries the owner's epoch that core's live Seal type no longer has.
	require.Equal(t, testInstallation, first.Seal().GetInstallationId())
	require.EqualValues(t, 3, first.Seal().GetInstallationRevision())
	require.EqualValues(t, 11, first.Seal().GetBuildIncarnation())
	require.EqualValues(t, testPrincipalEpoch, first.Seal().GetPrincipalEpoch())
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
	client := newTestMintClient(t, host, projectedFile(t, "projected"), now)

	_, err := client.Credential(t.Context())
	require.NoError(t, err)
	require.EqualValues(t, 1, host.pin.checks.Load(), "the first mint checks the pin too")

	// A drift is a REFUSAL, and the test's name always said so while its
	// assertion said the opposite. The previous revision returned the held
	// credential with a nil error here, because "serve the held credential
	// rather than manufacture an outage" had been applied to every error
	// instead of only to outages — and this assertion was changed to match,
	// which is the worst shape a test failure can take.
	//
	// ErrMintRefused means the host will say the same thing again and a
	// process that sees it must not serve. A credential still having a minute
	// left does not change that: the value it is sealed to has moved.
	host.pin.set(testAudience, errors.New("audience changed under a running process"))
	clock = testClock.Add(14 * time.Minute)
	_, err = client.Credential(t.Context())
	require.ErrorIs(t, err, ErrMintRefused)
	require.ErrorContains(t, err, "audience changed")
	require.EqualValues(t, 2, host.pin.checks.Load())
	require.EqualValues(t, 1, host.requests.Load(), "a drifted authority must not reach the mint endpoint")

	// And it is TERMINAL. A later call does not outlive it, and the pin being
	// put back does not resurrect the client: the process already minted
	// against a value that has since moved, and only a restart re-establishes
	// what it runs under.
	require.ErrorIs(t, client.Refused(), ErrMintRefused)
	host.pin.set(testAudience, nil)
	_, err = client.Credential(t.Context())
	require.ErrorIs(t, err, ErrMintRefused)
	require.EqualValues(t, 1, host.requests.Load())
	require.EqualValues(t, 2, host.pin.checks.Load(), "a refused client stops asking")
}

// The first mint, specifically: a client constructed at boot whose pin has
// already moved by the time anything asks for a credential must not mint.
func TestTheFirstMintRefusesAnAlreadyDriftedAuthority(t *testing.T) {
	now := func() time.Time { return testClock }
	host := newMintHost(t, now)
	host.pin.set(testAudience, errors.New("binding changed before the first call"))
	client := newTestMintClient(t, host, projectedFile(t, "projected"), now)

	_, err := client.Credential(t.Context())
	require.ErrorIs(t, err, ErrMintRefused)
	require.ErrorContains(t, err, "binding changed")
	require.EqualValues(t, 0, host.requests.Load(),
		"the pin is checked before the projection is presented to anything")
}

// testPin stands in for the process's boot-read authority: it answers the
// pinned audience and counts the rechecks. The root SDK's *codefly.Authority
// has the same two methods.
type testPin struct {
	mu       sync.Mutex
	checks   atomic.Uint64
	reads    atomic.Uint64
	audience string
	err      error
	valueErr error
}

func newTestPin() *testPin { return &testPin{audience: testAudience} }

func (p *testPin) Recheck(context.Context) error {
	p.checks.Add(1)
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.err
}

func (p *testPin) Value(name string, key string) (string, error) {
	p.reads.Add(1)
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.valueErr != nil {
		return "", p.valueErr
	}
	if name != testAudienceName.Name || key != testAudienceName.Key {
		return "", errors.New("authority-bearing value was not read at boot: " + name + "/" + key)
	}
	return p.audience, nil
}

func (p *testPin) set(audience string, recheck error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.audience = audience
	p.err = recheck
}

var testAudienceName = AuthorityValue{Name: "platform", Key: "work-context-audience"}

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
	clock := testClock
	now := func() time.Time { return clock }
	host := newMintHost(t, now)
	path := projectedFile(t, "projected-before")
	client := newTestMintClient(t, host, path, now)

	held, err := client.Credential(t.Context())
	require.NoError(t, err)
	require.EqualValues(t, 1, host.pin.checks.Load())
	require.EqualValues(t, 1, host.pin.reads.Load(), "the audience is READ from the pin, not passed in")

	require.NoError(t, os.WriteFile(path, []byte("projected-after"), 0o600))
	replaced, err := client.Refresh(t.Context(), held)
	require.NoError(t, err)
	require.NotEqual(t, held.Token(), replaced.Token())
	require.EqualValues(t, 2, host.pin.checks.Load())
	require.EqualValues(t, 2, host.pin.reads.Load())
	require.Equal(t, "Bearer projected-after", host.presented.Load())

	// A drifted pin REFUSES the refresh, and the refusal is what the caller
	// gets. Handing the credential back would be worse than useless here: the
	// caller asked for a replacement because the far end refused this one, so
	// returning it reports a replacement that did not happen.
	// A refresh inside the rate limit is an outage to the caller, so move past
	// it before asserting what a DRIFT does.
	clock = testClock.Add(5 * time.Minute)
	host.pin.set(testAudience, errors.New("audience changed under a running process"))
	_, err = client.Refresh(t.Context(), replaced)
	require.ErrorIs(t, err, ErrMintRefused)
	require.ErrorContains(t, err, "audience changed")
	require.ErrorIs(t, client.Refused(), ErrMintRefused)
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

// A credential is checked against its OWN window before it is installed, and
// the sentinel says whether the next attempt could do better.
//
// The renewal check only ever looked at the credential already held, so a
// response that was delayed, or minted against a clock well behind this
// process's, was installed as a success — counted as a working mint — and then
// refused by every receiver.
//
// The window tested is **not_before**, which is the claim core's verifier
// tests. Testing issued_at was testing a different window from the one the
// credential would be judged against.
//
// And the sentinels matter rather than being decoration. ErrMintRefused means
// "the host will say the same thing again, do not serve"; a merely DELAYED
// response is not that, so an already-expired credential and a lifetime that is
// all lead are ErrMintUnavailable. A clock far enough apart to make a
// credential not-yet-valid, and a credential longer than this process will
// hold, are configuration and will not fix themselves.
func TestMintRefusesACredentialThatIsUnusableOnArrival(t *testing.T) {
	now := func() time.Time { return testClock }

	for name, arrange := range map[string]struct {
		mintedAt  time.Time
		mintedFor time.Duration
		sentinel  error
		says      string
	}{
		"already expired, which is what a delayed response looks like": {
			mintedAt: testClock.Add(-time.Hour), mintedFor: 15 * time.Minute,
			sentinel: ErrMintUnavailable, says: "expired at",
		},
		"not yet valid, which is a clock that will not fix itself": {
			mintedAt: testClock.Add(time.Hour), mintedFor: 15 * time.Minute,
			sentinel: ErrMintRefused, says: "not valid until",
		},
		"whole remaining lifetime inside the renewal lead": {
			mintedAt: testClock, mintedFor: 4 * time.Second,
			sentinel: ErrMintUnavailable, says: "inside the renewal lead",
		},
	} {
		t.Run(name, func(t *testing.T) {
			host := newMintHost(t, now)
			mintedAt, mintedFor := arrange.mintedAt, arrange.mintedFor
			host.mintedAt, host.mintedFor = &mintedAt, &mintedFor
			client := newTestMintClient(t, host, projectedFile(t, "projected"), now)

			_, err := client.Credential(t.Context())
			require.ErrorIs(t, err, arrange.sentinel)
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

	// There is no client-side lifetime ceiling any more, and that is core's
	// cap arriving rather than a check being dropped. A review asked for one
	// because core checked only that a TTL was positive; this carried one,
	// labelled a stopgap with its own condition — it goes when core has a cap.
	// Core has one now (Authority.MaxTTL, DefaultMaxTTL of an hour), so a
	// credential longer than the host permits is refused where it is MINTED,
	// which is the side of the wire that binds every client rather than the
	// ones that opted in.
	//
	// What this test asserts about it is therefore core's constant, not a
	// number of ours: a host cannot configure its way past it without a
	// reviewer seeing the configuration.
	// The ceiling is BACK, as defence in depth, and this asserts what THIS
	// client does rather than what core's constant says: a host that raises
	// its own MaxTTL past what this process will hold is refused here.
	//
	// Core's cap is the primary one and this is the second layer. Deleting
	// this layer on the strength of core having a cap was a weakening, because
	// MaxTTL is configurable with no ceiling of its own and nothing bounds a
	// lifetime at use.
	host = newMintHost(t, now)
	host.authority.core.MaxTTL = 30 * 24 * time.Hour // a host that raised it
	month := 30 * 24 * time.Hour
	host.mintedAt, host.mintedFor = &monthStart, &month
	client = newTestMintClient(t, host, projectedFile(t, "projected"), now)
	_, err = client.Credential(t.Context())
	require.ErrorIs(t, err, ErrMintRefused)
	require.ErrorContains(t, err, "holds one for at most")

	// And it is configurable, because what a process should hold is the
	// deployment's call — the point is that there IS one.
	host = newMintHost(t, now)
	host.authority.core.MaxTTL = 30 * 24 * time.Hour
	week := 7 * 24 * time.Hour
	host.mintedAt, host.mintedFor = &monthStart, &week
	client = newTestMintClient(t, host, projectedFile(t, "projected"), now,
		func(options *MintOptions) { options.MaxCredentialLifetime = 14 * 24 * time.Hour })
	credential, err := client.Credential(t.Context())
	require.NoError(t, err)
	require.Equal(t, testClock.Add(week), credential.ExpiresAt())
}

// monthStart is an addressable testClock, for the host overrides above.
var monthStart = testClock

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
	require.Equal(t, "projection-audience", fields["projection_audience"])
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
// Two things changed here. The old test asserted the returned classification
// after the redirect had already been followed, which is the wrong thing
// entirely: by then the projected token had been sent to an address nothing
// configured. And the hole the first fix closed by copying a supplied client is
// now closed by not accepting one — a caller cannot supply an http.Client at
// all, because inspecting one could not close a nil Transport (the global,
// mutable http.DefaultTransport), a wrapping RoundTripper, a DialTLSContext
// that bypasses TLSClientConfig, or a caller mutating the shared *Transport
// after construction.
//
// So the client under test here is the one the SDK builds, which is the only
// one there is, and what is asserted is containment: zero requests at the
// destination, asserted before the error is even looked at.
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

	// The root pool trusts BOTH servers, so nothing but the refusal stops the
	// second request: a client that could not verify the destination's
	// certificate would pass this test for the wrong reason.
	client, err := NewMintClient(MintOptions{
		URL:                redirector.URL,
		Authority:          newTestPin(),
		Audience:           testAudienceName,
		ProjectedToken:     ProjectedTokenFile(projectedFile(t, "projected")),
		ProjectionAudience: "projection-audience",
		Now:                now,
		RootCAs:            certPoolOf(redirector, elsewhere),
	})
	require.NoError(t, err)

	_, err = client.Credential(t.Context())

	require.EqualValues(t, 0, elsewhereRequests.Load(),
		"the redirect destination must receive no request: the first one carried the projection")
	require.ErrorIs(t, err, ErrMintRefused)
	require.NotErrorIs(t, err, ErrMintUnavailable,
		"a redirected credential request is not something to retry")
	require.ErrorContains(t, err, "redirected")
	require.Equal(t, MintCounts{}, client.Counts())
}

// The transport is the SDK's, and a caller cannot reach it.
//
// This is the finding in its sharpest form: the previous version inspected a
// supplied *http.Client and refused the one configuration it could see
// (InsecureSkipVerify on an *http.Transport). Four configurations it could not
// see each sent the projected bearer over an unauthenticated channel. None of
// them is reachable now, because there is no option to supply.
func TestTheMintTransportIsOwnedByTheClient(t *testing.T) {
	client := mintHTTPClient(nil)

	transport, ok := client.Transport.(*http.Transport)
	require.True(t, ok, "the client builds a concrete *http.Transport, not a wrapper it cannot reason about")
	require.NotNil(t, transport.TLSClientConfig, "a nil TLS config would mean the package defaults")
	require.False(t, transport.TLSClientConfig.InsecureSkipVerify)
	require.EqualValues(t, tls.VersionTLS12, transport.TLSClientConfig.MinVersion)
	require.Nil(t, transport.DialTLSContext,
		"a custom TLS dialer bypasses TLSClientConfig entirely")
	require.Nil(t, transport.DialContext)
	require.Nil(t, transport.Proxy,
		"a proxy for a credential request is an address the configuration did not name")
	require.NotNil(t, client.CheckRedirect)

	// It is not http.DefaultTransport, which is global and mutable: anything
	// in the process could have reconfigured that one.
	require.NotSame(t, http.DefaultTransport, client.Transport)

	// Two clients do not share a transport, so nothing one caller does to its
	// client can reach another's.
	require.NotSame(t, client.Transport, mintHTTPClient(nil).Transport)

	// The root pool is the ONLY thing a caller says about it, and it lands
	// where it is used.
	pool := x509.NewCertPool()
	withRoots := mintHTTPClient(pool)
	rooted, ok := withRoots.Transport.(*http.Transport)
	require.True(t, ok)
	require.Same(t, pool, rooted.TLSClientConfig.RootCAs)

	// And the redirect refusal is on it, as a refusal rather than as
	// http.ErrUseLastResponse, so net/http never sends the second request.
	request, err := http.NewRequest(http.MethodGet, "https://example.invalid/_mint", nil)
	require.NoError(t, err)
	require.ErrorIs(t, client.CheckRedirect(request, nil), ErrMintRefused)
}

func TestNewMintClientValidatesItsConfiguration(t *testing.T) {
	valid := MintOptions{
		URL:                "https://mint.example/platform/_mint",
		Authority:          newTestPin(),
		Audience:           testAudienceName,
		ProjectedToken:     ProjectedTokenFile("/var/run/secrets/token"),
		ProjectionAudience: "projection-audience",
	}
	_, err := NewMintClient(valid)
	require.NoError(t, err)

	for name, mutate := range map[string]func(*MintOptions){
		"no url": func(o *MintOptions) { o.URL = "" },
		// Plaintext is the one that mattered: the projection travels on this
		// request as a bearer credential, so http was a disclosure the
		// configuration could choose.
		"plaintext http":       func(o *MintOptions) { o.URL = "http://mint.example/_mint" },
		"url with query":       func(o *MintOptions) { o.URL = "https://mint.example/_mint?as=root" },
		"url with credentials": func(o *MintOptions) { o.URL = "https://user:pass@mint.example/_mint" },
		"url with fragment":    func(o *MintOptions) { o.URL = "https://mint.example/_mint#f" },
		// The audience is read from the pin, so there must BE a pin and it must
		// be named. A free-string audience beside an optional pin made the
		// drift check guard a value the mint did not use.
		"no authority pin":       func(o *MintOptions) { o.Authority = nil },
		"no audience name":       func(o *MintOptions) { o.Audience = AuthorityValue{} },
		"audience name only":     func(o *MintOptions) { o.Audience = AuthorityValue{Name: "platform"} },
		"audience key only":      func(o *MintOptions) { o.Audience = AuthorityValue{Key: "audience"} },
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
	require.Equal(t, testInstallation, credential.Seal().GetInstallationId())
	require.EqualValues(t, 3, credential.Seal().GetInstallationRevision())

	// Seal hands back a CLONE of the wire message. A caller that mutated it
	// must not be able to change what the credential reports it is bound to —
	// and the type is the carried seal rather than core's live Seal, which a
	// client cannot answer for.
	mutated := credential.Seal()
	mutated.InstallationId = "installation-the-caller-preferred"
	require.Equal(t, testInstallation, credential.Seal().GetInstallationId())

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

// A renewal that fails does not take a working credential away.
//
// This is the finding in its sharpest form: entering the renewal lead and
// getting a 503 used to return an error to every caller while the credential in
// hand had minutes of validity left. The client manufactured an outage out of a
// credential that still worked, and then — because each caller retried under
// the lock with no hold-off — made one mint request per caller at exactly the
// moment the host was least able to serve them.
func TestAFailedRenewalServesTheHeldCredentialUntilItExpires(t *testing.T) {
	clock := testClock
	now := func() time.Time { return clock }
	host := newMintHost(t, now)
	client := newTestMintClient(t, host, projectedFile(t, "projected"), now)

	held, err := client.Credential(t.Context())
	require.NoError(t, err)
	require.EqualValues(t, 1, host.requests.Load())

	// Inside the renewal lead, with the host refusing.
	host.refuseWith = http.StatusServiceUnavailable
	clock = testClock.Add(13 * time.Minute)
	served, err := client.Credential(t.Context())
	require.NoError(t, err, "a credential with two minutes left is still a credential")
	require.Equal(t, held.Token(), served.Token())
	require.EqualValues(t, 2, host.requests.Load(), "it tried once")

	// Ten more callers inside the hold-off make NO further requests. Without
	// the hold-off this was one request per caller.
	for range 10 {
		again, err := client.Credential(t.Context())
		require.NoError(t, err)
		require.Equal(t, held.Token(), again.Token())
	}
	require.EqualValues(t, 2, host.requests.Load(),
		"a failed mint holds off the next attempt; a request per caller is the heartbeat again")

	// Past the hold-off it tries again — still refused, still serving.
	clock = testClock.Add(13*time.Minute + 2*minMintBackoff)
	_, err = client.Credential(t.Context())
	require.NoError(t, err)
	require.EqualValues(t, 3, host.requests.Load())

	// Once the held credential has actually expired there is nothing to serve,
	// and the outage is the caller's problem to know about.
	clock = testClock.Add(20 * time.Minute)
	_, err = client.Credential(t.Context())
	require.ErrorIs(t, err, ErrMintUnavailable)
	require.Equal(t, MintCounts{Mints: 1}, client.Counts(),
		"a failed renewal is not a renewal")

	// And when the host comes back, the renewal happens.
	host.refuseWith = 0
	clock = testClock.Add(20*time.Minute + time.Minute)
	fresh, err := client.Credential(t.Context())
	require.NoError(t, err)
	require.NotEqual(t, held.Token(), fresh.Token())
	require.Equal(t, MintCounts{Mints: 1, Renewals: 1}, client.Counts())
}

// The hold-off grows, so a long outage is not a steady stream of requests.
func TestTheMintHoldOffGrowsWithConsecutiveFailures(t *testing.T) {
	require.Equal(t, minMintBackoff, mintBackoff(1))
	require.Equal(t, 2*minMintBackoff, mintBackoff(2))
	require.Equal(t, 4*minMintBackoff, mintBackoff(3))
	require.Equal(t, maxMintBackoff, mintBackoff(30),
		"and it is bounded: a hold-off nobody ever leaves is an outage of our own")
	require.LessOrEqual(t, mintBackoff(100), maxMintBackoff)
}

// A caller whose context is cancelled while another goroutine is minting stops
// waiting. The mint used to happen under the client's mutex, which made every
// waiting caller's ctx meaningless: a cancelled request still blocked until the
// request it was not making had finished.
//
// The host holds its answer for a bounded moment rather than indefinitely, and
// releases on cleanup, so a failing assertion cannot wedge the server.
func TestAWaitingCallerHonoursItsContext(t *testing.T) {
	now := func() time.Time { return testClock }
	host := newMintHost(t, now)
	release := make(chan struct{})
	var releaseOnce sync.Once
	letGo := func() { releaseOnce.Do(func() { close(release) }) }
	t.Cleanup(letGo)
	host.before = func() {
		select {
		case <-release:
		case <-time.After(2 * time.Second):
		}
	}
	client := newTestMintClient(t, host, projectedFile(t, "projected"), now)

	minted := make(chan error, 1)
	go func() {
		_, err := client.Credential(context.Background())
		minted <- err
	}()

	// Wait until the host has the request in hand, so the call below is
	// certainly a waiter rather than the minter.
	require.Eventually(t, func() bool { return host.requests.Load() == 1 },
		2*time.Second, time.Millisecond)

	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := client.Credential(cancelled)
	require.ErrorIs(t, err, ErrMintUnavailable)
	require.ErrorIs(t, err, context.Canceled)
	require.EqualValues(t, 1, host.requests.Load(),
		"a waiting caller does not queue a second request")

	letGo()
	require.NoError(t, <-minted)
	require.Equal(t, MintCounts{Mints: 1}, client.Counts())
}

// A waiting caller that holds a usable credential gets it rather than an error,
// even when its own context is cancelled: the credential in hand is valid, and
// the caller asked for a credential rather than for a mint.
func TestACancelledWaiterStillGetsAUsableHeldCredential(t *testing.T) {
	clock := testClock
	now := func() time.Time { return clock }
	host := newMintHost(t, now)
	client := newTestMintClient(t, host, projectedFile(t, "projected"), now)

	held, err := client.Credential(t.Context())
	require.NoError(t, err)

	release := make(chan struct{})
	var releaseOnce sync.Once
	letGo := func() { releaseOnce.Do(func() { close(release) }) }
	t.Cleanup(letGo)
	host.before = func() {
		select {
		case <-release:
		case <-time.After(2 * time.Second):
		}
	}
	clock = testClock.Add(13 * time.Minute)

	renewing := make(chan struct{})
	go func() {
		defer close(renewing)
		_, _ = client.Credential(context.Background())
	}()
	require.Eventually(t, func() bool { return host.requests.Load() == 2 },
		2*time.Second, time.Millisecond)

	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	served, err := client.Credential(cancelled)
	require.NoError(t, err, "a valid credential in hand beats a cancelled wait")
	require.Equal(t, held.Token(), served.Token())

	letGo()
	<-renewing
}

// A receiver whose live state lags refuses every FRESH credential, so each
// refusal is a new generation and the failure hold-off never engages. The bound
// has to be a bound on successful refreshes.
//
// The previous version of this test used a 503 host, so no new generation ever
// appeared and it modelled an outage rather than the lagging receiver it
// claimed — and it asserted that handing the refused credential back was a
// success, which is the C2 defect written down as expected behaviour.
func TestASuccessfulRefreshIsRateLimitedSoALaggingReceiverCannotMintForever(t *testing.T) {
	clock := testClock
	now := func() time.Time { return clock }
	host := newMintHost(t, now)
	client := newTestMintClient(t, host, projectedFile(t, "projected"), now)

	held, err := client.Credential(t.Context())
	require.NoError(t, err)
	require.EqualValues(t, 1, host.requests.Load())

	// The host mints happily; it is the RECEIVER that is behind, so every
	// credential this caller presents comes back ErrRevoked and every refusal
	// is on a credential one generation newer than the last.
	current := held
	served := 0
	refused := 0
	for range 20 {
		next, err := client.Refresh(t.Context(), current)
		switch {
		case err == nil:
			require.NotEqual(t, current.Token(), next.Token(),
				"a successful refresh must never hand back the credential that was refused")
			current = next
			served++
		default:
			require.ErrorIs(t, err, ErrMintUnavailable,
				"a rate-limited refresh is an outage to the caller, not a refusal")
			require.ErrorContains(t, err, "held off")
			refused++
		}
	}

	require.Positive(t, served, "the first refusal must get a replacement")
	require.Positive(t, refused, "and the twentieth must not")
	require.LessOrEqual(t, int(host.requests.Load()), 4,
		"twenty refusals on twenty successive generations must not be twenty mints")
	counts := client.Counts()
	require.EqualValues(t, 1, counts.Mints)
	require.LessOrEqual(t, int(counts.Refreshes), 3)

	// The rate limit is a limit and not a wall: once it elapses, a refresh
	// works again.
	clock = testClock.Add(5 * time.Minute)
	recovered, err := client.Refresh(t.Context(), current)
	require.NoError(t, err)
	require.NotEqual(t, current.Token(), recovered.Token())
}

// A refusal from the host is never dressed up as a replacement.
//
// This is the sequence the review set out, and it is the likely one: the
// installation is revoked, so the receiver answers ErrRevoked, so the caller
// refreshes — and the host refuses the mint for the same reason. The previous
// revision returned the refused credential with a nil error, for its whole
// remaining lifetime, so a caller could not tell "replaced" from "here is the
// revoked one again".
func TestARefusedRefreshNeverReturnsTheRefusedCredential(t *testing.T) {
	now := func() time.Time { return testClock }
	host := newMintHost(t, now)
	client := newTestMintClient(t, host, projectedFile(t, "projected"), now)

	held, err := client.Credential(t.Context())
	require.NoError(t, err)

	// The installation is revoked, so the host refuses the mint too.
	host.refuseWith = http.StatusForbidden
	replacement, err := client.Refresh(t.Context(), held)
	require.ErrorIs(t, err, ErrMintRefused)
	require.Empty(t, replacement.Token(),
		"a refused refresh returns no credential at all, least of all the refused one")

	// Terminal, so a caller looping cannot be handed the revoked credential on
	// the next pass either — and Credential does not hand it out.
	require.ErrorIs(t, client.Refused(), ErrMintRefused)
	_, err = client.Credential(t.Context())
	require.ErrorIs(t, err, ErrMintRefused)
	again, err := client.Refresh(t.Context(), held)
	require.ErrorIs(t, err, ErrMintRefused)
	require.Empty(t, again.Token())
}

// A cancelled caller must not become everybody else's outage.
//
// The shared mint runs on the LEADER's context. If the leader's caller gives
// up, that used to count as a failure: failures++ and a hold-off, so every
// waiter then hit "held off" — and at boot, with no credential held, one
// cancelled first request was an outage for every other caller, growing toward
// a minute with each repetition. A caller giving up is not the host failing.
func TestACancelledLeaderDoesNotHoldOffEveryoneElse(t *testing.T) {
	now := func() time.Time { return testClock }
	host := newMintHost(t, now)
	release := make(chan struct{})
	var releaseOnce sync.Once
	letGo := func() { releaseOnce.Do(func() { close(release) }) }
	t.Cleanup(letGo)
	host.before = func() {
		select {
		case <-release:
		case <-time.After(2 * time.Second):
		}
	}
	client := newTestMintClient(t, host, projectedFile(t, "projected"), now)

	// The leader cancels while the host is still holding its request. There is
	// no credential, so nothing can be served.
	leader, cancel := context.WithCancel(context.Background())
	leaderDone := make(chan error, 1)
	go func() {
		_, err := client.Credential(leader)
		leaderDone <- err
	}()
	require.Eventually(t, func() bool { return host.requests.Load() == 1 },
		2*time.Second, time.Millisecond)
	cancel()
	require.ErrorIs(t, <-leaderDone, ErrMintUnavailable)
	letGo()

	// A caller arriving now must be able to mint. Under the old behaviour it
	// was held off for a second, and for longer each time a caller cancelled.
	credential, err := client.Credential(t.Context())
	require.NoError(t, err, "a cancelled leader must not hold off the next caller")
	require.NotEmpty(t, credential.Token())
	require.Equal(t, MintCounts{Mints: 1}, client.Counts(),
		"and the cancellation is not counted as a mint that happened")
}

// An outage is still servable, and a refusal is still not: the two branches
// that the previous revision collapsed into one, asserted apart.
func TestOnlyAnOutageServesTheHeldCredential(t *testing.T) {
	for name, arrange := range map[string]struct {
		status   int
		sentinel error
		serves   bool
	}{
		"503 is an outage": {http.StatusServiceUnavailable, ErrMintUnavailable, true},
		"429 is an outage": {http.StatusTooManyRequests, ErrMintUnavailable, true},
		"403 is a refusal": {http.StatusForbidden, ErrMintRefused, false},
		"401 is a refusal": {http.StatusUnauthorized, ErrMintRefused, false},
		"400 is a refusal": {http.StatusBadRequest, ErrMintRefused, false},
		"404 is a refusal": {http.StatusNotFound, ErrMintRefused, false},
	} {
		t.Run(name, func(t *testing.T) {
			clock := testClock
			now := func() time.Time { return clock }
			host := newMintHost(t, now)
			client := newTestMintClient(t, host, projectedFile(t, "projected"), now)

			held, err := client.Credential(t.Context())
			require.NoError(t, err)

			host.refuseWith = arrange.status
			clock = testClock.Add(13 * time.Minute) // inside the renewal lead
			served, err := client.Credential(t.Context())

			if arrange.serves {
				require.NoError(t, err,
					"a credential with two minutes left survives the host being unreachable")
				require.Equal(t, held.Token(), served.Token())
				require.NoError(t, client.Refused())
				return
			}
			require.ErrorIs(t, err, arrange.sentinel)
			require.Empty(t, served.Token(),
				"a refusal returns no credential: this process must not serve")
			require.ErrorIs(t, client.Refused(), ErrMintRefused,
				"and the refusal is terminal")
		})
	}
}
