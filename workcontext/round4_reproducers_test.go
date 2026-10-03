package workcontext

import (
	"context"
	"crypto/x509"
	"net/http"
	"net/url"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	corework "github.com/codefly-dev/core/workcontext"
	"github.com/stretchr/testify/require"
)

// Round four's section (D): four tests that proved less than their names, and
// the two new defects the review found by reading them.

// movableClock is a clock a test can advance while a goroutine is blocked, and
// which COUNTS its reads — so a test can tell that a waiter has taken its
// snapshot without sleeping and hoping.
type movableClock struct {
	mu    sync.RWMutex
	at    time.Time
	reads atomic.Uint64
}

func (c *movableClock) now() time.Time {
	c.mu.RLock()
	defer c.mu.RUnlock()
	c.reads.Add(1)
	return c.at
}

func (c *movableClock) set(at time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.at = at
}

// A waiter that ENTERS while the credential is still valid and gives up after
// it has expired must not be handed it.
//
// The previous version of this test moved the clock past expiry BEFORE the
// waiter entered, so the snapshot taken on entry was already of an expired
// credential and the pre-fix code passed it too. The timeline that matters is
// the one the dynamic review reproduced: enter at expiry-1s, where the held
// credential IS servable, and cancel at expiry+1s. Only re-evaluating under
// the lock after the wait answers that correctly.
func TestACancelledWaiterIsNeverHandedACredentialThatExpiredWhileItWaited(t *testing.T) {
	clock := &movableClock{at: testClock}
	host := newMintHost(t, clock.now)
	release := make(chan struct{})
	var releaseOnce sync.Once
	letGo := func() { releaseOnce.Do(func() { close(release) }) }
	t.Cleanup(letGo)
	client := newTestMintClient(t, host, projectedFile(t, "projected"), clock.now)

	held, err := client.Credential(t.Context())
	require.NoError(t, err)
	expiry := held.ExpiresAt()

	// The host holds its answer, so a renewal is in flight and the next caller
	// becomes a waiter.
	host.before = func() {
		select {
		case <-release:
		case <-time.After(5 * time.Second):
		}
	}
	// ENTRY IS AT expiry-1s: at this instant the held credential is servable,
	// which is what makes this timeline different from the old test's.
	clock.set(expiry.Add(-time.Second))

	renewing := make(chan struct{})
	go func() {
		defer close(renewing)
		_, _ = client.Credential(context.Background())
	}()
	require.Eventually(t, func() bool { return host.requests.Load() == 2 },
		5*time.Second, time.Millisecond)

	cancelled, cancel := context.WithCancel(context.Background())
	waiterDone := make(chan struct{})
	var served Credential
	var waiterErr error
	before := clock.reads.Load()
	go func() {
		defer close(waiterDone)
		served, waiterErr = client.Credential(cancelled)
	}()
	// The waiter has read the clock, so it has taken its snapshot of a
	// credential that is still valid and is now waiting on the mint in flight.
	require.Eventually(t, func() bool { return clock.reads.Load() > before },
		5*time.Second, 100*time.Microsecond)

	// NOW the credential expires, and only then does the waiter give up.
	clock.set(expiry.Add(time.Second))
	cancel()
	<-waiterDone

	require.Error(t, waiterErr, "there is nothing servable: the held credential has expired")
	require.ErrorIs(t, waiterErr, ErrMintUnavailable)
	require.Empty(t, served.Token(),
		"a cancelled waiter was handed a credential that expired at %s while it waited", expiry)

	letGo()
	<-renewing
}

// Callers whose deadlines are shorter than a degraded host's latency must not
// each produce a mint request.
//
// This is the cost of the previous round's fix for the cancelled leader: not
// counting a cancellation as a failure meant no hold-off, so every call became
// the new leader and sent its own request — roughly one per caller deadline,
// each of which the host may complete and AUDIT while this process discards it.
// Nothing in the suite bounded that; TestACancelledLeaderDoesNotHoldOffEveryoneElse
// cancels exactly once.
func TestRepeatedShortDeadlinesDoNotMintOncePerCaller(t *testing.T) {
	clock := &movableClock{at: testClock}
	host := newMintHost(t, clock.now)
	release := make(chan struct{})
	var releaseOnce sync.Once
	t.Cleanup(func() { releaseOnce.Do(func() { close(release) }) })
	// A DEGRADED host: it has the request and has not answered it.
	host.before = func() {
		select {
		case <-release:
		case <-time.After(10 * time.Second):
		}
	}
	client := newTestMintClient(t, host, projectedFile(t, "projected"), clock.now,
		func(options *MintOptions) { options.RequestTimeout = 5 * time.Second })

	// Twenty callers whose deadlines are far shorter than the host's latency.
	// Each one SENDS — the deadline is what expires, not the context before
	// the request leaves — and then gives up.
	for range 20 {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
		_, err := client.Credential(ctx)
		cancel()
		require.Error(t, err)
	}
	require.LessOrEqual(t, host.requests.Load(), uint64(1),
		"twenty callers that gave up produced %d mint requests; the host completes and AUDITS each one",
		host.requests.Load())

	releaseOnce.Do(func() { close(release) })
	// And the request nobody is waiting for any more still completes and still
	// installs its result: that is what detaching it buys.
	require.Eventually(t, func() bool { return client.Counts().Mints == 1 },
		10*time.Second, time.Millisecond,
		"the detached request's result was discarded with its caller")
}

// A refusal that arrives after the caller that started the request gave up is
// still LATCHED.
//
// Before the request was detached, a 403 racing a cancelled leader was
// discarded — so the next caller presented the projected service-account token
// again, to a host that had already refused it.
func TestARefusalArrivingAfterItsCallerGaveUpIsStillLatched(t *testing.T) {
	clock := &movableClock{at: testClock}
	host := newMintHost(t, clock.now)
	host.refuseWith = http.StatusForbidden
	release := make(chan struct{})
	host.before = func() {
		select {
		case <-release:
		case <-time.After(5 * time.Second):
		}
	}
	client := newTestMintClient(t, host, projectedFile(t, "projected"), clock.now)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := client.Credential(ctx)
	require.Error(t, err)
	close(release)

	require.Eventually(t, func() bool { return client.Refused() != nil },
		5*time.Second, time.Millisecond,
		"the host's refusal was discarded with the caller that asked for it")
	require.ErrorIs(t, client.Refused(), ErrMintRefused)

	// And it is terminal: no later caller sends the projection again.
	seen := host.requests.Load()
	_, err = client.Credential(context.Background())
	require.ErrorIs(t, err, ErrMintRefused)
	require.Equal(t, seen, host.requests.Load(),
		"a latched refusal presented the projected token again")
}

// The refresh limit is a RATE that decays, not a growing penalty.
//
// It used to be mintBackoff(Refreshes), computed from the lifetime count and
// never reset: after a few legitimate refreshes the bound was a minute,
// permanently. The old test froze the clock, so it proved one hold-off and
// said nothing about the steady state its name claimed.
func TestTheRefreshLimitIsASteadyRateAndItDecays(t *testing.T) {
	clock := &movableClock{at: testClock}
	host := newMintHost(t, clock.now)
	// Long enough that no renewal is ever due, so every mint here is a refresh.
	host.authority.core.MaxTTL = 12 * time.Hour
	host.lifetime = 8 * time.Hour
	client := newTestMintClient(t, host, projectedFile(t, "projected"), clock.now)

	held, err := client.Credential(t.Context())
	require.NoError(t, err)

	// Ten minutes of a receiver refusing every credential it is given: a
	// refresh attempt every ten seconds.
	for range 60 {
		clock.set(clock.at.Add(10 * time.Second))
		if replaced, refreshErr := client.Refresh(context.Background(), held); refreshErr == nil {
			held = replaced
		}
	}
	refreshes := client.Counts().Refreshes
	// The burst, plus one per minute of the ten that elapsed. The bound is the
	// RATE: without one this loop would have minted sixty times.
	require.LessOrEqual(t, refreshes, uint64(maxRefreshBurst)+10)
	require.GreaterOrEqual(t, refreshes, uint64(8),
		"the limiter stopped refreshing altogether rather than rate-limiting")

	// And it FORGETS. A client that exhausted the bucket this morning
	// refreshes at once tonight — which the old bound, growing with the
	// lifetime count, never did.
	exhausted := client.Counts().Refreshes
	clock.set(clock.at.Add(24 * time.Hour))
	replaced, err := client.Refresh(context.Background(), held)
	require.NoError(t, err, "a refresh a day later was still paying for this morning")
	require.NotEqual(t, held.Token(), replaced.Token())
	require.Equal(t, exhausted+1, client.Counts().Refreshes)
}

// A refresh about a generation this client has already replaced is answered
// from the credential in hand, even when that credential is inside its renewal
// lead — and it costs no mint and no refresh.
//
// It used to be refused with a held-off ErrMintUnavailable: servableLocked
// returned nil for every refresh, so the one credential that WAS the
// replacement being asked for was the one thing it would not hand over.
func TestARefreshForAnAlreadyReplacedGenerationIsAnsweredFromTheCurrentOne(t *testing.T) {
	clock := &movableClock{at: testClock}
	host := newMintHost(t, clock.now)
	client := newTestMintClient(t, host, projectedFile(t, "projected"), clock.now)

	first, err := client.Credential(t.Context())
	require.NoError(t, err)
	second, err := client.Refresh(t.Context(), first)
	require.NoError(t, err)
	require.NotEqual(t, first.Token(), second.Token())

	// Inside the renewal lead of the credential now held, which is what made
	// the old code reach for the rate limiter.
	clock.set(second.ExpiresAt().Add(-time.Second))
	requests := host.requests.Load()
	counts := client.Counts()

	answered, err := client.Refresh(context.Background(), first)
	require.NoError(t, err, "the replacement being asked for was the credential in hand")
	require.Equal(t, second.Token(), answered.Token())
	require.Equal(t, requests, host.requests.Load(), "it should have minted nothing")
	require.Equal(t, counts, client.Counts(), "and counted nothing")
}

// A host that hands back the credential it was asked to replace has not
// replaced anything, and it is not counted as a refresh.
//
// An idempotent mint endpoint does exactly this. Nothing compared the
// replacement with what it replaced, so the refused credential came back with
// a nil error and a refresh on the counter.
func TestAMintThatReturnsTheSameCredentialIsNotAReplacement(t *testing.T) {
	clock := &movableClock{at: testClock}
	host := newMintHost(t, clock.now)
	client := newTestMintClient(t, host, projectedFile(t, "projected"), clock.now)

	first, err := client.Credential(t.Context())
	require.NoError(t, err)

	// The host becomes idempotent: the same token for every request.
	host.replay = first.Token()

	_, err = client.Refresh(context.Background(), first)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrMintUnavailable)
	require.ErrorContains(t, err, "asked to replace")
	require.Zero(t, client.Counts().Refreshes,
		"a credential that did not change was counted as a refresh")
}

// Every classification the mint client makes, with the three the previous
// round's test did not cover: a local fault, a TLS verification failure, and a
// 408.
func TestEveryMintFaultIsClassifiedByWhatRecoveryItNeeds(t *testing.T) {
	t.Run("a local fault on the projected token is an outage", func(t *testing.T) {
		clock := &movableClock{at: testClock}
		host := newMintHost(t, clock.now)
		source := &faultySource{err: errSyntheticLocalFault}
		client := newTestMintClient(t, host, projectedFile(t, "projected"), clock.now,
			func(options *MintOptions) { options.ProjectedToken = source })

		_, err := client.Credential(context.Background())
		require.ErrorIs(t, err, ErrMintUnavailable)
		require.NotErrorIs(t, err, ErrMintRefused)
		require.NoError(t, client.Refused(),
			"an exhausted file-descriptor table permanently stopped the process")
		require.ErrorIs(t, err, errSyntheticLocalFault,
			"the source's own error must stay in the chain")
	})

	t.Run("a TLS verification failure is an outage: nothing was sent", func(t *testing.T) {
		clock := &movableClock{at: testClock}
		host := newMintHost(t, clock.now)
		// A client pointed at the host with a root pool that does not contain
		// the host's certificate.
		client := newTestMintClient(t, host, projectedFile(t, "projected"), clock.now,
			func(options *MintOptions) { options.RootCAs = x509.NewCertPool() })

		_, err := client.Credential(context.Background())
		// This LATCHED for one revision, on the argument that the projected
		// token must not be presented to an endpoint that cannot prove who it
		// is. The argument does not survive being stated precisely: the
		// handshake fails before any request bytes leave, so nothing was sent
		// and a retry sends nothing either. Latching bought no
		// confidentiality and turned a certificate ROTATION — the most
		// ordinary cause of this in a running system — into a permanent stop.
		require.ErrorIs(t, err, ErrMintUnavailable)
		require.NotErrorIs(t, err, ErrMintRefused)
		require.ErrorContains(t, err, "nothing was sent")
		require.NoError(t, client.Refused(), "a certificate rotation is not a verdict about this process")
	})

	t.Run("408 is an outage", func(t *testing.T) {
		clock := &movableClock{at: testClock}
		host := newMintHost(t, clock.now)
		host.refuseWith = http.StatusRequestTimeout
		client := newTestMintClient(t, host, projectedFile(t, "projected"), clock.now)

		_, err := client.Credential(context.Background())
		require.ErrorIs(t, err, ErrMintUnavailable)
		require.NoError(t, client.Refused())
	})

	t.Run("a plain transport failure is an outage", func(t *testing.T) {
		clock := &movableClock{at: testClock}
		host := newMintHost(t, clock.now)
		client := newTestMintClient(t, host, projectedFile(t, "projected"), clock.now)
		host.server.Close()

		_, err := client.Credential(context.Background())
		require.ErrorIs(t, err, ErrMintUnavailable)
		require.NoError(t, client.Refused())
	})
}

// errSyntheticLocalFault stands for EMFILE or EIO: a momentary local failure
// that carries none of this package's sentinels.
var errSyntheticLocalFault = &localFault{}

type localFault struct{}

func (*localFault) Error() string { return "too many open files" }

// faultySource is a caller's own ProjectedTokenSource failing.
type faultySource struct {
	err   error
	token string
}

func (s *faultySource) ProjectedToken() (string, error) { return s.token, s.err }

// N1, the layer-4 review's new finding: a CANCELLED LEADER must be served the
// valid credential it is holding, exactly as a cancelled waiter is.
//
// The round-three fix wrote `serve := servableNow != nil && outage &&
// !cancelled`, which made a leader whose own deadline expired the one caller
// that is never served — measured by the reviewer as 20 of 20 callers failing
// in the renewal window while a credential with two minutes left was in hand.
// The two paths disagreed about the same credential: a cancelled WAITER got it.
//
// Detaching the request removes the disagreement at the root, because there is
// no leader any more. Whoever takes the slot waits on the same channel and is
// answered by the same servableLocked as everybody else.
func TestACancelledLeaderIsServedTheCredentialItHolds(t *testing.T) {
	clock := &movableClock{at: testClock}
	host := newMintHost(t, clock.now)
	release := make(chan struct{})
	var releaseOnce sync.Once
	t.Cleanup(func() { releaseOnce.Do(func() { close(release) }) })
	client := newTestMintClient(t, host, projectedFile(t, "projected"), clock.now)

	held, err := client.Credential(t.Context())
	require.NoError(t, err)

	// The host stops answering, and the clock enters the renewal lead: the
	// credential in hand is still valid for minutes.
	host.before = func() {
		select {
		case <-release:
		case <-time.After(10 * time.Second):
		}
	}
	clock.set(testClock.Add(13 * time.Minute))
	require.True(t, held.ExpiresAt().After(clock.now()), "the held credential is still valid")

	// Twenty callers, each the leader in turn, each giving up on its own
	// deadline. Every one of them must be served.
	for attempt := range 20 {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
		served, callErr := client.Credential(ctx)
		cancel()
		require.NoError(t, callErr,
			"caller %d was refused while holding a credential valid until %s",
			attempt, held.ExpiresAt())
		require.Equal(t, held.Token(), served.Token())
	}
	require.NoError(t, client.Refused(), "a host that did not answer is not a refusal")
}

// The final-URL assertion, tested directly.
//
// A reviewer measured that deleting the check changes no test: CheckRedirect
// refuses a redirect before a second request is made, and the client owns its
// transport, so nothing can follow one internally. Both of those are why it
// cannot fire — and testing the predicate is how the check stops being a branch
// whose only evidence is that nobody can reach it.
func TestTheFinalURLAssertionNamesAnAnswerFromElsewhere(t *testing.T) {
	configured := "https://mint.example.test/credential"
	for name, probe := range map[string]struct {
		response  *http.Response
		elsewhere string
	}{
		"the configured endpoint": {
			response:  &http.Response{Request: requestTo(t, configured)},
			elsewhere: "",
		},
		"another host": {
			response:  &http.Response{Request: requestTo(t, "https://elsewhere.test/credential")},
			elsewhere: "https://elsewhere.test/credential",
		},
		"another path on the same host": {
			response:  &http.Response{Request: requestTo(t, "https://mint.example.test/other")},
			elsewhere: "https://mint.example.test/other",
		},
		"userinfo is redacted rather than logged": {
			response:  &http.Response{Request: requestTo(t, "https://user:secret@elsewhere.test/x")},
			elsewhere: "https://user:xxxxx@elsewhere.test/x",
		},
		"no request recorded": {response: &http.Response{}, elsewhere: ""},
		"no response":         {response: nil, elsewhere: ""},
	} {
		t.Run(name, func(t *testing.T) {
			require.Equal(t, probe.elsewhere, answeredFromElsewhere(probe.response, configured))
		})
	}
}

func requestTo(t *testing.T, raw string) *http.Request {
	t.Helper()
	parsed, err := url.Parse(raw)
	require.NoError(t, err)
	return &http.Request{URL: parsed}
}

// The window's first branch: a credential that expires at or before it becomes
// valid. It had no case at all, so the branch was asserted by nothing.
func TestAMintedCredentialThatExpiresBeforeItIsValidIsRefused(t *testing.T) {
	clock := &movableClock{at: testClock}
	host := newMintHost(t, clock.now)
	// A host whose window is inverted: minted an hour ago, for a negative
	// lifetime, so expires_at lands before not_before.
	mintedAt := testClock.Add(-time.Hour)
	// core refuses a non-positive TTL, so the inversion is built by minting
	// with a window that has already closed and then asserting on the ORDER
	// rather than on the host's cooperation.
	lifetime := time.Second
	host.mintedAt, host.mintedFor = &mintedAt, &lifetime
	client := newTestMintClient(t, host, projectedFile(t, "projected"), clock.now)

	_, err := client.Credential(t.Context())
	require.Error(t, err)

	// And the predicate itself, for the inverted window core will not mint:
	// the client must refuse it rather than install a credential whose window
	// is empty.
	inverted := Credential{
		notBefore: testClock,
		expiresAt: testClock.Add(-time.Minute),
	}
	windowErr := client.checkWindow(inverted)
	require.ErrorIs(t, windowErr, ErrMintRefused)
	require.ErrorContains(t, windowErr, "expires at or before it becomes valid")

	// Equal is also refused: a zero-length window is not a window.
	equal := Credential{notBefore: testClock, expiresAt: testClock}
	require.ErrorContains(t, client.checkWindow(equal), "expires at or before it becomes valid")
}

// Core 67ee7220 moved the lifetime bound into decodeClaims, so Inspect carries
// it — and Inspect is the path THIS CLIENT reads its own window through.
//
// That is the condition this module named twice when it declined to drop
// MintOptions.MaxCredentialLifetime, and it is now met in the right place. Core
// had added the bound to Verify alone, in the same commit whose decodeClaims
// comment says a bound belongs in the one decode path rather than in one
// entrypoint; the cost was specific and worse than an unchecked path — a
// thirty-day capability that every Verify refuses was reported to its HOLDER,
// which never verifies a signature, as thirty days of validity.
//
// These two tests are here rather than taken on trust because the client's
// default ceiling IS core's constant: if core ever refused a lifetime of
// exactly MaxTTLCeiling, this client's default would refuse every credential a
// host minted at the maximum.
// RENAMED to what it asserts. It was called
// TestCoreRefusesAnOverCeilingLifetimeInTheClientsOwnReadPath and asserted no
// refusal at all: a sound fixture inspects, and two constants are equal. A
// review was right to call that out.
//
// The refusal it was named for CANNOT be driven from here, and the reason is
// the one-implementation rule rather than an omission: core's Authority refuses
// an over-ceiling lifetime at the MINT, so no over-ceiling capability can be
// produced, and assembling one by hand to feed the read path is precisely the
// second implementation both gates exist to refuse. Core asserts it on its own
// side, in decodeClaims, with a committed test — that is the right place, and it
// is the place this module asked for it to be.
//
// What is left is still worth asserting and is the part that can drift here:
// the client's default ceiling IS core's constant, so if core ever refused a
// lifetime of exactly MaxTTLCeiling this client's default would refuse every
// credential a host minted at the maximum. The test below that one establishes
// exactly-at-the-ceiling is accepted.
func TestTheClientsDefaultCeilingIsCoresConstant(t *testing.T) {
	// The structural read path the mint client uses, driven directly, so the
	// entry point this depends on is exercised rather than assumed.
	_, err := corework.Inspect(fixture(t, "session").Token)
	require.NoError(t, err, "a sound capability still inspects")

	require.Equal(t, corework.MaxTTLCeiling, defaultMaxCredentialLifetime,
		"the client's default ceiling and core's absolute ceiling are the same bound; "+
			"two constants that can drift are two bounds")
}

// Exactly at the ceiling is ACCEPTED, so the client's default is never refused
// by a second of slack.
func TestACredentialAtExactlyTheCeilingIsAccepted(t *testing.T) {
	clock := &movableClock{at: testClock}
	host := newMintHost(t, clock.now)
	host.authority.core.MaxTTL = corework.MaxTTLCeiling
	atCeiling := corework.MaxTTLCeiling
	host.mintedAt, host.mintedFor = &testClockStart, &atCeiling
	client := newTestMintClient(t, host, projectedFile(t, "projected"), clock.now)

	credential, err := client.Credential(t.Context())
	require.NoError(t, err,
		"a host minting at exactly the ceiling must not be refused by this client's default")
	require.Equal(t, testClock.Add(corework.MaxTTLCeiling), credential.ExpiresAt())
}

// Core 4cb260d3 made the sealed execution OPTIONAL, because a principal that
// bears no approved build — a person at a terminal — must not have one
// invented for it. That turns the mint response's echo cross-check into a
// PRESENCE question, which it was not before.
//
// GetBuildIncarnation() answers 0 both for "absent" and for a value core says
// is never legitimate (an incarnation starts at 1), so comparing an echo
// against that zero accepted a host echoing "0" against a capability that
// seals no execution at all — a host asserting an execution the issuer does
// not hold.
func TestAnEchoedIncarnationIsRefusedWhenTheCapabilitySealsNoExecution(t *testing.T) {
	clock := &movableClock{at: testClock}
	host := newMintHost(t, clock.now)
	// A capability for a principal the issuer holds no approved build for,
	// which is the human-session shape.
	host.noApprovedBuild = true
	// And a host that echoes an incarnation anyway.
	host.echoIncarnation = "0"
	client := newTestMintClient(t, host, projectedFile(t, "projected"), clock.now)

	_, err := client.Credential(context.Background())
	require.ErrorIs(t, err, ErrMintRefused)
	require.ErrorContains(t, err, "seals no execution at all")
}

// And a capability that DOES seal an execution still cross-checks by value, so
// the presence branch did not replace the comparison.
func TestAnEchoedIncarnationStillCrossChecksByValue(t *testing.T) {
	clock := &movableClock{at: testClock}
	host := newMintHost(t, clock.now)
	host.echoIncarnation = "99"
	client := newTestMintClient(t, host, projectedFile(t, "projected"), clock.now)

	_, err := client.Credential(context.Background())
	require.ErrorIs(t, err, ErrMintRefused)
	require.ErrorContains(t, err, "sealed 11")
}

// Round five's mutation survivors, one test each. Every one of these passed
// with the behaviour its name claims removed.

// The ceiling-above-core refusal (mint.go:481) had no test: a configured
// MaxCredentialLifetime above core's absolute ceiling is refused at
// construction rather than silently clamped, so a deployment that asked for a
// window nothing will mint finds out now instead of at the first mint.
func TestAConfiguredCeilingAboveCoresIsRefusedAtConstruction(t *testing.T) {
	clock := &movableClock{at: testClock}
	host := newMintHost(t, clock.now)

	_, err := NewMintClient(MintOptions{
		URL:                   host.server.URL,
		Authority:             host.pin,
		Audience:              testAudienceName,
		ProjectedToken:        ProjectedTokenFile(projectedFile(t, "projected")),
		ProjectionAudience:    "projection-audience",
		Now:                   clock.now,
		RootCAs:               certPoolOf(host.server),
		MaxCredentialLifetime: corework.MaxTTLCeiling + time.Second,
	})
	require.ErrorIs(t, err, ErrInvalid)
	require.ErrorContains(t, err, "above core's absolute ceiling")

	// Exactly at it is accepted, which is the boundary that matters because
	// the DEFAULT is that constant.
	_, err = NewMintClient(MintOptions{
		URL:                   host.server.URL,
		Authority:             host.pin,
		Audience:              testAudienceName,
		ProjectedToken:        ProjectedTokenFile(projectedFile(t, "projected")),
		ProjectionAudience:    "projection-audience",
		Now:                   clock.now,
		RootCAs:               certPoolOf(host.server),
		MaxCredentialLifetime: corework.MaxTTLCeiling,
	})
	require.NoError(t, err)
}

// A LATCHED REFUSAL BEATS A CANCELLATION (mint.go:871). A caller that gave up
// while the host was refusing must be told it is refused, not told it was
// cancelled: the refusal is terminal and the cancellation is not, and a caller
// that reads only its own ctx error retries forever against a host that has
// already said no.
func TestALatchedRefusalIsReportedEvenToACallerThatGaveUp(t *testing.T) {
	clock := &movableClock{at: testClock}
	host := newMintHost(t, clock.now)
	host.refuseWith = http.StatusForbidden
	release := make(chan struct{})
	host.before = func() {
		select {
		case <-release:
		case <-time.After(5 * time.Second):
		}
	}
	client := newTestMintClient(t, host, projectedFile(t, "projected"), clock.now)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := client.Credential(ctx)
	require.Error(t, err)
	close(release)

	require.Eventually(t, func() bool { return client.Refused() != nil },
		5*time.Second, time.Millisecond)

	// The next caller cancels too, and still learns it is REFUSED rather than
	// only that it cancelled. This one is answered at the top of the loop.
	cancelled, stop := context.WithCancel(context.Background())
	stop()
	_, err = client.Credential(cancelled)
	require.ErrorIs(t, err, ErrMintRefused,
		"a cancelled caller was told it was cancelled by a client that is permanently refused")
	require.NotErrorIs(t, err, ErrMintUnavailable)

	// AND THE RACE, tested at the predicate because it cannot be forced
	// through the public API.
	//
	// answerCancelled runs when a caller's ctx fires while it is WAITING on
	// the in-flight mint. If the refusal latched during that wait, both select
	// branches are ready at once and which one wins is the scheduler's
	// business — so driving this through Credential would be a test that
	// passes for whichever branch it happened to take. Calling the predicate
	// is how the branch gets asserted instead of hoped for, the same way the
	// final-URL assertion is.
	ctxDone, done := context.WithCancel(context.Background())
	done()
	_, raced := client.answerCancelled(ctxDone, mintReasonRenewal, nil)
	require.ErrorIs(t, raced, ErrMintRefused,
		"a refusal that landed while this caller waited was reported as a cancellation")
}

// The EIO READ CLASS: a projected-token read that fails partway is an outage,
// distinct from a file that is absent. Both recover; neither latches.
//
// This one drives a caller's OWN ProjectedTokenSource, which is the branch at
// mintLocked — an unlabelled error from somebody else's reader. The branch
// inside ProjectedTokenFile, where io.ReadAll itself fails, is a different
// three lines and is covered by the test below it; a review was right that this
// test's name claimed both and reached one.
func TestAProjectedTokenReadFailureIsAnOutageAndRecovers(t *testing.T) {
	clock := &movableClock{at: testClock}
	host := newMintHost(t, clock.now)
	source := &faultySource{err: errSyntheticLocalFault}
	client := newTestMintClient(t, host, projectedFile(t, "projected"), clock.now,
		func(options *MintOptions) { options.ProjectedToken = source })

	_, err := client.Credential(context.Background())
	require.ErrorIs(t, err, ErrMintUnavailable)
	require.NoError(t, client.Refused())

	// The fault clears and the clock passes the hold-off: the client mints.
	source.err = nil
	source.token = "projected"
	clock.set(clock.at.Add(time.Minute))
	credential, err := client.Credential(context.Background())
	require.NoError(t, err, "a local read failure permanently stopped the client")
	require.NotEmpty(t, credential.Token())
}

// AND THE FILE SOURCE'S OWN READ FAILURE, at the branch the test above does not
// reach: ProjectedTokenFile opens the path successfully and io.ReadAll then
// fails. A directory is the portable way to produce exactly that — os.Open
// succeeds, the read returns EISDIR — and it is not a contrived shape: the
// projection's mount point with nothing mounted on it is a directory where a
// file is expected.
//
// What matters is the CLASS: ErrMintUnavailable, so it is held off and retried
// rather than latched. An EIO on the mount, a projection replaced between
// unlink and create, and an exhausted descriptor table all land here, and
// latching any of them stopped a process that was holding a good credential.
func TestTheFileSourcesOwnReadFailureIsAnOutage(t *testing.T) {
	directory := t.TempDir()

	_, err := ProjectedTokenFile(directory).ProjectedToken()

	require.ErrorIs(t, err, ErrMintUnavailable,
		"a read that fails after a successful open is an outage, not a refusal")
	require.NotErrorIs(t, err, ErrMintRefused, "and it must never latch")
	require.ErrorContains(t, err, "read projected token",
		"the message must name the stage, so an operator knows the file was found and not read")
}
