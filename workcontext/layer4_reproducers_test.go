package workcontext

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"math/big"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	corework "github.com/codefly-dev/core/workcontext"
	"github.com/stretchr/testify/require"
)

// The reproducers from the dynamic review (layer 4), kept as tests rather than
// described in a reply.
//
// They ran in a sandbox with no OS sockets, which is why they reach for
// net.Pipe and real TLS over it instead of httptest: that exercises Go's actual
// TLS and HTTP machinery without a listener. They are kept in that form on
// purpose — a test that cannot run where the next reviewer runs it is a test
// that stops being evidence.

// D1. The effective transport, not the inspectable one.
//
// At the reviewed head a nil Transport was approved as "a RoundTripper this
// package cannot inspect", and net/http then substitutes http.DefaultTransport
// — which is a package-level variable any code in the process can replace. With
// an InsecureSkipVerify transport installed there, a default MintClient sent
// the projected bearer to an untrusted TLS endpoint and reported success. The
// review observed `Bearer fixture-bearer` arrive.
//
// It cannot happen now because there is nothing to inspect and nothing to
// substitute: the client BINDS a transport it built. This test holds that, by
// making http.DefaultTransport hostile and asserting the bearer never arrives.
func TestTheDefaultTransportIsNeverTheOneThatCarriesTheBearer(t *testing.T) {
	authority := newAuthority(t)
	payload, err := json.Marshal(mintResponse{WorkContext: authority.start(t, mintInput{})})
	require.NoError(t, err)

	public, private := corework.FixtureKeyPair()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		DNSNames:     []string{"mint.example.test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, public, private)
	require.NoError(t, err)
	serverTLS := &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: private}},
		MinVersion:   tls.VersionTLS12,
	}

	// An endpoint nothing configured, reachable only through the hostile
	// default transport, recording every Authorization header it is shown.
	received := make(chan string, 4)
	hostile := &http.Transport{
		DisableKeepAlives: true,
		//nolint:gosec // the hostile configuration IS the test
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		DialContext: func(context.Context, string, string) (net.Conn, error) {
			caller, endpoint := net.Pipe()
			go func() {
				defer func() {
					_ = endpoint.Close()
				}()
				conn := tls.Server(endpoint, serverTLS)
				request, readErr := http.ReadRequest(bufio.NewReader(conn))
				if readErr != nil {
					return
				}
				received <- request.Header.Get("Authorization")
				_, _ = io.Copy(io.Discard, request.Body)
				_ = request.Body.Close()
				response := &http.Response{
					StatusCode: http.StatusOK, ProtoMajor: 1, ProtoMinor: 1,
					Header:        http.Header{"Content-Type": []string{"application/json"}},
					ContentLength: int64(len(payload)),
					Body:          io.NopCloser(strings.NewReader(string(payload))),
				}
				_ = response.Write(conn)
			}()
			return caller, nil
		},
	}
	previous := http.DefaultTransport
	http.DefaultTransport = hostile
	t.Cleanup(func() {
		http.DefaultTransport = previous
		hostile.CloseIdleConnections()
	})

	client, err := NewMintClient(MintOptions{
		URL:                "https://mint.example.test/mint",
		Authority:          newTestPin(),
		Audience:           testAudienceName,
		ProjectedToken:     ProjectedTokenFile(projectedFile(t, "fixture-bearer")),
		ProjectionAudience: "projection-audience",
		Now:                func() time.Time { return testClock },
	})
	require.NoError(t, err)

	// The mint fails because mint.example.test resolves nowhere through the
	// transport the CLIENT built — and it fails as an OUTAGE, which is the
	// assertion that distinguishes "the client used its own transport and
	// could not reach the host" from "the client used the hostile one and got
	// an answer". Accepting any error would also have accepted success
	// followed by some later failure.
	_, err = client.Credential(t.Context())
	require.ErrorIs(t, err, ErrMintUnavailable)
	require.Equal(t, MintCounts{}, client.Counts(),
		"nothing was minted, so nothing was counted")

	select {
	case bearer := <-received:
		t.Fatalf("the hostile default transport carried the projection: the endpoint was shown %q", bearer)
	default:
	}

	// And structurally: the client's transport is its own, bound at
	// construction, so no later substitution of http.DefaultTransport can
	// reach it either.
	require.NotSame(t, http.DefaultTransport, client.httpClient.Transport)
	bound, ok := client.httpClient.Transport.(*http.Transport)
	require.True(t, ok)
	require.False(t, bound.TLSClientConfig.InsecureSkipVerify)
	require.Nil(t, bound.DialContext)
	require.Nil(t, bound.DialTLSContext)
}

// D2. Omitting both installation carriers used to skip the seal check
// altogether, so FromHeaders reported success for a malformed token, one
// carrying no seal, and one whose actor hop carried no epoch.
//
// The review's probe is kept in its own right rather than folded into the
// carrier tests, because what it demonstrates is the SHAPE of the mistake: a
// pre-check whose strictness depended on what the caller had chosen to attach.
func TestOmittingBothCarriersDoesNotSkipTheSealCheck(t *testing.T) {
	for name, token := range map[string]string{
		"malformed":          "not-a-token",
		"missing seal":       fixture(t, "missing-seal").Token,
		"actor with noepoch": fixture(t, "actor-without-epoch").Token,
		"foreign encoding":   fixture(t, "foreign-encoding").Token,
	} {
		t.Run(name, func(t *testing.T) {
			bare := http.Header{}
			bare.Set(HeaderName, token)
			_, err := FromHeaders(bare)
			require.Error(t, err,
				"a capability with no carriers beside it is still a capability, and still checked")
		})
	}
}

// D3. Refreshing an old generation returned its replacement even after that
// replacement had expired.
//
// The generation check answered "somebody already replaced that one" and handed
// the replacement over without looking at it. A caller refused on an old
// credential — which is exactly the caller most likely to have been holding one
// for a while — was given an expired one.
func TestRefreshingAnOldGenerationDoesNotHandBackAnExpiredReplacement(t *testing.T) {
	clock := testClock
	now := func() time.Time { return clock }
	host := newMintHost(t, now)
	client := newTestMintClient(t, host, projectedFile(t, "projected"), now)

	first, err := client.Credential(t.Context())
	require.NoError(t, err)
	replaced, err := client.Refresh(t.Context(), first)
	require.NoError(t, err)
	require.EqualValues(t, 2, host.requests.Load())

	// Time passes until the replacement has expired outright.
	clock = testClock.Add(30 * time.Minute)
	require.True(t, clock.After(replaced.ExpiresAt()), "the replacement has expired")

	// A caller that was refused on the FIRST credential comes back. The
	// generation has moved on, so nothing needs replacing on that account —
	// but what is held is expired, and an expired credential must not be
	// handed to anybody.
	current, err := client.Refresh(t.Context(), first)
	require.NoError(t, err)
	require.True(t, current.ExpiresAt().After(clock),
		"Refresh handed back a credential that expired at %s, and it is %s",
		current.ExpiresAt(), clock)
	require.NotEqual(t, replaced.Token(), current.Token())
	require.EqualValues(t, 3, host.requests.Load(), "it minted rather than handing over a dead credential")

	// The same for Credential, which is the path that always checked.
	clock = testClock.Add(90 * time.Minute)
	fresh, err := client.Credential(t.Context())
	require.NoError(t, err)
	require.True(t, fresh.ExpiresAt().After(clock))
}

// D4. A type named mintRequest or mintResponse outside the endpoint's own file
// inherited the JSON exemption, so `extra/payload.go` could hold a json-tagged
// struct enumerating a capability's fields by hand — the deleted
// implementation — with the gate green.
func TestTheGateDoesNotLetMintBodyNamesTravel(t *testing.T) {
	source := "package extra\n" +
		"type mintRequest struct { Principal string `json:\"principal\"` }\n" +
		"type mintResponse struct { Epoch uint64 `json:\"epoch\"` }"
	for _, path := range []string{"extra/payload.go", "grpctransport/mint.go", "mint_bodies.go"} {
		t.Run(path, func(t *testing.T) {
			findings := inspectForSecondImplementation(parseSource(t, path, source))
			require.NotEmpty(t, findings,
				"a namesake mintRequest/mintResponse outside %s inherits the exemption", mintEndpointJSONFile)
			require.Contains(t, strings.Join(findings, "\n"), "struct with json tags")
		})
	}

	// And the real file keeps its exemption, so the gate is not green by
	// refusing everything.
	genuine := "package workcontext\n" +
		"type mintRequest struct { Audience string `json:\"audience\"` }\n" +
		"type mintResponse struct { WorkContext string `json:\"work_context\"` }"
	require.Empty(t, inspectForSecondImplementation(parseSource(t, mintEndpointJSONFile, genuine)))
}

// The review's own redirect containment probe, which it ran with an in-process
// RoundTripper because the sandbox denied listeners. Kept because it asserts
// containment without needing a socket, which the httptest version cannot.
func TestRedirectContainmentWithoutASocket(t *testing.T) {
	var destination atomic.Uint64
	authority := newAuthority(t)
	payload, err := json.Marshal(mintResponse{WorkContext: authority.start(t, mintInput{})})
	require.NoError(t, err)

	client, err := NewMintClient(MintOptions{
		URL:                "https://mint.example.test/mint",
		Authority:          newTestPin(),
		Audience:           testAudienceName,
		ProjectedToken:     ProjectedTokenFile(projectedFile(t, "projected")),
		ProjectionAudience: "projection-audience",
		Now:                func() time.Time { return testClock },
	})
	require.NoError(t, err)

	// Replace the bound transport's round trip, which only a test in this
	// package can do: a 307 to another host, then a 200 at the destination.
	client.httpClient.Transport = roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.URL.Host != "mint.example.test" {
			destination.Add(1)
			return &http.Response{
				StatusCode: http.StatusOK, Request: request,
				Header: http.Header{"Content-Type": []string{"application/json"}},
				Body:   io.NopCloser(strings.NewReader(string(payload))),
			}, nil
		}
		return &http.Response{
			StatusCode: http.StatusTemporaryRedirect, Request: request,
			Header: http.Header{"Location": []string{"https://elsewhere.example.test/mint"}},
			Body:   http.NoBody,
		}, nil
	})

	_, err = client.Credential(t.Context())
	require.EqualValues(t, 0, destination.Load(),
		"the redirect destination received a request carrying the projection")
	require.ErrorIs(t, err, ErrMintRefused)
	require.ErrorContains(t, err, "redirected")
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) { return f(request) }

// The hour-long acceptance run the dynamic review supplied and this suite did
// not have. It passed there (1,952 calls, one mint request) and is kept so the
// arithmetic is a gate rather than a reviewer's one-off.
//
// It establishes ENDPOINT ISSUANCE COUNT and not durable host audit events,
// which is the review's own caveat and remains true.
//
// # The arithmetic moved, and #47's acceptance criterion moved with it
//
// Core now caps what an authority will mint: Authority.MaxTTL, defaulting to
// DefaultMaxTTL of one hour. One mint across an hour of calls needs a lifetime
// of at least run/(1-lead) — 75 minutes at the default 0.2 lead — so **at
// core's default cap, "exactly one mint for an hour's run" is NOT reachable**.
// An hour of calls costs one mint and one renewal.
//
// That is the host's ceiling working, not a defect, and the acceptance
// criterion has to be read against it: what the mint-once model guarantees is
// a credential's own clock, not a fixed number. The heartbeat this replaced
// made 240 requests an hour per surface. Two is not one, and it is also not
// 240.
//
// Both shapes are asserted, because a consumer sizing this needs to know which
// one its host has chosen.
func TestAnHourOfCallsCostsOneMintAndOneRenewalAtCoresDefaultCeiling(t *testing.T) {
	// A credential as long as the host will mint by default.
	requests, counts := hourOfCalls(t, time.Hour, 0)
	require.EqualValues(t, 2, requests,
		"at a one-hour ceiling and a 0.2 lead, an hour of calls is one mint and one renewal")
	require.Equal(t, MintCounts{Mints: 1, Renewals: 1}, counts)
}

// And the one-mint shape, when a host raises its own ceiling deliberately —
// which is where that decision belongs, and where a reviewer sees it.
func TestAnHourOfCallsCostsOneMintWhenTheHostMintsLongerThanTheRun(t *testing.T) {
	requests, counts := hourOfCalls(t, 90*time.Minute, 2*time.Hour)
	require.EqualValues(t, 1, requests,
		"an hour of calls on a credential that outlives the run plus its lead is ONE endpoint request")
	require.Equal(t, MintCounts{Mints: 1}, counts)
}

// hourOfCalls runs 32 concurrent first calls and then 32 calls in each of 60
// simulated minutes, and reports what the endpoint was asked for.
func hourOfCalls(t *testing.T, lifetime time.Duration, maxTTL time.Duration) (uint64, MintCounts) {
	t.Helper()
	clock := testClock
	var clockMu sync.RWMutex
	now := func() time.Time {
		clockMu.RLock()
		defer clockMu.RUnlock()
		return clock
	}
	host := newMintHost(t, now)
	host.lifetime = lifetime
	host.authority.core.MaxTTL = maxTTL // zero takes core's DefaultMaxTTL
	client := newTestMintClient(t, host, projectedFile(t, "projected"), now)

	// Errors are collected and asserted on the TEST goroutine: require inside a
	// goroutine calls FailNow off it, which Go's testing package does not
	// support and which can leave the run reporting a pass.
	var waiting sync.WaitGroup
	failures := make(chan error, 32)
	for range 32 {
		waiting.Add(1)
		go func() {
			defer waiting.Done()
			if _, err := client.Credential(context.Background()); err != nil {
				failures <- err
			}
		}()
	}
	waiting.Wait()
	close(failures)
	for err := range failures {
		require.NoError(t, err, "a concurrent first call must not fail")
	}

	for minute := range 60 {
		clockMu.Lock()
		clock = testClock.Add(time.Duration(minute) * time.Minute)
		clockMu.Unlock()
		for range 32 {
			_, err := client.Credential(t.Context())
			require.NoError(t, err)
		}
	}
	return host.requests.Load(), client.Counts()
}

// D3 (round three). A transient response-body read failure must not stop the
// client permanently.
//
// The host answers 200 and the connection goes away mid-body. That was wrapped
// in ErrMintRefused, which became TERMINAL once refusals started latching: one
// interrupted read permanently stopped a process holding a perfectly good
// credential, and it stayed stopped after the endpoint recovered. A body that
// stops mid-read is an outage.
func TestAnInterruptedResponseBodyIsAnOutageRatherThanARefusal(t *testing.T) {
	clock := testClock
	now := func() time.Time { return clock }
	host := newMintHost(t, now)
	client := newTestMintClient(t, host, projectedFile(t, "projected"), now)

	held, err := client.Credential(t.Context())
	require.NoError(t, err)

	// A 200 whose body fails partway. The transport is the client's, so the
	// failure is injected through it rather than through a socket.
	transport, ok := client.httpClient.Transport.(*http.Transport)
	require.True(t, ok)
	t.Cleanup(func() { client.httpClient.Transport = transport })
	client.httpClient.Transport = roundTripFunc(func(request *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK, Request: request,
			Header: http.Header{"Content-Type": []string{"application/json"}},
			Body:   io.NopCloser(interruptedBody{}),
		}, nil
	})

	// Inside the renewal lead, so the credential in hand still has minutes.
	clock = testClock.Add(13 * time.Minute)
	served, err := client.Credential(t.Context())
	require.NoError(t, err, "an interrupted read is an outage, and the held credential survives it")
	require.Equal(t, held.Token(), served.Token())
	require.NoError(t, client.Refused(), "and it must not be latched as terminal")

	// And the endpoint recovering recovers the client.
	client.httpClient.Transport = transport
	clock = testClock.Add(13*time.Minute + 2*minMintBackoff)
	fresh, err := client.Credential(t.Context())
	require.NoError(t, err)
	require.NotEqual(t, held.Token(), fresh.Token())
}

// interruptedBody returns a short read and then a transport failure, which is
// what a connection dropped after the headers looks like to io.ReadAll.
type interruptedBody struct{}

func (interruptedBody) Read(p []byte) (int, error) {
	copied := copy(p, `{"work_context":"partial`)
	return copied, io.ErrUnexpectedEOF
}

// An oversized or malformed COMPLETE response stays terminal, because the host
// answered and answered wrongly: retrying gets the same answer.
func TestACompleteButUnacceptableResponseStaysTerminal(t *testing.T) {
	now := func() time.Time { return testClock }
	host := newMintHost(t, now)
	client := newTestMintClient(t, host, projectedFile(t, "projected"), now)

	oversized := strings.Repeat("a", maxMintResponseBytes+64)
	client.httpClient.Transport = roundTripFunc(func(request *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK, Request: request,
			Header: http.Header{"Content-Type": []string{"application/json"}},
			Body:   io.NopCloser(strings.NewReader(`{"work_context":"` + oversized + `"}`)),
		}, nil
	})

	_, err := client.Credential(t.Context())
	require.ErrorIs(t, err, ErrMintRefused)
	require.ErrorContains(t, err, "exceeds")
	require.ErrorIs(t, client.Refused(), ErrMintRefused)
}

// D4 (round three). A cancelled waiter must not be handed an EXPIRED credential.
//
// The waiter snapshotted the credential and its servability BEFORE waiting,
// then answered from that snapshot on cancellation without re-reading the
// clock. A waiter that started a second before expiry and cancelled a second
// after it received an expired credential with a nil error — and two seconds
// fits easily inside the default five-second request timeout.
func TestACancelledWaiterIsNeverHandedAnExpiredCredential(t *testing.T) {
	clock := testClock
	var clockMu sync.RWMutex
	now := func() time.Time {
		clockMu.RLock()
		defer clockMu.RUnlock()
		return clock
	}
	host := newMintHost(t, now)
	release := make(chan struct{})
	var releaseOnce sync.Once
	letGo := func() { releaseOnce.Do(func() { close(release) }) }
	t.Cleanup(letGo)
	client := newTestMintClient(t, host, projectedFile(t, "projected"), now)

	held, err := client.Credential(t.Context())
	require.NoError(t, err)
	expiry := held.ExpiresAt()

	// One second before expiry, with the host holding its answer: a renewal is
	// in flight and a second caller becomes a waiter.
	host.before = func() {
		select {
		case <-release:
		case <-time.After(2 * time.Second):
		}
	}
	clockMu.Lock()
	clock = expiry.Add(-time.Second)
	clockMu.Unlock()

	renewing := make(chan struct{})
	go func() {
		defer close(renewing)
		_, _ = client.Credential(context.Background())
	}()
	require.Eventually(t, func() bool { return host.requests.Load() == 2 },
		2*time.Second, time.Millisecond)

	// The waiter's own context is cancelled one second AFTER expiry.
	clockMu.Lock()
	clock = expiry.Add(time.Second)
	clockMu.Unlock()
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	served, err := client.Credential(cancelled)

	require.Error(t, err, "there is nothing servable: the held credential has expired")
	require.ErrorIs(t, err, ErrMintUnavailable)
	require.Empty(t, served.Token(),
		"a cancelled waiter was handed a credential that expired at %s", expiry)

	letGo()
	<-renewing
}

// D6 (round three). DisallowUnknownFields applies to the value just decoded and
// says nothing about what follows it, so a valid response with a second JSON
// value appended was accepted. The response is ONE object and nothing after it.
func TestAMintResponseCarryingTrailingJSONIsRefused(t *testing.T) {
	now := func() time.Time { return testClock }
	authority := newAuthority(t)
	token := authority.start(t, mintInput{})

	for name, payload := range map[string]string{
		"a second object":   `{"work_context":"` + token + `"}{"unsupported_security_field":true}`,
		"a trailing array":  `{"work_context":"` + token + `"}[1,2,3]`,
		"a trailing scalar": `{"work_context":"` + token + `"} 7`,
	} {
		t.Run(name, func(t *testing.T) {
			host := newMintHost(t, now)
			client := newTestMintClient(t, host, projectedFile(t, "projected"), now)
			client.httpClient.Transport = roundTripFunc(func(request *http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: http.StatusOK, Request: request,
					Header: http.Header{"Content-Type": []string{"application/json"}},
					Body:   io.NopCloser(strings.NewReader(payload)),
				}, nil
			})

			_, err := client.Credential(t.Context())
			require.ErrorIs(t, err, ErrMintRefused)
			require.ErrorContains(t, err, "more than one JSON value")
		})
	}

	// And trailing WHITESPACE is fine: a response is allowed to end in a
	// newline, which is what most encoders write.
	host := newMintHost(t, now)
	client := newTestMintClient(t, host, projectedFile(t, "projected"), now)
	client.httpClient.Transport = roundTripFunc(func(request *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK, Request: request,
			Header: http.Header{"Content-Type": []string{"application/json"}},
			Body:   io.NopCloser(strings.NewReader(`{"work_context":"` + token + `"}` + "\n\n  ")),
		}, nil
	})
	_, err := client.Credential(t.Context())
	require.NoError(t, err, "a trailing newline is not a second value")
}
