package workcontext

import (
	"context"
	"errors"
	"testing"
	"time"

	corework "github.com/codefly-dev/core/workcontext"
	"github.com/codefly-dev/core/workcontext/conformance"
	"github.com/stretchr/testify/require"
)

// The failure a stream guard exists to prevent is the quiet one: a stream
// opened under an installation revision the host has since replaced, still
// draining a snapshot computed under authority that no longer exists. Nothing
// in the stream fails, nothing is logged, and the data keeps arriving.
//
// The check is per emission, so the revocation lands IMMEDIATELY after a
// successful check and the very next message is refused. Under the cadence this
// replaced — bounded at fifteen minutes — that message and every message for
// the next fifteen minutes still left.
func TestStreamTerminatesOnTheFirstMessageAfterTheCredentialIsSuperseded(t *testing.T) {
	a := newAuthority(t)
	token := a.start(t, mintInput{})
	verifier := a.verifier(t)

	rechecks := 0
	guard, err := NewStreamGuard(StreamGuardOptions{
		Recheck: func(ctx context.Context) error {
			rechecks++
			_, verifyErr := verifier.Verify(ctx, token)
			return verifyErr
		},
	})
	require.NoError(t, err)

	// Every message is re-checked, including the first: a stream never emits on
	// the strength of the check that opened it.
	for message := 1; message <= 4; message++ {
		require.NoError(t, guard.BeforeSend(t.Context()))
		require.Equal(t, message, rechecks,
			"message %d must have re-presented the credential", message)
	}

	// The host moves the installation on, with no time passing at all. The very
	// next message is refused, and the refusal says the state moved under the
	// credential (ErrRevoked) rather than that the credential is malformed, so
	// the caller knows a fresh credential would be accepted.
	moved := testSeal
	moved.InstallationRevision++
	require.NoError(t, a.seals.Put(testPrincipal, moved))

	err = guard.BeforeSend(t.Context())
	require.ErrorIs(t, err, ErrStreamTerminated)
	require.ErrorIs(t, err, ErrRevoked)
	require.Equal(t, 5, rechecks, "the refusal came from a check, not from a cached answer")
	require.ErrorIs(t, guard.Terminated(), ErrStreamTerminated)
}

// Expiry is visible for the same reason revocation is: the check is per
// emission, so a credential that runs out mid-stream stops the stream at the
// next message. The verifier's own clock moves — the earlier version of this
// test advanced a clock the guard held and left the verifier's fixed, so it
// provided no expiry evidence at all.
func TestStreamTerminatesWhenTheCredentialExpiresMidStream(t *testing.T) {
	a := newAuthority(t)
	token := a.start(t, mintInput{}) // a fifteen-minute credential

	verifying := testClock
	verifier := a.verifier(t)
	verifier.Now = func() time.Time { return verifying }

	guard, err := NewStreamGuard(StreamGuardOptions{
		Recheck: func(ctx context.Context) error {
			_, verifyErr := verifier.Verify(ctx, token)
			return verifyErr
		},
	})
	require.NoError(t, err)
	require.NoError(t, guard.BeforeSend(t.Context()))

	verifying = testClock.Add(16 * time.Minute)
	err = guard.BeforeSend(t.Context())
	require.ErrorIs(t, err, ErrStreamTerminated)
	require.ErrorIs(t, err, ErrInvalid, "an expired credential is invalid, not revoked")
}

// A live source that could not be reached has not said the credential is good.
// Treating "I could not ask" as a pass is how a stream outlives the authority
// it was opened under while every log line stays clean, so an unavailable
// source terminates the stream exactly as a refusal does.
func TestStreamTerminatesWhenTheLiveSourceIsUnavailable(t *testing.T) {
	unavailable := errors.New("installation state store unreachable")
	answers := []error{nil, unavailable}
	guard, err := NewStreamGuard(StreamGuardOptions{
		Recheck: func(context.Context) error {
			answer := answers[0]
			if len(answers) > 1 {
				answers = answers[1:]
			}
			return answer
		},
	})
	require.NoError(t, err)

	require.NoError(t, guard.BeforeSend(t.Context()))
	err = guard.BeforeSend(t.Context())
	require.ErrorIs(t, err, ErrStreamTerminated)
	require.ErrorIs(t, err, unavailable,
		"the reason stays in the chain: the caller needs to tell an outage from a revocation")
	require.NotErrorIs(t, err, ErrRevoked)
}

// A terminated stream stays terminated. A caller that loops past the first
// refusal must not be handed a second chance to emit, and the authority coming
// back must not resurrect a stream that has already been refused: the messages
// it would send were computed under authority that was withdrawn.
func TestATerminatedStreamIsNotResumed(t *testing.T) {
	refuse := true
	rechecks := 0
	guard, err := NewStreamGuard(StreamGuardOptions{
		Recheck: func(context.Context) error {
			rechecks++
			if refuse {
				return ErrRevoked
			}
			return nil
		},
	})
	require.NoError(t, err)

	require.ErrorIs(t, guard.BeforeSend(t.Context()), ErrStreamTerminated)
	require.Equal(t, 1, rechecks)

	refuse = false
	for range 3 {
		require.ErrorIs(t, guard.BeforeSend(t.Context()), ErrStreamTerminated,
			"a stream is terminated once, and the authority coming back does not undo it")
	}
	require.Equal(t, 1, rechecks, "a terminated stream asks nothing further")
}

func TestStreamGuardValidatesItsConfiguration(t *testing.T) {
	_, err := NewStreamGuard(StreamGuardOptions{})
	require.ErrorIs(t, err, ErrInvalid)
	require.ErrorContains(t, err, "needs a re-check")

	guard, err := NewStreamGuard(StreamGuardOptions{
		Recheck: func(context.Context) error { return nil },
	})
	require.NoError(t, err)
	require.ErrorIs(t, guard.BeforeSend(nil), ErrInvalid)

	var absent *StreamGuard
	require.ErrorIs(t, absent.BeforeSend(context.Background()), ErrInvalid)
	require.NoError(t, absent.Terminated())
}

// The per-emission re-check must NOT consume a single-use capability.
//
// This is the bug the README shipped: the documented recipe called
// verifier.Verify on every emission, core's Verify consumes a single-use nonce,
// and every grant capability is single-use — so a grant-opened stream died with
// ErrReplayed at its FIRST message. The error even looked like a replay attack
// rather than like the guard eating its own credential.
//
// The fix is core's (*Verifier).Recheck, which re-reads what can move and never
// touches the replay store. RecheckWith is how this module hands a caller that
// call instead of the one that compiles just as well and breaks later.
func TestTheStreamRecheckDoesNotConsumeASingleUseCapability(t *testing.T) {
	settings := conformance.New(time.Now())
	verifier := &Verifier{
		Issuer:    settings.Issuer,
		Audience:  settings.Audience,
		Keys:      corework.FixtureKeys(),
		Revisions: settings.Revisions,
		Replay:    settings.Replay,
		Grants:    settings.Grants,
		Seals:     settings.Seals,
		Now:       settings.Now,
	}

	fixtures, err := corework.Fixtures(settings.Now())
	require.NoError(t, err)
	var grant corework.Fixture
	for _, candidate := range fixtures {
		if candidate.SingleUse {
			grant = candidate
			break
		}
	}
	require.NotEmpty(t, grant.Token, "core's kit has no single-use fixture to test with")

	// The one legitimate consumption.
	verified, err := verifier.Verify(t.Context(), grant.Token)
	require.NoError(t, err)

	// Now the stream, built the way this module recommends.
	guard, err := NewStreamGuard(StreamGuardOptions{
		Recheck: RecheckWith(verifier, verified),
	})
	require.NoError(t, err)
	for message := range 5 {
		require.NoError(t, guard.BeforeSend(t.Context()),
			"message %d must not be refused as a replay of the stream's own credential", message+1)
	}
	require.NoError(t, guard.Terminated())

	// And the capability is still spent exactly once overall: presenting it to
	// Verify again is a replay, which is what single-use means.
	_, err = verifier.Verify(t.Context(), grant.Token)
	require.ErrorIs(t, err, ErrReplayed)

	// Whereas a guard built on Verify — the recipe this replaces — dies on its
	// first message. Asserted so the regression is a failing test rather than a
	// README nobody re-reads.
	consuming, err := NewStreamGuard(StreamGuardOptions{
		Recheck: func(ctx context.Context) error {
			_, verifyErr := verifier.Verify(ctx, grant.Token)
			return verifyErr
		},
	})
	require.NoError(t, err)
	require.ErrorIs(t, consuming.BeforeSend(t.Context()), ErrReplayed,
		"this is the bug: Verify in a loop spends the nonce the loop depends on")
}

func TestRecheckWithRefusesIncompleteArguments(t *testing.T) {
	require.ErrorIs(t, RecheckWith(nil, nil)(context.Background()), ErrInvalid)
}
