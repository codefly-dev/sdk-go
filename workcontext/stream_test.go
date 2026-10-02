package workcontext

import (
	"context"
	"errors"
	"testing"
	"time"

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
