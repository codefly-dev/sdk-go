package workcontext

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// The failure a stream guard exists to prevent is the quiet one: a stream
// opened under an installation revision the host has since replaced, still
// draining a snapshot computed under authority that no longer exists. Nothing
// in the stream fails, nothing is logged, and the data keeps arriving.
func TestStreamTerminatesWhenTheCredentialIsSuperseded(t *testing.T) {
	clock := testClock
	a := newAuthority(t)
	token := a.start(t, mintInput{})
	verifier := a.verifier(t)

	// The host's live view of the installation revision, which it moves while
	// the stream is open. The re-check is core's verify against it, which is
	// what an ordinary call performs.
	rechecks := 0
	guard, err := NewStreamGuard(StreamGuardOptions{
		Interval: 30 * time.Second,
		Now:      func() time.Time { return clock },
		Recheck: func(ctx context.Context) error {
			rechecks++
			_, verifyErr := verifier.Verify(ctx, token)
			return verifyErr
		},
	})
	require.NoError(t, err)

	// The first message is re-checked rather than riding on the check that
	// opened the stream.
	require.NoError(t, guard.BeforeSend(t.Context()))
	require.Equal(t, 1, rechecks)

	// Messages inside the cadence cost nothing.
	clock = clock.Add(20 * time.Second)
	require.NoError(t, guard.BeforeSend(t.Context()))
	require.Equal(t, 1, rechecks)

	// The cadence elapses and the credential is still current.
	clock = clock.Add(20 * time.Second)
	require.NoError(t, guard.BeforeSend(t.Context()))
	require.Equal(t, 2, rechecks)
	require.NoError(t, guard.Terminated())

	// The host moves the installation on. The next message past the cadence is
	// refused, and the refusal says the state moved under the credential
	// (ErrRevoked) rather than that the credential is malformed, so the caller
	// knows a fresh credential would be accepted.
	moved := testSeal
	moved.InstallationRevision++
	require.NoError(t, a.seals.Put(testPrincipal, moved))
	clock = clock.Add(31 * time.Second)
	err = guard.BeforeSend(t.Context())
	require.ErrorIs(t, err, ErrStreamTerminated)
	require.ErrorIs(t, err, ErrRevoked)
	require.ErrorIs(t, guard.Terminated(), ErrStreamTerminated)
}

// A terminated stream stays terminated. A caller that loops past the first
// refusal must not be handed a second chance to emit, and restoring the old
// revision must not resurrect a stream that has already been refused: the
// messages it would send were computed under authority that was withdrawn.
func TestATerminatedStreamIsNotResumed(t *testing.T) {
	clock := testClock
	refuse := true
	guard, err := NewStreamGuard(StreamGuardOptions{
		Interval: time.Second,
		Now:      func() time.Time { return clock },
		Recheck: func(context.Context) error {
			if refuse {
				return ErrRevoked
			}
			return nil
		},
	})
	require.NoError(t, err)

	first := guard.BeforeSend(t.Context())
	require.ErrorIs(t, first, ErrStreamTerminated)

	refuse = false
	clock = clock.Add(time.Hour)
	for range 3 {
		require.ErrorIs(t, guard.BeforeSend(t.Context()), ErrStreamTerminated,
			"a stream is terminated once, and the authority coming back does not undo it")
	}
}

func TestStreamGuardValidatesItsCadence(t *testing.T) {
	_, err := NewStreamGuard(StreamGuardOptions{Interval: time.Minute})
	require.ErrorIs(t, err, ErrInvalid)
	require.ErrorContains(t, err, "needs a re-check")

	for name, interval := range map[string]time.Duration{
		"zero":             0,
		"sub-second":       500 * time.Millisecond,
		"beyond the bound": maxStreamRecheckInterval + time.Second,
	} {
		t.Run(name, func(t *testing.T) {
			_, err := NewStreamGuard(StreamGuardOptions{
				Interval: interval,
				Recheck:  func(context.Context) error { return nil },
			})
			require.ErrorIs(t, err, ErrInvalid)
			require.ErrorContains(t, err, "interval")
		})
	}

	guard, err := NewStreamGuard(StreamGuardOptions{
		Interval: time.Minute,
		Recheck:  func(context.Context) error { return nil },
	})
	require.NoError(t, err)
	require.ErrorIs(t, guard.BeforeSend(nil), ErrInvalid)

	var absent *StreamGuard
	require.ErrorIs(t, absent.BeforeSend(context.Background()), ErrInvalid)
	require.NoError(t, absent.Terminated())
}
