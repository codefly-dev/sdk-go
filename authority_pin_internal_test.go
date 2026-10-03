package codefly

import (
	"fmt"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

// The pin is installed whole or not at all, and never overwritten.
//
// This is tested at the primitive rather than through ReadAuthority because the
// defect was an interleaving, and an interleaving is not what a unit test can
// reproduce: two readers both observed no pin, both resolved — to different
// values, across a configuration reload — and both succeeded, the second
// install silently replacing the first. The race detector sees nothing, because
// every access was correctly locked. What IS testable is the property that
// makes the interleaving harmless, so that is what is asserted here: a proposed
// set is compared against the pins and installed under one hold of the write
// lock, and a set conflicting in any name installs none of its names.
func TestPinningAnAuthoritySetIsWholeOrNothing(t *testing.T) {
	first := AuthorityValueName{Name: "pin-whole", Key: "audience"}
	second := AuthorityValueName{Name: "pin-whole", Key: "binding"}
	t.Cleanup(func() {
		authorityPinsMu.Lock()
		defer authorityPinsMu.Unlock()
		delete(authorityPins, first)
		delete(authorityPins, second)
	})

	require.NoError(t, pinAuthorityValues(map[AuthorityValueName]string{first: "one"}))

	// A set whose first name conflicts must install neither name.
	err := pinAuthorityValues(map[AuthorityValueName]string{
		first:  "two",
		second: "a value nobody has seen",
	})
	require.ErrorIs(t, err, ErrAuthorityValueChanged)
	require.ErrorContains(t, err, first.String())

	pinned, ok := authorityPin(first)
	require.True(t, ok)
	require.Equal(t, "one", pinned,
		"a conflicting install must not overwrite the pin the process already minted against")
	_, ok = authorityPin(second)
	require.False(t, ok,
		"a set that conflicts in one name must install none of its names")

	// Re-installing the same values is not a conflict: reading the authority
	// twice is allowed and must agree, which is the same comparison.
	require.NoError(t, pinAuthorityValues(map[AuthorityValueName]string{first: "one"}))
}

// Concurrent installs of DIFFERENT values for one name: exactly one wins, the
// pin is the winner's, and every loser is told the value changed.
//
// The external version of this test was not evidence. It ran several readers
// against a constant environment value, so every reader resolved the same
// string and they agreed whatever the code did — it passed against the racy
// pre-fix version too. The race is only observable when the readers resolve
// DIFFERENT values, which is what a configuration reload between two reads
// produces and what this drives directly.
//
// Against the old unconditional install every goroutine succeeded and the last
// writer won, so the process ended up holding several *Authority values that
// disagreed about the audience it runs under, with the race detector seeing
// nothing because every access was correctly locked.
func TestConcurrentPinsOfDifferentValuesLeaveOneWinner(t *testing.T) {
	name := AuthorityValueName{Name: "pin-race", Key: "audience"}
	t.Cleanup(func() {
		authorityPinsMu.Lock()
		defer authorityPinsMu.Unlock()
		delete(authorityPins, name)
	})

	const readers = 32
	outcomes := make(chan error, readers)
	proposed := make([]string, readers)
	var waiting sync.WaitGroup
	start := make(chan struct{})
	for reader := range readers {
		proposed[reader] = fmt.Sprintf("audience-%02d", reader)
		waiting.Add(1)
		go func() {
			defer waiting.Done()
			<-start // all of them at once, so the interleaving is real
			outcomes <- pinAuthorityValues(map[AuthorityValueName]string{name: proposed[reader]})
		}()
	}
	close(start)
	waiting.Wait()
	close(outcomes)

	won := 0
	for err := range outcomes {
		if err == nil {
			won++
			continue
		}
		require.ErrorIs(t, err, ErrAuthorityValueChanged,
			"a loser must be told the value changed, not given some other error")
	}
	require.Equal(t, 1, won,
		"%d concurrent installs of different values must leave exactly one winner", readers)

	pinned, ok := authorityPin(name)
	require.True(t, ok)
	require.Contains(t, proposed, pinned, "the pin is one of the proposed values")
}
