package codefly

import (
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
