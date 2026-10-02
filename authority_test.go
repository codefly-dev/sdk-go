package codefly_test

import (
	"testing"

	codefly "github.com/codefly-dev/sdk-go"
	"github.com/stretchr/testify/require"
)

// Deliverable 5: a value that carries authority is read once, at boot, and the
// SDK refuses a change to it under a running process. The host is the authority
// for these values; a process that already minted a credential against the old
// one cannot be made correct by noticing the new one.
func TestAuthorityValuesAreReadOnceAndADriftIsRefused(t *testing.T) {
	t.Setenv("CODEFLY__WORKSPACE_CONFIGURATION__MINT_ONE__AUDIENCE", "warden.evidence")
	require.NoError(t, codefly.LoadEnvironmentVariables())

	authority, err := codefly.ReadAuthority(t.Context(), codefly.AuthorityValueName{Name: "mint-one", Key: "audience"})
	require.NoError(t, err)
	value, err := authority.Value("mint-one", "audience")
	require.NoError(t, err)
	require.Equal(t, "warden.evidence", value)
	require.NoError(t, authority.Recheck(t.Context()), "nothing has moved yet")

	// The host changes the value under the running process.
	t.Setenv("CODEFLY__WORKSPACE_CONFIGURATION__MINT_ONE__AUDIENCE", "warden.something-else")
	require.NoError(t, codefly.LoadEnvironmentVariables())

	// The frozen read is unchanged — that is what "read once" means.
	value, err = authority.Value("mint-one", "audience")
	require.NoError(t, err)
	require.Equal(t, "warden.evidence", value)

	// And the drift is an error, not a reload.
	err = authority.Recheck(t.Context())
	require.ErrorIs(t, err, codefly.ErrAuthorityValueChanged)
	require.ErrorContains(t, err, "mint-one/audience")
}

// An authority-bearing value withdrawn is a withdrawal, not an absence to
// tolerate. A process whose audience has been removed must not keep serving on
// the one it remembers.
func TestAuthorityValueWithdrawnIsAChange(t *testing.T) {
	t.Setenv("CODEFLY__WORKSPACE_CONFIGURATION__MINT_GONE__AUDIENCE", "warden.evidence")
	require.NoError(t, codefly.LoadEnvironmentVariables())
	authority, err := codefly.ReadAuthority(t.Context(), codefly.AuthorityValueName{Name: "mint-gone", Key: "audience"})
	require.NoError(t, err)

	t.Setenv("CODEFLY__WORKSPACE_CONFIGURATION__MINT_GONE__AUDIENCE", "")
	require.NoError(t, codefly.LoadEnvironmentVariables())
	err = authority.Recheck(t.Context())
	require.ErrorIs(t, err, codefly.ErrAuthorityValueChanged)
	require.ErrorContains(t, err, "no longer configured")
}

// The ordinary accessor is the one product code reaches for by habit, so it
// must not be the way around the pin. A pinned name answers from the boot read,
// and a drifted live value is refused there too.
func TestWorkspaceValueAnswersFromThePinAndRefusesADrift(t *testing.T) {
	t.Setenv("CODEFLY__WORKSPACE_CONFIGURATION__MINT_PINNED__BINDING", "binding-0a9f")
	require.NoError(t, codefly.LoadEnvironmentVariables())
	_, err := codefly.ReadAuthority(t.Context(), codefly.AuthorityValueName{Name: "mint-pinned", Key: "binding"})
	require.NoError(t, err)

	value, err := codefly.For(t.Context()).WorkspaceValue("mint-pinned", "binding")
	require.NoError(t, err)
	require.Equal(t, "binding-0a9f", value)

	t.Setenv("CODEFLY__WORKSPACE_CONFIGURATION__MINT_PINNED__BINDING", "binding-somebody-elses")
	require.NoError(t, codefly.LoadEnvironmentVariables())
	_, err = codefly.For(t.Context()).WorkspaceValue("mint-pinned", "binding")
	require.ErrorIs(t, err, codefly.ErrAuthorityValueChanged)

	// A name nobody pinned is untouched by any of this.
	t.Setenv("CODEFLY__WORKSPACE_CONFIGURATION__MINT_FREE__LABEL", "first")
	require.NoError(t, codefly.LoadEnvironmentVariables())
	label, err := codefly.For(t.Context()).WorkspaceValue("mint-free", "label")
	require.NoError(t, err)
	require.Equal(t, "first", label)
	t.Setenv("CODEFLY__WORKSPACE_CONFIGURATION__MINT_FREE__LABEL", "second")
	require.NoError(t, codefly.LoadEnvironmentVariables())
	label, err = codefly.For(t.Context()).WorkspaceValue("mint-free", "label")
	require.NoError(t, err)
	require.Equal(t, "second", label, "only authority-bearing values are frozen")
}

// A partially-known authority is not an authority. Continuing with the names
// that did resolve would let a process serve under an identity it could not
// fully establish, which is the quiet half of a missing credential.
func TestReadAuthorityFailsWholeWhenOneNameIsMissing(t *testing.T) {
	t.Setenv("CODEFLY__WORKSPACE_CONFIGURATION__MINT_PARTIAL__AUDIENCE", "warden.evidence")
	require.NoError(t, codefly.LoadEnvironmentVariables())

	_, err := codefly.ReadAuthority(t.Context(),
		codefly.AuthorityValueName{Name: "mint-partial", Key: "audience"},
		codefly.AuthorityValueName{Name: "mint-partial", Key: "binding"},
	)
	require.ErrorIs(t, err, codefly.ErrAuthorityValueMissing)
	require.ErrorContains(t, err, "mint-partial/binding")

	// Nothing was pinned, so the ordinary accessor still answers live.
	value, err := codefly.For(t.Context()).WorkspaceValue("mint-partial", "audience")
	require.NoError(t, err)
	require.Equal(t, "warden.evidence", value)
}

// A name the process never declared is not answerable from a frozen set.
// Declaring the set up front is what makes "read once" checkable at all.
func TestAuthorityRefusesANameItNeverRead(t *testing.T) {
	t.Setenv("CODEFLY__WORKSPACE_CONFIGURATION__MINT_DECLARED__AUDIENCE", "warden.evidence")
	require.NoError(t, codefly.LoadEnvironmentVariables())
	authority, err := codefly.ReadAuthority(t.Context(), codefly.AuthorityValueName{Name: "mint-declared", Key: "audience"})
	require.NoError(t, err)

	_, err = authority.Value("mint-declared", "binding")
	require.ErrorIs(t, err, codefly.ErrAuthorityValueUnread)

	var never *codefly.Authority
	_, err = never.Value("mint-declared", "audience")
	require.ErrorIs(t, err, codefly.ErrAuthorityValueUnread)
	require.ErrorIs(t, never.Recheck(t.Context()), codefly.ErrAuthorityValueUnread)

	_, err = codefly.ReadAuthority(t.Context())
	require.ErrorIs(t, err, codefly.ErrAuthorityValueMissing)
	_, err = codefly.ReadAuthority(t.Context(), codefly.AuthorityValueName{Name: "   ", Key: "audience"})
	require.ErrorIs(t, err, codefly.ErrAuthorityValueMissing)
}

// Reading the same name twice is allowed and must agree. The second read is
// held to the pin exactly as Recheck would hold it, so a process cannot obtain
// a second, differently-valued authority by asking again.
func TestReadingTheAuthorityTwiceMustAgree(t *testing.T) {
	t.Setenv("CODEFLY__WORKSPACE_CONFIGURATION__MINT_TWICE__AUDIENCE", "warden.evidence")
	require.NoError(t, codefly.LoadEnvironmentVariables())
	name := codefly.AuthorityValueName{Name: "mint-twice", Key: "audience"}
	first, err := codefly.ReadAuthority(t.Context(), name)
	require.NoError(t, err)
	second, err := codefly.ReadAuthority(t.Context(), name)
	require.NoError(t, err)
	firstValue, err := first.Value(name.Name, name.Key)
	require.NoError(t, err)
	secondValue, err := second.Value(name.Name, name.Key)
	require.NoError(t, err)
	require.Equal(t, firstValue, secondValue)
	require.Equal(t, []codefly.AuthorityValueName{name}, second.Names())
	require.False(t, second.ReadAt().IsZero())

	t.Setenv("CODEFLY__WORKSPACE_CONFIGURATION__MINT_TWICE__AUDIENCE", "warden.other")
	require.NoError(t, codefly.LoadEnvironmentVariables())
	_, err = codefly.ReadAuthority(t.Context(), name)
	require.ErrorIs(t, err, codefly.ErrAuthorityValueChanged)
}

// A secret-namespace value is authority-bearing in the same way, so the
// two-namespace lookup WorkspaceValue performs has to be the one ReadAuthority
// performs too — otherwise a binding delivered as a secret would read as
// missing at boot and live afterwards.
func TestAuthorityReadsTheSecretNamespaceToo(t *testing.T) {
	t.Setenv("CODEFLY__WORKSPACE_SECRET_CONFIGURATION__MINT_SECRET__BINDING", "binding-secret")
	require.NoError(t, codefly.LoadEnvironmentVariables())
	authority, err := codefly.ReadAuthority(t.Context(), codefly.AuthorityValueName{Name: "mint-secret", Key: "binding"})
	require.NoError(t, err)
	value, err := authority.Value("mint-secret", "binding")
	require.NoError(t, err)
	require.Equal(t, "binding-secret", value)
}
