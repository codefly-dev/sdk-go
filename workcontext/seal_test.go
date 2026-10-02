package workcontext

import (
	"net/http"
	"net/http/httptest"
	"testing"

	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
	"github.com/stretchr/testify/require"
)

// The headline refusal: a credential minted while the host held revision N is
// refused by a verifier that has moved to N+1. It is ErrWorkContextSuperseded
// and not ErrWorkContextInvalid, because the holder's correct response is to
// mint again — and a holder that cannot tell the two apart either retries what
// will never work or gives up on what one mint would fix.
func TestSealedCredentialIsRefusedOnceTheInstallationRevisionMoves(t *testing.T) {
	token, _, err := workContextTestSigner(t, workContextTestTime).StartTask(workContextTestInput())
	require.NoError(t, err)
	verifier := workContextTestVerifier(t, workContextTestTime)

	current := workContextTestExpected()
	_, err = verifier.VerifyWorkContext(token, current)
	require.NoError(t, err, "the credential verifies on the revision it was minted for")

	moved := workContextTestExpected()
	moved.Seal.InstallationRevision++
	_, err = verifier.VerifyWorkContext(token, moved)
	require.ErrorIs(t, err, ErrWorkContextSuperseded)
	require.NotErrorIs(t, err, ErrWorkContextUnavailable, "a superseded credential must not look retryable")
	require.ErrorContains(t, err, "installation revision")
}

// A different installation is not a stale one. It can never become valid, so it
// is invalid rather than superseded: minting again on this process would
// produce a credential for the same wrong installation.
func TestSealedCredentialIsRefusedForAnotherInstallation(t *testing.T) {
	token, _, err := workContextTestSigner(t, workContextTestTime).StartTask(workContextTestInput())
	require.NoError(t, err)

	elsewhere := workContextTestExpected()
	elsewhere.Seal.InstallationID = "installation-somewhere-else"
	_, err = workContextTestVerifier(t, workContextTestTime).VerifyWorkContext(token, elsewhere)
	require.ErrorIs(t, err, ErrWorkContextInvalid)
	require.NotErrorIs(t, err, ErrWorkContextSuperseded)
	require.ErrorContains(t, err, "sealed to installation")
}

// The build is sealed so a credential cannot be carried onto another binary.
// Same principal, same installation, same revision, different build: refused.
func TestSealedCredentialIsRefusedForAnotherBuild(t *testing.T) {
	token, _, err := workContextTestSigner(t, workContextTestTime).StartTask(workContextTestInput())
	require.NoError(t, err)

	rebuilt := workContextTestExpected()
	rebuilt.Seal.BuildIncarnation = "build-incarnation-2026-07-24-b"
	_, err = workContextTestVerifier(t, workContextTestTime).VerifyWorkContext(token, rebuilt)
	require.ErrorIs(t, err, ErrWorkContextInvalid)
	require.ErrorContains(t, err, "build incarnation")
}

// A principal whose epoch has moved has had its authority changed. The
// credential was sound and is now superseded.
func TestSealedCredentialIsRefusedOnceThePrincipalEpochMoves(t *testing.T) {
	token, _, err := workContextTestSigner(t, workContextTestTime).StartTask(workContextTestInput())
	require.NoError(t, err)

	moved := workContextTestExpected()
	moved.Seal.PrincipalEpoch++
	_, err = workContextTestVerifier(t, workContextTestTime).VerifyWorkContext(token, moved)
	require.ErrorIs(t, err, ErrWorkContextSuperseded)
	require.ErrorContains(t, err, "principal epoch")
}

// A seal is whole or it is not a seal. Each field missing in turn must refuse
// at signing time, so a credential nobody can verify is never handed out.
func TestSigningRefusesAnIncompleteSeal(t *testing.T) {
	for name, mutate := range map[string]func(*Seal){
		"principal epoch":       func(s *Seal) { s.PrincipalEpoch = 0 },
		"installation id":       func(s *Seal) { s.InstallationID = "" },
		"installation revision": func(s *Seal) { s.InstallationRevision = 0 },
		"build incarnation":     func(s *Seal) { s.BuildIncarnation = "" },
	} {
		t.Run(name, func(t *testing.T) {
			input := workContextTestInput()
			seal := input.Seal
			mutate(&seal)
			input.Seal = seal
			_, _, err := workContextTestSigner(t, workContextTestTime).StartTask(input)
			require.ErrorIs(t, err, ErrWorkContextInvalid)
			require.ErrorContains(t, err, "seal ")
		})
	}
}

// A verifier that does not state where it is cannot refuse a credential from
// somewhere else, so an unstated expectation is refused rather than read as
// "accept anything".
func TestVerificationRefusesAVerifierThatStatesNoSeal(t *testing.T) {
	token, _, err := workContextTestSigner(t, workContextTestTime).StartTask(workContextTestInput())
	require.NoError(t, err)

	for name, expected := range map[string]WorkContextExpectations{
		"nothing at all":       {Delegation: &DelegationExpectations{}},
		"no installation":      {Delegation: &DelegationExpectations{}, Seal: SealExpectations{PrincipalEpoch: 7, InstallationRevision: 41, BuildIncarnation: "b"}},
		"no revision":          {Delegation: &DelegationExpectations{}, Seal: SealExpectations{PrincipalEpoch: 7, InstallationID: "i", BuildIncarnation: "b"}},
		"no build incarnation": {Delegation: &DelegationExpectations{}, Seal: SealExpectations{PrincipalEpoch: 7, InstallationID: "i", InstallationRevision: 41}},
		"no principal epoch":   {Delegation: &DelegationExpectations{}, Seal: SealExpectations{InstallationID: "i", InstallationRevision: 41, BuildIncarnation: "b"}},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := workContextTestVerifier(t, workContextTestTime).VerifyWorkContext(token, expected)
			require.ErrorIs(t, err, ErrWorkContextInvalid)
			require.ErrorContains(t, err, "expected ")
		})
	}
}

// The exact-binding rule, stated as the acceptance criterion states it: a
// credential sealed to binding X cannot be used for binding Y even when Y's
// scopes are a superset of X's. Scope containment is not binding identity, and
// a verifier that searched for a binding admitting the call would find Y.
func TestOperationBindingIsResolvedByIdentityNotByScope(t *testing.T) {
	input := workContextTestInput()
	input.OperationBinding = &OperationBinding{
		BindingID:          "binding-x",
		BindingRevision:    3,
		BindingIncarnation: "incarnation-x",
	}
	// Y admits strictly more than the credential asks for. Under a scope search
	// this credential would pass as Y.
	input.AuthorityScopes = []*basev0.WorkScopeV1{
		{ResourceKind: "evidence", Actions: []string{"append"}},
	}
	input.ActorChain = nil

	token, _, err := workContextTestSigner(t, workContextTestTime).StartTask(input)
	require.NoError(t, err)
	verifier := workContextTestVerifier(t, workContextTestTime)

	expected := workContextTestExpected()
	expected.Delegation = nil
	expected.OperationBinding = &OperationBindingExpectations{
		BindingID: "binding-x", BindingRevision: 3, BindingIncarnation: "incarnation-x",
	}
	verified, err := verifier.VerifyWorkContext(token, expected)
	require.NoError(t, err)
	require.Equal(t, "binding-x", verified.OperationBinding().BindingID)

	superset := expected
	superset.OperationBinding = &OperationBindingExpectations{
		BindingID: "binding-y", BindingRevision: 3, BindingIncarnation: "incarnation-x",
	}
	_, err = verifier.VerifyWorkContext(token, superset)
	require.ErrorIs(t, err, ErrWorkContextInvalid)
	require.ErrorContains(t, err, "sealed to operation binding")

	movedRevision := expected
	movedRevision.OperationBinding = &OperationBindingExpectations{
		BindingID: "binding-x", BindingRevision: 4, BindingIncarnation: "incarnation-x",
	}
	_, err = verifier.VerifyWorkContext(token, movedRevision)
	require.ErrorIs(t, err, ErrWorkContextSuperseded, "a binding revision that moved is re-mintable")

	otherIncarnation := expected
	otherIncarnation.OperationBinding = &OperationBindingExpectations{
		BindingID: "binding-x", BindingRevision: 3, BindingIncarnation: "incarnation-z",
	}
	_, err = verifier.VerifyWorkContext(token, otherIncarnation)
	require.ErrorIs(t, err, ErrWorkContextInvalid)
	require.ErrorContains(t, err, "incarnation")
}

// An operation credential presented where no binding was named is refused, and
// so is an ordinary credential presented where one was. Neither direction is a
// tolerable default: the first would let a credential issued to act through one
// binding act outside every binding, and the second would let a call that needs
// a binding proceed without one.
func TestOperationBindingPresenceIsCheckedBothWays(t *testing.T) {
	signer := workContextTestSigner(t, workContextTestTime)
	verifier := workContextTestVerifier(t, workContextTestTime)

	bound := workContextTestInput()
	bound.OperationBinding = &OperationBinding{
		BindingID: "binding-x", BindingRevision: 1, BindingIncarnation: "incarnation-x",
	}
	boundToken, _, err := signer.StartTask(bound)
	require.NoError(t, err)
	_, err = verifier.VerifyWorkContext(boundToken, workContextTestExpected())
	require.ErrorIs(t, err, ErrWorkContextInvalid)
	require.ErrorContains(t, err, "presented where no binding was named")

	plainToken, _, err := signer.StartTask(workContextTestInput())
	require.NoError(t, err)
	expectsBinding := workContextTestExpected()
	expectsBinding.OperationBinding = &OperationBindingExpectations{
		BindingID: "binding-x", BindingRevision: 1, BindingIncarnation: "incarnation-x",
	}
	_, err = verifier.VerifyWorkContext(plainToken, expectsBinding)
	require.ErrorIs(t, err, ErrWorkContextInvalid)
	require.ErrorContains(t, err, "seals none")
}

// An operation binding travels whole or not at all. A payload carrying part of
// one would otherwise resolve to a binding identity nobody approved.
func TestPartialOperationBindingOnTheWireIsRefused(t *testing.T) {
	_, seal, binding, err := readSealedToken(mustSignBoundToken(t))
	require.NoError(t, err)
	require.NotNil(t, binding)
	require.Equal(t, workContextTestSeal(), seal)

	id := "binding-x"
	_, _, err = sealFromPayload(workContextPayload{
		PrincipalEpoch:       "7",
		InstallationID:       "installation-0a9f",
		InstallationRevision: "41",
		BuildIncarnation:     "build",
		OperationBindingID:   &id,
	})
	require.ErrorIs(t, err, ErrWorkContextInvalid)
	require.ErrorContains(t, err, "id, revision and incarnation together")
}

func mustSignBoundToken(t *testing.T) WorkContextToken {
	t.Helper()
	input := workContextTestInput()
	input.OperationBinding = &OperationBinding{
		BindingID: "binding-x", BindingRevision: 3, BindingIncarnation: "incarnation-x",
	}
	token, _, err := workContextTestSigner(t, workContextTestTime).StartTask(input)
	require.NoError(t, err)
	return token
}

// Deliverable 3: the installation reaches the far end on every outbound
// request, beside the capability rather than inside it only.
func TestAttachCarriesTheSealedInstallationOnEveryRequest(t *testing.T) {
	token, _, err := workContextTestSigner(t, workContextTestTime).StartTask(workContextTestInput())
	require.NoError(t, err)
	request := httptest.NewRequest(http.MethodGet, "https://service.internal/v1/records", nil)
	require.NoError(t, AttachWorkContext(request, token))

	seal := workContextTestSeal()
	require.Equal(t, seal.InstallationID, request.Header.Get(InstallationIDHeaderName))
	require.Equal(t, "41", request.Header.Get(InstallationRevisionHeaderName))
	require.Equal(t, token.Encoded(), request.Header.Get(WorkContextHeaderName))
}

// A token with no readable seal cannot be attached at all. Attaching it bare
// would produce a request that looks authorized and names no installation,
// which is the shape the whole change exists to remove.
func TestAttachRefusesAnUnsealedToken(t *testing.T) {
	unsealed, err := ParseWorkContextToken("e30.AAAA")
	require.NoError(t, err)
	request := httptest.NewRequest(http.MethodGet, "https://service.internal/v1/records", nil)
	require.ErrorIs(t, AttachWorkContext(request, unsealed), ErrWorkContextInvalid)
	require.Empty(t, request.Header.Get(WorkContextHeaderName))
	require.Empty(t, request.Header.Get(InstallationIDHeaderName))
}

// Deliverable 2's separate checks. The owner is the delegating principal and
// the final actor is the calling one; matching one says nothing about the other.
func TestDelegatingAndCallingPrincipalsAreCheckedSeparately(t *testing.T) {
	token, _, err := workContextTestSigner(t, workContextTestTime).StartTask(workContextTestInput())
	require.NoError(t, err)
	verifier := workContextTestVerifier(t, workContextTestTime)

	both := workContextTestExpected()
	both.OwnerPrincipalID, both.OwnerPrincipalKind = "principal-antoine", "user"
	both.Delegation = &DelegationExpectations{
		PrincipalID: "agent-claude-code", PrincipalKind: "agent", DelegationID: "delegation-1",
	}
	_, err = verifier.VerifyWorkContext(token, both)
	require.NoError(t, err)

	// The owner this verifier expects, a caller it does not.
	wrongCaller := both
	wrongCaller.Delegation = &DelegationExpectations{PrincipalID: "agent-someone-else"}
	_, err = verifier.VerifyWorkContext(token, wrongCaller)
	require.ErrorIs(t, err, ErrWorkContextInvalid)
	require.ErrorContains(t, err, "caller mismatch")

	// The caller this verifier expects, an owner it does not.
	wrongOwner := both
	wrongOwner.OwnerPrincipalID = "principal-other"
	_, err = verifier.VerifyWorkContext(token, wrongOwner)
	require.ErrorIs(t, err, ErrWorkContextInvalid)
	require.ErrorContains(t, err, "owner mismatch")

	// A verifier that never considered delegation refuses a delegated caller
	// rather than checking only the principal that delegated.
	directOnly := both
	directOnly.Delegation = nil
	_, err = verifier.VerifyWorkContext(token, directOnly)
	require.ErrorIs(t, err, ErrWorkContextInvalid)
	require.ErrorContains(t, err, "only a direct owner call is accepted")
}

// The owner's kind is required, and an agent owner must name its agent
// manifest identity. Either half without the other is a credential that claims
// to be an agent nothing can name, or names an agent while presenting as a user.
func TestOwnerKindAndAgentIdentityAreOneFact(t *testing.T) {
	signer := workContextTestSigner(t, workContextTestTime)

	missingKind := workContextTestInput()
	missingKind.OwnerPrincipalKind = ""
	_, _, err := signer.StartTask(missingKind)
	require.ErrorIs(t, err, ErrWorkContextInvalid)
	require.ErrorContains(t, err, "owner_principal_kind is required")

	agentWithoutIdentity := workContextTestInput()
	agentWithoutIdentity.OwnerPrincipalKind = PrincipalKindAgent
	_, _, err = signer.StartTask(agentWithoutIdentity)
	require.ErrorIs(t, err, ErrWorkContextInvalid)
	require.ErrorContains(t, err, "owner_agent_id is required")

	userWithIdentity := workContextTestInput()
	userWithIdentity.OwnerAgentID = "agent-manifest-1"
	_, _, err = signer.StartTask(userWithIdentity)
	require.ErrorIs(t, err, ErrWorkContextInvalid)
	require.ErrorContains(t, err, `owner_agent_id is set on a "user" owner`)

	agent := workContextTestInput()
	agent.OwnerPrincipalKind = PrincipalKindAgent
	agent.OwnerAgentID = "agent-manifest-1"
	token, _, err := signer.StartTask(agent)
	require.NoError(t, err)
	expected := workContextTestExpected()
	expected.OwnerPrincipalKind = PrincipalKindAgent
	verified, err := workContextTestVerifier(t, workContextTestTime).VerifyWorkContext(token, expected)
	require.NoError(t, err)
	require.Equal(t, "agent-manifest-1", verified.Claims().GetOwnerAgentId())
}

// An exchange moves authority between boundaries inside one execution, so the
// seal is the same on both sides. A hop that could restate it would be a hop
// that could move a credential onto another build or another installation.
func TestExchangeAndChildSessionCarryTheSealUnchanged(t *testing.T) {
	signer := workContextTestSigner(t, workContextTestTime)
	parent, _, err := signer.StartTask(workContextTestInput())
	require.NoError(t, err)

	exchanged, _, err := signer.ExchangeWorkContextAudience(parent, ExchangeWorkContextAudienceInput{
		Audience: "warden.gateway",
	})
	require.NoError(t, err)
	child, _, err := signer.StartChildSession(parent, StartChildSessionInput{
		SessionID: "session-child", Audience: "warden.tools",
		Actor: &basev0.WorkActorV1{
			PrincipalId: "tool-editor", PrincipalKind: "tool", DelegationId: "delegation-2",
			GrantedScopes: []*basev0.WorkScopeV1{{ResourceKind: "evidence", Actions: []string{"append"}}},
		},
	})
	require.NoError(t, err)
	session, _, err := signer.StartSession(parent, StartRootSessionInput{
		SessionID: "session-second", Audience: "warden.evidence",
	})
	require.NoError(t, err)

	for name, token := range map[string]WorkContextToken{
		"audience exchange": exchanged,
		"child session":     child,
		"root session":      session,
	} {
		t.Run(name, func(t *testing.T) {
			_, seal, binding, err := readSealedToken(token)
			require.NoError(t, err)
			require.Equal(t, workContextTestSeal(), seal)
			require.Nil(t, binding)
		})
	}
}
