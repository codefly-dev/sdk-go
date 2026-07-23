package codefly

import (
	"crypto/ed25519"
	"encoding/base64"
	"net/http"
	"strings"
	"testing"
	"time"

	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
	"github.com/stretchr/testify/require"
)

var workContextTestTime = time.Date(2026, 7, 23, 12, 34, 56, 0, time.UTC)

func workContextTestKeys() (ed25519.PublicKey, ed25519.PrivateKey) {
	seed := make([]byte, ed25519.SeedSize)
	for index := range seed {
		seed[index] = byte(index)
	}
	privateKey := ed25519.NewKeyFromSeed(seed)
	return privateKey.Public().(ed25519.PublicKey), privateKey
}

func workContextTestSigner(t *testing.T, now time.Time) *WorkContextSigner {
	t.Helper()
	_, privateKey := workContextTestKeys()
	signer, err := NewWorkContextSigner(WorkContextSignerOptions{
		Issuer:     "https://accounts.codefly.dev/work-context",
		KeyID:      "work-context-test-2026-07",
		PrivateKey: privateKey,
		Now:        func() time.Time { return now },
		Nonce:      func() (string, error) { return "nonce-fixed-for-golden", nil },
	})
	require.NoError(t, err)
	return signer
}

func workContextTestInput() StartTaskInput {
	return StartTaskInput{
		Audience:              "warden.evidence",
		TenantID:              "tenant-codefly",
		OwnerPrincipalID:      "principal-antoine",
		TaskID:                "task-roadmap",
		SessionID:             "session-root",
		AuthorizationRevision: ^uint64(0),
		ReplayPolicy:          WorkContextReplayIdempotent,
		AuthorityScopes: []*basev0.WorkScopeV1{
			{
				ResourceKind: "repository",
				Actions:      []string{"write", "read", "write"},
				ResourceIds:  []string{"repo-warden", "repo-codefly"},
			},
			{
				ResourceKind: "evidence",
				Actions:      []string{"append"},
			},
		},
		ActorChain: []*basev0.WorkActorV1{
			{
				PrincipalId:   "agent-claude-code",
				PrincipalKind: "agent",
				DelegationId:  "delegation-1",
				GrantedScopes: []*basev0.WorkScopeV1{
					{
						ResourceKind: "repository",
						Actions:      []string{"write", "read"},
						ResourceIds:  []string{"repo-warden"},
					},
					{
						ResourceKind: "evidence",
						Actions:      []string{"append"},
					},
				},
			},
		},
		AttributionTeamIDs: []string{"team-platform", "team-ai", "team-platform"},
		WorkspaceID:        "workspace-deus",
		ProjectID:          "project-warden",
		TTL:                5 * time.Minute,
	}
}

func workContextTestVerifier(t *testing.T, now time.Time) *WorkContextVerifier {
	t.Helper()
	publicKey, _ := workContextTestKeys()
	verifier, err := NewWorkContextVerifier(WorkContextVerifierOptions{
		PublicKeys: map[string]ed25519.PublicKey{
			"work-context-test-2026-07": publicKey,
		},
		Now: func() time.Time { return now },
	})
	require.NoError(t, err)
	return verifier
}

func TestWorkContextStartTaskVerifyAndCanonicalize(t *testing.T) {
	signer := workContextTestSigner(t, workContextTestTime)
	token, claims, err := signer.StartTask(workContextTestInput())
	require.NoError(t, err)
	require.NotEmpty(t, token.Encoded())
	require.LessOrEqual(t, len(token.Encoded()), WorkContextMaxTokenBytes)

	require.Equal(t, []string{"team-ai", "team-platform"}, claims.AttributionTeamIds)
	require.Equal(t, []string{"evidence", "repository"}, []string{
		claims.AuthorityScopes[0].ResourceKind,
		claims.AuthorityScopes[1].ResourceKind,
	})
	require.Equal(t, []string{"read", "write"}, claims.AuthorityScopes[1].Actions)
	require.Equal(t, []string{"repo-codefly", "repo-warden"}, claims.AuthorityScopes[1].ResourceIds)

	verified, err := workContextTestVerifier(t, workContextTestTime).Verify(token, WorkContextExpectations{
		Issuer:           "https://accounts.codefly.dev/work-context",
		Audience:         "warden.evidence",
		TenantID:         "tenant-codefly",
		OwnerPrincipalID: "principal-antoine",
		TaskID:           "task-roadmap",
		SessionID:        "session-root",
	})
	require.NoError(t, err)
	require.Equal(t, ^uint64(0), verified.AuthorizationRevision, "uint64 revision must survive the JavaScript-safe wire representation")
	require.Equal(t, "agent-claude-code", verified.ActorChain[0].PrincipalId)
}

func TestRequireWorkContextScopeUsesFinalActorEffectiveAuthority(t *testing.T) {
	_, claims, err := workContextTestSigner(t, workContextTestTime).StartTask(workContextTestInput())
	require.NoError(t, err)

	require.NoError(t, RequireWorkContextScope(claims, WorkContextScopeRequirement{
		ResourceKind:            "repository",
		Action:                  "write",
		ResourceID:              "repo-warden",
		RequireExplicitResource: true,
	}))
	require.NoError(t, RequireWorkContextScope(claims, WorkContextScopeRequirement{
		ResourceKind: "evidence",
		Action:       "append",
		ResourceID:   "codefly.execution",
	}), "empty resource IDs grant every resource of the kind")
	err = RequireWorkContextScope(claims, WorkContextScopeRequirement{
		ResourceKind:            "evidence",
		Action:                  "append",
		ResourceID:              "codefly.execution",
		RequireExplicitResource: true,
	})
	require.ErrorIs(t, err, ErrWorkContextDenied, "explicit producer binding must reject wildcard authority")

	for _, denied := range []WorkContextScopeRequirement{
		{ResourceKind: "repository", Action: "write", ResourceID: "repo-codefly"},
		{ResourceKind: "repository", Action: "admin", ResourceID: "repo-warden"},
		{ResourceKind: "repository", Action: "write"},
		{ResourceKind: "deployment", Action: "write", ResourceID: "prod"},
	} {
		err = RequireWorkContextScope(claims, denied)
		require.ErrorIs(t, err, ErrWorkContextDenied)
	}
}

func TestRequireWorkContextScopeDistinguishesInvalidClaimsFromDenial(t *testing.T) {
	err := RequireWorkContextScope(nil, WorkContextScopeRequirement{
		ResourceKind: "evidence", Action: "append", ResourceID: "codefly.execution",
	})
	require.ErrorIs(t, err, ErrWorkContextInvalid)
	require.NotErrorIs(t, err, ErrWorkContextDenied)

	_, claims, err := workContextTestSigner(t, workContextTestTime).StartTask(workContextTestInput())
	require.NoError(t, err)
	claims.ActorChain[0].GrantedScopes[0].Actions = []string{"write", "read"}
	err = RequireWorkContextScope(claims, WorkContextScopeRequirement{
		ResourceKind: "repository", Action: "read", ResourceID: "repo-warden",
	})
	require.ErrorIs(t, err, ErrWorkContextInvalid, "mutated non-canonical claims must fail closed")
}

func TestWorkContextWireGolden(t *testing.T) {
	token, _, err := workContextTestSigner(t, workContextTestTime).StartTask(workContextTestInput())
	require.NoError(t, err)

	// Shared with sdk-js. A byte-identical token proves payload field order,
	// uint64 handling, sorting, base64url, and Ed25519 signing agree.
	const expected = "eyJ0eXAiOiJjb2RlZmx5LndvcmstY29udGV4dC92MSIsImFsZ29yaXRobSI6IkVkMjU1MTkiLCJrZXlfaWQiOiJ3b3JrLWNvbnRleHQtdGVzdC0yMDI2LTA3IiwiaXNzdWVyIjoiaHR0cHM6Ly9hY2NvdW50cy5jb2RlZmx5LmRldi93b3JrLWNvbnRleHQiLCJhdWRpZW5jZSI6IndhcmRlbi5ldmlkZW5jZSIsIm5vdF9iZWZvcmVfdW5peCI6MTc4NDgxMDA5NiwiaXNzdWVkX2F0X3VuaXgiOjE3ODQ4MTAwOTYsImV4cGlyZXNfYXRfdW5peCI6MTc4NDgxMDM5Niwibm9uY2UiOiJub25jZS1maXhlZC1mb3ItZ29sZGVuIiwiYXV0aG9yaXphdGlvbl9yZXZpc2lvbiI6IjE4NDQ2NzQ0MDczNzA5NTUxNjE1IiwicmVwbGF5X3BvbGljeSI6ImlkZW1wb3RlbnQiLCJ0ZW5hbnRfaWQiOiJ0ZW5hbnQtY29kZWZseSIsIm93bmVyX3ByaW5jaXBhbF9pZCI6InByaW5jaXBhbC1hbnRvaW5lIiwidGFza19pZCI6InRhc2stcm9hZG1hcCIsInNlc3Npb25faWQiOiJzZXNzaW9uLXJvb3QiLCJhdXRob3JpdHlfc2NvcGVzIjpbeyJyZXNvdXJjZV9raW5kIjoiZXZpZGVuY2UiLCJhY3Rpb25zIjpbImFwcGVuZCJdLCJyZXNvdXJjZV9pZHMiOltdfSx7InJlc291cmNlX2tpbmQiOiJyZXBvc2l0b3J5IiwiYWN0aW9ucyI6WyJyZWFkIiwid3JpdGUiXSwicmVzb3VyY2VfaWRzIjpbInJlcG8tY29kZWZseSIsInJlcG8td2FyZGVuIl19XSwiYWN0b3JfY2hhaW4iOlt7InByaW5jaXBhbF9pZCI6ImFnZW50LWNsYXVkZS1jb2RlIiwicHJpbmNpcGFsX2tpbmQiOiJhZ2VudCIsImRlbGVnYXRpb25faWQiOiJkZWxlZ2F0aW9uLTEiLCJncmFudGVkX3Njb3BlcyI6W3sicmVzb3VyY2Vfa2luZCI6ImV2aWRlbmNlIiwiYWN0aW9ucyI6WyJhcHBlbmQiXSwicmVzb3VyY2VfaWRzIjpbXX0seyJyZXNvdXJjZV9raW5kIjoicmVwb3NpdG9yeSIsImFjdGlvbnMiOlsicmVhZCIsIndyaXRlIl0sInJlc291cmNlX2lkcyI6WyJyZXBvLXdhcmRlbiJdfV19XSwiYXR0cmlidXRpb25fdGVhbV9pZHMiOlsidGVhbS1haSIsInRlYW0tcGxhdGZvcm0iXSwid29ya3NwYWNlX2lkIjoid29ya3NwYWNlLWRldXMiLCJwcm9qZWN0X2lkIjoicHJvamVjdC13YXJkZW4ifQ.pVZhqvPljkv6SyFD9UAg_oKC4SPj4hIV1Ha0W33cCV04IeaayLDe0w8iVgbxy9wwE2AWY8dXbIMmvnVk0QQRAQ"
	require.Equal(t, expected, token.Encoded())
}

func TestWorkContextRejectsForgeryAndClaimSubstitution(t *testing.T) {
	token, _, err := workContextTestSigner(t, workContextTestTime).StartTask(workContextTestInput())
	require.NoError(t, err)
	verifier := workContextTestVerifier(t, workContextTestTime)

	segments := strings.Split(token.Encoded(), ".")
	payload, err := base64.RawURLEncoding.DecodeString(segments[0])
	require.NoError(t, err)
	payload[len(payload)/2] ^= 1
	forged, err := ParseWorkContextToken(base64.RawURLEncoding.EncodeToString(payload) + "." + segments[1])
	require.NoError(t, err)
	_, err = verifier.Verify(forged, WorkContextExpectations{Audience: "warden.evidence"})
	require.ErrorIs(t, err, ErrWorkContextInvalid)
	require.Contains(t, err.Error(), "signature")

	for name, expected := range map[string]WorkContextExpectations{
		"audience": {Audience: "other-service"},
		"tenant":   {TenantID: "tenant-mind"},
		"owner":    {OwnerPrincipalID: "principal-other"},
		"task":     {TaskID: "task-other"},
		"session":  {SessionID: "session-other"},
	} {
		t.Run(name, func(t *testing.T) {
			_, verifyErr := verifier.Verify(token, expected)
			require.ErrorIs(t, verifyErr, ErrWorkContextInvalid)
			require.Contains(t, verifyErr.Error(), "mismatch")
		})
	}
}

func TestWorkContextRejectsExpiredFutureAndExcessiveLifetime(t *testing.T) {
	token, _, err := workContextTestSigner(t, workContextTestTime).StartTask(workContextTestInput())
	require.NoError(t, err)

	_, err = workContextTestVerifier(t, workContextTestTime.Add(7*time.Minute)).Verify(token, WorkContextExpectations{})
	require.ErrorIs(t, err, ErrWorkContextInvalid)
	require.Contains(t, err.Error(), "expired")

	futureInput := workContextTestInput()
	futureInput.NotBefore = workContextTestTime.Add(2 * time.Minute)
	futureToken, _, err := workContextTestSigner(t, workContextTestTime).StartTask(futureInput)
	require.NoError(t, err)
	_, err = workContextTestVerifier(t, workContextTestTime).Verify(futureToken, WorkContextExpectations{})
	require.ErrorIs(t, err, ErrWorkContextInvalid)
	require.Contains(t, err.Error(), "not active")

	longInput := workContextTestInput()
	longInput.TTL = WorkContextMaxTTL + time.Second
	_, _, err = workContextTestSigner(t, workContextTestTime).StartTask(longInput)
	require.ErrorIs(t, err, ErrWorkContextInvalid)
	require.Contains(t, err.Error(), "lifetime")
}

func TestWorkContextChildSessionPreservesOwnershipAndAttenuates(t *testing.T) {
	signer := workContextTestSigner(t, workContextTestTime)
	parent, parentClaims, err := signer.StartTask(workContextTestInput())
	require.NoError(t, err)

	childToken, child, err := signer.StartChildSession(parent, StartChildSessionInput{
		SessionID: "session-child",
		Audience:  "warden.tools",
		Actor: &basev0.WorkActorV1{
			PrincipalId:   "tool-codefly-editor",
			PrincipalKind: "tool",
			DelegationId:  "delegation-2",
			GrantedScopes: []*basev0.WorkScopeV1{
				{
					ResourceKind: "repository",
					Actions:      []string{"write"},
					ResourceIds:  []string{"repo-warden"},
				},
			},
		},
	})
	require.NoError(t, err)
	require.Equal(t, parentClaims.TenantId, child.TenantId)
	require.Equal(t, parentClaims.OwnerPrincipalId, child.OwnerPrincipalId)
	require.Equal(t, parentClaims.TaskId, child.TaskId)
	require.Equal(t, "session-root", child.GetParentSessionId())
	require.Equal(t, "session-child", child.SessionId)
	require.Len(t, child.ActorChain, 2)

	verified, err := workContextTestVerifier(t, workContextTestTime).Verify(childToken, WorkContextExpectations{
		Audience:         "warden.tools",
		TenantID:         parentClaims.TenantId,
		OwnerPrincipalID: parentClaims.OwnerPrincipalId,
		TaskID:           parentClaims.TaskId,
		SessionID:        "session-child",
		ParentSessionID:  stringPointer("session-root"),
	})
	require.NoError(t, err)
	require.Equal(t, "tool-codefly-editor", verified.ActorChain[1].PrincipalId)
}

func TestWorkContextChildSessionRejectsScopeWidening(t *testing.T) {
	signer := workContextTestSigner(t, workContextTestTime)
	parent, _, err := signer.StartTask(workContextTestInput())
	require.NoError(t, err)

	cases := map[string][]*basev0.WorkScopeV1{
		"new action": {
			{ResourceKind: "repository", Actions: []string{"admin"}, ResourceIds: []string{"repo-warden"}},
		},
		"new resource": {
			{ResourceKind: "repository", Actions: []string{"read"}, ResourceIds: []string{"repo-mind"}},
		},
		"explicit to wildcard": {
			{ResourceKind: "repository", Actions: []string{"read"}},
		},
		"new resource kind": {
			{ResourceKind: "secrets", Actions: []string{"read"}},
		},
	}
	for name, scopes := range cases {
		t.Run(name, func(t *testing.T) {
			_, _, childErr := signer.StartChildSession(parent, StartChildSessionInput{
				SessionID: "session-child",
				Actor: &basev0.WorkActorV1{
					PrincipalId:   "actor-child",
					PrincipalKind: "agent",
					DelegationId:  "delegation-child",
					GrantedScopes: scopes,
				},
			})
			require.ErrorIs(t, childErr, ErrWorkContextInvalid)
			require.Contains(t, childErr.Error(), "widens authority")
		})
	}
}

func TestWorkContextHeaderIsSDKOwned(t *testing.T) {
	token, _, err := workContextTestSigner(t, workContextTestTime).StartTask(workContextTestInput())
	require.NoError(t, err)
	request, err := http.NewRequest(http.MethodPost, "https://warden.example/receipts", nil)
	require.NoError(t, err)
	require.NoError(t, AttachWorkContext(request, token))
	require.Equal(t, token.Encoded(), request.Header.Get(WorkContextHeaderName))

	extracted, err := WorkContextFromHeaders(request.Header)
	require.NoError(t, err)
	require.Equal(t, token.Encoded(), extracted.Encoded())
}

func TestWorkContextMalformedTokensFailClosed(t *testing.T) {
	verifier := workContextTestVerifier(t, workContextTestTime)
	for _, encoded := range []string{"", "one-segment", "a.b.c", "!!!.!!!"} {
		token, parseErr := ParseWorkContextToken(encoded)
		if parseErr == nil {
			_, parseErr = verifier.Verify(token, WorkContextExpectations{})
		}
		require.ErrorIs(t, parseErr, ErrWorkContextInvalid, encoded)
	}
}
