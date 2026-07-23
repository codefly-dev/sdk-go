package codefly

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestWorkContextJWKSVerifierCachesAndRefreshesUnknownRotation(t *testing.T) {
	firstPublic, firstPrivate := workContextJWKSKey(1)
	secondPublic, secondPrivate := workContextJWKSKey(2)
	var requests atomic.Int32
	var mu sync.RWMutex
	keys := map[string]ed25519.PublicKey{"key-1": firstPublic}
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		requests.Add(1)
		mu.RLock()
		defer mu.RUnlock()
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write(workContextJWKSJSON(t, keys))
	}))
	t.Cleanup(server.Close)

	verifier, err := NewWorkContextJWKSVerifier(WorkContextJWKSVerifierOptions{
		URL: server.URL, Now: func() time.Time { return workContextTestTime },
	})
	require.NoError(t, err)
	first := workContextJWKSToken(t, "key-1", firstPrivate)
	for range 3 {
		claims, err := verifier.Verify(t.Context(), first, WorkContextExpectations{
			Issuer: "https://accounts.codefly.dev/work-context", Audience: "warden.evidence",
		})
		require.NoError(t, err)
		require.Equal(t, "tenant-codefly", claims.GetTenantId())
	}
	require.EqualValues(t, 1, requests.Load())

	mu.Lock()
	keys = map[string]ed25519.PublicKey{"key-2": secondPublic}
	mu.Unlock()
	second := workContextJWKSToken(t, "key-2", secondPrivate)
	_, err = verifier.Verify(t.Context(), second, WorkContextExpectations{
		Issuer: "https://accounts.codefly.dev/work-context", Audience: "warden.evidence",
	})
	require.NoError(t, err)
	require.EqualValues(t, 2, requests.Load())

	// Removed keys fail after the rotation refresh. The verifier permits only
	// one unknown-key refresh per cache generation, so arbitrary key IDs cannot
	// turn verification into an unbounded request loop.
	for index := range 50 {
		_, err = verifier.Verify(
			t.Context(),
			workContextJWKSToken(t, fmt.Sprintf("unknown-%d", index), firstPrivate),
			WorkContextExpectations{},
		)
		require.Error(t, err)
	}
	_, err = verifier.Verify(t.Context(), first, WorkContextExpectations{})
	require.Error(t, err)
	require.EqualValues(t, 2, requests.Load())
}

func TestWorkContextJWKSVerifierRejectsRedirects(t *testing.T) {
	publicKey, privateKey := workContextJWKSKey(1)
	var destinationRequests atomic.Int32
	destination := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		destinationRequests.Add(1)
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write(workContextJWKSJSON(t, map[string]ed25519.PublicKey{"key-1": publicKey}))
	}))
	t.Cleanup(destination.Close)
	source := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		http.Redirect(writer, request, destination.URL, http.StatusTemporaryRedirect)
	}))
	t.Cleanup(source.Close)

	verifier, err := NewWorkContextJWKSVerifier(WorkContextJWKSVerifierOptions{
		URL: source.URL, Now: func() time.Time { return workContextTestTime },
	})
	require.NoError(t, err)
	_, err = verifier.Verify(
		t.Context(),
		workContextJWKSToken(t, "key-1", privateKey),
		WorkContextExpectations{},
	)
	require.Error(t, err)
	require.Zero(t, destinationRequests.Load())
}

func TestWorkContextJWKSVerifierSuppressesConcurrentRotationRefresh(t *testing.T) {
	firstPublic, _ := workContextJWKSKey(1)
	secondPublic, secondPrivate := workContextJWKSKey(2)
	var requests atomic.Int32
	var rotated atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		requests.Add(1)
		keys := map[string]ed25519.PublicKey{"key-1": firstPublic}
		if rotated.Load() {
			keys = map[string]ed25519.PublicKey{"key-2": secondPublic}
		}
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write(workContextJWKSJSON(t, keys))
	}))
	t.Cleanup(server.Close)
	verifier, err := NewWorkContextJWKSVerifier(WorkContextJWKSVerifierOptions{
		URL: server.URL, Now: func() time.Time { return workContextTestTime },
	})
	require.NoError(t, err)
	_, err = verifier.Verify(
		t.Context(),
		workContextJWKSToken(t, "key-1", workContextJWKSPrivateForSeed(1)),
		WorkContextExpectations{},
	)
	require.NoError(t, err)
	rotated.Store(true)

	token := workContextJWKSToken(t, "key-2", secondPrivate)
	const callers = 20
	start := make(chan struct{})
	failures := make(chan error, callers)
	var wait sync.WaitGroup
	for range callers {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			_, verifyErr := verifier.Verify(context.Background(), token, WorkContextExpectations{})
			failures <- verifyErr
		}()
	}
	close(start)
	wait.Wait()
	close(failures)
	for verifyErr := range failures {
		require.NoError(t, verifyErr)
	}
	require.EqualValues(t, 2, requests.Load())
}

func TestWorkContextJWKSVerifierRefreshesExpiredCacheWithoutRefreshingBadSignatures(t *testing.T) {
	publicKey, privateKey := workContextJWKSKey(1)
	_, wrongPrivateKey := workContextJWKSKey(2)
	var requests atomic.Int32
	var mu sync.RWMutex
	now := workContextTestTime
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write(workContextJWKSJSON(t, map[string]ed25519.PublicKey{"key-1": publicKey}))
	}))
	t.Cleanup(server.Close)
	verifier, err := NewWorkContextJWKSVerifier(WorkContextJWKSVerifierOptions{
		URL: server.URL,
		Now: func() time.Time {
			mu.RLock()
			defer mu.RUnlock()
			return now
		},
		CacheTTL: time.Minute,
	})
	require.NoError(t, err)

	_, err = verifier.Verify(
		t.Context(),
		workContextJWKSToken(t, "key-1", privateKey),
		WorkContextExpectations{},
	)
	require.NoError(t, err)
	require.EqualValues(t, 1, requests.Load())

	// A known key ID with an invalid signature is an invalid token, not a key
	// rotation signal, and must never cause network I/O.
	_, err = verifier.Verify(
		t.Context(),
		workContextJWKSToken(t, "key-1", wrongPrivateKey),
		WorkContextExpectations{},
	)
	require.Error(t, err)
	require.EqualValues(t, 1, requests.Load())

	mu.Lock()
	now = now.Add(time.Minute)
	mu.Unlock()
	_, err = verifier.Verify(
		t.Context(),
		workContextJWKSToken(t, "key-1", privateKey),
		WorkContextExpectations{},
	)
	require.NoError(t, err)
	require.EqualValues(t, 2, requests.Load())
}

func TestWorkContextJWKSVerifierBoundsAndValidatesRemoteKeys(t *testing.T) {
	cases := []struct {
		name        string
		status      int
		contentType string
		body        []byte
	}{
		{name: "status", status: http.StatusServiceUnavailable, contentType: "application/json", body: []byte(`{}`)},
		{name: "content type", status: http.StatusOK, contentType: "text/plain", body: []byte(`{}`)},
		{name: "empty", status: http.StatusOK, contentType: "application/json", body: []byte(`{"keys":[]}`)},
		{name: "wrong curve", status: http.StatusOK, contentType: "application/json", body: []byte(`{"keys":[{"kty":"OKP","crv":"X25519","kid":"key-1","x":"AA"}]}`)},
		{name: "oversized", status: http.StatusOK, contentType: "application/json", body: make([]byte, maxWorkContextJWKSBytes+1)},
	}
	_, privateKey := workContextJWKSKey(1)
	token := workContextJWKSToken(t, "key-1", privateKey)
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
				writer.Header().Set("Content-Type", testCase.contentType)
				writer.WriteHeader(testCase.status)
				_, _ = writer.Write(testCase.body)
			}))
			t.Cleanup(server.Close)
			verifier, err := NewWorkContextJWKSVerifier(WorkContextJWKSVerifierOptions{
				URL: server.URL, Now: func() time.Time { return workContextTestTime },
			})
			require.NoError(t, err)
			_, err = verifier.Verify(t.Context(), token, WorkContextExpectations{})
			require.Error(t, err)
		})
	}
}

func TestNewWorkContextJWKSVerifierRejectsUnsafeConfiguration(t *testing.T) {
	cases := []WorkContextJWKSVerifierOptions{
		{},
		{URL: "accounts.example.test/keys"},
		{URL: "file:///tmp/keys.json"},
		{URL: "https://user:secret@accounts.example.test/keys"},
		{URL: "https://accounts.example.test/keys?tenant=codefly"},
		{URL: "https://accounts.example.test/keys#fragment"},
		{URL: "https://accounts.example.test/keys", CacheTTL: time.Millisecond},
		{URL: "https://accounts.example.test/keys", CacheTTL: maxWorkContextJWKSCacheTTL + time.Second},
		{URL: "https://accounts.example.test/keys", RequestTimeout: maxWorkContextJWKSRequestTimeout + time.Millisecond},
	}
	for _, options := range cases {
		_, err := NewWorkContextJWKSVerifier(options)
		require.Error(t, err)
	}
}

func workContextJWKSKey(seedByte byte) (ed25519.PublicKey, ed25519.PrivateKey) {
	privateKey := workContextJWKSPrivateForSeed(seedByte)
	return privateKey.Public().(ed25519.PublicKey), privateKey
}

func workContextJWKSPrivateForSeed(seedByte byte) ed25519.PrivateKey {
	seed := make([]byte, ed25519.SeedSize)
	for index := range seed {
		seed[index] = seedByte + byte(index)
	}
	return ed25519.NewKeyFromSeed(seed)
}

func workContextJWKSToken(
	t *testing.T,
	keyID string,
	privateKey ed25519.PrivateKey,
) WorkContextToken {
	t.Helper()
	signer, err := NewWorkContextSigner(WorkContextSignerOptions{
		Issuer: "https://accounts.codefly.dev/work-context", KeyID: keyID,
		PrivateKey: privateKey, Now: func() time.Time { return workContextTestTime },
		Nonce: func() (string, error) {
			return fmt.Sprintf("nonce-%s", keyID), nil
		},
	})
	require.NoError(t, err)
	token, _, err := signer.StartTask(workContextTestInput())
	require.NoError(t, err)
	return token
}

func workContextJWKSJSON(
	t *testing.T,
	keys map[string]ed25519.PublicKey,
) []byte {
	t.Helper()
	document := struct {
		Keys []map[string]string `json:"keys"`
	}{}
	for keyID, publicKey := range keys {
		document.Keys = append(document.Keys, map[string]string{
			"kty": "OKP", "crv": "Ed25519", "alg": "EdDSA", "use": "sig",
			"kid": keyID, "x": base64.RawURLEncoding.EncodeToString(publicKey),
		})
	}
	payload, err := json.Marshal(document)
	require.NoError(t, err)
	return payload
}
