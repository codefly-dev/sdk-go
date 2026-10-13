package ingress

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	codefly "github.com/codefly-dev/sdk-go"
)

// backend is a stand-in for the module's generated REST listener, on loopback.
func backend(t *testing.T, handler http.HandlerFunc) *url.URL {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	target, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	return target
}

func TestTheFrontForwardsTheRequestWhole(t *testing.T) {
	type seen struct {
		method, path, query, body, authorization, custom, forwardedFor, host string
	}
	got := make(chan seen, 1)
	target := backend(t, func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		got <- seen{r.Method, r.URL.Path, r.URL.RawQuery, string(body), r.Header.Get("Authorization"), r.Header.Get("X-Codefly-Test"), r.Header.Get("X-Forwarded-For"), r.Host}
		w.Header().Set("X-Answer", "yes")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte("answered"))
	})
	front := httptest.NewServer(frontTo(target))
	t.Cleanup(front.Close)

	req, err := http.NewRequest(http.MethodPost, front.URL+"/v1/widgets/things/42?view=full&x=1", strings.NewReader(`{"name":"w"}`))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer viewer-token")
	req.Header.Set("X-Codefly-Test", "kept")
	req.Header.Set("X-Forwarded-For", "203.0.113.9")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	answer, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusCreated || string(answer) != "answered" || resp.Header.Get("X-Answer") != "yes" {
		t.Fatalf("answer %d %q %q", resp.StatusCode, answer, resp.Header.Get("X-Answer"))
	}
	s := <-got
	if s.method != http.MethodPost || s.path != "/v1/widgets/things/42" || s.query != "view=full&x=1" || s.body != `{"name":"w"}` {
		t.Errorf("forwarded %+v", s)
	}
	if s.authorization != "Bearer viewer-token" || s.custom != "kept" {
		t.Errorf("headers lost: %+v", s)
	}
	if s.forwardedFor != "" {
		t.Errorf("X-Forwarded-For = %q: the front adds none and drops the caller's", s.forwardedFor)
	}
	if s.host != target.Host {
		t.Errorf("Host = %q, want the target's %q", s.host, target.Host)
	}
}

func TestTheFrontFlushesAStreamAsItIsWritten(t *testing.T) {
	release := make(chan struct{})
	target := backend(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("first\n"))
		w.(http.Flusher).Flush()
		<-release
		_, _ = w.Write([]byte("second\n"))
	})
	front := httptest.NewServer(frontTo(target))
	t.Cleanup(front.Close)
	defer close(release)

	resp, err := http.Get(front.URL + "/v1/widgets/stream")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	line := make(chan string, 1)
	go func() {
		first, _ := bufio.NewReader(resp.Body).ReadString('\n')
		line <- first
	}()
	select {
	case first := <-line:
		if first != "first\n" {
			t.Fatalf("first chunk %q", first)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the first chunk was held back until the stream ended")
	}
}

func TestTheFrontAnswersAnUnavailableEndpointWithoutDetail(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	front := httptest.NewServer(frontTo(&url.URL{Scheme: "http", Host: addr}))
	t.Cleanup(front.Close)
	resp, err := http.Get(front.URL + "/v1/widgets/x")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway || strings.Contains(string(body), addr) {
		t.Errorf("answer %d %q", resp.StatusCode, body)
	}
}

func TestTheFrontIsLoopbackOnly(t *testing.T) {
	for _, tc := range []struct {
		host string
		port uint16
		want string
	}{
		{"localhost", 8080, "http://127.0.0.1:8080"},
		{"127.0.0.1", 8080, "http://127.0.0.1:8080"},
		{"::1", 8080, "http://[::1]:8080"},
		{"[::1]", 8080, "http://[::1]:8080"},
		{"10.0.0.5", 8080, ""},
		{"api.widgets.svc", 8080, ""},
		{"0.0.0.0", 8080, ""},
		{"localhost", 0, ""},
	} {
		got, err := loopbackTarget(tc.host, tc.port)
		if tc.want == "" {
			if err == nil {
				t.Errorf("loopbackTarget(%q, %d) = %s; want a refusal", tc.host, tc.port, got)
			}
			continue
		}
		if err != nil || got.String() != tc.want {
			t.Errorf("loopbackTarget(%q, %d) = %v, %v; want %s", tc.host, tc.port, got, err, tc.want)
		}
	}
}

func TestFrontResolvesThisServicesOwnEndpoint(t *testing.T) {
	t.Setenv("CODEFLY__MODULE", "widgets")
	t.Setenv("CODEFLY__SERVICE", "api")
	t.Setenv("CODEFLY__ENDPOINT__WIDGETS__API__REST__REST", "http://localhost:18080")
	// A service resolves endpoints as the module Init pinned, as every
	// generated main does before its configure hook runs.
	if _, err := codefly.Init(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err := Front(t.Context(), ""); err != nil {
		t.Fatalf("Front(rest) with a loopback endpoint: %v", err)
	}
	t.Setenv("CODEFLY__ENDPOINT__WIDGETS__API__REST__REST", "http://api.widgets.svc:8080")
	if err := codefly.LoadEnvironmentVariables(); err != nil {
		t.Fatal(err)
	}
	if _, err := Front(t.Context(), "rest"); err == nil || !strings.Contains(err.Error(), "not loopback") {
		t.Errorf("a non-loopback resolution was fronted: %v", err)
	}
	if err := os.Unsetenv("CODEFLY__ENDPOINT__WIDGETS__API__REST__REST"); err != nil {
		t.Fatal(err)
	}
	if err := codefly.LoadEnvironmentVariables(); err != nil {
		t.Fatal(err)
	}
	if _, err := Front(t.Context(), "rest"); err == nil {
		t.Error("an unresolved endpoint was fronted")
	}
}
