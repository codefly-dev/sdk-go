package ingress

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	codefly "github.com/codefly-dev/sdk-go"
	"github.com/codefly-dev/sdk-go/workload"
)

// host is a stand-in for the host's report endpoint: TLS under identity,
// verifying callers against the cell, answering each report from answers in
// turn (the last one repeats) and recording what it was sent.
type host struct {
	mu       sync.Mutex
	answers  []int
	reports  []hostReport
	endpoint string
}

type hostReport struct {
	authorization, contentType string
	body                       map[string]string
	presented                  string
}

func (c *cell) host(t *testing.T, identity string, answers ...int) *host {
	t.Helper()
	h := &host{answers: answers}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{
		ReadHeaderTimeout: 5 * time.Second,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			h.mu.Lock()
			defer h.mu.Unlock()
			report := hostReport{authorization: r.Header.Get("Authorization"), contentType: r.Header.Get("Content-Type")}
			raw, _ := io.ReadAll(r.Body)
			_ = json.Unmarshal(raw, &report.body)
			if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 && len(r.TLS.PeerCertificates[0].URIs) == 1 {
				report.presented = r.TLS.PeerCertificates[0].URIs[0].String()
			}
			h.reports = append(h.reports, report)
			status := h.answers[len(h.answers)-1]
			if len(h.reports) <= len(h.answers) {
				status = h.answers[len(h.reports)-1]
			}
			if r.URL.Path != ReportPath {
				status = http.StatusNotFound
			}
			w.WriteHeader(status)
		}),
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{*c.identity(t, identity)},
			ClientCAs:    c.roots,
			ClientAuth:   tls.RequireAndVerifyClientCert,
			MinVersion:   tls.VersionTLS13,
		},
	}
	go func() { _ = server.ServeTLS(ln, "", "") }()
	t.Cleanup(func() { _ = server.Close() })
	h.endpoint = "https://" + ln.Addr().String() + ReportPath
	return h
}

func (h *host) received() []hostReport {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]hostReport(nil), h.reports...)
}

var fast = backoff{first: 10 * time.Millisecond, ceiling: 40 * time.Millisecond, refused: 50 * time.Millisecond}

// serve starts an ingress on an ephemeral loopback port.
func serve(t *testing.T, files workload.Files, reportURL string, opts ...Option) *Ingress {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	all := append([]Option{
		WithFiles(files), WithListener(ln), WithReportURL(reportURL), WithPrefix("widgets"),
		WithAdvertisedOrigin("widgets.modules.svc:" + strings.Split(ln.Addr().String(), ":")[1]),
		func(o *options) { o.backoff = fast },
	}, opts...)
	in, err := Serve(context.Background(), http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("served"))
	}), all...)
	if err != nil {
		_ = ln.Close()
		t.Fatalf("Serve: %v", err)
	}
	t.Cleanup(func() { _ = in.Close() })
	return in
}

func TestTheIngressServesOnlyTheGatewayOverTLS(t *testing.T) {
	c := newCell(t)
	files := c.files(t, testPrincipal)
	h := c.host(t, testGatewayPrincipal, http.StatusNoContent)
	in := serve(t, files, h.endpoint)
	addr := "https://" + in.Addr().String() + "/v1/widgets/thing"

	resp, err := c.caller(c.identity(t, testGatewayPrincipal), false).Get(addr)
	if err != nil {
		t.Fatalf("the gateway was refused: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if string(body) != "served" {
		t.Fatalf("served %q", body)
	}
	if _, err := c.caller(c.identity(t, testNeighbour), false).Get(addr); err == nil {
		t.Error("a workload from the same anchor that the admitted set does not name was served")
	}
	if resp, err := (&http.Client{Timeout: 5 * time.Second}).Get("http://" + in.Addr().String() + "/"); err == nil {
		raw, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if string(raw) == "served" {
			t.Error("plain HTTP was served")
		}
	}
	if !strings.HasPrefix(in.Origin(), "https://widgets.modules.svc:") {
		t.Errorf("Origin = %q", in.Origin())
	}
}

func TestTheReportIsRetriedUntilRecordedAndThenStops(t *testing.T) {
	c := newCell(t)
	files := c.files(t, testPrincipal)
	h := c.host(t, testGatewayPrincipal, http.StatusServiceUnavailable, http.StatusBadGateway, http.StatusNoContent)
	in := serve(t, files, h.endpoint)
	select {
	case <-in.Reported():
	case <-time.After(5 * time.Second):
		t.Fatalf("the report was never recorded: %+v", h.received())
	}
	time.Sleep(150 * time.Millisecond)
	reports := h.received()
	if len(reports) != 3 {
		t.Fatalf("the host was sent %d reports; want 3 (two outages, then recorded, then nothing)", len(reports))
	}
	last := reports[2]
	if last.authorization != "Bearer projected-token" {
		t.Errorf("Authorization = %q: the projected token, read fresh from its file", last.authorization)
	}
	if last.contentType != "application/json" {
		t.Errorf("Content-Type = %q", last.contentType)
	}
	if last.body["prefix"] != "widgets" || last.body["upstream"] != in.Origin() || len(last.body) != 2 {
		t.Errorf("body = %v; want prefix widgets and upstream %s, and nothing else", last.body, in.Origin())
	}
	if last.presented != testPrincipal {
		t.Errorf("the report presented %q; want this workload's own SVID %q", last.presented, testPrincipal)
	}
}

func TestARefusalIsRetriedSlowlyAndARotatedTokenIsRead(t *testing.T) {
	c := newCell(t)
	files := c.files(t, testPrincipal)
	h := c.host(t, testGatewayPrincipal, http.StatusForbidden, http.StatusNoContent)
	in := serve(t, files, h.endpoint)
	// Rotated between the refusal and the retry.
	writeFile(t, files.Token, "rotated-token\n")
	select {
	case <-in.Reported():
	case <-time.After(5 * time.Second):
		t.Fatalf("a refusal was not retried: %+v", h.received())
	}
	reports := h.received()
	if len(reports) != 2 || reports[1].authorization != "Bearer rotated-token" {
		t.Fatalf("reports = %+v; want the retry to carry the rotated token", reports)
	}
}

func TestTheReportIsNeverMadeToAHostTheSetsDoNotName(t *testing.T) {
	c := newCell(t)
	files := c.files(t, testPrincipal)
	impostor := c.host(t, testNeighbour, http.StatusNoContent)
	in := serve(t, files, impostor.endpoint)
	select {
	case <-in.Reported():
		t.Fatal("a host holding a certificate from the anchor, not named as the gateway, recorded the report")
	case <-time.After(300 * time.Millisecond):
	}
	if got := impostor.received(); len(got) != 0 {
		t.Fatalf("the projected token reached a destination the provisioned sets do not name: %+v", got)
	}
}

func TestServeRefusesWhatItCannotResolve(t *testing.T) {
	c := newCell(t)
	files := c.files(t, testPrincipal)
	h := c.host(t, testGatewayPrincipal, http.StatusNoContent)
	handler := http.NotFoundHandler()
	refused := func(t *testing.T, names string, opts ...Option) {
		t.Helper()
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = ln.Close() }()
		in, err := Serve(context.Background(), handler, append([]Option{WithListener(ln), WithPrefix("widgets"), WithAdvertisedOrigin("widgets.modules.svc:9443")}, opts...)...)
		if err == nil {
			_ = in.Close()
			t.Fatalf("Serve started; want a refusal naming %s", names)
		}
		if !strings.Contains(err.Error(), names) {
			t.Errorf("the refusal %q does not name %s", err, names)
		}
	}
	without := func(edit func(*workload.Files)) workload.Files {
		f := files
		edit(&f)
		return f
	}
	t.Run("no identity", func(t *testing.T) {
		refused(t, workload.CertFileOverride, WithFiles(without(func(f *workload.Files) { f.Cert = "" })), WithReportURL(h.endpoint))
	})
	t.Run("no admitted callers", func(t *testing.T) {
		refused(t, workload.AllowedCallersFileKey, WithFiles(without(func(f *workload.Files) { f.AllowedCallers = "" })), WithReportURL(h.endpoint))
	})
	t.Run("no token", func(t *testing.T) {
		refused(t, workload.TokenFileKey, WithFiles(without(func(f *workload.Files) { f.Token = "" })), WithReportURL(h.endpoint))
	})
	t.Run("no gateway set", func(t *testing.T) {
		refused(t, workload.GatewayPeersFileKey, WithFiles(without(func(f *workload.Files) { f.GatewayPeers = "" })), WithReportURL(h.endpoint))
	})
	t.Run("disjoint gateway and mint sets", func(t *testing.T) {
		f := c.files(t, testPrincipal)
		writeFile(t, f.MintPeers, testNeighbour+"\n")
		refused(t, "both provisioned sets", WithFiles(f), WithReportURL(h.endpoint))
	})
	t.Run("a plaintext destination", func(t *testing.T) {
		refused(t, "not https", WithFiles(files), WithReportURL("http://gw.test:8443"+ReportPath))
	})
	t.Run("another path", func(t *testing.T) {
		refused(t, ReportPath, WithFiles(files), WithReportURL("https://gw.test:8443/modules/_work-context"))
	})
	t.Run("a destination carrying a query", func(t *testing.T) {
		refused(t, "query", WithFiles(files), WithReportURL("https://gw.test:8443"+ReportPath+"?token=x"))
	})
	t.Run("no destination at all", func(t *testing.T) {
		t.Setenv("CODEFLY__CREDENTIAL_MINT_URL", "")
		refused(t, CredentialMintURL, WithFiles(files))
	})
	t.Run("an origin that names no machine", func(t *testing.T) {
		refused(t, "unspecified", WithFiles(files), WithReportURL(h.endpoint), WithAdvertisedOrigin("0.0.0.0:9443"))
	})
	if _, err := Serve(context.Background(), nil); err == nil {
		t.Error("Serve with no handler started")
	}
}

func TestTheReportGoesToTheMintsOrigin(t *testing.T) {
	t.Setenv("CODEFLY__CREDENTIAL_MINT_URL", "https://gw.test:8443/modules/_work-context")
	got, err := resolveReportURL("")
	if err != nil || got != "https://gw.test:8443"+ReportPath {
		t.Fatalf("resolveReportURL = %q, %v", got, err)
	}
	t.Setenv("CODEFLY__CREDENTIAL_MINT_URL", "::")
	if _, err := resolveReportURL(""); err == nil {
		t.Error("an unparsable mint URL resolved")
	}
}

func TestTheAdvertisedOriginIsTheComposition(t *testing.T) {
	listening := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 41234}
	t.Setenv("CODEFLY__MODULE", "widgets")
	t.Setenv("CODEFLY__SERVICE", "api")

	t.Setenv("CODEFLY__SELF_ENDPOINT__WIDGETS__API__INGRESS__HTTP", "http://api.widgets.svc:9443")
	t.Setenv("CODEFLY__ENVIRONMENT", "staging")
	if err := codefly.LoadEnvironmentVariables(); err != nil {
		t.Fatal(err)
	}
	if got, err := advertisedOrigin(context.Background(), listening); err != nil || got != "https://api.widgets.svc:9443" {
		t.Fatalf("advertisedOrigin = %q, %v; want the advertised address, as https", got, err)
	}

	if err := os.Unsetenv("CODEFLY__SELF_ENDPOINT__WIDGETS__API__INGRESS__HTTP"); err != nil {
		t.Fatal(err)
	}
	if err := codefly.LoadEnvironmentVariables(); err != nil {
		t.Fatal(err)
	}
	if _, err := advertisedOrigin(context.Background(), listening); err == nil {
		t.Error("a deployed workload with no advertised address reported its loopback")
	}

	t.Setenv("CODEFLY__ENVIRONMENT", "local")
	if err := codefly.LoadEnvironmentVariables(); err != nil {
		t.Fatal(err)
	}
	if got, err := advertisedOrigin(context.Background(), listening); err != nil || got != "https://localhost:41234" {
		t.Fatalf("advertisedOrigin = %q, %v; a local run reports the port it listens on", got, err)
	}
	if codefly.Module() != "widgets" {
		t.Errorf("Module = %q", codefly.Module())
	}
}

func TestOriginsAreHostAndPortOnly(t *testing.T) {
	for raw, want := range map[string]string{
		"svc.ns:9443":              "https://svc.ns:9443",
		"http://svc.ns:9443":       "https://svc.ns:9443",
		"https://svc.ns:9443/":     "https://svc.ns:9443",
		"https://svc.ns:9443/path": "",
		"https://u@svc.ns:9443":    "",
		"svc.ns":                   "",
		"svc.ns:99999":             "",
		"[::]:9443":                "",
	} {
		got, err := httpsOrigin(raw)
		if (want == "") != (err != nil) || got != want {
			t.Errorf("httpsOrigin(%q) = %q, %v; want %q", raw, got, err, want)
		}
	}
}

func TestJitterStaysWithinAQuarter(t *testing.T) {
	for range 100 {
		if got := jittered(time.Second); got > time.Second || got < 750*time.Millisecond {
			t.Fatalf("jittered(1s) = %s", got)
		}
	}
	if jittered(0) != 0 {
		t.Error("jittered(0) is not 0")
	}
}
