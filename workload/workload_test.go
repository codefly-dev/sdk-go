package workload

import (
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	codefly "github.com/codefly-dev/sdk-go"
)

// staticIdentity is a consumer-supplied source that returns one configuration.
type staticIdentity struct{ config *tls.Config }

func (s staticIdentity) ServerTLSConfig() (*tls.Config, error) { return s.config, nil }

func TestABootWithoutAnIdentityIsRefusedByName(t *testing.T) {
	c := newCell(t)
	files := c.files(t, testPrincipal)
	admitted := IdentitySet(files.AllowedCallers, "allowed callers")
	for _, tc := range []struct {
		name  string
		files Files
		names string
	}{
		{"no certificate", Files{Key: files.Key, TrustBundle: files.TrustBundle}, CertFileOverride},
		{"no key", Files{Cert: files.Cert, TrustBundle: files.TrustBundle}, KeyFileOverride},
		{"no anchor", Files{Cert: files.Cert, Key: files.Key}, TrustBundleFileOverride},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewListener(Projected(tc.files), testPrincipal, admitted)
			if err == nil {
				t.Fatal("a listener with no identity material was built: there is no plain listener to fall back to")
			}
			if !strings.Contains(err.Error(), tc.names) {
				t.Errorf("the refusal %q does not name %s", err, tc.names)
			}
		})
	}
	if _, err := NewListener(Projected(files), testPrincipal, nil); err == nil || !strings.Contains(err.Error(), AllowedCallersFileKey) {
		t.Errorf("a listener with no admitted set was not refused by name: %v", err)
	}
}

func TestAListenerIsHeldToItsOwnFrozenPrincipal(t *testing.T) {
	c := newCell(t)
	files := c.files(t, testNeighbour)
	_, err := NewListener(Projected(files), testPrincipal, IdentitySet(files.AllowedCallers, "allowed callers"))
	if err == nil {
		t.Fatal("a pair projected for another workload was served")
	}
	if !strings.Contains(err.Error(), testNeighbour) || !strings.Contains(err.Error(), testPrincipal) {
		t.Errorf("the refusal %q does not name both identities", err)
	}
}

func TestThePrincipalIsReadFromTheServedLeaf(t *testing.T) {
	c := newCell(t)
	principal, err := PrincipalOf(Projected(c.files(t, testPrincipal)))
	if err != nil || principal != testPrincipal {
		t.Fatalf("PrincipalOf = %q, %v; want %q", principal, err, testPrincipal)
	}
	// A leaf naming several identities is not a SPIFFE identity.
	certPEM, keyPEM := c.leaf(t, testPrincipal, testNeighbour)
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := PrincipalOf(staticIdentity{config: &tls.Config{Certificates: []tls.Certificate{pair}}}); err == nil {
		t.Error("a leaf naming two URI identities yielded a principal")
	}
	if _, err := PrincipalOf(nil); err == nil {
		t.Error("no source yielded a principal")
	}
}

func TestAnAuthenticatedCallerIsNotAutomaticallyAnAuthorisedOne(t *testing.T) {
	c := newCell(t)
	files := c.files(t, testPrincipal)
	_, addr := serving(t, files)

	resp, err := c.caller(c.identity(t, testGatewayPrincipal), false).Get("https://" + addr + "/")
	if err != nil {
		t.Fatalf("the admitted gateway was refused: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if string(body) != "served" {
		t.Fatalf("served %q", body)
	}
	// A neighbour holds a certificate from the same anchor and is not admitted.
	if _, err := c.caller(c.identity(t, testNeighbour), false).Get("https://" + addr + "/"); err == nil {
		t.Error("a caller from this cell's anchor that the admitted set does not name was served")
	}
	// No certificate at all.
	anonymous := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: c.roots, MinVersion: tls.VersionTLS13}}}
	if _, err := anonymous.Get("https://" + addr + "/"); err == nil {
		t.Error("a caller presenting no certificate was served")
	}
	// Plain HTTP is not served.
	if resp, err := (&http.Client{Timeout: 5 * time.Second}).Get("http://" + addr + "/"); err == nil {
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if string(body) == "served" {
			t.Error("plain HTTP was served")
		}
	}
}

func TestPeerTrustIsReadAtEveryHandshake(t *testing.T) {
	c := newCell(t)
	files := c.files(t, testPrincipal)
	_, addr := serving(t, files)
	gateway := c.identity(t, testGatewayPrincipal)
	if _, err := c.caller(gateway, false).Get("https://" + addr + "/"); err != nil {
		t.Fatalf("control: %v", err)
	}
	// The bundle now names another root: a caller under the old one is refused
	// on its next handshake, with no restart.
	writeFile(t, files.TrustBundle, string(newCell(t).anchorPEM))
	if _, err := c.caller(gateway, false).Get("https://" + addr + "/"); err == nil {
		t.Error("a caller whose root was removed from the bundle was served on a new handshake")
	}
	// An unreadable anchor refuses rather than falls back.
	writeFile(t, files.TrustBundle, "not a certificate\n")
	if _, err := c.caller(gateway, false).Get("https://" + addr + "/"); err == nil {
		t.Error("an unusable anchor admitted a caller")
	}
}

func TestAnEstablishedCallerIsClosedOnceNoLongerAdmitted(t *testing.T) {
	c := newCell(t)
	files := c.files(t, testPrincipal)
	_, addr := serving(t, files)
	client := c.caller(c.identity(t, testGatewayPrincipal), true)
	get := func() error {
		resp, err := client.Get("https://" + addr + "/")
		if err != nil {
			return err
		}
		_, _ = io.ReadAll(resp.Body)
		return resp.Body.Close()
	}
	if err := get(); err != nil {
		t.Fatalf("control: %v", err)
	}
	writeFile(t, files.AllowedCallers, testNeighbour+"\n")
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		time.Sleep(200 * time.Millisecond)
		// A closed keep-alive connection is redialled by net/http, and the new
		// handshake is refused too: either way the de-admitted caller stops
		// being served within the recheck interval.
		if get() != nil {
			return
		}
	}
	t.Error("a caller removed from the admitted set kept being served on its established connection")
}

func TestARotatedLeafIsStillHeldToTheFrozenPrincipal(t *testing.T) {
	c := newCell(t)
	files := c.files(t, testPrincipal)
	_, addr := serving(t, files)
	gateway := c.identity(t, testGatewayPrincipal)
	if _, err := c.caller(gateway, false).Get("https://" + addr + "/"); err != nil {
		t.Fatalf("control: %v", err)
	}
	certPEM, keyPEM := c.leaf(t, testNeighbour)
	writeFile(t, files.Key, string(keyPEM))
	writeFile(t, files.Cert, string(certPEM))
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		time.Sleep(100 * time.Millisecond)
		if _, err := c.caller(gateway, false).Get("https://" + addr + "/"); err != nil {
			t.Logf("refused: %v", err)
			return
		}
	}
	t.Error("a rotation to a neighbouring workload's pair was served under it")
}

func TestASourceCannotReplaceThePostureItIsHeldTo(t *testing.T) {
	c := newCell(t)
	files := c.files(t, testPrincipal)
	conforming := func(t *testing.T) *tls.Config {
		t.Helper()
		config, err := Projected(files).ServerTLSConfig()
		if err != nil {
			t.Fatal(err)
		}
		return config
	}
	if err := usableServerIdentity(conforming(t)); err != nil {
		t.Fatalf("the conforming projected configuration was refused, so nothing below is about the field it changes: %v", err)
	}
	for _, tc := range []struct {
		name  string
		lower func(*tls.Config)
	}{
		{"a clock of its own", func(cfg *tls.Config) { cfg.Time = func() time.Time { return time.Unix(0, 0) } }},
		//nolint:staticcheck // Deliberately sets the deprecated field, to prove the refusal fires.
		{"a randomness source of its own", func(cfg *tls.Config) { cfg.Rand = strings.NewReader("not random") }},
		{"the session secrets written out", func(cfg *tls.Config) { cfg.KeyLogWriter = io.Discard }},
		{"resumption tickets it encodes", func(cfg *tls.Config) {
			cfg.WrapSession = func(tls.ConnectionState, *tls.SessionState) ([]byte, error) { return nil, nil }
		}},
		{"resumption tickets it decodes", func(cfg *tls.Config) {
			cfg.UnwrapSession = func([]byte, tls.ConnectionState) (*tls.SessionState, error) { return nil, nil }
		}},
		{"no verification at all", func(cfg *tls.Config) { cfg.InsecureSkipVerify = true }},
		{"a resumption ticket key of its own", func(cfg *tls.Config) {
			//nolint:staticcheck // Deliberately sets the deprecated field, to prove the refusal fires.
			cfg.SessionTicketKey = [32]byte{1}
		}},
		{"its own chain verifier", func(cfg *tls.Config) {
			cfg.VerifyPeerCertificate = func([][]byte, [][]*x509.Certificate) error { return nil }
		}},
		{"its own connection verifier", func(cfg *tls.Config) {
			cfg.VerifyConnection = func(tls.ConnectionState) error { return nil }
		}},
		{"a floor below TLS 1.3", func(cfg *tls.Config) { cfg.MinVersion = tls.VersionTLS12 }},
		{"no caller authentication", func(cfg *tls.Config) { cfg.ClientAuth = tls.RequestClientCert }},
		{"no anchor named", func(cfg *tls.Config) { cfg.GetConfigForClient = nil; cfg.ClientCAs = nil }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			config := conforming(t)
			tc.lower(config)
			if err := usableServerIdentity(config); err == nil {
				t.Error("a configuration below the posture was accepted")
			}
		})
	}
}

func TestASourcesPerConnectionCallbackCannotLowerThePosture(t *testing.T) {
	c := newCell(t)
	files := c.files(t, testPrincipal)
	anchor, err := peerAnchor(files.TrustBundle)
	if err != nil {
		t.Fatal(err)
	}
	conforming := func() *tls.Config {
		config, err := Projected(files).ServerTLSConfig()
		if err != nil {
			t.Fatal(err)
		}
		return config
	}
	answered := func(lower func(*tls.Config)) *tls.Config {
		base := conforming()
		base.GetConfigForClient = func(*tls.ClientHelloInfo) (*tls.Config, error) {
			answer := conforming()
			answer.GetConfigForClient = nil
			answer.ClientCAs = anchor
			lower(answer)
			return answer, nil
		}
		holdPerConnectionPosture(base, testPrincipal, func() ([]string, error) { return []string{testGatewayPrincipal}, nil })
		return base
	}
	if _, err := answered(func(*tls.Config) {}).GetConfigForClient(&tls.ClientHelloInfo{}); err != nil {
		t.Fatalf("a conforming per-connection answer was refused: %v", err)
	}
	for _, tc := range []struct {
		name, names string
		lower       func(*tls.Config)
	}{
		{"the session secrets written out", "KeyLogWriter", func(cfg *tls.Config) { cfg.KeyLogWriter = io.Discard }},
		{"a clock of its own", "Time", func(cfg *tls.Config) { cfg.Time = func() time.Time { return time.Unix(0, 0) } }},
		{"its own chain verifier", "VerifyPeerCertificate", func(cfg *tls.Config) {
			cfg.VerifyPeerCertificate = func([][]byte, [][]*x509.Certificate) error { return nil }
		}},
		{"a floor below TLS 1.3", "TLS 1.3", func(cfg *tls.Config) { cfg.MinVersion = tls.VersionTLS12 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := answered(tc.lower).GetConfigForClient(&tls.ClientHelloInfo{})
			if err == nil || !strings.Contains(err.Error(), tc.names) {
				t.Fatalf("a per-connection answer lowering %s was not refused for it: %v", tc.names, err)
			}
		})
	}
	// A neighbour's leaf in a per-connection answer is refused as it is served,
	// in a real handshake: the selection the wrapper holds runs there.
	certPEM, keyPEM := c.leaf(t, testNeighbour)
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	base := conforming()
	inner := base.GetConfigForClient
	base.GetConfigForClient = func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
		answer, err := inner(hello)
		if err != nil {
			return nil, err
		}
		answer.GetCertificate = func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return &pair, nil }
		return answer, nil
	}
	listener, err := NewListener(staticPeerAnchored{config: base, bundle: files.TrustBundle}, testPrincipal, IdentitySet(files.AllowedCallers, "allowed callers"))
	if err != nil {
		t.Fatalf("NewListener: %v", err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := listener.Server(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("served")) }))
	go func() { _ = server.Serve(listener.Listen(ln)) }()
	t.Cleanup(func() { _ = server.Close() })
	if _, err := c.caller(c.identity(t, testGatewayPrincipal), false).Get("https://" + ln.Addr().String() + "/"); err == nil {
		t.Error("a per-connection answer serving a neighbouring workload's leaf completed a handshake")
	}
}

func TestASourcesConfigurationIsNotMutatedAndResumptionIsOff(t *testing.T) {
	c := newCell(t)
	files := c.files(t, testPrincipal)
	shared, err := Projected(files).ServerTLSConfig()
	if err != nil {
		t.Fatal(err)
	}
	hadVerify, hadPerConn := shared.VerifyConnection != nil, shared.GetConfigForClient != nil
	listener, err := NewListener(staticPeerAnchored{config: shared, bundle: files.TrustBundle}, testPrincipal, IdentitySet(files.AllowedCallers, "allowed callers"))
	if err != nil {
		t.Fatalf("NewListener: %v", err)
	}
	if listener.config == shared {
		t.Fatal("the listener serves the source's own configuration")
	}
	if (shared.VerifyConnection != nil) != hadVerify || (shared.GetConfigForClient != nil) != hadPerConn {
		t.Error("the source's configuration was written in place")
	}
	if listener.config.VerifyConnection == nil {
		t.Error("the configuration this listener serves carries no caller admission")
	}
	if !listener.config.SessionTicketsDisabled {
		t.Error("resumption is on: a resumed connection presents no certificate")
	}
	for _, proto := range listener.config.NextProtos {
		if proto == "h2" {
			t.Error("the listener advertises h2: net/http skips the hook that records a connection's admitted identity for HTTP/2")
		}
	}
	if listener.Principal() != testPrincipal {
		t.Errorf("Principal = %q", listener.Principal())
	}
	// A per-handshake source that cannot be asked for its anchor is refused.
	if _, err := NewListener(staticIdentity{config: shared}, testPrincipal, IdentitySet(files.AllowedCallers, "allowed callers")); err == nil || !strings.Contains(err.Error(), "PeerAnchorSource") {
		t.Errorf("a per-handshake source with no anchor accessor was accepted: %v", err)
	}
}

type staticPeerAnchored struct {
	config *tls.Config
	bundle string
}

func (s staticPeerAnchored) ServerTLSConfig() (*tls.Config, error) { return s.config, nil }
func (s staticPeerAnchored) PeerAnchor() (*x509.CertPool, error)   { return peerAnchor(s.bundle) }

// platform is a host answering under identity, verifying callers against the
// cell, recording the identity each request was made by.
func (c *cell) platform(t *testing.T, identity string, handler http.HandlerFunc) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{*c.identity(t, identity)},
			ClientCAs:    c.roots,
			ClientAuth:   tls.RequireAndVerifyClientCert,
			MinVersion:   tls.VersionTLS13,
		},
	}
	go func() { _ = server.ServeTLS(ln, "", "") }()
	t.Cleanup(func() { _ = server.Close() })
	return ln.Addr().String()
}

func TestTheClientPresentsThisWorkloadOnlyToAnAdmittedPlatform(t *testing.T) {
	c := newCell(t)
	files := c.files(t, testPrincipal)
	listener, _ := serving(t, files)
	var presented string
	answering := func(w http.ResponseWriter, r *http.Request) {
		if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 && len(r.TLS.PeerCertificates[0].URIs) == 1 {
			presented = r.TLS.PeerCertificates[0].URIs[0].String()
		}
		if r.URL.Path == "/redirect" {
			http.Redirect(w, r, "/elsewhere", http.StatusTemporaryRedirect)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
	gateway := c.platform(t, testGatewayPrincipal, answering)
	impostor := c.platform(t, testNeighbour, answering)
	peers := func(addr string) func() ([]string, error) {
		return IdentitySet(files.GatewayPeers, "gateway peers")
	}
	client, err := listener.Client(peers, gateway)
	if err != nil {
		t.Fatalf("Client: %v", err)
	}
	resp, err := client.Get("https://" + gateway + "/")
	if err != nil {
		t.Fatalf("the admitted gateway was refused: %v", err)
	}
	_ = resp.Body.Close()
	if presented != testPrincipal {
		t.Errorf("the client presented %q, want %q", presented, testPrincipal)
	}
	if _, err := client.Get("https://" + impostor + "/"); err == nil {
		t.Error("this workload's credentials were presented to a destination the provisioned set does not name")
	}
	resp, err = client.Get("https://" + gateway + "/redirect")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusTemporaryRedirect {
		t.Errorf("a redirect was followed (status %d): every header but three is copied to the new target", resp.StatusCode)
	}
	if _, err := listener.Client(nil, gateway); err == nil {
		t.Error("a client with no destination sets was built")
	}
}

func TestAdmissionSetsAreReadWholeAndFailClosed(t *testing.T) {
	for _, tc := range []struct {
		name, raw string
		want      []string
		refused   bool
	}{
		{"one per line", "spiffe://a.test/x\nspiffe://a.test/y\n", []string{"spiffe://a.test/x", "spiffe://a.test/y"}, false},
		{"commas and comments", "spiffe://a.test/x, spiffe://a.test/y # gateway\n", []string{"spiffe://a.test/x", "spiffe://a.test/y"}, false},
		{"a fragment at the end", "spiffe://a.test/x\nspiffe://a.test/y", nil, true},
		{"a byte-order mark", "\ufeffspiffe://a.test/x\n", nil, true},
		{"not a SPIFFE ID", "https://a.test/x\n", nil, true},
		{"a control character", "spiffe://a.test/x\x01\n", nil, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseIdentities(tc.raw)
			if tc.refused {
				if err == nil {
					t.Fatalf("accepted %q as %v", tc.raw, got)
				}
				return
			}
			if err != nil || strings.Join(got, "|") != strings.Join(tc.want, "|") {
				t.Fatalf("ParseIdentities = %v, %v; want %v", got, err, tc.want)
			}
		})
	}
	if _, err := IdentitySet("", "unresolved")(); err == nil {
		t.Error("an unresolved path admitted something")
	}
	c := newCell(t)
	files := c.files(t, testPrincipal)
	writeFile(t, files.AllowedCallers, "# nobody\n")
	if _, err := IdentitySet(files.AllowedCallers, "callers")(); err == nil {
		t.Error("an empty set admitted something")
	}
	writeFile(t, files.AllowedCallers, strings.Repeat("#", admissionFileLimit+1)+"\n")
	if _, err := IdentitySet(files.AllowedCallers, "callers")(); err == nil {
		t.Error("an oversized set was read")
	}
	one := func() ([]string, error) { return []string{"spiffe://a.test/x", "spiffe://a.test/y"}, nil }
	other := func() ([]string, error) { return []string{"spiffe://a.test/y"}, nil }
	if both, err := Intersect(one, other, "host:1")(); err != nil || len(both) != 1 || both[0] != "spiffe://a.test/y" {
		t.Errorf("Intersect = %v, %v", both, err)
	}
	none := func() ([]string, error) { return []string{"spiffe://a.test/z"}, nil }
	if _, err := Intersect(one, none, "host:1")(); err == nil {
		t.Error("two disjoint sets admitted someone at a shared address")
	}
}

func TestDialAddressMakesThePortExplicit(t *testing.T) {
	for raw, want := range map[string]string{
		"https://gw.test/modules":      "gw.test:443",
		"https://gw.test:8443/modules": "gw.test:8443",
		"http://gw.test/":              "gw.test:80",
		"::":                           "",
	} {
		if got := DialAddress(raw); got != want {
			t.Errorf("DialAddress(%q) = %q, want %q", raw, got, want)
		}
	}
}

// TestTheServedCertificateIsHeldAtSelectionNotByProbe: a source keyed on the
// hello answers a probe with the approved leaf and a real handshake with a
// neighbour's. What a handshake selects is what is compared.
func TestTheServedCertificateIsHeldAtSelectionNotByProbe(t *testing.T) {
	c := newCell(t)
	files := c.files(t, testPrincipal)
	approved := c.identity(t, testPrincipal)
	neighbour := c.identity(t, testNeighbour)
	anchor, err := peerAnchor(files.TrustBundle)
	if err != nil {
		t.Fatal(err)
	}
	keyed := &tls.Config{
		MinVersion: tls.VersionTLS13,
		ClientAuth: tls.RequireAndVerifyClientCert,
		ClientCAs:  anchor,
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			if len(hello.CipherSuites) > 0 {
				return neighbour, nil
			}
			return approved, nil
		},
	}
	listener, err := NewListener(staticIdentity{config: keyed}, testPrincipal, IdentitySet(files.AllowedCallers, "allowed callers"))
	if err != nil {
		t.Fatalf("the probe was answered with the approved leaf, so the boot should pass: %v", err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := listener.Server(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("served")) }))
	go func() { _ = server.Serve(listener.Listen(ln)) }()
	t.Cleanup(func() { _ = server.Close() })
	if _, err := c.caller(c.identity(t, testGatewayPrincipal), false).Get("https://" + ln.Addr().String() + "/"); err == nil {
		t.Error("a handshake was answered with the neighbour's leaf the probe never saw")
	}
}

func TestTheProjectionIsReadFromTheGroupAndItsOverrides(t *testing.T) {
	t.Setenv("CODEFLY__WORKSPACE_CONFIGURATION__WORKLOAD_IDENTITY__CERT_FILE", "/projected/tls.crt")
	t.Setenv("CODEFLY__WORKSPACE_CONFIGURATION__WORKLOAD_IDENTITY__ALLOWED_CALLERS_FILE", "/projected/allowed-callers")
	t.Setenv("CODEFLY__WORKLOAD_IDENTITY_CERT_FILE", "/override/tls.crt")
	t.Setenv("CODEFLY__WORKLOAD_TOKEN_FILE", "/override/token")
	if err := codefly.LoadEnvironmentVariables(); err != nil {
		t.Fatal(err)
	}
	files := ProjectedFiles(t.Context())
	if files.Cert != "/override/tls.crt" {
		t.Errorf("Cert = %q: an explicit override wins over the group", files.Cert)
	}
	if files.AllowedCallers != "/projected/allowed-callers" {
		t.Errorf("AllowedCallers = %q: the group answers what no override names", files.AllowedCallers)
	}
	if files.Token != "/override/token" || files.Key != "" {
		t.Errorf("Token = %q, Key = %q", files.Token, files.Key)
	}
}

func TestASuppliedSourceIsHeldToThePostureOutboundToo(t *testing.T) {
	c := newCell(t)
	files := c.files(t, testPrincipal)
	approved := c.identity(t, testPrincipal)
	anchor, err := peerAnchor(files.TrustBundle)
	if err != nil {
		t.Fatal(err)
	}
	supplied := &tls.Config{
		MinVersion:   tls.VersionTLS13,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    anchor,
		Certificates: []tls.Certificate{*approved},
	}
	listener, err := NewListener(staticIdentity{config: supplied}, testPrincipal, IdentitySet(files.AllowedCallers, "allowed callers"))
	if err != nil {
		t.Fatalf("NewListener: %v", err)
	}
	if principal, err := PrincipalOf(staticIdentity{config: supplied}); err != nil || principal != testPrincipal {
		t.Fatalf("PrincipalOf = %q, %v", principal, err)
	}
	var presented string
	gateway := c.platform(t, testGatewayPrincipal, func(w http.ResponseWriter, r *http.Request) {
		presented = r.TLS.PeerCertificates[0].URIs[0].String()
		w.WriteHeader(http.StatusNoContent)
	})
	client, err := listener.Client(func(string) func() ([]string, error) {
		return IdentitySet(files.GatewayPeers, "gateway peers")
	}, gateway)
	if err != nil {
		t.Fatalf("Client: %v", err)
	}
	resp, err := client.Get("https://" + gateway + "/")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	_ = resp.Body.Close()
	if presented != testPrincipal {
		t.Errorf("presented %q", presented)
	}
}

func TestAnEstablishedPlatformConnectionIsDroppedOnceNoLongerAdmitted(t *testing.T) {
	c := newCell(t)
	files := c.files(t, testPrincipal)
	listener, _ := serving(t, files)
	gateway := c.platform(t, testGatewayPrincipal, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	client, err := listener.Client(func(string) func() ([]string, error) {
		return IdentitySet(files.GatewayPeers, "gateway peers")
	}, gateway)
	if err != nil {
		t.Fatalf("Client: %v", err)
	}
	get := func() error {
		resp, err := client.Get("https://" + gateway + "/")
		if err != nil {
			return err
		}
		return resp.Body.Close()
	}
	if err := get(); err != nil {
		t.Fatalf("control: %v", err)
	}
	// Held across a recheck tick while still admitted: the connection stays.
	time.Sleep(1200 * time.Millisecond)
	if err := get(); err != nil {
		t.Fatalf("a still-admitted platform connection was dropped: %v", err)
	}
	writeFile(t, files.GatewayPeers, testNeighbour+"\n")
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		time.Sleep(200 * time.Millisecond)
		if get() != nil {
			return
		}
	}
	t.Error("this workload kept presenting its credentials to a destination the provisioned set no longer names")
}

func TestTheOutboundCertificateIsHeldToTheFrozenPrincipal(t *testing.T) {
	c := newCell(t)
	neighbour := c.identity(t, testNeighbour)
	config := &tls.Config{Certificates: []tls.Certificate{*neighbour}}
	if err := holdPresentedCertificate(config, testPrincipal); err == nil {
		t.Error("a static outbound certificate naming another workload was accepted")
	}
	config = &tls.Config{GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) { return neighbour, nil }}
	if err := holdPresentedCertificate(config, testPrincipal); err == nil {
		t.Error("an outbound certificate callback answering with another workload was accepted")
	}
	if err := holdPresentedCertificate(&tls.Config{}, testPrincipal); err == nil {
		t.Error("an outbound client presenting nothing was accepted")
	}
	if err := holdPresentedCertificate(&tls.Config{}, ""); err == nil {
		t.Error("an outbound client with no principal was accepted")
	}
	two := &tls.Config{Certificates: []tls.Certificate{*neighbour, *neighbour}}
	if err := holdPresentedCertificate(two, testPrincipal); err == nil {
		t.Error("an outbound client choosing between certificates was accepted")
	}
	if err := holdServedCertificate(two, testPrincipal); err == nil {
		t.Error("a listener choosing between certificates was accepted")
	}
	if err := holdServedCertificate(&tls.Config{}, ""); err == nil {
		t.Error("a listener with no principal was accepted")
	}
}
