package ingress

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"time"

	codefly "github.com/codefly-dev/sdk-go"
)

// DefaultFrontAPI is the endpoint Front proxies to when none is named: the
// generated REST surface a module serves /v1/<alias>/* on.
const DefaultFrontAPI = "rest"

// Front is a handler for Serve that forwards to one of THIS service's own
// endpoints over loopback.
//
// A module's gateway surface (/v1/<alias>/*, transcoded by its generated
// server) is served by a listener the module's code does not own and cannot
// hand to Serve as a handler. Front resolves that endpoint the way every
// address is resolved — the SDK's resolution for this process's own module and
// service, never a typed port — and proxies to it, so the gateway reaches the
// generated surface through the SVID listener and nothing else changes.
//
// Loopback only. The resolved address must be localhost or a loopback IP (a
// rendered cell localizes a service's own endpoint carrier to the address it
// binds, so this is what both a cell and a local run resolve); any other
// resolution is refused rather than proxied, because the ingress would then be
// an authenticated front for a destination that is not this process.
//
// Everything the caller sent is forwarded: method, path, query, body and
// headers — Authorization included, since the gateway's bearer and capability
// are what the module authenticates the request by — except the hop-by-hop
// headers, which no proxy forwards. No X-Forwarded-* header is added, and
// any the caller sent is dropped (httputil's Rewrite behaviour, used without
// SetXForwarded): the only caller of this front is the gateway, already
// authenticated by its SVID, and a forwarding chain this hop did not verify is
// not one it should vouch for. The outbound Host is the target's. Responses are
// flushed as written (FlushInterval -1), so a stream reaches the gateway as it
// is produced.
func Front(ctx context.Context, api string) (http.Handler, error) {
	api = strings.TrimSpace(api)
	if api == "" {
		api = DefaultFrontAPI
	}
	instance, err := codefly.For(ctx).Endpoint(api).API(api).ResolveNetworkInstance()
	if err != nil {
		return nil, fmt.Errorf("ingress: resolve this service's own %q endpoint to front: %w", api, err)
	}
	target, err := loopbackTarget(instance.Hostname, instance.Port)
	if err != nil {
		return nil, fmt.Errorf("ingress: this service's %q endpoint resolves to %s: %w", api, instance.Address, err)
	}
	return frontTo(target), nil
}

// loopbackTarget is http://<loopback>:port for a hostname that names this
// machine, and a refusal for anything else. "localhost" is dialled as
// 127.0.0.1 rather than resolved, so no resolver configuration can point it
// elsewhere.
func loopbackTarget(hostname string, port uint16) (*url.URL, error) {
	if port == 0 {
		return nil, errors.New("it names no port")
	}
	host := strings.TrimSuffix(strings.TrimSpace(hostname), ".")
	var ip net.IP
	if strings.EqualFold(host, "localhost") {
		ip = net.IPv4(127, 0, 0, 1)
	} else if ip = net.ParseIP(strings.Trim(host, "[]")); ip == nil || !ip.IsLoopback() {
		return nil, fmt.Errorf("%q is not loopback: the ingress fronts this process's own endpoint and nothing else", hostname)
	}
	return &url.URL{Scheme: "http", Host: net.JoinHostPort(ip.String(), strconv.Itoa(int(port)))}, nil
}

func frontTo(target *url.URL) http.Handler {
	transport := &http.Transport{
		Proxy:                 nil,
		DialContext:           (&net.Dialer{Timeout: 5 * time.Second}).DialContext,
		MaxIdleConnsPerHost:   64,
		IdleConnTimeout:       30 * time.Second,
		ResponseHeaderTimeout: 0, // a declared stream may take as long as its method allows
	}
	return &httputil.ReverseProxy{
		Rewrite: func(r *httputil.ProxyRequest) {
			r.SetURL(target)
		},
		Transport:     transport,
		FlushInterval: -1,
		ErrorHandler: func(w http.ResponseWriter, _ *http.Request, _ error) {
			// The module's own endpoint did not answer. Its detail stays here.
			http.Error(w, "module endpoint unavailable", http.StatusBadGateway)
		},
	}
}
