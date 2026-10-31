package fronting

import (
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// capturedOrigin is what the camouflage upstream observed for one request.
type capturedOrigin struct {
	host        string
	path        string
	query       string
	proto       string
	forwardHost string
	auth        string
	date        string
	nonce       string
	apiVersion  string
}

// newOrigin starts a loopback origin that captures the request and answers
// with the given extra headers.
func newOrigin(t *testing.T, captured chan<- capturedOrigin, extra map[string]string) *httptest.Server {
	t.Helper()
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		captured <- capturedOrigin{
			host:        r.Host,
			path:        r.URL.Path,
			query:       r.URL.RawQuery,
			proto:       r.Header.Get("X-Forwarded-Proto"),
			forwardHost: r.Header.Get("X-Forwarded-Host"),
			auth:        r.Header.Get("Authorization"),
			date:        r.Header.Get("X-Date"),
			nonce:       r.Header.Get("X-Trace-Id"),
			apiVersion:  r.Header.Get("X-Api-Version"),
		}
		for name, value := range extra {
			w.Header().Set(name, value)
		}
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, "origin body")
	}))
	t.Cleanup(origin.Close)
	return origin
}

func TestSiteHandlerBuiltinPage(t *testing.T) {
	handler, err := NewSiteHandler(Config{SiteName: "Acme"})
	if err != nil {
		t.Fatalf("NewSiteHandler: %v", err)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "https://site.example.com/", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	page := rec.Body.String()
	for _, want := range []string{"<!doctype html>", "<title>Acme</title>", "<h1>Acme</h1>", "The site is running."} {
		if !strings.Contains(page, want) {
			t.Fatalf("page does not contain %q: %q", want, page)
		}
	}
	if got := rec.Header().Get("Server"); got != DefaultServerHeader {
		t.Fatalf("Server = %q, want %q", got, DefaultServerHeader)
	}
	if got := rec.Header().Get("Content-Type"); got != "text/html; charset=utf-8" {
		t.Fatalf("Content-Type = %q", got)
	}
	if got := rec.Header().Get("Cache-Control"); got != "public, max-age=300" {
		t.Fatalf("Cache-Control = %q", got)
	}
}

func TestSiteHandlerBuiltinRoutes(t *testing.T) {
	handler, err := NewSiteHandler(Config{})
	if err != nil {
		t.Fatalf("NewSiteHandler: %v", err)
	}

	tests := []struct {
		name       string
		method     string
		path       string
		wantStatus int
		wantBody   string
		wantType   string
	}{
		{name: "root", method: http.MethodGet, path: "/", wantStatus: 200, wantBody: "<h1>Welcome</h1>", wantType: "text/html; charset=utf-8"},
		{name: "index", method: http.MethodGet, path: "/index.html", wantStatus: 200, wantBody: "<h1>Welcome</h1>", wantType: "text/html; charset=utf-8"},
		{name: "head root", method: http.MethodHead, path: "/", wantStatus: 200, wantType: "text/html; charset=utf-8"},
		{name: "robots", method: http.MethodGet, path: "/robots.txt", wantStatus: 200, wantBody: "User-agent: *\nDisallow:\n", wantType: "text/plain; charset=utf-8"},
		{name: "head robots", method: http.MethodHead, path: "/robots.txt", wantStatus: 200, wantType: "text/plain; charset=utf-8"},
		{name: "favicon", method: http.MethodGet, path: "/favicon.ico", wantStatus: http.StatusNoContent},
		{name: "missing", method: http.MethodGet, path: "/missing.js", wantStatus: http.StatusNotFound, wantBody: "404 page not found"},
		{name: "post root", method: http.MethodPost, path: "/", wantStatus: http.StatusNotFound},
		{name: "put robots", method: http.MethodPut, path: "/robots.txt", wantStatus: http.StatusNotFound},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, httptest.NewRequest(tt.method, "https://site.example.com"+tt.path, nil))

			if rec.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d", rec.Code, tt.wantStatus)
			}
			if tt.wantBody != "" && !strings.Contains(rec.Body.String(), tt.wantBody) {
				t.Fatalf("body = %q, want it to contain %q", rec.Body.String(), tt.wantBody)
			}
			if tt.method == http.MethodHead && rec.Body.Len() != 0 {
				t.Fatalf("HEAD returned a body: %q", rec.Body.String())
			}
			if tt.wantType != "" {
				if got := rec.Header().Get("Content-Type"); got != tt.wantType {
					t.Fatalf("Content-Type = %q, want %q", got, tt.wantType)
				}
			}
			if got := rec.Header().Get("Server"); got != DefaultServerHeader {
				t.Fatalf("Server = %q, want %q", got, DefaultServerHeader)
			}
		})
	}
}

func TestSiteHandlerLocalProxy(t *testing.T) {
	captured := make(chan capturedOrigin, 1)
	origin := newOrigin(t, captured, map[string]string{
		"Server":  "origin-server",
		"Alt-Svc": `h3=":443"; ma=2592000`,
	})
	handler, err := NewSiteHandler(Config{
		Site: SiteConfig{Mode: SiteModeLocal, Upstream: origin.URL},
	})
	if err != nil {
		t.Fatalf("NewSiteHandler: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "https://front.example.com/hello", nil)
	req.Header.Set("Authorization", "HMAC-SHA256 Signature=deadbeef")
	req.Header.Set("X-Api-Version", "v1")
	req.Header.Set("X-Date", "1700000000")
	req.Header.Set("X-Trace-Id", "0123456789abcdef")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if got := rec.Body.String(); got != "origin body" {
		t.Fatalf("body = %q, want the upstream body", got)
	}
	if got := rec.Header().Values("Server"); len(got) != 1 || got[0] != DefaultServerHeader {
		t.Fatalf("Server = %v, want exactly [%s]", got, DefaultServerHeader)
	}
	if got := rec.Header().Get("Alt-Svc"); got != "" {
		t.Fatalf("Alt-Svc = %q, want it stripped", got)
	}

	seen := <-captured
	if seen.host != "front.example.com" {
		t.Fatalf("upstream Host = %q, want the client Host (preserve_host local default)", seen.host)
	}
	if seen.path != "/hello" {
		t.Fatalf("upstream path = %q", seen.path)
	}
	if seen.proto != "https" {
		t.Fatalf("X-Forwarded-Proto = %q, want https", seen.proto)
	}
	if seen.forwardHost != "front.example.com" {
		t.Fatalf("X-Forwarded-Host = %q", seen.forwardHost)
	}
	if seen.auth != "" || seen.date != "" || seen.nonce != "" || seen.apiVersion != "" {
		t.Fatalf("fronting auth headers leaked upstream: %+v", seen)
	}
}

func TestSiteHandlerLocalProxyJoinsUpstreamPath(t *testing.T) {
	captured := make(chan capturedOrigin, 1)
	origin := newOrigin(t, captured, nil)
	handler, err := NewSiteHandler(Config{
		Site: SiteConfig{Mode: SiteModeLocal, Upstream: origin.URL + "/base"},
	})
	if err != nil {
		t.Fatalf("NewSiteHandler: %v", err)
	}

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "https://front.example.com/hello?x=1", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	seen := <-captured
	if seen.path != "/base/hello" {
		t.Fatalf("upstream path = %q, want /base/hello", seen.path)
	}
	if seen.query != "x=1" {
		t.Fatalf("upstream query = %q, want x=1", seen.query)
	}
}

func TestSiteHandlerRemoteRewritesHost(t *testing.T) {
	captured := make(chan capturedOrigin, 1)
	origin := newOrigin(t, captured, nil)
	handler, err := NewSiteHandler(Config{
		Site: SiteConfig{Mode: SiteModeRemote, Upstream: origin.URL},
	})
	if err != nil {
		t.Fatalf("NewSiteHandler: %v", err)
	}

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "https://front.example.com/", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	wantHost := strings.TrimPrefix(origin.URL, "http://")
	if seen := <-captured; seen.host != wantHost {
		t.Fatalf("upstream Host = %q, want the upstream host %q", seen.host, wantHost)
	}
}

func TestSiteHandlerRemotePreserveHost(t *testing.T) {
	captured := make(chan capturedOrigin, 1)
	origin := newOrigin(t, captured, nil)
	handler, err := NewSiteHandler(Config{
		Site: SiteConfig{Mode: SiteModeRemote, Upstream: origin.URL, PreserveHost: boolPtr(true)},
	})
	if err != nil {
		t.Fatalf("NewSiteHandler: %v", err)
	}

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "https://front.example.com/", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if seen := <-captured; seen.host != "front.example.com" {
		t.Fatalf("upstream Host = %q, want the preserved client Host", seen.host)
	}
}

func TestSiteHandlerUpstreamFailureFallsBackToBuiltin(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := listener.Addr().String()
	_ = listener.Close()

	handler, err := NewSiteHandler(Config{
		SiteName: "Fallback",
		Site:     SiteConfig{Mode: SiteModeLocal, Upstream: "http://" + addr},
	})
	if err != nil {
		t.Fatalf("NewSiteHandler: %v", err)
	}

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "https://front.example.com/", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want the builtin page with 200", rec.Code)
	}
	page := rec.Body.String()
	if !strings.Contains(page, "<h1>Fallback</h1>") {
		t.Fatalf("fallback body = %q, want the builtin page", page)
	}
	if got := rec.Header().Get("Server"); got != DefaultServerHeader {
		t.Fatalf("Server = %q", got)
	}
	if got := rec.Header().Get("Content-Type"); got != "text/html; charset=utf-8" {
		t.Fatalf("Content-Type = %q", got)
	}
}

func TestSiteHandlerTLSUpstream(t *testing.T) {
	captured := make(chan capturedOrigin, 1)
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		captured <- capturedOrigin{host: r.Host, path: r.URL.Path}
		_, _ = io.WriteString(w, "tls origin body")
	}))
	t.Cleanup(origin.Close)

	// With insecure_skip_verify the self-signed upstream is reachable.
	handler, err := NewSiteHandler(Config{
		Site: SiteConfig{Mode: SiteModeRemote, Upstream: origin.URL, InsecureSkipVerify: true},
	})
	if err != nil {
		t.Fatalf("NewSiteHandler: %v", err)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "https://front.example.com/", nil))
	if rec.Code != http.StatusOK || rec.Body.String() != "tls origin body" {
		t.Fatalf("insecure TLS upstream: status = %d, body = %q", rec.Code, rec.Body.String())
	}
	if seen := <-captured; seen.host != strings.TrimPrefix(origin.URL, "https://") {
		t.Fatalf("upstream Host = %q", seen.host)
	}

	// Without it the handshake fails and the builtin page is served instead.
	strict := Config{
		SiteName: "Strict",
		Site:     SiteConfig{Mode: SiteModeRemote, Upstream: origin.URL},
	}
	strictHandler, err := NewSiteHandler(strict)
	if err != nil {
		t.Fatalf("NewSiteHandler: %v", err)
	}
	rec = httptest.NewRecorder()
	strictHandler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "https://front.example.com/", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "<h1>Strict</h1>") {
		t.Fatalf("TLS verification failure did not fall back to the builtin page: %q", rec.Body.String())
	}
}

func TestSiteHandlerInvalidConfig(t *testing.T) {
	if _, err := NewSiteHandler(Config{Site: SiteConfig{Mode: SiteModeLocal}}); err == nil {
		t.Fatal("NewSiteHandler accepted local mode without an upstream")
	}
	if _, err := NewSiteHandler(Config{Site: SiteConfig{Upstream: "ftp://127.0.0.1:21"}}); err == nil {
		t.Fatal("NewSiteHandler accepted an unsupported upstream scheme")
	}
	if _, err := NewSiteHandler(Config{Transport: "quic"}); err == nil {
		t.Fatal("NewSiteHandler accepted an unsupported transport")
	}
}
