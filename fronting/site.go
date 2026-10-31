package fronting

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"
)

// Site proxy constants. They mirror Caddy's reverse_proxy defaults closely
// enough for a camouflage layer while bounding how long a probe can be held
// open by a broken upstream.
const (
	frontingSiteDialTimeout           = 5 * time.Second
	frontingSiteTLSHandshakeTimeout   = 5 * time.Second
	frontingSiteResponseHeaderTimeout = 10 * time.Second
	frontingSiteIdleConnTimeout       = 90 * time.Second
	frontingSiteMaxIdlePerHost        = 16
	frontingSiteKeepAlive             = 30 * time.Second
)

// siteHandler answers unauthenticated fronting traffic with either the
// built-in decoy page or a Caddy-like reverse proxy to the configured local or
// remote upstream.
type siteHandler struct {
	builtin   http.Handler
	proxy     *httputil.ReverseProxy
	transport *http.Transport
}

// ServeHTTP dispatches to the reverse proxy when one is configured.
func (h *siteHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if h.proxy != nil {
		// The fronting entry point already set the Server header for the
		// tunnel path. httputil.ReverseProxy *copies* upstream headers with
		// Header.Add, so leaving the pre-set value in place would emit two
		// Server header lines on proxied responses (Caddy emits one). The
		// proxy's ModifyResponse sets the single authoritative value.
		w.Header().Del("Server")
		h.proxy.ServeHTTP(w, r)
		return
	}
	h.builtin.ServeHTTP(w, r)
}

// CloseIdleConnections releases idle upstream connections held by the site
// proxy transport.
func (h *siteHandler) CloseIdleConnections() {
	if h.transport != nil {
		h.transport.CloseIdleConnections()
	}
}

// NewSiteHandler builds the handler that answers unauthenticated fronting
// requests: the generated built-in decoy page (builtin mode) or an
// httputil.ReverseProxy with Caddy reverse_proxy semantics for local and
// remote upstreams.
//
// The upstream is always operator-configured, never derived from the request,
// so the proxy does not introduce an SSRF surface. When the upstream cannot be
// reached the handler falls back to the built-in page with status 200, so a
// probe never sees a proxy error.
func NewSiteHandler(cfg Config) (http.Handler, error) {
	if err := cfg.Normalize(); err != nil {
		return nil, err
	}
	builtin := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		serveBuiltinDecoy(w, r, cfg)
	})
	if cfg.Site.Mode != SiteModeLocal && cfg.Site.Mode != SiteModeRemote {
		return builtin, nil
	}

	upstream := cfg.Site.upstreamURL()
	if upstream == nil {
		return nil, fmt.Errorf("fronting: site mode %q requires an upstream", cfg.Site.Mode)
	}
	serverHeader := cfg.ServerHeader
	preserveHost := cfg.Site.preserveHostEnabled()
	transport := &http.Transport{
		DialContext: (&net.Dialer{
			Timeout:   frontingSiteDialTimeout,
			KeepAlive: frontingSiteKeepAlive,
		}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   frontingSiteMaxIdlePerHost,
		IdleConnTimeout:       frontingSiteIdleConnTimeout,
		TLSHandshakeTimeout:   frontingSiteTLSHandshakeTimeout,
		ResponseHeaderTimeout: frontingSiteResponseHeaderTimeout,
		ExpectContinueTimeout: time.Second,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: cfg.Site.InsecureSkipVerify,
			MinVersion:         tls.VersionTLS12,
		},
	}

	handler := &siteHandler{builtin: builtin, transport: transport}
	handler.proxy = &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			clientHost := req.Host
			forwardedProto := "http"
			if req.TLS != nil {
				forwardedProto = "https"
			}

			// Caddy sets the forwarding headers itself and ignores inbound
			// values from untrusted peers, so drop them before ReverseProxy
			// appends the real client address to X-Forwarded-For.
			req.Header.Del("X-Forwarded-For")
			joinSiteUpstreamURL(req.URL, upstream)
			if !preserveHost {
				req.Host = upstream.Host
			}
			req.Header.Set("X-Forwarded-Proto", forwardedProto)
			if clientHost != "" {
				req.Header.Set("X-Forwarded-Host", clientHost)
			}
			// Never forward our internal fronting auth metadata.
			StripAuthHeaders(req.Header)
		},
		Transport:     transport,
		FlushInterval: -1,
		ModifyResponse: func(resp *http.Response) error {
			if serverHeader != "" {
				resp.Header.Set("Server", serverHeader)
			}
			// We do not serve HTTP/3, so advertising h3 via Alt-Svc would be a
			// fingerprint (and would send probes to a dead endpoint).
			resp.Header.Del("Alt-Svc")
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			// An unreachable upstream must look like the built-in site, never
			// like a proxy or an internal wiring failure.
			time.Sleep(authJitter())
			writeBuiltinDecoyPage(w, r, cfg, http.StatusOK)
		},
	}
	return handler, nil
}

// joinSiteUpstreamURL rewrites reqURL to target, joining paths and queries with
// the same rules as httputil.NewSingleHostReverseProxy. Trailing slashes were
// already trimmed from the upstream during Config.Normalize.
func joinSiteUpstreamURL(reqURL, upstream *url.URL) {
	reqURL.Scheme = upstream.Scheme
	reqURL.Host = upstream.Host
	reqURL.Path, reqURL.RawPath = joinURLPath(upstream, reqURL)
	if upstream.RawQuery == "" || reqURL.RawQuery == "" {
		reqURL.RawQuery = upstream.RawQuery + reqURL.RawQuery
	} else {
		reqURL.RawQuery = upstream.RawQuery + "&" + reqURL.RawQuery
	}
}

// joinURLPath mirrors net/http/httputil.joinURLPath.
func joinURLPath(a, b *url.URL) (path, rawpath string) {
	if a.RawPath == "" && b.RawPath == "" {
		return singleJoiningSlash(a.Path, b.Path), ""
	}
	apath := a.EscapedPath()
	bpath := b.EscapedPath()
	aslash := strings.HasSuffix(apath, "/")
	bslash := strings.HasPrefix(bpath, "/")
	switch {
	case aslash && bslash:
		return a.Path + b.Path[1:], apath + bpath[1:]
	case !aslash && !bslash:
		return a.Path + "/" + b.Path, apath + "/" + bpath
	}
	return a.Path + b.Path, apath + bpath
}

func singleJoiningSlash(a, b string) string {
	aslash := strings.HasSuffix(a, "/")
	bslash := strings.HasPrefix(b, "/")
	switch {
	case aslash && bslash:
		return a + b[1:]
	case !aslash && !bslash:
		return a + "/" + b
	}
	return a + b
}

// serveBuiltinDecoy serves the generated decoy website for the builtin site
// mode. It is intentionally minimal: a landing page, robots.txt and favicon,
// with ordinary 404s for everything else.
func serveBuiltinDecoy(w http.ResponseWriter, r *http.Request, cfg Config) {
	w.Header().Set("Server", cfg.ServerHeader)

	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.NotFound(w, r)
		return
	}

	switch r.URL.Path {
	case "/", "/index.html":
		writeBuiltinDecoyPage(w, r, cfg, http.StatusOK)
	case "/robots.txt":
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		if r.Method == http.MethodHead {
			w.WriteHeader(http.StatusOK)
			return
		}
		_, _ = io.WriteString(w, "User-agent: *\nDisallow:\n")
	case "/favicon.ico":
		w.WriteHeader(http.StatusNoContent)
	default:
		http.NotFound(w, r)
	}
}

// writeBuiltinDecoyPage renders the generated decoy landing page with the given
// status code. It is also the site proxy's upstream-failure fallback, so proxy
// failures never surface as 502s or internal errors.
func writeBuiltinDecoyPage(w http.ResponseWriter, r *http.Request, cfg Config, status int) {
	w.Header().Set("Server", cfg.ServerHeader)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=300")
	body := fmt.Sprintf(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>%s</title>
</head>
<body>
<main>
<h1>%s</h1>
<p>The site is running.</p>
</main>
</body>
</html>
`, cfg.SiteName, cfg.SiteName)
	if r.Method == http.MethodHead {
		w.WriteHeader(status)
		return
	}
	w.WriteHeader(status)
	_, _ = io.WriteString(w, body)
}
