// Package fronting implements the TSUNAMI HTTPS/HTTP2/WebSocket fronting
// layer: HTTP-layer request signing and replay protection, client and server
// side net.Conn adapters for the authenticated tunnel, and the decoy site
// handler that answers unauthenticated traffic.
//
// The package does not import the TSUNAMI protocol package. Callers are
// responsible for the transport itself: fronting works on a connection that has
// already completed its TLS handshake (ALPN "h2" for the h2 transport,
// "http/1.1" for the WebSocket transport).
package fronting

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"path"
	"strconv"
	"strings"
	"time"
)

const (
	// TransportH2 carries the tunnel over an HTTP/2 POST request/response
	// stream.
	TransportH2 = "h2"
	// TransportWebSocket carries the tunnel over an HTTP/1.1 WebSocket
	// upgrade.
	TransportWebSocket = "websocket"

	// DefaultPath is deliberately ordinary-looking and can be overridden.
	DefaultPath = "/assets/update"
	// DefaultServerHeader matches Caddy's default HTTP Server header.
	DefaultServerHeader = "Caddy"
	// DefaultUserAgent mimics a recent Chrome browser to blend with normal
	// traffic.
	DefaultUserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"

	// H2FlowControlWindow is set to 4 MiB per stream, within the range real Go
	// HTTP/2 servers use, while still supporting high throughput on
	// high-latency links.
	H2FlowControlWindow int32 = 4 << 20
	// H2MaxFrameSize uses 32 KiB, slightly above Go's 16 KiB default but within
	// the range CDN-fronted servers commonly use.
	H2MaxFrameSize uint32 = 32 << 10

	// ClockSkew is the accepted HTTP-layer auth timestamp window.
	ClockSkew = 2 * time.Minute

	// defaultSiteName is the title of the generated decoy page.
	defaultSiteName = "Welcome"
	// httpFlushThreshold amortizes h2 flushes without delaying control frames.
	httpFlushThreshold = 1 << 20
)

// Config holds the fronting settings shared by the client and server side.
type Config struct {
	// Enabled turns on tunnel handling on the server side. When false, every
	// request is answered by the decoy site handler.
	Enabled bool

	// Path is the HTTP route that accepts authenticated tunnels.
	Path string
	// Host optionally overrides the HTTP Host header (and :authority) on the
	// client. Defaults to the host part of the peer address.
	Host string
	// Secret is the HTTP-layer shared secret. Callers must pass the same secret
	// to the client and the server. Derive the HMAC key with KeyFromSecret.
	Secret string
	// Transport selects the client tunnel transport: h2 or websocket. The
	// server chooses ServeHTTP2 or ServeHTTP1, respectively.
	Transport string

	// ServerHeader is emitted for all HTTP responses. Default: Caddy.
	ServerHeader string
	// SiteName is the title of the built-in decoy website.
	SiteName string
	// Site configures the site camouflage layer that answers unauthenticated
	// fronting requests (built-in page or Caddy-like reverse proxy).
	Site SiteConfig
}

// Normalize fills in default values and validates Path, Transport, Host and
// the site camouflage block. It returns the first configuration error and is
// idempotent: calling it again leaves an already valid configuration
// unchanged.
//
// Normalize must succeed before a Config is used by NewClientConn,
// ServeHTTP2, ServeHTTP1 or NewSiteHandler. Those functions always normalize
// their own copy, so callers may also pass a zero-value Config with only the
// fields they care about.
func (c *Config) Normalize() error {
	if c.Path == "" {
		c.Path = DefaultPath
	}
	tunnelPath := c.Path
	if !strings.HasPrefix(tunnelPath, "/") {
		tunnelPath = "/" + tunnelPath
	}
	tunnelPath = path.Clean(tunnelPath)
	if tunnelPath == "." {
		tunnelPath = DefaultPath
	}
	if strings.ContainsAny(tunnelPath, "?#\\") || containsControl(tunnelPath) {
		return fmt.Errorf("fronting: invalid tunnel path %q", c.Path)
	}
	c.Path = tunnelPath

	if c.Host != "" {
		if strings.ContainsAny(c.Host, "/?#@") || containsControl(c.Host) {
			return fmt.Errorf("fronting: invalid host %q", c.Host)
		}
	}

	switch transport := strings.ToLower(strings.TrimSpace(c.Transport)); transport {
	case "":
		c.Transport = TransportH2
	case TransportH2, TransportWebSocket:
		c.Transport = transport
	default:
		return fmt.Errorf("fronting: unsupported transport %q (want %q or %q)", c.Transport, TransportH2, TransportWebSocket)
	}

	if c.ServerHeader == "" {
		c.ServerHeader = DefaultServerHeader
	}
	if containsControl(c.ServerHeader) {
		return fmt.Errorf("fronting: invalid server header %q", c.ServerHeader)
	}
	if c.SiteName == "" {
		c.SiteName = defaultSiteName
	}
	return c.Site.normalize()
}

// containsControl reports whether s contains bytes that are never valid in an
// HTTP path, Host value or header value.
func containsControl(s string) bool {
	return strings.ContainsFunc(s, func(r rune) bool { return r <= 0x20 || r == 0x7f })
}

// SiteMode selects how the fronting layer answers unauthenticated requests.
type SiteMode string

const (
	// SiteModeBuiltin serves the generated zero-dependency decoy page.
	SiteModeBuiltin SiteMode = "builtin"
	// SiteModeLocal reverse proxies to a local HTTP endpoint. This is the
	// "same-IP real site" mode: the cover website runs next to TSUNAMI.
	SiteModeLocal SiteMode = "local"
	// SiteModeRemote reverse proxies to a third-party website. This is the
	// "borrowed content" mode: the cover site is another real site.
	SiteModeRemote SiteMode = "remote"
)

// SiteConfig configures site camouflage for unauthenticated fronting requests.
// It mirrors the semantics of Caddy's reverse_proxy directive.
type SiteConfig struct {
	// Mode selects builtin, local or remote. Empty infers local for
	// loopback/private/link-local upstreams and remote otherwise.
	Mode SiteMode
	// Upstream is the origin URL (http or https) or a bare host:port. Required
	// for local and remote modes, ignored in builtin mode. Bare host:port
	// values get a scheme inferred with Caddy's rule: https when the port is
	// 443, otherwise http.
	Upstream string
	// PreserveHost keeps the client's Host header on upstream requests. Nil
	// selects the mode default: true for local, false for remote.
	PreserveHost *bool
	// InsecureSkipVerify disables TLS certificate verification for HTTPS
	// upstreams. Only use it when the upstream certificate cannot be fixed.
	InsecureSkipVerify bool

	// upstream is the parsed origin, set by normalize.
	upstream *url.URL
}

// preserveHostEnabled reports whether the client Host header is forwarded to
// the upstream. With no explicit override the mode default applies: local
// preserves the client Host (Caddy's default for same-host upstreams), remote
// rewrites it to the upstream host:port.
func (s SiteConfig) preserveHostEnabled() bool {
	if s.PreserveHost != nil {
		return *s.PreserveHost
	}
	return s.Mode == SiteModeLocal
}

// upstreamURL returns the parsed site upstream, or nil in builtin mode.
func (s SiteConfig) upstreamURL() *url.URL { return s.upstream }

// normalize validates and resolves a site configuration in place.
func (s *SiteConfig) normalize() error {
	mode := SiteMode(strings.ToLower(strings.TrimSpace(string(s.Mode))))
	switch mode {
	case "", SiteModeBuiltin, SiteModeLocal, SiteModeRemote:
	default:
		s.Mode = mode
		s.upstream = nil
		return fmt.Errorf("fronting: unsupported site mode %q (want %q, %q or %q)", s.Mode, SiteModeBuiltin, SiteModeLocal, SiteModeRemote)
	}
	s.Mode = mode
	s.Upstream = strings.TrimSpace(s.Upstream)

	if s.Mode == SiteModeBuiltin {
		s.upstream = nil
		return nil
	}
	if s.Upstream == "" {
		if s.Mode == "" {
			s.Mode = SiteModeBuiltin
			s.upstream = nil
			return nil
		}
		s.upstream = nil
		return fmt.Errorf("fronting: site mode %q requires a site upstream", s.Mode)
	}

	upstream, err := parseSiteUpstream(s.Upstream)
	if err != nil {
		s.upstream = nil
		return err
	}
	s.upstream = upstream
	s.Upstream = upstream.String()
	if s.Mode == "" {
		s.Mode = SiteModeRemote
		if isLocalUpstreamHost(upstream.Hostname()) {
			s.Mode = SiteModeLocal
		}
	}
	return nil
}

// parseSiteUpstream validates and normalizes a site upstream. Bare host:port
// values are accepted and get a scheme inferred with Caddy's rule: https when
// the port is 443, otherwise http. Trailing slashes are trimmed so the
// Caddy-style path join does not emit "//".
func parseSiteUpstream(raw string) (*url.URL, error) {
	value := strings.TrimSpace(raw)
	if !strings.Contains(value, "://") {
		value = inferUpstreamScheme(value) + "://" + value
	}
	parsed, err := url.Parse(value)
	if err != nil {
		return nil, fmt.Errorf("fronting: parse site upstream %q: %w", raw, err)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return nil, fmt.Errorf("fronting: site upstream %q must use http or https, got %q", raw, parsed.Scheme)
	}
	if parsed.Host == "" {
		return nil, fmt.Errorf("fronting: site upstream %q has no host", raw)
	}
	if parsed.User != nil {
		return nil, fmt.Errorf("fronting: site upstream %q must not contain credentials", raw)
	}
	if port := parsed.Port(); port != "" {
		number, err := strconv.Atoi(port)
		if err != nil || number < 1 || number > 65535 {
			return nil, fmt.Errorf("fronting: site upstream %q has invalid port %q", raw, port)
		}
	}
	// Fragments are never forwarded to upstreams.
	parsed.Fragment = ""
	parsed.RawFragment = ""
	// Trim the trailing slash so the Caddy-style path join does not emit "//".
	if strings.HasSuffix(parsed.Path, "/") {
		parsed.Path = strings.TrimRight(parsed.Path, "/")
		parsed.RawPath = ""
	}
	return parsed, nil
}

// inferUpstreamScheme applies Caddy's scheme rule for bare upstreams: https
// when the port is 443, otherwise http.
func inferUpstreamScheme(value string) string {
	if port, ok := bareUpstreamPort(value); ok && port == "443" {
		return "https"
	}
	return "http"
}

// bareUpstreamPort extracts the port from a scheme-less upstream, ignoring any
// path, query or fragment.
func bareUpstreamPort(value string) (string, bool) {
	hostport := value
	if i := strings.IndexAny(hostport, "/?#"); i >= 0 {
		hostport = hostport[:i]
	}
	_, port, err := net.SplitHostPort(hostport)
	if err != nil {
		return "", false
	}
	return port, true
}

// isLocalUpstreamHost reports whether host denotes the local machine (or a
// private/link-local network), which selects local site camouflage.
func isLocalUpstreamHost(host string) bool {
	normalized := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	if normalized == "" {
		return false
	}
	if normalized == "localhost" || strings.HasSuffix(normalized, ".localhost") {
		return true
	}
	address, err := netip.ParseAddr(normalized)
	if err != nil {
		return false
	}
	address = address.Unmap()
	return address.IsLoopback() || address.IsPrivate() ||
		address.IsLinkLocalUnicast() || address.IsUnspecified()
}

// KeyFromSecret derives the fixed-size HTTP-layer HMAC key.
func KeyFromSecret(secret string) [32]byte {
	return sha256.Sum256([]byte(secret))
}

// CaddyLikeTLSConfig returns TLS settings matching Caddy's standard Go TLS
// shape closely enough for this embedded fronting layer. It is provided for
// callers that serve the fronting listener themselves; ALPN already advertises
// "h2" and "http/1.1".
func CaddyLikeTLSConfig(certs []tls.Certificate) *tls.Config {
	return &tls.Config{
		Certificates: certs,
		NextProtos:   []string{"h2", "http/1.1"},
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   tls.VersionTLS13,
		CipherSuites: caddyLikeCipherSuites(),
		CurvePreferences: []tls.CurveID{
			tls.X25519,
			tls.CurveP256,
		},
	}
}

func caddyLikeCipherSuites() []uint16 {
	return []uint16{
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
		tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
	}
}

// tunnelHost returns the HTTP Host / :authority value used for the fronting
// request. Config.Host wins; otherwise the host part of the peer address is
// used (IPv6 literals are bracketed).
func tunnelHost(cfg *Config, conn net.Conn) (string, error) {
	if cfg.Host != "" {
		return cfg.Host, nil
	}
	if conn != nil {
		if addr := conn.RemoteAddr(); addr != nil {
			host := addr.String()
			if h, _, err := net.SplitHostPort(host); err == nil {
				host = h
			}
			if host != "" {
				if strings.Contains(host, ":") && !strings.HasPrefix(host, "[") {
					host = "[" + host + "]"
				}
				return host, nil
			}
		}
	}
	return "", fmt.Errorf("fronting: cannot determine the fronting host: set Config.Host")
}

// endpointURL builds the HTTPS fronting endpoint URL.
func endpointURL(host, tunnelPath string) string {
	return (&url.URL{
		Scheme: "https",
		Host:   host,
		Path:   tunnelPath,
	}).String()
}

// authJitter returns a random duration between 1-5ms to add to the decoy
// response path, making it indistinguishable from the authenticated path's
// time-to-first-byte.
func authJitter() time.Duration {
	var b [2]byte
	_, _ = rand.Read(b[:])
	ms := 1 + int(binary.LittleEndian.Uint16(b[:]))%5
	return time.Duration(ms) * time.Millisecond
}
