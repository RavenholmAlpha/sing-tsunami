package fronting

import (
	"net"
	"strings"
	"testing"
)

func boolPtr(v bool) *bool { return &v }

func TestNormalizeDefaults(t *testing.T) {
	var cfg Config
	if err := cfg.Normalize(); err != nil {
		t.Fatalf("Normalize() = %v", err)
	}
	if cfg.Path != DefaultPath {
		t.Fatalf("Path = %q, want %q", cfg.Path, DefaultPath)
	}
	if cfg.Transport != TransportH2 {
		t.Fatalf("Transport = %q, want %q", cfg.Transport, TransportH2)
	}
	if cfg.ServerHeader != DefaultServerHeader {
		t.Fatalf("ServerHeader = %q, want %q", cfg.ServerHeader, DefaultServerHeader)
	}
	if cfg.SiteName != "Welcome" {
		t.Fatalf("SiteName = %q, want Welcome", cfg.SiteName)
	}
	if cfg.Site.Mode != SiteModeBuiltin {
		t.Fatalf("Site.Mode = %q, want builtin", cfg.Site.Mode)
	}
	if cfg.Site.upstreamURL() != nil {
		t.Fatal("builtin site mode exposed an upstream URL")
	}
	if cfg.Enabled {
		t.Fatal("Enabled defaulted to true")
	}
	if cfg.Site.preserveHostEnabled() {
		t.Fatal("builtin site mode reported preserve_host")
	}
}

func TestNormalizePath(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		want    string
		wantErr bool
	}{
		{name: "empty", in: "", want: DefaultPath},
		{name: "relative", in: "static/app.js", want: "/static/app.js"},
		{name: "clean", in: "/static/../assets/./update", want: "/assets/update"},
		{name: "root", in: "/", want: "/"},
		{name: "query", in: "/assets/update?x=1", wantErr: true},
		{name: "fragment", in: "/assets#frag", wantErr: true},
		{name: "space", in: "/assets update", wantErr: true},
		{name: "control", in: "/assets\x01update", wantErr: true},
		{name: "backslash", in: `\assets\update`, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := Config{Path: tt.in}
			err := cfg.Normalize()
			if tt.wantErr {
				if err == nil {
					t.Fatalf("Normalize() accepted path %q", tt.in)
				}
				return
			}
			if err != nil {
				t.Fatalf("Normalize() = %v", err)
			}
			if cfg.Path != tt.want {
				t.Fatalf("Path = %q, want %q", cfg.Path, tt.want)
			}
		})
	}
}

func TestNormalizeHost(t *testing.T) {
	if err := (&Config{Host: "example.com:8443"}).Normalize(); err != nil {
		t.Fatalf("valid host rejected: %v", err)
	}
	for _, host := range []string{"exa mple.com", "example.com/path", "user@example.com", "example.com?x"} {
		if err := (&Config{Host: host}).Normalize(); err == nil {
			t.Fatalf("invalid host %q accepted", host)
		}
	}
}

func TestNormalizeTransport(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		want    string
		wantErr bool
	}{
		{name: "empty", in: "", want: TransportH2},
		{name: "h2", in: "h2", want: TransportH2},
		{name: "upper h2", in: "H2", want: TransportH2},
		{name: "websocket", in: TransportWebSocket, want: TransportWebSocket},
		{name: "padded websocket", in: " websocket ", want: TransportWebSocket},
		{name: "invalid", in: "quic", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := Config{Transport: tt.in}
			err := cfg.Normalize()
			if tt.wantErr {
				if err == nil {
					t.Fatalf("Normalize() accepted transport %q", tt.in)
				}
				return
			}
			if err != nil {
				t.Fatalf("Normalize() = %v", err)
			}
			if cfg.Transport != tt.want {
				t.Fatalf("Transport = %q, want %q", cfg.Transport, tt.want)
			}
		})
	}
}

func TestNormalizeInfersSiteMode(t *testing.T) {
	tests := []struct {
		name        string
		site        SiteConfig
		wantMode    SiteMode
		wantUpstrm  string
		wantPreserv bool
	}{
		{name: "no upstream is builtin", wantMode: SiteModeBuiltin},
		{name: "builtin mode is kept", site: SiteConfig{Mode: SiteModeBuiltin}, wantMode: SiteModeBuiltin},
		{
			name: "loopback ipv4 upstream is local", site: SiteConfig{Upstream: "http://127.0.0.1:8080"},
			wantMode: SiteModeLocal, wantUpstrm: "http://127.0.0.1:8080", wantPreserv: true,
		},
		{
			name: "localhost name is local", site: SiteConfig{Upstream: "localhost:8080"},
			wantMode: SiteModeLocal, wantUpstrm: "http://localhost:8080", wantPreserv: true,
		},
		{
			name: "loopback ipv6 is local", site: SiteConfig{Upstream: "[::1]:8080"},
			wantMode: SiteModeLocal, wantUpstrm: "http://[::1]:8080", wantPreserv: true,
		},
		{
			name: "rfc1918 upstream is local", site: SiteConfig{Upstream: "10.1.2.3:8080"},
			wantMode: SiteModeLocal, wantUpstrm: "http://10.1.2.3:8080", wantPreserv: true,
		},
		{
			name: "ipv6 ula upstream is local", site: SiteConfig{Upstream: "http://[fd00::1]:8080"},
			wantMode: SiteModeLocal, wantUpstrm: "http://[fd00::1]:8080", wantPreserv: true,
		},
		{
			name: "link local upstream is local", site: SiteConfig{Upstream: "169.254.10.20:80"},
			wantMode: SiteModeLocal, wantUpstrm: "http://169.254.10.20:80", wantPreserv: true,
		},
		{
			name: "public host is remote", site: SiteConfig{Upstream: "https://www.example.com"},
			wantMode: SiteModeRemote, wantUpstrm: "https://www.example.com", wantPreserv: false,
		},
		{
			name: "explicit local is respected", site: SiteConfig{Mode: SiteModeLocal, Upstream: "http://192.168.1.5:8080"},
			wantMode: SiteModeLocal, wantUpstrm: "http://192.168.1.5:8080", wantPreserv: true,
		},
		{
			name: "explicit remote is respected", site: SiteConfig{Mode: SiteModeRemote, Upstream: "http://127.0.0.1:8080"},
			wantMode: SiteModeRemote, wantUpstrm: "http://127.0.0.1:8080", wantPreserv: false,
		},
		{
			name: "explicit preserve_host false wins", site: SiteConfig{Mode: SiteModeLocal, Upstream: "http://127.0.0.1:8080", PreserveHost: boolPtr(false)},
			wantMode: SiteModeLocal, wantUpstrm: "http://127.0.0.1:8080", wantPreserv: false,
		},
		{
			name: "explicit preserve_host true wins", site: SiteConfig{Mode: SiteModeRemote, Upstream: "https://www.example.com", PreserveHost: boolPtr(true)},
			wantMode: SiteModeRemote, wantUpstrm: "https://www.example.com", wantPreserv: true,
		},
		{
			name: "builtin ignores upstream", site: SiteConfig{Mode: SiteModeBuiltin, Upstream: "not a url"},
			wantMode: SiteModeBuiltin, wantUpstrm: "not a url",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := Config{Site: tt.site}
			if err := cfg.Normalize(); err != nil {
				t.Fatalf("Normalize() = %v", err)
			}
			if cfg.Site.Mode != tt.wantMode {
				t.Fatalf("site mode = %q, want %q", cfg.Site.Mode, tt.wantMode)
			}
			if cfg.Site.Upstream != tt.wantUpstrm {
				t.Fatalf("site upstream = %q, want %q", cfg.Site.Upstream, tt.wantUpstrm)
			}
			if got := cfg.Site.preserveHostEnabled(); got != tt.wantPreserv {
				t.Fatalf("preserve host = %t, want %t", got, tt.wantPreserv)
			}
			if tt.wantMode == SiteModeBuiltin && cfg.Site.upstreamURL() != nil {
				t.Fatal("builtin mode parsed an upstream URL")
			}
			if tt.wantMode != SiteModeBuiltin && cfg.Site.upstreamURL() == nil {
				t.Fatal("local/remote mode did not parse an upstream URL")
			}
		})
	}
}

func TestNormalizeInfersUpstreamScheme(t *testing.T) {
	tests := []struct {
		name       string
		upstream   string
		wantScheme string
		wantHost   string
	}{
		{name: "bare host port defaults to http", upstream: "127.0.0.1:8080", wantScheme: "http", wantHost: "127.0.0.1:8080"},
		{name: "bare host port 443 is https", upstream: "site.example.com:443", wantScheme: "https", wantHost: "site.example.com:443"},
		{name: "bare host defaults to http", upstream: "origin.example.com", wantScheme: "http", wantHost: "origin.example.com"},
		{name: "explicit https kept", upstream: "https://site.example.com:8443", wantScheme: "https", wantHost: "site.example.com:8443"},
		{name: "explicit http kept", upstream: "http://site.example.com:8080", wantScheme: "http", wantHost: "site.example.com:8080"},
		{name: "bare ipv6 443 is https", upstream: "[::1]:443", wantScheme: "https", wantHost: "[::1]:443"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := Config{Site: SiteConfig{Upstream: tt.upstream}}
			if err := cfg.Normalize(); err != nil {
				t.Fatalf("Normalize() = %v", err)
			}
			parsed := cfg.Site.upstreamURL()
			if parsed == nil {
				t.Fatal("upstream URL was not parsed")
			}
			if parsed.Scheme != tt.wantScheme {
				t.Fatalf("scheme = %q, want %q", parsed.Scheme, tt.wantScheme)
			}
			if parsed.Host != tt.wantHost {
				t.Fatalf("host = %q, want %q", parsed.Host, tt.wantHost)
			}
		})
	}
}

func TestNormalizeTrimsUpstreamTrailingSlash(t *testing.T) {
	cfg := Config{Site: SiteConfig{Upstream: "http://127.0.0.1:8080/"}}
	if err := cfg.Normalize(); err != nil {
		t.Fatalf("Normalize() = %v", err)
	}
	if cfg.Site.Upstream != "http://127.0.0.1:8080" {
		t.Fatalf("upstream = %q, want trailing slash trimmed", cfg.Site.Upstream)
	}

	withPath := Config{Site: SiteConfig{Mode: SiteModeLocal, Upstream: "http://127.0.0.1:8080/base/"}}
	if err := withPath.Normalize(); err != nil {
		t.Fatalf("Normalize() = %v", err)
	}
	if withPath.Site.Upstream != "http://127.0.0.1:8080/base" {
		t.Fatalf("upstream with path = %q, want trailing slash trimmed", withPath.Site.Upstream)
	}
}

func TestNormalizeSiteRejectsInvalidUpstreams(t *testing.T) {
	tests := []struct {
		name     string
		site     SiteConfig
		wantPart string
	}{
		{name: "unsupported scheme", site: SiteConfig{Upstream: "ftp://127.0.0.1:21"}, wantPart: "must use http or https"},
		{name: "missing host", site: SiteConfig{Upstream: "https://"}, wantPart: "has no host"},
		{name: "unparsable url", site: SiteConfig{Upstream: "http://exa mple.com"}, wantPart: "parse site upstream"},
		{name: "credentials not supported", site: SiteConfig{Upstream: "http://user:pass@127.0.0.1:8080"}, wantPart: "must not contain credentials"},
		{name: "invalid port", site: SiteConfig{Upstream: "http://127.0.0.1:99999"}, wantPart: "invalid port"},
		{name: "non numeric port", site: SiteConfig{Upstream: "http://127.0.0.1:http"}, wantPart: "parse site upstream"},
		{name: "local mode without upstream", site: SiteConfig{Mode: SiteModeLocal}, wantPart: "requires a site upstream"},
		{name: "remote mode without upstream", site: SiteConfig{Mode: SiteModeRemote}, wantPart: "requires a site upstream"},
		{name: "unknown mode", site: SiteConfig{Mode: SiteMode("neighbour"), Upstream: "https://example.com"}, wantPart: "unsupported site mode"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := Config{Site: tt.site}
			err := cfg.Normalize()
			if err == nil {
				t.Fatal("expected a site configuration error")
			}
			if !strings.Contains(err.Error(), tt.wantPart) {
				t.Fatalf("error = %q, want it to contain %q", err, tt.wantPart)
			}
		})
	}
}

func TestNormalizeSiteIgnoresFragment(t *testing.T) {
	cfg := Config{Site: SiteConfig{Upstream: "https://example.com/site#fragment"}}
	if err := cfg.Normalize(); err != nil {
		t.Fatalf("Normalize() = %v", err)
	}
	if got := cfg.Site.upstreamURL().Fragment; got != "" {
		t.Fatalf("upstream fragment = %q, want empty", got)
	}
}

func TestNormalizeIsIdempotent(t *testing.T) {
	cfg := Config{
		Path:      "/static/app.js",
		Transport: TransportWebSocket,
		Site:      SiteConfig{Upstream: "127.0.0.1:8080/"},
	}
	if err := cfg.Normalize(); err != nil {
		t.Fatalf("first Normalize() = %v", err)
	}
	first := cfg
	if err := cfg.Normalize(); err != nil {
		t.Fatalf("second Normalize() = %v", err)
	}
	if cfg.Path != first.Path || cfg.Transport != first.Transport ||
		cfg.ServerHeader != first.ServerHeader || cfg.SiteName != first.SiteName {
		t.Fatalf("second Normalize changed defaults: %+v -> %+v", first, cfg)
	}
	if cfg.Site.Mode != first.Site.Mode || cfg.Site.Upstream != first.Site.Upstream {
		t.Fatalf("second Normalize changed site config: %+v -> %+v", first.Site, cfg.Site)
	}
	if cfg.Site.upstreamURL() == nil || cfg.Site.upstreamURL().String() != "http://127.0.0.1:8080" {
		t.Fatalf("upstream URL after second Normalize = %v", cfg.Site.upstreamURL())
	}
}

func TestTunnelHost(t *testing.T) {
	cfg := Config{Host: "front.example.com"}
	if err := cfg.Normalize(); err != nil {
		t.Fatalf("Normalize() = %v", err)
	}
	host, err := tunnelHost(&cfg, nil)
	if err != nil || host != "front.example.com" {
		t.Fatalf("tunnelHost = %q, %v", host, err)
	}

	// Without an override the peer address is used (net.Pipe reports "pipe").
	serverSide, clientSide := net.Pipe()
	defer serverSide.Close()
	defer clientSide.Close()
	auto := Config{}
	if err := auto.Normalize(); err != nil {
		t.Fatalf("Normalize() = %v", err)
	}
	host, err = tunnelHost(&auto, serverSide)
	if err != nil || host != "pipe" {
		t.Fatalf("tunnelHost(pipe) = %q, %v", host, err)
	}

	if got := endpointURL("front.example.com", DefaultPath); got != "https://front.example.com"+DefaultPath {
		t.Fatalf("endpointURL = %q", got)
	}
}
