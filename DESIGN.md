# sing-tsunami design / porting notes

This repository is the TSUNAMI protocol as a standalone Go module for sing-box
integration. Source of truth for wire semantics is the TSUNAMI implementation
at `https://github.com/RavenholmAlpha/tsunami` (local checkout:
`D:\claudeproject\tsunami` during development).

## Package layout

```
protocol/   frame, command, auth, settings, session, stream, address helpers
padding/    padding scheme v2 (parser, writer, keepalive) - imports protocol
fronting/   HTTPS/HTTP2/WebSocket fronting, HMAC, decoy/site handler - no protocol import
client.go   root package tsunami: client session pool + Dial/CreateStream
service.go  root package tsunami: server-side auth + session + per-stream handler
```

Root package name is `tsunami`; module path is
`github.com/RavenholmAlpha/sing-tsunami`.

## Root API (frozen for the sing-box adapter)

```go
package tsunami

type User struct { Name, Password string }

type ClientConfig struct {
    // Password is the TSUNAMI user password; auth sends SHA-256(password).
    Password string
    // DialOut returns a transport connection ready for the TSUNAMI handshake:
    // plain TLS, or a fronting tunnel returned by fronting.NewClientConn.
    // Called by the session pool when it needs a new session.
    DialOut func(ctx context.Context) (net.Conn, error)
    // PaddingScheme is the initial scheme text; nil uses padding.DefaultScheme().
    PaddingScheme []byte
    IdleSessionCheckInterval time.Duration // default 30s
    IdleSessionTimeout       time.Duration // default 5m
    MinIdleSession           int           // default 0
}

func NewClient(ctx context.Context, cfg ClientConfig) (*Client, error)
func (c *Client) CreateStream(ctx context.Context) (net.Conn, error)
func (c *Client) Dial(ctx context.Context, destination string) (net.Conn, error) // CreateStream + WriteAddr
func (c *Client) Close() error

type ServiceConfig struct {
    Users         []User
    PaddingScheme []byte // nil uses padding.DefaultScheme()
    // Handler runs once per opened stream, in its own goroutine. destination
    // is the SOCKS5 address the client wrote first ("host:port", IPv6 without
    // brackets is possible; use net.JoinHostPort style consumers). The handler
    // owns conn and must close it.
    Handler func(ctx context.Context, conn net.Conn, source net.Addr, destination string)
}

func NewService(cfg ServiceConfig) (*Service, error)
// NewConnection blocks until the session ends; conn is post-TLS (or a
// fronting tunnel from fronting.ServeHTTP2).
func (s *Service) NewConnection(ctx context.Context, conn net.Conn, source net.Addr) error

func WriteAddr(w io.Writer, destination string) error // SOCKS5 ATYP encoding
func ReadAddr(r io.Reader) (string, error)            // returns "host:port"
```

## Fronting API

```go
package fronting

type SiteMode string // "builtin", "local", "remote"

type SiteConfig struct {
    Mode               SiteMode
    Upstream           string // required for local/remote; URL or host:port
    PreserveHost       *bool  // default: local=true, remote=false
    InsecureSkipVerify bool
}

type Config struct {
    Enabled      bool
    Path         string // e.g. /static/js/main.1a2b3c4d.js
    Host         string // client Host header override (defaults to SNI)
    Secret       string
    Transport    string // "h2" (default) or "websocket"
    ServerHeader string // default "Caddy"
    SiteName     string // built-in decoy page title, default "Welcome"
    Site         SiteConfig
}

// Normalize fills defaults and validates Path/Transport/Site; returns error.
func (c *Config) Normalize() error

// NewClientConn wraps an already-handshaked TLS conn (ALPN h2 for the h2
// transport) and performs the signed fronting request. The returned conn is
// the tunnel byte stream.
func NewClientConn(conn net.Conn, cfg Config) (net.Conn, error)

// ServeHTTP2 runs an HTTP/2 server on an already-handshaked TLS conn (ALPN
// h2). Authenticated requests to cfg.Path are converted into a net.Conn and
// passed to onTunnel (which must block until the tunnel ends); every other
// request is served by decoy.
func ServeHTTP2(ctx context.Context, conn net.Conn, cfg Config, onTunnel func(net.Conn) error, decoy http.Handler) error

// ServeHTTP1 is the WebSocket-transport counterpart (HTTP/1.1 upgrade).
func ServeHTTP1(ctx context.Context, conn net.Conn, cfg Config, onTunnel func(net.Conn) error, decoy http.Handler) error

// NewSiteHandler builds the decoy handler for unauthenticated requests:
// builtin generated page, or httputil.ReverseProxy to cfg.Site.Upstream with
// Caddy-like semantics (Host rewrite unless preserve_host, X-Forwarded-*,
// Alt-Svc stripped, upstream failure falls back to the built-in page).
func NewSiteHandler(cfg Config) (http.Handler, error)

func SignRequest(req *http.Request, key [32]byte, now time.Time)
func VerifyRequest(req *http.Request, keys [][32]byte, now time.Time, skew time.Duration, cache *NonceCache) bool
func KeyFromSecret(secret string) [32]byte
```

## Porting rules

- Copy from the TSUNAMI repo, keeping wire behavior byte-identical:
  `pkg/protocol/{frame,command,auth,settings,session,stream,address}.go`,
  `pkg/padding/{scheme,writer}.go`, `pkg/fronting/{auth,httpconn,ws,config}.go`,
  plus `pkg/client` (dial/auth/settings), `pkg/server` (auth/settings/session
  loop/padding push), `pkg/mux/pool.go` (client session pool), and the
  site-camouflage handler from `pkg/server/server.go`.
- Rewrite imports: `github.com/tsunami-protocol/tsunami/pkg/protocol` becomes
  `github.com/RavenholmAlpha/sing-tsunami/protocol`, etc.
- Keep protocol constants and command numbers exactly as in the source.
- No TSUNAMI binary/config/control-plane/fronting-CLI dependencies; no
  `pkg/surge`, `pkg/control`, `pkg/node`, `pkg/config`, `pkg/fallback`.
- Fronting must use `golang.org/x/net/http2` for the client and
  `http2.ServeConn` for the server (no `net/http.Server` on a listener).
- Keep error text useful but avoid leaking secrets (never log passwords,
  fronting secrets or raw auth hashes).
- Dependencies: stdlib + `golang.org/x/net` only.
- Code must be `gofmt` clean and pass `go vet ./...`.
- Write unit tests for frame, padding, auth/settings, session lifecycle and
  fronting HMAC/tunnel adapters. Add a loopback TLS client↔service test if
  practical.

## sing-box adapter contract (implemented on the fork branch)

- outbound: `DialOut` = `common/tls` dialer (uTLS Chrome fingerprint when
  configured) + optional `fronting.NewClientConn`.
- inbound: TLS handshake, then either `Service.NewConnection` (no fronting) or
  `fronting.ServeHTTP2/ServeHTTP1` with `onTunnel` calling
  `Service.NewConnection` and `decoy` from `fronting.NewSiteHandler`.
- Destination handling: `CreateStream` + `WriteAddr` on the client,
  `ReadAddr`/Handler destination on the service.
- UoT is handled by the sing-box adapter (`sing/common/uot`), not this module.
