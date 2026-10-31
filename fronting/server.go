package fronting

import (
	"context"
	"errors"
	"net"
	"net/http"
	"sync"
	"time"

	"golang.org/x/net/http2"
)

// Default server tuning for the camouflage listener. They mirror the TSUNAMI
// server: bounded header reads and a short idle timeout keep probe connections
// from pinning resources.
const (
	serverReadHeaderTimeout = 10 * time.Second
	serverIdleTimeout       = 2 * time.Minute
	serverMaxHeaderBytes    = 1 << 20
)

// ServeHTTP2 runs an HTTP/2 server on an already-handshaked connection (ALPN
// h2). Authenticated POST requests to cfg.Path are converted into a net.Conn
// that carries the tunnel byte stream and passed to onTunnel, which must block
// until the tunnel ends. Every other request (and every request when fronting
// is disabled) is answered by decoy; a nil decoy selects the built-in site
// handler from NewSiteHandler.
//
// ServeHTTP2 blocks until the connection ends. It does not report protocol
// errors from the peer, and never leaks them as HTTP error responses.
func ServeHTTP2(ctx context.Context, conn net.Conn, cfg Config, onTunnel func(net.Conn) error, decoy http.Handler) error {
	if conn == nil {
		return errors.New("fronting: nil connection")
	}
	handler, err := newFrontingHandler(cfg, onTunnel, decoy, false)
	if err != nil {
		conn.Close()
		return err
	}
	if ctx == nil {
		ctx = context.Background()
	}

	server := &http2.Server{
		MaxReadFrameSize:             H2MaxFrameSize,
		MaxUploadBufferPerConnection: H2FlowControlWindow,
		MaxUploadBufferPerStream:     H2FlowControlWindow,
	}
	opts := &http2.ServeConnOpts{
		Context: ctx,
		Handler: handler,
		BaseConfig: &http.Server{
			ReadHeaderTimeout: serverReadHeaderTimeout,
			IdleTimeout:       serverIdleTimeout,
			MaxHeaderBytes:    serverMaxHeaderBytes,
		},
	}

	// http2.ServeConn has no cancellation mechanism, so closing the connection
	// is the only way to honor ctx.
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			_ = conn.Close()
		case <-done:
		}
	}()

	server.ServeConn(conn, opts)
	return nil
}

// ServeHTTP1 is the WebSocket-transport counterpart of ServeHTTP2: it runs an
// HTTP/1.1 server on the single already-handshaked connection (ALPN
// http/1.1). An authenticated GET upgrade to cfg.Path is converted into a
// net.Conn and passed to onTunnel, which must block until the tunnel ends.
// Everything else is answered by decoy; a nil decoy selects the built-in site
// handler from NewSiteHandler.
//
// ServeHTTP1 blocks until the connection ends.
func ServeHTTP1(ctx context.Context, conn net.Conn, cfg Config, onTunnel func(net.Conn) error, decoy http.Handler) error {
	if conn == nil {
		return errors.New("fronting: nil connection")
	}
	handler, err := newFrontingHandler(cfg, onTunnel, decoy, true)
	if err != nil {
		conn.Close()
		return err
	}
	if ctx == nil {
		ctx = context.Background()
	}
	handler.started = make(chan struct{})
	handler.finished = make(chan struct{})

	watched := newWatchedConn(conn)
	listener := newSingleConnListener(watched)
	server := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: serverReadHeaderTimeout,
		IdleTimeout:       serverIdleTimeout,
		MaxHeaderBytes:    serverMaxHeaderBytes,
	}

	serveErr := make(chan error, 1)
	go func() { serveErr <- server.Serve(listener) }()

	select {
	case <-watched.closed:
	case <-ctx.Done():
	}

	_ = listener.Close() // unblocks the Accept loop
	_ = server.Close()   // closes a connection still in plain HTTP/1.1 state
	_ = watched.Close()  // terminates a hijacked WebSocket tunnel

	// If a tunnel was established, let its handler unwind before returning.
	// onTunnel is expected to return once the underlying conn is closed; the
	// timeout only guards against a handler that ignores that.
	select {
	case <-handler.started:
		select {
		case <-handler.finished:
		case <-time.After(5 * time.Second):
		}
	default:
	}

	select {
	case <-serveErr:
	case <-time.After(5 * time.Second):
	}
	return nil
}

// frontingHandler implements the HTTP-level dispatch shared by both server
// transports: authenticated tunnel requests win, everything else is decoy.
type frontingHandler struct {
	cfg       Config
	key       [32]byte
	hasKey    bool
	cache     *NonceCache
	onTunnel  func(net.Conn) error
	decoy     http.Handler
	webSocket bool

	// started and finished are used by ServeHTTP1 to wait for an established
	// tunnel to unwind; they are nil on the HTTP/2 path.
	started    chan struct{}
	finished   chan struct{}
	startOnce  sync.Once
	finishOnce sync.Once
}

// newFrontingHandler normalizes cfg and builds the request dispatcher.
func newFrontingHandler(cfg Config, onTunnel func(net.Conn) error, decoy http.Handler, webSocket bool) (*frontingHandler, error) {
	if onTunnel == nil {
		return nil, errors.New("fronting: nil tunnel handler")
	}
	if err := cfg.Normalize(); err != nil {
		return nil, err
	}
	if cfg.Enabled && cfg.Secret == "" {
		return nil, errors.New("fronting: enabled fronting requires a secret")
	}
	if decoy == nil {
		builtin, err := NewSiteHandler(cfg)
		if err != nil {
			return nil, err
		}
		decoy = builtin
	}
	handler := &frontingHandler{
		cfg:       cfg,
		onTunnel:  onTunnel,
		decoy:     decoy,
		webSocket: webSocket,
		cache:     NewNonceCache(ClockSkew + 30*time.Second),
	}
	if cfg.Enabled && cfg.Secret != "" {
		handler.key = KeyFromSecret(cfg.Secret)
		handler.hasKey = true
	}
	return handler, nil
}

func (h *frontingHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Server", h.cfg.ServerHeader)
	if h.tryTunnel(w, r) {
		return
	}
	// Align the decoy time-to-first-byte with the tunnel path so an observer
	// cannot distinguish authentication failure from success by timing.
	time.Sleep(authJitter())
	h.decoy.ServeHTTP(w, r)
}

// tryTunnel reports whether the request was handled as a tunnel.
func (h *frontingHandler) tryTunnel(w http.ResponseWriter, r *http.Request) bool {
	if !h.cfg.Enabled || !h.hasKey {
		return false
	}
	if r.URL == nil || r.URL.Path != h.cfg.Path {
		return false
	}

	if h.webSocket {
		// The WebSocket transport is an HTTP/1.1 GET upgrade.
		if r.Method != http.MethodGet || !isWebSocketUpgrade(r) {
			return false
		}
		if !VerifyRequest(r, [][32]byte{h.key}, time.Now(), ClockSkew, h.cache) {
			return false
		}
		return h.serveWebSocketTunnel(w, r)
	}

	// The h2 transport is a POST with the tunnel as the request/response body.
	if r.Method != http.MethodPost {
		return false
	}
	if !VerifyRequest(r, [][32]byte{h.key}, time.Now(), ClockSkew, h.cache) {
		return false
	}
	return h.serveHTTP2Tunnel(w, r)
}

// serveHTTP2Tunnel commits the octet-stream response and runs the tunnel.
func (h *frontingHandler) serveHTTP2Tunnel(w http.ResponseWriter, r *http.Request) bool {
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	if flusher, ok := w.(http.Flusher); ok {
		flusher.Flush()
	}
	h.runTunnel(newHTTPServerConn(w, r))
	return true
}

// serveWebSocketTunnel upgrades the request to a WebSocket tunnel.
func (h *frontingHandler) serveWebSocketTunnel(w http.ResponseWriter, r *http.Request) bool {
	tunnel, hijacked, err := upgradeServer(w, r, h.cfg.ServerHeader)
	if err != nil {
		if hijacked {
			// The 101 response may already be on the wire; nothing sensible can
			// be written any more, and a decoy response would corrupt the
			// stream.
			return true
		}
		return false
	}
	h.runTunnel(tunnel)
	return true
}

// runTunnel invokes onTunnel with conn and closes conn afterwards. A panic in
// the tunnel handler must not surface as an HTTP error: the response is already
// committed, so the panic is swallowed (http.ErrAbortHandler keeps its usual
// abort semantics).
func (h *frontingHandler) runTunnel(conn net.Conn) {
	if h.started != nil {
		h.startOnce.Do(func() { close(h.started) })
	}
	defer func() {
		recovered := recover()
		_ = conn.Close()
		if h.finished != nil {
			h.finishOnce.Do(func() { close(h.finished) })
		}
		if recovered != nil && recovered != http.ErrAbortHandler {
			return
		}
		if recovered != nil {
			panic(recovered)
		}
	}()
	_ = h.onTunnel(conn)
}

// watchedConn reports when the connection is closed (by the HTTP server for a
// normal connection, or by the tunnel handler for a hijacked one).
type watchedConn struct {
	net.Conn
	once   sync.Once
	closed chan struct{}
}

func newWatchedConn(conn net.Conn) *watchedConn {
	return &watchedConn{Conn: conn, closed: make(chan struct{})}
}

func (c *watchedConn) Close() error {
	c.once.Do(func() { close(c.closed) })
	return c.Conn.Close()
}

// singleConnListener hands out exactly one connection, then blocks until the
// listener is closed. That keeps http.Server.Serve waiting for the single
// connection instead of returning early.
type singleConnListener struct {
	conn net.Conn
	addr net.Addr

	mu        sync.Mutex
	accepted  bool
	closed    chan struct{}
	closeOnce sync.Once
}

func newSingleConnListener(conn net.Conn) *singleConnListener {
	listener := &singleConnListener{conn: conn, closed: make(chan struct{})}
	if conn != nil {
		listener.addr = conn.LocalAddr()
	}
	return listener
}

func (l *singleConnListener) Accept() (net.Conn, error) {
	l.mu.Lock()
	if !l.accepted {
		l.accepted = true
		conn := l.conn
		l.mu.Unlock()
		return conn, nil
	}
	l.mu.Unlock()
	<-l.closed
	return nil, net.ErrClosed
}

func (l *singleConnListener) Close() error {
	l.closeOnce.Do(func() { close(l.closed) })
	return nil
}

func (l *singleConnListener) Addr() net.Addr { return l.addr }
