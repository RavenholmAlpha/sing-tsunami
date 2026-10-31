// Package tsunami implements the TSUNAMI proxy protocol: the client side
// (session pool, muxed streams, authentication, padding) and the service side
// (authentication, settings exchange, per-stream handler callback).
//
// The package implements the wire protocol only. Transport concerns - TCP,
// TLS, uTLS fingerprints, fronting tunnels, routing and accounting - belong to
// the caller. The protocol, padding and fronting details live in the sibling
// packages protocol, padding and fronting.
package tsunami

import (
	"context"
	"crypto/rand"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/RavenholmAlpha/sing-tsunami/padding"
	"github.com/RavenholmAlpha/sing-tsunami/protocol"
)

const (
	// authPaddingMin and authPaddingMax bound the random padding0 blob carried
	// by the authentication request. Auth padding is deliberately decoupled
	// from the padding scheme: scheme rule 0 belongs to each stream's first
	// data write (the SOCKS target address), not to the session handshake.
	authPaddingMin = 24
	authPaddingMax = 88

	// authConfirmTimeout bounds the wait for the server-settings frame that
	// confirms successful authentication. settingsTimeout bounds the server
	// side read of the client-settings frame.
	authConfirmTimeout = 5 * time.Second
	settingsTimeout    = 5 * time.Second
)

// ClientConfig configures a Client.
type ClientConfig struct {
	// Password is the TSUNAMI user password; auth sends SHA-256(password).
	Password string
	// DialOut returns a transport connection ready for the TSUNAMI handshake:
	// plain TLS, or a fronting tunnel returned by fronting.NewClientConn.
	// Called by the session pool when it needs a new session.
	DialOut func(ctx context.Context) (net.Conn, error)
	// PaddingScheme is the initial scheme text; nil uses padding.DefaultScheme().
	PaddingScheme []byte
	// IdleSessionCheckInterval is how often the pool scans for idle sessions.
	// Default 30s.
	IdleSessionCheckInterval time.Duration
	// IdleSessionTimeout is the nominal idle timeout per session. The effective
	// deadline is jittered by [0.7, 1.3) on every check. Default 5m.
	IdleSessionTimeout time.Duration
	// MinIdleSession is the minimum number of idle sessions to keep alive.
	// Default 0: an idle client drains to zero sessions.
	MinIdleSession int
}

// Client is a TSUNAMI client. It maintains a pool of multiplexed sessions and
// opens one stream per proxied connection.
type Client struct {
	cfg          ClientConfig
	pool         *sessionPool
	passwordHash [protocol.AuthHashLen]byte
	seq          atomic.Uint64

	mu            sync.Mutex
	closed        bool
	paddingScheme *padding.Scheme
}

// NewClient creates a TSUNAMI client. It does not dial: sessions are created
// lazily by the pool when CreateStream/Dial needs one. ctx is accepted for
// symmetry with the rest of the API; per-session contexts are taken from
// CreateStream/Dial.
func NewClient(ctx context.Context, cfg ClientConfig) (*Client, error) {
	if cfg.Password == "" {
		return nil, fmt.Errorf("tsunami: password is required")
	}
	if cfg.DialOut == nil {
		return nil, fmt.Errorf("tsunami: DialOut is required")
	}

	scheme := padding.DefaultScheme()
	if len(cfg.PaddingScheme) > 0 {
		parsed, err := padding.Parse(string(cfg.PaddingScheme))
		if err != nil {
			return nil, fmt.Errorf("tsunami: parse padding scheme: %w", err)
		}
		scheme = parsed
	}

	c := &Client{
		cfg:           cfg,
		passwordHash:  protocol.PasswordHash(cfg.Password),
		paddingScheme: scheme,
	}
	c.pool = newSessionPool(poolOptions{
		minIdleSession:    cfg.MinIdleSession,
		idleCheckInterval: cfg.IdleSessionCheckInterval,
		idleTimeout:       cfg.IdleSessionTimeout,
	}, c.dialSession)
	return c, nil
}

// CreateStream opens a new multiplexed stream. The returned connection carries
// raw tunnel bytes; the caller must write the destination address itself (Dial
// does that) and must close the connection when done.
func (c *Client) CreateStream(ctx context.Context) (net.Conn, error) {
	c.mu.Lock()
	closed := c.closed
	c.mu.Unlock()
	if closed {
		return nil, fmt.Errorf("tsunami: client is closed")
	}
	if ctx == nil {
		ctx = context.Background()
	}

	session, err := c.pool.GetOrCreateSession(ctx)
	if err != nil {
		return nil, fmt.Errorf("tsunami: get session: %w", err)
	}
	stream, err := session.OpenStream()
	if err != nil {
		return nil, fmt.Errorf("tsunami: open stream: %w", err)
	}
	return newStreamConn(stream, streamAddr{network: "tsunami", address: "client"}, streamAddr{network: "tsunami", address: "server"}), nil
}

// Dial opens a new stream to destination ("host:port") by creating a stream
// and writing the target address as its first payload.
func (c *Client) Dial(ctx context.Context, destination string) (net.Conn, error) {
	conn, err := c.CreateStream(ctx)
	if err != nil {
		return nil, err
	}
	if err := WriteAddr(conn, destination); err != nil {
		_ = conn.Close()
		return nil, err
	}
	// Report the proxied destination as the stream's remote address; this is
	// what callers generally expect from a Dial-style API. It is not resolved.
	if sc, ok := conn.(*streamConn); ok {
		sc.remote = streamAddr{network: "tsunami", address: destination}
	}
	return conn, nil
}

// Close shuts down the client and all sessions.
func (c *Client) Close() error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.closed = true
	c.mu.Unlock()

	c.pool.Close()
	return nil
}

// dialSession creates a transport connection, authenticates, exchanges
// settings and starts the session event loop.
func (c *Client) dialSession(ctx context.Context) (*protocol.Session, error) {
	conn, err := c.cfg.DialOut(ctx)
	if err != nil {
		return nil, fmt.Errorf("tsunami: dial: %w", err)
	}
	if conn == nil {
		return nil, fmt.Errorf("tsunami: dial: DialOut returned a nil connection")
	}
	session, err := c.startSession(conn)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	return session, nil
}

// authPaddingLen returns a random auth padding length in
// [authPaddingMin, authPaddingMax], well below protocol.MaxFrameDataLen.
func authPaddingLen() int {
	return padding.RandomInRange(authPaddingMin, authPaddingMax)
}

// startSession performs the client handshake on an established transport
// connection and returns a running protocol.Session.
func (c *Client) startSession(conn net.Conn) (*protocol.Session, error) {
	scheme := c.currentPaddingScheme()

	padding0 := make([]byte, authPaddingLen())
	if _, err := rand.Read(padding0); err != nil {
		return nil, fmt.Errorf("tsunami: generate auth padding: %w", err)
	}
	if err := protocol.EncodeAuthRequest(conn, c.passwordHash, padding0); err != nil {
		return nil, fmt.Errorf("tsunami: send auth request: %w", err)
	}

	session := protocol.NewSession(conn, c.seq.Add(1))

	// Wire the padding writer into the session write path before the first
	// frame is written: settings and every later frame must be padded.
	pw := padding.NewWriterForRole(conn, scheme, padding.RoleClient)
	bindClientPadding(session, pw)
	session.SetOnPaddingSchemeUpdate(func(data []byte) error {
		return c.applyPaddingSchemeUpdate(data, pw)
	})

	settings := &protocol.ClientSettings{
		Version:    protocol.CurrentVersion,
		Client:     "http-client/1.0",
		PaddingMD5: scheme.MD5(),
		// Shaping is not implemented by this library; the field stays false.
		Shaping: false,
		// Advertise that this client parses the v2 padding scheme syntax. The
		// server only pushes scheme text when the client advertises it, so
		// pre-v2 peers are never sent `~min-max` rules they cannot parse.
		PaddingV2: true,
	}
	if err := session.SendSettings(settings); err != nil {
		_ = session.Close()
		return nil, &authError{reason: "send client settings", err: err}
	}

	// Authentication succeeds when the server replies with server settings.
	_ = conn.SetReadDeadline(time.Now().Add(authConfirmTimeout))
	frame, err := protocol.DecodeFrame(conn)
	_ = conn.SetReadDeadline(time.Time{})
	if err != nil {
		_ = session.Close()
		return nil, &authError{reason: "waiting for server settings", err: err}
	}
	if frame.Command != protocol.CmdServerSettings || frame.StreamID != 0 || len(frame.Data) == 0 {
		_ = session.Close()
		return nil, &authError{
			reason: fmt.Sprintf("unexpected auth confirmation frame command=%s stream=%d data_len=%d",
				frame.Command, frame.StreamID, len(frame.Data)),
		}
	}
	serverSettings, err := protocol.DecodeServerSettings(frame.Data)
	if err != nil {
		_ = session.Close()
		return nil, fmt.Errorf("tsunami: decode server settings: %w", err)
	}
	if serverSettings.Version != protocol.CurrentVersion {
		_ = session.Close()
		return nil, fmt.Errorf("tsunami: server version=%d: %w", serverSettings.Version, protocol.ErrVersionMismatch)
	}

	go func() {
		_ = session.RunEventLoop()
	}()
	return session, nil
}

// bindClientPadding routes session frame writes through a padding writer and
// forgets per-stream padding epochs when streams close. The writer is passed as
// a parameter so re-binding after a connection wrapper swap only affects the
// current writer.
func bindClientPadding(session *protocol.Session, pw *padding.Writer) {
	session.SetPaddingWriteFn(func(frames []*protocol.Frame) error {
		return pw.WriteFramesWithPadding(frames)
	})
	session.SetOnStreamClosed(func(id uint32) {
		pw.ForgetStream(id)
	})
}

// currentPaddingScheme returns the client's active padding scheme.
func (c *Client) currentPaddingScheme() *padding.Scheme {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.paddingScheme == nil {
		c.paddingScheme = padding.DefaultScheme()
	}
	return c.paddingScheme
}

// applyPaddingSchemeUpdate parses a scheme pushed by the server and applies it
// to the client and to the session writer that received it.
func (c *Client) applyPaddingSchemeUpdate(data []byte, writer *padding.Writer) error {
	scheme, err := padding.Parse(string(data))
	if err != nil {
		return fmt.Errorf("tsunami: parse padding scheme update: %w", err)
	}

	c.mu.Lock()
	c.paddingScheme = scheme
	c.mu.Unlock()

	if writer != nil {
		writer.UpdateScheme(scheme)
	}
	return nil
}

// authError reports a failure during the client authentication handshake while
// still matching protocol.ErrAuthFailed via errors.Is. It never contains the
// password or the auth hash.
type authError struct {
	reason string
	err    error
}

func (e *authError) Error() string {
	if e.err != nil {
		return fmt.Sprintf("tsunami: authentication failed: %s: %v", e.reason, e.err)
	}
	return fmt.Sprintf("tsunami: authentication failed: %s", e.reason)
}

func (e *authError) Unwrap() error { return e.err }

func (e *authError) Is(target error) bool { return target == protocol.ErrAuthFailed }
