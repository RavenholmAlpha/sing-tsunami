package tsunami

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/RavenholmAlpha/sing-tsunami/padding"
	"github.com/RavenholmAlpha/sing-tsunami/protocol"
)

const (
	// authTimeout bounds the server-side read of the auth request.
	authTimeout = 10 * time.Second
)

// User is a static TSUNAMI credential. The password itself never crosses the
// wire: the client authenticates with SHA-256(password).
type User struct {
	Name     string
	Password string
}

// ServiceConfig configures a Service.
type ServiceConfig struct {
	// Users is the static credential list. Passwords are hashed with SHA-256
	// at construction time.
	Users []User
	// PaddingScheme is the server's scheme text; nil uses
	// padding.DefaultScheme().
	PaddingScheme []byte
	// Handler runs once per opened stream, in its own goroutine. destination
	// is the SOCKS5 address the client wrote first ("host:port", IPv6 hosts
	// are bracketed unless the peer encoded a bare address; use
	// net.SplitHostPort-style consumers). The handler owns conn and must close
	// it.
	Handler func(ctx context.Context, conn net.Conn, source net.Addr, destination string)
}

// Service is the server side of the TSUNAMI protocol: it authenticates
// connections, negotiates settings and padding, and dispatches opened streams
// to the configured Handler.
type Service struct {
	cfg    ServiceConfig
	scheme *padding.Scheme
	users  map[[protocol.AuthHashLen]byte]User
}

// NewService creates a TSUNAMI service.
func NewService(cfg ServiceConfig) (*Service, error) {
	if cfg.Handler == nil {
		return nil, fmt.Errorf("tsunami: Handler is required")
	}
	if len(cfg.Users) == 0 {
		return nil, fmt.Errorf("tsunami: at least one user is required")
	}

	users := make(map[[protocol.AuthHashLen]byte]User, len(cfg.Users))
	for _, user := range cfg.Users {
		if user.Password == "" {
			return nil, fmt.Errorf("tsunami: user %q has an empty password", user.Name)
		}
		users[protocol.PasswordHash(user.Password)] = user
	}

	scheme := padding.DefaultScheme()
	if len(cfg.PaddingScheme) > 0 {
		parsed, err := padding.Parse(string(cfg.PaddingScheme))
		if err != nil {
			return nil, fmt.Errorf("tsunami: parse padding scheme: %w", err)
		}
		scheme = parsed
	}

	return &Service{cfg: cfg, scheme: scheme, users: users}, nil
}

// NewConnection runs the server side of one TSUNAMI session on conn. conn must
// already be past the transport handshake (plain TLS, or a fronting tunnel from
// fronting.ServeHTTP2/ServeHTTP1). source is the client's transport address;
// nil falls back to conn.RemoteAddr().
//
// NewConnection blocks until the session ends and closes conn before
// returning. A clean peer disconnect ends the session with a nil error; only
// framing and write failures are reported.
func (s *Service) NewConnection(ctx context.Context, conn net.Conn, source net.Addr) error {
	if conn == nil {
		return fmt.Errorf("tsunami: nil connection")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if source == nil {
		source = conn.RemoteAddr()
	}
	// The caller may also close the transport; closing here matches the
	// reference server, which owns the accepted connection.
	defer func() { _ = conn.Close() }()

	// Authentication phase.
	_ = conn.SetReadDeadline(time.Now().Add(authTimeout))
	authReq, err := protocol.DecodeAuthRequest(conn)
	if err != nil {
		return fmt.Errorf("tsunami: read auth request: %w", err)
	}
	if _, ok := s.users[authReq.Hash]; !ok {
		return fmt.Errorf("tsunami: authentication failed: %w", protocol.ErrAuthFailed)
	}
	_ = conn.SetReadDeadline(time.Time{})

	// Client settings: the first frame after authentication.
	_ = conn.SetReadDeadline(time.Now().Add(settingsTimeout))
	settingsFrame, err := protocol.DecodeFrame(conn)
	_ = conn.SetReadDeadline(time.Time{})
	if err != nil {
		return fmt.Errorf("tsunami: read client settings: %w", err)
	}
	if settingsFrame.Command != protocol.CmdSettings || settingsFrame.StreamID != 0 || len(settingsFrame.Data) == 0 {
		return fmt.Errorf("tsunami: invalid client settings frame command=%s stream=%d data_len=%d: %w",
			settingsFrame.Command, settingsFrame.StreamID, len(settingsFrame.Data), protocol.ErrInvalidFrame)
	}
	clientSettings, err := protocol.DecodeClientSettings(settingsFrame.Data)
	if err != nil {
		return fmt.Errorf("tsunami: decode client settings: %w", err)
	}
	if clientSettings.Version != protocol.CurrentVersion {
		return fmt.Errorf("tsunami: client version=%d: %w", clientSettings.Version, protocol.ErrVersionMismatch)
	}

	session := protocol.NewSession(conn, 0)

	// Wire the padding writer into the session write path before the settings
	// reply is written: control frames are padded for the whole session.
	pw := padding.NewWriterForRole(conn, s.scheme, padding.RoleServer)
	bindServerPadding(session, pw)

	session.SetOnStreamOpen(func(stream *protocol.Stream) {
		s.handleStream(ctx, conn, source, stream)
	})

	// Reply to the client settings; this frame is the client's auth-success
	// confirmation.
	serverSettings := &protocol.ServerSettings{
		Version:   protocol.CurrentVersion,
		SurgeMode: protocol.SurgeModeNone,
	}
	if err := session.SendServerSettings(serverSettings); err != nil {
		_ = session.Close()
		return fmt.Errorf("tsunami: send server settings: %w", err)
	}

	// Push the server scheme only to clients that advertised the v2 syntax and
	// whose scheme differs. Pre-v2 clients cannot parse `~min-max` rules and
	// would close the session on a pushed update.
	if clientSettings.PaddingV2 && clientSettings.PaddingMD5 != "" && clientSettings.PaddingMD5 != s.scheme.MD5() {
		if err := session.WriteFrame(protocol.NewFrame(protocol.CmdUpdatePaddingScheme, 0, []byte(s.scheme.Encode()))); err != nil {
			_ = session.Close()
			return fmt.Errorf("tsunami: send padding scheme: %w", err)
		}
	}

	// Idle keepalive waste, only when the active scheme defines it.
	var keepalive *padding.KeepaliveGenerator
	if s.scheme.Keepalive != nil {
		keepalive = padding.NewKeepaliveGenerator(s.scheme.Keepalive, session.WriteFrame)
		keepalive.Start()
		defer keepalive.Stop()
	}
	session.SetOnStreamCountChange(func(activeCount int) {
		if keepalive != nil {
			keepalive.SetActive(activeCount > 0)
		}
	})

	// Close the session when the caller's context is canceled; NewConnection
	// blocks until the session ends either way.
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			_ = session.Close()
		case <-done:
		}
	}()

	if err := session.RunEventLoop(); err != nil &&
		!errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) {
		return fmt.Errorf("tsunami: session: %w", err)
	}
	return nil
}

// bindServerPadding routes session frame writes through a padding writer and
// forgets per-stream padding epochs when streams close.
func bindServerPadding(session *protocol.Session, pw *padding.Writer) {
	session.SetPaddingWriteFn(func(frames []*protocol.Frame) error {
		return pw.WriteFramesWithPadding(frames)
	})
	session.SetOnStreamClosed(func(id uint32) {
		pw.ForgetStream(id)
	})
}

// handleStream reads the stream's target address and runs the configured
// handler in its own goroutine. The session invokes OnStreamOpen in a
// goroutine, so reading the address here does not stall the session loop.
func (s *Service) handleStream(ctx context.Context, transport net.Conn, source net.Addr, stream *protocol.Stream) {
	destination, err := protocol.ReadSocksAddr(stream)
	if err != nil {
		_ = stream.Close()
		return
	}

	conn := newStreamConn(stream, transport.LocalAddr(), source)
	go func() {
		// The handler owns the connection and must close it; this close is a
		// safety net for handlers that return without doing so.
		defer func() { _ = conn.Close() }()
		s.cfg.Handler(ctx, conn, source, destination)
	}()
}
