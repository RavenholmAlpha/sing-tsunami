package tsunami

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/RavenholmAlpha/sing-tsunami/padding"
	"github.com/RavenholmAlpha/sing-tsunami/protocol"
)

// loopbackHandler is the Service handler used by the loopback tests.
type loopbackHandler func(ctx context.Context, conn net.Conn, source net.Addr, destination string)

// newLoopbackClient starts a Service and a Client wired together with net.Pipe:
// every DialOut call creates a fresh in-memory connection pair and runs the
// server side of the session on the other end.
func newLoopbackClient(t *testing.T, servicePassword string, handler loopbackHandler, configure func(*ClientConfig)) *Client {
	t.Helper()

	if handler == nil {
		handler = func(_ context.Context, conn net.Conn, _ net.Addr, _ string) {
			_, _ = io.Copy(conn, conn)
		}
	}
	return newLoopbackClientWithService(t, ServiceConfig{
		Users:   []User{{Name: "alice", Password: servicePassword}},
		Handler: handler,
	}, servicePassword, configure)
}

// newLoopbackClientWithService is newLoopbackClient with full control over the
// ServiceConfig (used to test padding-scheme negotiation).
func newLoopbackClientWithService(t *testing.T, serviceCfg ServiceConfig, clientPassword string, configure func(*ClientConfig)) *Client {
	t.Helper()

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	service, err := NewService(serviceCfg)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}

	cfg := ClientConfig{
		Password: clientPassword,
		DialOut: func(dialCtx context.Context) (net.Conn, error) {
			clientConn, serverConn := net.Pipe()
			bufferedClient := newBufferedPipeConn(clientConn)
			bufferedServer := newBufferedPipeConn(serverConn)
			go func() {
				_ = service.NewConnection(dialCtx, bufferedServer, bufferedServer.RemoteAddr())
			}()
			return bufferedClient, nil
		},
	}
	if configure != nil {
		configure(&cfg)
	}

	client, err := NewClient(ctx, cfg)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })
	return client
}

func TestLoopbackEcho(t *testing.T) {
	client := newLoopbackClient(t, "secret-password", nil, nil)

	conn, err := client.Dial(context.Background(), "127.0.0.1:8080")
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	if got := client.pool.ActiveStreamCount(); got != 1 {
		t.Fatalf("active streams after Dial = %d, want 1", got)
	}

	payload := []byte("hello tsunami")
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("write payload: %v", err)
	}
	echo := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, echo); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if !bytes.Equal(echo, payload) {
		t.Fatalf("echo = %q, want %q", echo, payload)
	}

	if err := conn.Close(); err != nil {
		t.Fatalf("close stream: %v", err)
	}
	if got := client.pool.ActiveStreamCount(); got != 0 {
		t.Fatalf("active streams after Close = %d, want 0", got)
	}

	// The session stays pooled and is reused for the next stream.
	second, err := client.Dial(context.Background(), "127.0.0.2:8080")
	if err != nil {
		t.Fatalf("second Dial: %v", err)
	}
	defer second.Close()
	if got := client.pool.SessionCount(); got != 1 {
		t.Fatalf("sessions after stream reuse = %d, want 1", got)
	}
}

func TestLoopbackDestination(t *testing.T) {
	destinations := make(chan string, 1)
	client := newLoopbackClient(t, "secret-password", loopbackHandler(func(_ context.Context, conn net.Conn, _ net.Addr, destination string) {
		destinations <- destination
		_, _ = io.Copy(conn, conn)
	}), nil)

	conn, err := client.Dial(context.Background(), "example.com:443")
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer conn.Close()

	select {
	case got := <-destinations:
		if got != "example.com:443" {
			t.Fatalf("destination = %q, want %q", got, "example.com:443")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("handler did not observe the destination")
	}
}

func TestLoopbackLargePayloadAndConcurrentStreams(t *testing.T) {
	client := newLoopbackClient(t, "secret-password", nil, nil)

	const (
		streamCount = 2
		payloadSize = 512 * 1024
	)

	var wg sync.WaitGroup
	errCh := make(chan error, streamCount)

	for i := 0; i < streamCount; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()

			conn, err := client.Dial(context.Background(), fmt.Sprintf("10.0.0.%d:443", i+1))
			if err != nil {
				errCh <- fmt.Errorf("stream %d dial: %w", i, err)
				return
			}
			defer conn.Close()

			payload := make([]byte, payloadSize)
			for j := range payload {
				payload[j] = byte(i*131 + j*7)
			}
			if _, err := conn.Write(payload); err != nil {
				errCh <- fmt.Errorf("stream %d write: %w", i, err)
				return
			}

			echo := make([]byte, payloadSize)
			if _, err := io.ReadFull(conn, echo); err != nil {
				errCh <- fmt.Errorf("stream %d read: %w", i, err)
				return
			}
			if !bytes.Equal(echo, payload) {
				errCh <- fmt.Errorf("stream %d echo mismatch", i)
			}
		}(i)
	}

	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Fatal(err)
	}
}

func TestLoopbackAuthFailure(t *testing.T) {
	client := newLoopbackClient(t, "correct-password", nil, func(cfg *ClientConfig) {
		cfg.Password = "wrong-password"
	})

	conn, err := client.Dial(context.Background(), "127.0.0.1:8080")
	if err == nil {
		_ = conn.Close()
		t.Fatal("Dial with the wrong password succeeded")
	}
	if !errors.Is(err, protocol.ErrAuthFailed) {
		t.Fatalf("Dial error = %v, want errors.Is(ErrAuthFailed)", err)
	}
}

func TestServiceRejectsWrongClientVersion(t *testing.T) {
	service, err := NewService(ServiceConfig{
		Users:   []User{{Name: "alice", Password: "secret-password"}},
		Handler: func(context.Context, net.Conn, net.Addr, string) {},
	})
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}

	serverConn, clientConn := net.Pipe()
	defer clientConn.Close()

	errCh := make(chan error, 1)
	go func() {
		errCh <- service.NewConnection(context.Background(), serverConn, nil)
	}()

	if err := protocol.EncodeAuthRequest(clientConn, protocol.PasswordHash("secret-password"), nil); err != nil {
		t.Fatalf("send auth request: %v", err)
	}
	settings := protocol.EncodeClientSettings(&protocol.ClientSettings{
		Version: protocol.ProtocolVersion2,
		Client:  "test",
	})
	if err := protocol.EncodeFrame(clientConn, protocol.NewFrame(protocol.CmdSettings, 0, settings)); err != nil {
		t.Fatalf("send client settings: %v", err)
	}

	select {
	case err := <-errCh:
		if !errors.Is(err, protocol.ErrVersionMismatch) {
			t.Fatalf("NewConnection error = %v, want errors.Is(ErrVersionMismatch)", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("NewConnection did not reject the wrong protocol version")
	}
}

func TestPoolClosesIdleSessions(t *testing.T) {
	client := newLoopbackClient(t, "secret-password", nil, func(cfg *ClientConfig) {
		cfg.IdleSessionCheckInterval = 10 * time.Millisecond
		cfg.IdleSessionTimeout = 30 * time.Millisecond
		cfg.MinIdleSession = 0
	})

	conn, err := client.Dial(context.Background(), "127.0.0.1:8080")
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	if err := conn.Close(); err != nil {
		t.Fatalf("close stream: %v", err)
	}

	deadline := time.Now().Add(3 * time.Second)
	for client.pool.SessionCount() != 0 {
		if time.Now().After(deadline) {
			t.Fatal("idle session was not closed")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestPoolKeepsMinIdleSession(t *testing.T) {
	client := newLoopbackClient(t, "secret-password", nil, func(cfg *ClientConfig) {
		cfg.IdleSessionCheckInterval = 10 * time.Millisecond
		cfg.IdleSessionTimeout = 20 * time.Millisecond
		cfg.MinIdleSession = 1
	})

	conn, err := client.Dial(context.Background(), "127.0.0.1:8080")
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	if err := conn.Close(); err != nil {
		t.Fatalf("close stream: %v", err)
	}

	// Well past several idle checks and the jittered timeout the session must
	// still be alive because MinIdleSession keeps one.
	time.Sleep(300 * time.Millisecond)
	if got := client.pool.SessionCount(); got != 1 {
		t.Fatalf("sessions with MinIdleSession=1 = %d, want 1", got)
	}
}

func TestServerPushesUpdatedPaddingScheme(t *testing.T) {
	serverSchemeText := "stop=2\nstream_bytes=2048\nctl=~40-120\n0=~60-80\n1=~60-80"
	serverScheme, err := padding.Parse(serverSchemeText)
	if err != nil {
		t.Fatalf("parse server scheme: %v", err)
	}

	client := newLoopbackClientWithService(t, ServiceConfig{
		Users:         []User{{Name: "alice", Password: "secret-password"}},
		PaddingScheme: []byte(serverSchemeText),
		Handler: func(_ context.Context, conn net.Conn, _ net.Addr, _ string) {
			_, _ = io.Copy(conn, conn)
		},
	}, "secret-password", nil)

	conn, err := client.Dial(context.Background(), "127.0.0.1:8080")
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer conn.Close()

	// The pushed scheme is applied by the session event loop, so poll briefly.
	deadline := time.Now().Add(5 * time.Second)
	for {
		if got := client.currentPaddingScheme().MD5(); got == serverScheme.MD5() {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("client scheme md5 = %s, want pushed md5 %s",
				client.currentPaddingScheme().MD5(), serverScheme.MD5())
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestServiceDoesNotPushSchemeToLegacyClient(t *testing.T) {
	// The client advertises no padding-v2 capability and reports a different
	// scheme MD5: the service must not push the v2 scheme text.
	serverSchemeText := "stop=2\nstream_bytes=2048\nctl=~40-120\n0=~60-80\n1=~60-80"

	service, err := NewService(ServiceConfig{
		Users:         []User{{Name: "alice", Password: "secret-password"}},
		PaddingScheme: []byte(serverSchemeText),
		Handler:       func(context.Context, net.Conn, net.Addr, string) {},
	})
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}

	serverConn, clientConn := net.Pipe()
	bufferedClient := newBufferedPipeConn(clientConn)
	bufferedServer := newBufferedPipeConn(serverConn)
	defer bufferedClient.Close()

	errCh := make(chan error, 1)
	go func() {
		errCh <- service.NewConnection(context.Background(), bufferedServer, nil)
	}()

	if err := protocol.EncodeAuthRequest(bufferedClient, protocol.PasswordHash("secret-password"), nil); err != nil {
		t.Fatalf("send auth request: %v", err)
	}
	legacySettings := protocol.EncodeClientSettings(&protocol.ClientSettings{
		Version:    protocol.CurrentVersion,
		Client:     "legacy-client",
		PaddingMD5: "0123456789abcdef0123456789abcdef",
		PaddingV2:  false,
	})
	if err := protocol.EncodeFrame(bufferedClient, protocol.NewFrame(protocol.CmdSettings, 0, legacySettings)); err != nil {
		t.Fatalf("send legacy client settings: %v", err)
	}

	_ = bufferedClient.SetReadDeadline(time.Now().Add(5 * time.Second))
	reply, err := protocol.DecodeFrame(bufferedClient)
	if err != nil {
		t.Fatalf("read server settings: %v", err)
	}
	if reply.Command != protocol.CmdServerSettings {
		t.Fatalf("reply command = %s, want SERVER_SETTINGS", reply.Command)
	}

	// Nothing else must be pushed. Drain until the short read deadline expires
	// and fail if a scheme update shows up.
	_ = bufferedClient.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	for {
		frame, err := protocol.DecodeFrame(bufferedClient)
		if err != nil {
			break
		}
		if frame.Command == protocol.CmdUpdatePaddingScheme {
			t.Fatalf("service pushed a padding scheme to a legacy client")
		}
	}

	_ = bufferedClient.Close()
	select {
	case <-errCh:
	case <-time.After(2 * time.Second):
		t.Fatal("service session did not end after the client disconnected")
	}
}

func TestClientSettingsAndAuth(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	bufferedClient := newBufferedPipeConn(clientConn)
	bufferedServer := newBufferedPipeConn(serverConn)

	type handshake struct {
		hash       [protocol.AuthHashLen]byte
		paddingLen int
		settings   *protocol.ClientSettings
	}
	handshakeCh := make(chan handshake, 1)
	serverErr := make(chan error, 1)

	go func() {
		authReq, err := protocol.DecodeAuthRequest(bufferedServer)
		if err != nil {
			serverErr <- err
			return
		}
		frame, err := protocol.DecodeFrame(bufferedServer)
		if err != nil {
			serverErr <- err
			return
		}
		if frame.Command != protocol.CmdSettings || frame.StreamID != 0 {
			serverErr <- fmt.Errorf("first frame after auth = %s stream=%d, want SETTINGS", frame.Command, frame.StreamID)
			return
		}
		settings, err := protocol.DecodeClientSettings(frame.Data)
		if err != nil {
			serverErr <- err
			return
		}
		handshakeCh <- handshake{hash: authReq.Hash, paddingLen: len(authReq.Padding), settings: settings}

		// Authentication confirmation.
		reply := protocol.EncodeServerSettings(&protocol.ServerSettings{Version: protocol.CurrentVersion})
		_ = protocol.EncodeFrame(bufferedServer, protocol.NewFrame(protocol.CmdServerSettings, 0, reply))
	}()

	client, err := NewClient(context.Background(), ClientConfig{
		Password: "secret-password",
		DialOut: func(context.Context) (net.Conn, error) {
			return bufferedClient, nil
		},
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })

	if _, err := client.pool.GetOrCreateSession(context.Background()); err != nil {
		t.Fatalf("establish session: %v", err)
	}

	select {
	case got := <-handshakeCh:
		if want := protocol.PasswordHash("secret-password"); got.hash != want {
			t.Fatalf("auth hash does not match SHA-256(password)")
		}
		if got.paddingLen < authPaddingMin || got.paddingLen > authPaddingMax {
			t.Fatalf("auth padding = %d bytes, want %d..%d", got.paddingLen, authPaddingMin, authPaddingMax)
		}
		if got.settings == nil {
			t.Fatal("client settings were not sent")
		}
		if got.settings.Version != protocol.CurrentVersion {
			t.Fatalf("client settings version = %d, want %d", got.settings.Version, protocol.CurrentVersion)
		}
		if got.settings.Client == "" {
			t.Fatal("client settings client name is empty")
		}
		if got.settings.PaddingMD5 != padding.DefaultScheme().MD5() {
			t.Fatalf("client settings padding md5 = %q, want %q", got.settings.PaddingMD5, padding.DefaultScheme().MD5())
		}
		if !got.settings.PaddingV2 {
			t.Fatal("client did not advertise padding-v2")
		}
		if got.settings.Shaping {
			t.Fatal("client advertised shaping without support")
		}
	case err := <-serverErr:
		t.Fatalf("fake server: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("client did not send auth + settings")
	}
}

// bufferedPipeConn turns one end of a net.Pipe into a buffered connection.
//
// net.Pipe is fully synchronous: a Write does not return until the peer has
// read every byte. Real transports (TCP, TLS) buffer instead, and the TSUNAMI
// handshake depends on that: the client sends its client-settings frame in one
// padded write, while the server reads only the settings frame and defers the
// trailing cmdWaste bytes to its event loop. On a raw net.Pipe the client's
// Write would block before the server reaches its event loop, deadlocking the
// handshake. The pump goroutine below drains the raw pipe eagerly, which is the
// behavior a kernel socket buffer provides.
type bufferedPipeConn struct {
	raw net.Conn

	mu       sync.Mutex
	buf      []byte
	readErr  error
	notEmpty chan struct{}
	readDL   time.Time
	writeDL  time.Time
}

func newBufferedPipeConn(raw net.Conn) *bufferedPipeConn {
	c := &bufferedPipeConn{raw: raw, notEmpty: make(chan struct{})}
	go c.pump()
	return c
}

func (c *bufferedPipeConn) pump() {
	buf := make([]byte, 32*1024)
	for {
		n, err := c.raw.Read(buf)
		c.mu.Lock()
		if n > 0 {
			c.buf = append(c.buf, buf[:n]...)
		}
		if err != nil {
			c.readErr = err
		}
		c.signalLocked()
		c.mu.Unlock()
		if err != nil {
			return
		}
	}
}

func (c *bufferedPipeConn) signalLocked() {
	close(c.notEmpty)
	c.notEmpty = make(chan struct{})
}

func (c *bufferedPipeConn) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	for {
		c.mu.Lock()
		if len(c.buf) > 0 {
			n := copy(p, c.buf)
			c.buf = c.buf[n:]
			c.mu.Unlock()
			return n, nil
		}
		if c.readErr != nil {
			err := c.readErr
			c.mu.Unlock()
			return 0, err
		}
		ready := c.notEmpty
		deadline := c.readDL
		c.mu.Unlock()

		var timer *time.Timer
		var timeout <-chan time.Time
		if !deadline.IsZero() {
			remaining := time.Until(deadline)
			if remaining <= 0 {
				return 0, os.ErrDeadlineExceeded
			}
			timer = time.NewTimer(remaining)
			timeout = timer.C
		}

		select {
		case <-ready:
			if timer != nil {
				timer.Stop()
			}
		case <-timeout:
			return 0, os.ErrDeadlineExceeded
		}
	}
}

func (c *bufferedPipeConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	deadline := c.writeDL
	c.mu.Unlock()
	if !deadline.IsZero() && !time.Now().Before(deadline) {
		return 0, os.ErrDeadlineExceeded
	}
	// The peer pump drains continuously, so this write never waits for the
	// peer's protocol reader (matching a buffered socket).
	if err := c.raw.SetWriteDeadline(deadline); err != nil {
		return 0, err
	}
	return c.raw.Write(p)
}

func (c *bufferedPipeConn) Close() error { return c.raw.Close() }

func (c *bufferedPipeConn) LocalAddr() net.Addr  { return c.raw.LocalAddr() }
func (c *bufferedPipeConn) RemoteAddr() net.Addr { return c.raw.RemoteAddr() }

func (c *bufferedPipeConn) SetDeadline(t time.Time) error {
	if err := c.SetReadDeadline(t); err != nil {
		return err
	}
	return c.SetWriteDeadline(t)
}

func (c *bufferedPipeConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	c.readDL = t
	c.signalLocked() // wake a blocked reader so it recomputes its deadline
	c.mu.Unlock()
	return nil
}

func (c *bufferedPipeConn) SetWriteDeadline(t time.Time) error {
	c.mu.Lock()
	c.writeDL = t
	c.mu.Unlock()
	return nil
}

var _ net.Conn = (*bufferedPipeConn)(nil)
