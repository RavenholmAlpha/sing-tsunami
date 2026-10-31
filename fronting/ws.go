package fronting

import (
	"bufio"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

const websocketGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

// isWebSocketUpgrade reports whether r is an HTTP/1.1 WebSocket upgrade.
func isWebSocketUpgrade(r *http.Request) bool {
	return strings.EqualFold(r.Header.Get("Upgrade"), "websocket") &&
		headerContainsToken(r.Header.Get("Connection"), "upgrade")
}

// upgradeServer upgrades an accepted HTTP request to a WebSocket net.Conn. The
// second result reports whether the connection was already hijacked (and the
// 101 response committed to the wire); when it is true the caller must not try
// to write a decoy response any more.
func upgradeServer(w http.ResponseWriter, r *http.Request, serverHeader string) (net.Conn, bool, error) {
	key := strings.TrimSpace(r.Header.Get("Sec-WebSocket-Key"))
	if key == "" {
		return nil, false, fmt.Errorf("fronting: missing websocket key")
	}
	if version := r.Header.Get("Sec-WebSocket-Version"); version != "13" {
		return nil, false, fmt.Errorf("fronting: unsupported websocket version %q", version)
	}

	conn, brw, err := http.NewResponseController(w).Hijack()
	if err != nil {
		return nil, false, fmt.Errorf("fronting: websocket hijack: %w", err)
	}

	accept := websocketAccept(key)
	response := "HTTP/1.1 101 Switching Protocols\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Accept: " + accept + "\r\n"
	if serverHeader != "" {
		response += "Server: " + serverHeader + "\r\n"
	}
	response += "\r\n"

	if _, err := brw.WriteString(response); err != nil {
		conn.Close()
		return nil, true, err
	}
	if err := brw.Flush(); err != nil {
		conn.Close()
		return nil, true, err
	}

	return newWebSocketConn(conn, brw.Reader, false), true, nil
}

// clientWebSocketHandshake performs a WebSocket client handshake on conn and
// returns the frame-adapted tunnel connection.
func clientWebSocketHandshake(conn net.Conn, endpoint *url.URL, host string, key [32]byte) (net.Conn, error) {
	wsKey, err := newWebSocketKey()
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest(http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return nil, err
	}
	if host != "" {
		req.Host = host
	}
	if req.Host == "" {
		req.Host = endpoint.Host
	}
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Sec-WebSocket-Version", "13")
	req.Header.Set("Sec-WebSocket-Key", wsKey)
	req.Header.Set("User-Agent", DefaultUserAgent)
	SignRequest(req, key, time.Now())

	if err := req.Write(conn); err != nil {
		return nil, fmt.Errorf("fronting: websocket request: %w", err)
	}

	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, req)
	if err != nil {
		return nil, fmt.Errorf("fronting: websocket response: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusSwitchingProtocols {
		return nil, fmt.Errorf("fronting: websocket status %s", resp.Status)
	}
	if !strings.EqualFold(resp.Header.Get("Upgrade"), "websocket") ||
		!headerContainsToken(resp.Header.Get("Connection"), "upgrade") {
		return nil, fmt.Errorf("fronting: invalid websocket upgrade response")
	}
	if got, want := resp.Header.Get("Sec-WebSocket-Accept"), websocketAccept(wsKey); got != want {
		return nil, fmt.Errorf("fronting: invalid websocket accept")
	}

	return newWebSocketConn(conn, br, true), nil
}

// webSocketConn adapts WebSocket frames into a stream-oriented net.Conn.
type webSocketConn struct {
	conn       net.Conn
	reader     *bufio.Reader
	maskWrites bool

	readBuf []byte
	writeMu sync.Mutex
}

// newWebSocketConn creates a WebSocket net.Conn wrapper.
func newWebSocketConn(conn net.Conn, reader *bufio.Reader, maskWrites bool) *webSocketConn {
	if reader == nil {
		reader = bufio.NewReader(conn)
	}
	return &webSocketConn{conn: conn, reader: reader, maskWrites: maskWrites}
}

func (c *webSocketConn) Read(p []byte) (int, error) {
	for len(c.readBuf) == 0 {
		payload, err := c.readFrame()
		if err != nil {
			return 0, err
		}
		c.readBuf = payload
	}
	n := copy(p, c.readBuf)
	c.readBuf = c.readBuf[n:]
	return n, nil
}

func (c *webSocketConn) Write(p []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if err := c.writeFrame(0x2, p); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *webSocketConn) Close() error {
	c.writeMu.Lock()
	_ = c.writeFrame(0x8, nil)
	c.writeMu.Unlock()
	return c.conn.Close()
}

func (c *webSocketConn) LocalAddr() net.Addr  { return c.conn.LocalAddr() }
func (c *webSocketConn) RemoteAddr() net.Addr { return c.conn.RemoteAddr() }

// Deadlines are forwarded to the underlying connection: unlike the HTTP/2
// adapter, a WebSocket connection has a single reader and writer, so applying
// deadlines to it is safe.
func (c *webSocketConn) SetDeadline(t time.Time) error      { return c.conn.SetDeadline(t) }
func (c *webSocketConn) SetReadDeadline(t time.Time) error  { return c.conn.SetReadDeadline(t) }
func (c *webSocketConn) SetWriteDeadline(t time.Time) error { return c.conn.SetWriteDeadline(t) }

func (c *webSocketConn) readFrame() ([]byte, error) {
	for {
		b1, err := c.reader.ReadByte()
		if err != nil {
			return nil, err
		}
		b2, err := c.reader.ReadByte()
		if err != nil {
			return nil, err
		}

		opcode := b1 & 0x0f
		masked := b2&0x80 != 0
		length := uint64(b2 & 0x7f)
		switch length {
		case 126:
			var ext [2]byte
			if _, err := io.ReadFull(c.reader, ext[:]); err != nil {
				return nil, err
			}
			length = uint64(binary.BigEndian.Uint16(ext[:]))
		case 127:
			var ext [8]byte
			if _, err := io.ReadFull(c.reader, ext[:]); err != nil {
				return nil, err
			}
			length = binary.BigEndian.Uint64(ext[:])
		}
		if length > 16*1024*1024 {
			return nil, fmt.Errorf("fronting: websocket frame too large")
		}

		var mask [4]byte
		if masked {
			if _, err := io.ReadFull(c.reader, mask[:]); err != nil {
				return nil, err
			}
		}
		payload := make([]byte, length)
		if _, err := io.ReadFull(c.reader, payload); err != nil {
			return nil, err
		}
		if masked {
			for i := range payload {
				payload[i] ^= mask[i%4]
			}
		}

		switch opcode {
		case 0x0, 0x1, 0x2:
			return payload, nil
		case 0x8:
			return nil, io.EOF
		case 0x9:
			c.writeMu.Lock()
			_ = c.writeFrame(0xA, payload)
			c.writeMu.Unlock()
		case 0xA:
			continue
		default:
			return nil, fmt.Errorf("fronting: unsupported websocket opcode 0x%x", opcode)
		}
	}
}

func (c *webSocketConn) writeFrame(opcode byte, payload []byte) error {
	header := make([]byte, 2, 14)
	header[0] = 0x80 | opcode
	payloadLen := len(payload)
	switch {
	case payloadLen < 126:
		header[1] = byte(payloadLen)
	case payloadLen <= 0xffff:
		header[1] = 126
		var ext [2]byte
		binary.BigEndian.PutUint16(ext[:], uint16(payloadLen))
		header = append(header, ext[:]...)
	default:
		header[1] = 127
		var ext [8]byte
		binary.BigEndian.PutUint64(ext[:], uint64(payloadLen))
		header = append(header, ext[:]...)
	}

	body := payload
	if c.maskWrites {
		header[1] |= 0x80
		var mask [4]byte
		if _, err := rand.Read(mask[:]); err != nil {
			return err
		}
		header = append(header, mask[:]...)
		body = make([]byte, len(payload))
		for i := range payload {
			body[i] = payload[i] ^ mask[i%4]
		}
	}
	if err := writeAll(c.conn, header); err != nil {
		return err
	}
	if len(body) == 0 {
		return nil
	}
	return writeAll(c.conn, body)
}

// writeAll writes p completely, tolerating short writes.
func writeAll(w io.Writer, p []byte) error {
	for len(p) > 0 {
		n, err := w.Write(p)
		if err != nil {
			return err
		}
		p = p[n:]
	}
	return nil
}

func websocketAccept(key string) string {
	sum := sha1.Sum([]byte(key + websocketGUID))
	return base64.StdEncoding.EncodeToString(sum[:])
}

func newWebSocketKey() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(b[:]), nil
}

func headerContainsToken(value, token string) bool {
	for _, part := range strings.Split(value, ",") {
		if strings.EqualFold(strings.TrimSpace(part), token) {
			return true
		}
	}
	return false
}
