package fronting

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sync/atomic"
	"time"

	"golang.org/x/net/http2"
)

// errConnReused is returned if the HTTP/2 transport tries to dial a second
// connection: the fronting tunnel is single-use by construction.
var errConnReused = errors.New("fronting: single-use transport connection was reused")

// NewClientConn wraps an already-handshaked connection (ALPN h2 for the h2
// transport, http/1.1 for the WebSocket transport) and starts the signed
// fronting request. The returned conn is the tunnel byte stream: writes are
// sent as the request body, reads return the response body.
//
// On error the connection is closed and must not be reused. The caller is
// responsible for closing the returned conn.
func NewClientConn(conn net.Conn, cfg Config) (net.Conn, error) {
	if conn == nil {
		return nil, errors.New("fronting: nil connection")
	}
	if err := cfg.Normalize(); err != nil {
		conn.Close()
		return nil, err
	}
	if cfg.Secret == "" {
		conn.Close()
		return nil, errors.New("fronting: a fronting secret is required")
	}
	host, err := tunnelHost(&cfg, conn)
	if err != nil {
		conn.Close()
		return nil, err
	}
	key := KeyFromSecret(cfg.Secret)
	if cfg.Transport == TransportWebSocket {
		return dialFrontedWebSocket(conn, cfg, host, key)
	}
	return dialFrontedH2(conn, cfg, host, key)
}

// dialFrontedH2 performs the HTTP/2 fronting request. The request body is a
// pipe that the caller writes to, and the response body is the tunnel's read
// side. The response headers usually arrive before the caller has written
// anything, but NewClientConn does not wait for them: authentication and
// protocol bytes may need to flow first with some servers, so the response is
// awaited lazily on the first read (any immediate failure is still reported
// synchronously).
func dialFrontedH2(conn net.Conn, cfg Config, host string, key [32]byte) (net.Conn, error) {
	endpoint, err := url.Parse(endpointURL(host, cfg.Path))
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("fronting: h2 endpoint: %w", err)
	}

	pr, pw := io.Pipe()
	req, err := http.NewRequest(http.MethodPost, endpoint.String(), pr)
	if err != nil {
		pw.Close()
		conn.Close()
		return nil, fmt.Errorf("fronting: h2 request: %w", err)
	}
	// Pin the Host explicitly so the signed value and the :authority pseudo
	// header cannot diverge.
	req.Host = host
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("Cache-Control", "no-store")
	req.Header.Set("User-Agent", DefaultUserAgent)
	SignRequest(req, key, time.Now())

	var dialed atomic.Bool
	transport := &http2.Transport{
		MaxReadFrameSize: H2MaxFrameSize,
		DialTLSContext: func(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			if dialed.Swap(true) {
				return nil, errConnReused
			}
			// The connection has already completed its TLS handshake and is
			// handed to the HTTP/2 transport exactly once.
			return conn, nil
		},
	}

	respCh := make(chan httpResponseResult, 1)
	go func() {
		resp, err := transport.RoundTrip(req)
		if err != nil {
			respCh <- httpResponseResult{err: fmt.Errorf("fronting: h2 request: %w", err)}
			return
		}
		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			respCh <- httpResponseResult{err: fmt.Errorf("fronting: h2 status %s", resp.Status)}
			return
		}
		if resp.ProtoMajor < 2 {
			resp.Body.Close()
			respCh <- httpResponseResult{err: fmt.Errorf("fronting: expected HTTP/2, got %s", resp.Proto)}
			return
		}
		respCh <- httpResponseResult{resp: resp}
	}()

	// Surface failures that happen before the response is needed (bad status,
	// transport error) without waiting for a slow server.
	select {
	case result := <-respCh:
		if result.err != nil {
			pw.Close()
			conn.Close()
			return nil, result.err
		}
		return newHTTPClientConn(result.resp, pw, conn), nil
	default:
		return newPendingHTTPClientConn(respCh, pw, conn), nil
	}
}

// dialFrontedWebSocket performs the HTTP/1.1 WebSocket upgrade on conn.
func dialFrontedWebSocket(conn net.Conn, cfg Config, host string, key [32]byte) (net.Conn, error) {
	endpoint, err := url.Parse(endpointURL(host, cfg.Path))
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("fronting: websocket endpoint: %w", err)
	}
	tunnel, err := clientWebSocketHandshake(conn, endpoint, host, key)
	if err != nil {
		conn.Close()
		return nil, err
	}
	return tunnel, nil
}
