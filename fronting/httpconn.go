package fronting

import (
	"errors"
	"io"
	"net"
	"net/http"
	"sync"
	"time"
)

// httpServerConn adapts an HTTP request/response pair into a net.Conn tunnel.
// Reads consume the request body, writes go to the response body and are
// flushed following the same heuristic as the TSUNAMI implementation: small
// writes (and every httpFlushThreshold bytes) are flushed immediately so
// interactive traffic is not delayed by h2 buffering.
type httpServerConn struct {
	body    io.ReadCloser
	writer  http.ResponseWriter
	flusher http.Flusher

	remote net.Addr
	local  net.Addr

	writeMu sync.Mutex
	closeMu sync.Mutex
	closed  bool

	bytesSinceFlush int
}

// newHTTPServerConn returns a net.Conn backed by r.Body and w. The response
// status line must already have been written (and flushed) by the caller.
func newHTTPServerConn(w http.ResponseWriter, r *http.Request) *httpServerConn {
	flusher, _ := w.(http.Flusher)
	return &httpServerConn{
		body:    r.Body,
		writer:  w,
		flusher: flusher,
		remote:  addrString(r.RemoteAddr),
		local:   addrString(r.Host),
	}
}

func (c *httpServerConn) Read(p []byte) (int, error) {
	return c.body.Read(p)
}

func (c *httpServerConn) Write(p []byte) (int, error) {
	c.closeMu.Lock()
	closed := c.closed
	c.closeMu.Unlock()
	if closed {
		return 0, net.ErrClosed
	}

	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	n, err := c.writer.Write(p)
	c.bytesSinceFlush += n
	if c.shouldFlush(n) {
		c.flushLocked()
	}
	return n, err
}

func (c *httpServerConn) shouldFlush(lastWrite int) bool {
	if c.flusher == nil || lastWrite <= 0 {
		return false
	}
	return lastWrite < 4096 || c.bytesSinceFlush >= httpFlushThreshold
}

func (c *httpServerConn) flushLocked() {
	c.flusher.Flush()
	c.bytesSinceFlush = 0
}

func (c *httpServerConn) Close() error {
	c.closeMu.Lock()
	defer c.closeMu.Unlock()
	if c.closed {
		return nil
	}
	c.closed = true
	c.writeMu.Lock()
	if c.flusher != nil && c.bytesSinceFlush > 0 {
		c.flushLocked()
	}
	c.writeMu.Unlock()
	return c.body.Close()
}

func (c *httpServerConn) LocalAddr() net.Addr  { return c.local }
func (c *httpServerConn) RemoteAddr() net.Addr { return c.remote }

// Deadlines are not supported by the HTTP tunnel adapter; the underlying
// connection lifetime is owned by the HTTP server. They are accepted as no-ops
// so the conn satisfies net.Conn.
func (c *httpServerConn) SetDeadline(time.Time) error      { return nil }
func (c *httpServerConn) SetReadDeadline(time.Time) error  { return nil }
func (c *httpServerConn) SetWriteDeadline(time.Time) error { return nil }

// httpResponseResult carries a pending HTTP tunnel response.
type httpResponseResult struct {
	resp *http.Response
	err  error
}

// httpClientConn adapts an HTTP response body and the request body pipe into a
// net.Conn. It can be created before the response headers arrive (pending), in
// which case reads wait for the response while writes can already push request
// body data.
type httpClientConn struct {
	reader io.ReadCloser
	writer *io.PipeWriter
	raw    net.Conn
	respCh <-chan httpResponseResult

	remote net.Addr
	local  net.Addr

	initOnce sync.Once
	initErr  error

	closeMu   sync.Mutex
	closed    bool
	closeOnce sync.Once
	closeErr  error
}

// newHTTPClientConn returns a net.Conn backed by resp.Body, the request body
// pipe and the underlying transport connection.
func newHTTPClientConn(resp *http.Response, writer *io.PipeWriter, raw net.Conn) *httpClientConn {
	c := &httpClientConn{writer: writer, raw: raw}
	if resp != nil {
		c.reader = resp.Body
	}
	c.setAddrs()
	return c
}

// newPendingHTTPClientConn returns a net.Conn that can write request body data
// before the HTTP response headers arrive. Reads wait for the response.
func newPendingHTTPClientConn(respCh <-chan httpResponseResult, writer *io.PipeWriter, raw net.Conn) *httpClientConn {
	c := &httpClientConn{respCh: respCh, writer: writer, raw: raw}
	c.setAddrs()
	return c
}

func (c *httpClientConn) setAddrs() {
	if c.raw != nil {
		c.local = c.raw.LocalAddr()
		c.remote = c.raw.RemoteAddr()
		return
	}
	c.local = addrString("")
	c.remote = addrString("")
}

func (c *httpClientConn) Read(p []byte) (int, error) {
	if err := c.ensureReader(); err != nil {
		return 0, err
	}
	return c.reader.Read(p)
}

func (c *httpClientConn) Write(p []byte) (int, error) {
	c.closeMu.Lock()
	closed := c.closed
	c.closeMu.Unlock()
	if closed || c.writer == nil {
		return 0, net.ErrClosed
	}
	return c.writer.Write(p)
}

func (c *httpClientConn) Close() error {
	c.closeOnce.Do(func() {
		c.closeMu.Lock()
		c.closed = true
		c.closeMu.Unlock()

		var errs []error
		if c.writer != nil {
			errs = append(errs, c.writer.Close())
		}
		if c.reader != nil {
			errs = append(errs, c.reader.Close())
		}
		if c.raw != nil {
			errs = append(errs, c.raw.Close())
		}
		c.closeErr = errors.Join(errs...)
	})
	return c.closeErr
}

func (c *httpClientConn) LocalAddr() net.Addr  { return c.local }
func (c *httpClientConn) RemoteAddr() net.Addr { return c.remote }

// Deadlines are not supported by the HTTP tunnel adapter: the connection is
// multiplexed by the HTTP transport, so a deadline cannot be applied to it
// without killing the whole tunnel. They are accepted as no-ops.
func (c *httpClientConn) SetDeadline(time.Time) error      { return nil }
func (c *httpClientConn) SetReadDeadline(time.Time) error  { return nil }
func (c *httpClientConn) SetWriteDeadline(time.Time) error { return nil }

func (c *httpClientConn) ensureReader() error {
	if c.reader != nil {
		return nil
	}
	c.initOnce.Do(func() {
		if c.respCh == nil {
			c.initErr = net.ErrClosed
			return
		}
		result := <-c.respCh
		if result.err != nil {
			c.initErr = result.err
			return
		}
		if result.resp == nil || result.resp.Body == nil {
			c.initErr = io.ErrUnexpectedEOF
			return
		}
		c.reader = result.resp.Body
	})
	return c.initErr
}

// simpleAddr is a net.Addr carrying only a string form.
type simpleAddr string

func (a simpleAddr) Network() string { return "fronting" }
func (a simpleAddr) String() string  { return string(a) }

func addrString(s string) net.Addr { return simpleAddr(s) }
