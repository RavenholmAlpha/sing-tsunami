package tsunami

import (
	"net"
	"time"

	"github.com/RavenholmAlpha/sing-tsunami/protocol"
)

// streamConn adapts a multiplexed protocol.Stream to net.Conn so callers can
// use ordinary stream-oriented code on top of a TSUNAMI session.
type streamConn struct {
	stream *protocol.Stream
	local  net.Addr
	remote net.Addr
}

// newStreamConn wraps stream. local and remote may be nil, in which case a
// synthetic address is reported.
func newStreamConn(stream *protocol.Stream, local, remote net.Addr) *streamConn {
	return &streamConn{
		stream: stream,
		local:  fallbackAddr(local),
		remote: fallbackAddr(remote),
	}
}

func (c *streamConn) Read(p []byte) (int, error)  { return c.stream.Read(p) }
func (c *streamConn) Write(p []byte) (int, error) { return c.stream.Write(p) }
func (c *streamConn) Close() error                { return c.stream.Close() }
func (c *streamConn) LocalAddr() net.Addr         { return c.local }
func (c *streamConn) RemoteAddr() net.Addr        { return c.remote }

// The TSUNAMI mux protocol has no per-stream deadline signaling. Deadlines are
// accepted for net.Conn compatibility but are not enforced; callers that need
// timeouts should close the connection or select on a context.
func (c *streamConn) SetDeadline(time.Time) error      { return nil }
func (c *streamConn) SetReadDeadline(time.Time) error  { return nil }
func (c *streamConn) SetWriteDeadline(time.Time) error { return nil }

// streamAddr is a synthetic net.Addr used when the underlying transport does
// not expose an address for a stream.
type streamAddr struct {
	network string
	address string
}

func (a streamAddr) Network() string { return a.network }
func (a streamAddr) String() string  { return a.address }

func fallbackAddr(addr net.Addr) net.Addr {
	if addr != nil {
		return addr
	}
	return streamAddr{network: "tsunami", address: "stream"}
}

var _ net.Conn = (*streamConn)(nil)
