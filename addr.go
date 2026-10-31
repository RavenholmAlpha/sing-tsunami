package tsunami

import (
	"fmt"
	"io"
	"net"
	"strconv"

	"github.com/RavenholmAlpha/sing-tsunami/protocol"
)

// WriteAddr writes destination to w using the SOCKS5 address encoding the
// TSUNAMI protocol uses for stream targets (ATYP byte, address, port).
//
// destination must be "host:port"; an IPv6 host needs the usual brackets
// ("[2001:db8::1]:443"). Hosts are sent as IPv4, IPv6, or a domain name,
// whichever form the text takes.
func WriteAddr(w io.Writer, destination string) error {
	encoded, err := encodeAddr(destination)
	if err != nil {
		return err
	}
	_, err = w.Write(encoded)
	return err
}

// ReadAddr reads one SOCKS5-encoded destination written by WriteAddr and
// returns it as "host:port".
//
// IPv6 hosts are returned in bracketed form ("[2001:db8::1]:443", via
// net.JoinHostPort), so callers that need a bare host should split the result
// with net.SplitHostPort.
func ReadAddr(r io.Reader) (string, error) {
	return protocol.ReadSocksAddr(r)
}

// encodeAddr builds the SOCKS5 wire form of destination.
func encodeAddr(destination string) ([]byte, error) {
	host, portStr, err := net.SplitHostPort(destination)
	if err != nil {
		return nil, fmt.Errorf("invalid target address: %w", err)
	}
	if host == "" {
		return nil, fmt.Errorf("invalid target address %q: empty host", destination)
	}

	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return nil, fmt.Errorf("invalid target port %q", portStr)
	}

	if ip := net.ParseIP(host); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			buf := make([]byte, 1+net.IPv4len+2)
			buf[0] = protocol.AtypIPv4
			copy(buf[1:5], ip4)
			buf[5] = byte(port >> 8)
			buf[6] = byte(port)
			return buf, nil
		}
		buf := make([]byte, 1+net.IPv6len+2)
		buf[0] = protocol.AtypIPv6
		copy(buf[1:17], ip.To16())
		buf[17] = byte(port >> 8)
		buf[18] = byte(port)
		return buf, nil
	}

	if len(host) > 255 {
		return nil, fmt.Errorf("domain too long: %s", host)
	}
	buf := make([]byte, 1+1+len(host)+2)
	buf[0] = protocol.AtypDomain
	buf[1] = byte(len(host))
	copy(buf[2:2+len(host)], host)
	buf[2+len(host)] = byte(port >> 8)
	buf[2+len(host)+1] = byte(port)
	return buf, nil
}
