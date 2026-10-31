package protocol

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
)

// ReadSocksAddr reads one SOCKS5-style address from r and returns host:port.
// It uses io.ReadFull so an address may span multiple PSH frames safely.
func ReadSocksAddr(r io.Reader) (string, error) {
	var atyp [1]byte
	if _, err := io.ReadFull(r, atyp[:]); err != nil {
		return "", fmt.Errorf("tsunami: read address type: %w", err)
	}

	switch atyp[0] {
	case AtypIPv4:
		var raw [4]byte
		if _, err := io.ReadFull(r, raw[:]); err != nil {
			return "", fmt.Errorf("tsunami: read IPv4 address: %w", err)
		}
		port, err := readAddressPort(r)
		if err != nil {
			return "", err
		}
		return net.JoinHostPort(net.IP(raw[:]).String(), port), nil

	case AtypDomain:
		var size [1]byte
		if _, err := io.ReadFull(r, size[:]); err != nil {
			return "", fmt.Errorf("tsunami: read domain length: %w", err)
		}
		if size[0] == 0 {
			return "", fmt.Errorf("tsunami: empty domain")
		}
		domain := make([]byte, size[0])
		if _, err := io.ReadFull(r, domain); err != nil {
			return "", fmt.Errorf("tsunami: read domain: %w", err)
		}
		port, err := readAddressPort(r)
		if err != nil {
			return "", err
		}
		return net.JoinHostPort(string(domain), port), nil

	case AtypIPv6:
		var raw [16]byte
		if _, err := io.ReadFull(r, raw[:]); err != nil {
			return "", fmt.Errorf("tsunami: read IPv6 address: %w", err)
		}
		port, err := readAddressPort(r)
		if err != nil {
			return "", err
		}
		return net.JoinHostPort(net.IP(raw[:]).String(), port), nil

	default:
		return "", fmt.Errorf("tsunami: unknown address type: 0x%02x", atyp[0])
	}
}

func readAddressPort(r io.Reader) (string, error) {
	var raw [2]byte
	if _, err := io.ReadFull(r, raw[:]); err != nil {
		return "", fmt.Errorf("tsunami: read address port: %w", err)
	}
	port := binary.BigEndian.Uint16(raw[:])
	if port == 0 {
		return "", fmt.Errorf("tsunami: invalid address port 0")
	}
	return fmt.Sprintf("%d", port), nil
}
