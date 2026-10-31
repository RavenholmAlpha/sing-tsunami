package tsunami

import (
	"bytes"
	"testing"

	"github.com/RavenholmAlpha/sing-tsunami/protocol"
)

func TestAddrRoundTrip(t *testing.T) {
	tests := []struct {
		name        string
		destination string
		want        string
	}{
		{name: "ipv4", destination: "127.0.0.1:8080", want: "127.0.0.1:8080"},
		{name: "domain", destination: "example.com:443", want: "example.com:443"},
		{name: "ipv6", destination: "[2001:db8::1]:443", want: "[2001:db8::1]:443"},
		{name: "ipv6 loopback", destination: "[::1]:53", want: "[::1]:53"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			if err := WriteAddr(&buf, tt.destination); err != nil {
				t.Fatalf("WriteAddr(%q): %v", tt.destination, err)
			}
			got, err := ReadAddr(&buf)
			if err != nil {
				t.Fatalf("ReadAddr: %v", err)
			}
			if got != tt.want {
				t.Fatalf("ReadAddr = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestWriteAddrEncoding(t *testing.T) {
	tests := []struct {
		name        string
		destination string
		atyp        byte
		length      int
	}{
		{name: "ipv4", destination: "127.0.0.1:80", atyp: protocol.AtypIPv4, length: 1 + 4 + 2},
		{name: "domain", destination: "example.com:443", atyp: protocol.AtypDomain, length: 1 + 1 + len("example.com") + 2},
		{name: "ipv6", destination: "[::1]:443", atyp: protocol.AtypIPv6, length: 1 + 16 + 2},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			if err := WriteAddr(&buf, tt.destination); err != nil {
				t.Fatalf("WriteAddr: %v", err)
			}
			encoded := buf.Bytes()
			if len(encoded) != tt.length {
				t.Fatalf("encoded length = %d, want %d", len(encoded), tt.length)
			}
			if encoded[0] != tt.atyp {
				t.Fatalf("ATYP = 0x%02x, want 0x%02x", encoded[0], tt.atyp)
			}
		})
	}
}

func TestWriteAddrRejectsInvalidDestinations(t *testing.T) {
	cases := []string{
		"",
		"example.com",
		"example.com:0",
		"example.com:65536",
		"example.com:not-a-port",
		":443",
	}
	for _, destination := range cases {
		var buf bytes.Buffer
		if err := WriteAddr(&buf, destination); err == nil {
			t.Errorf("WriteAddr(%q) = nil error, want error", destination)
		}
	}
}

func TestReadAddrRejectsTruncatedInput(t *testing.T) {
	for _, data := range [][]byte{
		{},
		{protocol.AtypIPv4, 127, 0, 0},
		{protocol.AtypDomain, 5, 'a', 'b'},
		{0x7f},
	} {
		if _, err := ReadAddr(bytes.NewReader(data)); err == nil {
			t.Errorf("ReadAddr(%v) = nil error, want error", data)
		}
	}
}
