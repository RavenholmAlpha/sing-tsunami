package protocol

import (
	"bytes"
	"io"
	"testing"
)

func TestReadSocksAddrAcrossShortReads(t *testing.T) {
	encoded := []byte{AtypDomain, 12, 'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 't', 'e', 's', 't', 0x01, 0xbb}
	reader := &shortReader{reader: bytes.NewReader(encoded), size: 2}
	address, err := ReadSocksAddr(reader)
	if err != nil {
		t.Fatalf("read address: %v", err)
	}
	if address != "example.test:443" {
		t.Fatalf("address = %q", address)
	}
}

func TestReadSocksAddrRejectsZeroPort(t *testing.T) {
	_, err := ReadSocksAddr(bytes.NewReader([]byte{AtypIPv4, 127, 0, 0, 1, 0, 0}))
	if err == nil {
		t.Fatal("expected zero-port error")
	}
}

type shortReader struct {
	reader io.Reader
	size   int
}

func (r *shortReader) Read(p []byte) (int, error) {
	if len(p) > r.size {
		p = p[:r.size]
	}
	return r.reader.Read(p)
}
