package tsunami

import (
	"bytes"
	"context"
	"net"
	"testing"

	"github.com/RavenholmAlpha/sing-tsunami/padding"
	"github.com/RavenholmAlpha/sing-tsunami/protocol"
)

func TestAuthPaddingLengthRange(t *testing.T) {
	seen := make(map[int]struct{})
	for i := 0; i < 2000; i++ {
		n := authPaddingLen()
		if n < authPaddingMin || n > authPaddingMax {
			t.Fatalf("auth padding length = %d, want %d..%d", n, authPaddingMin, authPaddingMax)
		}
		seen[n] = struct{}{}
	}
	if len(seen) < 2 {
		t.Fatalf("auth padding length is not randomized: only saw %v", seen)
	}
}

func TestApplyPaddingSchemeUpdateUpdatesClientAndWriter(t *testing.T) {
	c := &Client{paddingScheme: padding.DefaultScheme()}
	var out bytes.Buffer
	writer := padding.NewWriter(&out, c.currentPaddingScheme())

	schemeText := "stop=2\nctl=~50-50\n0=~60-60\n1=~80-80"
	expected, err := padding.Parse(schemeText)
	if err != nil {
		t.Fatalf("parse expected scheme: %v", err)
	}

	if err := c.applyPaddingSchemeUpdate([]byte(schemeText), writer); err != nil {
		t.Fatalf("apply padding update: %v", err)
	}
	if got := c.currentPaddingScheme().MD5(); got != expected.MD5() {
		t.Fatalf("client scheme md5 = %s, want %s", got, expected.MD5())
	}

	// Control frames use the updated ctl rule (~50).
	before := out.Len()
	if err := writer.WriteFramesWithPadding([]*protocol.Frame{
		protocol.NewFrame(protocol.CmdFIN, 1, nil),
	}); err != nil {
		t.Fatalf("write padded control frame: %v", err)
	}
	if got := out.Len() - before; got != 50 {
		t.Fatalf("padded control write length = %d, want 50", got)
	}

	// The per-stream epoch starts at rule 0 (~60), then rule 1 (~80).
	before = out.Len()
	if err := writer.WriteFramesWithPadding([]*protocol.Frame{
		protocol.NewFrame(protocol.CmdPSH, 3, make([]byte, 10)),
	}); err != nil {
		t.Fatalf("write first padded stream frame: %v", err)
	}
	if got := out.Len() - before; got != 60 {
		t.Fatalf("first stream write length = %d, want 60", got)
	}

	before = out.Len()
	if err := writer.WriteFramesWithPadding([]*protocol.Frame{
		protocol.NewFrame(protocol.CmdPSH, 3, make([]byte, 10)),
	}); err != nil {
		t.Fatalf("write second padded stream frame: %v", err)
	}
	if got := out.Len() - before; got != 80 {
		t.Fatalf("second stream write length = %d, want 80", got)
	}
}

func TestApplyPaddingSchemeUpdateRejectsInvalidScheme(t *testing.T) {
	original := padding.DefaultScheme()
	c := &Client{paddingScheme: original}

	if err := c.applyPaddingSchemeUpdate([]byte("stop=bad"), nil); err == nil {
		t.Fatal("expected invalid scheme error")
	}
	if got := c.currentPaddingScheme().MD5(); got != original.MD5() {
		t.Fatalf("client scheme changed after invalid update: got %s, want %s", got, original.MD5())
	}
}

func TestNewClientValidatesConfig(t *testing.T) {
	if _, err := NewClient(nil, ClientConfig{}); err == nil {
		t.Fatal("NewClient without password or DialOut returned no error")
	}
	if _, err := NewClient(nil, ClientConfig{Password: "secret"}); err == nil {
		t.Fatal("NewClient without DialOut returned no error")
	}
	if _, err := NewClient(nil, ClientConfig{Password: "secret", DialOut: func(ctx context.Context) (net.Conn, error) {
		return nil, nil
	}, PaddingScheme: []byte("stop=bad")}); err == nil {
		t.Fatal("NewClient with an invalid padding scheme returned no error")
	}
}

func TestNewServiceValidatesConfig(t *testing.T) {
	handler := func(context.Context, net.Conn, net.Addr, string) {}
	if _, err := NewService(ServiceConfig{}); err == nil {
		t.Fatal("NewService without handler returned no error")
	}
	if _, err := NewService(ServiceConfig{Handler: handler}); err == nil {
		t.Fatal("NewService without users returned no error")
	}
	if _, err := NewService(ServiceConfig{
		Users:   []User{{Name: "alice"}},
		Handler: handler,
	}); err == nil {
		t.Fatal("NewService with an empty password returned no error")
	}
	if _, err := NewService(ServiceConfig{
		Users:         []User{{Name: "alice", Password: "secret"}},
		Handler:       handler,
		PaddingScheme: []byte("stop=bad"),
	}); err == nil {
		t.Fatal("NewService with an invalid padding scheme returned no error")
	}
}
