package protocol

import (
	"io"
	"net"
	"testing"
	"time"
)

func TestSessionMaxStreams(t *testing.T) {
	serverSide, clientSide := net.Pipe()
	session := NewSession(serverSide, 0)
	session.SetMaxStreams(3)
	session.SetOnStreamOpen(func(s *Stream) {})
	go session.RunEventLoop()
	go io.Copy(io.Discard, clientSide)

	for i := 1; i <= 5; i++ {
		if err := EncodeFrame(clientSide, NewFrame(CmdSYN, uint32(i), nil)); err != nil {
			t.Fatalf("send SYN %d: %v", i, err)
		}
	}

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if session.ActiveStreamCount() >= 3 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	time.Sleep(100 * time.Millisecond)
	if got := session.ActiveStreamCount(); got != 3 {
		t.Fatalf("active streams = %d, want 3 (limit)", got)
	}
	_ = session.Close()
}
