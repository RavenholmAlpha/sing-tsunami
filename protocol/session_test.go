package protocol

import (
	"bytes"
	"errors"
	"testing"
	"time"
)

type testReadWriteCloser struct {
	bytes.Buffer
}

func TestSessionSYNACKResolvesOpenStream(t *testing.T) {
	conn := &testReadWriteCloser{}
	session := NewSession(conn, 1)
	stream := newStream(1, session)
	session.streams[stream.id] = stream

	if err := session.handleFrame(NewFrame(CmdSYNACK, stream.id, nil)); err != nil {
		t.Fatalf("handle SYNACK: %v", err)
	}
	if err := stream.waitForOpen(time.Second); err != nil {
		t.Fatalf("wait for successful SYNACK: %v", err)
	}
}

func TestSessionSYNACKRejectsOpenStream(t *testing.T) {
	conn := &testReadWriteCloser{}
	session := NewSession(conn, 1)
	stream := newStream(1, session)
	session.streams[stream.id] = stream

	if err := session.handleFrame(NewFrame(CmdSYNACK, stream.id, []byte("policy denied"))); err != nil {
		t.Fatalf("handle rejected SYNACK: %v", err)
	}
	if err := stream.waitForOpen(time.Second); !errors.Is(err, ErrStreamRejected) {
		t.Fatalf("wait error = %v, want ErrStreamRejected", err)
	}
}

func (c *testReadWriteCloser) Close() error {
	return nil
}

func TestSessionUpdatePaddingSchemeCallback(t *testing.T) {
	session := NewSession(&testReadWriteCloser{}, 1)
	payload := []byte("stop=1\n0=50-50")

	var got []byte
	session.SetOnPaddingSchemeUpdate(func(data []byte) error {
		got = append([]byte(nil), data...)
		return nil
	})

	if err := session.handleFrame(NewFrame(CmdUpdatePaddingScheme, 0, payload)); err != nil {
		t.Fatalf("handle update padding frame: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("callback data = %q, want %q", got, payload)
	}
}

func TestSessionUpdatePaddingSchemeCallbackError(t *testing.T) {
	session := NewSession(&testReadWriteCloser{}, 1)
	wantErr := errors.New("bad padding update")

	session.SetOnPaddingSchemeUpdate(func(data []byte) error {
		return wantErr
	})

	err := session.handleFrame(NewFrame(CmdUpdatePaddingScheme, 0, []byte("bad")))
	if !errors.Is(err, wantErr) {
		t.Fatalf("handle update padding error = %v, want %v", err, wantErr)
	}
}

func TestStreamWriteBatchesPaddingFrames(t *testing.T) {
	session := NewSession(&testReadWriteCloser{}, 1)
	stream := newStream(1, session)

	var calls int
	var frameCount int
	session.SetPaddingWriteFn(func(frames []*Frame) error {
		calls++
		frameCount = len(frames)
		return nil
	})

	data := make([]byte, MaxFrameDataLen+1)
	n, err := stream.Write(data)
	if err != nil {
		t.Fatalf("stream write: %v", err)
	}
	if n != len(data) {
		t.Fatalf("write n = %d, want %d", n, len(data))
	}
	if calls != 1 {
		t.Fatalf("padding write calls = %d, want 1", calls)
	}
	if frameCount != 2 {
		t.Fatalf("batched frame count = %d, want 2", frameCount)
	}
}

func TestSessionOnStreamClosedHook(t *testing.T) {
	session := NewSession(&testReadWriteCloser{}, 1)
	stream := newStream(7, session)
	session.streams[stream.id] = stream

	closed := make(chan uint32, 1)
	session.SetOnStreamClosed(func(id uint32) {
		closed <- id
	})

	if err := stream.Close(); err != nil {
		t.Fatalf("close stream: %v", err)
	}

	select {
	case id := <-closed:
		if id != 7 {
			t.Fatalf("closed stream id = %d, want 7", id)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("onStreamClosed was not called for a locally closed stream")
	}
	if got := session.ActiveStreamCount(); got != 0 {
		t.Fatalf("active streams = %d, want 0", got)
	}
}

func TestSessionOnStreamClosedHookOnRemoteFIN(t *testing.T) {
	session := NewSession(&testReadWriteCloser{}, 1)
	stream := newStream(9, session)
	session.streams[9] = stream

	closed := make(chan uint32, 1)
	session.SetOnStreamClosed(func(id uint32) {
		closed <- id
	})

	if err := session.handleFrame(NewFrame(CmdFIN, 9, nil)); err != nil {
		t.Fatalf("handle FIN: %v", err)
	}

	select {
	case id := <-closed:
		if id != 9 {
			t.Fatalf("closed stream id = %d, want 9", id)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("onStreamClosed was not called for a remote FIN")
	}
	if got := session.ActiveStreamCount(); got != 0 {
		t.Fatalf("active streams = %d, want 0", got)
	}
}

func TestSessionOnStreamClosedHookRunsOutsideStreamLock(t *testing.T) {
	session := NewSession(&testReadWriteCloser{}, 1)
	stream := newStream(3, session)
	session.streams[3] = stream

	done := make(chan struct{})
	session.SetOnStreamClosed(func(id uint32) {
		// These callbacks take streamMu; they would deadlock if the hook ran
		// while removeStream still held the lock.
		if count := session.ActiveStreamCount(); count != 0 {
			t.Errorf("active streams inside callback = %d, want 0", count)
		}
		session.IsIdle()
		close(done)
	})

	go func() {
		if err := stream.Close(); err != nil {
			t.Errorf("close stream: %v", err)
		}
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("onStreamClosed callback deadlocked on streamMu")
	}
}

func TestSessionWithoutOnStreamClosedHook(t *testing.T) {
	session := NewSession(&testReadWriteCloser{}, 1)
	stream := newStream(5, session)
	session.streams[5] = stream

	// No hook set: closing must not panic.
	if err := stream.Close(); err != nil {
		t.Fatalf("close stream: %v", err)
	}
}
