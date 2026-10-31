package protocol

import (
	"errors"
	"testing"
	"time"
)

func TestStreamDeliverDataBackpressuresWithoutDropping(t *testing.T) {
	stream := newStream(1, NewSession(&testReadWriteCloser{}, 1))
	for i := 0; i < cap(stream.readBuf); i++ {
		if err := stream.deliverData([]byte{byte(i)}); err != nil {
			t.Fatalf("fill read buffer: %v", err)
		}
	}

	marker := []byte("marker")
	delivered := make(chan error, 1)
	go func() {
		delivered <- stream.deliverData(marker)
	}()

	select {
	case err := <-delivered:
		t.Fatalf("deliverData returned before buffer space was available: %v", err)
	case <-time.After(50 * time.Millisecond):
	}

	buf := make([]byte, len(marker))
	if _, err := stream.Read(buf[:1]); err != nil {
		t.Fatalf("read one buffered frame: %v", err)
	}

	select {
	case err := <-delivered:
		if err != nil {
			t.Fatalf("deliver blocked frame: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("deliverData did not resume after buffer space was available")
	}

	for i := 1; i < cap(stream.readBuf); i++ {
		if _, err := stream.Read(buf[:1]); err != nil {
			t.Fatalf("drain buffered frame %d: %v", i, err)
		}
	}

	n, err := stream.Read(buf)
	if err != nil {
		t.Fatalf("read marker: %v", err)
	}
	if got := string(buf[:n]); got != string(marker) {
		t.Fatalf("marker = %q, want %q", got, marker)
	}
}

func TestStreamDeliverDataUnblocksWhenClosed(t *testing.T) {
	stream := newStream(1, NewSession(&testReadWriteCloser{}, 1))
	for i := 0; i < cap(stream.readBuf); i++ {
		if err := stream.deliverData([]byte{0}); err != nil {
			t.Fatalf("fill read buffer: %v", err)
		}
	}

	delivered := make(chan error, 1)
	go func() {
		delivered <- stream.deliverData([]byte("blocked"))
	}()

	select {
	case err := <-delivered:
		t.Fatalf("deliverData returned before close: %v", err)
	case <-time.After(50 * time.Millisecond):
	}

	stream.closeByRemote(nil)

	select {
	case err := <-delivered:
		if !errors.Is(err, ErrStreamClosed) {
			t.Fatalf("deliverData error = %v, want %v", err, ErrStreamClosed)
		}
	case <-time.After(time.Second):
		t.Fatal("deliverData did not unblock after stream close")
	}
}
