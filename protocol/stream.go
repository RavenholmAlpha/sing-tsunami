package protocol

import (
	"fmt"
	"io"
	"sync"
	"sync/atomic"
	"time"
)

// Stream represents a single multiplexed proxy connection within a Session.
type Stream struct {
	id       uint32
	session  *Session
	priority uint8

	// Read side: incoming data from remote.
	readBuf     chan []byte
	readBufOnce sync.Once
	doneCh      chan struct{} // closed when stream is done, unblocks reads and delivery
	readLeft    []byte        // leftover from partial reads
	openResult  chan error    // resolved by SYNACK for locally initiated streams
	openOnce    sync.Once

	// State.
	closed  atomic.Bool
	closeMu sync.Mutex

	// Flow tracking.
	bytesRead    atomic.Int64
	bytesWritten atomic.Int64
}

// streamReadBufFrames bounds the per-stream frame queue. Frames can be up to
// 64 KiB, so this caps buffered data per stream at ~256 KiB; a slow reader
// applies backpressure instead of letting a stream allocate without bound.
const streamReadBufFrames = 4

// newStream creates a new stream within a session.
func newStream(id uint32, session *Session) *Stream {
	return &Stream{
		id:         id,
		session:    session,
		priority:   DefaultStreamPriority,
		readBuf:    make(chan []byte, streamReadBufFrames),
		doneCh:     make(chan struct{}),
		openResult: make(chan error, 1),
	}
}

func (s *Stream) waitForOpen(timeout time.Duration) error {
	// Prefer an already delivered SYNACK result over doneCh. Rejection closes
	// the stream as part of cleanup, but callers still need the rejection cause.
	select {
	case err := <-s.openResult:
		return err
	default:
	}

	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case err := <-s.openResult:
		return err
	case <-timer.C:
		return fmt.Errorf("tsunami: wait for stream %d SYNACK: %w", s.id, ErrSessionClosed)
	case <-s.doneCh:
		select {
		case err := <-s.openResult:
			return err
		default:
		}
		return ErrStreamClosed
	}
}

func (s *Stream) resolveOpen(err error) {
	s.openOnce.Do(func() {
		s.openResult <- err
	})
}

// closeReadBuf safely marks the read side closed exactly once.
// It may be called concurrently from Stream.Close, closeByRemote, or Session.Close.
func (s *Stream) closeReadBuf() {
	s.readBufOnce.Do(func() {
		close(s.doneCh)
	})
}

// ID returns the stream identifier.
func (s *Stream) ID() uint32 {
	return s.id
}

// Read reads data from the stream, implementing io.Reader.
func (s *Stream) Read(p []byte) (int, error) {
	if len(s.readLeft) > 0 {
		n := copy(p, s.readLeft)
		s.readLeft = s.readLeft[n:]
		s.bytesRead.Add(int64(n))
		return n, nil
	}

	// Drain already-buffered data before observing a concurrent close.
	select {
	case data := <-s.readBuf:
		return s.consumeReadData(p, data), nil
	default:
	}

	if s.closed.Load() {
		return 0, ErrStreamClosed
	}

	select {
	case data := <-s.readBuf:
		return s.consumeReadData(p, data), nil
	case <-s.doneCh:
		return 0, io.EOF
	}
}

func (s *Stream) consumeReadData(p []byte, data []byte) int {
	n := copy(p, data)
	if n < len(data) {
		s.readLeft = data[n:]
	}
	s.bytesRead.Add(int64(n))
	return n
}

// Write writes data to the stream by sending cmdPSH frames, implementing io.Writer.
// Frames are batched and written under a single lock acquisition to reduce contention.
func (s *Stream) Write(p []byte) (int, error) {
	if s.closed.Load() {
		return 0, ErrStreamClosed
	}
	if len(p) == 0 {
		return 0, nil
	}

	// Build all frames first, then write under a single lock.
	var frames []*Frame
	for off := 0; off < len(p); {
		n := len(p) - off
		if n > MaxFrameDataLen {
			n = MaxFrameDataLen
		}
		frames = append(frames, NewFrame(CmdPSH, s.id, p[off:off+n]))
		off += n
	}

	if err := s.session.writeFrames(frames); err != nil {
		return 0, err
	}

	s.bytesWritten.Add(int64(len(p)))
	return len(p), nil
}

// Close closes the stream by sending cmdFIN.
func (s *Stream) Close() error {
	s.closeMu.Lock()
	defer s.closeMu.Unlock()

	if s.closed.Load() {
		return nil
	}
	s.closed.Store(true)
	s.resolveOpen(ErrStreamClosed)

	// Send FIN to remote (best effort).
	_ = s.session.writeFrame(NewFrame(CmdFIN, s.id, nil))

	s.closeReadBuf()
	s.session.removeStream(s.id)

	return nil
}

// deliverData pushes incoming data into the stream's read buffer.
// If the buffer is full, this applies backpressure instead of dropping data.
func (s *Stream) deliverData(data []byte) error {
	select {
	case <-s.doneCh:
		return ErrStreamClosed
	default:
	}

	select {
	case s.readBuf <- data:
		return nil
	case <-s.doneCh:
		return ErrStreamClosed
	}
}

// closeByRemote is called when the remote sends cmdFIN for this stream.
func (s *Stream) closeByRemote(err error) {
	s.closeMu.Lock()
	defer s.closeMu.Unlock()

	if s.closed.Load() {
		return
	}
	s.closed.Store(true)
	if err == nil {
		err = ErrStreamClosed
	}
	s.resolveOpen(err)
	s.closeReadBuf()
	s.session.removeStream(s.id)
}

// SetPriority sets the stream's scheduling priority (0=highest, 255=lowest).
func (s *Stream) SetPriority(priority uint8) {
	s.priority = priority
}

// Priority returns the stream's scheduling priority.
func (s *Stream) Priority() uint8 {
	return s.priority
}

// BytesRead returns the total number of bytes read from this stream.
func (s *Stream) BytesRead() int64 {
	return s.bytesRead.Load()
}

// BytesWritten returns the total number of bytes written to this stream.
func (s *Stream) BytesWritten() int64 {
	return s.bytesWritten.Load()
}
