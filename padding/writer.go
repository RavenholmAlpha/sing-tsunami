package padding

import (
	"encoding/binary"
	"io"
	"sync"
	"sync/atomic"
	"time"

	"github.com/RavenholmAlpha/sing-tsunami/protocol"
)

// maxTrackedStreams bounds the per-stream padding epoch table. Sessions are
// long-lived and can carry thousands of streams; when the table grows beyond
// this limit the oldest entry is pruned. Closed streams are normally removed
// through ForgetStream (wired to Session.SetOnStreamClosed), so pruning is
// only a safety net against callers that never report stream closes.
const maxTrackedStreams = 1024

// streamState is the padding epoch of a single data stream.
type streamState struct {
	idx        int       // number of data writes seen for this stream
	bytes      int       // bytes written for this stream (payload + padding)
	insertedAt time.Time // used to prune the oldest entries
	seq        uint64    // tie-breaker when timestamps are equal
}

// Writer wraps a TLS connection writer and applies the PaddingScheme to
// outgoing data.
//
// Data writes are bucketed per stream: a call whose frames are all CmdPSH with
// the same non-zero StreamID advances that stream's epoch. Everything else is
// a control write and always uses the scheme's ctl rule.
type Writer struct {
	w      io.Writer
	scheme *Scheme
	role   Role
	fw     *protocol.FrameWriter

	mu       sync.Mutex
	ctlIdx   int   // control-bucket write counter (PacketIndex)
	ctlBytes int64 // bytes written for control writes (observability)
	streams  map[uint32]*streamState
	nextSeq  uint64
	rawBuf   []byte // reusable encoding buffer for unpadded frame writes
}

// NewWriter creates a new padding-aware writer for the client role.
//
// Kept for compatibility; use NewWriterForRole to select the direction.
func NewWriter(w io.Writer, scheme *Scheme) *Writer {
	return NewWriterForRole(w, scheme, RoleClient)
}

// NewWriterForRole creates a padding-aware writer for the given direction.
// role selects the directional c<idx> / s<idx> padding rules.
func NewWriterForRole(w io.Writer, scheme *Scheme, role Role) *Writer {
	return &Writer{
		w:       w,
		scheme:  scheme,
		role:    role,
		fw:      protocol.NewFrameWriter(w),
		streams: make(map[uint32]*streamState),
	}
}

// UpdateScheme replaces the current padding scheme. It takes effect from the
// next write on this writer; per-stream epochs are preserved across updates.
func (pw *Writer) UpdateScheme(scheme *Scheme) {
	pw.mu.Lock()
	defer pw.mu.Unlock()
	pw.scheme = scheme
}

// ForgetStream drops the padding epoch of a stream. Sessions call it when the
// stream closes so closed streams do not occupy the bounded epoch table and so
// a future stream reusing the ID starts with a fresh epoch.
func (pw *Writer) ForgetStream(id uint32) {
	pw.mu.Lock()
	delete(pw.streams, id)
	pw.mu.Unlock()
}

// WriteFramesWithPadding writes frames applying the PaddingScheme rules.
//
// The bucket is decided per call:
//   - every frame is CmdPSH with the same non-zero StreamID: that stream's
//     epoch decides whether/how to pad this write;
//   - anything else (settings, SYN/SYNACK/FIN, heartbeats, padding updates,
//     keepalive waste, mixed batches): the control bucket, which always uses
//     the scheme's ctl rule for the whole session lifetime.
//
// On the unpadded fast path frames are encoded into a buffer reused by this
// Writer (it is serialized by its own mutex), so that path does not allocate.
func (pw *Writer) WriteFramesWithPadding(frames []*protocol.Frame) error {
	if len(frames) == 0 {
		// Nothing to serialize and nothing to pad.
		return nil
	}
	for _, f := range frames {
		if f == nil {
			return protocol.ErrInvalidFrame
		}
		if len(f.Data) > protocol.MaxFrameDataLen {
			return protocol.ErrFrameTooLarge
		}
	}

	pw.mu.Lock()
	defer pw.mu.Unlock()

	if pw.scheme == nil {
		return pw.writeFramesRawLocked(frames)
	}

	if id, ok := dataStreamBucket(frames); ok {
		return pw.writeStreamLocked(frames, id)
	}
	return pw.writeControlLocked(frames)
}

// writeStreamLocked applies the per-stream epoch to a data write.
func (pw *Writer) writeStreamLocked(frames []*protocol.Frame, id uint32) error {
	state := pw.streams[id]
	if state == nil {
		pw.nextSeq++
		state = &streamState{insertedAt: time.Now(), seq: pw.nextSeq}
		pw.streams[id] = state
		pw.pruneStreamsLocked()
	}

	idx := state.idx
	state.idx++

	var segments []Segment
	if pw.scheme.StreamBytes <= 0 || state.bytes < pw.scheme.StreamBytes {
		segments = pw.scheme.GetSegmentsFor(pw.role, idx)
	}
	if segments == nil {
		// Unpadded fast path: encode into the Writer's reusable buffer.
		if err := pw.writeFramesRawLocked(frames); err != nil {
			return err
		}
		state.bytes += wireLen(frames)
		return nil
	}

	written, err := pw.applySegments(serializeFrames(frames), segments)
	state.bytes += written
	return err
}

// writeControlLocked applies the ctl rule to a streamless write.
//
// Control padding is intentionally NOT limited by stop / stream_bytes: SYN,
// SYNACK, FIN, heartbeats and padding updates keep occurring for the whole
// life of the session, and leaving them unpadded after a short epoch would
// leak tiny, highly regular record sizes.
func (pw *Writer) writeControlLocked(frames []*protocol.Frame) error {
	pw.ctlIdx++
	segments := pw.scheme.ControlRules
	if segments == nil {
		if err := pw.writeFramesRawLocked(frames); err != nil {
			return err
		}
		pw.ctlBytes += int64(wireLen(frames))
		return nil
	}

	written, err := pw.applySegments(serializeFrames(frames), segments)
	pw.ctlBytes += int64(written)
	return err
}

// applySegments applies a padding rule to the serialized write and returns the
// number of bytes written to the underlying writer.
func (pw *Writer) applySegments(userData []byte, segments []Segment) (int, error) {
	written := 0
	offset := 0
	remaining := len(userData)

	for _, seg := range segments {
		if seg.IsPadTo {
			// Pad-to consumes the rest of the payload and ends the rule.
			n, err := pw.writePadTo(userData[offset:], seg)
			written += n
			return written, err
		}

		if seg.IsCheck {
			// 'c' check: if user data is exhausted, stop sending
			if remaining <= 0 {
				return written, nil
			}
			continue
		}

		targetLen := RandomInRange(seg.MinSize, seg.MaxSize)
		if targetLen < 0 {
			targetLen = 0
		}

		if remaining >= targetLen {
			// Enough user data — send a chunk of user data
			n, err := pw.w.Write(userData[offset : offset+targetLen])
			written += n
			if err != nil {
				return written, err
			}
			offset += targetLen
			remaining -= targetLen
		} else if remaining > 0 {
			// Not enough user data — send remaining user data + waste padding
			// Subtract FrameHeaderLen because the waste frame wire format adds its own header
			wasteSize := clampWasteSize(targetLen - remaining - protocol.FrameHeaderLen)
			wasteFrame := protocol.NewWasteFrame(wasteSize)
			wasteBytes := serializeFrames([]*protocol.Frame{wasteFrame})

			// Combine: remaining user data + waste frame
			combined := make([]byte, remaining+len(wasteBytes))
			copy(combined, userData[offset:offset+remaining])
			copy(combined[remaining:], wasteBytes)

			n, err := pw.w.Write(combined)
			written += n
			if err != nil {
				return written, err
			}
			offset += remaining
			remaining = 0
		} else {
			// No user data left — send pure waste padding
			wasteSize := clampWasteSize(targetLen - protocol.FrameHeaderLen)
			if err := pw.fw.WriteFrame(protocol.NewWasteFrame(wasteSize)); err != nil {
				return written, err
			}
			written += protocol.FrameHeaderLen + wasteSize
		}
	}

	// If user data still has remaining bytes after all segments, send directly
	if remaining > 0 {
		n, err := pw.w.Write(userData[offset:])
		written += n
		return written, err
	}

	return written, nil
}

// writePadTo emits payload as a SINGLE write padded to a random target size in
// [MinSize, MaxSize] by appending one cmdWaste frame inside the same write.
//
// The target is clamped to [len(payload)+FrameHeaderLen, MaxPadTarget]:
//   - the lower bound guarantees room for the waste frame header, so padding is
//     possible as long as the payload itself is below the record cap;
//   - the upper bound is the TLS record plaintext limit.
//
// If the payload is already at least as large as the requested target, it is
// written unchanged (one record, no waste frame, never split). The same applies
// when the payload leaves no room for a waste header below MaxPadTarget.
func (pw *Writer) writePadTo(payload []byte, seg Segment) (int, error) {
	target := RandomInRange(seg.MinSize, seg.MaxSize)
	if len(payload) >= target {
		// Already at least as large as the wanted record: nothing to add.
		n, err := pw.w.Write(payload)
		return n, err
	}

	minTarget := len(payload) + protocol.FrameHeaderLen
	if minTarget > MaxPadTarget {
		// Payload alone already reaches the TLS record limit: one record, no
		// room for an appended waste frame.
		n, err := pw.w.Write(payload)
		return n, err
	}
	if target < minTarget {
		target = minTarget
	}
	if target > MaxPadTarget {
		target = MaxPadTarget
	}
	wasteSize := target - minTarget

	out := make([]byte, target)
	copy(out, payload)
	waste := out[len(payload):]
	waste[0] = byte(protocol.CmdWaste)
	// waste[1:5] is the stream ID and stays zero; the length is the waste payload size.
	binary.BigEndian.PutUint16(waste[5:7], uint16(wasteSize))

	n, err := pw.w.Write(out)
	return n, err
}

// maxReusableRawBuf bounds the encoding buffer retained per Writer. Writes up
// to this size are encoded without allocating; larger writes fall back to the
// shared pooled encoder so one huge write does not pin memory for the session.
const maxReusableRawBuf = 128 * 1024

// writeFramesRawLocked encodes frames into the Writer's reusable buffer and
// writes them in one call without padding. pw.mu must be held. The reusable
// buffer keeps the common unpadded path allocation-free.
func (pw *Writer) writeFramesRawLocked(frames []*protocol.Frame) error {
	total := wireLen(frames)
	if total > maxReusableRawBuf {
		// Rare huge write: use the shared pooled encoder instead of retaining a
		// large per-writer buffer for the rest of the session.
		return pw.fw.WriteFrames(frames)
	}
	if cap(pw.rawBuf) < total {
		pw.rawBuf = make([]byte, 0, total)
	}
	buf := pw.rawBuf[:0]
	var header [protocol.FrameHeaderLen]byte
	for _, f := range frames {
		header[0] = byte(f.Command)
		header[1] = byte(f.StreamID >> 24)
		header[2] = byte(f.StreamID >> 16)
		header[3] = byte(f.StreamID >> 8)
		header[4] = byte(f.StreamID)
		header[5] = byte(len(f.Data) >> 8)
		header[6] = byte(len(f.Data))
		buf = append(buf, header[:]...)
		buf = append(buf, f.Data...)
	}
	if _, err := pw.w.Write(buf); err != nil {
		return err
	}
	pw.rawBuf = buf[:0]
	return nil
}

// prunesStreamsLocked removes the oldest stream state when the table is over
// the limit. pw.mu must be held.
func (pw *Writer) pruneStreamsLocked() {
	if len(pw.streams) <= maxTrackedStreams {
		return
	}
	var oldestID uint32
	var oldest *streamState
	for id, state := range pw.streams {
		if oldest == nil ||
			state.insertedAt.Before(oldest.insertedAt) ||
			(state.insertedAt.Equal(oldest.insertedAt) && state.seq < oldest.seq) {
			oldestID, oldest = id, state
		}
	}
	delete(pw.streams, oldestID)
}

// dataStreamBucket reports the stream a write belongs to when every frame is
// CmdPSH with the same non-zero StreamID.
func dataStreamBucket(frames []*protocol.Frame) (uint32, bool) {
	id := frames[0].StreamID
	if id == 0 {
		return 0, false
	}
	for _, f := range frames {
		if f.Command != protocol.CmdPSH || f.StreamID != id {
			return 0, false
		}
	}
	return id, true
}

// wireLen returns the TSUNAMI wire size of the given frames.
func wireLen(frames []*protocol.Frame) int {
	total := 0
	for _, f := range frames {
		total += protocol.FrameHeaderLen + len(f.Data)
	}
	return total
}

// clampWasteSize guards generated cmdWaste frames: a frame payload must fit in
// the 16-bit wire length field (protocol.MaxFrameDataLen). Scheme segment sizes
// are operator-controlled, so huge ranges are clamped instead of producing
// malformed frames.
func clampWasteSize(size int) int {
	if size < 0 {
		return 0
	}
	if size > protocol.MaxFrameDataLen {
		return protocol.MaxFrameDataLen
	}
	return size
}

// WriteRaw writes raw bytes directly without padding (used after padding stop).
// It bypasses epoch and budget bookkeeping.
func (pw *Writer) WriteRaw(data []byte) error {
	pw.mu.Lock()
	defer pw.mu.Unlock()
	_, err := pw.w.Write(data)
	return err
}

// PacketIndex returns the number of control-bucket writes processed by this
// writer.
//
// Before per-stream epochs this used to be the per-session TLS write counter.
// There is no single session-wide data-write counter anymore, so the value now
// tracks the control bucket only (settings, SYN/SYNACK/FIN, heartbeats,
// padding updates, keepalive waste). Kept for callers that only need a
// monotonic progress indicator.
func (pw *Writer) PacketIndex() int {
	pw.mu.Lock()
	defer pw.mu.Unlock()
	return pw.ctlIdx
}

// ControlBytes returns the total number of bytes (payload + padding) written
// for control-bucket writes. It is exposed for observability; control padding
// itself is not limited by any budget.
func (pw *Writer) ControlBytes() int64 {
	pw.mu.Lock()
	defer pw.mu.Unlock()
	return pw.ctlBytes
}

// serializeFrames converts frames to their wire format bytes.
func serializeFrames(frames []*protocol.Frame) []byte {
	size := 0
	for _, f := range frames {
		size += protocol.FrameHeaderLen + len(f.Data)
	}

	buf := make([]byte, 0, size)
	var header [protocol.FrameHeaderLen]byte
	for _, f := range frames {
		header[0] = byte(f.Command)
		header[1] = byte(f.StreamID >> 24)
		header[2] = byte(f.StreamID >> 16)
		header[3] = byte(f.StreamID >> 8)
		header[4] = byte(f.StreamID)
		header[5] = byte(len(f.Data) >> 8)
		header[6] = byte(len(f.Data))
		buf = append(buf, header[:]...)
		buf = append(buf, f.Data...)
	}

	return buf
}

// KeepaliveGenerator sends minimal waste packets during idle periods.
// Behaves like a TLS heartbeat: 30-60s intervals, 4-8 byte packets.
// Only active when all Streams in the Session are idle.
type KeepaliveGenerator struct {
	config   *KeepaliveConfig
	stopCh   chan struct{}
	once     sync.Once
	isActive atomic.Bool                   // tracks whether streams are active
	writeFn  func(f *protocol.Frame) error // session-safe write function
}

// NewKeepaliveGenerator creates a keepalive generator from the scheme's config.
// writeFn should route writes through the session's write path for thread safety.
func NewKeepaliveGenerator(config *KeepaliveConfig, writeFn func(f *protocol.Frame) error) *KeepaliveGenerator {
	return &KeepaliveGenerator{
		config:  config,
		stopCh:  make(chan struct{}),
		writeFn: writeFn,
	}
}

// Start begins generating keepalive packets in a background goroutine.
func (kg *KeepaliveGenerator) Start() {
	if kg.config == nil {
		return
	}
	go kg.run()
}

// Stop stops the keepalive generator.
func (kg *KeepaliveGenerator) Stop() {
	kg.once.Do(func() {
		close(kg.stopCh)
	})
}

// SetActive marks whether there are active streams.
// Keepalive packets are only sent when no streams are active.
func (kg *KeepaliveGenerator) SetActive(active bool) {
	kg.isActive.Store(active)
}

func (kg *KeepaliveGenerator) run() {
	for {
		intervalMs := RandomInRange(kg.config.IntervalMinMs, kg.config.IntervalMaxMs)

		select {
		case <-kg.stopCh:
			return
		case <-time.After(time.Duration(intervalMs) * time.Millisecond):
			// Only send keepalive when idle (no active streams)
			if kg.isActive.Load() {
				continue
			}
			size := RandomInRange(kg.config.SizeMin, kg.config.SizeMax)
			wasteFrame := protocol.NewWasteFrame(size)
			_ = kg.writeFn(wasteFrame)
		}
	}
}
