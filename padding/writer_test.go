package padding

import (
	"bytes"
	"fmt"
	"io"
	"sync"
	"testing"

	"github.com/RavenholmAlpha/sing-tsunami/protocol"
)

// recordingWriter records each underlying Write call separately so tests can
// assert how many outer records a padded write produced.
type recordingWriter struct {
	mu     sync.Mutex
	writes [][]byte
}

func (r *recordingWriter) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.writes = append(r.writes, append([]byte(nil), p...))
	return len(p), nil
}

func (r *recordingWriter) lengths() []int {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]int, len(r.writes))
	for i, w := range r.writes {
		out[i] = len(w)
	}
	return out
}

func (r *recordingWriter) writeAt(i int) []byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.writes[i]
}

func (r *recordingWriter) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.writes)
}

func mustParseScheme(t *testing.T, text string) *Scheme {
	t.Helper()
	scheme, err := Parse(text)
	if err != nil {
		t.Fatalf("parse scheme %q: %v", text, err)
	}
	return scheme
}

func pshFrame(streamID uint32, size int) *protocol.Frame {
	data := make([]byte, size)
	for i := range data {
		data[i] = byte(i)
	}
	return protocol.NewFrame(protocol.CmdPSH, streamID, data)
}

func controlFrame(cmd protocol.Command) *protocol.Frame {
	return protocol.NewFrame(cmd, 0, nil)
}

// decodeAll decodes the frames contained in one write.
func decodeAll(t *testing.T, raw []byte) []*protocol.Frame {
	t.Helper()
	var frames []*protocol.Frame
	reader := bytes.NewReader(raw)
	for reader.Len() > 0 {
		frame, err := protocol.DecodeFrame(reader)
		if err != nil {
			t.Fatalf("decode frame: %v", err)
		}
		frames = append(frames, frame)
	}
	return frames
}

func requireWriteLengths(t *testing.T, got, want []int) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("write lengths = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("write lengths = %v, want %v", got, want)
		}
	}
}

func TestWriterPerStreamEpochIsolation(t *testing.T) {
	// A tiny epoch: each stream gets exactly ONE padded write, then raw data.
	scheme := mustParseScheme(t, "stop=1\n0=~100-100")
	out := &recordingWriter{}
	pw := NewWriter(out, scheme)

	// Stream 1, first write: pads to 100 bytes.
	if err := pw.WriteFramesWithPadding([]*protocol.Frame{pshFrame(1, 10)}); err != nil {
		t.Fatalf("stream 1 write 1: %v", err)
	}
	// Stream 1, second write: epoch exhausted -> raw (7 header + 10 data).
	if err := pw.WriteFramesWithPadding([]*protocol.Frame{pshFrame(1, 10)}); err != nil {
		t.Fatalf("stream 1 write 2: %v", err)
	}
	// Stream 2, first write: its own epoch, padded to 100 again. This is the
	// core regression: later streams on the same session must be masked.
	if err := pw.WriteFramesWithPadding([]*protocol.Frame{pshFrame(2, 10)}); err != nil {
		t.Fatalf("stream 2 write 1: %v", err)
	}

	requireWriteLengths(t, out.lengths(), []int{100, 17, 100})

	// The padded writes carry the original PSH frame plus one waste frame.
	for _, idx := range []int{0, 2} {
		frames := decodeAll(t, out.writeAt(idx))
		if len(frames) != 2 {
			t.Fatalf("padded write %d frames = %d, want 2", idx, len(frames))
		}
		if frames[0].Command != protocol.CmdPSH || len(frames[0].Data) != 10 {
			t.Fatalf("padded write %d first frame = %s len=%d", idx, frames[0].Command, len(frames[0].Data))
		}
		if frames[1].Command != protocol.CmdWaste || len(frames[1].Data) != 76 {
			t.Fatalf("padded write %d waste frame = %s len=%d, want WASTE len=76",
				idx, frames[1].Command, len(frames[1].Data))
		}
	}
}

func TestWriterPadToOneRecordAtTarget(t *testing.T) {
	scheme := mustParseScheme(t, "stop=1\n0=~200-200")
	out := &recordingWriter{}
	pw := NewWriter(out, scheme)

	// PSH wire size = 7 + 11 = 18, so the waste frame carries 200-18-7 = 175.
	if err := pw.WriteFramesWithPadding([]*protocol.Frame{pshFrame(3, 11)}); err != nil {
		t.Fatalf("write: %v", err)
	}
	requireWriteLengths(t, out.lengths(), []int{200})

	frames := decodeAll(t, out.writeAt(0))
	if len(frames) != 2 {
		t.Fatalf("frames = %d, want 2 (PSH + WASTE)", len(frames))
	}
	if frames[1].Command != protocol.CmdWaste || len(frames[1].Data) != 175 {
		t.Fatalf("waste frame = %s len=%d, want WASTE len=175", frames[1].Command, len(frames[1].Data))
	}
}

func TestWriterPadToZeroWasteBoundary(t *testing.T) {
	// Requested target 67, payload wire size 60: the target is already large
	// enough for the waste header, so the waste frame has an empty payload but
	// is still emitted inside the same record (total 67).
	scheme := mustParseScheme(t, "stop=1\n0=~67-67")
	out := &recordingWriter{}
	pw := NewWriter(out, scheme)

	if err := pw.WriteFramesWithPadding([]*protocol.Frame{pshFrame(1, 53)}); err != nil {
		t.Fatalf("write: %v", err)
	}
	requireWriteLengths(t, out.lengths(), []int{67})
	frames := decodeAll(t, out.writeAt(0))
	if len(frames) != 2 || frames[0].Command != protocol.CmdPSH || len(frames[0].Data) != 53 {
		t.Fatalf("frames = %+v, want PSH(53) + WASTE(0)", frames)
	}
	if frames[1].Command != protocol.CmdWaste || len(frames[1].Data) != 0 {
		t.Fatalf("waste frame = %s len=%d, want WASTE(0)", frames[1].Command, len(frames[1].Data))
	}
}

func TestWriterPadToNeverSplitsLargePayload(t *testing.T) {
	scheme := mustParseScheme(t, "stop=1\n0=~50-50")
	out := &recordingWriter{}
	pw := NewWriter(out, scheme)

	// Payload wire size 207 exceeds the target: pad-to writes it unchanged as
	// one record instead of splitting it.
	if err := pw.WriteFramesWithPadding([]*protocol.Frame{pshFrame(1, 200)}); err != nil {
		t.Fatalf("write: %v", err)
	}
	requireWriteLengths(t, out.lengths(), []int{207})
	frames := decodeAll(t, out.writeAt(0))
	if len(frames) != 1 || frames[0].Command != protocol.CmdPSH || len(frames[0].Data) != 200 {
		t.Fatalf("frames = %+v, want single PSH(200)", frames)
	}

	// Payload bigger than the TLS record plaintext limit: still one write, no
	// waste frame (there is no room for one inside MaxPadTarget).
	out2 := &recordingWriter{}
	pw2 := NewWriter(out2, scheme)
	if err := pw2.WriteFramesWithPadding([]*protocol.Frame{pshFrame(1, MaxPadTarget)}); err != nil {
		t.Fatalf("write huge: %v", err)
	}
	requireWriteLengths(t, out2.lengths(), []int{MaxPadTarget + protocol.FrameHeaderLen})
	frames = decodeAll(t, out2.writeAt(0))
	if len(frames) != 1 {
		t.Fatalf("huge payload frames = %d, want 1", len(frames))
	}
}

func TestWriterPadToClampsTarget(t *testing.T) {
	// Requested targets are clamped to the TLS record plaintext limit.
	scheme := mustParseScheme(t, "stop=1\n0=~20000-20000")
	out := &recordingWriter{}
	pw := NewWriter(out, scheme)

	if err := pw.WriteFramesWithPadding([]*protocol.Frame{pshFrame(1, 10)}); err != nil {
		t.Fatalf("write: %v", err)
	}
	requireWriteLengths(t, out.lengths(), []int{MaxPadTarget})
	frames := decodeAll(t, out.writeAt(0))
	if len(frames) != 2 {
		t.Fatalf("frames = %d, want 2", len(frames))
	}
	if want := MaxPadTarget - 17 - protocol.FrameHeaderLen; len(frames[1].Data) != want {
		t.Fatalf("waste len = %d, want %d", len(frames[1].Data), want)
	}
}

func TestWriterPadToConsumesOnlyFirstPadToSegment(t *testing.T) {
	// ~ is only meaningful as the last segment: the first pad-to segment
	// consumes the rest of the payload and ends the rule.
	scheme := mustParseScheme(t, "stop=1\n0=~100-100,~20-20")
	out := &recordingWriter{}
	pw := NewWriter(out, scheme)

	if err := pw.WriteFramesWithPadding([]*protocol.Frame{pshFrame(1, 10)}); err != nil {
		t.Fatalf("write: %v", err)
	}
	requireWriteLengths(t, out.lengths(), []int{100})
}

func TestWriterStreamBudgetStop(t *testing.T) {
	// Budget of 100 bytes: after two 60-byte padded writes the stream is sent
	// raw even though the epoch (stop=10) is far from exhausted.
	scheme := mustParseScheme(t, `stop=10
stream_bytes=100
0=~60-60
1=~60-60
2=~60-60`)
	out := &recordingWriter{}
	pw := NewWriter(out, scheme)

	for i := 0; i < 4; i++ {
		if err := pw.WriteFramesWithPadding([]*protocol.Frame{pshFrame(1, 10)}); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
	}
	requireWriteLengths(t, out.lengths(), []int{60, 60, 17, 17})

	pw.mu.Lock()
	state := pw.streams[1]
	bytesWritten := state.bytes
	pw.mu.Unlock()
	if bytesWritten != 154 {
		t.Fatalf("stream bytes = %d, want 154", bytesWritten)
	}
}

func TestWriterZeroStreamBytesIsUnlimited(t *testing.T) {
	// stream_bytes <= 0 disables the byte budget; only stop limits padding.
	scheme := mustParseScheme(t, "stop=2\nstream_bytes=0\n0=~50-50\n1=~50-50\n2=~50-50")
	out := &recordingWriter{}
	pw := NewWriter(out, scheme)

	for i := 0; i < 3; i++ {
		if err := pw.WriteFramesWithPadding([]*protocol.Frame{pshFrame(1, 10)}); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
	}
	requireWriteLengths(t, out.lengths(), []int{50, 50, 17})
}

func TestWriterDirectionalRulePrecedence(t *testing.T) {
	scheme := mustParseScheme(t, `stop=1
0=~50-50
c0=~100-100
s0=~200-200`)

	clientOut := &recordingWriter{}
	clientWriter := NewWriterForRole(clientOut, scheme, RoleClient)
	if err := clientWriter.WriteFramesWithPadding([]*protocol.Frame{pshFrame(1, 10)}); err != nil {
		t.Fatalf("client write: %v", err)
	}
	requireWriteLengths(t, clientOut.lengths(), []int{100})

	serverOut := &recordingWriter{}
	serverWriter := NewWriterForRole(serverOut, scheme, RoleServer)
	if err := serverWriter.WriteFramesWithPadding([]*protocol.Frame{pshFrame(1, 10)}); err != nil {
		t.Fatalf("server write: %v", err)
	}
	requireWriteLengths(t, serverOut.lengths(), []int{200})

	// NewWriter keeps the historical client-role default.
	legacyOut := &recordingWriter{}
	legacyWriter := NewWriter(legacyOut, scheme)
	if err := legacyWriter.WriteFramesWithPadding([]*protocol.Frame{pshFrame(1, 10)}); err != nil {
		t.Fatalf("legacy write: %v", err)
	}
	requireWriteLengths(t, legacyOut.lengths(), []int{100})

	// Without an override both directions fall back to the shared rule.
	sharedScheme := mustParseScheme(t, "stop=1\n0=~75-75")
	for _, role := range []Role{RoleClient, RoleServer} {
		out := &recordingWriter{}
		pw := NewWriterForRole(out, sharedScheme, role)
		if err := pw.WriteFramesWithPadding([]*protocol.Frame{pshFrame(1, 10)}); err != nil {
			t.Fatalf("role %d write: %v", role, err)
		}
		requireWriteLengths(t, out.lengths(), []int{75})
	}
}

func TestWriterControlBucket(t *testing.T) {
	scheme := mustParseScheme(t, "stop=1\nctl=~100-100\n0=~50-50")
	out := &recordingWriter{}
	pw := NewWriter(out, scheme)

	controlWrites := []*protocol.Frame{
		protocol.NewFrame(protocol.CmdSettings, 0, make([]byte, 20)),
		protocol.NewFrame(protocol.CmdSYN, 1, nil),
		protocol.NewFrame(protocol.CmdSYNACK, 1, nil),
		protocol.NewFrame(protocol.CmdFIN, 1, nil),
		protocol.NewFrame(protocol.CmdHeartRequest, 0, nil),
		protocol.NewFrame(protocol.CmdUpdatePaddingScheme, 0, []byte("stop=1")),
		protocol.NewFrame(protocol.CmdWaste, 0, make([]byte, 4)),
		// A CmdPSH with StreamID 0 is still a control write.
		protocol.NewFrame(protocol.CmdPSH, 0, make([]byte, 8)),
	}
	for i, frame := range controlWrites {
		if err := pw.WriteFramesWithPadding([]*protocol.Frame{frame}); err != nil {
			t.Fatalf("control write %d: %v", i, err)
		}
	}

	// Mixed-stream batches are control writes too.
	if err := pw.WriteFramesWithPadding([]*protocol.Frame{
		pshFrame(1, 5),
		pshFrame(2, 5),
	}); err != nil {
		t.Fatalf("mixed batch: %v", err)
	}
	// Different command on an otherwise single stream is a control write.
	if err := pw.WriteFramesWithPadding([]*protocol.Frame{
		pshFrame(1, 5),
		protocol.NewFrame(protocol.CmdFIN, 1, nil),
	}); err != nil {
		t.Fatalf("mixed command batch: %v", err)
	}

	for i, length := range out.lengths() {
		if length != 100 {
			t.Fatalf("control write %d length = %d, want 100", i, length)
		}
	}
	if got := pw.PacketIndex(); got != len(controlWrites)+2 {
		t.Fatalf("PacketIndex = %d, want %d", got, len(controlWrites)+2)
	}
	if got := pw.ControlBytes(); got != int64(100*(len(controlWrites)+2)) {
		t.Fatalf("ControlBytes = %d, want %d", got, 100*(len(controlWrites)+2))
	}

	// A pure single-stream CmdPSH write still uses the stream epoch.
	if err := pw.WriteFramesWithPadding([]*protocol.Frame{pshFrame(3, 10)}); err != nil {
		t.Fatalf("stream write: %v", err)
	}
	lengths := out.lengths()
	if last := lengths[len(lengths)-1]; last != 50 {
		t.Fatalf("stream write length = %d, want 50", last)
	}
}

func TestWriterControlUnaffectedByStopAndBudget(t *testing.T) {
	// stop=1 and a tiny budget only limit data streams. Control writes keep
	// the ctl rule for the whole session lifetime: the 100th control write must
	// still be padded, otherwise FIN/heartbeat records degrade to 7 bytes.
	scheme := mustParseScheme(t, "stop=1\nstream_bytes=1\nctl=~120-120")
	out := &recordingWriter{}
	pw := NewWriter(out, scheme)

	// Consume the data-stream epoch and budget first.
	if err := pw.WriteFramesWithPadding([]*protocol.Frame{pshFrame(1, 30)}); err != nil {
		t.Fatalf("stream write: %v", err)
	}

	const controls = 100
	for i := 0; i < controls; i++ {
		if err := pw.WriteFramesWithPadding([]*protocol.Frame{controlFrame(protocol.CmdFIN)}); err != nil {
			t.Fatalf("control write %d: %v", i, err)
		}
	}

	lengths := out.lengths()
	// First write is the raw stream write (7+30), then 100 padded controls.
	requireWriteLengths(t, lengths[:1], []int{37})
	if len(lengths) != controls+1 {
		t.Fatalf("writes = %d, want %d", len(lengths), controls+1)
	}
	for i := 1; i < len(lengths); i++ {
		if lengths[i] != 120 {
			t.Fatalf("control write %d length = %d, want 120", i, lengths[i])
		}
	}
	if got := pw.PacketIndex(); got != controls {
		t.Fatalf("PacketIndex = %d, want %d", got, controls)
	}
}

func TestWriterLegacySplitScheme(t *testing.T) {
	scheme := mustParseScheme(t, "stop=2\n0=30-30\n1=100-400")
	out := &recordingWriter{}
	pw := NewWriter(out, scheme)

	// Write 0: payload (17) is shorter than the 30-byte segment, so remaining
	// data plus a waste frame fill exactly 30 bytes.
	if err := pw.WriteFramesWithPadding([]*protocol.Frame{pshFrame(1, 10)}); err != nil {
		t.Fatalf("write 0: %v", err)
	}
	requireWriteLengths(t, out.lengths(), []int{30})
	frames := decodeAll(t, out.writeAt(0))
	if len(frames) != 2 || frames[1].Command != protocol.CmdWaste || len(frames[1].Data) != 30-17-protocol.FrameHeaderLen {
		t.Fatalf("legacy padded write = %+v", frames)
	}

	// Write 1: a 507-byte payload is split by the legacy segment splitter into
	// a first chunk of 100..400 bytes plus the remainder: exactly two writes.
	out2 := &recordingWriter{}
	pw2 := NewWriter(out2, scheme)
	if err := pw2.WriteFramesWithPadding([]*protocol.Frame{pshFrame(1, 10)}); err != nil {
		t.Fatalf("write 0: %v", err)
	}
	if err := pw2.WriteFramesWithPadding([]*protocol.Frame{pshFrame(1, 500)}); err != nil {
		t.Fatalf("large write: %v", err)
	}
	lengths := out2.lengths()
	if len(lengths) != 3 {
		t.Fatalf("write lengths = %v, want 3 writes", lengths)
	}
	if lengths[0] != 30 {
		t.Fatalf("first write length = %d, want 30", lengths[0])
	}
	if total := lengths[1] + lengths[2]; total != 507 {
		t.Fatalf("split total = %d, want 507", total)
	}
	if lengths[1] < 100 || lengths[1] > 400 {
		t.Fatalf("first split chunk = %d, want 100..400", lengths[1])
	}

	// Rule indices restart for a new stream (per-stream epoch, not per-session).
	out3 := &recordingWriter{}
	pw3 := NewWriter(out3, scheme)
	for i := 0; i < 2; i++ {
		_ = pw3.WriteFramesWithPadding([]*protocol.Frame{pshFrame(1, 10)})
	}
	if err := pw3.WriteFramesWithPadding([]*protocol.Frame{pshFrame(2, 10)}); err != nil {
		t.Fatalf("new stream write: %v", err)
	}
	lengths = out3.lengths()
	if lengths[len(lengths)-1] != 30 {
		t.Fatalf("new stream first write length = %d, want 30", lengths[len(lengths)-1])
	}
}

func TestWriterSplitSegmentWasteSizeClamped(t *testing.T) {
	// Split segments are operator-controlled: a target larger than the 16-bit
	// frame payload limit must clamp generated cmdWaste frames instead of
	// producing a malformed frame.
	scheme := mustParseScheme(t, "stop=1\n0=100000-100000")
	out := &recordingWriter{}
	pw := NewWriter(out, scheme)

	if err := pw.WriteFramesWithPadding([]*protocol.Frame{pshFrame(1, 10)}); err != nil {
		t.Fatalf("write: %v", err)
	}
	frames := decodeAll(t, out.writeAt(0))
	if len(frames) != 2 {
		t.Fatalf("frames = %d, want 2 (payload + clamped waste)", len(frames))
	}
	if frames[1].Command != protocol.CmdWaste || len(frames[1].Data) != protocol.MaxFrameDataLen {
		t.Fatalf("waste frame = %s len=%d, want WASTE len=%d",
			frames[1].Command, len(frames[1].Data), protocol.MaxFrameDataLen)
	}

	// The pure-waste branch (payload exhausted before the big segment) clamps too.
	scheme = mustParseScheme(t, "stop=1\n0=30-30,100000-100000")
	out = &recordingWriter{}
	pw = NewWriter(out, scheme)
	if err := pw.WriteFramesWithPadding([]*protocol.Frame{pshFrame(1, 10)}); err != nil {
		t.Fatalf("write: %v", err)
	}
	lengths := out.lengths()
	if len(lengths) != 2 {
		t.Fatalf("write lengths = %v, want 2 writes", lengths)
	}
	if want := protocol.FrameHeaderLen + protocol.MaxFrameDataLen; lengths[1] != want {
		t.Fatalf("pure waste write = %d, want %d", lengths[1], want)
	}
}

func TestWriterDefaultSchemeMasksEveryStreamAndDirection(t *testing.T) {
	scheme := DefaultScheme()
	assertInRange := func(label string, got, min, max int) {
		t.Helper()
		if got < min || got > max {
			t.Fatalf("%s record = %d, want %d..%d", label, got, min, max)
		}
	}

	// Client direction: SOCKS addr write -> ClientHello -> app data, fresh
	// epoch for the second stream.
	clientOut := &recordingWriter{}
	clientWriter := NewWriterForRole(clientOut, scheme, RoleClient)
	for i := 0; i < 3; i++ {
		if err := clientWriter.WriteFramesWithPadding([]*protocol.Frame{pshFrame(11, 10)}); err != nil {
			t.Fatalf("client stream 11 write %d: %v", i, err)
		}
	}
	if err := clientWriter.WriteFramesWithPadding([]*protocol.Frame{pshFrame(12, 10)}); err != nil {
		t.Fatalf("client stream 12 write: %v", err)
	}
	if err := clientWriter.WriteFramesWithPadding([]*protocol.Frame{controlFrame(protocol.CmdFIN)}); err != nil {
		t.Fatalf("client control write: %v", err)
	}
	clientLengths := clientOut.lengths()
	if len(clientLengths) != 5 {
		t.Fatalf("client writes = %v, want 5", clientLengths)
	}
	assertInRange("client rule c0", clientLengths[0], 80, 200)
	assertInRange("client rule c1", clientLengths[1], 900, 1200)
	assertInRange("client rule c2", clientLengths[2], 500, 1200)
	assertInRange("client rule c0 (new stream)", clientLengths[3], 80, 200)
	assertInRange("client ctl", clientLengths[4], 40, 160)

	// Server direction: server handshake flight -> app data.
	serverOut := &recordingWriter{}
	serverWriter := NewWriterForRole(serverOut, scheme, RoleServer)
	for i := 0; i < 3; i++ {
		if err := serverWriter.WriteFramesWithPadding([]*protocol.Frame{pshFrame(21, 10)}); err != nil {
			t.Fatalf("server stream 21 write %d: %v", i, err)
		}
	}
	serverLengths := serverOut.lengths()
	if len(serverLengths) != 3 {
		t.Fatalf("server writes = %v, want 3", serverLengths)
	}
	assertInRange("server rule s0", serverLengths[0], 2600, 4200)
	assertInRange("server rule s1", serverLengths[1], 700, 1400)
	assertInRange("server rule s2", serverLengths[2], 700, 1400)
}

func TestWriterControlSplitRule(t *testing.T) {
	// ctl accepts legacy split segments as well as pad-to segments.
	scheme := mustParseScheme(t, "stop=1\nctl=60-60")
	out := &recordingWriter{}
	pw := NewWriter(out, scheme)

	if err := pw.WriteFramesWithPadding([]*protocol.Frame{controlFrame(protocol.CmdHeartRequest)}); err != nil {
		t.Fatalf("control write: %v", err)
	}
	requireWriteLengths(t, out.lengths(), []int{60})
}

func TestWriterForgetStream(t *testing.T) {
	scheme := mustParseScheme(t, "stop=1\n0=~60-60")
	out := &recordingWriter{}
	pw := NewWriter(out, scheme)

	if err := pw.WriteFramesWithPadding([]*protocol.Frame{pshFrame(7, 10)}); err != nil {
		t.Fatalf("write 1: %v", err)
	}
	if err := pw.WriteFramesWithPadding([]*protocol.Frame{pshFrame(7, 10)}); err != nil {
		t.Fatalf("write 2: %v", err)
	}
	requireWriteLengths(t, out.lengths(), []int{60, 17})

	// After the stream closes, a stream reusing the ID gets a fresh epoch.
	pw.ForgetStream(7)
	if err := pw.WriteFramesWithPadding([]*protocol.Frame{pshFrame(7, 10)}); err != nil {
		t.Fatalf("write 3: %v", err)
	}
	requireWriteLengths(t, out.lengths(), []int{60, 17, 60})

	// Unknown IDs are harmless.
	pw.ForgetStream(12345)
}

func TestWriterPrunesOldestStream(t *testing.T) {
	scheme := mustParseScheme(t, "stop=1\n0=~40-40")
	pw := NewWriter(io.Discard, scheme)

	total := maxTrackedStreams + 1
	for id := uint32(1); id <= uint32(total); id++ {
		if err := pw.WriteFramesWithPadding([]*protocol.Frame{pshFrame(id, 3)}); err != nil {
			t.Fatalf("write stream %d: %v", id, err)
		}
	}

	pw.mu.Lock()
	tracked := len(pw.streams)
	_, oldestPresent := pw.streams[1]
	_, newestPresent := pw.streams[uint32(total)]
	pw.mu.Unlock()

	if tracked != maxTrackedStreams {
		t.Fatalf("tracked streams = %d, want %d", tracked, maxTrackedStreams)
	}
	if oldestPresent {
		t.Fatal("oldest stream should have been pruned")
	}
	if !newestPresent {
		t.Fatal("newest stream should still be tracked")
	}
}

func TestWriterUnpaddedFastPath(t *testing.T) {
	scheme := mustParseScheme(t, "stop=0\nctl=")
	pw := NewWriter(io.Discard, scheme)

	frames := []*protocol.Frame{pshFrame(1, 10)}
	if err := pw.WriteFramesWithPadding(frames); err != nil {
		t.Fatalf("write: %v", err)
	}

	allocs := testing.AllocsPerRun(100, func() {
		if err := pw.WriteFramesWithPadding(frames); err != nil {
			t.Fatalf("write: %v", err)
		}
	})
	if allocs != 0 {
		t.Fatalf("unpadded fast path allocations = %v per write, want 0", allocs)
	}

	// Control writes are unpadded too when ctl= is explicitly disabled.
	pw.mu.Lock()
	before := len(pw.streams)
	pw.mu.Unlock()
	if before != 1 {
		t.Fatalf("tracked streams = %d, want 1", before)
	}
}

func TestWriterUnpaddedLargeWriteFallsBack(t *testing.T) {
	// Writes larger than the retained buffer limit use the shared encoder but
	// must still produce exactly one record with intact frame boundaries.
	scheme := mustParseScheme(t, "stop=0\nctl=")
	out := &recordingWriter{}
	pw := NewWriter(out, scheme)

	const frameCount = 6
	const frameSize = 60000
	frames := make([]*protocol.Frame, 0, frameCount)
	for i := 0; i < frameCount; i++ {
		frames = append(frames, pshFrame(1, frameSize))
	}
	if err := pw.WriteFramesWithPadding(frames); err != nil {
		t.Fatalf("write: %v", err)
	}
	wantLen := wireLen(frames)
	if wantLen <= maxReusableRawBuf {
		t.Fatalf("test payload = %d, need > %d to hit the fallback", wantLen, maxReusableRawBuf)
	}
	requireWriteLengths(t, out.lengths(), []int{wantLen})
	decoded := decodeAll(t, out.writeAt(0))
	if len(decoded) != frameCount {
		t.Fatalf("decoded frames = %d, want %d", len(decoded), frameCount)
	}
	for i, frame := range decoded {
		if len(frame.Data) != frameSize {
			t.Fatalf("decoded frame %d size = %d, want %d", i, len(frame.Data), frameSize)
		}
	}
}

func TestWriterEmptyAndInvalidWrites(t *testing.T) {
	scheme := mustParseScheme(t, "stop=1\n0=~60-60")
	out := &recordingWriter{}
	pw := NewWriter(out, scheme)

	if err := pw.WriteFramesWithPadding(nil); err != nil {
		t.Fatalf("empty write: %v", err)
	}
	if out.count() != 0 {
		t.Fatalf("empty write produced %d writes", out.count())
	}

	if err := pw.WriteFramesWithPadding([]*protocol.Frame{nil}); err != protocol.ErrInvalidFrame {
		t.Fatalf("nil frame error = %v, want ErrInvalidFrame", err)
	}
	tooLarge := protocol.NewFrame(protocol.CmdPSH, 1, make([]byte, protocol.MaxFrameDataLen+1))
	if err := pw.WriteFramesWithPadding([]*protocol.Frame{tooLarge}); err != protocol.ErrFrameTooLarge {
		t.Fatalf("oversized frame error = %v, want ErrFrameTooLarge", err)
	}
	if out.count() != 0 {
		t.Fatalf("invalid writes produced %d writes", out.count())
	}
}

func TestWriterUpdateScheme(t *testing.T) {
	out := &recordingWriter{}
	pw := NewWriter(out, mustParseScheme(t, "stop=1\n0=~60-60"))
	if err := pw.WriteFramesWithPadding([]*protocol.Frame{pshFrame(1, 10)}); err != nil {
		t.Fatalf("write 1: %v", err)
	}

	pw.UpdateScheme(mustParseScheme(t, "stop=1\n0=~80-80"))
	if err := pw.WriteFramesWithPadding([]*protocol.Frame{pshFrame(2, 10)}); err != nil {
		t.Fatalf("write 2: %v", err)
	}
	requireWriteLengths(t, out.lengths(), []int{60, 80})
}

func TestWriterPacketIndexOnlyCountsControl(t *testing.T) {
	scheme := mustParseScheme(t, "stop=2\nctl=~50-50\n0=~50-50\n1=~50-50")
	out := &recordingWriter{}
	pw := NewWriter(out, scheme)

	for i := 0; i < 2; i++ {
		if err := pw.WriteFramesWithPadding([]*protocol.Frame{pshFrame(1, 10)}); err != nil {
			t.Fatalf("data write %d: %v", i, err)
		}
	}
	if got := pw.PacketIndex(); got != 0 {
		t.Fatalf("PacketIndex after data writes = %d, want 0", got)
	}
	if err := pw.WriteFramesWithPadding([]*protocol.Frame{controlFrame(protocol.CmdHeartRequest)}); err != nil {
		t.Fatalf("control write: %v", err)
	}
	if got := pw.PacketIndex(); got != 1 {
		t.Fatalf("PacketIndex after control write = %d, want 1", got)
	}
}

func TestWriterConcurrentAccess(t *testing.T) {
	scheme := mustParseScheme(t, "stop=4\nstream_bytes=4096\nctl=~60-60\n0=~60-60\n1=~80-80\n2=~100-100\n3=~120-120")
	pw := NewWriter(io.Discard, scheme)

	const goroutines = 8
	const iterations = 50
	errCh := make(chan error, goroutines)
	var wg sync.WaitGroup
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			streamID := uint32(g + 1)
			for i := 0; i < iterations; i++ {
				if err := pw.WriteFramesWithPadding([]*protocol.Frame{pshFrame(streamID, 10)}); err != nil {
					errCh <- fmt.Errorf("data write: %w", err)
					return
				}
				if err := pw.WriteFramesWithPadding([]*protocol.Frame{controlFrame(protocol.CmdHeartRequest)}); err != nil {
					errCh <- fmt.Errorf("control write: %w", err)
					return
				}
				if i%10 == 0 {
					pw.ForgetStream(streamID)
				}
			}
		}(g)
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Fatal(err)
	}
	if got := pw.PacketIndex(); got != goroutines*iterations {
		t.Fatalf("PacketIndex = %d, want %d", got, goroutines*iterations)
	}
}

func TestWriterNilSchemeWritesRaw(t *testing.T) {
	out := &recordingWriter{}
	pw := NewWriter(out, nil)
	frames := []*protocol.Frame{pshFrame(1, 10)}
	if err := pw.WriteFramesWithPadding(frames); err != nil {
		t.Fatalf("write: %v", err)
	}
	requireWriteLengths(t, out.lengths(), []int{17})
}

func TestWriterWriteRaw(t *testing.T) {
	scheme := mustParseScheme(t, "stop=1\n0=~60-60")
	out := &recordingWriter{}
	pw := NewWriter(out, scheme)

	if err := pw.WriteRaw([]byte{1, 2, 3}); err != nil {
		t.Fatalf("write raw: %v", err)
	}
	requireWriteLengths(t, out.lengths(), []int{3})
	// WriteRaw bypasses epoch bookkeeping.
	pw.mu.Lock()
	tracked := len(pw.streams)
	pw.mu.Unlock()
	if tracked != 0 {
		t.Fatalf("WriteRaw created %d stream states, want 0", tracked)
	}
}
