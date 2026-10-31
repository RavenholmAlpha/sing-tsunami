package protocol

import (
	"bytes"
	"testing"
)

func TestFrameEncodeDecode(t *testing.T) {
	tests := []struct {
		name  string
		frame *Frame
	}{
		{
			name:  "empty data",
			frame: NewFrame(CmdSYN, 1, nil),
		},
		{
			name:  "small data",
			frame: NewFrame(CmdPSH, 42, []byte("hello tsunami")),
		},
		{
			name:  "waste frame",
			frame: NewWasteFrame(100),
		},
		{
			name:  "max stream id",
			frame: NewFrame(CmdFIN, 0xFFFFFFFF, nil),
		},
		{
			name:  "settings data",
			frame: NewFrame(CmdSettings, 0, []byte("v=3\nclient=http-client/1.0")),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer

			// Encode
			if err := EncodeFrame(&buf, tt.frame); err != nil {
				t.Fatalf("encode failed: %v", err)
			}

			// Check header size
			expectedLen := FrameHeaderLen + len(tt.frame.Data)
			if buf.Len() != expectedLen {
				t.Fatalf("encoded length = %d, want %d", buf.Len(), expectedLen)
			}

			// Decode
			decoded, err := DecodeFrame(&buf)
			if err != nil {
				t.Fatalf("decode failed: %v", err)
			}

			// Verify
			if decoded.Command != tt.frame.Command {
				t.Errorf("command = %v, want %v", decoded.Command, tt.frame.Command)
			}
			if decoded.StreamID != tt.frame.StreamID {
				t.Errorf("streamID = %d, want %d", decoded.StreamID, tt.frame.StreamID)
			}
			if !bytes.Equal(decoded.Data, tt.frame.Data) {
				t.Errorf("data mismatch: got %d bytes, want %d bytes", len(decoded.Data), len(tt.frame.Data))
			}
		})
	}
}

func TestFrameTooLarge(t *testing.T) {
	var buf bytes.Buffer
	bigData := make([]byte, MaxFrameDataLen+1)
	frame := NewFrame(CmdPSH, 1, bigData)
	err := EncodeFrame(&buf, frame)
	if err != ErrFrameTooLarge {
		t.Errorf("expected ErrFrameTooLarge, got %v", err)
	}
}

func TestFrameWriterMultipleFrames(t *testing.T) {
	var buf bytes.Buffer
	fw := NewFrameWriter(&buf)

	frames := []*Frame{
		NewFrame(CmdSYN, 1, nil),
		NewFrame(CmdPSH, 1, []byte("data")),
		NewFrame(CmdFIN, 1, nil),
	}

	if err := fw.WriteFrames(frames); err != nil {
		t.Fatalf("write frames failed: %v", err)
	}

	// Read back all 3 frames
	fr := NewFrameReader(&buf)
	for i, expected := range frames {
		decoded, err := fr.ReadFrame()
		if err != nil {
			t.Fatalf("read frame %d failed: %v", i, err)
		}
		if decoded.Command != expected.Command {
			t.Errorf("frame %d: command = %v, want %v", i, decoded.Command, expected.Command)
		}
		if decoded.StreamID != expected.StreamID {
			t.Errorf("frame %d: streamID = %d, want %d", i, decoded.StreamID, expected.StreamID)
		}
	}
}

func TestCommandString(t *testing.T) {
	if CmdSYN.String() != "SYN" {
		t.Errorf("CmdSYN.String() = %q, want %q", CmdSYN.String(), "SYN")
	}
	if CmdWaste.String() != "WASTE" {
		t.Errorf("CmdWaste.String() = %q, want %q", CmdWaste.String(), "WASTE")
	}
	if Command(0xFF).String() != "UNKNOWN" {
		t.Errorf("unknown command string = %q, want %q", Command(0xFF).String(), "UNKNOWN")
	}
}
