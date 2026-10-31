package protocol

import (
	"bytes"
	"testing"
)

func TestClientSettingsEncodeDecode(t *testing.T) {
	original := &ClientSettings{
		Version:        3,
		Client:         "http-client/1.0",
		PaddingMD5:     "abcdef0123456789",
		SurgeBandwidth: 100,
		PaddingV2:      true,
	}

	data := EncodeClientSettings(original)
	decoded, err := DecodeClientSettings(data)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}

	if decoded.Version != original.Version {
		t.Errorf("version = %d, want %d", decoded.Version, original.Version)
	}
	if decoded.Client != original.Client {
		t.Errorf("client = %q, want %q", decoded.Client, original.Client)
	}
	if decoded.PaddingMD5 != original.PaddingMD5 {
		t.Errorf("paddingMD5 = %q, want %q", decoded.PaddingMD5, original.PaddingMD5)
	}
	if decoded.SurgeBandwidth != original.SurgeBandwidth {
		t.Errorf("surgeBandwidth = %d, want %d", decoded.SurgeBandwidth, original.SurgeBandwidth)
	}
	if !decoded.PaddingV2 {
		t.Error("padding-v2 capability was not round-tripped")
	}
}

// TestClientSettingsLegacyDecode ensures a pre-v2 client (no padding-v2 key)
// decodes as not supporting the v2 scheme syntax. The server relies on this to
// avoid pushing `~min-max` rules to old clients.
func TestClientSettingsLegacyDecode(t *testing.T) {
	data := []byte("v=3\nclient=http-client/1.0\npadding-md5=abcdef\nshaping=1\n")
	decoded, err := DecodeClientSettings(data)
	if err != nil {
		t.Fatalf("decode legacy settings: %v", err)
	}
	if decoded.PaddingV2 {
		t.Fatal("legacy settings must not advertise padding-v2")
	}
	// Encoding a client without the capability must omit the key so old
	// servers keep ignoring the settings blob.
	if bytes.Contains(EncodeClientSettings(decoded), []byte("padding-v2")) {
		t.Fatal("padding-v2 key must be omitted when the capability is not set")
	}
}

func TestServerSettingsEncodeDecode(t *testing.T) {
	original := &ServerSettings{
		Version:        3,
		SurgeMode:      SurgeModeAuto,
		MaxConnections: 4,
	}

	data := EncodeServerSettings(original)
	decoded, err := DecodeServerSettings(data)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}

	if decoded.Version != original.Version {
		t.Errorf("version = %d, want %d", decoded.Version, original.Version)
	}
	if decoded.SurgeMode != original.SurgeMode {
		t.Errorf("surgeMode = %q, want %q", decoded.SurgeMode, original.SurgeMode)
	}
	if decoded.MaxConnections != original.MaxConnections {
		t.Errorf("maxConnections = %d, want %d", decoded.MaxConnections, original.MaxConnections)
	}
}

func TestClientSettingsMinimal(t *testing.T) {
	s := &ClientSettings{Version: 1}
	data := EncodeClientSettings(s)
	decoded, err := DecodeClientSettings(data)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if decoded.Version != 1 {
		t.Errorf("version = %d, want 1", decoded.Version)
	}
}
