package protocol

import (
	"fmt"
	"strconv"
	"strings"
)

// ClientSettings represents the settings sent by the client in cmdSettings.
type ClientSettings struct {
	Version        int
	Client         string
	PaddingMD5     string
	SurgeBandwidth int // Mbps, 0 = disabled
	Shaping        bool
	// PaddingV2 reports that the client can parse the v2 padding scheme syntax
	// (`~min-max` pad-to segments, `ctl`, `stream_bytes`, directional rules).
	// The server must not push v2 scheme text to clients that do not advertise
	// it: pre-v2 clients reject the pushed text and close the session.
	PaddingV2 bool
}

// EncodeClientSettings serializes client settings to the wire format.
func EncodeClientSettings(s *ClientSettings) []byte {
	var b strings.Builder
	fmt.Fprintf(&b, "v=%d\n", s.Version)
	fmt.Fprintf(&b, "client=%s\n", s.Client)
	if s.PaddingMD5 != "" {
		fmt.Fprintf(&b, "padding-md5=%s\n", s.PaddingMD5)
	}
	if s.SurgeBandwidth > 0 {
		fmt.Fprintf(&b, "surge-bandwidth=%d\n", s.SurgeBandwidth)
	}
	if s.Shaping {
		fmt.Fprintf(&b, "shaping=1\n")
	}
	if s.PaddingV2 {
		fmt.Fprintf(&b, "padding-v2=1\n")
	}
	return []byte(b.String())
}

// DecodeClientSettings parses client settings from wire format.
func DecodeClientSettings(data []byte) (*ClientSettings, error) {
	s := &ClientSettings{Version: 1}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	for _, line := range lines {
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key, val := parts[0], parts[1]
		switch key {
		case "v":
			v, err := strconv.Atoi(val)
			if err != nil {
				return nil, fmt.Errorf("tsunami: invalid version: %w", err)
			}
			s.Version = v
		case "client":
			s.Client = val
		case "padding-md5":
			s.PaddingMD5 = val
		case "surge-bandwidth":
			bw, err := strconv.Atoi(val)
			if err != nil {
				return nil, fmt.Errorf("tsunami: invalid surge-bandwidth: %w", err)
			}
			s.SurgeBandwidth = bw
		case "shaping":
			s.Shaping = val == "1"
		case "padding-v2":
			s.PaddingV2 = val == "1"
		}
	}
	return s, nil
}

// SurgeMode defines the server's allowed Surge congestion control mode.
type SurgeMode string

const (
	SurgeModeNone SurgeMode = "none"
	SurgeModeAuto SurgeMode = "auto"
)

// ServerSettings represents the settings sent by the server in cmdServerSettings.
type ServerSettings struct {
	Version        int
	SurgeMode      SurgeMode
	MaxConnections int
	Threshold      int // concurrent stream threshold for Layer 2 upgrade
	Shaping        bool
}

// EncodeServerSettings serializes server settings to the wire format.
func EncodeServerSettings(s *ServerSettings) []byte {
	var b strings.Builder
	fmt.Fprintf(&b, "v=%d\n", s.Version)
	if s.SurgeMode != "" {
		fmt.Fprintf(&b, "surge-mode=%s\n", string(s.SurgeMode))
	}
	if s.MaxConnections > 0 {
		fmt.Fprintf(&b, "max-connections=%d\n", s.MaxConnections)
	}
	if s.Threshold > 0 {
		fmt.Fprintf(&b, "threshold=%d\n", s.Threshold)
	}
	if s.Shaping {
		fmt.Fprintf(&b, "shaping=1\n")
	}
	return []byte(b.String())
}

// DecodeServerSettings parses server settings from wire format.
func DecodeServerSettings(data []byte) (*ServerSettings, error) {
	s := &ServerSettings{Version: 1, SurgeMode: SurgeModeAuto}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	for _, line := range lines {
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key, val := parts[0], parts[1]
		switch key {
		case "v":
			v, err := strconv.Atoi(val)
			if err != nil {
				return nil, fmt.Errorf("tsunami: invalid version: %w", err)
			}
			s.Version = v
		case "surge-mode":
			s.SurgeMode = SurgeMode(val)
		case "max-connections":
			mc, err := strconv.Atoi(val)
			if err != nil {
				return nil, fmt.Errorf("tsunami: invalid max-connections: %w", err)
			}
			s.MaxConnections = mc
		case "threshold":
			th, err := strconv.Atoi(val)
			if err != nil {
				return nil, fmt.Errorf("tsunami: invalid threshold: %w", err)
			}
			s.Threshold = th
		case "shaping":
			s.Shaping = val == "1"
		}
	}
	return s, nil
}
