// Package padding implements the TSUNAMI programmable padding system.
//
// A Writer applies a Scheme to one direction of a session. The scheme controls
// two independent padding epochs:
//
//   - Data streams. Every stream starts its own write epoch: the stream's
//     first, second, ... data write consult rule 0, 1, ... of the scheme.
//     Rules stop applying for that stream after `stop` writes or once the
//     stream has emitted `stream_bytes` bytes. Because the epoch is per
//     stream, every proxied TLS connection - not just the first one on a
//     long-lived session - has its inner handshake masked.
//   - Control writes. Frames that do not belong to a single data stream
//     (settings, SYN/SYNACK/FIN, heartbeats, padding-scheme updates, keepalive
//     waste and mixed batches) use the single `ctl` rule for the whole session
//     lifetime. They keep happening after any per-stream epoch has ended, so
//     they must not be epoch-limited.
//
// Two size dimensions are supported per rule: split segments (`min-max`, with
// optional `c` checkpoints) and pad-to segments (`~min-max`) that emit the
// whole write as a single TLS record padded to a plausible size.
package padding

import (
	"crypto/md5"
	"fmt"
	"math/rand/v2"
	"strconv"
	"strings"
)

// Default values for scheme keys that are not present in the parsed text.
const (
	// DefaultStop is the default number of data writes per stream that may be
	// padded (the per-stream epoch length).
	DefaultStop = 6
	// DefaultStreamBytes is the default per-stream padded-byte budget. Padding
	// stops for a stream once the total bytes written for it reach the budget.
	DefaultStreamBytes = 12288
	// MaxPadTarget is the maximum pad-to target in bytes. It matches the TLS
	// record plaintext limit (2^14): the TLS layer already splits larger
	// writes into several records, so padding to a bigger record is pointless.
	MaxPadTarget = 16384
)

// defaultControlMin/Max define the implicit `ctl=~40-160` rule that applies
// when a scheme does not contain a ctl key.
const (
	defaultControlMin = 40
	defaultControlMax = 160
)

// Role identifies the direction in which a Writer sends data. It selects the
// directional c<idx> / s<idx> padding rule overrides.
type Role int

const (
	// RoleClient is the client side of a session: writes go client -> server.
	RoleClient Role = iota
	// RoleServer is the server side of a session: writes go server -> client.
	RoleServer
)

// Scheme represents a parsed PaddingScheme.
type Scheme struct {
	// Stop is the per-stream epoch length: a data stream consults rules for
	// its writes 0 .. Stop-1 only. Streams are counted individually, not the
	// session as a whole.
	Stop int
	// StreamBytes is the per-stream padded-byte budget. Once the total bytes
	// written for a stream reach this value, the stream is sent unmodified.
	// Values <= 0 disable the budget.
	StreamBytes int
	// Rules maps a data-write index to its segment list. It is the fallback
	// rule shared by both directions.
	Rules map[int][]Segment
	// ClientRules holds c<idx> overrides: client -> server data writes.
	ClientRules map[int][]Segment
	// ServerRules holds s<idx> overrides: server -> client data writes.
	ServerRules map[int][]Segment
	// ControlRules is applied to every streamless (control) write for the
	// whole session lifetime. nil disables control-write padding.
	ControlRules []Segment
	// Keepalive configuration for idle-period background waste.
	Keepalive *KeepaliveConfig
	// Raw stores the original text for MD5 computation.
	Raw string
}

// Segment represents a single segment in a packet's padding strategy.
type Segment struct {
	MinSize int  // minimum segment size in bytes
	MaxSize int  // maximum segment size in bytes
	IsCheck bool // 'c' — if user data is exhausted, stop here
	// IsPadTo marks a `~min-max` segment: emit the entire remaining payload as
	// ONE write and pad it to a random target in [MinSize, MaxSize] by
	// appending a cmdWaste frame inside the same write. The first pad-to
	// segment consumes the rest of the payload and ends the rule.
	IsPadTo bool
}

// KeepaliveConfig defines minimal idle-period keepalive parameters.
// Sends tiny cmdWaste packets at long intervals, similar to TLS heartbeat.
// Only active when all Streams in the Session are idle.
type KeepaliveConfig struct {
	IntervalMinMs int // minimum interval between keepalive packets (ms)
	IntervalMaxMs int // maximum interval between keepalive packets (ms)
	SizeMin       int // minimum keepalive packet size (bytes)
	SizeMax       int // maximum keepalive packet size (bytes)
}

// defaultControlRules returns the implicit `ctl=~40-160` rule. A fresh slice is
// returned for every parse so schemes never share mutable segment state.
func defaultControlRules() []Segment {
	return []Segment{{MinSize: defaultControlMin, MaxSize: defaultControlMax, IsPadTo: true}}
}

// DefaultScheme returns the default PaddingScheme.
//
// Rule indices are data-write indices inside ONE stream, not write indices of
// the session:
//   - client stream write order: SOCKS target address frame, inner TLS
//     ClientHello, then application data;
//   - server stream write order: inner TLS server flight (ServerHello ..
//     Certificate), then application data.
//
// The directional c<n>/s<n> rules express both flights in one scheme: c1 masks
// the client's ClientHello while s0 masks the server's flight, so neither
// direction leaks its real handshake sizes.
func DefaultScheme() *Scheme {
	raw := `stop=6
stream_bytes=12288
ctl=~40-160
c0=~80-200
c1=~900-1200
c2=~500-1200
s0=~2600-4200
s1=~700-1400
s2=~700-1400
3=~300-800
4=~300-800
5=~300-800
keepalive=45000-90000:4-8`
	scheme, _ := Parse(raw)
	return scheme
}

// Parse parses a PaddingScheme text definition.
//
// The parser is backward compatible with the original (session-epoch) scheme
// format: plain `<idx>=` rules, `min-max` split segments and `c` check
// segments keep working unchanged, and unknown keys are ignored. `stop` and
// the data rules now mean "per stream" on new clients.
func Parse(text string) (*Scheme, error) {
	s := &Scheme{
		Stop:         DefaultStop,
		StreamBytes:  DefaultStreamBytes,
		Rules:        make(map[int][]Segment),
		ClientRules:  make(map[int][]Segment),
		ServerRules:  make(map[int][]Segment),
		ControlRules: defaultControlRules(),
		Raw:          text,
	}

	lines := strings.Split(strings.TrimSpace(text), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key, val := parts[0], parts[1]

		switch {
		case key == "stop":
			n, err := strconv.Atoi(strings.TrimSpace(val))
			if err != nil {
				return nil, fmt.Errorf("padding: invalid stop value: %w", err)
			}
			s.Stop = n

		case key == "stream_bytes":
			n, err := strconv.Atoi(strings.TrimSpace(val))
			if err != nil {
				return nil, fmt.Errorf("padding: invalid stream_bytes value: %w", err)
			}
			s.StreamBytes = n

		case key == "keepalive":
			// keepalive=30000-60000:4-8
			kp := strings.SplitN(val, ":", 2)
			if len(kp) != 2 {
				continue
			}
			interval, err := parseRange(kp[0])
			if err != nil {
				continue
			}
			size, err := parseRange(kp[1])
			if err != nil {
				continue
			}
			s.Keepalive = &KeepaliveConfig{
				IntervalMinMs: interval[0],
				IntervalMaxMs: interval[1],
				SizeMin:       size[0],
				SizeMax:       size[1],
			}

		case key == "ctl":
			if strings.TrimSpace(val) == "" {
				// `ctl=` explicitly disables control-write padding; the
				// implicit default only applies when the key is absent.
				s.ControlRules = nil
				continue
			}
			segments, err := parseSegments(val)
			if err != nil {
				return nil, fmt.Errorf("padding: invalid ctl rule: %w", err)
			}
			s.ControlRules = segments

		case strings.HasPrefix(key, "c") && len(key) > 1:
			// Client -> server directional override: c<idx>=<segments>.
			idx, ok := parseRuleKey(key[1:])
			if !ok {
				continue // unknown key
			}
			segments, err := parseSegments(val)
			if err != nil {
				return nil, fmt.Errorf("padding: invalid client rule for packet %d: %w", idx, err)
			}
			s.ClientRules[idx] = segments

		case strings.HasPrefix(key, "s") && len(key) > 1:
			// Server -> client directional override: s<idx>=<segments>.
			idx, ok := parseRuleKey(key[1:])
			if !ok {
				continue // unknown key
			}
			segments, err := parseSegments(val)
			if err != nil {
				return nil, fmt.Errorf("padding: invalid server rule for packet %d: %w", idx, err)
			}
			s.ServerRules[idx] = segments

		default:
			// Packet index rule: 0=30-30 or 2=400-500,c,500-1000,...
			idx, err := strconv.Atoi(strings.TrimSpace(key))
			if err != nil {
				continue // skip unknown keys
			}
			segments, err := parseSegments(val)
			if err != nil {
				return nil, fmt.Errorf("padding: invalid rule for packet %d: %w", idx, err)
			}
			s.Rules[idx] = segments
		}
	}

	return s, nil
}

// parseRuleKey parses the numeric part of a directional rule key.
func parseRuleKey(s string) (int, bool) {
	idx, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil || idx < 0 {
		return 0, false
	}
	return idx, true
}

// parseSegments parses a comma-separated segment list like
// "400-500,c,500-1000" or "~900-1200".
func parseSegments(val string) ([]Segment, error) {
	parts := strings.Split(val, ",")
	segments := make([]Segment, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			return nil, fmt.Errorf("padding: empty segment")
		}
		if p == "c" {
			segments = append(segments, Segment{IsCheck: true})
			continue
		}
		if strings.HasPrefix(p, "~") {
			// Pad-to segment: ~min-max, or ~N for N..N.
			r, err := parsePadToRange(strings.TrimSpace(p[1:]))
			if err != nil {
				return nil, err
			}
			if r[0] < 0 || r[1] < 0 {
				return nil, fmt.Errorf("padding: negative pad-to range: %s", p)
			}
			segments = append(segments, Segment{MinSize: r[0], MaxSize: r[1], IsPadTo: true})
			continue
		}
		r, err := parseRange(p)
		if err != nil {
			return nil, err
		}
		segments = append(segments, Segment{MinSize: r[0], MaxSize: r[1]})
	}
	return segments, nil
}

// parsePadToRange parses the target of a pad-to segment: "min-max" or "N".
func parsePadToRange(s string) ([2]int, error) {
	if !strings.Contains(s, "-") {
		n, err := strconv.Atoi(strings.TrimSpace(s))
		if err != nil {
			return [2]int{}, fmt.Errorf("padding: invalid pad-to size: %s", s)
		}
		return [2]int{n, n}, nil
	}
	return parseRange(s)
}

// parseRange parses "min-max" into [min, max].
func parseRange(s string) ([2]int, error) {
	parts := strings.SplitN(s, "-", 2)
	if len(parts) != 2 {
		return [2]int{}, fmt.Errorf("padding: invalid range: %s", s)
	}
	min, err := strconv.Atoi(strings.TrimSpace(parts[0]))
	if err != nil {
		return [2]int{}, err
	}
	max, err := strconv.Atoi(strings.TrimSpace(parts[1]))
	if err != nil {
		return [2]int{}, err
	}
	return [2]int{min, max}, nil
}

// MD5 returns the lowercase hex MD5 digest of the scheme's raw text.
func (s *Scheme) MD5() string {
	h := md5.Sum([]byte(s.Raw))
	return fmt.Sprintf("%x", h)
}

// GetSegments returns the shared segment list for a per-stream packet index,
// or nil if the index is outside the scheme's stop epoch.
//
// It ignores role-specific overrides and the per-stream byte budget; Writer
// uses GetSegmentsFor instead. Kept for compatibility with existing callers.
func (s *Scheme) GetSegments(packetIdx int) []Segment {
	if packetIdx < 0 || packetIdx >= s.Stop {
		return nil
	}
	return s.Rules[packetIdx]
}

// GetSegmentsFor returns the segment list for the given direction and
// per-stream packet index.
//
// Lookup order: the direction's override map (c<idx> for RoleClient, s<idx> for
// RoleServer), then the shared rules, then nil. The per-stream stop epoch is
// applied first.
func (s *Scheme) GetSegmentsFor(role Role, packetIdx int) []Segment {
	if packetIdx < 0 || packetIdx >= s.Stop {
		return nil
	}
	if role == RoleServer {
		if segments, ok := s.ServerRules[packetIdx]; ok {
			return segments
		}
	} else {
		if segments, ok := s.ClientRules[packetIdx]; ok {
			return segments
		}
	}
	return s.Rules[packetIdx]
}

// RandomInRange returns a random integer in [min, max].
// Uses math/rand/v2 which is automatically seeded from a secure source in Go 1.22+.
func RandomInRange(min, max int) int {
	if min >= max {
		return min
	}
	return min + rand.IntN(max-min+1)
}

// Encode serializes the scheme back to text format.
func (s *Scheme) Encode() string {
	return s.Raw
}
