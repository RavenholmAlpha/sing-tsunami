// Package protocol defines the TSUNAMI proxy protocol wire format and commands.
package protocol

// Protocol version constants.
const (
	ProtocolVersion1 = 1
	ProtocolVersion2 = 2
	ProtocolVersion3 = 3 // TSUNAMI extended
	CurrentVersion   = ProtocolVersion3
)

// Command byte constants for the session frame header.
type Command uint8

const (
	// ═══════════ Protocol Version 1 ═══════════

	// CmdWaste is a padding frame. Receivers MUST read and silently discard its data.
	CmdWaste Command = 0x00
	// CmdSYN opens a new Stream. streamId MUST be monotonically increasing within a Session.
	CmdSYN Command = 0x01
	// CmdPSH carries stream payload data.
	CmdPSH Command = 0x02
	// CmdFIN closes a Stream. No reply FIN is needed.
	CmdFIN Command = 0x03
	// CmdSettings is sent client→server as the first frame of every new Session.
	CmdSettings Command = 0x04
	// CmdAlert is sent server→client with a warning message; both sides close the Session.
	CmdAlert Command = 0x05
	// CmdUpdatePaddingScheme is sent server→client to push a new PaddingScheme.
	CmdUpdatePaddingScheme Command = 0x06

	// ═══════════ Protocol Version 2 ═══════════

	// CmdSYNACK is sent server→client to confirm a Stream is open.
	CmdSYNACK Command = 0x07
	// CmdHeartRequest is a keep-alive ping.
	CmdHeartRequest Command = 0x08
	// CmdHeartResponse is a keep-alive pong.
	CmdHeartResponse Command = 0x09
	// CmdServerSettings is sent server→client with server capabilities.
	CmdServerSettings Command = 0x0A

	// ═══════════ Protocol Version 3 (TSUNAMI) ═══════════

	// CmdSurgeCtrl carries Surge congestion control signaling.
	CmdSurgeCtrl Command = 0x0B
	// CmdBandwidthReport carries periodic bandwidth statistics (bidirectional).
	CmdBandwidthReport Command = 0x0C
	// CmdStreamPriority sets the priority of a Stream.
	CmdStreamPriority Command = 0x0D
)

// String returns the human-readable name for a command.
func (c Command) String() string {
	switch c {
	case CmdWaste:
		return "WASTE"
	case CmdSYN:
		return "SYN"
	case CmdPSH:
		return "PSH"
	case CmdFIN:
		return "FIN"
	case CmdSettings:
		return "SETTINGS"
	case CmdAlert:
		return "ALERT"
	case CmdUpdatePaddingScheme:
		return "UPDATE_PADDING"
	case CmdSYNACK:
		return "SYNACK"
	case CmdHeartRequest:
		return "HEART_REQ"
	case CmdHeartResponse:
		return "HEART_RSP"
	case CmdServerSettings:
		return "SERVER_SETTINGS"
	case CmdSurgeCtrl:
		return "SURGE_CTRL"
	case CmdBandwidthReport:
		return "BW_REPORT"
	case CmdStreamPriority:
		return "STREAM_PRIORITY"
	default:
		return "UNKNOWN"
	}
}

// HasData returns true if this command type may carry data payload.
func (c Command) HasData() bool {
	switch c {
	case CmdWaste, CmdPSH, CmdSettings, CmdAlert,
		CmdUpdatePaddingScheme, CmdSYNACK, CmdServerSettings,
		CmdSurgeCtrl, CmdBandwidthReport, CmdStreamPriority:
		return true
	default:
		return false
	}
}

// Surge control action constants.
const (
	SurgeActionReportThroughput = 0x01
	SurgeActionRequestMoreConn  = 0x02
	SurgeActionReduceConn       = 0x03
	SurgeActionBandwidthLimit   = 0x04
)

// MaxFrameDataLen is the maximum data length in a single frame (65535 bytes).
const MaxFrameDataLen = 0xFFFF

// FrameHeaderLen is the fixed frame header size: cmd(1) + streamId(4) + dataLen(2) = 7.
const FrameHeaderLen = 7

// AuthHashLen is the length of SHA-256(password).
const AuthHashLen = 32

// UoTMagicAddress is the UoT v2 magic domain for UDP-over-TCP signaling.
const UoTMagicAddress = "sp.v2.udp-over-tcp.arpa"

// LegacyUoTMagicAddress is accepted by servers during the v3 migration.
// New clients always use UoTMagicAddress.
const LegacyUoTMagicAddress = "love.uot.world.anytls"

// SOCKS5 address types.
const (
	AtypIPv4   = 0x01
	AtypDomain = 0x03
	AtypIPv6   = 0x04
)

// Default stream priority.
const DefaultStreamPriority = 128
