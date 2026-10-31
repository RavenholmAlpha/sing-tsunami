package protocol

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"strings"
	"time"
)

// PasswordHash computes SHA-256(password) used for authentication.
func PasswordHash(password string) [AuthHashLen]byte {
	return sha256.Sum256([]byte(password))
}

// AuthRequest represents the client authentication payload.
//
// Wire format:
//
//	+-------------------+-------------------+-----------+
//	| SHA-256(password) | padding0 length   | padding0  |
//	+-------------------+-------------------+-----------+
//	| 32 Bytes          | uint16 Big-Endian | variable  |
//	+-------------------+-------------------+-----------+
type AuthRequest struct {
	Hash    [AuthHashLen]byte
	Padding []byte
}

// EncodeAuthRequest writes the authentication request in a single write call
// to avoid predictable packet size patterns.
func EncodeAuthRequest(w io.Writer, hash [AuthHashLen]byte, padding []byte) error {
	paddingLen := len(padding)
	if paddingLen > MaxFrameDataLen {
		return ErrAuthPaddingTooLarge
	}
	buf := make([]byte, AuthHashLen+2+paddingLen)

	copy(buf[:AuthHashLen], hash[:])
	binary.BigEndian.PutUint16(buf[AuthHashLen:AuthHashLen+2], uint16(paddingLen))
	if paddingLen > 0 {
		copy(buf[AuthHashLen+2:], padding)
	}

	_, err := w.Write(buf)
	return err
}

// DecodeAuthRequest reads and parses the authentication request.
func DecodeAuthRequest(r io.Reader) (*AuthRequest, error) {
	// Read hash + padding length (32 + 2 = 34 bytes)
	var header [AuthHashLen + 2]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return nil, fmt.Errorf("tsunami: read auth header: %w", err)
	}

	req := &AuthRequest{}
	copy(req.Hash[:], header[:AuthHashLen])
	paddingLen := binary.BigEndian.Uint16(header[AuthHashLen : AuthHashLen+2])

	if paddingLen > 0 {
		req.Padding = make([]byte, paddingLen)
		if _, err := io.ReadFull(r, req.Padding); err != nil {
			return nil, fmt.Errorf("tsunami: read auth padding: %w", err)
		}
	}

	return req, nil
}

// AuthOverhead is the fixed overhead of the authentication message: hash(32) + paddingLen(2) = 34.
const AuthOverhead = AuthHashLen + 2

// Authenticator handles server-side user authentication.
type Authenticator struct {
	users map[[AuthHashLen]byte]*UserInfo
}

// UserInfo holds per-user metadata.
type UserInfo struct {
	ID       string
	Name     string
	Password string

	// TokenHash is the hex-encoded SHA-256 token/password hash.
	// External panels should prefer this over sending plaintext Password.
	TokenHash string

	Disabled  bool
	ExpiresAt time.Time

	Bandwidth     int   // Mbps, 0 = unlimited. Kept for config compatibility.
	SpeedLimitBps int64 // Bytes per second, 0 = unlimited.

	QuotaBytes        int64
	UsedUploadBytes   int64
	UsedDownloadBytes int64

	MaxSessions int
	MaxDevices  int

	Metadata map[string]string
}

// AuthHash returns the authentication hash for this user.
func (u *UserInfo) AuthHash() ([AuthHashLen]byte, error) {
	var hash [AuthHashLen]byte
	if u == nil {
		return hash, fmt.Errorf("tsunami: nil user")
	}

	tokenHash := strings.TrimSpace(u.TokenHash)
	if tokenHash != "" {
		decoded, err := hex.DecodeString(tokenHash)
		if err != nil {
			return hash, fmt.Errorf("tsunami: invalid token hash for user %q: %w", u.Name, err)
		}
		if len(decoded) != AuthHashLen {
			return hash, fmt.Errorf("tsunami: invalid token hash length for user %q: got %d, want %d", u.Name, len(decoded), AuthHashLen)
		}
		copy(hash[:], decoded)
		return hash, nil
	}

	if u.Password == "" {
		return hash, fmt.Errorf("tsunami: user %q has no password or token hash", u.Name)
	}
	return PasswordHash(u.Password), nil
}

// Identity returns a stable user key for logs, traffic accounting, and limits.
func (u *UserInfo) Identity() string {
	if u == nil {
		return ""
	}
	if u.ID != "" {
		return u.ID
	}
	if u.Name != "" {
		return u.Name
	}
	if u.TokenHash != "" {
		if len(u.TokenHash) > 12 {
			return u.TokenHash[:12]
		}
		return u.TokenHash
	}
	return "anonymous"
}

// IsUsable returns whether the user may open a new authenticated session.
func (u *UserInfo) IsUsable(now time.Time) (bool, string) {
	if u == nil {
		return false, "nil user"
	}
	if u.Disabled {
		return false, "disabled"
	}
	if !u.ExpiresAt.IsZero() && now.After(u.ExpiresAt) {
		return false, "expired"
	}
	if u.QuotaBytes > 0 && u.UsedUploadBytes+u.UsedDownloadBytes >= u.QuotaBytes {
		return false, "quota exceeded"
	}
	return true, ""
}

// Clone returns a copy of the user metadata.
func (u *UserInfo) Clone() *UserInfo {
	if u == nil {
		return nil
	}
	cloned := *u
	if u.Metadata != nil {
		cloned.Metadata = make(map[string]string, len(u.Metadata))
		for k, v := range u.Metadata {
			cloned.Metadata[k] = v
		}
	}
	return &cloned
}

// NewAuthenticator creates a new Authenticator with the given user list.
func NewAuthenticator(users []*UserInfo) *Authenticator {
	a := &Authenticator{
		users: make(map[[AuthHashLen]byte]*UserInfo, len(users)),
	}
	for _, u := range users {
		hash, err := u.AuthHash()
		if err != nil {
			continue
		}
		a.users[hash] = u
	}
	return a
}

// Authenticate checks the provided hash against known users.
// Returns the matched UserInfo or nil if authentication fails.
func (a *Authenticator) Authenticate(hash [AuthHashLen]byte) *UserInfo {
	var matched *UserInfo
	for knownHash, user := range a.users {
		if subtle.ConstantTimeCompare(hash[:], knownHash[:]) == 1 {
			matched = user
		}
	}
	if matched == nil {
		return nil
	}
	if ok, _ := matched.IsUsable(time.Now()); !ok {
		return nil
	}
	return matched
}
