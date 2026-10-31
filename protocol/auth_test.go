package protocol

import (
	"bytes"
	"crypto/sha256"
	"testing"
)

func TestPasswordHash(t *testing.T) {
	hash := PasswordHash("test-password")
	expected := sha256.Sum256([]byte("test-password"))
	if hash != expected {
		t.Errorf("password hash mismatch")
	}
}

func TestAuthEncodeDecode(t *testing.T) {
	hash := PasswordHash("my-secure-password")
	padding := []byte("random-padding-data")

	var buf bytes.Buffer
	if err := EncodeAuthRequest(&buf, hash, padding); err != nil {
		t.Fatalf("encode auth: %v", err)
	}

	// Must be exactly: 32 (hash) + 2 (len) + len(padding)
	expectedLen := AuthHashLen + 2 + len(padding)
	if buf.Len() != expectedLen {
		t.Fatalf("encoded length = %d, want %d", buf.Len(), expectedLen)
	}

	decoded, err := DecodeAuthRequest(&buf)
	if err != nil {
		t.Fatalf("decode auth: %v", err)
	}

	if decoded.Hash != hash {
		t.Errorf("hash mismatch")
	}
	if !bytes.Equal(decoded.Padding, padding) {
		t.Errorf("padding mismatch")
	}
}

func TestAuthenticator(t *testing.T) {
	users := []*UserInfo{
		{Name: "alice", Password: "alice-pass"},
		{Name: "bob", Password: "bob-pass"},
	}
	auth := NewAuthenticator(users)

	// Valid users
	aliceHash := PasswordHash("alice-pass")
	if user := auth.Authenticate(aliceHash); user == nil || user.Name != "alice" {
		t.Errorf("alice should authenticate")
	}

	bobHash := PasswordHash("bob-pass")
	if user := auth.Authenticate(bobHash); user == nil || user.Name != "bob" {
		t.Errorf("bob should authenticate")
	}

	// Invalid user
	badHash := PasswordHash("wrong-pass")
	if user := auth.Authenticate(badHash); user != nil {
		t.Errorf("wrong password should not authenticate, got user: %s", user.Name)
	}
}

func TestAuthNoPadding(t *testing.T) {
	hash := PasswordHash("test")
	var buf bytes.Buffer
	if err := EncodeAuthRequest(&buf, hash, nil); err != nil {
		t.Fatalf("encode auth without padding: %v", err)
	}

	expectedLen := AuthHashLen + 2 // hash + padding length (0)
	if buf.Len() != expectedLen {
		t.Fatalf("encoded length = %d, want %d", buf.Len(), expectedLen)
	}

	decoded, err := DecodeAuthRequest(&buf)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(decoded.Padding) != 0 {
		t.Errorf("expected no padding, got %d bytes", len(decoded.Padding))
	}
}
