package fronting

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"
)

// sha256Sum is the expected derivation used by KeyFromSecret.
func sha256Sum(s string) [32]byte { return sha256.Sum256([]byte(s)) }

// signedRequest builds a request and signs it with KeyFromSecret(secret).
func signedRequest(t *testing.T, method, target, host, secret string, now time.Time) (*http.Request, [32]byte) {
	t.Helper()
	req, err := http.NewRequest(method, target, nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Host = host
	key := KeyFromSecret(secret)
	SignRequest(req, key, now)
	return req, key
}

func TestSignAndVerifyRequest(t *testing.T) {
	now := time.Unix(1700000000, 0)
	req, key := signedRequest(t, http.MethodPost, "https://example.com"+DefaultPath, "example.com", "secret", now)

	if got := req.Header.Get("X-Api-Version"); got != "v1" {
		t.Fatalf("X-Api-Version = %q, want v1", got)
	}
	if got := req.Header.Get("X-Date"); got != strconv.FormatInt(now.Unix(), 10) {
		t.Fatalf("X-Date = %q", got)
	}
	if nonce := req.Header.Get("X-Trace-Id"); len(nonce) != 32 {
		t.Fatalf("X-Trace-Id length = %d, want 32", len(nonce))
	}
	if auth := req.Header.Get("Authorization"); !strings.HasPrefix(auth, "HMAC-SHA256 Signature=") {
		t.Fatalf("Authorization = %q", auth)
	}
	for name := range req.Header {
		if strings.Contains(strings.ToLower(name), "tsunami") {
			t.Fatalf("signed request leaked project marker header %q", name)
		}
	}

	if !VerifyRequest(req, [][32]byte{key}, now, ClockSkew, nil) {
		t.Fatal("signed request did not verify")
	}
	// Any accepted key may verify (one fronting secret per user).
	other := KeyFromSecret("another-secret")
	if !VerifyRequest(req, [][32]byte{other, key}, now, ClockSkew, nil) {
		t.Fatal("request did not verify against the second accepted key")
	}
	// The Host is part of the MAC in lowercase form.
	req.Host = "EXAMPLE.COM"
	if !VerifyRequest(req, [][32]byte{key}, now, ClockSkew, nil) {
		t.Fatal("host should be compared case-insensitively")
	}
}

func TestSignRequestUsesFreshNonces(t *testing.T) {
	now := time.Unix(1700000000, 0)
	first, key := signedRequest(t, http.MethodPost, "https://example.com"+DefaultPath, "example.com", "secret", now)
	second, _ := signedRequest(t, http.MethodPost, "https://example.com"+DefaultPath, "example.com", "secret", now)

	if first.Header.Get("X-Trace-Id") == second.Header.Get("X-Trace-Id") {
		t.Fatal("two signatures reused the same nonce")
	}
	if first.Header.Get("Authorization") == second.Header.Get("Authorization") {
		t.Fatal("two signatures produced the same MAC")
	}
	if !VerifyRequest(second, [][32]byte{key}, now, ClockSkew, nil) {
		t.Fatal("second signed request did not verify")
	}
}

func TestVerifyRequestRejectsTampering(t *testing.T) {
	now := time.Unix(1700000000, 0)
	signed := func() (*http.Request, [32]byte) {
		return signedRequest(t, http.MethodPost, "https://example.com"+DefaultPath, "example.com", "secret", now)
	}

	tests := []struct {
		name   string
		mutate func(*http.Request)
	}{
		{"host", func(r *http.Request) { r.Host = "probe.example.com" }},
		{"method", func(r *http.Request) { r.Method = http.MethodGet }},
		{"path", func(r *http.Request) { r.URL.Path = "/other" }},
		{"date", func(r *http.Request) {
			r.Header.Set("X-Date", strconv.FormatInt(now.Unix()+1, 10))
		}},
		{"nonce", func(r *http.Request) { r.Header.Set("X-Trace-Id", "0011223344556677") }},
		{"signature", func(r *http.Request) {
			auth := r.Header.Get("Authorization")
			last := auth[len(auth)-1]
			replacement := byte('0')
			if last == '0' {
				replacement = '1'
			}
			r.Header.Set("Authorization", auth[:len(auth)-1]+string(replacement))
		}},
		{"version", func(r *http.Request) { r.Header.Set("X-Api-Version", "v2") }},
		{"missing auth", func(r *http.Request) { r.Header.Del("Authorization") }},
		{"missing date", func(r *http.Request) { r.Header.Del("X-Date") }},
		{"missing nonce", func(r *http.Request) { r.Header.Del("X-Trace-Id") }},
		{"missing version", func(r *http.Request) { r.Header.Del("X-Api-Version") }},
		{"short nonce", func(r *http.Request) { r.Header.Set("X-Trace-Id", "abc") }},
		{"long nonce", func(r *http.Request) {
			r.Header.Set("X-Trace-Id", strings.Repeat("a", 129))
		}},
		{"non-hex signature", func(r *http.Request) {
			r.Header.Set("Authorization", "HMAC-SHA256 Signature=zzzz")
		}},
		{"empty signature", func(r *http.Request) {
			r.Header.Set("Authorization", "HMAC-SHA256 Signature=")
		}},
		{"bare signature", func(r *http.Request) {
			r.Header.Set("Authorization", "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef")
		}},
		{"unparsable date", func(r *http.Request) { r.Header.Set("X-Date", "yesterday") }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, key := signed()
			tt.mutate(req)
			if VerifyRequest(req, [][32]byte{key}, now, ClockSkew, nil) {
				t.Fatal("tampered request verified")
			}
		})
	}
}

func TestVerifyRequestRejectsUnknownKey(t *testing.T) {
	now := time.Unix(1700000000, 0)
	req, _ := signedRequest(t, http.MethodPost, "https://example.com"+DefaultPath, "example.com", "secret", now)
	if VerifyRequest(req, [][32]byte{KeyFromSecret("wrong-secret")}, now, ClockSkew, nil) {
		t.Fatal("request verified with an unrelated key")
	}
	if VerifyRequest(req, nil, now, ClockSkew, nil) {
		t.Fatal("request verified with an empty key list")
	}
	if VerifyRequest(nil, [][32]byte{KeyFromSecret("secret")}, now, ClockSkew, nil) {
		t.Fatal("nil request verified")
	}
}

func TestVerifyRequestClockSkew(t *testing.T) {
	now := time.Unix(1700000000, 0)
	req, key := signedRequest(t, http.MethodPost, "https://example.com"+DefaultPath, "example.com", "secret", now)
	keys := [][32]byte{key}

	tests := []struct {
		name string
		at   time.Time
		want bool
	}{
		{"same instant", now, true},
		{"one minute later", now.Add(time.Minute), true},
		{"one minute earlier", now.Add(-time.Minute), true},
		{"just inside future skew", now.Add(ClockSkew - time.Second), true},
		{"outside future skew", now.Add(ClockSkew + time.Second), false},
		{"just outside past skew", now.Add(-ClockSkew - time.Second), false},
		{"ten minutes later", now.Add(10 * time.Minute), false},
		{"ten minutes earlier", now.Add(-10 * time.Minute), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := VerifyRequest(req, keys, tt.at, ClockSkew, nil); got != tt.want {
				t.Fatalf("VerifyRequest at %v = %t, want %t", tt.at, got, tt.want)
			}
		})
	}
}

func TestVerifyRequestRejectsReplay(t *testing.T) {
	now := time.Unix(1700000000, 0)
	req, key := signedRequest(t, http.MethodPost, "https://example.com"+DefaultPath, "example.com", "secret", now)
	keys := [][32]byte{key}
	cache := NewNonceCache(ClockSkew + 30*time.Second)

	if !VerifyRequest(req, keys, now, ClockSkew, cache) {
		t.Fatal("first verification failed")
	}
	if VerifyRequest(req, keys, now, ClockSkew, cache) {
		t.Fatal("replayed request verified")
	}
	// A nil cache disables replay protection by design.
	if !VerifyRequest(req, keys, now, ClockSkew, nil) {
		t.Fatal("nil cache should not reject a valid signature")
	}
}

func TestNonceCache(t *testing.T) {
	// The zero value is usable.
	var zero NonceCache
	if !zero.Add("0123456789abcdef") {
		t.Fatal("zero-value cache rejected a fresh nonce")
	}
	if zero.Add("0123456789abcdef") {
		t.Fatal("zero-value cache accepted a duplicate nonce")
	}

	cache := NewNonceCache(time.Minute)
	t0 := time.Unix(1700000000, 0)
	if !cache.add("0123456789abcdef", t0) {
		t.Fatal("fresh nonce rejected")
	}
	if cache.add("0123456789abcdef", t0.Add(30*time.Second)) {
		t.Fatal("cached nonce accepted after 30s")
	}
	if !cache.add("0123456789abcdef", t0.Add(2*time.Minute)) {
		t.Fatal("expired nonce was not accepted again")
	}
}

func TestStripAuthHeaders(t *testing.T) {
	req, _ := signedRequest(t, http.MethodPost, "https://example.com"+DefaultPath, "example.com", "secret", time.Unix(1700000000, 0))
	req.Header.Set("X-Forwarded-Proto", "https")
	StripAuthHeaders(req.Header)
	for _, name := range []string{"X-Api-Version", "X-Date", "X-Trace-Id", "Authorization"} {
		if req.Header.Get(name) != "" {
			t.Fatalf("%s was not stripped", name)
		}
	}
	if req.Header.Get("X-Forwarded-Proto") != "https" {
		t.Fatal("StripAuthHeaders removed a non-fronting header")
	}
}

func TestKeyFromSecret(t *testing.T) {
	first := KeyFromSecret("secret")
	second := KeyFromSecret("secret")
	if first != second {
		t.Fatal("KeyFromSecret is not deterministic")
	}
	if first == KeyFromSecret("other") {
		t.Fatal("different secrets produced the same key")
	}
	// The key is a SHA-256 digest of the secret.
	if first != sha256Sum("secret") {
		t.Fatal("KeyFromSecret is not sha256(secret)")
	}
}

// TestSignatureWireFormat pins the exact TSUNAMI HMAC scheme: MAC over
// method, escaped path, lowercased Host, timestamp and nonce, emitted as
// "HMAC-SHA256 Signature=<hex>".
func TestSignatureWireFormat(t *testing.T) {
	now := time.Unix(1700000000, 0)
	req, err := http.NewRequest(http.MethodPost, "https://example.com/assets/update", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Host = "Example.COM"
	key := KeyFromSecret("secret")
	SignRequest(req, key, now)

	nonce := req.Header.Get("X-Trace-Id")
	mac := hmac.New(sha256.New, key[:])
	fmt.Fprintf(mac, "%s\n%s\n%s\n%s\n%s", "POST", "/assets/update", "example.com", "1700000000", nonce)
	want := "HMAC-SHA256 Signature=" + hex.EncodeToString(mac.Sum(nil))
	if got := req.Header.Get("Authorization"); got != want {
		t.Fatalf("Authorization = %q, want %q", got, want)
	}
}
