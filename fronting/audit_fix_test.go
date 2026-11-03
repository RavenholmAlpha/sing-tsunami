package fronting

import (
	"fmt"
	"net/http"
	"testing"
	"time"
)

// An invalid signature must not populate the replay cache: only requests that
// pass HMAC verification take the replay check. Otherwise any unauthenticated
// client could grow the cache without bound.
func TestVerifyRequestDoesNotCacheInvalidSignatures(t *testing.T) {
	key := KeyFromSecret("secret")
	cache := NewNonceCache(5 * time.Minute)
	now := time.Now()

	req, err := http.NewRequest(http.MethodPost, "https://example.com/assets/update", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Host = "example.com"
	SignRequest(req, key, now)
	req.Header.Set(headerAuth, "HMAC-SHA256 Signature=deadbeef")
	if VerifyRequest(req, [][32]byte{key}, now, ClockSkew, cache) {
		t.Fatal("bogus signature verified")
	}
	cache.mu.Lock()
	invalidEntries := len(cache.entries)
	cache.mu.Unlock()
	if invalidEntries != 0 {
		t.Fatalf("invalid signature populated the replay cache: %d entries", invalidEntries)
	}

	valid, err := http.NewRequest(http.MethodPost, "https://example.com/assets/update", nil)
	if err != nil {
		t.Fatal(err)
	}
	valid.Host = "example.com"
	SignRequest(valid, key, now)
	if !VerifyRequest(valid, [][32]byte{key}, now, ClockSkew, cache) {
		t.Fatal("valid signature rejected")
	}
	cache.mu.Lock()
	validEntries := len(cache.entries)
	cache.mu.Unlock()
	if validEntries != 1 {
		t.Fatalf("valid request should cache exactly one nonce, got %d", validEntries)
	}
}

func TestNonceCacheIsBounded(t *testing.T) {
	cache := NewNonceCache(5 * time.Minute)
	cache.maxEntries = 64
	for i := 0; i < 1000; i++ {
		cache.Add(fmt.Sprintf("nonce-%032d", i))
	}
	cache.mu.Lock()
	size := len(cache.entries)
	cache.mu.Unlock()
	if size > cache.maxEntries {
		t.Fatalf("nonce cache grew to %d entries, limit %d", size, cache.maxEntries)
	}
}
