package fronting

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	headerVersion = "X-Api-Version"
	headerDate    = "X-Date"
	headerNonce   = "X-Trace-Id"
	headerAuth    = "Authorization"
	authVersion   = "v1"

	// noncePruneInterval bounds how often expired nonces are swept. Eviction is
	// lazy (on Add) so a NonceCache holds no background goroutine.
	noncePruneInterval = 30 * time.Second
	// defaultNonceTTL covers the full accepted timestamp window plus margin, so
	// a nonce cannot be replayed after its timestamp becomes unacceptable.
	defaultNonceTTL = ClockSkew + 30*time.Second
)

// NonceCache records recently seen request nonces so that replayed fronting
// requests are rejected. The zero value is ready to use and remembers nonces
// for ClockSkew+30s. Expired entries are pruned lazily on Add, so the cache
// holds no goroutine and never needs to be closed.
type NonceCache struct {
	mu        sync.Mutex
	entries   map[string]time.Time
	ttl       time.Duration
	lastPrune time.Time
}

// NewNonceCache returns a nonce cache that remembers nonces for ttl. A ttl <= 0
// selects the default of ClockSkew+30s.
func NewNonceCache(ttl time.Duration) *NonceCache {
	return &NonceCache{ttl: ttl}
}

// Add records nonce and reports whether it was not seen before. It returns
// false for a nonce that is already in the cache (a replay).
func (c *NonceCache) Add(nonce string) bool {
	return c.add(nonce, time.Now())
}

// add is Add with an explicit clock, which keeps invalidation testable.
func (c *NonceCache) add(nonce string, now time.Time) bool {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.entries == nil {
		c.entries = make(map[string]time.Time)
	}
	ttl := c.ttl
	if ttl <= 0 {
		ttl = defaultNonceTTL
	}
	if c.lastPrune.IsZero() || now.Sub(c.lastPrune) >= noncePruneInterval {
		cutoff := now.Add(-ttl)
		for seen, at := range c.entries {
			if at.Before(cutoff) {
				delete(c.entries, seen)
			}
		}
		c.lastPrune = now
	}
	if _, seen := c.entries[nonce]; seen {
		return false
	}
	c.entries[nonce] = now
	return true
}

// StripAuthHeaders removes fronting-only request metadata before a decoy proxy
// forwards unauthenticated traffic to a normal origin.
func StripAuthHeaders(h http.Header) {
	h.Del(headerVersion)
	h.Del(headerDate)
	h.Del(headerNonce)
	h.Del(headerAuth)
}

// SignRequest adds the HTTP-layer authentication headers to req:
//
//	X-Api-Version: v1
//	X-Date: <unix seconds>
//	X-Trace-Id: <random nonce>
//	Authorization: HMAC-SHA256 Signature=<hex>
//
// The MAC covers the method, the escaped request path, the lowercased Host,
// the timestamp and the nonce. Verifiers must present the same Host value the
// request carries on the wire.
func SignRequest(req *http.Request, key [32]byte, now time.Time) {
	if req == nil {
		return
	}
	if req.Header == nil {
		req.Header = make(http.Header)
	}
	nonce, err := randomNonce()
	if err != nil {
		// crypto/rand is documented never to fail on supported platforms; fall
		// back to a time+counter nonce instead of panicking. Failure remains
		// fail-closed because the server validates the nonce's shape and the
		// MAC covers it.
		nonce = fallbackNonce(now)
	}
	ts := strconv.FormatInt(now.Unix(), 10)

	req.Header.Set(headerVersion, authVersion)
	req.Header.Set(headerDate, ts)
	req.Header.Set(headerNonce, nonce)
	req.Header.Set(headerAuth, "HMAC-SHA256 Signature="+computeMAC(req.Method, requestPath(req), req.Host, ts, nonce, key))
}

// VerifyRequest checks the HTTP-layer authentication of req against any of the
// accepted keys. The timestamp must be within skew of now, and cache (when
// non-nil) rejects nonces seen before. A nil cache disables replay protection.
func VerifyRequest(req *http.Request, keys [][32]byte, now time.Time, skew time.Duration, cache *NonceCache) bool {
	if req == nil || len(keys) == 0 {
		return false
	}
	if req.Header.Get(headerVersion) != authVersion {
		return false
	}
	ts := req.Header.Get(headerDate)
	nonce := req.Header.Get(headerNonce)
	authHeader := req.Header.Get(headerAuth)
	if ts == "" || nonce == "" || authHeader == "" {
		return false
	}
	signature := strings.TrimPrefix(authHeader, "HMAC-SHA256 Signature=")
	if signature == authHeader {
		return false
	}
	if len(nonce) < 16 || len(nonce) > 128 {
		return false
	}
	timestamp, err := strconv.ParseInt(ts, 10, 64)
	if err != nil {
		return false
	}
	when := time.Unix(timestamp, 0)
	if when.After(now.Add(skew)) || when.Before(now.Add(-skew)) {
		return false
	}
	if _, err := hex.DecodeString(signature); err != nil {
		return false
	}

	// Replay protection is evaluated before the MAC so that a failed signature
	// also burns its nonce (fail closed).
	if cache != nil && !cache.Add(nonce) {
		return false
	}

	path := requestPath(req)
	for _, key := range keys {
		want := computeMAC(req.Method, path, req.Host, ts, nonce, key)
		if subtle.ConstantTimeCompare([]byte(strings.ToLower(signature)), []byte(want)) == 1 {
			return true
		}
	}
	return false
}

// requestPath returns the escaped request path used by the HMAC. The fallback
// to Path mirrors the URL escaping rules for an empty escaped path.
func requestPath(req *http.Request) string {
	if req.URL == nil {
		return ""
	}
	if escaped := req.URL.EscapedPath(); escaped != "" {
		return escaped
	}
	return req.URL.Path
}

func computeMAC(method, path, host, ts, nonce string, key [32]byte) string {
	mac := hmac.New(sha256.New, key[:])
	fmt.Fprintf(mac, "%s\n%s\n%s\n%s\n%s", method, path, strings.ToLower(host), ts, nonce)
	return hex.EncodeToString(mac.Sum(nil))
}

func randomNonce() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("fronting: nonce: %w", err)
	}
	return hex.EncodeToString(b[:]), nil
}

// nonceFallbackCounter makes fallbackNonce unique even within one nanosecond.
var nonceFallbackCounter atomic.Uint64

// fallbackNonce derives a nonce without crypto/rand. It is only reachable if
// the system random source is broken.
func fallbackNonce(now time.Time) string {
	var buf [24]byte
	binary.BigEndian.PutUint64(buf[:8], uint64(now.UnixNano()))
	binary.BigEndian.PutUint64(buf[8:16], nonceFallbackCounter.Add(1))
	sum := sha256.Sum256(buf[:])
	return hex.EncodeToString(sum[:16])
}
