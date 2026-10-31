package tsunami

import (
	"context"
	"fmt"
	"math/rand/v2"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/RavenholmAlpha/sing-tsunami/protocol"
)

// Default session pool lifecycle values, ported from the TSUNAMI mux pool.
//
// The lifecycle knobs exist to keep the client from looking like a synthetic
// beacon: a client that always keeps one TLS connection open, or that emits an
// application heartbeat on a fixed period, is easy to distinguish from real
// browsing traffic. Wherever the phase of an event would otherwise be
// predictable it is randomized, and the pool is allowed to drain to zero
// sessions so an idle client has no tunnel at all.
const (
	defaultIdleSessionCheckInterval = 30 * time.Second
	defaultIdleSessionTimeout       = 5 * time.Minute
	defaultHeartbeatMin             = 25 * time.Second
	defaultHeartbeatMax             = 55 * time.Second
	defaultHeartbeatTimeout         = 90 * time.Second
)

// poolOptions configures a sessionPool. Zero fields fall back to the defaults
// above.
type poolOptions struct {
	minIdleSession    int
	idleCheckInterval time.Duration
	idleTimeout       time.Duration
	heartbeatMin      time.Duration
	heartbeatMax      time.Duration
	heartbeatTimeout  time.Duration
}

func (o poolOptions) normalized() poolOptions {
	if o.minIdleSession < 0 {
		o.minIdleSession = 0
	}
	if o.idleCheckInterval <= 0 {
		o.idleCheckInterval = defaultIdleSessionCheckInterval
	}
	if o.idleTimeout <= 0 {
		o.idleTimeout = defaultIdleSessionTimeout
	}
	if o.heartbeatMin <= 0 {
		o.heartbeatMin = defaultHeartbeatMin
	}
	if o.heartbeatMax <= 0 {
		o.heartbeatMax = defaultHeartbeatMax
	}
	if o.heartbeatMax < o.heartbeatMin {
		o.heartbeatMax = o.heartbeatMin
	}
	if o.heartbeatTimeout <= 0 {
		o.heartbeatTimeout = defaultHeartbeatTimeout
	}
	return o
}

// heartbeatAction is the outcome of a keep-alive decision for one session.
type heartbeatAction int

const (
	// heartbeatIdle means no action is needed for this session right now.
	heartbeatIdle heartbeatAction = iota
	// heartbeatSend means a CmdHeartRequest should be sent.
	heartbeatSend
	// heartbeatClose means the session is considered dead and should be closed.
	heartbeatClose
)

// heartbeatState is the pool-side keep-alive bookkeeping for one session. It is
// only accessed while holding sessionPool.mu.
type heartbeatState struct {
	// nextPing is the earliest time at which a heartbeat may be sent. It is
	// anchored to the session's last activity plus a random delay so a client
	// that is actively using the tunnel never appears to ping on a fixed clock.
	nextPing time.Time
	// awaitingSince is when the outstanding heartbeat was sent. It is the zero
	// value when no pong is outstanding.
	awaitingSince time.Time
}

// sessionPool manages a set of reusable multiplexed sessions.
type sessionPool struct {
	opts   poolOptions
	dialFn func(ctx context.Context) (*protocol.Session, error)

	sessions []*protocol.Session
	mu       sync.Mutex
	createMu sync.Mutex
	stopped  atomic.Bool
	stopCh   chan struct{}

	heartbeatState map[*protocol.Session]heartbeatState

	// Jitter sources. They are fields so tests can substitute deterministic
	// functions; they are never changed while the pool is in use.
	randDuration func(min, max time.Duration) time.Duration
	randFloat64  func() float64
}

func newSessionPool(opts poolOptions, dialFn func(ctx context.Context) (*protocol.Session, error)) *sessionPool {
	p := &sessionPool{
		opts:           opts.normalized(),
		dialFn:         dialFn,
		stopCh:         make(chan struct{}),
		heartbeatState: make(map[*protocol.Session]heartbeatState),
		randDuration:   defaultRandDuration,
		randFloat64:    rand.Float64,
	}
	go p.idleChecker()
	go p.heartbeatLoop()
	return p
}

// GetOrCreateSession returns an existing session or creates a new one.
//
// Strategy: prefer idle sessions (newest first), fall back to any non-closed
// session for multiplexing, create a new one only if no sessions exist at all.
func (p *sessionPool) GetOrCreateSession(ctx context.Context) (*protocol.Session, error) {
	if ctx == nil {
		ctx = context.Background()
	}

	p.mu.Lock()
	var bestIdle, bestAny *protocol.Session
	for _, s := range p.sessions {
		if s.IsClosed() {
			continue
		}
		bestAny = s // sessions are appended in creation order: the last is newest
		if s.IsIdle() {
			bestIdle = s
		}
	}
	p.mu.Unlock()

	if bestIdle != nil {
		return bestIdle, nil
	}
	if bestAny != nil {
		return bestAny, nil
	}

	// No sessions at all - create the first one. Holding createMu across the
	// dial makes concurrent creators share a single session.
	p.createMu.Lock()
	defer p.createMu.Unlock()

	p.mu.Lock()
	for _, s := range p.sessions {
		if !s.IsClosed() {
			p.mu.Unlock()
			return s, nil
		}
	}
	p.mu.Unlock()

	return p.createSession(ctx)
}

// createSession dials a new session and adds it to the pool.
func (p *sessionPool) createSession(ctx context.Context) (*protocol.Session, error) {
	if p.stopped.Load() {
		return nil, fmt.Errorf("tsunami: session pool is closed")
	}

	session, err := p.dialFn(ctx)
	if err != nil {
		return nil, err
	}
	if session == nil {
		return nil, fmt.Errorf("tsunami: dial returned a nil session")
	}

	p.mu.Lock()
	if p.stopped.Load() {
		p.mu.Unlock()
		_ = session.Close()
		return nil, fmt.Errorf("tsunami: session pool is closed")
	}
	p.sessions = append(p.sessions, session)
	p.mu.Unlock()

	// A session that has not carried a stream yet has no idle timestamp; start
	// its idle clock now so it cannot live forever.
	if !session.IsClosed() && session.IsIdle() && session.IdleSince().IsZero() {
		session.SetIdleSince(time.Now())
	}
	return session, nil
}

// SessionCount returns the number of non-closed sessions.
func (p *sessionPool) SessionCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()

	count := 0
	for _, s := range p.sessions {
		if !s.IsClosed() {
			count++
		}
	}
	return count
}

// ActiveStreamCount returns the total number of active streams across all
// sessions.
func (p *sessionPool) ActiveStreamCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()

	total := 0
	for _, s := range p.sessions {
		if !s.IsClosed() {
			total += s.ActiveStreamCount()
		}
	}
	return total
}

// idleChecker periodically scans for and closes idle sessions.
func (p *sessionPool) idleChecker() {
	ticker := time.NewTicker(p.opts.idleCheckInterval)
	defer ticker.Stop()

	for {
		select {
		case <-p.stopCh:
			return
		case <-ticker.C:
			if p.stopped.Load() {
				return
			}
			p.cleanupIdle()
		}
	}
}

// idleCloseDeadline returns IdleTimeout scaled by a random factor in [0.7, 1.3).
// The jitter prevents idle sessions (and therefore connection teardown) from
// happening on a predictable period, which would itself be a traffic pattern.
func idleCloseDeadline(base time.Duration, randFloat func() float64) time.Duration {
	factor := 0.7 + 0.6*randFloat() // [0.7, 1.3)
	return time.Duration(float64(base) * factor)
}

// cleanupIdle removes sessions that have been idle too long. At least
// MinIdleSession idle sessions are kept; with the default of 0 an idle client
// eventually has no open session at all.
func (p *sessionPool) cleanupIdle() {
	type idleCandidate struct {
		session *protocol.Session
		idleFor time.Duration
	}

	now := time.Now()

	p.mu.Lock()

	// First pass: drop already-closed sessions and their keep-alive state.
	live := make([]*protocol.Session, 0, len(p.sessions))
	for _, s := range p.sessions {
		if s.IsClosed() {
			delete(p.heartbeatState, s)
			continue
		}
		live = append(live, s)
	}
	p.sessions = live

	idleCount := 0
	candidates := make([]idleCandidate, 0, len(live))
	for _, s := range live {
		if !s.IsIdle() {
			continue
		}
		idleCount++

		idleSince := s.IdleSince()
		if idleSince.IsZero() {
			// Safety net: start the idle clock rather than keeping a session
			// with no timestamp forever.
			s.SetIdleSince(now)
			continue
		}

		// Random deadline per session and per check: no shared cutoff.
		if now.Sub(idleSince) > idleCloseDeadline(p.opts.idleTimeout, p.randFloat64) {
			candidates = append(candidates, idleCandidate{session: s, idleFor: now.Sub(idleSince)})
		}
	}

	closeable := idleCount - p.opts.minIdleSession
	if closeable <= 0 || len(candidates) == 0 {
		p.mu.Unlock()
		return
	}

	// Close the longest-idle sessions first so the sessions we keep are the
	// most recently used ones.
	sort.Slice(candidates, func(i, j int) bool {
		return candidates[i].idleFor > candidates[j].idleFor
	})

	closing := make(map[*protocol.Session]struct{}, len(candidates))
	for _, c := range candidates {
		if closeable <= 0 {
			break
		}
		closing[c.session] = struct{}{}
		delete(p.heartbeatState, c.session)
		closeable--
	}

	remaining := make([]*protocol.Session, 0, len(live))
	for _, s := range live {
		if _, ok := closing[s]; ok {
			continue
		}
		remaining = append(remaining, s)
	}
	p.sessions = remaining
	p.mu.Unlock()

	// Session.Close writes to the connection, so it must happen outside the
	// pool lock.
	for s := range closing {
		_ = s.Close()
	}
}

// heartbeatTickInterval returns the interval of the heartbeat scheduler tick.
// It is deliberately shorter than the heartbeat period so jittered deadlines
// are honored with reasonable precision, and capped at 5s.
func heartbeatTickInterval(opts poolOptions) time.Duration {
	interval := opts.heartbeatMax / 4
	if interval <= 0 {
		interval = time.Millisecond
	}
	if interval > 5*time.Second {
		interval = 5 * time.Second
	}
	return interval
}

// defaultRandDuration returns a random duration in [min, max].
func defaultRandDuration(min, max time.Duration) time.Duration {
	if max <= min {
		return min
	}
	return min + time.Duration(rand.Int64N(int64(max-min)+1))
}

// scheduleNextPing anchors the next heartbeat to the session's last observed
// activity: a client that is actively using the tunnel never emits an
// application ping on a fixed schedule, and never within HeartbeatMin of real
// traffic.
func scheduleNextPing(lastActive, now time.Time, opts poolOptions, randDur func(min, max time.Duration) time.Duration) time.Time {
	if lastActive.IsZero() || lastActive.After(now) {
		lastActive = now
	}
	return lastActive.Add(randDur(opts.heartbeatMin, opts.heartbeatMax))
}

// heartbeatDecision computes what the pool should do with one session at the
// given instant. It is pure: the caller owns locking and state persistence.
func heartbeatDecision(now, lastActive, lastPong time.Time, st heartbeatState, opts poolOptions,
	randDur func(min, max time.Duration) time.Duration) (heartbeatAction, heartbeatState) {

	// A heartbeat is outstanding: either the pong arrived or the session is dead.
	if !st.awaitingSince.IsZero() {
		if lastPong.After(st.awaitingSince) {
			st.awaitingSince = time.Time{}
			st.nextPing = scheduleNextPing(lastActive, now, opts, randDur)
			return heartbeatIdle, st
		}
		if now.Sub(st.awaitingSince) > opts.heartbeatTimeout {
			return heartbeatClose, st
		}
		return heartbeatIdle, st
	}

	if st.nextPing.IsZero() {
		// First observation: anchor the schedule to the session's activity.
		st.nextPing = scheduleNextPing(lastActive, now, opts, randDur)
		return heartbeatIdle, st
	}

	// Any traffic within the last HeartbeatMin pushes the ping out; this is
	// what keeps the heartbeat from firing while the user is active.
	if !lastActive.IsZero() && now.Sub(lastActive) < opts.heartbeatMin {
		st.nextPing = lastActive.Add(randDur(opts.heartbeatMin, opts.heartbeatMax))
		return heartbeatIdle, st
	}

	if now.Before(st.nextPing) {
		return heartbeatIdle, st
	}

	st.awaitingSince = now
	st.nextPing = now.Add(randDur(opts.heartbeatMin, opts.heartbeatMax))
	return heartbeatSend, st
}

// heartbeatLoop runs the single keep-alive scheduler goroutine.
func (p *sessionPool) heartbeatLoop() {
	ticker := time.NewTicker(heartbeatTickInterval(p.opts))
	defer ticker.Stop()

	for {
		select {
		case <-p.stopCh:
			return
		case now := <-ticker.C:
			if p.stopped.Load() {
				return
			}
			p.runHeartbeat(now)
		}
	}
}

// runHeartbeat advances the keep-alive state of every session, then performs
// the resulting sends and closes outside the pool lock.
func (p *sessionPool) runHeartbeat(now time.Time) {
	var sends, closes []*protocol.Session

	p.mu.Lock()

	kept := make([]*protocol.Session, 0, len(p.sessions))
	for _, s := range p.sessions {
		if s.IsClosed() {
			delete(p.heartbeatState, s)
			continue
		}

		st := p.heartbeatState[s]
		action, next := heartbeatDecision(now, s.LastActive(), s.LastPong(), st, p.opts, p.randDuration)
		switch action {
		case heartbeatSend:
			sends = append(sends, s)
			p.heartbeatState[s] = next
			kept = append(kept, s)
		case heartbeatClose:
			closes = append(closes, s)
			delete(p.heartbeatState, s)
		default:
			p.heartbeatState[s] = next
			kept = append(kept, s)
		}
	}

	// Drop keep-alive state for sessions that are no longer in the pool.
	if len(p.heartbeatState) > 0 {
		live := make(map[*protocol.Session]struct{}, len(kept))
		for _, s := range kept {
			live[s] = struct{}{}
		}
		for s := range p.heartbeatState {
			if _, ok := live[s]; !ok {
				delete(p.heartbeatState, s)
			}
		}
	}
	p.sessions = kept
	p.mu.Unlock()

	// Session writes/closes can block on the connection: never hold the pool
	// mutex while doing them.
	for _, s := range sends {
		_ = s.SendHeartbeat()
	}
	for _, s := range closes {
		_ = s.Close()
	}
}

// Close closes all sessions in the pool, clears the keep-alive state and stops
// the background goroutines. It is safe to call more than once.
func (p *sessionPool) Close() {
	if !p.stopped.CompareAndSwap(false, true) {
		return
	}
	close(p.stopCh)

	p.mu.Lock()
	sessions := p.sessions
	p.sessions = nil
	p.heartbeatState = make(map[*protocol.Session]heartbeatState)
	p.mu.Unlock()

	for _, s := range sessions {
		_ = s.Close()
	}
}
