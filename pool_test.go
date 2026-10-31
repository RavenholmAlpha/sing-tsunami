package tsunami

import (
	"bytes"
	"context"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/RavenholmAlpha/sing-tsunami/protocol"
)

func testPoolOptions() poolOptions {
	return poolOptions{
		heartbeatMin:     25 * time.Second,
		heartbeatMax:     55 * time.Second,
		heartbeatTimeout: 90 * time.Second,
	}.normalized()
}

// fixedMinRand returns the minimum duration, making heartbeat scheduling
// deterministic in tests.
func fixedMinRand(min, max time.Duration) time.Duration { return min }

func TestPoolOptionsNormalized(t *testing.T) {
	got := poolOptions{minIdleSession: -1}.normalized()
	if got.minIdleSession != 0 {
		t.Fatalf("minIdleSession = %d, want 0", got.minIdleSession)
	}
	if got.idleCheckInterval != defaultIdleSessionCheckInterval {
		t.Fatalf("idleCheckInterval = %v, want %v", got.idleCheckInterval, defaultIdleSessionCheckInterval)
	}
	if got.idleTimeout != defaultIdleSessionTimeout {
		t.Fatalf("idleTimeout = %v, want %v", got.idleTimeout, defaultIdleSessionTimeout)
	}
	if got.heartbeatMin != defaultHeartbeatMin || got.heartbeatMax != defaultHeartbeatMax {
		t.Fatalf("heartbeat range = %v-%v, want %v-%v",
			got.heartbeatMin, got.heartbeatMax, defaultHeartbeatMin, defaultHeartbeatMax)
	}
	if got.heartbeatTimeout != defaultHeartbeatTimeout {
		t.Fatalf("heartbeatTimeout = %v, want %v", got.heartbeatTimeout, defaultHeartbeatTimeout)
	}

	// An inverted range collapses to the minimum.
	got = poolOptions{heartbeatMin: 40 * time.Second, heartbeatMax: 10 * time.Second}.normalized()
	if got.heartbeatMax != got.heartbeatMin {
		t.Fatalf("heartbeatMax = %v, want %v", got.heartbeatMax, got.heartbeatMin)
	}
}

func TestIdleCloseDeadlineJitter(t *testing.T) {
	base := 100 * time.Second

	if got := idleCloseDeadline(base, func() float64 { return 0 }); got != 70*time.Second {
		t.Fatalf("minimum jitter deadline = %v, want 70s", got)
	}
	if got := idleCloseDeadline(base, func() float64 { return 0.5 }); got != 100*time.Second {
		t.Fatalf("mid jitter deadline = %v, want 100s", got)
	}
	got := idleCloseDeadline(base, func() float64 { return 0.999999 })
	if got < 129*time.Second || got > 130*time.Second {
		t.Fatalf("maximum jitter deadline = %v, want 129s..130s", got)
	}
}

func TestHeartbeatDecisionFirstObservation(t *testing.T) {
	opts := testPoolOptions()
	now := time.Unix(1000, 0)

	action, st := heartbeatDecision(now, now, time.Time{}, heartbeatState{}, opts, fixedMinRand)
	if action != heartbeatIdle {
		t.Fatalf("action = %v, want heartbeatIdle", action)
	}
	if want := now.Add(opts.heartbeatMin); !st.nextPing.Equal(want) {
		t.Fatalf("nextPing = %v, want %v", st.nextPing, want)
	}
	if !st.awaitingSince.IsZero() {
		t.Fatalf("awaitingSince = %v, want zero", st.awaitingSince)
	}
}

func TestHeartbeatDecisionSendsWhenDue(t *testing.T) {
	opts := testPoolOptions()
	base := time.Unix(1000, 0)
	now := base.Add(60 * time.Second)

	action, st := heartbeatDecision(now, base, time.Time{}, heartbeatState{nextPing: base.Add(25 * time.Second)}, opts, fixedMinRand)
	if action != heartbeatSend {
		t.Fatalf("action = %v, want heartbeatSend", action)
	}
	if !st.awaitingSince.Equal(now) {
		t.Fatalf("awaitingSince = %v, want %v", st.awaitingSince, now)
	}
	if want := now.Add(opts.heartbeatMin); !st.nextPing.Equal(want) {
		t.Fatalf("nextPing = %v, want %v", st.nextPing, want)
	}
}

func TestHeartbeatDecisionWaitsForPong(t *testing.T) {
	opts := testPoolOptions()
	base := time.Unix(1000, 0)
	now := base.Add(30 * time.Second)
	st := heartbeatState{awaitingSince: base, nextPing: base.Add(25 * time.Second)}

	action, next := heartbeatDecision(now, base, time.Time{}, st, opts, fixedMinRand)
	if action != heartbeatIdle {
		t.Fatalf("action = %v, want heartbeatIdle", action)
	}
	if !next.awaitingSince.Equal(base) {
		t.Fatalf("awaitingSince = %v, want %v", next.awaitingSince, base)
	}

	// No pong within HeartbeatTimeout: the session is declared dead.
	late := base.Add(opts.heartbeatTimeout + time.Second)
	action, _ = heartbeatDecision(late, base, time.Time{}, st, opts, fixedMinRand)
	if action != heartbeatClose {
		t.Fatalf("action after timeout = %v, want heartbeatClose", action)
	}
}

func TestHeartbeatDecisionPongClearsOutstanding(t *testing.T) {
	opts := testPoolOptions()
	base := time.Unix(1000, 0)
	lastActive := base.Add(time.Second)
	st := heartbeatState{awaitingSince: base, nextPing: base.Add(25 * time.Second)}

	action, next := heartbeatDecision(base.Add(2*time.Second), lastActive, lastActive, st, opts, fixedMinRand)
	if action != heartbeatIdle {
		t.Fatalf("action = %v, want heartbeatIdle", action)
	}
	if !next.awaitingSince.IsZero() {
		t.Fatalf("awaitingSince = %v, want zero", next.awaitingSince)
	}
	if want := lastActive.Add(opts.heartbeatMin); !next.nextPing.Equal(want) {
		t.Fatalf("nextPing = %v, want %v", next.nextPing, want)
	}
}

func TestHeartbeatDecisionSuppressedByTraffic(t *testing.T) {
	opts := testPoolOptions()
	base := time.Unix(1000, 0)
	now := base.Add(10 * time.Second)
	lastActive := now.Add(-5 * time.Second)
	st := heartbeatState{nextPing: base.Add(6 * time.Second)}

	action, next := heartbeatDecision(now, lastActive, time.Time{}, st, opts, fixedMinRand)
	if action != heartbeatIdle {
		t.Fatalf("action = %v, want heartbeatIdle while traffic is recent", action)
	}
	if want := lastActive.Add(opts.heartbeatMin); !next.nextPing.Equal(want) {
		t.Fatalf("nextPing = %v, want %v", next.nextPing, want)
	}

	// A deadline still in the future is honored as-is when there is no recent
	// traffic.
	st = heartbeatState{nextPing: base.Add(25 * time.Second)}
	action, next = heartbeatDecision(now, base.Add(-time.Hour), time.Time{}, st, opts, fixedMinRand)
	if action != heartbeatIdle {
		t.Fatalf("action = %v, want heartbeatIdle before the deadline", action)
	}
	if !next.nextPing.Equal(base.Add(25 * time.Second)) {
		t.Fatalf("nextPing = %v, want %v", next.nextPing, base.Add(25*time.Second))
	}
}

func TestScheduleNextPing(t *testing.T) {
	opts := testPoolOptions()
	now := time.Unix(1000, 0)

	if got, want := scheduleNextPing(now, now, opts, fixedMinRand), now.Add(opts.heartbeatMin); !got.Equal(want) {
		t.Fatalf("scheduleNextPing = %v, want %v", got, want)
	}
	maxRand := func(min, max time.Duration) time.Duration { return max }
	if got, want := scheduleNextPing(now, now, opts, maxRand), now.Add(opts.heartbeatMax); !got.Equal(want) {
		t.Fatalf("scheduleNextPing = %v, want %v", got, want)
	}
	// A zero lastActive is anchored to now, and a future lastActive is clamped.
	got := scheduleNextPing(time.Time{}, now, opts, fixedMinRand)
	if want := now.Add(opts.heartbeatMin); !got.Equal(want) {
		t.Fatalf("scheduleNextPing(zero) = %v, want %v", got, want)
	}
	got = scheduleNextPing(now.Add(time.Hour), now, opts, fixedMinRand)
	if want := now.Add(opts.heartbeatMin); !got.Equal(want) {
		t.Fatalf("scheduleNextPing(future) = %v, want %v", got, want)
	}
}

func TestHeartbeatTickInterval(t *testing.T) {
	if got := heartbeatTickInterval(poolOptions{heartbeatMax: 55 * time.Second}); got != 5*time.Second {
		t.Fatalf("heartbeatTickInterval(55s) = %v, want 5s", got)
	}
	if got := heartbeatTickInterval(poolOptions{heartbeatMax: 4 * time.Second}); got != time.Second {
		t.Fatalf("heartbeatTickInterval(4s) = %v, want 1s", got)
	}
	if got := heartbeatTickInterval(poolOptions{heartbeatMax: time.Millisecond}); got != 250*time.Microsecond {
		t.Fatalf("heartbeatTickInterval(1ms) = %v, want 250us", got)
	}
	if got := heartbeatTickInterval(poolOptions{heartbeatMax: 0}); got != time.Millisecond {
		t.Fatalf("heartbeatTickInterval(0) = %v, want 1ms", got)
	}
}

// nopConn is an in-memory io.ReadWriteCloser used by pool tests that only need
// a live Session object, not a working frame exchange.
type nopConn struct{ bytes.Buffer }

func (c *nopConn) Close() error { return nil }

func TestPoolConcurrentFirstDial(t *testing.T) {
	var dials atomic.Int32
	pool := newSessionPool(poolOptions{}, func(context.Context) (*protocol.Session, error) {
		dials.Add(1)
		time.Sleep(20 * time.Millisecond)
		return protocol.NewSession(&nopConn{}, uint64(dials.Load())), nil
	})
	t.Cleanup(pool.Close)

	var wg sync.WaitGroup
	errCh := make(chan error, 16)
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := pool.GetOrCreateSession(context.Background())
			errCh <- err
		}()
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		if err != nil {
			t.Fatalf("GetOrCreateSession: %v", err)
		}
	}
	if got := dials.Load(); got != 1 {
		t.Fatalf("dial count = %d, want 1 (concurrent first dials must share one session)", got)
	}
	if got := pool.SessionCount(); got != 1 {
		t.Fatalf("session count = %d, want 1", got)
	}
}

// newPipeSessionForPool creates a client-side protocol.Session on one end of a
// net.Pipe and a peer goroutine on the other end. The peer acknowledges SYN and
// optionally answers heartbeats.
func newPipeSessionForPool(t *testing.T, seq uint64, answerHeartbeats bool) (*protocol.Session, *atomic.Int64) {
	t.Helper()

	clientConn, peerConn := net.Pipe()
	session := protocol.NewSession(clientConn, seq)
	var heartbeats atomic.Int64

	peerDone := make(chan struct{})
	go func() {
		defer close(peerDone)
		defer peerConn.Close()
		for {
			frame, err := protocol.DecodeFrame(peerConn)
			if err != nil {
				return
			}
			var reply *protocol.Frame
			switch frame.Command {
			case protocol.CmdSYN:
				reply = protocol.NewFrame(protocol.CmdSYNACK, frame.StreamID, nil)
			case protocol.CmdHeartRequest:
				heartbeats.Add(1)
				if answerHeartbeats {
					reply = protocol.NewFrame(protocol.CmdHeartResponse, 0, nil)
				}
			}
			if reply == nil {
				continue
			}
			if err := protocol.EncodeFrame(peerConn, reply); err != nil {
				return
			}
		}
	}()

	loopDone := make(chan struct{})
	go func() {
		defer close(loopDone)
		_ = session.RunEventLoop()
	}()

	t.Cleanup(func() {
		_ = session.Close()
		_ = peerConn.Close()
		select {
		case <-peerDone:
		case <-time.After(2 * time.Second):
			t.Log("pool test: peer goroutine did not exit")
		}
		select {
		case <-loopDone:
		case <-time.After(2 * time.Second):
			t.Log("pool test: session event loop did not exit")
		}
	})
	return session, &heartbeats
}

func TestPoolHeartbeatPongKeepsSessionAlive(t *testing.T) {
	var heartbeats *atomic.Int64
	pool := newSessionPool(poolOptions{
		heartbeatMin:     30 * time.Millisecond,
		heartbeatMax:     60 * time.Millisecond,
		heartbeatTimeout: 250 * time.Millisecond,
	}, func(context.Context) (*protocol.Session, error) {
		session, seen := newPipeSessionForPool(t, 1, true)
		heartbeats = seen
		return session, nil
	})
	t.Cleanup(pool.Close)

	session, err := pool.GetOrCreateSession(context.Background())
	if err != nil {
		t.Fatalf("GetOrCreateSession: %v", err)
	}

	time.Sleep(600 * time.Millisecond)

	if got := heartbeats.Load(); got < 2 {
		t.Fatalf("peer observed %d heartbeat requests in 600ms, want at least 2", got)
	}
	if session.IsClosed() {
		t.Fatal("session was closed although the peer answered every heartbeat")
	}
	if got := pool.SessionCount(); got != 1 {
		t.Fatalf("session count = %d, want 1 while heartbeats are answered", got)
	}
}

func TestPoolHeartbeatTimeoutClosesUnresponsiveSession(t *testing.T) {
	var heartbeats *atomic.Int64
	pool := newSessionPool(poolOptions{
		heartbeatMin:     20 * time.Millisecond,
		heartbeatMax:     40 * time.Millisecond,
		heartbeatTimeout: 80 * time.Millisecond,
	}, func(context.Context) (*protocol.Session, error) {
		session, seen := newPipeSessionForPool(t, 1, false)
		heartbeats = seen
		return session, nil
	})
	t.Cleanup(pool.Close)

	session, err := pool.GetOrCreateSession(context.Background())
	if err != nil {
		t.Fatalf("GetOrCreateSession: %v", err)
	}

	deadline := time.Now().Add(3 * time.Second)
	for pool.SessionCount() != 0 || !session.IsClosed() {
		if time.Now().After(deadline) {
			t.Fatal("unresponsive session was not closed after HeartbeatTimeout")
		}
		time.Sleep(5 * time.Millisecond)
	}
	if got := heartbeats.Load(); got < 1 {
		t.Fatalf("peer observed %d heartbeat requests, want at least 1", got)
	}
}

func TestPoolIdleCleanupSkipsActiveSessions(t *testing.T) {
	pool := newSessionPool(poolOptions{
		minIdleSession:    0,
		idleCheckInterval: 20 * time.Millisecond,
		idleTimeout:       50 * time.Millisecond,
	}, func(context.Context) (*protocol.Session, error) {
		session, _ := newPipeSessionForPool(t, 1, true)
		return session, nil
	})
	t.Cleanup(pool.Close)

	session, err := pool.GetOrCreateSession(context.Background())
	if err != nil {
		t.Fatalf("GetOrCreateSession: %v", err)
	}
	stream, err := session.OpenStream()
	if err != nil {
		t.Fatalf("OpenStream: %v", err)
	}

	// Idle cleanup must not retire a session that is carrying a stream.
	time.Sleep(200 * time.Millisecond)
	if session.IsClosed() {
		t.Fatal("session with an active stream was closed by idle cleanup")
	}
	if got := pool.SessionCount(); got != 1 {
		t.Fatalf("session count = %d, want 1 while the stream is active", got)
	}

	if err := stream.Close(); err != nil {
		t.Fatalf("stream.Close: %v", err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for pool.SessionCount() != 0 {
		if time.Now().After(deadline) {
			t.Fatal("session was not closed after its last stream went away")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestPoolCloseClosesSessions(t *testing.T) {
	pool := newSessionPool(poolOptions{}, func(context.Context) (*protocol.Session, error) {
		return protocol.NewSession(&nopConn{}, 1), nil
	})

	session, err := pool.GetOrCreateSession(context.Background())
	if err != nil {
		t.Fatalf("GetOrCreateSession: %v", err)
	}

	pool.Close()
	if !session.IsClosed() {
		t.Fatal("session was not closed by Close")
	}
	if got := pool.SessionCount(); got != 0 {
		t.Fatalf("session count after Close = %d, want 0", got)
	}
	// Close is idempotent.
	pool.Close()
}
