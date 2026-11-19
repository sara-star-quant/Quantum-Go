package tunnel

import (
	"net"
	"strings"
	"testing"
	"time"
)

// limitObserver records which sources the rate limits turned away.
type limitObserver struct {
	connections []string
	handshakes  []string
}

func (o *limitObserver) OnConnectionRateLimit(ip string) { o.connections = append(o.connections, ip) }
func (o *limitObserver) OnHandshakeRateLimit(ip string)  { o.handshakes = append(o.handshakes, ip) }

// The per-IP limit must turn the next connection away: close it, tell the observer which source
// it came from, and return a rate-limit error. A connection under the limit must come back
// wrapped so that closing it frees its slot, and a listener with no limit must pass it through.
func TestCheckIPRateLimitTurnsAwayTheNextConnection(t *testing.T) {
	newConn := func() (*closeSpy, net.Conn) {
		a, b := net.Pipe()
		t.Cleanup(func() { _ = a.Close(); _ = b.Close() })
		return &closeSpy{Conn: a}, b
	}

	t.Run("no limiter passes the connection through", func(t *testing.T) {
		conn, _ := newConn()
		got, err := (&Listener{}).checkIPRateLimit(conn, "192.0.2.1")
		if err != nil || got != net.Conn(conn) {
			t.Fatalf("got %v, %v; want the same connection and no error", got, err)
		}
	})

	t.Run("limit of one", func(t *testing.T) {
		obs := &limitObserver{}
		cfg := DefaultTransportConfig()
		cfg.RateLimitObserver = obs
		l := &Listener{config: cfg, ipLimiter: NewIPRateLimiter(1)}

		first, _ := newConn()
		admitted, err := l.checkIPRateLimit(first, "192.0.2.1")
		if err != nil {
			t.Fatalf("first connection: %v", err)
		}
		if _, wrapped := admitted.(*rateLimitedConn); !wrapped || first.closed {
			t.Fatalf("first connection: wrapped=%v closed=%v, want wrapped and open", wrapped, first.closed)
		}

		second, _ := newConn()
		got, err := l.checkIPRateLimit(second, "192.0.2.1")
		if err == nil || got != nil {
			t.Fatalf("second connection from the same address: conn=%v err=%v, want a refusal", got, err)
		}
		if !isProtocolError(err) || !strings.Contains(err.Error(), "connection rate limit exceeded") {
			t.Fatalf("refusal = %v, want a protocol error naming the connection rate limit", err)
		}
		if !second.closed {
			t.Fatal("the refused connection was left open")
		}
		if len(obs.connections) != 1 || obs.connections[0] != "192.0.2.1" {
			t.Fatalf("observer saw %v, want one report for 192.0.2.1", obs.connections)
		}

		other, _ := newConn()
		if _, err := l.checkIPRateLimit(other, "192.0.2.2"); err != nil {
			t.Fatalf("a different address was refused: %v", err)
		}

		_ = admitted.Close() // frees the slot
		third, _ := newConn()
		if _, err := l.checkIPRateLimit(third, "192.0.2.1"); err != nil {
			t.Fatalf("after the first connection closed, the address is still refused: %v", err)
		}
	})
}

// A responder that is over the handshake rate limit must not run the handshake: it closes the
// connection, reports the source, and fails the session. The first handshake spends the burst.
func TestPerformHandshakeRateLimitRefusesBeforeAnyWork(t *testing.T) {
	obs := &limitObserver{}
	cfg := DefaultTransportConfig()
	cfg.RateLimitObserver = obs
	cfg.HandshakeTimeout = 200 * time.Millisecond // if the guard is ever deleted, fail fast instead of waiting out the default
	limiter := NewHandshakeLimiter(0.001, 1)      // one handshake, then none for a thousand seconds
	if !limiter.AllowHandshake() {
		t.Fatal("the burst should admit the first handshake")
	}
	l := &Listener{config: cfg, handshakeLimiter: limiter}

	session, err := NewSession(RoleResponder)
	if err != nil {
		t.Fatal(err)
	}
	rec := &recObserver{}
	session.SetObserver(rec)

	a, b := net.Pipe()
	t.Cleanup(func() { _ = b.Close() })
	conn := &closeSpy{Conn: a}

	err = l.performHandshake(session, conn, "198.51.100.9")
	if err == nil || !isProtocolError(err) || !strings.Contains(err.Error(), "handshake rate limit exceeded") {
		t.Fatalf("performHandshake = %v, want a protocol error naming the handshake rate limit", err)
	}
	if !conn.closed {
		t.Fatal("the refused connection was left open")
	}
	if len(obs.handshakes) != 1 || obs.handshakes[0] != "198.51.100.9" {
		t.Fatalf("observer saw %v, want one report for 198.51.100.9", obs.handshakes)
	}
	if len(rec.calls) != 2 || rec.calls[0] != "failed" || rec.calls[1] != "end" {
		t.Fatalf("session observer calls = %v, want failed then end", rec.calls)
	}
}
