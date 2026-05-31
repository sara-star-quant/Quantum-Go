package tunnel

import (
	"testing"
	"time"
)

// cookieAddr is a minimal net.Addr for cookie-binding tests.
type cookieAddr string

func (a cookieAddr) Network() string { return "udp" }
func (a cookieAddr) String() string  { return string(a) }

func TestCookieRoundTrip(t *testing.T) {
	cs, err := newCookieSigner(nil)
	if err != nil {
		t.Fatalf("newCookieSigner: %v", err)
	}
	addr := cookieAddr("203.0.113.7:5000")
	cookie := cs.issue(addr)
	if len(cookie) != cookieSize {
		t.Fatalf("cookie size = %d, want %d", len(cookie), cookieSize)
	}
	if !cs.verify(addr, cookie) {
		t.Fatal("freshly issued cookie failed verification")
	}
}

func TestCookieRejectsWrongAddr(t *testing.T) {
	cs, err := newCookieSigner(nil)
	if err != nil {
		t.Fatalf("newCookieSigner: %v", err)
	}
	cookie := cs.issue(cookieAddr("203.0.113.7:5000"))
	if cs.verify(cookieAddr("203.0.113.8:5000"), cookie) {
		t.Fatal("cookie verified for a different address")
	}
}

func TestCookieExpiry(t *testing.T) {
	clk := time.Unix(1_700_000_000, 0)
	cs, err := newCookieSigner(func() time.Time { return clk })
	if err != nil {
		t.Fatalf("newCookieSigner: %v", err)
	}
	addr := cookieAddr("203.0.113.7:5000")
	cookie := cs.issue(addr)

	clk = clk.Add(cookieLifetime - time.Second)
	if !cs.verify(addr, cookie) {
		t.Fatal("cookie expired before its lifetime")
	}
	clk = clk.Add(2 * time.Second)
	if cs.verify(addr, cookie) {
		t.Fatal("cookie verified past its lifetime")
	}
}

func TestCookieRejectsFutureTimestamp(t *testing.T) {
	clk := time.Unix(1_700_000_000, 0)
	cs, err := newCookieSigner(func() time.Time { return clk })
	if err != nil {
		t.Fatalf("newCookieSigner: %v", err)
	}
	addr := cookieAddr("203.0.113.7:5000")
	cookie := cs.issue(addr)
	// Rewind the clock so the cookie appears issued in the future.
	clk = clk.Add(-time.Minute)
	if cs.verify(addr, cookie) {
		t.Fatal("cookie with a future timestamp verified")
	}
}

func TestCookieRejectsTamper(t *testing.T) {
	cs, err := newCookieSigner(nil)
	if err != nil {
		t.Fatalf("newCookieSigner: %v", err)
	}
	addr := cookieAddr("203.0.113.7:5000")
	cookie := cs.issue(addr)
	cookie[len(cookie)-1] ^= 0xff
	if cs.verify(addr, cookie) {
		t.Fatal("tampered cookie verified")
	}
}

func TestCookieRejectsBadLength(t *testing.T) {
	cs, err := newCookieSigner(nil)
	if err != nil {
		t.Fatalf("newCookieSigner: %v", err)
	}
	addr := cookieAddr("203.0.113.7:5000")
	if cs.verify(addr, nil) {
		t.Fatal("nil cookie verified")
	}
	if cs.verify(addr, cs.issue(addr)[:cookieSize-1]) {
		t.Fatal("short cookie verified")
	}
}

func TestCookieDistinctSecrets(t *testing.T) {
	a, err := newCookieSigner(nil)
	if err != nil {
		t.Fatalf("newCookieSigner: %v", err)
	}
	b, err := newCookieSigner(nil)
	if err != nil {
		t.Fatalf("newCookieSigner: %v", err)
	}
	addr := cookieAddr("203.0.113.7:5000")
	if b.verify(addr, a.issue(addr)) {
		t.Fatal("cookie issued by one signer verified by another")
	}
}
