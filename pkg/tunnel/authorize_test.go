package tunnel

import (
	"errors"
	"net"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

var errRevoked = errors.New("key revoked on 2026-11-14")

type acceptOutcome struct {
	tunnel *Tunnel
	err    error
}

// authListener starts a PSK listener whose Authorize hook is hook, and returns it with a channel
// of every Accept outcome, refused handshakes included.
func authListener(t *testing.T, hook func(PeerInfo) error, mutate func(*TransportConfig)) (*Listener, chan acceptOutcome) {
	t.Helper()
	ln, err := Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	keys := map[string][]byte{"alice": pskBytes(1), "bob": pskBytes(50), "panic": pskBytes(90), "block": pskBytes(130)}
	cfg := DefaultTransportConfig()
	cfg.PSKLookup = func(id []byte) []byte { return keys[string(id)] }
	cfg.RequirePSK = true
	cfg.Authorize = hook
	if mutate != nil {
		mutate(&cfg)
	}
	ln.SetConfig(cfg)
	out := make(chan acceptOutcome, 4096)
	go func() {
		for {
			tun, err := ln.Accept()
			if err != nil && errors.Is(err, net.ErrClosed) {
				return
			}
			out <- acceptOutcome{tun, err}
		}
	}()
	return ln, out
}

func dialAs(t *testing.T, ln *Listener, id string, key []byte) (*Tunnel, error) {
	t.Helper()
	cfg := DefaultTransportConfig()
	cfg.PSK, cfg.PSKIdentity = key, []byte(id)
	return DialWithConfig("tcp", ln.Addr().String(), cfg)
}

func nextOutcome(t *testing.T, out chan acceptOutcome) acceptOutcome {
	t.Helper()
	select {
	case o := <-out:
		return o
	case <-time.After(30 * time.Second):
		t.Fatal("Accept returned nothing")
		return acceptOutcome{}
	}
}

func TestAuthorizeAllowsAndSeesThePeer(t *testing.T) {
	var seen atomic.Pointer[PeerInfo]
	ln, out := authListener(t, func(p PeerInfo) error { seen.Store(&p); return nil }, nil)
	client, err := dialAs(t, ln, "alice", pskBytes(1))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	o := nextOutcome(t, out)
	if o.err != nil || o.tunnel == nil {
		t.Fatalf("an allowed peer was not served: %v", o.err)
	}
	t.Cleanup(func() { _ = o.tunnel.Close() })
	p := seen.Load()
	if p == nil || string(p.Identity) != "alice" || p.Suite == 0 || p.RemoteAddr == nil {
		t.Fatalf("the hook saw %+v, want the proven identity, suite and address", p)
	}
	if err := client.Send([]byte("hi")); err != nil {
		t.Fatal(err)
	}
	o.tunnel.SetReadTimeout(10 * time.Second)
	if got, err := o.tunnel.Receive(); err != nil || string(got) != "hi" {
		t.Fatalf("an allowed tunnel is not usable: %q, %v", got, err)
	}
}

// A refusal reaches Accept as ErrPeerNotAuthorized, never as a tunnel; the reason stays on the
// server; the peer sees an ended connection and not the reason.
func TestAuthorizeRefusalNeverReachesTheApplication(t *testing.T) {
	ln, out := authListener(t, func(p PeerInfo) error {
		if string(p.Identity) == "bob" {
			return errRevoked
		}
		return nil
	}, nil)
	client, err := dialAs(t, ln, "bob", pskBytes(50))
	if err == nil {
		t.Cleanup(func() { _ = client.Close() })
		client.SetReadTimeout(10 * time.Second)
		_, err = client.Receive()
	}
	if err == nil {
		t.Fatal("a refused peer was able to read from the server")
	}
	if strings.Contains(err.Error(), "revoked") {
		t.Fatalf("the refusal reason reached the peer: %v", err)
	}
	o := nextOutcome(t, out)
	if o.tunnel != nil {
		t.Fatal("a refused peer was handed to the application")
	}
	if !errors.Is(o.err, ErrPeerNotAuthorized) || !errors.Is(o.err, errRevoked) || !strings.Contains(o.err.Error(), "revoked") {
		t.Fatalf("Accept reported %v, want ErrPeerNotAuthorized with the reason", o.err)
	}
}

// A hook that panics, or that never returns, refuses its own peer and nothing else: the next
// peer is still served.
func TestAuthorizeHookCannotWedgeTheAcceptLoop(t *testing.T) {
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	ln, out := authListener(t, func(p PeerInfo) error {
		switch string(p.Identity) {
		case "panic":
			panic("boom")
		case "block":
			<-release
		}
		return nil
	}, func(c *TransportConfig) { c.HandshakeTimeout = 400 * time.Millisecond })

	for _, id := range []struct {
		name string
		key  []byte
	}{{"panic", pskBytes(90)}, {"block", pskBytes(130)}} {
		c, err := dialAs(t, ln, id.name, id.key)
		if err == nil {
			t.Cleanup(func() { _ = c.Close() })
		}
		o := nextOutcome(t, out)
		if o.tunnel != nil || !errors.Is(o.err, ErrPeerNotAuthorized) {
			t.Fatalf("%s: got tunnel=%v err=%v, want a refusal", id.name, o.tunnel != nil, o.err)
		}
	}
	client, err := dialAs(t, ln, "alice", pskBytes(1))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	o := nextOutcome(t, out)
	if o.err != nil || o.tunnel == nil {
		t.Fatalf("a peer after a panicking and a blocking hook was not served: %v", o.err)
	}
	_ = o.tunnel.Close()
}

// Many refusals must leave no goroutine, pending slot or connection behind. The pending limit is
// 8 and 300 peers are refused, so a leaked slot would shed the peer that follows.
func TestAuthorizeRefusalChurnLeavesNothingBehind(t *testing.T) {
	var allow atomic.Bool
	ln, out := authListener(t, func(PeerInfo) error {
		if allow.Load() {
			return nil
		}
		return errors.New("no")
	}, func(c *TransportConfig) { c.MaxPendingHandshakes = 8 })
	base := runtime.NumGoroutine()
	for range 300 {
		c, err := dialAs(t, ln, "bob", pskBytes(50))
		if err == nil {
			_ = c.Close()
		}
		if o := nextOutcome(t, out); o.tunnel != nil || !errors.Is(o.err, ErrPeerNotAuthorized) {
			t.Fatalf("got tunnel=%v err=%v, want a refusal", o.tunnel != nil, o.err)
		}
	}
	allow.Store(true)
	client, err := dialAs(t, ln, "bob", pskBytes(50))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	if o := nextOutcome(t, out); o.err != nil || o.tunnel == nil {
		t.Fatalf("a pending slot leaked: the peer after 300 refusals was not served: %v", o.err)
	} else {
		_ = o.tunnel.Close()
	}
	_ = client.Close()
	for deadline := time.Now().Add(10 * time.Second); runtime.NumGoroutine() > base+4; time.Sleep(10 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("%d goroutines after the churn, %d before", runtime.NumGoroutine(), base)
		}
	}
}
