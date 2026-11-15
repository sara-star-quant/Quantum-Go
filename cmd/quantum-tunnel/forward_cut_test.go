package main

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sara-star-quant/quantum-go/pkg/tunnel"
)

type cutFixture struct {
	srv     *forwarder
	auth    forwardAuth
	clients string
	keys    map[string]string
	logMu   sync.Mutex
	lines   []string
}

func (c *cutFixture) writeClients(t *testing.T) {
	t.Helper()
	var s string
	for _, id := range []string{"alice", "bob"} {
		if k, ok := c.keys[id]; ok {
			s += fmt.Sprintf("%s %s\n", id, k)
		}
	}
	if err := os.WriteFile(c.clients, []byte(s), 0o600); err != nil {
		t.Fatal(err)
	}
}

func newCutFixture(t *testing.T, lim forwardLimits) *cutFixture {
	t.Helper()
	up, _ := startUpstream(t, echoHandler)
	c := &cutFixture{keys: map[string]string{"alice": randomPSK(t), "bob": randomPSK(t)}}
	c.clients = writeSecret(t, "clients.txt", "", 0o600)
	c.writeClients(t)
	c.auth = forwardAuth{clientsFile: c.clients}
	cfg, err := buildForwardConfig(true, c.auth)
	if err != nil {
		t.Fatal(err)
	}
	c.srv, err = startForwardServer("127.0.0.1:0", up, cfg, lim, c.logf)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.srv.Close() })
	return c
}

// connect opens a tunnel to the server as identity, with the key the fixture holds for it now.
func (c *cutFixture) connect(t *testing.T, identity, keyHex string) *tunnel.Tunnel {
	t.Helper()
	return connectTo(t, c.srv.Addr().String(), identity, keyHex)
}

func connectTo(t *testing.T, addr, identity, keyHex string) *tunnel.Tunnel {
	t.Helper()
	pskFile := writeSecret(t, identity+".hex", keyHex+"\n", 0o600)
	cfg, err := buildForwardConfig(false, forwardAuth{pskFile: pskFile, identity: identity})
	if err != nil {
		t.Fatal(err)
	}
	tn, err := tunnel.DialWithConfig("tcp", addr, cfg)
	if err != nil {
		t.Fatalf("%s: dial: %v", identity, err)
	}
	t.Cleanup(func() { _ = tn.Close() })
	tn.SetReadTimeout(10 * time.Second)
	return tn
}

// roundTrip sends one byte through the echo upstream and reports whether it came back.
func roundTrip(tn *tunnel.Tunnel) bool {
	if err := tn.Send([]byte{frameData, 'x'}); err != nil {
		return false
	}
	data, err := tn.Receive()
	return err == nil && len(data) == 2 && data[0] == frameData
}

// waitCut polls for the event, the connection ending, and reports whether it ended in time.
func waitCut(tn *tunnel.Tunnel, within time.Duration) bool {
	for deadline := time.Now().Add(within); time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
		if !roundTrip(tn) {
			return true
		}
	}
	return false
}

func (c *cutFixture) reload(t *testing.T) {
	t.Helper()
	if err := reloadKeys(c.srv, true, c.auth, c.logf); err != nil {
		t.Fatal(err)
	}
}

func (c *cutFixture) logf(format string, args ...any) {
	c.logMu.Lock()
	defer c.logMu.Unlock()
	c.lines = append(c.lines, fmt.Sprintf(format, args...))
}

func (c *cutFixture) logged(substr string) bool {
	c.logMu.Lock()
	defer c.logMu.Unlock()
	for _, l := range c.lines {
		if strings.Contains(l, substr) {
			return true
		}
	}
	return false
}

// A removed identity is cut while it is mid-session; an identity whose key did not change keeps
// working. This is the stolen-key case: rotation must end the attacker's live session.
func TestForwardReloadCutsARemovedIdentity(t *testing.T) {
	c := newCutFixture(t, testLimits)
	alice, bob := c.connect(t, "alice", c.keys["alice"]), c.connect(t, "bob", c.keys["bob"])
	if !roundTrip(alice) || !roundTrip(bob) {
		t.Fatal("both sessions should work before the reload")
	}
	delete(c.keys, "bob")
	c.writeClients(t)
	c.reload(t)
	if !waitCut(bob, 10*time.Second) {
		t.Fatal("a session whose identity was removed survived the reload")
	}
	if !c.logged("cut 1 open connections") {
		t.Fatalf("the reload did not log how many connections it cut: %q", c.lines)
	}
	if !roundTrip(alice) {
		t.Fatal("a session whose key did not change was cut")
	}
}

func TestForwardReloadCutsAChangedKey(t *testing.T) {
	c := newCutFixture(t, testLimits)
	old := c.keys["alice"]
	alice := c.connect(t, "alice", old)
	if !roundTrip(alice) {
		t.Fatal("the session should work before the reload")
	}
	c.keys["alice"] = randomPSK(t)
	c.writeClients(t)
	c.reload(t)
	if !waitCut(alice, 10*time.Second) {
		t.Fatal("a session proved with the replaced key survived the reload")
	}
	if !roundTrip(c.connect(t, "alice", c.keys["alice"])) {
		t.Fatal("a new session with the new key does not work")
	}
}

// --keep-sessions-on-reload restores the routine-rotation behavior: open sessions stay.
func TestForwardKeepSessionsOnReload(t *testing.T) {
	c := newCutFixture(t, testLimits)
	c.srv.keepSessions.Store(true)
	bob := c.connect(t, "bob", c.keys["bob"])
	if !roundTrip(bob) { // the session is registered once the upstream answers
		t.Fatal("the session should work before the reload")
	}
	delete(c.keys, "bob")
	c.writeClients(t)
	c.reload(t)
	if waitCut(bob, 1500*time.Millisecond) {
		t.Fatal("the session was cut although --keep-sessions-on-reload is set")
	}
}

// The lifetime cap ends a session that is idle and in good standing.
func TestForwardMaxSessionLifetimeClosesAnIdleSession(t *testing.T) {
	lim := testLimits
	lim.maxLifetime = 400 * time.Millisecond
	c := newCutFixture(t, lim)
	alice := c.connect(t, "alice", c.keys["alice"])
	if !waitCut(alice, 10*time.Second) {
		t.Fatal("the session outlived --max-session-lifetime")
	}
}

// Sessions leave no trace in the registry once they end.
func TestForwardSessionRegistryEmptiesAfterChurn(t *testing.T) {
	c := newCutFixture(t, testLimits)
	for range 100 {
		tn := c.connect(t, "alice", c.keys["alice"])
		if !roundTrip(tn) {
			t.Fatal("a session should work")
		}
		_ = tn.Close()
	}
	for deadline := time.Now().Add(10 * time.Second); ; time.Sleep(20 * time.Millisecond) {
		c.srv.live.mu.Lock()
		n := len(c.srv.live.m)
		c.srv.live.mu.Unlock()
		if n == 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%d sessions still registered after every client closed", n)
		}
	}
}

func TestLiveSessionStale(t *testing.T) {
	key := make([]byte, 32)
	key[0] = 1
	s := &liveSession{identity: "a", keyID: tunnel.PSKFingerprint(key)}
	same := func([]byte) []byte { return key }
	other := func([]byte) []byte { k := make([]byte, 32); k[0] = 2; return k }
	gone := func([]byte) []byte { return nil }
	if s.stale(same) || !s.stale(other) || !s.stale(gone) || !s.stale(nil) {
		t.Fatal("stale must be false only when the table still holds the proved key")
	}
}

// A reload can swap the key table after a handshake finished and before the session reaches the
// registry. Such a session was never visible to the reload, so serveOne checks the current table
// itself. Here the table already lacks the identity when serveOne starts: the session must be cut.
func TestServeOneCutsASessionThatMissedTheReload(t *testing.T) {
	up, _ := startUpstream(t, echoHandler)
	aliceKey := randomPSK(t)
	handshakeCfg := tunnel.DefaultTransportConfig()
	handshakeCfg.PSKLookup = func(id []byte) []byte {
		if string(id) == "alice" {
			k, _ := decodePSK(aliceKey)
			return k
		}
		return nil
	}
	handshakeCfg.RequirePSK = true
	ln, err := tunnel.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	ln.SetConfig(handshakeCfg)
	accepted := make(chan *tunnel.Tunnel, 1)
	go func() {
		if tn, err := ln.Accept(); err == nil {
			accepted <- tn
		}
	}()
	client := connectTo(t, ln.Addr().String(), "alice", aliceKey)
	srvTunnel := <-accepted

	f := &forwarder{ops: newForwardOps()}
	newer := tunnel.DefaultTransportConfig()
	newer.PSKLookup = func([]byte) []byte { return nil } // the reload already removed alice
	f.cfg.Store(&newer)
	var logged atomic.Bool
	go serveOne(f, srvTunnel, up, testLimits, func(format string, args ...any) {
		if fmt.Sprintf(format, args...) != "" {
			logged.Store(true)
		}
	})
	if !waitCut(client, 10*time.Second) {
		t.Fatal("a session whose key was already gone from the table was served")
	}
	if !logged.Load() {
		t.Fatal("the cut was not logged")
	}
}

// A failed reload (a corrupt clients file) keeps the current keys and cuts nobody.
func TestForwardFailedReloadCutsNothing(t *testing.T) {
	c := newCutFixture(t, testLimits)
	alice := c.connect(t, "alice", c.keys["alice"])
	if !roundTrip(alice) {
		t.Fatal("the session should work before the reload")
	}
	if err := os.WriteFile(c.clients, []byte("not a clients file\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := reloadKeys(c.srv, true, c.auth, c.logf); err == nil {
		t.Fatal("a corrupt clients file was accepted")
	}
	if waitCut(alice, 1500*time.Millisecond) {
		t.Fatal("a failed reload cut a session")
	}
}

// A cut that blocks (a peer that does not read its close alert) must not hold up the reload,
// which runs on the command's signal loop.
func TestCutStaleDoesNotWaitForASlowCut(t *testing.T) {
	var r liveSessions
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	for i := range 5 {
		r.add(&liveSession{identity: fmt.Sprint("id", i), keyID: []byte{1}, cut: func() { <-release }})
	}
	done := make(chan int, 1)
	go func() { done <- r.cutStale(func([]byte) []byte { return nil }) }()
	select {
	case n := <-done:
		if n != 5 {
			t.Fatalf("cut %d sessions, want 5", n)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("cutStale waited for blocked cuts")
	}
}
