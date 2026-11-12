package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func nopLog(string, ...any) {}

func writeSecret(t *testing.T, name, content string, mode os.FileMode) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, mode); err != nil { // WriteFile applies the umask, which would hide the mode under test
		t.Fatal(err)
	}
	return p
}

func randomPSK(t *testing.T) string {
	t.Helper()
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(b)
}

var testLimits = forwardLimits{maxConns: 64, idleTimeout: 30 * time.Second, dialTimeout: 5 * time.Second}

// startUpstream runs a TCP server that calls handle for every connection and counts them.
func startUpstream(t *testing.T, handle func(net.Conn)) (addr string, accepted *atomic.Int64) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	accepted = new(atomic.Int64)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			accepted.Add(1)
			go func() {
				defer func() { _ = c.Close() }()
				handle(c)
			}()
		}
	}()
	return ln.Addr().String(), accepted
}

func echoHandler(c net.Conn) {
	_, _ = io.Copy(c, c)
	if tc, ok := c.(*net.TCPConn); ok {
		_ = tc.CloseWrite()
	}
}

// startPair starts a server forwarder to upstream and a client forwarder in front of it, and
// returns the address an application connects to.
func startPair(t *testing.T, upstream string, srvAuth, cliAuth forwardAuth, lim forwardLimits) string {
	t.Helper()
	srvCfg, err := buildForwardConfig(true, srvAuth)
	if err != nil {
		t.Fatalf("server config: %v", err)
	}
	cliCfg, err := buildForwardConfig(false, cliAuth)
	if err != nil {
		t.Fatalf("client config: %v", err)
	}
	srv, err := startForwardServer("127.0.0.1:0", upstream, srvCfg, lim, nopLog)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = srv.Close() })
	cli, err := startForwardClient("127.0.0.1:0", srv.Addr().String(), cliCfg, lim, nopLog)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cli.Close() })
	return cli.Addr().String()
}

func sharedPSKPair(t *testing.T, upstream string, lim forwardLimits) string {
	t.Helper()
	p := writeSecret(t, "psk.hex", randomPSK(t)+"\n", 0o600)
	a := forwardAuth{pskFile: p}
	return startPair(t, upstream, a, a, lim)
}

func dial(t *testing.T, addr string) *net.TCPConn {
	t.Helper()
	c, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_ = c.SetDeadline(time.Now().Add(30 * time.Second))
	t.Cleanup(func() { _ = c.Close() })
	return c.(*net.TCPConn)
}

// A client that finishes sending and then waits for the reply must still get it: the EOF
// travels through the tunnel as a frame, and the reply travels back.
func TestForwardHalfClose(t *testing.T) {
	up, _ := startUpstream(t, func(c net.Conn) {
		data, _ := io.ReadAll(c) // returns only after the client's EOF arrives
		_, _ = c.Write([]byte("got:" + string(data)))
	})
	c := dial(t, sharedPSKPair(t, up, testLimits))
	if _, err := c.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	if err := c.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	reply, err := io.ReadAll(c)
	if err != nil {
		t.Fatal(err)
	}
	if string(reply) != "got:hello" {
		t.Fatalf("reply %q, want %q", reply, "got:hello")
	}
}

func TestForwardLargeTransferIntegrity(t *testing.T) {
	up, _ := startUpstream(t, echoHandler)
	c := dial(t, sharedPSKPair(t, up, testLimits))

	const total = 20 << 20
	want := sha256.New()
	chunk := make([]byte, 64<<10)
	werr := make(chan error, 1)
	go func() {
		defer func() { _ = c.CloseWrite() }()
		for sent := 0; sent < total; sent += len(chunk) {
			_, _ = rand.Read(chunk)
			want.Write(chunk)
			if _, err := c.Write(chunk); err != nil {
				werr <- err
				return
			}
		}
		werr <- nil
	}()
	got := sha256.New()
	n, err := io.Copy(got, c)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if err := <-werr; err != nil {
		t.Fatalf("write: %v", err)
	}
	if n != total || hex.EncodeToString(got.Sum(nil)) != hex.EncodeToString(want.Sum(nil)) {
		t.Fatalf("read back %d bytes (want %d) or the hash differs", n, total)
	}
}

func TestForwardConcurrentConnections(t *testing.T) {
	up, _ := startUpstream(t, echoHandler)
	addr := sharedPSKPair(t, up, testLimits)
	var wg sync.WaitGroup
	errs := make(chan string, 50)
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c, err := net.DialTimeout("tcp", addr, 5*time.Second)
			if err != nil {
				errs <- err.Error()
				return
			}
			defer func() { _ = c.Close() }()
			_ = c.SetDeadline(time.Now().Add(30 * time.Second))
			msg := make([]byte, 100<<10)
			_, _ = rand.Read(msg)
			go func() { _, _ = c.Write(msg); _ = c.(*net.TCPConn).CloseWrite() }()
			back, err := io.ReadAll(c)
			if err != nil || string(back) != string(msg) {
				errs <- "echo mismatch"
			}
		}()
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		t.Error(e)
	}
}

// HTTP/1.1 and unencrypted HTTP/2 (the transport gRPC uses) both cross a pair unchanged.
// Both come from the standard library, so no extra module is needed.
func TestForwardHTTP(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "proto="+r.Proto)
	})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	serverProtocols := new(http.Protocols)
	serverProtocols.SetHTTP1(true)
	serverProtocols.SetUnencryptedHTTP2(true)
	srv := &http.Server{Handler: handler, Protocols: serverProtocols, ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Shutdown(context.Background()) })
	addr := sharedPSKPair(t, ln.Addr().String(), testLimits)

	get := func(client *http.Client) string {
		resp, err := client.Get("http://" + addr + "/")
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		b, _ := io.ReadAll(resp.Body)
		return string(b)
	}
	h1 := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{}}
	if got := get(h1); got != "proto=HTTP/1.1" {
		t.Fatalf("HTTP/1.1 got %q", got)
	}
	clientProtocols := new(http.Protocols)
	clientProtocols.SetUnencryptedHTTP2(true) // HTTP/2 with prior knowledge, as gRPC does
	h2 := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{Protocols: clientProtocols}}
	if got := get(h2); got != "proto=HTTP/2.0" {
		t.Fatalf("HTTP/2 got %q", got)
	}
}

func TestForwardWrongPSKIsRejected(t *testing.T) {
	up, accepted := startUpstream(t, echoHandler)
	srvAuth := forwardAuth{pskFile: writeSecret(t, "s.hex", randomPSK(t), 0o600)}
	cliAuth := forwardAuth{pskFile: writeSecret(t, "c.hex", randomPSK(t), 0o600)}
	c := dial(t, startPair(t, up, srvAuth, cliAuth, testLimits))
	_, _ = c.Write([]byte("hello"))
	_ = c.SetReadDeadline(time.Now().Add(10 * time.Second))
	if n, err := c.Read(make([]byte, 16)); err == nil || n != 0 {
		t.Fatalf("a client with the wrong PSK got %d bytes back, err %v", n, err)
	}
	if accepted.Load() != 0 {
		t.Fatalf("the upstream saw %d connections from an unauthenticated client", accepted.Load())
	}
}

func TestForwardPerClientIdentities(t *testing.T) {
	up, _ := startUpstream(t, echoHandler)
	aliceKey, bobKey := randomPSK(t), randomPSK(t)
	clients := writeSecret(t, "clients.txt", "# two clients\nalice "+aliceKey+"\nbob "+bobKey+"\n", 0o600)
	srvAuth := forwardAuth{clientsFile: clients}

	ok := func(identity, key string) bool {
		p := writeSecret(t, identity+".hex", key, 0o600)
		addr := startPair(t, up, srvAuth, forwardAuth{pskFile: p, identity: identity}, testLimits)
		c := dial(t, addr)
		_ = c.SetDeadline(time.Now().Add(10 * time.Second))
		_, _ = c.Write([]byte("ping"))
		_ = c.CloseWrite()
		back, err := io.ReadAll(c)
		return err == nil && string(back) == "ping"
	}
	if !ok("alice", aliceKey) || !ok("bob", bobKey) {
		t.Fatal("a listed client could not connect")
	}
	if ok("mallory", randomPSK(t)) {
		t.Fatal("an unlisted identity connected")
	}
	if ok("alice", bobKey) {
		t.Fatal("alice connected with bob's key")
	}
}

func TestForwardRefusesToStartWithoutAuth(t *testing.T) {
	if _, err := buildForwardConfig(true, forwardAuth{}); err == nil {
		t.Fatal("the server started without any authentication")
	}
	if _, err := buildForwardConfig(false, forwardAuth{}); err == nil {
		t.Fatal("the client started without a PSK")
	}
	if _, err := buildForwardConfig(true, forwardAuth{insecure: true}); err != nil {
		t.Fatalf("--insecure-no-auth was refused: %v", err)
	}
}

func TestForwardMaxConnections(t *testing.T) {
	up, _ := startUpstream(t, echoHandler)
	lim := testLimits
	lim.maxConns = 2
	addr := sharedPSKPair(t, up, lim)

	roundTrip := func(c *net.TCPConn) bool {
		_ = c.SetDeadline(time.Now().Add(5 * time.Second))
		if _, err := c.Write([]byte("x")); err != nil {
			return false
		}
		b := make([]byte, 1)
		_, err := io.ReadFull(c, b)
		return err == nil
	}
	a, b := dial(t, addr), dial(t, addr)
	if !roundTrip(a) || !roundTrip(b) {
		t.Fatal("the first two connections should work")
	}
	third := dial(t, addr)
	if roundTrip(third) {
		t.Fatal("a third connection got through a limit of two")
	}
	_ = a.Close()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if roundTrip(dial(t, addr)) {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("a slot never freed after a connection closed")
}

func TestForwardIdleTimeout(t *testing.T) {
	up, _ := startUpstream(t, echoHandler)
	lim := testLimits
	lim.idleTimeout = 400 * time.Millisecond
	c := dial(t, sharedPSKPair(t, up, lim))
	_, _ = c.Write([]byte("x"))
	start := time.Now()
	_ = c.SetReadDeadline(time.Now().Add(10 * time.Second))
	_, _ = io.ReadFull(c, make([]byte, 1)) // the echo
	_, err := io.ReadAll(c)                // then silence until the idle timeout closes it
	if err != nil && !strings.Contains(err.Error(), "reset") {
		t.Logf("read ended with %v", err)
	}
	if d := time.Since(start); d > 6*time.Second {
		t.Fatalf("an idle connection stayed open %v with a 400ms idle timeout", d)
	}
}

func TestForwardUpstreamDown(t *testing.T) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	dead := ln.Addr().String()
	_ = ln.Close() // nothing listens here now
	c := dial(t, sharedPSKPair(t, dead, testLimits))
	_, _ = c.Write([]byte("hello"))
	start := time.Now()
	_ = c.SetReadDeadline(time.Now().Add(10 * time.Second))
	_, _ = io.ReadAll(c)
	if d := time.Since(start); d > 8*time.Second {
		t.Fatalf("the client waited %v for a dead upstream", d)
	}
}

func TestForwardKeyFiles(t *testing.T) {
	good := writeSecret(t, "good.hex", randomPSK(t)+"\n", 0o600)
	if _, err := readPSKFile(good); err != nil {
		t.Fatalf("a valid PSK file was refused: %v", err)
	}
	if runtime.GOOS != "windows" {
		for mode, accepted := range map[os.FileMode]bool{0o600: true, 0o400: true, 0o440: true, 0o640: true, 0o644: false, 0o620: false, 0o666: false} {
			p := writeSecret(t, "mode.hex", randomPSK(t), mode)
			_, err := readPSKFile(p)
			if accepted && err != nil {
				t.Fatalf("mode %#o was refused: %v", mode, err)
			}
			if !accepted && (err == nil || !strings.Contains(err.Error(), "chmod 600")) {
				t.Fatalf("mode %#o was accepted: %v", mode, err)
			}
		}
	}
	short := writeSecret(t, "short.hex", "abcd", 0o600)
	if _, err := readPSKFile(short); err == nil {
		t.Fatal("a short PSK was accepted")
	}
	notHex := writeSecret(t, "nothex.hex", strings.Repeat("zz", 32), 0o600)
	if _, err := readPSKFile(notHex); err == nil {
		t.Fatal("a non-hex PSK was accepted")
	}
	bad := writeSecret(t, "bad.txt", "alice\n", 0o600)
	if _, err := readClientsFile(bad); err == nil {
		t.Fatal("a malformed clients line was accepted")
	}
	empty := writeSecret(t, "empty.txt", "# nobody\n", 0o600)
	if _, err := readClientsFile(empty); err == nil {
		t.Fatal("an empty clients file was accepted")
	}
}

func TestLoopbackHost(t *testing.T) {
	for in, want := range map[string]string{
		":8080":          "127.0.0.1:8080",
		"0.0.0.0:80":     "0.0.0.0:80",
		"127.0.0.1:9000": "127.0.0.1:9000",
	} {
		if got, err := loopbackHost(in); err != nil || got != want {
			t.Errorf("loopbackHost(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	if _, err := loopbackHost("no-port"); err == nil {
		t.Error("an address without a port was accepted")
	}
}

// A download with a silent client is not idle: the upstream keeps sending for longer than the
// idle timeout and the connection must survive to the end.
func TestForwardOneWayTrafficIsNotIdle(t *testing.T) {
	up, _ := startUpstream(t, func(c net.Conn) {
		for range 8 {
			_, _ = c.Write([]byte("tick"))
			time.Sleep(150 * time.Millisecond)
		}
	})
	lim := testLimits
	lim.idleTimeout = 500 * time.Millisecond // shorter than the 1.2s the upstream streams for
	c := dial(t, sharedPSKPair(t, up, lim))
	data, err := io.ReadAll(c)
	if err != nil || len(data) != 32 {
		t.Fatalf("got %d bytes, err %v; want all 32 bytes with a clean end", len(data), err)
	}
}

func TestForwardRejectsConflictingAuthFlags(t *testing.T) {
	p := writeSecret(t, "psk.hex", randomPSK(t)+"\n", 0o600)
	if _, err := buildForwardConfig(false, forwardAuth{insecure: true, pskFile: p}); err == nil {
		t.Fatal("--insecure-no-auth with --psk-file was accepted and would ignore the PSK")
	}
}

func TestForwardRefusesLaxServerKeyFile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows permission bits carry no meaning, so the check does not run there")
	}
	psk := writeSecret(t, "psk.hex", randomPSK(t)+"\n", 0o600)
	key := writeSecret(t, "server.key", "not read", 0o644)
	_, err := buildForwardConfig(true, forwardAuth{pskFile: psk, serverKey: key})
	if err == nil || !strings.Contains(err.Error(), "chmod 600") {
		t.Fatalf("a 0644 --server-key was not refused with a chmod hint: %v", err)
	}
}

func TestReadClientsFileRejectsDuplicateIdentity(t *testing.T) {
	k := randomPSK(t)
	p := writeSecret(t, "clients.txt", "alice "+k+"\nalice "+k+"\n", 0o600)
	if _, err := readClientsFile(p); err == nil || !strings.Contains(err.Error(), "twice") {
		t.Fatalf("a duplicate identity was accepted: %v", err)
	}
}

// A key rotation by SIGHUP: open connections keep working, a client that still holds the old
// key is refused once the server reloads, and a bad file leaves the current keys in place.
func TestForwardReloadRotatesKeys(t *testing.T) {
	up, _ := startUpstream(t, echoHandler)
	pskPath := writeSecret(t, "psk.hex", randomPSK(t)+"\n", 0o600)
	auth := forwardAuth{pskFile: pskPath}

	srvCfg, err := buildForwardConfig(true, auth)
	if err != nil {
		t.Fatal(err)
	}
	srv, err := startForwardServer("127.0.0.1:0", up, srvCfg, testLimits, nopLog)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = srv.Close() })
	cliCfg, err := buildForwardConfig(false, auth)
	if err != nil {
		t.Fatal(err)
	}
	cli, err := startForwardClient("127.0.0.1:0", srv.Addr().String(), cliCfg, testLimits, nopLog)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cli.Close() })

	roundTrip := func(c *net.TCPConn) bool {
		_ = c.SetDeadline(time.Now().Add(5 * time.Second))
		if _, err := c.Write([]byte("x")); err != nil {
			return false
		}
		_, err := io.ReadFull(c, make([]byte, 1))
		return err == nil
	}
	open := dial(t, cli.Addr().String())
	if !roundTrip(open) {
		t.Fatal("the first connection should work")
	}

	// A bad file: the rebuild fails, so nothing is swapped and the old keys still work.
	if err := os.WriteFile(pskPath, []byte("not a key"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := buildForwardConfig(true, auth); err == nil {
		t.Fatal("a corrupt PSK file was accepted on reload")
	}
	if !roundTrip(dial(t, cli.Addr().String())) {
		t.Fatal("a failed reload broke the current keys")
	}

	// Rotate: write a new key and reload the server only.
	if err := os.WriteFile(pskPath, []byte(randomPSK(t)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	next, err := buildForwardConfig(true, auth)
	if err != nil {
		t.Fatal(err)
	}
	srv.Reload(next)
	if !roundTrip(open) {
		t.Fatal("an open connection died on reload")
	}
	if roundTrip(dial(t, cli.Addr().String())) {
		t.Fatal("a client with the old key got through after the server reloaded")
	}

	// Reload the client too: new connections work again.
	nextCli, err := buildForwardConfig(false, auth)
	if err != nil {
		t.Fatal(err)
	}
	cli.Reload(nextCli)
	if !roundTrip(dial(t, cli.Addr().String())) {
		t.Fatal("a connection with the rotated key failed")
	}
}

func TestForwardServerRefusesSameIdentityInBothFiles(t *testing.T) {
	k := randomPSK(t)
	psk := writeSecret(t, "psk.hex", k+"\n", 0o600)
	clients := writeSecret(t, "clients.txt", "default "+k+"\n", 0o600)
	if _, err := buildForwardConfig(true, forwardAuth{pskFile: psk, clientsFile: clients}); err == nil {
		t.Fatal("an identity in both files was accepted, so which key wins would be unclear")
	}
}

// reloadKeys is what SIGHUP runs: a bad file keeps the current keys, and a server ignores
// --server-key so a broken key file cannot block a PSK rotation.
func TestReloadKeys(t *testing.T) {
	up, _ := startUpstream(t, echoHandler)
	psk := writeSecret(t, "psk.hex", randomPSK(t)+"\n", 0o600)
	auth := forwardAuth{pskFile: psk}
	srvCfg, err := buildForwardConfig(true, auth)
	if err != nil {
		t.Fatal(err)
	}
	srv, err := startForwardServer("127.0.0.1:0", up, srvCfg, testLimits, nopLog)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = srv.Close() })
	before := srv.cfg.Load()

	if err := os.WriteFile(psk, []byte("junk"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := reloadKeys(srv, true, auth, nopLog); err == nil {
		t.Fatal("a corrupt file was reloaded")
	}
	if srv.cfg.Load() != before {
		t.Fatal("a failed reload replaced the config")
	}

	if err := os.WriteFile(psk, []byte(randomPSK(t)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	auth.serverKey = filepath.Join(t.TempDir(), "missing.key") // a server reload must not read it
	if err := reloadKeys(srv, true, auth, nopLog); err != nil {
		t.Fatalf("a good PSK file was refused because of --server-key: %v", err)
	}
	if srv.cfg.Load() == before {
		t.Fatal("a good reload did not swap the config")
	}
}

func TestForwardRejectsBadIdentity(t *testing.T) {
	psk := writeSecret(t, "psk.hex", randomPSK(t)+"\n", 0o600)
	if _, err := buildForwardConfig(true, forwardAuth{pskFile: psk, identity: strings.Repeat("x", 256)}); err == nil {
		t.Fatal("a 256-byte identity was accepted")
	}
	clients := writeSecret(t, "clients.txt", strings.Repeat("x", 256)+" "+randomPSK(t)+"\n", 0o600)
	if _, err := readClientsFile(clients); err == nil {
		t.Fatal("a 256-byte client identity was accepted")
	}
}
