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

	"github.com/sara-star-quant/quantum-go/pkg/chkem"
	"github.com/sara-star-quant/quantum-go/pkg/tunnel"
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

// --suite x-wing moves a whole pair onto the X-Wing suite with no config edits, and the
// server needs no matching flag.
func TestForwardSuiteFlag(t *testing.T) {
	up, _ := startUpstream(t, echoHandler)
	psk := writeSecret(t, "psk.hex", randomPSK(t)+"\n", 0o600)
	cliAuth := forwardAuth{pskFile: psk, suite: "x-wing"}
	cfg, err := buildForwardConfig(false, cliAuth)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.KEMSuite != chkem.SuiteXWing {
		t.Fatalf("KEMSuite = %v, want x-wing", cfg.KEMSuite)
	}
	c := dial(t, startPair(t, up, forwardAuth{pskFile: psk}, cliAuth, testLimits))
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := c.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, 5)
	if _, err := io.ReadFull(c, got); err != nil || string(got) != "hello" {
		t.Fatalf("echo through an x-wing pair: %q, %v", got, err)
	}
	if _, err := buildForwardConfig(true, forwardAuth{pskFile: psk, suite: "x-wing"}); err == nil {
		t.Fatal("--suite on the server side was accepted")
	}
	if _, err := buildForwardConfig(false, forwardAuth{pskFile: psk, suite: "nope"}); err == nil {
		t.Fatal("an unknown suite was accepted")
	}
}

func TestDecodePSKRejectsRepeatedByte(t *testing.T) {
	if _, err := decodePSK(strings.Repeat("00", 32)); err == nil {
		t.Fatal("an all-zero PSK was accepted")
	}
	if _, err := decodePSK(strings.Repeat("ab", 32)); err == nil {
		t.Fatal("a PSK of one repeated byte was accepted")
	}
	if _, err := decodePSK(randomPSK(t)); err != nil {
		t.Fatalf("a random PSK was refused: %v", err)
	}
}

// A peer that authenticates and then sends a frame type the forwarder does not know must be
// cut off, with nothing handed to the upstream.
func TestForwardUnknownFrameTypeEndsTheConnection(t *testing.T) {
	var got atomic.Int64
	upstreamDone := make(chan struct{})
	up, _ := startUpstream(t, func(c net.Conn) {
		n, _ := io.Copy(io.Discard, c)
		got.Add(n)
		close(upstreamDone)
	})
	psk := writeSecret(t, "psk.hex", randomPSK(t)+"\n", 0o600)
	cfg, err := buildForwardConfig(true, forwardAuth{pskFile: psk})
	if err != nil {
		t.Fatal(err)
	}
	srv, err := startForwardServer("127.0.0.1:0", up, cfg, testLimits, nopLog)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = srv.Close() })

	cliCfg, err := buildForwardConfig(false, forwardAuth{pskFile: psk})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := tunnel.DialWithConfig("tcp", srv.Addr().String(), cliCfg)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = raw.Close() }()
	if err := raw.Send([]byte{0x07, 'x', 'y'}); err != nil {
		t.Fatal(err)
	}
	raw.SetReadTimeout(5 * time.Second)
	if _, err := raw.Receive(); err == nil {
		t.Fatal("the server kept the connection open after an unknown frame type")
	}
	select {
	case <-upstreamDone: // the upstream connection closed, so the byte count is final
	case <-time.After(5 * time.Second):
		t.Fatal("the upstream connection stayed open after an unknown frame type")
	}
	if got.Load() != 0 {
		t.Fatalf("the upstream received %d bytes from an unknown frame", got.Load())
	}
}

// One source address cannot hold more connections than --max-conns-per-ip allows.
func TestForwardPerIPConnectionLimit(t *testing.T) {
	up, _ := startUpstream(t, echoHandler)
	psk := writeSecret(t, "psk.hex", randomPSK(t)+"\n", 0o600)
	auth := forwardAuth{pskFile: psk}
	srvCfg, err := buildForwardConfig(true, auth)
	if err != nil {
		t.Fatal(err)
	}
	lim := testLimits
	lim.maxPerIP = 1
	srv, err := startForwardServer("127.0.0.1:0", up, srvCfg, lim, nopLog)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = srv.Close() })
	cliCfg, err := buildForwardConfig(false, auth)
	if err != nil {
		t.Fatal(err)
	}
	first, err := tunnel.DialWithConfig("tcp", srv.Addr().String(), cliCfg)
	if err != nil {
		t.Fatalf("the first connection was refused: %v", err)
	}
	defer func() { _ = first.Close() }()
	cliCfg.HandshakeTimeout = 3 * time.Second
	if second, err := tunnel.DialWithConfig("tcp", srv.Addr().String(), cliCfg); err == nil {
		_ = second.Close()
		t.Fatal("a second connection from the same address got through a limit of one")
	}

	// The slot frees when the first connection closes, so the same address can connect again.
	_ = first.Close()
	var again *tunnel.Tunnel
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); time.Sleep(100 * time.Millisecond) {
		if again, err = tunnel.DialWithConfig("tcp", srv.Addr().String(), cliCfg); err == nil {
			_ = again.Close()
			return
		}
	}
	t.Fatalf("the slot never freed after the first connection closed: %v", err)
}

func TestForwardHandshakeBurstNeverZero(t *testing.T) {
	up, _ := startUpstream(t, echoHandler)
	psk := writeSecret(t, "psk.hex", randomPSK(t)+"\n", 0o600)
	auth := forwardAuth{pskFile: psk}
	srvCfg, err := buildForwardConfig(true, auth)
	if err != nil {
		t.Fatal(err)
	}
	lim := testLimits
	lim.handshakeRate = 0.25 // slower than one every two seconds: a burst of 0 would refuse everyone
	srv, err := startForwardServer("127.0.0.1:0", up, srvCfg, lim, nopLog)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = srv.Close() })
	cliCfg, err := buildForwardConfig(false, auth)
	if err != nil {
		t.Fatal(err)
	}
	c, err := tunnel.DialWithConfig("tcp", srv.Addr().String(), cliCfg)
	if err != nil {
		t.Fatalf("a slow handshake rate refused the first handshake: %v", err)
	}
	_ = c.Close()
}

// A stranger that connects and hangs up during the handshake must not stop the forwarder.
// Two such failures in a row return the same error from Accept, and the accept loop once
// read that as a dead listener and exited.
func TestForwardSurvivesRepeatedAbortedHandshakes(t *testing.T) {
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

	for range 5 {
		c, err := net.Dial("tcp", srv.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		_ = c.Close() // hang up before sending a ClientHello
	}
	time.Sleep(300 * time.Millisecond)
	select {
	case <-srv.done:
		t.Fatal("the forwarder stopped after aborted handshakes")
	default:
	}

	cliCfg, err := buildForwardConfig(false, auth)
	if err != nil {
		t.Fatal(err)
	}
	cli, err := startForwardClient("127.0.0.1:0", srv.Addr().String(), cliCfg, testLimits, nopLog)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cli.Close() })
	c := dial(t, cli.Addr().String())
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := c.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(c, make([]byte, 1)); err != nil {
		t.Fatalf("a real client could not connect after aborted handshakes: %v", err)
	}
}

// When the listening socket itself dies, the forwarder must stop, so a supervisor restarts it
// instead of leaving a process that serves nobody.
func TestForwardStopsWhenTheListenerDies(t *testing.T) {
	up, _ := startUpstream(t, echoHandler)
	psk := writeSecret(t, "psk.hex", randomPSK(t)+"\n", 0o600)
	srvCfg, err := buildForwardConfig(true, forwardAuth{pskFile: psk})
	if err != nil {
		t.Fatal(err)
	}
	srv, err := startForwardServer("127.0.0.1:0", up, srvCfg, testLimits, nopLog)
	if err != nil {
		t.Fatal(err)
	}
	_ = srv.closeFn() // the socket dies without a shutdown request
	select {
	case <-srv.done:
	case <-time.After(10 * time.Second):
		t.Fatal("the forwarder kept running with a dead listener")
	}
}

// Two identities that share a key cannot be told apart, so a clients file that does that is
// refused at startup and on reload.
func TestForwardRefusesIdentitiesSharingAKey(t *testing.T) {
	k := randomPSK(t)
	clients := writeSecret(t, "clients.txt", "alice "+k+"\nbob "+k+"\n", 0o600)
	_, err := buildForwardConfig(true, forwardAuth{clientsFile: clients})
	if err == nil || !strings.Contains(err.Error(), "share one key") {
		t.Fatalf("a clients file with a shared key was accepted: %v", err)
	}
}

// The files `keygen` writes must work with --server-key and --pin as the docs promise, for
// both suites. An earlier loader read them as raw bytes and refused every real file.
func TestForwardPinsWithKeygenFiles(t *testing.T) {
	for _, suite := range []string{"chkem-v1", "x-wing"} {
		t.Run(suite, func(t *testing.T) {
			dir := t.TempDir()
			gen := func(name string) (key, pub string) {
				out := filepath.Join(dir, name)
				if err := runKeygen(out, false, "", suite, io.Discard); err != nil {
					t.Fatal(err)
				}
				return out + ".key", out + ".pub"
			}
			serverKey, serverPub := gen("server")
			_, otherPub := gen("other")
			psk := writeSecret(t, "psk.hex", randomPSK(t)+"\n", 0o600)
			up, _ := startUpstream(t, echoHandler)

			roundTrip := func(addr string) error {
				c := dial(t, addr)
				_ = c.SetDeadline(time.Now().Add(8 * time.Second))
				if _, err := c.Write([]byte("x")); err != nil {
					return err
				}
				_, err := io.ReadFull(c, make([]byte, 1))
				return err
			}

			good := startPair(t, up,
				forwardAuth{pskFile: psk, serverKey: serverKey},
				forwardAuth{pskFile: psk, pin: serverPub}, testLimits)
			if err := roundTrip(good); err != nil {
				t.Fatalf("a client that pins the server's keygen pin failed: %v", err)
			}

			wrong := startPair(t, up,
				forwardAuth{pskFile: psk, serverKey: serverKey},
				forwardAuth{pskFile: psk, pin: otherPub}, testLimits)
			if err := roundTrip(wrong); err == nil {
				t.Fatal("a client that pins a different key got through")
			}

			unpinned := startPair(t, up,
				forwardAuth{pskFile: psk, serverKey: serverKey},
				forwardAuth{pskFile: psk}, testLimits)
			if err := roundTrip(unpinned); err == nil {
				t.Fatal("a client with no pin got through a server that requires static auth")
			}
		})
	}
}
