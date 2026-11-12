//go:build !windows

package main

import (
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// shortDir returns a private directory with a path short enough for a socket on macOS, whose
// limit is about 100 bytes (t.TempDir names include the test name and overflow it).
func shortDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "qg")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	return dir
}

func echoRoundTrip(t *testing.T, network, addr string) error {
	t.Helper()
	c, err := net.DialTimeout(network, addr, 5*time.Second)
	if err != nil {
		return err
	}
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(8 * time.Second))
	if _, err := c.Write([]byte("x")); err != nil {
		return err
	}
	_, err = io.ReadFull(c, make([]byte, 1))
	return err
}

// The plain side listens on a Unix socket that only its owner can use, and the tunnel carries
// the bytes to an upstream that is itself a Unix socket.
func TestForwardOverUnixSockets(t *testing.T) {
	dir := shortDir(t)
	upSock := filepath.Join(dir, "up.sock")
	upLn, err := net.Listen("unix", upSock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = upLn.Close() })
	go func() {
		for {
			c, err := upLn.Accept()
			if err != nil {
				return
			}
			go func() { defer func() { _ = c.Close() }(); echoHandler(c) }()
		}
	}()

	psk := writeSecret(t, "psk.hex", randomPSK(t)+"\n", 0o600)
	auth := forwardAuth{pskFile: psk}
	srvCfg, _ := buildForwardConfig(true, auth)
	srv, err := startForwardServer("127.0.0.1:0", unixPrefix+upSock, srvCfg, testLimits, nopLog)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = srv.Close() })
	cliCfg, _ := buildForwardConfig(false, auth)
	plain := filepath.Join(dir, "plain.sock")
	cli, err := startForwardClient(unixPrefix+plain, srv.Addr().String(), cliCfg, testLimits, nopLog)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cli.Close() })

	fi, err := os.Stat(plain)
	if err != nil {
		t.Fatal(err)
	}
	if got := fi.Mode().Perm(); got != 0o600 {
		t.Fatalf("socket mode %#o, want 0600", got)
	}
	if err := echoRoundTrip(t, "unix", plain); err != nil {
		t.Fatalf("a round trip through the unix sockets failed: %v", err)
	}
}

func TestListenPlainSocketModes(t *testing.T) {
	dir := shortDir(t)

	ln, err := listenPlain(unixPrefix+filepath.Join(dir, "g.sock"), 0o660)
	if err != nil {
		t.Fatal(err)
	}
	fi, _ := os.Stat(filepath.Join(dir, "g.sock"))
	if got := fi.Mode().Perm(); got != 0o660 {
		t.Fatalf("socket mode %#o, want 0660", got)
	}
	_ = ln.Close()

	for _, bad := range []os.FileMode{0o666, 0o604, 0o1600} {
		if ln, err := listenPlain(unixPrefix+filepath.Join(dir, "bad.sock"), bad); err == nil {
			_ = ln.Close()
			t.Fatalf("mode %#o was accepted", bad)
		}
	}
}

func TestListenPlainRefusesUnsafeTargets(t *testing.T) {
	dir := shortDir(t)

	loose := filepath.Join(dir, "loose")
	if err := os.Mkdir(loose, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(loose, 0o777); err != nil {
		t.Fatal(err)
	}
	if ln, err := listenPlain(unixPrefix+filepath.Join(loose, "s.sock"), 0); err == nil {
		_ = ln.Close()
		t.Fatal("a socket in a world-writable directory was accepted")
	}

	if ln, err := listenPlain(unixPrefix+"@abstract", 0); err == nil || !strings.Contains(err.Error(), "abstract") {
		if err == nil {
			_ = ln.Close()
		}
		t.Fatalf("an abstract socket was accepted: %v", err)
	}

	file := filepath.Join(dir, "plain.txt")
	if err := os.WriteFile(file, []byte("keep me"), 0o600); err != nil {
		t.Fatal(err)
	}
	if ln, err := listenPlain(unixPrefix+file, 0); err == nil {
		_ = ln.Close()
		t.Fatal("a regular file was replaced by a socket")
	}
	if b, _ := os.ReadFile(file); string(b) != "keep me" {
		t.Fatal("a regular file was modified")
	}
}

// A socket file left behind by a crash is replaced; one that something still answers on is not.
func TestListenPlainStaleAndLiveSockets(t *testing.T) {
	dir := shortDir(t)
	path := filepath.Join(dir, "s.sock")

	// A stale socket: bind it, then abandon the file without unlinking it.
	stale, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	stale.(*net.UnixListener).SetUnlinkOnClose(false)
	_ = stale.Close()
	if _, err := os.Lstat(path); err != nil {
		t.Fatalf("the stale socket file is missing: %v", err)
	}
	ln, err := listenPlain(unixPrefix+path, 0)
	if err != nil {
		t.Fatalf("a stale socket blocked a restart: %v", err)
	}
	if again, err := listenPlain(unixPrefix+path, 0); err == nil {
		_ = again.Close()
		t.Fatal("a live socket was taken over")
	}
	_ = ln.Close()
	if _, err := os.Lstat(path); err == nil {
		t.Fatal("closing the listener left its socket file behind")
	}
}
