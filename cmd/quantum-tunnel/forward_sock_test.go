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

	for _, bad := range []os.FileMode{0o666, 0o604, 0o1600, 0o200, 0o020, 0o060, 0o400, 0o700, 0o760, 0o670} {
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
	sticky := filepath.Join(dir, "sticky")
	if err := os.Mkdir(sticky, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(sticky, os.ModeSticky|0o777); err != nil {
		t.Fatal(err)
	}
	if ln, err := listenPlain(unixPrefix+filepath.Join(sticky, "s.sock"), 0); err == nil {
		_ = ln.Close()
		t.Fatal("a socket in a sticky world-writable directory was accepted")
	}
	group := filepath.Join(dir, "group")
	if err := os.Mkdir(group, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(group, 0o770); err != nil {
		t.Fatal(err)
	}
	if ln, err := listenPlain(unixPrefix+filepath.Join(group, "s.sock"), 0); err == nil {
		_ = ln.Close()
		t.Fatal("a socket in a group-writable directory was accepted")
	}
	long := unixPrefix + filepath.Join(dir, strings.Repeat("x", maxSocketPath))
	if ln, err := listenPlain(long, 0); err == nil || !strings.Contains(err.Error(), "bytes") {
		if err == nil {
			_ = ln.Close()
		}
		t.Fatalf("an overlong path got %v, want a message naming the length", err)
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

// Only a refused connection proves a socket is stale. A socket that exists but cannot be probed
// (here: the owner removed every permission) might still be live, so it stays and the start fails.
func TestListenPlainLeavesAnUnprobeableSocketAlone(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root can connect to any socket")
	}
	dir := shortDir(t)
	path := filepath.Join(dir, "s.sock")
	live, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = live.Close() }()
	if err := os.Chmod(path, 0o000); err != nil {
		t.Fatal(err)
	}
	if ln, err := listenPlain(unixPrefix+path, 0); err == nil {
		_ = ln.Close()
		t.Fatal("a socket that could not be probed was taken over")
	}
	if _, err := os.Lstat(path); err != nil {
		t.Fatalf("the unprobeable socket was deleted: %v", err)
	}
}

// Binding goes through a staging directory. Nothing of it may remain beside the socket, and the
// final path must carry the requested mode from the first moment it exists.
func TestListenPlainLeavesNoStagingDirectory(t *testing.T) {
	dir := shortDir(t)
	ln, err := listenPlain(unixPrefix+filepath.Join(dir, "s.sock"), 0o660)
	if err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != "s.sock" {
		t.Fatalf("directory holds %v, want only s.sock", entries)
	}
	_ = ln.Close()
}

func TestResolveSocketMode(t *testing.T) {
	if m, err := resolveSocketMode("", false, ":8080"); err != nil || m != defaultSocketMode {
		t.Fatalf("unset flag: %v %v", m, err)
	}
	if m, err := resolveSocketMode("0660", true, "unix:/x"); err != nil || m != 0o660 {
		t.Fatalf("0660 on a unix address: %v %v", m, err)
	}
	if _, err := resolveSocketMode("0660", true, "127.0.0.1:8080"); err == nil {
		t.Fatal("--socket-mode with a TCP listen address was silently accepted")
	}
	if _, err := resolveSocketMode("rwx", true, "unix:/x"); err == nil {
		t.Fatal("a non-octal mode was accepted")
	}
	if err := checkSocketMode(0); err == nil {
		t.Fatal("mode 0 was accepted")
	}
}

func TestConnLabelForLocalSockets(t *testing.T) {
	dir := shortDir(t)
	ln, err := net.Listen("unix", filepath.Join(dir, "l.sock"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	go func() {
		c, err := net.Dial("unix", filepath.Join(dir, "l.sock"))
		if err == nil {
			defer func() { _ = c.Close() }()
			time.Sleep(200 * time.Millisecond)
		}
	}()
	c, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	if got := connLabel(c); got != "local socket" {
		t.Fatalf("label %q, want a readable name for a local socket", got)
	}
}

// A second forwarder on the same path must fail without displacing the first, and the first
// closing after a restart replaced its path must not delete the new socket.
func TestListenPlainNeverDisplacesALiveSocket(t *testing.T) {
	dir := shortDir(t)
	path := unixPrefix + filepath.Join(dir, "s.sock")
	first, err := listenPlain(path, 0)
	if err != nil {
		t.Fatal(err)
	}
	if second, err := listenPlain(path, 0); err == nil {
		_ = second.Close()
		t.Fatal("a second listener took over a live socket path")
	}
	// The first must still accept connections.
	go func() {
		c, err := net.Dial("unix", filepath.Join(dir, "s.sock"))
		if err == nil {
			_ = c.Close()
		}
	}()
	if c, err := first.Accept(); err != nil {
		t.Fatalf("the first listener stopped working after a second tried to start: %v", err)
	} else {
		_ = c.Close()
	}

	// Simulate a restart that already replaced the path: the old listener's Close leaves it alone.
	sock := filepath.Join(dir, "s.sock")
	if err := os.Remove(sock); err != nil {
		t.Fatal(err)
	}
	replacement, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = replacement.Close() }()
	_ = first.Close()
	if _, err := os.Lstat(sock); err != nil {
		t.Fatalf("closing an old listener deleted the replacement's socket: %v", err)
	}
}
