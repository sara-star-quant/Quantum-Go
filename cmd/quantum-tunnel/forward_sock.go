package main

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// unixPrefix marks an address as a Unix domain socket path, as in "unix:/run/qt.sock".
const unixPrefix = "unix:"

// defaultSocketMode lets only the owner connect. Pass 0660 to share the socket with a group.
const defaultSocketMode os.FileMode = 0o600

// maxSocketPath leaves room for the staging directory that binding adds (about 20 bytes) under the
// shortest sun_path limit in use (104 bytes on macOS and the BSDs, 108 on Linux), so a long path
// gets a clear error instead of "invalid argument" from bind.
const maxSocketPath = 80

// unixPath returns the socket path of a "unix:" address.
func unixPath(addr string) (string, bool) {
	if p, ok := strings.CutPrefix(addr, unixPrefix); ok {
		return p, true
	}
	return "", false
}

// errNoUnixSockets is returned on platforms without Unix socket support in this tool.
var errNoUnixSockets = errors.New("unix sockets are not supported on Windows")

// dialUpstream connects to the fixed upstream: a TCP address, or a Unix socket as "unix:/path".
func dialUpstream(upstream string, timeout time.Duration) (net.Conn, error) {
	if path, ok := unixPath(upstream); ok {
		if runtime.GOOS == "windows" {
			return nil, errNoUnixSockets
		}
		return net.DialTimeout("unix", path, timeout)
	}
	return net.DialTimeout("tcp", upstream, timeout)
}

// connLabel names a local connection for the log. A Unix socket peer has no address, so it reads
// "local socket" and not a blank.
func connLabel(c net.Conn) string {
	if a := c.RemoteAddr(); a != nil && a.String() != "" && a.String() != "@" {
		return a.String()
	}
	return "local socket"
}

// resolveSocketMode turns the --socket-mode flag into a mode. The flag only means something for
// a unix: --listen address, so setting it anywhere else is an error and not a silent no-op.
func resolveSocketMode(value string, set bool, listen string) (os.FileMode, error) {
	_, isUnix := unixPath(listen)
	if !set {
		return defaultSocketMode, nil
	}
	if !isUnix {
		return 0, errors.New("--socket-mode applies only to a client --listen address of the form unix:/path")
	}
	m, err := strconv.ParseUint(value, 8, 32)
	if err != nil {
		return 0, fmt.Errorf("--socket-mode %q is not an octal permission such as 0600", value)
	}
	if m == 0 {
		return 0, errors.New("--socket-mode 0 would lock out every user; use 0600 or 0660")
	}
	return os.FileMode(m), nil
}

// checkSocketMode accepts exactly 0600 (owner) and 0660 (owner and group). Anything else is a
// mistake: wider exposes the tunnel, narrower locks the owner out.
func checkSocketMode(mode os.FileMode) error {
	if mode != 0o600 && mode != 0o660 {
		return fmt.Errorf("--socket-mode %#o must give the owner read and write and no access to others; use 0600 or 0660", mode)
	}
	return nil
}

// listenPlain opens the plain side of a client: a TCP address, or a Unix socket as "unix:/path"
// that only the permitted users can reach.
func listenPlain(addr string, mode os.FileMode) (net.Listener, error) {
	path, ok := unixPath(addr)
	if !ok {
		return net.Listen("tcp", addr)
	}
	if runtime.GOOS == "windows" {
		return nil, errNoUnixSockets
	}
	if mode == 0 {
		mode = defaultSocketMode
	}
	if err := checkSocketMode(mode); err != nil {
		return nil, err
	}
	if strings.HasPrefix(path, "@") {
		return nil, errors.New("abstract unix sockets have no file permissions; use a path")
	}
	if len(path) > maxSocketPath {
		return nil, fmt.Errorf("socket path is %d bytes; keep it under %d (the operating system limit is about 104)", len(path), maxSocketPath)
	}
	if err := checkSocketDir(filepath.Dir(path)); err != nil {
		return nil, err
	}
	if err := clearStaleSocket(path); err != nil {
		return nil, err
	}
	return listenUnixPrivate(path, mode)
}

// clearStaleSocket removes a leftover socket file that nothing answers on. Only a refused
// connection proves the file is stale. A live socket, a path that is not a socket, and any other
// failure to connect (a full backlog, a permission error, a timeout) are errors, so a restart
// never deletes a file that might still be in use. The probe is one short connection, which a
// running forwarder on that path treats as a client and answers with a tunnel handshake.
func clearStaleSocket(path string) error {
	fi, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if fi.Mode()&os.ModeSocket == 0 {
		return fmt.Errorf("%s exists and is not a socket", path)
	}
	c, err := net.DialTimeout("unix", path, time.Second)
	if err == nil {
		_ = c.Close()
		return fmt.Errorf("%s is already in use", path)
	}
	if !errors.Is(err, syscall.ECONNREFUSED) {
		return fmt.Errorf("cannot tell whether %s is in use, so it was left alone: %w", path, err)
	}
	return os.Remove(path)
}
