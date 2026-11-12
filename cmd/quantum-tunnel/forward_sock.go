package main

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// unixPrefix marks an address as a Unix domain socket path, as in "unix:/run/qt.sock".
const unixPrefix = "unix:"

// defaultSocketMode lets only the owner connect. Pass 0660 to share the socket with a group.
const defaultSocketMode os.FileMode = 0o600

// unixPath returns the socket path of a "unix:" address.
func unixPath(addr string) (string, bool) {
	if p, ok := strings.CutPrefix(addr, unixPrefix); ok {
		return p, true
	}
	return "", false
}

// dialUpstream connects to the fixed upstream: a TCP address, or a Unix socket as "unix:/path".
func dialUpstream(upstream string, timeout time.Duration) (net.Conn, error) {
	if path, ok := unixPath(upstream); ok {
		if runtime.GOOS == "windows" {
			return nil, errors.New("unix sockets are not supported on Windows")
		}
		return net.DialTimeout("unix", path, timeout)
	}
	return net.DialTimeout("tcp", upstream, timeout)
}

// listenPlain opens the plain side of a client: a TCP address, or a Unix socket as "unix:/path"
// that only the permitted users can reach.
func listenPlain(addr string, mode os.FileMode) (net.Listener, error) {
	path, ok := unixPath(addr)
	if !ok {
		return net.Listen("tcp", addr)
	}
	if runtime.GOOS == "windows" {
		return nil, errors.New("unix sockets are not supported on Windows")
	}
	if mode == 0 {
		mode = defaultSocketMode
	}
	if mode&0o007 != 0 || mode&^0o777 != 0 {
		return nil, fmt.Errorf("--socket-mode %#o would give access to every user; use 0600 or 0660", mode)
	}
	if strings.HasPrefix(path, "@") {
		return nil, errors.New("abstract unix sockets have no file permissions; use a path")
	}
	path, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	if err := checkSocketDir(filepath.Dir(path)); err != nil {
		return nil, err
	}
	if err := clearStaleSocket(path); err != nil {
		return nil, err
	}
	return listenUnixPrivate(path, mode)
}

// checkSocketDir refuses a directory other users can write to (unless it is sticky, like /tmp),
// because they could replace the socket or race its permissions.
func checkSocketDir(dir string) error {
	fi, err := os.Stat(dir)
	if err != nil {
		return err
	}
	if !fi.IsDir() {
		return fmt.Errorf("%s is not a directory", dir)
	}
	if fi.Mode().Perm()&0o022 != 0 && fi.Mode()&os.ModeSticky == 0 {
		return fmt.Errorf("%s is writable by its group or others; put the socket in a private directory", dir)
	}
	return nil
}

// clearStaleSocket removes a leftover socket file that nothing answers on. A live socket, or a
// path that is not a socket, is an error, so a restart never deletes another program's file.
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
	if c, err := net.DialTimeout("unix", path, time.Second); err == nil {
		_ = c.Close()
		return fmt.Errorf("%s is already in use", path)
	}
	return os.Remove(path)
}
