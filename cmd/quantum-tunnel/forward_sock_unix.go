//go:build !windows

package main

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"syscall"
)

// checkSocketDir refuses a directory that another user owns or that group or others can write
// to, sticky or not: they could replace the socket or hold a path in it. It checks this one
// directory, not its ancestors, so place the socket in a directory the service owns.
func checkSocketDir(dir string) error {
	fi, err := os.Stat(dir)
	if err != nil {
		return err
	}
	if !fi.IsDir() {
		return fmt.Errorf("%s is not a directory", dir)
	}
	if fi.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("%s is writable by its group or others; put the socket in a private directory", dir)
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok && int(st.Uid) != os.Geteuid() {
		return fmt.Errorf("%s is owned by another user; put the socket in a directory this user owns", dir)
	}
	return nil
}

// listenUnixPrivate binds a Unix socket that no other user can reach at any moment. It binds in a
// fresh 0700 directory next to the target, sets the mode there, and only then renames the socket
// into place, so the final path never exists with looser permissions and no process-wide state
// such as the umask changes. The listener removes the final path when it closes.
func listenUnixPrivate(path string, mode os.FileMode) (net.Listener, error) {
	stage, err := os.MkdirTemp(filepath.Dir(path), ".qt-")
	if err != nil {
		return nil, err
	}
	defer func() { _ = os.RemoveAll(stage) }()
	staged := filepath.Join(stage, "s")
	ln, err := net.Listen("unix", staged)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(staged, mode); err != nil {
		_ = ln.Close()
		return nil, err
	}
	// Link, not rename: it refuses to replace an existing path, so a second forwarder that lost a
	// race for the same path fails here and never displaces the first one's live socket.
	if err := os.Link(staged, path); err != nil {
		_ = ln.Close()
		return nil, fmt.Errorf("%s is already in use: %w", path, err)
	}
	placed, err := os.Lstat(path)
	if err != nil {
		_ = ln.Close()
		return nil, err
	}
	return &removingListener{Listener: ln, path: path, placed: placed}, nil
}

// removingListener unlinks the socket's final path on Close, because the net package only knows
// the staging path it bound. It removes the path only while it still names this listener's own
// socket, so a restart that already replaced it is left alone.
type removingListener struct {
	net.Listener
	path   string
	placed os.FileInfo
}

func (l *removingListener) Close() error {
	err := l.Listener.Close()
	if cur, statErr := os.Lstat(l.path); statErr == nil && os.SameFile(cur, l.placed) {
		_ = os.Remove(l.path)
	}
	return err
}
