//go:build !windows

package main

import (
	"net"
	"os"
	"syscall"
)

// listenUnixPrivate binds a Unix socket that no other user can reach, even for an instant: the
// umask is tightened around the bind, so the socket never exists with looser permissions, and
// then the file is set to the requested mode. The umask is process-wide, but this runs during
// startup before the forwarder serves anything.
func listenUnixPrivate(path string, mode os.FileMode) (net.Listener, error) {
	old := syscall.Umask(0o177)
	ln, err := net.Listen("unix", path)
	syscall.Umask(old)
	if err != nil {
		return nil, err
	}
	if mode != defaultSocketMode {
		if err := os.Chmod(path, mode); err != nil {
			_ = ln.Close()
			return nil, err
		}
	}
	return ln, nil
}
