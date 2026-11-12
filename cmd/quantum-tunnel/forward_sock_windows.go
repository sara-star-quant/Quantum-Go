//go:build windows

package main

import (
	"errors"
	"net"
	"os"
)

func listenUnixPrivate(string, os.FileMode) (net.Listener, error) {
	return nil, errors.New("unix sockets are not supported on Windows")
}
