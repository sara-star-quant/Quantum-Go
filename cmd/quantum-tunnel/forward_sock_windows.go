//go:build windows

package main

import (
	"net"
	"os"
)

func checkSocketDir(string) error { return errNoUnixSockets }

func listenUnixPrivate(string, os.FileMode) (net.Listener, error) { return nil, errNoUnixSockets }
