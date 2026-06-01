//go:build !linux

package tunnel

import (
	"context"
	"net"
)

// listenReusePort opens a single UDP socket on platforms without portable
// SO_REUSEPORT load-balancing semantics, so ListenDatagram degrades to one receiver
// (still correct, just not parallel). It ignores n. No golang.org/x/sys import.
func listenReusePort(network, addr string, _ int) ([]*net.UDPConn, error) {
	var lc net.ListenConfig
	pc, err := lc.ListenPacket(context.Background(), network, addr)
	if err != nil {
		return nil, err
	}
	return []*net.UDPConn{pc.(*net.UDPConn)}, nil
}
