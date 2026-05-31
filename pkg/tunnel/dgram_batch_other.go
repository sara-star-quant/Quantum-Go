//go:build !linux

package tunnel

import "net"

// newBatchIO returns the portable single-datagram fallback on platforms without
// recvmmsg/sendmmsg support. It does not import golang.org/x/net.
func newBatchIO(conn net.PacketConn) batchIO {
	return newFallbackIO(conn)
}
