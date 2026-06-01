//go:build !linux

package tunnel

import "net"

// newBatchIO returns the portable single-datagram fallback on platforms without
// recvmmsg/sendmmsg support. It does not import golang.org/x/net. The gro flag is
// ignored: UDP_GRO is Linux-only, so offload is a no-op here.
func newBatchIO(conn net.PacketConn, _ bool) batchIO {
	return newFallbackIO(conn)
}
