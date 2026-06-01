//go:build linux

package tunnel

import (
	"context"
	"net"
	"syscall"

	"golang.org/x/sys/unix"
)

// listenReusePort opens n UDP sockets all bound to the same address via
// SO_REUSEPORT, so the kernel load-balances inbound datagrams across them by 4-tuple
// flow hash. The first socket binds the requested addr (resolving a :0 port to a
// concrete one); the remaining sockets bind that resolved addr so they share it. On
// any error it closes the sockets already opened and returns the error, so there is
// no partially-built endpoint and no leaked fd.
func listenReusePort(network, addr string, n int) ([]*net.UDPConn, error) {
	lc := net.ListenConfig{
		Control: func(_, _ string, c syscall.RawConn) error {
			var serr error
			if cerr := c.Control(func(fd uintptr) {
				// SO_REUSEPORT lets multiple sockets bind the same addr and load-balances
				// across them; SO_REUSEADDR eases rebind. Both must be set before bind,
				// which is exactly when this control hook runs.
				if err := unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEPORT, 1); err != nil {
					serr = err
					return
				}
				serr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEADDR, 1)
			}); cerr != nil {
				return cerr
			}
			return serr
		},
	}

	conns := make([]*net.UDPConn, 0, n)
	bindAddr := addr
	for range n {
		pc, err := lc.ListenPacket(context.Background(), network, bindAddr)
		if err != nil {
			for _, c := range conns {
				_ = c.Close()
			}
			return nil, err
		}
		uc := pc.(*net.UDPConn)
		conns = append(conns, uc)
		// After the first bind, pin the remaining sockets to the now-concrete port so
		// a :0 request resolves once and all n share one addr:port.
		bindAddr = uc.LocalAddr().String()
	}
	return conns, nil
}
