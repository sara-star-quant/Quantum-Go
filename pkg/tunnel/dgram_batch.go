package tunnel

import (
	"net"

	"github.com/sara-star-quant/quantum-go/internal/constants"
)

// batchIO reads datagrams from and writes datagrams to the endpoint's packet
// conn. On Linux over a *net.UDPConn it uses batched recvmmsg/sendmmsg syscalls
// (one syscall per batch instead of per datagram); everywhere else, and whenever
// the conn is not a *net.UDPConn (e.g. an in-memory test conn), it falls back to
// one-at-a-time ReadFrom/WriteTo. newBatchIO is defined per-platform in
// dgram_batch_linux.go / dgram_batch_other.go.
type batchIO interface {
	// recv reads one batch of datagrams and calls dispatch for each, in arrival
	// order, with a freshly-allocated payload copy the callee may retain. It blocks
	// until at least one datagram is available and returns the underlying read
	// error (e.g. on close) so the receive loop can exit.
	recv(dispatch func(src net.Addr, payload []byte)) error
	// writeAll writes every frame to dst, best-effort: write errors are ignored,
	// matching the single-shot send sites (handshake/rekey retransmission recovers
	// any dropped frame). Safe for concurrent use.
	writeAll(frames [][]byte, dst net.Addr)
}

// fallbackIO is the portable one-datagram-at-a-time implementation over the
// net.PacketConn interface. recv is only ever driven by the single Serve
// goroutine, so its reusable read buffer needs no synchronization; writeAll
// touches only the conn (which is safe for concurrent WriteTo), so it is safe to
// call from many goroutines alongside recv.
type fallbackIO struct {
	conn net.PacketConn
	buf  []byte
}

func newFallbackIO(conn net.PacketConn) *fallbackIO {
	return &fallbackIO{conn: conn, buf: make([]byte, constants.DatagramMTU+512)}
}

func (f *fallbackIO) recv(dispatch func(src net.Addr, payload []byte)) error {
	n, src, err := f.conn.ReadFrom(f.buf)
	if err != nil {
		return err
	}
	data := make([]byte, n)
	copy(data, f.buf[:n])
	dispatch(src, data)
	return nil
}

func (f *fallbackIO) writeAll(frames [][]byte, dst net.Addr) {
	for _, fr := range frames {
		_, _ = f.conn.WriteTo(fr, dst)
	}
}
