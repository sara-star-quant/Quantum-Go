//go:build linux

package tunnel

import (
	"net"

	"github.com/sara-star-quant/quantum-go/internal/constants"
	"golang.org/x/net/ipv4"
	"golang.org/x/sys/unix"
)

// newBatchIO returns a recvmmsg/sendmmsg-backed batchIO when conn is a
// *net.UDPConn, else the portable single-datagram fallback (e.g. an in-memory
// test conn). ipv4.PacketConn is used for both address families: we read only the
// payload and source address (no control messages), which recvmmsg handles
// regardless of whether the socket is v4 or v6.
func newBatchIO(conn net.PacketConn) batchIO {
	udp, ok := conn.(*net.UDPConn)
	if !ok {
		return newFallbackIO(conn)
	}
	pc := ipv4.NewPacketConn(udp)
	rmsgs := make([]ipv4.Message, constants.DatagramBatchSize)
	for i := range rmsgs {
		rmsgs[i].Buffers = [][]byte{make([]byte, constants.DatagramMTU+512)}
	}
	return &linuxBatchIO{pc: pc, rmsgs: rmsgs}
}

type linuxBatchIO struct {
	pc *ipv4.PacketConn
	// rmsgs holds the reusable receive buffers. It is owned exclusively by the
	// single Serve/recv goroutine, so it needs no synchronization.
	rmsgs []ipv4.Message
}

func (b *linuxBatchIO) recv(dispatch func(src net.Addr, payload []byte)) error {
	// MSG_WAITFORONE makes recvmmsg return as soon as the first datagram is
	// available (draining any others already queued) instead of blocking until the
	// whole batch fills, matching ReadFrom's "block for one, return promptly"
	// latency. Without it, recvmmsg with a NULL timeout waits for the full batch.
	n, err := b.pc.ReadBatch(b.rmsgs, unix.MSG_WAITFORONE)
	if err != nil {
		return err
	}
	for i := 0; i < n; i++ {
		m := &b.rmsgs[i]
		// Copy out before the next ReadBatch overwrites the shared buffer; the
		// payload is routed onward (reassembly / recvCh) and outlives this call.
		data := make([]byte, m.N)
		copy(data, m.Buffers[0][:m.N])
		dispatch(m.Addr, data)
	}
	return nil
}

func (b *linuxBatchIO) writeAll(frames [][]byte, dst net.Addr) {
	if len(frames) == 0 {
		return
	}
	// Fresh message slice per call: writeAll is called concurrently from multiple
	// goroutines, so a shared reusable slice would race. Flights are infrequent, so
	// this small allocation is irrelevant.
	msgs := make([]ipv4.Message, len(frames))
	for i, fr := range frames {
		msgs[i].Buffers = [][]byte{fr}
		msgs[i].Addr = dst
	}
	// Best-effort, matching the WriteTo sites; a short or failed write is recovered
	// by handshake/rekey retransmission.
	_, _ = b.pc.WriteBatch(msgs, 0)
}
