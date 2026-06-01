//go:build linux

package tunnel

import (
	"encoding/binary"
	"net"

	"github.com/sara-star-quant/quantum-go/internal/constants"
	"golang.org/x/net/ipv4"
	"golang.org/x/sys/unix"
)

const (
	// groReadBufferSize sizes each receive buffer when UDP_GRO is on: the kernel
	// coalesces a burst of same-flow datagrams into one buffer, up to ~64KB, so the
	// buffer must hold a full coalesced burst or the kernel truncates it.
	groReadBufferSize = 65536
	// groBatchSize is the recvmmsg slot count under GRO. Each slot already holds many
	// datagrams' worth of bytes, so far fewer slots are needed than the per-datagram
	// path, keeping the per-socket buffer footprint bounded (groBatchSize*64KB).
	groBatchSize = 8
	// groControlSize reserves room for the UDP_GRO control message recvmmsg returns
	// alongside a coalesced datagram (a cmsghdr plus the segment size).
	groControlSize = 64
)

// newBatchIO returns a recvmmsg/sendmmsg-backed batchIO when conn is a
// *net.UDPConn, else the portable single-datagram fallback (e.g. an in-memory
// test conn). ipv4.PacketConn is used for both address families: recvmmsg handles
// the payload, source address, and control messages regardless of whether the
// socket is v4 or v6. When gro is set and UDP_GRO enables on the socket, the receive
// path reads coalesced bursts and re-splits them (see recv).
func newBatchIO(conn net.PacketConn, gro bool) batchIO {
	udp, ok := conn.(*net.UDPConn)
	if !ok {
		return newFallbackIO(conn)
	}
	pc := ipv4.NewPacketConn(udp)
	groOn := gro && enableGRO(udp)

	count := constants.DatagramBatchSize
	bufSize := constants.DatagramMTU + 512
	if groOn {
		count = groBatchSize
		bufSize = groReadBufferSize
	}
	rmsgs := make([]ipv4.Message, count)
	for i := range rmsgs {
		rmsgs[i].Buffers = [][]byte{make([]byte, bufSize)}
		if groOn {
			rmsgs[i].OOB = make([]byte, groControlSize)
		}
	}
	return &linuxBatchIO{pc: pc, rmsgs: rmsgs, gro: groOn}
}

// enableGRO turns on UDP_GRO for the socket, best-effort. It returns false on a
// kernel without UDP_GRO (pre-5.7) or any setsockopt error, leaving the caller on the
// plain per-datagram receive path.
func enableGRO(udp *net.UDPConn) bool {
	rc, err := udp.SyscallConn()
	if err != nil {
		return false
	}
	var ok bool
	if err := rc.Control(func(fd uintptr) {
		ok = unix.SetsockoptInt(int(fd), unix.SOL_UDP, unix.UDP_GRO, 1) == nil
	}); err != nil {
		return false
	}
	return ok
}

type linuxBatchIO struct {
	pc *ipv4.PacketConn
	// rmsgs holds the reusable receive buffers. It is owned exclusively by the
	// single Serve/recv goroutine, so it needs no synchronization.
	rmsgs []ipv4.Message
	// gro is set when UDP_GRO is active: recv must then re-split each coalesced
	// buffer into its constituent datagrams.
	gro bool
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
		// Borrowed buffers: dispatch must not retain them (see the recv contract in
		// dgram_batch.go). Each message has its own backing buffer in rmsgs, and the
		// next ReadBatch only overwrites them after this loop returns, so passing the
		// slices directly is safe and avoids a per-datagram copy. Under GRO the kernel
		// coalesces a burst into m.Buffers[0][:m.N] and reports the segment size in the
		// control message; splitSegments hands each datagram to dispatch in turn.
		segSize := 0
		if b.gro {
			segSize = groSegmentSize(m.OOB[:m.NN])
		}
		splitSegments(m.Buffers[0][:m.N], segSize, m.Addr, dispatch)
	}
	return nil
}

// splitSegments invokes dispatch once per segSize-sized segment of data (the final
// segment may be shorter). A non-positive segSize, or data that fits in a single
// segment, yields one call with all of data - the no-GRO and no-coalescing cases. It
// is a free function so the split is unit-testable without a socket.
func splitSegments(data []byte, segSize int, src net.Addr, dispatch func(net.Addr, []byte)) {
	if segSize <= 0 || len(data) <= segSize {
		dispatch(src, data)
		return
	}
	for off := 0; off < len(data); off += segSize {
		end := off + segSize
		if end > len(data) {
			end = len(data)
		}
		dispatch(src, data[off:end])
	}
}

// groSegmentSize reads the segment size the kernel reported in the UDP_GRO control
// message, or 0 if absent or malformed. The kernel writes the size as a C int, so it
// is read in native byte order.
func groSegmentSize(oob []byte) int {
	if len(oob) == 0 {
		return 0
	}
	msgs, err := unix.ParseSocketControlMessage(oob)
	if err != nil {
		return 0
	}
	for i := range msgs {
		h := msgs[i].Header
		if h.Level == unix.SOL_UDP && h.Type == unix.UDP_GRO && len(msgs[i].Data) >= 4 {
			return int(binary.NativeEndian.Uint32(msgs[i].Data))
		}
	}
	return 0
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
