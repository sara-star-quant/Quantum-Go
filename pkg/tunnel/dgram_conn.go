// Package tunnel - dgram_conn.go is the public application handle for an
// established datagram session. A DatagramEndpoint multiplexes many sessions over
// one PacketConn; a DatagramConn is one such session, exposing message-oriented
// Send/Recv plus an authenticated Close. It is obtained from DialDatagram
// (initiator) or DatagramEndpoint.Accept (responder).
package tunnel

import (
	"net"
	"sync"

	"github.com/sara-star-quant/quantum-go/internal/constants"
	qerrors "github.com/sara-star-quant/quantum-go/internal/errors"
	"github.com/sara-star-quant/quantum-go/pkg/protocol"
)

// DatagramConn is one established datagram session. Send and Recv are message
// oriented: each Send emits exactly one datagram and each Recv returns exactly one
// peer datagram's payload. Unlike a stream conn there is no FIN; Close is a single
// best-effort authenticated CLOSE and teardown is otherwise driven by idle reaping.
//
// Send and SendBatch are safe for concurrent use: calls are serialized, because they
// share a reusable frame buffer and sequence numbers must be sealed in order. Recv is
// safe to call from another goroutine at the same time.
type DatagramConn struct {
	ep *DatagramEndpoint
	ds *datagramSession

	// sendMu serializes Send and SendBatch, which share sendBuf and batchBuf.
	sendMu sync.Mutex
	// sendBuf is the reusable frame buffer for Send (header || ciphertext || tag),
	// retained across calls so the steady-state send path allocates nothing.
	sendBuf []byte
	// batchBuf holds the sealed frames of one SendBatch, retained across calls.
	batchBuf []byte
}

// newDatagramConn wraps an established datagram session.
func newDatagramConn(ep *DatagramEndpoint, ds *datagramSession) *DatagramConn {
	return &DatagramConn{
		ep:      ep,
		ds:      ds,
		sendBuf: make([]byte, 0, constants.DatagramMTU),
	}
}

// Send encrypts p into a single DATA datagram and writes it to the peer. It
// returns ErrMessageTooLarge if p exceeds DatagramMaxDataPayload (the datagram
// transport does no fragmentation of application data and no PMTU discovery).
func (c *DatagramConn) Send(p []byte) error {
	if len(p) > constants.DatagramMaxDataPayload {
		return qerrors.ErrMessageTooLarge
	}
	c.sendMu.Lock()
	defer c.sendMu.Unlock()
	s := c.ds.getSession()
	seq := s.nextDatagramSeq()
	// Build header || ciphertext || tag in the reusable buffer: the header is both
	// the frame prefix and the AEAD AAD, and DatagramSealTo appends the sealed
	// payload after it in place, so the steady-state send path allocates nothing.
	header := protocol.AppendDatagramDataHeader(c.sendBuf[:0], protocol.DatagramHeader{
		Epoch:     s.datagramSendEpoch(),
		RecvIndex: c.ds.peerIndex,
		Seq:       seq,
	})
	frame, err := s.DatagramSealTo(header, header, seq, p)
	if err != nil {
		return err
	}
	c.sendBuf = frame[:0] // retain the (grown) backing array for the next Send
	if _, err := c.ep.conn.WriteTo(frame, c.ds.currentPeerAddr()); err != nil {
		return err
	}
	s.BytesSent.Add(int64(len(p)))
	s.PacketsSent.Add(1)

	// Rotate the epoch well before the per-epoch key budget is exhausted. Only the
	// initiator drives rekey; it runs in the background so Send never blocks.
	if s.Role == RoleInitiator && !c.ds.rekeyActive.Load() && s.datagramRekeyDue(seq) {
		go func() { _ = c.Rekey() }()
	}
	return nil
}

// maxGSOSegments and maxGSOBytes are the kernel's limits for one segmented send.
const (
	maxGSOSegments = 64
	maxGSOBytes    = 65507
)

// SendBatch sends every payload as its own DATA datagram, like calling Send for
// each, but when the endpoint has offload enabled (WithDatagramOffload) on a kernel
// that supports it, runs of equal-size datagrams go out in a single syscall via UDP
// segmentation offload. Datagram sizes, sequence numbers and the wire format are the
// same either way, and any send the kernel will not segment falls back to plain
// sends, so no datagram is lost. Concurrent calls are serialized, so one batch's
// datagrams are never interleaved with another call's. An error stops the batch;
// earlier payloads were already sent.
func (c *DatagramConn) SendBatch(payloads [][]byte) error {
	if len(payloads) == 0 {
		return nil
	}
	for _, p := range payloads {
		if len(p) > constants.DatagramMaxDataPayload {
			return qerrors.ErrMessageTooLarge
		}
	}
	c.sendMu.Lock()
	defer c.sendMu.Unlock()
	s := c.ds.getSession()
	dst := c.ds.currentPeerAddr()

	// Seal every payload back to back; offsets record where each frame ends.
	buf := c.batchBuf[:0]
	ends := make([]int, 0, len(payloads))
	var lastSeq uint64
	for _, p := range payloads {
		seq := s.nextDatagramSeq()
		lastSeq = seq
		header := protocol.AppendDatagramDataHeader(buf, protocol.DatagramHeader{
			Epoch:     s.datagramSendEpoch(),
			RecvIndex: c.ds.peerIndex,
			Seq:       seq,
		})
		frame, err := s.DatagramSealTo(header, header[len(buf):], seq, p)
		if err != nil {
			return err
		}
		buf = frame
		ends = append(ends, len(buf))
	}
	c.batchBuf = buf[:0]

	// Walk the frames, sending each run of equal-size frames (the last may be
	// shorter) as one segmented send when possible.
	start := 0
	for i := 0; i < len(ends); {
		segSize := ends[i] - start
		runEnd, n := ends[i], 1
		for j := i + 1; j < len(ends) && n < maxGSOSegments; j++ {
			size := ends[j] - ends[j-1]
			if size > segSize || runEnd+size-start > maxGSOBytes {
				break
			}
			runEnd = ends[j]
			n++
			if size < segSize {
				break // a short frame can only end a run
			}
		}
		if n > 1 && c.ep.batch.writeGSO(buf[start:runEnd], segSize, dst) {
			i += n
			start = runEnd
			continue
		}
		// Plain send for one frame (or the run the kernel refused), then re-scan.
		if _, err := c.ep.conn.WriteTo(buf[start:ends[i]], dst); err != nil {
			return err
		}
		start = ends[i]
		i++
	}

	var total int64
	for _, p := range payloads {
		total += int64(len(p))
	}
	s.BytesSent.Add(total)
	s.PacketsSent.Add(int64(len(payloads)))
	if s.Role == RoleInitiator && !c.ds.rekeyActive.Load() && s.datagramRekeyDue(lastSeq) {
		go func() { _ = c.Rekey() }()
	}
	return nil
}

// Recv returns the next decrypted application payload, blocking until one arrives
// or the session is closed (ErrTunnelClosed) or the endpoint shuts down.
func (c *DatagramConn) Recv() ([]byte, error) {
	select {
	case b := <-c.ds.recvCh:
		return b, nil
	case <-c.ds.closed:
		return nil, qerrors.ErrTunnelClosed
	case <-c.ep.done:
		return nil, errEndpointClosed
	}
}

// Close sends one best-effort authenticated CLOSE and tears the session down
// locally. It is idempotent.
func (c *DatagramConn) Close() error {
	s := c.ds.getSession()
	if s != nil {
		seq := s.nextDatagramSeq()
		header := protocol.EncodeDatagramHeader(protocol.DatagramHeader{
			Type:      protocol.DatagramFrameClose,
			Epoch:     s.datagramSendEpoch(),
			RecvIndex: c.ds.peerIndex,
			Seq:       seq,
		})
		if tag, err := s.DatagramSeal(header, seq, nil); err == nil {
			_, _ = c.ep.conn.WriteTo(append(header, tag...), c.ds.currentPeerAddr())
		}
		s.Close()
	}
	c.ds.teardown(c.ep.registry)
	return nil
}

// RemoteAddr returns the peer's current address, which follows the peer across
// roaming (NAT rebind / path change), so it may differ from the dial/accept
// address after the peer moves.
func (c *DatagramConn) RemoteAddr() net.Addr { return c.ds.currentPeerAddr() }

// Session exposes the underlying Session (statistics, state).
func (c *DatagramConn) Session() *Session { return c.ds.getSession() }

// Accept returns the next inbound established datagram session as a DatagramConn,
// blocking until one is available or the endpoint closes.
func (e *DatagramEndpoint) Accept() (*DatagramConn, error) {
	select {
	case ds := <-e.acceptCh:
		return newDatagramConn(e, ds), nil
	case <-e.done:
		return nil, errEndpointClosed
	}
}
