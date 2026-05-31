// Package tunnel - dgram_conn.go is the public application handle for an
// established datagram session. A DatagramEndpoint multiplexes many sessions over
// one PacketConn; a DatagramConn is one such session, exposing message-oriented
// Send/Recv plus an authenticated Close. It is obtained from DialDatagram
// (initiator) or DatagramEndpoint.Accept (responder).
package tunnel

import (
	"net"

	"github.com/sara-star-quant/quantum-go/internal/constants"
	qerrors "github.com/sara-star-quant/quantum-go/internal/errors"
	"github.com/sara-star-quant/quantum-go/pkg/protocol"
)

// DatagramConn is one established datagram session. Send and Recv are message
// oriented: each Send emits exactly one datagram and each Recv returns exactly one
// peer datagram's payload. Unlike a stream conn there is no FIN; Close is a single
// best-effort authenticated CLOSE and teardown is otherwise driven by idle reaping.
//
// Send is safe for use from one goroutine at a time; Recv from another. Send is
// not safe for concurrent callers (it shares no buffer in this phase, but the
// contract is reserved for the zero-alloc path).
type DatagramConn struct {
	ep   *DatagramEndpoint
	ds   *datagramSession
	peer net.Addr
}

// newDatagramConn wraps an established datagram session.
func newDatagramConn(ep *DatagramEndpoint, ds *datagramSession) *DatagramConn {
	return &DatagramConn{ep: ep, ds: ds, peer: ds.peerAddr}
}

// Send encrypts p into a single DATA datagram and writes it to the peer. It
// returns ErrMessageTooLarge if p exceeds DatagramMaxDataPayload (the datagram
// transport does no fragmentation of application data and no PMTU discovery).
func (c *DatagramConn) Send(p []byte) error {
	if len(p) > constants.DatagramMaxDataPayload {
		return qerrors.ErrMessageTooLarge
	}
	s := c.ds.session
	seq := s.nextDatagramSeq()
	header := protocol.EncodeDatagramHeader(protocol.DatagramHeader{
		Type:      protocol.DatagramFrameData,
		Epoch:     s.datagramSendEpoch(),
		RecvIndex: c.ds.peerIndex,
		Seq:       seq,
	})
	ct, err := s.DatagramSeal(header, seq, p)
	if err != nil {
		return err
	}
	frame := append(header, ct...)
	if _, err := c.ep.conn.WriteTo(frame, c.peer); err != nil {
		return err
	}
	s.BytesSent.Add(int64(len(p)))
	s.PacketsSent.Add(1)
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
	s := c.ds.session
	if s != nil {
		seq := s.nextDatagramSeq()
		header := protocol.EncodeDatagramHeader(protocol.DatagramHeader{
			Type:      protocol.DatagramFrameClose,
			Epoch:     s.datagramSendEpoch(),
			RecvIndex: c.ds.peerIndex,
			Seq:       seq,
		})
		if tag, err := s.DatagramSeal(header, seq, nil); err == nil {
			_, _ = c.ep.conn.WriteTo(append(header, tag...), c.peer)
		}
		s.Close()
	}
	c.ds.teardown(c.ep.registry)
	return nil
}

// RemoteAddr returns the peer's current address.
func (c *DatagramConn) RemoteAddr() net.Addr { return c.peer }

// Session exposes the underlying Session (statistics, state).
func (c *DatagramConn) Session() *Session { return c.ds.session }

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
