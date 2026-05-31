package tunnel

import (
	"net"
	"testing"
	"time"

	"github.com/sara-star-quant/quantum-go/internal/constants"
)

// discardConn is a net.PacketConn whose WriteTo discards instantly and whose
// ReadFrom blocks until close. It isolates the send-path CPU/alloc cost from any
// real socket so a benchmark measures framing + AEAD, not the kernel.
type discardConn struct{ closed chan struct{} }

func newDiscardConn() *discardConn { return &discardConn{closed: make(chan struct{})} }

func (c *discardConn) WriteTo(p []byte, _ net.Addr) (int, error) { return len(p), nil }
func (c *discardConn) ReadFrom([]byte) (int, net.Addr, error) {
	<-c.closed
	return 0, nil, net.ErrClosed
}
func (c *discardConn) Close() error                     { close(c.closed); return nil }
func (c *discardConn) LocalAddr() net.Addr              { return memAddr{name: "discard"} }
func (c *discardConn) SetDeadline(time.Time) error      { return nil }
func (c *discardConn) SetReadDeadline(time.Time) error  { return nil }
func (c *discardConn) SetWriteDeadline(time.Time) error { return nil }

// benchDatagramConn builds an established DatagramConn over a discard conn without
// running a handshake: it keys an initiator session directly so Send has a live
// epoch cipher.
func benchDatagramConn(b *testing.B) *DatagramConn {
	b.Helper()
	s, err := NewSession(RoleInitiator)
	if err != nil {
		b.Fatalf("session: %v", err)
	}
	ms := make([]byte, constants.CHKEMSharedSecretSize)
	for i := range ms {
		ms[i] = byte(i)
	}
	if err := s.InitializeDatagramKeys(ms, constants.CipherSuiteAES256GCM); err != nil {
		b.Fatalf("keys: %v", err)
	}
	ep, err := NewDatagramEndpoint(newDiscardConn())
	if err != nil {
		b.Fatalf("endpoint: %v", err)
	}
	ds := &datagramSession{
		session:   s,
		peerIndex: 0x1234,
		recvCh:    make(chan []byte, 1),
		closed:    make(chan struct{}),
	}
	ds.setPeerAddr(&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9})
	return newDatagramConn(ep, ds)
}

// BenchmarkDatagramSend measures the steady-state send path. The frame buffer
// (header || ciphertext || tag) is reused with no allocation; the single residual
// alloc/op is the 12-byte nonce, which escapes to the heap through Go's cipher.AEAD
// interface boundary and is inherent to the standard library (run with -benchmem).
func BenchmarkDatagramSend(b *testing.B) {
	c := benchDatagramConn(b)
	payload := make([]byte, 1200-constants.DatagramDataOverhead)
	b.SetBytes(int64(len(payload)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := c.Send(payload); err != nil {
			b.Fatalf("send: %v", err)
		}
	}
}
