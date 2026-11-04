package tunnel

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	qerrors "github.com/sara-star-quant/quantum-go/internal/errors"
	"github.com/sara-star-quant/quantum-go/pkg/protocol"
)

// faultConn wraps a net.Conn and injects the failures a real network produces.
type faultConn struct {
	net.Conn
	mu       sync.Mutex
	writeErr error         // returned by every Write when set
	stall    bool          // Write blocks until its deadline
	dropAll  bool          // swallow writes (report success, send nothing)
	cutAfter int           // when > 0, only this many bytes of the next Write go out, then the conn closes
	delay    time.Duration // added before each Write
	wdl      time.Time     // last write deadline
	done     chan struct{} // closed by Close
	once     sync.Once
}

func (c *faultConn) Close() error {
	c.once.Do(func() { close(c.done) })
	return c.Conn.Close()
}

func (c *faultConn) set(f func(*faultConn)) { c.mu.Lock(); f(c); c.mu.Unlock() }

func (c *faultConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	err, stall, drop, cut, delay, wdl := c.writeErr, c.stall, c.dropAll, c.cutAfter, c.delay, c.wdl
	c.mu.Unlock()
	if delay > 0 {
		time.Sleep(delay)
	}
	switch {
	case err != nil:
		return 0, err
	case stall:
		var expire <-chan time.Time
		if !wdl.IsZero() {
			expire = time.After(time.Until(wdl))
		}
		select { // a blocked socket write ends at its deadline or when the conn closes
		case <-expire:
			return 0, os.ErrDeadlineExceeded
		case <-c.done:
			return 0, net.ErrClosed
		}
	case drop:
		return len(p), nil
	case cut > 0 && cut < len(p):
		n, _ := c.Conn.Write(p[:cut])
		_ = c.Conn.Close()
		return n, io.ErrClosedPipe
	}
	return c.Conn.Write(p)
}

func (c *faultConn) SetWriteDeadline(t time.Time) error {
	c.mu.Lock()
	c.wdl = t
	c.mu.Unlock()
	return c.Conn.SetWriteDeadline(t)
}

func tcpPair(t *testing.T) (a, b net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	acc := make(chan net.Conn, 1)
	go func() { c, _ := ln.Accept(); acc <- c }()
	a, err = net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	b = within(t, "accept", func() net.Conn { return <-acc })
	t.Cleanup(func() { _ = a.Close(); _ = b.Close() })
	return a, b
}

// faultyClient completes a real handshake over TCP and returns the client Transport (its
// conn wrapped in a faultConn) plus the peer's raw socket, which the test drives by hand.
func faultyClient(t *testing.T, cfg TransportConfig) (*Transport, *faultConn, net.Conn) {
	t.Helper()
	ca, cb := tcpPair(t)
	fc := &faultConn{Conn: ca, done: make(chan struct{})}
	ci, _ := NewSession(RoleInitiator)
	ri, _ := NewSession(RoleResponder)
	errs := make(chan error, 2)
	go func() { errs <- InitiatorHandshake(ci, fc) }()
	go func() { errs <- ResponderHandshake(ri, cb) }()
	for range 2 {
		if err := within(t, "handshake", func() error { return <-errs }); err != nil {
			t.Fatalf("handshake: %v", err)
		}
	}
	tr, err := NewTransport(ci, fc, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tr.Close() })
	return tr, fc, cb
}

func frame(typ protocol.MessageType, payload []byte) []byte {
	b := make([]byte, protocol.HeaderSize+len(payload))
	b[0] = byte(typ)
	binary.BigEndian.PutUint32(b[1:], uint32(len(payload)))
	copy(b[protocol.HeaderSize:], payload)
	return b
}

func receiveResult(t *testing.T, tr *Transport) ([]byte, error) {
	t.Helper()
	type r struct {
		p   []byte
		err error
	}
	got := within(t, "Receive", func() r { p, err := tr.Receive(); return r{p, err} })
	return got.p, got.err
}

func TestStreamSendSurfacesWriteFailures(t *testing.T) {
	boom := errors.New("connection reset")
	for name, tc := range map[string]struct {
		set  func(*faultConn)
		want func(error) bool
	}{
		"write error":      {func(c *faultConn) { c.writeErr = boom }, func(e error) bool { return errors.Is(e, boom) }},
		"mid-record close": {func(c *faultConn) { c.cutAfter = 7 }, func(e error) bool { return errors.Is(e, io.ErrClosedPipe) }},
	} {
		t.Run(name, func(t *testing.T) {
			tr, fc, _ := faultyClient(t, DefaultTransportConfig())
			fc.set(tc.set)
			err := within(t, "Send", func() error { return tr.Send([]byte("payload")) })
			if err == nil || !tc.want(err) {
				t.Fatalf("Send = %v", err)
			}
		})
	}
}

func TestStreamWriteTimeoutDoesNotHang(t *testing.T) {
	cfg := DefaultTransportConfig()
	cfg.WriteTimeout = 100 * time.Millisecond
	tr, fc, _ := faultyClient(t, cfg)
	fc.set(func(c *faultConn) { c.stall = true })
	if err := within(t, "Send", func() error { return tr.Send([]byte("payload")) }); err == nil {
		t.Fatal("Send into a stalled connection reported success")
	}
}

func TestStreamReadTimeoutDoesNotHang(t *testing.T) {
	cfg := DefaultTransportConfig()
	cfg.ReadTimeout = 100 * time.Millisecond
	tr, _, _ := faultyClient(t, cfg)
	_, err := receiveResult(t, tr)
	var ne net.Error
	if !errors.As(err, &ne) || !ne.Timeout() {
		t.Fatalf("Receive on a silent peer = %v, want a timeout", err)
	}
}

func TestStreamReceiveRejectsBrokenFrames(t *testing.T) {
	oversize := make([]byte, protocol.HeaderSize)
	oversize[0] = byte(protocol.MessageTypeData)
	binary.BigEndian.PutUint32(oversize[1:], 0xFFFFFFFF)

	for name, tc := range map[string]struct {
		send func(net.Conn)
		want func(error) bool
	}{
		"oversize length prefix": {
			func(c net.Conn) { _, _ = c.Write(oversize) },
			func(e error) bool { return errors.Is(e, qerrors.ErrMessageTooLarge) },
		},
		"half a header then close": {
			func(c net.Conn) { _, _ = c.Write([]byte{byte(protocol.MessageTypeData), 0, 0}); _ = c.Close() },
			func(e error) bool { return errors.Is(e, io.ErrUnexpectedEOF) },
		},
		"half a record then close": {
			func(c net.Conn) {
				f := frame(protocol.MessageTypeData, make([]byte, 100))
				_, _ = c.Write(f[:40])
				_ = c.Close()
			},
			func(e error) bool { return errors.Is(e, io.ErrUnexpectedEOF) },
		},
		"clean close": {
			func(c net.Conn) { _ = c.Close() },
			func(e error) bool { return errors.Is(e, qerrors.ErrTunnelClosed) },
		},
		"unknown message type": {
			func(c net.Conn) { _, _ = c.Write(frame(protocol.MessageType(0xEE), nil)) },
			func(e error) bool { return e != nil },
		},
		"forged data record": {
			func(c net.Conn) { _, _ = c.Write(frame(protocol.MessageTypeData, make([]byte, 64))) },
			func(e error) bool { return e != nil },
		},
	} {
		t.Run(name, func(t *testing.T) {
			tr, _, peer := faultyClient(t, DefaultTransportConfig())
			tc.send(peer)
			if _, err := receiveResult(t, tr); !tc.want(err) {
				t.Fatalf("Receive = %v", err)
			}
		})
	}
}

func TestStreamAlertHandling(t *testing.T) {
	codec := protocol.NewCodec()
	t.Run("close notify ends the tunnel", func(t *testing.T) {
		tr, _, peer := faultyClient(t, DefaultTransportConfig())
		_, _ = peer.Write(codec.EncodeAlert(protocol.AlertLevelWarning, protocol.AlertCodeCloseNotify, "bye"))
		if _, err := receiveResult(t, tr); !errors.Is(err, qerrors.ErrTunnelClosed) {
			t.Fatalf("got %v, want ErrTunnelClosed", err)
		}
		if err := tr.Send([]byte("x")); !errors.Is(err, qerrors.ErrTunnelClosed) {
			t.Fatalf("Send after close notify = %v", err)
		}
	})
	t.Run("fatal alert surfaces as an error", func(t *testing.T) {
		tr, _, peer := faultyClient(t, DefaultTransportConfig())
		_, _ = peer.Write(codec.EncodeAlert(protocol.AlertLevelFatal, protocol.AlertCodeInternalError, "boom"))
		_, err := receiveResult(t, tr)
		if err == nil || errors.Is(err, qerrors.ErrTunnelClosed) {
			t.Fatalf("got %v, want an alert error", err)
		}
	})
}

func TestStreamPingPong(t *testing.T) {
	tr, _, peer := faultyClient(t, DefaultTransportConfig())

	// A ping from the peer is answered with a pong and Receive keeps waiting.
	done := make(chan error, 1)
	go func() { _, err := tr.Receive(); done <- err }()
	_, _ = peer.Write(frame(protocol.MessageTypePing, nil))
	hdr := make([]byte, protocol.HeaderSize)
	_ = peer.SetReadDeadline(time.Now().Add(30 * time.Second))
	if _, err := io.ReadFull(peer, hdr); err != nil || hdr[0] != byte(protocol.MessageTypePong) {
		t.Fatalf("reply to ping = %v %v", hdr, err)
	}
	select {
	case err := <-done:
		t.Fatalf("Receive returned %v on a ping", err)
	case <-time.After(50 * time.Millisecond):
	}

	// Our ping reaches the peer.
	if err := tr.SendPing(); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(peer, hdr); err != nil || hdr[0] != byte(protocol.MessageTypePing) {
		t.Fatalf("SendPing wire bytes = %v %v", hdr, err)
	}

	// A flood of unsolicited pongs and pings never grows the stack or returns.
	for range 500 {
		_, _ = peer.Write(frame(protocol.MessageTypePong, nil))
	}
	_ = tr.Close()
	if err := within(t, "Receive after Close", func() error { return <-done }); err == nil {
		t.Fatal("Receive returned nil after Close")
	}
}

// Rekey while several goroutines send: every record must arrive, in an unbroken
// stream, whichever key it was sealed under.
func TestStreamRekeyUnderLoad(t *testing.T) {
	ca, cb := tcpPair(t)
	ci, _ := NewSession(RoleInitiator)
	ri, _ := NewSession(RoleResponder)
	errs := make(chan error, 2)
	go func() { errs <- InitiatorHandshake(ci, ca) }()
	go func() { errs <- ResponderHandshake(ri, cb) }()
	for range 2 {
		if err := within(t, "handshake", func() error { return <-errs }); err != nil {
			t.Fatal(err)
		}
	}
	client, _ := NewTransport(ci, ca, DefaultTransportConfig())
	server, _ := NewTransport(ri, cb, DefaultTransportConfig())

	const senders, each = 4, 60
	var got atomic.Int64
	recvDone := make(chan struct{})
	go func() {
		defer close(recvDone)
		for got.Load() < senders*each {
			if _, err := server.Receive(); err != nil {
				t.Errorf("server Receive: %v", err)
				return
			}
			got.Add(1)
		}
	}()
	// The client must also read to process the rekey response.
	go func() {
		for {
			if _, err := client.Receive(); err != nil {
				return
			}
		}
	}()

	var wg sync.WaitGroup
	for range senders {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range each {
				if err := client.Send([]byte("load")); err != nil {
					t.Errorf("Send: %v", err)
					return
				}
				if i == each/2 {
					_ = client.SendRekey()
				}
			}
		}()
	}
	wg.Wait()
	within(t, "all records", func() struct{} { <-recvDone; return struct{}{} })
	if got.Load() != senders*each {
		t.Fatalf("received %d of %d records", got.Load(), senders*each)
	}
	_ = client.Close()
	_ = server.Close()
}
