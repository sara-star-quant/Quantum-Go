package tunnel

import (
	"bytes"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	qerrors "github.com/sara-star-quant/quantum-go/internal/errors"
)

type fakeAddr string

func (a fakeAddr) Network() string { return "fake" }
func (a fakeAddr) String() string  { return string(a) }

type addrConn struct {
	net.Conn
	addr net.Addr
}

func (c addrConn) RemoteAddr() net.Addr { return c.addr }

func TestExtractRemoteIP(t *testing.T) {
	cases := []struct {
		name string
		addr net.Addr
		want string
	}{
		{"tcp", &net.TCPAddr{IP: net.ParseIP("192.0.2.7"), Port: 4433}, "192.0.2.7"},
		{"other network with port", fakeAddr("198.51.100.2:9"), "198.51.100.2"},
		{"no port", fakeAddr("peer-without-port"), "peer-without-port"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := extractRemoteIP(addrConn{addr: tc.addr}); got != tc.want {
				t.Fatalf("extractRemoteIP = %q, want %q", got, tc.want)
			}
		})
	}
}

// recObserver records the calls the failure paths make, in order.
type recObserver struct {
	quietObserver
	calls    []string
	protoErr error
}

func (o *recObserver) OnSessionFailed(error) { o.calls = append(o.calls, "failed") }
func (o *recObserver) OnSessionEnd()         { o.calls = append(o.calls, "end") }
func (o *recObserver) OnProtocolError(err error) {
	o.calls = append(o.calls, "protocol")
	o.protoErr = err
}

func TestFailSessionReportsFailureThenEnd(t *testing.T) {
	s, err := NewSession(RoleResponder)
	if err != nil {
		t.Fatal(err)
	}
	l := &Listener{}
	l.failSession(s, errors.New("boom")) // no observer: must not panic

	o := &recObserver{}
	s.SetObserver(o)
	l.failSession(s, errors.New("boom"))
	if len(o.calls) != 2 || o.calls[0] != "failed" || o.calls[1] != "end" {
		t.Fatalf("calls = %v, want [failed end]", o.calls)
	}
}

func TestRecordProtocolErrorReportsOnlyProtocolErrors(t *testing.T) {
	s, err := NewSession(RoleResponder)
	if err != nil {
		t.Fatal(err)
	}
	o := &recObserver{}
	s.SetObserver(o)
	tr := &Transport{session: s}

	tr.recordProtocolError(nil)
	tr.recordProtocolError(errors.New("plain io error"))
	if len(o.calls) != 0 {
		t.Fatalf("non-protocol errors reached the observer: %v", o.calls)
	}
	tr.recordProtocolError(qerrors.ErrInvalidMessage)
	if len(o.calls) != 1 || !errors.Is(o.protoErr, qerrors.ErrInvalidMessage) {
		t.Fatalf("calls = %v, err = %v", o.calls, o.protoErr)
	}

	s.SetObserver(nil)
	tr.recordProtocolError(qerrors.ErrInvalidMessage) // no observer: must not panic
}

func TestDatagramOpenToBranches(t *testing.T) {
	a, b := datagramSessionPair(t)
	header, ct := sealFrame(t, a, 5, []byte("payload"))

	// A nil nonce allocates scratch; a caller-owned one gives the same result.
	for _, nonce := range [][]byte{nil, make([]byte, 12)} {
		pt, err := b.DatagramOpenTo([]byte("pre-"), 0, 5, ct, header, nonce)
		if err != nil || string(pt) != "pre-payload" {
			t.Fatalf("open: pt=%q err=%v", pt, err)
		}
	}

	// A flipped ciphertext bit and a wrong sequence both fail authentication.
	bad := append([]byte(nil), ct...)
	bad[0] ^= 1
	if _, err := b.DatagramOpenTo(nil, 0, 5, bad, header, nil); err == nil {
		t.Fatal("tampered ciphertext opened")
	}
	if _, err := b.DatagramOpenTo(nil, 0, 6, ct, header, nil); err == nil {
		t.Fatal("wrong sequence opened")
	}
	// An epoch the session never held reports no cipher, not a panic.
	if _, err := b.DatagramOpenTo(nil, 9, 5, ct, header, nil); err == nil {
		t.Fatal("unknown epoch opened")
	}
}

// A failed initiator handshake must report failure then end to the observer and close the
// connection, so a caller never holds a half-open socket after an error.
func TestHandshakeOverFailureReportsAndClosesConn(t *testing.T) {
	s, err := NewSession(RoleInitiator)
	if err != nil {
		t.Fatal(err)
	}
	o := &recObserver{}
	s.SetObserver(o)
	pipe, server := net.Pipe()
	_ = server.Close()
	client := &closeSpy{Conn: pipe}
	cfg := DefaultTransportConfig()
	cfg.HandshakeTimeout = 2 * time.Second

	tun, err := handshakeOver(client, s, cfg)
	if err == nil || tun != nil {
		t.Fatalf("handshake against a closed peer: tunnel=%v err=%v", tun, err)
	}
	if len(o.calls) != 2 || o.calls[0] != "failed" || o.calls[1] != "end" {
		t.Fatalf("observer calls = %v, want [failed end]", o.calls)
	}
	if !client.closed {
		t.Fatal("connection still open after a failed handshake")
	}
}

type closeSpy struct {
	net.Conn
	closed bool
}

func (c *closeSpy) Close() error { c.closed = true; return c.Conn.Close() }

type rw struct {
	io.Reader
	io.Writer
}

// The responder must return an error, never panic or hang, on an empty stream and on bytes
// that are not a handshake.
func TestResponderHandshakeRejectsEmptyAndGarbage(t *testing.T) {
	garbage := bytes.Repeat([]byte{0xA5, 0x00, 0xFF, 0x13}, 64)
	for name, in := range map[string][]byte{"empty": nil, "garbage": garbage} {
		t.Run(name, func(t *testing.T) {
			s, err := NewSession(RoleResponder)
			if err != nil {
				t.Fatal(err)
			}
			if err := ResponderHandshake(s, rw{bytes.NewReader(in), io.Discard}); err == nil {
				t.Fatal("responder accepted a non-handshake stream")
			}
		})
	}
}
