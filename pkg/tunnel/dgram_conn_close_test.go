package tunnel

import (
	"errors"
	"testing"

	qerrors "github.com/sara-star-quant/quantum-go/internal/errors"
)

func closedConnWithBuffered(t *testing.T, payloads ...string) (*DatagramConn, *captureConn) {
	t.Helper()
	conn := &captureConn{}
	e := mustEndpoint(t, conn)
	_, _, ds := registerEstablished(t, e, udp("198.51.100.1", 4000))
	c := &DatagramConn{ep: e, ds: ds}
	for _, p := range payloads {
		ds.recvCh <- []byte(p)
	}
	ds.teardown(e.registry)
	return c, conn
}

// After the session closes, Recv must hand over what is already buffered, in order, and then
// return ErrTunnelClosed every time. The select over the data channel and the closed signal used
// to pick at random, so a reader could see a payload, then the error, then another payload.
func TestRecvAfterCloseDrainsTheBufferThenFails(t *testing.T) {
	for trial := range 200 {
		c, _ := closedConnWithBuffered(t, "one", "two", "three")
		for i, want := range []string{"one", "two", "three"} {
			got, err := c.Recv()
			if err != nil || string(got) != want {
				t.Fatalf("trial %d, call %d: got %q, %v; want %q", trial, i+1, got, err, want)
			}
		}
		for i := range 3 {
			if _, err := c.Recv(); !errors.Is(err, qerrors.ErrTunnelClosed) {
				t.Fatalf("trial %d, call %d after the buffer: got %v, want ErrTunnelClosed", trial, i+4, err)
			}
		}
	}
}

// A closed session writes nothing when asked to rekey.
func TestRekeyOnAClosedSessionWritesNothing(t *testing.T) {
	conn := &captureConn{}
	e := mustEndpoint(t, conn)
	_, _, ds := registerEstablished(t, e, udp("198.51.100.1", 4000))
	// registerEstablished builds the responder side; the initiator drives rekey.
	ds.getSession().Role = RoleInitiator
	c := &DatagramConn{ep: e, ds: ds}
	ds.getSession().Close()
	ds.teardown(e.registry)

	if err := c.Rekey(); err == nil {
		t.Fatal("Rekey on a closed session must fail")
	}
	conn.mu.Lock()
	defer conn.mu.Unlock()
	if len(conn.written) != 0 {
		t.Fatalf("Rekey on a closed session wrote %d datagrams", len(conn.written))
	}
}
