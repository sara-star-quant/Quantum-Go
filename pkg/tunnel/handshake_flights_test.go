package tunnel

import (
	"net"
	"sync"
	"testing"
)

// flightRecorder wraps one end of a pipe and logs which side wrote, so a test can
// count direction changes (flights) on the wire.
type flightRecorder struct {
	net.Conn
	side byte
	mu   *sync.Mutex
	log  *[]byte
}

func (f *flightRecorder) Write(p []byte) (int, error) {
	f.mu.Lock()
	if n := len(*f.log); n == 0 || (*f.log)[n-1] != f.side {
		*f.log = append(*f.log, f.side)
	}
	f.mu.Unlock()
	return f.Conn.Write(p)
}

// TestStreamHandshakeFlights pins the stream handshake to three flights: ClientHello,
// then ServerHello+ServerFinished together, then ClientFinished. The initiator is
// keyed after one round trip.
func TestStreamHandshakeFlights(t *testing.T) {
	c, s := net.Pipe()
	var (
		mu  sync.Mutex
		log []byte
	)
	client := &flightRecorder{Conn: c, side: 'C', mu: &mu, log: &log}
	server := &flightRecorder{Conn: s, side: 'S', mu: &mu, log: &log}

	ci, _ := NewSession(RoleInitiator)
	ri, _ := NewSession(RoleResponder)
	errc := make(chan error, 1)
	go func() { errc <- ResponderHandshake(ri, server) }()
	if err := InitiatorHandshake(ci, client); err != nil {
		t.Fatalf("InitiatorHandshake: %v", err)
	}
	if err := <-errc; err != nil {
		t.Fatalf("ResponderHandshake: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if got := string(log); got != "CSC" {
		t.Fatalf("flights = %q, want %q (ClientHello, ServerHello+ServerFinished, ClientFinished)", got, "CSC")
	}
}
