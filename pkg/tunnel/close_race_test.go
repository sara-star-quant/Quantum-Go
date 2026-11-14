package tunnel

import (
	"errors"
	"sync"
	"testing"
	"time"
)

// streamPair completes a real handshake over TCP and returns both transports.
func streamPair(t *testing.T) (client, server *Transport) {
	t.Helper()
	ca, cb := tcpPair(t)
	ci, _ := NewSession(RoleInitiator)
	ri, _ := NewSession(RoleResponder)
	errs := make(chan error, 2)
	go func() { errs <- InitiatorHandshake(ci, ca) }()
	go func() { errs <- ResponderHandshake(ri, cb) }()
	for range 2 {
		if err := within(t, "handshake", func() error { return <-errs }); err != nil {
			t.Fatalf("handshake: %v", err)
		}
	}
	client, err := NewTransport(ci, ca, DefaultTransportConfig())
	if err != nil {
		t.Fatal(err)
	}
	server, err = NewTransport(ri, cb, DefaultTransportConfig())
	if err != nil {
		t.Fatal(err)
	}
	return client, server
}

// Both sides close at the same moment while each is reading and sending. Every call must
// return, a blocked Receive must end with an error, and a second Close must be a no-op.
// Run under -race: the interesting failures are races between Close and the peer's close
// notice, not wrong return values.
func TestStreamCloseRacesPeerClose(t *testing.T) {
	for range 20 {
		client, server := streamPair(t)
		var wg sync.WaitGroup
		start := make(chan struct{})
		for _, tr := range []*Transport{client, server} {
			wg.Add(3)
			go func() { defer wg.Done(); <-start; _, _ = tr.Receive() }()
			go func() {
				defer wg.Done()
				<-start
				for range 5 {
					if tr.Send([]byte("x")) != nil {
						return
					}
				}
			}()
			go func() { defer wg.Done(); <-start; _ = tr.Close() }()
		}
		close(start)
		within(t, "close race", func() struct{} { wg.Wait(); return struct{}{} })

		for _, tr := range []*Transport{client, server} {
			if err := tr.Close(); err != nil {
				t.Fatalf("second Close: %v", err)
			}
			if _, err := tr.Receive(); err == nil {
				t.Fatal("Receive after Close returned no error")
			}
			if err := tr.Send([]byte("late")); err == nil {
				t.Fatal("Send after Close returned no error")
			}
		}
	}
}

// The datagram transport has no connection to drop, so a Close racing the peer's CLOSE frame
// must still tear both sessions down, end a blocked Recv with ErrTunnelClosed, and leave no
// session in either registry.
func TestDatagramCloseRacesPeerClose(t *testing.T) {
	for i := range 10 {
		client, server, epA, epB := dgramPair(t, uint64(100+i), 0, 0, 0)
		var wg sync.WaitGroup
		start := make(chan struct{})
		recvErr := make(chan error, 2)
		for _, c := range []*DatagramConn{client, server} {
			wg.Add(3)
			go func() {
				defer wg.Done()
				<-start
				_, err := c.Recv()
				recvErr <- err
			}()
			go func() {
				defer wg.Done()
				<-start
				for range 5 {
					_ = c.Send([]byte("x"))
				}
			}()
			go func() { defer wg.Done(); <-start; _ = c.Close() }()
		}
		close(start)
		within(t, "datagram close race", func() struct{} { wg.Wait(); return struct{}{} })

		for range 2 {
			if err := <-recvErr; err != nil && !errors.Is(err, ErrTunnelClosed) {
				t.Fatalf("Recv ended with %v, want ErrTunnelClosed", err)
			}
		}
		for _, c := range []*DatagramConn{client, server} {
			if err := c.Close(); err != nil {
				t.Fatalf("second Close: %v", err)
			}
			if err := c.Send([]byte("late")); !errors.Is(err, ErrTunnelClosed) {
				t.Fatalf("Send after Close: %v, want ErrTunnelClosed", err)
			}
			if err := c.SendBatch([][]byte{[]byte("late")}); !errors.Is(err, ErrTunnelClosed) {
				t.Fatalf("SendBatch after Close: %v, want ErrTunnelClosed", err)
			}
		}
		deadline := time.Now().Add(5 * time.Second)
		for epA.registry.lookup(client.ds.index) != nil || epB.registry.lookup(server.ds.index) != nil {
			if time.Now().After(deadline) {
				t.Fatal("a closed session is still registered")
			}
			time.Sleep(5 * time.Millisecond)
		}
		_ = epA.Close()
		_ = epB.Close()
	}
}
