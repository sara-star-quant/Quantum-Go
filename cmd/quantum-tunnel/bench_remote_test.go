package main

import (
	"testing"
	"time"
)

// A receiver and a sender in separate goroutines over loopback, in both modes. The same
// code runs on two hosts with --serve and --connect.
func TestRemoteThroughputBothModes(t *testing.T) {
	const total = 4 << 20
	chunk := make([]byte, 8<<10)
	for _, plain := range []bool{false, true} {
		name := "tunnel"
		if plain {
			name = "plain"
		}
		t.Run(name, func(t *testing.T) {
			ready := make(chan string, 1)
			type served struct {
				res throughputResult
				err error
			}
			done := make(chan served, 1)
			go func() {
				r, err := serveThroughput("127.0.0.1:0", plain, 30*time.Second, ready)
				done <- served{r, err}
			}()
			var addr string
			select {
			case addr = <-ready:
			case <-time.After(10 * time.Second):
				t.Fatal("receiver never became ready")
			}

			sent, err := connectThroughput(addr, plain, total, 30*time.Second, chunk, 5)
			if err != nil {
				t.Fatalf("connect: %v", err)
			}
			var srv served
			select {
			case srv = <-done:
			case <-time.After(30 * time.Second):
				t.Fatal("receiver did not finish")
			}
			if srv.err != nil {
				t.Fatalf("serve: %v", srv.err)
			}
			if sent.sent < total || srv.res.received != sent.sent {
				t.Fatalf("sent %d, received %d, want at least %d delivered intact", sent.sent, srv.res.received, total)
			}
			if srv.res.recvDur <= 0 || srv.res.recvMBps() <= 0 {
				t.Fatalf("no receive timing: %+v", srv.res)
			}
			if !plain && (srv.res.cipher != "AES-256-GCM" || sent.cipher != "AES-256-GCM") {
				t.Fatalf("negotiated cipher server %q client %q", srv.res.cipher, sent.cipher)
			}
		})
	}
}

func TestConnectFailsFastWhenNothingListens(t *testing.T) {
	start := time.Now()
	if _, err := connectThroughput("127.0.0.1:1", false, 1<<20, 5*time.Second, make([]byte, 1024), 2); err == nil {
		t.Fatal("connect to a closed port succeeded")
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Fatalf("gave up after %v, want a couple of attempts", d)
	}
}
