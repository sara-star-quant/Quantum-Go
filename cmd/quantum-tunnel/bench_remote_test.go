package main

import (
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"github.com/sara-star-quant/quantum-go/pkg/tunnel"
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
				r, err := serveFlows("127.0.0.1:0", plain, 30*time.Second, 1, ready)
				done <- served{r, err}
			}()
			var addr string
			select {
			case addr = <-ready:
			case <-time.After(10 * time.Second):
				t.Fatal("receiver never became ready")
			}

			sent, err := connectFlows(addr, plain, total, 30*time.Second, chunk, 5, 1)
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
	if _, err := connectFlows("127.0.0.1:1", false, 1<<20, 5*time.Second, make([]byte, 1024), 2, 1); err == nil {
		t.Fatal("connect to a closed port succeeded")
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Fatalf("gave up after %v, want a couple of attempts", d)
	}
}

// Several flows share one receiver; every byte sent arrives and the cipher is negotiated
// on each.
func TestRemoteThroughputMultiFlow(t *testing.T) {
	const total, flows = 6 << 20, 3
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
				r, err := serveFlows("127.0.0.1:0", plain, 30*time.Second, flows, ready)
				done <- served{r, err}
			}()
			var addr string
			select {
			case addr = <-ready:
			case <-time.After(10 * time.Second):
				t.Fatal("receiver never became ready")
			}
			sent, err := connectFlows(addr, plain, total, 30*time.Second, chunk, 5, flows)
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
			if !plain && srv.res.cipher != "AES-256-GCM" {
				t.Fatalf("negotiated cipher %q", srv.res.cipher)
			}
		})
	}
}

// The datagram mode over loopback, single and batched sends. Loopback can drop a
// datagram under load, so the test checks that most arrive and that the loss figure
// matches the sequence gap instead of demanding zero.
func TestRemoteDatagram(t *testing.T) {
	for _, batch := range []int{1, 8} {
		t.Run(fmt.Sprintf("batch=%d", batch), func(t *testing.T) {
			ready := make(chan string, 1)
			type served struct {
				res datagramResult
				err error
			}
			done := make(chan served, 1)
			go func() {
				r, err := serveDatagram("127.0.0.1:0", false, 3*time.Second, ready)
				done <- served{r, err}
			}()
			var addr string
			select {
			case addr = <-ready:
			case <-time.After(10 * time.Second):
				t.Fatal("receiver never became ready")
			}
			sent, err := connectDatagram(addr, false, 500*time.Millisecond, 1000, batch, 5, 0)
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
			r := srv.res
			if r.datagrams == 0 || r.datagrams > sent.datagrams {
				t.Fatalf("received %d of %d sent", r.datagrams, sent.datagrams)
			}
			if r.expected < r.datagrams || r.expected > sent.datagrams {
				t.Fatalf("expected %d outside [received %d, sent %d]", r.expected, r.datagrams, sent.datagrams)
			}
			if r.cipher != "AES-256-GCM" || r.recvMBps() <= 0 {
				t.Fatalf("cipher %q rate %.2f", r.cipher, r.recvMBps())
			}
			if l := r.lossPct(); l < 0 || l > 100 {
				t.Fatalf("loss %.2f%% out of range", l)
			}
		})
	}
}

// waitReady returns the receiver's bound address, failing fast instead of hanging if it
// never comes up.
func waitReady(t *testing.T, ready <-chan string) string {
	t.Helper()
	select {
	case addr := <-ready:
		return addr
	case <-time.After(10 * time.Second):
		t.Fatal("receiver never became ready")
		return ""
	}
}

func TestConnectDatagramRejectsBadRecordSize(t *testing.T) {
	for _, size := range []int{seqLen - 1, 1 << 20} {
		if _, err := connectDatagram("127.0.0.1:1", false, time.Second, size, 1, 1, 0); err == nil {
			t.Fatalf("record size %d accepted", size)
		}
	}
}

// A duration-limited sender must finish without error while the receiver's own
// deadline passes, on every flow: the receiver drains instead of closing early.
func TestRemoteFlowsSenderSurvivesReceiverDeadline(t *testing.T) {
	const flows = 4
	chunk := make([]byte, 8<<10)
	for _, plain := range []bool{false, true} {
		t.Run(fmt.Sprintf("plain=%v", plain), func(t *testing.T) {
			ready := make(chan string, 1)
			done := make(chan error, 1)
			go func() {
				_, err := serveFlows("127.0.0.1:0", plain, time.Second, flows, ready)
				done <- err
			}()
			addr := waitReady(t, ready)
			sent, err := connectFlows(addr, plain, 1<<40, 2*time.Second, chunk, 5, flows)
			if err != nil {
				t.Fatalf("sender failed after the receiver deadline: %v", err)
			}
			if sent.sent == 0 || sent.cpu < 0 {
				t.Fatalf("no send result: %+v", sent)
			}
			select {
			case err := <-done:
				if err != nil {
					t.Fatalf("serve: %v", err)
				}
			case <-time.After(30 * time.Second):
				t.Fatal("receiver did not finish")
			}
		})
	}
}

// With a rate set the sender offers close to that load, not a blast. Loss is not
// asserted: UDP may drop on a loaded machine, and the loss figure itself is covered by
// the accounting checks in TestRemoteDatagram.
func TestRemoteDatagramPacedRate(t *testing.T) {
	const rate = 40.0 // Mbps
	ready := make(chan string, 1)
	done := make(chan datagramResult, 1)
	serveErr := make(chan error, 1)
	go func() {
		r, err := serveDatagram("127.0.0.1:0", false, 3*time.Second, ready)
		serveErr <- err
		done <- r
	}()
	addr := waitReady(t, ready)
	sent, err := connectDatagram(addr, false, time.Second, 1000, 4, 5, rate)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	got := float64(sent.sent) * 8 / sent.sendDur.Seconds() / 1e6
	if got < rate*0.8 || got > rate*1.2 {
		t.Fatalf("offered %.1f Mbps, want within 20%% of %.0f", got, rate)
	}
	var r datagramResult
	select {
	case r = <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("receiver did not finish")
	}
	if err := <-serveErr; err != nil {
		t.Fatalf("serve: %v", err)
	}
	if r.datagrams == 0 {
		t.Fatalf("receiver counted nothing at a paced %v Mbps", rate)
	}
}

func TestConnectDatagramRejectsNegativeRate(t *testing.T) {
	if _, err := connectDatagram("127.0.0.1:1", false, time.Second, 1000, 1, 1, -1); err == nil {
		t.Fatal("negative rate accepted")
	}
}

// A sender that opens fewer flows than the receiver expects ends the run with the
// flows it got instead of hanging the receiver.
func TestRemoteFlowsFewerThanExpected(t *testing.T) {
	old := flowAcceptTimeout
	flowAcceptTimeout = 500 * time.Millisecond
	t.Cleanup(func() { flowAcceptTimeout = old })

	ready := make(chan string, 1)
	done := make(chan throughputResult, 1)
	go func() {
		r, _ := serveFlows("127.0.0.1:0", true, 30*time.Second, 3, ready)
		done <- r
	}()
	addr := waitReady(t, ready)
	sent, err := connectFlows(addr, true, 4<<20, 30*time.Second, make([]byte, 8<<10), 5, 2)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	select {
	case r := <-done:
		if r.flows != 2 || r.received != sent.sent {
			t.Fatalf("receiver saw %d flows and %d bytes, sender sent %d over 2", r.flows, r.received, sent.sent)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("receiver hung waiting for the missing flow")
	}
}

// One failed flow does not discard the others: the sender reports what the healthy
// flows moved and an error naming the count.
func TestConnectFlowsKeepsHealthyFlowResults(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	go func() { // accept one flow, drain it, refuse the rest by closing at once
		for i := 0; ; i++ {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			if i == 0 {
				go func() { _, _ = io.Copy(io.Discard, c); _ = c.Close() }()
			} else {
				_ = c.Close()
			}
		}
	}()
	res, err := connectFlows(ln.Addr().String(), true, 1<<30, time.Second, make([]byte, 8<<10), 2, 4)
	if err == nil {
		t.Fatal("expected an error for the failed flows")
	}
	if res.sent == 0 {
		t.Fatalf("healthy flow result was dropped: %v", err)
	}
}

// A sender that outlasts the receiver's window finishes without error, and the receiver
// counts only its own window.
func TestRemoteDatagramSenderOutlastsReceiverWindow(t *testing.T) {
	ready := make(chan string, 1)
	done := make(chan datagramResult, 1)
	go func() {
		r, _ := serveDatagram("127.0.0.1:0", false, time.Second, ready)
		done <- r
	}()
	addr := waitReady(t, ready)
	sent, err := connectDatagram(addr, false, 3*time.Second, 1000, 1, 5, 20)
	if err != nil {
		t.Fatalf("sender failed after the receiver's window: %v", err)
	}
	select {
	case r := <-done:
		if r.datagrams == 0 || r.datagrams >= sent.datagrams {
			t.Fatalf("receiver counted %d of %d sent: want a partial, nonzero window", r.datagrams, sent.datagrams)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("receiver did not finish")
	}
}

// A peer that completes the handshake and then sends nothing, or only datagrams too
// short to carry a sequence number, ends the receiver by idle timeout with zero counted.
func TestRemoteDatagramIdleAndShortPayloads(t *testing.T) {
	ready := make(chan string, 1)
	done := make(chan datagramResult, 1)
	go func() {
		r, _ := serveDatagram("127.0.0.1:0", false, time.Second, ready)
		done <- r
	}()
	addr := waitReady(t, ready)
	ep, _, err := datagramEndpoint(":0", false)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ep.Close() }()
	dst, _ := net.ResolveUDPAddr("udp", addr)
	conn, err := tunnel.DialDatagram(ep, dst)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	for range 3 {
		_ = conn.Send([]byte{1, 2, 3})
	}
	select {
	case r := <-done:
		if r.datagrams != 0 || r.expected != 0 || r.lossPct() != 0 {
			t.Fatalf("short payloads were counted: %+v", r)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("receiver hung on an idle peer")
	}
}

func TestBenchFlagError(t *testing.T) {
	if err := benchFlagError(false, false, []string{"--datagram"}); err == nil {
		t.Fatal("remote-only flag without --serve or --connect accepted")
	}
	if err := benchFlagError(true, true, nil); err == nil {
		t.Fatal("--baseline with --connect accepted")
	}
	if err := benchFlagError(true, false, []string{"--datagram", "--rate"}); err != nil {
		t.Fatalf("valid remote combination rejected: %v", err)
	}
	if err := benchFlagError(false, true, nil); err != nil {
		t.Fatalf("--baseline without remote rejected: %v", err)
	}
}
