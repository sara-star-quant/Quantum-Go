package main

import (
	"errors"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	qerrors "github.com/sara-star-quant/quantum-go/internal/errors"
	"github.com/sara-star-quant/quantum-go/pkg/tunnel"
)

// tunnelPair returns an established insecure tunnel pair: the dialing side (the rekey
// initiator) and the accepting side.
func tunnelPair(t *testing.T) (cli, srv *tunnel.Tunnel) {
	t.Helper()
	ln, err := tunnel.ListenInsecure("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	acc := make(chan *tunnel.Tunnel, 1)
	go func() {
		s, err := ln.Accept()
		if err != nil {
			close(acc)
			return
		}
		acc <- s
	}()
	cli, err = tunnel.DialInsecure("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	srv = <-acc
	if srv == nil {
		t.Fatal("accept failed")
	}
	t.Cleanup(func() { _ = cli.Close(); _ = srv.Close() })
	return cli, srv
}

// tcpConnPair returns two connected TCP sockets on loopback.
func tcpConnPair(t *testing.T) (a, b *net.TCPConn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	acc := make(chan net.Conn, 1)
	go func() { c, _ := ln.Accept(); acc <- c }()
	ca, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	cb := <-acc
	_ = ca.SetDeadline(time.Now().Add(30 * time.Second))
	_ = cb.SetDeadline(time.Now().Add(30 * time.Second))
	t.Cleanup(func() { _ = ca.Close(); _ = cb.Close() })
	return ca.(*net.TCPConn), cb.(*net.TCPConn)
}

// A peer that has already sent its EOF frame must not stop the pipe from reading the tunnel:
// the rekey response and later records still arrive on it. The client (the rekey initiator)
// uploads, the far side has nothing to say and says so first, and a rekey started after that
// EOF must still finish and the upload must arrive whole.
func TestPipeFinishesARekeyAfterThePeerSentEOF(t *testing.T) {
	cli, srv := tunnelPair(t)
	app, pipeSide := tcpConnPair(t)

	pipeDone := make(chan struct{})
	go func() { defer close(pipeDone); pipe(pipeSide, cli, 0) }()

	// The far side reads like a forwarder would: it counts data frames and ends on EOF.
	var got atomic.Int64
	srvDone := make(chan error, 1)
	go func() {
		for {
			data, err := srv.Receive()
			if err != nil {
				srvDone <- err
				return
			}
			switch data[0] {
			case frameData:
				got.Add(int64(len(data) - 1))
			case frameEOF:
				srvDone <- nil
				return
			}
		}
	}()

	// The far side finishes first. The app sees the half-close, which proves the pipe
	// consumed the EOF frame before the rekey below starts.
	if err := srv.Send([]byte{frameEOF}); err != nil {
		t.Fatal(err)
	}
	if _, err := app.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Fatalf("app read after the far side's EOF: %v, want io.EOF", err)
	}

	chunk := make([]byte, 32<<10)
	var sent int64
	write := func() {
		t.Helper()
		if _, err := app.Write(chunk); err != nil {
			t.Fatalf("app write: %v", err)
		}
		sent += int64(len(chunk))
	}
	write()
	if err := cli.SendRekey(); err != nil {
		t.Fatalf("first rekey: %v", err)
	}
	write()

	// A second rekey is refused while the first is pending, and accepted once the pipe has
	// processed the response. It can only be processed if the pipe still reads the tunnel.
	deadline := time.Now().Add(15 * time.Second)
	for {
		err := cli.SendRekey()
		if err == nil {
			break
		}
		if !errors.Is(err, qerrors.ErrRekeyInProgress) {
			t.Fatalf("second rekey: %v", err)
		}
		if time.Now().After(deadline) {
			t.Fatal("the first rekey never finished: the pipe stopped reading the tunnel after the peer's EOF")
		}
		time.Sleep(5 * time.Millisecond)
	}
	write()

	if err := app.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	if err := <-srvDone; err != nil {
		t.Fatalf("far side: %v", err)
	}
	if got.Load() != sent {
		t.Fatalf("far side received %d bytes, the app sent %d", got.Load(), sent)
	}
	select {
	case <-pipeDone:
	case <-time.After(15 * time.Second):
		t.Fatal("pipe did not end after both sides sent EOF")
	}
}
