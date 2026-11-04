package tunnel_test

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sara-star-quant/quantum-go/pkg/crypto"
	"github.com/sara-star-quant/quantum-go/pkg/tunnel"
)

// countingObserver counts the session events a plain send and receive produce.
type countingObserver struct {
	encrypts, decrypts atomic.Int32
}

func (o *countingObserver) OnSessionStart()       {}
func (o *countingObserver) OnSessionEnd()         {}
func (o *countingObserver) OnSessionFailed(error) {}
func (o *countingObserver) OnReplayDetected()     {}
func (o *countingObserver) OnAuthFailure()        {}
func (o *countingObserver) OnProtocolError(error) {}
func (o *countingObserver) OnHandshakeStart(ctx context.Context) (context.Context, func(error)) {
	return ctx, func(error) {}
}
func (o *countingObserver) OnEncrypt(ctx context.Context, _ int) (context.Context, func(error)) {
	o.encrypts.Add(1)
	return ctx, func(error) {}
}
func (o *countingObserver) OnDecrypt(ctx context.Context, _ int) (context.Context, func(error)) {
	o.decrypts.Add(1)
	return ctx, func(error) {}
}
func (o *countingObserver) OnRekeyStart(ctx context.Context) (context.Context, func(error)) {
	return ctx, func(error) {}
}

func TestPublicSessionObserverAndFIPSFlag(t *testing.T) {
	ln, err := tunnel.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer func() { _ = ln.Close() }()
	got := make(chan []byte, 1)
	go func() {
		c, aerr := ln.Accept()
		if aerr != nil {
			return
		}
		p, _ := c.Receive()
		got <- p
	}()

	client, err := tunnel.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer func() { _ = client.Close() }()

	obs := &countingObserver{}
	s := client.Session()
	s.SetObserver(obs)
	if err := client.Send([]byte("observed")); err != nil {
		t.Fatalf("Send: %v", err)
	}
	select {
	case p := <-got:
		if string(p) != "observed" {
			t.Fatalf("got %q", p)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("record not delivered")
	}
	if obs.encrypts.Load() == 0 {
		t.Fatal("observer saw no encrypt event after SetObserver")
	}

	// FIPS compliance needs FIPS mode and an approved negotiated cipher.
	want := crypto.FIPSMode() && s.CipherSuite.IsFIPSApproved()
	if got := s.IsFIPSCompliant(); got != want {
		t.Fatalf("IsFIPSCompliant = %v, want %v", got, want)
	}
	if crypto.FIPSMode() && !s.IsFIPSCompliant() {
		t.Fatal("session negotiated under the fips tag is not FIPS compliant")
	}
}

func TestPublicPoolConnAccessors(t *testing.T) {
	addr, cleanup := startEchoServer(t)
	defer cleanup()
	pool := createTestPool(t, addr)
	defer func() { _ = pool.Close() }()

	conn, err := pool.Acquire(context.Background())
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	if conn.Tunnel() == nil || conn.Session() == nil {
		t.Fatal("live PoolConn returned a nil Tunnel or Session")
	}
	if conn.RemoteAddr() != addr {
		t.Fatalf("RemoteAddr = %q, want %q", conn.RemoteAddr(), addr)
	}
	if conn.LocalAddr() == "" || conn.LocalAddr() == addr {
		t.Fatalf("LocalAddr = %q, want a distinct local address", conn.LocalAddr())
	}
	if created := conn.CreatedAt(); created.IsZero() || time.Since(created) > time.Minute {
		t.Fatalf("CreatedAt = %v", created)
	}
	if err := conn.SendPing(); err != nil {
		t.Fatalf("SendPing: %v", err)
	}

	if err := conn.Release(); err != nil {
		t.Fatalf("Release: %v", err)
	}
	// After release every accessor must refuse rather than touch a pooled tunnel.
	if conn.Tunnel() != nil || conn.Session() != nil || conn.LocalAddr() != "" || conn.RemoteAddr() != "" {
		t.Fatal("released PoolConn still exposes its tunnel")
	}
	if err := conn.SendPing(); !errors.Is(err, tunnel.ErrConnReleased) {
		t.Fatalf("SendPing after release = %v, want ErrConnReleased", err)
	}
	if _, err := conn.Receive(); !errors.Is(err, tunnel.ErrConnReleased) {
		t.Fatalf("Receive after release = %v, want ErrConnReleased", err)
	}
	if err := conn.Send([]byte("x")); !errors.Is(err, tunnel.ErrConnReleased) {
		t.Fatalf("Send after release = %v, want ErrConnReleased", err)
	}
}
