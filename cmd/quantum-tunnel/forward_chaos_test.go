package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"runtime"
	"sync"
	"testing"
	"time"
)

// goroutinesSettle reports whether the goroutine count falls to base+slack within timeout.
// It polls for the event (the count dropping), so a slow machine only makes it wait longer.
func goroutinesSettle(base, slack int, timeout time.Duration) bool {
	for deadline := time.Now().Add(timeout); ; time.Sleep(10 * time.Millisecond) {
		if runtime.NumGoroutine() <= base+slack {
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
	}
}

// noGoroutineLeak fails the test if goroutines started during it are still running after its
// own cleanups (the forwarders it started) have run. Call it before starting anything.
func noGoroutineLeak(t *testing.T) {
	t.Helper()
	base := runtime.NumGoroutine()
	t.Cleanup(func() {
		if !goroutinesSettle(base, 2, 10*time.Second) {
			buf := make([]byte, 1<<16)
			t.Errorf("goroutines leaked: %d now, %d before\n%s", runtime.NumGoroutine(), base, buf[:runtime.Stack(buf, true)])
		}
	})
}

// The check itself must fail on a leak, or every test that relies on it proves nothing.
func TestGoroutineCheckSeesALeak(t *testing.T) {
	base := runtime.NumGoroutine()
	stop := make(chan struct{})
	var wg sync.WaitGroup
	for range 10 {
		wg.Go(func() { <-stop })
	}
	if goroutinesSettle(base, 2, 200*time.Millisecond) {
		t.Fatal("ten blocked goroutines were not noticed")
	}
	close(stop)
	wg.Wait()
	if !goroutinesSettle(base, 2, 10*time.Second) {
		t.Fatal("the count did not settle after the goroutines ended")
	}
}

// An upstream that hangs up in the middle of an upload must end the client's connection, not
// leave the forwarder holding it.
func TestForwardUpstreamClosesEarlyDuringUpload(t *testing.T) {
	noGoroutineLeak(t)
	up, _ := startUpstream(t, func(c net.Conn) {
		_, _ = io.ReadFull(c, make([]byte, 1024))
		_ = c.Close()
	})
	c := dial(t, sharedPSKPair(t, up, testLimits))

	writeDone := make(chan struct{})
	go func() {
		defer close(writeDone)
		buf := make([]byte, 64<<10)
		for range 512 { // 32 MiB: far more than the sockets can hold
			if _, err := c.Write(buf); err != nil {
				return
			}
		}
	}()
	readDone := make(chan struct{})
	go func() { defer close(readDone); _, _ = io.Copy(io.Discard, c) }()
	for _, ch := range []chan struct{}{readDone, writeDone} {
		select {
		case <-ch:
		case <-time.After(20 * time.Second):
			t.Fatal("the client's connection stayed open after the upstream closed")
		}
	}
}

// A client that resets its connection in the middle of a transfer must reach the upstream as
// an ended connection.
func TestForwardClientResetMidTransfer(t *testing.T) {
	noGoroutineLeak(t)
	ended := make(chan int64, 1)
	up, _ := startUpstream(t, func(c net.Conn) {
		n, _ := io.Copy(io.Discard, c)
		ended <- n
	})
	c := dial(t, sharedPSKPair(t, up, testLimits))
	if _, err := c.Write(make([]byte, 256<<10)); err != nil {
		t.Fatal(err)
	}
	_ = c.SetLinger(0) // Close now sends a reset, not a graceful FIN
	_ = c.Close()
	select {
	case <-ended:
	case <-time.After(20 * time.Second):
		t.Fatal("the upstream never saw the connection end")
	}
}

// A client that reads slowly must still receive every byte, in order. The forwarder applies
// backpressure; it must not drop, reorder or time out a transfer that is making progress.
func TestForwardSlowReaderGetsEveryByte(t *testing.T) {
	noGoroutineLeak(t)
	const total = 16 << 20
	want := sha256.New()
	up, _ := startUpstream(t, func(c net.Conn) {
		chunk := make([]byte, 64<<10)
		for sent := 0; sent < total; sent += len(chunk) {
			_, _ = rand.Read(chunk)
			want.Write(chunk)
			if _, err := c.Write(chunk); err != nil {
				return
			}
		}
		if tc, ok := c.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
		}
	})
	c := dial(t, sharedPSKPair(t, up, testLimits))

	got := sha256.New()
	buf := make([]byte, 32<<10)
	var n int64
	for i := 0; ; i++ {
		if i%32 == 0 {
			time.Sleep(20 * time.Millisecond) // slow the reader; the result does not depend on it
		}
		m, err := c.Read(buf)
		got.Write(buf[:m])
		n += int64(m)
		if err != nil {
			if !errors.Is(err, io.EOF) {
				t.Fatalf("read: %v after %d bytes", err, n)
			}
			break
		}
	}
	if n != total || hex.EncodeToString(got.Sum(nil)) != hex.EncodeToString(want.Sum(nil)) {
		t.Fatalf("received %d bytes (want %d) or the hash differs", n, total)
	}
}
