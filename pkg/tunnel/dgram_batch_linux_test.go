//go:build linux

package tunnel

import (
	"bytes"
	"net"
	"testing"
	"time"
)

// TestLinuxBatchIORecvLoopback exercises the real recvmmsg/WriteBatch path over a
// loopback *net.UDPConn: several datagrams sent are all received and handed to the
// dispatch callback. It runs only on Linux, where newBatchIO returns the
// x/net-backed implementation for a *net.UDPConn.
func TestLinuxBatchIORecvLoopback(t *testing.T) {
	rx, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen rx: %v", err)
	}
	defer func() { _ = rx.Close() }()
	tx, err := net.DialUDP("udp", nil, rx.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatalf("dial tx: %v", err)
	}
	defer func() { _ = tx.Close() }()

	bio := newBatchIO(rx, false)
	if _, ok := bio.(*linuxBatchIO); !ok {
		t.Fatalf("newBatchIO over *net.UDPConn = %T, want *linuxBatchIO", bio)
	}

	want := [][]byte{[]byte("one"), []byte("two"), []byte("three"), []byte("four")}
	for _, d := range want {
		if _, err := tx.Write(d); err != nil {
			t.Fatalf("write: %v", err)
		}
	}

	// Bound the wait so a lost datagram fails fast instead of hanging; loopback
	// does not drop these few.
	_ = rx.SetReadDeadline(time.Now().Add(2 * time.Second))
	got := make([][]byte, 0, len(want))
	for len(got) < len(want) {
		if err := bio.recv(func(_ net.Addr, payload []byte) {
			got = append(got, payload)
		}); err != nil {
			t.Fatalf("recv after %d/%d datagrams: %v", len(got), len(want), err)
		}
	}

	for _, w := range want {
		if !containsBytes(got, w) {
			t.Errorf("datagram %q not received (got %d datagrams)", w, len(got))
		}
	}
}

func containsBytes(set [][]byte, want []byte) bool {
	for _, b := range set {
		if bytes.Equal(b, want) {
			return true
		}
	}
	return false
}

// BenchmarkDatagramRecvBatch measures loopback receive throughput through the
// batched path (run with -benchmem). Compare against BenchmarkDatagramRecvSingle
// to see the recvmmsg syscall-amortization win.
func BenchmarkDatagramRecvBatch(b *testing.B) {
	benchRecv(b, func(rx *net.UDPConn) batchIO { return newBatchIO(rx, false) })
}

// BenchmarkDatagramRecvSingle measures the same loopback receive throughput
// through the portable one-datagram-per-syscall fallback, so the batched
// benchmark above has a same-machine baseline to compare against.
func BenchmarkDatagramRecvSingle(b *testing.B) {
	benchRecv(b, func(rx *net.UDPConn) batchIO { return newFallbackIO(rx) })
}

// benchRecv floods a loopback socket and drains it through the batchIO that newIO
// returns, so the batched and single-shot receive paths share one harness.
func benchRecv(b *testing.B, newIO func(*net.UDPConn) batchIO) {
	b.Helper()
	rx, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		b.Fatalf("listen: %v", err)
	}
	defer func() { _ = rx.Close() }()
	tx, err := net.DialUDP("udp", nil, rx.LocalAddr().(*net.UDPAddr))
	if err != nil {
		b.Fatalf("dial: %v", err)
	}
	defer func() { _ = tx.Close() }()

	payload := make([]byte, 1200)
	stop := make(chan struct{})
	go func() {
		for {
			select {
			case <-stop:
				return
			default:
				_, _ = tx.Write(payload)
			}
		}
	}()

	bio := newIO(rx)
	b.SetBytes(int64(len(payload)))
	b.ReportAllocs()
	b.ResetTimer()

	received := 0
	for received < b.N {
		if err := bio.recv(func(_ net.Addr, _ []byte) { received++ }); err != nil {
			b.Fatalf("recv: %v", err)
		}
	}
	b.StopTimer()
	close(stop)
}
