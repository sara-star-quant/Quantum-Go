package tunnel

import (
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/sara-star-quant/quantum-go/internal/constants"
	"github.com/sara-star-quant/quantum-go/pkg/crypto"
	"github.com/sara-star-quant/quantum-go/pkg/protocol"
)

// benchStreamPair returns an established sender/receiver Transport pair over a real
// TCP loopback connection. A real socket (not net.Pipe, which is a synchronous
// in-memory hand-off) exercises the receive path's real syscalls and per-record
// allocations. Keys are shared directly rather than via a full handshake.
func benchStreamPair(b *testing.B) (sender, receiver *Transport, cleanup func()) {
	b.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.Fatalf("listen: %v", err)
	}
	type accepted struct {
		c   net.Conn
		err error
	}
	accCh := make(chan accepted, 1)
	go func() {
		c, aerr := ln.Accept()
		accCh <- accepted{c, aerr}
	}()
	clientConn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		b.Fatalf("dial: %v", err)
	}
	acc := <-accCh
	if acc.err != nil {
		b.Fatalf("accept: %v", acc.err)
	}

	masterSecret := make([]byte, constants.CHKEMSharedSecretSize)
	_ = crypto.SecureRandom(masterSecret)
	cs, _ := NewSession(RoleInitiator)
	_ = cs.InitializeKeys(masterSecret, constants.CipherSuiteAES256GCM)
	ss, _ := NewSession(RoleResponder)
	_ = ss.InitializeKeys(masterSecret, constants.CipherSuiteAES256GCM)

	sender = &Transport{
		session:      cs,
		conn:         clientConn,
		codec:        protocol.NewCodec(),
		writeTimeout: 30 * time.Second,
	}
	receiver = &Transport{
		session:     ss,
		conn:        acc.c,
		codec:       protocol.NewCodec(),
		readTimeout: 30 * time.Second,
	}
	cleanup = func() {
		_ = clientConn.Close()
		_ = acc.c.Close()
		_ = ln.Close()
	}
	return sender, receiver, cleanup
}

// BenchmarkStreamReceiveSmallRecords measures the small-record receive path: a sender
// floods records continuously while the receiver drains b.N of them. It reports
// per-record throughput and allocations - the receive loop reuses one buffer across
// records, so allocations stay flat as the record rate climbs.
func BenchmarkStreamReceiveSmallRecords(b *testing.B) {
	for _, size := range []int{64, 256, 1024} {
		b.Run(fmt.Sprintf("record=%dB", size), func(b *testing.B) {
			sender, receiver, cleanup := benchStreamPair(b)
			defer cleanup()
			payload := make([]byte, size)

			stop := make(chan struct{})
			var wg sync.WaitGroup
			wg.Add(1)
			go func() {
				defer wg.Done()
				for {
					select {
					case <-stop:
						return
					default:
					}
					// Post-stop write errors (from the unblock deadline below) are
					// expected; just exit. A real early failure surfaces as a receiver
					// timeout, failing the benchmark there.
					if err := sender.Send(payload); err != nil {
						return
					}
				}
			}()

			b.SetBytes(int64(size))
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, err := receiver.Receive(); err != nil {
					b.Fatalf("receive %d/%d: %v", i, b.N, err)
				}
			}
			b.StopTimer()

			close(stop)
			_ = sender.conn.SetWriteDeadline(time.Now()) // unblock a sender parked in Write
			wg.Wait()
		})
	}
}
