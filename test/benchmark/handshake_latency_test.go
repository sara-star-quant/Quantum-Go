package benchmark

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/sara-star-quant/quantum-go/pkg/tunnel"
)

// delayFrame is one Write travelling the simulated link.
type delayFrame struct {
	data []byte
	at   time.Time
}

// delayEnd is one end of an in-memory link with a fixed one-way latency. Writes are
// queued and become readable latency later, so back-to-back writes overlap in flight
// like packets on a real path. Order is preserved.
type delayEnd struct {
	in      chan delayFrame
	out     chan delayFrame
	latency time.Duration
	buf     []byte
}

func newDelayLink(latency time.Duration) (a, b *delayEnd) {
	ab := make(chan delayFrame, 64)
	ba := make(chan delayFrame, 64)
	return &delayEnd{in: ba, out: ab, latency: latency}, &delayEnd{in: ab, out: ba, latency: latency}
}

func (e *delayEnd) Write(p []byte) (int, error) {
	e.out <- delayFrame{data: append([]byte(nil), p...), at: time.Now().Add(e.latency)}
	return len(p), nil
}

func (e *delayEnd) Read(p []byte) (int, error) {
	if len(e.buf) == 0 {
		f := <-e.in
		time.Sleep(time.Until(f.at))
		e.buf = f.data
	}
	n := copy(p, e.buf)
	e.buf = e.buf[n:]
	return n, nil
}

// BenchmarkHandshakeLatency measures the stream handshake over a link with a fixed
// round-trip time. client-ms is when the initiator is keyed and may send data;
// server-ms is when the responder has verified ClientFinished and may read it. The
// round-trip count shows directly: client-ms is about 1 RTT plus crypto, server-ms
// about 1.5 RTT.
func BenchmarkHandshakeLatency(b *testing.B) {
	for _, rtt := range []time.Duration{20 * time.Millisecond, 100 * time.Millisecond, 500 * time.Millisecond} {
		b.Run(fmt.Sprintf("rtt=%s", rtt), func(b *testing.B) {
			var clientTotal, serverTotal time.Duration
			for i := 0; i < b.N; i++ {
				c, s := newDelayLink(rtt / 2)
				initiator, _ := tunnel.NewSession(tunnel.RoleInitiator)
				responder, _ := tunnel.NewSession(tunnel.RoleResponder)

				start := time.Now()
				var wg sync.WaitGroup
				var serverDone time.Duration
				wg.Add(1)
				go func() {
					defer wg.Done()
					_ = tunnel.ResponderHandshake(responder, s)
					serverDone = time.Since(start)
				}()
				_ = tunnel.InitiatorHandshake(initiator, c)
				clientTotal += time.Since(start)
				wg.Wait()
				serverTotal += serverDone
			}
			b.ReportMetric(float64(clientTotal.Microseconds())/float64(b.N)/1000, "client-ms")
			b.ReportMetric(float64(serverTotal.Microseconds())/float64(b.N)/1000, "server-ms")
		})
	}
}
