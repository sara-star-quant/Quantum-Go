package main

import (
	"encoding/binary"
	"fmt"
	"math"
	"net"
	"sync/atomic"
	"time"

	"github.com/sara-star-quant/quantum-go/internal/constants"
	"github.com/sara-star-quant/quantum-go/pkg/tunnel"
)

// seqLen is the sequence number each benchmark datagram carries in its first bytes, so
// the receiver can count loss without any channel back to the sender.
const seqLen = 8

// datagramResult is one measured datagram transfer. UDP has no flow control, so the
// receiver's delivered count against the highest sequence it saw is the loss figure.
type datagramResult struct {
	throughputResult
	datagrams int64 // datagrams received (receiver) or sent (sender)
	expected  int64 // highest sequence seen plus one (receiver only)
}

func (r datagramResult) lossPct() float64 {
	if r.expected <= 0 {
		return 0
	}
	return 100 * float64(r.expected-r.datagrams) / float64(r.expected)
}

func datagramEndpoint(addr string, offload bool) (*tunnel.DatagramEndpoint, net.PacketConn, error) {
	pc, err := net.ListenPacket("udp", addr)
	if err != nil {
		return nil, nil, err
	}
	// UDP has no flow control, so ask for a large receive buffer; Linux clamps it to
	// net.core.rmem_max without saying so.
	if uc, ok := pc.(*net.UDPConn); ok {
		_ = uc.SetReadBuffer(4 << 20)
	}
	// A benchmark measures transport cost, not authentication, so it runs unauthenticated on purpose.
	opts := []tunnel.DatagramEndpointOption{tunnel.WithAllowUnauthenticated()}
	if offload {
		opts = append(opts, tunnel.WithDatagramOffload())
	}
	ep, err := tunnel.NewDatagramEndpoint(pc, opts...)
	if err != nil {
		_ = pc.Close()
		return nil, nil, err
	}
	go ep.Serve()
	return ep, pc, nil
}

// serveDatagram accepts one datagram session on addr and counts what arrives in the
// duration after the first datagram.
func serveDatagram(addr string, offload bool, duration time.Duration, ready chan<- string) (datagramResult, error) {
	var res datagramResult
	cpuStart := processCPUTime()
	ep, pc, err := datagramEndpoint(addr, offload)
	if err != nil {
		return res, err
	}
	defer func() { _ = ep.Close() }()
	if ready != nil {
		ready <- pc.LocalAddr().String()
	}
	conn, err := ep.Accept()
	if err != nil {
		return res, err
	}
	res.cipher = conn.Session().CipherSuite.String()

	// Count for duration from the first datagram, but keep draining until the sender
	// goes quiet for two seconds, so a sender that outlasts this window finishes cleanly
	// and its own figure covers a run the receiver actually saw. The idle clock starts
	// at accept, so a sender that connects and never sends does not hang the receiver.
	var firstNs, lastNs atomic.Int64
	lastNs.Store(time.Now().UnixNano())
	done := make(chan struct{})
	defer close(done)
	go func() {
		t := time.NewTicker(200 * time.Millisecond)
		defer t.Stop()
		for {
			select {
			case <-done:
				return
			case <-t.C:
				if time.Since(time.Unix(0, lastNs.Load())) >= 2*time.Second {
					_ = conn.Close()
					return
				}
			}
		}
	}()

	var countedLastNs int64
	for {
		p, err := conn.Recv()
		if err != nil {
			break
		}
		now := time.Now().UnixNano()
		lastNs.Store(now)
		if len(p) < seqLen {
			continue
		}
		// A sequence at or above MaxInt64 cannot come from a real sender, so skip it.
		u := binary.BigEndian.Uint64(p)
		if u >= math.MaxInt64 {
			continue
		}
		firstNs.CompareAndSwap(0, now)
		if time.Duration(now-firstNs.Load()) >= duration {
			continue
		}
		countedLastNs = now
		res.datagrams++
		res.received += int64(len(p))
		if seq := int64(u) + 1; seq > res.expected { // #nosec G115 -- u < MaxInt64 by the guard above
			res.expected = seq
		}
	}
	if f := firstNs.Load(); f != 0 {
		res.recvDur = time.Duration(countedLastNs - f)
	}
	res.cpu = processCPUTime() - cpuStart
	return res, nil
}

// connectDatagram dials addr and sends chunk-sized datagrams, batch at a time, until
// duration. With rateMbps 0 it sends as fast as the socket accepts; otherwise it paces to
// that offered load, so loss and CPU can be read at a fixed rate instead of at a blast.
func connectDatagram(addr string, offload bool, duration time.Duration, chunk, batch, dialAttempts int, rateMbps float64) (datagramResult, error) {
	var res datagramResult
	if rateMbps < 0 {
		return res, fmt.Errorf("--rate must not be negative")
	}
	if chunk < seqLen || chunk > constants.DatagramMaxDataPayload {
		return res, fmt.Errorf("datagram records must be %d to %d bytes, got %d", seqLen, constants.DatagramMaxDataPayload, chunk)
	}
	if batch < 1 {
		batch = 1
	}
	dst, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return res, err
	}
	cpuStart := processCPUTime()
	ep, _, err := datagramEndpoint(":0", offload)
	if err != nil {
		return res, err
	}
	defer func() { _ = ep.Close() }()
	var conn *tunnel.DatagramConn
	for i := 0; i < dialAttempts; i++ {
		if conn, err = tunnel.DialDatagram(ep, dst); err == nil {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	if err != nil {
		return res, err
	}
	res.cipher = conn.Session().CipherSuite.String()
	go func() {
		for {
			if _, err := conn.Recv(); err != nil {
				return
			}
		}
	}()

	payloads := make([][]byte, batch)
	for i := range payloads {
		payloads[i] = make([]byte, chunk)
	}
	var seq uint64
	start := time.Now()
	for time.Since(start) < duration {
		for _, p := range payloads {
			binary.BigEndian.PutUint64(p, seq)
			seq++
		}
		if batch == 1 {
			err = conn.Send(payloads[0])
		} else {
			err = conn.SendBatch(payloads)
		}
		if err != nil {
			return res, err
		}
		if rateMbps > 0 {
			// Pace on cumulative bytes so a late wakeup is paid back, keeping the average exact.
			due := start.Add(time.Duration(float64(seq) * float64(chunk) * 8 / (rateMbps * 1e6) * float64(time.Second)))
			if d := time.Until(due); d > 0 {
				time.Sleep(d)
			}
		}
	}
	res.sendDur = time.Since(start)
	res.datagrams = int64(seq)           // #nosec G115 -- seq counts datagrams sent in one bounded run, far below MaxInt64
	res.sent = int64(seq) * int64(chunk) // #nosec G115 -- same bound, times a record size of at most 1170
	_ = conn.Close()
	res.cpu = processCPUTime() - cpuStart
	return res, nil
}

func printDatagramResult(role string, r datagramResult) {
	fmt.Printf("\n%s (datagram tunnel)\n", role)
	if r.cipher != "" {
		fmt.Printf("  Cipher (negotiated): %s\n", r.cipher)
	}
	if role == "Receiver" {
		fmt.Printf("  Received: %d datagrams, %s in %v\n  Throughput: %.2f MB/s (%.2f Mbps)\n", r.datagrams, formatSize(r.received), r.recvDur, r.recvMBps(), r.recvMBps()*8)
		fmt.Printf("  Loss: %.2f%% (%d of %d, by sequence number; tail loss not counted)\n", r.lossPct(), r.expected-r.datagrams, r.expected)
	} else {
		fmt.Printf("  Sent: %d datagrams, %s in %v\n  Send rate: %.2f MB/s (the receiver's figure is the delivered rate)\n", r.datagrams, formatSize(r.sent), r.sendDur, r.sendMBps())
	}
	if r.cpu > 0 {
		bytes := r.received
		if role != "Receiver" {
			bytes = r.sent
		}
		if bytes > 0 {
			fmt.Printf("  CPU on this host: %.2f CPU-s/GiB\n", r.cpu.Seconds()/(float64(bytes)/(1<<30)))
		}
	}
}
