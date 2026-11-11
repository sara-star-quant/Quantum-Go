package main

import (
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sara-star-quant/quantum-go/pkg/tunnel"
)

// flowStat is what one accepted connection received.
type flowStat struct {
	received    int64
	first, last time.Time
	cipher      string
}

// flowAcceptTimeout is how long serveFlows waits for the next flow after the first
// one arrives, so a sender that opens fewer flows than the receiver expects ends the
// run with what it got instead of hanging. A variable so tests can shorten it.
var flowAcceptTimeout = 30 * time.Second

// serveFlows accepts up to flows connections on addr and reports their summed bytes.
// All flows share one counting window, from the first byte on any flow to duration
// later, so flows that start late do not stretch the measurement.
func serveFlows(addr string, plain bool, duration time.Duration, flows int, ready chan<- string) (throughputResult, error) {
	var res throughputResult
	cpuStart := processCPUTime()

	var accept func() (func(*atomic.Int64) flowStat, error)
	if plain {
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			return res, err
		}
		defer func() { _ = ln.Close() }()
		if ready != nil {
			ready <- ln.Addr().String()
		}
		accept = func() (func(*atomic.Int64) flowStat, error) {
			conn, err := ln.Accept()
			if err != nil {
				return nil, err
			}
			return func(start *atomic.Int64) flowStat { return recvPlain(conn, start, duration) }, nil
		}
	} else {
		ln, err := tunnel.Listen("tcp", addr)
		if err != nil {
			return res, err
		}
		defer func() { _ = ln.Close() }()
		if ready != nil {
			ready <- ln.Addr().String()
		}
		accept = func() (func(*atomic.Int64) flowStat, error) {
			conn, err := ln.Accept()
			if err != nil {
				return nil, err
			}
			return func(start *atomic.Int64) flowStat { return recvTunnel(conn, start, duration) }, nil
		}
	}

	type accepted struct {
		run func(*atomic.Int64) flowStat
		err error
	}
	incoming := make(chan accepted)
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		for {
			run, err := accept()
			select {
			case incoming <- accepted{run, err}:
			case <-stop:
				return
			}
			if err != nil {
				return
			}
		}
	}()

	var start atomic.Int64
	stats := make([]flowStat, flows)
	var wg sync.WaitGroup
	n := 0
	for n < flows {
		var a accepted
		if n == 0 {
			a = <-incoming
		} else {
			select {
			case a = <-incoming:
			case <-time.After(flowAcceptTimeout):
				a.err = errNoMoreFlows
			}
		}
		if a.err == errNoMoreFlows {
			break
		}
		if a.err != nil {
			wg.Wait()
			return res, a.err
		}
		wg.Add(1)
		go func(i int, run func(*atomic.Int64) flowStat) {
			defer wg.Done()
			stats[i] = run(&start)
		}(n, a.run)
		n++
	}
	wg.Wait()
	res.flows = n

	var first, last time.Time
	for _, st := range stats[:n] {
		res.received += st.received
		if res.cipher == "" {
			res.cipher = st.cipher
		}
		if !st.first.IsZero() && (first.IsZero() || st.first.Before(first)) {
			first = st.first
		}
		if st.last.After(last) {
			last = st.last
		}
	}
	if !first.IsZero() {
		res.recvDur = last.Sub(first)
	}
	res.cpu = processCPUTime() - cpuStart
	return res, nil
}

var errNoMoreFlows = errors.New("no more flows")

// inWindow reports whether a read at now still counts: the window opens at the first
// byte on any flow and lasts duration.
func inWindow(start *atomic.Int64, now time.Time, duration time.Duration) bool {
	start.CompareAndSwap(0, now.UnixNano())
	return now.Sub(time.Unix(0, start.Load())) < duration
}

// recvPlain counts bytes inside the shared window, then keeps draining without
// counting so a sender that is still writing finishes cleanly instead of hitting a
// closed connection.
func recvPlain(conn net.Conn, start *atomic.Int64, duration time.Duration) flowStat {
	defer func() { _ = conn.Close() }()
	var st flowStat
	buf := make([]byte, 64<<10)
	for {
		n, err := conn.Read(buf)
		if n > 0 {
			if now := time.Now(); inWindow(start, now, duration) {
				if st.first.IsZero() {
					st.first = now
				}
				st.received += int64(n)
				st.last = now
			}
		}
		if err != nil {
			return st
		}
	}
}

// recvTunnel is recvPlain for a tunnel.
func recvTunnel(conn *tunnel.Tunnel, start *atomic.Int64, duration time.Duration) flowStat {
	defer func() { _ = conn.Close() }()
	st := flowStat{cipher: conn.Session().CipherSuite.String()}
	buf := make([]byte, 0, 64<<10)
	for {
		data, err := conn.ReceiveInto(buf[:0])
		if err != nil {
			return st
		}
		if now := time.Now(); inWindow(start, now, duration) {
			if st.first.IsZero() {
				st.first = now
			}
			st.received += int64(len(data))
			st.last = now
		}
	}
}

// connectOne dials addr and sends chunk-sized records until totalBytes or
// duration. The receiver's figures are the ones that count; this side reports its own
// send rate and CPU. dialAttempts tolerates a receiver that is still starting.
func connectOne(addr string, plain bool, totalBytes int64, duration time.Duration, chunk []byte, dialAttempts int) (throughputResult, error) {
	var res throughputResult
	cpuStart := processCPUTime()
	var sent int64
	var start time.Time

	if plain {
		var conn net.Conn
		var err error
		for i := 0; i < dialAttempts; i++ {
			if conn, err = net.Dial("tcp", addr); err == nil {
				break
			}
			time.Sleep(200 * time.Millisecond)
		}
		if err != nil {
			return res, err
		}
		defer func() { _ = conn.Close() }()
		start = time.Now()
		for sent < totalBytes && time.Since(start) < duration {
			n, err := conn.Write(chunk)
			sent += int64(n)
			if err != nil {
				return res, err
			}
		}
	} else {
		var client *tunnel.Tunnel
		var err error
		for i := 0; i < dialAttempts; i++ {
			if client, err = tunnel.Dial("tcp", addr); err == nil {
				break
			}
			time.Sleep(200 * time.Millisecond)
		}
		if err != nil {
			return res, err
		}
		res.cipher = client.Session().CipherSuite.String()
		// The initiator must Receive so an automatic rekey can complete its response.
		drained := make(chan struct{})
		go func() {
			defer close(drained)
			for {
				if _, err := client.Receive(); err != nil {
					return
				}
			}
		}()
		start = time.Now()
		var sendErr error
		for sent < totalBytes && time.Since(start) < duration {
			if sendErr = client.Send(chunk); sendErr != nil {
				break
			}
			sent += int64(len(chunk))
		}
		res.sendDur = time.Since(start)
		_ = client.Close()
		<-drained
		res.sent = sent
		res.cpu = processCPUTime() - cpuStart
		return res, sendErr
	}

	res.sent = sent
	res.sendDur = time.Since(start)
	res.cpu = processCPUTime() - cpuStart
	return res, nil
}

// connectFlows runs flows parallel senders, each moving its share of totalBytes. The
// result sums the flows that succeeded, and the error says how many did not, so one bad
// flow does not discard the others. CPU is one process-wide figure, not a per-flow sum.
func connectFlows(addr string, plain bool, totalBytes int64, duration time.Duration, chunk []byte, dialAttempts, flows int) (throughputResult, error) {
	if flows <= 1 {
		return connectOne(addr, plain, totalBytes, duration, chunk, dialAttempts)
	}
	cpuStart := processCPUTime()
	per := (totalBytes + int64(flows) - 1) / int64(flows)
	results := make([]throughputResult, flows)
	errs := make([]error, flows)
	var wg sync.WaitGroup
	for i := 0; i < flows; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results[i], errs[i] = connectOne(addr, plain, per, duration, chunk, dialAttempts)
		}()
	}
	wg.Wait()
	var res throughputResult
	var failed int
	var firstErr error
	for i, r := range results {
		if errs[i] != nil {
			failed++
			if firstErr == nil {
				firstErr = errs[i]
			}
			continue
		}
		res.sent += r.sent
		if r.sendDur > res.sendDur {
			res.sendDur = r.sendDur
		}
		if res.cipher == "" {
			res.cipher = r.cipher
		}
	}
	res.cpu = processCPUTime() - cpuStart
	if failed > 0 {
		return res, fmt.Errorf("%d of %d flows failed: %w", failed, flows, firstErr)
	}
	return res, nil
}

func printRemoteResult(role string, plain bool, r throughputResult) {
	mode := "tunnel"
	if plain {
		mode = "plain TCP"
	}
	fmt.Printf("\n%s (%s)\n", role, mode)
	if r.cipher != "" {
		fmt.Printf("  Cipher (negotiated): %s\n", r.cipher)
	}
	if role == "Receiver" {
		fmt.Printf("  Received: %s in %v\n  Throughput: %.2f MB/s (%.2f Mbps)\n", formatSize(r.received), r.recvDur, r.recvMBps(), r.recvMBps()*8)
	} else {
		fmt.Printf("  Sent: %s in %v\n  Send rate: %.2f MB/s (the receiver's figure is the delivered rate)\n", formatSize(r.sent), r.sendDur, r.sendMBps())
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
