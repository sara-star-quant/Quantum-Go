package main

import (
	"fmt"
	"net"
	"time"

	"github.com/sara-star-quant/quantum-go/pkg/tunnel"
)

// serveThroughput accepts one connection on addr and measures what arrives, through a
// tunnel or, with plain, over bare TCP. Run it on one host and connectThroughput on
// another to measure a real link instead of loopback. ready, if set, receives the bound
// address once the listener is up.
func serveThroughput(addr string, plain bool, duration time.Duration, ready chan<- string) (throughputResult, error) {
	var res throughputResult
	cpuStart := processCPUTime()
	var received int64
	var first time.Time

	if plain {
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			return res, err
		}
		defer func() { _ = ln.Close() }()
		if ready != nil {
			ready <- ln.Addr().String()
		}
		conn, err := ln.Accept()
		if err != nil {
			return res, err
		}
		defer func() { _ = conn.Close() }()
		buf := make([]byte, 64<<10)
		for {
			n, err := conn.Read(buf)
			if n > 0 {
				if first.IsZero() {
					first = time.Now()
				}
				received += int64(n)
			}
			if err != nil || (!first.IsZero() && time.Since(first) >= duration) {
				break
			}
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
		conn, err := ln.Accept()
		if err != nil {
			return res, err
		}
		defer func() { _ = conn.Close() }()
		res.cipher = conn.Session().CipherSuite.String()
		buf := make([]byte, 0, 64<<10)
		for {
			data, err := conn.ReceiveInto(buf[:0])
			if err != nil {
				break
			}
			if first.IsZero() {
				first = time.Now()
			}
			received += int64(len(data))
			if time.Since(first) >= duration {
				break
			}
		}
	}

	res.received = received
	if !first.IsZero() {
		res.recvDur = time.Since(first)
	}
	res.cpu = processCPUTime() - cpuStart
	return res, nil
}

// connectThroughput dials addr and sends chunk-sized records until totalBytes or
// duration. The receiver's figures are the ones that count; this side reports its own
// send rate and CPU. dialAttempts tolerates a receiver that is still starting.
func connectThroughput(addr string, plain bool, totalBytes int64, duration time.Duration, chunk []byte, dialAttempts int) (throughputResult, error) {
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
