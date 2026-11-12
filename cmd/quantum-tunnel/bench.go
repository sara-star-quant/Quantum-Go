package main

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sara-star-quant/quantum-go/pkg/tunnel"
)

func runBench(handshakes, datagramHandshakes int, throughputTest bool, sizeStr, durationStr, cipherSuite, chunkStr string, baseline bool) {
	const bannerWidth = 59
	fmt.Println("╔" + strings.Repeat("═", bannerWidth) + "╗")
	fmt.Printf("║%-*s║\n", bannerWidth, "      Quantum-Resistant Tunnel Benchmark")
	fmt.Printf("║%-*s║\n", bannerWidth, "      CH-KEM: ML-KEM-1024 + X25519")
	fmt.Println("╚" + strings.Repeat("═", bannerWidth) + "╝")
	fmt.Println()

	if handshakes == 0 && datagramHandshakes == 0 && !throughputTest {
		fmt.Println("No benchmarks specified. Use --handshakes, --datagram-handshakes, or --throughput")
		fmt.Println("Run 'quantum-tunnel bench --help' for usage")
		os.Exit(1)
	}

	if handshakes > 0 {
		benchHandshakes(handshakes)
		fmt.Println()
	}

	if datagramHandshakes > 0 {
		benchDatagramHandshakes(datagramHandshakes)
		fmt.Println()
	}

	if throughputTest {
		size, err := parseSize(sizeStr)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Invalid --size: %v\n", err)
			os.Exit(1)
		}
		chunk, err := parseSize(chunkStr)
		if err != nil || chunk <= 0 {
			fmt.Fprintf(os.Stderr, "Invalid --chunk %q: want a positive size such as 8KB or 60KB\n", chunkStr)
			os.Exit(1)
		}
		if cipherSuite != "aes-gcm" {
			// The client offers AES-256-GCM first and the server takes the first suite both
			// support, so another cipher cannot be requested yet. Refuse instead of
			// reporting a run under a label it did not use.
			fmt.Fprintf(os.Stderr, "--cipher %s is not supported yet: the tunnel negotiates AES-256-GCM\n", cipherSuite)
			os.Exit(1)
		}
		duration := parseDuration(durationStr)
		if err := benchThroughput(size, duration, int(chunk), baseline); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
	}
}

func benchHandshakes(count int) {
	fmt.Printf("Benchmarking Handshakes (%d iterations)\n", count)
	fmt.Println(strings.Repeat("─", 60))

	listener, err := tunnel.ListenInsecure("tcp", "127.0.0.1:0")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: Failed to start listener: %v\n", err)
		os.Exit(1)
	}
	defer func() { _ = listener.Close() }()

	addr := listener.Addr().String()
	fmt.Printf("Test setup: %s\n\n", addr)

	durations := make([]time.Duration, count)
	errors := 0

	var wg sync.WaitGroup

	// Server goroutine
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < count; i++ {
			conn, err := listener.Accept()
			if err != nil {
				errors++
				continue
			}
			_ = conn.Close()
		}
	}()

	// Client goroutines
	startTime := time.Now()
	for i := 0; i < count; i++ {
		handshakeStart := time.Now()

		client, err := tunnel.DialInsecure("tcp", addr)
		if err != nil {
			errors++
			durations[i] = 0
			continue
		}

		durations[i] = time.Since(handshakeStart)
		_ = client.Close()

		// Progress indicator every 10% (or every iteration if count < 10)
		step := count / 10
		if step == 0 {
			step = 1
		}
		if (i+1)%step == 0 || i == count-1 {
			fmt.Printf("Progress: %d/%d (%.0f%%)\r", i+1, count, float64(i+1)/float64(count)*100)
		}
	}
	fmt.Println()

	wg.Wait()
	totalTime := time.Since(startTime)

	successCount := count - errors
	printHandshakeResults(count, successCount, errors, totalTime, durations)
}

// benchDatagramHandshakes measures full CH-KEM handshakes over the connectionless
// UDP transport on loopback: it dials sequentially through DialDatagram, which
// fragments the post-quantum Hellos and drives retransmission, so the result is
// directly comparable to the stream handshake number. The encrypted datagram data
// path is not implemented yet, so there is no datagram throughput benchmark.
func benchDatagramHandshakes(count int) {
	fmt.Printf("Benchmarking Datagram Handshakes (%d iterations)\n", count)
	fmt.Println(strings.Repeat("─", 60))

	responderConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: Failed to open responder socket: %v\n", err)
		os.Exit(1)
	}
	responder, err := tunnel.NewDatagramEndpoint(responderConn, tunnel.WithAllowUnauthenticated())
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: Failed to create responder endpoint: %v\n", err)
		os.Exit(1)
	}
	go responder.Serve()
	defer func() { _ = responder.Close() }()

	initiatorConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: Failed to open initiator socket: %v\n", err)
		os.Exit(1)
	}
	initiator, err := tunnel.NewDatagramEndpoint(initiatorConn, tunnel.WithAllowUnauthenticated())
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: Failed to create initiator endpoint: %v\n", err)
		os.Exit(1)
	}
	go initiator.Serve()
	defer func() { _ = initiator.Close() }()

	dst := responderConn.LocalAddr()
	fmt.Printf("Test setup: %s -> %s\n\n", initiatorConn.LocalAddr(), dst)

	durations := make([]time.Duration, count)
	errors := 0

	startTime := time.Now()
	for i := 0; i < count; i++ {
		handshakeStart := time.Now()

		session, err := tunnel.DialDatagram(initiator, dst)
		if err != nil {
			errors++
			durations[i] = 0
			continue
		}
		durations[i] = time.Since(handshakeStart)
		_ = session

		step := count / 10
		if step == 0 {
			step = 1
		}
		if (i+1)%step == 0 || i == count-1 {
			fmt.Printf("Progress: %d/%d (%.0f%%)\r", i+1, count, float64(i+1)/float64(count)*100)
		}
	}
	fmt.Println()

	totalTime := time.Since(startTime)
	successCount := count - errors
	printHandshakeResults(count, successCount, errors, totalTime, durations)
}

func printHandshakeResults(total, successful, failed int, totalTime time.Duration, durations []time.Duration) {
	if failed == total {
		fmt.Fprintf(os.Stderr, "All handshakes failed\n")
		os.Exit(1)
	}

	var sum, min, max time.Duration
	min = time.Hour // Initialize to large value

	for _, d := range durations {
		if d == 0 {
			continue
		}
		sum += d
		if d < min {
			min = d
		}
		if d > max {
			max = d
		}
	}

	avg := sum / time.Duration(successful)

	fmt.Println("\nResults:")
	fmt.Printf("  Total handshakes: %d\n", total)
	fmt.Printf("  Successful: %d\n", successful)
	fmt.Printf("  Failed: %d\n", failed)
	fmt.Printf("  Total time: %v\n", totalTime)
	fmt.Println()
	fmt.Println("Handshake Performance:")
	fmt.Printf("  Average: %v\n", avg)
	fmt.Printf("  Minimum: %v\n", min)
	fmt.Printf("  Maximum: %v\n", max)
	fmt.Printf("  Throughput: %.2f handshakes/sec\n", float64(successful)/totalTime.Seconds())
	fmt.Println()

	printHandshakeRating(avg)
}

func printHandshakeRating(avg time.Duration) {
	if avg < 2*time.Millisecond {
		fmt.Println("✓ Performance: Excellent (< 2ms avg)")
	} else if avg < 5*time.Millisecond {
		fmt.Println("✓ Performance: Good (< 5ms avg)")
	} else if avg < 10*time.Millisecond {
		fmt.Println("⚠ Performance: Acceptable (< 10ms avg)")
	} else {
		fmt.Println("⚠ Performance: Slow (> 10ms avg)")
	}
}

// throughputResult is one measured transfer.
type throughputResult struct {
	sent, received   int64
	sendDur, recvDur time.Duration
	cpu              time.Duration // user+system CPU of this process (both ends), 0 if unavailable
	cipher           string        // negotiated cipher, empty for plain TCP
	flows            int           // connections the receiver accepted, 0 when not counted
}

func (r throughputResult) recvMBps() float64 {
	if r.recvDur <= 0 {
		return 0
	}
	return float64(r.received) / r.recvDur.Seconds() / 1e6
}

func (r throughputResult) sendMBps() float64 {
	if r.sendDur <= 0 {
		return 0
	}
	return float64(r.sent) / r.sendDur.Seconds() / 1e6
}

// cpuPerGiB is the CPU seconds spent per GiB delivered.
func (r throughputResult) cpuPerGiB() float64 {
	if r.cpu <= 0 || r.received <= 0 {
		return 0
	}
	return r.cpu.Seconds() / (float64(r.received) / (1 << 30))
}

func benchThroughput(totalBytes int64, duration time.Duration, chunkSize int, baseline bool) error {
	fmt.Printf("Benchmarking Throughput\n")
	fmt.Println(strings.Repeat("─", 60))
	fmt.Printf("Target: %s over %v, %s records\n\n", formatSize(totalBytes), duration, formatSize(int64(chunkSize)))

	chunk := make([]byte, chunkSize)
	for i := range chunk {
		chunk[i] = byte(i % 256)
	}

	var plain throughputResult
	if baseline {
		fmt.Println("Plain TCP baseline (no encryption)")
		var err error
		if plain, err = measureTCP(totalBytes, duration, chunk); err != nil {
			return fmt.Errorf("baseline: %w", err)
		}
		fmt.Printf("  %.2f MB/s", plain.recvMBps())
		if c := plain.cpuPerGiB(); c > 0 {
			fmt.Printf(", %.2f CPU-s/GiB", c)
		}
		fmt.Print("\n\n")
	}

	res, err := measureTunnel(totalBytes, duration, chunk)
	if err != nil {
		return err
	}
	printThroughputResults(res)

	if baseline && plain.recvMBps() > 0 && res.recvMBps() > 0 {
		fmt.Println()
		fmt.Println("Versus plain TCP, same records, same host:")
		fmt.Printf("  Throughput: %.1f%% of plain TCP (%.2f vs %.2f MB/s)\n",
			100*res.recvMBps()/plain.recvMBps(), res.recvMBps(), plain.recvMBps())
		if pc, tc := plain.cpuPerGiB(), res.cpuPerGiB(); pc > 0 && tc > 0 {
			fmt.Printf("  CPU: %.2f vs %.2f CPU-s/GiB (%.1fx)\n", tc, pc, tc/pc)
		}
		fmt.Println("  Loopback, one process for both ends: CPU covers client and server together.")
	}
	return nil
}

// measureTunnel moves up to totalBytes (or for duration) through a tunnel on loopback.
func measureTunnel(totalBytes int64, duration time.Duration, chunk []byte) (throughputResult, error) {
	var res throughputResult
	listener, err := tunnel.ListenInsecure("tcp", "127.0.0.1:0")
	if err != nil {
		return res, fmt.Errorf("start listener: %w", err)
	}
	defer func() { _ = listener.Close() }()
	addr := listener.Addr().String()

	var wg sync.WaitGroup
	var totalSent, totalReceived atomic.Int64
	var sendDuration, receiveDuration time.Duration
	var srvErr, cliErr error
	cipher := make(chan string, 1)

	cpuStart := processCPUTime()

	// Receive() handles rekey messages internally and only returns data frames, so the
	// counter reflects application payload.
	wg.Add(1)
	go func() {
		defer wg.Done()
		conn, err := listener.Accept()
		if err != nil {
			srvErr = fmt.Errorf("accept: %w", err)
			return
		}
		defer func() { _ = conn.Close() }()

		var receiveStart time.Time     // starts at the first payload, not at Accept
		buf := make([]byte, 0, 64<<10) // one buffer for every record: no allocation per receive
		for {
			data, err := conn.ReceiveInto(buf[:0])
			if err != nil {
				break
			}
			if receiveStart.IsZero() {
				receiveStart = time.Now()
			}
			totalReceived.Add(int64(len(data)))
			if time.Since(receiveStart) >= duration {
				break
			}
		}
		if !receiveStart.IsZero() {
			receiveDuration = time.Since(receiveStart)
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		client, err := tunnel.DialInsecure("tcp", addr)
		if err != nil {
			cliErr = fmt.Errorf("dial: %w", err)
			return
		}
		defer func() { _ = client.Close() }()
		cipher <- client.Session().CipherSuite.String()

		// Full-duplex drainer: the initiator must Receive so that an automatic rekey
		// (triggered mid-stream once the byte threshold is crossed) can complete its
		// response handshake. Without this, the stream stalls at the first rekey.
		drainerDone := make(chan struct{})
		go func() {
			defer close(drainerDone)
			for {
				if _, err := client.Receive(); err != nil {
					return
				}
			}
		}()

		sendStart := time.Now()
		lastProgress := time.Now()
		for totalSent.Load() < totalBytes && time.Since(sendStart) < duration {
			if err := client.Send(chunk); err != nil {
				cliErr = fmt.Errorf("send: %w", err)
				break
			}
			sent := totalSent.Add(int64(len(chunk)))
			if time.Since(lastProgress) >= time.Second {
				fmt.Printf("Progress: %s / %s (%.1f MB/s)\r", formatSize(sent), formatSize(totalBytes),
					float64(sent)/time.Since(sendStart).Seconds()/1e6)
				lastProgress = time.Now()
			}
		}
		sendDuration = time.Since(sendStart)

		// Close unblocks the drainer; wait for it so the goroutine doesn't outlive us.
		_ = client.Close()
		<-drainerDone
	}()

	wg.Wait()
	res = throughputResult{
		sent: totalSent.Load(), received: totalReceived.Load(),
		sendDur: sendDuration, recvDur: receiveDuration,
		cpu: processCPUTime() - cpuStart,
	}
	select {
	case res.cipher = <-cipher:
	default:
	}
	if srvErr != nil {
		return res, srvErr
	}
	return res, cliErr
}

// measureTCP is the unencrypted baseline: the same chunk over a plain loopback TCP stream.
func measureTCP(totalBytes int64, duration time.Duration, chunk []byte) (throughputResult, error) {
	var res throughputResult
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return res, err
	}
	defer func() { _ = ln.Close() }()

	var wg sync.WaitGroup
	var totalSent, totalReceived atomic.Int64
	var sendDuration, receiveDuration time.Duration
	var srvErr, cliErr error
	cpuStart := processCPUTime()

	wg.Add(1)
	go func() {
		defer wg.Done()
		conn, err := ln.Accept()
		if err != nil {
			srvErr = err
			return
		}
		defer func() { _ = conn.Close() }()
		buf := make([]byte, 64*1024)
		var receiveStart time.Time
		for {
			n, err := conn.Read(buf)
			if n > 0 {
				if receiveStart.IsZero() {
					receiveStart = time.Now()
				}
				totalReceived.Add(int64(n))
			}
			if err != nil || (!receiveStart.IsZero() && time.Since(receiveStart) >= duration) {
				break
			}
		}
		if !receiveStart.IsZero() {
			receiveDuration = time.Since(receiveStart)
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		conn, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			cliErr = err
			return
		}
		defer func() { _ = conn.Close() }()
		sendStart := time.Now()
		for totalSent.Load() < totalBytes && time.Since(sendStart) < duration {
			n, err := conn.Write(chunk)
			totalSent.Add(int64(n))
			if err != nil {
				cliErr = err
				break
			}
		}
		sendDuration = time.Since(sendStart)
	}()

	wg.Wait()
	res = throughputResult{
		sent: totalSent.Load(), received: totalReceived.Load(),
		sendDur: sendDuration, recvDur: receiveDuration,
		cpu: processCPUTime() - cpuStart,
	}
	if srvErr != nil {
		return res, srvErr
	}
	return res, cliErr
}

func printThroughputResults(r throughputResult) {
	fmt.Println()
	fmt.Println("\nResults:")
	if r.cipher != "" {
		fmt.Printf("  Cipher (negotiated): %s\n", r.cipher)
	}
	fmt.Printf("  Data sent: %s\n", formatSize(r.sent))
	fmt.Printf("  Data received: %s\n", formatSize(r.received))
	fmt.Printf("  Send duration: %v\n", r.sendDur)
	fmt.Printf("  Receive duration: %v\n", r.recvDur)
	fmt.Println()

	if r.sendDur > 0 {
		fmt.Printf("Send Throughput: %.2f MB/s (%.2f Mbps)\n", r.sendMBps(), r.sendMBps()*8)
	}
	if r.recvDur > 0 {
		fmt.Printf("Receive Throughput: %.2f MB/s (%.2f Mbps)\n", r.recvMBps(), r.recvMBps()*8)
	}
	if c := r.cpuPerGiB(); c > 0 {
		fmt.Printf("CPU: %.2f CPU-s/GiB (client and server)\n", c)
	}
	if r.sendDur > 0 && r.recvDur > 0 {
		printThroughputRating((r.sendMBps() + r.recvMBps()) / 2)
	}
}

func printThroughputRating(avgMBps float64) {
	fmt.Println()
	if avgMBps > 500 {
		fmt.Println("✓ Performance: Excellent (> 500 MB/s)")
	} else if avgMBps > 200 {
		fmt.Println("✓ Performance: Good (> 200 MB/s)")
	} else if avgMBps > 50 {
		fmt.Println("✓ Performance: Acceptable (> 50 MB/s)")
	} else {
		fmt.Println("⚠ Performance: May need optimization (< 50 MB/s)")
	}
}

// parseSize parses sizes such as "100", "8KB", "60k", "1GiB". An unknown unit or a
// malformed number is an error, not a silently tiny size.
func parseSize(s string) (int64, error) {
	s = strings.TrimSpace(s)
	i := 0
	for i < len(s) && s[i] >= '0' && s[i] <= '9' {
		i++
	}
	value, err := strconv.ParseInt(s[:i], 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid size %q", s)
	}
	unit := strings.TrimSpace(s[i:])
	mult := int64(1)
	switch strings.ToLower(unit) {
	case "":
	case "kb", "kib", "k":
		mult = 1 << 10
	case "mb", "mib", "m":
		mult = 1 << 20
	case "gb", "gib", "g":
		mult = 1 << 30
	case "tb", "tib", "t":
		mult = 1 << 40
	default:
		return 0, fmt.Errorf("invalid size %q: unknown unit %q", s, unit)
	}
	if value > (1<<62)/mult {
		return 0, fmt.Errorf("invalid size %q: too large", s)
	}
	return value * mult, nil
}

func parseDuration(s string) time.Duration {
	d, err := time.ParseDuration(s)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Invalid duration: %s\n", s)
		os.Exit(1)
	}
	return d
}

func formatSize(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	units := []string{"KB", "MB", "GB", "TB", "PB", "EB"}
	if exp >= len(units) {
		exp = len(units) - 1
	}
	return fmt.Sprintf("%.2f %s", float64(bytes)/float64(div), units[exp])
}
