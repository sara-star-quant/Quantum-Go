package main

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/pzverkov/quantum-go/pkg/tunnel"
)

func runBench(handshakes int, throughputTest bool, sizeStr, durationStr, cipherSuite string) {
	fmt.Println("╔═══════════════════════════════════════════════════════════╗")
	fmt.Println("║      Quantum-Resistant VPN Benchmark                     ║")
	fmt.Println("║      CH-KEM: ML-KEM-1024 + X25519                        ║")
	fmt.Println("╚═══════════════════════════════════════════════════════════╝")
	fmt.Println()

	if handshakes == 0 && !throughputTest {
		fmt.Println("No benchmarks specified. Use --handshakes or --throughput")
		fmt.Println("Run 'quantum-vpn bench --help' for usage")
		os.Exit(1)
	}

	if handshakes > 0 {
		benchHandshakes(handshakes)
		fmt.Println()
	}

	if throughputTest {
		size := parseSize(sizeStr)
		duration := parseDuration(durationStr)
		benchThroughput(size, duration, cipherSuite)
	}
}

func benchHandshakes(count int) {
	fmt.Printf("Benchmarking Handshakes (%d iterations)\n", count)
	fmt.Println(strings.Repeat("─", 60))

	listener, err := tunnel.Listen("tcp", "127.0.0.1:0")
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

		client, err := tunnel.Dial("tcp", addr)
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

func benchThroughput(totalBytes int64, duration time.Duration, cipherSuiteStr string) {
	fmt.Printf("Benchmarking Throughput\n")
	fmt.Println(strings.Repeat("─", 60))
	fmt.Printf("Target: %s over %v\n", formatSize(totalBytes), duration)
	fmt.Printf("Cipher: %s\n\n", cipherSuiteStr)

	listener, err := tunnel.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: Failed to start listener: %v\n", err)
		os.Exit(1)
	}
	defer func() { _ = listener.Close() }()

	addr := listener.Addr().String()

	var wg sync.WaitGroup
	var totalSent, totalReceived int64
	var sendDuration, receiveDuration time.Duration

	// Data chunk (8KB)
	chunkSize := 8192
	chunk := make([]byte, chunkSize)
	for i := range chunk {
		chunk[i] = byte(i % 256)
	}

	// Server goroutine
	wg.Add(1)
	go func() {
		defer wg.Done()

		conn, err := listener.Accept()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Accept error: %v\n", err)
			return
		}
		defer func() { _ = conn.Close() }()

		receiveStart := time.Now()
		for {
			data, err := conn.Receive()
			if err != nil {
				break
			}
			totalReceived += int64(len(data))

			// Check if we should stop
			if time.Since(receiveStart) >= duration {
				break
			}
		}
		receiveDuration = time.Since(receiveStart)
	}()

	// Client goroutine
	wg.Add(1)
	go func() {
		defer wg.Done()

		time.Sleep(100 * time.Millisecond) // Let server start

		client, err := tunnel.Dial("tcp", addr)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Dial error: %v\n", err)
			return
		}
		defer func() { _ = client.Close() }()

		sendStart := time.Now()
		bytesToSend := totalBytes
		lastProgress := time.Now()

		for totalSent < bytesToSend && time.Since(sendStart) < duration {
			if err := client.Send(chunk); err != nil {
				fmt.Fprintf(os.Stderr, "Send error: %v\n", err)
				break
			}
			totalSent += int64(len(chunk))

			// Progress update every second
			if time.Since(lastProgress) >= time.Second {
				elapsed := time.Since(sendStart)
				mbps := float64(totalSent) / elapsed.Seconds() / 1024 / 1024
				fmt.Printf("Progress: %s / %s (%.1f MB/s)\r",
					formatSize(totalSent), formatSize(bytesToSend), mbps)
				lastProgress = time.Now()
			}
		}
		sendDuration = time.Since(sendStart)
	}()

	wg.Wait()

	printThroughputResults(totalSent, totalReceived, sendDuration, receiveDuration)
}

func printThroughputResults(totalSent, totalReceived int64, sendDuration, receiveDuration time.Duration) {
	fmt.Println()
	fmt.Println("\nResults:")
	fmt.Printf("  Data sent: %s\n", formatSize(totalSent))
	fmt.Printf("  Data received: %s\n", formatSize(totalReceived))
	fmt.Printf("  Send duration: %v\n", sendDuration)
	fmt.Printf("  Receive duration: %v\n", receiveDuration)
	fmt.Println()

	if sendDuration > 0 {
		sendMBps := float64(totalSent) / sendDuration.Seconds() / 1024 / 1024
		fmt.Printf("Send Throughput: %.2f MB/s (%.2f Mbps)\n", sendMBps, sendMBps*8)
	}

	if receiveDuration > 0 {
		recvMBps := float64(totalReceived) / receiveDuration.Seconds() / 1024 / 1024
		fmt.Printf("Receive Throughput: %.2f MB/s (%.2f Mbps)\n", recvMBps, recvMBps*8)
	}

	avgMBps := (float64(totalSent)/sendDuration.Seconds() + float64(totalReceived)/receiveDuration.Seconds()) / 2 / 1024 / 1024
	printThroughputRating(avgMBps)
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

func parseSize(s string) int64 {
	// Simple parser for sizes like "100MB", "1GB"
	var value int64
	var unit string
	_, _ = fmt.Sscanf(s, "%d%s", &value, &unit)

	switch unit {
	case "KB", "kb", "K", "k":
		return value * 1024
	case "MB", "mb", "M", "m":
		return value * 1024 * 1024
	case "GB", "gb", "G", "g":
		return value * 1024 * 1024 * 1024
	default:
		return value
	}
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
	units := []string{"KB", "MB", "GB", "TB"}
	return fmt.Sprintf("%.2f %s", float64(bytes)/float64(div), units[exp])
}
