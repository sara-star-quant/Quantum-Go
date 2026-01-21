package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/pzverkov/quantum-go/pkg/metrics"
	"github.com/pzverkov/quantum-go/pkg/tunnel"
)

func runDemo(mode, addr, message string, verbose bool, obsAddr, logLevel, logFormat, tracing string) {
	collector, observerFactory, logger, err := setupObservability(logLevel, logFormat, tracing)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	switch mode {
	case "server":
		runDemoServer(addr, verbose, obsAddr, collector, observerFactory, logger)
	case "client":
		runDemoClient(addr, message, verbose, observerFactory)
	default:
		fmt.Fprintf(os.Stderr, "Invalid mode: %s (use 'server' or 'client')\n", mode)
		os.Exit(1)
	}
}

func runDemoServer(addr string, verbose bool, obsAddr string, collector *metrics.Collector, observerFactory tunnel.ObserverFactory, logger *metrics.Logger) {
	fmt.Println("╔═══════════════════════════════════════════════════════════╗")
	fmt.Println("║      Quantum-Resistant VPN Demo Server                   ║")
	fmt.Println("║      CH-KEM: ML-KEM-1024 + X25519                        ║")
	fmt.Println("╚═══════════════════════════════════════════════════════════╝")
	fmt.Println()

	if verbose {
		fmt.Println("Security Properties:")
		fmt.Println("  • Post-Quantum: ML-KEM-1024 (NIST Category 5)")
		fmt.Println("  • Classical: X25519 (128-bit)")
		fmt.Println("  • Hybrid: Secure if EITHER algorithm is secure")
		fmt.Println("  • Encryption: AES-256-GCM")
		fmt.Println()
	}

	fmt.Printf("Starting server on %s...\n", addr)

	listener, err := tunnel.Listen("tcp", addr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: Failed to start listener: %v\n", err)
		os.Exit(1)
	}
	defer func() { _ = listener.Close() }()

	config := tunnel.DefaultTransportConfig()
	config.ObserverFactory = observerFactory
	config.RateLimitObserver = metrics.NewRateLimitObserver(collector, logger)
	listener.SetConfig(config)

	actualAddr := listener.Addr().String()
	fmt.Printf("✓ Server listening on %s\n", actualAddr)
	fmt.Println("Waiting for connections... (Press Ctrl+C to stop)")
	fmt.Println()

	if obsAddr != "" {
		server := metrics.NewServer(metrics.ServerConfig{
			Collector:        collector,
			Version:          version,
			Namespace:        "quantum_vpn",
			EnablePrometheus: true,
			EnableHealth:     true,
		})

		go func() {
			if err := server.ListenAndServe(obsAddr); err != nil && !errors.Is(err, http.ErrServerClosed) {
				logger.Error("observability server error", metrics.Fields{"error": err.Error()})
			}
		}()

		fmt.Printf("✓ Observability server on %s (metrics: /metrics, health: /health)\n", obsAddr)
	}

	// Handle graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-sigChan
		fmt.Println("\n\nShutting down server...")
		_ = listener.Close()
		os.Exit(0)
	}()

	connectionNum := 0
	for {
		connectionNum++
		fmt.Printf("[%s] Waiting for connection #%d...\n", time.Now().Format("15:04:05"), connectionNum)

		conn, err := listener.Accept()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Accept error: %v\n", err)
			continue
		}

		fmt.Printf("[%s] ✓ Connection #%d established\n", time.Now().Format("15:04:05"), connectionNum)

		if verbose {
			fmt.Printf("  Remote: %s\n", conn.RemoteAddr())
			fmt.Printf("  Local: %s\n", conn.LocalAddr())
			session := conn.Session()
			if session != nil {
				fmt.Printf("  Session ID: %x...\n", session.ID[:8])
				fmt.Printf("  Cipher Suite: %v\n", session.CipherSuite)
			}
		}

		// Handle connection in goroutine
		go handleConnection(conn, connectionNum, verbose)
	}
}

func handleConnection(conn *tunnel.Tunnel, connNum int, verbose bool) {
	defer func() { _ = conn.Close() }()

	for {
		if verbose {
			fmt.Printf("[%s] [Conn #%d] Waiting for data...\n", time.Now().Format("15:04:05"), connNum)
		}

		data, err := conn.Receive()
		if err != nil {
			if err == io.EOF || strings.Contains(err.Error(), "closed") {
				fmt.Printf("[%s] [Conn #%d] Client disconnected\n", time.Now().Format("15:04:05"), connNum)
			} else {
				fmt.Printf("[%s] [Conn #%d] Receive error: %v\n", time.Now().Format("15:04:05"), connNum, err)
			}
			return
		}

		fmt.Printf("[%s] [Conn #%d] ← Received: %q (%d bytes)\n",
			time.Now().Format("15:04:05"), connNum, string(data), len(data))

		// Echo back
		response := fmt.Sprintf("Echo: %s", data)
		if err := conn.Send([]byte(response)); err != nil {
			fmt.Printf("[%s] [Conn #%d] Send error: %v\n", time.Now().Format("15:04:05"), connNum, err)
			return
		}

		if verbose {
			fmt.Printf("[%s] [Conn #%d] → Sent: %q\n", time.Now().Format("15:04:05"), connNum, response)
		}
	}
}

func runDemoClient(addr, message string, verbose bool, observerFactory tunnel.ObserverFactory) {
	fmt.Println("╔═══════════════════════════════════════════════════════════╗")
	fmt.Println("║      Quantum-Resistant VPN Demo Client                   ║")
	fmt.Println("║      CH-KEM: ML-KEM-1024 + X25519                        ║")
	fmt.Println("╚═══════════════════════════════════════════════════════════╝")
	fmt.Println()

	if verbose {
		fmt.Println("Handshake Protocol:")
		fmt.Println("  1. ClientHello → CH-KEM public key (1600 bytes)")
		fmt.Println("  2. ServerHello ← CH-KEM ciphertext (1600 bytes)")
		fmt.Println("  3. ClientFinished → Encrypted verify_data")
		fmt.Println("  4. ServerFinished ← Encrypted verify_data")
		fmt.Println()
	}

	fmt.Printf("Connecting to %s...\n", addr)

	startHandshake := time.Now()
	config := tunnel.DefaultTransportConfig()
	config.ObserverFactory = observerFactory

	client, err := tunnel.DialWithConfig("tcp", addr, config)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: Failed to connect: %v\n", err)
		os.Exit(1)
	}
	defer func() { _ = client.Close() }()

	handshakeDuration := time.Since(startHandshake)

	fmt.Printf("✓ Connected successfully\n")
	if verbose {
		fmt.Printf("  Handshake time: %v\n", handshakeDuration)
		fmt.Printf("  Local: %s\n", client.LocalAddr())
		fmt.Printf("  Remote: %s\n", client.RemoteAddr())
		session := client.Session()
		if session != nil {
			fmt.Printf("  Session ID: %x...\n", session.ID[:8])
			fmt.Printf("  Cipher Suite: %v\n", session.CipherSuite)
		}
	}
	fmt.Println()

	// If message is "-", read from stdin
	if message == "-" {
		fmt.Println("Interactive mode (type messages, Ctrl+D to exit):")
		runInteractiveClient(client, verbose)
		return
	}

	// Send single message
	fmt.Printf("Sending: %q\n", message)
	if err := client.Send([]byte(message)); err != nil {
		fmt.Fprintf(os.Stderr, "Error: Send failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("✓ Message sent")

	fmt.Println("Waiting for response...")
	response, err := client.Receive()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: Receive failed: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("✓ Received: %q\n", string(response))

	if verbose {
		session := client.Session()
		if session != nil {
			stats := session.Stats()
			fmt.Println()
			fmt.Println("Session Statistics:")
			fmt.Printf("  Bytes sent: %d\n", stats.BytesSent)
			fmt.Printf("  Bytes received: %d\n", stats.BytesReceived)
			fmt.Printf("  Packets sent: %d\n", stats.PacketsSent)
			fmt.Printf("  Packets received: %d\n", stats.PacketsRecv)
		}
	}
}

func runInteractiveClient(client *tunnel.Tunnel, verbose bool) {
	scanner := bufio.NewScanner(os.Stdin)
	messageNum := 0

	for {
		fmt.Print("> ")
		if !scanner.Scan() {
			break // EOF or error
		}

		message := scanner.Text()
		if message == "" {
			continue
		}

		messageNum++

		if verbose {
			fmt.Printf("[%d] Sending: %q\n", messageNum, message)
		}

		if err := client.Send([]byte(message)); err != nil {
			fmt.Fprintf(os.Stderr, "Send error: %v\n", err)
			return
		}

		if verbose {
			fmt.Printf("[%d] Waiting for response...\n", messageNum)
		}

		response, err := client.Receive()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Receive error: %v\n", err)
			return
		}

		fmt.Printf("← %s\n", string(response))
	}

	if err := scanner.Err(); err != nil {
		fmt.Fprintf(os.Stderr, "Input error: %v\n", err)
	}
}

func setupObservability(logLevel, logFormat, tracing string) (*metrics.Collector, tunnel.ObserverFactory, *metrics.Logger, error) {
	level, err := parseLogLevel(logLevel)
	if err != nil {
		return nil, nil, nil, err
	}

	format, err := parseLogFormat(logFormat)
	if err != nil {
		return nil, nil, nil, err
	}

	logger := metrics.NewLogger(
		metrics.WithOutput(os.Stderr),
		metrics.WithLevel(level),
		metrics.WithFormat(format),
		metrics.WithFields(metrics.Fields{"app": "quantum-vpn"}),
	)
	metrics.SetLogger(logger)

	switch strings.ToLower(tracing) {
	case "none":
		metrics.SetTracer(metrics.NoOpTracer{})
	case "simple":
		metrics.SetTracer(metrics.NewSimpleTracer())
	case "otel":
		if !metrics.OTelEnabled() {
			return nil, nil, nil, fmt.Errorf("otel tracing not enabled (build with -tags otel)")
		}
		metrics.SetTracer(metrics.NewOTelTracer("quantum-vpn"))
	default:
		return nil, nil, nil, fmt.Errorf("invalid tracing mode: %s (use none, simple, or otel)", tracing)
	}

	collector := metrics.NewCollector(metrics.Labels{
		"service": "quantum-vpn",
	})
	metrics.SetGlobal(collector)

	observerFactory := func(session *tunnel.Session) tunnel.Observer {
		return metrics.NewTunnelObserver(metrics.TunnelObserverConfig{
			Collector: collector,
			SessionID: session.ID,
			Role:      roleLabel(session.Role),
		})
	}

	return collector, observerFactory, logger, nil
}

func parseLogLevel(level string) (metrics.Level, error) {
	switch strings.ToLower(level) {
	case "debug":
		return metrics.LevelDebug, nil
	case "info":
		return metrics.LevelInfo, nil
	case "warn", "warning":
		return metrics.LevelWarn, nil
	case "error":
		return metrics.LevelError, nil
	case "silent", "off", "none":
		return metrics.LevelSilent, nil
	default:
		return metrics.LevelInfo, fmt.Errorf("invalid log level: %s (use debug, info, warn, error, silent)", level)
	}
}

func parseLogFormat(format string) (metrics.Format, error) {
	switch strings.ToLower(format) {
	case "text":
		return metrics.FormatText, nil
	case "json":
		return metrics.FormatJSON, nil
	default:
		return metrics.FormatText, fmt.Errorf("invalid log format: %s (use text or json)", format)
	}
}

func roleLabel(role tunnel.Role) string {
	if role == tunnel.RoleResponder {
		return "responder"
	}
	return "initiator"
}
