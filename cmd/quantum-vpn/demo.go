package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/pzverkov/quantum-go/pkg/tunnel"
)

func runDemo(mode, addr, message string, verbose bool) {
	switch mode {
	case "server":
		runDemoServer(addr, verbose)
	case "client":
		runDemoClient(addr, message, verbose)
	default:
		fmt.Fprintf(os.Stderr, "Invalid mode: %s (use 'server' or 'client')\n", mode)
		os.Exit(1)
	}
}

func runDemoServer(addr string, verbose bool) {
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
	defer listener.Close()

	actualAddr := listener.Addr().String()
	fmt.Printf("✓ Server listening on %s\n", actualAddr)
	fmt.Println("Waiting for connections... (Press Ctrl+C to stop)")
	fmt.Println()

	// Handle graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-sigChan
		fmt.Println("\n\nShutting down server...")
		listener.Close()
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
	defer conn.Close()

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

func runDemoClient(addr, message string, verbose bool) {
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
	client, err := tunnel.Dial("tcp", addr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: Failed to connect: %v\n", err)
		os.Exit(1)
	}
	defer client.Close()

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
