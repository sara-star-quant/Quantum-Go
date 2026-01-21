package main

import (
	"flag"
	"fmt"
	"os"

	pkgversion "github.com/pzverkov/quantum-go/pkg/version"
)

// Build-time variables (set via -ldflags)
var (
	version   = ""        // Set via -ldflags "-X main.version=x.y.z"
	buildTime = "unknown" // Set via -ldflags "-X main.buildTime=..."
	gitCommit = "unknown" // Set via -ldflags "-X main.gitCommit=..."
)

func getVersion() string {
	if version != "" {
		return version
	}
	return pkgversion.String()
}

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	command := os.Args[1]

	switch command {
	case "demo":
		demoCommand()
	case "bench":
		benchCommand()
	case "example":
		exampleCommand()
	case "version":
		fmt.Printf("quantum-vpn version %s\n", getVersion())
		if buildTime != "unknown" {
			fmt.Printf("Built: %s\n", buildTime)
		}
		if gitCommit != "unknown" {
			fmt.Printf("Commit: %s\n", gitCommit)
		}
	case "help", "--help", "-h":
		printUsage()
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n\n", command)
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println(`quantum-vpn - Quantum-Resistant VPN Demo & Benchmark Tool

USAGE:
    quantum-vpn <command> [options]

COMMANDS:
    demo      Run interactive demo (client/server)
    bench     Run performance benchmarks
    example   Show example usage with explanations
    version   Print version information
    help      Show this help message

Run 'quantum-vpn <command> --help' for more information on a command.

EXAMPLES:
    # Start demo server
    quantum-vpn demo --mode server --addr :8443

    # Connect demo client
    quantum-vpn demo --mode client --addr localhost:8443

    # Run handshake benchmark
    quantum-vpn bench --handshakes 100

    # Run throughput benchmark
    quantum-vpn bench --throughput --size 1GB --duration 30s

    # Show interactive examples
    quantum-vpn example

PROJECT:
    Quantum-Go - Cascaded Hybrid KEM (CH-KEM) VPN Encryption
    https://github.com/pzverkov/quantum-go

    Security: ML-KEM-1024 (NIST FIPS 203) + X25519 (RFC 7748)
    Defense-in-depth: Secure if EITHER algorithm is secure`)
}

func demoCommand() {
	fs := flag.NewFlagSet("demo", flag.ExitOnError)
	mode := fs.String("mode", "server", "Mode: server or client")
	addr := fs.String("addr", "localhost:8443", "Address to listen/connect")
	message := fs.String("message", "Hello from quantum-vpn!", "Message to send (client mode)")
	verbose := fs.Bool("verbose", false, "Verbose output")
	obsAddr := fs.String("obs-addr", ":9090", "Observability server address (server mode). Empty disables")
	logLevel := fs.String("log-level", "warn", "Log level: debug, info, warn, error, silent")
	logFormat := fs.String("log-format", "text", "Log format: text or json")
	tracing := fs.String("tracing", "none", "Tracing mode: none, simple, otel (requires -tags otel)")

	fs.Usage = func() {
		fmt.Println(`USAGE: quantum-vpn demo [options]

Run an interactive client/server demo of the quantum-resistant VPN tunnel.

OPTIONS:`)
		fs.PrintDefaults()
		fmt.Println(`
EXAMPLES:
    # Terminal 1: Start server
    quantum-vpn demo --mode server --addr :8443

    # Terminal 2: Connect client
    quantum-vpn demo --mode client --addr localhost:8443 --message "Test message"

    # Verbose output (show handshake details)
    quantum-vpn demo --mode server --addr :8443 --verbose`)
	}

	_ = fs.Parse(os.Args[2:])

	runDemo(*mode, *addr, *message, *verbose, *obsAddr, *logLevel, *logFormat, *tracing)
}

func benchCommand() {
	fs := flag.NewFlagSet("bench", flag.ExitOnError)
	handshakes := fs.Int("handshakes", 0, "Number of handshakes to benchmark (0 = skip)")
	throughput := fs.Bool("throughput", false, "Run throughput benchmark")
	size := fs.String("size", "100MB", "Data size for throughput test (e.g., 100MB, 1GB)")
	duration := fs.String("duration", "10s", "Duration for throughput test (e.g., 10s, 1m)")
	cipherSuite := fs.String("cipher", "aes-gcm", "Cipher suite: aes-gcm or chacha20")

	fs.Usage = func() {
		fmt.Println(`USAGE: quantum-vpn bench [options]

Run performance benchmarks for handshake and data throughput.

OPTIONS:`)
		fs.PrintDefaults()
		fmt.Println(`
EXAMPLES:
    # Benchmark 100 handshakes
    quantum-vpn bench --handshakes 100

    # Benchmark throughput for 30 seconds
    quantum-vpn bench --throughput --duration 30s

    # Benchmark 1GB data transfer with ChaCha20-Poly1305
    quantum-vpn bench --throughput --size 1GB --cipher chacha20

    # Run all benchmarks
    quantum-vpn bench --handshakes 100 --throughput --size 500MB`)
	}

	_ = fs.Parse(os.Args[2:])

	runBench(*handshakes, *throughput, *size, *duration, *cipherSuite)
}

func exampleCommand() {
	if len(os.Args) > 2 && (os.Args[2] == "--help" || os.Args[2] == "-h") {
		fmt.Println(`USAGE: quantum-vpn example

Display interactive examples with code snippets showing how to use the library.

This command shows:
  - Basic client/server setup
  - Low-level CH-KEM API usage
  - Security considerations
  - Common patterns`)
		return
	}

	showExamples()
}
