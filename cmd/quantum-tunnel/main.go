// Command quantum-tunnel is a demo, key generation and benchmark tool for the
// Quantum-Go library: it runs example tunnels, creates server identities with keygen,
// and measures handshake and throughput performance.
package main

import (
	"flag"
	"fmt"
	"os"

	pkgversion "github.com/sara-star-quant/quantum-go/pkg/version"
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
	case "keygen":
		keygenCommand()
	case "version":
		fmt.Printf("quantum-tunnel version %s\n", getVersion())
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
	fmt.Println(`quantum-tunnel - Quantum-Resistant Tunnel Demo & Benchmark Tool

USAGE:
    quantum-tunnel <command> [options]

COMMANDS:
    demo      Run interactive demo (client/server)
    bench     Run performance benchmarks
    example   Show example usage with explanations
    keygen    Generate a static-key server identity for endpoint auth
    version   Print version information
    help      Show this help message

Run 'quantum-tunnel <command> --help' for more information on a command.

EXAMPLES:
    # Start demo server
    quantum-tunnel demo --mode server --addr :8443

    # Connect demo client
    quantum-tunnel demo --mode client --addr localhost:8443

    # Run handshake benchmark
    quantum-tunnel bench --handshakes 100

    # Run throughput benchmark
    quantum-tunnel bench --throughput --size 1GB --duration 30s

    # Show interactive examples
    quantum-tunnel example

    # Generate a static-key server identity (server.key + server.pub)
    quantum-tunnel keygen

PROJECT:
    Quantum-Go - Cascaded Hybrid KEM (CH-KEM) Tunnel Encryption
    https://github.com/sara-star-quant/quantum-go

    Security: ML-KEM-1024 (NIST FIPS 203) + X25519 (RFC 7748)
    Defense-in-depth: Secure if EITHER algorithm is secure`)
}

func demoCommand() {
	fs := flag.NewFlagSet("demo", flag.ExitOnError)
	mode := fs.String("mode", "server", "Mode: server or client")
	addr := fs.String("addr", "localhost:8443", "Address to listen/connect")
	message := fs.String("message", "Hello from quantum-tunnel!", "Message to send (client mode)")
	verbose := fs.Bool("verbose", false, "Verbose output")
	obsAddr := fs.String("obs-addr", ":9090", "Observability server address (server mode). Empty disables")
	logLevel := fs.String("log-level", "warn", "Log level: debug, info, warn, error, silent")
	logFormat := fs.String("log-format", "text", "Log format: text or json")
	tracing := fs.String("tracing", "none", "Tracing mode: none, simple, otel (requires -tags otel)")

	fs.Usage = func() {
		fmt.Println(`USAGE: quantum-tunnel demo [options]

Run an interactive client/server demo of the quantum-resistant tunnel.

OPTIONS:`)
		fs.PrintDefaults()
		fmt.Println(`
EXAMPLES:
    # Terminal 1: Start server
    quantum-tunnel demo --mode server --addr :8443

    # Terminal 2: Connect client
    quantum-tunnel demo --mode client --addr localhost:8443 --message "Test message"

    # Verbose output (show handshake details)
    quantum-tunnel demo --mode server --addr :8443 --verbose`)
	}

	_ = fs.Parse(os.Args[2:])

	runDemo(*mode, *addr, *message, *verbose, *obsAddr, *logLevel, *logFormat, *tracing)
}

func benchCommand() {
	fs := flag.NewFlagSet("bench", flag.ExitOnError)
	handshakes := fs.Int("handshakes", 0, "Number of stream (TCP) handshakes to benchmark (0 = skip)")
	datagramHandshakes := fs.Int("datagram-handshakes", 0, "Number of datagram (UDP) handshakes to benchmark (0 = skip)")
	throughput := fs.Bool("throughput", false, "Run throughput benchmark")
	size := fs.String("size", "100MB", "Data size for throughput test (e.g., 100MB, 1GB)")
	duration := fs.String("duration", "10s", "Duration for throughput test (e.g., 10s, 1m)")
	cipherSuite := fs.String("cipher", "aes-gcm", "Cipher suite; only aes-gcm is supported (the tunnel negotiates it)")
	chunk := fs.String("chunk", "8KB", "Record size for the throughput test (e.g., 8KB, 60KB); throughput depends strongly on it")
	serve := fs.String("serve", "", "Receive a throughput test on this address (e.g., :9000); run --connect on another host")
	connect := fs.String("connect", "", "Send a throughput test to a --serve address (e.g., host:9000)")
	plain := fs.Bool("plain", false, "With --serve or --connect, use plain TCP instead of the tunnel")
	baseline := fs.Bool("baseline", false, "Also run a plain TCP baseline with the same records and report the tunnel's overhead against it")

	fs.Usage = func() {
		fmt.Println(`USAGE: quantum-tunnel bench [options]

Run performance benchmarks for handshake and data throughput.

OPTIONS:`)
		fs.PrintDefaults()
		fmt.Println(`
EXAMPLES:
    # Benchmark 100 stream (TCP) handshakes
    quantum-tunnel bench --handshakes 100

    # Benchmark 100 datagram (UDP) handshakes
    quantum-tunnel bench --datagram-handshakes 100

    # Benchmark throughput for 30 seconds
    quantum-tunnel bench --throughput --duration 30s

    # Move 10GB in 60KB records and compare with plain TCP
    quantum-tunnel bench --throughput --size 10GB --duration 5m --chunk 60KB --baseline

    # Measure a real link: receive on one host, send from another
    quantum-tunnel bench --serve :9000
    quantum-tunnel bench --connect host:9000 --size 10GB --duration 5m --chunk 60KB

    # Run all benchmarks
    quantum-tunnel bench --handshakes 100 --throughput --size 500MB`)
	}

	_ = fs.Parse(os.Args[2:])

	if *serve != "" || *connect != "" {
		runRemoteBench(*serve, *connect, *plain, *size, *duration, *chunk)
		return
	}

	runBench(*handshakes, *datagramHandshakes, *throughput, *size, *duration, *cipherSuite, *chunk, *baseline)
}

func exampleCommand() {
	if len(os.Args) > 2 && (os.Args[2] == "--help" || os.Args[2] == "-h") {
		fmt.Println(`USAGE: quantum-tunnel example

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

// runRemoteBench runs one side of a two-host throughput test.
func runRemoteBench(serve, connect string, plain bool, sizeStr, durationStr, chunkStr string) {
	if serve != "" && connect != "" {
		fmt.Fprintln(os.Stderr, "Use either --serve or --connect, not both")
		os.Exit(1)
	}
	size, err := parseSize(sizeStr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Invalid --size: %v\n", err)
		os.Exit(1)
	}
	chunkSize, err := parseSize(chunkStr)
	if err != nil || chunkSize <= 0 {
		fmt.Fprintf(os.Stderr, "Invalid --chunk %q: want a positive size such as 8KB or 60KB\n", chunkStr)
		os.Exit(1)
	}
	duration := parseDuration(durationStr)

	if serve != "" {
		ready := make(chan string, 1)
		go func() { fmt.Printf("Listening on %s, waiting for one sender...\n", <-ready) }()
		res, err := serveThroughput(serve, plain, duration, ready)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		printRemoteResult("Receiver", plain, res)
		return
	}

	chunk := make([]byte, chunkSize)
	for i := range chunk {
		chunk[i] = byte(i % 256)
	}
	fmt.Printf("Sending %s to %s in %s records for up to %v\n", formatSize(size), connect, formatSize(chunkSize), duration)
	res, err := connectThroughput(connect, plain, size, duration, chunk, 50)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	printRemoteResult("Sender", plain, res)
}
