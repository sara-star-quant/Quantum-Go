# Command-Line Tool (quantum-tunnel)

The `quantum-tunnel` tool provides interactive demos, examples, and benchmarking utilities.

## Installation

```bash
go install github.com/sara-star-quant/quantum-go/cmd/quantum-tunnel@latest
```

Or build from source:

```bash
git clone https://github.com/sara-star-quant/quantum-go
cd quantum-go
go build -o quantum-tunnel ./cmd/quantum-tunnel/
```

## Demo Mode

Run an encrypted interactive chat session:

```bash
# Terminal 1: Start server
quantum-tunnel demo --mode server --addr :8443

# Terminal 2: Connect client
quantum-tunnel demo --mode client --addr localhost:8443

# Interactive mode (type messages)
quantum-tunnel demo --mode client --addr localhost:8443 --message "-"

# Verbose output (show handshake details)
quantum-tunnel demo --mode server --addr :8443 --verbose
```

### Observability (Server Mode)

Expose Prometheus metrics and health endpoints alongside the demo server:

```bash
# Start demo server with observability endpoints
quantum-tunnel demo --mode server --addr :8443 --obs-addr :9090
```

Set `--obs-addr ""` to disable the observability server.

Endpoints:
- `http://localhost:9090/metrics` (Prometheus)
- `http://localhost:9090/health` (detailed health)
- `http://localhost:9090/healthz` (liveness)
- `http://localhost:9090/readyz` (readiness)

Rate limiting metrics (Prometheus counters):
- `quantum_tunnel_rate_limit_connections_total`
- `quantum_tunnel_rate_limit_handshakes_total`

Logging and tracing controls:

```bash
# Structured logs and tracing options
quantum-tunnel demo --mode server --log-level info --log-format json --tracing otel
```

Note: OpenTelemetry tracing requires building with the `otel` tag, for example:

```bash
go build -tags otel -o quantum-tunnel ./cmd/quantum-tunnel
```

## Benchmark Mode

Test performance on your hardware:

```bash
# Benchmark 100 stream (TCP) handshakes
quantum-tunnel bench --handshakes 100

# Benchmark 100 datagram (UDP) handshakes
quantum-tunnel bench --datagram-handshakes 100

# Benchmark throughput for 30 seconds
quantum-tunnel bench --throughput --duration 30s

# Benchmark 1GB data transfer with ChaCha20-Poly1305
quantum-tunnel bench --throughput --size 1GB --cipher chacha20

# Run all benchmarks
quantum-tunnel bench --handshakes 100 --throughput --size 500MB
```

### Verified Performance (Apple M1 Pro, Go 1.26.3, loopback)
- **Handshakes (stream/TCP)**: ~1,450/sec (~670us each, full CH-KEM, sequential)
- **Handshakes (datagram/UDP)**: ~1,300/sec (~760us each, full CH-KEM, sequential)
- **Cipher throughput**: ~2.5 GB/s AES-256-GCM raw AEAD (ARMv8 Crypto Extensions); ~0.7 GB/s ChaCha20-Poly1305
- **Single-tunnel throughput (stream/TCP)**: ~690 MB/s (5.5 Gb/s) end-to-end over TCP, sustained across automatic rekeys
- **Datagram data path (UDP)**: encrypted, zero-alloc send (~3 GB/s isolated on M1 Pro darwin); one-way single-flow delivered goodput ~58 MB/s on macOS loopback (a loopback artifact) and ~1.8 Gb/s on Linux (container arm64, indicative)

> The datagram data path is syscall-bound, not crypto-bound; macOS loopback has a slow
> per-datagram socket path, so its single-flow number is a loopback artifact rather than a
> transport limit. See the README Performance section for the platform breakdown.

## Example Mode

View standard implementation patterns directly in your terminal:

```bash
quantum-tunnel example
```

Covers:
- Basic client/server setup
- Low-level CH-KEM API
- Custom configuration
- Session management
- Error handling
- Security best practices
