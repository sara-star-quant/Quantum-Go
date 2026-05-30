# Command-Line Tool (quantum-vpn)

The `quantum-vpn` tool provides interactive demos, examples, and benchmarking utilities.

## Installation

```bash
go install github.com/sara-star-quant/quantum-go/cmd/quantum-vpn@latest
```

Or build from source:

```bash
git clone https://github.com/sara-star-quant/quantum-go
cd quantum-go
go build -o quantum-vpn ./cmd/quantum-vpn/
```

## Demo Mode

Run an encrypted interactive chat session:

```bash
# Terminal 1: Start server
quantum-vpn demo --mode server --addr :8443

# Terminal 2: Connect client
quantum-vpn demo --mode client --addr localhost:8443

# Interactive mode (type messages)
quantum-vpn demo --mode client --addr localhost:8443 --message "-"

# Verbose output (show handshake details)
quantum-vpn demo --mode server --addr :8443 --verbose
```

### Observability (Server Mode)

Expose Prometheus metrics and health endpoints alongside the demo server:

```bash
# Start demo server with observability endpoints
quantum-vpn demo --mode server --addr :8443 --obs-addr :9090
```

Set `--obs-addr ""` to disable the observability server.

Endpoints:
- `http://localhost:9090/metrics` (Prometheus)
- `http://localhost:9090/health` (detailed health)
- `http://localhost:9090/healthz` (liveness)
- `http://localhost:9090/readyz` (readiness)

Rate limiting metrics (Prometheus counters):
- `quantum_vpn_rate_limit_connections_total`
- `quantum_vpn_rate_limit_handshakes_total`

Logging and tracing controls:

```bash
# Structured logs and tracing options
quantum-vpn demo --mode server --log-level info --log-format json --tracing otel
```

Note: OpenTelemetry tracing requires building with the `otel` tag, for example:

```bash
go build -tags otel -o quantum-vpn ./cmd/quantum-vpn
```

## Benchmark Mode

Test performance on your hardware:

```bash
# Benchmark 100 stream (TCP) handshakes
quantum-vpn bench --handshakes 100

# Benchmark 100 datagram (UDP) handshakes
quantum-vpn bench --datagram-handshakes 100

# Benchmark throughput for 30 seconds
quantum-vpn bench --throughput --duration 30s

# Benchmark 1GB data transfer with ChaCha20-Poly1305
quantum-vpn bench --throughput --size 1GB --cipher chacha20

# Run all benchmarks
quantum-vpn bench --handshakes 100 --throughput --size 500MB
```

### Verified Performance (Apple M1 Pro, Go 1.26.3, loopback)
- **Handshakes (stream/TCP)**: ~1,450/sec (~670us each, full CH-KEM, sequential)
- **Handshakes (datagram/UDP)**: ~1,300/sec (~760us each, full CH-KEM, sequential)
- **Cipher throughput**: ~2.5 GB/s AES-256-GCM raw AEAD (ARMv8 Crypto Extensions); ~0.7 GB/s ChaCha20-Poly1305
- **Single-tunnel throughput (stream/TCP)**: ~690 MB/s (5.5 Gb/s) end-to-end over TCP, sustained across automatic rekeys

> The datagram (UDP) transport currently implements the handshake only; its encrypted data
> path is not yet landed, so there is no datagram throughput number. End-to-end stream
> throughput is currently allocation-bound and below the raw cipher rate.

## Example Mode

View standard implementation patterns directly in your terminal:

```bash
quantum-vpn example
```

Covers:
- Basic client/server setup
- Low-level CH-KEM API
- Custom configuration
- Session management
- Error handling
- Security best practices
