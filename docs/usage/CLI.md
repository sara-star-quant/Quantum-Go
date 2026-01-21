# Command-Line Tool (quantum-vpn)

The `quantum-vpn` tool provides interactive demos, examples, and benchmarking utilities.

## Installation

```bash
go install github.com/pzverkov/quantum-go/cmd/quantum-vpn@latest
```

Or build from source:

```bash
git clone https://github.com/pzverkov/quantum-go
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
# Benchmark 100 handshakes
quantum-vpn bench --handshakes 100

# Benchmark throughput for 30 seconds
quantum-vpn bench --throughput --duration 30s

# Benchmark 1GB data transfer with ChaCha20-Poly1305
quantum-vpn bench --throughput --size 1GB --cipher chacha20

# Run all benchmarks
quantum-vpn bench --handshakes 100 --throughput --size 500MB
```

### Verified Performance (Apple M1 Pro)
- **Handshakes**: ~1,800/sec (0.5ms latency)
- **Throughput**: >2.0 GB/s (AES-NI / ARMv8 Crypto)

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
