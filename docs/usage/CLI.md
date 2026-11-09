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

Throughput options: `--size` (bytes to move, for example `10GB`), `--duration` (stop after this long), `--chunk` (record size, default `8KB`; throughput depends strongly on it), and `--baseline` (also run plain TCP with the same records and report the tunnel's throughput share and CPU cost against it). Sizes accept `KB`, `MB`, `GB`, `TB` and the `KiB` forms; an unknown unit is an error. To measure a real link, run `quantum-tunnel bench --serve :9000` on one host and `quantum-tunnel bench --connect host:9000 --size 10GB --duration 5m --chunk 60KB` on another; add `--plain` on both sides for a plain TCP reference. The receiver reports the delivered rate, and each side reports CPU per GiB for its own host. `scripts/docker-bench.sh` runs the same test between two containers on a bridge network when you have only one machine. `--cipher` accepts only `aes-gcm`, because the tunnel negotiates AES-256-GCM and cannot be asked for another cipher yet. Throughput is reported in decimal MB/s.

```bash
# Benchmark 100 stream (TCP) handshakes
quantum-tunnel bench --handshakes 100

# Benchmark 100 datagram (UDP) handshakes
quantum-tunnel bench --datagram-handshakes 100

# Benchmark throughput for 30 seconds
quantum-tunnel bench --throughput --duration 30s

# Move 10GB in 60KB records and compare against plain TCP
quantum-tunnel bench --throughput --size 10GB --duration 5m --chunk 60KB --baseline

# Run all benchmarks
quantum-tunnel bench --handshakes 100 --throughput --size 500MB
```

### Verified Performance (Apple M1 Pro, Go 1.26.3, loopback)
- **Handshakes (stream/TCP)**: ~1,450/sec (~670us each, full CH-KEM, sequential)
- **Handshakes (datagram/UDP)**: ~1,300/sec (~760us each, full CH-KEM, sequential)
- **Cipher throughput**: ~2.5 GB/s AES-256-GCM raw AEAD (ARMv8 Crypto Extensions); ~0.7 GB/s ChaCha20-Poly1305
- **Single-tunnel throughput (stream/TCP)**: ~2.5 GB/s with 60 KB records and ~1.2 GB/s with 8 KB records, end-to-end over TCP on loopback; it depends on the record size, see [PERFORMANCE.md](../PERFORMANCE.md#throughput-by-record-size-and-cost-against-plain-tcp)
- **Datagram data path (UDP)**: encrypted, zero-alloc send (~3 GB/s isolated on M1 Pro darwin); one-way single-flow delivered goodput ~58 MB/s on macOS loopback (a loopback artifact) and ~280 MB/s (~2.2 Gb/s) on Linux (container arm64, indicative)
- **Datagram aggregate (UDP, Linux `SO_REUSEPORT`)**: a single receive goroutine tops out ~365 MB/s aggregate; spreading receive across 8 sockets lifts it ~1.6x to ~565 MB/s on an 8-core container, scaling further on a many-core host

> The datagram data path is syscall-bound, not crypto-bound; macOS loopback has a slow
> per-datagram socket path, so its single-flow number is a loopback artifact rather than a
> transport limit. See the README Performance section for the platform breakdown.

## Keygen Mode (v0.0.12+)

Generate a long-term CH-KEM server identity for static-key endpoint authentication:

```bash
# Write server.key (secret seed, mode 0600) and server.pub (public pin)
quantum-tunnel keygen

# Custom file prefix
quantum-tunnel keygen --out prod-edge

# Generate an X-Wing identity instead of CH-KEM-v1
quantum-tunnel keygen --suite x-wing --out edge

# Re-derive the public pin from an existing secret key
quantum-tunnel keygen --pub-from server.key --out server
```

The `--suite` flag selects the identity's KEM suite (`chkem-v1` default, or `x-wing`); the seed and pin files are tagged with the suite so a loader self-selects it. Keep `server.key` secret and persistent (load it on the server via `chkem.ParseTaggedKeyPair`); distribute `server.pub` to clients (pin it via `chkem.ParseTaggedPublicKey`). The command prints an SSH-style `SHA256:` fingerprint so operators can verify the pin out-of-band, and refuses to overwrite an existing file without `--force`. See [CONFIGURATION.md](CONFIGURATION.md#endpoint-authentication-v0012) for wiring the keys into a tunnel.

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
