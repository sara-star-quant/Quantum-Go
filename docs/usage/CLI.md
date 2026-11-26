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

| Throughput option | Meaning |
|---|---|
| `--size` | Bytes to move, for example `10GB`. Sizes accept `KB`, `MB`, `GB`, `TB` and the `KiB` forms; an unknown unit is an error. |
| `--duration` | Stop after this long. |
| `--chunk` | Record size, default `8KB`. Throughput depends strongly on it. |
| `--baseline` | Also run plain TCP with the same records and report the tunnel's throughput share and CPU cost against it. |
| `--cipher` | Accepts only `aes-gcm`: the tunnel negotiates AES-256-GCM and cannot be asked for another cipher yet. |

The tool reports throughput in decimal MB/s. Multiply by 0.008 to get Gbps.

### Between two hosts

To measure a real link, start the server on one host and connect from another:

```bash
quantum-tunnel bench --serve :9000
quantum-tunnel bench --connect host:9000 --size 10GB --duration 5m --chunk 60KB
```

- The receiver reports the delivered rate, and each side reports CPU per GiB for its own host.
- Add `--plain` on both sides for a plain TCP reference.
- Add `--flows N` on both sides to run N parallel connections. Some clouds cap one flow well below the instance limit (about 5 Gbps on AWS in a default placement), so a single flow can understate the link.
- With only one machine, `scripts/docker-bench.sh` runs the same test between two containers on a bridge network.

### Datagram transport

Add `--datagram` on both sides. It does not combine with `--plain` or `--flows`.

- Record sizes go up to the datagram payload limit (1170 bytes).
- `--batch N` sends N datagrams per `SendBatch` call.
- `--offload` turns on Linux UDP segmentation and receive offload.
- `--rate Mbps` paces the sender to a fixed offered load (default: as fast as possible).
- The receiver reports loss from sequence numbers. UDP has no flow control, so an unpaced sender's loss figure includes the receiver falling behind.

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

Measured handshake CPU time and throughput are in [PERFORMANCE.md](../PERFORMANCE.md).

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

## Inventory Mode

```bash
quantum-tunnel inventory
```

Prints one JSON document describing this build: version, commit, Go version, platform, protocol version, the KEM and cipher suites it can negotiate, FIPS build mode, whether Go's own FIPS mode is on, the self-test result and the module dependencies. Attach it to a deployment record or diff it between releases; `schema_version` changes when a field changes meaning.

It holds no keys, addresses or configuration, and it describes Quantum-Go only, not the network around it. A FIPS build mode of `true` is not a validation claim; see [FIPS](../FIPS.md).

```bash
quantum-tunnel inventory --format cyclonedx
```

Prints the same build as a CycloneDX 1.6 cryptography bill of materials: one `cryptographic-asset` component per algorithm (ML-KEM-1024 and -768, X25519, SHAKE-256, SHA3-256, the two combiners, AES-256-GCM, ChaCha20-Poly1305) and one protocol component whose cipher suites pair each KEM suite with each AEAD this build offers. Every algorithm states `certificationLevel: none`, because a build mode or a validated module underneath does not validate Quantum-Go. A suite an application registered shows up with no algorithm detail. The output is deterministic (no timestamp, no serial number), so it diffs cleanly between releases. The 1.6 output was checked against the published CycloneDX 1.6 JSON schema by hand when it was written; CI checks its structure and enum values, not the schema file.

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
