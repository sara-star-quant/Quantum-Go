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
