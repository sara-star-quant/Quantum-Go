# Quantum-Go

**Quantum-Resistant VPN Encryption using Cascaded Hybrid KEM (CH-KEM)**

[![Go Version](https://img.shields.io/badge/Go-1.24+-00ADD8?style=flat&logo=go)](https://go.dev)
[![Go Reference](https://pkg.go.dev/badge/github.com/pzverkov/quantum-go.svg)](https://pkg.go.dev/github.com/pzverkov/quantum-go)
[![Security Level](https://img.shields.io/badge/Security-NIST%20Category%205-green)](https://csrc.nist.gov/projects/post-quantum-cryptography)
[![License](https://img.shields.io/badge/License-MIT-blue)](LICENSE)

---

## Overview

Quantum-Go is a production-ready, quantum-resistant VPN encryption library implementing a novel **Cascaded Hybrid Key Encapsulation Mechanism (CH-KEM)**. It provides defense-in-depth security by combining:

- **ML-KEM-1024** (NIST FIPS 203) - Post-quantum lattice-based cryptography
- **X25519** (RFC 7748) - Classical elliptic curve Diffie-Hellman
- **SHAKE-256** (NIST FIPS 202) - Cryptographic key derivation

## Security Properties

| Property | Status |
|----------|--------|
| Post-Quantum Security | ML-KEM-1024 (NIST Category 5) |
| Classical Security | X25519 (128-bit) |
| Hybrid Guarantee | Secure if EITHER algorithm is secure |
| Forward Secrecy | Ephemeral keys per session |
| FIPS Compliance | Roadmap for FIPS 140-3 |

## Quick Start

### Installation

```bash
go get github.com/pzverkov/quantum-go
```

**Requirements:** Go 1.24 or later

### Basic Usage

```go
package main

import (
    "fmt"
    "github.com/pzverkov/quantum-go/pkg/tunnel"
)

func main() {
    // Server
    listener, _ := tunnel.Listen("tcp", ":8443")
    defer listener.Close()

    go func() {
        for {
            conn, _ := listener.Accept()
            go func(t *tunnel.Tunnel) {
                defer t.Close()
                data, _ := t.Receive()
                fmt.Printf("Received: %s\n", data)
            }(conn)
        }
    }()

    // Client
    client, _ := tunnel.Dial("tcp", "localhost:8443")
    defer client.Close()

    client.Send([]byte("Hello, quantum-resistant world!"))
}
```

### Low-Level CH-KEM API

```go
package main

import (
    "fmt"
    "github.com/pzverkov/quantum-go/pkg/chkem"
)

func main() {
    // Generate key pair (recipient)
    keyPair, _ := chkem.GenerateKeyPair()

    // Encapsulate (sender)
    ciphertext, sharedSecretSender, _ := chkem.Encapsulate(keyPair.PublicKey())

    // Decapsulate (recipient)
    sharedSecretRecipient, _ := chkem.Decapsulate(ciphertext, keyPair)

    // Both now have the same 32-byte shared secret
    fmt.Printf("Secrets match: %v\n",
        bytes.Equal(sharedSecretSender, sharedSecretRecipient))
}
```

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Application Layer                        │
├─────────────────────────────────────────────────────────────┤
│  pkg/tunnel/                                                │
│  ├── Dial()        - Connect as client                     │
│  ├── Listen()      - Accept connections                    │
│  ├── Send()        - Encrypted transmission                │
│  └── Receive()     - Encrypted reception                   │
├─────────────────────────────────────────────────────────────┤
│  pkg/chkem/                                                 │
│  ├── GenerateKeyPair()  - CH-KEM key generation           │
│  ├── Encapsulate()      - Create shared secret            │
│  └── Decapsulate()      - Recover shared secret           │
├─────────────────────────────────────────────────────────────┤
│  pkg/crypto/                                                │
│  ├── ML-KEM-1024       - Post-quantum KEM                 │
│  ├── X25519            - Classical ECDH                   │
│  ├── SHAKE-256         - Key derivation                   │
│  └── AES-256-GCM       - Authenticated encryption         │
└─────────────────────────────────────────────────────────────┘
```

## Protocol Overview

```
Initiator                              Responder
    │                                      │
    │───────── ClientHello ───────────────>│
    │  • CH-KEM public key (1600 bytes)    │
    │  • Supported cipher suites           │
    │                                      │
    │<──────── ServerHello ────────────────│
    │  • CH-KEM ciphertext (1600 bytes)    │
    │  • Selected cipher suite             │
    │                                      │
    │  [Both derive shared secret K]       │
    │                                      │
    │═══════ Encrypted Tunnel ═════════════│
```

## Performance

Typical benchmarks on modern hardware (Intel i7, Go 1.24+):

| Operation | Time | Throughput |
|-----------|------|------------|
| CH-KEM Key Generation | ~1.5ms | 666 ops/s |
| CH-KEM Encapsulation | ~0.8ms | 1,250 ops/s |
| CH-KEM Decapsulation | ~0.7ms | 1,428 ops/s |
| Full Handshake | ~5ms | 200 handshakes/s |
| AES-256-GCM (1400B) | ~1μs | 1.3 GB/s |

Run benchmarks:

```bash
go test -bench=. -benchmem ./test/benchmark/
```

## Command-Line Tool

The `quantum-vpn` tool provides interactive demos and benchmarking:

### Installation

```bash
go install github.com/pzverkov/quantum-go/cmd/quantum-vpn@latest
```

Or build from source:

```bash
git clone https://github.com/pzverkov/quantum-go
cd quantum-go
go build -o quantum-vpn ./cmd/quantum-vpn/
```

### Demo Mode

Run an interactive client/server demo:

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

### Benchmark Mode

Performance testing:

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

Expected performance on modern hardware:
- **Handshakes**: 600-800/sec (~1.5ms each)
- **Throughput**: 200-500 MB/s (hardware dependent)

### Example Mode

View interactive code examples:

```bash
quantum-vpn example
```

Shows examples for:
- Basic client/server setup
- Low-level CH-KEM API
- Custom configuration
- Session management
- Error handling
- Security best practices

## Testing

```bash
# Unit tests
go test ./... -v

# Integration tests
go test ./test/integration -v

# Benchmarks
go test ./test/benchmark -bench=. -benchmem

# Race detection
go test ./... -race
```

## Documentation

| Document | Description |
|----------|-------------|
| [Mathematical Foundation](docs/math/MATHEMATICAL_FOUNDATION.md) | MLWE, CH-KEM proofs |
| [Technical Architecture](docs/technical/ARCHITECTURE.md) | System design, API |
| [FIPS 140-3 Roadmap](docs/compliance/FIPS_140_3_ROADMAP.md) | Compliance path |
| [Risk Assessment](docs/compliance/RISK_ASSESSMENT.md) | Security analysis |

## Key Sizes

| Component | Size |
|-----------|------|
| CH-KEM Public Key | 1,600 bytes |
| CH-KEM Ciphertext | 1,600 bytes |
| Shared Secret | 32 bytes |
| Session Overhead | ~3.2 KB per handshake |

## Cipher Suites

| Suite | Status | Use Case |
|-------|--------|----------|
| AES-256-GCM | Default | FIPS environments |
| ChaCha20-Poly1305 | Supported | Non-AES-NI systems |

## Security Considerations

1. **Key Storage:** Use HSM for long-term keys in production
2. **Key Rotation:** Rotate session keys based on time/data limits
3. **Side Channels:** Uses Go standard library (audited by Trail of Bits)
4. **Memory:** Sensitive keys are zeroized after use

## Compliance

- **NIST FIPS 203:** ML-KEM-1024 compliant
- **NIST FIPS 202:** SHAKE-256 compliant
- **FIPS 140-3:** Roadmap documented for validation
- **NSA CNSA 2.0:** Aligned with post-quantum transition guidelines

## Contributing

Contributions are welcome! Please read our contributing guidelines and submit pull requests.

## License

MIT License - see [LICENSE](LICENSE) for details.

## Acknowledgments

- NIST Post-Quantum Cryptography Standardization
- Go Cryptography Team
- CRYSTALS-Kyber Design Team

---

**Disclaimer:** This software is provided for educational and research purposes. For production use in high-security environments, conduct independent security audits and consider FIPS validation requirements.
