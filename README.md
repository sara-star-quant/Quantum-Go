# Quantum-Go

**Quantum-Resistant VPN Encryption using Cascaded Hybrid KEM (CH-KEM)**

[![Go Version](https://img.shields.io/badge/Go-1.24+-00ADD8?style=flat&logo=go)](https://go.dev)
[![Go Reference](https://pkg.go.dev/badge/github.com/pzverkov/quantum-go.svg)](https://pkg.go.dev/github.com/pzverkov/quantum-go)
[![Go Report Card](https://goreportcard.com/badge/pzverkov/quantum-go)](https://goreportcard.com/report/github.com/pzverkov/quantum-go)
[![Go Build](https://github.com/pzverkov/quantum-go/actions/workflows/ci.yml/badge.svg)](https://github.com/pzverkov/quantum-go/actions/workflows/ci.yml)
[![Security Level](https://img.shields.io/badge/Security-NIST%20Category%205-green)](https://csrc.nist.gov/projects/post-quantum-cryptography)
[![FIPS Mode](https://img.shields.io/badge/FIPS%20140--3-Ready-orange)](docs/FIPS.md)
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
| Forward Secrecy | Ephemeral keys per session (and per rekey) |
| Session Resumption | Encrypted tickets with secure abbreviated handshake |
| FIPS 140-3 | Build mode with POST/CST self-tests ([docs](docs/FIPS.md)) |

## Features

### Core Cryptography
- Hybrid CH-KEM key exchange (ML-KEM-1024 + X25519)
- AES-256-GCM and ChaCha20-Poly1305 cipher suites
- Automatic session rekeying with replay protection

### FIPS 140-3 Compliance
- **FIPS build mode** via `-tags fips` (AES-GCM only)
- **Power-On Self-Tests (POST)** - KAT verification at module load
- **Conditional Self-Tests (CST)** - Pairwise consistency and RNG health checks
- Runtime compliance verification with `crypto.FIPSMode()`

### Production Hardening
- Connection pooling with health checking
- Buffer pooling (75%+ allocation reduction)
- Per-IP rate limiting and DoS protection
- Prometheus metrics and OpenTelemetry tracing

## Quick Start

```bash
go get github.com/pzverkov/quantum-go
```

```go
import "github.com/pzverkov/quantum-go/pkg/tunnel"

// Server
listener, _ := tunnel.Listen("tcp", ":8443", nil)
conn, _ := listener.Accept()

// Client
conn, _ := tunnel.Dial("tcp", "server:8443", nil)
```

For FIPS mode, build with:
```bash
go build -tags fips ./...
```

See [Quick Start Guide](docs/usage/QUICKSTART.md) for detailed examples.

## Documentation

| Guide | Description |
|-------|-------------|
| [Quick Start](docs/usage/QUICKSTART.md) | Installation and basic usage |
| [FIPS Compliance](docs/FIPS.md) | FIPS 140-3 build mode and self-tests |
| [Configuration](docs/usage/CONFIGURATION.md) | Tuning timeouts, rate limiting, and sessions |
| [CLI Reference](docs/usage/CLI.md) | Using `quantum-vpn` for demos and benchmarks |
| [Architecture](docs/technical/ARCHITECTURE.md) | CH-KEM protocol and security design |
| [Roadmap](docs/ROADMAP.md) | Development roadmap and compliance plans |

## Performance

Optimized with SIMD/Assembly (AES-NI, AVX2/AVX-512, hardware SHA3).

| Platform | Handshakes/sec | Throughput (AES-GCM) |
|----------|----------------|----------------------|
| Apple Silicon (M-series) | ~2,200 | ~4 GB/s |
| Cloud instance (c6i.xlarge) | 1,800-2,500 | 3-5 GB/s |
| Mid-range server (Xeon Silver) | 2,500-3,500 | 4-7 GB/s |
| Enterprise (Xeon Platinum / EPYC) | 3,500-5,000 | 8-12 GB/s |

Run `quantum-vpn benchmark` on your target hardware. See [CLI Reference](docs/usage/CLI.md#benchmark-mode).

## Contributing

Contributions welcome! See [CONTRIBUTING.md](CONTRIBUTING.md) for:
- Development setup
- Test suite (unit, integration, fuzz)
- PR process

## License

MIT License - see [LICENSE](LICENSE).

---

## Compliance & Liability

**IMPORTANT: By using, cloning, or forking this repository, you acknowledge and agree to the following:**

### Export Controls
This software implements ECCN 5D002 dual-use cryptographic technology. Users are solely responsible for compliance with:
- **US**: Export Administration Regulations (EAR). Access by foreign nationals may constitute a "deemed export."
- **EU**: Dual-Use Regulation (EU 2021/821). Open-source exemptions may apply.
- **Other**: Local import/export regulations (e.g., French ANSSI declaration, UK SPIRE licensing).

### FIPS Validation Status
This library implements FIPS 203/202 parameters with Power-On and Conditional Self-Tests. However, it is **NOT** a FIPS 140-3 validated cryptographic module. Federal agencies and regulated industries requiring FIPS validation must treat this as research-grade software.

### Jurisdiction Restrictions
Strong encryption is restricted or regulated in certain jurisdictions (e.g., China, Russia, UAE, Saudi Arabia). This software **must not** be used to bypass telecommunications regulations. Users deploying in restricted regions assume full responsibility for legal compliance.

### No Warranty
THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY ARISING FROM THE USE OF THIS SOFTWARE.

See [ROADMAP.md](docs/ROADMAP.md#global-compliance--regulatory-considerations) for detailed regulatory guidance covering 15+ jurisdictions.
