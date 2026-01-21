# Quantum-Go

**Quantum-Resistant VPN Encryption using Cascaded Hybrid KEM (CH-KEM)**

[![Go Version](https://img.shields.io/badge/Go-1.24+-00ADD8?style=flat&logo=go)](https://go.dev)
[![Go Reference](https://pkg.go.dev/badge/github.com/pzverkov/quantum-go.svg)](https://pkg.go.dev/github.com/pzverkov/quantum-go)
[![Go Report Card](https://goreportcard.com/badge/pzverkov/quantum-go)](https://goreportcard.com/report/github.com/pzverkov/quantum-go) 
[![Go Build](https://github.com/pzverkov/quantum-go/actions/workflows/ci.yml/badge.svg)](https://github.com/pzverkov/quantum-go/actions/workflows/ci.yml)
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
| Forward Secrecy | Ephemeral keys per session (and per rekey) |
| Session Resumption | Secure abbreviated handshake with encrypted tickets |
| FIPS Compliance | Roadmap for FIPS 140-3 |

## v0.0.6 Highlights

- **Connection Pooling**: Reusable tunnel connections with health checking
- **Buffer Pooling**: 75%+ reduction in memory allocations
- **Rate Limiting**: Per-IP connection and handshake rate limiting
- **Observability**: Prometheus metrics, OpenTelemetry tracing, structured logging

## Quick Start

See [Quick Start Guide](docs/usage/QUICKSTART.md) for detailed installation and usage instructions.

```bash
go get github.com/pzverkov/quantum-go
```

## Documentation

| Guide | Description |
|-------|-------------|
| **[Quick Start](docs/usage/QUICKSTART.md)** | Installation and basic usage examples |
| **[Configuration](docs/usage/CONFIGURATION.md)** | Tuning timeouts, rate limiting (v0.0.6), and session resumption |
| **[CLI Reference](docs/usage/CLI.md)** | Using `quantum-vpn` for demos and benchmarking |
| **[Architecture](docs/technical/ARCHITECTURE.md)** | Deep dive into CH-KEM protocol, keys, and security design |
| **[Mathematical Foundation](docs/math/MATHEMATICAL_FOUNDATION.md)** | Formal proofs for MLWE and hybrid safety |
| **[Compliance Roadmap](docs/compliance/FIPS_140_3_ROADMAP.md)** | Path to FIPS 140-3 validation |

## Performance

The library is optimized for high throughput using SIMD/Assembly where available (X25519, SHA3).
See [CLI Reference](docs/usage/CLI.md#benchmark-mode) for running benchmarks on your hardware.

**Verified Results (Apple M1 Pro):**
- **Handshakes:** ~1,800/sec (full)
- **Throughput:** >2.2 GB/s (Session Encrypt), >3.0 GB/s (Raw AES)

## Contributing

We warmly welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for details on:
- Setting up the development environment
- Running the test suite (Unit, Integration, Fuzz)
- Coding standards and PR process

## License

MIT License - see [LICENSE](LICENSE) for details.

## Acknowledgments

- NIST Post-Quantum Cryptography Standardization
- Go Cryptography Team
- CRYSTALS-Kyber Design Team

---

## Global Regulation & Liability (Read Carefully)

**IMPORTANT: By using, cloning, or forking this repository, you acknowledge and agree to the following terms:**

### 1. Responsibility of Use
Quantum-Go is a high-assurance cryptographic tool. **You (the User)** assume full responsibility for complying with all applicable local, national, and international laws where you install, deploy, or transport this software. The developers of Quantum-Go disclaim all liability for:
- Use of this software to bypass telecommunications regulations (e.g., VoIP blocking, VPN bans).
- Deployment in jurisdictions where strong encryption is restricted (e.g., China, Russia, UAE, Saudi Arabia).
- Failure to obtain necessary export/import licenses or file declarations (e.g., US BIS, EU Dual-Use, French ANSSI).

### 2. Agency & Enterprise Compliance
Government agencies and corporate entities must verify:
- **Export Control:** This software involves Class 5 (5D002) dual-use technology. Access by foreign nationals may constitute a "deemed export."
- **FIPS Validation:** While this library implements FIPS 203 parameters, it is **NOT** currently FIPS 140-3 validated. Federal agencies requiring FIPS validation for production data must treat this as "research grade."
- **Data Sovereignty:** Users are responsible for ensuring packet data handling complies with GDPR, CCPA, and regional data residency laws (e.g., Saudi ECC-1).

### 3. No Warranty
THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

---

**Regulatory Warning:** Quantum-Go must not be used to bypass telecommunications regulations. Users are solely responsible for ensuring compliance with all local laws and regulations.
