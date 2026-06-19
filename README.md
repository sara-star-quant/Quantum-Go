# Quantum-Go

**Quantum-Resistant Tunnel Encryption using Cascaded Hybrid KEM (CH-KEM)**

[![Go Version](https://img.shields.io/badge/Go-1.26+-00ADD8?style=flat&logo=go)](https://go.dev)
[![Go Reference](https://pkg.go.dev/badge/github.com/sara-star-quant/quantum-go.svg)](https://pkg.go.dev/github.com/sara-star-quant/quantum-go)
[![Go Report Card](https://goreportcard.com/badge/pzverkov/quantum-go)](https://goreportcard.com/report/github.com/sara-star-quant/quantum-go)
[![Go Build](https://github.com/sara-star-quant/quantum-go/actions/workflows/ci.yml/badge.svg)](https://github.com/sara-star-quant/quantum-go/actions/workflows/ci.yml)
[![Security Level](https://img.shields.io/badge/Security-NIST%20Category%205-green)](https://csrc.nist.gov/projects/post-quantum-cryptography)
[![FIPS Mode](https://img.shields.io/badge/FIPS%20140--3-Ready-orange)](docs/FIPS.md)
[![License](https://img.shields.io/badge/License-MIT-blue)](LICENSE)

---

## Overview

Quantum-Go is a research-grade (pre-1.0), quantum-resistant tunnel encryption library implementing a novel **Cascaded Hybrid Key Encapsulation Mechanism (CH-KEM)**. It provides defense-in-depth security by combining:

- **ML-KEM-1024** (NIST FIPS 203) - Post-quantum lattice-based cryptography
- **X25519** (RFC 7748) - Classical elliptic curve Diffie-Hellman
- **SHAKE-256** (NIST FIPS 202) - Cryptographic key derivation

## Security Properties

| Property | Status |
|----------|--------|
| Post-Quantum Security | ML-KEM-1024 (NIST Category 5) |
| Classical Security | X25519 (128-bit) |
| Hybrid Guarantee | Secure if EITHER algorithm is secure |
| Endpoint Authentication | Opt-in: static-key server pinning, server require-auth, and PSK mutual auth (off by default) |
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

## Scope

Quantum-Go is a tunnel **encryption library**, not a VPN client. It encrypts and
authenticates bytes over a `net.Conn` or UDP socket. It does not configure, capture, or
route operating-system network traffic.

**What the library gives you (connection continuity):**

- **Authenticated roaming** - a datagram session can survive the peer's IP or port
  changing (NAT rebind, Wi-Fi to cellular): it demuxes by a random connection index, not
  source address, and rebinds only after an AEAD-authenticated packet.
- **Reliable handshake** - the post-quantum handshake retransmits lost flights with
  backoff over a lossy UDP path.
- **Rekey, resumption, and idle reaping** for long-lived sessions.

**What the library does NOT do (the integrating application's responsibility):**

- **Reconnect after a full disconnect** - the library has no auto-redial loop;
  re-establishing with `Dial` / `DialDatagram` is the caller's responsibility.
- **DNS leak prevention** - the library does not control the operating-system resolver.
- **Kill-switch** - the library does not block non-tunnel traffic when the tunnel is down.
- **TUN device and system routing** - the library does not capture or route host traffic
  into the tunnel.

These properties belong to a VPN client built around the library, not to the library
itself. This text describes the software, not security or legal advice; Quantum-Go ships
under the MIT License, "as is" and without warranty (see [LICENSE](LICENSE) and the
Compliance & Liability section below).

## Quick Start

```bash
go get github.com/sara-star-quant/quantum-go
```

```go
import "github.com/sara-star-quant/quantum-go/pkg/tunnel"

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
| [CLI Reference](docs/usage/CLI.md) | Using `quantum-tunnel` for demos and benchmarks |
| [Architecture](docs/technical/ARCHITECTURE.md) | CH-KEM protocol and security design |
| [Threat Model](docs/technical/THREAT_MODEL.md) | Self-authored threat and risk analysis (NIST SP 800-30) |
| [Roadmap](docs/ROADMAP.md) | Development roadmap and compliance plans |

## Performance

Hardware-accelerated where available (ARMv8 Crypto Extensions on Apple Silicon;
AES-NI / AVX2 / hardware SHA-3 on x86-64). Go 1.26.3 (Green Tea GC).

Two transports share the crypto core: a **TCP/stream** transport (length-prefixed
framing) and a connectionless **UDP/datagram** transport (separate wire format, no
interop). The datagram path is complete end to end: fragmented PQ handshake with
retransmission, an encrypted zero-alloc data plane, reliable rekey, a load-gated
stateless anti-amplification cookie, authenticated roaming, batched `recvmmsg`
receive on Linux, and optional fixed-size handshake padding.

**Measured (Apple M1 Pro, Go 1.26.3, loopback):**

| Metric | Result |
|--------|--------|
| AES-256-GCM cipher (raw AEAD, single core) | ~2.5 GB/s |
| ChaCha20-Poly1305 cipher (raw AEAD) | ~0.7 GB/s |
| Handshakes/sec (stream/TCP, full CH-KEM, sequential) | ~1,450 (~670 µs each) |
| Handshakes/sec (datagram/UDP, full CH-KEM, sequential) | ~1,300 (~760 µs each) |
| Endpoint auth handshake cost (opt-in) | static-key ~+40% (one extra CH-KEM leg); PSK negligible (one KDF fold); data plane unaffected |
| Stream per-record overhead | 16 B AEAD (tag only; nonce derived, not transmitted, was 28) + 13 B frame header (type, length, seq) = 29 B total (was 41) |
| Single-tunnel throughput (stream/TCP, AES-GCM, end-to-end) | ~690 MB/s (5.5 Gb/s), sustained across rekeys |
| Datagram send (seal + frame, isolated, zero-alloc steady state) | ~3.0 GB/s (~380 ns/op, 1 alloc/op) |
| Datagram goodput (UDP, one-way single flow, full receive loop) | ~58 MB/s on macOS loopback; ~1.8 Gb/s on Linux (see below) |

The datagram data path is **syscall-bound, not crypto-bound**: the isolated send
path is ~3 GB/s, so per-datagram throughput is set by the send + receive syscalls,
not the AEAD. macOS loopback has a slow per-datagram socket path, so the single-flow
goodput there (~58 MB/s) is a loopback artifact, not a transport limit. On Linux the
same single flow delivers far more:

**Measured (Linux, Go 1.26, single flow, container arm64 - indicative, a VM depresses
absolutes):**

| Metric | Result |
|--------|--------|
| Datagram goodput (UDP, one-way single flow, delivered) | ~280 MB/s (~2.2 Gb/s) |
| Datagram aggregate goodput (single receive goroutine, 1-8 flows) | peaks ~365 MB/s near 4 flows, then plateaus |
| Datagram aggregate goodput (`SO_REUSEPORT`, 8 flows, 1->8 sockets) | ~355 -> ~565 MB/s (~1.6x across 8 cores) |
| Datagram send (isolated, zero-alloc steady state) | ~1.2 GB/s |
| Datagram receive, `recvmmsg` batch vs one syscall per datagram | ~1030 vs ~975 MB/s |

The end-to-end goodput is delivered throughput (the benchmark flow-controls the
sender so dropped datagrams are never counted), the full path: seal, send, kernel,
receive loop, demux, AEAD open, delivery. A single receive goroutine demuxing and
AEAD-opening every datagram is the per-endpoint ceiling (~365 MB/s aggregate on this
8-core VM); `ListenDatagram` spreads that work across cores with `SO_REUSEPORT`,
lifting aggregate goodput ~1.6x (to ~565 MB/s here) and scaling further on a
many-core host. A CPU profile of the delivered path is ~35% AES (already
hardware-accelerated), ~30% syscalls, the rest framing/alloc/bookkeeping. The
~2.5 GB/s aggregate mark is a cores-in-parallel target (AES-GCM is ~2.5 GB/s/core):
reaching it takes more cores than this VM plus fewer syscalls per datagram, which
`UDP_SEGMENT`/`UDP_GRO` offload (on the [roadmap](docs/ROADMAP.md)) provides. Optional handshake
padding (`WithHandshakePadding`) trades roughly +42% handshake bandwidth (a
ClientHello flight grows from ~1700 to 2400 bytes) for uniform-size,
fingerprint-resistant handshake datagrams; it never touches the data plane.

**Estimated on other hardware** (extrapolated from cipher throughput; not yet
independently measured; run the benchmark to verify):

| Platform | AES-256-GCM cipher (raw) |
|----------|--------------------------|
| Cloud instance (c6i.xlarge) | 3-5 GB/s |
| Mid-range server (Xeon Silver) | 4-7 GB/s |
| Enterprise (Xeon Platinum / EPYC) | 8-12 GB/s |

Run `quantum-tunnel bench --handshakes N --datagram-handshakes N --throughput` on your target hardware. See [CLI Reference](docs/usage/CLI.md#benchmark-mode).

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

### No Legal Advice
Nothing in this repository - including documentation, compliance references, FIPS implementation details, and regulatory guidance - constitutes legal, regulatory, or compliance advice. Users should consult qualified legal counsel for guidance on applicable laws and regulations in their jurisdiction.

### User Responsibility
By using, cloning, forking, or incorporating this software, you acknowledge that you are solely responsible for determining its legality in your jurisdiction and for compliance with all applicable laws, regulations, and standards. The authors and copyright holders bear no responsibility for how this software is used or deployed.

See [ROADMAP.md](docs/ROADMAP.md#global-compliance--regulatory-considerations) for regulatory references covering 15+ jurisdictions.
