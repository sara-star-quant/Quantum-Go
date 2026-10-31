# Quantum-Go

**Quantum-Resistant Tunnel Encryption using Cascaded Hybrid KEM (CH-KEM)**

[![Go Version](https://img.shields.io/badge/Go-1.26+-00ADD8?style=flat&logo=go)](https://go.dev)
[![Go Reference](https://pkg.go.dev/badge/github.com/sara-star-quant/quantum-go.svg)](https://pkg.go.dev/github.com/sara-star-quant/quantum-go)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/sara-star-quant/Quantum-Go/badge)](https://scorecard.dev/viewer/?uri=github.com/sara-star-quant/Quantum-Go)
[![Go Build](https://github.com/sara-star-quant/quantum-go/actions/workflows/ci.yml/badge.svg)](https://github.com/sara-star-quant/quantum-go/actions/workflows/ci.yml)
[![Security Level](https://img.shields.io/badge/Security-NIST%20Category%205-green)](https://csrc.nist.gov/projects/post-quantum-cryptography)
[![FIPS Mode](https://img.shields.io/badge/FIPS%20140--3-Ready-orange)](docs/FIPS.md)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue)](LICENSE)

---


## Overview

Quantum-Go is a research-grade (pre-1.0) tunnel **encryption library** for Go. It encrypts and authenticates bytes over a `net.Conn` or a UDP socket using a **Cascaded Hybrid KEM (CH-KEM)** that combines:

- **ML-KEM-1024** (NIST FIPS 203): post-quantum lattice-based key encapsulation
- **X25519** (RFC 7748): classical elliptic-curve Diffie-Hellman
- **SHAKE-256** (NIST FIPS 202): key derivation

The session is secure if either algorithm is. It is a library, not a VPN client: see [Scope](docs/SCOPE.md) for what it does and does not do.

## Highlights

- **One round trip to a keyed client.** The 6.0 handshake lets the client send data after 1 RTT, on both the stream and datagram transports (about 21 ms on a 20 ms link).
- **Two transports.** TCP/stream, and a connectionless UDP/datagram transport with fragmented handshake, retransmission, reliable rekey, anti-DoS cookies and authenticated roaming.
- **Fast data plane.** About 690 MB/s on one stream tunnel. Datagrams reach 528 to 701 MB/s per flow on Linux with batching and UDP offload.
- **Endpoint authentication, opt-in.** Static-key server pinning, and per-client pre-shared keys for mutual authentication.
- **Pluggable KEM suites.** CH-KEM-v1 by default, or X-Wing (ML-KEM-768 plus X25519) for smaller handshakes.
- **Verified and hardened.** ProVerif models of secrecy, hybrid security, forward secrecy and authentication; fuzzing; FIPS 140-3 build mode; release workflow with cosign signatures and build-provenance attestation.

## Quick start

```bash
go get github.com/sara-star-quant/quantum-go
```

Stream (TCP):

```go
import "github.com/sara-star-quant/quantum-go/pkg/tunnel"

// Server
ln, _ := tunnel.Listen("tcp", ":8443")
conn, _ := ln.Accept()
msg, _ := conn.Receive()

// Client
c, _ := tunnel.Dial("tcp", "server:8443")
_ = c.Send([]byte("hello"))
```

Datagram (UDP), with batching and Linux UDP offload:

```go
// Server
ep, _ := tunnel.ListenDatagram("udp", ":51820", tunnel.WithDatagramOffload())
go ep.Serve()
conn, _ := ep.Accept()
pkt, _ := conn.Recv()

// Client
cep, _ := tunnel.ListenDatagram("udp", ":0", tunnel.WithDatagramOffload())
go cep.Serve()
c, _ := tunnel.DialDatagram(cep, serverAddr)
_ = c.SendBatch([][]byte{p1, p2, p3})
```

FIPS mode: `go build -tags fips ./...`. More in the [Quick Start guide](docs/usage/QUICKSTART.md).

## Performance

Measured on CI runners and a laptop; full tables, methodology and reproduction steps are in [docs/PERFORMANCE.md](docs/PERFORMANCE.md).

| Metric | Result |
|--------|--------|
| Client can send data after | 1 RTT (stream and datagram), under 1 ms of crypto |
| Handshake CPU, both sides | 340 to 610 µs (Linux, macOS, Windows runners); static-key auth adds about 35 to 50% |
| Stream throughput, single tunnel | about 690 MB/s (5.5 Gb/s) |
| Datagram goodput, single flow, Linux | 196 / 304 MB/s per datagram (x86 / arm64), 701 / 528 MB/s with `SendBatch` and offload |
| AES-256-GCM, raw, one core | about 2.5 GB/s |
| Wire cost | 29 B per stream record; about 1.7 KB handshake flight (ML-KEM-1024) |

## Security properties

| Property | Status |
|----------|--------|
| Post-quantum security | ML-KEM-1024 (NIST Category 5) |
| Classical security | X25519 (128-bit) |
| Hybrid guarantee | Secure if either algorithm is secure |
| Endpoint authentication | Opt-in: static-key server pinning, require-auth, per-client PSK mutual auth |
| Forward secrecy | Ephemeral keys per session and per rekey |
| Session resumption | Encrypted tickets with an abbreviated handshake |
| FIPS 140-3 | Build mode with POST and CST self-tests ([docs](docs/FIPS.md)); not a validated module |

## Documentation

| Guide | Description |
|-------|-------------|
| [Quick Start](docs/usage/QUICKSTART.md) | Installation and basic usage |
| [Configuration](docs/usage/CONFIGURATION.md) | Timeouts, rate limiting, sessions, authentication |
| [CLI reference](docs/usage/CLI.md) | `quantum-tunnel` demos, key generation and benchmarks |
| [Performance](docs/PERFORMANCE.md) | Measured latency, handshake cost and throughput |
| [Datagram transport](docs/datagram-transport.md) and [DoS defences](docs/datagram-dos.md) | UDP transport design and limits |
| [Architecture](docs/technical/ARCHITECTURE.md) | CH-KEM protocol and security design |
| [Protocol specification](docs/PROTOCOL.md) | Wire handshake, KEM negotiation, key schedule |
| [Formal verification](docs/formal/README.md) | Machine-checked ProVerif proofs |
| [Threat model](docs/technical/THREAT_MODEL.md) | Threat and risk analysis (NIST SP 800-30) |
| [FIPS compliance](docs/FIPS.md) | FIPS 140-3 build mode and self-tests |
| [Scope](docs/SCOPE.md) | What the library does and does not do |
| [Audit readiness](docs/compliance/AUDIT_READINESS.md) | Crypto inventory, claims-to-evidence map, supply chain |
| [Roadmap](docs/ROADMAP.md) | Development roadmap and compliance plans |
| [Changelog](CHANGELOG.md) | Release history |

## Contributing

Contributions are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for the development setup, test suite (unit, integration, fuzz), DCO sign-off and PR process. Report vulnerabilities privately, as described in [SECURITY.md](SECURITY.md).

## License

Apache License 2.0. See [LICENSE](LICENSE), [NOTICE](NOTICE) and [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md). Apache 2.0 includes an express patent grant, relevant in the patent-heavy post-quantum space.

## Compliance and liability

This software implements ECCN 5D002 dual-use cryptography, is not a FIPS 140-3 validated module, and is provided "as is" without warranty. Export, import and jurisdiction rules are your responsibility, and nothing here is legal advice. Read the full [compliance and liability notice](docs/compliance/COMPLIANCE_NOTICE.md) before using or redistributing it.
