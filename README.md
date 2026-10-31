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


**Post-quantum encryption for your Go network code. Keyed in one round trip. Familiar `Dial` and `Listen`.**

Traffic an attacker records today can be decrypted later by a quantum computer. Quantum-Go closes that gap now: a **hybrid ML-KEM-1024 + X25519** handshake, so an attacker has to break both algorithms to read a session. You keep your protocol and your sockets; the library encrypts and authenticates the bytes.

## What you get

- **Speed to first byte.** The client sends data after **1 round trip** on both transports: 21 ms on a 20 ms link, 101 ms on a 100 ms link. The handshake costs 340 to 610 µs of CPU for both sides.
- **Throughput.** About **690 MB/s** on a single stream tunnel. On Linux, batched datagram sends with UDP offload reach **701 MB/s** (x86-64) and **528 MB/s** (arm64) per flow, up to 3.6 times a plain send.
- **Top-tier post-quantum security.** ML-KEM-1024 is NIST security level 5. Prefer smaller handshakes? Switch to the X-Wing suite (ML-KEM-768 + X25519).
- **Two transports, one API.** TCP, and a connectionless UDP transport with retransmission, reliable rekey, anti-DoS cookies and roaming across IP changes.
- **Authentication you control.** Pin your server's key, or issue each client its own pre-shared key. A client with no key looks the same as one with a wrong key.
- **Proof, not promises.** Machine-checked ProVerif models, published conformance vectors, fuzzed parsers, a written wire specification, and releases signed with cosign and attested.
- **A licence you can ship.** Apache-2.0 with an express patent grant, a licence scan on every release, and full third-party notices.

How it stacks up against WireGuard, Rosenpass, IKEv2 and hybrid TLS, including where it loses: [docs/COMPARISON.md](docs/COMPARISON.md).

## Who it is for

- You build a Go service, agent, relay or edge component and want quantum-resistant transport **without running a VPN daemon, a kernel module or root**.
- You need an auditable protocol: a spec, proofs and test vectors you can hand to a reviewer.

## Who it is not for

- You want a VPN client with a TUN device, routing, DNS handling and a kill-switch. This is a library; see [Scope](docs/SCOPE.md).
- You need a FIPS 140-3 *validated* module today. The library ships a FIPS build mode with self-tests, but it is not validated.

## The honest part

Quantum-Go is **pre-1.0 and research-grade**, and it has **not had a third-party audit**. Its handshake is about ten times larger than WireGuard's because ML-KEM-1024 is large. That is the price of security level 5, and the reason the smaller X-Wing suite exists.

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
| Session resumption | Experimental low-level ticket API; not used by `Dial` or `Listen` ([details](docs/usage/CONFIGURATION.md#session-resumption)) |
| FIPS 140-3 | Build mode with POST and CST self-tests ([docs](docs/FIPS.md)); not a validated module |

## Documentation

| Guide | Description |
|-------|-------------|
| [Quick Start](docs/usage/QUICKSTART.md) | Installation and basic usage |
| [Configuration](docs/usage/CONFIGURATION.md) | Timeouts, rate limiting, sessions, authentication |
| [CLI reference](docs/usage/CLI.md) | `quantum-tunnel` demos, key generation and benchmarks |
| [Performance](docs/PERFORMANCE.md) | Measured latency, handshake cost and throughput |
| [Comparison](docs/COMPARISON.md) | Quantum-Go next to WireGuard, Rosenpass, IKEv2 and hybrid TLS |
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
