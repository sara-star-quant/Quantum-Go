# Quantum-Go

**Quantum-Resistant Tunnel Encryption using Cascaded Hybrid KEM (CH-KEM)**

[![Go Version](https://img.shields.io/badge/Go-1.26+-00ADD8?style=flat&logo=go)](https://go.dev)
[![Go Reference](https://pkg.go.dev/badge/github.com/sara-star-quant/quantum-go.svg)](https://pkg.go.dev/github.com/sara-star-quant/quantum-go)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/sara-star-quant/Quantum-Go/badge)](https://scorecard.dev/viewer/?uri=github.com/sara-star-quant/Quantum-Go)
[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/16700/badge)](https://www.bestpractices.dev/projects/16700)
[![Codecov](https://codecov.io/gh/sara-star-quant/Quantum-Go/branch/main/graph/badge.svg)](https://codecov.io/gh/sara-star-quant/Quantum-Go)
[![Go Build](https://github.com/sara-star-quant/quantum-go/actions/workflows/ci.yml/badge.svg)](https://github.com/sara-star-quant/quantum-go/actions/workflows/ci.yml)
[![Fuzz](https://github.com/sara-star-quant/quantum-go/actions/workflows/fuzz.yml/badge.svg)](https://github.com/sara-star-quant/quantum-go/actions/workflows/fuzz.yml)
[![KEM parameter set](https://img.shields.io/badge/KEM-ML--KEM--1024%20(NIST%20Category%205)-green)](https://csrc.nist.gov/projects/post-quantum-cryptography)
[![FIPS build mode](https://img.shields.io/badge/FIPS%20build%20mode-not%20validated-orange)](docs/FIPS.md)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue)](LICENSE)

**Post-quantum encryption for your Go network code. Keyed in one round trip. Familiar `Dial` and `Listen`.**

An attacker can record traffic today and decrypt it later with a quantum computer. Quantum-Go reduces that exposure for the traffic its tunnel protects. Its **hybrid ML-KEM-1024 + X25519** handshake is designed so that an attacker has to break both algorithms to read a session. A symbolic model checks this; the computational proof for the default combiner is open (see [SECURITY.md](SECURITY.md)). You keep your protocol and your sockets, and the library encrypts and authenticates the bytes.

## Status

- **Pre-1.0 and research-grade.** No third-party audit yet.
- **Not a validated FIPS 140-3 module.** A FIPS build mode with self-tests ships.
- **Large handshake.** About ten times the size of WireGuard's, because ML-KEM-1024 keys and ciphertexts are large. The X-Wing suite is the smaller option, at a lower security level.
- **Reviewable core.** The core is about 9,000 lines of Go outside tests, blank lines and comments (chkem, crypto, protocol, tunnel, internal), small enough for one reviewer to read end to end. `scripts/loc.sh` checks the figure in CI.

## Features

- **One round trip.** The client sends data after 1 RTT on both transports.
- **Two transports.** TCP, plus a UDP transport with retransmission, reliable rekey, anti-DoS cookies and roaming across IP changes.
- **Authentication by default.** Pin the server's key or give each client its own pre-shared key. Unauthenticated use needs an explicit opt-out. A client with no key looks the same as one with a wrong key.
- **Choice of KEM suite.** The default uses ML-KEM-1024 (NIST security level 5) with X25519. Set `KEMSuite` to X-Wing (ML-KEM-768 + X25519) for smaller handshakes, or register your own suite.
- **Batched sends.** `SendBatch` speeds up bursts of small stream records on macOS, Windows and x86-64 Linux, and datagrams on Linux with UDP offload.
- **Checkable evidence.** ProVerif models in CI (symbolic, so their results are statements about the model), conformance vectors, fuzzed parsers, a wire specification, and releases signed with cosign and attested.
- **Apache-2.0.** Includes an express patent grant. Each release gets a license scan and ships full third-party notices.

## Performance

Cloud results come first because they cross a real network. [PERFORMANCE.md](docs/PERFORMANCE.md) has the full tables, the method and the steps to reproduce them.

| What | Result |
|------|--------|
| **Two Google Cloud hosts** (`c3-standard-8`, 20 Gbps link) | One flow: about 10 to 11 Gbps at 8 KB records, 14 to 18 Gbps at 60 KB (varies between runs). Four or more flows: about 20.4 Gbps, the same as plain TCP. |
| **Two AWS hosts** (`c7i-flex.large`) | Two or more flows, 8 KB and 60 KB records: 12.4 Gbps, the instance limit, within 0.4% of plain TCP. |
| **Small records** (1400 B, four flows) | 7.2 to 8.2 Gbps on AWS and 12.9 to 13.5 Gbps on Google Cloud, against 12.4 and 20.6 Gbps for plain TCP. |
| **Datagram loss**, Google Cloud, 1 to 4 Gbps offered | Under 0.01% with the built-in 256-entry inbox and a 4 MiB receive buffer (raise `rmem_max`). An earlier setup, a 64-entry inbox and the default socket buffer, lost 5 to 7%. A 2 vCPU AWS pair tuned the same way loses 0.2% to 0.5% at 4 Gbps because the receiver runs out of CPU. |
| **One stream tunnel, loopback** | Laptop (Apple M1 Pro): about 20 Gbps at 60 KB records, 9.6 Gbps at 8 KB. Linux CI runners: about 11 to 13 Gbps at 60 KB. |
| **Datagram, one flow, loopback** (Linux CI, x86-64 / arm64) | 1.6 / 2.4 Gbps with `Send`; 5.6 / 4.2 Gbps with `SendBatch` and offload. |
| **`SendBatch`, 256 B stream records** | 2 to 3x on macOS, Windows and x86-64 Linux. From 8 KB up, about 1.0x on Linux and Windows; the macOS runner still gains 1.4 to 1.8x. |
| **Time until the client can send** | 1 RTT plus about 1 ms or less: 21 ms on a 20 ms link, 101 ms on a 100 ms link. |
| **Handshake CPU, both sides** | 340 to 610 µs on Linux, macOS and Windows CI runners. Static-key authentication adds about 35 to 50%. |
| **Raw AES-256-GCM, one core** | About 2.5 GB/s (Apple M1 Pro). |
| **Wire cost** | 29 B per stream record; about 1.7 KB for the client's handshake flight (ML-KEM-1024). |

## Is it for you?

**A good fit if you:**
- run a TCP service you cannot change (a database, a broker, an HTTP or gRPC service) and want it behind a post-quantum tunnel. `quantum-tunnel forward` needs no code changes; try the [Docker Compose demo](examples/forward-demo/README.md) in about 10 minutes.
- build a Go service, agent, relay or edge component and want quantum-resistant transport **without a VPN daemon, a kernel module or root**.
- need a protocol you can hand to a reviewer, with a spec, symbolic models and test vectors.

**Not a fit if you:**
- want a VPN client with a TUN device, routing, DNS handling and a kill switch. This is a library; see [Scope](docs/SCOPE.md).
- need a FIPS 140-3 *validated* module today.

[Comparison](docs/COMPARISON.md) sets Quantum-Go next to WireGuard, Rosenpass, IKEv2 and hybrid TLS, including where it loses.

## Quick start

No Go code? Run [`quantum-tunnel forward`](docs/usage/FORWARD.md) next to the service and next to its users ([demo](examples/forward-demo/README.md)). For Go code:

```bash
go get github.com/sara-star-quant/quantum-go
```

Stream (TCP):

```go
import "github.com/sara-star-quant/quantum-go/pkg/tunnel"

cfg := tunnel.DefaultTransportConfig()
cfg.PSK, cfg.PSKIdentity = psk, []byte("client-1") // 32+ random bytes shared out of band

// Server
ln, _ := tunnel.Listen("tcp", ":8443")
ln.SetConfig(cfg)
conn, _ := ln.Accept()
msg, _ := conn.Receive()

// Client
c, _ := tunnel.DialWithConfig("tcp", "server:8443", cfg)
_ = c.Send([]byte("hello"))
```

Authentication is required: a PSK, a pinned or static server key, or `AllowUnauthenticated = true` (`DialInsecure` and `ListenInsecure` for tests and demos). Without one, `Dial` and `Accept` return `ErrAuthenticationRequired`.

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

## Security properties

| Property | Status |
|----------|--------|
| Post-quantum security | ML-KEM-1024 (NIST Category 5) |
| Classical security | X25519 (128-bit) |
| Hybrid property | Intended: secure if either algorithm holds. Symbolic model only (C-04); the computational proof is open (C-03, [claims register](docs/technical/CLAIMS.md)) |
| Endpoint authentication | Required: PSK, static-key server pinning or require-auth; explicit opt-out for tests |
| Forward secrecy | Ephemeral keys per session and per rekey |
| Session resumption | Removed in v0.0.26: it gave no speedup, so every connection does a full handshake |
| FIPS 140-3 | Build mode with POST and CST self-tests ([docs](docs/FIPS.md)); not a validated module |

## Documentation

**Use it**

| Guide | What it covers |
|-------|----------------|
| [Quick Start](docs/usage/QUICKSTART.md) | Installation and basic usage |
| [Configuration](docs/usage/CONFIGURATION.md) | Timeouts, rate limiting, sessions, authentication |
| [Forward mode](docs/usage/FORWARD.md) | Protect any TCP service without code changes |
| [Trying forward mode](docs/usage/PILOT.md) | Running it on a real link, what to expect and how to send feedback |
| [CLI reference](docs/usage/CLI.md) | Demos, key generation and benchmarks |
| [Security events](docs/usage/SECURITY_EVENTS.md) | Signals for pin mismatch, downgrade and replay, with benign causes |
| [Try it on AWS or Google Cloud](docs/usage/CLOUD_BENCH.md) | One script, two VMs, about ten minutes, torn down for you |
| [AI and cloud workloads](docs/usage/AI_AND_CLOUD.md) | Where post-quantum transport fits and where TLS already covers you |

**Evaluate it**

| Guide | What it covers |
|-------|----------------|
| [Scope and status](docs/SCOPE.md) | Shipped, planned and out of scope |
| [Comparison](docs/COMPARISON.md) | WireGuard, Rosenpass, IKEv2 and hybrid TLS |
| [Performance](docs/PERFORMANCE.md) | Latency, handshake cost and throughput |
| [Stability](docs/STABILITY.md) | What may change, enforced bounds and what each error means |
| [Threat model](docs/technical/THREAT_MODEL.md) | Threat and risk analysis (NIST SP 800-30) |
| [Claims register](docs/technical/CLAIMS.md) | Each security claim, its status and evidence |
| [Formal verification](docs/formal/README.md) | ProVerif models checked in CI |
| [Audit readiness](docs/compliance/AUDIT_READINESS.md) | Crypto inventory, claims-to-evidence map, supply chain |
| [FIPS build mode](docs/FIPS.md) | FIPS 140-3 build mode and self-tests |

**Design and history**

| Guide | What it covers |
|-------|----------------|
| [Architecture](docs/technical/ARCHITECTURE.md) | CH-KEM protocol and security design |
| [Protocol specification](docs/PROTOCOL.md) | Wire handshake, KEM negotiation, key schedule |
| [Datagram transport](docs/datagram-transport.md) and [DoS defences](docs/datagram-dos.md) | UDP transport design and limits |
| [Datagram fault model](docs/technical/FAULT_MODEL.md) | The lossy test network, what each test checks and how to re-run it |
| [Roadmap](docs/ROADMAP.md) | Development and compliance plans |
| [Changelog](CHANGELOG.md) | Release history |

## Contributing

Contributions are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for the development setup, test suite (unit, integration, fuzz), DCO sign-off and PR process. Report vulnerabilities privately, as described in [SECURITY.md](SECURITY.md).

## License

Apache License 2.0. See [LICENSE](LICENSE), [NOTICE](NOTICE) and [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md). Apache 2.0 includes an express patent grant, relevant in the patent-heavy post-quantum space.

## Compliance and liability

This software implements ECCN 5D002 dual-use cryptography, is not a FIPS 140-3 validated module, and is provided "as is" without warranty. Export, import and jurisdiction rules are your responsibility, and nothing here is legal advice. Read the full [compliance and liability notice](docs/compliance/COMPLIANCE_NOTICE.md) before using or redistributing it.
