# Scope

Quantum-Go is a tunnel **encryption library**, not a VPN client. It encrypts and
authenticates bytes over a `net.Conn` or UDP socket. It does not configure, capture, or
route operating-system network traffic.

**What the library gives you (connection continuity):**

- **Authenticated roaming** - a datagram session can survive the peer's IP or port
  changing (NAT rebind, Wi-Fi to cellular): it demuxes by a random connection index, not
  source address, and rebinds only after an AEAD-authenticated packet.
- **Reliable handshake** - the post-quantum handshake retransmits lost flights with
  backoff over a lossy UDP path.
- **Rekey and idle reaping** for long-lived sessions.

**What the library does NOT do (the integrating application's responsibility):**

- **Reconnect after a full disconnect** - the library has no auto-redial loop;
  re-establishing with `Dial` / `DialDatagram` is the caller's responsibility.
- **DNS leak prevention** - the library does not control the operating-system resolver.
- **Kill-switch** - the library does not block non-tunnel traffic when the tunnel is down.
- **TUN device and system routing** - the library does not capture or route host traffic
  into the tunnel.

## Status of every capability

Read this table before describing what Quantum-Go can or cannot do. "Shipped" names the first release that has it, "planned" names the issue that tracks it, and anything else is stated as not done or out of scope. When a change ships or closes something listed here, the same pull request updates its row (see [CONTRIBUTING](../CONTRIBUTING.md)).

| Capability | Status |
|---|---|
| Hybrid ML-KEM-1024 + X25519 key exchange, AEAD records (AES-256-GCM, ChaCha20-Poly1305) | shipped |
| Stream (TCP) and datagram (UDP) transports | stream shipped; datagram since v0.0.11 |
| Client keyed after one round trip | shipped, v0.0.17 |
| Rekeying for long-lived sessions | shipped |
| Server key pinning (stream and datagram) | shipped, v0.0.12 |
| Per-client pre-shared keys and require-PSK | shipped, v0.0.17 |
| Opt-in X-Wing suite and negotiable KEM suites | shipped, v0.0.15 |
| FIPS build mode with power-on self-tests | shipped, v0.0.7; not a validated module |
| Datagram drop counter (`InboxDropped`) | shipped, v0.0.24 |
| Two-host and cloud benchmarking (`bench`, `scripts/cloud-bench.sh`) | shipped, v0.0.24 |
| Session resumption | removed in v0.0.26 ([#146](https://github.com/sara-star-quant/Quantum-Go/issues/146)): it never sped anything up; every connection does a full handshake |
| `net.Conn` adapter, HTTP and gRPC over the tunnel | planned ([#219](https://github.com/sara-star-quant/Quantum-Go/issues/219)) |
| Forward mode that protects any TCP service without code changes | on `main`, unreleased ([#220](https://github.com/sara-star-quant/Quantum-Go/issues/220)); see [forward mode](usage/FORWARD.md) |
| UDP forwarding (QUIC, HTTP/3, CoAP) | not planned: low impact, TLS already covers QUIC |
| Traffic profiles and workload labels | planned ([#222](https://github.com/sara-star-quant/Quantum-Go/issues/222)) |
| Authenticated peer identity, authorize hook, client device keys, live-session revocation | planned ([#196](https://github.com/sara-star-quant/Quantum-Go/issues/196)) |
| Path-MTU discovery for datagrams | planned ([#144](https://github.com/sara-star-quant/Quantum-Go/issues/144)) |
| Faster single stream flow by splitting reads from decryption | under evaluation ([#193](https://github.com/sara-star-quant/Quantum-Go/issues/193)) |
| Second independent implementation checked against the conformance vectors | planned, help wanted ([#145](https://github.com/sara-star-quant/Quantum-Go/issues/145)) |
| Third-party security audit | not done |
| FIPS 140-3 (CMVP) validation | not done |

## What this project is not

- **Not an AI-security product.** Transport encryption protects model weights, training data and prompts *in transit*. It does nothing about prompt injection, model poisoning, data leakage or supply-chain attacks. See [AI and cloud workloads](usage/AI_AND_CLOUD.md).
- **Not a replacement for TLS between Go services.** Go's `crypto/tls` already offers hybrid post-quantum key exchange by default (from Go 1.24, with a Category 5 option from Go 1.26). Quantum-Go adds value where TLS does not fit; the library cannot serve `net/http` or gRPC directly until #219 lands, but the [forward mode](usage/FORWARD.md) protects any TCP service, HTTP and gRPC included, without code changes.
- **Not a zero-trust broker or policy engine.** For ZTA, ZTNA and zero-trust edge designs it can be the encrypted, authenticated data plane. Policy decisions, posture checks and user identity belong in a product built on top. Today the server cannot tell which authenticated identity a session belongs to; that is #196. A workload label (#222) will be operator-supplied telemetry, never a security attribute, and must not drive an allow or deny decision.
- **Not for GPU fabrics.** Line rates of tens or hundreds of Gbps over RDMA or InfiniBand need hardware offload that a Go userspace tunnel cannot match.

These properties belong to a VPN client built around the library, not to the library
itself. This text describes the software, not security or legal advice; Quantum-Go ships
under the Apache License 2.0, "as is" and without warranty (see [LICENSE](LICENSE) and the
[compliance notice](compliance/COMPLIANCE_NOTICE.md)).
