# Performance

All numbers here are measured, not projected, unless a section says otherwise. Hardware-accelerated where available (ARMv8 Crypto Extensions on Apple Silicon, AES-NI / AVX2 / hardware SHA-3 on x86-64).

Two transports share the crypto core: a TCP/stream transport (length-prefixed framing) and a connectionless UDP/datagram transport (separate wire format, no interop). The datagram path is complete end to end: fragmented post-quantum handshake with retransmission, an encrypted zero-allocation data plane, reliable rekey, a load-gated stateless anti-amplification cookie, authenticated roaming, batched `recvmmsg` receive on Linux, optional UDP segmentation and receive offload, and optional fixed-size handshake padding.

## How these numbers were produced

- **CI runners:** the [Benchmarks workflow](../.github/workflows/bench.yml) runs on GitHub-hosted Linux x86-64, Linux arm64, macOS arm64 and Windows x86-64 runners. These are shared 3 to 4 vCPU virtual machines, so treat them as indicative, not as the ceiling of the hardware.
- **Laptop:** Apple M1 Pro, loopback, Go 1.26.
- **Container:** Linux arm64 VM with 8 cores (Docker Desktop), loopback.
- **Reproduce:** `quantum-tunnel bench --handshakes N --datagram-handshakes N --throughput` ([CLI reference](usage/CLI.md#benchmark-mode)), or `go test ./test/benchmark/ -bench Handshake` and `go test ./pkg/tunnel/ -bench DatagramEndToEnd`.

## Connection setup

Protocol 6.0 merges ServerHello and ServerFinished into one server flight, so the client is keyed after one round trip instead of two.

| Metric | Result |
|--------|--------|
| Time until the client can send data (stream) | 1 RTT + under 1 ms: 21 ms at 20 ms RTT, 101 ms at 100 ms, 501 ms at 500 ms (was 44, 204, 1004) |
| Time until the server can read client data (stream) | 1.5 RTT + under 1 ms: 31 ms at 20 ms RTT, 151 ms at 100 ms |
| Time until the client can send data (datagram, no loss) | 1 RTT + about 1 ms: 21 ms at 20 ms RTT, 101 ms at 100 ms (Linux runners) |
| Datagram handshake with reordered packets | No retransmit needed. Before the fix a reordered server flight cost a full 500 ms timer |
| Responder keypair generation | Skipped (the responder never used it): about 100 µs less CPU per handshake |

### Handshake CPU

Both sides of one handshake, no network, 20 runs, on CI runners:

| Runner | CPU | Handshake | With static-key auth |
|--------|-----|-----------|----------------------|
| Linux x86-64 | AMD EPYC 7763 | about 610 µs | about 820 µs |
| Linux arm64 | Ampere (ubuntu-24.04-arm) | about 520 µs | about 780 µs |
| macOS arm64 | Apple M1 (virtual) | about 450 µs | about 670 µs |
| Windows x86-64 | AMD EPYC 9V45 | about 340 µs | about 450 µs |

Handshake latency is round-trip bound, so faster hardware only shrinks the crypto part. PSK authentication adds one KDF fold (negligible). A 20,000-dial same-source soak passed on all four platforms with no stalls and no leaked state.

## Data plane

AES-256-GCM seals at about 2.5 GB/s per core and ChaCha20-Poly1305 at about 0.7 GB/s (raw AEAD, Apple M1 Pro). The stream transport reaches about 690 MB/s (5.5 Gb/s) single tunnel, sustained across rekeys. Per-record overhead on the stream is 29 bytes (16 B AEAD tag, nonce derived and not transmitted, plus a 13 B frame header).

The datagram data path is syscall-bound, not crypto-bound: the isolated send path runs at about 3 GB/s on a laptop, so throughput is set by the send and receive system calls. Two features attack that cost.

### Datagram goodput, single flow (CI runners, Linux)

Delivered goodput over loopback: the benchmark flow-controls the sender so drops are never counted, and measures seal, send, kernel, receive loop, demux, AEAD open and delivery.

| Runner | `Send` (one syscall per datagram) | `SendBatch`, no offload | `SendBatch` with `WithDatagramOffload` |
|--------|-----------------------------------|--------------------------|-----------------------------------------|
| Linux x86-64, 4 vCPU | 196 MB/s | 189 MB/s | **701 MB/s (3.6x)** |
| Linux arm64, 4 vCPU | 304 MB/s | 319 MB/s | **528 MB/s (1.7x)** |

`SendBatch` plus `WithDatagramOffload` sends runs of equal-size datagrams with one syscall using `UDP_SEGMENT` and receives them coalesced with `UDP_GRO`. It falls back to plain sends where the kernel or NIC refuses, and it needs the caller to hand over several packets at once (a VPN reading a TUN device in batches does). In a Docker Linux VM on a laptop the gain was smaller (about 330 to 430 MB/s, 1.3x), because the receiving goroutine becomes the limit; results depend on the kernel and the receive side.

### Other datagram measurements

Measured earlier in a Linux container (arm64, 8 cores), before the benchmark flow-control window was widened, so the absolute single-flow figure is conservative:

| Metric | Result |
|--------|--------|
| Aggregate goodput, single receive goroutine, 1 to 8 flows | peaks about 365 MB/s near 4 flows, then plateaus |
| Aggregate goodput, `SO_REUSEPORT`, 8 flows, 1 to 8 sockets | about 355 to 565 MB/s (1.6x across 8 cores) |
| Datagram send, isolated, zero-allocation steady state | about 1.2 GB/s (Linux), about 3.0 GB/s (laptop, about 380 ns per datagram) |
| `recvmmsg` batch versus one syscall per datagram | about 1030 versus 975 MB/s |

On macOS loopback the single-flow goodput is about 66 MB/s: that platform has a slow per-datagram socket path, a loopback artifact and not a transport limit.

A single receive goroutine demuxing and opening every datagram is the per-endpoint ceiling. `ListenDatagram` spreads that work across cores with `SO_REUSEPORT`. A CPU profile of the delivered path is about 35% AES (already hardware-accelerated), about 30% system calls, and the rest framing, allocation and bookkeeping.

Optional handshake padding (`WithHandshakePadding`) costs roughly 42% more handshake bandwidth (a ClientHello flight grows from about 1,700 to 2,400 bytes) for uniform-size, fingerprint-resistant handshake datagrams. It never touches the data plane.

## Comparison with other protocols

Order-of-magnitude only: different hardware, different measurements.

| | Round trips until the client can send | Handshake bytes | Post-quantum |
|---|---|---|---|
| Quantum-Go 6.0 | 1 RTT | about 1.7 KB client flight plus a matching server flight (ML-KEM-1024) | Yes, hybrid with X25519 |
| WireGuard | 1 RTT | 148 B initiation, 92 B response ([protocol](https://wireguard.com/protocol)) | No |
| TLS 1.3 with X25519MLKEM768 | 1 RTT after TCP | adds about 1,176 B client and 1,088 B server ([Red Sift](https://redsift.com/blog/post-quantum-mlkem-performance)) | Yes |

Quantum-Go matches WireGuard on round trips. It is about ten times larger on the wire because ML-KEM-1024 carries 1,568-byte keys and ciphertexts each way (NIST security level 5). The X-Wing suite (ML-KEM-768 plus X25519) is already supported and roughly halves that. CPU is small: published hybrid-TLS measurements put the ML-KEM cost under 0.1 ms per side.

## Tuning

- **Batch your sends:** use `DatagramConn.SendBatch` with `WithDatagramOffload()` on Linux when you can hand over several packets at once.
- **Spread receive across cores:** `ListenDatagram` uses `SO_REUSEPORT` sockets, one per core by default.
- **Smaller handshakes:** choose the X-Wing suite or pin a static server key.
- **Server concurrency:** stream handshakes run in their own goroutines (capped at 1,024 in flight), so one slow peer does not block others.

See [Configuration](usage/CONFIGURATION.md) and [Datagram transport](datagram-transport.md) for the options.
