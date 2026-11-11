# Performance

All numbers here are measured, not projected, unless a section says otherwise. Hardware-accelerated where available (ARMv8 Crypto Extensions on Apple Silicon, AES-NI / AVX2 / hardware SHA-3 on x86-64).

Two transports share the crypto core: a TCP/stream transport (length-prefixed framing) and a connectionless UDP/datagram transport (separate wire format, no interop). The datagram path is complete end to end: fragmented post-quantum handshake with retransmission, an encrypted zero-allocation data plane, reliable rekey, a load-gated stateless anti-amplification cookie, authenticated roaming, batched `recvmmsg` receive on Linux, optional UDP segmentation and receive offload, and optional fixed-size handshake padding.

## How these numbers were produced

- **CI runners:** the [Benchmarks workflow](../.github/workflows/bench.yml) runs on GitHub-hosted Linux x86-64, Linux arm64, macOS arm64 and Windows x86-64 runners. These are shared 3 to 4 vCPU virtual machines, so treat them as indicative, not as the ceiling of the hardware.
- **Laptop:** Apple M1 Pro, loopback, Go 1.27, quiet machine, network-filtering software turned off.
- **Hygiene:** measure with network-filtering software (a VPN client, antivirus or endpoint-security agent) turned off. Such software can sit on every socket call, loopback included: on the laptop used here, quitting one VPN client roughly doubled 60 KB-record throughput (about 1.2 to 2.5 GB/s) and tripled 8 KB-record throughput. Check that the machine is idle before a run, alternate the builds you compare, and repeat each run.
- **Container:** Linux arm64 VM with 8 cores (Docker Desktop), loopback.
- **Container bridge:** `scripts/docker-bench.sh [repetitions]` runs the throughput bench between two containers on a bridge network and prints the tunnel against plain TCP per record size, with the spread between runs. It is closer to two hosts than loopback, but it is still one machine.
- **Cloud:** two VMs in one zone on AWS (`eu-north-1`, `c7i-flex.large`) and Google Cloud (`europe-north1`, `c3-standard-8`), private addresses, `quantum-tunnel bench --serve` on one and `--connect` on the other, one 10 s run per cell. The laptop only sent commands, so no laptop VPN or filter touched these numbers. Single runs, not medians: treat them as indicative. See [Between two cloud hosts](#between-two-cloud-hosts).
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

AES-256-GCM seals at about 2.5 GB/s per core and ChaCha20-Poly1305 at about 0.7 GB/s (raw AEAD, Apple M1 Pro). The stream transport reaches about 2.5 GB/s on a single tunnel with 60 KB records on a quiet laptop; the record size moves this a lot, see the next section. Per-record overhead on the stream is 29 bytes (16 B AEAD tag, nonce derived and not transmitted, plus a 13 B frame header).

The datagram data path is syscall-bound, not crypto-bound: the isolated send path runs at about 3 GB/s on a laptop, so throughput is set by the send and receive system calls. Two features attack that cost.

### Throughput by record size and cost against plain TCP

`quantum-tunnel bench --throughput --baseline --chunk <size>` moves the same bytes in the same record size over a plain TCP stream and over a tunnel, on loopback, in one process. Apple M1 Pro, Go 1.27.3, AES-256-GCM, decimal MB/s, two 4 GiB runs per row averaged, quiet machine with network-filtering software turned off:

| Record size | Tunnel | Plain TCP | Tunnel as share of plain TCP | CPU per GiB, tunnel vs plain TCP |
|-------------|--------|-----------|------------------------------|----------------------------------|
| 8 KB | 1185 MB/s | 1982 MB/s | 60% | 1.62 vs 0.93 CPU-s (1.7x) |
| 16 KB | 1520 MB/s | 3068 MB/s | 50% | 1.25 vs 0.60 CPU-s (2.1x) |
| 60 KB | 2558 MB/s | 4947 MB/s | 52% | 0.77 vs 0.35 CPU-s (2.2x) |

The tunnel's two runs of each row agreed within 1%; the plain TCP reference moved more (at 16 KB it read 3145 and 2992 MB/s).

A dataset-sized transfer, 10 GiB of synthetic bytes (a repeating pattern; the tunnel does not compress, so the content does not matter) as a size class, not a real dataset, through one tunnel:

| Record size | Tunnel | Plain TCP |
|-------------|--------|-----------|
| 60 KB | 4.2 s (2545 MB/s) | 2.2 s (4869 MB/s) |
| 8 KB | 9.0 s (1195 MB/s) | 5.3 s (2031 MB/s) |

The rate matched the shorter runs, so it does not fall off with more data. Read these with three limits in mind:
- Loopback has no network limit. On a real link the network usually sets the rate and the tunnel's share of it is higher. `bench --serve` and `bench --connect` run the same test across two hosts, which is how to measure it.
- Client and server share one process and one set of cores here, so the CPU figures cover both ends. On separate hosts each side pays about half.
- The datagram transport is not in this table: it does not retransmit application data, so a transfer time is not meaningful there. Its goodput is in the section above.

The in-process Go benchmark (`BenchmarkStreamReceiveLargeRecords`, 2335 MB/s at 60 KB on this laptop) and this tool agree to within about 10%.

Receive timing starts at the first byte, not at `Accept`.

### Batching small stream records

For small records the cost is the syscall, not the bytes: on macOS, 88% of CPU in the small-record benchmark is `read` and `write`. `Tunnel.SendBatch` seals a burst under one lock and writes it. Small records go out in one vectored write, bulky ones one at a time, so a batch is always contiguous and in order. The cut-over is per platform and comes from measurement: no limit on macOS, 4 KB average record size on Windows, 2 KB elsewhere. The receiver sees ordinary records and needs no change.

A batch of 8 against one `Send` per record, `BenchmarkStreamSendBatch` over loopback on the bench workflow's runners (4 shared vCPUs). Each cell is the median of two runs of three samples. Shared runners drift by 10% or more between runs, so treat the figures as direction:

| Platform | 256 B records | 1400 B | 4 KB | 8 KB | 16 KB |
|----------|---------------|--------|------|------|-------|
| macOS arm64 | 2.2x | 1.9x | 1.5x | 1.8x | 1.4x |
| Windows x86-64 | 3.1x | 2.3x | 1.5x | 1.0x | 0.98x |
| Linux x86-64 | 2.65x | 1.02x | 1.01x | 1.02x | 0.99x |
| Linux arm64 | 1.05x | 1.08x | 1.06x | 1.01x | 0.95x |

In short:
- Small records gain wherever a syscall is expensive: 2 to 3x on macOS and Windows, and 2.65x at 256 B on x86-64 Linux.
- On Linux there is little to gain from 1400 B up in a loopback benchmark, because the receiver is the limit by then. Two-host numbers are not in yet.
- Bulky records take the same path as `Send`, so they land at about 1.0x. One cell stayed low in both runs (Windows, 32 records of 16 KB: 0.85x and 0.95x). From 8 KB up, use `Send`.
- A batch of 8 gets nearly all of the benefit; larger batches add little.

On a quiet Apple M1 Pro laptop a batch of 8 gave 3.4x at 256 B, 2.4x at 1400 B and 1.6x at 8 KB, in line with the macOS runner.

I tried a receive-side read-ahead (so one `read` serves many records) twice and left it out. On Linux loopback it raised batched throughput by up to 1.7x but cut plain per-record sends to about 0.45x, and a heuristic that enables it only for bursts did not avoid that. Loopback charges the sender for waking a faster receiver, so a second test used two containers on a bridge network (`scripts/docker-bench.sh`; Docker Desktop on an Apple M1 Pro, quiet machine, network-filtering software off, medians of three interleaved runs, read-ahead for records up to 4 KB against direct reads):

| Record size | Plain `Send` | `SendBatch` of 8 | Receiver CPU per GiB, batch of 8 |
|-------------|--------------|------------------|----------------------------------|
| 1400 B | 272 to 276 MB/s (+2%) | 641 to 830 MB/s (+29%) | 1.73 to 1.31 (-24%) |
| 2048 B | 388 to 331 MB/s (-15%) | 769 to 980 MB/s (+28%) | 1.45 to 1.16 (-20%) |

Read-ahead is a clear win for small records that arrive in bursts. It also cost plain 2 KB sends 15% in all three runs, and a receiver cannot cheaply tell a bursty sender from a plain one, so it stays out. At 4 KB and above the container VM produced two throughput modes (identical runs read 584, 948 and 584 MB/s), so those cells could not resolve a difference of 10%. A bridge is closer to a real network than loopback but is still one machine; two real hosts running the same script and `bench --serve` and `--connect` would settle it.

`SendBatch` is aimed at a VPN reading packets from a TUN device in bursts.

### Allocations per stream record

A stream record used to allocate about three times its own size: a ciphertext buffer and a second frame buffer on send, and the plaintext plus a small additional-data buffer on receive. Records are now sealed straight into a pooled frame, the sequence number in the frame header serves as the AEAD additional data, and the nonce uses memory that is already on the heap. The wire format is unchanged: a frame from the new path is byte-identical to the old one and opens on an unchanged receiver, and the reverse.

`BenchmarkStreamReceiveLargeRecords` and `BenchmarkStreamReceiveSmallRecords` (sender and receiver in one process, Apple M1 Pro, median of three runs, with network-filtering software such as a VPN client or antivirus turned off, because those tax every socket call including loopback):

| Record size | Allocated per record, before to after | Allocations per record | Throughput |
|-------------|---------------------------------------|------------------------|------------|
| 60 KB | 196,674 to 65,592 B | 8 to 2 | 1465 to 2335 MB/s (+59%) |
| 16 KB | 53,305 to 16,396 B | 8 to 2 | 993 to 1474 MB/s (+48%) |
| 1 KB | 3,384 to 1,029 B | 8 to 2 | 174 to 199 MB/s (+14%) |

End to end with `bench --throughput`, alternating the old and new build on the same quiet machine (two rounds that agreed within 1%), throughput rose 55% at 60 KB records (1486 to 2310 MB/s), 46% at 16 KB (1005 to 1470) and 43% at 8 KB (795 to 1137), and CPU per GiB fell 41%, 35% and 32% (1.64 to 0.96, 2.16 to 1.40, 2.71 to 1.83).

| Platform | 16 KB records | 60 KB records | 1 KB records |
|----------|---------------|---------------|--------------|
| Linux arm64 | 922 to 1385 MB/s (+50%) | 931 to 1636 MB/s (+76%) | 332 to 402 MB/s (+21%) |
| Linux x86-64 | 865 to 1169 MB/s (+35%) | 962 to 1451 MB/s (+51%) | 281 to 269 MB/s (-4%, the two runs disagreed in sign) |
| macOS arm64 | 775 to 1346 MB/s (+74%) | 1056 to 1773 MB/s (+68%) | 198 to 261 MB/s (+32%) |
| Windows x86-64 | 526 to 962 MB/s (+83%) | 696 to 651 MB/s (-6%) | 112 to 148 MB/s (+32%) |

Both Linux architectures were consistent from run to run. macOS and Windows moved by tens of percent between runs, so only their direction is meaningful. Windows at 60 KB was lower in both runs (-5% and -7%); that is the one cell that looks like a real cost, and its cause has not been found.

`Receive` returns a fresh plaintext for every record. `ReceiveInto(buf[:0])` appends it to a buffer you reuse instead and allocates nothing once the buffer is large enough. With it and a `SendBatch` that reuses its working lists, the same quiet laptop gained a further 11% throughput at 60 KB records (2310 to 2562 MB/s), 4% at 16 KB and 6% at 8 KB, with 21%, 11% and 14% less CPU per GiB. Stream send, stream batch send, datagram send, datagram batch send and receive into a reused buffer now allocate nothing per record in steady state, with or without an observer attached, and tests assert it. `Observer.OnEncrypt` and `OnDecrypt` report after the record finishes instead of returning a closure, which is what made an attached observer allocate.

### Where stream time goes

A CPU profile of 60 KB records over loopback (`BenchmarkStreamReceiveLargeRecords`, quiet laptop) shows about 66% of CPU in `read` and `write` system calls, about 4.5% in AES-GCM, and most of the rest in scheduler and netpoll waits; for 1 KB records it is 88% system calls. The tunnel runs at about half of plain TCP. A record costs a header read and a payload read, where the plain TCP loop reads 64 KB at once, so receive-side read-ahead is the obvious next lever. It gained 29% for batched small records and cost plain 2 KB sends 15% in container-bridge tests (see the batching section), so it was not shipped.

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

## Between two cloud hosts

Receiver-delivered rate, one tunnel (or plain TCP stream) per flow, 10 s per cell, in Gbps. A flow count above one means that many parallel connections on the same two hosts (`--flows`).

**Google Cloud, `c3-standard-8` pair, same zone (the link measured 20.4 Gbps):**

| Flows | 8 KB plain | 8 KB tunnel | 60 KB plain | 60 KB tunnel |
|-------|-----------|-------------|-------------|--------------|
| 1 | 20.5 | 10.1 | 20.5 | 14.3 |
| 4 | 20.5 | 20.7 | 20.4 | 20.2 |
| 8 | 20.7 | 20.4 | 20.5 | 20.2 |
| 16 | 20.4 | 20.4 | 20.4 | 20.4 |

**AWS, `c7i-flex.large` pair, same zone (2 vCPUs, up to 12.5 Gbps):** one flow reached 9.5 Gbps for plain TCP and the tunnel at both record sizes, and two or more flows reached 12.4 Gbps for both, which is the instance limit. A different pair of the same type topped out at 4.96 Gbps on one flow, so single-flow numbers depend on placement; compare flow counts within one pair.

What this says:

- **One tunnel flow is CPU-bound on a fast link.** On the 20 Gbps link a single tunnel flow stops at 10.1 Gbps with 8 KB records and 14.3 Gbps with 60 KB, because one goroutine does both the reads and the AES-GCM open. With four or more flows the tunnel fills the link and matches plain TCP.
- **Where the receiver's time goes** (8 KB records, Linux VM, loopback): about 49% in AES-GCM open, about 39% in the `read` syscall, and about 12% for framing, replay window, deadlines and clock calls. At 1 KB the `read` syscall is the largest item at about 30% and AES drops to about 5%. Allocation is one 5-byte allocation per record.
- **CPU per GiB** (AWS, four flows, 60 KB records): tunnel receiver 0.69 and sender 0.40 CPU-seconds, against 0.40 and 0.12 for plain TCP.

**Datagram transport** (Google Cloud `c3-standard-8` pair, 1100-byte records, offload on, 16 datagrams per `SendBatch`, `--rate` pacing), loss at a fixed offered load:

| Offered | Stock host: 64-entry inbox, default socket buffer | 256-entry inbox, 4 MiB receive buffer, `rmem_max` raised |
|---------|---------------------------------------------------|----------------------------------------------------------|
| 1 Gbps | 6.9% | under 0.01% |
| 2 Gbps | 5.1% | under 0.01% |
| 4 Gbps | 7.3% | under 0.01% |

Receiver CPU stayed low and the kernel's `RcvbufErrors` counter barely moved during the stock-host runs, so the drops were inside the library, and the change in the right column fixes them. See [Socket buffers at high rates](datagram-transport.md#socket-buffers-at-high-rates) for the setting. An unpaced blast delivers about 6.1 to 6.5 Gbps with 15% to 22% loss in both columns, because the receiver is CPU-bound there. Without offload, `SendBatch` sent at the same rate for batch sizes 1 and 16 (about 480 MB/s on this pair), so batching only paid off with offload on.

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
- **Use several flows on a fast link:** one stream flow is CPU-bound at about 10 to 14 Gbps on a 20 Gbps link, and four or more flows fill it.
- **Raise `net.core.rmem_max` for datagram receivers** above a few hundred Mbps, to at least 4 MiB; the setting and the numbers are in the [datagram transport doc](datagram-transport.md#socket-buffers-at-high-rates).
- **Smaller handshakes:** choose the X-Wing suite or pin a static server key.
- **Server concurrency:** stream handshakes run in their own goroutines (capped at 1,024 in flight), so one slow peer does not block others.

See [Configuration](usage/CONFIGURATION.md) and [Datagram transport](datagram-transport.md) for the options.
