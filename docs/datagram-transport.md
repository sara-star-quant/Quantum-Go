# UDP / Datagram Transport (design)

This document describes the connectionless datagram transport that complements
the existing TCP/stream transport. The two share the crypto core (`pkg/chkem`,
`pkg/crypto`, and the `Session` key/rekey secret derivation) but have **separate
wire formats**. There is no TCP↔UDP interop, by design.

The transport is being built incrementally. This document tracks the design and
is updated as pieces land.

## Status

| Component | File | Status |
|-----------|------|--------|
| Datagram wire codec | `pkg/protocol/datagram_codec.go` | implemented |
| Multi-word replay window | `pkg/tunnel/replay.go` | implemented |
| Bounded handshake reassembler | `pkg/tunnel/reassembly.go` | implemented |
| Datagram constants | `internal/constants/constants.go` | implemented |
| Endpoint + demux + dial/accept | `pkg/tunnel/datagram.go` | implemented |
| Reliable handshake FSM + driver + wiring | `pkg/tunnel/dgram_handshake_{fsm,driver,wire}.go` | implemented |
| Epoch cipher selection + derived-nonce seal/open | `pkg/tunnel/dgram_session.go` | implemented |
| Data path (DatagramConn Send/Recv/Close) + idle reaper | `pkg/tunnel/dgram_conn.go`, `datagram.go` | implemented |
| Reliable rekey transport (fragmented sub-handshake) | `pkg/tunnel/dgram_rekey.go` | implemented |
| Zero-alloc in-place AEAD send path | `pkg/crypto/aead_inplace.go`, `pkg/tunnel/dgram_session_inplace.go`, `dgram_conn.go` | implemented |
| Batched recvmmsg receive + sendmmsg flights (Linux; portable fallback) | `pkg/tunnel/dgram_batch{,_linux,_other}.go`, `datagram.go` | implemented |
| Stateless cookie / anti-amplification | `pkg/tunnel/dgram_cookie.go`, `datagram.go` | implemented |
| Authenticated roaming | `pkg/tunnel/datagram.go` | implemented |
| Optional fixed-size handshake padding (anti-fingerprinting) | `pkg/tunnel/dgram_handshake.go`, `datagram.go`, `pkg/protocol/datagram_codec.go` | implemented |

## Wire format

Every datagram is exactly one frame. There is no cross-datagram length prefix
and **no transmitted nonce**.

Common 14-byte header (all frame types):

```
[FrameType:1][Epoch:1][RecvIndex:4 BE][Seq:8 BE]
```

- **FrameType** — DATA, HANDSHAKE, CLOSE, or RETRY (RETRY reserved for a future stateless-retry exchange).
- **Epoch** — selects the receive cipher for DATA frames (see *Rekey*). Carried
  in the clear but authenticated: the AEAD AAD is the entire 14-byte header, so a
  flipped epoch is rejected, not merely mis-routed.
- **RecvIndex** — the random connection index the *receiver* assigned to this
  session. The sender echoes it; the receiver demultiplexes by index, **not by
  source address**. `0` means "unknown" (the first ClientHello).
- **Seq** — a globally monotonic, **never-reset** 64-bit counter. It is both the
  replay counter and the low 8 bytes of the AEAD nonce.

DATA frame: `[header] || AEAD ciphertext(incl. tag)`.

HANDSHAKE frame appends an extension before the (possibly fragmented) message:

```
[SenderIndex:4][MsgType:1][FragOffset:2][FragLen:2][TotalLen:2][CookieLen:1][Cookie:CookieLen]
```

`CookieLen` is `0` today; the field exists so a future stateless-retry hardening
needs no wire change.

## Key design decisions (improve, do not inherit)

- **Nonce is derived, not transmitted.** `nonce = noncePrefix(4B) || seq(8B)`.
  `seq` is globally monotonic and never reset across a rekey, so per-`(key,nonce)`
  uniqueness holds trivially (the epoch rotates the key well before any 2⁶⁴ wrap),
  one replay window covers the whole session, and we save 12 bytes/packet versus
  the stream path. This also realizes session-bound nonces (ROADMAP #2).

- **Demux by random connection index, not source address.** A session survives
  NAT rebind/roaming, one address can host many sessions, and indices resist
  off-path guessing (CSPRNG, regenerated on the rare active-table collision). The
  source address is only a hint, updated after an AEAD-valid packet
  (authenticated-rebinding enforcement is future work).

- **Epoch-based rekey (reorder-safe).** The stream transport promotes the new
  receive cipher on the first new-key packet and discards the old one — correct
  only for in-order delivery. The datagram path instead carries a 1-byte epoch
  per frame (in the AAD); the receiver selects the cipher by epoch and retains
  the previous epoch's receive cipher for a bounded window (by sequence distance
  and time) before retiring it. Epoch is mod 256; only adjacent epochs are ever
  live, so wrap is unambiguous.

- **Reliable rekey as a fragmented sub-handshake.** The CH-KEM public key and
  ciphertext (~1.6 KB each) exceed the MTU, so a rekey is a small two-message
  exchange (RekeyInit -> RekeyResponse) reusing the handshake fragmenter and
  reassembler. Each message is authenticated under the *current* epoch (so an
  off-path party cannot inject a rekey) and carries its own derived nonce. Only
  the handshake initiator drives rekey, which avoids both sides rekeying at once;
  it retransmits the RekeyInit with backoff until the response arrives. The
  responder answers reactively and caches its sealed response, replaying it
  verbatim on a retransmitted RekeyInit - it must never re-run the randomized
  `Encapsulate`, which would derive a different secret and desync the epochs. The
  initiator starts a rekey in the background well before the per-epoch key budget
  is exhausted (`pkg/tunnel/dgram_rekey.go`).

- **Single, wide, never-reset replay window.** A multi-word sliding bitmap
  (`DatagramReplayWindowBits`, default 1024) over the monotonic sequence,
  tolerant of datagram reordering. It is never reset on rekey — resetting it
  would re-arm a fresh window that re-opens a one-packet replay at the rekey
  boundary (the same hazard the stream path guards against).

- **App-layer fragmentation for handshakes only.** The PQ Hellos (~1.7 KB)
  exceed the conservative 1200-byte datagram budget, so handshake messages are
  fragmented and reassembled. Data frames are capped to a single datagram (a
  tunnel's inner payload ≤ MTU), so the reassembler only ever sees the bounded,
  few-message handshake. Reassembly runs pre-auth and is bounded three ways:
  per-source concurrent-buffer cap, per-message size cap, and a timeout.

- **No FIN over UDP.** Sessions are reaped by idle timeout; CLOSE is a
  best-effort datagram, never relied upon. `Send` emits one datagram per call and
  rejects payloads larger than `DatagramMaxDataPayload` (no PMTU discovery).

## DoS posture

Amplification is inherently low: the ~1.7 KB ClientHello must be fully received
and reassembled before the comparable ServerHello is sent (response:request ≈
1:1, not an amplifier). The implementation additionally reuses the existing rate
limiters and enforces a hard, core-scaled ceiling on concurrent half-open
handshakes (`reserveSource` drops new sources once the ceiling is reached). A
load-gated stateless cookie closes the residual spoofed-source state-exhaustion
gap and enforces a strict anti-amplification bound, and a session follows a
roaming peer only on an authenticated, replay-fresh frame; see
[datagram-dos.md](datagram-dos.md).

### Optional handshake padding (anti-fingerprinting)

`WithHandshakePadding()` zero-pads every handshake and rekey datagram to the MTU,
so ClientHello, ServerHello, and the rekey sub-handshake are size-indistinguishable
on the wire, defeating passive size-based traffic analysis of "a CH-KEM handshake is
happening here." It is off by default (it costs bandwidth) and never pads the data
plane. The padding rides after the fragment payload and outside the declared
fragment length, so the receiver slices it off before reassembly: it never enters
the reassembled message or the handshake transcript, cannot smuggle bytes into the
authenticated handshake, and does not change per-source reassembly memory (sized by
the declared total length, not the datagram size). It also cannot weaken the
anti-amplification bound, since a RETRY is only ever sent when it is no larger than
the triggering datagram. The receiver tolerates padding unconditionally, so a
padding peer interoperates with a non-padding one; for full effect enable it on both
ends.

## Scaling and configuration

A single receive goroutine demuxing and AEAD-opening every datagram is the
aggregate-throughput ceiling on a busy multi-session server. `ListenDatagram`
opens N `SO_REUSEPORT` sockets bound to one address; the kernel load-balances
inbound datagrams across them by flow hash and `Serve` runs one receive goroutine
per socket, so demux and AEAD-open spread across cores. On platforms without
`SO_REUSEPORT` it transparently degrades to one socket. `NewDatagramEndpoint`
(single socket) is unchanged.

Measured on an 8-core arm64 Linux container (loopback, indicative): a single receive
goroutine tops out around 365 MB/s aggregate delivered goodput; spreading receive
across sockets lifts it about 1.6x, from ~355 MB/s (1 socket) to ~565 MB/s (8
sockets). The scaling is sublinear here because the loopback path and the benchmark's
own senders share the same 8 cores; a many-core host with real NIC receive queues has
more headroom. The single-flow path remains syscall-bound (~280 MB/s, ~2.2 Gb/s), so
the next per-flow lever is `UDP_SEGMENT`/`UDP_GRO` offload (see "Out of scope" below).

```go
ep, err := tunnel.ListenDatagram("udp", "0.0.0.0:51820")
if err != nil { /* ... */ }
go ep.Serve()
```

- `WithReceiveSockets(n)` sets the `SO_REUSEPORT` socket count (clamped to
  `[1, DatagramMaxReceiveSockets]`); the default is `min(GOMAXPROCS,
  DatagramMaxReceiveSockets)`.
- `WithMaxHalfOpen(n)` pins the concurrent half-open handshake ceiling. The default
  autoscales with core count - `clamp(GOMAXPROCS * 256, 1024, 8192)` - and the
  cookie-pressure water-mark tracks at half of it; see
  [datagram-dos.md](datagram-dos.md).

### High-assurance deployment example

A conservative deployment can pin the capacity/DoS knobs and enable handshake
padding:

```go
ep, _ := tunnel.ListenDatagram("udp", addr,
    tunnel.WithMaxHalfOpen(1024),  // pinned, predictable half-open budget
    tunnel.WithHandshakePadding(), // size-uniform handshakes (traffic analysis)
)
```

This only pins capacity and DoS-posture knobs. The cryptography (ML-KEM-1024 +
X25519 CH-KEM) is fixed and already at the high-assurance tier, matching the
conservative posture BSI / US-federal guidance favors. It is **not** a certified
BSI/FIPS profile; for FIPS 140-3 build mode see [FIPS.md](FIPS.md).

## Out of scope (future)

GSO/GRO offload, PMTU discovery, multipath, and a parallel per-datagram crypto
pipeline (revisited after the current baseline is measured).
