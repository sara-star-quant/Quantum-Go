# UDP / Datagram Transport — phased design (refined)

> **Planning-environment caveat (read first).** During this refinement the
> sandbox stopped returning tool output after the first call. I confirmed the
> package layout (one successful `find`/`ls`) but could **not** re-open the
> source files to re-verify line numbers or internal structures. Items that
> depend on unverified internals are tagged **[VERIFY]** below — confirm each
> against the code before/while implementing. The one structural correction I
> *could* confirm from the directory listing is called out in §0.

---

## Context

The transport is TCP/stream-only. The draft's exploration found stream
assumptions throughout: blocking `io.ReadFull` handshake reads, length-prefixed
framing, a single-writer `writeMu`, a 64-entry replay window, and a rekey that
*assumes in-order delivery* (promote-on-first-new-key, discard-old). None of
that survives datagram reordering, loss, duplication, or the ~1644 B Hellos that
exceed a 1500 B MTU. UDP needs a purpose-built datagram transport, not a port of
the stream code.

**Goal:** a clean-sheet, connectionless datagram transport that reuses the
crypto core unchanged and *improves on* (does not inherit) the TCP stack's
constrained choices. Delivered as a phased epic with an explicit Datagram API
(not `Dial`/`Listen("udp")`), DoS/amplification hardening deferred to Phase 2 but
with its wire hooks reserved in Phase 1.

**Reused unchanged (no fork):** `pkg/chkem`, `pkg/crypto` (AEAD,
`DeriveTrafficKeys`, `DeriveRekeySecret`, KDF), and the `Session` key/rekey
*secret-derivation* primitives. **New:** the transport/framing/handshake-delivery
layers. The TCP wire format is untouched; UDP is a separate transport with its
own framing (no TCP↔UDP interop, documented).

---

## §0. Corrections to the draft (confirmed structural facts)

- **There is no `pkg/tunnel/replay.go`.** The `pkg/tunnel` listing contains
  `session.go`, `handshake.go`, `transport.go`, `limiter.go`, `ticket.go`,
  pool/observer files, and tests — but no `replay.go`. The draft lists
  `replay.go` under *Extended* and as the home of the multi-word window. The
  replay window today lives inside another file (almost certainly `session.go`).
  **Action:** treat the replay window as **New** code — create
  `pkg/tunnel/replay.go` housing the multi-word window type, and have the
  datagram recv path use it. Decide during implementation whether to also
  migrate the TCP window into it or leave TCP's in place (prefer leaving TCP
  untouched to avoid regressing the stream path). **[VERIFY]** the current
  window's exact location/shape.

- Everywhere the draft says "extend `pkg/tunnel/replay.go`", read "add
  `pkg/tunnel/replay.go` (new)".

---

## Architecture at a glance

```
                         ┌─────────────────────────── DatagramEndpoint ──────────────────────────┐
   *net.UDPConn ──recv──▶│ parse frame header (type,epoch,recvIndex,seq)                          │
                         │   │                                                                    │
                         │   ├─ recvIndex ─▶ session table (random CSPRNG index, NOT src addr)    │
                         │   │                    │                                               │
   data datagram ────────┼───┤            ┌───────┴────────┐                                      │
   [type|epoch|idx|seq|ct]   │            │ found session  │ ── epoch ─▶ select recv cipher       │
                         │   │            │                │            (cur | prev-retained)     │
                         │   │            │                │ ── seq  ─▶ global replay window      │
                         │   │            │                │            (multi-word, never reset) │
                         │   │            │                │ ── AEAD Open (AAD = idx||epoch)      │
                         │   │            │                │ ── on success: maybe rebind src addr │
                         │   │            └────────────────┘            (Phase 2 enforcement)     │
                         │   │                                                                    │
   handshake datagram ───┼───┴─▶ reassembler (HANDSHAKE only, bounded) ─▶ dgram_handshake FSM     │
   [type|...|msgID|fragOff|     (per-src cap, per-buf cap, timeout)        (retransmit/dedup/      │
    fragLen|totalLen|...]                                                   flight cache)          │
                         │                                                                         │
   new session ─────────┼────────────────────────────────────────────────▶ accept channel         │
                         └─────────────────────────────────────────────────────────────────────────┘
```

The crypto core (`chkem`, `crypto`, `Session` secret derivation) sits unchanged
underneath; only header parsing, demux, reassembly, the handshake FSM, epoch
cipher selection, and the replay window are new.

---

## Phase 1 — Functional UDP datagram transport (PR 1)

### Wire format (`pkg/protocol/datagram_codec.go`, new)

Self-contained per-datagram frame, **no cross-datagram length prefix, no
transmitted nonce**:

```
data:      [type:1][epoch:1][recvIndex:4][seq:8] || ciphertext+tag
           └────────── AAD includes recvIndex + epoch ──────────┘
handshake: [type:1][epoch:1][recvIndex:4][seq:8][senderIndex:4]
           [msgID:?][fragOffset:?][fragLen:?][totalLen:?] || ct+tag
```

- **Nonce is derived, not sent:** `nonce = sessionNoncePrefix(4B) || seq(8B)`
  (12 B AEAD nonce). `seq` is the **single** replay counter *and* AEAD nonce
  counter, **globally monotonic, never reset across rekey**. This (a) keeps
  per-`(key,nonce)` uniqueness trivially — key changes by epoch before any
  realistic 2⁶⁴ wrap, and within an epoch `seq` is unique; (b) gives one replay
  window for the whole session; (c) delivers ROADMAP #2 session-bound nonces for
  free; (d) saves 12 B/packet vs the TCP path that prepends the nonce.
- `recvIndex` + `epoch` go in the **AEAD AAD** (authenticated — a flipped epoch
  is *rejected*, not merely mis-routed).
- **Overhead budget (state it for the Send error):** data header = 1+1+4+8 =
  **14 B** + **16 B** tag = **30 B**/datagram. With a conservative 1200 B
  datagram budget, max inner payload ≈ **1170 B**. Define the exact constant in
  `internal/constants`.
- Confirm field widths for `msgID`/`fragOffset`/`fragLen`/`totalLen` against the
  ~1644 B Hello reassembly need (totalLen must hold ≥ ~1700; offsets/lengths fit
  in 2 B at a 1200 B MTU). **[VERIFY]** existing message sizes via
  `EncodeClientHello`/`EncodeServerHello`. **[VERIFY]** that these encode
  functions exist with those names in `pkg/protocol`.

### Endpoint + demux (`pkg/tunnel/datagram.go`, new)

- `DatagramEndpoint` over a single `*net.UDPConn`. Demux **by random per-session
  connection index** carried in every frame (WireGuard receiver-index model),
  **not by source address** → a session survives NAT rebind/roaming, one address
  hosts many sessions, indices resist off-path guessing (CSPRNG via
  `pkg/crypto/random`, not sequential; regenerate on the rare active-table
  collision). **[VERIFY]** the CSPRNG helper name in `pkg/crypto/random.go`.
- Source address is a *hint*, updated only after an AEAD-valid packet (secure
  roaming; enforcement lands in Phase 2, hook present in Phase 1).
- New sessions surface on an **accept channel** (connectionless) — no
  `net.Listener.Accept` shape.

### Phase 1a — correctness (land + benchmark before optimizing)

**Reassembly (`pkg/tunnel/reassembly.go`, new) — HANDSHAKE messages only.**
Data frames are capped to one datagram (a VPN inner payload ≤ MTU), so the
reassembler never sees data traffic — only the bounded, few-message handshake.
Bound it hard (it runs pre-auth): per-source cap on concurrent buffers,
per-buffer size cap, and a timeout; reject/evict on breach.

**Reliable handshake (`pkg/tunnel/dgram_handshake.go`, new), bilateral.**
- Both sides retransmit their last flight on timeout or on receiving a duplicate
  of the peer's prior flight; the **initiator** owns the abort timeout +
  exponential backoff + bounded retries; per-flight dedup.
- The **responder caches its generated ServerHello + derived secret** (keyed by
  connection index) and replays that flight *verbatim* on a duplicate
  ClientHello — it must **never** re-run the randomized `Encapsulate`, which would
  derive a different secret and desync the sides. **[VERIFY]** the `Encapsulate`
  entry point in `pkg/chkem`.
- Reuse existing message *contents*
  (`EncodeClientHello`/`ServerHello`/`Finished`), wrapped in datagram+fragment
  framing. **[VERIFY]** these names.

**Lifecycle (no TCP FIN over UDP).** Reap by idle timeout; close is a
best-effort datagram, never relied on. **Send contract changes:** one datagram
per `Send`; payload capped to the datagram MTU (overhead-adjusted); `Send`
returns a clear, typed error on oversize (PMTU discovery out of scope).
**Resumption** reuses the existing ticket `Resume`/`ExportTicket` flow within the
new framing. **[VERIFY]** ticket API names in `pkg/tunnel/ticket.go`.

**Rekey + replay reworked for reordering (NOT inherited).**
- **Epoch-based rekey:** 1-byte `epoch` per data frame, in the AAD. Receiver
  selects cipher by epoch and retains the *previous* epoch's recv cipher for a
  bounded window (seq-distance **and** time), then retires it. Define wrap
  handling: epoch is mod 256, only adjacent epochs are ever live, so wrap is
  unambiguous. Replaces the unsafe in-order promote/discard trial-decrypt.
  *Alternative considered:* trial-decrypt current-then-previous with no epoch
  byte — simpler, no wire field, but pays a second `Open` during the window;
  epoch chosen since the UDP wire is new anyway.
- **Implementation guidance (avoid TCP regression):** add the epoch-keyed cipher
  selection as a **datagram-specific recv path / new methods on `Session`**,
  reusing `DeriveRekeySecret` and the pending-cipher derivation — **do not mutate
  the TCP recv path's promote/discard logic.** **[VERIFY]** how `Session`
  currently stores current/pending ciphers so the datagram path can hold
  `{epoch → cipher}` for the two live epochs.
- **Single global replay window** (`pkg/tunnel/replay.go`, new): multi-word
  bitmap (≥1024, ROADMAP #5) over the monotonic `seq`, **never reset across
  rekey** — epoch picks the cipher, the window tracks seq independently. This
  carries the boundary-replay lesson from the TCP fix (resetting the window on
  key change re-opens a one-packet replay).

**Reserve DoS hooks now (no Phase-2 wire change):** include an optional cookie
field and a `RetryRequest` message type in the handshake framing.

**Phase-1 DoS posture (not wide-open despite no cookie yet):**
- Reuse `HandshakeLimiter` (global rate); adapt `IPRateLimiter` to a
  per-source-addr half-open handshake cap; bound concurrent half-open sessions.
  **[VERIFY]** `HandshakeLimiter` / `IPRateLimiter` signatures in
  `pkg/tunnel/limiter.go`.
- Amplification is inherently low: the ~1644 B PQ ClientHello must be fully
  received/reassembled before the ~1642 B ServerHello is sent, so
  response:request ≈ 1:1 (not an amplifier). Document this; the Phase-2 cookie
  closes the residual spoofed-source state-exhaustion gap.

### Phase 1b — performance (after a measured 1a baseline)

Design 1a to *allow* these (header headroom in the frame layout, no forced
copies); land and tune them after a correctness baseline + benchmark, mirroring
the TCP "measure then optimize" approach:
- **Zero-alloc steady-state path:** encrypt in place into a reusable
  per-endpoint datagram buffer with header headroom; `SealAppend`/`OpenInto`-style
  AEAD; stack `[8]byte`/`[12]byte` nonce+AAD scratch. Target 0 allocs/op on send
  and on the opt-in receive path. **[VERIFY]** which append/in-place AEAD entry
  points `pkg/crypto/aead.go` exposes (reuse, don't add).
- **Batched syscalls:** `recvmmsg`/`sendmmsg` via `golang.org/x/net/ipv4|ipv6`
  `PacketConn` `ReadBatch`/`WriteBatch`. Adds a direct `golang.org/x/net` dep
  (already indirect) — **confirm before promoting to a direct dep.**
- **Drop per-packet overhead:** atomic `LastActivity` (no per-packet
  `mu.Lock()`), coarse deadlines, no per-packet `time.Now()` in the hot path.

---

## Phase 2 — DoS / amplification hardening + assurance (PR 2)

- **Stateless retry/cookie:** responder holds no state until the client echoes a
  MAC'd cookie bound to its source address (HelloRetryRequest / WireGuard-cookie
  / Rosenpass-biscuit style). Enforce **anti-amplification** (never send >~1×
  received bytes to an unverified source). Uses the Phase-1 reserved cookie
  field — no wire change.
- **Authenticated address rebinding (roaming):** migrate a session's peer
  address only after an AEAD-valid packet from the new address (prevents off-path
  hijack/redirect via spoofed source). UDP-specific property, no TCP analog.
- **Assurance:** threat-model doc in `docs/`; fuzz the datagram parser +
  reassembler + cookie path; negative tests for spoofed-source and
  amplification.
- *Optional:* fixed-size datagram padding for traffic-analysis resistance.

---

## UDP-native improvements (explicit, not inherited)

| Area | TCP today | UDP design |
|------|-----------|------------|
| Nonce | `[0000‖counter]` prepended (12 B/pkt) | derived from `seq`+session prefix, **not transmitted** (−12 B/pkt; ROADMAP #2) |
| Demux / roaming | one TCP conn per peer | random per-frame connection index; address rebind only after an authenticated packet |
| Rekey activation | in-order trial-decrypt, promote+discard | explicit 1-byte epoch (in AAD) per frame; reorder-safe |
| Replay window | 64 entries | ≥1024 multi-word, single global, reorder-tolerant, never reset |
| Data-path allocs | per packet | zero-alloc in-place encrypt into reused buffer |
| Syscalls | one write/read per packet | batched recvmmsg/sendmmsg |
| Per-packet bookkeeping | `mu.Lock()`+`time.Now()` | atomic timestamp, coarse deadlines |
| Source spoofing/DoS | n/a (TCP) | stateless cookie + anti-amplification (Phase 2) |
| HoL blocking | inherent | none; opens door to parallel per-datagram crypto (future) |

---

## Critical files

- **New:** `pkg/tunnel/datagram.go` (endpoint + index demux + accept channel),
  `pkg/tunnel/dgram_handshake.go` (retransmit/timeout/flight-cache/dedup),
  `pkg/tunnel/reassembly.go` (bounded handshake reassembly),
  `pkg/tunnel/replay.go` (multi-word global window — **new, not extended**),
  `pkg/protocol/datagram_codec.go` (frame + fragment format).
- **Extended (additively, no TCP-path regression):** `pkg/tunnel/session.go`
  (datagram recv path with epoch→cipher selection; reuse `DeriveRekeySecret` /
  pending-cipher derivation), `internal/constants/constants.go` (UDP MTU,
  payload cap, fragment limits, window size, epoch width),
  `pkg/protocol/messages.go` (cookie/retry + fragment headers),
  `pkg/tunnel/limiter.go` (per-src half-open cap; reuse existing limiters).
- **Reused unchanged:** `pkg/chkem`, `pkg/crypto` (aead, kdf, random), `Session`
  secret/rekey derivation.

---

## Implementation order

1. `datagram_codec.go` frame/fragment encode+decode + unit tests (pure, no I/O).
2. `replay.go` multi-word window + table-driven reorder/dup tests.
3. `reassembly.go` bounded reassembler + bounds/timeout tests.
4. `datagram.go` endpoint skeleton: UDPConn, index table, accept channel, demux.
5. `dgram_handshake.go` bilateral retransmit FSM + responder flight cache;
   wire in `chkem` Encapsulate/Decapsulate and existing Hello/Finished encoders.
6. Epoch cipher selection on the datagram recv path in `session.go`; close the
   data plane (`Send`/recv) with the new framing + replay window.
7. Limiter integration + reserved cookie/retry fields (no enforcement yet).
8. Phase-1a verification suite + loopback baseline. **Then** Phase 1b. **Then**
   Phase 2 in a separate PR.

---

## Verification

- **Phase 1a (correctness):** a deterministic, seeded fault-injection
  `net.PacketConn` (configurable drop/reorder/duplicate rates) drives tests for
  fragmentation+reassembly, handshake completion under drop/reorder/dup, rekey
  under reorder (epoch selection + previous-epoch retention + retirement), replay
  window under reorder, reassembly memory bounds, half-open caps. `go test ./...
  -race`. Establish a loopback-UDP throughput + handshakes/sec baseline.
- **Phase 1b (performance):** `testing.AllocsPerRun == 0` on the send path;
  loopback-UDP throughput with/without batched I/O vs the 1a baseline
  (benchstat); confirm no correctness regression under `-race`.
- **Phase 2:** spoofed-source/amplification tests (unverified source can neither
  create session state nor elicit a larger-than-received response), cookie
  round-trip, address-rebind only after an AEAD-valid packet; fuzz parser +
  reassembler + cookie path.

## Out of scope (future)

GSO/GRO offload, PMTU discovery, multipath, parallel per-datagram crypto pipeline
(revisit after the Phase-1 baseline is measured).

---

## Open items to confirm during implementation (the **[VERIFY]** list)

1. Current location/shape of the 64-entry replay window (no `replay.go` exists).
2. How `Session` stores current/pending ciphers + the rekey state machine entry
   points (`DeriveRekeySecret`, pending-cipher promotion) — to add an
   epoch-keyed selection without touching the TCP path.
3. Exact `pkg/protocol` encoder names (`EncodeClientHello`/`ServerHello`/
   `Finished`) and current Hello sizes (drives fragment header widths).
4. `pkg/chkem` `Encapsulate`/`Decapsulate` entry points (responder must cache,
   not re-run, Encapsulate).
5. `pkg/crypto/aead.go` in-place/append AEAD entry points and
   `pkg/crypto/random.go` CSPRNG helper (reuse for zero-alloc + index gen).
6. `HandshakeLimiter` / `IPRateLimiter` signatures in `limiter.go`.
7. Ticket `Resume`/`ExportTicket` API in `ticket.go`.
