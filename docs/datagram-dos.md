# Datagram transport: DoS threat model and anti-amplification

This document covers the denial-of-service posture of the UDP/datagram transport
and the stateless return-routability cookie that hardens its handshake. For the
transport's wire format and handshake mechanics see
[datagram-transport.md](datagram-transport.md).

## Threat

UDP source addresses are trivially spoofable, so a connectionless handshake has
two classic abuse surfaces:

- **State / CPU exhaustion.** An attacker floods handshake initiations from forged
  sources. For each, a naive server allocates per-source reassembly buffers and
  runs an expensive CH-KEM `Encapsulate`, exhausting memory or CPU without ever
  completing a handshake.
- **Reflection / amplification.** Because the server's `ServerHello` (~1.6 KB) is
  larger than the triggering `ClientHello` fragment, a spoofed initiation makes the
  server reflect amplified traffic at a victim whose address the attacker forged.

The dominant exhaustion vector specifically is **reassembler occupancy**: the PQ
`ClientHello` spans multiple datagrams, so an attacker can send only the leading
fragment from each of many forged sources, filling the reassembler's global
source table and never completing a message. Any defense keyed on *completed*
handshakes (e.g. a half-open responder count) would never see this attack.

## Defense: load-gated stateless cookie

Before committing reassembly buffers or CH-KEM work for a source it does not
already track, the endpoint can demand a **return-routability cookie** the source
must echo. An off-path spoofer never receives the cookie (it goes to the forged
address), so it cannot proceed. This is the QUIC `RETRY` posture.

- **Stateless.** A cookie is `HMAC-SHA256(secret, addr || issue_time)` plus the
  8-byte issue time; the server keeps no per-source state to issue or verify one.
  The 32-byte secret is drawn from the CSPRNG per endpoint at startup. (See
  `pkg/tunnel/dgram_cookie.go`.)
- **Load-gated.** The gate is inactive under normal load, so honest handshakes add
  zero round trips. It engages only when the endpoint is under pressure, defined as
  either the in-progress reassembly source count **or** the global half-open count
  crossing `DatagramCookiePressureHighWater` (half of the hard half-open cap). The
  two signals are complementary: reassembler occupancy catches the
  partial-fragment flood, the half-open count catches a completed-ClientHello /
  CH-KEM flood.
- **Pre-reassembly.** The gate sits in `routeDatagram` *before* `reasm.Add`, so a
  rejected frame allocates no reassembly buffer and triggers no CH-KEM. Verifying a
  cookie (one HMAC over ~40 bytes) is far cheaper than the buffer it prevents.
- **Keyed on "known source", not `RecvIndex`.** The gate lets through only sources
  already tracked (an established session by connection index, or an in-progress
  responder by source address). Gating on tracked-ness rather than on
  `RecvIndex == 0` is what stops an attacker from dodging the gate by stamping a
  random nonzero `RecvIndex` on a spoofed bootstrap `ClientHello`.

## Anti-amplification

The `RETRY` carrying a cookie is `DatagramHeaderSize + cookieSize` = 14 + 40 = 54
bytes. The server sends it only:

- in response to a `ClientHello` first fragment (`FragOffset == 0`), and
- only when the `RETRY` is no larger than the triggering datagram
  (`len(request) >= len(retry)`).

The size check makes `RETRY` strictly de-amplifying even against a deliberately
tiny runt fragment: the response is never larger than the request, so `RETRY` can
never itself be used as a reflector. A valid cookie replayed from a spoofed
address also buys nothing: the resulting `ServerHello` goes to the bound address,
which the off-path attacker cannot receive.

## Tradeoffs and residual gaps

- **Endpoint-wide pressure.** A flood pushes the whole endpoint into
  cookie-required mode, so honest clients pay one extra round trip for the duration
  of the flood. Per-source pressure scoping is future work.
- **Cookie lifetime.** Cookies are valid for 10 seconds (`cookieLifetime`),
  bounding the replay window for a captured cookie from the same address.
- **Secret rotation is restart-only.** A process restart rotates the cookie secret
  and invalidates outstanding cookies, costing one extra `RETRY` round trip on the
  next attempt. Periodic in-process rotation (with a two-generation accept window
  so a rotation does not invalidate in-flight cookies) is future work.
- **Per-source pressure scoping** and a deeper anti-amplification budget are
  future refinements.

## Authenticated roaming

A datagram session is demultiplexed by its connection index, not its source
address, so it can survive a peer changing address (NAT rebind, network change).
The receive loop advances the session's send address (`peerAddr`) to a new source
only when a DATA frame from that source both authenticates (AEAD Open succeeds)
and is replay-fresh (passes the replay window's `Check`). See `routeDatagram` in
`pkg/tunnel/datagram.go`.

Gating the address update on the replay-window `Check` is what makes roaming safe:

- A captured frame replayed from an attacker-controlled address fails `Check`
  (the sequence is already recorded), so an off-path attacker cannot steer the
  session to an address it controls, even though it can copy ciphertext verbatim.
- A forged frame fails AEAD Open, so it never reaches the address update and never
  advances the replay window (the window is recorded only after authentication).
- Only the genuine peer, which holds the send key and produces fresh sequence
  numbers, can move the path.

`peerAddr` is an atomic pointer: the receive loop is the sole writer, while the
send and rekey goroutines read it lock-free, so roaming adds no contention to the
data send path. `DatagramConn.RemoteAddr` reflects the current address and so
follows the peer across a roam.

Residual: there is no explicit path-validation challenge before adopting a new
address (the authenticated-and-fresh test is the validation). An on-path attacker
who can both observe and inject within the live sequence window is out of scope,
as it is for the data plane generally.

## Tests

- `pkg/tunnel/dgram_cookie_test.go` - cookie issue/verify, expiry, address
  binding, tamper rejection, per-endpoint secret isolation.
- `pkg/tunnel/dgram_cookie_gate_test.go` - `knownSource`, global half-open
  accounting, pressure threshold, spoofed-source flood (zero sessions, zero
  reassembly sources, only de-amplifying RETRYs), runt-fragment no-RETRY floor,
  valid-cookie admission, RETRY delivery to the initiator.
- `pkg/tunnel/dgram_handshake_e2e_test.go` - full handshake completing through the
  cookie gate under forced pressure.
- `test/fuzz/datagram_fuzz_test.go` - `FuzzParseDatagramRetry`,
  `FuzzParseDatagramHandshake`.
