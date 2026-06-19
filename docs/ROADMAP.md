# Quantum-Go Development Roadmap

**Version:** 4.2
**Last Updated:** 2026-06-19

---

## Current Status: v0.0.12

> **Direction.** Next is **stream security parity**: bring the TCP/stream path up to the
> datagram path and clear the hardening backlog (role binding, ticket server binding,
> 1024-bit stream replay window, session-bound stream nonce, real `.text` module integrity,
> CI security). After that, **crypto-agility and endpoint authentication** toward v0.1.0
> (HQC code-based KEM diversification for a CH-KEM v2 triple cascade; peer authentication).

## Strategic Priorities (valuation-driven)

For a cryptographic library, market evaluation is gated by reduction of trust-uncertainty, not
feature count. Stream-security parity (above) remains the immediate near-term cleanup. Beyond it,
the next major arc is sequenced by credibility impact, not by version-tag order:

1. **Endpoint authentication** (v0.1.0 #1). Today there is none: any party can impersonate any
   server, so an unauthenticated tunnel is a demo, not a deployable product. This is the single
   biggest blocker and is pulled to the front of the arc.
2. **Formal verification** (v0.1.0; Lafourcade influence, see [Design Influences](DESIGN_INFLUENCES.md)).
   Labor, not capital. A machine-checked proof of the CH-KEM composition is the highest credibility
   gain per dollar and the clearest differentiator versus other Go PQ libraries.
3. **Standards-conformant hybrid combiner interop** (v1.0.0; see Design Influences 2.8). Removes the
   bespoke-island liability by mapping the combiner to a published proof and enabling an interop profile.
4. **Third-party audit + real FIPS 140-3 validation** (v1.0.0 prerequisites). The capital-gated
   commercialization gate; sequenced after auth and formal verification make it worth paying for.

These sit explicitly *ahead of* the enterprise tooling tier (config management, HSM glue, Helm/Terraform),
which is table-stakes packaging rather than a valuation multiplier.

### Completed Features
- [x] CH-KEM hybrid key exchange (X25519 + ML-KEM-1024)
- [x] Network Rekey Protocol (handshake and activation)
- [x] Session Resumption (encrypted tickets)
- [x] Alert Protocol (standardized error reporting)
- [x] Graceful shutdown with CloseNotify
- [x] Comprehensive test suite (85%+ coverage on core packages)
- [x] Replay protection (sliding window)
- [x] Connection pooling with health checking
- [x] Buffer pooling (75%+ allocation reduction)
- [x] Rate limiting and DoS protection
- [x] Prometheus metrics and OpenTelemetry tracing
- [x] FIPS 140-3 build mode with POST/CST self-tests
- [x] Regulatory clarity (EU open source exemption, user deployment guidance)
- [x] UDP/datagram transport (fragmented PQ handshake, encrypted data plane, reliable rekey, stateless cookie/anti-amplification, authenticated roaming, SO_REUSEPORT receive scaling, UDP_GRO offload)
- [x] Stream handshake timeout on Accept (slow-loris bound); honest KAT-vector module-integrity check

---

## Completed Releases

### v0.0.6 - Hardening & Observability
**Theme:** Production hardening and operational visibility.

#### 1. Rate Limiting & DoS Protection
**Priority:** High | **Effort:** Medium

- [x] Add connection rate limiting (per IP)
- [x] Add handshake rate limiting
- [x] Add configurable limits via `TransportConfig`
- [x] Add metrics for rate limit events

#### 2. Metrics & Observability
**Priority:** High | **Effort:** Medium

- [x] Add Prometheus-compatible metrics export
- [x] Add OpenTelemetry tracing support
- [x] Add structured logging with levels
- [x] Add health check endpoint for CLI server mode

#### 3. Connection Pooling
**Priority:** Medium | **Effort:** Medium

- [x] Implement connection pool with configurable size
- [x] Add idle connection timeout
- [x] Add health checking for pooled connections
- [x] Add pool statistics

#### 4. Buffer Pooling
**Priority:** Low | **Effort:** Low

- [x] Pool message buffers using `sync.Pool`
- [x] Pool encryption/decryption buffers
- [x] Add benchmarks comparing pooled vs non-pooled

---

### v0.0.7 - FIPS Mode
**Theme:** FIPS 140-3 compliance preparation.

#### 1. FIPS Build Mode
**Priority:** High | **Effort:** Medium

- [x] Add `//go:build fips` conditional compilation
- [x] Disable ChaCha20-Poly1305 in FIPS mode (AES-GCM only)
- [x] Add FIPS mode indicator in session/transport
- [x] Add runtime FIPS mode check
- [x] Document FIPS deployment requirements

#### 2. Power-On Self-Tests (POST)
**Priority:** High | **Effort:** Medium

Required for FIPS 140-3 validation.

- [x] Implement POST for ML-KEM (KAT check on init)
- [x] Implement POST for AES-GCM (KAT check on init)
- [x] Implement POST for SHAKE-256 (KAT check on init)
- [x] Add integrity check (hash of module binary)
- [x] Add failure handling (panic or degraded mode)

#### 3. Conditional Self-Tests
**Priority:** Medium | **Effort:** Low

- [x] Add pairwise consistency test on key generation
- [x] Add DRBG health check on RNG output

---

### v0.0.8 - Regulatory & Documentation Clarity
**Theme:** Clear regulatory guidance and documentation improvements.

#### 1. Open Source Export Status
**Priority:** High | **Effort:** Low

- [x] Document EU Dual-Use Regulation exemption for public domain software
- [x] Clarify project origin (Spain/EU) and applicable regulations
- [x] Reframe US/BIS guidance as user deployment consideration (not developer obligation)
- [x] Distinguish developer obligations vs user deployment responsibilities

#### 2. User Deployment Guidance
**Priority:** High | **Effort:** Low

- [x] Reframe regulatory section as guidance for deployers
- [x] Add "User Action" items for 15+ jurisdictions
- [x] Document that open source on GitHub is generally exempt
- [x] Clarify restrictions in highly regulated zones (must not bypass telecom regulations)

---

### v0.0.9 - Security Hardening Phase 1 (Completed)

**Theme:** Critical protocol-level security fixes identified by internal security audit.
**Released:** 2026-03-13

> These findings addressed protocol composition weaknesses. The cryptographic primitives
> (ML-KEM, X25519, SHAKE-256, AEAD) are correctly implemented at the algorithm level.
> The fixes are in how they are composed in the handshake, resumption, and rekey protocols.

#### 1. Session Resumption Forward Secrecy
**Priority:** Critical | **Effort:** High

- [x] Perform fresh CH-KEM exchange during resumption (PSK + ECDHE mode)
- [x] Mix ticket master secret with fresh KEM shared secret via `DeriveResumptionSecret`
- [x] Ensure resumed sessions derive unique traffic keys per session
- [x] Add test: verify resumed session keys differ from original session keys
- [x] Add test: verify forward secrecy holds when ticket key is compromised

**Reference:** TLS 1.3 PSK with (EC)DHE key exchange (RFC 8446, Section 2.2)

#### 2. Verify Data Shared Secret Binding
**Priority:** Critical | **Effort:** Medium

- [x] Include shared secret in verify_data derivation via `DeriveKeyMultiple`
- [x] Use domain-separated construction: `SHAKE-256(shared_secret || transcript || label)`
- [x] Add test: verify that different shared secrets produce different verify_data

**Reference:** TLS 1.3 Finished = HMAC(finished_key, transcript_hash) (RFC 8446, Section 4.4.4)

#### 3. Rekey Message Authentication
**Priority:** Critical | **Effort:** High

- [x] Encrypt rekey messages using current session AEAD keys
- [x] Rekey wire format changed to `[Type] [Len] [Seq(8B)] [AEAD-Ciphertext]`
- [x] Add test: verify forged rekey messages are rejected
- [x] Add test: verify rekey succeeds through encrypted channel
- [x] Add test: verify public key not visible in plaintext on the wire
- [ ] Authenticate Ping/Pong/Close control messages (deferred to v0.0.10)

#### 4. Key Material Zeroization
**Priority:** Critical | **Effort:** Medium

- [x] Use `runtime.KeepAlive` after zeroing to prevent dead store elimination
- [x] Replace custom `ConstantTimeCompare` with `crypto/subtle.ConstantTimeCompare`
- [x] Remove fragile alias-based zeroization pattern in `deriveHandshakeKeys`, `InitializeKeys`, and `Rekey`
- [x] Add test: verify `Zeroize` actually writes zeros (read back after call)
- [ ] Document CIRCL/ecdh limitation: private key bytes cannot be zeroed externally (deferred)

#### 5. Iterative Message Handling
**Priority:** High | **Effort:** Low

- [x] Replace recursive `Receive()` with iterative loop
- [x] Add test: verify handling of 10,000+ consecutive Ping messages without crash

#### 6. Rekey Forward Secrecy (Key Ratcheting)
**Priority:** Critical | **Effort:** Low

- [x] Wire existing `DeriveRekeySecret(oldMasterSecret, freshKEMSecret)` into rekey flow
- [x] Derive traffic keys from ratcheted secret, not raw KEM output
- [x] Zeroize intermediate fresh KEM secret after mixing

**Impact:** Compromise of a single rekey no longer exposes all subsequent traffic.

#### 7. KDF Error Handling (Panic Elimination)
**Priority:** Critical | **Effort:** Low

- [x] Replace `panic()` with error returns in `TranscriptHash`
- [x] Update all callers (chkem `Encapsulate`/`Decapsulate`, tests, benchmarks)

**Impact:** Malformed peer data can no longer crash the tunnel process.

#### 8. Error Message Sanitization
**Priority:** High | **Effort:** Low

- [x] Replace `err.Error()` with generic "handshake failed" in all 8 `sendHandshakeAlert` calls
- [x] Add test: verify alert wire data contains only generic description
- [x] Add IP address masking in rate limit logging (`maskIP()`)
- [x] Remove crypto material from test log output (`t.Logf`)

#### 9. Dependency Upgrades & Go 1.26
**Priority:** High | **Effort:** Low

- [x] Upgrade Go from 1.24 to 1.26 (`runtime/secret`, Green Tea GC, ~18% faster ML-KEM)
- [x] Upgrade `golang.org/x/crypto` v0.47.0 -> v0.49.0 (SSH CVE fixes)
- [x] Upgrade `go.opentelemetry.io/otel` v1.39.0 -> v1.42.0
- [x] Upgrade `golang.org/x/sys` v0.40.0 -> v0.42.0

---

## Upcoming Releases

### v0.0.10 - Cryptographic Protocol Hardening

**Theme:** Address identified mathematical and protocol-level weaknesses in how
cryptographic primitives are composed. The primitives themselves are sound; the
composition needs strengthening.
**Target:** Q2 2026

> **Status:** v0.0.10 shipped as *Data-Plane Rekey Reliability & Throughput* (see
> CHANGELOG): the rekey send-deadlock fix, dual-cipher trial-decryption activation
> (item #6 below, delivered without a new wire message), the boundary-packet replay fix,
> the 64 GiB rekey-byte threshold, and the stdlib `crypto/sha3` migration. v0.0.11 then
> shipped the datagram transport plus two of these items - handshake timeout (#4) and an
> honest KAT-vector module-integrity check (#7, full `.text` integrity still pending). The
> rest (role binding, ticket server binding, and the stream-path nonce/replay catch-up)
> carry forward to the stream-security-parity release.

#### 1. Role Binding in CH-KEM Transcript
**Priority:** Critical | **Effort:** Small

The CH-KEM transcript hash included public keys and ciphertext but NOT the role
(initiator/responder) or protocol version. This enabled role-confusion/reflection
where an initiator could be tricked into completing a handshake with itself.

- [x] Add role indicator byte to `TranscriptHash` components in `Encapsulate`/`Decapsulate`
- [x] Add protocol version to transcript hash
- [x] Add test: legit (responder encapsulate / initiator decapsulate) produces matching secrets
- [x] Add test: same role on both sides produces mismatched secrets (reflection resistance)

> **Done (Unreleased).** Both `Encapsulate`/`Decapsulate` bind the protocol version and the
> encapsulating (responder) role into the transcript. `ProtocolVersion` bumped to `0x0002` and the
> wire version to `2.0` (wire-incompatible with prior builds; mismatched peers rejected cleanly). This
> is composition hardening, not authentication, and does not stop an active relaying MitM. Measured
> cost about +1% per KEM operation, no allocation change, no data-plane impact.

**Reference:** NIST SP 800-56C Rev. 2 (context/role in KDF)

#### 2. AEAD Nonce Session Binding
**Priority:** Critical | **Effort:** Small

AEAD nonces use format `[0000 || counter(8B)]`. Two sessions with the same key
produce identical nonce sequences, breaking GCM confidentiality guarantees.

- [ ] Add 4-byte `noncePrefix` field to AEAD struct, populated from session ID
- [ ] Nonce format becomes `[sessionID[0:4] || counter(8B)]`
- [ ] Update all 10 `NewAEAD()` call sites to pass session ID prefix
- [ ] Add test: verify two sessions with same key produce different nonces

> Scope: this item tracks the **stream/TCP** path. The datagram transport already
> ships session-bound nonces by construction (`nonce = derived 4-byte prefix || seq`,
> never transmitted; see UDP / Datagram Transport below). This item closes the gap
> on the stream path only.

**Reference:** NIST SP 800-38D Section 8.2 (deterministic nonce construction)

#### 3. Resumption Ticket Server Binding
**Priority:** High | **Effort:** Small

Resumption tickets are not bound to the server that issued them. A captured ticket
can be replayed against a different server that shares the same ticket encryption key.

- [ ] Include `SHA-256(server_public_key)` in ticket plaintext
- [ ] Validate server identity on ticket decryption
- [ ] Add test: verify ticket from server A is rejected by server B

#### 4. Handshake Timeout
**Priority:** High | **Effort:** Low

`Listener.Accept()` calls `ResponderHandshake` with no timeout. A malicious client
can connect and never send data, exhausting goroutines and file descriptors.

- [x] Set `conn.SetDeadline` before `ResponderHandshake` (v0.0.11)
- [x] Make handshake timeout configurable via `TransportConfig` (default: 30s) (v0.0.11)
- [x] Add test: verify slow-loris style connections are terminated (v0.0.11)

#### 5. Replay Window Expansion
**Priority:** Medium | **Effort:** Small

Current replay window is only 64 packets. At 1 Gbps with 1500-byte packets
(~83,000 pps), this gives <1ms tolerance for out-of-order delivery.

- [ ] Increase replay window to 1024+ using multi-word bitmap
- [ ] Add test: verify out-of-order packets within window are accepted
- [ ] Add benchmark: measure replay check overhead at larger window sizes

> Scope: this item tracks the **stream/TCP** path's 64-entry window. The datagram
> transport already uses a 1024-bit multi-word window (`DatagramReplayWindow`,
> `pkg/tunnel/replay.go`), never reset across rekey. This item carries that design
> back to the stream path.

#### 6. Rekey Activation Confirmation (DONE in v0.0.10, via trial decryption)
**Priority:** Critical (was Medium) | **Effort:** Medium

The fixed +16 sequence offset failed at speed: the sender outran the rekey round-trip,
so the responder switched its receive key while the initiator was still sending under the
old key, dropping the connection. Solved without a new wire message; each side switches
its send cipher explicitly and promotes its receive cipher lazily via dual-cipher trial
decryption (try current, fall back to pending). Reliable under load and high latency.

- [x] Reliable activation under load/latency (dual-cipher trial decryption)
- [x] Add test: rekey completes when the sender outruns the round-trip
- [ ] (Superseded) explicit rekey-ack message type, unnecessary with trial decryption

#### 7. Module Integrity Verification
**Priority:** Medium | **Effort:** Medium

`CheckModuleIntegrity()` used to unconditionally return `Verified: true` with a placeholder
hash. v0.0.11 made it honest: a real comparison of the embedded KAT vectors against a pinned
hash, scoped in the docs as KAT-vector integrity, not binary `.text` integrity.

- [x] Pin the real KAT-vector hash and report a real comparison; document the scope (v0.0.11)
- [ ] Implement build-time `.text`/binary HMAC embedding (full module integrity)
- [ ] Compare actual vs expected `.text` hash at runtime
- [ ] In FIPS mode: fail hard if the `.text` integrity check fails

#### 8. CI Security Improvements (DONE)
**Priority:** Medium | **Effort:** Low

- [x] Remove `-no-fail` from Gosec scanner configuration (all current findings triaged: 14 bounded G115 conversions + the KAT-nonce G407, each with a justified `#nosec`; one replay cast rewritten to drop the conversion)
- [x] Add FIPS build/test job: `go test -tags fips -race ./...`
- [x] Add `go vet` to CI (`go vet` has no `-race`; race stays on the test job)
- [x] Benchmark tool data race: already resolved (`cmd/quantum-tunnel/bench.go` uses `atomic.Int64`)

---

## UDP / Datagram Transport (Phased Epic)

A connectionless datagram transport that complements the TCP/stream transport.
The two share the crypto core (`pkg/chkem`, `pkg/crypto`, and the `Session`
key/rekey secret derivation) but have **separate wire formats** with no interop,
by design. See [datagram-transport.md](datagram-transport.md) for the wire format
and design rationale.

The datagram path is a clean-sheet design that improves on (does not inherit) the
stream stack: a derived, never-transmitted nonce (`prefix || seq`), demux by random
connection index (NAT/roam survivable), explicit per-frame epoch for reorder-safe
rekey, and a 1024-bit never-reset replay window. It therefore realizes roadmap
items #2 (nonce session binding) and #5 (replay window expansion) natively for UDP.

### Phase 1a - Functional data plane

- [x] Datagram wire codec, fragmentation, bounded reassembler
- [x] Endpoint + index demux + accept channel
- [x] Reliable handshake (fragmented PQ flights, retransmission/backoff, flight cache)
- [x] 1024-bit multi-word replay window
- [ ] Per-session derived nonce prefix + datagram key init
- [ ] Epoch-keyed cipher selection on the datagram recv path
- [ ] Encrypted DATA send/recv + public `DatagramConn` (`Send`/`Recv`/`Close`/`Accept`)
- [ ] Authenticated CLOSE (AEAD-verified before teardown)
- [ ] Datagram rekey transport (reliable RekeyInit/Response over the lossy channel)
- [ ] Idle-timeout reaper
- [ ] Fault-injection test suite + loopback throughput baseline

### Phase 1b - Performance

- [x] Zero-alloc steady-state data path (in-place AEAD into a reused buffer)
- [x] Batched syscalls (`recvmmsg`/`sendmmsg` via `golang.org/x/net` `ipv4`/`ipv6`)
- [x] Coarse deadlines / atomic activity timestamp (no per-packet `time.Now()`)
- [x] `SO_REUSEPORT` multi-socket receive (demux + AEAD-open spread across cores; ~1.6x aggregate on 8 cores)
- [x] `UDP_GRO` receive offload behind `WithDatagramOffload()` (kernel coalesces a burst, receive loop re-splits; Linux-only, opt-in)
- [ ] `UDP_SEGMENT` (GSO) send offload (fewer send syscalls; needs a batched-send seam, measurement-gated)
- [ ] Parallel per-datagram crypto pipeline

### Phase 2 - DoS / amplification hardening

- [ ] Stateless retry cookie (no server state until source proves reachability; reuses the reserved cookie field, no wire change)
- [ ] Anti-amplification bound (never send more than received to an unverified source)
- [ ] Authenticated address rebinding (roaming only after an AEAD-valid packet)
- [ ] Threat-model doc + fuzz targets (parser, reassembler, cookie) + spoofed-source negative tests
- [ ] Optional fixed-size datagram padding (traffic-analysis resistance)

---

### Enterprise Features (post stream-parity)

**Theme:** Enterprise deployment readiness. Table-stakes packaging, sequenced after the credibility
work in Strategic Priorities (authentication, formal verification, audit), not before it.
**Target:** unscheduled (was mislabeled v0.0.11, which shipped as the datagram transport release)

#### 1. Configuration Management
**Priority:** High | **Effort:** Medium

- [ ] YAML/TOML configuration file support
- [ ] Environment variable overrides
- [ ] Configuration validation and error reporting
- [ ] Hot-reload for non-cryptographic settings

#### 2. HSM Integration
**Priority:** High | **Effort:** High

- [ ] PKCS#11 interface for key storage
- [ ] Support for AWS CloudHSM / Azure Dedicated HSM
- [ ] Key escrow and backup mechanisms
- [ ] HSM health monitoring

#### 3. Deployment Tooling
**Priority:** Medium | **Effort:** Medium

- [ ] Systemd service unit files
- [ ] Docker Compose examples
- [ ] Kubernetes deployment manifests (Helm chart)
- [ ] Terraform modules for cloud deployment

---

### v0.1.0 - Authentication & Audit Preparation

**Theme:** Add endpoint authentication and prepare for third-party security audit.
**Target:** Q4 2026

#### 1. Endpoint Authentication
**Priority:** Critical | **Effort:** High

The protocol provided no pre-handshake authentication. Any party could impersonate
any server. This is the most fundamental missing security property. Static-key
pinning (stream path) now closes it for the pinned-server case; the rest follows.

- [x] PSK-based mutual authentication mode (pre-shared symmetric key) -
  `TransportConfig.PSK`/`PSKIdentity` and datagram `WithPSK`; a 32-byte PSK folds
  into the master secret (domain-separated from the static fold), composes with
  static-key pinning, and fails closed at the Finished MAC on mismatch. Protocol 2.2
- [x] Static key verification mode (pin remote public key) - stream and datagram;
  client encapsulates a second CH-KEM leg to the pinned server key, folds it into
  the master secret, fails closed with `ErrServerKeyMismatch`.
- [x] Include authentication proof in ClientHello (optional static-KEM ciphertext)
- [x] Add test: verify unauthenticated/wrong-pin peer is rejected
- [x] Add test: verify authenticated peer is accepted
- [x] Datagram path wiring (`WithStaticIdentity`/`WithPinnedServerKey`) - wrong-pin
  fails closed as a retry-ceiling timeout (no fail-fast signal yet)
- [x] `quantum-tunnel keygen` CLI for static-key generation and pin distribution -
  writes a base64 secret seed (mode 0600) and public pin, prints an `SHA256:`
  fingerprint, and re-derives the pin from a seed via `--pub-from`
- [x] Server-side require-auth (`TransportConfig.RequireStaticAuth`, datagram
  `WithRequireStaticAuth`) - rejects unpinned clients with `ErrStaticAuthRequired`
  (stream) or a retry-ceiling timeout (datagram); misconfiguration without a static
  key fails closed with `ErrStaticAuthMisconfigured`
- [ ] Document authentication modes in SECURITY.md

**Reference:** WireGuard static key authentication, TLS 1.3 PSK mode (RFC 8446 Section 2.2)

#### 2. Code Quality
**Priority:** High | **Effort:** Medium

- [ ] Static analysis report (golangci-lint, gosec)
- [ ] Code documentation for all exported symbols
- [ ] Architecture documentation
- [x] Threat model documentation (self-authored, [THREAT_MODEL.md](technical/THREAT_MODEL.md); independent audit still pending)

#### 3. Security Testing
**Priority:** High | **Effort:** High

- [ ] Fuzzing infrastructure for protocol parsing
- [ ] Negative testing for error paths
- [ ] Timing attack resistance verification
- [ ] Memory safety validation

#### 4. Compliance Documentation
**Priority:** High | **Effort:** Medium

- [ ] NIST SP 800-131A compliance checklist
- [ ] FIPS 140-3 compliance mapping
- [ ] SOC 2 relevant controls documentation

---

### v1.0.0 - Production Release

**Theme:** First production-ready, stable release.
**Target:** 2027

#### Prerequisites
- [ ] All v0.0.6-v0.0.11 features complete
- [ ] Third-party security audit completed
- [ ] Security audit findings remediated
- [ ] Performance benchmarks published
- [ ] API stability guarantee (semantic versioning)
- [ ] Migration guide from pre-release versions

#### Release Artifacts
- [ ] Signed binaries for Linux, macOS, Windows
- [ ] Docker images (multi-arch)
- [ ] Package manager releases (Homebrew, APT, etc.)
- [ ] Go module stable release

#### Documentation
- [ ] Complete API reference
- [ ] Deployment guide
- [ ] Operations runbook
- [ ] Troubleshooting guide

---

## Global Compliance & Regulatory Considerations

> **CAUTION**
> **Advisory Only**: The following compliance information is based on public regulatory documentation and is provided for **informational purposes only**. It does **NOT** constitute legal advice. Organizations must consult with their own legal counsel and trade compliance officers before deploying this software.

> **Note for Users**: This section describes regulatory considerations for **users deploying** Quantum-Go in various jurisdictions. As an open-source project publicly available on GitHub, the software may be eligible for export control exemptions under "public domain" provisions in some jurisdictions, but this determination depends on specific circumstances and applicable law.

### Cryptographic Export Controls

#### European Union (Project Origin)
- **Dual-Use Regulation (EU 2021/821)**: Governs encryption exports from EU member states.
- **Open Source Exemption**: Article 2(2) provides a potential exemption for software "in the public domain" (publicly available without restrictions).
- **Status**: Quantum-Go is MIT-licensed open source on GitHub and may be eligible for this exemption. Deployers should verify applicability with legal counsel.

#### United States
- **EAR (Export Administration Regulations)**: ECCN 5D002 applies to encryption software.
- **License Exception TSU**: Publicly available open-source software may qualify for exemption.
- **For US-based deployers**: Commercial use may require BIS notification; consult compliance counsel.

#### For Users Deploying in Regulated Jurisdictions

The following jurisdictions have specific requirements for **users deploying** encryption software:

#### China
- **Commercial Cryptography Regulations**: Foreign cryptographic products may require certification for commercial use.
- **User Action**: Organizations deploying in China should consult local compliance counsel.

#### Russia
- **FSB Certification**: Required for cryptographic products in certain regulated sectors.
- **User Action**: Quantum-Go is not certified for regulated use in Russia.

#### Australia
- **Defence Trade Controls Act (DTCA)**: Controls supply of DSGL technology.
- **Wassenaar Arrangement**: Australia is a signatory; strong encryption is controlled.
- **User Action**: Deployers should verify DSGL status for their use case.

#### France
- **ANSSI Regulations**: Commercial supply may require declaration or authorization.
- **User Action**: Commercial deployers should verify ANSSI requirements.

#### India
- **Department of Telecommunications (DoT)**: ISP/Telecom licenses may have encryption restrictions.
- **DPDP Act 2023**: Mandates security but government retains decryption/interception powers.
- **User Action**: Deployers should understand "traceability" requirements for substantial intermediaries.

#### Latin America (LATAM)
- **Brazil (ANATEL)**: Act 77/21 prohibits hardcoded keys/backdoors in telecom equipment.
- **Mexico**: Wassenaar signatory with dual-use controls.
- **User Action**: Commercial deployers should verify local requirements.

#### United Kingdom
- **Post-Brexit**: Retained EU Dual-Use Regulation (2021/821).
- **NCSC Guidance**: CPA recommended for government use.
- **User Action**: Open source may be covered by OGEL; commercial use may differ. Verify with legal counsel.

#### Israel
- **Defense Export Control**: Strictly regulated; commercial/defense distinction is critical.
- **User Action**: Defense sector use requires separate licensing.

#### Asia-Pacific (APAC)
- **Japan (METI)**: Encryption is a controlled item under catch-all controls.
- **Singapore**: Strategic Goods (Control) Act applies.
- **User Action**: Commercial deployers should assess licensing requirements.

#### Middle East
- **UAE & Saudi Arabia**: tunnel usage to bypass telecom restrictions is illegal.
- **Data Residency**: In-country data storage often mandated.
- **User Action**: Must not be used to bypass telecommunications regulations.

### Data Sovereignty

- [ ] Add deployment guidance for data residency requirements
- [ ] Document key storage location considerations
- [ ] Add region-specific configuration examples

### Industry Compliance

#### Financial Services
- [ ] PCI DSS compliance documentation
- [ ] SOC 2 Type II relevant controls
- [ ] Banking regulatory alignment (OCC, FCA, MAS)

#### Healthcare
- [ ] HIPAA technical safeguards mapping
- [ ] HITECH Act considerations

#### Government
- [ ] FedRAMP readiness assessment
- [ ] NATO RESTRICTED / EU RESTRICTED suitability

---

## Future Considerations (v1.1.0+)

### Potential Features
- **ML-KEM-768 support** - NIST Category 3 for constrained environments
- **Certificate-based authentication** - X.509 with PQ signatures (ML-DSA)
- **Multi-path transport** - Redundant connections for reliability
- **Hardware acceleration** - AES-NI and AVX optimization verification
- **WebSocket transport** - For firewall traversal

### Research Items
- **ML-DSA integration** - Post-quantum signatures for authentication
- **Hybrid certificates** - Dual classical/PQ certificate chains
- **SLH-DSA (SPHINCS+)** - Stateless hash-based signatures as alternative
- **CH-KEM v2: code-based KEM diversification (HQC)** - Add a third, family-diverse
  KEM member so the cascade is secure if ANY of {structured lattice (ML-KEM),
  code-based (HQC), classical ECDH (X25519)} holds, hedging a hypothetical
  lattice-family break. HQC is NIST's selected code-based backup KEM (March 2025);
  it is the only standardized, MTU-workable code-based option (Classic McEliece's
  ~1 MB public key is impractical for the datagram handshake; BIKE was not selected).
  Prerequisites and costs, in order: (1) a small KEM-agility interface in `pkg/chkem`
  so cascade members are pluggable (today ML-KEM-1024 + X25519 are hardcoded);
  (2) HQC-256 to match Category 5, which carries a ~7 KB public key and ~14.5 KB
  ciphertext - the datagram handshake grows from ~2 fragments to ~13+, so it leans
  harder on the existing fragmenter/reassembler and is more loss-sensitive;
  (3) verify HQC support and parameter set in `cloudflare/circl` before committing.
  Not urgent: the current ML-KEM-1024 + X25519 hybrid already backstops a lattice
  weakening classically and a quantum adversary post-quantumly, so this is
  defense-in-depth diversification, not a fix for a present exposure.

### Adapted Research Directions

Techniques adapted from published PQ cryptography research. See [Design Influences](DESIGN_INFLUENCES.md) for full attribution and differentiation.

| Technique | Target | Source |
|-----------|--------|--------|
| Labeled component hashing (KEM binding) | v0.0.10 | Cremers et al. CCS '24 |
| Two-tier rekey cadence (KDF ratchet + full KEM) | v0.0.11 | Rosenpass (Varner et al.) |
| CPA-only ephemeral KEM for lightweight rekey | v0.0.11 | Kudelski/Stebila-Mosca |
| Formal verification in ProVerif/Tamarin | v0.1.0 | Lafourcade et al. USENIX Sec '25 |
| 3-message handshake optimization | v1.0.0+ | Schwabe et al. IEEE S&P '21 |
| Stateless responder / DoS resilience cookie | v1.0.0+ | Rosenpass biscuit pattern |
| Standardized hybrid KEM combiner (interop + proof reuse) | v1.0.0 | X-Wing (Barbosa et al. '24), CFRG hybrid-KEM |

---

## Contributing

See [CONTRIBUTING.md](../CONTRIBUTING.md) for development setup and contribution guidelines.

When picking up a task:
1. Create an issue or comment on existing one
2. Create a feature branch from `develop`
3. Implement with tests
4. Submit PR with description referencing this roadmap

---

*Document Version: 4.2*
*Last Updated: 2026-06-19*
