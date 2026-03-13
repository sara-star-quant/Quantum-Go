# Quantum-Go Development Roadmap

**Version:** 4.0
**Last Updated:** 2026-03-13

---

## Current Status: v0.0.8

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

## Completed Releases

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

#### 1. Role Binding in CH-KEM Transcript
**Priority:** Critical | **Effort:** Small

The CH-KEM transcript hash includes public keys and ciphertext but NOT the role
(initiator/responder) or protocol version. This enables reflection attacks where
an initiator can be tricked into completing a handshake with itself.

- [ ] Add role indicator byte to `TranscriptHash` components in `Encapsulate`/`Decapsulate`
- [ ] Add protocol version to transcript hash
- [ ] Add test: verify Encapsulate(role=initiator) and Decapsulate(role=responder) produce matching secrets
- [ ] Add test: verify same role on both sides produces mismatched secrets (reflection resistance)

**Reference:** NIST SP 800-56C Rev. 2 (context/role in KDF)

#### 2. AEAD Nonce Session Binding
**Priority:** Critical | **Effort:** Small

AEAD nonces use format `[0000 || counter(8B)]`. Two sessions with the same key
produce identical nonce sequences, breaking GCM confidentiality guarantees.

- [ ] Add 4-byte `noncePrefix` field to AEAD struct, populated from session ID
- [ ] Nonce format becomes `[sessionID[0:4] || counter(8B)]`
- [ ] Update all 10 `NewAEAD()` call sites to pass session ID prefix
- [ ] Add test: verify two sessions with same key produce different nonces

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

- [ ] Set `conn.SetDeadline` before `ResponderHandshake`
- [ ] Make handshake timeout configurable via `TransportConfig` (default: 30s)
- [ ] Add test: verify slow-loris style connections are terminated

#### 5. Replay Window Expansion
**Priority:** Medium | **Effort:** Small

Current replay window is only 64 packets. At 1 Gbps with 1500-byte packets
(~83,000 pps), this gives <1ms tolerance for out-of-order delivery.

- [ ] Increase replay window to 1024+ using multi-word bitmap
- [ ] Add test: verify out-of-order packets within window are accepted
- [ ] Add benchmark: measure replay check overhead at larger window sizes

#### 6. Rekey Activation Confirmation
**Priority:** Medium | **Effort:** Medium

Rekey activation uses a fixed sequence offset (+16 packets). If the responder
hasn't processed the rekey message by then, decryption fails.

- [ ] Add explicit rekey-ack message type
- [ ] Both sides activate only after confirmation exchange
- [ ] Add test: verify rekey completes under high-latency conditions

#### 7. Module Integrity Verification
**Priority:** Medium | **Effort:** Medium

`CheckModuleIntegrity()` unconditionally returns `Verified: true` with a placeholder hash.

- [ ] Implement build-time hash embedding (HMAC of `.text` section or binary)
- [ ] Compare actual vs expected hash at runtime
- [ ] In FIPS mode: fail hard if integrity check fails
- [ ] Alternative: remove `Verified: true` and document as not-yet-implemented

#### 8. CI Security Improvements
**Priority:** Medium | **Effort:** Low

- [ ] Remove `-no-fail` from Gosec scanner configuration
- [ ] Add FIPS build/test job: `go test -tags fips -race ./...`
- [ ] Add `go vet -race` to CI matrix
- [ ] Fix data race in benchmark tool (`atomic.AddInt64` for counters)

---

### v0.0.11 - Enterprise Features

**Theme:** Enterprise deployment readiness.
**Target:** Q3 2026

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

The protocol provides no pre-handshake authentication. Any party can impersonate
any server. This is the most fundamental missing security property.

- [ ] PSK-based mutual authentication mode (pre-shared symmetric key)
- [ ] Static key verification mode (pin remote public key)
- [ ] Include authentication proof in ClientHello/ServerHello
- [ ] Add test: verify unauthenticated peer is rejected
- [ ] Add test: verify authenticated peer is accepted
- [ ] Document authentication modes in SECURITY.md

**Reference:** WireGuard static key authentication, TLS 1.3 PSK mode (RFC 8446 Section 2.2)

#### 2. Code Quality
**Priority:** High | **Effort:** Medium

- [ ] Static analysis report (golangci-lint, gosec)
- [ ] Code documentation for all exported symbols
- [ ] Architecture documentation
- [ ] Threat model documentation

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
- **UAE & Saudi Arabia**: VPN usage to bypass telecom restrictions is illegal.
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

---

## Contributing

See [CONTRIBUTING.md](../CONTRIBUTING.md) for development setup and contribution guidelines.

When picking up a task:
1. Create an issue or comment on existing one
2. Create a feature branch from `develop`
3. Implement with tests
4. Submit PR with description referencing this roadmap

---

*Document Version: 4.0*
*Last Updated: 2026-03-13*
