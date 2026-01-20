# Quantum-Go Development Roadmap

**Version:** 1.0
**Last Updated:** 2026-01-20

---

## Current Status: v0.0.4

### Completed Features
- Core CH-KEM implementation (ML-KEM-1024 + X25519)
- 4-message handshake protocol
- AES-256-GCM and ChaCha20-Poly1305 cipher suites
- Replay protection with sliding window
- Basic session rekeying (time/bytes/nonce triggers)
- Ping/Pong keepalive messages
- CLI tool with demo, benchmark, and example modes
- Comprehensive test suite (75-96% coverage across packages)
- KAT tests for cryptographic correctness
- Fuzz tests for security-critical parsers

---

## v0.0.5 - Protocol Completion

**Theme:** Complete the protocol implementation with full rekey and session management.

### 1. Network Rekey Protocol
**Priority:** High
**Effort:** Medium

Currently `Session.Rekey()` and `NeedsRekey()` exist, but the network-level `MessageTypeRekey` handling is not implemented.

**Tasks:**
- [x] Implement `Transport.sendRekey()` - send new CH-KEM public key
- [x] Implement `Transport.handleRekey()` - process incoming rekey messages
- [x] Add rekey state machine (pending, active, completed)
- [x] Implement key activation at specified sequence number
- [x] Add tests for rekey protocol (happy path, edge cases)
- [x] Add tests for rekey under load (concurrent send/receive during rekey)

**Files to modify:**
- `pkg/tunnel/transport.go`
- `pkg/tunnel/session.go`
- `pkg/protocol/codec.go` (if needed)

### 2. Session Resumption
**Priority:** Medium
**Effort:** Medium

SessionID exists in the protocol but resumption is not implemented.

**Tasks:**
- [ ] Design session ticket format (encrypted session state)
- [ ] Implement `Session.ExportTicket()` - export resumable session state
- [ ] Implement `Session.Resume()` - restore session from ticket
- [ ] Add abbreviated handshake for resumption (skip full CH-KEM)
- [ ] Add session ticket encryption (with server-side key)
- [ ] Add ticket lifetime and rotation
- [ ] Add tests for session resumption

**Files to modify:**
- `pkg/tunnel/session.go`
- `pkg/tunnel/handshake.go`
- `pkg/protocol/messages.go` (add ticket structures)

### 3. Alert Protocol
**Priority:** Medium
**Effort:** Low

`MessageTypeAlert` is defined but minimally used.

**Tasks:**
- [ ] Implement `Transport.sendAlert()` for all error conditions
- [ ] Add graceful shutdown with `AlertCodeCloseNotify`
- [ ] Map internal errors to appropriate alert codes
- [ ] Add alert logging for debugging
- [ ] Add tests for alert handling

**Files to modify:**
- `pkg/tunnel/transport.go`
- `pkg/tunnel/session.go`

### 4. Improve Test Coverage
**Priority:** Medium
**Effort:** Low

Target: 90%+ coverage on all packages.

**Tasks:**
- [ ] Add tests for `sendPong`/`encodePong` (currently 0%)
- [ ] Add tests for alert message encoding/decoding
- [ ] Add integration tests for rekey under load
- [ ] Add tests for connection timeout scenarios

---

## v0.0.6 - Hardening & Performance

**Theme:** Production readiness with security hardening.

### 1. Rate Limiting
**Priority:** High
**Effort:** Medium

DoS protection mentioned in risk assessment.

**Tasks:**
- [ ] Add connection rate limiting (per IP)
- [ ] Add handshake rate limiting
- [ ] Add configurable limits via `TransportConfig`
- [ ] Add metrics for rate limit events

### 2. Connection Pooling
**Priority:** Medium
**Effort:** Medium

Performance optimization for high-throughput scenarios.

**Tasks:**
- [ ] Implement connection pool with configurable size
- [ ] Add idle connection timeout
- [ ] Add health checking for pooled connections
- [ ] Add pool statistics

### 3. Metrics & Observability
**Priority:** Medium
**Effort:** Medium

**Tasks:**
- [ ] Add Prometheus-compatible metrics export
- [ ] Add OpenTelemetry tracing support
- [ ] Add structured logging with levels
- [ ] Add health check endpoint for CLI server mode

### 4. Buffer Pooling
**Priority:** Low
**Effort:** Low

Memory optimization using `sync.Pool`.

**Tasks:**
- [ ] Pool message buffers
- [ ] Pool encryption/decryption buffers
- [ ] Add benchmarks comparing pooled vs non-pooled

---

## v0.0.7 - FIPS Mode

**Theme:** FIPS 140-3 compliance preparation.

### 1. FIPS Build Mode
**Priority:** High
**Effort:** Medium

**Tasks:**
- [ ] Add `//go:build fips` conditional compilation
- [ ] Disable ChaCha20-Poly1305 in FIPS mode (AES-GCM only)
- [ ] Add FIPS mode indicator in session/transport
- [ ] Add runtime FIPS mode check
- [ ] Document FIPS deployment requirements

### 2. Power-On Self-Tests
**Priority:** High
**Effort:** Medium

Required for FIPS 140-3 validation.

**Tasks:**
- [ ] Implement POST for ML-KEM (KAT check on init)
- [ ] Implement POST for AES-GCM (KAT check on init)
- [ ] Implement POST for SHAKE-256 (KAT check on init)
- [ ] Add integrity check (hash of module binary)
- [ ] Add failure handling (panic or degraded mode)

### 3. Conditional Self-Tests
**Priority:** Medium
**Effort:** Low

**Tasks:**
- [ ] Add pairwise consistency test on key generation
- [ ] Add DRBG health check on RNG output

---

## v0.1.0 - Production Release

**Theme:** First production-ready release.

### Prerequisites
- [ ] All v0.0.5-v0.0.7 features complete
- [ ] Third-party security audit
- [ ] Performance benchmarks published
- [ ] API stability guarantee
- [ ] Migration guide from pre-release versions

### Features
- [ ] HSM integration (PKCS#11 interface)
- [ ] Configuration file support
- [ ] Systemd service integration
- [ ] Docker Compose examples
- [ ] Kubernetes deployment manifests

---

## Future Considerations (v0.2.0+)

### Potential Features
- **ML-KEM-768 support** - NIST Category 3 for constrained environments
- **Certificate-based authentication** - X.509 with PQ signatures
- **Multi-path transport** - Redundant connections for reliability
- **Hardware acceleration** - AES-NI optimization verification
- **WebSocket transport** - For firewall traversal

### Research Items
- **ML-DSA integration** - Post-quantum signatures for authentication
- **Hybrid certificates** - Dual classical/PQ certificate chains
- **Formal verification** - Protocol model in ProVerif/Tamarin

---

## Contributing

See [CONTRIBUTING.md](../CONTRIBUTING.md) for development setup and contribution guidelines.

When picking up a task:
1. Create an issue or comment on existing one
2. Create a feature branch from `develop`
3. Implement with tests
4. Submit PR with description referencing this roadmap

---

*Document Version: 1.0*
*Last Updated: 2026-01-20*
