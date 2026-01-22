# Quantum-Go Development Roadmap

**Version:** 2.1
**Last Updated:** 2026-01-22

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

## v0.0.6 - Hardening & Observability

**Theme:** Production hardening and operational visibility.

### 1. Rate Limiting & DoS Protection
**Priority:** High | **Effort:** Medium

- [x] Add connection rate limiting (per IP)
- [x] Add handshake rate limiting
- [x] Add configurable limits via `TransportConfig`
- [x] Add metrics for rate limit events

### 2. Metrics & Observability
**Priority:** High | **Effort:** Medium

- [x] Add Prometheus-compatible metrics export
- [x] Add OpenTelemetry tracing support
- [x] Add structured logging with levels
- [x] Add health check endpoint for CLI server mode

### 3. Connection Pooling
**Priority:** Medium | **Effort:** Medium

- [x] Implement connection pool with configurable size
- [x] Add idle connection timeout
- [x] Add health checking for pooled connections
- [x] Add pool statistics

### 4. Buffer Pooling
**Priority:** Low | **Effort:** Low

- [x] Pool message buffers using `sync.Pool`
- [x] Pool encryption/decryption buffers
- [x] Add benchmarks comparing pooled vs non-pooled

---

## v0.0.7 - FIPS Mode

**Theme:** FIPS 140-3 compliance preparation.

### 1. FIPS Build Mode
**Priority:** High | **Effort:** Medium

- [x] Add `//go:build fips` conditional compilation
- [x] Disable ChaCha20-Poly1305 in FIPS mode (AES-GCM only)
- [x] Add FIPS mode indicator in session/transport
- [x] Add runtime FIPS mode check
- [x] Document FIPS deployment requirements

### 2. Power-On Self-Tests (POST)
**Priority:** High | **Effort:** Medium

Required for FIPS 140-3 validation.

- [x] Implement POST for ML-KEM (KAT check on init)
- [x] Implement POST for AES-GCM (KAT check on init)
- [x] Implement POST for SHAKE-256 (KAT check on init)
- [x] Add integrity check (hash of module binary)
- [x] Add failure handling (panic or degraded mode)

### 3. Conditional Self-Tests
**Priority:** Medium | **Effort:** Low

- [x] Add pairwise consistency test on key generation
- [x] Add DRBG health check on RNG output

---

## v0.0.8 - Regulatory & Documentation Clarity

**Theme:** Clear regulatory guidance and documentation improvements.

### 1. Open Source Export Status
**Priority:** High | **Effort:** Low

- [x] Document EU Dual-Use Regulation exemption for public domain software
- [x] Clarify project origin (Spain/EU) and applicable regulations
- [x] Reframe US/BIS guidance as user deployment consideration (not developer obligation)
- [x] Distinguish developer obligations vs user deployment responsibilities

### 2. User Deployment Guidance
**Priority:** High | **Effort:** Low

- [x] Reframe regulatory section as guidance for deployers
- [x] Add "User Action" items for 15+ jurisdictions
- [x] Document that open source on GitHub is generally exempt
- [x] Clarify restrictions in highly regulated zones (must not bypass telecom regulations)

---

## v0.0.9 - Enterprise Features

**Theme:** Enterprise deployment readiness.

### 1. Configuration Management
**Priority:** High | **Effort:** Medium

- [ ] YAML/TOML configuration file support
- [ ] Environment variable overrides
- [ ] Configuration validation and error reporting
- [ ] Hot-reload for non-cryptographic settings

### 2. HSM Integration
**Priority:** High | **Effort:** High

- [ ] PKCS#11 interface for key storage
- [ ] Support for AWS CloudHSM / Azure Dedicated HSM
- [ ] Key escrow and backup mechanisms
- [ ] HSM health monitoring

### 3. Deployment Tooling
**Priority:** Medium | **Effort:** Medium

- [ ] Systemd service unit files
- [ ] Docker Compose examples
- [ ] Kubernetes deployment manifests (Helm chart)
- [ ] Terraform modules for cloud deployment

---

## v0.1.0 - Security Audit Preparation

**Theme:** Prepare for third-party security audit.

### 1. Code Quality
**Priority:** High | **Effort:** Medium

- [ ] Static analysis report (golangci-lint, gosec)
- [ ] Code documentation for all exported symbols
- [ ] Architecture documentation
- [ ] Threat model documentation

### 2. Security Testing
**Priority:** High | **Effort:** High

- [ ] Fuzzing infrastructure for protocol parsing
- [ ] Negative testing for error paths
- [ ] Timing attack resistance verification
- [ ] Memory safety validation

### 3. Compliance Documentation
**Priority:** High | **Effort:** Medium

- [ ] NIST SP 800-131A compliance checklist
- [ ] FIPS 140-3 compliance mapping
- [ ] SOC 2 relevant controls documentation

---

## v1.0.0 - Production Release

**Theme:** First production-ready, stable release.

### Prerequisites
- [ ] All v0.0.6-v0.0.9 features complete
- [ ] Third-party security audit completed
- [ ] Security audit findings remediated
- [ ] Performance benchmarks published
- [ ] API stability guarantee (semantic versioning)
- [ ] Migration guide from pre-release versions

### Release Artifacts
- [ ] Signed binaries for Linux, macOS, Windows
- [ ] Docker images (multi-arch)
- [ ] Package manager releases (Homebrew, APT, etc.)
- [ ] Go module stable release

### Documentation
- [ ] Complete API reference
- [ ] Deployment guide
- [ ] Operations runbook
- [ ] Troubleshooting guide

---

## Global Compliance & Regulatory Considerations

> **CAUTION**
> **Advisory Only**: The following compliance information is based on public regulatory documentation and is provided for **informational purposes only**. It does **NOT** constitute legal advice. Organizations must consult with their own legal counsel and trade compliance officers before deploying this software.

> **Note for Users**: This section describes regulatory considerations for **users deploying** Quantum-Go in various jurisdictions. As an open-source project publicly available on GitHub, the software itself is generally exempt from export controls under "public domain" exemptions in most jurisdictions.

### Cryptographic Export Controls

#### European Union (Project Origin)
- **Dual-Use Regulation (EU 2021/821)**: Governs encryption exports from EU member states.
- **Open Source Exemption**: Software "in the public domain" (publicly available without restrictions) is **exempt** from controls under Article 2(2).
- **Status**: Quantum-Go qualifies for the public domain exemption as MIT-licensed open source on GitHub.

#### United States
- **EAR (Export Administration Regulations)**: ECCN 5D002 applies to encryption software.
- **License Exception TSU**: Publicly available open-source software qualifies for exemption.
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
- **User Action**: Open source generally covered by OGEL; commercial use may differ.

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
- **Formal verification** - Protocol model in ProVerif/Tamarin
- **SLH-DSA (SPHINCS+)** - Stateless hash-based signatures as alternative

---

## Contributing

See [CONTRIBUTING.md](../CONTRIBUTING.md) for development setup and contribution guidelines.

When picking up a task:
1. Create an issue or comment on existing one
2. Create a feature branch from `develop`
3. Implement with tests
4. Submit PR with description referencing this roadmap

---

*Document Version: 2.0*  
*Last Updated: 2026-01-21*
