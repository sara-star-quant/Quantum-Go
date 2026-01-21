# Quantum-Go Development Roadmap

**Version:** 2.0  
**Last Updated:** 2026-01-21

---

## Current Status: v0.0.5

### Completed Features
- [x] CH-KEM hybrid key exchange (X25519 + ML-KEM-1024)
- [x] Network Rekey Protocol (handshake and activation)
- [x] Session Resumption (encrypted tickets)
- [x] Alert Protocol (standardized error reporting)
- [x] Graceful shutdown with CloseNotify
- [x] Comprehensive test suite (85%+ coverage on core packages)
- [x] Replay protection (sliding window)

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

- [ ] Pool message buffers using `sync.Pool`
- [ ] Pool encryption/decryption buffers
- [ ] Add benchmarks comparing pooled vs non-pooled

---

## v0.0.7 - FIPS Mode

**Theme:** FIPS 140-3 compliance preparation.

### 1. FIPS Build Mode
**Priority:** High | **Effort:** Medium

- [ ] Add `//go:build fips` conditional compilation
- [ ] Disable ChaCha20-Poly1305 in FIPS mode (AES-GCM only)
- [ ] Add FIPS mode indicator in session/transport
- [ ] Add runtime FIPS mode check
- [ ] Document FIPS deployment requirements

### 2. Power-On Self-Tests (POST)
**Priority:** High | **Effort:** Medium

Required for FIPS 140-3 validation.

- [ ] Implement POST for ML-KEM (KAT check on init)
- [ ] Implement POST for AES-GCM (KAT check on init)
- [ ] Implement POST for SHAKE-256 (KAT check on init)
- [ ] Add integrity check (hash of module binary)
- [ ] Add failure handling (panic or degraded mode)

### 3. Conditional Self-Tests
**Priority:** Medium | **Effort:** Low

- [ ] Add pairwise consistency test on key generation
- [ ] Add DRBG health check on RNG output

---

## v0.0.8 - Enterprise Features

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

## v0.0.9 - Security Audit Preparation

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
> **Advisory Only**: The following compliance roadmap is based on public regulatory documentation (EAR, dual-use lists) and is provided for **informational purposes only**. It does **NOT** constitute legal advice. Organizations must consult with their own legal counsel and trade compliance officers before exporting or deploying this software globally.

### Cryptographic Export Controls

#### United States
- **EAR (Export Administration Regulations)**: CH-KEM using ML-KEM-1024 and AES-256 may require export classification. ECCN 5D002 applies to encryption software.
- **License Exception ENC**: Open-source and publicly available software typically qualifies.
- **Action:** File notification with BIS (Bureau of Industry and Security) before v1.0.0 release.

#### European Union (Spain & General)
- **Dual-Use Regulation (EU 2021/821)**: governs encryption exports.
- **Open Source Exemption**: Software "in the public domain" is generally exempt from controls.
- **Spain Specifics**: Authority is *Ministerio de Economía, Comercio y Empresa*. Commercial exporters typically register with **REOCE**.
- **Action:** Verify "Public Domain" exemption applicability for GitHub distribution. Consider voluntary REOCE registration for corporate entities.

#### China
- **Commercial Cryptography Regulations**: Foreign cryptographic products may require certification for commercial use in China.
- **Action:** Document limitations for China deployments; consider separate compliance track.

#### Russia
- **FSB Certification**: Required for cryptographic products used in certain sectors.
- **Action:** Document that Quantum-Go is not certified for regulated use in Russia.

#### Australia
- **Defence Trade Controls Act (DTCA)**: Controls supply of DSGL technology to foreign persons.
- **Wassenaar Arrangement**: Australia is a signatory; strong encryption is controlled.
- **Action:** Verify DSGL status before supplying software to non-citizens within Australia or exporting.

#### France
- **ANSSI Regulations**: Import/Supply requires **Declaration** (for standard use) or **Authorization**.
- **Usage**: Generally unrestricted, but *supply* is strictly regulated.
- **Action:** File ANSSI declaration (minimum 1 month notice) before distribution in France.

#### India
- **Department of Telecommunications (DoT)**: ISP/Telecom licenses often require "bulk encryption" restrictions (40-bit limit historical, now focus on traceability).
- **DPDP Act 2023**: Mandates security but government retains decryption/interception powers.
- **Key Escrow**: Be aware of "traceability" requirements effectively mandating escrow-like capabilities for substantial intermediaries.
- **Action:** Clarify "traceability" vs "end-to-end encryption" stance for Indian deployments.

#### Latin America (LATAM)
- **Brazil (ANATEL)**: Act 77/21 prohibits hardcoded keys/backdoors in telecom equipment. New cybersecurity audits effective Nov 2025.
- **Mexico**: Wassenaar signatory. Export of dual-use software requires Ministry of Economy permit.
- **Action:** Ensure "Security by Design" compliance for Brazil and check export permits for Mexico.

#### United Kingdom
- **Post-Brexit Rules**: Retained EU Dual-Use Regulation (2021/821). Export of controlled encryption to non-EU/Five Eyes often requires license via SPIRE/LITE.
- **NCSC Guidance**: Adherence to NCSC "Commercial Product Assurance" (CPA) recommended for government use.
- **Action:** Verify whether OGEL (Open General Export Licence) applies to Quantum-Go distribution.

#### Israel
- **Defense Export Control**: Strictly regulated by DECA (Ministry of Defense). "Encryption Order" revoked in 2026 for alignment with Wassenaar, but commercial/defense distinction remains critical.
- **Action:** File for export license if targeting defense sector; follow Ministry of Economy rules for civilian use.

#### Asia-Pacific (APAC)
- **Japan (METI)**: Strong List/Catch-all controls. Encryption is a controlled item requiring MITI license for export.
- **Singapore**: Strategic Goods (Control) Act. Export/Transfer of ML-KEM technology may require XO Permit.
- **Action:** Assess need for specific export licenses for Japanese/Singaporean markets.

#### Middle East
- **UAE & Saudi Arabia**: Tight control on VoIP/VPN usage. VPNs used to bypass telecom restrictions are illegal.
- **Data Residency**: Strong preference (and sometimes mandate) for in-country data storage (e.g., Saudi ECC-1:2018).
- **Action:** Provide clear disclaimer that Quantum-Go must not be used to bypass telecom regulations in these regions.

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
