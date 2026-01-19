# Security Policy

## Reporting security vulnerabilities

**DO NOT open public GitHub issues for security vulnerabilities.**

The Quantum-Go project takes security seriously. If you discover a security vulnerability, please follow responsible disclosure practices:

### How to report

1. **Email the maintainers directly** at: `pzverkov@protonmail.com` (or security contact in profile)

2. **Include the following information**:
   - Type of vulnerability (e.g., timing side-channel, authentication bypass, key compromise)
   - Affected version(s)
   - Steps to reproduce or proof-of-concept
   - Potential impact assessment
   - Suggested remediation (if any)
   - Your contact information for follow-up

3. **Encryption (Optional but Recommended)**:
   - For highly sensitive disclosures, request PGP key via initial email
   - Encrypt details with provided public key

### What to expect

- **Acknowledgment**: Within 72 hours of report submission
- **Initial assessment**: Within 5 business days
- **Status updates**: Every 7 days until resolution
- **Coordinated disclosure**: We will work with you on disclosure timeline
- **Credit**: Security researchers will be credited in release notes (unless anonymity requested)

### Out of scope

The following are explicitly **not** in scope for security reports:
- Denial of Service (DoS) attacks requiring >1000 requests
- Issues in third-party dependencies (report to upstream)
- Social engineering attacks
- Physical attacks requiring device access
- Theoretical attacks without practical exploitation

---

## Supported versions

| Version | Supported          | Notes                          |
| ------- | ------------------ | ------------------------------ |
| 0.0.2+  | Yes                | Current development release    |
| < 0.0.2 | No                 | Pre-release, not supported     |

**Note**: This project is currently in early development (v0.0.x). Production use is **not recommended** without independent security audit.

---

## Security architecture

### Cryptographic guarantees

Quantum-Go implements a **Cascaded Hybrid KEM (CH-KEM)** providing:

1. **Post-Quantum security**: ML-KEM-1024 (CRYSTALS-Kyber, NIST FIPS 203)
   - NIST Category 5 security level (~256-bit)
   - Resistant to Grover's algorithm (quantum search)
   - Based on Module Learning With Errors (MLWE) hardness

2. **Classical security**: X25519 (Curve25519, RFC 7748)
   - 128-bit security against classical attacks
   - Constant-time implementation (via Go stdlib)
   - Widely deployed and analyzed

3. **Hybrid security guarantee**:
   - System remains secure if **EITHER** algorithm is secure
   - Defense-in-depth against cryptanalytic breakthroughs
   - Combined secret: `K = SHAKE-256(K_x || K_m || transcript || domain)`

4. **Authenticated encryption**:
   - AES-256-GCM (FIPS 140-2 approved)
   - ChaCha20-Poly1305 (RFC 8439)
   - Nonce-misuse resistance via sequence numbering

5. **Forward secrecy**:
   - Ephemeral keys per session
   - Automatic rekeying (1 hour, 1GB, or 2^28 packets)
   - Old keys zeroized after use

### Security properties

| Property                  | Status              | Implementation                         |
|---------------------------|---------------------|----------------------------------------|
| IND-CCA2 Security         | Provided            | ML-KEM-1024 + X25519                   |
| Post-Quantum Resistance   | Provided            | ML-KEM-1024 (NIST Category 5)          |
| Forward Secrecy           | Provided            | Ephemeral keys per session             |
| Replay Protection         | Provided            | Sliding window (64-bit sequence)       |
| Nonce-Misuse Resistance   | Partial/Conditional | Sequence-based nonces (must not reuse) |
| Side-Channel Resistance   | Partial/Conditional | Relies on Go stdlib (audited)          |
| Key Compromise Impersonation | Not provided     | Not designed for (ephemeral keys)      |

---

## Threat model

### Assumptions

**In scope**:
- Quantum adversary with Shor's algorithm (breaks RSA/ECC)
- Active network attacker (MITM, replay, tampering)
- Passive eavesdropper recording traffic for future decryption
- Compromised session keys (forward secrecy protects past sessions)

**Out of scope**:
- Physical attacks on runtime memory
- Side-channel attacks on non-constant-time operations
- Malicious participants (requires authentication layer)
- Post-compromise security (PCS) after long-term key compromise
- Traffic analysis / metadata leakage

### Known limitations

1. **No authentication**: This library provides encryption only. **You must implement**:
   - Peer authentication (certificates, pre-shared keys, etc.)
   - Identity binding to CH-KEM public keys
   - Authorization policies

2. **Nonce management**:
   - Sequence-based nonces are safe for single-threaded or properly synchronized use
   - **DO NOT** use same session keys from multiple goroutines without external locking
   - Nonce exhaustion triggers automatic rekey

3. **Timing side-channels**:
   - ML-KEM implementation (cloudflare/circl) uses constant-time operations
   - X25519 from Go stdlib is constant-time
   - **AES-GCM requires hardware AES-NI** for constant-time (CPU flags checked)
   - ChaCha20-Poly1305 is software-constant-time

4. **Memory safety**:
   - Go runtime does not guarantee memory zeroization
   - Garbage collector may copy secrets to new locations
   - Swapping to disk may leak key material
   - Mitigation: Use HSM/TPM for long-term keys

5. **Random number generation**:
   - Uses `crypto/rand` (Linux: getrandom syscall)
   - Ensure `/dev/urandom` is properly seeded on older systems
   - In virtualized environments, verify entropy availability

---

## Security recommendations

### For production deployments

#### Critical requirements

1. **Independent security audit**:
   - Engage professional cryptographic auditors
   - Review implementation against NIST FIPS 203 specification
   - Test side-channel resistance on target hardware

2. **Key management**:
   - Store long-term keys in Hardware Security Modules (HSM)
   - Use TPM for key derivation on edge devices
   - Implement key rotation policies (quarterly recommended)
   - Never reuse ephemeral session keys

3. **Authentication layer**:
   - Implement mutual authentication (X.509 certificates recommended)
   - Bind identities to CH-KEM public keys
   - Use certificate transparency for public key distribution
   - Consider TOFU (Trust On First Use) for low-security contexts

4. **Monitoring & incident response**:
   - Log handshake failures (potential attacks)
   - Monitor for unusual rekey rates
   - Alert on replay detection events
   - Have key revocation procedures ready

5. **Compliance**:
   - For FIPS 140-3: See [FIPS_140_3_ROADMAP.md](docs/compliance/FIPS_140_3_ROADMAP.md)
   - For CNSA 2.0: ML-KEM-1024 aligns with NSA guidance
   - Ensure AES-256-GCM mode for FIPS environments

#### Best practices

1. **Deployment**:
   - Enable TLS 1.3 for initial handshake transport (defense-in-depth)
   - Use pinned certificates for known peers
   - Implement connection limits per IP
   - Deploy intrusion detection systems (IDS)

2. **Configuration**:
   ```go
   config := tunnel.TransportConfig{
       MaxMessageSize: 1024 * 1024, // 1MB max
       // Add timeouts, buffer limits
   }
   ```
   - Set conservative message size limits
   - Configure timeouts for handshake/data operations
   - Enable connection-level rate limiting

3. **Testing**:
   - Run fuzz tests on public-facing parsers weekly
   - Execute KAT tests before deployment
   - Perform load testing under realistic conditions
   - Test failover and rekey scenarios

4. **Updates**:
   - Subscribe to security advisories (GitHub Watch → Releases)
   - Monitor CVE databases for Go crypto library issues
   - Update dependencies monthly (cloudflare/circl, golang.org/x/crypto)
   - Test updates in staging before production rollout

5. **Secure coding**:
   ```go
   // DO: Zeroize sensitive data
   defer crypto.Zeroize(secretKey)

   // DON'T: Log sensitive information
   // log.Printf("Shared secret: %x", secret) // NEVER DO THIS

   // DO: Handle errors
   if err := tunnel.InitiatorHandshake(session, conn); err != nil {
       conn.Close()
       return fmt.Errorf("handshake failed: %w", err)
   }
   ```

---

## Cryptographic dependencies

| Dependency            | Version | Purpose                  | Audit Status                           |
|-----------------------|---------|--------------------------|----------------------------------------|
| cloudflare/circl      | v1.6.2+ | ML-KEM-1024             | Audited by Trail of Bits (2023)        |
| golang.org/x/crypto   | v0.30.0+| ChaCha20, SHAKE-256     | Go Security Team maintained            |
| Go stdlib crypto      | 1.24+   | AES-GCM, X25519, crypto/rand | Regular security audits          |

**Dependency update policy**:
- Monitor security advisories
- Update within 7 days for critical CVEs
- Test thoroughly before deployment

---

## Security testing

### Available tests

```bash
# Known Answer Tests (deterministic crypto verification)
go test ./pkg/crypto -v -run "TestKAT"

# Fuzz testing (security-critical parsers)
go test -fuzz=FuzzParsePublicKey -fuzztime=1h ./test/fuzz/
go test -fuzz=FuzzDecodeClientHello -fuzztime=1h ./test/fuzz/
go test -fuzz=FuzzAEADOpen -fuzztime=1h ./test/fuzz/

# Race condition detection
go test ./... -race

# Benchmark (detect performance regressions)
go test ./test/benchmark -bench=. -benchmem
```

### Third-party security tools

Recommended for production deployments:

1. **Static analysis**:
   - `gosec` - Go security checker
   - `govulncheck` - Known vulnerability scanner
   - CodeQL / Semgrep

2. **Fuzzing**:
   - OSS-Fuzz integration (planned)
   - Custom fuzz harnesses in `test/fuzz/`

3. **Timing analysis**:
   - dudect - Constant-time verification
   - Intel PT (Processor Trace) for side-channels

---

## Vulnerability disclosure timeline

When a security issue is confirmed:

1. **Day 0**: Acknowledgment sent to reporter
2. **Day 1-5**: Validation and impact assessment
3. **Day 6-30**: Patch development and internal testing
4. **Day 31-60**: Coordinated disclosure with reporter
5. **Day 60**: Public disclosure and release (unless extended)

**Embargo Period**: 90 days maximum for critical vulnerabilities, shorter for lower severity.

---

## Security hall of fame

We acknowledge security researchers who responsibly disclose vulnerabilities:

<!-- Reserved for future contributors -->
*No vulnerabilities reported yet. Be the first to help improve Quantum-Go's security!*

---

## Additional resources

- [NIST Post-Quantum Cryptography Standardization](https://csrc.nist.gov/projects/post-quantum-cryptography)
- [NIST FIPS 203: ML-KEM Standard](https://csrc.nist.gov/publications/detail/fips/203/final)
- [RFC 7748: Elliptic Curves for Security (X25519)](https://www.rfc-editor.org/rfc/rfc7748)
- [NIST FIPS 202: SHA-3 Standard](https://csrc.nist.gov/publications/detail/fips/202/final)
- [NSA CNSA 2.0: Quantum Transition Guidelines](https://media.defense.gov/2022/Sep/07/2003071834/-1/-1/0/CSA_CNSA_2.0_ALGORITHMS_.PDF)

---

**Last updated**: 2026-01-19
**Next review**: 2026-04-19 (quarterly updates)
