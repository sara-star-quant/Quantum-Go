# Security Policy

## Reporting security vulnerabilities

**DO NOT open public GitHub issues for security vulnerabilities.**

The Quantum-Go project takes security seriously. If you discover a security vulnerability, please follow responsible disclosure practices:

### How to report

1. **Report privately** through [GitHub private vulnerability reporting](https://github.com/sara-star-quant/Quantum-Go/security/advisories/new), where only the maintainers can see the report

2. **Include the following information**:
   - Type of vulnerability (e.g., timing side-channel, authentication bypass, key compromise)
   - Affected version(s)
   - Steps to reproduce or proof-of-concept
   - Potential impact assessment
   - Suggested remediation (if any)
   - Your contact information for follow-up

3. **Encryption (Optional but Recommended)**:
   - For highly sensitive disclosures, say so in the report and we will agree an encrypted channel in the advisory thread
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

While Quantum-Go is pre-1.0, only the latest release receives security fixes, and fixes are not backported. Run the latest release; each published advisory lists the versions it affects and the version that fixes it.

Releases before v0.0.9 contain known protocol-level weaknesses in session resumption, rekey authentication and transcript binding.

Production use of any release is **not recommended** without an independent security audit, and none has been done.

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
   - Intended property: the session key stays secret if **EITHER** algorithm holds. Checked in the symbolic model (`docs/formal/chkem_hybrid.pv`, claim C-04); the computational argument is a self-authored sketch (C-03, see the table below)
   - Defense-in-depth against cryptanalytic breakthroughs
   - Combined secret: SHAKE-256 over the domain string, then the length-prefixed `K_x`, `K_m` and transcript hash; the transcript also binds version and role

4. **Authenticated encryption**:
   - AES-256-GCM (a FIPS-approved algorithm; this library is not a validated module)
   - ChaCha20-Poly1305 (RFC 8439)
   - Nonce uniqueness from sequence numbering; no nonce-misuse resistance

5. **Forward secrecy**:
   - Ephemeral keys per session
   - Automatic rekeying (1 hour, 64 GiB, or 2^28 packets)
   - Old keys zeroized after use

### Security properties

| Property                  | Status              | Implementation                         |
|---------------------------|---------------------|----------------------------------------|
| ML-KEM-1024 IND-CCA2 | By design, per FIPS 203 (C-01) | NIST's analysis of ML-KEM; not a result for this library |
| X25519 | Diffie-Hellman, assumption-based (C-02) | RFC 7748; not a KEM, and no IND-CCA2 notion applies on its own |
| IND-CCA2 of the CH-KEM-v1 combiner | Argued, not reviewed (C-03) | Self-authored reduction sketch, `docs/math/MATHEMATICAL_FOUNDATION.md` section 7.1; no published or machine-checked proof |
| Post-Quantum Resistance   | Provided            | ML-KEM-1024 (NIST Category 5); the assurance is NIST's analysis, not a result for this library |
| Forward Secrecy           | Provided (C-05, symbolic model) | Ephemeral keys per session             |
| Replay Protection         | Provided (C-11) | Sliding window (1024, multi-word); tested, not verified symbolically |
| Endpoint Authentication   | Required (PSK or key) (C-06, C-07) | Static-key pinning (server) + PSK (mutual) |
| Nonce-Misuse Resistance   | Partial/Conditional | Session-bound derived nonce (prefix \|\| seq), not transmitted |
| Side-Channel Resistance   | Partial/Conditional (C-16: constant time not claimed) | Relies on the Go standard library and on circl; no side-channel evaluation of this library's own code |
| Key Compromise Impersonation | Not provided     | Not designed for (ephemeral keys)      |

### Authentication modes

Since v0.0.29 the library requires authentication: an endpoint needs a PSK or a PSK lookup, a static key (server) or a pinned server key (client), or an explicit `AllowUnauthenticated` (`DialInsecure` and `ListenInsecure` for tests and demos). With the opt-out on both sides, the handshake provides encryption and forward secrecy but does not prove peer identity, so an active attacker can sit in the middle.

**Static-key server authentication** (one way to satisfy the authentication requirement, since v0.0.12) lets a client cryptographically pin a server's long-term identity, stopping an active relaying machine-in-the-middle for the pinned-server case (checked in the symbolic model, `docs/formal/chkem_auth.pv`).

1. Generate a long-term server identity:

   ```
   quantum-tunnel keygen --out server
   ```

   This writes `server.key` (secret seed, base64, mode 0600) and `server.pub` (public pin, base64), and prints an `SHA256:` fingerprint. Keep `server.key` secret and persistent (the identity must survive restarts); distribute `server.pub` to clients and verify its fingerprint out-of-band.

2. Server (Listen): load the secret seed and prove possession.

   ```go
   seed, _ := base64.StdEncoding.DecodeString(strings.TrimSpace(string(keyFile)))
   kp, _ := chkem.ParseKeyPair(seed)
   cfg := tunnel.TransportConfig{StaticKeyPair: kp}
   ```

   Datagram transport: `tunnel.WithStaticIdentity(kp)`.

3. Client (Dial): pin the public key and require proof.

   ```go
   pin, _ := base64.StdEncoding.DecodeString(strings.TrimSpace(string(pubFile)))
   pub, _ := chkem.ParsePublicKey(pin)
   cfg := tunnel.TransportConfig{PinnedServerKey: pub}
   ```

   Datagram transport: `tunnel.WithPinnedServerKey(pub)`.

The client encapsulates a second CH-KEM leg to the pinned key and folds the secret into the master secret, so only the holder of the static private key derives matching handshake keys. The ephemeral leg stays a mandatory input, so **forward secrecy is preserved** even if the static key later leaks.

**Failure behavior**: a wrong, absent, or stripped pin fails closed.
- Stream path: fails fast with `ErrServerKeyMismatch`.
- Datagram path: fails closed as a retry-ceiling timeout (the server drops the undecryptable ClientFinished as if lost), so `DialDatagram` returns `ErrServerKeyMismatch` only after the handshake times out.

The wire alert stays generic, so a prober that guesses pins learns nothing from the alert. Identity hiding is by design and is not yet modelled ([#280](https://github.com/sara-star-quant/Quantum-Go/issues/280)).

**Requiring authentication (server side)**: by default a server with a static identity still serves clients that do not pin it (the static leg is opt-in from the client). Set `TransportConfig.RequireStaticAuth` (stream) or `tunnel.WithRequireStaticAuth()` (datagram) to reject any client that does not authenticate the server, closing a silent downgrade where a misconfigured or stripped client connects unauthenticated. An unpinned client then fails closed: stream with `ErrStaticAuthRequired`, datagram as a retry-ceiling timeout. Requiring auth without a static key is a misconfiguration that fails closed (`ErrStaticAuthMisconfigured`). This requires clients to prove they used the server's public key; it is not client identity verification (the key is public).

**PSK mutual authentication** (opt-in) gives the mutual property that static-key pinning does not: both peers share a secret 32-byte pre-shared key, so each authenticates the other. Set the same key and identity label on both sides:

```go
psk := make([]byte, 32) // 256-bit, from crypto/rand; distribute out-of-band
// Server (Listen):
cfg := tunnel.TransportConfig{PSK: psk, PSKIdentity: []byte("edge-01")}
// Client (Dial):
cfg := tunnel.TransportConfig{PSK: psk, PSKIdentity: []byte("edge-01")}
// Datagram: tunnel.WithPSK([]byte("edge-01"), psk) on both endpoints.
```

The client advertises the identity label so the server selects the matching key, and both fold the PSK into the master secret (domain-separated from the static fold, applied after it). Only holders of the same PSK derive matching handshake keys, so a wrong, mismatched, or stripped PSK fails closed at the Finished MAC. An unknown identity skips the fold rather than erroring, so the server leaks no oracle about which identities it knows. The ephemeral leg stays mandatory, so forward secrecy holds even if the PSK later leaks. PSK composes with static-key pinning (configure both and both legs fold). The identity label travels in clear, so treat it as public; keep the key secret. PSK distribution and rotation are the deployer's responsibility.

**Not yet provided**: certificate- or token-based client identity. Static-key pinning authenticates the server to the client; PSK authenticates both peers under a shared secret. Neither binds a per-client asymmetric identity; for that, layer it externally.

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
- Malicious participants beyond static-key pinning (server) and PSK (mutual); per-client asymmetric identity remains external
- Post-compromise security (PCS) after long-term key compromise
- Traffic analysis / metadata leakage

### Known limitations

#### Protocol-level (planned for future releases)

1. **Partial endpoint authentication** (static-key server pinning and PSK mutual auth; per-client asymmetric identity still external):
   - Static-key pinning authenticates the **server** to a pinning client; a PSK authenticates **both** peers under a shared secret (see [Authentication modes](#authentication-modes)). With the explicit opt-out on both sides, the protocol provides encryption only.
   - There is **no certificate- or token-based client identity**: PSK proves shared-secret possession, not a per-client asymmetric credential.
   - For per-client asymmetric identity today, layer it externally (mTLS-style certificates).

2. **Resumption tickets**: removed in v0.0.26 together with the unused resumption API, so the old server-binding gap no longer exists. Every connection does a full handshake.

#### Implementation-level

3. **Nonce management**:
   - Sequence-based nonces are safe for single-threaded or properly synchronized use
   - **DO NOT** use same session keys from multiple goroutines without external locking
   - Nonce exhaustion triggers automatic rekey

4. **Timing side-channels**:
   - ML-KEM-1024 comes from cloudflare/circl (Go's `crypto/mlkem` in `-tags fips` builds) and the X-Wing suite from circl; both document constant-time implementations; this project has not tested that (see [#276](https://github.com/sara-star-quant/Quantum-Go/issues/276))
   - X25519 from Go stdlib is constant-time
   - AES-GCM timing depends on Go's implementation and the hardware; the library checks no CPU flags
   - ChaCha20-Poly1305 is software-constant-time

5. **Memory safety**:
   - Go runtime does not guarantee memory zeroization
   - Garbage collector may copy secrets to new locations
   - Swapping to disk may leak key material
   - Mitigation: Use HSM/TPM for long-term keys
   - v0.0.9 added `runtime.KeepAlive` to prevent dead store elimination of `Zeroize`

6. **Random number generation**:
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
   cfg := tunnel.DefaultTransportConfig()
   cfg.RateLimit.MaxConnectionsPerIP = 100
   ```
   - Set connection and handshake limits
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
| cloudflare/circl      | see go.mod | ML-KEM-1024 (default build), X-Wing | Audit status not verified by us; advisories tracked by govulncheck in CI |
| golang.org/x/crypto   | see go.mod | ChaCha20-Poly1305                 | Go Security Team maintained            |
| Go stdlib crypto      | 1.26+   | ML-KEM-1024 (`-tags fips`), AES-GCM, X25519, SHAKE-256, crypto/rand | Trail of Bits audit of the Go cryptography packages, May 2025, covering ECDH, ML-KEM, AES-GCM and the random number generator ([Go blog](https://go.dev/blog/tob-crypto-audit)) |

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
Published advisories are listed on the [security advisories page](https://github.com/sara-star-quant/Quantum-Go/security/advisories).

---

## Additional resources

- [NIST Post-Quantum Cryptography Standardization](https://csrc.nist.gov/projects/post-quantum-cryptography)
- [NIST FIPS 203: ML-KEM Standard](https://csrc.nist.gov/publications/detail/fips/203/final)
- [RFC 7748: Elliptic Curves for Security (X25519)](https://www.rfc-editor.org/rfc/rfc7748)
- [NIST FIPS 202: SHA-3 Standard](https://csrc.nist.gov/publications/detail/fips/202/final)
- [NSA CNSA 2.0: Quantum Transition Guidelines](https://media.defense.gov/2022/Sep/07/2003071834/-1/-1/0/CSA_CNSA_2.0_ALGORITHMS_.PDF)

---

**Last updated**: 2026-11-19
**Next review**: 2027-02-19 (quarterly updates)
