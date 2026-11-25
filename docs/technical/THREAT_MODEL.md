# Quantum-Go Threat Model

This is a self-authored threat model, informed by the NIST SP 800-30 risk methodology. It is NOT an independent third-party security audit; a third-party audit is tracked separately on the roadmap. Risk ratings reflect the authors' analysis of the design as of the dates noted.

**Last Updated:** 2026-11-26 (v0.0.36, wire protocol 6.0)

Revised after two independent code reads before v0.0.36. T12 to T15 are new (half-open slot exhaustion from one valid address, forgery attempts against one AEAD key, the static pinned-key accept or reject signal, rekey failure and desync); T8 and the protocol vulnerabilities in 5.3 were updated, and 5.3 now lists what the reads found, fixed or open. The scores for T1 to T5 are unchanged from the January assessment. Section 6 is a table of every threat before and after mitigation, replacing the two grids that predated the November revision. Each security claim this document relies on is in the [claims register](CLAIMS.md) with its status and evidence.

**Background reading, linked and not copied:** why a future quantum computer matters (Shor's algorithm breaks the elliptic-curve and finite-field key exchange used today, and Grover's algorithm halves the strength of symmetric keys, which is why AES-256 stays fine) is taught in IBM's [Quantum Learning](https://quantum.cloud.ibm.com/learning/en) courses. How this protocol compares with published analyses is in [RELATED_WORK](RELATED_WORK.md). The standard this library implements is [NIST FIPS 203](https://csrc.nist.gov/pubs/fips/203/final), the primary source for any claim about ML-KEM.

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Scope and Methodology](#2-scope-and-methodology)
3. [Asset Identification](#3-asset-identification)
4. [Threat Analysis](#4-threat-analysis)
5. [Vulnerability Assessment](#5-vulnerability-assessment)
6. [Risk Matrix](#6-risk-matrix)
7. [Mitigation Strategies](#7-mitigation-strategies)
8. [Residual Risk](#8-residual-risk)
9. [Recommendations](#9-recommendations)

---

## 1. Executive Summary

This threat model evaluates the security posture of the Quantum-Go tunnel encryption system implementing the Cascaded Hybrid Key Encapsulation Mechanism (CH-KEM). It covers cryptographic, implementation, operational, and regulatory risks.

### 1.1 Overall Risk Rating

**MODERATE** - This is a self-assessment of the design, not a certification or third-party sign-off.

### 1.2 Key Findings

| Category           | Risk Level | Key Concern                                                                                                                      |
| ------------------ | ---------- | -------------------------------------------------------------------------------------------------------------------------------- |
| Cryptographic      | Low        | Algorithm strength well-established                                                                                              |
| Implementation     | Moderate   | Standard library dependencies                                                                                                    |
| Operational        | Moderate   | Key management practices                                                                                                         |
| Quantum Threat     | Low        | Hybrid ML-KEM-1024 and X25519 key exchange; that it holds if either component holds is argued, not proven (claims register C-03) |
| Regulatory         | Low        | FIPS compliance roadmap defined                                                                                                  |
| Availability (UDP) | Moderate   | A cookie proves an address, not how many handshakes it may hold (T12)                                                            |

---

## 2. Scope and Methodology

### 2.1 Assessment Scope

**In Scope:**
- CH-KEM cryptographic algorithm
- ML-KEM-1024 implementation (Go crypto/mlkem)
- X25519 implementation (Go crypto/ecdh)
- Key derivation (SHAKE-256)
- Authenticated encryption (AES-256-GCM, ChaCha20-Poly1305)
- Protocol handshake and transport (stream/TCP and datagram/UDP)
- Endpoint authentication: static-key pinning and pre-shared keys
- KEM suite negotiation, HelloRetryRequest and the public suite registry
- Datagram fragmentation, the return-routability cookie and roaming
- Key management lifecycle

**Out of Scope:**
- Underlying operating system security
- Network infrastructure
- Hardware security modules
- Physical security
- User authentication mechanisms
- The code of externally registered KEM suites (the registering application owns it; see T11)

### 2.2 Methodology

Risk assessment follows NIST SP 800-30 Rev. 1:

1. **Prepare:** Define scope and information gathering
2. **Conduct:** Threat/vulnerability identification and analysis
3. **Communicate:** Document findings and recommendations
4. **Maintain:** Ongoing monitoring and updates

### 2.3 Risk Calculation

```
Risk = Likelihood × Impact

Likelihood Scale: 1 (Very Low) to 5 (Very High)
Impact Scale: 1 (Negligible) to 5 (Critical)
Risk Score: 1-25
```

| Score | Risk Level |
| ----- | ---------- |
| 1-4   | Low        |
| 5-9   | Moderate   |
| 10-16 | High       |
| 17-25 | Critical   |

---

## 3. Asset Identification

### 3.1 Critical Assets

| Asset ID | Asset                         | Classification   | Value    |
| -------- | ----------------------------- | ---------------- | -------- |
| A1       | Long-term CH-KEM private keys | Highly Sensitive | Critical |
| A2       | Session master secrets        | Sensitive        | High     |
| A3       | Traffic encryption keys       | Sensitive        | High     |
| A4       | Encrypted traffic             | Confidential     | High     |
| A5       | Protocol implementation       | Proprietary      | Medium   |
| A6       | Configuration data            | Internal         | Low      |

### 3.2 Data Flow

```
+--------------------------------------------------------------+
|                      Data Flow Diagram                       |
+--------------------------------------------------------------+
|                                                              |
|  [User Data] --> [Session] --> [Encryption] --> [Network]    |
|       |             |               |               |        |
|       v             v               v               v        |
|   A6: Config    A2: Master      A3: Traffic     A4: Data     |
|                   Secret          Keys                       |
|                     |                                        |
|                     v                                        |
|               A1: Long-term                                  |
|                 Private Key                                  |
|                                                              |
+--------------------------------------------------------------+
```

---

## 4. Threat Analysis

### 4.1 Threat Actors

| Actor                      | Capability | Motivation   | Likelihood |
| -------------------------- | ---------- | ------------ | ---------- |
| Nation State (Current)     | High       | Intelligence | Medium     |
| Nation State (Future CRQC) | Very High  | Intelligence | Medium     |
| Organized Crime            | Medium     | Financial    | Low        |
| Insider                    | Varies     | Various      | Low        |
| Opportunistic Attacker     | Low        | Various      | Medium     |

### 4.2 Threat Scenarios

#### T1: Cryptanalytic Attack on ML-KEM
- **Description:** Mathematical breakthrough weakening MLWE assumption
- **Likelihood:** Very Low (1)
- **Impact:** Critical (5)
- **Risk Score:** 5 (Moderate)

#### T2: Quantum Computer Attack (Harvest-Now-Decrypt-Later)
- **Description:** Adversary stores encrypted traffic for future quantum decryption
- **Likelihood:** Medium (3)
- **Impact:** High (4)
- **Risk Score:** 12 (High) - **Mitigated by ML-KEM**

#### T3: Side-Channel Attack
- **Description:** Timing or power analysis to extract keys
- **Likelihood:** Low (2)
- **Impact:** High (4)
- **Risk Score:** 8 (Moderate)

#### T4: Implementation Vulnerability
- **Description:** Bug in cryptographic code enabling key recovery
- **Likelihood:** Low (2)
- **Impact:** Critical (5)
- **Risk Score:** 10 (High)

#### T5: Key Compromise (Long-term)
- **Description:** Theft or unauthorized access to private keys
- **Likelihood:** Low (2)
- **Impact:** Critical (5)
- **Risk Score:** 10 (High)

#### T6: Protocol Attack (MitM)
- **Description:** Man-in-the-middle during handshake
- **Likelihood:** Low (2)
- **Impact:** High (4)
- **Risk Score:** 8 (Moderate)

#### T7: Replay Attack
- **Description:** Replay of captured packets to disrupt or attack
- **Likelihood:** Medium (3)
- **Impact:** Medium (3)
- **Risk Score:** 9 (Moderate)

#### T8: Denial of Service
- **Description:** Resource exhaustion through handshake flooding, and on UDP, reassembler occupancy and reflection from spoofed sources (see [datagram-dos.md](../datagram-dos.md))
- **Likelihood:** Medium (3)
- **Impact:** Medium (3)
- **Risk Score:** 9 (Moderate)

#### T9: Downgrade via Suite Negotiation
- **Description:** An active attacker strips or rewrites the offered KEM suites, or tampers with a HelloRetryRequest, to steer both peers onto a weaker suite
- **Likelihood:** Low (2)
- **Impact:** High (4)
- **Risk Score:** 8 (Moderate)

#### T10: Traffic Analysis and Protocol Fingerprinting
- **Description:** A passive observer classifies the tunnel as Quantum-Go from its unencrypted framing (the datagram header is a constant 14-byte layout and the PQ handshake has distinctive sizes), or infers activity from record sizes and timing. The payload stays encrypted; this is a metadata and censorship-resistance concern, not a confidentiality break
- **Likelihood:** High (4)
- **Impact:** Low (2)
- **Risk Score:** 8 (Moderate)

#### T11: Malicious or Defective External KEM Suite
- **Description:** An application registers a suite through `chkem.RegisterSuite` that leaks or weakens the shared secret. A registered suite runs in-process with access to handshake secrets, so the library cannot contain it
- **Likelihood:** Low (2)
- **Impact:** Critical (5)
- **Risk Score:** 10 (High)

#### T12: Half-Open Slot Exhaustion from One Valid Address
- **Description:** The stateless cookie proves that a source can receive at its address, so it stops spoofed floods. It does not limit how many handshakes one real address may hold: a single host that passes the gate can take one half-open slot per source port (and an IPv6 /64 as many as it likes) until the ceiling of 1,024 to 8,192 is full, and new peers are dropped. RFC 9147 section 5.1 says the same of DTLS 1.3: the cookie exchange "does not provide any defense against DoS attacks mounted from valid IP addresses"
- **Likelihood:** Medium (3)
- **Impact:** Medium (3)
- **Risk Score:** 9 (Moderate)

#### T13: Forgery Attempts Against One AEAD Key
- **Description:** An on-path attacker sends forged records under a live key and counts on each guess having a small chance of passing. The integrity bound stays negligible only up to a limit on failed attempts per key (RFC 9001 section 6.6: 2^36 for ChaCha20-Poly1305)
- **Likelihood:** Low (2)
- **Impact:** High (4)
- **Risk Score:** 8 (Moderate)

#### T14: Accept or Reject Signal on the Static Pinned Key
- **Description:** With a pinned static key, a client that builds the static ciphertext itself learns from the server's first flight whether decapsulation returned the value it predicted: one bit per online attempt. If an implementation compared the ciphertext incompletely this bit would be a plaintext-checking oracle (CVE-2026-10097 in another library did exactly that); a failure-boosting attack needs crafted ciphertexts, which the parameter analysis of FIPS 203 does not cover for adversarial choice. The model that would settle it is an authenticated key exchange model, which is not yet chosen (#276, #277)
- **Likelihood:** Low (2)
- **Impact:** High (4)
- **Risk Score:** 8 (Moderate)

#### T15: Rekey Failure and Desynchronization
- **Description:** A rekey that fails after it began can leave the peers on different keys: the request or response may be on the wire when a write fails, or a response may not decapsulate. A session that cannot rekey runs until its key reaches its wear limit
- **Likelihood:** Medium (3)
- **Impact:** Medium (3)
- **Risk Score:** 9 (Moderate)

---

## 5. Vulnerability Assessment

### 5.1 Algorithm Vulnerabilities

| ID  | Vulnerability              | Severity | Status                    |
| --- | -------------------------- | -------- | ------------------------- |
| V1  | ML-KEM side-channel in NTT | Medium   | Mitigated (Go std lib)    |
| V2  | X25519 timing leaks        | Low      | Mitigated (constant-time) |
| V3  | SHAKE-256 length extension | N/A      | Not applicable to XOF     |
| V4  | AES-GCM nonce reuse        | Critical | Mitigated (counter nonce) |

### 5.2 Implementation Vulnerabilities

| ID  | Vulnerability           | Severity | Status                       |
| --- | ----------------------- | -------- | ---------------------------- |
| V5  | Memory disclosure       | High     | Mitigated (zeroization)      |
| V6  | Integer overflow        | Medium   | Mitigated (Go bounds)        |
| V7  | Buffer overflow         | High     | Mitigated (Go memory safety) |
| V8  | Improper error handling | Medium   | Addressed in design          |

### 5.3 Protocol Vulnerabilities

| ID  | Vulnerability                                                                                                                                                                       | Severity | Status                                                                                                                                                                                                                                                                                                                                                  |
| --- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| V9  | Downgrade attack                                                                                                                                                                    | High     | Mitigated: the Finished MAC binds the transcript including the offered suite list, and a HelloRetryRequest uses a synthetic transcript hash. Covered by the transcript-agreement proof and by tamper and HRR tests; negotiation and HRR are not modeled separately in ProVerif                                                                          |
| V10 | Version rollback                                                                                                                                                                    | Medium   | Mitigated (version binding)                                                                                                                                                                                                                                                                                                                             |
| V11 | Replay attack                                                                                                                                                                       | Medium   | Mitigated (derived nonce, 1024-bit sliding window on both transports)                                                                                                                                                                                                                                                                                   |
| V12 | Session hijacking                                                                                                                                                                   | High     | Mitigated (encryption)                                                                                                                                                                                                                                                                                                                                  |
| V13 | Spoofed-source amplification and reassembler exhaustion (UDP)                                                                                                                       | Medium   | Partly mitigated: a load-gated stateless cookie engages under pressure and the RETRY never exceeds the datagram that triggered it. Below the pressure threshold an endpoint answers unverified sources, the cookie does not limit one valid address (V21), and a deeper amplification budget is future work (see [datagram-dos.md](../datagram-dos.md)) |
| V14 | Role confusion and reflection                                                                                                                                                       | Medium   | Mitigated (role bound into the CH-KEM transcript; X-Wing's combiner is spec-fixed, so the handshake transcript and Finished carry it)                                                                                                                                                                                                                   |
| V15 | Unauthenticated peer                                                                                                                                                                | High     | Closed by default since v0.0.29: an endpoint needs a PSK or a static or pinned key, or an explicit `AllowUnauthenticated`; only an explicit opt-out leaves it open                                                                                                                                                                                      |
| V16 | Wire fingerprinting                                                                                                                                                                 | Low      | Open (only opt-in handshake padding exists)                                                                                                                                                                                                                                                                                                             |
| V17 | A malformed first ClientHello held a datagram responder's half-open slot and kept a goroutine spinning                                                                              | High     | Fixed in 0.0.36 (GHSA-qqwq-hqjh-4hgf, affects 0.0.17 to 0.0.35); the responder's timer now arms when it is created, with driver and endpoint tests                                                                                                                                                                                                      |
| V18 | A forged RekeyInit under the cached epoch made the responder resend its response to its peer                                                                                        | Low      | Fixed in 0.0.36: the cache answers only a byte-identical retransmit                                                                                                                                                                                                                                                                                     |
| V19 | Half-open cleanup keyed by address could free a newer responder's slot                                                                                                              | Low      | Fixed in 0.0.36 (cleanup by owning session)                                                                                                                                                                                                                                                                                                             |
| V20 | A failed stream rekey left the session marked as rekeying                                                                                                                           | Medium   | Fixed in 0.0.36 (the session closes)                                                                                                                                                                                                                                                                                                                    |
| V21 | One real address can hold many half-open slots (T12)                                                                                                                                | Medium   | Open: an optional per-address cap is planned, default off, because users behind one NAT share an address                                                                                                                                                                                                                                                |
| V22 | Datagram rekey: after every response flight was lost, the initiator's next attempt used a fresh init, so the responder's cached response never matched and the pair could not rekey | Medium   | Fixed after 0.0.36 (unreleased): the initiator resends the same init until the responder answers; end-to-end test                                                                                                                                                                                                                                       |
| V23 | A forged RETRY with a garbage cookie can use up the initiator's three honored RETRYs                                                                                                | Low      | Open: needs the 32-bit sender index; accepted for now                                                                                                                                                                                                                                                                                                   |
| V24 | Forged records under a live key (T13)                                                                                                                                               | Medium   | Mitigated: a datagram session closes after 2^36 failed authentications (claim C-21); a stream ends on the first failed record                                                                                                                                                                                                                           |

---

## 6. Risk Matrix

Likelihood (L) and impact (I) use the scales in 2.3. Scores for T1 to T11 come from the earlier assessments (the two grids that used to sit here are replaced by this table); T12 to T15 were scored on 2026-11-26.

### 6.1 Every Threat, Before and After Mitigation

| Threat | Pre-mitigation (L x I) | Post-mitigation (L x I) | Note                                                                                                     |
| ------ | ---------------------- | ----------------------- | -------------------------------------------------------------------------------------------------------- |
| T1     | 1 x 5 = 5 (Moderate)   | 1 x 2 = 2 (Low)         | -                                                                                                        |
| T2     | 3 x 4 = 12 (High)      | 1 x 2 = 2 (Low)         | -                                                                                                        |
| T3     | 2 x 4 = 8 (Moderate)   | 2 x 4 = 8 (Moderate)    | -                                                                                                        |
| T4     | 2 x 5 = 10 (High)      | 1 x 3 = 3 (Low)         | -                                                                                                        |
| T5     | 2 x 5 = 10 (High)      | 1 x 3 = 3 (Low)         | -                                                                                                        |
| T6     | 2 x 4 = 8 (Moderate)   | 2 x 2 = 4 (Low)         | -                                                                                                        |
| T7     | 3 x 3 = 9 (Moderate)   | 2 x 3 = 6 (Moderate)    | -                                                                                                        |
| T8     | 3 x 3 = 9 (Moderate)   | 2 x 3 = 6 (Moderate)    | Datagram responder fix in 0.0.36 (V17)                                                                   |
| T9     | 2 x 4 = 8 (Moderate)   | 1 x 4 = 4 (Low)         | Negotiation path has tests, no separate formal model                                                     |
| T10    | 4 x 2 = 8 (Moderate)   | 4 x 2 = 8 (Moderate)    | No control removes it; padding is opt-in and does not hide the header                                    |
| T11    | 2 x 5 = 10 (High)      | 2 x 5 = 10 (High)       | An in-process suite cannot be sandboxed                                                                  |
| T12    | 3 x 3 = 9 (Moderate)   | 3 x 3 = 9 (Moderate)    | No mitigation yet: an optional per-address cap is planned, default off                                   |
| T13    | 2 x 4 = 8 (Moderate)   | 1 x 4 = 4 (Low)         | Datagram: close at 2^36 failures (C-21); stream: first failure ends the session                          |
| T14    | 2 x 4 = 8 (Moderate)   | 2 x 4 = 8 (Moderate)    | Unchanged until an authenticated key exchange model is chosen and applied                                |
| T15    | 3 x 3 = 9 (Moderate)   | 2 x 3 = 6 (Moderate)    | Stream failure closes the session (0.0.36); the datagram lost-response stall is fixed after 0.0.36 (V22) |

### 6.2 What Does Not Improve

T3 and T14 stay where they are for different reasons: T3 relies on the standard library's constant-time code, which this project has not tested (claim C-16), and T14 waits for an authenticated key exchange model. T10, T11 and T12 do not improve because no control removes them today: padding is opt-in and does not hide the header, an in-process suite cannot be sandboxed, and the per-address cap for T12 is planned and not built.

---

## 7. Mitigation Strategies

### 7.1 Cryptographic Mitigations

| Threat            | Mitigation          | Effectiveness |
| ----------------- | ------------------- | ------------- |
| T1 (ML-KEM break) | Hybrid with X25519  | High          |
| T2 (Quantum)      | ML-KEM-1024         | Full          |
| T3 (Side-channel) | Go standard library | High          |

**Implementation:**
```go
// Both shares are hashed with a transcript of both public keys, both
// ciphertexts, the version and the role. That the output stays secret if
// either component holds is argued, not proven (claims register, C-03).
K = SHAKE-256(domain || K_x25519 || K_mlkem || transcript)
```

### 7.2 Implementation Mitigations

| Threat              | Mitigation            | Effectiveness |
| ------------------- | --------------------- | ------------- |
| T4 (Impl bugs)      | Go std lib, testing   | High          |
| T5 (Key compromise) | Zeroization, rotation | Medium        |

**Implementation:**
```go
// Secure key zeroization
func (s *Session) Close() {
    crypto.Zeroize(s.masterSecret)
    s.LocalKeyPair.Zeroize()
}
```

Keys rotate by a rekey that the initiator starts before a key reaches its wear limit (2^28 packets or 2^36 bytes; the limits are tested against the AES-GCM confidentiality bound, claim C-22).

### 7.3 Protocol Mitigations

| Threat                  | Mitigation                                                                                                                                                   | Effectiveness                                                                                       |
| ----------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------------------------------------------------------------------------------- |
| T6 (MitM)               | Transcript binding; optional static-key pinning and PSK for peer identity                                                                                    | High with pinning or PSK, none against an active attacker when both sides opt out of authentication |
| T7 (Replay)             | Derived per-direction nonce prefix and a 1024-bit sliding window; the datagram window is never reset across a rekey                                          | High                                                                                                |
| T8 (DoS)                | Per-IP and handshake rate limits, handshake timeout, `MaxPendingHandshakes`; on UDP a load-gated stateless cookie and a de-amplifying RETRY                  | Medium to High under load; Medium otherwise                                                         |
| T9 (Downgrade)          | Offered suites bound into the Finished transcript; HelloRetryRequest synthetic transcript hash; offer list enforced on both sides, including the FIPS filter | High, tested; not separately modeled                                                                |
| T10 (Fingerprinting)    | Optional fixed-size handshake padding                                                                                                                        | Low                                                                                                 |
| T12 (One valid address) | Global half-open ceiling; load-gated cookie; a per-address cap is planned as an option                                                                       | Low against a single host today; the ceiling bounds memory, not availability                        |
| T13 (Forgery attempts)  | Datagram session closes after 2^36 failed authentications; the stream ends on the first failed record; usage limits tested                                   | High                                                                                                |
| T14 (Static-key signal) | Implicit rejection; the full ciphertext compared by the standard library and circl, tested at every byte; rate limits bound attempts                         | Medium; the model is open                                                                           |
| T15 (Rekey failure)     | A failed stream rekey closes the session; within one datagram rekey attempt the same init is retransmitted until a response arrives                          | Medium; the datagram lost-response case is fixed after 0.0.36                                       |
| T11 (External suite)    | Explicit registration, ids from `0x8000`, a cap of 16, the shared `suitetest` conformance battery                                                            | Low against a malicious suite, Medium against an accidentally defective one                         |

**Replay protection:** each direction keeps a 1024-bit window of recent sequence numbers, and the AEAD nonce is the derived prefix joined with the sequence number, so a nonce is never reused within a key epoch.

---

## 8. Residual Risk

### 8.1 Accepted Risks

| Risk                                                 | Justification                                                                                                                              | Area           |
| ---------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------ | -------------- |
| Side-channel (reduced)                               | Using audited std lib                                                                                                                      | Implementation |
| Key theft (reduced)                                  | Operational controls                                                                                                                       | Operations     |
| Algorithm break (very low)                           | Multiple layers                                                                                                                            | Cryptographic  |
| Wire fingerprinting (T10)                            | No obfuscation layer yet; padding is opt-in                                                                                                | Protocol       |
| External suite code (T11)                            | The registering application owns the suite's code and supply chain                                                                         | Operations     |
| One valid address holding many half-open slots (T12) | Memory is bounded by the ceiling; the per-address cap waits for a pilot that shows the need, because users behind one NAT share an address | Protocol       |
| Static pinned-key signal (T14)                       | One bit per online attempt, rate limited, no known failure attack; accepted until an authenticated key exchange model is applied           | Cryptographic  |

### 8.2 Residual Risk Summary

| Category       | Pre-Mitigation | Post-Mitigation | Accepted    |
| -------------- | -------------- | --------------- | ----------- |
| Cryptographic  | Moderate       | Low             | Yes         |
| Implementation | High           | Moderate        | Yes         |
| Protocol       | Moderate       | Low             | Yes         |
| Operational    | High           | Moderate        | Conditional |

**Overall Residual Risk: LOW to MODERATE** for the stream transport and for authenticated deployments; MODERATE for an internet-facing datagram responder until the per-address cap and the datagram rekey fix exist.

---

## 9. Recommendations

### 9.1 High Priority

1. **Choose an authenticated key exchange model for the handshake** (Bellare-Rogaway with forward secrecy, CK or eCK) and apply it to the computational argument; this also settles T14. Tracked in #277 and #276
2. **Build the optional per-address half-open cap** (T12), default off, and document a starting value for deployments that face the internet
3. **Model suite negotiation and HelloRetryRequest in ProVerif.** Downgrade resistance rests on the transcript-agreement proof and on tests today; the negotiation path itself is not formally modeled
4. **Establish key management procedures** including rotation schedules
5. **Deploy monitoring** for cryptographic operation failures
6. **Reduce wire fingerprinting (T10)** with an optional obfuscation layer; the default header is a constant layout

### 9.2 Medium Priority

1. **Third-party security audit** of cryptographic implementation
2. **Penetration testing** of protocol implementation
3. **Develop incident response plan** for key compromise scenarios

### 9.3 Long-term

1. **FIPS 140-3 validation** process initiation
2. **Hardware security module integration** for key storage
3. **Continuous monitoring** of cryptographic research for new attacks

### 9.4 Operational Recommendations

| Area         | Recommendation                    | Priority |
| ------------ | --------------------------------- | -------- |
| Key Storage  | Use HSM for production            | High     |
| Key Rotation | Maximum 1 year for long-term keys | High     |
| Logging      | Log all cryptographic failures    | Medium   |
| Monitoring   | Alert on unusual patterns         | Medium   |
| Training     | Security awareness for operators  | Medium   |

---

## Appendix A: Glossary

| Term   | Definition                                  |
| ------ | ------------------------------------------- |
| CRQC   | Cryptographically Relevant Quantum Computer |
| MLWE   | Module Learning With Errors                 |
| CH-KEM | Cascaded Hybrid Key Encapsulation Mechanism |
| HSM    | Hardware Security Module                    |
| FIPS   | Federal Information Processing Standard     |

---

## Appendix B: Document Control

**Last Updated:** 2026-11-26 (v0.0.36)
