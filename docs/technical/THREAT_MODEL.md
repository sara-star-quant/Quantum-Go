# Quantum-Go Threat Model

This is a self-authored threat model, informed by the NIST SP 800-30 risk methodology. It is NOT an independent third-party security audit; a third-party audit is tracked separately on the roadmap. Risk ratings reflect the authors' analysis of the design as of the dates noted.

**Last Updated:** 2026-11-08 (v0.0.20, wire protocol 6.0)

Revised for the datagram transport, endpoint authentication, KEM suite negotiation with HelloRetryRequest, the public suite registry and the one-round-trip handshake. T9 to T11 are new; T6 to T8 and the protocol vulnerabilities in 5.3 were updated. The scores for T1 to T5 are unchanged from the January assessment, and the grids in 6.1 and 6.2 predate this revision (T9 to T11 are in 6.3).

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

| Category | Risk Level | Key Concern |
|----------|------------|-------------|
| Cryptographic | Low | Algorithm strength well-established |
| Implementation | Moderate | Standard library dependencies |
| Operational | Moderate | Key management practices |
| Quantum Threat | Low | Full post-quantum protection |
| Regulatory | Low | FIPS compliance roadmap defined |

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
|-------|------------|
| 1-4 | Low |
| 5-9 | Moderate |
| 10-16 | High |
| 17-25 | Critical |

---

## 3. Asset Identification

### 3.1 Critical Assets

| Asset ID | Asset | Classification | Value |
|----------|-------|----------------|-------|
| A1 | Long-term CH-KEM private keys | Highly Sensitive | Critical |
| A2 | Session master secrets | Sensitive | High |
| A3 | Traffic encryption keys | Sensitive | High |
| A4 | Encrypted traffic | Confidential | High |
| A5 | Protocol implementation | Proprietary | Medium |
| A6 | Configuration data | Internal | Low |

### 3.2 Data Flow

```
┌─────────────────────────────────────────────────────────────┐
│                    Data Flow Diagram                        │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  [User Data] ──> [Session] ──> [Encryption] ──> [Network]  │
│       │              │              │               │       │
│       │              │              │               │       │
│       ▼              ▼              ▼               ▼       │
│   A6: Config     A2: Master     A3: Traffic    A4: Data    │
│                   Secret          Keys                      │
│                      │                                      │
│                      │                                      │
│                      ▼                                      │
│                 A1: Long-term                               │
│                   Private Key                               │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

---

## 4. Threat Analysis

### 4.1 Threat Actors

| Actor | Capability | Motivation | Likelihood |
|-------|------------|------------|------------|
| Nation State (Current) | High | Intelligence | Medium |
| Nation State (Future CRQC) | Very High | Intelligence | Medium |
| Organized Crime | Medium | Financial | Low |
| Insider | Varies | Various | Low |
| Opportunistic Attacker | Low | Various | Medium |

### 4.2 Threat Scenarios

#### T1: Cryptanalytic Attack on ML-KEM
**Description:** Mathematical breakthrough weakening MLWE assumption
**Likelihood:** Very Low (1)
**Impact:** Critical (5)
**Risk Score:** 5 (Moderate)

#### T2: Quantum Computer Attack (Harvest-Now-Decrypt-Later)
**Description:** Adversary stores encrypted traffic for future quantum decryption
**Likelihood:** Medium (3)
**Impact:** High (4)
**Risk Score:** 12 (High) - **Mitigated by ML-KEM**

#### T3: Side-Channel Attack
**Description:** Timing or power analysis to extract keys
**Likelihood:** Low (2)
**Impact:** High (4)
**Risk Score:** 8 (Moderate)

#### T4: Implementation Vulnerability
**Description:** Bug in cryptographic code enabling key recovery
**Likelihood:** Low (2)
**Impact:** Critical (5)
**Risk Score:** 10 (High)

#### T5: Key Compromise (Long-term)
**Description:** Theft or unauthorized access to private keys
**Likelihood:** Low (2)
**Impact:** Critical (5)
**Risk Score:** 10 (High)

#### T6: Protocol Attack (MitM)
**Description:** Man-in-the-middle during handshake
**Likelihood:** Low (2)
**Impact:** High (4)
**Risk Score:** 8 (Moderate)

#### T7: Replay Attack
**Description:** Replay of captured packets to disrupt or attack
**Likelihood:** Medium (3)
**Impact:** Medium (3)
**Risk Score:** 9 (Moderate)

#### T8: Denial of Service
**Description:** Resource exhaustion through handshake flooding, and on UDP, reassembler occupancy and reflection from spoofed sources (see [datagram-dos.md](../datagram-dos.md))
**Likelihood:** Medium (3)
**Impact:** Medium (3)
**Risk Score:** 9 (Moderate)

#### T9: Downgrade via Suite Negotiation
**Description:** An active attacker strips or rewrites the offered KEM suites, or tampers with a HelloRetryRequest, to steer both peers onto a weaker suite
**Likelihood:** Low (2)
**Impact:** High (4)
**Risk Score:** 8 (Moderate)

#### T10: Traffic Analysis and Protocol Fingerprinting
**Description:** A passive observer classifies the tunnel as Quantum-Go from its unencrypted framing (the datagram header is a constant 14-byte layout and the PQ handshake has distinctive sizes), or infers activity from record sizes and timing. The payload stays encrypted; this is a metadata and censorship-resistance concern, not a confidentiality break
**Likelihood:** High (4)
**Impact:** Low (2)
**Risk Score:** 8 (Moderate)

#### T11: Malicious or Defective External KEM Suite
**Description:** An application registers a suite through `chkem.RegisterSuite` that leaks or weakens the shared secret. A registered suite runs in-process with access to handshake secrets, so the library cannot contain it
**Likelihood:** Low (2)
**Impact:** Critical (5)
**Risk Score:** 10 (High)

---

## 5. Vulnerability Assessment

### 5.1 Algorithm Vulnerabilities

| ID | Vulnerability | Severity | Status |
|----|---------------|----------|--------|
| V1 | ML-KEM side-channel in NTT | Medium | Mitigated (Go std lib) |
| V2 | X25519 timing leaks | Low | Mitigated (constant-time) |
| V3 | SHAKE-256 length extension | N/A | Not applicable to XOF |
| V4 | AES-GCM nonce reuse | Critical | Mitigated (counter nonce) |

### 5.2 Implementation Vulnerabilities

| ID | Vulnerability | Severity | Status |
|----|---------------|----------|--------|
| V5 | Memory disclosure | High | Mitigated (zeroization) |
| V6 | Integer overflow | Medium | Mitigated (Go bounds) |
| V7 | Buffer overflow | High | Mitigated (Go memory safety) |
| V8 | Improper error handling | Medium | Addressed in design |

### 5.3 Protocol Vulnerabilities

| ID | Vulnerability | Severity | Status |
|----|---------------|----------|--------|
| V9 | Downgrade attack | High | Mitigated: the Finished MAC binds the transcript including the offered suite list, and a HelloRetryRequest uses a synthetic transcript hash. Covered by the transcript-agreement proof and by tamper and HRR tests; negotiation and HRR are not modeled separately in ProVerif |
| V10 | Version rollback | Medium | Mitigated (version binding) |
| V11 | Replay attack | Medium | Mitigated (derived nonce, 1024-bit sliding window on both transports) |
| V12 | Session hijacking | High | Mitigated (encryption) |
| V13 | Spoofed-source amplification and reassembler exhaustion (UDP) | Medium | Partly mitigated: a load-gated stateless cookie engages under pressure and the RETRY never exceeds the datagram that triggered it. Below the pressure threshold an endpoint answers unverified sources, and a deeper amplification budget is future work (see [datagram-dos.md](../datagram-dos.md)) |
| V14 | Role confusion and reflection | Medium | Mitigated (role bound into the CH-KEM transcript; X-Wing's combiner is spec-fixed, so the handshake transcript and Finished carry it) |
| V15 | Unauthenticated peer | High | Closed by default since v0.0.29: an endpoint needs a PSK or a static or pinned key, or an explicit `AllowUnauthenticated`; only an explicit opt-out leaves it open |
| V16 | Wire fingerprinting | Low | Open (only opt-in handshake padding exists) |

---

## 6. Risk Matrix

### 6.1 Pre-Mitigation Risk Matrix

```
Impact
   ▲
 5 │     │     │ T1  │ T4,T5│     │
   │     │     │     │     │     │
 4 │     │ T3,T6│     │ T2  │     │
   │     │     │     │     │     │
 3 │     │ T7,T8│     │     │     │
   │     │     │     │     │     │
 2 │     │     │     │     │     │
   │     │     │     │     │     │
 1 │     │     │     │     │     │
   └─────┴─────┴─────┴─────┴─────►
     1     2     3     4     5   Likelihood
```

### 6.2 Post-Mitigation Risk Matrix

```
Impact
   ▲
 5 │     │     │     │     │     │
   │     │     │     │     │     │
 4 │     │ T3  │     │     │     │
   │     │     │     │     │     │
 3 │ T4,T5│ T7,T8│     │     │     │
   │     │     │     │     │     │
 2 │ T1,T2│ T6  │     │     │     │
   │     │     │     │     │     │
 1 │     │     │     │     │     │
   └─────┴─────┴─────┴─────┴─────►
     1     2     3     4     5   Likelihood
```

### 6.3 Threats Added in the November 2026 Revision

| Threat | Pre-mitigation (L x I) | Post-mitigation (L x I) | Residual |
|--------|------------------------|-------------------------|----------|
| T9 Downgrade via negotiation | 2 x 4 = 8 (Moderate) | 1 x 4 = 4 (Low) | Low; the negotiation path has tests but no separate formal model |
| T10 Fingerprinting | 4 x 2 = 8 (Moderate) | 4 x 2 = 8 (Moderate) | Moderate by default; reduced only where handshake padding is enabled |
| T11 External suite | 2 x 5 = 10 (High) | 2 x 5 = 10 (High) | High; conditional on the supply chain of the registered code |

T10 and T11 do not improve after mitigation because the library has no control that removes them: padding is opt-in and does not hide the header, and an in-process suite cannot be sandboxed.

---

## 7. Mitigation Strategies

### 7.1 Cryptographic Mitigations

| Threat | Mitigation | Effectiveness |
|--------|------------|---------------|
| T1 (ML-KEM break) | Hybrid with X25519 | High |
| T2 (Quantum) | ML-KEM-1024 | Full |
| T3 (Side-channel) | Go standard library | High |

**Implementation:**
```go
// Defense-in-depth: CH-KEM provides security if EITHER
// X25519 OR ML-KEM is broken
K = SHAKE-256(K_x25519 || K_mlkem || transcript)
```

### 7.2 Implementation Mitigations

| Threat | Mitigation | Effectiveness |
|--------|------------|---------------|
| T4 (Impl bugs) | Go std lib, testing | High |
| T5 (Key compromise) | Zeroization, rotation | Medium |

**Implementation:**
```go
// Secure key zeroization
func (s *Session) Close() {
    crypto.Zeroize(s.masterSecret)
    s.LocalKeyPair.Zeroize()
}

// Automatic key rotation
if session.NeedsRekey() {
    session.Rekey(newSecret)
}
```

### 7.3 Protocol Mitigations

| Threat | Mitigation | Effectiveness |
|--------|------------|---------------|
| T6 (MitM) | Transcript binding; optional static-key pinning and PSK for peer identity | High with pinning or PSK, none against an active attacker when both sides opt out of authentication |
| T7 (Replay) | Derived per-direction nonce prefix and a 1024-bit sliding window; the datagram window is never reset across a rekey | High |
| T8 (DoS) | Per-IP and handshake rate limits, handshake timeout, `MaxPendingHandshakes`; on UDP a load-gated stateless cookie and a de-amplifying RETRY | Medium to High under load; Medium otherwise |
| T9 (Downgrade) | Offered suites bound into the Finished transcript; HelloRetryRequest synthetic transcript hash; offer list enforced on both sides, including the FIPS filter | High, tested; not separately modeled |
| T10 (Fingerprinting) | Optional fixed-size handshake padding | Low |
| T11 (External suite) | Explicit registration, ids from `0x8000`, a cap of 16, the shared `suitetest` conformance battery | Low against a malicious suite, Medium against an accidentally defective one |

**Replay protection:** each direction keeps a 1024-bit window of recent sequence numbers, and the AEAD nonce is the derived prefix joined with the sequence number, so a nonce is never reused within a key epoch.

---

## 8. Residual Risk

### 8.1 Accepted Risks

| Risk | Justification | Area |
|------|---------------|------|
| Side-channel (reduced) | Using audited std lib | Implementation |
| Key theft (reduced) | Operational controls | Operations |
| Algorithm break (very low) | Multiple layers | Cryptographic |
| Wire fingerprinting (T10) | No obfuscation layer yet; padding is opt-in | Protocol |
| External suite code (T11) | The registering application owns the suite's code and supply chain | Operations |

### 8.2 Residual Risk Summary

| Category | Pre-Mitigation | Post-Mitigation | Accepted |
|----------|----------------|-----------------|----------|
| Cryptographic | Moderate | Low | Yes |
| Implementation | High | Moderate | Yes |
| Protocol | Moderate | Low | Yes |
| Operational | High | Moderate | Conditional |

**Overall Residual Risk: LOW to MODERATE**

---

## 9. Recommendations

### 9.1 High Priority

1. **Model suite negotiation and HelloRetryRequest in ProVerif.** Downgrade resistance rests on the transcript-agreement proof and on tests today; the negotiation path itself is not formally modeled
2. **Establish key management procedures** including rotation schedules
3. **Deploy monitoring** for cryptographic operation failures
4. **Reduce wire fingerprinting (T10)** with an optional obfuscation layer; the default header is a constant layout

### 9.2 Medium Priority

1. **Third-party security audit** of cryptographic implementation
2. **Penetration testing** of protocol implementation
3. **Develop incident response plan** for key compromise scenarios

### 9.3 Long-term

1. **FIPS 140-3 validation** process initiation
2. **Hardware security module integration** for key storage
3. **Continuous monitoring** of cryptographic research for new attacks

### 9.4 Operational Recommendations

| Area | Recommendation | Priority |
|------|----------------|----------|
| Key Storage | Use HSM for production | High |
| Key Rotation | Maximum 1 year for long-term keys | High |
| Logging | Log all cryptographic failures | Medium |
| Monitoring | Alert on unusual patterns | Medium |
| Training | Security awareness for operators | Medium |

---

## Appendix A: Glossary

| Term | Definition |
|------|------------|
| CRQC | Cryptographically Relevant Quantum Computer |
| MLWE | Module Learning With Errors |
| CH-KEM | Cascaded Hybrid Key Encapsulation Mechanism |
| HSM | Hardware Security Module |
| FIPS | Federal Information Processing Standard |

---

## Appendix B: Document Control

**Last Updated:** 2026-11-08
