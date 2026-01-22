# FIPS 140-3 Compliance Roadmap

**Document Classification:** Regulatory Guidance
**Version:** 1.0
**Applicable Standard:** FIPS 140-3 (ISO/IEC 19790:2012)

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Compliance Overview](#2-compliance-overview)
3. [Algorithm Compliance Matrix](#3-algorithm-compliance-matrix)
4. [Cryptographic Module Boundary](#4-cryptographic-module-boundary)
5. [Security Requirements Mapping](#5-security-requirements-mapping)
6. [Implementation Requirements](#6-implementation-requirements)
7. [Validation Process](#7-validation-process)
8. [Timeline and Milestones](#8-timeline-and-milestones)
9. [Risk Assessment](#9-risk-assessment)
10. [Regulatory References](#10-regulatory-references)

---

## 1. Executive Summary

This document outlines the roadmap for achieving FIPS 140-3 compliance for the Quantum-Go cryptographic module. The module implements post-quantum cryptography using ML-KEM-1024 (FIPS 203) combined with classical X25519, positioned for federal government and high-security enterprise deployments.

### 1.1 Compliance Status

| Component | Standard | Status |
|-----------|----------|--------|
| ML-KEM-1024 | FIPS 203 | ✅ FIPS Approved (Aug 2024) |
| AES-256-GCM | FIPS 197 + SP 800-38D | ✅ FIPS Approved |
| SHA-3/SHAKE-256 | FIPS 202 | ✅ FIPS Approved |
| X25519 | RFC 7748 | ⚠️ Non-FIPS (hybrid mode allowed) |
| ChaCha20-Poly1305 | RFC 8439 | ⚠️ Non-FIPS (optional) |

### 1.2 Target Security Level

**FIPS 140-3 Security Level 1** (Software module)

Higher security levels (2-4) require physical security controls and are applicable to hardware modules.

---

## 2. Compliance Overview

### 2.1 FIPS 140-3 vs 140-2

| Aspect | FIPS 140-2 | FIPS 140-3 |
|--------|------------|------------|
| Effective | May 2001 | Sep 2019 |
| PQC Support | No | Yes (as of 2024) |
| ISO Alignment | Limited | Full (ISO/IEC 19790:2012) |
| Testing | CMVP only | CMVP + ISO 24759 |
| Deprecation | Sep 2026 | Current |

### 2.2 Post-Quantum Cryptography in FIPS

As of August 13, 2024, NIST approved the following PQC algorithms for FIPS 140-3:

| Algorithm | Standard | Use Case |
|-----------|----------|----------|
| ML-KEM | FIPS 203 | Key Encapsulation |
| ML-DSA | FIPS 204 | Digital Signatures |
| SLH-DSA | FIPS 205 | Digital Signatures (hash-based) |

### 2.3 Hybrid Mode Compliance

NIST explicitly permits hybrid key establishment combining:
- One FIPS-approved algorithm (ML-KEM-1024)
- One non-FIPS algorithm (X25519)

**Requirement:** The FIPS-approved algorithm MUST be used; the combined scheme is considered compliant if ML-KEM is part of the key derivation.

---

## 3. Algorithm Compliance Matrix

### 3.1 Key Encapsulation

| Algorithm | Standard | Security Level | Quantum-Go Implementation |
|-----------|----------|----------------|---------------------------|
| ML-KEM-512 | FIPS 203 | Category 1 | Not implemented |
| ML-KEM-768 | FIPS 203 | Category 3 | Available for future |
| ML-KEM-1024 | FIPS 203 | Category 5 | ✅ Primary implementation |

### 3.2 Symmetric Encryption

| Algorithm | Standard | Key Size | Status |
|-----------|----------|----------|--------|
| AES-GCM | FIPS 197 + SP 800-38D | 256-bit | ✅ FIPS Approved |
| ChaCha20-Poly1305 | RFC 8439 | 256-bit | ⚠️ Non-FIPS option |

**Recommendation:** Use AES-256-GCM for FIPS-compliant deployments.

### 3.3 Hash Functions and KDF

| Algorithm | Standard | Output | Status |
|-----------|----------|--------|--------|
| SHA3-256 | FIPS 202 | 256-bit | ✅ FIPS Approved |
| SHAKE-256 | FIPS 202 | Variable | ✅ FIPS Approved |
| HKDF-SHA256 | SP 800-56C | Variable | ✅ FIPS Approved |

### 3.4 Random Number Generation

| Source | Standard | Status |
|--------|----------|--------|
| crypto/rand (OS CSPRNG) | SP 800-90A/B | ✅ Depends on OS |

**Note:** FIPS compliance requires the underlying OS DRBG to be FIPS-validated.

---

## 4. Cryptographic Module Boundary

### 4.1 Module Definition

```
┌─────────────────────────────────────────────────────────────┐
│                 CRYPTOGRAPHIC MODULE BOUNDARY               │
│                                                             │
│  ┌─────────────────────────────────────────────────────┐   │
│  │                    pkg/crypto/                       │   │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  │   │
│  │  │   ML-KEM    │  │    AEAD     │  │    KDF      │  │   │
│  │  │  (FIPS 203) │  │(FIPS 197/38)│  │ (FIPS 202)  │  │   │
│  │  └─────────────┘  └─────────────┘  └─────────────┘  │   │
│  │                                                      │   │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  │   │
│  │  │   X25519    │  │   Random    │  │  Zeroize    │  │   │
│  │  │ (RFC 7748)  │  │ (SP 800-90) │  │             │  │   │
│  │  └─────────────┘  └─────────────┘  └─────────────┘  │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
│  ┌─────────────────────────────────────────────────────┐   │
│  │                    pkg/chkem/                        │   │
│  │  ┌───────────────────────────────────────────────┐  │   │
│  │  │  CH-KEM (Cascaded Hybrid Key Encapsulation)   │  │   │
│  │  │    - ML-KEM-1024 (FIPS approved)              │  │   │
│  │  │    - X25519 (hybrid component)                │  │   │
│  │  │    - SHAKE-256 KDF (FIPS approved)            │  │   │
│  │  └───────────────────────────────────────────────┘  │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
└─────────────────────────────────────────────────────────────┘
                              │
                              │ API Interface
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                  OUTSIDE MODULE BOUNDARY                    │
│                                                             │
│  pkg/tunnel/    - Protocol logic                           │
│  pkg/protocol/  - Message formatting                       │
│  Application    - User code                                │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### 4.2 Services Provided

| Service | Description | FIPS Algorithm |
|---------|-------------|----------------|
| Key Generation | Generate CH-KEM key pairs | ML-KEM-1024 |
| Key Encapsulation | Create shared secrets | ML-KEM-1024 + X25519 |
| Key Decapsulation | Recover shared secrets | ML-KEM-1024 + X25519 |
| Encryption | Authenticated encryption | AES-256-GCM |
| Decryption | Authenticated decryption | AES-256-GCM |
| Key Derivation | Derive session keys | SHAKE-256 |
| Zeroization | Secure key erasure | N/A |

---

## 5. Security Requirements Mapping

### 5.1 FIPS 140-3 Section Requirements

| Section | Requirement | Implementation |
|---------|-------------|----------------|
| 7.2 | Cryptographic Module Specification | Defined module boundary |
| 7.3 | Cryptographic Module Interfaces | API documented |
| 7.4 | Roles, Services, Authentication | Operator role, no auth (Level 1) |
| 7.5 | Software Security | Go memory safety |
| 7.6 | Operational Environment | Standard Go runtime |
| 7.7 | Physical Security | N/A (Level 1) |
| 7.8 | Non-Invasive Security | Side-channel mitigations |
| 7.9 | Sensitive Security Parameters | Key zeroization |
| 7.10 | Self-Tests | Power-on and conditional tests |
| 7.11 | Life-Cycle Assurance | Version control, code review |
| 7.12 | Mitigation of Other Attacks | Documented in threat model |

### 5.2 Self-Test Requirements

**Power-On Self-Tests (POST):**

| Test | Algorithm | Method |
|------|-----------|--------|
| KAT-KEM | ML-KEM-1024 | Known-answer encaps/decaps |
| KAT-AES | AES-256-GCM | Known-answer encrypt/decrypt |
| KAT-SHAKE | SHAKE-256 | Known-answer hash |
| Integrity | Module code | SHA-256 of binary |

**Conditional Self-Tests:**

| Trigger | Test |
|---------|------|
| Key generation | Pairwise consistency |
| RNG output | DRBG health check |

---

## 6. Implementation Requirements

### 6.1 Code Requirements

1. **No Hardcoded Keys:** All keys must be generated or input
2. **Secure Zeroization:** Overwrite sensitive data before deallocation
3. **Error Handling:** No information leakage through errors
4. **Constant-Time:** Critical operations must be constant-time
5. **Input Validation:** All inputs must be validated before use

### 6.2 Build Requirements

```go
// build_fips.go
//go:build fips

package crypto

import (
    "crypto/mlkem"  // FIPS 203
    "crypto/aes"    // FIPS 197
    "crypto/sha3"   // FIPS 202
)

// FIPSMode indicates whether the module is operating in FIPS mode
var FIPSMode = true
```

### 6.3 Entropy Source Requirements

For FIPS compliance, the entropy source must be a FIPS-validated DRBG:

| Operating System | Entropy Source | FIPS Status |
|------------------|----------------|-------------|
| Linux | /dev/urandom (getrandom) | Kernel DRBG |
| Windows | CNG BCryptGenRandom | FIPS 140-2 validated |
| macOS | SecRandomCopyBytes | Common Criteria |

---

## 7. Validation Process

### 7.1 CMVP Validation Steps

1. **Preparation**
   - Complete implementation documentation
   - Implement self-tests
   - Prepare test vectors

2. **Lab Selection**
   - Choose NVLAP-accredited CST lab
   - Estimated cost: $50,000 - $150,000
   - Timeline: 12-18 months

3. **Testing**
   - Algorithm validation (CAVP)
   - Module validation (CMVP)
   - Entropy assessment (if applicable)

4. **Certification**
   - CMVP review
   - Certificate issuance
   - Listing on NIST website

### 7.2 Algorithm Validation

| Algorithm | CAVP Test | Vectors Required |
|-----------|-----------|------------------|
| ML-KEM-1024 | ACVP-ML-KEM | KeyGen, Encaps, Decaps |
| AES-256-GCM | ACVP-AES | Encrypt, Decrypt, GMAC |
| SHAKE-256 | ACVP-SHA3 | XOF tests |

---

## 8. Timeline and Milestones

### 8.1 Phase 1: Preparation (Months 1-3)

- [x] Complete algorithm implementation
- [x] Implement self-tests (KAT tests for all crypto primitives)
- [x] Document module design
- [ ] Internal security review (in progress)

### 8.2 Phase 2: Testing Preparation (Months 4-6)

- [ ] Generate test vectors
- [ ] Prepare CAVP submissions
- [ ] Select CST laboratory
- [ ] Begin entropy documentation

### 8.3 Phase 3: Validation (Months 7-18)

- [ ] CAVP algorithm testing
- [ ] CMVP module testing
- [ ] Address lab findings
- [ ] Final documentation

### 8.4 Phase 4: Maintenance (Ongoing)

- [ ] Monitor algorithm status
- [ ] Security updates
- [ ] Re-validation as needed

---

## 9. Risk Assessment

### 9.1 Compliance Risks

| Risk | Likelihood | Impact | Mitigation |
|------|------------|--------|------------|
| Algorithm de-listing | Low | High | Use standardized algorithms |
| Validation delays | Medium | Medium | Early engagement with lab |
| Cost overruns | Medium | Medium | Clear scope definition |
| Implementation changes | Medium | High | Stable API design |

### 9.2 Security Risks

| Risk | Likelihood | Impact | Mitigation |
|------|------------|--------|------------|
| Side-channel leakage | Medium | High | Use standard library |
| Implementation bugs | Medium | High | Extensive testing |
| Key compromise | Low | Critical | Zeroization, HSM option |

---

## 10. Regulatory References

### 10.1 Primary Standards

1. **FIPS 140-3** - Security Requirements for Cryptographic Modules
2. **FIPS 203** - Module-Lattice-Based Key-Encapsulation Mechanism
3. **FIPS 197** - Advanced Encryption Standard (AES)
4. **FIPS 202** - SHA-3 Standard

### 10.2 Supporting Documents

1. **SP 800-56C** - Key-Derivation Methods in Key-Establishment Schemes
2. **SP 800-90A/B/C** - Random Number Generation
3. **SP 800-131A** - Transitioning Cryptographic Algorithms
4. **NIST IR 8547** - Transition to Post-Quantum Cryptography

### 10.3 Relevant Guidance

1. **NSA CNSA 2.0** - Commercial National Security Algorithm Suite
2. **CISA PQC Guidance** - Post-Quantum Cryptography Initiative
3. **OMB M-23-02** - Migrating to Post-Quantum Cryptography

---

## Appendix A: Contact Information

**NIST CMVP:**
- Website: <https://csrc.nist.gov/projects/cryptographic-module-validation-program>
- Email: <cmvp@nist.gov>

**NVLAP Accredited Labs:**
- List: <https://www.nist.gov/nvlap/nvlap-lab-directory>

---

*Document Version: 1.1*
*Last Updated: 2026-01-20*
*Review Date: Quarterly*
