# Design Influences

## 1. Design Philosophy

Quantum-Go's Cascaded Hybrid KEM (CH-KEM) is an original protocol designed from first principles. It is not a fork, derivative, or reimplementation of any existing VPN protocol, including WireGuard, Noise Framework, or any post-quantum WireGuard variant.

The protocol draws on the shared knowledge base of post-quantum cryptography research, adapting general concepts and design principles where they improve security. This document provides attribution for those influences and clarifies how our approach differs.

**Guiding rule:** We adapt general cryptographic concepts and design principles. We do not copy code, wire formats, protocol state machines, or specific novel constructions from any project.

---

## 2. Academic Influences

### 2.1 PSK + Fresh KEM for Session Resumption

**Source:** TLS 1.3 (RFC 8446, Section 2.2)

**Concept:** Resumed sessions should combine a pre-shared key (ticket secret) with a fresh key exchange to provide forward secrecy, rather than relying on the ticket secret alone.

**Our adaptation:** `DeriveResumptionSecret(psk, freshKEM)` combines the ticket secret with a fresh CH-KEM exchange. Implemented in v0.0.9.

**Difference:** TLS 1.3 uses HKDF-based key scheduling with a PSK binder. CH-KEM uses SHAKE-256 with domain separation (`"CH-KEM-VPN-Resumption"`), feeding both the PSK and fresh KEM output into a single XOF derivation. Our construction is simpler because we have a single KEM type rather than negotiable key exchange groups.

### 2.2 Frequent Key Refresh Cadence

**Source:** Rosenpass (Karolin Varner et al., 2023)

**Concept:** Post-quantum VPN tunnels benefit from frequent key refresh (Rosenpass uses 2-minute re-handshake intervals) to limit the window of exposure if a session key is compromised.

**Our adaptation:** Two-tier rekey architecture - lightweight KDF-only ratcheting for frequent refresh, plus periodic full CH-KEM exchange for cryptographic renewal.

**Difference:** Rosenpass runs a separate key exchange protocol alongside WireGuard, producing a PSK that WireGuard consumes. Our rekey is integrated into the CH-KEM protocol itself. The lightweight tier uses `DeriveRekeySecret(oldMaster, freshKEM)` to ratchet secrets without a separate protocol layer. The full KEM rekey is already authenticated via the session's AEAD cipher (v0.0.9).

### 2.3 CPA-Only Ephemeral KEM

**Source:** Kudelski Security PQ-WG; Stebila-Mosca framework (SAC 2016)

**Concept:** Ephemeral KEM keys that are used once and immediately discarded do not require IND-CCA2 security. A CPA-only (IND-CPA) ML-KEM instantiation is sufficient and more efficient, since the Fujisaki-Okamoto transform's re-encryption check is unnecessary when the ciphertext is never reused.

**Our adaptation:** CPA-only ML-KEM for the lightweight rekey tier (planned). Full handshake retains IND-CCA2 ML-KEM-1024.

**Difference:** Kudelski applies this optimization to the initial handshake. We restrict it to ephemeral rekey exchanges where the key pair is generated, used once, and immediately zeroized. The initial handshake retains full IND-CCA2 security via the standard ML-KEM-1024 Fujisaki-Okamoto transform.

### 2.4 KEM Binding Properties

**Source:** Cremers, Dax, Medinger - "Keeping Up with the KEMs: Stronger Security Notions for KEMs and Automated Analysis of KEM-based Protocols." ACM CCS 2024.

**Concept:** KEM-based protocols require careful binding between the KEM ciphertext, public key, and shared secret to prevent subtle misbinding attacks. The paper defines a hierarchy of binding properties (LEAK-BIND-K-CT, LEAK-BIND-K-PK, etc.) and shows that many deployed protocols fail to achieve them.

**Our adaptation:** Labeled component hashing in `TranscriptHash` - each KEM component is hashed with an explicit label identifying its algorithm and role.

**Difference:** We add `"CH-KEM/1.0/X25519"` and `"CH-KEM/1.0/ML-KEM"` labels as `TranscriptHash` components (planned for v0.0.10). This uses our existing SHAKE-256 domain separation infrastructure rather than the paper's formal Tamarin verification model. The binding property we target is equivalent to their LEAK-BIND-K-CT definition.

### 2.5 Formal Verification Methodology

**Source:** Lafourcade, et al. - "A Tale of Two Worlds: A Formal Story of WireGuard Hybridization." USENIX Security 2025.

**Concept:** Post-quantum hybrid protocols should be formally verified to ensure that the composition of classical and post-quantum primitives does not introduce subtle vulnerabilities absent in either component alone.

**Our adaptation:** ProVerif/Tamarin model of the CH-KEM 4-message handshake (planned for v0.1.0 audit preparation).

**Difference:** Lafourcade's analysis targets WireGuard's Noise IK pattern with bolt-on PQ KEM. Our model will cover CH-KEM's TLS 1.3-structured handshake, which has a fundamentally different message flow (4-message with explicit Finished messages vs. Noise IK's 2-message pattern).

### 2.6 KEM-Based Handshake Optimization

**Source:** Hulsing, Ning, Schwabe, Weber, Zimmermann - "Post-quantum WireGuard." IEEE S&P 2021.

**Concept:** KEM-based handshakes can reduce round trips by merging server response messages, since KEMs (unlike interactive DH) allow the responder to encapsulate in a single message.

**Our adaptation:** 3-message handshake variant merging ServerHello and ServerFinished (planned for v1.0.0+).

**Difference:** Schwabe's PQ-WireGuard maintains WireGuard's Noise IK 2-message pattern. Our optimization targets the TLS 1.3-structured 4-message handshake, reducing it to 3 messages while preserving explicit key confirmation via Finished messages.

### 2.7 Stateless Responder Concepts

**Source:** Rosenpass biscuit pattern (Varner et al., 2023)

**Concept:** Servers can avoid per-connection state during the handshake by encrypting their state into a cookie ("biscuit") sent to the client, which the client returns in subsequent messages. This provides DoS resilience by preventing attackers from exhausting server memory with half-open connections.

**Our adaptation:** Server-encrypted state cookie for DoS resilience (planned for v1.0.0+).

**Difference:** Rosenpass uses a dedicated biscuit key separate from the handshake keys. Our design encrypts the server state using the server's existing AEAD infrastructure with a key derived from the long-term server key, avoiding the need for an additional key management layer.

---

## 3. What We Explicitly Do Not Use

### 3.1 WireGuard / Noise Framework

CH-KEM is not based on the Noise Framework or WireGuard protocol. While we study PQ-WireGuard research for design insights, our protocol uses a TLS 1.3-structured handshake with explicit ClientHello/ServerHello/Finished messages, not Noise's pattern-based message flow.

### 3.2 RKEM / Rebar Construction

We do not implement the Ratcheted KEM (RKEM) or Rebar construction described by Wiggers et al. PQShield, the employer of several Rebar authors, holds 40+ patents in post-quantum cryptography. While the academic paper is CC BY licensed, the underlying construction may be covered by patents. Our key ratcheting uses a simpler `DeriveRekeySecret(oldMaster, freshKEM)` construction based on standard KDF composition.

### 3.3 Dagger KEM

We do not use the Dagger KEM construction (Schwabe et al.) as it is based on Saber, which was not selected for NIST standardization. Our implementation uses NIST-standardized ML-KEM-1024 (FIPS 203) exclusively.

---

## 4. Standards References

The following normative standards directly govern our implementation:

| Standard | Description | Usage in CH-KEM |
|----------|-------------|-----------------|
| NIST FIPS 203 | ML-KEM (Module-Lattice-Based Key-Encapsulation Mechanism) | Post-quantum KEM component |
| RFC 7748 | Elliptic Curves for Security (X25519) | Classical ECDH component |
| NIST FIPS 202 | SHA-3 Standard (SHAKE-256) | Key derivation, domain separation |
| NIST SP 800-56C Rev. 2 | Key-Derivation Methods in Key-Establishment Schemes | KDF design, context/role binding |
| NIST SP 800-38D | Recommendation for GCM Mode | AEAD nonce construction |
| RFC 8446 | TLS 1.3 | Handshake structure, PSK+ECDHE resumption model |

---

## 5. Academic References

1. IETF RFC 8446: "The Transport Layer Security (TLS) Protocol Version 1.3." 2018.

2. Karolin Varner, Wai Yi Feng, David Koisser, Lisa Schmidt, Benjamin Lipp, Prabhanjan Ananth, and Cas Cremers. "Rosenpass: A Formally Verified, Post-Quantum Secure VPN." 2023. <https://rosenpass.eu/>

3. Kudelski Security. "Post-Quantum WireGuard." NIST 3rd Post-Quantum Cryptography Standardization Conference, 2021.

4. Douglas Stebila and Michele Mosca. "Post-Quantum Key Exchange for the Internet and the Open Quantum Safe Project." Selected Areas in Cryptography (SAC), 2016.

5. Cas Cremers, Alexander Dax, and Niklas Medinger. "Keeping Up with the KEMs: Stronger Security Notions for KEMs and Automated Analysis of KEM-based Protocols." ACM Conference on Computer and Communications Security (CCS), 2024.

6. Pascal Lafourcade, Dhekra Mahmoud, and Sylvain Music. "A Tale of Two Worlds: A Formal Story of WireGuard Hybridization." USENIX Security Symposium, 2025.

7. Andreas Hulsing, Kai-Chun Ning, Peter Schwabe, Fiona Johanna Weber, and Philip R. Zimmermann. "Post-quantum WireGuard." IEEE Symposium on Security and Privacy (S&P), 2021.

---

*Document Version: 1.0*
*Last Updated: 2026-03-13*
