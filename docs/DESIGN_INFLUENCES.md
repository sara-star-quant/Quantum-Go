# Design Influences

## 1. Design Philosophy

Quantum-Go's Cascaded Hybrid KEM (CH-KEM) is an independently designed protocol with a TLS 1.3-structured handshake. It is not a fork, derivative, or reimplementation of any existing tunnel protocol, including WireGuard, the Noise Framework, or any post-quantum WireGuard variant.

The protocol draws on published post-quantum cryptography research and public standards, adopting general concepts and design principles where they improve security. This document credits those sources and states how our approach differs. It is an engineering record, not legal advice; the licensing posture is in [section 6](#6-licensing-and-attribution-posture).

**Guiding rule:** We adapt general cryptographic concepts and design principles. We do not copy code, wire formats, protocol state machines, or specific novel constructions from any project.

---

## 2. Academic Influences

### 2.1 PSK + Fresh KEM for Session Resumption

**Source:** TLS 1.3 (RFC 8446, Section 2.2)

**Concept:** Resumed sessions should combine a pre-shared key (ticket secret) with a fresh key exchange to provide forward secrecy, rather than relying on the ticket secret alone.

**Our adaptation:** `DeriveResumptionSecret(psk, freshKEM)` combined the ticket secret with a fresh CH-KEM exchange (v0.0.9). Removed in v0.0.26: nothing in `Dial` or `Listen` used it and it gave no speedup, so it is kept here as history only.

**Difference (history):** the removed construction used SHAKE-256 with its own domain separation label and fed both the PSK and fresh KEM output into a single XOF derivation. The label no longer exists in the code. The PSK mixing the library does ship is the handshake PSK, described in the protocol specification.

### 2.2 Frequent Key Refresh Cadence

**Source:** Rosenpass (Varner et al.; project whitepaper)

**Concept:** Post-quantum tunnels benefit from frequent key refresh (Rosenpass uses 2-minute re-handshake intervals) to limit the window of exposure if a session key is compromised.

**Our adaptation:** Two-tier rekey architecture - lightweight KDF-only ratcheting for frequent refresh, plus periodic full CH-KEM exchange for cryptographic renewal.

**Difference:** Rosenpass runs a separate key exchange protocol alongside WireGuard, producing a PSK that WireGuard consumes. Our rekey is integrated into the CH-KEM protocol itself. The lightweight tier uses `DeriveRekeySecret(oldMaster, freshKEM)` to ratchet secrets without a separate protocol layer. The full KEM rekey is already authenticated via the session's AEAD cipher (v0.0.9).

### 2.3 CPA-Only Ephemeral KEM

**Source:** Kudelski Security's PQ-WireGuard work (Raynal, NIST PQC conference 2021); Stebila-Mosca framework (SAC 2016)

**Concept:** Ephemeral KEM keys that are used once and immediately discarded do not require IND-CCA2 security. A CPA-only (IND-CPA) ML-KEM instantiation is sufficient and more efficient, since the Fujisaki-Okamoto transform's re-encryption check is unnecessary when the ciphertext is never reused.

**Our adaptation:** CPA-only ML-KEM for the lightweight rekey tier (planned). Full handshake retains IND-CCA2 ML-KEM-1024.

**Difference:** Kudelski's design applies this optimization to the initial handshake. We restrict it to ephemeral rekey exchanges where the key pair is generated, used once, and immediately zeroized. The initial handshake retains full IND-CCA2 security via the standard ML-KEM-1024 Fujisaki-Okamoto transform.

### 2.4 KEM Binding Properties

**Source:** Cremers, Dax, Medinger - "Keeping Up with the KEMs: Stronger Security Notions for KEMs and Automated Analysis of KEM-based Protocols." ACM CCS 2024.

**Concept:** KEM-based protocols require careful binding between the KEM ciphertext, public key, and shared secret to prevent subtle misbinding attacks. The paper defines a hierarchy of binding properties (LEAK-BIND-K-CT, LEAK-BIND-K-PK, etc.) and shows that many deployed protocols fail to achieve them.

**Our adaptation:** Labeled component hashing in `TranscriptHash` - each KEM component is hashed with an explicit label identifying its algorithm and role.

**Difference:** We would add `"CH-KEM/1.0/X25519"` and `"CH-KEM/1.0/ML-KEM"` labels as `TranscriptHash` components (not implemented yet; no release is scheduled). This uses our existing SHAKE-256 domain separation infrastructure rather than the paper's formal Tamarin verification model. The binding property we target is equivalent to their LEAK-BIND-K-CT definition.

### 2.5 Formal Verification Methodology

**Source:** Lafourcade, Mahmoud, Ruhault and Taleb - "A Tale of Two Worlds, a Formal Story of WireGuard Hybridization." USENIX Security 2025.

**Concept:** Post-quantum hybrid protocols should be formally verified to ensure that the composition of classical and post-quantum primitives does not introduce subtle vulnerabilities absent in either component alone.

**Our adaptation (delivered):** a ProVerif symbolic model of the CH-KEM handshake machine-checks session-key secrecy, the hybrid "secure if either leg holds" guarantee, forward secrecy, and injective server authentication, with planted-flaw negative tests for non-vacuity. See [docs/formal/](formal/README.md). This is symbolic (Dolev-Yao) verification of the protocol composition; it complements the computational IND-CCA argument in [math/MATHEMATICAL_FOUNDATION.md](math/MATHEMATICAL_FOUNDATION.md).

**Difference:** The Lafourcade et al. analysis targets WireGuard's Noise IK pattern with bolt-on PQ KEM. Our model covers CH-KEM's TLS 1.3-structured handshake, which has a fundamentally different message flow (explicit Finished messages vs. Noise IK's 2-message pattern).

### 2.6 KEM-Based Handshake Optimization

**Source:** Hülsing, Ning, Schwabe, Weber, Zimmermann - "Post-quantum WireGuard." IEEE S&P 2021.

**Concept:** KEM-based handshakes can reduce round trips by merging server response messages, since KEMs (unlike interactive DH) allow the responder to encapsulate in a single message.

**Our adaptation:** 3-message handshake variant merging ServerHello and ServerFinished into one server flight (protocol 6.0). The client is keyed after one round trip.

**Difference:** Schwabe's PQ-WireGuard maintains WireGuard's Noise IK 2-message pattern. Our optimization targets the TLS 1.3-structured 4-message handshake, reducing it to 3 flights while preserving explicit key confirmation via Finished messages.

### 2.7 Stateless Responder Concepts

**Source:** Rosenpass biscuit pattern (Varner et al.; project whitepaper)

**Concept:** Servers can avoid per-connection state during the handshake by encrypting their state into a cookie ("biscuit") sent to the client, which the client returns in subsequent messages. This provides DoS resilience by preventing attackers from exhausting server memory with half-open connections.

**Our adaptation:** The datagram transport already ships a stateless, HMAC-signed return-routability cookie that the client echoes, which gives the DoS-resilience goal without encrypting handshake state. A biscuit-style responder that carries encrypted handshake state remains a candidate (planned for v1.0.0+, not implemented).

**Difference:** Rosenpass uses a dedicated biscuit key separate from the handshake keys. Our design encrypts the server state using the server's existing AEAD infrastructure with a key derived from the long-term server key, avoiding the need for an additional key management layer.

### 2.8 Standardized Hybrid KEM Combiner

**Source:** X-Wing (Barbosa, Connolly, Duarte, Kaiser, Schwabe, Varner, Westerbaan; ePrint 2024/039) and the CFRG/IETF generic hybrid-KEM combiner work.

**Concept:** A hybrid KEM that combines a post-quantum KEM with X25519 should run both shares through a standardized, proof-carrying combiner that binds the ML-KEM ciphertext and the X25519 share into the final key derivation. X-Wing is the concrete, widely-reviewed instantiation of this idea.

**Our adaptation:** X-Wing ships as an opt-in KEM suite (since v0.0.15). The open direction, targeted at v1.0.0, is to align the default CH-KEM combiner step to the standardized construction so the derivation maps to a published IND-CCA proof and an interop profile becomes possible.

**Difference and accuracy note:** X-Wing is fixed to ML-KEM-768 + X25519 (NIST Category 1). Quantum-Go uses ML-KEM-1024 (Category 5), so adopting X-Wing verbatim would downgrade the KEM. The direction is therefore one of two honest options: (a) adapt the combiner *construction* (its labeled SHA3 binding of the ML-KEM ciphertext and X25519 share) to our ML-KEM-1024 instantiation, keeping Category 5; and/or (b) offer an X-Wing-conformant Category-1 profile as an explicit interop option. Our current combiner, `SHAKE-256(K_x25519 || K_mlkem || transcript)`, is already sound and already binds the public keys and ciphertext through the transcript; aligning buys conformance and proof reuse, not a fix for a defect.

---

## 3. What We Explicitly Do Not Use

### 3.1 WireGuard / Noise Framework

CH-KEM is not based on the Noise Framework or WireGuard protocol. While we study PQ-WireGuard research for design insights, our protocol uses a TLS 1.3-structured handshake with explicit ClientHello/ServerHello/Finished messages, not Noise's pattern-based message flow.

### 3.2 Ratcheted and reinforced KEM constructions

We do not implement the ratcheted KEM constructions (RKEM, Rebar) from the post-quantum WireGuard literature. Our key ratcheting uses a simpler `DeriveRekeySecret(oldMaster, freshKEM)` construction built from standard KDF composition. Where a construction's licensing position is unclear, we take the conservative path and stay with standardized primitives.

### 3.3 Non-standardized KEMs

We use only NIST-standardized ML-KEM-1024 (FIPS 203) and, as an opt-in suite, X-Wing (ML-KEM-768 plus X25519). We do not use KEMs that NIST has not standardized.

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
| RFC 8446 | TLS 1.3 | Handshake structure, PSK+ECDHE model (the resumption part was removed in v0.0.26) |

---

## 5. Academic References

1. IETF RFC 8446: "The Transport Layer Security (TLS) Protocol Version 1.3." 2018.

2. Karolin Varner, Benjamin Lipp, Wanja Zaeske, Lisa Schmidt, and Prabhpreet Dua. "Rosenpass" (protocol whitepaper). <https://rosenpass.eu/whitepaper.pdf>

3. Mathilde Raynal (Kudelski Security and EPFL). "PQ-WireGuard: we did it again." NIST Third PQC Standardization Conference, 8 June 2021. <https://csrc.nist.gov/presentations/2021/pq-wireguard-we-did-it-again>

4. Douglas Stebila and Michele Mosca. "Post-Quantum Key Exchange for the Internet and the Open Quantum Safe Project." Selected Areas in Cryptography (SAC), 2016.

5. Cas Cremers, Alexander Dax, and Niklas Medinger. "Keeping Up with the KEMs: Stronger Security Notions for KEMs and Automated Analysis of KEM-based Protocols." ACM Conference on Computer and Communications Security (CCS), 2024.

6. Pascal Lafourcade, Dhekra Mahmoud, Sylvain Ruhault, and Abdul Rahman Taleb. "A Tale of Two Worlds, a Formal Story of WireGuard Hybridization." 34th USENIX Security Symposium, 2025. <https://www.usenix.org/conference/usenixsecurity25/presentation/lafourcade>

7. Andreas Hülsing, Kai-Chun Ning, Peter Schwabe, Fiona Johanna Weber, and Philip R. Zimmermann. "Post-quantum WireGuard." IEEE Symposium on Security and Privacy (S&P), 2021. <https://eprint.iacr.org/2020/379>

8. Manuel Barbosa, Deirdre Connolly, João Diogo Duarte, Aaron Kaiser, Peter Schwabe, Karolin Varner, and Bas Westerbaan. "X-Wing: The Hybrid KEM You've Been Looking For." IACR ePrint 2024/039 (last revised 2025-03-19). <https://eprint.iacr.org/2024/039>

---

## 6. Licensing and attribution posture

- **Concepts, not code.** We adopt published ideas and cite them. We copy no code, wire formats or state machines from any project named here. The only third-party code we ship comes through Go modules, all permissive and listed in [LICENSE_AUDIT.md](compliance/LICENSE_AUDIT.md).
- **Source terms checked.** Papers we build on are used under their stated terms: the post-quantum WireGuard and X-Wing ePrint pages both carry CC BY 4.0 (checked 2026-11-11). We do not build on papers published under non-derivative or non-commercial terms, and we do not take code from repositories without a license file. Rosenpass (Apache-2.0) and Kudelski's pq-wireguard (MIT, archived) are studied for concepts only.
- **Names.** WireGuard, Rosenpass, X-Wing and the other names above identify the works we reference. Their owners hold the rights in those names; our use is descriptive, and nothing here implies endorsement or affiliation.
- **Citations are checked against the source.** Each author list and title above was verified against the publisher or the paper's own page; report a mistake as an issue and we correct it.
- **Not legal advice.** This is an engineering record. Anyone relying on it for a legal question, including patents, should ask counsel.

---

*Document Version: 1.2*
*Last Updated: 2026-11-11*
