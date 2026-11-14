# Related work

This document compares the protocol with the closest published work and lists what that work shows the protocol has not covered. Written 2026-11-13.

**Method and limits.** Each entry states how much of its source was read. Most entries rest on the abstract and metadata page alone, so a statement about a paper's results is limited to what the abstract says and may be imprecise. Statements about this library come from the code and [PROTOCOL.md](../PROTOCOL.md). Statements marked **Inference** are the maintainers' reading, not the authors' claim. Each gap links to its tracking issue. No comparison here should be quoted before it is checked against the full paper.

## PQ-WireGuard and its hybrids

### Revisiting PQ WireGuard (Hashimoto, Katsumata, Niot, Wiggers; IEEE S&P 2026)

[ePrint 2025/1758](https://eprint.iacr.org/2025/1758). Read: abstract page.

- Redesigns the post-quantum WireGuard handshake and proves it secure in a new computational model that captures features the first analysis (Hulsing et al.) did not model. The motivation includes the server memory cost of large Classic McEliece public keys and KEM binding issues (it cites Cremers et al., CCS 2024).
- Its building block is a "reinforced KEM" (Rebar). This library does not use it. The ephemeral exchange uses ML-KEM, so the Classic McEliece key-size problem that motivates the construction does not arise here.
- **Same:** a handshake built from KEMs instead of Diffie-Hellman, with a binding concern addressed in the design.
- **Different (per its abstract):** the authors give a computational proof; we give symbolic ProVerif models only. The original PQ-WireGuard design aimed to fit the handshake in one UDP packet (the abstract says so). Our datagram handshake is fragmented, because ML-KEM-1024 key shares do not fit, and uses a cookie against floods; our stream transport is plain TCP.
- **Gap:** no computational proof of our handshake. [#277](https://github.com/sara-star-quant/Quantum-Go/issues/277) scopes one (a plan and dossier); the proof itself is not started.

### A Tale of Two Worlds (Lafourcade, Mahmoud, Ruhault, Taleb; USENIX Security 2025)

[ePrint 2025/1179](https://eprint.iacr.org/2025/1179). Read: abstract page.

- Finds weaknesses in the original PQ-WireGuard, fixes them (PQ-WireGuard*), builds Hybrid-WireGuard from WireGuard and PQ-WireGuard*, and proves it with the SAPIC+ framework, which generates ProVerif, DeepSec and Tamarin models from one specification.
- **Same:** hybrid classical plus post-quantum design, ProVerif as a verifier.
- **Different (per its abstract):** they generate models for more than one tool (ProVerif, DeepSec, Tamarin) from a single specification.
- **Inference:** SAPIC+ would let us run the same model through Tamarin as a second opinion on the properties we already prove, without writing the model twice. Tracked in [#280](https://github.com/sara-star-quant/Quantum-Go/issues/280).

## Combiners and KEM binding

### X-Wing (Barbosa, Connolly, Duarte, Kaiser, Schwabe, Varner, Westerbaan)

[ePrint 2024/039](https://eprint.iacr.org/2024/039). Read: abstract page.

- A hybrid KEM from X25519 and ML-KEM-768 with SHA3-256. IND-CCA secure if the strong Diffie-Hellman assumption holds in the X25519 group (random oracle model), or if ML-KEM-768 is IND-CCA secure and SHA3-256 is a secure PRF (standard model). The authors say the efficiency gain depends on the concrete components and may not carry to other pairs.
- **Same:** the X-Wing suite in this library is X-Wing, byte for byte, from circl, gated by the specification's vectors.
- **Different:** CH-KEM-v1, the default suite, is our own combiner (X25519 and ML-KEM-1024 through a SHAKE-256 KDF). The X-Wing proof does not cover it. Its security rests on our symbolic models and on the combiner design (below), not on a published computational proof.
- **Gap:** a computational argument for the CH-KEM-v1 combiner. [#277](https://github.com/sara-star-quant/Quantum-Go/issues/277) scopes it (a plan and dossier); the proof itself is not started.

### Keeping Up with the KEMs (Cremers, Dax, Medinger)

[ePrint 2023/1933](https://eprint.iacr.org/2023/1933). Read: abstract page.

- Defines stronger "binding" notions for KEMs (how a KEM's outputs determine other values), proves relations between them, and gives a Tamarin library to derive the binding a protocol needs or to check it against a concrete KEM. Its example shows the key exchange from the original Kyber paper needing stronger properties than the paper proved, via re-encapsulation attacks.
- **Same:** our design does not assume the KEM is binding. The CH-KEM-v1 combiner input is `TH(pk_x25519, pk_mlkem, ct_x25519_ephemeral, ct_mlkem, 0x0002, role)` plus both shared secrets (PROTOCOL.md section 4.1), so both public keys, both ciphertexts, a combiner version and the role enter the derived secret.
- **Not checked:** whether that input meets the specific binding properties in the paper. Only the abstract was read; it does not list the properties or say which standardized KEMs satisfy them. Checking this with the paper's Tamarin library is tracked in [#280](https://github.com/sara-star-quant/Quantum-Go/issues/280).

### KEMTLS (Schwabe, Stebila, Wiggers; CCS 2020)

[ePrint 2020/534](https://eprint.iacr.org/2020/534). Read: abstract page.

- Authenticates the TLS 1.3 server with a KEM instead of a signature, to save bandwidth and server CPU.
- **Same idea:** our optional static-key pin makes the client encapsulate to the server's long-term KEM key, so the server proves possession by decapsulating, with no signature anywhere in the protocol.
- The abstract page does not describe the message flow or round trips, so no comparison of the two is made here. **Inference:** pinning a pre-distributed key is what lets our handshake stay at one round trip; the details need the full paper.

## Standards

### RFC 10024: PQ/T hybrid key agreement for TLS 1.3 (Kwiatkowski, Kampanakis, Westerbaan, Stebila; August 2026)

[RFC 10024](https://www.rfc-editor.org/info/rfc10024/). Read: info page (title, status, abstract and the regulatory note).

- Proposed Standard defining X25519MLKEM768, SecP256r1MLKEM768 and SecP384r1MLKEM1024. For X25519MLKEM768 it says the ML-KEM implementation must be certified in a FIPS-approved setting.
- **Consistent with:** building the ML-KEM leg on Go's FIPS module in `-tags fips` builds ([PERFORMANCE.md](../PERFORMANCE.md#kem-backend-circl-and-the-standard-library)). CH-KEM-v1 is not a TLS group and none of this standard is claimed for it.

## Implementation attacks

### Decryption failure oracle attack on ML-KEM (Guo, Nabokov, Johansson; USENIX Security 2026)

[USENIX page](https://www.usenix.org/conference/usenixsecurity26/presentation/guo-qian), [ePrint 2026/070](https://eprint.iacr.org/2026/070). Read: abstract text from search results only; the PDF could not be read here.

- A chosen-ciphertext side-channel attack that uses a decryption-failure oracle, combining adaptive queries with belief propagation over LDPC codes. For ML-KEM-768 with a 95 percent accurate oracle it needs 2,950 queries, against 7,000 perfect-oracle queries for a prior attack.
- **Inference, not the authors' claim:** such an attack needs many queries against one decapsulation key. Our ephemeral keys decapsulate once, so they offer one query. A long-lived decapsulation key that sees attacker-chosen ciphertexts is the exposed surface: the server's static key in the pin leg today, and a client device key (planned, [#236](https://github.com/sara-star-quant/Quantum-Go/issues/236)) decapsulating ciphertexts a hostile server chooses. The rate limits in forward mode and the library bound query volume, but they were not designed as a countermeasure for this.
- **Gap:** no analysis of this exposure for the static-key leg. To be written before device keys ([#236](https://github.com/sara-star-quant/Quantum-Go/issues/236)) and considered in the constant-time and side-channel work ([#276](https://github.com/sara-star-quant/Quantum-Go/issues/276)).

### Phantom Timing Leaks on Cortex-M4 (Anne; ePrint 2026/2744)

[ePrint 2026/2744](https://eprint.iacr.org/2026/2744). Read: abstract page.

- A pre-registered study of dudect-style fixed-versus-random timing tests on nine ML-KEM decapsulation implementations. Invalid ciphertexts showed no difference in 18 of 18 campaigns; fresh valid ciphertexts flagged all nine implementations by 4 to 15 cycles; a matched control removed the difference for seven; an A/A test with identical inputs still gave a huge statistic for one. The authors conclude a harness can create the "leak", and recommend matched controls, A/A tests and per-trial correctness checks (they found 220 wrong shared secrets in 49,830 trials of one build).
- **Applies to us as method:** the constant-time work ([#276](https://github.com/sara-star-quant/Quantum-Go/issues/276)) runs an A/A control and a matched control first, and checks correctness per trial.

## Coverage of the literature search

A search of arXiv, ePrint and general web results on 2026-11-13 found no paper that formally verifies a hybrid ML-KEM plus X25519 tunnel handshake with a datagram transport, a stateless cookie and static-key pinning. That is a statement about that search, not a survey of the field, and not a claim of novelty.

## Open questions this review raises

| Question | Tracked in |
|---|---|
| Computational proof of the CH-KEM-v1 combiner and the handshake | [#277](https://github.com/sara-star-quant/Quantum-Go/issues/277), which scopes it; the proof is not started |
| Combiner binding check, a second-verifier run, key-compromise impersonation and identity-hiding queries for the current handshake | [#280](https://github.com/sara-star-quant/Quantum-Go/issues/280) |
| Models for rekey, cookie and replay | [#252](https://github.com/sara-star-quant/Quantum-Go/issues/252) |
| Chosen-ciphertext exposure of long-lived decapsulation keys | [#236](https://github.com/sara-star-quant/Quantum-Go/issues/236) (device keys), [#276](https://github.com/sara-star-quant/Quantum-Go/issues/276) (side-channel tests) |
| Read the full papers, not only abstracts, before a public claim leans on them | [#272](https://github.com/sara-star-quant/Quantum-Go/issues/272), which stays open for this |
