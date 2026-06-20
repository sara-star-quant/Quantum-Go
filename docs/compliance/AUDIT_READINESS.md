# Audit readiness

This document prepares Quantum-Go for a third-party security audit: it states the scope, inventories
the cryptography, maps each security claim to its evidence, records the supply-chain posture, lists the
known limitations honestly, and points to everything an auditor needs. It is not an audit and makes no
certification claim; it is the package an auditor (or a buyer's security team) starts from.

Protocol version: 5.0. Last updated: 2026-06-20.

## 1. Scope

In scope for a cryptographic-protocol audit:
- The handshake and key schedule (`pkg/tunnel/handshake.go`, `pkg/crypto/kdf.go`), KEM-suite negotiation
  and HelloRetryRequest, and the Finished/transcript binding.
- The KEM constructions (`pkg/chkem`): CH-KEM-v1 (ML-KEM-1024 + X25519) and X-Wing (ML-KEM-768 + X25519),
  and the static-key / PSK authentication folds.
- The record layer, rekey ratchet, replay window, and the datagram fragmentation + return-routability
  cookie (`pkg/tunnel`, `pkg/protocol`).
- The cryptographic wrappers (`pkg/crypto`) over the underlying primitives.

Out of scope (audit the deployment separately): operating-system and hardware security, the host CSPRNG
beyond its use, side channels in the underlying libraries (delegated to those projects' audits), and the
application protocol carried inside the tunnel.

## 2. System overview and trust boundaries

A TLS 1.3-structured 4-message handshake establishes a hybrid post-quantum session key, then an
authenticated-encryption record layer carries data over a stream (TCP) or datagram (UDP) transport. The
adversary model, assets, and trust boundaries are in
[`../technical/THREAT_MODEL.md`](../technical/THREAT_MODEL.md); the wire protocol is specified in
[`../PROTOCOL.md`](../PROTOCOL.md).

## 3. Cryptographic inventory

| Primitive | Standard | Implementation | Use |
| --------- | -------- | -------------- | --- |
| ML-KEM-1024 | FIPS 203 | cloudflare/circl v1.6.3 | CH-KEM-v1 PQ leg (ephemeral + static) |
| ML-KEM-768 | FIPS 203 | cloudflare/circl v1.6.3 | X-Wing PQ leg |
| X25519 | RFC 7748 | Go stdlib `crypto/ecdh` | classical leg in both suites |
| X-Wing | draft-connolly-cfrg-xwing-kem | cloudflare/circl `kem/xwing` | SuiteXWing (byte-exact) |
| SHAKE-256 / SHA3-256 | FIPS 202 | Go stdlib `crypto/sha3` | combiner, KDF, transcript hash |
| AES-256-GCM | NIST SP 800-38D | Go stdlib `crypto/aes`+`cipher` | AEAD record layer (FIPS-approved) |
| ChaCha20-Poly1305 | RFC 8439 | golang.org/x/crypto | AEAD record layer (non-FIPS) |

The combiner and key schedule (domain-separation labels, framing) are specified in PROTOCOL.md Sections 2,
4, 5, and 7. There is no bespoke primitive: every algorithm is a published standard from a vetted library.

## 4. Security claims to evidence

Each claim from [`../../SECURITY.md`](../../SECURITY.md) maps to concrete, reproducible evidence.

| Claim | Evidence |
| ----- | -------- |
| IND-CCA2 hybrid (secure if either leg holds) | computational argument in [`../math/MATHEMATICAL_FOUNDATION.md`](../math/MATHEMATICAL_FOUNDATION.md) 7.1; machine-checked symbolic proof `docs/formal/chkem_hybrid.pv` |
| Session-key secrecy | `docs/formal/chkem_secrecy.pv` (ProVerif) |
| Forward secrecy | `docs/formal/chkem_fs.pv`; rekey ratchet (PROTOCOL.md 8) |
| Server authentication (static-key) | `docs/formal/chkem_auth.pv` (injective); `pkg/tunnel` static-auth tests |
| Downgrade resistance | HRR synthetic-hash transcript (PROTOCOL.md 5.2); the transcript-agreement proof; `TestHRRClientHello1TamperBreaksFinished` |
| Replay protection | 1024-bit sliding window; `pkg/tunnel` replay tests |
| Wire conformance / interop | `docs/PROTOCOL.md`; published known-answer vectors `testdata/conformance/` |
| Standard primitives, correctly used | conformance vectors + X-Wing spec-vector KAT |
| FIPS operational posture | [`../FIPS.md`](../FIPS.md); POST/CST self-tests; the FIPS build/test CI job |

## 5. Supply chain

Direct dependencies are few and reputable: `cloudflare/circl` (PQ primitives), `golang.org/x/crypto`,
`golang.org/x/net`, `golang.org/x/sys`, and OpenTelemetry for observability. Versions are pinned in
`go.mod`/`go.sum`. `govulncheck` runs in CI (the `vuln` job) and currently reports no known
vulnerabilities. License: Apache 2.0 (with a `NOTICE` file); dependencies are permissively licensed.

## 6. Known limitations (honest)

- The handshake is unauthenticated by default; endpoint authentication (static-key pinning, PSK mutual) is
  opt-in. An unconfigured tunnel provides encryption and forward secrecy but not peer identity.
- Resumption tickets are not yet bound to server identity (verified-open; design captured, not shipped).
- Sequence-based nonces require single-threaded or externally-synchronized use of a session's keys.
- Side-channel and constant-time guarantees rely on the underlying libraries (Go stdlib, circl).
- Key-compromise impersonation is not a design goal.
- The formal proofs are symbolic (perfect-cryptography); they verify the protocol composition, not the Go
  implementation byte-for-byte (the conformance vectors pin that), and do not replace the computational
  argument. See `docs/formal/README.md`.

## 7. Reproducing the evidence

```
go test ./... -race                 # full suite, including conformance and auth tests
go test -tags fips ./...            # FIPS build and tests
go run golang.org/x/vuln/cmd/govulncheck@latest ./...   # supply-chain scan
docs/formal/verify.sh               # machine-checked ProVerif proofs (+ negative tests)
go test ./test/conformance/         # known-answer vectors vs testdata/conformance/vectors.json
```

CI gates all of the above (test, lint, govulncheck, FIPS, and the path-filtered formal-proof workflow).

## 8. Artifact index

- Wire protocol specification: [`../PROTOCOL.md`](../PROTOCOL.md)
- Threat model: [`../technical/THREAT_MODEL.md`](../technical/THREAT_MODEL.md)
- Mathematical foundation (computational argument): [`../math/MATHEMATICAL_FOUNDATION.md`](../math/MATHEMATICAL_FOUNDATION.md)
- Formal verification (symbolic proofs): [`../formal/README.md`](../formal/README.md) + `RESULTS.txt`
- Conformance vectors: `../../testdata/conformance/` (README + vectors.json)
- Security policy and properties: [`../../SECURITY.md`](../../SECURITY.md)
- FIPS posture: [`../FIPS.md`](../FIPS.md) and [`FIPS_140_3_ROADMAP.md`](FIPS_140_3_ROADMAP.md)
- Design influences and attributions: [`../DESIGN_INFLUENCES.md`](../DESIGN_INFLUENCES.md)

## 9. Readiness checklist and recommended focus

Ready: documented wire protocol; machine-checked symbolic proofs with non-vacuity negative tests;
reproducible interop vectors; threat model; computational argument; clean govulncheck; FIPS build mode with
POST/CST; gosec/lint/race CI gates.

Recommended auditor focus: the combiner and key-schedule domain separation; the HRR synthetic-hash
transcript and downgrade resistance; the static-key/PSK fold and the suite-dispatch of the static leg; the
datagram return-routability and reassembly anti-DoS bounds; nonce derivation and the replay window across a
rekey; and the model-to-code fidelity gap noted in the formal README.
