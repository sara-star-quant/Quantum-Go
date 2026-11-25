# Claims register

Every security claim this project makes, with one status and the evidence behind it. A reader can check any claim by following its evidence column, and `scripts/check-claims.py` runs in CI to make sure each row is well formed, that the files and tests it names exist, and that no document cites a claim ID that is not here. The script does not judge whether a claim is true. That is the reader's job, and this page is there to make it quick.

Last checked: 2026-11-19, repository state at the commit that added this page.

## Statuses

A status says what kind of evidence stands behind the claim. It is not a grade.

| Status | What it means | What the evidence column must name |
|---|---|---|
| Proven | A machine-checked proof of the claim exists, with its assumptions stated | A file that holds it. No row has this status today |
| Modelled | A symbolic model checks the claim. The result is a statement about the model under perfect-cryptography assumptions; ProVerif produces no certificate another tool can check | A model file (`.pv`), and a negative twin where one exists |
| Tested | A named automated test fails when the claim stops holding, and a mutation of the code it covers makes the test fail | At least one `Test` or `Fuzz` function that exists |
| Argued | A written argument exists and has not been independently reviewed or machine-checked | The document, and the issue that tracks the open points |
| Cited | The claim rests on a published standard or an external source, not on this project's own evidence | A URL, or an RFC or FIPS number |
| Not claimed | A reader might assume the property, and the project does not provide it | The file that says so |

## How to read a row

The claim is stated as narrowly as the evidence allows. A row marked Modelled says nothing about the Go code beyond what C-15 says. A row marked Tested covers the cases the test builds, no more. Where a claim has two kinds of evidence, the status names the strongest one the project produced itself, and the evidence column lists the rest.

## Adding or changing a claim

1. Write the claim in one sentence that a hostile reader could try to break.
2. Pick the status the evidence earns, not the one the sentence would like.
3. Name the evidence in backticks so the script can check it. Do not use a pipe character in a cell.
4. Cite the ID (for example C-03) wherever a document makes the claim.
5. When evidence changes, change the row in the same pull request.

## Register

| ID | Claim | Status | Evidence | Stated in |
|---|---|---|---|---|
| C-01 | ML-KEM-1024 is IND-CCA2 secure | Cited | FIPS 203, https://csrc.nist.gov/pubs/fips/203/final. `TestWycheproofMLKEM1024` checks our wrapper against independent vectors on both builds; it says nothing about the scheme's security | SECURITY.md, docs/PROTOCOL.md |
| C-02 | X25519 gives Diffie-Hellman key agreement under a Diffie-Hellman-type assumption, and our wrapper refuses an all-zero shared secret | Cited | RFC 7748. `TestWycheproofX25519` pins the refusal and the standard's edge cases | SECURITY.md |
| C-03 | The CH-KEM-v1 combiner is IND-CCA2 secure if either component holds | Argued | `docs/math/MATHEMATICAL_FOUNDATION.md` section 7.1, a self-authored sketch whose status note lists two open points (an additive bound, and the assumption for the Diffie-Hellman leg). #277 tracks the computational proof | SECURITY.md, README.md, docs/math/MATHEMATICAL_FOUNDATION.md, docs/technical/RELATED_WORK.md |
| C-04 | The session key stays secret if either leg holds, against a symbolic network attacker | Modelled | `docs/formal/chkem_hybrid.pv`, `docs/formal/RESULTS.txt`, negative twin `docs/formal/negative/hybrid_broken.pv` | README.md, SECURITY.md, docs/COMPARISON.md, docs/formal/README.md |
| C-05 | Session keys stay secret after a long-term key leaks (forward secrecy), in the symbolic model | Modelled | `docs/formal/chkem_fs.pv`, negative twin `docs/formal/negative/fs_broken.pv` | SECURITY.md, docs/formal/README.md |
| C-06 | A client that pins the server key authenticates the server, and an active relay is refused | Modelled | `docs/formal/chkem_auth.pv`, negative twin `docs/formal/negative/auth_broken.pv`; `TestStaticAuthWrongPinRejected` and `TestDgramStaticAuthWrongPinRejected` show both transports refuse a wrong pin | SECURITY.md, docs/formal/README.md |
| C-07 | Holders of the same PSK authenticate each other | Modelled | `docs/formal/chkem_psk.pv`, negative twin `docs/formal/negative/psk_broken.pv` | SECURITY.md, docs/formal/README.md |
| C-08 | A forged or stripped suite offer, or a forged HelloRetryRequest, does not downgrade the suite | Modelled | `docs/formal/chkem_negotiation.pv`, negative twin `docs/formal/negative/negotiation_broken.pv`; `TestHandshakeRejectsDowngradedServerHello` | docs/technical/THREAT_MODEL.md, docs/formal/README.md |
| C-09 | A rekey keeps earlier epochs secret after an epoch master leaks, and an attacker with no keys cannot get a forged rekey accepted | Modelled | `docs/formal/chkem_rekey.pv`, `docs/formal/chkem_rekey_auth.pv`. The model records a limit: an attacker who already holds the current master can read the next epoch (`docs/formal/negative/rekey_active_after_compromise.pv`) | docs/formal/README.md |
| C-10 | The datagram server allocates handshake state for a spoofed address only if it issued a cookie to that address's owner, and it stops creating reassembly state for cookieless sources at the high-water mark | Modelled | `docs/formal/chkem_cookie.pv`, negative twins `docs/formal/negative/cookie_no_address_binding_broken.pv` and `docs/formal/negative/cookie_mac_not_verified_broken.pv`; `TestCookieGateStopsNewReassemblyStateAtTheHighWaterMark` | docs/datagram-dos.md |
| C-11 | A stream record is delivered at most once, and a forged record cannot use up a sequence number | Tested | `TestStreamForgedFrameDoesNotConsumeSequenceNumbers`, `TestStreamDuplicateGenuineFrameDeliversOnce`, `TestRekeyAtSessionLevelCarriesDataBothWaysAndRejectsBoundaryReplay`. Replay is not modelled symbolically (`docs/formal/README.md`) | SECURITY.md |
| C-12 | A stream handshake that loses its link at any step fails with the link's own error and leaves its session closed | Tested | `TestStreamHandshakeSurvivesAnIOFaultAtEveryStep` | CHANGELOG.md |
| C-13 | Memory held for pre-authentication fragment reassembly stays within sources times per-source buffers times message size | Tested | `TestReassemblerHeldBytesStayWithinTheCapsAndAmplificationIsRecorded`, which also records an amplification of 2,304 times at its test ceiling, because buffers take the size a sender declares | docs/datagram-dos.md |
| C-14 | The wrappers around ML-KEM-1024, X25519, AES-256-GCM and ChaCha20-Poly1305 match independent test vectors | Tested | `TestWycheproofMLKEM1024`, `TestWycheproofX25519`, `TestWycheproofAEAD`, `pkg/crypto/testdata/wycheproof/README.md` | pkg/crypto/testdata/wycheproof/README.md |
| C-15 | The Go code implements the modelled protocol | Not claimed | `docs/formal/README.md` (Scope and model fidelity): the models check the design, and the conformance vectors in `test/conformance` pin the primitives only | docs/formal/README.md |
| C-16 | Secret-handling code runs in constant time | Not claimed | `docs/technical/RELATED_WORK.md`; upstream libraries document constant-time implementations and this project has not tested it. #276 tracks the test | SECURITY.md |
| C-17 | A third party has audited this library | Not claimed | `SECURITY.md`, `docs/SCOPE.md` | README.md, SECURITY.md, docs/COMPARISON.md |
| C-18 | This library is a FIPS 140-3 validated module | Not claimed | `docs/SCOPE.md`, `docs/FIPS.md` | README.md, docs/SCOPE.md |
| C-19 | The CH-KEM-v1 key binds both public keys, both ciphertexts, the protocol version and the role, for honest and leaked key pairs (the K-binds-PK and K-binds-CT properties of Cremers, Dax and Medinger), with the component secrets held equal | Tested | `TestCombinerKeyBindsEveryBoundValue`, `TestCombinerFramingSeparatesAdjacentValues`, `TestDecapsulateUnderAnotherKeyPairOrRoleGivesAnotherKey`; the combination is `combineKey` in `pkg/chkem/chkem.go`. Each bound value was dropped from the derivation to confirm a test fails | docs/PROTOCOL.md |
| C-20 | The key stays bound when an adversary chooses the key pairs (the malicious-key forms), and the ciphertext alone binds the key or the public key | Not claimed | `pkg/chkem/binding_test.go` (header comment). The handshake never lets an adversary choose our key pairs, and the paper shows a KEM with implicit rejection, such as ML-KEM, cannot give ciphertext-only binding. #280 tracks any further binding analysis | pkg/chkem/binding_test.go |
| C-21 | A datagram session closes after 2^36 datagrams fail authentication, counted across all epochs, so one AEAD key allows an attacker only a bounded number of forgery attempts | Tested | `TestDatagramSessionClosesAtTheForgeryLimit`, `TestUnknownEpochFramesDoNotSpendTheForgeryBudget`, `TestForgedRekeyControlSpendsTheForgeryBudget`, `TestForgeryLimitTearsDownTheConnection`. The limit is the RFC 9001 section 6.6 figure for ChaCha20-Poly1305. The stream transport ends the session on the first failed record, so it needs no counter | docs/PROTOCOL.md |
| C-22 | One AES-256-GCM key never seals enough to exceed the TLS 1.3 confidentiality target of 2^-60: the packet and byte caps keep s + q + 1 below 2^34.5 for both transports | Tested | `TestRekeyLimitsKeepAESGCMConfidentialityWithinTheTLSTarget` checks the constants against the bound of the CFRG AEAD limits draft; it does not prove AES-GCM secure. The datagram margin is thin (about 2^-60.5 at the hard cap), and the test fails if the MTU or a cap grows | docs/PROTOCOL.md |
