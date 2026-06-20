# Conformance test vectors

`vectors.json` is the published known-answer vector set for the Quantum-Go protocol.
An independent implementation can validate byte-for-byte that it matches the CH-KEM-v1
and X-Wing constructions, the key schedule, the wire encoding, and the record layer.

The file is generated from, and checked against, the implementation by
`test/conformance/conformance_test.go`. Regenerate it with:

```
go test ./test/conformance/ -update
```

CI runs the test without `-update`, so any drift fails. A change to `vectors.json`
means a crypto-core or wire change; scrutinize the diff.

## Format

All byte fields are lowercase hex. `format_version` is the schema version. `digest` is
the SHA-256 of the canonical (compact) JSON with the `digest` field cleared.

- `kem_suites[]`: for each KEM suite, `seed` -> `public_key`, and `encap_seed` ->
  `ciphertext` + `shared_secret`.
- `key_schedule`: a fixed `master_secret` (and a fixed `transcript`) -> the handshake
  keys/IVs, traffic keys, stream and datagram nonce prefixes, and the Finished
  verify_data values.
- `auth_folds`: the static-key and PSK authentication folds.
- `wire_messages[]`: fixed message structs -> their exact encoded bytes.
- `records[]`: a fixed traffic key + nonce prefix + sequence + plaintext -> the AEAD
  ciphertext and the assembled Data record, per cipher suite. The ChaCha20-Poly1305
  record is absent under the FIPS build.

## Reproduction recipe

Constructions and framing are normative in `docs/PROTOCOL.md` (the KDF and transcript
framing in Section 2, the KEM combiner in Section 4, the key schedule in Section 5, the
record layer in Section 7). Anchored to FIPS 203 (ML-KEM), RFC 7748 (X25519), FIPS 202
(SHA-3/SHAKE), and the X-Wing draft, so the vectors are cross-implementation.

Seed and coin semantics:

- CH-KEM-v1 `seed` (96 bytes) = 32-byte X25519 private scalar || 64-byte ML-KEM
  key-generation seed (FIPS 203). `encap_seed` (64 bytes) = 32-byte X25519 ephemeral
  scalar || 32-byte ML-KEM encapsulation coins. The ciphertext is
  `X25519_ephemeral_public || ML-KEM_ciphertext`; the shared secret follows the
  Section 4.1 combiner with the encapsulator role = responder (`0x02`).
- X-Wing `seed` (32 bytes) is the X-Wing key-derivation seed; `encap_seed` (64 bytes) is
  the X-Wing encapsulation seed (draft-connolly-cfrg-xwing-kem).
- The nonce in a record vector is `nonce_prefix || seq` (4 + 8 bytes); the AEAD AAD is
  the 8-byte big-endian `seq`.
