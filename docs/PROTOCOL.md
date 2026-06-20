# Quantum-Go Wire Protocol Specification

**Status:** Interop profile, descriptive of the current implementation.
**Wire protocol version:** 5.0
**Last updated:** 2026-06-20

This document specifies the Quantum-Go tunnel handshake and KEM negotiation on the wire, so that an
independent implementation can interoperate and so the construction maps to published cryptographic
standards. It covers the handshake and key schedule; the data-plane record layer, rekey, and datagram
fragmentation are specified separately (see `docs/datagram-transport.md` and a forthcoming data-plane
section). This is a profile of an existing implementation, not an IETF standards-track document.

## 1. Scope and versions

Two independent version numbers appear and MUST NOT be conflated:

- **Wire protocol version** `protocol.Current = 5.0` (major 5, minor 0). Carried in ClientHello and
  ServerHello. Compatibility is major-only: a peer accepts another peer iff the major versions match. Major
  5 length-prefixes the KEM material so the wire carries suite-dependent key and ciphertext sizes.
- **KEM combiner version** `0x0002`. A fixed 2-byte tag bound into the CH-KEM-v1 combiner transcript for
  domain separation of the KEM construction itself (Section 4.1). It is internal to the combiner and is not
  negotiated.

Roles: the **initiator** (client) decapsulates; the **responder** (server) encapsulates. The role is bound
into the combiner transcript for reflection resistance (Section 4.1).

## 2. Cryptographic primitives and notation

- `SHAKE-256` (FIPS 202): the extendable-output function used for all key derivation.
- `SHA3-256` (FIPS 202): the fixed-output hash used for transcript hashing.
- `||` denotes concatenation. `len32(x)` is the 4-byte big-endian length of `x`. `len16`, `len8` likewise.

Two framing functions are normative:

- `KDF(domain, [in_1, ..., in_n], L)` = `SHAKE-256( len32(|domain|) || domain || len32(n) ||
  len32(|in_1|) || in_1 || ... || len32(|in_n|) || in_n )` read for `L` bytes. (`DeriveKeyMultiple`.)
- `TH(c_1, ..., c_m)` = `SHA3-256( len32(m) || len32(|c_1|) || c_1 || ... || len32(|c_m|) || c_m )`.
  (`TranscriptHash`.)

All key-schedule labels are ASCII domain-separation strings, listed in Section 6.

## 3. KEM suites

A KEM suite is identified by a 2-byte `SuiteID` and produces a 32-byte shared secret. The shared-secret
size is uniform across suites, so the key schedule (Section 5) is suite-independent; only the public-key
and ciphertext sizes and the internal construction differ.

| SuiteID | Name | Construction | Pubkey | Ciphertext | NIST cat | FIPS |
| ------- | ---- | ------------ | ------ | ---------- | -------- | ---- |
| 0x0001  | CH-KEM-v1 | ML-KEM-1024 + X25519, SHAKE-256 combiner | 1600 | 1600 | 5 | yes (operational) |
| 0x0002  | X-Wing | ML-KEM-768 + X25519, draft-connolly-cfrg-xwing-kem | 1216 | 1120 | 1 | yes (operational) |

CH-KEM-v1 is the mandatory-to-implement default: any two conforming peers share it, so negotiation always
succeeds. "FIPS (operational)" means the suite is permitted in the FIPS build; it is a hybrid that uses
X25519, so it is an operational posture, not a strict FIPS 140-3 algorithm claim.

### 3.1 CH-KEM-v1 (0x0001)

A cascaded hybrid of ML-KEM-1024 (FIPS 203) and X25519 (RFC 7748). Serialized public key and ciphertext
are the 32-byte X25519 part followed by the 1568-byte ML-KEM part. The combiner is specified in Section
4.1. The construction follows the standardized hybrid-KEM combiner direction (X-Wing / CFRG generic
combiner): both shares are bound, together with the public keys and ciphertexts, into a SHA3 transcript
that feeds the final SHAKE-256 derivation. It keeps ML-KEM-1024 (Category 5) rather than adopting X-Wing
verbatim (which fixes ML-KEM-768, Category 1).

### 3.2 X-Wing (0x0002)

The standardized X-Wing KEM (ML-KEM-768 + X25519, draft-connolly-cfrg-xwing-kem), wrapped byte-for-byte
from a certified implementation, so its outputs are interoperable with any other X-Wing peer. X-Wing's
combiner is fixed by its specification; role and version binding therefore come from the handshake
transcript (Section 5), not from the KEM. X-Wing is the explicit Category-1 interop profile.

## 4. KEM operations

`Encapsulate(recipient_pk, role) -> (ciphertext, shared_secret)` and
`Decapsulate(ciphertext, key_pair, role) -> shared_secret`.

### 4.1 CH-KEM-v1 combiner

Let `K_x` be the X25519 shared secret (RFC 7748 Diffie-Hellman between the ephemeral and recipient keys)
and `K_m` the ML-KEM-1024 shared secret. Both peers compute the same transcript hash:

```
transcript = TH( pk_x25519, pk_mlkem, ct_x25519_ephemeral, ct_mlkem, 0x0002, role )
```

where `0x0002` is the 2-byte KEM combiner version and `role` is a single byte (initiator = 0x01,
responder = 0x02). The encapsulator binds its own role; the decapsulator binds the peer's role, so a
reflected or same-role exchange does not match. The shared secret is:

```
shared_secret = KDF( "CH-KEM-v1-SharedSecret", [ K_x, K_m, transcript ], 32 )
```

ML-KEM-1024's Fujisaki-Okamoto transform provides IND-CCA2 with implicit rejection: a wrong key yields a
pseudo-random secret with no error, so the mismatch surfaces only at the Finished MAC (Section 5), never as
a decapsulation oracle. X25519 contributes classical hardness, so the hybrid is secure if either the
structured lattice or the elliptic-curve assumption holds.

### 4.2 X-Wing

X-Wing encapsulation and decapsulation are exactly as specified by draft-connolly-cfrg-xwing-kem; the
`role` argument is ignored (the combiner is spec-fixed). The 32-byte shared secret enters the key schedule
identically to CH-KEM-v1.

## 5. Handshake

### 5.1 Message flow

```
initiator (client)                          responder (server)
  ClientHello            -------->
                         <--------           HelloRetryRequest    (optional, suite mismatch)
  ClientHello (retry)    -------->
                         <--------           ServerHello
  ClientFinished         -------->           (encrypted)
                         <--------           ServerFinished       (encrypted)
```

Message types: ClientHello 0x01, ServerHello 0x02, ClientFinished 0x03, ServerFinished 0x04,
HelloRetryRequest 0x05.

Over a stream transport, ClientHello, ServerHello, and HelloRetryRequest are framed as
`type(1) || len32(payload) || payload`. ClientFinished and ServerFinished are sent as encrypted records,
`len32(ciphertext) || ciphertext`, where the ciphertext is the AEAD seal of the framed Finished message
under the handshake key. Over the datagram transport the same logical messages are fragmented and
reassembled (see `docs/datagram-transport.md`).

### 5.2 KEM-suite negotiation and HelloRetryRequest

The ClientHello carries the `KEMSuite` the client's key share uses, plus `KEMSuites`, the full list of
suites the client supports (in preference order). The KEM public key, the optional static-auth ciphertext,
the ServerHello ciphertext, and the rekey public key are each 2-byte length-prefixed (protocol 5.0), so the
wire carries suite-dependent sizes.

If the responder does not support the client's `KEMSuite`, it replies with a HelloRetryRequest naming a
mutually-supported suite chosen from the client's `KEMSuites` in the responder's preference order (or fails
if there is no overlap). The client adopts the named suite, regenerates its key share, and resends one
ClientHello; `clientRandom`, `SessionID`, and the `KEMSuites` list stay stable across the retry. The
exchange is bounded to a single HelloRetryRequest per handshake.

The HelloRetryRequest is bound into the transcript using the RFC 8446 Section 4.4.1 synthetic message hash:
on a retry the transcript becomes `SHA3-256(ClientHello1) || HelloRetryRequest || ClientHello2 || ...`
instead of `ClientHello1 || ...`. Both peers compute the same substitution, so tampering with the first
ClientHello (a downgrade attempt) diverges the two transcripts and fails the Finished MAC.

The responder echoes the negotiated `KEMSuite` in ServerHello; the initiator rejects a mismatched echo.
The suite is therefore bound both by the explicit echo and by the transcript.

### 5.3 Transcript and Finished

The transcript is the concatenation of the handshake messages in order: the framed ClientHello(s) and
ServerHello, then the plaintext Finished messages as they are produced (Section 5.1), with the
HelloRetryRequest substitution of Section 5.2 when a retry occurs.

```
client_verify_data = KDF( "CH-KEM-Tunnel-ClientFinished", [ master_secret, transcript_through_ServerHello ], 32 )
server_verify_data = KDF( "CH-KEM-Tunnel-ServerFinished", [ master_secret, transcript_through_ClientFinished ], 32 )
```

Each peer recomputes and compares the other's `verify_data` in constant time. A mismatch aborts the
handshake. Because `verify_data` binds both the master secret and the full transcript, it authenticates the
negotiated suite, versions, randoms, and (when present) the authentication folds of Section 5.5.

### 5.4 Key schedule

Let `ss` be the KEM shared secret from Section 4. The master secret is `ss` after the optional
authentication folds of Section 5.5 (in the unauthenticated case `master_secret = ss`). Keys derive from
the master secret:

```
handshake keys (init/resp key + IV) = KDF( "CH-KEM-Tunnel-Handshake", [ master_secret ], ... )
traffic   keys (init/resp key)       = KDF( "CH-KEM-Tunnel-Traffic",   [ master_secret ], ... )
```

The handshake keys protect the Finished messages; the traffic keys protect the data plane. Per-direction
AEAD nonce prefixes derive from the master secret with `"CH-KEM-Tunnel-Stream-Nonce"` (stream) and
`"CH-KEM-Tunnel-Datagram-Nonce"` (datagram); the nonce is the derived prefix concatenated with the record
sequence number and is not transmitted.

### 5.5 Optional authentication (opt-in)

- **Static-key server pinning.** The client encapsulates to a pinned server static key (in that key's own
  suite, independent of the negotiated ephemeral suite) and folds the result:
  `master_secret = KDF( "CH-KEM-Tunnel-Authentication", [ ss, static_secret ], 32 )`. Only the holder of the
  matching private key derives the same secret; a wrong pin fails closed at the Finished MAC.
- **Pre-shared key (mutual).** When both peers hold a PSK and the client advertises the matching identity,
  the PSK folds via `"CH-KEM-Tunnel-PSK"`. An unknown or absent identity means no fold, so a client that
  expected a PSK fails closed at the Finished MAC with no identity oracle.

Both folds occur before key derivation and the Finished MAC, so they authenticate the whole handshake.

## 6. Cipher suites (AEAD)

| CipherSuite | AEAD | FIPS-approved |
| ----------- | ---- | ------------- |
| 0x0001 | AES-256-GCM (NIST SP 800-38D) | yes |
| 0x0002 | ChaCha20-Poly1305 (RFC 8439) | no |

The ClientHello lists supported cipher suites; the responder selects one and echoes it in ServerHello. The
FIPS build restricts selection to AES-256-GCM.

## 7. Key-schedule labels (domain separation)

All labels are ASCII. `KDF` and `TH` are defined in Section 2.

| Label | Use |
| ----- | --- |
| `CH-KEM-v1-SharedSecret` | CH-KEM-v1 combiner output (Section 4.1) |
| `CH-KEM-Tunnel-ClientFinished` / `CH-KEM-Tunnel-ServerFinished` | Finished verify_data (Section 5.3) |
| `CH-KEM-Tunnel-Handshake` | handshake key + IV derivation |
| `CH-KEM-Tunnel-Traffic` | traffic key derivation |
| `CH-KEM-Tunnel-Stream-Nonce` / `CH-KEM-Tunnel-Datagram-Nonce` | per-direction AEAD nonce prefixes |
| `CH-KEM-Tunnel-Authentication` | static-key auth fold (Section 5.5) |
| `CH-KEM-Tunnel-PSK` | pre-shared-key fold (Section 5.5) |
| `CH-KEM-Tunnel-Rekey` | rekey secret derivation (data-plane spec) |
| `CH-KEM-Tunnel-Resumption` | resumption secret derivation |

## 8. Conformance

A conforming implementation MUST implement CH-KEM-v1 (0x0001), reject a peer with a different major wire
version, and bind the negotiated suite, versions, and transcript into the Finished MAC as in Section 5. It
SHOULD implement HelloRetryRequest (Section 5.2) so it can negotiate with a peer that leads with a
different suite. The X-Wing suite (0x0002) MUST be byte-exact with draft-connolly-cfrg-xwing-kem; the
implementation gates it against the published X-Wing test vectors (the SHAKE-128 digest of the spec
vectors) as a conformance check.

## 9. Normative references

- FIPS 203 - Module-Lattice-Based Key-Encapsulation Mechanism Standard (ML-KEM).
- FIPS 202 - SHA-3 Standard: Permutation-Based Hash and Extendable-Output Functions (SHA3-256, SHAKE-256).
- RFC 7748 - Elliptic Curves for Security (X25519).
- draft-connolly-cfrg-xwing-kem - X-Wing: general-purpose hybrid post-quantum KEM.
- RFC 8446 - The Transport Layer Security (TLS) Protocol Version 1.3 (Section 4.4.1 synthetic message hash).
- NIST SP 800-38D - Galois/Counter Mode (AES-256-GCM).
- RFC 8439 - ChaCha20 and Poly1305 for IETF Protocols.

See also `docs/DESIGN_INFLUENCES.md` Section 2.8 for the standardized hybrid-KEM combiner direction.
