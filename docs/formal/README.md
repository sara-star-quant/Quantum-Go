# Formal verification of the CH-KEM handshake

Machine-checked symbolic (Dolev-Yao) proofs of the Quantum-Go handshake's core security
properties, using [ProVerif](https://bblanche.gitlabpages.inria.fr/proverif/) 2.05. The
committed proof log is [`RESULTS.txt`](RESULTS.txt).

## What is proven

| Property | Model | ProVerif query | Result |
| -------- | ----- | -------------- | ------ |
| Session-key secrecy | `chkem_secrecy.pv` | `attacker(secretMsg)` unreachable | proven |
| Hybrid security (secure if EITHER leg holds) | `chkem_hybrid.pv` | secrecy holds when the attacker is given one leg's secret, both legs | proven |
| Forward secrecy | `chkem_fs.pv` | secrecy holds after the long-term key leaks (phase 1) | proven |
| Server authentication (injective) + transcript agreement | `chkem_auth.pv` | `inj-event(ClientAccept) ==> inj-event(ServerRunning)` | proven |

The hybrid result machine-checks the headline guarantee: the session key stays secret as long
as the structured-lattice (ML-KEM) OR the classical (X25519) leg holds. Server authentication
gives agreement on the full transcript, which is the symbolic Finished-binding / anti-downgrade
property.

## Adversary model

The active Dolev-Yao attacker controls the entire network (intercept, modify, drop, inject,
replay, reorder), runs unbounded concurrent sessions, and applies every public operation. The
hybrid and forward-secrecy models additionally hand the attacker a compromised secret (one leg's
key; the long-term static key). A query asks whether ANY attacker strategy violates the property,
over all sessions - an exhaustive symbolic search, not a single trace.

## Non-vacuity (the proofs have teeth)

Two safeguards, both enforced by `verify.sh`:

- **Reachability.** Each model proves an honest run completes (an `event` is reachable), so a
  secrecy result is not vacuously true on a dead protocol.
- **Negative tests.** `negative/` holds a planted-flaw twin of each model (the combiner forgets a
  secret; the Finished is not key-bound). Each MUST fail its query. A suite that cannot detect a
  planted flaw is not assurance; these show it does.

## Scope and model fidelity (read this before citing the proofs)

This is SYMBOLIC verification under the perfect-cryptography assumption. It checks the PROTOCOL
COMPOSITION - secrecy, the hybrid combiner, authentication, forward secrecy, transcript binding -
and catches protocol-logic flaws (man-in-the-middle, replay, downgrade, authentication bypass,
mis-binding). It does NOT cover computational or probabilistic attacks, side channels, or weak
randomness; those are the computational IND-CCA argument in
[`../math/MATHEMATICAL_FOUNDATION.md`](../math/MATHEMATICAL_FOUNDATION.md) and the planned audit.

Symbolic verification proves the protocol DESIGN, not the Go implementation. The model primitives
map to the code as follows, and the byte-level behavior of those functions is pinned by the
committed conformance vectors (`../../testdata/conformance/`):

| Model primitive | Code realization |
| --------------- | ---------------- |
| KEM `aenc`/`adec` | `pkg/chkem` over `pkg/crypto/{mlkem,x25519,xwing}.go` |
| combiner `deriveMaster` / `authMaster` | `crypto.DeriveCHKEMSecret`, `crypto.DeriveAuthenticatedSecret` (`pkg/crypto/kdf.go`) |
| Finished MAC `macf` | the verify_data KDF (`pkg/tunnel/handshake.go`) |
| transcript `TH` | `crypto.TranscriptHash` (`pkg/crypto/kdf.go`) |

Design-proven (ProVerif) plus implementation-pinned (conformance vectors) is the honest claim.
Closing the gap fully would need code-level verification, which is out of scope.

## Reproducing

```
docker build -t qgo-proverif -f docs/formal/proverif.Dockerfile docs/formal/
docs/formal/verify.sh
```

`verify.sh` runs every model through the pinned ProVerif image, requires every positive query to
prove and every negative query to fail, and regenerates `RESULTS.txt`. CI runs the same script,
path-filtered to `docs/formal/**` so it does not gate ordinary commits.

## Keeping the model in sync

The models track `pkg/chkem`, `pkg/tunnel/handshake.go`, and `pkg/crypto/kdf.go`. A change to the
handshake or KEM construction in those files requires reviewing and, if needed, updating these
models - the path-filtered CI will not catch protocol drift on its own.

## Coverage map

Proven now: session-key secrecy, hybrid security, forward secrecy, injective server authentication
(static-key-pinned mode), for protocol version 5.0.

Planned (extends the suite as drop-in `*.pv` files): PSK mutual-authentication mode; an explicit
HelloRetryRequest / suite-negotiation process modeling downgrade as a distinct query; the
rekey-ratchet forward secrecy; per-suite models (X-Wing, a future CH-KEM-v2); and a computational
proof (CryptoVerif/EasyCrypt).
