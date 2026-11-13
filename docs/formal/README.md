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
| Suite negotiation: agreement on the offered list, no downgrade to the weak suite, no acceptance after a forged HelloRetryRequest | `chkem_negotiation.pv` | `inj-event(ClientAccept(sp,o,t)) ==> inj-event(ServerRunning(sp,o,t))`, `event(AcceptedWeak)` and `event(AcceptedAfterRetry)` unreachable | proven |
| Rekey forward secrecy and passive post-compromise secrecy (an attacker who watches but does not alter messages): epoch-0 data stays secret after the epoch-1 master leaks, and epoch-2 data stays secret because the rekey mixes a fresh KEM secret. Not secure against an active attacker who already holds the current master (see the limitation below) | `chkem_rekey.pv` | `attacker(secretE0)` and `attacker(secretE2)` unreachable | proven |
| Rekey agreement against an active attacker with no key material: every accepted rekey was offered with that key share and sequence number (agreement, not "accepted exactly once": replay is not excluded here), and the next epoch's data stays secret | `chkem_rekey_auth.pv` | `event(RekeyAccepted) ==> event(RekeyOffered)`, `attacker(secretE1)` unreachable | proven |
| Datagram cookie authenticity against an off-path spoofer: the server allocates handshake state for an address only if it issued the cookie to that address's owner (not injective: a cookie the owner sent in the clear can be replayed until it expires) | `chkem_cookie.pv` | `event(Alloc(addrA, ck)) ==> event(IssuedToOwner(addrA, ck))` | proven |

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

## Rekey: what the models leave out, and the limitation they record

- **Passive and active are separate models on purpose.** `chkem_rekey.pv` hands the attacker the epoch-1 master and lets him watch every rekey message but not alter them, which is the case where a fresh KEM secret protects the next epoch. `chkem_rekey_auth.pv` gives him the whole network but no key material.
- **Documented limitation (`negative/rekey_active_after_compromise.pv`, expected to fail).** A rekey is sealed only under the current epoch keys, so an attacker who already holds the current epoch master can open and forge rekey records, swap in his own key share and read the next epoch. A rekey protects against an attacker who does not hold the current key; recovering from a compromise needs a new authenticated handshake, that is a new connection. The model records this so the guarantee is not overstated.
- **Replay window: not proven symbolically.** ProVerif has no atomic test-and-set on state, so "accept each sequence number once" cannot be expressed without a race between parallel receivers: an injective query fails for a reason about the tool, not the protocol. Replay protection is covered by tests in `pkg/tunnel`, among them `TestRekeyReplayWindowRejectsBoundaryReplay` (a replay across a rekey boundary) and `TestDatagramRekeyReplayedFramesIgnored`. A stateful prover is the right tool and the work is queued ([#280](https://github.com/sara-star-quant/Quantum-Go/issues/280)). The models carry the sequence number inside the sealed message and nothing more.
- **Per-direction keys.** The request and the response are sealed under different keys (`kdfDir`), as in the record layer. With one shared key ProVerif replays a response as a request, a reflection the real protocol does not allow.
- **Sequence numbers are modelled as unguessable fresh values**, not the small predictable counters of the real record layer. Agreement does not depend on guessing them, since every sealed message needs the epoch key, but the model does not capture an attacker predicting or choosing numbers.
- **Abstracted:** the activation sequence (`current_send_seq + 16`), trial decryption at the boundary, epoch counters on datagrams, and AEAD associated data. The symbolic encryption `senc` is authenticated by construction.

## Datagram cookie: scope

`chkem_cookie.pv` proves the claim the code makes in `pkg/tunnel/dgram_cookie.go`: a host that only spoofs a victim's address never receives the cookie, so it cannot make the server allocate state for that address. The attacker owns his own address, sees what the victim sends and controls the network, but cannot see what the server sends to the victim: **off-path**. An on-path attacker who can read packets addressed to the victim defeats return routability by design, and the model does not claim otherwise. The query is **not injective**: the owner's second packet carries the cookie in the clear and the attacker is allowed to see it, so replaying it with a spoofed source makes the server allocate again, as in the code until the 10 second lifetime ends it. The cookie binds the address and the timestamp, not the hello, as in the code. Abstracted: the timestamp is an unguessable fresh value here, where the code uses a guessable clock reading and checks its age (an attack that predicts the timestamp or depends on expiry is outside the model), the secret's rotation at restart, and the CPU cost of verifying a cookie. Twins: a cookie MAC that does not bind the address (`cookie_no_address_binding_broken.pv`) and a server that accepts any cookie without verifying its MAC (`cookie_mac_not_verified_broken.pv`) both fail the query.

## Non-vacuity (the proofs have teeth)

Two safeguards, both enforced by `verify.sh`:

- **Reachability.** Each model proves an honest run completes (an `event` is reachable), so a
  secrecy result is not vacuously true on a dead protocol.
- **Negative tests.** `negative/` holds a planted-flaw twin of each model (the combiner forgets a
  secret; the Finished is not key-bound). Each MUST fail its query. One twin (`rekey_active_after_compromise.pv`) is not a planted flaw but a real limitation, explained below. A suite that cannot detect a
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
(static-key-pinned mode), PSK mutual authentication including the RequirePSK dummy fold, and suite negotiation with downgrade and forged-retry resistance, for protocol version 6.0.

Protocol 6.0 merged ServerHello and ServerFinished into one flight. The server-authentication
model already abstracts the handshake to one server MAC over the transcript, so it covers the
merged flight unchanged: a client accepts only after verifying a ServerFinished that only the
holder of the pinned static key can produce. Suite negotiation and the HelloRetryRequest downgrade check are modeled in `chkem_negotiation.pv` for the authenticated modes (with no server or PSK authentication an active attacker is a full man in the middle, so downgrade is moot there). Not modeled: the stream and datagram framing and the replay window (the rekey ratchet and the datagram cookie are modeled, see the sections above and below). Those are covered by the Go tests.

Planned (extends the suite as drop-in `*.pv` files): a stateful model of the replay window in a
stateful prover; client device-key mutual authentication including key-compromise impersonation
(with the device-key design); per-suite models (X-Wing, a future CH-KEM-v2); and a computational
proof (CryptoVerif/EasyCrypt).
