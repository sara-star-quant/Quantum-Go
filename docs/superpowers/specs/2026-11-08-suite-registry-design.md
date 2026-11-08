# Public KEM suite registry and conformance harness

## Intent

Let code outside `pkg/chkem` add a KEM suite without forking the library, and give every suite (built-in or external) one shared test battery it must pass. This is the first step of a longer arc: wire obfuscation, a packet-conn transport seam, then a second datagram transport. The registry is the extension seam that later stronger-crypto suites (a triple cascade once a trusted HQC primitive exists) plug into.

## Problems found in the current code

1. `chkem.Suite` is public but unimplementable outside the package: `KeyPair`, `PublicKey` and `Ciphertext` have only unexported fields, so an external suite cannot construct them.
2. The registry is a fixed unexported map and `SupportedSuites()` is a hardcoded slice.
3. The initiator always starts with `DefaultSuite()`; a non-default suite is reached only through HelloRetryRequest or a pinned server key. There is no client preference option.
4. Suite correctness is tested per suite by hand. Nothing stops a new suite from skipping the tamper, reflection or size checks.

## Goals

- Exported constructors so an external suite can build its key pair, public key and ciphertext.
- `RegisterSuite(Suite) error`, safe for concurrent use, with hard validation.
- `suitetest.Run(t, Suite)`: a conformance battery run against both built-in suites and available to external authors.
- No change to the default wire or to handshake bytes when nothing is registered.

## Non-goals

- No client preference option in this step (problem 3 stays open; tracked as the next step of the arc).
- No HQC or any new primitive.
- No unregister, no replace.

## Anti-goals (would make this a failure even if it works)

- A registered suite silently weakening downgrade protection or FIPS gating.
- An external id colliding with a future built-in id.
- A global mutable default.

## Design

- **Id space.** Built-ins use `0x0001-0x7FFF`. `RegisterSuite` accepts only ids `>= 0x8000` (`CustomSuiteMin`). Registering a built-in id, a duplicate, id 0, a nil suite, or a suite reporting non-positive sizes returns an error.
- **Order.** `SupportedSuites()` returns built-ins first (CH-KEM-v1 first), then registered suites in registration order. The default stays preferred, so registering a suite changes nothing for peers that do not know it.
- **FIPS.** `SupportedSuites()` drops any suite with `IsFIPSApproved() == false` when `crypto.FIPSMode()` is true. `GetSuite` is unchanged, so a stored identity of a filtered suite fails at the offer check, not by panic.
- **Downgrade.** Unchanged: the synthetic-hash HRR transcript already binds the offered list, and the offer list now includes registered suites, so an attacker stripping one is detected by the existing Finished check.
- **Concurrency.** An `RWMutex` guards the registry. `GetSuite` and `SupportedSuites` take the read lock and return copies.
- **Constructors.** `SuiteKeyHandle` (exported form of the existing `suiteKeyHandle`), `NewSuiteKeyPair(id, handle)`, `NewSuitePublicKey(id, raw)`, `NewSuiteCiphertext(id, raw)`, and `(*KeyPair).Handle() any`. They reject id 0 (reserved for CH-KEM-v1 internals).
- **Conformance battery (`pkg/chkem/suitetest`).** For a `Suite`: sizes match serialized lengths; encapsulate/decapsulate round trip agrees; seed-derived key pair is deterministic; wrong-length public key and ciphertext are rejected; a bit-flipped ciphertext never yields the original secret; a different key pair never yields the original secret; secrets are 32 bytes; `ID()` is stable; parse-then-serialize round trips. Reflection (same role both sides) is checked only when the suite reports role binding via an optional `RoleBinder` interface, because X-Wing is spec-fixed and does not bind role.

## Left to the builder

Names of test helpers; where the id constants live; error values for registration failures (reuse `qerrors` where a fit exists).

## Builder-check notes (my calls)

- Minimum custom id `0x8000` is my call; a smaller reserved range would also work.
- Reachability of a custom suite (problem 3) is deliberately deferred; it is visible only through HRR until the preference option lands.
