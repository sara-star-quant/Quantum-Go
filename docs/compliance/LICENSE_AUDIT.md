# Licensing audit

Checked 2026-10-30 against every release tag (v0.0.1 to v0.0.16) and the current main.
This is an engineering record, not legal advice.

## Project license

- v0.0.1 to v0.0.14 shipped under the MIT License.
- v0.0.15 and later ship under the Apache License 2.0 (relicensed 2026-06-19 for the express patent grant).
- The copyright holder is the sole author of the code. The only other committer is dependabot (version bumps).
- Releases already published stay under the license they shipped with.

## Third-party modules

Every module version used by any release tag was checked. All are permissive and compatible with Apache-2.0 (and were with MIT). No copyleft, no source-available, no license changes across the versions used.

| Module | License | Used for |
|---|---|---|
| github.com/cloudflare/circl | BSD-3-Clause | ML-KEM-1024 and X-Wing |
| golang.org/x/crypto, x/net, x/sys | BSD-3-Clause | ChaCha20-Poly1305, UDP batching, syscalls |
| go.opentelemetry.io/otel (+ metric, trace, auto/sdk) | Apache-2.0 | optional `otel` build tag |
| github.com/go-logr/logr, stdr | Apache-2.0 | OpenTelemetry dependency |
| github.com/cespare/xxhash/v2 | MIT | OpenTelemetry dependency |

`THIRD_PARTY_NOTICES.md` carries the license texts. Regenerate it with `scripts/gen-third-party-notices.sh` after any `go.mod` change. Release archives and the Docker image ship `LICENSE`, `NOTICE`, and `THIRD_PARTY_NOTICES.md`.

Earlier release archives contained only the binary. The notices are present in every source tarball through `go.mod` and the module licenses, and in the repository; from the next release the archives and image carry them directly.

## Design sources

No third-party code is copied into the repository (no vendor directory, no copied-from markers). Designs are adapted as concepts only, with attribution in `docs/DESIGN_INFLUENCES.md`.

| Source | Terms |
|---|---|
| TLS 1.3 (RFC 8446), RFC 7748, FIPS 202/203 | public standards |
| Post-quantum WireGuard (ePrint 2020/379) | CC BY 4.0 |
| X-Wing (ePrint 2024/039) | CC BY 4.0 |
| Rosenpass (code) | Apache-2.0 / MIT |
| Kudelski pq-wireguard (code) | MIT |

Deliberately not used: RKEM / Rebar (patent risk), Dagger KEM (not standardized), and papers published under non-derivative terms (for example ePrint 2026/1581, CC BY-NC-ND).

## Patent research from public sources

Method: query the IETF Datatracker IPR database (`/api/v1/ipr/iprdocrel/`, control query on RFC 6386 returns 2 disclosures, so the zero results below are meaningful) for the specifications each shipped mechanism is based on, plus NIST's published position on ML-KEM. Date: 2026-10-30. This reads public disclosures only; it is not a freedom-to-operate opinion.

| Mechanism | Basis | IETF IPR disclosures |
|---|---|---|
| Pre-shared key folding and per-identity PSKs | RFC 8446 s2.2, RFC 9258, RFC 8784 | none |
| ChaCha20-Poly1305, HKDF, X25519 | RFC 7539 / 8439, RFC 5869, RFC 7748 | none |
| Hybrid KEM combiner (X-Wing) | draft-connolly-cfrg-xwing-kem, draft-ietf-tls-hybrid-design | none |
| ML-KEM in TLS | draft-ietf-tls-mlkem, draft-ietf-tls-ecdhe-mlkem | one general statement (#7227) by an IETF participant, holder listed as "Unknown", no identified claim |
| ML-KEM (FIPS 203) | NIST | NIST states it holds royalty-free patent licenses covering implementers of ML-KEM as published; commentators note the field of use is narrow, so deviating from ML-KEM is outside it |

Consequences for the design:
- Keep ML-KEM exactly as FIPS 203 specifies it. No compressed or modified variants.
- Authentication additions stay symmetric (PSK) and follow public RFC mechanisms until a patent opinion covers KEM-based client authentication.
- Do not build on constructions from PQShield (Rebar / reinforced KEM) or on papers published under non-derivative terms.

## Scanner result

ScanCode Toolkit 32.5.0 (Apache-2.0) scanned all 312 files in the repository (licenses, copyrights, package manifests) on 2026-10-30.

- No Go source or script carries a third-party license text or copyright. The only copyright holder detected is the project author.
- The other licenses detected are mentions in docs (this audit record, the changelog, the contribution guide), not license texts embedded in code.
- ScanCode matches license text. It does not detect snippet-level similarity to other code, so it does not answer the question of AI-generated code that resembles licensed code. That risk is covered by review, the provenance rules in `CONTRIBUTING.md`, and known-answer tests for the crypto. A snippet-matching service (for example ScanOSS) could be added if the project wants it; it sends code fingerprints to an external service, so it is not enabled.

Every release now runs the scan (`license-scan` job in `.github/workflows/release.yml`), fails the release if shipped code carries a foreign license or copyright holder (`scripts/check-license-scan.py`), and attaches `scancode.json` to the GitHub release. A planted GPL header in a test copy makes the check fail.

## Other risks

| Risk | Status |
|---|---|
| Name | Searched public sources on 2026-10-30: no trademark registration or filing found for "Quantum-Go" or "QuantumGo". A commercial service called QuantumVPN uses a different name. A web search cannot confirm registration status; check USPTO, EUIPO, and WIPO Global Brand Database before relying on the name as a brand. |
| Contributor chain | Contributions need a DCO sign-off (`CONTRIBUTING.md`); the `DCO` workflow fails outside pull requests without one. No contributor agreement. |
| Copyright holder | The notice names the project author personally. Confirm whether the author or an employing company owns the work before relying on that. |
| Liability | Apache-2.0 disclaims warranty and limits liability (sections 7 and 8). |

## Residual items

- Public disclosures are checked above; no counsel review has happened. Get an opinion before shipping a KEMTLS-style or other paper-derived design.
- The container image bundles Alpine (busybox is GPL-2.0, musl is MIT) as a separate component; it is distributed as an aggregate, not linked with Quantum-Go.
