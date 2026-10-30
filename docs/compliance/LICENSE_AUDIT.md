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

## Residual items

- Patent status of ML-KEM, X-Wing, and any KEMTLS-style design is not checked here. Get counsel's opinion before shipping a new design built on a paper.
- The container image bundles Alpine (busybox is GPL-2.0, musl is MIT) as a separate component; it is distributed as an aggregate, not linked with Quantum-Go.
