#!/usr/bin/env bash
# Lines of library code (no tests, blank lines or comments), to keep the reviewable
# surface visible. "core" is the protocol and crypto path an auditor must read.
set -euo pipefail
cd "$(dirname "$0")/.."

loc() { find "$@" -name '*.go' ! -name '*_test.go' -print0 | xargs -0 cat | grep -cvE '^\s*(//|$)'; }

printf 'core    (chkem, crypto, protocol, tunnel, internal): %6d\n' "$(loc pkg/chkem pkg/crypto pkg/protocol pkg/tunnel internal)"
printf 'metrics (optional observability):                    %6d\n' "$(loc pkg/metrics)"
printf 'cmd     (CLI):                                       %6d\n' "$(loc cmd)"
