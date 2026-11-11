#!/usr/bin/env bash
# Lines of library code (no tests, blank lines or comments), to keep the reviewable
# surface visible. "core" is the protocol and crypto path an auditor must read.
set -euo pipefail
cd "$(dirname "$0")/.."

loc() { find "$@" -name '*.go' ! -name '*_test.go' -print0 | xargs -0 cat | grep -cvE '^\s*(//|$)'; }

core=$(loc pkg/chkem pkg/crypto pkg/protocol pkg/tunnel internal)

# --check fails when the line count quoted in README.md has drifted more than 5% from the
# real core count, so a refactor or a feature cannot leave the README stale.
if [[ "${1:-}" == "--check" ]]; then
	claimed=$(sed -nE 's/.*about ([0-9]+),([0-9]{3}) lines of Go.*/\1\2/p' README.md | head -1)
	[[ -n "$claimed" ]] || { echo "README.md has no 'about N,NNN lines of Go' claim to check" >&2; exit 1; }
	diff=$((core > claimed ? core - claimed : claimed - core))
	if ((diff * 100 > claimed * 5)); then
		echo "README.md says about $claimed lines, core is $core. Update the README line." >&2
		exit 1
	fi
	echo "README line count ok (claims $claimed, core is $core)"
	exit 0
fi

printf 'core    (chkem, crypto, protocol, tunnel, internal): %6d\n' "$core"
printf 'metrics (optional observability):                    %6d\n' "$(loc pkg/metrics)"
printf 'cmd     (CLI):                                       %6d\n' "$(loc cmd)"
