#!/usr/bin/env bash
# Run every Go fuzz target for a bounded time. A crash leaves its input under the package's
# testdata/fuzz directory; the script keeps going and fails at the end if any target failed.
#
#   FUZZTIME=60s FUZZ_FILTER='^Fuzz' scripts/fuzz.sh [package pattern, default ./...]
set -uo pipefail

fuzztime=${FUZZTIME:-60s}
filter=${FUZZ_FILTER:-^Fuzz}
pattern=${1:-./...}
failed=0
ran=0

for pkg in $(go list "$pattern"); do
  targets=$(go test -list "$filter" "$pkg" 2>/dev/null | grep -E '^Fuzz' || true)
  for target in $targets; do
    ran=$((ran + 1))
    echo "=== fuzz $pkg $target for $fuzztime"
    if ! go test -run '^$' -fuzz "^${target}\$" -fuzztime "$fuzztime" "$pkg"; then
      echo "FAILED: $pkg $target"
      failed=$((failed + 1))
    fi
  done
done

echo "fuzzed $ran targets, $failed failed"
[ "$ran" -gt 0 ] || { echo "no fuzz targets matched $filter"; exit 1; }
[ "$failed" -eq 0 ]
