#!/usr/bin/env bash
# Run the tests a change adds or edits many times, shuffled, under CPU contention, with
# the race detector and again under the fips build tag. A test that only passes on a
# quiet machine (fixed sleeps, tight timing bounds, work that only suits the default
# build mode) fails here before it reaches CI.
#
# Usage: scripts/stress-changed-tests.sh [base-ref]   (default origin/main)
# Env:   COUNT=10 runs per test, HOGS=<n> background CPU burners (default: half the CPUs)
set -euo pipefail

base="${1:-origin/main}"
count="${COUNT:-10}"
cpus="$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 4)"
hogs="${HOGS:-$(( cpus / 2 > 0 ? cpus / 2 : 1 ))}"

changed="$(git diff --name-only --diff-filter=AM "$base"...HEAD -- '*_test.go' || true)"
if [ -z "$changed" ]; then
  echo "no test files changed against $base"
  exit 0
fi

# Group by package directory. Added Test/Fuzz funcs are run by name; a package whose
# test files changed only in helpers is run whole, fewer times.
declare -A names whole
while IFS= read -r f; do
  dir="./$(dirname "$f")"
  added="$(git diff -U0 "$base"...HEAD -- "$f" | grep -oE '^\+func (Test|Fuzz)[A-Za-z0-9_]*' | sed 's/^+func //' || true)"
  if [ -n "$added" ]; then
    names["$dir"]+="$(echo "$added" | tr '\n' '|')"
  else
    whole["$dir"]=1
  fi
done <<< "$changed"

pids=()
cleanup() { for p in "${pids[@]:-}"; do kill "$p" 2>/dev/null || true; done; }
trap cleanup EXIT
for _ in $(seq "$hogs"); do
  ( while :; do :; done ) &
  pids+=($!)
done
echo "stressing with $hogs CPU burners, $count runs per test"

fail=0
run() {
  local label="$1"; shift
  echo "== $label"
  if ! go test "$@"; then fail=1; echo "FAILED: $label"; fi
}

for dir in "${!names[@]}"; do
  pattern="^(${names[$dir]%|})\$"
  run "$dir race (${pattern})" -race -count="$count" -shuffle=on -cpu 1,4 -run "$pattern" "$dir"
  run "$dir fips (${pattern})" -tags fips -count="$count" -shuffle=on -run "$pattern" "$dir"
done
# Whole-package pass for every changed package. Some failures only show when the
# package's tests run together (leaked goroutines, shared sockets, accumulated load),
# which is how CI runs them, so targeted runs alone are not enough.
declare -A pkgs
for dir in "${!names[@]}" "${!whole[@]}"; do pkgs["$dir"]=1; done
for dir in "${!pkgs[@]}"; do
  run "$dir race (whole package)" -race -count=2 -shuffle=on "$dir"
  run "$dir fips (whole package)" -tags fips -count=1 -shuffle=on "$dir"
done
exit "$fail"
