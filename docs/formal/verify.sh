#!/usr/bin/env bash
# Verify the Quantum-Go ProVerif models: every positive model must PROVE all its
# queries, every negative (planted-flaw) model must FAIL its security query. Writes
# the proof log to RESULTS.txt. The same script runs locally and in CI.
set -u
DIR="$(cd "$(dirname "$0")" && pwd)"
IMG="${PROVERIF_IMAGE:-qgo-proverif}"
RESULTS="$DIR/RESULTS.txt"
run() { docker run --rm -v "$DIR:/work" -w /work "$IMG" -lib prelude "$1" 2>&1; }

ver=$(docker run --rm "$IMG" -help 2>&1 | head -1)
# No commit/date in the header: RESULTS.txt then changes only when the PROOFS change,
# so CI can assert the committed log is up to date. Git history provides traceability.
{
  echo "Quantum-Go formal verification results"
  echo "Tool: $ver"
  echo "Protocol version verified: 5.0"
  echo
} > "$RESULTS"

fail=0
echo "== positive models (must prove) =="
for f in "$DIR"/*.pv; do
  name=$(basename "$f"); out=$(run "$name")
  { echo "=== $name ==="; echo "$out" | grep -E "^RESULT"; echo; } >> "$RESULTS"
  res=$(echo "$out" | grep -E "^RESULT")
  bad=$(echo "$res" | grep -vE "is true|not event\([A-Za-z0-9]+\) is false")
  if [ -z "$res" ] || echo "$out" | grep -q "cannot be proved" || [ -n "$bad" ]; then
    echo "  FAIL  $name"; [ -n "$bad" ] && echo "$bad" | sed 's/^/        /'; fail=1
  else echo "  ok    $name"; fi
done

echo "== negative models (must fail) =="
for f in "$DIR"/negative/*.pv; do
  name=$(basename "$f"); out=$(run "negative/$name")
  { echo "=== negative/$name ==="; echo "$out" | grep -E "^RESULT"; echo; } >> "$RESULTS"
  res=$(echo "$out" | grep -E "^RESULT")
  if [ -n "$res" ] && echo "$res" | grep -q "is false"; then
    echo "  ok    $name (flaw detected)"
  else echo "  FAIL  $name (flaw NOT detected)"; fail=1; fi
done

[ "$fail" = 0 ] && echo "ALL MODELS VERIFIED" || echo "VERIFICATION FAILED"
exit $fail
