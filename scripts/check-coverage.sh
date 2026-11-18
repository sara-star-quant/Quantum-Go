#!/usr/bin/env bash
# Fails when library coverage falls below a floor, in total or in a named package.
# Usage: scripts/check-coverage.sh <floors-file> <profile> [<profile>...]
# Several profiles merge by taking the highest hit count per block, so a branch that only the
# FIPS build runs counts as covered. The floors file holds "<package> <percent>" lines, where
# <package> is a directory such as pkg/crypto or the word "total". Text after # is a comment.
set -euo pipefail
[ $# -ge 2 ] || { echo "usage: $0 <floors-file> <profile>..." >&2; exit 2; }
floors=$1; shift

awk -v floors="$floors" '
BEGIN {
  while ((getline line < floors) > 0) {
    sub(/#.*/, "", line)
    if (split(line, f, " ") == 2) { floor[f[1]] = f[2]; order[++nf] = f[1] }
  }
}
/^mode:/ { next }
{
  key = $1; stmts[key] = $2
  if (!(key in hits) || $3 > hits[key]) hits[key] = $3
}
END {
  for (key in stmts) {
    pkg = key; sub(/:.*/, "", pkg); sub(/\/[^\/]*$/, "", pkg)
    sub(/^github.com\/sara-star-quant\/quantum-go\//, "", pkg)
    total[pkg] += stmts[key]; all += stmts[key]
    if (hits[key] > 0) { covered[pkg] += stmts[key]; allc += stmts[key] }
  }
  bad = 0
  for (i = 1; i <= nf; i++) {
    name = order[i]
    t = (name == "total") ? all : total[name]
    c = (name == "total") ? allc : covered[name]
    if (t == 0) { printf "%-16s no statements found: wrong name?\n", name; bad = 1; continue }
    pct = 100 * c / t
    ok = (pct >= floor[name])
    printf "%-16s %5.1f%%  floor %s%%  %s\n", name, pct, floor[name], ok ? "ok" : "BELOW FLOOR"
    if (!ok) bad = 1
  }
  exit bad
}' "$@"
