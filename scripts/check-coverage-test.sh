#!/usr/bin/env bash
# Checks scripts/check-coverage.sh against a fixture: crypto is 80 percent alone, 100 percent with
# the second profile merged, tunnel is 100 percent, the total is 90 percent alone.
set -u
cd "$(dirname "$0")"
fail=0
expect() { # expect <exit> <label> <floors> <profile>...
  want=$1; label=$2; floors=$3; shift 3
  printf '%s\n' "$floors" > /tmp/floors.$$
  ./check-coverage.sh /tmp/floors.$$ "$@" > /tmp/out.$$ 2>&1
  got=$?
  if [ "$got" != "$want" ]; then echo "FAIL $label: exit $got, want $want"; cat /tmp/out.$$; fail=1; else echo "ok   $label"; fi
}
A=testdata/coverage-fixture.profile
B=testdata/coverage-fixture-more.profile
expect 0 "floor under measured passes"       $'total 89\npkg/crypto 79\npkg/tunnel 99' $A
expect 1 "package under its floor fails"     $'pkg/crypto 81' $A
expect 1 "total under its floor fails"       $'total 91' $A
expect 0 "merged profile lifts a package"    $'pkg/crypto 99' $A $B
expect 1 "unknown package in floors fails"   $'pkg/nothing 1' $A
expect 0 "comments and blanks are ignored"   $'# note\n\ntotal 50  # why' $A
rm -f /tmp/floors.$$ /tmp/out.$$
exit $fail
