#!/usr/bin/env bash
# Build every release binary twice, from copies of this checkout in different directories and
# two seconds apart, and fail if any digest differs. This proves the binaries do not depend on
# the build directory or the wall clock. It does not prove two machines match: that also needs
# the same Go toolchain, which the release notes record.
set -euo pipefail
cd "$(dirname "$0")/.."

sha() {
	if command -v sha256sum >/dev/null; then sha256sum "$1" | cut -d' ' -f1; else shasum -a 256 "$1" | cut -d' ' -f1; fi
}

a=$(mktemp -d)
b=$(mktemp -d)
trap 'rm -rf "$a" "$b"' EXIT
for d in "$a" "$b"; do
	cp -R . "$d/src"
	rm -rf "$d/src/bin"
done

(cd "$a/src" && make build-all VERSION=0.0.0-repro >/dev/null)
sleep 2
(cd "$b/src" && make build-all VERSION=0.0.0-repro >/dev/null)

fail=0
count=0
while IFS= read -r f; do
	count=$((count + 1))
	da=$(sha "$a/src/bin/$f")
	db=$(sha "$b/src/bin/$f")
	if [ "$da" = "$db" ]; then
		echo "same      $f  ${da:0:16}"
	else
		echo "DIFFERENT $f  ${da:0:16} vs ${db:0:16}" >&2
		fail=1
	fi
done < <(cd "$a/src/bin" && find . -type f -name 'quantum-tunnel-*' | sort)

[ "$count" -gt 0 ] || { echo "no binaries were built" >&2; exit 1; }
exit "$fail"
