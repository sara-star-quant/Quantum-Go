#!/usr/bin/env bash
# Build every release binary twice from clean checkouts of HEAD in different directories, with
# different time zones and fresh Go build caches, two seconds apart, and fail if any digest
# differs. The module cache is shared: go.sum already pins its contents. It proves the binaries do not depend on the build directory, the wall clock,
# the time zone or the build cache, on this host with this Go toolchain. It does not prove two
# machines match: that also needs the same Go version, which the release notes record.
set -euo pipefail
cd "$(dirname "$0")/.."

sha() {
	if command -v sha256sum >/dev/null; then sha256sum "$1" | cut -d' ' -f1; else shasum -a 256 "$1" | cut -d' ' -f1; fi
}

root=$(mktemp -d)
cleanup() {
	git worktree remove --force "$root/a/src" 2>/dev/null || true
	git worktree remove --force "$root/b/src" 2>/dev/null || true
	chmod -R u+w "$root" 2>/dev/null || true
	rm -rf "$root"
}
trap cleanup EXIT

for d in a b; do
	mkdir -p "$root/$d"
	git worktree add --detach --quiet "$root/$d/src" HEAD
done

build() { # build <dir> <time zone>
	(cd "$root/$1/src" && TZ="$2" GOCACHE="$root/$1/cache" make build-all VERSION=0.0.0-repro >/dev/null)
}
build a UTC
sleep 2
build b Pacific/Auckland

fail=0
count=0
while IFS= read -r f; do
	count=$((count + 1))
	da=$(sha "$root/a/src/bin/$f")
	db=$(sha "$root/b/src/bin/$f")
	if [ "$da" = "$db" ]; then
		echo "same      $f  ${da:0:16}"
	else
		echo "DIFFERENT $f  ${da:0:16} vs ${db:0:16}" >&2
		fail=1
	fi
done < <(cd "$root/a/src/bin" && find . -type f -name 'quantum-tunnel-*' | sort)

[ "$count" -gt 0 ] || { echo "no binaries were built" >&2; exit 1; }
exit "$fail"
