#!/usr/bin/env bash
# Verify a published release from the outside: download its assets into a fresh directory and
# check them the way a user would.
#
#   scripts/release-verify.sh v0.0.31 [owner/repo]
#   scripts/release-verify.sh v0.0.31 --dir DIR     check assets already downloaded into DIR
#
# Checks: every asset matches checksums-sha256.txt and every archive is listed in it; each
# archive has a build provenance attestation whose workflow identity names this tag; the SBOM
# parses; the Go module proxy resolves the tag to the tagged commit; the archive for this
# platform carries LICENSE, NOTICE and the third-party notices and its binary reports the tag
# and the tagged commit. Needs gh (logged in), curl, python3 and tar. Exits non-zero on the
# first class of failure it cannot excuse; it prints every check it ran.
set -uo pipefail

TAG=${1:-}
[ -n "$TAG" ] || { sed -n '2,13p' "$0" | sed 's/^# \{0,1\}//'; exit 2; }
shift
REPO=sara-star-quant/Quantum-Go
DIR=
while [ $# -gt 0 ]; do
	case "$1" in
	--dir) DIR=${2:?--dir needs a path}; shift ;;
	*/*) REPO=$1 ;;
	*) echo "unknown argument: $1" >&2; exit 2 ;;
	esac
	shift
done
VER=${TAG#v}
MODULE=$(printf '%s' "github.com/$REPO" | tr '[:upper:]' '[:lower:]')

for tool in gh curl python3 tar; do
	command -v "$tool" >/dev/null 2>&1 || { echo "error: $tool not found in PATH" >&2; exit 2; }
done

failed=0
pass() { printf 'PASS  %s\n' "$*"; }
fail() { printf 'FAIL  %s\n' "$*"; failed=$((failed + 1)); }

if [ -z "$DIR" ]; then
	DIR=$(mktemp -d)
	trap 'rm -rf "$DIR"' EXIT
	gh release download "$TAG" -R "$REPO" -D "$DIR" >/dev/null 2>&1 || { echo "error: cannot download $TAG from $REPO" >&2; exit 2; }
fi
cd "$DIR" || exit 2

sha_check() {
	if command -v sha256sum >/dev/null 2>&1; then sha256sum -c "$1" 2>&1; else shasum -a 256 -c "$1" 2>&1; fi
}

# The commit the tag points at, from the API, not from a local clone.
COMMIT=$(gh api "repos/$REPO/commits/$TAG" --jq .sha 2>/dev/null)
if [ -n "$COMMIT" ]; then pass "tag $TAG resolves to ${COMMIT:0:12}"; else fail "tag $TAG does not resolve"; fi

# Release page: published, not a draft, with notes.
meta=$(gh release view "$TAG" -R "$REPO" --json isDraft,body -q '"\(.isDraft)|\(.body|length)"' 2>/dev/null)
case "$meta" in
false\|0) fail "release notes are empty" ;;
false\|*) pass "release is published with notes" ;;
*) fail "release page unreadable or still a draft ($meta)" ;;
esac

# Checksums: every listed file verifies, and every archive is listed.
if [ -f checksums-sha256.txt ]; then
	if out=$(sha_check checksums-sha256.txt); then pass "all listed assets match checksums-sha256.txt"; else fail "checksum mismatch: $(printf '%s' "$out" | grep -v ': OK$' | head -3 | tr '\n' ' ')"; fi
	for f in quantum-tunnel-*.tar.gz quantum-tunnel-*.zip; do
		[ -e "$f" ] || continue
		if grep -q " $f\$" checksums-sha256.txt; then pass "$f is listed"; else fail "$f is not in checksums-sha256.txt"; fi
	done
else
	fail "checksums-sha256.txt is missing"
fi

# Attestation per archive: the signing workflow must be release.yml at this tag.
for f in quantum-tunnel-*.tar.gz quantum-tunnel-*.zip; do
	[ -e "$f" ] || continue
	id=$(gh attestation verify "$f" -R "$REPO" --format json 2>/dev/null | python3 -I -c '
import sys, json
try:
    d = json.load(sys.stdin)
    print(d[0]["verificationResult"]["signature"]["certificate"]["subjectAlternativeName"])
except Exception:
    pass')
	case "$id" in
	*"/.github/workflows/release.yml@refs/tags/$TAG") pass "$f attested by release.yml at $TAG" ;;
	"") fail "$f has no verifiable attestation" ;;
	*) fail "$f attested by an unexpected identity: $id" ;;
	esac
done

# SBOM.
if [ -f sbom.spdx.json ]; then
	if n=$(python3 -I -c '
import json
d = json.load(open("sbom.spdx.json"))
assert d["spdxVersion"].startswith("SPDX-")
assert len(d["packages"]) > 0
print(len(d["packages"]))' 2>/dev/null); then pass "SBOM parses ($n packages)"; else fail "SBOM does not parse"; fi
else
	fail "sbom.spdx.json is missing"
fi

# Go module proxy: the tag resolves, to the tagged commit.
info=$(curl -fsS "https://proxy.golang.org/$MODULE/@v/$TAG.info" 2>/dev/null)
got=$(printf '%s' "$info" | python3 -I -c '
import sys, json
try:
    d = json.load(sys.stdin)
    print(d["Version"] + " " + d.get("Origin", {}).get("Hash", ""))
except Exception:
    pass')
if [ "$got" = "$TAG $COMMIT" ]; then pass "Go proxy resolves $TAG to the tagged commit"; else fail "Go proxy answer '$got' does not match '$TAG $COMMIT'"; fi

# The archive for this platform: contents, and the binary's own report.
os=$(uname -s | tr '[:upper:]' '[:lower:]')
case "$(uname -m)" in x86_64 | amd64) arch=amd64 ;; arm64 | aarch64) arch=arm64 ;; *) arch=unknown ;; esac
archive="quantum-tunnel-$VER-$os-$arch.tar.gz"
if [ -f "$archive" ]; then
	rm -rf unpacked && mkdir unpacked && tar -xzf "$archive" -C unpacked
	for f in LICENSE NOTICE THIRD_PARTY_NOTICES.md; do
		if [ -f "unpacked/$f" ]; then pass "$archive carries $f"; else fail "$archive lacks $f"; fi
	done
	bin=$(find unpacked -type f -name 'quantum-tunnel*' | head -1)
	if [ -n "$bin" ]; then
		chmod +x "$bin"
		report=$("$bin" version 2>&1)
		case "$report" in *"$TAG"*) pass "binary reports $TAG" ;; *) fail "binary does not report $TAG: $(printf '%s' "$report" | head -1)" ;; esac
		case "$report" in *"${COMMIT:0:12}"*) pass "binary reports commit ${COMMIT:0:12}" ;; *) fail "binary does not report commit ${COMMIT:0:12}" ;; esac
		if command -v go >/dev/null 2>&1; then
			if go version -m "$bin" 2>/dev/null | grep -q 'vcs.modified=true'; then fail "binary was built from a modified tree"; else pass "binary was not built from a modified tree"; fi
		fi
	else
		fail "no binary inside $archive"
	fi
else
	echo "SKIP  no archive for $os/$arch, binary not run"
fi

if [ "$failed" -eq 0 ]; then echo "release $TAG verified"; else echo "release $TAG: $failed check(s) failed"; fi
[ "$failed" -eq 0 ]
