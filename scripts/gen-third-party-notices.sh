#!/bin/sh
# Regenerate THIRD_PARTY_NOTICES.md: the license text of every third-party module
# linked into the shipped code. Run from the repository root after changing go.mod.
set -eu
out=THIRD_PARTY_NOTICES.md
{
	echo "# Third-party notices"
	echo
	echo "Quantum-Go is licensed under the Apache License 2.0 (see LICENSE and NOTICE)."
	echo "It links the third-party modules below. Each is redistributed under its own"
	echo "license, reproduced here as those licenses require."
	echo
	# Union over every shipped platform and the opt-in otel build tag.
	for os in linux darwin windows; do
		for tags in "" otel; do
			GOOS=$os go list -tags "$tags" -deps -f '{{if and .Module (not .Module.Main)}}{{.Module.Path}} {{.Module.Version}} {{.Module.Dir}}{{end}}' ./...
		done
	done | sort -u | while read -r path version dir; do
		echo "## $path $version"
		echo
		for f in "$dir"/LICENSE "$dir"/LICENSE.md "$dir"/LICENSE.txt "$dir"/COPYING "$dir"/NOTICE; do
			if [ -f "$f" ]; then
				echo "### $(basename "$f")"
				echo
				echo '```text'
				cat "$f"
				echo '```'
				echo
			fi
		done
	done
} > "$out"
