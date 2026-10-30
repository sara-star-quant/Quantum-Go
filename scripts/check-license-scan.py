#!/usr/bin/env python3
"""Fail a release when ScanCode finds a foreign license or copyright in shipped code.

Usage: check-license-scan.py scancode.json

Code files (Go, shell, Makefile, Dockerfile, workflows) must carry no license other
than Apache-2.0 and no copyright holder outside ALLOWED_HOLDERS. Docs may mention other
licenses (the audit record names every dependency license), so they are not checked.
"""
import json
import os
import sys

CODE_SUFFIXES = (".go", ".sh", ".py", ".yml", ".yaml", ".mod")
CODE_NAMES = ("Makefile", "Dockerfile")
ALLOWED_LICENSES = {None, "Apache-2.0"}
MIN_SCORE = 90
ALLOWED_HOLDERS = ("Petro Zverkov", "Peter Z.")


def is_code(path: str) -> bool:
    base = os.path.basename(path)
    return base in CODE_NAMES or path.endswith(CODE_SUFFIXES)


def main(path: str) -> int:
    with open(path, encoding="utf-8") as fh:
        files = json.load(fh)["files"]
    problems = []
    scanned = 0
    for f in files:
        if f["type"] != "file" or not is_code(f["path"]):
            continue
        scanned += 1
        for det in f.get("license_detections", []):
            for m in det["matches"]:
                expr = m["license_expression_spdx"]
                # Low-scoring matches are prose that merely mentions a license (for
                # example "licensed under the Apache License 2.0"), not a license text.
                if m["score"] >= MIN_SCORE and expr not in ALLOWED_LICENSES:
                    problems.append(f"{f['path']}:{m['start_line']}: license {expr}")
        for c in f.get("copyrights", []):
            if not any(h in c["copyright"] for h in ALLOWED_HOLDERS):
                problems.append(f"{f['path']}: copyright {c['copyright']!r}")
    print(f"checked {scanned} code files")
    for p in problems:
        print("FAIL", p)
    return 1 if problems else 0


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    sys.exit(main(sys.argv[1]))
