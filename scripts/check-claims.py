#!/usr/bin/env python3
"""Check docs/technical/CLAIMS.md against the repository.

Usage: check-claims.py [--root DIR]

The register lists each security claim with a status and its evidence. This script fails when
a row is malformed, when its evidence does not exist, or when a document cites a claim ID that
the register does not hold. It does not judge whether a claim is true.

Statuses and what each one needs in the Evidence column (backticked tokens are checked):
  Proven       a path that exists
  Modelled     a path ending in .pv (or another model file) that exists
  Tested       at least one Test* or Fuzz* function that exists in a _test.go file
  Argued       a path that exists, or an issue reference such as #277
  Cited        a URL, or an RFC or FIPS number
  Not claimed  a path that exists
A cell holds no pipe character. Backticked tokens that look like a path must exist; backticked
Test* and Fuzz* names must be defined as functions in a _test.go file.
"""
import argparse
import os
import re
import sys

REGISTER = os.path.join("docs", "technical", "CLAIMS.md")
STATUSES = {"Proven", "Modelled", "Tested", "Argued", "Cited", "Not claimed"}
ID_RE = re.compile(r"^C-\d{2}$")
CITE_RE = re.compile(r"\bC-\d{2}\b")
TEST_RE = re.compile(r"^(Test|Fuzz)\w+$")
PATH_EXTS = (".md", ".pv", ".go", ".txt", ".sh", ".yml", ".yaml", ".py", ".json")
SKIP_DIRS = {".git", ".claude", ".code-review-graph", "node_modules", "testdata"}
MODEL_EXTS = (".pv", ".spthy", ".ec", ".cv")


def walk(root, suffix):
    for dirpath, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for name in files:
            if name.endswith(suffix):
                yield os.path.join(dirpath, name)


def defined_tests(root):
    names = set()
    rx = re.compile(r"^func ((?:Test|Fuzz)\w+)\(", re.M)
    for path in walk(root, "_test.go"):
        with open(path, encoding="utf-8", errors="replace") as fh:
            names.update(rx.findall(fh.read()))
    return names


def parse_rows(text):
    rows = []
    for no, line in enumerate(text.splitlines(), 1):
        if not line.startswith("| C-"):
            continue
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        rows.append((no, cells))
    return rows


def check_register(root, problems):
    path = os.path.join(root, REGISTER)
    if not os.path.isfile(path):
        problems.append(f"{REGISTER}: the claims register does not exist")
        return set()
    with open(path, encoding="utf-8") as fh:
        text = fh.read()
    tests = defined_tests(root)
    ids = set()
    for no, cells in parse_rows(text):
        where = f"{REGISTER}:{no}"
        if len(cells) != 5:
            problems.append(f"{where}: expected 5 cells (ID, claim, status, evidence, stated in), found {len(cells)}")
            continue
        cid, claim, status, evidence, _ = cells
        if not ID_RE.match(cid):
            problems.append(f"{where}: bad ID {cid!r}, want C-NN")
        if cid in ids:
            problems.append(f"{where}: duplicate ID {cid}")
        ids.add(cid)
        if not claim:
            problems.append(f"{where}: {cid} has no claim text")
        if status not in STATUSES:
            problems.append(f"{where}: {cid} has unknown status {status!r}; use one of {sorted(STATUSES)}")
            continue
        if not evidence:
            problems.append(f"{where}: {cid} has no evidence")
            continue
        tokens = re.findall(r"`([^`]+)`", evidence)
        paths = [t for t in tokens if "/" in t or t.endswith(PATH_EXTS)]
        test_names = [t for t in tokens if TEST_RE.match(t)]
        for p in paths:
            if not os.path.exists(os.path.join(root, p)):
                problems.append(f"{where}: {cid} cites {p}, which does not exist")
        for t in test_names:
            if t not in tests:
                problems.append(f"{where}: {cid} cites {t}, which no _test.go file defines")
        has_issue = re.search(r"(^|[^\w])#\d+\b", evidence) is not None
        has_source = re.search(r"https?://|RFC ?\d+|FIPS ?\d+", evidence) is not None
        if status == "Tested" and not test_names:
            problems.append(f"{where}: {cid} is Tested but names no Test or Fuzz function")
        elif status == "Modelled" and not any(p.endswith(MODEL_EXTS) for p in paths):
            problems.append(f"{where}: {cid} is Modelled but names no model file")
        elif status == "Argued" and not (paths or has_issue):
            problems.append(f"{where}: {cid} is Argued but names no document or issue")
        elif status == "Cited" and not has_source:
            problems.append(f"{where}: {cid} is Cited but gives no URL, RFC or FIPS number")
        elif status in ("Proven", "Not claimed") and not paths:
            problems.append(f"{where}: {cid} is {status} but names no file")
    return ids


def check_citations(root, ids, problems):
    register = os.path.normpath(os.path.join(root, REGISTER))
    cited = 0
    for path in walk(root, ".md"):
        if os.path.normpath(path) == register:
            continue
        with open(path, encoding="utf-8", errors="replace") as fh:
            for no, line in enumerate(fh, 1):
                for cid in CITE_RE.findall(line):
                    cited += 1
                    if cid not in ids:
                        rel = os.path.relpath(path, root)
                        problems.append(f"{rel}:{no}: cites {cid}, which the register does not hold")
    return cited


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", default=".")
    args = ap.parse_args()
    problems = []
    ids = check_register(args.root, problems)
    cited = check_citations(args.root, ids, problems) if ids else 0
    for p in problems:
        print(p)
    if problems:
        print(f"{len(problems)} problem(s)")
        return 1
    print(f"{len(ids)} claims, {cited} citations: ok")
    return 0


if __name__ == "__main__":
    sys.exit(main())
