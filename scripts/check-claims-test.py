#!/usr/bin/env python3
"""Tests for check-claims.py. Run: python3 -I scripts/check-claims-test.py"""
import importlib.util
import os
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPT = os.path.join(HERE, "check-claims.py")

HEADER = "| ID | Claim | Status | Evidence | Stated in |\n|---|---|---|---|---|\n"


def run(root):
    p = subprocess.run([sys.executable, "-I", SCRIPT, "--root", root], capture_output=True, text=True)
    return p.returncode, p.stdout + p.stderr


class Repo:
    """A throwaway repository with a claims register and a few evidence files."""

    def __init__(self, rows, extra=None):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = self.tmp.name
        self.write("docs/technical/CLAIMS.md", "# Claims\n\n" + HEADER + "".join(r + "\n" for r in rows))
        self.write("docs/formal/model.pv", "(* model *)\n")
        self.write("docs/notes.md", "notes\n")
        self.write("pkg/a/a_test.go", "package a\n\nfunc TestDefined(t *testing.T) {}\nfunc FuzzDefined(f *testing.F) {}\n")
        for path, text in (extra or {}).items():
            self.write(path, text)

    def write(self, rel, text):
        path = os.path.join(self.root, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(text)

    def check(self):
        try:
            return run(self.root)
        finally:
            self.tmp.cleanup()


OK_ROWS = [
    "| C-01 | A tested claim | Tested | `TestDefined` | README |",
    "| C-02 | A modelled claim | Modelled | `docs/formal/model.pv` | SECURITY.md |",
    "| C-03 | An argued claim | Argued | `docs/notes.md` section 7, #277 | docs |",
    "| C-04 | A cited claim | Cited | FIPS 203, https://csrc.nist.gov/pubs/fips/203/final | docs |",
    "| C-05 | A claim we do not make | Not claimed | `docs/notes.md` | docs |",
]


class CheckClaims(unittest.TestCase):
    def assertFails(self, repo, needle):
        code, out = repo.check()
        self.assertNotEqual(code, 0, out)
        self.assertIn(needle, out)

    def test_valid_register_passes(self):
        code, out = Repo(OK_ROWS).check()
        self.assertEqual(code, 0, out)

    def test_unknown_status_fails(self):
        self.assertFails(Repo(["| C-01 | x | Probably | `docs/notes.md` | a |"]), "status")

    def test_duplicate_id_fails(self):
        self.assertFails(Repo(OK_ROWS + [OK_ROWS[0]]), "duplicate")

    def test_missing_evidence_fails(self):
        self.assertFails(Repo(["| C-01 | x | Argued |  | a |"]), "evidence")

    def test_missing_path_fails(self):
        self.assertFails(Repo(["| C-01 | x | Argued | `docs/missing.md` | a |"]), "docs/missing.md")

    def test_undefined_test_name_fails(self):
        self.assertFails(Repo(["| C-01 | x | Tested | `TestNotThere` | a |"]), "TestNotThere")

    def test_tested_without_a_test_fails(self):
        self.assertFails(Repo(["| C-01 | x | Tested | `docs/notes.md` | a |"]), "Tested")

    def test_modelled_without_a_model_fails(self):
        self.assertFails(Repo(["| C-01 | x | Modelled | `docs/notes.md` | a |"]), "Modelled")

    def test_cited_without_a_source_fails(self):
        self.assertFails(Repo(["| C-01 | x | Cited | the standard says so | a |"]), "Cited")

    def test_fuzz_target_counts_as_a_test(self):
        code, out = Repo(["| C-01 | x | Tested | `FuzzDefined` | a |"]).check()
        self.assertEqual(code, 0, out)

    def test_dangling_citation_fails(self):
        repo = Repo(OK_ROWS, {"README.md": "See claim C-99 for details.\n"})
        self.assertFails(repo, "C-99")

    def test_existing_citation_passes(self):
        repo = Repo(OK_ROWS, {"README.md": "See claim C-02 for details.\n", "SECURITY.md": "| property | C-04 |\n"})
        code, out = repo.check()
        self.assertEqual(code, 0, out)

    def test_citations_in_claude_dir_and_in_the_register_are_ignored(self):
        repo = Repo(OK_ROWS, {".claude/plan.md": "C-77 is a local note\n"})
        code, out = repo.check()
        self.assertEqual(code, 0, out)

    def test_register_missing_fails(self):
        with tempfile.TemporaryDirectory() as d:
            code, out = run(d)
            self.assertNotEqual(code, 0)
            self.assertIn("CLAIMS.md", out)


if __name__ == "__main__":
    unittest.main(verbosity=2)
