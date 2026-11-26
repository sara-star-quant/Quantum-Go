#!/usr/bin/env python3
"""Tests for scripts/release-notes.py. Run: python3 -I scripts/release-notes-test.py"""
import importlib.util
import os
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location("release_notes", os.path.join(HERE, "release-notes.py"))
rn = importlib.util.module_from_spec(spec)
spec.loader.exec_module(rn)

REPO, VER = "o/r", "1.2.3"
BASE = f"https://github.com/{REPO}/blob/v{VER}/"


def tree(files):
    d = tempfile.mkdtemp()
    for f in files:
        p = os.path.join(d, f)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        open(p, "w").close()
    return d


class LinkTests(unittest.TestCase):
    def setUp(self):
        self.root = tree(["docs/PROTOCOL.md", "pkg/tunnel/session.go", "SECURITY.md", "docs/technical/THREAT_MODEL.md"])

    def link(self, text):
        return rn.link_paths(text, REPO, VER, self.root)

    def test_backticked_path_is_linked_to_the_tag(self):
        self.assertEqual(self.link("see `docs/PROTOCOL.md`"), f"see [`docs/PROTOCOL.md`]({BASE}docs/PROTOCOL.md)")

    def test_bare_path_is_linked(self):
        self.assertEqual(self.link("in docs/PROTOCOL.md section 8"), f"in [docs/PROTOCOL.md]({BASE}docs/PROTOCOL.md) section 8")

    def test_relative_markdown_link_is_rewritten(self):
        self.assertEqual(self.link("[spec](docs/PROTOCOL.md#x)"), f"[spec]({BASE}docs/PROTOCOL.md#x)")
        self.assertEqual(self.link("[tm](../docs/technical/THREAT_MODEL.md)"), f"[tm]({BASE}docs/technical/THREAT_MODEL.md)")

    def test_path_that_does_not_exist_is_left_alone(self):
        self.assertEqual(self.link("see `docs/NOPE.md` and docs/NOPE.md"), "see `docs/NOPE.md` and docs/NOPE.md")

    def test_absolute_links_are_untouched_and_not_double_linked(self):
        s = "[spec](https://example.com/docs/PROTOCOL.md)"
        self.assertEqual(self.link(s), s)
        once = self.link("[docs/PROTOCOL.md](docs/PROTOCOL.md)")
        self.assertEqual(once.count("]("), 1)

    def test_top_level_files(self):
        self.assertEqual(self.link("SECURITY.md applies"), f"[SECURITY.md]({BASE}SECURITY.md) applies")

    def test_go_file_with_line_free_path(self):
        self.assertIn(f"({BASE}pkg/tunnel/session.go)", self.link("fixed in `pkg/tunnel/session.go`"))

    def test_substring_of_a_longer_path_is_not_linked(self):
        self.assertEqual(self.link("xdocs/PROTOCOL.md"), "xdocs/PROTOCOL.md")


class SectionTests(unittest.TestCase):
    LOG = "# Changelog\n\n## [Unreleased][]\n\nnext\n\n## [1.2.3][] - 2026-01-01\n\n**Theme:** t\n\n### Fixed\n\n- a\n\n## [1.2.2][] - 2025-12-01\n\nold\n"

    def test_picks_only_that_version(self):
        s = rn.section(self.LOG, "1.2.3")
        self.assertTrue(s.startswith("**Theme:**"))
        self.assertNotIn("old", s)
        self.assertNotIn("next", s)

    def test_missing_version_is_empty(self):
        self.assertEqual(rn.section(self.LOG, "9.9.9"), "")


if __name__ == "__main__":
    unittest.main()
