#!/usr/bin/env python3
"""Print the release notes body for one version, with every file reference linked to that tag.

Usage: scripts/release-notes.py VERSION OWNER/REPO [ROOT]

It takes the "## [VERSION]" section of CHANGELOG.md and rewrites two things so the notes
read correctly on the release page, where a relative link would resolve against the default
branch and drift from the code the release shipped:

  * markdown links with a relative target, such as [PROTOCOL](docs/PROTOCOL.md);
  * repository paths in backticks or plain text, such as `docs/PROTOCOL.md`, that exist in the
    tree at ROOT (the tag's checkout).

Both become links to https://github.com/OWNER/REPO/blob/vVERSION/PATH. Paths that do not exist
in the tree are left alone, so prose cannot grow dead links. Standard library only.
"""
import os
import re
import sys

PATH_RE = re.compile(
    r"(?<![\w/.:#-])"
    r"((?:docs|pkg|cmd|scripts|internal|test|testdata|\.github)/[\w./-]*[\w]"
    r"|(?:README|CHANGELOG|SECURITY|CONTRIBUTING|ROADMAP|SCOPE|NOTICE|LICENSE)(?:\.md)?)"
    r"(?![\w/-])"
)
LINK_RE = re.compile(r"\[([^\]]*)\]\(([^)\s]+)\)")
CODE_RE = re.compile(r"`([^`\n]+)`")


def section(changelog: str, version: str) -> str:
    out, on = [], False
    for line in changelog.splitlines():
        if re.match(r"^## \[", line):
            if on:
                break
            on = line.startswith(f"## [{version}]")
            continue
        if on:
            out.append(line)
    return "\n".join(out).strip("\n")


def permalink(repo: str, version: str, path: str) -> str:
    return f"https://github.com/{repo}/blob/v{version}/{path}"


def exists(root: str, path: str) -> bool:
    return os.path.isfile(os.path.join(root, path))


def link_paths(text: str, repo: str, version: str, root: str) -> str:
    def fix_link(m: re.Match) -> str:
        label, target = m.group(1), m.group(2)
        if re.match(r"^(https?:|mailto:|#)", target):
            return m.group(0)
        path = target.split("#")[0].lstrip("./")
        while path.startswith("../"):
            path = path[3:]
        if exists(root, path):
            frag = ("#" + target.split("#", 1)[1]) if "#" in target else ""
            return f"[{label}]({permalink(repo, version, path)}{frag})"
        return m.group(0)

    # Work segment by segment so nothing inside an existing link is linked twice.
    parts, last = [], 0
    for m in LINK_RE.finditer(text):
        parts.append(("text", text[last:m.start()]))
        parts.append(("link", fix_link(m)))
        last = m.end()
    parts.append(("text", text[last:]))

    def link_plain(seg: str) -> str:
        def code(m: re.Match) -> str:
            inner = m.group(1)
            pm = re.fullmatch(PATH_RE, inner)
            if pm and exists(root, inner):
                return f"[`{inner}`]({permalink(repo, version, inner)})"
            return m.group(0)

        # Backticked paths first, then bare paths outside backticks.
        pieces, pos = [], 0
        for cm in CODE_RE.finditer(seg):
            pieces.append(("plain", seg[pos:cm.start()]))
            pieces.append(("code", code(cm)))
            pos = cm.end()
        pieces.append(("plain", seg[pos:]))

        def bare(s: str) -> str:
            return PATH_RE.sub(
                lambda m: f"[{m.group(1)}]({permalink(repo, version, m.group(1))})"
                if exists(root, m.group(1))
                else m.group(0),
                s,
            )

        return "".join(bare(s) if kind == "plain" else s for kind, s in pieces)

    return "".join(link_paths_seg if kind == "link" else link_plain(link_paths_seg) for kind, link_paths_seg in parts)


def main(argv: list) -> int:
    if len(argv) < 3:
        print(__doc__, file=sys.stderr)
        return 2
    version, repo = argv[1].lstrip("v"), argv[2]
    root = argv[3] if len(argv) > 3 else "."
    with open(os.path.join(root, "CHANGELOG.md"), encoding="utf-8") as f:
        body = section(f.read(), version)
    if not body:
        print(f"no CHANGELOG section for {version}", file=sys.stderr)
        return 1
    print(link_paths(body, repo, version, root))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
