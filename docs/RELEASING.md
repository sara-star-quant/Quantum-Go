# Releasing

How a release is cut and what has to be true first. The rules exist because each one was learned from a release that skipped it.

## The gate

A tag goes on a commit only when all of these hold:

1. Main CI and Scorecard are green on that exact commit, and the last three runs of main are green.
2. `scripts/stress-changed-tests.sh` passed for every test the release touched.
3. `golangci-lint run ./...`, `go vet ./...` and `gofmt -l .` are clean. Run them before each push, and let a failure stop the push.
4. Every CI failure on main has an issue. A flake that reproduces blocks the release. A failure that passed on rerun and passes locally does not, but it keeps its issue open.
5. The CHANGELOG entries match the merged diff. Advisory IDs are named. A number appears only with a saved measurement behind it.
6. The tag is signed and sits on the merge commit of the release PR.

## Steps

1. Open a release PR titled `cut vX.Y.Z`: move Unreleased under the new version with today's date, write a one-paragraph Theme (impact first, with an upgrade note first if anything breaks), update the compare links and the status line in `ROADMAP.md`. Pick `0.0.N` while the project is pre-1.0.
2. Land it by fast-forward (`git push origin <branch>:main`) so signed commits stay signed. Do not rebase-merge or squash-merge: both rewrite or re-author commits.
3. Wait for main CI and Scorecard on the release commit. Never tag a pending run.
4. Tag and push one tag: `git tag -s vX.Y.Z -m vX.Y.Z <commit> && git push origin vX.Y.Z`. A push of more than three tags does not start workflows.
5. Watch the release workflow (`gh run watch <id>`). The Docker publish job runs after Create Release; the run is not done until it finishes.
6. Verify the published release from the outside:

   ```
   scripts/release-verify.sh vX.Y.Z
   ```

   It downloads the assets into a fresh directory and checks them: every asset against `checksums-sha256.txt`, a build attestation per archive that names `release.yml` at the tag, the SBOM, the Go proxy answer (the tag resolves to the tagged commit), the license files in the archive, and the binary's own report of the tag and commit. It exits non-zero on any failure. `go.dev` and `pkg.go.dev` can lag the proxy by a few minutes; a 404 there at first is a queue, not a failure.
7. Report the version, tag, workflow result and the verifier output.

## Release notes standard

The notes are the CHANGELOG section for the version, published verbatim on the release page. Write them for the person deciding whether to upgrade.

- **Theme first:** two or three sentences, the outcome for an operator before the mechanism, and whether they must act. A breaking change leads.
- **Order:** Upgrade notes, Security, then Fixed, Changed, Added, Docs, CI. Upgrade notes say who is affected, what stops working and the fix.
- **One line per entry:** the outcome, then the cause in a clause. No process narration (who reviewed what stays out of the entries), and a number only with a saved measurement behind it.
- **Advisories:** name the GHSA id. Never link a draft advisory: it returns 404.
- **File references:** write the full repository path, such as `docs/PROTOCOL.md`, in backticks or plain text. `scripts/release-notes.py` links every path that exists at the tag to that tag's copy (`blob/vX.Y.Z/...`), so a reader sees the file as the release shipped it. A bare name like PROTOCOL.md is not linked. CI renders the newest section on every change and fails on a surviving relative link.
- **The release PR** is titled `cut vX.Y.Z` and has a two-line body; the theme and the upgrade notes live in the CHANGELOG, not in the PR text.

## Releases that are not routine

- **Security fix.** Tag first, then publish the draft advisory. Never link a draft advisory from the CHANGELOG: it returns 404. Release notes state the affected version, the fixed version, the impact in one line and a workaround, with no trigger steps.
- **Published releases are immutable.** The setting is stored per release; turning it off does not unlock earlier ones. Do not retro-edit a release. A wrong number in notes is corrected in the next release, in the open.
- **A verifier failure.** Read the workflow log before changing anything. A checksum or attestation failure on a published release is a security event: stop, do not re-tag, open a private advisory.

## What the verifier does not cover

It does not run the changed behavior against the released binary, and it does not repeat the reproducible-build check (`scripts/repro-check.sh`, which CI runs on main). For a release whose point is a fix, also run the failing scenario against the downloaded binary.
