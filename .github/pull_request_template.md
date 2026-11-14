## What changed and why

<!-- A couple of plain sentences. Lead with the impact. -->

## Checklist

- [ ] Tests cover the change, and a test fails without it (positive control or mutation check)
- [ ] `go test ./... -race` and `go test -tags fips ./...` pass locally
- [ ] Commits carry a `Signed-off-by` line (`git commit -s`)
- [ ] Cryptographic or wire changes cite a specification or paper and add known-answer tests
- [ ] `CHANGELOG.md` has an entry under Unreleased for anything a user would notice
- [ ] Docs and numbers are updated, and every number traces to a saved measurement
