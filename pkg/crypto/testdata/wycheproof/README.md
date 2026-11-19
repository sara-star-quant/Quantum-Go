# Wycheproof test vectors

Vendored, unmodified copies of vectors from Project Wycheproof (https://github.com/C2SP/wycheproof), licensed Apache-2.0 (see LICENSE in this directory).

Source commit: 65ca494727a52944c204441c860b039e6786b99b

| File | SHA-256 |
|---|---|
| mlkem_1024_test.json | 17c5b764d78c05522f1980fcb41d82add573f11de5d13004ae0b83bf46d9c43a |

The tests in `pkg/crypto` verify each hash before they read a file, so an edit to a vector fails the build. To update, fetch the new files from `testvectors_v1/` at a new commit, replace the hashes here and in the tests, and review the test counts the tests assert.

This data is test input only. It is not part of any release archive.
