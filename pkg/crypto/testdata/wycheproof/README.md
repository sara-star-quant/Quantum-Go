# Wycheproof test vectors

Vendored, unmodified copies of vectors from Project Wycheproof (https://github.com/C2SP/wycheproof), licensed Apache-2.0 (see LICENSE in this directory).

Source commit: 65ca494727a52944c204441c860b039e6786b99b

| File | SHA-256 |
|---|---|
| mlkem_1024_test.json | 17c5b764d78c05522f1980fcb41d82add573f11de5d13004ae0b83bf46d9c43a |
| x25519_test.json | 35c3f5231cf25cc640b524d403461deee9e49441d5d915a3a25b2c8ff5adbe7d |
| aes_gcm_test.json | 985e5ecc172e181eaf49e89508b9470dcf478002eb7e8559c707eb42dc97dfe7 |
| chacha20_poly1305_test.json | fe61d25f90e1bde4461d00eafe61049e5f29bd999f36b766df9cda90906ad53d |

The tests in `pkg/crypto` verify each hash before they read a file, so an edit to a vector fails the build. To update, fetch the new files from `testvectors_v1/` at a new commit, replace the hashes here and in the tests, and review the test counts the tests assert.

This data is test input only. It is not part of any release archive.
