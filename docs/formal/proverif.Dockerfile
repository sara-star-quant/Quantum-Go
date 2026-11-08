# ProVerif runner for the Quantum-Go formal models. Built on opam's official OCaml
# image; "opam install" fetches and builds ProVerif. The same image runs locally
# (docs/formal/verify.sh) and in CI (.github/workflows/formal.yml).
#
# The ProVerif version and the base image digest are pinned for reproducible proofs.
# To update the base, resolve the digest of the new tag and replace it below.
FROM ocaml/opam:debian-12@sha256:d75e6a0f8f636506ba1909ba4e1d9bb3f44269578d4e48206d35d791f2573297
RUN opam install -y proverif.2.05
ENTRYPOINT ["opam", "exec", "--", "proverif"]
