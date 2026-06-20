# ProVerif runner for the Quantum-Go formal models. Built on opam's official OCaml
# image; "opam install" fetches and builds ProVerif. The same image runs locally
# (docs/formal/verify.sh) and in CI (.github/workflows/formal.yml).
#
# The ProVerif version is pinned for reproducible proofs. For a fully reproducible
# build, also pin the base by digest (FROM ocaml/opam:debian-12@sha256:...).
FROM ocaml/opam:debian-12
RUN opam install -y proverif.2.05
ENTRYPOINT ["opam", "exec", "--", "proverif"]
