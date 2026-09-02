#!/usr/bin/env bash
# INV-7: a tool whose pitch is build provenance must produce its own.
#
# This checks **build determinism**: two clean builds from the same source, with
# the same pinned toolchain, produce a byte-identical binary.
#
# Read the limitation honestly. Determinism on one machine is necessary but not
# sufficient, and it is NOT the claim that matters. A compromised n3tra builds
# itself deterministically too. The claim that carries weight is
# "unrelated parties rebuilt it and got the same hash", which requires
# independent rebuilders and a transparency log — neither of which exists yet.
#
# Do not describe n3tra as "reproducible" on the strength of this script alone.
set -euo pipefail

cd "$(dirname "$0")/.."

if ! command -v cargo >/dev/null 2>&1 && [ -f "$HOME/.cargo/env" ]; then
  # shellcheck disable=SC1091
  . "$HOME/.cargo/env"
fi

TMP="$(mktemp -d)"
trap 'rm -rf "${TMP}"' EXIT

hash_of() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | cut -d' ' -f1
  else
    shasum -a 256 "$1" | cut -d' ' -f1
  fi
}

build() {
  local label="$1"
  echo "  build ${label} ..."
  # A fresh target dir each time, so nothing is carried over between builds.
  CARGO_TARGET_DIR="${TMP}/target-${label}" \
    cargo build --release -p n3t-cli --quiet
  cp "${TMP}/target-${label}/release/n3t" "${TMP}/n3t-${label}"
}

echo "toolchain: $(rustc --version)"
echo "pinned by: $(grep '^channel' rust-toolchain.toml)"
echo

build a
build b

ha="$(hash_of "${TMP}/n3t-a")"
hb="$(hash_of "${TMP}/n3t-b")"

echo
echo "  build a: ${ha}"
echo "  build b: ${hb}"
echo

if [ "${ha}" = "${hb}" ]; then
  echo "DETERMINISTIC: two clean builds produced identical binaries."
  echo
  echo "This is NOT a reproducibility guarantee. It shows the build does not vary"
  echo "with time, path, or build order on this machine. The claim that actually"
  echo "matters — an independent party rebuilding and getting this hash — still"
  echo "needs to be established before any release makes it."
  exit 0
fi

cat >&2 <<EOF
NON-DETERMINISTIC: the two builds differ.

Usual causes, in order of likelihood:
  - an absolute path embedded in the binary (set --remap-path-prefix)
  - a build script reading the environment or the clock
  - a dependency embedding a build timestamp

Investigate with:
  cmp -l "${TMP}/n3t-a" "${TMP}/n3t-b" | head
EOF
exit 1
