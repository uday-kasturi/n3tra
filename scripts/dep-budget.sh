#!/usr/bin/env bash
# Dependency budget gate (Stage 0, hard CI gate).
#
# A security tool with 400 transitive dependencies is both a real risk and an
# indefensible look. This runs from day one rather than being retrofitted, because
# budgets are only enforceable before they are exceeded.
#
# Counts *normal* edges only: dev-dependencies (proptest, the differential
# harnesses against osv-scanner and grype) do not ship in the release binary and
# are not charged against the budget. INV-12 is asserted separately by the
# standalone-container test.
set -euo pipefail

BUDGET="${DEP_BUDGET:-150}"

cd "$(dirname "$0")/.."

# Local runs often have cargo installed but not exported into a non-login shell.
if ! command -v cargo >/dev/null 2>&1 && [ -f "$HOME/.cargo/env" ]; then
  # shellcheck disable=SC1091
  . "$HOME/.cargo/env"
fi

# `--workspace` is required once there is more than one member, and the whole
# pipeline runs with pipefail disabled so a cargo failure surfaces as a clear
# error rather than an empty count that silently "passes".
tree() {
  cargo tree --workspace --edges normal --prefix none
}

if ! raw="$(tree 2>&1)"; then
  echo "FAIL: could not compute dependency tree:" >&2
  echo "${raw}" >&2
  exit 1
fi

actual="$(printf '%s\n' "${raw}" \
  | awk 'NF {print $1" "$2}' \
  | sort -u \
  | { grep -v '^n3t-' || true; } \
  | wc -l \
  | tr -d ' ')"

if [ -z "${actual}" ] || [ "${actual}" -eq 0 ]; then
  echo "FAIL: dependency count came back empty; the gate is not actually running." >&2
  exit 1
fi

echo "transitive dependencies: ${actual} / ${BUDGET}"

if [ "${actual}" -gt "${BUDGET}" ]; then
  cat >&2 <<EOF

FAIL: dependency budget exceeded (${actual} > ${BUDGET}).

Every new dependency requires written justification in its PR. Before raising
the budget, check whether the code can be written directly: crates/n3t-core/src/pct.rs
is ~40 lines and replaced a percent-encoding dependency.

Current tree:
EOF
  printf '%s\n' "${raw}" | awk 'NF {print "  "$1" "$2}' | sort -u >&2
  exit 1
fi
