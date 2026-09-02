#!/usr/bin/env bash
# Differential comparison against osv-scanner (Stage 0 exit criterion).
#
# INV-12: osv-scanner is a TEST HARNESS here, not a runtime dependency. n3tra
# never invokes it, parses its output, or requires it installed. This script
# exists only to calibrate n3tra's own engine during development, and it must
# never be reachable from any code path in the release binary.
#
# Every disagreement gets investigated and written down in tests/DELTAS.md.
# Some will be their bugs. Most will be yours.
#
# Usage: scripts/differential.sh <path-to-repo> [...]
set -euo pipefail

cd "$(dirname "$0")/.."

if ! command -v cargo >/dev/null 2>&1 && [ -f "$HOME/.cargo/env" ]; then
  # shellcheck disable=SC1091
  . "$HOME/.cargo/env"
fi

if ! command -v osv-scanner >/dev/null 2>&1; then
  cat >&2 <<'EOF'
osv-scanner not installed — this harness cannot run.

  brew install osv-scanner
  # or: go install github.com/google/osv-scanner/cmd/osv-scanner@latest

This is a dev-only tool. n3tra itself does not need it (INV-12).
EOF
  exit 127
fi

cargo build --release --quiet

targets=("$@")
if [ ${#targets[@]} -eq 0 ]; then
  targets=(testbed/python-vulnerable testbed/npm-vulnerable)
fi

overall=0

for target in "${targets[@]}"; do
  echo "=============================================================="
  echo "target: ${target}"
  echo "=============================================================="

  n3t_ids="$(mktemp)"
  osv_ids="$(mktemp)"

  ./target/release/n3t audit "${target}" --format json 2>/dev/null \
    | python3 -c 'import json,sys; [print(f["id"]) for f in json.load(sys.stdin)["findings"]]' \
    | sort -u > "${n3t_ids}" || true

  osv-scanner scan source --format json "${target}" 2>/dev/null \
    | python3 -c '
import json, sys
doc = json.load(sys.stdin)
for res in doc.get("results", []):
    for pkg in res.get("packages", []):
        for v in pkg.get("vulnerabilities", []):
            print(v["id"])
' | sort -u > "${osv_ids}" || true

  echo "n3tra findings:       $(wc -l < "${n3t_ids}" | tr -d ' ')"
  echo "osv-scanner findings: $(wc -l < "${osv_ids}" | tr -d ' ')"
  echo

  # A finding osv-scanner reports and n3tra does not is the serious direction:
  # a false negative in a scanner is the worst possible defect.
  if missing="$(comm -13 "${n3t_ids}" "${osv_ids}")" && [ -n "${missing}" ]; then
    echo "MISSED by n3tra (investigate first — these are potential false negatives):"
    printf '%s\n' "${missing}" | sed 's/^/  /'
    overall=1
    echo
  fi

  if extra="$(comm -23 "${n3t_ids}" "${osv_ids}")" && [ -n "${extra}" ]; then
    echo "EXTRA in n3tra (may be correct — osv-scanner has gaps too):"
    printf '%s\n' "${extra}" | sed 's/^/  /'
    echo
  fi

  if [ -z "${missing}" ] && [ -z "${extra}" ]; then
    echo "identical finding sets"
    echo
  fi

  rm -f "${n3t_ids}" "${osv_ids}"
done

if [ "${overall}" -ne 0 ]; then
  echo "Deltas found. Document every one in tests/DELTAS.md before the Stage 0 gate."
fi
exit "${overall}"
