#!/usr/bin/env bash
# Generate lockfiles with the CURRENTLY RELEASED package managers.
#
# The failure this exists to catch is silent under-reporting: a package manager
# ships a new lockfile format, a parser stops understanding it, and n3tra quietly
# reports fewer packages while still looking like it worked. The `tests/corpus`
# files are pinned and therefore go stale by design; this generates fresh ones.
#
# Writes into tests/drift/<ecosystem>/. Run nightly, never pinned.
set -euo pipefail

cd "$(dirname "$0")/.."
DRIFT="tests/drift"
rm -rf "${DRIFT}"
mkdir -p "${DRIFT}"

have() { command -v "$1" >/dev/null 2>&1; }

note() { printf '  %-8s %s\n' "$1" "$2"; }

# A tiny but non-trivial dependency set: a scope, a transitive tree, and a
# package with peer dependencies, so the generated lockfile exercises the shapes
# the parsers actually branch on.
NPM_DEPS='"dependencies": { "@babel/core": "^7.24.0", "left-pad": "1.3.0", "debug": "^4.3.4" }'

gen_npm() {
  have npm || { note npm "not installed, skipped"; return; }
  local d="${DRIFT}/npm"; mkdir -p "$d"
  printf '{ "name": "drift-npm", "version": "1.0.0", "private": true, %s }\n' "${NPM_DEPS}" > "$d/package.json"
  (cd "$d" && npm install --package-lock-only --silent >/dev/null 2>&1) \
    && note npm "package-lock.json v$(python3 -c 'import json;print(json.load(open("'"$d"'/package-lock.json"))["lockfileVersion"])')" \
    || note npm "generation failed"
}

gen_pnpm() {
  have pnpm || { note pnpm "not installed, skipped"; return; }
  local d="${DRIFT}/pnpm"; mkdir -p "$d"
  printf '{ "name": "drift-pnpm", "version": "1.0.0", "private": true, %s }\n' "${NPM_DEPS}" > "$d/package.json"
  (cd "$d" && pnpm install --lockfile-only --ignore-scripts >/dev/null 2>&1) \
    && note pnpm "pnpm-lock.yaml $(head -1 "$d/pnpm-lock.yaml" 2>/dev/null || true)" \
    || note pnpm "generation failed"
}

gen_yarn() {
  have yarn || { note yarn "not installed, skipped"; return; }
  local d="${DRIFT}/yarn"; mkdir -p "$d"
  printf '{ "name": "drift-yarn", "version": "1.0.0", "private": true, %s }\n' "${NPM_DEPS}" > "$d/package.json"
  (cd "$d" && yarn install --mode=update-lockfile >/dev/null 2>&1) \
    && note yarn "yarn.lock generated" \
    || note yarn "generation failed"
}

gen_uv() {
  have uv || { note uv "not installed, skipped"; return; }
  local d="${DRIFT}/uv"; mkdir -p "$d"
  cat > "$d/pyproject.toml" <<'EOF'
[project]
name = "drift-uv"
version = "0.1.0"
requires-python = ">=3.9"
dependencies = ["requests>=2.31.0", "jinja2>=3.1.0"]
EOF
  (cd "$d" && uv lock >/dev/null 2>&1) \
    && note uv "uv.lock v$(grep -m1 '^version' "$d/uv.lock" | tr -dc '0-9')" \
    || note uv "generation failed"
}

gen_poetry() {
  have poetry || { note poetry "not installed, skipped"; return; }
  local d="${DRIFT}/poetry"; mkdir -p "$d"
  cat > "$d/pyproject.toml" <<'EOF'
[tool.poetry]
name = "drift-poetry"
version = "0.1.0"
description = ""
authors = []
package-mode = false

[tool.poetry.dependencies]
python = "^3.9"
requests = "^2.31.0"

[build-system]
requires = ["poetry-core"]
build-backend = "poetry.core.masonry.api"
EOF
  (cd "$d" && poetry lock --no-interaction >/dev/null 2>&1) \
    && note poetry "poetry.lock generated" \
    || note poetry "generation failed"
}

echo "generating lockfiles with current package managers ..."
gen_npm
gen_pnpm
gen_yarn
gen_uv
gen_poetry

echo
found="$(find "${DRIFT}" -name '*.lock' -o -name '*lock.json' -o -name '*lock.yaml' | wc -l | tr -d ' ')"
echo "generated ${found} lockfile(s) in ${DRIFT}/"
if [ "${found}" -eq 0 ]; then
  echo "no lockfiles generated — nothing to check" >&2
  exit 1
fi
