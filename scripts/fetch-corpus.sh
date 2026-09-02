#!/usr/bin/env bash
# Fetch real lockfiles from well-known repositories into tests/corpus/.
#
# Pinned by commit SHA, not by branch. A corpus that moves under you turns a
# parser regression into a flaky test and destroys the signal entirely.
#
# First run resolves each repo's current HEAD and writes tests/corpus/CORPUS.lock.
# Later runs replay that file exactly. Refreshing is deliberate:
#
#   rm tests/corpus/CORPUS.lock && ./scripts/fetch-corpus.sh
#
# then review the resulting diff before committing.
set -euo pipefail

cd "$(dirname "$0")/.."
CORPUS="tests/corpus"
LOCK="${CORPUS}/CORPUS.lock"

# name|repo|path-in-repo
# Chosen to cover every format the Stage 0 parsers claim to handle, using
# projects large enough that their lockfiles exercise real-world shapes
# (scopes, nested duplicates, peer suffixes, multi-spec entries).
CANDIDATES=(
  "npm-cli|npm/cli|package-lock.json"
  "express|expressjs/express|package-lock.json"
  "axios|axios/axios|package-lock.json"
  "react|facebook/react|yarn.lock"
  "babel|babel/babel|yarn.lock"
  "vite|vitejs/vite|pnpm-lock.yaml"
  "vue-core|vuejs/core|pnpm-lock.yaml"
  "poetry|python-poetry/poetry|poetry.lock"
  "pydantic|pydantic/pydantic|uv.lock"
  "flask-reqs|pallets/flask|requirements/tests.txt"
  "sentry-reqs|getsentry/sentry|requirements-base.txt"
)

mkdir -p "${CORPUS}"

resolve_sha() {
  local repo="$1"
  curl -fsSL \
    -H "Accept: application/vnd.github+json" \
    ${GITHUB_TOKEN:+-H "Authorization: Bearer ${GITHUB_TOKEN}"} \
    "https://api.github.com/repos/${repo}/commits?per_page=1" 2>/dev/null \
    | python3 -c 'import json,sys; print(json.load(sys.stdin)[0]["sha"])' 2>/dev/null
}

fetch_one() {
  local name="$1" repo="$2" sha="$3" path="$4"
  local dest="${CORPUS}/${name}"
  local out="${dest}/$(basename "${path}")"
  mkdir -p "${dest}"
  if curl -fsSL "https://raw.githubusercontent.com/${repo}/${sha}/${path}" -o "${out}" 2>/dev/null \
     && [ -s "${out}" ]; then
    printf '%s %s %s\n' "${repo}" "${sha}" "${path}" > "${dest}/.provenance"
    echo "  ok    ${name}  $(basename "${path}")  $(wc -c < "${out}" | tr -d ' ') bytes"
    return 0
  fi
  rm -rf "${dest}"
  return 1
}

if [ -f "${LOCK}" ]; then
  echo "replaying ${LOCK} ..."
  ok=0; miss=0
  while IFS=' ' read -r name repo sha path; do
    [ -z "${name:-}" ] && continue
    case "${name}" in \#*) continue ;; esac
    if fetch_one "${name}" "${repo}" "${sha}" "${path}"; then
      ok=$((ok + 1))
    else
      echo "  MISS  ${name} (${repo}@${sha}:${path})" >&2
      miss=$((miss + 1))
    fi
  done < "${LOCK}"
  echo
  echo "corpus: ${ok} fetched, ${miss} missing"
  [ "${miss}" -eq 0 ] || exit 1
  exit 0
fi

echo "no ${LOCK} — resolving current HEADs and pinning ..."
: > "${LOCK}.tmp"
ok=0
for entry in "${CANDIDATES[@]}"; do
  IFS='|' read -r name repo path <<< "${entry}"
  sha="$(resolve_sha "${repo}" || true)"
  if [ -z "${sha}" ]; then
    echo "  skip  ${name}: could not resolve HEAD for ${repo}" >&2
    continue
  fi
  if fetch_one "${name}" "${repo}" "${sha}" "${path}"; then
    printf '%s %s %s %s\n' "${name}" "${repo}" "${sha}" "${path}" >> "${LOCK}.tmp"
    ok=$((ok + 1))
  else
    echo "  skip  ${name}: ${path} not present at ${repo}@${sha:0:8}" >&2
  fi
done

mv "${LOCK}.tmp" "${LOCK}"
echo
echo "pinned ${ok} corpus entries in ${LOCK}"
