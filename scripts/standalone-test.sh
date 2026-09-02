#!/usr/bin/env bash
# INV-12: n3tra must produce a complete, correct result on a machine where no
# other security tooling is installed.
#
# Builds a scratch image containing the n3t binary and fixture repos, and nothing
# else — no syft, no trivy, no grype, no osv-scanner, no package managers, not
# even a shell beyond busybox. If any code path secretly depended on another
# scanner, or on a resolver being present, it fails here.
#
# The offline assertion is the sharp one: with no network and a cold cache the
# audit must report `unknown` (exit 2), never `clean` (exit 0). That is INV-5
# proven in the harshest environment we can construct.
set -euo pipefail

cd "$(dirname "$0")/.."

if ! command -v cargo >/dev/null 2>&1 && [ -f "$HOME/.cargo/env" ]; then
  # shellcheck disable=SC1091
  . "$HOME/.cargo/env"
fi

# This is the STRONGEST form of the INV-12 check: no tooling AND no network,
# in an image containing literally nothing but our binary. The weaker form —
# empty PATH, same assertions — lives in crates/n3t-cli/tests/standalone.rs and
# runs on every `cargo test`, so a Docker outage degrades coverage rather than
# removing it.
fallback() {
  echo
  echo "Falling back to the non-container INV-12 test (empty PATH, no tooling)." >&2
  echo "This is weaker: it does not prove network isolation." >&2
  cargo test -p n3t-cli --test standalone
}

if ! command -v docker >/dev/null 2>&1; then
  echo "docker not installed" >&2
  fallback
  exit $?
fi
if ! docker info >/dev/null 2>&1; then
  echo "docker daemon not running" >&2
  fallback
  exit $?
fi
# A daemon that answers `info` but cannot pull is a real and common state
# (proxy, rate limit, wedged VM). Detect it up front rather than hanging.
if ! docker image inspect "${RUST_IMAGE:-rust:1.90-alpine}" >/dev/null 2>&1; then
  echo "pulling ${RUST_IMAGE:-rust:1.90-alpine} (90s budget) ..."
  if ! ( docker pull "${RUST_IMAGE:-rust:1.90-alpine}" >/dev/null 2>&1 &
         pid=$!
         for _ in $(seq 1 18); do sleep 5; kill -0 $pid 2>/dev/null || break; done
         if kill -0 $pid 2>/dev/null; then kill $pid 2>/dev/null; exit 1; fi
         wait $pid ); then
    echo "docker pull did not complete within 90s — registry unreachable or daemon wedged" >&2
    fallback
    exit $?
  fi
fi


WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT

# Build for the host architecture. Cross-building x86_64 on an arm64 host runs
# under emulation and takes tens of minutes, which is long enough that the check
# stops being run — and a check nobody runs is not a check.
case "$(uname -m)" in
  arm64|aarch64) TARGET=aarch64-unknown-linux-musl; PLATFORM=linux/arm64 ;;
  *)             TARGET=x86_64-unknown-linux-musl;  PLATFORM=linux/amd64 ;;
esac

echo "building a static ${TARGET} binary ..."
# A fully static binary is the point: the scratch image then contains our
# artifact and nothing else, so any hidden dependency on external tooling fails.
docker run --rm --platform "${PLATFORM}" \
  -v "$PWD":/src \
  -v "${WORK}":/out \
  -w /src \
  rust:1.90-alpine \
  sh -c "apk add --no-cache musl-dev >/dev/null 2>&1 &&
         cargo build --release --target ${TARGET} -p n3t-cli 2>&1 | tail -3 &&
         cp target/${TARGET}/release/n3t /out/n3t" \
  || { echo "cross-build failed" >&2; exit 1; }

cp -R testbed "${WORK}/testbed"

cat > "${WORK}/Dockerfile" <<'EOF'
FROM scratch
COPY n3t /n3t
COPY testbed /testbed
ENTRYPOINT ["/n3t"]
EOF

echo "building scratch image ..."
docker build -q --platform "${PLATFORM}" -t n3tra-standalone:test "${WORK}" >/dev/null

echo
echo "--- image contents (must be only the binary and fixtures) ---"
docker run --rm --platform "${PLATFORM}" --entrypoint /n3t n3tra-standalone:test --version

fail=0
check() {
  local desc="$1" expected="$2"; shift 2
  set +e
  docker run --rm --platform "${PLATFORM}" --network none n3tra-standalone:test "$@" >/dev/null 2>&1
  local rc=$?
  set -e
  if [ "${rc}" -eq "${expected}" ]; then
    echo "  ok    ${desc} (exit ${rc})"
  else
    echo "  FAIL  ${desc}: expected exit ${expected}, got ${rc}" >&2
    fail=$((fail + 1))
  fi
}

echo
echo "--- offline, no network, cold cache (INV-5: must be unknown, never clean) ---"
check "audit python-vulnerable" 2 audit /testbed/python-vulnerable --offline --cache-dir /tmp/c
check "audit npm-vulnerable"    2 audit /testbed/npm-vulnerable --offline --cache-dir /tmp/c
check "audit clean-project"     2 audit /testbed/clean-project --offline --cache-dir /tmp/c

echo
echo "--- inventory works with no tooling present at all ---"
set +e
out="$(docker run --rm --platform "${PLATFORM}" --network none n3tra-standalone:test scan /testbed/npm-vulnerable --no-native --format json 2>/dev/null)"
set -e
count="$(printf '%s' "${out}" | tr ',' '\n' | grep -c 'packages_discovered' || true)"
discovered="$(printf '%s' "${out}" | python3 -c 'import json,sys; print(json.load(sys.stdin)["packages_discovered"])' 2>/dev/null || echo 0)"
if [ "${discovered}" = "5" ]; then
  echo "  ok    scan discovered ${discovered} packages with no package managers installed"
else
  echo "  FAIL  scan discovered ${discovered} packages, expected 5" >&2
  fail=$((fail + 1))
fi

echo
if [ "${fail}" -eq 0 ]; then
  echo "INV-12 standalone test PASSED"
else
  echo "INV-12 standalone test FAILED (${fail} check(s))" >&2
  exit 1
fi
