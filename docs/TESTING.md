# Testing n3tra Stage 0 by hand

Stage 0 is **L0 only**: it reports what the build *declares*, not what it was
observed to do. The observation layers (L1–L3) that make n3tra different arrive in
Stages 1–2. Everything below exercises the correlation and advisory plumbing that
those layers will feed.

## 0. Build it

```bash
cargo build --release
```

The binary lands at `target/release/n3t`. Put it on your PATH if you like:

```bash
export PATH="$PWD/target/release:$PATH"
```

## 1. Run the test suite

```bash
cargo test --workspace
```

158 tests. Then the strict lint pass — `panic`, `unwrap`, `expect`, and
`indexing` are all `deny` in every crate, and `unsafe_code` is forbidden:

```bash
cargo clippy --all-targets -- -D warnings
```

And the dependency budget gate (Stage 0 hard gate, currently 46 / 150):

```bash
./scripts/dep-budget.sh
```

## 2. The testbed

Four fixture projects in `testbed/`, each exercising one behavior:

| Fixture | What it proves | Expected exit |
|---|---|---|
| `python-vulnerable/` | Old pins with many real advisories | `1` (failed) |
| `npm-vulnerable/` | npm lockfile v3, scopes, nested duplicates | `1` (failed) |
| `python-unpinned/` | **Unpinned deps cannot be checked → `unknown`** | `2` (unknown) |
| `clean-project/` | A current pin with nothing outstanding | `0` (clean) |

### Inventory only, no network

```bash
./target/release/n3t scan testbed/npm-vulnerable
```

Note what it does *not* say. `scan` performs no advisory lookup, so it prints
`INVENTORY ONLY` rather than a verdict. A run that checked nothing must never
read as a pass.

### Audit against live OSV

```bash
./target/release/n3t audit testbed/python-vulnerable
```

~123 findings across 5 packages, most-severe first, with CVSS base scores
computed from the vector rather than taken from a label.

### The important one: coverage gaps

```bash
./target/release/n3t audit testbed/python-unpinned; echo "exit: $?"
```

Two unpinned requirements, so nothing can be matched. Verdict is **`unknown`,
exit 2** — explicitly not a pass. That is INV-5 working.

## 3. Verify the invariants yourself

The checks worth running by hand, because their failure would be silent.

### INV-5 — a cold offline cache must not yield a pass

```bash
./target/release/n3t audit testbed/clean-project --offline --cache-dir /tmp/n3t-cold; echo "exit: $?"
```

Must be exit `2`, not `0`. An attacker who can block your network must not
thereby obtain a passing scan. Warm the cache and repeat to see it become `0`:

```bash
./target/release/n3t audit testbed/clean-project --cache-dir /tmp/n3t-warm && ./target/release/n3t audit testbed/clean-project --offline --cache-dir /tmp/n3t-warm; echo "exit: $?"
```

### INV-12 — works with no other tooling installed

Two forms. The always-on one runs with every `cargo test`:

```bash
cargo test -p n3t-cli --test standalone
```

It invokes the real binary with `env_clear()` and `PATH` pointing at an empty
directory — no `npm`, no `pip`, no shell, no competing scanner — and asserts
inventory is unchanged and an offline cold-cache audit still exits `2`.

The stronger form additionally proves network isolation:

```bash
./scripts/standalone-test.sh
```

Static musl binary in a `scratch` image containing the fixtures and literally
nothing else, run with `--network none`. It needs a Docker daemon that can pull;
if one is not available it says so and falls back to the test above within 90s
rather than hanging. **This form has not yet run** — Docker on the development
machine cannot pull images — so network isolation is unverified until CI runs it.

### Unknown lockfile formats fail loudly

```bash
mkdir -p /tmp/n3t-future && printf '{"lockfileVersion":9,"packages":{"node_modules/x":{"version":"1.0.0"}}}' > /tmp/n3t-future/package-lock.json && ./target/release/n3t audit /tmp/n3t-future
```

Zero packages and a coverage gap — not a partial parse.

### Build determinism (INV-7)

```bash
./scripts/reproducible.sh
```

Two clean builds, byte-identical. Read the caveat it prints: this is *not*
reproducibility. A compromised n3tra builds itself deterministically too. The
claim that matters needs independent rebuilders and a transparency log.

## 4. The real-world corpus

Pinned lockfiles from npm/cli, axios, react, babel, vite, vue-core, poetry, and
pydantic — the thing that found two parser bugs the hand-written fixtures missed.

```bash
./scripts/fetch-corpus.sh
cargo test -p n3t-parse --test corpus
```

`tests/corpus/CORPUS.lock` pins every file by commit SHA, so a fetch is
reproducible. To refresh deliberately: delete it, re-fetch, review the diff in
`crates/n3t-parse/tests/corpus.rs` expectations.

Expected counts, each reconciled by hand against independent ground truth:

| Corpus | Packages | Exclusions |
|---|---|---|
| npm-cli | 993 | 0 |
| axios | 666 | 0 |
| react | 2377 | 1 (`link:` workspace entry) |
| babel | 1573 | 1 (176 `workspace:` monorepo members) |
| vite | 1294 | 1 (109 `file:` local paths) |
| vue-core | 620 | 0 |
| poetry | 80 | 0 |
| pydantic | 174 | 1 (2 editable workspace members) |

**Exclusions are not gaps.** A gap means "we could not tell" and forces
`unknown`; an exclusion means "we understood it and deliberately did not report
it" and is purely informational. Keeping them distinct is what stopped 109 of
vite's 1403 entries from vanishing silently.

## 5. Fuzzing

Lockfiles are attacker-influenced input in the threat model — a malicious PR
supplies one — so the parsers are a real attack surface.

```bash
cargo +nightly fuzz run purl fuzz/seeds/purl -- -max_total_time=60
cargo +nightly fuzz run lockfiles -- -max_total_time=60
cargo +nightly fuzz run advisory -- -max_total_time=60
```

Needs `cargo install cargo-fuzz --locked` on nightly.

`purl` asserts more than "no panic": it asserts **normalization is idempotent**
(`parse(serialize(parse(s))) == parse(s)`). That property is load-bearing — graph
node identity and the advisory cache are both keyed on the canonical string, so an
unstable normalization silently splits one package into two. It found four bugs;
see `fuzz/seeds/README.md`.

## 6. Differential vs osv-scanner

Dev-only harness, never a runtime dependency (INV-12):

```bash
brew install osv-scanner
./scripts/differential.sh testbed/python-vulnerable testbed/npm-vulnerable tests/corpus/react tests/corpus/babel
```

Current state: identical finding sets on six of eight targets, and **zero false
negatives** anywhere. The three remaining deltas are all osv-scanner false
positives on local workspace directories — analyzed in `tests/DELTAS.md`.

This harness caught the worst bug in the project so far: yarn alias headers
(`eslint-v9@npm:eslint@^9.0.0`) were read as package names, inventing
dependencies that were not installed, which collided with npm typosquats and
produced **six false "malicious package" findings** on react and babel.

## 7. Format drift

`tests/corpus` is pinned and goes stale by design. This is the opposite — it runs
against whatever package managers are released *today*:

```bash
./scripts/format-drift.sh
cargo test -p n3t-parse --test format_drift
```

Runs nightly in CI with npm/pnpm/yarn/uv/poetry all installed at latest. Catches
silent under-reporting when a lockfile format changes, within a day instead of
eighteen months.

## 8. Point it at your own projects

```bash
./target/release/n3t audit ~/some/python-project
./target/release/n3t audit ~/some/node-project
./target/release/n3t scan  /            # dpkg inventory on a Debian-family box
```

| Flag | Effect |
|---|---|
| `--no-native` | Skip `npm ls` / `pip list`; parse lockfiles only |
| `--cvss 7.0` | Report only at or above this base score |
| `--min-version-age 14` | Flag anything published in the last 14 days |
| `--offline` | Cache only; a miss is `unknown` |
| `--gate-floor medium` | Let medium-confidence attributions gate (default: high) |
| `--format json\|sarif\|junit` | Machine-readable output |

Performance: a cold audit of react's 2383 packages takes ~6s; warm, 0.13s.
Lookups are batched through OSV's `querybatch` and advisory details are fetched
across 16 threads — serial fetching took 24s and blew the Stage 0 budget.

```bash
./target/release/n3t cache
```

## What is still not done

Honest list, so nothing here reads as passing when it isn't:

- **Reproducibility is not established.** Determinism on one machine is verified;
  independent rebuilders and a transparency log are not.
- **No 30-repo false-positive corpus.** The 8-repo corpus plus the differential
  covers a lot, but the clean-repo FP target from the brief is not measured.
- **Ecosystem coverage is Python/npm/apt only.** Cargo, Go, Maven, RubyGems and
  the rest are each ~150 lines behind the `Ecosystem` trait.
- **`--min-version-age` only supports npm and PyPI.** Other ecosystems report the
  policy as inapplicable rather than checking.

And the whole point of the project — L1/L2/L3 observation — is Stages 1 and 2.
Everything above only ever sees what a manifest *claims*.
