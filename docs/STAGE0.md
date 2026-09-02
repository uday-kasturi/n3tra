# Stage 0 exit criteria — status

From the implementation brief, §4 Stage 0. Each criterion with what was actually
done and what was measured.

## Exit criteria

### ✅ Findings match `osv-scanner` on the fixture corpus, or every delta is explained

`./scripts/differential.sh` against **osv-scanner 2.5.1 / osv-scalibr 0.5.2**:

| Target | n3tra | osv-scanner | |
|---|---|---|---|
| testbed/python-vulnerable | 123 | 123 | identical |
| testbed/npm-vulnerable | 17 | 17 | identical |
| tests/corpus/axios | 3 | 3 | identical |
| tests/corpus/poetry | 2 | 2 | identical |
| tests/corpus/vue-core | 22 | 22 | identical |
| tests/corpus/npm-cli | 29 | 29 | identical |
| tests/corpus/react | 198 | 199 | 1 delta |
| tests/corpus/babel | 21 | 23 | 2 deltas |

**Zero false negatives.** All three deltas are osv-scanner false positives on
local workspace directories, analyzed in [`tests/DELTAS.md`](../tests/DELTAS.md).

### ✅ Dependency budget gate active and passing

**46 / 150**, enforced by `./scripts/dep-budget.sh` in CI. Percent-encoding was
hand-written (~40 lines) rather than adding a crate; `ureq` was chosen over
`reqwest` for roughly a third of the transitive tree; concurrency uses
`std::thread::scope` rather than an async runtime.

### ⚠️ Reproducible build verified by an independent rebuilder — **NOT MET**

`./scripts/reproducible.sh` verifies **determinism**: two clean builds produce a
byte-identical binary (`6b5417e5…`, toolchain pinned to 1.90.0).

That is necessary but not sufficient, and it is *not* the claim that matters — a
compromised n3tra builds itself deterministically too. Independent rebuilders and
a transparency log do not exist yet. **No release should describe n3tra as
reproducible until they do.**

### ✅ INV-12 — works with no other tooling installed

`crates/n3t-cli/tests/standalone.rs` runs the real binary with `env_clear()` and
`PATH` pointing at an empty directory: no `npm`, no `pip`, no shell, and no
competing scanner. Inventory is byte-identical to a normal run, and an offline
cold-cache audit still exits `2`. The release binary links only `libSystem` and
`libiconv`.

The stronger container form (`scripts/standalone-test.sh` — static musl binary in
a `scratch` image with `--network none`) is written and wired into CI but **has
not been executed**. The development machine's disk hit 100% (139MiB free on
228GiB), which is what made Docker pulls appear to hang and ultimately stopped
Docker Desktop from starting at all. The script detects an unusable daemon within
90s and falls back to the non-container test rather than hanging, so the weaker
check always runs.

Network isolation therefore remains unproven locally and will first be exercised
on a CI runner, where disk and daemon are both clean.

### ✅ Zero panics across the corpus; malformed lockfiles produce errors

- 158 unit/integration tests, `panic`/`unwrap`/`expect`/`indexing` all `deny`,
  `unsafe_code` forbidden crate-wide.
- Fuzzing found **4 real bugs**, all fixed; post-fix runs clean at 5.2M (purl),
  3.1M (lockfiles), 5.7M (advisory) executions.
- Corpus: 8 real lockfiles totalling ~3.9MB parse without panic.

### ✅ Cold run over a 2000-dependency repo under 10 seconds

react, 2383 packages, cold cache: **6.1s**. Warm: **0.13s**. Inventory alone: 4ms.

This started at 23.8s. Fixed by batching through OSV `querybatch` (one request per
500 packages instead of one per package) and fetching advisory details across 16
threads.

## Bugs found while closing the stage

The harnesses earned their place immediately. All six were found by tooling, not
by reading code:

| # | Bug | Found by | Impact |
|---|---|---|---|
| 1 | Blank line after `packages:` closed the pnpm section | corpus | **0 packages** from a 500KB lockfile |
| 2 | 109 of vite's 1403 entries (`file:` paths) dropped silently | corpus | invisible under-reporting |
| 3 | uv.lock editable workspace members dropped for lacking a version | corpus | same class as #2 |
| 4 | Subpath written unencoded; `parse` trims → canonical form reparsed differently | fuzz | node identity splits |
| 5 | Namespace/subpath `%2F` re-split as a separator; then a double-decode | fuzz | node identity splits |
| 6 | **Yarn alias headers read as package names** | differential | **6 false "malicious package" findings** on react and babel |

Bug 6 is the one worth remembering. `eslint-v9@npm:eslint@^9.0.0` names a local
alias, not a package. Reading the label as a package invented dependencies that
were not installed — and because npm's namespace is dense with typosquats, the
invented names collided with real `MAL-` advisories. Nothing but a differential
run against real repositories would have surfaced it.

## Design decisions made during the stage

**Gaps vs exclusions.** Bugs 1–3 all had the same root cause: no way to
distinguish *"we could not tell"* from *"we understood it and chose not to report
it"*. `Inventory` now carries both. Gaps force `unknown`; exclusions are
informational and always printed. Anything neither understood nor excludable must
be a gap — otherwise silent loss returns wearing a label.

**`scan` never emits a verdict.** It performs no advisory lookup, so "clean" from
`scan` would be the same category of lie as "clean" from a crashed collector. It
prints `INVENTORY ONLY` and `"outcome": "inventory_only"`.

**Server-side version matching.** n3tra queries OSV with a concrete version rather
than implementing SemVer + PEP 440 + dpkg comparators. A subtly wrong comparator
produces false negatives, the worst defect a scanner can have. Consequence: the
cache is keyed by exact PURL and offline is genuinely cache-only.

## Test infrastructure now in place

| | |
|---|---|
| `scripts/fetch-corpus.sh` | 8 real lockfiles, pinned by SHA in `CORPUS.lock` |
| `scripts/differential.sh` | vs osv-scanner (dev-only harness — INV-12) |
| `scripts/dep-budget.sh` | hard gate at 150 |
| `scripts/standalone-test.sh` | INV-12 in a `scratch` image, `--network none` (falls back when Docker is unavailable) |
| `crates/n3t-cli/tests/standalone.rs` | INV-12 always-on: empty env, empty PATH |
| `scripts/reproducible.sh` | build determinism |
| `scripts/format-drift.sh` | lockfiles from *current* package managers, nightly |
| `fuzz/` | 3 targets, 4 regression seeds |
| `.github/workflows/ci.yml` | fmt, clippy, tests, budget, corpus, fuzz smoke, standalone, determinism |
| `.github/workflows/nightly.yml` | format drift, 30-min fuzz per target, differential |

## Not done, and not claimed

- Independent rebuilders / transparency log (see above).
- The containerized INV-12 test has never actually run; only its weaker
  empty-PATH counterpart has.
- 30-repo clean false-positive corpus. The 8-repo corpus plus the differential
  covers much of it, but the specific FP target is unmeasured.
- Ecosystems beyond Python, npm, and apt.
- `--min-version-age` covers npm and PyPI only; others report the policy as
  inapplicable rather than silently passing.
