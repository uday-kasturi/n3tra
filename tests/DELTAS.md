# Differential deltas vs osv-scanner

Stage 0 exit criterion: findings match `osv-scanner` on the fixture corpus, **or**
every difference has a written explanation here.

Run the harness with:

```bash
./scripts/differential.sh testbed/python-vulnerable testbed/npm-vulnerable tests/corpus/react tests/corpus/babel
```

`osv-scanner` is a dev-only test harness (INV-12). n3tra never invokes it at
runtime and does not require it installed.

## Status

Last run against **osv-scanner 2.5.1 / osv-scalibr 0.5.2**.

| Target | n3tra | osv-scanner | Result |
|---|---|---|---|
| `testbed/python-vulnerable` | 123 | 123 | identical |
| `testbed/npm-vulnerable` | 17 | 17 | identical |
| `tests/corpus/axios` | 3 | 3 | identical |
| `tests/corpus/poetry` | 2 | 2 | identical |
| `tests/corpus/vue-core` | 22 | 22 | identical |
| `tests/corpus/npm-cli` | 29 | 29 | identical |
| `tests/corpus/react` | 198 | 199 | 1 delta, explained below |
| `tests/corpus/babel` | 21 | 23 | 2 deltas, explained below |

**Zero false negatives.** Every advisory osv-scanner reports against a real
registry dependency, n3tra also reports. The three remaining deltas are all cases
where osv-scanner reports a finding against a *local workspace directory* and
n3tra does not.

## How to triage a delta

Direction matters, and the two are not symmetric:

- **n3tra missed something osv-scanner found.** Investigate first, always. A false
  negative is the worst defect a scanner can have, and this direction blocks the
  stage gate.
- **n3tra found something osv-scanner did not.** Often correct — different
  ecosystem coverage, a newer advisory snapshot, or a lockfile shape osv-scanner
  parses less completely. Still needs a written reason.

## Explained deltas

### D1 — `MAL-2025-19860` on `tests/corpus/react` (osv-scanner false positive)

osv-scanner reports react as containing the malicious package
`eslint-plugin-react-internal`. The lockfile entry is:

```
"eslint-plugin-react-internal@link:./scripts/eslint-rules":
```

That is a `link:` to a directory inside react's own repository. It is not the npm
package of the same name, and the npm package with that name is a typosquat
carrying a `MAL-` advisory. Treating the local directory as the registry package
turns "react vendors a local lint rule" into "react ships malware".

n3tra classifies `link:`/`workspace:`/`file:`/`portal:`/`patch:` entries as local
paths, excludes them from advisory matching, and reports the exclusion count in
its output. **n3tra is correct here.**

### D2, D3 — `GHSA-67hx-6x53-jw92` and `GHSA-968p-4wvh-cqc8` on `tests/corpus/babel` (osv-scanner false positives)

osv-scanner matched these against:

```
@babel/traverse   0.0.0-use.local
@babel/helpers    0.0.0-use.local
@babel/runtime    0.0.0-use.local
```

`0.0.0-use.local` is yarn's **placeholder version** for a workspace member — the
source being developed in the monorepo, not a published artifact. It satisfies any
`>= 0` advisory range, so every workspace package with any advisory in its history
produces a hit. babel's monorepo has 176 workspace members, so this generalizes
badly.

Crucially, **no coverage is lost**: babel's lockfile also contains the real
registry dependencies

```
"@babel/traverse@npm:^7.0.0, ... @babel/traverse@npm:^7.29.7"
"@babel/helpers@npm:^7.12.5, ... @babel/helpers@npm:^7.29.7"
```

which resolve to concrete versions, and n3tra checks those normally. The advisories
simply do not apply to the resolved versions.

**n3tra is correct here.**

## Structural differences expected on any repo

Design choices, not bugs:

1. **Version resolution.** n3tra queries OSV with a concrete version and lets the
   server do range matching; osv-scanner evaluates ranges locally. Where a
   lockfile pins a version the two agree exactly. Where a version is unpinned,
   n3tra reports a **coverage gap** and osv-scanner generally reports nothing.
   n3tra's `unknown` is the more honest answer and will look like a delta.

2. **Local path entries.** As above (D1–D3). n3tra excludes them deliberately and
   reports the count; osv-scanner matches them against the registry namespace.

3. **`MAL-` severity class.** n3tra scores malicious-package advisories as their
   own class rather than folding them into a CVSS band, so severity *counts* will
   not line up even when the finding sets are identical.

4. **Unattributed `deb` packages.** n3tra refuses to guess a distro feed when
   `/etc/os-release` is unreadable, because guessing `debian` for an Ubuntu image
   silently matches the wrong advisory set. Expect fewer deb findings and one gap
   where osv-scanner guesses.

5. **CVSS v4-only advisories.** n3tra declines to compute a v4 base score and falls
   back to the textual severity label. A tool that fabricates a v4 number will
   disagree on score while agreeing on the finding.

## What the differential harness has already caught

Worth recording, because it is the argument for keeping the harness:

- **Yarn alias false positives.** `eslint-v9@npm:eslint@^9.0.0` names a *local
  alias*, not a package. n3tra read the alias label as a package name, invented
  dependencies that were not installed, and — because npm's namespace is full of
  typosquats — those invented names collided with real `MAL-` advisories. n3tra
  reported **five false malicious-package findings on react and one on babel**
  before this was fixed. Nothing but a differential run on real repos would have
  surfaced it.
