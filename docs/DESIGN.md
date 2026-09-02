# fabriax — build-time dependency observability, universal SCA, and active remediation

**Status:** design draft
**Date:** 2026-08-16

## 1. Thesis

Existing tools answer *"what does the manifest say is installed, and is it vulnerable?"*

- `fetter` — Python only, static, declared-set only. Good CVSS/OSV reporting.
- `osv-scanner` / `grype` / `trivy` — multi-ecosystem, but still reason over declared manifests, lockfiles, or a finished image. They see the *result*, not the *act* of building.
- `dependabot` / `renovate` — remediate, but only by version bump, and only against declared graphs.

Two gaps nobody covers well:

1. **Ground truth during the build.** What actually got fetched, written to disk, and *loaded* while the artifact was being produced — including everything that never appears in any lockfile (`curl | bash` in a Dockerfile, an npm `postinstall` pulling a tarball, a compromised CI action, a vendored blob).
2. **What to do when there is no clean upgrade.** Every scanner stops at "CVE-2026-XXXX, severity 9.1, no fixed version." That is exactly the moment the operator needs help most.

fabriax closes both. Three planes:

```
  ┌─────────────────────────────────────────────────────────┐
  │  OBSERVATION      L0 declared · L1 interposed           │
  │                   L2 kernel   · L3 materialized         │
  └────────────────────────┬────────────────────────────────┘
                           │  raw events (pid, path, url, hash)
  ┌────────────────────────▼────────────────────────────────┐
  │  CORRELATION      attribution → PURL → dependency graph │
  │                   + usage facts + integrity facts       │
  └────────────────────────┬────────────────────────────────┘
                           │  findings (PURL, advisory, evidence)
  ┌────────────────────────▼────────────────────────────────┐
  │  REMEDIATION      the ladder: upgrade → override →      │
  │                   patch → shim → neutralize → contain   │
  │                   each verified by re-running the build │
  └─────────────────────────────────────────────────────────┘
```

## 2. Observation plane

Four collectors, layered by privilege and fidelity, all feeding one event bus. You **union** their output and tag every artifact with which layers saw it. The disagreements between layers are the product.

### L0 — Declared
Parse manifests and lockfiles. Zero privilege, works everywhere, instant. This is the *expected* set — the baseline everything else is diffed against.

### L1 — Interposed
PATH shims around package-manager binaries (`pip`, `uv`, `npm`, `pnpm`, `yarn`, `cargo`, `go`, `apt-get`, `apk`, `dnf`, `gem`, `mvn`, `gradle`, `nuget`, `composer`, `pixi`, `brew`). Records argv, resolved registry URLs, response hashes, exit status. Plus an `LD_PRELOAD` / `DYLD_INSERT_LIBRARIES` variant to catch `dlopen`.

Portable — macOS, unprivileged runners, container-based CI. This is the baseline that must always work.

### L2 — Kernel
eBPF on Linux (`aya` or `libbpf-rs`, in-process with the Rust binary):

| Hook | Answers |
|---|---|
| `execve` / `execveat` | who ran what, under which parent — catches postinstall scripts |
| `openat` / `mmap` | which files were actually **read** → which packages were actually **used** |
| `connect` + DNS | where bytes came from → typosquat / unknown-registry / exfil detection |
| file writes under package roots | what landed, attributed to the process that put it there |

macOS equivalent is the Endpoint Security framework (requires entitlement); where unavailable, degrade to L1 + L3.

Requires a privileged Linux runner. Must be optional, never a hard dependency.

### L3 — Materialized
Content-addressed filesystem state: snapshot inode + hash before/after each build step, or read OCI layer blobs directly for container builds. Catches anything that reached disk regardless of how it got there. Works with BuildKit, Bazel, Nix, make — anything.

Computing a Merkle tree over files actually accessed during compilation gives a tamper-evident, intrinsic identifier for the build's real input set (cf. Bomfather, arXiv 2503.02097).

### The findings fall out of the diffs

| Condition | Finding |
|---|---|
| in L1/L2/L3, absent from L0 | **undeclared dependency** — the headline capability |
| in L0, never `openat`'d in L2 | **declared but unused** — drives usage-gated triage |
| L2 fetch from host outside registry allowlist | **unknown provenance / possible exfil** |
| L3 hash ≠ upstream registry hash | **tampered artifact** |
| L2 process tree: `npm postinstall` → `curl` → `sh` | **suspicious build behavior** |

## 3. Correlation plane

### Universal identity: PURL
`pkg:pypi/requests@2.31.0`, `pkg:npm/lodash@4.17.21`, `pkg:deb/debian/openssl@3.0.11`.

One identifier space across every ecosystem is what makes the tool genuinely agnostic: **one vulnerability lookup path, N thin parsers.** CPE only as a fallback for OS packages with no clean PURL mapping. Adding an ecosystem must never touch the core.

### Attribution: file path → package
Ecosystem-specific ownership rules, tried in order, then content-hash fallback against the registry:

- Python — `site-packages/<dist>-<ver>.dist-info/RECORD`
- Node — nearest enclosing `node_modules/<pkg>/package.json`
- Debian/Ubuntu — `/var/lib/dpkg/info/<pkg>.list`
- Alpine — `/lib/apk/db/installed`
- Rust — cargo fingerprint dirs + `Cargo.lock`
- Go — module cache path structure
- fallback — SHA-256 → registry content lookup

This is the fuzziest part of the system, especially for compiled and vendored code. Attribution confidence must be a first-class field on every node, not a hidden assumption.

### Output: Artifact Dependency Graph
Nodes: PURLs, files, processes, network endpoints.
Edges: `declared`, `installed`, `loaded`, `spawned`, `fetched-from`.

Each node carries `{sources: [L0..L3], attribution_confidence, first_seen_by}`.

### Vulnerability matching
OSV.dev as primary — it is PURL-native and spans ~30 ecosystems, which is exactly the agnostic property we need. GHSA plus distro feeds for OS packages. Report CVSS score, vector, and severity (fetter parity), **annotated with usage facts from L2**: `severity 9.8, but never loaded during build`.

## 4. Remediation plane

The differentiator. A **ladder**, attempted in order. Each rung is a concrete, reversible, recorded action — never a silent mutation.

**1. Upgrade.** Solve for the minimum version bump clearing the advisory while satisfying every other constraint in the resolved graph. Drive the native resolver rather than reimplementing it (`uv lock --upgrade-package`, `npm install pkg@x`, `cargo update -p`).

**2. Transitive override.** Vuln sits in a transitive dep whose parent pins it. Emit the fix in the ecosystem's native format: npm `overrides`, pnpm `resolutions`, pip/uv constraints, Cargo `[patch]`, Maven `dependencyManagement`, Go `replace`.

**3. Backport patch.** No fixed release exists. Pull the upstream fix commit referenced by the advisory, generate a minimal patch against the pinned version, apply as a vendored overlay.

**4. Virtual patch / shim.** Source can't be changed. Inject a guard at the call boundary — a `sitecustomize.py` wrapping the vulnerable function for Python, a loader hook for Node, a narrowed seccomp/AppArmor profile for OS packages. **Explicitly labeled temporary. Loudly. Opt-in only.**

**5. Neutralize.** L2 proves the package was never loaded. Strip it from the artifact or stub it — a zero-risk removal, because you have runtime evidence it is dead weight. Only this tool can justify this rung, because only this tool has the evidence.

**6. Contain.** Nothing above works. Block the package's egress and filesystem writes via sandbox policy, and gate the finding behind a documented, time-boxed exception.

### Two rules that keep this from becoming a liability

**Every fix is verified.** The tool re-runs the build under observation and confirms (a) the vulnerable code path is gone and (b) nothing else regressed. A "temporary fix" is only trustworthy if it is *proven*, and the observation plane is exactly what makes proof possible. This verify-loop is the reason the remediation layer can exist at all.

**Every mitigation expires.** Rungs 3–6 carry a TTL and an upstream watch. When a real fix ships, fabriax opens the upgrade PR and removes its own shim. Without this you have built a technical-debt machine that quietly accumulates unreviewed monkeypatches.

Output is a signed, declarative `fixplan` — reviewable before it is applied.

## 5. CI/CD integration

Single static Rust binary, no runtime dependencies.

```bash
fabriax build -- docker build .        # wrap any build command, transparently
fabriax build -- make release
fabriax audit --cvss 7.0               # fetter-style audit, any ecosystem
fabriax fix --ladder-max 3 --verify    # remediate, stopping before virtual patches
```

- **Wrap mode** is the primary interface — works with make, docker, bazel, npm, anything.
- **BuildKit frontend** + SBOM attestation so `docker buildx build --attest` carries the result.
- **Emits:** CycloneDX + SPDX (SBOM), in-toto / SLSA v1 (provenance over the *observed* set, not the declared one), SARIF (code-scanning UI), JUnit (test panes).
- **`--gate`** with policy-as-code: CVSS threshold, license rules, `undeclared-dependency = fatal`, registry allowlist.
- **Baseline/diff mode** — fail only on findings new since `main`. Non-negotiable for adoption; a tool that reports 400 pre-existing findings on day one gets disabled on day two.
- Wrappers: GitHub Action, GitLab component, CircleCI orb.

## 6. Sequencing

Ecosystem coverage fans out continuously and in parallel with these; the plugin trait is what makes that cheap.

| Milestone | Content | Result |
|---|---|---|
| **M0** | PURL core, L0 parsers (Python, npm, apt), OSV matching, CVSS report | fetter parity, already multi-ecosystem |
| **M1** | L1 shims + L3 diff | **"undeclared dependency"** — first capability nobody else has |
| **M2** | L2 eBPF: execve, openat, connect | usage facts + tamper detection |
| **M3** | Ladder rungs 1–2 + build-verify loop | trustworthy auto-fix |
| **M4** | Rungs 3–6, TTL/expiry/watch, signed attestation | the full differentiator |

## 7. Known hard parts

- **eBPF availability in CI.** GitHub-hosted runners are VMs and can load eBPF with `sudo`; most Kubernetes-based runners cannot. L1 + L3 must be a genuinely good fallback, not a stub.
- **Attribution accuracy** for compiled, vendored, and statically-linked code is inherently fuzzy. Surface confidence rather than pretending certainty.
- **Event volume.** A large build produces millions of syscalls. Filtering must happen in-kernel; a userspace firehose will not keep up.
- **Virtual patching is the risky rung.** Opt-in, loud, expiring, and never the default.
- **"Unused" is a claim about one build,** not about production. Wording in the UI must not let users read runtime safety into build-time evidence.

## 8. References

- [Bomfather: eBPF kernel-level monitoring for build dependencies](https://arxiv.org/html/2503.02097)
- [fetter-rs](https://github.com/fetter-io/fetter-rs) — prior art for the audit/report layer
- [OSV.dev](https://osv.dev) — PURL-native, multi-ecosystem advisory database
- [CI/CD build hardening: eBPF, runtime SBOMs, SLSA](https://cycode.com/blog/cicd-build-hardening/)
