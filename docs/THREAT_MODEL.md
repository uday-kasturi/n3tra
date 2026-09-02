# n3tra threat model

n3tra is a privileged actor inside every build it touches. A compromised
build-security tool can inject code into every downstream build while appearing
legitimate, which makes n3tra itself a high-value target — arguably higher-value
than the builds it protects.

The invariants in the implementation brief exist to bound that. This document
records what each adversary can do and which invariant answers them.

## Adversaries, in priority order

### 1. Compromised n3tra release or patch feed

The worst case, because it inverts the tool's purpose.

| Mitigation | Invariant |
|---|---|
| Observer cannot write, exec, or open sockets | INV-1 |
| No code path mutates a user repository | INV-4 |
| No self-update (an auto-updater is an RCE channel by design) | INV-7 |
| Reproducible builds, verified by independent rebuilders | INV-7 |
| Patches signed with a **different** key than releases | Stage 4 |
| Patch transparency log, so no one receives a targeted patch invisible to others | Stage 4 |
| Signed revocation feed, failing **open** on network error | Stage 4 |

Self-attestation is circular and we say so in the README: a compromised n3tra
reports itself clean. The claim that carries weight is not "n3tra says n3tra is
clean" but "unrelated parties rebuilt it and got the same hash." The revocation
feed fails open deliberately — failing closed would make it a remote off-switch
for other people's builds.

### 2. Malicious repository under scan

A hostile repo controls its lockfiles, build scripts, and environment. Lockfiles
are therefore **attacker-influenced input**: a malicious PR can supply one.

- Every parser gets a `cargo-fuzz` target (Stage 0).
- Malformed input produces errors, never panics — a Stage 0 exit criterion,
  covered today by `purl::tests::hostile_input_never_panics`.
- The repo must not be able to crash n3tra into a *passing* verdict. This is the
  confused-deputy case and it is answered structurally: see INV-5 below.

### 3. Attacker suppressing detection

Every route to blinding the collector must land on `unknown`, never `clean`:

| Route | Detected by |
|---|---|
| Crash or kill the collector | `UnknownReason::ObserverTerminated` |
| Exhaust the ring buffer | `UnknownReason::EventLossPossible` |
| Bypass the L1 shims (absolute path, `env -i`, PATH reset) | `UnknownReason::ShimBypassed` |
| Run the build on a kernel n3tra cannot see | `UnknownReason::BuildRanElsewhere` (INV-11) |

The last is the most dangerous, because it is **silent by default**: a detached
builder produces an empty event stream, and a naive implementation reports a clean
build. It is indistinguishable from success, which makes it worse than a crash.
Hence the mandatory pre-flight and post-flight check that the target cgroup
actually appeared in the observed stream.

INV-5 is enforced by construction rather than convention in `n3t-core::verdict`:
`Outcome::Clean` is **derived, never constructed**, and only from
`Coverage::Complete`. There is no code path that turns absent evidence into a pass,
and `verdict::tests::partial_coverage_outranks_findings` asserts that partial
coverage outranks even a clean finding list.

### 4. n3tra as a cross-tenant observer

**A threat n3tra itself introduces**, and therefore one that must be designed out
rather than documented around.

eBPF attaches at the kernel and containers share the host kernel. A host-wide
attach on a shared self-hosted runner sees every other tenant's build: registry
tokens in argv, source paths, private dependency names.

INV-10 answers this by filtering on the target build's cgroup subtree **in the
kernel**, so out-of-scope events never reach userspace at all. The Stage 2 exit
criteria include a two-tenant isolation test; that test failing is a security
incident in the tool, not a bug.

### 5. Operator over-trusting output

Real, not a UX nicety. A confident wrong "safe to remove" is worse than no tool.

- INV-8: `Confidence` carries its consequences as methods. `Low` cannot gate and
  cannot generate a fixplan under *any* configuration, including an operator who
  sets the floor to `Low`.
- INV-9: usage claims are scoped to one build, checked mechanically by
  `n3t_core::wording::check` rather than left to reviewer discipline. "Unused" is
  a prohibited string.

The rung 5 split exists for the same reason. "Not loaded during the build,
therefore removable" holds for build-time toolchains and is close to
*anti-correlated* with necessity for containerized interpreted-language services,
where the database driver and HTTP client load when the container starts serving,
not during `docker build`. Only 5a (strip build-only artifacts) ships.

## Explicitly out of scope

- **Build server compromise** (SolarWinds-shaped). If the attacker owns the machine,
  they own the collector. n3tra detects nothing here and the README says so.
- **Maintainer account compromise** (Shai-Hulud, event-stream). Not detectable by
  observation. Partially covered by `MAL-` advisories and the version-cooldown
  policy, both of which are data, not evidence.
- **Runtime attacks.** All evidence is build-scoped, always.

## Trust boundary

```
  n3t-observe  (elevated, may attach probes)
      |  append-only event log  ← the only thing it can write
      v
  n3t-fix      (ordinary build user, zero elevated privilege)
```

They never share a process. A compromised observer yields **a liar, not an
injector** — it can produce false events, but it cannot write to the workspace,
execute anything, or reach the network.

Because the event log crosses this boundary, its encoding is a security concern
rather than a cosmetic one: an encoding that fails only in production is an
availability bug on the path that produces verdicts. `tests/serde_round_trip.rs`
covers every core type for this reason, including that a verdict which was
`Unknown` before serialization does not deserialize into something that passes.
