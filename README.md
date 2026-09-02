# n3tra

n3tra is a build-time dependency tool. The command-line binary is called `n3t`.

## The idea

Most dependency scanners read a manifest or a lockfile and tell you what is
declared and whether it is vulnerable. They see the result of a build, not the
build itself. Two things tend to fall through the gaps:

1. What actually happens during a build. Files that get fetched, written, and
   loaded while the artifact is produced, including things that never show up in
   any lockfile. Examples are a `curl | bash` step in a Dockerfile, an npm
   postinstall that pulls a tarball, or a vendored binary blob.
2. What to do when there is no clean upgrade. Many scanners stop at "here is a
   vulnerability, there is no fixed version." That is often the point where an
   operator needs the most help.

n3tra is an attempt to work on both of these.

## How it is organized

n3tra is split into three planes.

| Plane | What it does |
|-------|--------------|
| Observation | Collects what a build declares and what it actually does, layered by how much privilege each collector needs |
| Correlation | Attributes raw events back to packages and builds a dependency graph with usage and integrity facts |
| Remediation | Works through a set of options (upgrade, override, patch, shim, neutralize, contain) and checks each one by re-running the build |

The observation plane starts from the declared set (manifests and lockfiles) and
adds higher-fidelity collectors on top. The disagreements between what is
declared and what is observed are the interesting part.

## Layout

The workspace is a set of Rust crates.

| Crate | Role |
|-------|------|
| `n3t-core` | Core types: package URLs, the dependency graph, verdicts, and the fix-plan schema. No I/O. |
| `n3t-parse` | Inventory. Uses native tooling first and falls back to hand-written lockfile parsers. |
| `n3t-advisory` | Advisory data: an OSV client, an on-disk cache, CVSS scoring, and version cooldown. |
| `n3t-cli` | The `n3t` binary. This is the user-facing, unprivileged entry point. |

`fuzz/` holds fuzzing harnesses and is kept out of the release build.
`docs/` has the design notes and threat model. `testbed/` holds fixtures for
format-drift testing.

## Status

Early. Version is 0.0.1 and the design is still a draft. See `docs/DESIGN.md`
for the current thinking and `docs/THREAT_MODEL.md` for the security model,
which matters here because the tool runs inside the builds it inspects.

## License

Apache-2.0.
