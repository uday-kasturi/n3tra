# eBPF attach-point allowlist (INV-3)

**Status:** empty until Stage 2. This file is the allowlist itself, not documentation
*about* the allowlist — the loader test in `n3t-observe` compares the set of loaded
programs against this table and fails if they diverge.

## INV-3: observation is provably passive

Every attach point listed here must be **attach-only**. The following are forbidden
outright, and their absence is asserted by test rather than by review:

- `bpf_override_return` — can alter syscall results, therefore can change build behavior
- Denying LSM hooks (`bpf_lsm_*` returning non-zero) — same
- Any `bpf_probe_write_user` — writes into the traced process
- Any helper that sends signals (`bpf_send_signal`, `bpf_send_signal_thread`)

The passivity guarantee is what makes the collector safe to run inside somebody
else's build at all. INV-13 follows from it: L2 observes, it never prevents. By the
time a fetch is visible to eBPF the bytes are already on disk; blocking would require
one of the forbidden verbs above.

If a future feature seems to need prevention, it belongs in L1 (the user's own opted-in
shim, behind `--enforce-registry-allowlist`), never here.

## Allowlist

| Program | Attach type | Hook | Purpose | Prevents? |
|---|---|---|---|---|
| _(none yet)_ | | | | |

### Planned for Stage 2

Listed here for review ahead of implementation; they do not become allowlisted until
they appear in the table above with a merged implementation.

| Program | Attach type | Hook | Purpose |
|---|---|---|---|
| `trace_execve` | tracepoint | `syscalls:sys_enter_execve` | process tree: who ran what, under which parent |
| `trace_execveat` | tracepoint | `syscalls:sys_enter_execveat` | same, for the `execveat` path |
| `trace_openat` | tracepoint | `syscalls:sys_enter_openat` | which package files were actually read |
| `trace_mmap` | tracepoint | `syscalls:sys_enter_mmap` | shared-object loads missed by `openat` |
| `trace_connect` | kprobe | `tcp_connect` | fetch provenance: where bytes came from |
| `trace_dns` | tracepoint | `net:net_dev_queue` | resolve endpoints to hostnames for allowlist matching |
| `trace_write_pkgroot` | tracepoint | `syscalls:sys_enter_write` | what landed under package roots, attributed to the writing process |

## Mandatory in-kernel filtering (INV-10)

Every program above filters on `bpf_get_current_cgroup_id()` against the target build's
cgroup subtree **in the kernel**, before the event reaches the ring buffer.

This is a tenancy requirement, not a performance optimization. Containers share the host
kernel, so a host-wide attach observes every container on that host — on a shared
self-hosted runner that means other tenants' registry tokens in argv, their source paths,
and their private dependency names. An unscoped collector is an accidental cross-tenant
exfiltration tool, and that is a threat n3tra itself introduces (threat model §4), so it
must be designed out rather than mitigated by policy.

The secondary benefit is real too: a large build emits millions of syscalls, and a
userspace firehose will not keep up.

## Amending this file

Adding a hook requires, in the same PR:

1. A row in the allowlist table with a stated purpose.
2. Confirmation the program uses no forbidden helper (the loader test checks this).
3. A note in `docs/THREAT_MODEL.md` if the hook widens what the collector can see.
