# AAASM-5532 — can Docker Desktop's Linux VM exercise `aa-isolation-native`'s Landlock/seccomp backend on this host?

Whether the arm64 Linux VM behind Docker Desktop on this macOS host can genuinely
run and enforce `aa-isolation-native`'s Landlock or seccomp confinement, so the
three attack classes the first AAASM-5532 pass deferred — fork/exec,
detached/re-parented descendants, and filesystem escape via symlink/rename — can
be tested against a real boundary instead of documented as unreachable.

- **Ticket:** [AAASM-5532](https://lightning-dust-mite.atlassian.net/browse/AAASM-5532) ·
  **Epic:** [AAASM-5526](https://lightning-dust-mite.atlassian.net/browse/AAASM-5526)
- **Compiled against** `remote/main` at `eee7e9e79`
- **Prior artifact:** `aa-integration-tests/tests/adversarial_isolation_launch.rs`'s
  own module doc, merged in PR #2333 (comment trail on the ticket)

## Verdict

**Neither Landlock nor seccomp is exercisable inside Docker Desktop's Linux VM on
this host.** Landlock is compiled out of the VM's kernel entirely — not a version
floor, not a seccomp/capability restriction, a build-time omission
(`CONFIG_SECURITY_LANDLOCK is not set`). `aa-isolation-native`'s seccomp backend is
separately unusable here for an unrelated, architecture-level reason: it is a
hand-built cBPF program against literal x86_64 syscall numbers, gated to
`target_os = "linux", target_arch = "x86_64"` in the crate's own source
(`aa-isolation-native/src/seccomp.rs:468`), and this VM is aarch64. No test was
written against either backend through Docker — doing so would have measured
nothing and reported a hollow pass, which is exactly what the first pass's own
module doc warned against.

**A second finding narrows the actually-open gap.** Re-reading
`aa-isolation-native`'s own existing test suite (which already runs on real Linux
on GitHub Actions' `ubuntu-latest`, no Docker involved) shows two of the three
"deferred" attack classes are **already covered**, just not from
`adversarial_isolation_launch.rs`'s own vantage point:

- Fork/exec: `linux_confinement_native.rs::descendant_confinement_at_three_depths`
  denies a descendant at nested-shell depths 0, 1 and 2, each against its own
  control (`"denied at fork/exec depths 0, 1 and 2, each against its own
  control"`).
- Filesystem escape via symlink/rename/hard link:
  `adversarial_boundary_native_linux.rs::a_symlinked_write_outside_the_grant_never_takes_effect`,
  `::a_rename_across_the_boundary_never_takes_effect`, and
  `::a_hard_link_cannot_bring_a_forbidden_file_into_the_grant` all exist and are
  named in `.ci/isolation-native-lane-scenarios.txt`, which the CI lane enforces
  as a closed set.

**The one class with zero coverage anywhere in the repo is detached/re-parented
descendants** — a process that `setsid`s and double-forks to escape its process
group and get re-parented to PID 1, rather than a plain nested `fork`/`exec`
chain. Every existing "grandchild" helper (`as_grandchild` in both
`aa-integration-tests/tests/adversarial/mod.rs` and
`aa-isolation-native/tests/*.rs`) stays inside one process tree rooted at the
launched program; none of them detach. This is a real, still-open gap, and it
needs the same thing the first pass already said it needs: a genuine Linux
kernel with Landlock/seccomp compiled in and running — which this host's Docker
VM is not.

## Evidence

### Docker Desktop's VM: a real, current, but Landlock-less kernel

```
$ docker version
Server: Docker Desktop 4.44.3 (202357)
 Engine: 28.3.2
 OS/Arch: linux/arm64

$ docker run --rm debian:12 uname -r
6.10.14-linuxkit

$ docker run --rm debian:12 uname -m
aarch64
```

`aa-isolation-native/src/rules.rs` pins the floor this crate requires:

```rust
pub const REQUIRED_ABI: landlock::ABI = landlock::ABI::V3;
pub const REQUIRED_ABI_VERSION: u32 = 3;
pub const REQUIRED_KERNEL_RELEASE: &str = "6.2";
```

`6.10.14 >= 6.2` by release number — the version floor is genuinely met. The
kernel is not, however, built with Landlock support:

```
$ docker run --rm debian:12 bash -c 'zcat /proc/config.gz | grep -i landlock'
# CONFIG_SECURITY_LANDLOCK is not set
```

Confirmed by a direct syscall probe (`landlock v0.4.7`, the exact version this
repo pins in `Cargo.lock`) built and run inside a `rust:1-slim` container on this
same VM:

```
$ cargo run --release   # minimal probe, landlock 0.4.7 + libc, see Method below
--- landlock_create_ruleset raw syscall probe ---
landlock_create_ruleset(NULL,0,VERSION) = -1 errno=Function not implemented (os error 38)
--- ABI probes (BestEffort would silently downgrade, so these use HardRequirement per-ABI) ---
V1 (Linux 5.13): FAILED fully incompatible access-rights: BitFlags<AccessFs>(...)
V2 (Linux 5.19): FAILED fully incompatible access-rights: BitFlags<AccessFs>(...)
V3 (Linux 6.2): FAILED fully incompatible access-rights: BitFlags<AccessFs>(...)
```

`errno 38` is `ENOSYS` — the kernel does not recognise the syscall number at
all, which is exactly what an absent `CONFIG_SECURITY_LANDLOCK` build predicts,
and is a different failure mode from a permission or seccomp refusal (which
would be `EPERM`/`EACCES` on a kernel that *has* the syscall). All three ABI
levels fail identically, including the oldest (Linux 5.13, ABI v1) — this is not
a version gap at all, it is total absence.

**This is a VM-kernel-build property, not a container-architecture one.** The
same probe against `debian:12 --platform linux/amd64` (Docker Desktop's QEMU
emulation path) reports the identical `CONFIG_SECURITY_LANDLOCK is not set` —
because it is the same underlying linuxkit VM kernel regardless of which
container architecture is requested; only userspace is emulated, not the
kernel.

### Seccomp: kernel-available, crate-unusable on this architecture

The kernel does carry seccomp:

```
$ docker run --rm debian:12 bash -c 'zcat /proc/config.gz | grep -i seccomp'
CONFIG_HAVE_ARCH_SECCOMP=y
CONFIG_HAVE_ARCH_SECCOMP_FILTER=y
CONFIG_SECCOMP=y
CONFIG_SECCOMP_FILTER=y
```

But `aa-isolation-native`'s own seccomp module is not a general seccomp
consumer — it hand-encodes a cBPF program whose comparisons are literal x86_64
syscall numbers, and the crate gates `install` accordingly:

```rust
// aa-isolation-native/src/seccomp.rs:468
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
```

with the non-matching arm named explicitly at `seccomp.rs:526-534` as "never
reached through this backend's own launcher, which is Linux+x86_64-gated one
level up." Docker Desktop's VM reports `aarch64`. Requesting a
`--platform linux/amd64` container does not change this: Docker Desktop's
cross-arch containers run under QEMU user-mode emulation, where the emulated
binary's syscalls are translated to the *host* kernel's native syscall numbers
before they reach the kernel — the kernel that installs and evaluates a seccomp
filter sees aarch64 syscall numbers regardless of which architecture the
container image declares. There is no configuration of this host's Docker VM
that gets an x86_64-numbered filter matched against the syscalls the kernel
actually receives.

### Method

- `docker version`, `docker run --rm debian:12 uname -r|-m`, and the
  `/proc/config.gz` greps above were run directly against this host's Docker
  Desktop.
- The Landlock syscall probe is a from-scratch two-file Cargo project
  (`landlock = "0.4.7"`, matching this repo's `Cargo.lock` pin, plus `libc`),
  built and executed with `docker run --rm -v <dir>:/work -w /work rust:1-slim
  cargo run --release` — genuinely compiled and executed inside the same VM
  kernel `aa-isolation-native` would run against, not simulated or read from
  documentation. The probe source is not committed (it is a disposable
  diagnostic, not part of the suite) but is reproducible from this report: a
  `main.rs` that calls `Ruleset::default().set_compatibility(HardRequirement)
  .handle_access(AccessFs::from_all(abi))` for each of `ABI::V1/V2/V3`, plus a
  raw `libc::syscall(444, ...)` call to `landlock_create_ruleset` for the errno.
- `aa-isolation-native/src/rules.rs` and `src/seccomp.rs` were read directly at
  `remote/main` `eee7e9e79` for the floor and the architecture gate.
- `aa-isolation-native/tests/linux_confinement_native.rs`,
  `tests/adversarial_boundary_native_linux.rs`, and
  `.ci/isolation-native-lane-scenarios.txt` were read to establish what the
  existing native-Linux CI lane already covers.

**One honest limit.** This was not tested against a bare-metal or
non-Docker-Desktop Linux VM (e.g. a cloud Linux host, `colima`, or `lima` with a
different kernel build) — the ticket scoped the investigation to *this host's
Docker Desktop* specifically, and that is what was measured. A differently-built
Linux VM could plausibly carry Landlock; this report makes no claim about any
kernel other than the one Docker Desktop actually ships on this machine today.

## What this means for the three deferred attack classes

| Attack class | Status | Where |
|---|---|---|
| Fork/exec | **Already covered**, not novel | `aa-isolation-native/tests/linux_confinement_native.rs::descendant_confinement_at_three_depths`, real Linux CI (`ubuntu-latest`), no Docker needed |
| Filesystem escape via symlink/rename | **Already covered**, not novel | `aa-isolation-native/tests/adversarial_boundary_native_linux.rs` (symlink, rename, hard-link scenarios), same CI lane |
| Detached/re-parented descendants (`setsid` + double-fork to PID 1) | **Still genuinely open** | No existing test anywhere in the repo exercises this; needs a real Linux 6.2+ host with Landlock compiled in — CI's own `ubuntu-latest` runner qualifies (it is what runs the two rows above); this host's Docker Desktop VM does not |

The first AAASM-5532 pass's module doc (`adversarial_isolation_launch.rs`)
described all three as one undifferentiated "need a confinement backend" gap.
That was accurate about *this suite's own* coverage (none of the three were
exercised **from `adversarial_isolation_launch.rs`**), but reading it as "none of
the three are tested anywhere" overstates the gap — two of them already have
real, CI-enforced coverage in `aa-isolation-native`'s own native-Linux test
files, just written directly against the backend rather than through the
`aasm run` launch path this suite drives. This report does not change that
suite's own scope (it still only exercises what this host can genuinely test)
but corrects the record on what remains actually unwritten.

## Recommendation

1. **Do not add Docker-hosted tests for AAASM-5532** on this host. No real
   confinement backend is exercisable through it — the evidence above is
   definitive (`ENOSYS` on the syscall itself, and a build-time config flag,
   not a permission denial that a differently-configured container might
   route around).
2. **Detached/re-parented descendants remains the one genuinely open item**
   from the original three. It belongs in
   `aa-isolation-native/tests/adversarial_boundary_native_linux.rs` (or a
   sibling file following the same pattern), written directly against
   `aa-isolation-native` using its existing `Scratch`/`as_grandchild` shape
   extended with a `setsid`/double-fork step, and run on the CI lane that
   already runs everything else in that file — `ubuntu-latest`, no Docker
   involved. It does not need this host at all.
3. **Correct `adversarial_isolation_launch.rs`'s module doc** to stop
   describing fork/exec and filesystem escape as undifferentiated future work
   alongside detached/re-parented descendants — they are done, elsewhere, and
   leaving the doc as-is invites someone to duplicate them. (Done by this
   change; see the diff.)
4. If a genuinely Landlock-capable local Linux VM is ever wanted for this kind
   of host-side spot-check, it is a separate, deliberate infrastructure
   decision (e.g. a `colima`/`lima` profile pinned to a kernel built with
   `CONFIG_SECURITY_LANDLOCK=y`) — not a Docker Desktop default, and out of
   scope for this ticket.
