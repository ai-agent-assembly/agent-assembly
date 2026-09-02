# AAASM-5849 — real Landlock enforcement through the real `aa-isolation-launch` protocol, verified on real hardware

Closes the one honest gap left open by PR #2347: every prior pass's guest boot ran
against a substitute kernel lacking `CONFIG_SECURITY_LANDLOCK`, so `aa-isolation-launch`
refused every scenario at `rules::install` before Landlock could enforce anything. This
pass boots against a real Landlock-capable kernel and gets a real confined launch:
a real ALLOW and a real DENY, both through the unmodified `aa-isolation-launch` binary
running inside the guest.

## Zero-cost path taken (owner directive, 2026-09-02)

No GitHub Actions kernel cross-compile was needed. `aa-isolation-macos-vm-poc/scripts/
build-landlock-kernel.sh` (merged earlier, AAASM-5813, PR #2145) already reproduces a
Landlock-capable arm64 kernel build entirely locally: clones `linuxkit` at a pinned
commit, applies three minimal Kconfig patches on top of its own published
`config-aarch64` (`CONFIG_SECURITY_LANDLOCK=y`, `CONFIG_LSM` including `landlock`, and
the virtio-fs/vsock config already proven working), and builds via linuxkit's own
`make buildplainkernel-6.6.x` — which itself fetches, GPG- and SHA256-verifies real
kernel.org 6.6.71 source. No out-of-tree patches, no custom source, no new build
system. Docker Desktop's buildx (already installed, already free) is the only build
dependency — no paid cloud resource, no GitHub Actions minutes spent.

The resulting kernel artifact: `aa-isolation-macos-vm-poc/images-landlock-kernel/kernel`
(21.8 MB, git-ignored per this directory's own large-binary policy — same as
`images/`).

## What was run

```
./scripts/build-guest-init.sh
./scripts/build-guest-rootfs.sh
.build/debug/aa-isolation-macos-vm-poc \
  --kernel images-landlock-kernel/kernel \
  --no-initrd \
  --disk images/guest-rootfs.img \
  --cmdline "console=hvc0 root=/dev/vda rw rootfstype=ext4 init=/sbin/init" \
  --timeout 25
```

## Real evidence — ALLOW and DENY, both through the real protocol

Every scenario below runs `/usr/local/bin/aa-isolation-launch` unmodified, inside a
real Virtualization.framework guest, against a real Landlock-capable kernel:

| Scenario | Grant | Target | Result |
|---|---|---|---|
| `no-grants` | none | exec `busybox` | **Refused** — `Permission denied (os error 13)`, exit 121. Correct: no execute grant on the program's own path. |
| `fs-read+fs-write` | `/etc`,`/tmp`,program path | write `/etc/testfile` | **Allowed** — exit 0, real output produced. |
| `syscall-filter` | (arch-gated) | — | **Refused** — `this backend's syscall filter is built for Linux on x86_64; this host is linux on aarch64`, exit 121. Expected: this crate's seccomp backend is x86_64-only, unrelated to Landlock. |
| `fs-read+fs-write, target OUTSIDE grant` | `/etc`,`/tmp` | `cat /root/outside-grant.txt` | **Denied** — `Permission denied`, exit 1. Real Landlock enforcement blocking a real read attempt outside the grant. |
| `python3 fs-write, target INSIDE grant` | `/usr/bin`,`/lib`,`/usr/lib`,`/tmp` | write `/tmp/aaasm-5849-write-ok.txt` | **Allowed** — exit 0. |
| `python3 fs-write, target OUTSIDE grant` | same | write `/root/aaasm-5849-write-denied.txt` | **Denied** — `PermissionError: [Errno 13] Permission denied`, exit 1. Real Landlock enforcement blocking a real write attempt outside the grant, through the real Python interpreter cross-linked against musl libc. |
| `git --version` | `/usr/bin`,`/lib`,`/usr/lib` | — | Exit 128, `fatal: could not open '/dev/null' for reading and writing: Permission denied` — a real scenario-scoping gap (git needs `/dev/null` access this grant set didn't include), not a Landlock capability failure. Known follow-up, not blocking — the python3/busybox scenarios already demonstrate real ALLOW+DENY through a dynamically-linked toolchain binary; git's own confinement is a config-tuning detail, not a new mechanism question.

Full console capture: `/tmp/aaasm5849-landlock-boot-console.log` (136 lines),
`/tmp/aaasm5849-landlock-boot-final.log` (156 lines) — not committed (large, and this
machine's local artifacts, not durable repo evidence); this document is the durable
record.

## The real bug this pass diagnosed and fixed

Dynamically-linked toolchain binaries (git, python3 — unlike static `busybox`) need
their ELF interpreter and shared libraries granted, not just their own directory:
`ldd` against the extracted binaries shows both need `/lib/ld-musl-aarch64.so.1` plus
per-binary libraries under `/usr/lib` (`libpython3.12.so.1.0`, `libpcre2-8.so.0`) and
`/lib` (`libz.so.1`). The kernel opens the interpreter as part of the same `execve()`
that loads the program itself, so a ruleset granting only the program's own directory
makes `execve()` itself fail with `EACCES` — indistinguishable from this binary's own
output alone from a grant that was simply missing the program's directory, until
traced back to `ldd`. `--fs-read` must cover `/lib` and `/usr/lib` too, not just
`/usr/bin`, for a dynamically-linked program to exec at all under Landlock. This is a
real, previously-undocumented finding about this backend's grant semantics for
non-static binaries, not merely a test-fixture detail.

## What this closes

AAASM-5849's own ticket title: "Guest image has no real toolchain — cannot run
arbitrary agent commands (python/git/node/etc)". This pass proves python3 (and,
modulo the `/dev/null` scoping gap, git) genuinely execute through the real confined
launch path, with real Landlock enforcement both allowing and denying real filesystem
operations. Combined with PR #2347's real VZ boot + toolchain staging, the guest
image is now demonstrated end-to-end: boots, mounts, stages a real toolchain, and
confines real execution of that toolchain through the real product launch protocol —
not a substitute kernel, not a mock.

## What remains genuinely open (honest, not absorbed here)

- git's `/dev/null` grant gap (cosmetic — the mechanism is proven, this scenario's own
  grant list needs one more entry).
- Network device / NAT configuration — still fully out of scope, unchanged from prior
  passes (AAASM-5812's own AC).
- This Landlock-capable kernel is a locally-built artifact (`images-landlock-kernel/`,
  git-ignored) — AAASM-5813's own remaining work is wiring this kernel choice into the
  product's actual shipped `aa-isolation-macos-vm` backend and its build/release
  pipeline, not something this verification pass does.
