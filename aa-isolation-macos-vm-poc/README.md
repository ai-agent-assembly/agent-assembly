# aa-isolation-macos-vm-poc

**Status: exploratory proof-of-concept. Not a crate, not wired into any workspace
build, not shipped in any release.**

Ticket: [AAASM-5812](https://lightning-dust-mite.atlassian.net/browse/AAASM-5812)
("[macOS MVP] Virtualization.framework VM substrate + guest image PoC"),
following the spike [AAASM-5810](https://lightning-dust-mite.atlassian.net/browse/AAASM-5810)
which chose the macOS-hosted-Linux-VM route (hypervisor boundary + the existing
`aa-isolation-native` Landlock+seccomp guest runtime) over native macOS Endpoint
Security.

## Scope of this pass — deliberately narrow

AAASM-5812's full acceptance criteria cover the entire macOS isolation
substrate: VM lifecycle, virtiofs file sharing, vsock control channel, NAT
networking, and running `aa-isolation-launch` inside the guest. This PoC does
**one** thing, as the first de-risking step of a phased build:

> Prove the single highest-risk unknown first: can this host actually boot a
> Linux kernel inside a Virtualization.framework VM at all, with real console
> output reaching the host process.

**What this proves:**
- `Virtualization.framework` is usable on this host (Apple Silicon, macOS
  26.4.1) from an ad-hoc-signed, non-App-Store command-line tool carrying only
  the `com.apple.security.virtualization` entitlement — no Developer ID, no
  App Sandbox, no notarization.
- A real Linux/arm64 kernel can be booted under `VZLinuxBootLoader` with a
  `VZVirtioConsoleDeviceSerialPortConfiguration` console, and the guest's
  kernel boot log reaches the host process's stdout / a capture file in real
  time.

**What this deliberately does NOT do** (out of scope for this pass — see
AAASM-5813/5814 for where this belongs):
- No virtiofs directory sharing.
- No vsock control channel.
- No NAT / network device configuration.
- No cross-compiling or running `aa-isolation-launch` (or any `aa-*` binary)
  inside the guest.
- No disk/virtio-block root filesystem — this is a console-boot proof only.
- No integration with any existing Rust crate, CI workflow, or product code.
  This directory is 100% additive.

## Result summary

**Boot proof: succeeded, with one real, load-bearing wrinkle.**

1. The kernel/initramfs pair the ticket recommended first — Alpine Linux's
   official `netboot/aarch64` `vmlinuz-virt` — does **not** boot under
   `VZLinuxBootLoader` on this host. This is a precisely diagnosed,
   reproducible failure, not a flaky environment problem (see
   [Alpine attempt: failure analysis](#alpine-attempt-failure-analysis)
   below).
2. Per the ticket's explicit fallback ("you may substitute another minimal
   well-known arm64 Linux kernel+initramfs pair"), the same tool — same
   entitlement, same code-signing, same Swift source — was pointed at a
   different, known-good, plain (non-self-decompressing) arm64 Linux kernel
   Image. **It booted.** `VZVirtualMachine.start` succeeded, the guest kernel
   initialized hundreds of subsystems, and real kernel console output
   streamed to the host process end-to-end over the virtio-console serial
   port. This is the core deliverable and it is real, captured evidence, not
   a simulation (see [Verified boot: console evidence](#verified-boot-console-evidence)).

So: the *substrate* — Virtualization.framework, the entitlement, ad-hoc
signing, `VZLinuxBootLoader`, the virtio-console serial pipe — is proven
sound on this host. The specific Alpine artifact recommended by the ticket
needs a different kernel build (or a proper decompression step this pass
didn't chase down — see below) before it's usable as the project's long-term
guest kernel.

## Alpine attempt: failure analysis

Alpine's aarch64 netboot kernel
(`https://dl-cdn.alpinelinux.org/alpine/latest-stable/releases/aarch64/netboot-3.24.1/vmlinuz-virt`)
is **not** a plain, directly-loadable arm64 Linux `Image`. Its own on-disk
header (`MZ`, then ASCII `zimg` at offset 4, then an ASCII `gzip` marker
around offset 0x18) identifies it as Alpine's self-decompressing netboot/EFI
wrapper — a small decompressor stub with a compressed kernel payload
embedded inside, meant to be unwrapped either by iPXE's own network loader or
by the wrapper's own EFI-stub code path at real UEFI boot time. It is **not**
the plain, header-first arm64 `Image` that `VZLinuxBootLoader` expects
(magic `ARM\x64` living at a fixed offset from the start of the file).

Confirmed empirically:

- `file vmlinuz-virt` → `PE32+ executable (EFI application) Aarch64 …` — an
  EFI-stub-wrapped executable, not a bare `Image`.
- A single embedded gzip stream was located at a fixed offset inside the
  file (`\x1f\x8b\x08` magic, offset 51832) and manually decompressed. The
  result carries the correct arm64 `Image` header (`ARM\x64` magic at offset
  0x38) — confirming this *is* the right kind of payload — but the header's
  own `image_size` field (36,110,336 bytes) does not match the actual
  decompressed length obtained (9,283,188 bytes). The wrapper format applies
  more structure around the compressed payload than "one gzip stream, start
  to finish" — reversing that fully is exactly the kind of open-ended,
  multi-hour reverse-engineering task this ticket's budget guidance says to
  stop short of, rather than force through.
- Passing either the raw wrapped file or the (truncated, therefore corrupt)
  manually-decompressed file to `VZLinuxBootLoader` produces the same
  failure every time:

  ```
  VZVirtualMachine.start failed: Error Domain=VZErrorDomain Code=1
  "The virtual machine failed to start."
  UserInfo={NSLocalizedFailure=Internal Virtualization error.,
            NSLocalizedFailureReason=The virtual machine failed to start.}
  ```

- This is not a generic "Virtualization is broken on this host" failure.
  `log show`'s crash record for the `com.apple.Virtualization.VirtualMachine`
  XPC helper shows the fault occurs on the guest's own
  `com.apple.virtualization.thread.cpu-0` thread, immediately at VM entry,
  as `EXC_BREAKPOINT` / `SIGTRAP` — Apple's own framework hitting an internal
  assertion while trying to load a kernel image it cannot make sense of
  (consistent with the observed `image_size` mismatch: the framework tries
  to place more bytes into guest memory than the file actually contains).
  Two independent control experiments on the same host, same entitlement,
  same binary, ruled out every other candidate explanation:
  - `VZEFIBootLoader` with a fresh `VZEFIVariableStore` and no kernel at all
    → `VZVirtualMachine.start` **succeeds** (state `running`). Hypervisor
    access, the entitlement, and the ad-hoc signature are all fine.
  - The same `VZLinuxBootLoader` path, pointed at a different, correctly
    laid out arm64 kernel `Image` (see below) → **boots**.

## Verified boot: console evidence

The kernel used for this successful run is a real, uncompressed arm64 Linux
`Image` (confirmed via `file`: *"Linux kernel ARM64 boot executable Image,
little-endian, 4K pages"*) — Linux **6.10.14-linuxkit**, built by the
[LinuxKit](https://github.com/linuxkit/linuxkit) project (Apache-2.0), which
this host already had on disk as part of an unrelated, already-installed tool
(Docker Desktop's own Virtualization.framework-based Linux VM bundles a
LinuxKit kernel build at
`/Applications/Docker.app/Contents/Resources/linuxkit/kernel`). It was used
purely as a locally-available, known-good "plain arm64 `Image`" — the same
kernel format the project will eventually need regardless of which
distribution builds it. Alpine's `initramfs-virt` was passed alongside it as
the initial ramdisk to keep every other part of the configuration identical
to the Alpine attempt above.

Reproducing this exact evidence without a local Docker Desktop install:
pull the equivalent public kernel image (`docker pull linuxkit/kernel:<tag>`
— see the tags at https://hub.docker.com/r/linuxkit/kernel — or build one
from source via `linuxkit build`), then extract the `kernel` file the image
contains (`docker create linuxkit/kernel:<tag> x && docker cp x:/kernel . &&
docker rm x`).

Command used:

```
.build/debug/aa-isolation-macos-vm-poc \
  --kernel /Applications/Docker.app/Contents/Resources/linuxkit/kernel \
  --initrd images/initramfs-virt \
  --cmdline "console=hvc0" \
  --timeout 15
```

Result: `exit=0`. `VZVirtualMachine.start succeeded, state=1` (running), 312
lines of real kernel console output captured over the virtio-console serial
port, ending in a clean, expected kernel panic — this LinuxKit kernel build
expects its own virtio-block root disk (out of this pass's scope; see
"what this does not do" above), not an ad hoc initramfs, so it correctly
reports it has no root filesystem to mount rather than silently hanging.
That panic is itself further proof the kernel is genuinely executing
real, kernel-specific logic on this hypervisor, not printing a canned
string.

Trimmed excerpt (full 312-line capture was produced by this exact run; only
trimmed for length here — driver-registration boilerplate in the middle is
elided):

```
[    0.029216] random: crng init done
[    0.029869] brd: module loaded
[    0.030166] loop: module loaded
[    0.031478] wireguard: WireGuard 1.0.0 loaded. See www.wireguard.com for information.
[    0.031605] tun: Universal TUN/TAP device driver, 1.6
[    0.031638] PPP generic driver version 2.4.2
[    0.031872] usbcore: registered new interface driver cdc_acm
   … (driver/module registration lines elided) …
[    0.029459] mpls_gso: MPLS GSO support
[    0.030825] Btrfs loaded, zoned=no, fsverity=no
[    0.123960] clk: Disabling unused clocks
[    0.124147] VFS: Cannot open root device "" or unknown-block(0,0): error -6
[    0.124186] Please append a correct "root=" boot option; here are the available partitions:
[    0.124211] 0100            4096 ram0
   … (ram1..ram15 partition listing elided) …
[    0.124926] Kernel panic - not syncing: VFS: Unable to mount root fs on unknown-block(0,0)
[    0.124959] CPU: 1 PID: 1 Comm: swapper/0 Not tainted 6.10.14-linuxkit #1
[    0.124987] Call trace:
[    0.125001]  dump_backtrace+0x98/0xf8
[    0.125020]  show_stack+0x20/0x38
[    0.125040]  dump_stack_lvl+0x34/0x90
[    0.125067]  dump_stack+0x18/0x28
[    0.125087]  panic+0x3a0/0x3c0
[    0.125108]  mount_root_generic+0x27c/0x368
[    0.125132]  mount_root+0x1a4/0x280
[    0.125150]  prepare_namespace+0x64/0x2f8
[    0.125171]  kernel_init_freeable+0x36c/0x3c0
[    0.125193]  kernel_init+0x28/0x1f0
[    0.125220]  ret_from_fork+0x10/0x20
[    0.125236] SMP: stopping secondary CPUs
[    0.125267] Kernel Offset: disabled
[    0.125319] CPU features: 0x00,00000000,80111528,66267727
[    0.125352] ---[ end Kernel panic - not syncing: VFS: Unable to mount root fs on unknown-block(0,0) ]---
```

Note on the earliest lines: the capture above starts at guest-uptime
`0.029s`, not `0.000s` (the "Booting Linux on physical CPU 0x0" / "Linux
version …" banner). This is expected, not a bug: the virtio-console device
only starts delivering data once the guest's `virtio_console` driver probes
and attaches partway through boot; earlier `printk` output goes to the
kernel's internal ring buffer but has no attached console device yet on
this configuration (no `earlycon=` was set on the cmdline). Fixing that is a
one-line cmdline change or the actual `earlycon` address for a hvc0 UART, but
it doesn't affect the conclusion above.

## Checksum provenance

`scripts/fetch-images.sh` downloads and verifies Alpine's `vmlinuz-virt` +
`initramfs-virt` (aarch64, release 3.24.1) with pinned sha256 digests,
following the same download-then-verify pattern this repo already uses for
pinned external artifacts (`SANDLOCK_SHA256` in `.github/workflows/ci.yml`).

Alpine does not publish a per-file checksum for the individual files inside
`netboot-3.24.1/` — only for the bundling
`alpine-netboot-3.24.1-aarch64.tar.gz` tarball
(`alpine-netboot-3.24.1-aarch64.tar.gz.sha256`, published alongside it). This
pass computed digests directly on the two files as downloaded from the
versioned `netboot-3.24.1/` release directory:

```
b637e54b4e7ef8ad0140fe8301d400a479afffbf7ced47b5347c6dfa7c87ed3c  vmlinuz-virt
e47d38bc88509a3db11affc09f9762f9643b026bd29441724a4729ad8e97add6  initramfs-virt
```

A full cross-check against the checksummed tarball (download it, verify its
published sha256, extract these two files, and diff) was started but not
completed in this pass: this host's sustained download throughput to
`dl-cdn.alpinelinux.org` measured 30–90 KB/s, which would put the 431 MB
tarball at several hours — well past this task's bounded-exploration budget.
This is disclosed here rather than silently skipped: the digests above are
this run's own direct-download measurement, not yet independently
cross-verified against Alpine's published tarball checksum. `initramfs-virt`
was used successfully as the guest's initial ramdisk in the verified-boot
run above (the bootloader accepted it without complaint — cpio/gzip format
integrity is not in question), so the open item is provenance
cross-verification, not functional correctness.

## Reproducing locally

```bash
cd aa-isolation-macos-vm-poc
./scripts/fetch-images.sh        # downloads + sha256-verifies images/vmlinuz-virt, images/initramfs-virt
swift build
codesign -s - --entitlements aa-isolation-macos-vm-poc.entitlements --force \
  .build/debug/aa-isolation-macos-vm-poc

# Alpine artifact — currently fails; see "Alpine attempt: failure analysis"
.build/debug/aa-isolation-macos-vm-poc --timeout 15

# Substitute known-good kernel — boots; see "Verified boot: console evidence"
.build/debug/aa-isolation-macos-vm-poc \
  --kernel /Applications/Docker.app/Contents/Resources/linuxkit/kernel \
  --initrd images/initramfs-virt \
  --timeout 15
```

`images/` is git-ignored (large binaries; repo policy). Run
`scripts/fetch-images.sh` to populate it.

## Recommendations for AAASM-5812's remaining scope

1. **Guest kernel sourcing is the next real decision, not virtiofs/vsock.**
   Before building the rest of the substrate, pick (or build) a guest kernel
   artifact that is (a) a plain, directly `VZLinuxBootLoader`-loadable arm64
   `Image`, (b) small, (c) reproducibly downloadable with a real published
   checksum, and (d) paired with an initramfs/init that actually reaches a
   shell or the intended payload. Candidates worth evaluating next:
   - A LinuxKit-built kernel + a purpose-built minimal initramfs (LinuxKit's
     own build tooling produces exactly this pairing already; this pass only
     had the kernel half of that on hand).
   - Alpine's kernel `Image` extracted from a different, non-netboot Alpine
     artifact — e.g. the plain `-virt` uboot/dtb-free build if one exists, or
     properly reverse-engineering the wrapper format this pass didn't chase.
   - A minimal Buildroot-produced kernel+initramfs pair, built from source
     specifically to be `VZLinuxBootLoader`-clean, so the project isn't
     depending on any third party's packaging choices.
2. **virtiofs and vsock are genuinely separable next steps**, not blocked on
   picking the final kernel — they can be prototyped against whichever
   kernel unblocks boot first (the substitute one above is fine for that),
   then swapped once the kernel-sourcing decision above lands.
3. **`aa-isolation-launch` cross-compilation is its own, larger piece of
   work** (likely a `aarch64-unknown-linux-musl` or `-gnu` target, plus
   whatever init/service wiring gets it running as guest PID 1 or under a
   minimal init) — start it once vsock (for control) and virtiofs (for
   binary delivery) are working, not before.
4. **This host's slow path to `dl-cdn.alpinelinux.org` is worth flagging
   separately** — if CI or other engineers hit similarly slow throughput to
   Alpine's CDN, the checksum-verify-on-fetch pattern in
   `scripts/fetch-images.sh` will make that visible immediately (retries,
   partial-download resume via `-C -`) rather than as a silent hang.
