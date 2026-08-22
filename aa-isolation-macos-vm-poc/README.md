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
networking, and running `aa-isolation-launch` inside the guest. This PoC was
built in two bounded increments:

1. **Boot proof** (first pass): can this host actually boot a Linux kernel
   inside a Virtualization.framework VM at all, with real console output
   reaching the host process. See "Result summary" below.
2. **virtiofs + vsock prototype** (this pass, still AAASM-5812): can a
   `VZVirtioFileSystemDevice` share a host directory into the guest, and can
   a `VZVirtioSocketDevice` carry a host↔guest byte stream, against the same
   substitute kernel — with a purpose-built minimal guest-init binary
   (`guest-init/`) so both are checked from *inside* the guest, not just
   host-side config acceptance. See "virtiofs + vsock: result summary"
   below — this is where the pass hit a real, precisely-diagnosed wall.

**What this proves (across both passes):**
- `Virtualization.framework` is usable on this host (Apple Silicon, macOS
  26.4.1) from an ad-hoc-signed, non-App-Store command-line tool carrying only
  the `com.apple.security.virtualization` entitlement — no Developer ID, no
  App Sandbox, no notarization.
- A real Linux/arm64 kernel can be booted under `VZLinuxBootLoader` with a
  `VZVirtioConsoleDeviceSerialPortConfiguration` console, and the guest's
  kernel boot log reaches the host process's stdout / a capture file in real
  time.
- `VZVirtioFileSystemDeviceConfiguration` (a single-directory virtiofs share)
  and `VZVirtioSocketDeviceConfiguration` + `VZVirtioSocketListener` (vsock)
  are accepted by `VZVirtualMachineConfiguration.validate()`, attach without
  error, and the VM reaches `running` state with both devices present, on
  this host, with this entitlement.
- A real, statically-linked aarch64 Linux ELF binary can be cross-compiled
  from this host using **only tools already installed** (rustc's own bundled
  `rust-lld`, no external musl-cross/zig toolchain) — see
  `guest-init/` and `scripts/build-guest-init.sh`.

**What this deliberately does NOT do** (out of scope for this pass — see
AAASM-5813/5814 for where this belongs):
- No NAT / network device configuration.
- No cross-compiling or running `aa-isolation-launch` (or any `aa-*` binary)
  inside the guest.
- No integration with any existing Rust crate, CI workflow, or product code.
  This directory is 100% additive. `guest-init/` is its own standalone Cargo
  workspace (see its `Cargo.toml`), not a member of the outer
  `agent-assembly` workspace.
- **Guest-side virtiofs mount / vsock dial is NOT verified** — see below for
  exactly why, and what the wall is.

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

## virtiofs + vsock: result summary

**Driver support confirmed in the substitute kernel.** Before writing any
guest code, the LinuxKit kernel binary itself
(`/Applications/Docker.app/Contents/Resources/linuxkit/kernel`) was checked
for the relevant driver symbols via `strings`:

```
$ strings kernel | grep -c virtio_fs_     # virtio-fs transport
21
$ strings kernel | grep -c fuse_mount     # FUSE (virtiofs rides on FUSE)
3
$ strings kernel | grep -c vhost_vsock    # host-side vsock transport
13
$ strings kernel | grep -c virtio_vsock   # guest-side vsock transport
9
```

Both are compiled in. This isn't a coincidence: Docker Desktop's own
LinuxKit VM (which this kernel is extracted from — see "Verified boot"
above) uses virtiofs for bind mounts and vsock for its host↔VM control API,
so a kernel build shipped for that purpose was always going to carry both.

**Host-side configuration: proven.** With both a
`VZVirtioFileSystemDeviceConfiguration` (tag `aa-share`, sharing a
freshly-created scratch temp directory containing a `marker.txt`) and a
`VZVirtioSocketDeviceConfiguration` attached to the same
`VZVirtualMachineConfiguration` used for the boot proof:

```
.build/debug/aa-isolation-macos-vm-poc \
  --kernel /Applications/Docker.app/Contents/Resources/linuxkit/kernel \
  --initrd images/guest-initramfs.cpio \
  --cmdline "console=hvc0" --timeout 8
```

```
[poc] virtiofs: created scratch share dir /var/folders/.../aa-isolation-macos-vm-poc-share-5F5888A2-... with marker.txt = virtiofs-marker-4130741A-...
[poc] virtiofs: sharing /var/folders/.../aa-isolation-macos-vm-poc-share-5F5888A2-... as tag 'aa-share'
[poc] vsock: device configured, will listen on guest-dialed port 5555 once VM starts
...
[poc] VZVirtualMachine.start succeeded, state=1
[poc] vsock: host listener registered on port 5555
...
[poc] vsock: connectionAccepted=false roundTripSucceeded=false
```

`config.validate()` accepted both devices, `VZVirtualMachine.start` reached
`running` state with them attached, and `VZVirtioSocketDevice
.setSocketListener(_:forPort:)` succeeded — all real API calls against real
Virtualization.framework objects, not stubs. This is genuine, if partial,
evidence: the substrate-level acceptance of virtiofs and vsock device
configuration is proven on this host.

**Guest-side round trip: NOT achieved — a real, precisely-diagnosed wall,
not a shortcut taken.** The plan was for `guest-init` (below) to mount the
share, echo `marker.txt`'s content to the console, dial vsock, and exchange
bytes with the host listener above. It never got the chance to run: the
guest kernel never reaches userspace at all with this initrd. Console output
ends at the exact same `Kernel panic - not syncing: VFS: Unable to mount
root fs on unknown-block(0,0)` panic already documented in "Verified boot"
above — meaning the kernel is not unpacking the supplied initrd as an
initramfs-rootfs and executing `/init` from it, full stop.

This was diagnosed empirically, not assumed, by varying every axis that
could plausibly explain a `/init`-not-found outcome and observing the
*identical* panic every time:

| Variant tried | Result |
|---|---|
| Our own uncompressed `newc` cpio (verified structurally correct — `070701` magic, `./init` entry present with mode `0100755`, correct file size, valid `TRAILER!!!`) | same panic |
| Same cpio, gzip-compressed | same panic |
| Explicit `rdinit=/init` on the kernel cmdline (rules out a non-default `ramdisk_execute_command`) | same panic |
| Alpine's `initramfs-virt` (original boot-proof run, different cpio entirely) | same panic |

A kernel that successfully unpacks an initramfs and finds `/init` never
reaches `mount_root_generic`/`prepare_namespace` at all — it execs `/init`
directly instead. Reaching that panic regardless of cpio content, compression,
or an explicit `rdinit=` override means `populate_rootfs()` is not running
this kernel's initrd through the initramfs-as-rootfs path — most likely
because this specific LinuxKit build's kernel config doesn't wire that up in
the way that matters here, corroborated by `strings kernel | grep -i
initramfs` returning nothing resembling `init/initramfs.c`'s own log output
(`"Trying to unpack rootfs image as initramfs"` is conspicuously absent),
while `rdinit_setup` / `rdinit=` and old-style-initrd strings (`/initrd.image`)
are present. It's also consistent with this kernel shipping alongside a
558 MB `boot.img` disk file in the same Docker.app directory — this build is
plausibly meant to boot from a virtio-block root disk, not a bootloader-
supplied cpio initrd.

This **confirms, rather than merely repeats**, the original boot-proof's own
tentative read ("this LinuxKit kernel build expects its own virtio-block
root disk... not an ad hoc initramfs") — that was a reasonable guess before;
it is now an empirically cross-checked conclusion. It is squarely the
**kernel-sourcing decision this pass was explicitly told not to resolve**
(see "Scope of this pass"), not a virtiofs/vsock-specific gap — the devices
themselves are proven to attach cleanly; guest code simply never gets to run
against them with this kernel/initrd combination.

### `guest-init`: the guest-side proof that's ready and waiting

`guest-init/` is a minimal PID 1 (raw `libc` syscalls, no shell, no runtime
beyond what mounting virtiofs and dialing vsock need) built specifically to
exercise both checks the moment a working guest kernel/rootfs exists:

- mounts `devtmpfs` at `/dev` and opens `/dev/hvc0` (falling back to
  `/dev/console`) directly by fd, rather than relying on `std::io::stdout`
  wrapping fd 1 — fd 1 isn't attached to anything when the kernel execs
  PID 1 with no `/dev` nodes present yet.
- `mount("aa-share", "/mnt/share", "virtiofs", …)`, then reads and echoes
  `/mnt/share/marker.txt` to the console (`VIRTIOFS-OK` on success).
- opens an `AF_VSOCK` socket, connects to `VMADDR_CID_HOST` (2) on port 5555
  (matching the host's registered listener above), sends a greeting, reads
  the host's reply, and echoes it (`VSOCK-OK` on success).
- parks in an infinite sleep loop (PID 1 must never exit).

It cross-compiles to a real static `aarch64-unknown-linux-musl` ELF
executable **using only tools already on this machine** — no
`musl-cross`/`zig`/other third-party cross-toolchain install was needed or
attempted:

```
cd guest-init
RUSTFLAGS="-C linker-flavor=ld.lld -C linker=rust-lld -C target-feature=+crt-static" \
  cargo build --release --target aarch64-unknown-linux-musl
```

This works because `rustc` ships its own `rust-lld` (a full LLVM linker,
multi-target, ELF-capable) inside its sysroot
(`$(rustc --print sysroot)/lib/rustlib/aarch64-apple-darwin/bin/rust-lld`),
and rustup's `aarch64-unknown-linux-musl` target component bundles a
self-contained musl libc + crt objects — so `cc`/ld64 (which can't link ELF)
never enters the picture. `scripts/build-guest-init.sh` wraps this, then
packs the resulting binary as the sole content of an uncompressed cpio
`newc` initramfs (`images/guest-initramfs.cpio`) — uncompressed specifically
so it doesn't depend on any `CONFIG_RD_*` decompressor, unlike Alpine's
netboot artifact (see "Alpine attempt: failure analysis").

`guest-init` itself is unverified — it never got to run. That is stated
plainly, not implied by silence: nothing between "cross-compiles cleanly"
and "genuinely mounts virtiofs and dials vsock" has been exercised. The
moment AAASM-5812's kernel-sourcing decision lands on something that boots
from a cpio initramfs (or `guest-init` gets adapted into a tiny root
filesystem image for a virtio-block boot instead), this binary is the
existing, ready-to-run artifact for finishing that guest-side proof — not
new work.

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
was accepted by `VZLinuxBootLoader` without complaint at the bootloader
level (no load/decode error) in the verified-boot run above — **correction,
this pass**: that is *not* the same as it having worked as an initramfs
rootfs. The "virtiofs + vsock" section above establishes, by direct
comparison against our own known-good-format cpio, that this kernel never
unpacks *any* supplied initrd as an initramfs-rootfs at all. So
`initramfs-virt`'s cpio/gzip format integrity was never actually exercised
end-to-end either — only that the bootloader could hand the bytes to the
kernel without erroring. The open item is genuinely broader than originally
scoped here: provenance cross-verification, *and* functional correctness is
now known to be blocked on the kernel-sourcing decision, not just unverified.

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

# virtiofs + vsock host-side proof (this pass) — builds guest-init, packs it
# into images/guest-initramfs.cpio, then attaches both devices. Guest-side
# checks never run — see "virtiofs + vsock: result summary" for the wall.
./scripts/build-guest-init.sh
.build/debug/aa-isolation-macos-vm-poc \
  --kernel /Applications/Docker.app/Contents/Resources/linuxkit/kernel \
  --initrd images/guest-initramfs.cpio \
  --timeout 15
# add --share-dir <path> / --share-tag <tag> / --vsock-port <port> to
# override the defaults, or --no-virtiofs / --no-vsock to disable either
# device individually.
```

`images/` is git-ignored (large binaries; repo policy). Run
`scripts/fetch-images.sh` to populate it.

## Recommendations for AAASM-5812's remaining scope

1. **Guest kernel/rootfs sourcing is now confirmed blocking, not just the
   next decision.** This pass's own finding sharpens the requirement beyond
   what the boot-proof pass could tell: it's not enough to find a plain
   `VZLinuxBootLoader`-loadable arm64 `Image` — the artifact must also
   actually **reach and exec `/init` from a bootloader-supplied initrd**
   (or, alternatively, the project commits to a virtio-block root disk
   instead of a cpio initramfs, matching how this substitute kernel's own
   origin — Docker Desktop's LinuxKit VM — actually boots). Verify this
   specific property empirically before adopting any candidate; don't infer
   it from "the kernel boots" alone, which is exactly the gap this pass
   fell into. Candidates worth evaluating next, in light of that:
   - A LinuxKit kernel **built together with** LinuxKit's own minimal
     initramfs via `linuxkit build` (this pass only had the bare kernel
     half on hand, extracted from an unrelated Docker Desktop install) —
     highest chance of an initramfs-compatible config, since it would be
     the pairing LinuxKit's tooling actually produces and tests, rather
     than a kernel half borrowed from a disk-image-booting deployment.
   - Alpine's kernel `Image` extracted from a different, non-netboot Alpine
     artifact — e.g. the plain `-virt` uboot/dtb-free build if one exists, or
     properly reverse-engineering the netboot wrapper format this pass
     didn't chase (see "Alpine attempt: failure analysis").
   - A minimal Buildroot-produced kernel+initramfs pair, built from source
     specifically to be `VZLinuxBootLoader`-clean with `CONFIG_BLK_DEV_INITRD`
     and initramfs-as-rootfs behavior explicitly verified, so the project
     isn't depending on any third party's packaging choices — and gets a
     kernel config it fully controls and can assert this property against.
   - Alternatively: **commit to a virtio-block root disk** (`root=/dev/vda`
     + `VZVirtioBlockDeviceConfiguration`) instead of a cpio initramfs. This
     is real, scoped work (needs an on-macOS ext2/ext4/vfat filesystem
     builder — not currently installed — plus a minimal root filesystem
     layout), not a quick swap, but it sidesteps the initramfs-support
     question entirely and is what this substitute kernel's own origin
     actually does (see the sibling `boot.img` next to it).
2. **virtiofs and vsock device *configuration* are proven separable from
   kernel sourcing** — attaching `VZVirtioFileSystemDeviceConfiguration` and
   `VZVirtioSocketDeviceConfiguration` and reaching `running` state works
   against any kernel that boots this far, independent of what that kernel
   does afterward. **Guest-side verification is not separable** — it needs
   a kernel/rootfs pairing that reaches userspace, i.e. it's gated on
   recommendation 1. `guest-init/` (this pass) is the ready-to-run guest
   binary for finishing that verification the moment recommendation 1 lands
   — no new guest code should be needed, only a working boot target to run
   it against.
3. **`aa-isolation-launch` cross-compilation is its own, larger piece of
   work** (likely a `aarch64-unknown-linux-musl` or `-gnu` target, plus
   whatever init/service wiring gets it running as guest PID 1 or under a
   minimal init) — start it once vsock (for control) and virtiofs (for
   binary delivery) are verified guest-side, not before. This pass's
   `guest-init/` also serves as a working example of cross-compiling a
   static aarch64 Linux binary from this host using only already-installed
   tooling (`rust-lld`, no external cross-toolchain) — the same technique
   applies directly to `aa-isolation-launch` once that work starts.
4. **This host's slow path to `dl-cdn.alpinelinux.org` is worth flagging
   separately** — if CI or other engineers hit similarly slow throughput to
   Alpine's CDN, the checksum-verify-on-fetch pattern in
   `scripts/fetch-images.sh` will make that visible immediately (retries,
   partial-download resume via `-C -`) rather than as a silent hang. This
   pass hit the same class of slow-CDN symptom again fetching the
   `aarch64-unknown-linux-musl` rustup component (~50 KB/s, multiple
   `rustup target add` invocations needed after transient corrupt-cache
   retries) — not unique to Alpine's CDN specifically on this host/network.
