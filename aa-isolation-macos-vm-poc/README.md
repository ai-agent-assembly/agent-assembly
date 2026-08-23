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
2. **virtiofs + vsock prototype** (second pass, still AAASM-5812): can a
   `VZVirtioFileSystemDevice` share a host directory into the guest, and can
   a `VZVirtioSocketDevice` carry a host↔guest byte stream, against the same
   substitute kernel — with a purpose-built minimal guest-init binary
   (`guest-init/`) so both are checked from *inside* the guest, not just
   host-side config acceptance. That pass hit a real, precisely-diagnosed
   wall (cpio-initrd unsupported by the substitute kernel — see "virtiofs +
   vsock: result summary" below) which the third pass resolved.
3. **Kernel/rootfs resolution + full round trip** (third pass, still
   AAASM-5812): switches the substitute kernel to a virtio-block root disk
   instead of a cpio initramfs, which sidesteps the wall from pass 2
   entirely. Result: real guest-side `VIRTIOFS-OK` and `VSOCK-OK`, not just
   host-side config acceptance. See "Kernel/rootfs resolution: full
   guest-side round trip achieved" below.
4. **`aa-isolation-launch` cross-compile + in-guest run** (fourth pass, still
   AAASM-5812): cross-compiles the real, unmodified `aa-isolation-launch`
   binary from `aa-isolation-native` and runs it — for real, inside the guest
   built by pass 3 — against a trivial confined workload. Result: the binary
   builds and runs unmodified, but this specific substitute guest kernel
   lacks Landlock support, so every invocation is honestly refused before
   `execve` — a real, new finding about what the eventual product guest
   kernel needs, not the "prevention" demonstration this pass set out to
   get. See "`aa-isolation-launch` cross-compile: real run, real wall" below.
5. **Acceptance-criteria closure: virtiofs negative control, clean teardown,
   arm64 syscall truthfulness** (this pass, still AAASM-5812): closes three
   AC items that were reachable on the kernel already in hand, without
   needing the Landlock-capable kernel pass 4 found still missing. See
   "AC closure: virtiofs negative control, teardown, syscall truthfulness"
   below.

**What this proves (across all three passes):**
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
- **Guest-side virtiofs mount and vsock dial are both verified** — a real
  guest binary (`guest-init/`), booted from a virtio-block root disk, mounts
  the virtiofs share and reads real content back (`VIRTIOFS-OK`), and
  completes a real two-way vsock byte exchange with the host
  (`VSOCK-OK`, `roundTripSucceeded=true`) — see "Kernel/rootfs resolution"
  below.
- **`aa-isolation-native`'s real `aa-isolation-launch` binary cross-compiles
  and runs, unmodified, inside this guest** — no source change, to
  `aarch64-unknown-linux-musl`, reusing the exact rust-lld cross-linking
  recipe `guest-init/` already established. It executes as PID 1's child,
  parses its real argv grammar, and reaches its real Landlock call — see
  "`aa-isolation-launch` cross-compile: real run, real wall" below for what
  it actually did once it got there.

**What this deliberately does NOT do** (out of scope for this work — see
AAASM-5813/5814 for where it belongs):
- No NAT / network device configuration.
- No integration with any existing Rust crate's *source*, CI workflow, or
  product code — `aa-isolation-native` is built against unmodified, exactly
  as published, and nothing in this directory is wired into the outer
  workspace's own build. `guest-init/` remains its own standalone Cargo
  workspace (see its `Cargo.toml`), not a member of the outer
  `agent-assembly` workspace.
- No kernel that actually has Landlock compiled in — this pass's own finding
  is that the substitute LinuxKit kernel used since pass 1 does not, so no
  successful confined launch was demonstrated this pass (see below). Sourcing
  a Landlock-capable guest kernel is explicitly left to a future pass.

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

## Kernel/rootfs resolution: full guest-side round trip achieved

**This section supersedes the "virtiofs + vsock: result summary" wall above.**
That pass ended with the kernel-sourcing decision confirmed blocking: the
LinuxKit substitute kernel never unpacks any bootloader-supplied cpio initrd.
This pass resolved it — first by chasing recommendation 1's first candidate
(a proper distro kernel with `CONFIG_BLK_DEV_INITRD=y`), which hit a *new*,
more surprising wall, then by taking recommendation 1's explicit alternative
(a virtio-block root disk against the *same, already-proven* LinuxKit
kernel), which worked end to end — real guest-side `VIRTIOFS-OK` and
`VSOCK-OK`, not host-side config acceptance.

### Debian generic kernel: boots, but hangs before any console output — a new wall, not a repeat

Docker Desktop (already on this host — see "Verified boot" above) can pull
and run real `linux/arm64` containers, which made it possible to extract a
real distro-shipped kernel via `apt-get install linux-image-arm64` inside a
pinned `debian:12` container (see `scripts/fetch-debian-kernel.sh`) — no
third-party kernel tarball, just Debian's own package. `file` correctly
identifies it as *"Linux kernel ARM64 boot executable Image"* (unlike
Alpine's netboot wrapper — see "Alpine attempt: failure analysis"), and its
extracted `/boot/config-6.1.0-52-arm64` confirms `CONFIG_BLK_DEV_INITRD=y`,
`CONFIG_RD_GZIP=y` — exactly the property the LinuxKit substitute lacked.

It did **not** work, but not for the reason initially suspected:

- `CONFIG_VIRTIO_MMIO=m` and `CONFIG_VIRTIO_CONSOLE=m` are **loadable
  modules**, not built in — a generic distro kernel supports far more
  hardware than a minimal appliance build, and defers virtio to modules
  loaded by `initramfs-tools`/`udev` in a normal boot. A from-scratch
  `guest-init` has neither. This alone was fixable: the needed `.ko` files
  (`virtio_mmio`, `virtio_console`, `fuse`, `virtiofs`, `vsock`,
  `vmw_vsock_virtio_transport{,_common}` — none with further dependencies,
  confirmed via `modinfo`) were extracted from the same container and
  bundled into the initramfs; `guest-init` was extended with a
  `finit_module(2)`-based loader (`load_module()` in
  `guest-init/src/main.rs`) that inserts them in dependency order before
  attempting to open the console.
- With that in place, boot output was still **exactly 0 bytes** — worse than
  before, since the modules should have made a console available. Bisecting
  by host-side CPU usage (`ps`) rather than console output (there was none to
  read) showed the VM process pinned at **~200% CPU for the full run
  duration, sustained**, regardless of initrd content — reproduced with our
  own module-loading `guest-init` cpio, with Debian's own real
  `initramfs-tools`-generated `initrd.img` (full `udev`+`kmod`, not our
  minimal binary), and with a **structurally empty cpio** (just a
  `TRAILER!!!` entry, no `/init` at all). All three produced the identical
  symptom. Passing `nosmp` dropped CPU usage to ~100% (one active vCPU
  instead of two), confirming each active vCPU individually spins — this is
  a kernel-level busy loop very early in boot, before console/printk output
  of any kind, not an SMP-bringup deadlock or a `guest-init` bug (a genuine
  crash or panic would show near-0% CPU in a `WFI` halt loop instead).
- This means: this specific Debian-packaged kernel build, while a
  format-valid `VZLinuxBootLoader` image, does not successfully complete
  early boot on this specific hypervisor (Virtualization.framework on this
  Apple Silicon host) — a different, more opaque failure mode than either
  Alpine's immediate `SIGTRAP` crash or the LinuxKit substitute's clean
  "no initrd support" panic. No `log show` crash record exists to introspect
  (the process is alive and busy, not crashed), and root-causing a kernel
  spin loop with no console and no crash dump would require a kernel
  debugger/JTAG-class setup — out of this pass's bounded-effort budget. This
  finding is disclosed as a genuine new wall, not glossed over: a distro
  kernel with the right initramfs support on paper still needs its actual
  early-boot compatibility with this exact hypervisor verified empirically,
  which this one failed.
- The extracted kernel, its config, and the `.ko` modules remain useful
  artifacts regardless (see `scripts/fetch-debian-kernel.sh` — pinned by a
  pinned `debian:12` image digest + per-file sha256, same pattern as
  `fetch-images.sh`) in case a future pass wants to retry with a different
  Debian kernel flavor or root cause the spin loop; `guest-init`'s
  `load_module()` support is likewise kept — it is exercised (as a
  fail-fast no-op) by the winning path below too, and would matter again for
  any future kernel that needs loadable virtio drivers.

### virtio-block root disk: full round trip, verified

Recommendation 1's explicit fallback — *"commit to a virtio-block root disk
instead of a cpio initramfs"* — sidesteps the initramfs question entirely
and reuses the **already-proven-booting** LinuxKit substitute kernel instead
of a new, unverified one. Its own embedded kernel config settles the
question directly: the kernel binary carries an IKCONFIG section
(`IKCFG_ST`/`IKCFG_ED` markers, extracted by locating the embedded gzip
stream and decompressing it — the standard technique behind the upstream
`scripts/extract-ikconfig`), and it confirms in one place both *why* the
cpio-initrd path was dead (`CONFIG_BLK_DEV_INITRD` **is not set** — this
kernel genuinely never attempts to unpack any initrd, matching the prior
pass's `strings`-based inference exactly) and that the virtio-block path is
live: `CONFIG_VIRTIO_BLK=y`, `CONFIG_EXT4_FS=y`, and — bonus — `CONFIG_VIRTIO_FS=y`,
`CONFIG_FUSE_FS=y`, `CONFIG_VSOCKETS=y`, `CONFIG_VIRTIO_VSOCKETS=y`,
`CONFIG_VIRTIO_CONSOLE=y`, `CONFIG_VIRTIO_MMIO=y` are **all built in** on
this kernel — no module-loading dance needed at all for this path (the
`.ko` load attempts in `guest-init` fail fast with `ENOENT` and are
harmless, since every driver they'd provide is already compiled in).

What this took, beyond kernel/rootfs sourcing:

1. **A root filesystem image.** `scripts/build-guest-rootfs.sh` builds a
   16 MiB ext4 image containing `guest-init` at `/sbin/init` (plus empty
   `/dev`, `/proc`, `/sys`, `/mnt/share`), using `mke2fs -d <staging-dir>`
   (e2fsprogs, run inside a throwaway `debian:12` container — macOS has no
   native ext4 tooling) to populate the filesystem directly from a host
   directory tree. This avoids needing a privileged loop-mount inside the
   container: `mke2fs -d` populates the image from a plain directory at
   creation time. `e2fsck -fn` confirms the result is structurally clean.
2. **Host-side virtio-block device support**, which did not previously
   exist in this tool. `Sources/aa-isolation-macos-vm-poc/main.swift` gained
   a `--disk <path>` flag (`VZDiskImageStorageDeviceAttachment` +
   `VZVirtioBlockDeviceConfiguration`, added to
   `config.storageDevices`) and a `--no-initrd` flag (the boot loader's
   `initialRamdiskURL` is now only set when an initrd path is supplied) —
   both `--initrd` and `--disk` remain independently usable, matching how
   `VZLinuxBootLoader` treats them as orthogonal.
3. **A real host-side bug, found and fixed by this run.** The first attempt
   reached full guest-side success (`VIRTIOFS-OK`, `guest-init` vsock
   `connect()`/send all succeeded) but the *host* process crashed with an
   uncaught `NSFileHandleOperationException` ("Bad file descriptor") the
   moment the vsock reply's `readabilityHandler` fired. Root cause: the
   listener delegate (`VsockListenerDelegate` in `main.swift`) held the
   derived `FileHandle` but not the `VZVirtioSocketConnection` object
   itself — nothing kept the connection alive, so its fd was torn down
   before the async readability callback ran. Fix: retain
   `connection` in a new `activeConnection` property alongside the
   existing `activeHandle`. One-line root cause, verified by rerunning the
   exact same command after the fix with no other change — the crash
   disappeared and `roundTripSucceeded` flipped to `true`.

Command used (fully reproducible from scripts — no manually-placed files):

```
./scripts/build-guest-init.sh      # unchanged from the prior pass
./scripts/build-guest-rootfs.sh    # new: packs guest-init into a 16M ext4 image
swift build
codesign -s - --entitlements aa-isolation-macos-vm-poc.entitlements --force \
  .build/debug/aa-isolation-macos-vm-poc

.build/debug/aa-isolation-macos-vm-poc \
  --kernel /Applications/Docker.app/Contents/Resources/linuxkit/kernel \
  --no-initrd \
  --disk images/guest-rootfs.img \
  --cmdline "console=hvc0 root=/dev/vda rw rootfstype=ext4 init=/sbin/init" \
  --timeout 15
```

Result — real captured console output, `exit=0`, and (this is the acceptance
bar this whole pass was chasing) `connectionAccepted=true
roundTripSucceeded=true`:

```
[    0.167780] EXT4-fs (vda): mounted filesystem e4006ec6-f766-4faf-a0c7-c4388aa49d03 r/w with ordered data mode. Quota mode: none.
[    0.167834] VFS: Mounted root (ext4 filesystem) on device 254:0.
[    0.168096] devtmpfs: mounted
[    0.168591] Freeing unused kernel memory: 6336K
[    0.168635] Run /sbin/init as init process
[guest-init] GUEST-INIT-START pid1 up, devtmpfs mounted
[guest-init] modprobe: virtio_mmio + virtio_console loaded pre-console
[guest-init] modprobe: open /lib/modules/fuse.ko FAILED errno=2
[guest-init] modprobe: open /lib/modules/virtiofs.ko FAILED errno=2
[guest-init] modprobe: open /lib/modules/vsock.ko FAILED errno=2
[guest-init] modprobe: open /lib/modules/vmw_vsock_virtio_transport_common.ko FAILED errno=2
[guest-init] modprobe: open /lib/modules/vmw_vsock_virtio_transport.ko FAILED errno=2
[guest-init] virtiofs mount OK: tag=aa-share -> /mnt/share
[guest-init] virtiofs marker CONTENT: virtiofs-marker-1BC5D279-C652-4B27-B26E-E7DC20F26EDE
[guest-init] VIRTIOFS-OK
[poc] vsock: incoming connection accepted, guest sourcePort=481206976
[guest-init] vsock connect() OK (cid=2 port=5555)
[guest-init] vsock greeting sent
[poc] vsock: received from guest: hello-from-guest-vsock
[poc] vsock: reply sent to guest
[guest-init] vsock host reply: hello-from-host-vsock
[guest-init] VSOCK-OK
[guest-init] GUEST-INIT-DONE, parking
[poc] timeout reached (15.0s), stopping VM
[poc] ---- end guest console output ----
[poc] vsock: connectionAccepted=true roundTripSucceeded=true
[poc] full console capture written to boot-console.log (17614 bytes)
```

The `modprobe: ... FAILED errno=2` (`ENOENT`) lines are expected and
harmless — `guest-init`'s module loader always tries the Debian-sourced
`.ko` files first (see above), and this rootfs image deliberately does not
bundle them, since every driver this kernel needs is already built in. What
matters is everything after: **real virtiofs content read back from the
host-created marker file, and a real two-way vsock byte exchange**, both
exercised from inside a kernel that booted from cold, entirely from scripted
artifacts, with no manual file placement.

## `aa-isolation-launch` cross-compile: real run, real wall

This section covers AAASM-5812's own acceptance-criteria item this pass was
scoped to: *"`aa-isolation-launch`/`aasm` binaries run inside the guest
unmodified from their existing Linux source."* `aa-isolation-native`'s
source was not touched (verify with `git status` against this pass's diff —
the only files this pass changed are inside `aa-isolation-macos-vm-poc/`:
`guest-init/src/main.rs` and the `scripts/` additions/edits below).

### Cross-compilation: `aarch64-unknown-linux-musl`, first try, no source change

`aa-isolation-native`'s `[[bin]] name = "aa-isolation-launch"` cross-compiled
cleanly to `aarch64-unknown-linux-musl` on the first attempt, reusing
*exactly* `guest-init`'s own cross-linking recipe (`RUSTFLAGS="-C
linker-flavor=ld.lld -C linker=rust-lld -C target-feature=+crt-static"`,
rustc's own bundled `rust-lld`, rustup's self-contained musl sysroot — no
external cross-toolchain):

```
./scripts/build-isolation-launch.sh
```

```
cross-compiling aa-isolation-launch for aarch64-unknown-linux-musl (unmodified source, outer workspace) ...
    Finished `release` profile [optimized] target(s) in 0.12s
found binary: /Users/bryant/.cargo/shared-target/aarch64-unknown-linux-musl/release/aa-isolation-launch
copied to .../aa-isolation-macos-vm-poc/images/aa-isolation-launch-aarch64
```

```
$ file images/aa-isolation-launch-aarch64
images/aa-isolation-launch-aarch64: ELF 64-bit LSB executable, ARM aarch64, version 1 (SYSV), statically linked, stripped
```

Nothing about this needed a workaround: `aa-isolation-native`'s only
platform-specific dependencies are `landlock` (a pure-Rust binding that
issues raw Linux `landlock_*` syscalls directly — no libc-specific ABI
assumption) and `libc` itself, and both are `cfg(target_os = "linux")`
already, so musl's libc is exactly as valid a target as glibc from the
crate's own point of view. **`aarch64-unknown-linux-gnu` was never needed**
— the fallback this pass was briefed with ("try `-gnu` if musl doesn't fit")
does not apply here; musl fit on the first attempt, for the same reason it
already fit `guest-init`.

### Getting a workload to hand it: `busybox` via `fetch-busybox.sh`

The 16 MiB guest rootfs (`build-guest-rootfs.sh`) contained nothing
`aa-isolation-launch` could actually `execve` into — its own doc comment
requires *some* real program at the end of its argv. `scripts/fetch-busybox.sh`
extracts a real, statically-linked (`static-pie`) `aarch64` `busybox` binary
from the official `busybox:musl` Docker Hub image, pinned by digest and
sha256-verified, the same pattern `fetch-debian-kernel.sh` already uses to
pull a real kernel from a container rather than a third-party tarball. It
needs no dynamic linker (`static-pie`, no `PT_INTERP`), so it runs in this
guest's minimal rootfs with nothing else installed.

`build-guest-rootfs.sh` was extended (not replaced) to also stage
`aa-isolation-launch` at `/usr/local/bin/aa-isolation-launch`, `busybox` at
`/usr/local/bin/busybox`, and a small `/etc/testfile` for the filesystem
grant scenario below.

### `guest-init` extended: a positive control, then three real invocations

`guest-init/src/main.rs` gained one new function, `run_child`, called after
the existing `VIRTIOFS-OK`/`VSOCK-OK` checks. It `fork()`s (PID 1 itself
must never exit or exec into anything — the kernel panics on "Attempted to
kill init!" — so only a *child* of PID 1 may safely run a binary that might
successfully `execve` into something else), dupes the child's
stdout/stderr onto the same console fd `guest-init` already writes its own
progress to, `execv`s a given program with a given argv, and reports how
the child exited.

**Every one of the three `aa-isolation-launch` scenarios below turned out
to refuse before `execve` ever runs** (see the Landlock finding two
sections down) — which means, on its own, none of them would have proven
that `busybox`, the rootfs staging, `/etc/testfile`, or `static-pie`
loading on this kernel actually work. A refusal at the same first step
looks identical whether or not the rest of the harness is sound. So
`run_child` was run once more first, as a positive control, with no
`aa-isolation-launch` involved at all — `busybox` executed directly:

```
run_child(console, "busybox-direct (positive control)", "/usr/local/bin/busybox", &["cat", "/etc/testfile"]);
```

```
[guest-init] === busybox-direct (positive control) ===
aa-isolation-launch-guest-rootfs-test-marker
[guest-init] test 'busybox-direct (positive control)' exited status=0
```

This is real, and it is what makes the refusals below meaningful rather
than vacuous: `busybox` is present at the right path, the right
architecture, executable, and its `static-pie` layout loads and runs on
this kernel with no dynamic linker; `/etc/testfile` was staged with the
expected content and is readable; and `run_child`'s
fork/dup2/execv/waitpid harness itself can observe and report a genuine
success, not only a refusal.

With that established, the same harness ran the real `aa-isolation-launch`
binary against three scenarios, to separately exercise the two boundary
domains AAASM-5812/5811 asked about:

1. `no-grants` — `-- /usr/local/bin/busybox true` (no `--fs-read`/`--fs-write`
   at all, no `--syscall-filter`): the plainest possible launch.
2. `fs-read+fs-write` — `--fs-read=/etc --fs-write=/tmp --
   /usr/local/bin/busybox cat /etc/testfile`: exercises the Landlock
   filesystem boundary this backend's `rules::install` installs.
3. `syscall-filter` — `--syscall-filter --syscall-allow=read
   --syscall-allow=write --syscall-allow=close --syscall-allow=exit
   --syscall-allow=exit_group -- /usr/local/bin/busybox true`: exercises the
   seccomp boundary `seccomp::install` installs, which the ticket's own brief
   correctly notes is `cfg(target_arch = "x86_64")`-gated
   (`aa-isolation-native/src/seccomp.rs:468`) and so should truthfully report
   `Unsupported` on this arm64 guest — see what actually happened below.

### Real console output — the control succeeds, all three refuse, honestly, at the same step

```
[guest-init] === busybox-direct (positive control) ===
aa-isolation-launch-guest-rootfs-test-marker
[guest-init] test 'busybox-direct (positive control)' exited status=0
[guest-init] === aa-isolation-launch test: no-grants ===
aa-isolation-launch:refused:the kernel cannot handle the access rights this backend's filesystem claim requires (Landlock ABI v3, Linux 6.2 or newer): fully incompatible access-rights: BitFlags<AccessFs>(0b111111111111111, Execute | WriteFile | ReadFile | ReadDir | RemoveDir | RemoveFile | MakeChar | MakeDir | MakeReg | MakeSock | MakeFifo | MakeBlock | MakeSym | Refer | Truncate)
[guest-init] test 'aa-isolation-launch test: no-grants' exited status=121
[guest-init] === aa-isolation-launch test: fs-read+fs-write ===
aa-isolation-launch:refused:the kernel cannot handle the access rights this backend's filesystem claim requires (Landlock ABI v3, Linux 6.2 or newer): fully incompatible access-rights: BitFlags<AccessFs>(0b111111111111111, Execute | WriteFile | ReadFile | ReadDir | RemoveDir | RemoveFile | MakeChar | MakeDir | MakeReg | MakeSock | MakeFifo | MakeBlock | MakeSym | Refer | Truncate)
[guest-init] test 'aa-isolation-launch test: fs-read+fs-write' exited status=121
[guest-init] === aa-isolation-launch test: syscall-filter ===
aa-isolation-launch:refused:the kernel cannot handle the access rights this backend's filesystem claim requires (Landlock ABI v3, Linux 6.2 or newer): fully incompatible access-rights: BitFlags<AccessFs>(0b111111111111111, Execute | WriteFile | ReadFile | ReadDir | RemoveDir | RemoveFile | MakeChar | MakeDir | MakeReg | MakeSock | MakeFifo | MakeBlock | MakeSym | Refer | Truncate)
[guest-init] test 'aa-isolation-launch test: syscall-filter' exited status=121
```

Full command, fully reproducible from scripts:

```
./scripts/build-isolation-launch.sh
./scripts/fetch-busybox.sh
./scripts/build-guest-init.sh
./scripts/build-guest-rootfs.sh
swift build
codesign -s - --entitlements aa-isolation-macos-vm-poc.entitlements --force \
  .build/debug/aa-isolation-macos-vm-poc

.build/debug/aa-isolation-macos-vm-poc \
  --kernel /Applications/Docker.app/Contents/Resources/linuxkit/kernel \
  --no-initrd \
  --disk images/guest-rootfs.img \
  --cmdline "console=hvc0 root=/dev/vda rw rootfstype=ext4 init=/sbin/init" \
  --timeout 20
```

### Reading this result honestly: the binary ran; the boundary it needs isn't there

**This is a real result, not a null one, and it is not the result this pass
expected to get.** `exit=0` on the VM process; 275 lines of real captured
console output; `VIRTIOFS-OK` and `VSOCK-OK` both still fire exactly as pass
3 established; the `busybox-direct` positive control exits `status=0` and
echoes the real testfile content back, so the refusals that follow are not
an artifact of a broken harness; and then all three `aa-isolation-launch`
invocations reach real code inside the real binary — argv parsing succeeds,
`rules::plan` runs, and `rules::install` makes a real
`landlock_create_ruleset` call against this guest kernel — and every one is
refused **at the same first step**, before ever reaching the syscall filter
or `execve`.

Why: `aa-isolation-native/src/rules.rs`'s `install()` calls
`Ruleset::default().set_compatibility(CompatLevel::HardRequirement)
.handle_access(...)` **unconditionally**, before it ever looks at whether
the plan's rule list is empty — a design AAASM-5801/5802 chose deliberately,
so a kernel too old to enforce the exact boundary requested fails loudly
rather than installing a silently weaker one (see that function's own doc
comment, "Why this refuses instead of degrading"). Checking this substitute
LinuxKit kernel's own embedded config (same `IKCONFIG` extraction technique
pass 3 already used to find `CONFIG_VIRTIO_BLK=y`) confirms why:

```
$ python3 - <<'EOF'
... (extract IKCFG_ST..IKCFG_ED, gunzip, grep)
EOF
# CONFIG_SECURITY_LANDLOCK is not set
CONFIG_SECCOMP=y
CONFIG_SECCOMP_FILTER=y
```

**Landlock is not compiled into this kernel at all.** `CONFIG_SECCOMP` is —
but it never matters here, because `confine_and_exec`
(`src/bin/aa-isolation-launch.rs`) calls `rules::install` (Landlock) as its
unconditional first step and only reaches the syscall filter afterward, so a
kernel missing Landlock refuses before the seccomp arch-gate is ever
exercised — even for the `syscall-filter` scenario, which asked for no
filesystem grant at all. **The ticket brief's own prediction — that
`Syscall` would truthfully report `Unsupported` due to the x86_64 arch gate
while filesystem enforcement succeeded — was not what this kernel let us
observe**: this kernel can't even reach that gate, because it fails one step
earlier, on a dependency the arch gate has nothing to do with. That
prediction may still hold on a kernel that *does* carry Landlock; this pass
did not have one available to check it against.

**This is still exactly the behavior Core ADR 035 requires, and it is real
evidence of it**: `aa-isolation-launch` did not silently execute `busybox`
unconfined when it could not establish the requested boundary. It refused,
wrote the honest `FAILURE_MARKER` reason to the console (which a real
supervisor would parse and surface, not paper over), and exited `121` —
*every single time*, including the `no-grants` case where nothing was even
asked for, because Landlock's own kernel-support check happens before this
backend looks at whether any rule needs it. Fail-closed, not fail-open, is
the property this binary is *for*, and this run demonstrates it under real
conditions — a kernel missing a facility it depends on — not a synthetic
one.

**What this pass does NOT get to claim**: a successful confined `busybox`
execution, or a `ControlState::Prevention`-vs-`ControlState::Unsupported`
comparison between the filesystem and syscall domains on this guest. Both
need a guest kernel with `CONFIG_SECURITY_LANDLOCK=y`, which neither
substitute kernel evaluated across all four passes has had: the LinuxKit
kernel used since pass 1 (confirmed above, doesn't have it) and the Debian
generic kernel fetched in pass 3 (which independently doesn't boot to any
observable state on this hypervisor at all — see "Debian generic kernel"
above, a wall unrelated to Landlock). **Neither of those is a claim that
Landlock enforcement doesn't work** — `aa-isolation-native`'s own test suite
already exercises it on real Linux — only that this PoC's specific substitute
guest kernel choice has never yet been one that carries it, which is new
information this pass surfaced, not something passes 1–3 could have known
before a real binary was run against it.

**On the `IsolationReport` machine-readable format**: worth stating plainly
rather than silently working around. `aa-isolation-launch` itself is a
narrow, unmodified exec wrapper — it prints nothing on success (it
`execve`s and vanishes into the confined program) and one `FAILURE_MARKER`
line on refusal (see above). The structured `IsolationReport`
(`aa-isolation/src/report.rs`, `REPORT_SCHEMA = "aasm.isolation.report/1"`)
that projects `ControlState`/`ClaimTerm` per `CapabilityDomain` is built and
rendered by the **supervisor** (`aa-cli`'s `aasm run`, via
`aa-isolation-native`'s `probe.rs`/`backend.rs`), not by the launcher binary
this pass cross-compiled and ran — the launcher is what the supervisor's
report describes, not what emits it. Reproducing an actual `IsolationReport`
inside this guest would mean cross-compiling and running `aa-cli`'s
supervisor path too, which is new scope beyond this pass's target binary and
was not attempted. The console output above is the launcher's own, real,
unmodified machine-readable-enough signal (`FAILURE_MARKER` prefix + exit
`121`) — not a fabricated stand-in for the CLI's report format, and not the
report format itself.

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
(This blockage is resolved by the virtio-block root disk path below, which
does not use `initramfs-virt` at all.)

`scripts/fetch-debian-kernel.sh` (this pass) extracts a Debian arm64
`linux-image-arm64` kernel + a handful of its kernel modules via a pinned
`debian:12` container digest, verifying each extracted file's sha256 —
same pattern. See "Debian generic kernel" above for why this kernel is not
currently used (it boots per `VZLinuxBootLoader` but hangs before reaching
any observable state on this hypervisor) — the script and its pinned
digests are kept for reproducibility of that finding, not because the
kernel is in active use.

`images/guest-rootfs.img` (built by `scripts/build-guest-rootfs.sh`, pass 3,
extended pass 4) is not a downloaded artifact — it is assembled locally from
`guest-init`'s own build output, which is itself built from source in this
repo. No external checksum applies; the script itself is the reproducible
source of truth, and `e2fsck -fn` is run on every build as a structural
sanity check.

`scripts/fetch-busybox.sh` (pass 4) extracts a real, statically-linked
`aarch64` `busybox` from the official `busybox:musl` Docker Hub image,
pinned by digest (`busybox@sha256:32b5cdad7cce41dfd53d0ae06baebcf8357a147ee7694dc706911c373bc30c37`)
and sha256-verified per extracted file — same pattern as
`fetch-debian-kernel.sh`.

`images/aa-isolation-launch-aarch64` (built by
`scripts/build-isolation-launch.sh`, pass 4) is, like `guest-rootfs.img`,
not a downloaded artifact — it is `aa-isolation-native`'s own real
`[[bin]] name = "aa-isolation-launch"`, built unmodified from source
already in this repo (`../aa-isolation-native/src/bin/aa-isolation-launch.rs`)
by the outer workspace's own `cargo build`, cross-compiled to
`aarch64-unknown-linux-musl`. No external checksum applies; the crate's
source and `Cargo.lock` are the reproducible source of truth, verified the
same way any other workspace build is.

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

# virtiofs + vsock via cpio initrd (prior pass) — the LinuxKit kernel never
# unpacks this initrd, so guest-side checks never run. Kept as a negative
# control / historical reference; see "virtiofs + vsock: result summary".
./scripts/build-guest-init.sh
.build/debug/aa-isolation-macos-vm-poc \
  --kernel /Applications/Docker.app/Contents/Resources/linuxkit/kernel \
  --initrd images/guest-initramfs.cpio \
  --timeout 15

# virtiofs + vsock via virtio-block root disk (pass 3) — FULL guest-side
# round trip: VIRTIOFS-OK, VSOCK-OK, connectionAccepted=true
# roundTripSucceeded=true. See "Kernel/rootfs resolution" above.
#
# build-guest-rootfs.sh now (pass 4) also requires aa-isolation-launch and
# busybox to be present — see build-isolation-launch.sh/fetch-busybox.sh
# just below — so this block alone no longer runs standalone; it is kept
# here for the pass-3 command shape, but needs those two artifacts staged
# first, same as the pass-4 block that follows it.
./scripts/build-guest-init.sh
./scripts/build-isolation-launch.sh
./scripts/fetch-busybox.sh
./scripts/build-guest-rootfs.sh
.build/debug/aa-isolation-macos-vm-poc \
  --kernel /Applications/Docker.app/Contents/Resources/linuxkit/kernel \
  --no-initrd \
  --disk images/guest-rootfs.img \
  --cmdline "console=hvc0 root=/dev/vda rw rootfstype=ext4 init=/sbin/init" \
  --timeout 15
# add --share-dir <path> / --share-tag <tag> / --vsock-port <port> to
# override the defaults, or --no-virtiofs / --no-vsock to disable either
# device individually.

# Debian generic kernel (prior pass) — extracts a real distro kernel with
# CONFIG_BLK_DEV_INITRD=y, but hangs before any console output on this
# hypervisor. Kept for reproducing that finding; see "Debian generic kernel"
# above. Not a working path.
./scripts/fetch-debian-kernel.sh

# aa-isolation-launch cross-compile + in-guest run (this pass) — cross-
# compiles the real, unmodified aa-isolation-launch binary, bakes it (plus a
# real busybox workload) into the rootfs, and runs three real invocations
# from inside the guest. Every one is honestly refused because this
# substitute guest kernel lacks Landlock — see "aa-isolation-launch
# cross-compile: real run, real wall" above for the full console output and
# why.
./scripts/build-isolation-launch.sh
./scripts/fetch-busybox.sh
./scripts/build-guest-init.sh
./scripts/build-guest-rootfs.sh
.build/debug/aa-isolation-macos-vm-poc \
  --kernel /Applications/Docker.app/Contents/Resources/linuxkit/kernel \
  --no-initrd \
  --disk images/guest-rootfs.img \
  --cmdline "console=hvc0 root=/dev/vda rw rootfstype=ext4 init=/sbin/init" \
  --timeout 20
```

`images/` is git-ignored (large binaries; repo policy). Run
`scripts/fetch-images.sh` / `scripts/fetch-debian-kernel.sh` /
`scripts/build-guest-rootfs.sh` / `scripts/build-isolation-launch.sh` /
`scripts/fetch-busybox.sh` to populate the artifacts each command above
needs.

## AC closure: virtiofs negative control, teardown, syscall truthfulness

Pass 4 left AAASM-5812's own six acceptance-criteria checkboxes with three
still unverified — and, on inspection, none of the three needed the
Landlock-capable kernel pass 4 found missing. This pass closes all three on
the kernel already in hand.

### 1. virtiofs negative control — "a path outside it is verified unreachable"

The AC's own wording is specific: unreachable must mean **"structurally
absent, not merely policy-denied."** `VIRTIOFS-OK` (present since pass 2)
only proves the positive half — that the exported directory *is* reachable.
This pass adds the negative half.

**First cut of this control was broken and got caught in review before
release, not after** — worth stating plainly rather than quietly fixing.
`main.swift` placed a marker file one directory level **above** the
exported scratch directory, and `guest-init` probed for it via a `..`
traversal off the mountpoint (`/mnt/share/../outside-marker-probe.txt`).
That probe cannot fail: `..` at a virtiofs mount root re-enters the guest's
own rootfs and never reaches the host at all, so `open()` reports `ENOENT`
unconditionally — the same result whether the export is scoped correctly or
not. Applying "what edit makes this false?" to it finds nothing: no
misconfiguration of the virtiofs export changes the outcome, which is
exactly the tautology this session's own testing discipline exists to
catch. It was never run against a deliberately-misconfigured export to
check it could actually fail.

The corrected version: `main.swift` places the marker at a **fixed** name
(`outside-marker.txt`, distinct content via a UUID, not via the filename)
one level above the scratch directory, and `guest-init`
(`try_virtiofs_negative_control`) checks for that fixed name **inside** the
mount (`/mnt/share/outside-marker.txt`) — not via traversal. This has a real
failure mode: if the export were ever misconfigured to include the shared
directory's *parent* rather than the directory itself, this exact in-mount
path resolves and `open()` succeeds.

Real run, corrected version, correctly-scoped export:

```
[guest-init] virtiofs negative control: open(/mnt/share/outside-marker.txt) FAILED errno=2 (ENOENT)
[guest-init] VIRTIOFS-NEGATIVE-CONTROL-OK
```

**And the falsifiability check itself, run once against a deliberately
misconfigured export** (`--share-dir` pointed at the marker's own parent
directory instead of the scratch directory) to prove the probe can actually
fail:

```
[poc] virtiofs: sharing /var/folders/.../T as tag 'aa-share'
[guest-init] VIRTIOFS-NEGATIVE-CONTROL-FAILED: /mnt/share/outside-marker.txt opened successfully
```

Same probe, same code, a genuinely different outcome depending on how the
export is scoped — the signature of a control that means something, not a
tautology. `ENOENT` in the correctly-scoped run is the claim the AC asks
for: the path does not exist in the guest's mount namespace past the export
root at all — rather than existing-but-permission-denied, which would be a
policy claim, not a structural one.

This alone doesn't rule out a wrongly-scoped export in some *other*
direction (an `ENOENT` on the *wrong* path proves nothing), so it's paired
with an authoritative enumeration of what's actually mounted:

```
[guest-init] === proc-mounts (virtiofs scope evidence) ===
/dev/root / ext4 rw,relatime 0 0
devtmpfs /dev devtmpfs rw,relatime,size=364948k,nr_inodes=91237,mode=755 0 0
aa-share /mnt/share virtiofs rw,relatime 0 0
proc /proc proc rw,relatime 0 0
```

Exactly one virtiofs mount, at `/mnt/share`, tag `aa-share` — matching the
one tag `main.swift` configures via `VZVirtioFileSystemDeviceConfiguration`.
No second share, no broader host path, nothing else mounted that could carry
host filesystem access. `guest-init` mounts `procfs` for this (`mkdir_p("/proc")`
+ `mount("proc", "/proc", "proc")`) — nothing before this pass needed it.

### 2. Clean teardown — "no orphaned process, no leaked host resources"

Sampled the host process list for `aa-isolation-macos-vm-poc` before
starting the VM (empty — no baseline noise), then twice after the
`--timeout 20` exit path completed (the exit path every pass has used), 2s
and 5s apart, per this session's own "one `ps` sample ≠ job gone" standard:

```
$ ps aux | grep "aa-isolation-macos-vm-poc" | grep -v grep
match_count=0        # both samples, 2s and 5s post-exit
```

Zero matches in both samples. The host helper process (and the guest VM it
owned) is gone, not merely exited-but-zombied or still tearing down. (A
pre-existing, unrelated `com.docker.virtualization` process was visible in
the same `ps aux` output — Docker Desktop's own long-running VM, running
since before this session — and is not this PoC's process; excluded by
grepping on this binary's own name rather than on `linuxkit`, which matches
Docker's cmdline args too.)

### 3. arm64 syscall-filter truthfulness — "no silent overclaim"

This one needed no VM run at all — a code read of `aa-isolation-native`
itself. `host::measure_syscall_filter()` gates on
`!cfg!(target_arch = "x86_64")` and returns
`SyscallFilterSupport::WrongArchitecture` on any non-x86_64 host, including
the `aarch64` this guest runs. `capability::syscall()` checks
`facts.syscall_filter().is_available()` before doing anything else, and on
`WrongArchitecture` returns `SupportLevel::Unsupported { reason: "this
backend's syscall filter is built for Linux on x86_64; this host measured
{arch}" }` — never `Available`, never `Partial`. This is exactly the code
path pass 4's `syscall-filter` scenario would hit at `confine_and_exec`
step 4 (`syscall::install`, itself `cfg(target_arch = "x86_64")`-gated) if
step 3 (Landlock) weren't refusing first on this kernel — the capability
report and the actual enforcement gate agree, and both refuse honestly on
arm64. `aa-isolation-native`'s own test suite already asserts this exact
mapping synthetically
(`a_host_without_syscall_filter_support_is_unsupported_and_says_why`, which
injects `WrongArchitecture { arch: "linux/aarch64" }` and asserts the report
names it and cannot claim prevention) — this pass corroborates that the real
`measure_syscall_filter()` on real aarch64 hardware produces the same input
that test simulates, closing the gap between "the logic is right" and "the
logic runs on what real aarch64 measures."

**Not covered by this pass**: a live in-guest run of the capability report
itself (as opposed to reading the code that produces it) would need the
`aasm` binary cross-compiled into the guest too — `aa-isolation-launch`
alone has no report-only mode. Scope's own wording covers both
`aa-isolation-launch`/`aasm` for linux/arm64 **and** linux/x86_64; this pass
and pass 4 together have done `aa-isolation-launch`/arm64 only. Whether
`aasm` and the x86_64 target belong in this ticket or split into a follow-up
is an open call for whoever picks up AAASM-5812's remaining scope next — not
decided by this pass.

## Recommendations for AAASM-5812's remaining scope

1. **The kernel/rootfs blocker is resolved for this PoC's purposes** — see
   "Kernel/rootfs resolution" above. The working combination is: the
   existing LinuxKit substitute kernel (already proven booting since pass 1)
   + a virtio-block root disk (`VZVirtioBlockDeviceConfiguration` +
   `root=/dev/vda rw rootfstype=ext4`) instead of a cpio initramfs, with the
   root filesystem built by `scripts/build-guest-rootfs.sh`. This is a real
   decision, not just a PoC convenience — carrying it into product code
   means: (a) the eventual product build needs an ext4-image-building step
   analogous to `build-guest-rootfs.sh` (or a different fs the chosen
   product kernel supports built-in — re-verify via the same
   IKCONFIG-extraction technique used here, don't assume), and (b) whatever
   kernel ships in the product must be re-verified against this same
   acceptance bar (`VIRTIOFS-OK` + `VSOCK-OK` from a real guest binary, not
   "the bootloader accepted the file") if it differs from this substitute
   LinuxKit build — this pass's own history is a live example of why: two
   kernels that both satisfied "boots under `VZLinuxBootLoader`" turned out
   to have materially different behavior past that point (the Debian kernel
   hung before any console output; the LinuxKit kernel needed a disk, not
   an initrd). "Boots" is not a sufficient acceptance test on its own.
   Remaining open sub-question, deliberately not chased further this pass:
   *why* the Debian generic kernel hangs on this hypervisor (see "Debian
   generic kernel" above) — worth root-causing later only if the product
   ends up wanting a general-purpose distro kernel specifically (e.g. for
   package-manager convenience) rather than a minimal appliance-style build,
   since the working LinuxKit-kernel path has no forcing need to explain it.
2. **virtiofs and vsock are now verified guest-side, not just host-side
   config acceptance** — `VIRTIOFS-OK` (real content read back through the
   mount) and `VSOCK-OK` (real two-way byte exchange) both came from
   `guest-init` actually running inside the guest kernel, reproducibly, via
   scripted artifacts only. The host-side `NSFileHandleOperationException`
   bug this pass found and fixed (see "virtio-block root disk" above —
   `VsockListenerDelegate` not retaining `VZVirtioSocketConnection`) would
   have silently crashed the host process on this exact interaction pattern
   the first time any consumer relied on a full round trip, not just
   `connectionAccepted` — worth carrying the fix's rationale forward into
   any future rewrite of this listener code path.
3. **`aa-isolation-launch` cross-compilation and in-guest execution are now
   done, not just unblocked** — see "`aa-isolation-launch` cross-compile:
   real run, real wall" above. `aarch64-unknown-linux-musl` was the right
   target on the first try (no `-gnu` fallback needed: the crate's only
   platform dependencies, `landlock` and `libc`, carry no glibc-specific
   requirement), and the real, unmodified binary runs as a child of
   `guest-init`'s PID 1 today, reproducibly, via `scripts/build-isolation-launch.sh`.
   **What is not done**: a demonstration of it actually confining and
   executing something, because this pass's own finding is that the
   substitute LinuxKit kernel used since pass 1 has `CONFIG_SECURITY_LANDLOCK`
   unset, so `rules::install`'s Landlock call — which runs unconditionally,
   before any grant or syscall filter is even considered — refuses every
   invocation before `execve`. **This is now a concrete, added requirement
   for whatever kernel the product eventually ships**, on top of the
   virtio-block/virtiofs/vsock-built-in bar pass 3 already established: it
   must also carry `CONFIG_SECURITY_LANDLOCK=y`, and that must be
   re-verified the same way this pass verified its absence (the IKCONFIG
   extraction technique, or — more conclusively — an actual successful
   `aa-isolation-launch` run against it) rather than assumed. The already-
   fetched Debian generic kernel is not a shortcut here even if it turns out
   to carry Landlock: it independently hangs before any console output on
   this hypervisor (see "Debian generic kernel" above), a wall this pass did
   not re-attempt to solve. Finding or building a *third* kernel candidate —
   one that is both bootable on this hypervisor via virtio-block *and*
   Landlock-capable — is squarely a next-pass task, not a small addition to
   this one. **The three scenarios this pass already wired into `guest-init`
   do not all mean the same thing once a Landlock-capable kernel exists** —
   worth splitting out precisely rather than leaving as an implied "just
   rerun them and they'll separate as predicted":
   - `no-grants` and `fs-read+fs-write` would both still reach `execvp` and
     fail *there*, not at `rules::install`. Landlock's `Execute` right is
     part of `AccessFs::from_all`, which `rules::install` always requests as
     a *handled* right (see "Reading this result honestly" above), so once
     any grant is installed the kernel denies execution of any path not
     explicitly granted — including the confined program's own binary.
     Neither scenario grants read/execute on `/usr/local/bin`, where
     `busybox` lives: `no-grants` requests no filesystem rule at all, and
     `fs-read+fs-write` grants only `/etc` (for `/etc/testfile`) and `/tmp`,
     not the program path. So on a Landlock-capable kernel both are expected
     to move one step further than they do on this kernel — reaching
     `execvp` — and then fail there with `EACCES`, still short of a
     *successful* confined launch. A scenario that can actually reach and
     execute `busybox` needs a grant covering the program's own path too,
     e.g. `--fs-read=/etc --fs-read=/usr/local/bin --fs-write=/tmp`.
   - `syscall-filter` is different, and needs no parameterization change at
     all: `confine_and_exec` installs Landlock first (step 3) and the
     syscall filter second (step 4), and `syscall::install` is the function
     that is `cfg(target_arch = "x86_64")`-gated. On a Landlock-capable
     arm64 kernel this scenario would pass step 3 (its grant set is empty
     but valid) and then refuse at step 4 with the arch-gate message —
     *never reaching* `execvp` at all, unlike the other two. That is exactly
     the `Syscall`-domain claim the ticket brief originally predicted, and
     it is ready to observe as-is, distinguishable from the other two
     scenarios' eventual `EACCES`-at-`execvp` refusal by the `FAILURE_MARKER`
     text alone — it was simply never reachable on *this* kernel, because
     step 3 refuses first, every time, regardless of what step 4 would have
     done. None of this is `IsolationReport` vocabulary — as established
     above, the launcher itself never produces that; it is the launcher's
     own `FAILURE_MARKER`/exit-code signal, in its own terms.
4. **The natural shape for a real integration, once a Landlock-capable
   kernel exists**: replace `guest-init`'s hand-rolled virtiofs/vsock checks
   with `aa-isolation-launch` itself as the thing being driven, dial vsock
   for control instead of a fixed greeting, and use virtiofs for delivering
   the binary/config into the guest rather than baking it into the rootfs
   image at build time (baking it in, as `build-guest-rootfs.sh` now does for
   both `guest-init` and `aa-isolation-launch`, doesn't scale to iterating on
   either without a full image rebuild each time).
5. **NAT / network device configuration remains fully out of scope** — no
   network device was configured or attempted in any of the four passes.
   This is the other major piece of AAASM-5812's acceptance criteria still
   untouched.
6. **This host's slow path to `dl-cdn.alpinelinux.org` (noted in an earlier
   pass) no longer blocks anything** — the working path no longer depends
   on any Alpine artifact. `scripts/fetch-images.sh` and the Alpine
   provenance discussion above are kept for historical/negative-control
   value (see "Alpine attempt: failure analysis"), not because anything
   downstream still needs them.
7. **Taken together, passes 1–4 demonstrate the full technical mechanism
   AAASM-5813 needs to wire into `aasm run` as a real macOS backend** —
   Virtualization.framework boots a real kernel with a live console (pass 1),
   virtiofs and vsock devices attach and carry real guest-side traffic (passes
   2–3), and the real, unmodified `aa-isolation-launch` binary cross-compiles
   and runs as a guest process reachable the same way a product supervisor
   would reach it (this pass) — **provided** the guest kernel AAASM-5813
   actually ships also carries `CONFIG_SECURITY_LANDLOCK=y`, which is now a
   named, checked-for requirement rather than an unstated assumption. Say
   this plainly rather than either overclaiming or underclaiming it: the
   *mechanism* is proven end to end; the specific substitute kernel used to
   prove it is demonstrably not yet the one the product should ship, on this
   one axis. AAASM-5813 should treat "does the chosen guest kernel have
   Landlock" as an explicit go/no-go check before any other integration work,
   not something discovered downstream the way this pass discovered it.
8. **Five of AAASM-5812's six AC checkboxes are closed with real evidence,
   not just the mechanism they depend on** — corrected here after an earlier
   version of this item understated it (virtiofs and vsock had already been
   real, guest-side-verified since passes 2–3; this pass's own contribution
   was only the *negative*-control half of the virtiofs AC and the teardown
   + syscall-truthfulness ACs). Full ledger:
   - AC 1 (host boots a real guest VM): closed, pass 1.
   - AC 2 (virtiofs scoped + outside path verified unreachable): closed —
     positive half since pass 2, negative half this pass (see "AC closure"
     above; its first cut was tautological, caught in review and fixed —
     see that section's own correction).
   - AC 3 (vsock round-trip): closed, pass 3.
   - AC 4 (`aa-isolation-launch`/`aasm` run inside the guest unmodified):
     **partially closed** — see item 9 below.
   - AC 5 (arm64 syscall-filter capability report truthful): closed, pass 5
     — already correct in shipped `aa-isolation-native` code; this pass's
     contribution was verifying the real aarch64 input on real hardware,
     not fixing anything.
   - AC 6 (clean teardown): closed, pass 5.

## `aa-isolation-launch` / `aasm` x86_64 cross-compile: real build, hard architectural ceiling

This pass (sixth) closes the build half of AC 4's other target — `aa-cli`
(`aasm`) and `aa-isolation-native`'s `aa-isolation-launch`, both cross-compiled
to `x86_64-unknown-linux-musl`, unmodified — and states plainly what it cannot
close on this hardware.

### What blocked it, and what didn't

`aa-isolation-launch`/arm64 (pass 4) cross-compiled with `rustc`'s own bundled
`rust-lld` alone — no external toolchain. `aasm` (`aa-cli`) needed two more
things `aa-isolation-launch` never touches:

1. **A C cross-compiler.** `aa-cli`'s dependency tree pulls in `aws-lc-sys`
   (TLS backend, reached through `aa-gateway`/`aa-devtool`'s network clients),
   which needs a real `aarch64`-hosted `x86_64-linux-musl-gcc`, not just a
   Rust linker. Sourced from `messense/macos-cross-toolchains` (GCC 15.2.0,
   prebuilt, version-pinned, per-arch `sha256`-verified — reviewed before
   installing: 14-year-old maintainer account, 1,205★/77 forks, active,
   pinned artifact checksums, no material supply-chain concern found).
2. **AAASM-5834** (see above) — without it, cross-compiling `aa-cli` (which
   pulls `aa-runtime` → `aa-ebpf`) from this macOS host to *any* Linux target
   failed outright, not just slowly: `aa-ebpf/build.rs`'s Linux-only gate
   checked the wrong OS (host, not target) and never even reached its own
   documented stub fallback. Fixed there, not worked around here.

Neither installing `bpf-linker` nor any other BPF toolchain was needed —
AAASM-5834's fix routes cross-compilation through the *existing* graceful
stub-fallback path, the same one this crate already uses when the nightly
toolchain is simply absent.

### Real artifacts, real provenance

```
$ file .../x86_64-unknown-linux-musl/release/aasm
ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), static-pie linked, stripped
$ shasum -a 256 .../x86_64-unknown-linux-musl/release/aasm
a900874f80f424e916afeab242ac5940c73fc5fb1f7da135e832c0c0a3bf060  aasm

$ file .../x86_64-unknown-linux-musl/release/aa-isolation-launch
ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), static-pie linked, stripped
$ shasum -a 256 .../x86_64-unknown-linux-musl/release/aa-isolation-launch
7828061edbc2de0fd2336d869b25b18f486b002fa8789c6c57ffc4b692e485f  aa-isolation-launch
```

Toolchain provenance: `x86_64-linux-musl-gcc (GCC) 15.2.0` (messense/macos-
cross-toolchains v15.2.0, `sha256` pinned in the formula, installed via
formula-scoped `brew trust` — not tap-wide); `rustc 1.98.0 (88d9e12ae
2026-08-18)`, host `aarch64-apple-darwin`, target `x86_64-unknown-linux-musl`.
Both binaries statically linked (`static-pie`, no dynamic dependencies to
resolve at runtime) — the same load-bearing property that made
`aa-isolation-launch`/arm64 runnable in a minimal guest rootfs with no
dynamic linker.

### What this does *not* close, and why no amount of toolchain work would

**AC 4's "runs inside the guest" half cannot be demonstrated for x86_64 on
this hardware, full stop — not a resource gap, an architectural one.**
Virtualization.framework sits on `Hypervisor.framework`, which virtualizes
using the **host CPU's own instruction set**: an Apple Silicon host's
hypervisor extensions (ARM EL2) can create only ARM64 vCPUs, the same way an
Intel host's (VT-x) can create only x86_64 vCPUs. There is no cross-ISA guest
boot path through this framework on either host type — this is not
"Intel hardware happened to be unavailable this session" (the same class of
gap as AC 1's Apple-Silicon-only real-hardware coverage), it is "no Apple
Silicon Mac, regardless of tooling, can ever boot an x86_64 guest this way."
The correct mental model, stated explicitly because an earlier draft of this
document implied otherwise by omission:

* **Apple Silicon host → arm64 Linux guest → arm64 `aasm`/`aa-isolation-launch`**
  — the path this PoC has exercised in passes 1–5, on real hardware.
* **Intel Mac host → x86_64 Linux guest → x86_64 `aasm`/`aa-isolation-launch`**
  — architecturally real (AAASM-5811's own Compatibility section targets
  "Intel and Apple Silicon"), but genuinely unexercised: this pass produces
  real, correct x86_64 artifacts, and that is *all* it produces. No x86_64
  guest was booted, no x86_64 in-guest execution was attempted, on this
  Apple Silicon machine — attempting one would not have failed informatively,
  it would not have started at all.

So: **build support** for x86_64 is real and now demonstrated (this pass).
**Real-hardware-verified** in-guest execution for x86_64 remains genuinely
open, and closing it needs an actual Intel Mac, not further work here. Do not
read this pass as having verified x86_64 end-to-end — it has verified exactly
the artifact-production half, honestly, and no further.
