//! Build script for aa-ebpf.
//!
//! Compiles the `aa-ebpf-probes` BPF crate (targeting `bpfel-unknown-none`)
//! and places the compiled binaries into `OUT_DIR/aa-ebpf-probes/…` so they
//! can be embedded with `aya::include_bytes_aligned!` in the userspace crate.
//!
//! ## Why not `aya_build::build_ebpf`?
//!
//! `aya_build` 0.1.3 runs `cargo build --package <name>` from the *caller's*
//! working directory — it does not use `Package::root_dir` as `current_dir`.
//! `aa-ebpf-probes` is a standalone workspace so cargo cannot resolve it as a
//! package from `aa-ebpf/`.  We invoke cargo directly with an explicit
//! `current_dir` to avoid this limitation.
//!
//! ## Source location: sibling vs `_embedded/`
//!
//! AAASM-2340: there are two possible source locations for the probes.
//!
//! * **`../aa-ebpf-probes/` (sibling)** — present in a workspace checkout.
//!   In this case the probes' inner Cargo.toml carries
//!   `aa-ebpf-common = { path = "../aa-ebpf-common" }`, which resolves to
//!   the sibling workspace crate. This is the dev / CI path.
//!
//! * **`aa-ebpf/_embedded/aa-ebpf-probes/` (bundled)** — present when
//!   built from a crates.io-published tarball. The bundled copy is
//!   staged by `.ci/stage-embedded-for-publish.sh` *before* publish;
//!   its inner Cargo.toml is rewritten to depend on the crates.io
//!   version of `aa-ebpf-common` (because the sibling crate is absent
//!   in the published tarball) and renamed to `Cargo.toml.embedded` so
//!   cargo's "nested package" tarball-exclusion doesn't drop it.
//!
//! Sibling takes priority — using it directly avoids any manifest
//! rewriting on dev / CI builds and keeps `_embedded/` untouched outside
//! of the publish flow.
//!
//! ## Graceful fallback
//!
//! When the nightly toolchain is not installed (the common case for
//! `cargo install aasm` users), the build script creates empty stub files
//! so the crate still compiles. Loading these stubs at runtime will fail
//! in `Ebpf::load()`, which the runtime handles via per-loader degradation.

use std::path::{Path, PathBuf};

const STAGED_MANIFEST: &str = "Cargo.toml.embedded";

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let manifest_dir =
        PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR is not set by Cargo"));
    let sibling_probes = manifest_dir.join("../aa-ebpf-probes");
    let embedded_probes = manifest_dir.join("_embedded/aa-ebpf-probes");

    // Resolve the probes source dir. Sibling takes priority over _embedded;
    // never touch _embedded outside of the publish-staging flow.
    let probes_dir: Option<PathBuf> = if sibling_probes.join("Cargo.toml").exists() {
        println!("cargo:rerun-if-changed={}", sibling_probes.display());
        Some(sibling_probes)
    } else if embedded_probes.join(STAGED_MANIFEST).exists() || embedded_probes.join("Cargo.toml").exists() {
        // crates.io install — sibling is gone, fall back to the bundled copy.
        restore_manifest_from_stage(&embedded_probes)?;
        println!("cargo:rerun-if-changed={}", embedded_probes.display());
        Some(embedded_probes)
    } else {
        None
    };

    // BPF compilation is Linux-only. On macOS/Windows the build script is a no-op;
    // the userspace constants in lib.rs are gated with the same cfg predicate.
    #[cfg(target_os = "linux")]
    {
        use std::{env, fs, process::Command};

        let out_dir = env::var("OUT_DIR")?;
        // Mirror the path layout used by aya-build: OUT_DIR/<package-name>/…
        // lib.rs embeds the binary at OUT_DIR/aa-ebpf-probes/bpfel-unknown-none/release/aa-hello
        let target_dir = PathBuf::from(&out_dir).join("aa-ebpf-probes");
        let release_dir = target_dir.join("bpfel-unknown-none/release");
        let binaries = ["aa-file-io", "aa-exec-probes", "aa-tls-probes", "aa-syscall-guard"];

        let build_ok = if let Some(dir) = probes_dir.as_ref() {
            // Run `cargo build --release` inside the probes workspace.
            // aa-ebpf-probes/.cargo/config.toml sets:
            //   target      = "bpfel-unknown-none"
            //   build-std   = ["core"]   (nightly only; rust-toolchain.toml pins nightly)
            let status = Command::new("rustup")
                .args(["run", "nightly", "cargo", "build", "--release"])
                .arg("--target-dir")
                .arg(&target_dir)
                .current_dir(dir)
                // Strip cargo's injected RUSTC wrappers so the probes workspace uses
                // the bare nightly rustc without the parent workspace overlay.
                .env_remove("RUSTC")
                .env_remove("RUSTC_WORKSPACE_WRAPPER")
                .status();
            matches!(status, Ok(s) if s.success())
        } else {
            false
        };

        if !build_ok {
            eprintln!(
                "cargo:warning=BPF probe compilation skipped/failed (no probe source or nightly toolchain missing). \
                 Creating empty stubs — eBPF loaders will degrade at runtime."
            );
            fs::create_dir_all(&release_dir)?;
            for name in &binaries {
                let path = release_dir.join(name);
                if !path.exists() {
                    fs::write(&path, b"")?;
                }
            }
        }

        // AAASM-3602: emit the sha256 of each embedded probe object as a
        // compile-time env var so the load-time integrity check can pin the
        // bytecode against the digest CI signed (EBPF_SHA256SUMS, AAASM-3601).
        // The digest is sourced from the *actual compiled object*, never
        // hand-written. A stub (empty file) hashes to the well-known empty
        // digest, which the runtime treats as "unverifiable stub" and refuses
        // to load — fail-closed, never degrade-to-allow.
        emit_object_digest(&release_dir, "aa-file-io", "AA_FILE_IO_BPF_SHA256")?;
        emit_object_digest(&release_dir, "aa-exec-probes", "AA_EXEC_BPF_SHA256")?;
        emit_object_digest(&release_dir, "aa-tls-probes", "AA_TLS_BPF_SHA256")?;
        emit_object_digest(&release_dir, "aa-syscall-guard", "AA_SYSCALL_GUARD_BPF_SHA256")?;
    }

    // On non-Linux the BPF statics in lib.rs are cfg'd out, so the digest env
    // vars are never read; emit empty placeholders so any `env!()` resolves.
    #[cfg(not(target_os = "linux"))]
    {
        for var in [
            "AA_FILE_IO_BPF_SHA256",
            "AA_EXEC_BPF_SHA256",
            "AA_TLS_BPF_SHA256",
            "AA_SYSCALL_GUARD_BPF_SHA256",
        ] {
            println!("cargo:rustc-env={var}=");
        }
    }

    // Suppress unused warning on non-Linux hosts.
    let _ = probes_dir;
    Ok(())
}

/// Hash a compiled probe object and emit `cargo:rustc-env=<var>=<hex>`.
#[cfg(target_os = "linux")]
fn emit_object_digest(release_dir: &Path, object: &str, var: &str) -> Result<(), Box<dyn std::error::Error>> {
    use sha2::{Digest, Sha256};

    let path = release_dir.join(object);
    let bytes = std::fs::read(&path)?;
    let digest = Sha256::digest(&bytes);
    println!("cargo:rustc-env={var}={}", hex::encode(digest));
    Ok(())
}

/// Restore `Cargo.toml.embedded` → `Cargo.toml` so nightly cargo can
/// parse and build the inner workspace from the bundled copy.
/// Idempotent: if a real `Cargo.toml` already exists, leave it alone.
fn restore_manifest_from_stage(probes_dir: &Path) -> std::io::Result<()> {
    let real = probes_dir.join("Cargo.toml");
    let staged = probes_dir.join(STAGED_MANIFEST);
    if real.exists() {
        return Ok(());
    }
    if staged.exists() {
        std::fs::rename(&staged, &real)?;
    }
    Ok(())
}
