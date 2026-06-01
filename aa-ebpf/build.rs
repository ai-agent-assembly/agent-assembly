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
//! AAASM-2340: when building from a checkout of the workspace the probes
//! source lives at `../aa-ebpf-probes/`. When building from a crates.io
//! tarball that sibling is gone, so the probes source must travel inside
//! the crate at `_embedded/aa-ebpf-probes/`. Mirror sibling → `_embedded`
//! when sibling exists so dev edits flow through; otherwise compile from
//! whatever is in `_embedded/`.
//!
//! ### Cargo nested-package quirk
//!
//! Cargo's tarball file-enumeration **excludes any subdirectory that
//! contains a `Cargo.toml`**, treating it as a nested package — even when
//! `[package].include` explicitly lists that subtree. To work around
//! this we stage the mirrored manifest as `Cargo.toml.embedded` (a name
//! cargo doesn't recognise as a manifest) and `OUTER_BUILD` (build.rs)
//! restores it to `Cargo.toml` before invoking nightly cargo on the
//! inner workspace. The mirrored manifest also gets its
//! `aa-ebpf-common` path-dep rewritten to a crates.io version because
//! the sibling `../aa-ebpf-common/` does not exist inside the published
//! tarball.
//!
//! The mirror runs on all host OSes so the tarball produced from a release
//! CI runner (which may or may not be Linux) carries the probe source. The
//! actual BPF compilation only runs on Linux (where aya works).
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

    // Step 1: ensure `_embedded/aa-ebpf-probes/` exists and is current.
    // Cross-platform so the tarball produced on any release runner carries
    // the probe source.
    if sibling_probes.join("Cargo.toml").exists() {
        let _ = std::fs::remove_dir_all(&embedded_probes);
        copy_dir_recursive(&sibling_probes, &embedded_probes)
            .expect("failed to mirror ../aa-ebpf-probes/ into _embedded/aa-ebpf-probes/");
        stage_manifest_for_publish(&embedded_probes).expect("failed to stage embedded manifest for publish");
        println!("cargo:rerun-if-changed={}", sibling_probes.display());
    }
    println!("cargo:rerun-if-changed={}", embedded_probes.display());

    // Step 2: BPF compilation is Linux-only. On macOS/Windows we are done
    // after mirroring; the userspace constants in lib.rs are gated with
    // the same cfg predicate as aya.
    #[cfg(target_os = "linux")]
    {
        use std::{env, fs, process::Command};

        // Restore the staged manifest before invoking nightly cargo.
        let probes_dir =
            if embedded_probes.join(STAGED_MANIFEST).exists() || embedded_probes.join("Cargo.toml").exists() {
                restore_manifest_from_stage(&embedded_probes).expect("failed to restore embedded manifest");
                Some(embedded_probes.clone())
            } else {
                None
            };

        let out_dir = env::var("OUT_DIR")?;
        let target_dir = PathBuf::from(&out_dir).join("aa-ebpf-probes");
        let release_dir = target_dir.join("bpfel-unknown-none/release");
        let binaries = ["aa-file-io", "aa-exec-probes", "aa-tls-probes"];

        let build_ok = if let Some(dir) = probes_dir.as_ref() {
            let status = Command::new("rustup")
                .args(["run", "nightly", "cargo", "build", "--release"])
                .arg("--target-dir")
                .arg(&target_dir)
                .current_dir(dir)
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
    }

    Ok(())
}

fn copy_dir_recursive(src: &Path, dst: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(dst)?;
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let ty = entry.file_type()?;
        let src_path = entry.path();
        // Skip the inner workspace's target/ — we never want to copy build artifacts.
        if src_path.file_name().map(|n| n == "target").unwrap_or(false) {
            continue;
        }
        let dst_path = dst.join(entry.file_name());
        if ty.is_dir() {
            copy_dir_recursive(&src_path, &dst_path)?;
        } else if ty.is_file() {
            std::fs::copy(&src_path, &dst_path)?;
        }
    }
    Ok(())
}

/// Rename the mirrored `Cargo.toml` to `Cargo.toml.embedded` so cargo's
/// tarball file-enumeration does not skip the directory as a "nested
/// package". Also rewrites the `aa-ebpf-common` path-dep to its
/// crates.io version since the sibling crate is gone in the tarball.
fn stage_manifest_for_publish(probes_dir: &Path) -> std::io::Result<()> {
    let real = probes_dir.join("Cargo.toml");
    let staged = probes_dir.join(STAGED_MANIFEST);
    if !real.exists() {
        return Ok(());
    }
    let original = std::fs::read_to_string(&real)?;
    let workspace_version = "0.0.1-alpha.3";
    let rewritten = original.replace(
        "aa-ebpf-common = { path = \"../aa-ebpf-common\" }",
        &format!("aa-ebpf-common = \"{workspace_version}\""),
    );
    std::fs::write(&staged, rewritten)?;
    std::fs::remove_file(&real)?;
    Ok(())
}

/// Restore `Cargo.toml.embedded` → `Cargo.toml` so nightly cargo can
/// parse and build the inner workspace. Idempotent: if a real
/// `Cargo.toml` already exists, leave it alone.
#[cfg(target_os = "linux")]
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
