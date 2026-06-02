//! aa-cli build script.
//!
//! `aasm` embeds the dashboard SPA via `include_dir!` (see
//! `src/commands/dashboard/start.rs`). The macro reads from
//! `$CARGO_MANIFEST_DIR/_embedded/dashboard/dist/`.
//!
//! That path is INSIDE the crate, so `cargo publish` bundles it into
//! the published tarball. release.yml pre-builds the dashboard
//! (`pnpm build` in `dashboard/`) then copies `dashboard/dist/` into
//! `aa-cli/_embedded/dashboard/dist/` BEFORE `cargo publish`.
//!
//! For local development (where `../dashboard/dist/` exists as a sibling
//! to aa-cli), this build script mirrors that directory into
//! `_embedded/dashboard/dist/` so the include_dir! macro picks up
//! local frontend changes without manual copying.
//!
//! AAASM-2340.

use std::path::PathBuf;

fn main() {
    let manifest_dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    let embedded = manifest_dir.join("_embedded/dashboard/dist");
    let sibling = manifest_dir.join("../dashboard/dist");
    let embedded_index = embedded.join("index.html");
    let sibling_index = sibling.join("index.html");

    // If the sibling dashboard/dist exists (local dev), mirror it into
    // _embedded/. The mirror keeps include_dir!'s view in sync with what
    // pnpm build produces.
    if sibling_index.exists() {
        // Recursively copy sibling → embedded (overwrite).
        let _ = std::fs::remove_dir_all(&embedded);
        copy_dir_recursive(&sibling, &embedded)
            .expect("failed to mirror ../dashboard/dist to _embedded/dashboard/dist");
        println!("cargo:rerun-if-changed=../dashboard/dist");
    } else if !embedded_index.exists() {
        // Neither the sibling nor the embedded path has the dashboard.
        // Generate a stub so include_dir! compiles. This branch fires
        // when someone clones the repo and does `cargo build -p aa-cli`
        // without first running `pnpm build` in dashboard/. The stub
        // makes `aasm dashboard start` return a "dashboard not built"
        // page rather than failing the build.
        std::fs::create_dir_all(&embedded).expect("cannot create _embedded/dashboard/dist");
        std::fs::write(
            &embedded_index,
            "<!doctype html><html><body>Dashboard not built. Run <code>pnpm build</code> in dashboard/ then rebuild aa-cli, OR install a published aasm binary that ships the prebuilt dashboard.</body></html>\n",
        )
        .expect("cannot write _embedded/dashboard/dist/index.html");
    }
    // else: _embedded/dashboard/dist/ already populated (from a prior
    // build OR from the published crates.io tarball — both fine).

    println!("cargo:rerun-if-changed=_embedded/dashboard/dist");
}

/// Recursively copy `src` → `dst`. Creates `dst` and any parent dirs as needed.
fn copy_dir_recursive(src: &std::path::Path, dst: &std::path::Path) -> std::io::Result<()> {
    std::fs::create_dir_all(dst)?;
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let kind = entry.file_type()?;
        let src_path = entry.path();
        let dst_path = dst.join(entry.file_name());
        if kind.is_dir() {
            copy_dir_recursive(&src_path, &dst_path)?;
        } else {
            std::fs::copy(&src_path, &dst_path)?;
        }
    }
    Ok(())
}
