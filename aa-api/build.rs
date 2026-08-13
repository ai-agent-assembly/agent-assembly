//! aa-api build script.
//!
//! The shipped `aa-api-server` embeds the dashboard SPA via `include_dir!`
//! (see `src/embedded_dashboard.rs`) so a bare, unpacked release tarball
//! serves the UI at `GET /` with no adjacent `dashboard/dist/` and no
//! `AASM_DASHBOARD_DIST` env var. The macro reads from
//! `$CARGO_MANIFEST_DIR/_embedded/dashboard/dist/`.
//!
//! That path is INSIDE the crate, so the release job stages the freshly-built
//! `dashboard/dist/` into `aa-api/_embedded/dashboard/dist/` BEFORE
//! `cargo build -p aa-api` (release.yml), the same way aa-cli's crates.io leg
//! stages it before `cargo publish`.
//!
//! For local development (where `../dashboard/dist/` exists as a sibling to
//! aa-api) this build script mirrors that directory into
//! `_embedded/dashboard/dist/` so the include_dir! macro picks up local
//! frontend changes without manual copying.
//!
//! Mirrors `aa-cli/build.rs` (AAASM-2340); added for AAASM-4517.

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
        // Generate a stub so include_dir! compiles. This branch fires when
        // someone clones the repo and does `cargo build -p aa-api` without
        // first running `pnpm build` in dashboard/. The stub makes local mode
        // serve a "dashboard not built" page rather than failing the build, so
        // the crate always compiles both with and without a staged dist.
        std::fs::create_dir_all(&embedded).expect("cannot create _embedded/dashboard/dist");
        std::fs::write(
            &embedded_index,
            "<!doctype html><html><body>Dashboard not built. Run <code>pnpm build</code> in dashboard/ then rebuild aa-api, OR install a published aasm release that ships the prebuilt dashboard.</body></html>\n",
        )
        .expect("cannot write _embedded/dashboard/dist/index.html");
    }
    // else: _embedded/dashboard/dist/ already populated (from a prior build OR
    // from the release-staging step — both fine).

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
