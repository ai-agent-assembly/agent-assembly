use std::path::PathBuf;

fn main() {
    let dist = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap())
        .join("../dashboard/dist");

    // Create a stub dist directory so include_dir! compiles when the SPA has not been built.
    if !dist.exists() {
        std::fs::create_dir_all(&dist).expect("cannot create dashboard/dist");
        std::fs::write(
            dist.join("index.html"),
            "<!doctype html><html><body>Dashboard not built. Run <code>pnpm build</code> in dashboard/.</body></html>\n",
        )
        .expect("cannot write dashboard/dist/index.html");
    }

    println!("cargo:rerun-if-changed=../dashboard/dist");
}
