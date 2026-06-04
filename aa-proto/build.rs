use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let manifest_dir =
        PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR is not set by Cargo"));

    // AAASM-2340: when building from a checkout of the workspace the .proto
    // files live at the workspace root (`../proto/`). When building from a
    // crates.io-published tarball the workspace is gone, so the .proto files
    // must travel inside the crate at `_embedded/proto/`. Mirror sibling →
    // _embedded when sibling exists so local dev edits to `../proto/` flow
    // through; otherwise compile from whatever is already in _embedded.
    let sibling_proto = manifest_dir
        .parent()
        .map(|p| p.join("proto"))
        .filter(|p| p.join("common.proto").exists());
    let embedded_proto = manifest_dir.join("_embedded/proto");

    let proto_root = if let Some(sibling) = sibling_proto {
        // Local dev: mirror sibling → _embedded so the same input source is
        // used in both dev and crates.io builds.
        let _ = std::fs::remove_dir_all(&embedded_proto);
        copy_dir_recursive(&sibling, &embedded_proto)
            .expect("failed to mirror ../proto/ into aa-proto/_embedded/proto/");
        println!("cargo:rerun-if-changed={}", sibling.display());
        embedded_proto.clone()
    } else if embedded_proto.join("common.proto").exists() {
        // crates.io install: _embedded/ ships in the tarball.
        embedded_proto.clone()
    } else {
        panic!(
            "neither sibling `../proto/` nor `aa-proto/_embedded/proto/` contains the .proto sources — \
             this checkout is missing the protobuf inputs required to build aa-proto"
        );
    };

    let proto_files = [
        proto_root.join("common.proto"),
        proto_root.join("agent.proto"),
        proto_root.join("policy.proto"),
        proto_root.join("audit.proto"),
        proto_root.join("event.proto"),
        proto_root.join("approval.proto"),
        proto_root.join("topology.proto"),
        proto_root.join("secrets.proto"),
        proto_root.join("invalidation.proto"),
    ];

    println!("cargo:rerun-if-changed={}", proto_root.display());

    tonic_prost_build::configure()
        .build_server(true)
        .build_client(true)
        .compile_protos(&proto_files, &[proto_root])?;

    Ok(())
}

fn copy_dir_recursive(src: &std::path::Path, dst: &std::path::Path) -> std::io::Result<()> {
    std::fs::create_dir_all(dst)?;
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let ty = entry.file_type()?;
        let src_path = entry.path();
        let dst_path = dst.join(entry.file_name());
        if ty.is_dir() {
            copy_dir_recursive(&src_path, &dst_path)?;
        } else if ty.is_file() {
            std::fs::copy(&src_path, &dst_path)?;
        }
    }
    Ok(())
}
