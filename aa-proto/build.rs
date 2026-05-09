use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Proto files live at the workspace root, one level above this crate.
    // Use CARGO_MANIFEST_DIR at runtime (not the env!() macro) so that the
    // path is resolved when the build script runs, not when it is compiled.
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR is not set by Cargo");
    let proto_root = PathBuf::from(&manifest_dir)
        .parent()
        .expect("aa-proto must be a direct child of the workspace root")
        .join("proto");

    let proto_files = [
        proto_root.join("common.proto"),
        proto_root.join("agent.proto"),
        proto_root.join("policy.proto"),
        proto_root.join("audit.proto"),
        proto_root.join("event.proto"),
        proto_root.join("approval.proto"),
        proto_root.join("topology.proto"),
    ];

    // Re-run this build script if any proto file changes.
    println!("cargo:rerun-if-changed={}", proto_root.display());

    tonic_prost_build::configure()
        .build_server(true)
        .build_client(true)
        .compile_protos(&proto_files, &[proto_root])?;

    Ok(())
}
