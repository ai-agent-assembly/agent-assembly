//! Source-introspection helpers for the integration-surface contract tests
//! (AAASM-4454).
//!
//! # Why read source instead of starting servers
//!
//! The contract these helpers support is *"the network surface the SDK depends
//! on is actually present on the server(s) the CLI starts"*. Proving that by
//! booting the real processes would require a gateway build, `protoc`, bound
//! ports, and a live gRPC/HTTP round-trip inside a unit-test — heavy, flaky, and
//! platform-bound. Instead these helpers treat the repository's own source files
//! as the authoritative description of each surface: which binary
//! `aasm start --mode local` launches, which gRPC services a crate registers,
//! which REST routes it declares. That is enough to detect the drift class that
//! AAASM-4447 uncovered (SDK speaks gRPC `AgentLifecycleService`, but the
//! local-mode server exposes only REST) without running anything.
//!
//! The trade-off: these assertions track the *declared* surface, not a live
//! handshake. That is the right altitude for a fast, deterministic contract test
//! that lives next to the code and fails the moment the wiring diverges.

use std::path::{Path, PathBuf};

/// Absolute path to the Cargo workspace root.
///
/// The `conformance` crate sits one level below the workspace root, so the
/// root is this crate's manifest-dir parent.
pub fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("conformance crate always has a parent (the workspace root)")
        .to_path_buf()
}

/// Read a workspace-relative source file to a `String`.
///
/// Panics with a descriptive message if the file cannot be read, so a contract
/// test that names a moved/renamed file fails loudly rather than silently
/// skipping its assertion.
pub fn read_repo_file(rel: &str) -> String {
    let path = workspace_root().join(rel);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("cannot read repo file {}: {}", path.display(), e))
}

/// Recursively collect every `*.rs` file under `<crate_dir>/src`.
///
/// `target/` and other build outputs live outside `src/`, so a plain walk of
/// `src/` is enough and needs no ignore handling.
pub fn crate_src_files(crate_dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let src = crate_dir.join("src");
    collect_rs(&src, &mut out);
    out.sort();
    out
}

fn collect_rs(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_rs(&path, out);
        } else if path.extension().map(|x| x == "rs").unwrap_or(false) {
            out.push(path);
        }
    }
}

/// Whether any `*.rs` file under `<crate_dir>/src` contains `needle`.
///
/// Used to check that a crate references a specific generated tonic server type
/// (e.g. `AgentLifecycleServiceServer`). It is a textual, not semantic, check —
/// deliberately so: the point is to detect that the wiring exists at all, and to
/// fail when it is deleted or renamed.
pub fn crate_src_contains(crate_dir: &Path, needle: &str) -> bool {
    crate_src_files(crate_dir)
        .iter()
        .any(|p| std::fs::read_to_string(p).map(|s| s.contains(needle)).unwrap_or(false))
}

/// Locate the crate directory whose `src/bin/<bin>.rs` provides the binary
/// named `bin`.
///
/// Returns `None` if no workspace crate ships that binary. Lets a contract test
/// map a spawned program name (`aa-api-server`) back to the crate whose surface
/// must satisfy the contract (`aa-api`), instead of hard-coding the mapping.
pub fn crate_dir_for_binary(bin: &str) -> Option<PathBuf> {
    let root = workspace_root();
    let entries = std::fs::read_dir(&root).ok()?;
    for entry in entries.flatten() {
        let dir = entry.path();
        if dir.is_dir() && dir.join("src/bin").join(format!("{bin}.rs")).exists() {
            return Some(dir);
        }
    }
    None
}

/// Extract the `rpc <Name>` method names declared inside `service <service>`
/// in a `.proto` file's text.
///
/// Returns the method names in declaration order. Returns an empty vec if the
/// service is not found. Brace-matches the service body so `rpc` tokens in
/// other services or in comments outside the block are not picked up.
pub fn proto_service_rpcs(proto_src: &str, service: &str) -> Vec<String> {
    let needle = format!("service {service}");
    let Some(start) = proto_src.find(&needle) else {
        return Vec::new();
    };
    // Find the opening brace of the service body, then walk to its match.
    let Some(open_rel) = proto_src[start..].find('{') else {
        return Vec::new();
    };
    let open = start + open_rel;
    let mut depth = 0usize;
    let mut end = open;
    for (i, ch) in proto_src[open..].char_indices() {
        match ch {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    end = open + i;
                    break;
                }
            }
            _ => {}
        }
    }
    let body = &proto_src[open + 1..end];
    body.lines()
        .filter_map(|line| {
            let line = line.trim();
            let rest = line.strip_prefix("rpc ")?;
            let name: String = rest.chars().take_while(|c| c.is_alphanumeric() || *c == '_').collect();
            (!name.is_empty()).then_some(name)
        })
        .collect()
}

/// The program name that `aasm start --mode local` launches, parsed from the
/// CLI's `start` command source.
///
/// Reads the mapping actually encoded in `start.rs` rather than assuming it, so
/// this contract test re-evaluates automatically if the local-mode entrypoint is
/// ever changed. The binary name is resolved through `start.rs`'s own single
/// source of truth — the `fn binary_name` match — whose `ModeArg::Local` arm is
/// a bare string literal (`ModeArg::Local => "aa-api-server"`). This tracks the
/// real indirection: the spawn site calls `Command::new(binary_name(self.mode))`
/// rather than embedding the literal, so parsing `binary_name` (not the
/// `Command::new(...)` call) is what actually mirrors the code. Returns `None`
/// if the arm can't be located.
pub fn local_mode_server_program(start_src: &str) -> Option<String> {
    // Scope to `fn binary_name` so we pick the binary-name mapping, not one of
    // the other `ModeArg::Local =>` arms (listen addr, banner text, etc.).
    let func = start_src.find("fn binary_name")?;
    let after_fn = &start_src[func..];
    let arm = after_fn.find("ModeArg::Local")?;
    let after_arm = &after_fn[arm..];
    let fat = after_arm.find("=>")?;
    let after_fat = &after_arm[fat + "=>".len()..];
    let q1 = after_fat.find('"')?;
    let after_q = &after_fat[q1 + 1..];
    let q2 = after_q.find('"')?;
    Some(after_q[..q2].to_string())
}

/// Whether a crate declares a REST route whose path plausibly registers an
/// agent — i.e. a `.route("…")` path literal containing `register`.
///
/// This is the REST half of the AAASM-4447 contract: a documented REST
/// registration path is an acceptable alternative to serving the gRPC
/// `AgentLifecycleService`. Matching on the path literal (not the handler name)
/// avoids false positives from unrelated handlers such as `ops::register_op`
/// mounted at `/ops`.
pub fn crate_has_registration_rest_route(crate_dir: &Path) -> bool {
    for file in crate_src_files(crate_dir) {
        let Ok(src) = std::fs::read_to_string(&file) else {
            continue;
        };
        for path in route_path_literals(&src) {
            if path.to_ascii_lowercase().contains("register") {
                return true;
            }
        }
    }
    false
}

/// Collect the path literals from `.route("<path>", …)` declarations in a
/// source file (the first string argument of each `.route(` call).
pub fn route_path_literals(src: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = src;
    while let Some(idx) = rest.find(".route(") {
        rest = &rest[idx + ".route(".len()..];
        // Skip whitespace to the first argument.
        let trimmed = rest.trim_start();
        if let Some(after_quote) = trimmed.strip_prefix('"') {
            if let Some(end) = after_quote.find('"') {
                out.push(after_quote[..end].to_string());
            }
        }
    }
    out
}
