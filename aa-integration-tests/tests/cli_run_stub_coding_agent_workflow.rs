//! AAASM-6297 (ST-10, campaign AAASM-6174) -- the governed coding-agent
//! workflow, driven by a deterministic **STUB** coding agent.
//!
//! # STUB, not a real agent -- read this before citing any result here
//!
//! Every test in this file launches `fixtures/stub_coding_agent/stub_agent.sh`
//! (a POSIX script) or an empty `claude` placeholder script. NEITHER is Claude
//! Code, Codex, Copilot or Windsurf. What these tests evidence is the
//! *governed-launch plumbing* -- `aasm run` + the transactional workspace + the
//! dedicated per-launch proxy + the gateway `PolicyService` + per-session
//! attribution -- when something that behaves like a coding agent (edits a
//! file, runs a shell command, attempts a policy-restricted tool call) is
//! launched under it. They are NOT evidence that any specific real agent
//! behaves this way, and must not be cited as a "real coding agent PASS".
//! The real-agent legs are in `verification-reports/AAASM-6297-coding-agent-workflow-founder-dogfood.md`
//! (founder DogFood) and are BLOCKED-ON-FOUNDER-DOGFOOD here.
//!
//! # The restricted action
//!
//! The policy-denied action is an MCP `tools/call` (`deny_test`) sent over the
//! governed HTTPS proxy and adjudicated by a real gateway `PolicyService`
//! (`aa_proxy::mcp_enforce`) -- the same mechanism
//! `cli_run_claude_deterministic_conformance.rs` (AAASM-5930) proves with the
//! real `claude` binary. A protected-path commit refusal is deliberately NOT
//! used as the "policy denies" leg: that is `cli_run_workspace_tx.rs`.
//!
//! # Property-specific controls
//!
//! * the denial is proven POLICY-caused, not availability-caused, by a paired
//!   control that flips exactly one property (`deny_test` allow:false -> true)
//!   with every other input held constant, and observes the call *reach* the
//!   upstream;
//! * the denial's cause is the persisted proxy audit record
//!   (`RefusalRule::McpToolCall`, `Blocked`), not merely "the sentinel is
//!   missing".
//!
//! # Platform
//!
//! macOS-hosted and Linux-hosted `--isolation none` launches only. On this
//! macOS host every confining backend refuses, so there is no execution
//! receipt to inspect for an executed run (asserted as truthful absence); the
//! commit-plus-receipt-verifies leg is Linux-only
//! (`cli_run_workspace_tx.rs` test 4) and is BLOCKED-NO-INFRA here.

#[allow(unused_imports)]
pub use common::precondition::evidence;

#[allow(unused_imports)]
mod common;
#[allow(unused_imports)]
mod conformance_gateway_support;
#[allow(dead_code, unused_imports)]
mod conformance_mcp_support;
#[allow(dead_code, unused_imports)]
mod conformance_support;
#[allow(unused_imports)]
mod grpc_gateway_support;
#[allow(unused_imports)]
mod proxy_trust_support;
#[allow(dead_code, unused_imports)]
mod spike_support;

#[cfg(target_os = "macos")]
fn stub_coding_agent_tail(s: &str) -> String {
    let lines: Vec<&str> = s.lines().collect();
    lines[lines.len().saturating_sub(40)..].join("\n")
}

#[cfg(unix)]
mod stub_coding_agent {
    use std::collections::{BTreeMap, BTreeSet};
    use std::io;
    use std::path::{Path, PathBuf};
    use std::process::{Command, Stdio};

    use aa_proxy::audit_jsonl::{ProxyAuditDecision, ProxyAuditEntry, RefusalRule};
    use aa_proxy::tls::CaStore;

    use super::conformance_mcp_support::{sentinel_path, ConformanceUpstream};
    use super::proxy_trust_support::TrustedProxy;
    use super::spike_support::proxy_harness::install_crypto_provider;

    const FIXTURE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/fixtures/stub_coding_agent");
    const MCP_HOST: &str = "mcp.example.com";
    const MCP_SERVER: &str = "conformance";
    const ALLOW_TOOL: &str = "allow_test";
    const DENY_TOOL: &str = "deny_test";

    /// Same shape as AAASM-5930's policy: `allow_test` allowed, `deny_test`
    /// denied (or, for the control, allowed -- the ONLY difference).
    fn write_policy(dir: &Path, name: &str, deny_test_allowed: bool) -> io::Result<PathBuf> {
        let path = dir.join(format!("{name}.yaml"));
        std::fs::write(
            &path,
            format!(
                "apiVersion: agent-assembly.dev/v1alpha1\nkind: GovernancePolicy\nmetadata:\n  name: {name}\n  \
                 version: \"0.1.0\"\nspec:\n  tools:\n    allow_test:\n      allow: true\n    deny_test:\n      \
                 allow: {deny_test_allowed}\n"
            ),
        )?;
        Ok(path)
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    enum Entry {
        Dir,
        File(Vec<u8>),
    }

    /// Directory that receives a raw witness of every snapshot, or `None`.
    ///
    /// HORO-1718 X2 needs the fixture tree as it was observed before and after
    /// a run, not only the in-test assertion that the two were equal. Setting
    /// this variable is an opt-in recording hook: it changes nothing a test
    /// compares and is unset in every ordinary lane.
    const WITNESS_ENV: &str = "AASM_STUB_SNAPSHOT_WITNESS_DIR";

    /// Write one witness file per `snapshot` call: the calling test, a
    /// process-wide sequence number, and for every entry its kind, length and
    /// sha256. Failures to record are reported, never swallowed, because a
    /// witness that silently stopped being written would read as absence.
    fn record_snapshot_witness(root: &Path, snap: &BTreeMap<String, Entry>) {
        use sha2::{Digest, Sha256};
        use std::sync::atomic::{AtomicUsize, Ordering};
        static SEQ: AtomicUsize = AtomicUsize::new(0);
        let Some(dir) = std::env::var_os(WITNESS_ENV).filter(|v| !v.is_empty()) else {
            return;
        };
        let dir = PathBuf::from(dir);
        std::fs::create_dir_all(&dir).expect("create witness dir");
        let seq = SEQ.fetch_add(1, Ordering::SeqCst);
        let test = std::thread::current().name().unwrap_or("unnamed").to_string();
        let entries: BTreeMap<&String, serde_json::Value> = snap
            .iter()
            .map(|(path, entry)| {
                let value = match entry {
                    Entry::Dir => serde_json::json!({ "kind": "dir" }),
                    Entry::File(bytes) => serde_json::json!({
                        "kind": "file",
                        "len": bytes.len(),
                        "sha256": hex::encode(Sha256::digest(bytes)),
                    }),
                };
                (path, value)
            })
            .collect();
        let doc = serde_json::json!({
            "test": test,
            "seq": seq,
            "pid": std::process::id(),
            "root_name": root.file_name().map(|n| n.to_string_lossy().into_owned()),
            "entries": entries,
        });
        let safe: String = test
            .chars()
            .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
            .collect();
        let file = dir.join(format!("{safe}-{seq:04}.json"));
        std::fs::write(&file, serde_json::to_vec_pretty(&doc).expect("witness json")).expect("write witness");
    }

    fn snapshot(root: &Path) -> BTreeMap<String, Entry> {
        let out = take_snapshot(root);
        record_snapshot_witness(root, &out);
        out
    }

    fn take_snapshot(root: &Path) -> BTreeMap<String, Entry> {
        let mut out = BTreeMap::new();
        let mut stack = vec![root.to_path_buf()];
        while let Some(dir) = stack.pop() {
            for entry in std::fs::read_dir(&dir).expect("read_dir") {
                let path = entry.expect("dir entry").path();
                let rel = path
                    .strip_prefix(root)
                    .expect("under root")
                    .to_string_lossy()
                    .into_owned();
                if path.is_dir() {
                    out.insert(rel, Entry::Dir);
                    stack.push(path);
                } else {
                    out.insert(rel, Entry::File(std::fs::read(&path).expect("read")));
                }
            }
        }
        out
    }

    fn copy_fixture(dst: &Path) -> io::Result<()> {
        use std::os::unix::fs::PermissionsExt;
        std::fs::create_dir_all(dst.join("src"))?;
        std::fs::copy(Path::new(FIXTURE).join("src/lib.txt"), dst.join("src/lib.txt"))?;
        let script = dst.join("stub_agent.sh");
        std::fs::copy(Path::new(FIXTURE).join("stub_agent.sh"), &script)?;
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755))?;
        Ok(())
    }

    fn tail(s: &str, n: usize) -> String {
        let lines: Vec<&str> = s.lines().collect();
        lines[lines.len().saturating_sub(n)..].join("\n")
    }

    fn read_audit(state: &Path) -> anyhow::Result<Vec<(PathBuf, Vec<ProxyAuditEntry>)>> {
        let runs = state.join("runs");
        let mut out = Vec::new();
        if runs.is_dir() {
            for e in std::fs::read_dir(&runs)? {
                let p = e?.path().join("audit.jsonl");
                if p.is_file() {
                    let raw = std::fs::read_to_string(&p)?;
                    let entries = raw
                        .lines()
                        .filter(|l| !l.trim().is_empty())
                        .map(|l| serde_json::from_str(l).map_err(|e| anyhow::anyhow!("audit line: {e}: {l}")))
                        .collect::<anyhow::Result<Vec<ProxyAuditEntry>>>()?;
                    out.push((p, entries));
                }
            }
        }
        Ok(out)
    }

    /// The one variable the sanitised launch forwards: the coverage runner's
    /// profile pattern. `aasm run --workspace-tx` runs with the fixture tree as
    /// its cwd, so an instrumented `aasm` that never sees this writes its
    /// `default_*.profraw` into the tree the exact-change-set oracle compares.
    /// Forwarding the runner's own pattern (already outside any fixture) keeps
    /// the full snapshot honest and the profile collected.
    const PROFILE_ENV: &str = "LLVM_PROFILE_FILE";

    /// Resolve `dir` through every symlink that exists, appending any not-yet-
    /// created tail verbatim. Lets the containment check run BEFORE anything is
    /// created, so a refused sink leaves no directories behind. A dangling
    /// symlink is an error, not a missing tail: creating through it would land
    /// wherever it points.
    fn canonicalize_with_missing_tail(dir: &Path) -> io::Result<PathBuf> {
        let mut missing = Vec::new();
        let mut cur = dir;
        loop {
            match cur.canonicalize() {
                Ok(mut resolved) => {
                    resolved.extend(missing.iter().rev());
                    return Ok(resolved);
                }
                Err(e) if e.kind() == io::ErrorKind::NotFound && cur.symlink_metadata().is_err() => {
                    let (Some(name), Some(parent)) = (cur.file_name(), cur.parent()) else {
                        return Err(e);
                    };
                    missing.push(name);
                    cur = parent;
                }
                Err(e) if e.kind() == io::ErrorKind::NotFound => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!("{PROFILE_ENV} directory crosses a dangling symlink"),
                    ));
                }
                Err(e) => return Err(e),
            }
        }
    }

    /// Validate the ambient coverage profile pattern for pass-through. `None`
    /// (ordinary lane) forwards nothing.
    ///
    /// Supported pattern: an absolute path whose directory part is literal
    /// (no `..` component, no `%` token) and whose final component is the
    /// file name, which may carry `%p`/`%m` tokens -- what `cargo llvm-cov`
    /// sets. (`Path::components` already drops interior `.` components, and
    /// `/a/./b` resolves exactly like `/a/b`, so `.` needs no refusal.) LLVM
    /// expands tokens in directory components into names this check cannot
    /// see, so they are refused rather than checked as literal directories.
    /// The directory and the fixture root are resolved through symlinks, and
    /// the sink directory must not lie inside the fixture root (a directory
    /// that contains the root is accepted: profiles land in that directory
    /// itself, not in the root's subtree); only then is the directory created.
    /// The returned pattern is the *resolved* directory joined with the
    /// original file name, so for a token-free file name the destination that
    /// was checked is the one forwarded, and `%` tokens in a file name still
    /// expand. A concrete (token-free) existing file name must not be a
    /// symlink; a file name with tokens is NOT resolved, so what LLVM expands
    /// it to is not checked, and a hard link to a fixture file is not
    /// detected. A same-user process racing the directory after this check is
    /// out of scope: the sink is a private directory of the harness's runner.
    fn validated_profile_sink(raw: Option<std::ffi::OsString>, tree: &Path) -> io::Result<Option<PathBuf>> {
        let Some(raw) = raw.filter(|v| !v.is_empty()) else {
            return Ok(None);
        };
        let pattern = PathBuf::from(raw);
        let bad = |why: &str| io::Error::new(io::ErrorKind::InvalidInput, format!("{PROFILE_ENV} {why}"));
        if !pattern.is_absolute() {
            return Err(bad("must be an absolute path"));
        }
        let dir = pattern.parent().ok_or_else(|| bad("has no directory"))?;
        let leaf = pattern.file_name().ok_or_else(|| bad("has no file name"))?;
        if dir
            .components()
            .any(|c| matches!(c, std::path::Component::ParentDir | std::path::Component::CurDir))
        {
            return Err(bad("directory must not contain . or .. components"));
        }
        if dir.to_string_lossy().contains('%') {
            return Err(bad("directory must not contain % tokens; only the file name may"));
        }
        let tree = tree.canonicalize()?;
        let resolved_dir = canonicalize_with_missing_tail(dir)?;
        if resolved_dir.starts_with(&tree) {
            return Err(bad("must point outside the fixture tree"));
        }
        std::fs::create_dir_all(&resolved_dir)?;
        let resolved = resolved_dir.join(leaf);
        if !leaf.to_string_lossy().contains('%')
            && std::fs::symlink_metadata(&resolved).is_ok_and(|m| m.file_type().is_symlink())
        {
            return Err(bad("file name must not be a symlink"));
        }
        Ok(Some(resolved))
    }

    /// Forward only the validated profile pattern into an already
    /// `env_clear`ed launch; every other ambient variable stays cleared.
    fn apply_profile_sink(cmd: &mut Command, sink: Option<&Path>) {
        if let Some(pattern) = sink {
            cmd.env(PROFILE_ENV, pattern);
        }
    }

    /// Everything one test host shares: a CA, the deterministic upstream, a
    /// real gateway with `PolicyService`, and the trusted-proxy precondition.
    struct Host {
        _tmp: tempfile::TempDir,
        root: PathBuf,
        ca_dir: PathBuf,
        sentinel_dir: PathBuf,
        state: PathBuf,
        gateway_endpoint: String,
        policy: PathBuf,
        profile_sink: Option<PathBuf>,
        upstream: ConformanceUpstream,
        proxy: TrustedProxy,
    }

    impl Host {
        async fn start(deny_test_allowed: bool) -> anyhow::Result<Self> {
            Self::start_with_profile_env(deny_test_allowed, std::env::var_os(PROFILE_ENV)).await
        }

        /// `start` with the coverage profile pattern supplied explicitly, so a
        /// test can exercise the real launch path under a chosen sink instead
        /// of whatever the runner happens to export.
        async fn start_with_profile_env(
            deny_test_allowed: bool,
            profile_env: Option<std::ffi::OsString>,
        ) -> anyhow::Result<Self> {
            install_crypto_provider();
            let tmp = tempfile::tempdir()?;
            let root = tmp.path().to_path_buf();
            let ca_dir = root.join("ca");
            let sentinel_dir = root.join("sentinels");
            let state = root.join("state");
            for d in [&ca_dir, &sentinel_dir, &state] {
                std::fs::create_dir_all(d)?;
            }
            let policy = write_policy(&root, "aaasm6297-stub", deny_test_allowed)?;
            let profile_sink = validated_profile_sink(profile_env, &root)?;
            let (gateway_endpoint, _registry) = super::conformance_gateway_support::start_full_gateway(&policy).await?;
            let ca = CaStore::load_or_create(&ca_dir)
                .await
                .map_err(|e| anyhow::anyhow!("certificate authority: {e}"))?;
            let upstream =
                ConformanceUpstream::start(&ca, MCP_HOST, MCP_SERVER, ALLOW_TOOL, DENY_TOOL, &sentinel_dir).await?;
            drop(ca);
            let proxy = TrustedProxy::start_intercepting(&ca_dir, upstream.addr, &state, &[])?;
            Ok(Self {
                _tmp: tmp,
                root,
                ca_dir,
                sentinel_dir,
                state,
                gateway_endpoint,
                policy,
                profile_sink,
                upstream,
                proxy,
            })
        }

        /// `aasm run --workspace-tx exec -- sh stub_agent.sh <session> <ca> <mode>`
        /// with an explicit environment -- nothing ambient crosses in.
        fn launch(&self, agent_id: &str, project: &Path, mode: &str) -> io::Result<std::process::Child> {
            self.launch_command(agent_id, project, mode)?.spawn()
        }

        /// The exact `Command` `launch` spawns, exposed so a test can assert the
        /// sanitised environment the real launch path builds rather than a
        /// re-derivation of it.
        fn launch_command(&self, agent_id: &str, project: &Path, mode: &str) -> io::Result<Command> {
            let home = self.root.join(format!("home-{agent_id}"));
            std::fs::create_dir_all(&home)?;
            let mut cmd = Command::new(self.proxy.aasm());
            cmd.env_clear()
                .current_dir(project)
                .env(
                    "PATH",
                    format!("{}:/usr/bin:/bin", self.proxy.proxy_bin_dir().display()),
                )
                .env("HOME", &home)
                .env("AASM_STATE_DIR", &self.state)
                .env("AA_CA_DIR", &self.ca_dir)
                .env("AA_DATA_DIR", self.proxy.data_dir())
                .env("AA_GATEWAY_ENDPOINT", &self.gateway_endpoint)
                .env("AA_TEST_PROXY_UPSTREAM", self.upstream.addr.to_string())
                .env("AA_PROXY_LLM_ONLY", "false")
                .env("AA_PROXY_SKIP_UPSTREAM_TLS_VERIFY", "1")
                .args(["run", "--workspace-tx", "--policy"])
                .arg(&self.policy)
                .args(["--agent-id", agent_id, "exec", "--", "sh", "stub_agent.sh", agent_id])
                .arg(self.ca_dir.join("ca-cert.pem"))
                .arg(mode)
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());
            apply_profile_sink(&mut cmd, self.profile_sink.as_deref());
            Ok(cmd)
        }
    }

    fn expected_tree(session: &str, mode: &str) -> BTreeSet<String> {
        let mut keys: BTreeSet<String> = ["src", "src/lib.txt", "stub_agent.sh", "out.txt", "results"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let mut tools = vec![ALLOW_TOOL];
        if mode.starts_with("deny") {
            tools.push(DENY_TOOL);
        }
        for t in tools {
            for ext in ["status", "body", "curl_err"] {
                keys.insert(format!("results/{t}.{ext}"));
            }
        }
        let _ = session;
        keys
    }

    fn file(tree: &BTreeMap<String, Entry>, key: &str) -> String {
        match tree.get(key) {
            Some(Entry::File(b)) => String::from_utf8_lossy(b).into_owned(),
            other => panic!("expected file at {key}, got {other:?}"),
        }
    }

    /// The exact-change-set oracle must see an arbitrary file whose name merely
    /// ends in `.profraw`; only the external sink may keep profiles out of the tree.
    #[test]
    fn snapshot_detects_an_arbitrary_profraw_file_as_an_unapproved_change() {
        let tree = tempfile::tempdir().expect("tempdir");
        copy_fixture(tree.path()).expect("fixture");
        let before = snapshot(tree.path());

        std::fs::write(tree.path().join("unexpected.profraw"), b"not a profile").expect("write");

        let after = snapshot(tree.path());
        assert_ne!(before, after, "an unexpected .profraw file must change the snapshot");
        assert_eq!(
            after.get("unexpected.profraw"),
            Some(&Entry::File(b"not a profile".to_vec()))
        );
    }

    /// A `.profraw`-named directory is not a free pass for what it contains.
    #[test]
    fn snapshot_detects_an_unapproved_file_inside_a_profraw_directory() {
        let tree = tempfile::tempdir().expect("tempdir");
        copy_fixture(tree.path()).expect("fixture");
        let before = snapshot(tree.path());

        let dir = tree.path().join("unexpected.profraw");
        std::fs::create_dir(&dir).expect("mkdir");
        std::fs::write(dir.join("child.rs"), b"fn unapproved() {}").expect("write");

        let after = snapshot(tree.path());
        assert_ne!(before, after, "a .profraw directory subtree must change the snapshot");
        assert_eq!(after.get("unexpected.profraw"), Some(&Entry::Dir));
        assert_eq!(
            after.get("unexpected.profraw/child.rs"),
            Some(&Entry::File(b"fn unapproved() {}".to_vec()))
        );
    }

    /// The sink validator accepts only an absolute pattern whose directory
    /// resolves outside the fixture tree, and an unset variable forwards nothing.
    #[test]
    fn profile_sink_validation_accepts_only_an_external_absolute_pattern() {
        let tree = tempfile::tempdir().expect("tempdir");
        copy_fixture(tree.path()).expect("fixture");
        let sink_dir = tempfile::tempdir().expect("sink dir");

        let pattern = sink_dir.path().join("cov").join("aa-%p-%m.profraw");
        let sink = validated_profile_sink(Some(pattern.clone().into_os_string()), tree.path())
            .expect("external sink is valid")
            .expect("sink present");
        let resolved = sink_dir
            .path()
            .canonicalize()
            .expect("canonical")
            .join("cov")
            .join("aa-%p-%m.profraw");
        assert_eq!(sink, resolved, "directory is resolved, file name text is unchanged");
        assert!(pattern.parent().expect("dir").is_dir(), "harness creates the sink dir");

        let inside = tree.path().join("aa-%p.profraw");
        assert!(validated_profile_sink(Some(inside.into_os_string()), tree.path()).is_err());
        assert!(validated_profile_sink(Some("relative/aa.profraw".into()), tree.path()).is_err());
        assert_eq!(validated_profile_sink(None, tree.path()).expect("unset"), None);
    }

    fn assert_refused(result: io::Result<Option<PathBuf>>) {
        let err = result.expect_err("sink must be refused");
        assert_eq!(
            err.kind(),
            io::ErrorKind::InvalidInput,
            "refused for the wrong reason: {err}"
        );
    }

    /// A concrete external file name that is a symlink into the tree would let
    /// the profile writer follow it into the fixture.
    #[test]
    fn profile_sink_refuses_an_external_leaf_symlink_into_the_tree() {
        let tree = tempfile::tempdir().expect("tempdir");
        copy_fixture(tree.path()).expect("fixture");
        let ext = tempfile::tempdir().expect("ext");
        let leaf = ext.path().join("leaf.profraw");
        std::os::unix::fs::symlink(tree.path().join("src/lib.txt"), &leaf).expect("symlink");

        assert_refused(validated_profile_sink(Some(leaf.into_os_string()), tree.path()));
    }

    /// A symlinked directory component resolves into the tree even though the
    /// spelled path looks external.
    #[test]
    fn profile_sink_refuses_a_symlinked_directory_into_the_tree() {
        let tree = tempfile::tempdir().expect("tempdir");
        copy_fixture(tree.path()).expect("fixture");
        let ext = tempfile::tempdir().expect("ext");
        let lnk = ext.path().join("lnk");
        std::os::unix::fs::symlink(tree.path(), &lnk).expect("symlink");

        assert_refused(validated_profile_sink(
            Some(lnk.join("aa-%p.profraw").into_os_string()),
            tree.path(),
        ));
    }

    /// The fixture root is canonicalised too: naming it through an alias must
    /// not hide an in-tree sink spelled the canonical way (macOS `/var` vs
    /// `/private/var` is the same shape).
    #[test]
    fn profile_sink_refuses_an_in_tree_dir_when_the_root_is_given_as_an_alias() {
        let tree = tempfile::tempdir().expect("tempdir");
        copy_fixture(tree.path()).expect("fixture");
        let ext = tempfile::tempdir().expect("ext");
        let alias = ext.path().join("alias");
        std::os::unix::fs::symlink(tree.path(), &alias).expect("symlink");
        let canonical_tree = tree.path().canonicalize().expect("canonical");

        assert_refused(validated_profile_sink(
            Some(canonical_tree.join("aa-%p.profraw").into_os_string()),
            &alias,
        ));
    }

    /// LLVM expands tokens in directory components too, so the validated
    /// directory would not be where profiles land.
    #[test]
    fn profile_sink_refuses_a_token_in_a_directory_component() {
        let tree = tempfile::tempdir().expect("tempdir");
        copy_fixture(tree.path()).expect("fixture");
        let ext = tempfile::tempdir().expect("ext");

        assert_refused(validated_profile_sink(
            Some(ext.path().join("%p").join("a.profraw").into_os_string()),
            tree.path(),
        ));
    }

    /// `..` would let a literal-looking directory resolve somewhere else.
    #[test]
    fn profile_sink_refuses_a_parent_dir_component() {
        let tree = tempfile::tempdir().expect("tempdir");
        copy_fixture(tree.path()).expect("fixture");
        let ext = tempfile::tempdir().expect("ext");
        let sneaky = ext.path().join("cov").join("..").join("a.profraw");

        assert_refused(validated_profile_sink(Some(sneaky.into_os_string()), tree.path()));
    }

    /// A refused sink must leave nothing behind: not a new in-tree directory,
    /// and not one reached through a dangling symlink that points into the tree.
    #[test]
    fn profile_sink_refusal_creates_no_directories() {
        let tree = tempfile::tempdir().expect("tempdir");
        copy_fixture(tree.path()).expect("fixture");
        let ext = tempfile::tempdir().expect("ext");

        let literal = tree.path().join("newdir");
        assert_refused(validated_profile_sink(
            Some(literal.join("aa-%p.profraw").into_os_string()),
            tree.path(),
        ));
        assert!(!literal.exists(), "an in-tree sink directory must not be created");

        let target = tree.path().join("viadangling");
        let lnk = ext.path().join("dangling");
        std::os::unix::fs::symlink(&target, &lnk).expect("symlink");
        assert_refused(validated_profile_sink(
            Some(lnk.join("aa-%p.profraw").into_os_string()),
            tree.path(),
        ));
        assert!(!target.exists(), "creation must not go through a dangling symlink");
    }

    /// What `cargo llvm-cov` actually sets: tokens only in the file name. The
    /// file name is forwarded verbatim (so `%m`/`%p` still expand) under the
    /// resolved directory.
    #[test]
    fn profile_sink_accepts_a_file_name_token_pattern_and_keeps_the_tokens() {
        let tree = tempfile::tempdir().expect("tempdir");
        copy_fixture(tree.path()).expect("fixture");
        let ext = tempfile::tempdir().expect("ext");
        let pattern = ext.path().join("cov").join("default_%m_%p.profraw");

        let sink = validated_profile_sink(Some(pattern.into_os_string()), tree.path())
            .expect("valid")
            .expect("present");
        assert_eq!(
            sink,
            ext.path()
                .canonicalize()
                .expect("canonical")
                .join("cov")
                .join("default_%m_%p.profraw")
        );
    }

    /// A token-free external file name that already exists as a regular file is
    /// a legitimate sink.
    #[test]
    fn profile_sink_accepts_an_existing_external_regular_file() {
        let tree = tempfile::tempdir().expect("tempdir");
        copy_fixture(tree.path()).expect("fixture");
        let ext = tempfile::tempdir().expect("ext");
        let pattern = ext.path().join("existing.profraw");
        std::fs::write(&pattern, b"old").expect("write");

        let sink = validated_profile_sink(Some(pattern.into_os_string()), tree.path())
            .expect("valid")
            .expect("present");
        assert_eq!(
            sink,
            ext.path().canonicalize().expect("canonical").join("existing.profraw")
        );
    }

    /// Variables the sanitised launch sets itself; anything else crossing in is
    /// a leak the exact-change-set oracle was not written to tolerate.
    const LAUNCH_ENV: [&str; 9] = [
        "PATH",
        "HOME",
        "AASM_STATE_DIR",
        "AA_CA_DIR",
        "AA_DATA_DIR",
        "AA_GATEWAY_ENDPOINT",
        "AA_TEST_PROXY_UPSTREAM",
        "AA_PROXY_LLM_ONLY",
        "AA_PROXY_SKIP_UPSTREAM_TLS_VERIFY",
    ];

    fn launch_env(cmd: &Command) -> BTreeMap<String, Option<String>> {
        cmd.get_envs()
            .map(|(k, v)| {
                (
                    k.to_string_lossy().into_owned(),
                    v.map(|v| v.to_string_lossy().into_owned()),
                )
            })
            .collect()
    }

    /// The real `Host::launch` environment, with an external sink: the one
    /// extra variable is the validated pattern, `env_clear` still applies, and
    /// nothing else is added. Deleting the forward in `launch`, or adding any
    /// further `.env()`, changes this key set and fails here.
    #[tokio::test(flavor = "multi_thread")]
    async fn launch_forwards_only_the_validated_profile_sink() -> anyhow::Result<()> {
        let sink_dir = tempfile::tempdir()?;
        let pattern = sink_dir.path().join("cov").join("aa-%p-%m.profraw");
        let resolved = sink_dir.path().canonicalize()?.join("cov").join("aa-%p-%m.profraw");
        let host = Host::start_with_profile_env(false, Some(pattern.clone().into_os_string())).await?;
        let project = host.root.join("project");
        copy_fixture(&project)?;

        let cmd = host.launch_command("aaasm6297-env", &project, "allow")?;
        let env = launch_env(&cmd);

        let mut expected: BTreeSet<String> = LAUNCH_ENV.iter().map(|k| k.to_string()).collect();
        expected.insert(PROFILE_ENV.to_string());
        assert_eq!(env.keys().cloned().collect::<BTreeSet<_>>(), expected);
        assert_eq!(
            env.get(PROFILE_ENV),
            Some(&Some(resolved.to_string_lossy().into_owned())),
            "the resolved sink with the original file name pattern is forwarded"
        );
        assert!(
            format!("{cmd:?}").contains(" env -i "),
            "launch must stay env_clear'ed: {cmd:?}"
        );
        Ok(())
    }

    /// Ordinary lane: with no sink the real launch environment carries no
    /// coverage variable at all.
    #[tokio::test(flavor = "multi_thread")]
    async fn launch_without_a_profile_sink_forwards_nothing() -> anyhow::Result<()> {
        let host = Host::start_with_profile_env(false, None).await?;
        let project = host.root.join("project");
        copy_fixture(&project)?;

        let cmd = host.launch_command("aaasm6297-env", &project, "allow")?;
        let env = launch_env(&cmd);

        assert_eq!(
            env.keys().cloned().collect::<BTreeSet<_>>(),
            LAUNCH_ENV.iter().map(|k| k.to_string()).collect::<BTreeSet<_>>()
        );
        assert!(!env.contains_key(PROFILE_ENV));
        Ok(())
    }

    /// The composite stub workflow: edit + shell + allowed call + DENIED call,
    /// inside one transactional workspace.
    #[tokio::test(flavor = "multi_thread")]
    async fn stub_agent_edit_shell_and_denied_call_commit_exactly_the_change_set_and_denial_is_policy_caused(
    ) -> anyhow::Result<()> {
        let host = Host::start(false).await?;
        let project = host.root.join("project");
        copy_fixture(&project)?;
        let initial = snapshot(&project);

        let out = host.launch("aaasm6297-stub-a", &project, "deny")?.wait_with_output()?;
        let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
        assert!(
            out.status.success(),
            "stub run failed; stderr tail:\n{}",
            tail(&stderr, 60)
        );
        assert!(
            stderr.contains("workspace_tx.committed=true"),
            "expected a committed workspace_tx block; stderr:\n{}",
            tail(&stderr, 60)
        );

        // ── the workspace commit applied exactly this agent's change set ──
        let after = snapshot(&project);
        assert_eq!(
            after.keys().cloned().collect::<BTreeSet<_>>(),
            expected_tree("a", "deny"),
            "base tree key set after commit"
        );
        assert_eq!(
            file(&after, "src/lib.txt"),
            "original content\nstub-edit-by-aaasm6297-stub-a\n"
        );
        assert_eq!(file(&after, "out.txt"), "built-by-aaasm6297-stub-a\n");
        assert_eq!(
            initial["stub_agent.sh"], after["stub_agent.sh"],
            "unchanged file stays identical"
        );

        // ── the allowed call reached the upstream; the denied one did not ──
        let st = |t: &str| file(&after, &format!("results/{t}.status"));
        assert_eq!(
            st(ALLOW_TOOL).trim(),
            "200",
            "allowed call must succeed: {}",
            file(&after, "results/allow_test.curl_err")
        );
        assert!(file(&after, "results/allow_test.body").contains("allow_test executed"));
        assert!(
            sentinel_path(&host.sentinel_dir, ALLOW_TOOL).exists(),
            "allowed call must reach the MCP server"
        );
        assert!(
            !sentinel_path(&host.sentinel_dir, DENY_TOOL).exists(),
            "the DENIED tool call reached the MCP server -- enforcement failed"
        );
        assert_eq!(
            host.upstream.tool_call_names(),
            [ALLOW_TOOL.to_string()].into_iter().collect(),
            "exactly the allowed tool reached the upstream"
        );
        // The agent saw something other than the success body for the denied call.
        assert!(
            !file(&after, "results/deny_test.body").contains("deny_test executed"),
            "agent-visible response to the denied call must not be the upstream's success"
        );

        // ── the persisted audit record says WHY (policy), attributed to this session ──
        let audits = read_audit(&host.state)?;
        assert_eq!(audits.len(), 1, "one launch => one per-launch audit.jsonl: {audits:?}");
        let blocked: Vec<_> = audits[0]
            .1
            .iter()
            .filter(|e| e.refusal_rule == Some(RefusalRule::McpToolCall))
            .collect();
        assert_eq!(
            blocked.len(),
            1,
            "exactly the one denied call is refused: {:?}",
            audits[0].1
        );
        assert_eq!(blocked[0].decision, ProxyAuditDecision::Blocked);
        assert_eq!(blocked[0].agent_id.as_deref(), Some("aaasm6297-stub-a"));

        // ── receipt truth: --isolation none => no confinement => NO receipt ──
        let receipts = host.state.join("execution-receipts");
        let n = std::fs::read_dir(&receipts).map(|r| r.count()).unwrap_or(0);
        assert_eq!(
            n, 0,
            "an unconfined (--isolation none) launch must not write an execution receipt"
        );
        eprintln!("STUB-ONLY evidence. aasm stderr tail:\n{}", tail(&stderr, 25));
        Ok(())
    }

    /// Paired control: identical harness, ONE property flipped (`deny_test`
    /// allow:false -> allow:true). The call must now reach the upstream, which
    /// proves the denial above is the policy's doing and not an upstream /
    /// proxy unavailability that would also have kept the sentinel absent.
    #[tokio::test(flavor = "multi_thread")]
    async fn stub_control_flipping_only_the_policy_lets_the_same_call_through() -> anyhow::Result<()> {
        let host = Host::start(true).await?;
        let project = host.root.join("project");
        copy_fixture(&project)?;
        let out = host
            .launch("aaasm6297-stub-ctl", &project, "deny")?
            .wait_with_output()?;
        let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
        assert!(
            out.status.success(),
            "stub run failed; stderr tail:\n{}",
            tail(&stderr, 60)
        );
        let after = snapshot(&project);
        assert_eq!(file(&after, "results/deny_test.status").trim(), "200");
        assert!(
            sentinel_path(&host.sentinel_dir, DENY_TOOL).exists(),
            "with the policy flipped the call must reach the upstream"
        );
        let blocked = read_audit(&host.state)?
            .into_iter()
            .flat_map(|(_, e)| e)
            .filter(|e| e.refusal_rule == Some(RefusalRule::McpToolCall))
            .count();
        assert_eq!(
            blocked, 0,
            "no McpToolCall refusal may be recorded when policy allows the call"
        );
        Ok(())
    }

    /// Two genuinely concurrent sessions (distinct agent ids, distinct
    /// projects, ONE shared state dir): each base receives only its own
    /// change set, and the denied call -- made by session A only -- is
    /// attributed to A and never to B.
    #[tokio::test(flavor = "multi_thread")]
    async fn stub_concurrent_sessions_do_not_cross_attribute_edits_or_denials() -> anyhow::Result<()> {
        let host = Host::start(false).await?;
        let (pa, pb) = (host.root.join("project-a"), host.root.join("project-b"));
        copy_fixture(&pa)?;
        copy_fixture(&pb)?;

        // both spawned before either is awaited
        let a = host.launch("aaasm6297-stub-A", &pa, "deny")?;
        let b = host.launch("aaasm6297-stub-B", &pb, "allow")?;
        let (oa, ob) = (a.wait_with_output()?, b.wait_with_output()?);
        for (n, o) in [("A", &oa), ("B", &ob)] {
            let e = String::from_utf8_lossy(&o.stderr).into_owned();
            assert!(o.status.success(), "session {n} failed; stderr tail:\n{}", tail(&e, 60));
            assert!(
                e.contains("workspace_tx.committed=true"),
                "session {n} stderr:\n{}",
                tail(&e, 60)
            );
        }

        let (ta, tb) = (snapshot(&pa), snapshot(&pb));
        assert_eq!(
            file(&ta, "src/lib.txt"),
            "original content\nstub-edit-by-aaasm6297-stub-A\n"
        );
        assert_eq!(
            file(&tb, "src/lib.txt"),
            "original content\nstub-edit-by-aaasm6297-stub-B\n"
        );
        assert_eq!(file(&ta, "out.txt"), "built-by-aaasm6297-stub-A\n");
        assert_eq!(file(&tb, "out.txt"), "built-by-aaasm6297-stub-B\n");
        assert_eq!(ta.keys().cloned().collect::<BTreeSet<_>>(), expected_tree("A", "deny"));
        assert_eq!(tb.keys().cloned().collect::<BTreeSet<_>>(), expected_tree("B", "allow"));
        assert!(
            !tb.contains_key("results/deny_test.status"),
            "B never attempted the denied call"
        );

        // Attribution. A run's audit dir is named after its own agent id, so the
        // file -> session mapping does not depend on the entries' content. The
        // proxy audit records only refusals here (an allowed call writes no
        // entry), so B's file being EMPTY is the expected, positive-shaped
        // result: B made no denied call and nothing is attributed to it.
        let audits = read_audit(&host.state)?;
        assert_eq!(
            audits.len(),
            2,
            "two launches => two per-launch audit files: {audits:?}"
        );
        let mut by_agent: BTreeMap<String, Vec<ProxyAuditEntry>> = BTreeMap::new();
        for (path, entries) in audits {
            let dir = path
                .parent()
                .unwrap()
                .file_name()
                .unwrap()
                .to_string_lossy()
                .into_owned();
            let who = if dir.starts_with("aaasm6297-stub-A-") {
                "A"
            } else if dir.starts_with("aaasm6297-stub-B-") {
                "B"
            } else {
                panic!("unexpected run dir {dir}")
            };
            by_agent.insert(who.to_string(), entries);
        }
        eprintln!("STUB-ONLY audit entries by session: {by_agent:#?}");
        let a_refusals: Vec<_> = by_agent["A"]
            .iter()
            .filter(|e| e.refusal_rule == Some(RefusalRule::McpToolCall))
            .collect();
        assert_eq!(a_refusals.len(), 1, "A's one denied call: {:?}", by_agent["A"]);
        assert_eq!(a_refusals[0].agent_id.as_deref(), Some("aaasm6297-stub-A"));
        assert!(
            by_agent["A"]
                .iter()
                .all(|e| e.agent_id.as_deref() == Some("aaasm6297-stub-A")),
            "every entry in A's file is A's: {:?}",
            by_agent["A"]
        );
        assert!(
            by_agent["B"]
                .iter()
                .all(|e| e.agent_id.as_deref() == Some("aaasm6297-stub-B")),
            "nothing foreign in B's file: {:?}",
            by_agent["B"]
        );
        assert_eq!(
            by_agent["B"].iter().filter(|e| e.refusal_rule.is_some()).count(),
            0,
            "B made no denied call, so no refusal may be attributed to it: {:?}",
            by_agent["B"]
        );
        assert_eq!(
            host.upstream.tool_call_names(),
            [ALLOW_TOOL.to_string()].into_iter().collect(),
            "only the allowed tool ever reached the upstream across both sessions"
        );
        Ok(())
    }

    /// A failing session leaves the base byte-for-byte unchanged (discard) even
    /// though it edited, ran a command, was allowed one call and was denied
    /// another. The out-of-workspace side effect (the allowed call reaching the
    /// upstream) is NOT rolled back, and the run says so.
    #[tokio::test(flavor = "multi_thread")]
    async fn stub_failed_session_is_discarded_and_base_stays_untouched() -> anyhow::Result<()> {
        let host = Host::start(false).await?;
        let project = host.root.join("project");
        copy_fixture(&project)?;
        let before = snapshot(&project);

        let out = host
            .launch("aaasm6297-stub-fail", &project, "deny-fail")?
            .wait_with_output()?;
        let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
        assert_eq!(
            out.status.code(),
            Some(7),
            "the agent's own exit code is propagated; stderr:\n{}",
            tail(&stderr, 40)
        );
        assert_eq!(
            snapshot(&project),
            before,
            "a failed session must leave the base tree untouched"
        );
        assert!(
            stderr.contains("workspace_tx.committed=false"),
            "a failed session must report committed=false; stderr:\n{}",
            tail(&stderr, 40)
        );
        assert!(!stderr.contains("workspace_tx.committed=true"));
        assert!(
            stderr.contains("workspace_tx.not_transactional"),
            "non-coverage must be stated:\n{}",
            tail(&stderr, 40)
        );
        // the agent really ran (control: the discard is not 'it never started')
        assert!(
            sentinel_path(&host.sentinel_dir, ALLOW_TOOL).exists(),
            "allowed call happened outside the workspace and is not undone"
        );
        assert!(!sentinel_path(&host.sentinel_dir, DENY_TOOL).exists());
        Ok(())
    }
}

#[cfg(target_os = "macos")]
mod stub_claude_isolation {
    //! AAASM-6297 AC3: `aasm run --isolation process -- claude` on macOS must
    //! refuse CLEANLY. The `claude` here is a STUB shell script placed on a
    //! PATH that EXCLUDES the real `/opt/homebrew/bin`, so a regression runs
    //! the stub (leaving a marker), never the real agent.
    use std::path::Path;
    use std::process::{Command, Stdio};

    use super::grpc_gateway_support::GrpcGateway;
    use super::proxy_trust_support::{self, TrustedProxy};

    fn policy(dir: &Path) -> std::path::PathBuf {
        let path = dir.join("policy.yaml");
        std::fs::write(
            &path,
            "apiVersion: agent-assembly/v1\nkind: Policy\nmetadata:\n  name: aaasm6297-claude-stub\nspec:\n  tools:\n    \
             read_file:\n      allow: true\n",
        )
        .unwrap();
        path
    }

    fn run(
        isolation: &[&str],
    ) -> (
        std::process::Output,
        std::path::PathBuf,
        std::path::PathBuf,
        tempfile::TempDir,
    ) {
        use std::os::unix::fs::PermissionsExt;
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap();
        let proxy = TrustedProxy::start().unwrap();
        let gateway = rt.block_on(GrpcGateway::start()).unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let bin = root.join("stubbin");
        let project = root.join("project");
        let state = root.join("state");
        let home = root.join("home");
        for d in [&bin, &project, &home] {
            std::fs::create_dir_all(d).unwrap();
        }
        let stub = bin.join("claude");
        // Answers the adapter's `--version` detection probe in the real
        // format but writes the marker ONLY for any other argv, so the marker
        // proves a LAUNCH, never merely a probe.
        std::fs::write(
            &stub,
            "#!/bin/sh\nif [ \"$1\" = \"--version\" ]; then echo '2.1.236 (Claude Code)'; exit 0; fi\n\
             echo \"STUB-CLAUDE-LAUNCHED $*\" > \"$PWD/claude-stub-ran.marker\"\n",
        )
        .unwrap();
        std::fs::set_permissions(&stub, std::fs::Permissions::from_mode(0o755)).unwrap();
        let aa_proxy_dir = proxy_trust_support::aa_proxy_binary().parent().unwrap().to_path_buf();
        let policy = policy(root);
        let out = Command::new(proxy.aasm())
            .env_clear()
            .current_dir(&project)
            .env(
                "PATH",
                format!("{}:{}:/usr/bin:/bin", bin.display(), aa_proxy_dir.display()),
            )
            .env("HOME", &home)
            .env("AASM_STATE_DIR", &state)
            .env("AA_CA_DIR", root.join("ca"))
            .env("AA_DATA_DIR", proxy.data_dir())
            .env("AA_GATEWAY_ENDPOINT", gateway.endpoint())
            .args(["run", "--policy"])
            .arg(&policy)
            .args(["--agent-id", "aaasm6297-claude-stub"])
            .args(isolation)
            .args(["claude", "--", "--aaasm6297-launch"])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .unwrap();
        (out, project, state, tmp)
    }

    /// POSITIVE control: with NO isolation the same stub IS launched through the
    /// same harness, so "marker absent" under `--isolation process` cannot be
    /// explained by the harness being unable to run the stub at all.
    #[test]
    fn stub_control_isolation_none_launches_the_stub_claude() {
        let (out, project, _state, _tmp) = run(&["--isolation", "none"]);
        let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
        assert!(
            project.join("claude-stub-ran.marker").exists(),
            "control: stub must run under --isolation none. status={:?}\nstderr:\n{}",
            out.status,
            super::stub_coding_agent_tail(&stderr)
        );
    }

    #[test]
    fn stub_isolation_process_refuses_cleanly_and_never_runs_the_agent() {
        let (out, project, state, _tmp) = run(&["--isolation", "process"]);
        let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
        assert!(
            !out.status.success(),
            "must refuse; stderr:\n{}",
            super::stub_coding_agent_tail(&stderr)
        );
        assert!(
            stderr.contains("backend cannot be selected on this host"),
            "must refuse with the isolation-specific reason, not an unrelated failure:\n{}",
            super::stub_coding_agent_tail(&stderr)
        );
        assert!(
            !project.join("claude-stub-ran.marker").exists(),
            "the (stub) agent must NOT have been started"
        );
        let n = std::fs::read_dir(state.join("execution-receipts"))
            .map(|d| d.count())
            .unwrap_or(0);
        assert_eq!(n, 0, "a refused launch writes no receipt");
        eprintln!(
            "STUB-ONLY refusal stderr tail:\n{}",
            super::stub_coding_agent_tail(&stderr)
        );
    }
}

#[cfg(not(unix))]
#[test]
fn stub_coding_agent_workflow_is_not_measured_on_this_host() {
    eprintln!("NOT MEASURED: stub coding-agent workflow requires a unix host");
}
