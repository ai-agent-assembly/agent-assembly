//! CLI integration tests for `aasm alerts` (AAASM-1460 / F121 ST-4).
//!
//! Exercises every `aasm alerts <leaf>` subcommand against a live
//! in-process gateway booted via `CliFixture`. For each leaf: happy path,
//! every `--output` format (json / yaml / table), and per-flag toggles.
//!
//! ## Leaf surface (from `aa-cli/src/commands/alerts/`)
//!
//! | Leaf    | Args         | Flags                          | Output shape                |
//! | ------- | ------------ | ------------------------------ | --------------------------- |
//! | list    | —            | `--agent`, `--severity`, `--status` | array of `AlertResponse`  |
//! | get     | `<alert_id>` | —                              | one `AlertResponse`         |
//! | resolve | `<alert_id>` | `--reason`, `--force`          | one `AlertResponse`         |
//!
//! ## Gateway-coverage gap (tracked by AAASM-1474)
//!
//! Only `GET /api/v1/alerts` is wired up in `aa-api/src/routes/alerts.rs`.
//! `GET /alerts/:id` and `POST /alerts/:id/resolve` are not implemented,
//! so the `get` / `resolve` **happy-path** tests in this file are
//! `#[ignore]`d with a doc-comment pointer to AAASM-1474. Once those
//! endpoints land, drop the `#[ignore]` attributes.
//!
//! The `get <unknown-id>` and `resolve <unknown-id>` **negative-path**
//! tests run unconditionally — they assert non-zero exit and a clean
//! error, which is the correct behaviour regardless of whether the
//! endpoint is missing (current 404) or implemented (future 404).
//!
//! ## Persisted alert shape (current API)
//!
//! `aa-api`'s `AlertResponse` has no `status` field today; the CLI's
//! response model defaults `status` to `"unresolved"` via serde. As a
//! result, `aasm alerts list --status resolved` returns an empty list
//! against any seeded alert. This is also tracked under AAASM-1474.

mod common;

use common::cli::CliFixture;

// =============================================================================
// aasm alerts list
// =============================================================================

#[tokio::test(flavor = "multi_thread")]
async fn alerts_list_happy_path_returns_seeded_records() {
    let fixture = CliFixture::start().await.expect("fixture should start");
    fixture.seed_alert(80, [0x11; 16]);
    fixture.seed_alert(95, [0x22; 16]);
    fixture.seed_alert(70, [0x33; 16]);

    let out = fixture
        .cmd()
        .args(["alerts", "list", "--output", "json"])
        .output()
        .expect("aasm alerts list should execute");
    assert!(
        out.status.success(),
        "should exit 0\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    let v = common::format::parse_json(&out.stdout);
    let arr = v.as_array().expect("list output should be a JSON array");
    assert_eq!(arr.len(), 3, "should return all 3 seeded alerts");
}
