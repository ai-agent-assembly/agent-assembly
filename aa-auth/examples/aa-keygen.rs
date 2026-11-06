//! `aa-keygen` (a cargo example, `cargo run -p aa-auth --example aa-keygen`) — issue an operator API key bound to an organization (AAASM-6444).
//!
//! The gateway binds an agent registration, and `GET /api/v1/logs`, to the
//! organization of the `aa_…` key presented. This appends such a key's entry
//! (argon2 hash only) to the key file named by `AA_API_KEYS_PATH` and writes the
//! raw key to a separate owner-only file. The raw key is never printed, so it
//! does not land in a terminal, log or transcript.
//!
//! The gateway reads the key file once at boot: a key added here, or revoked by
//! removing its entry, takes effect after the gateway restarts.
//!
//! ```text
//! aa-keygen --keys-file keys.json --key-out acme.key --org acme [--team t] [--scope read|write|admin]...
//! ```

use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;

use aa_auth::api_key::{ApiKey, ApiKeyEntry};
use aa_auth::scope::Scope;

fn main() {
    if let Err(message) = run(std::env::args().skip(1).collect()) {
        eprintln!("aa-keygen: {message}");
        std::process::exit(2);
    }
}

fn run(args: Vec<String>) -> Result<(), String> {
    let (mut keys_file, mut key_out, mut org, mut team) = (None, None, None, None);
    let mut scopes = Vec::new();
    let mut it = args.into_iter();
    while let Some(flag) = it.next() {
        let mut value = || it.next().ok_or_else(|| format!("{flag} needs a value"));
        match flag.as_str() {
            "--keys-file" => keys_file = Some(value()?),
            "--key-out" => key_out = Some(value()?),
            "--org" => org = Some(value()?),
            "--team" => team = Some(value()?),
            "--scope" => scopes.push(match value()?.as_str() {
                "read" => Scope::Read,
                "write" => Scope::Write,
                "admin" => Scope::Admin,
                other => return Err(format!("unknown scope {other:?}")),
            }),
            other => return Err(format!("unknown argument {other:?}")),
        }
    }
    let keys_file = keys_file.ok_or("--keys-file is required")?;
    let key_out = key_out.ok_or("--key-out is required")?;
    // An empty org (or team) serialises as an empty string, which the gateway reads as
    // "bound to nothing": the key would be an unbound key the operator thinks is bound.
    if org.as_deref().is_some_and(str::is_empty) || team.as_deref().is_some_and(str::is_empty) {
        return Err("--org and --team must not be empty; omit the flag for an unbound key".into());
    }
    if std::path::Path::new(&key_out).exists() {
        return Err(format!(
            "{key_out} already exists; refusing to overwrite a raw key file"
        ));
    }
    if scopes.is_empty() {
        scopes.push(Scope::Read);
    }

    let key = ApiKey::generate();
    let entry = ApiKeyEntry {
        id: format!("keygen-{}", key.lookup()),
        key_hash: key.hash().map_err(|e| e.to_string())?,
        scopes,
        created_at: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
        expires_at: None,
        label: org.as_ref().map(|o| format!("org {o}")),
        team_id: team,
        org_id: org,
        key_lookup: Some(key.lookup()),
    };

    let mut entries: Vec<ApiKeyEntry> = match std::fs::read_to_string(&keys_file) {
        Ok(text) => serde_json::from_str(&text).map_err(|e| format!("{keys_file}: {e}"))?,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
        Err(e) => return Err(format!("{keys_file}: {e}")),
    };
    entries.push(entry);

    // The key file is replaced atomically (temp file in the same directory, then rename)
    // so a crash never leaves a truncated key store, and the raw key file is created only
    // after that succeeded, so a failed write leaves neither an entry nor an orphan key.
    let keys_path = std::path::Path::new(&keys_file);
    let tmp = keys_path.with_extension(format!("tmp{}", std::process::id()));
    std::fs::write(&tmp, serde_json::to_vec_pretty(&entries).map_err(|e| e.to_string())?)
        .map_err(|e| format!("{}: {e}", tmp.display()))?;
    std::fs::rename(&tmp, keys_path).map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        format!("{keys_file}: {e}")
    })?;

    let mut out = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&key_out)
        .map_err(|e| format!("{key_out}: {e}"))?;
    out.write_all(key.as_str().as_bytes()).map_err(|e| e.to_string())?;
    Ok(())
}
