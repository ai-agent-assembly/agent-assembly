//! Shared atomic JSON-file persistence helpers for approval stores.

use std::path::Path;

/// Atomically write `value` as pretty-printed JSON to `path`.
///
/// Creates parent directories if absent, writes to `<path>.tmp`, then renames.
/// Accepts `map_io` and `map_json` function pointers so callers can map into
/// their own error types without the helper knowing about them.
pub(super) fn write_json_atomic<T, E>(
    path: &Path,
    value: &T,
    map_io: fn(std::io::Error) -> E,
    map_json: fn(serde_json::Error) -> E,
) -> Result<(), E>
where
    T: serde::Serialize,
{
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(map_io)?;
    }
    let json = serde_json::to_string_pretty(value).map_err(map_json)?;
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, &json).map_err(map_io)?;
    std::fs::rename(&tmp, path).map_err(map_io)?;
    Ok(())
}
