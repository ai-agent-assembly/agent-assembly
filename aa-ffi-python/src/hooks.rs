//! Hook registry — discovers and installs Python hook modules for detected frameworks.
//!
//! After `detect_frameworks()` identifies which AI frameworks are loaded in the
//! Python process, `install_hooks()` attempts to import the corresponding
//! `aa_hooks.<framework>` Python module and call its `install(handle)` function.
//!
//! Gracefully degrades: if a hook module is missing or its `install()` raises,
//! we log a warning and skip — never propagate the error.

use pyo3::prelude::*;
use pyo3::types::PyList;

use crate::handle::AssemblyHandle;

/// Maps detected framework name → Python hook module path.
const HOOK_MODULES: &[(&str, &str)] = &[
    ("openai", "aa_hooks.openai"),
    ("langgraph", "aa_hooks.langgraph"),
    ("openai-agents", "aa_hooks.openai_agents"),
    ("mcp", "aa_hooks.mcp"),
    // Future adapters:
    // ("anthropic", "aa_hooks.anthropic"),
    // ("langchain", "aa_hooks.langchain"),
];

/// Ensure the `aa_hooks` package directory is on `sys.path`.
///
/// Adds `<crate>/python` to `sys.path` if not already present, so that
/// `import aa_hooks.openai` resolves to the in-tree Python hook modules.
fn ensure_hooks_on_path(py: Python<'_>) -> PyResult<()> {
    let hooks_dir = concat!(env!("CARGO_MANIFEST_DIR"), "/python");
    let sys = py.import("sys")?;
    let path = sys.getattr("path")?.cast_into::<PyList>()?;

    // Check if already present.
    let already = path
        .iter()
        .any(|entry| entry.extract::<String>().map(|s| s == hooks_dir).unwrap_or(false));

    if !already {
        path.insert(0, hooks_dir)?;
    }

    Ok(())
}

/// Attempt to install Python hook modules for each detected framework.
///
/// Returns the list of framework names for which hooks were successfully installed.
/// Never propagates Python exceptions — logs warnings and skips on failure.
pub fn install_hooks(py: Python<'_>, handle: &Bound<'_, AssemblyHandle>, detected: &[String]) -> Vec<String> {
    // Add the in-tree Python hook package to sys.path.
    if let Err(e) = ensure_hooks_on_path(py) {
        tracing::warn!(error = %e, "failed to add aa_hooks to sys.path; hooks will not be installed");
        return Vec::new();
    }

    let mut installed = Vec::new();

    for (framework, module_path) in HOOK_MODULES {
        if !detected.iter().any(|d| d == framework) {
            continue;
        }

        match py.import(module_path) {
            Ok(module) => match module.call_method1("install", (handle,)) {
                Ok(_) => {
                    tracing::info!(framework = %framework, module = %module_path, "hook installed");
                    installed.push(framework.to_string());
                }
                Err(e) => {
                    tracing::warn!(
                        framework = %framework,
                        error = %e,
                        "hook install() failed; skipping"
                    );
                }
            },
            Err(e) => {
                tracing::warn!(
                    framework = %framework,
                    module = %module_path,
                    error = %e,
                    "hook module not found; skipping"
                );
            }
        }
    }

    installed
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hook_modules_table_is_nonempty() {
        assert!(!HOOK_MODULES.is_empty());
    }

    #[test]
    fn hook_modules_entries_are_valid() {
        for &(framework, module_path) in HOOK_MODULES {
            assert!(!framework.is_empty());
            assert!(module_path.starts_with("aa_hooks."));
        }
    }

    /// Helper: create a test handle for use in hook installation tests.
    fn test_handle() -> AssemblyHandle {
        let (tx, _rx) = tokio::sync::mpsc::channel(16);
        let ipc = crate::ipc::IpcHandle {
            cmd_tx: tx,
            thread: None,
        };
        AssemblyHandle::new(ipc, vec!["openai".to_string()])
    }

    #[test]
    fn install_hooks_no_frameworks_is_noop() {
        pyo3::Python::initialize();
        Python::attach(|py| {
            let handle = Py::new(py, test_handle()).unwrap();
            let installed = install_hooks(py, handle.bind(py), &[]);
            assert!(installed.is_empty());
        });
    }

    #[test]
    fn install_hooks_unknown_framework_skips() {
        pyo3::Python::initialize();
        Python::attach(|py| {
            let handle = Py::new(py, test_handle()).unwrap();
            let detected = vec!["pytorch".to_string()];
            let installed = install_hooks(py, handle.bind(py), &detected);
            assert!(installed.is_empty());
        });
    }

    #[test]
    fn install_hooks_openai_without_openai_package_degrades() {
        // When the openai Python package is not installed, the hook's
        // install() will fail — but install_hooks should degrade gracefully.
        pyo3::Python::initialize();
        Python::attach(|py| {
            let handle = Py::new(py, test_handle()).unwrap();
            let detected = vec!["openai".to_string()];
            let installed = install_hooks(py, handle.bind(py), &detected);
            // The hook module (aa_hooks.openai) will be found (it's in-tree),
            // but install() will try to import the openai package which may
            // not be installed in the test environment. Either way, no panic.
            // We just verify it returns without error.
            assert!(installed.len() <= 1);
        });
    }
}
