# AAASM-29: `aa-runtime` Bootstrap Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Bootstrap the `aa-runtime` crate with Tokio multi-thread runtime, structured concurrency via `TaskTracker` + `CancellationToken`, graceful SIGTERM/SIGINT shutdown, structured JSON logging, and the full epic module scaffolding.

**Architecture:** `main.rs` initialises tracing then calls `runtime::run(config)`. The `run()` function creates a `TaskTracker` and `CancellationToken`, waits for a shutdown signal via `lifecycle::wait_for_shutdown_signal()`, cancels the token, drains all tracked tasks within a configurable timeout, then exits. Stub modules (`ipc`, `pipeline`, `health`) are declared in `lib.rs` but left empty for AAASM-30/31/32.

**Tech Stack:** Rust 2021 edition, `tokio 1` (full features), `tokio-util 0.7` (TaskTracker + CancellationToken), `tracing 0.1`, `tracing-subscriber 0.3` (json + env-filter)

**Worktree:** `/Users/bryant/Bryant-Developments/ai-agent-assembly/agent-assembly-v0.0.1-AAASM-29-tokio_runtime_init`
**Branch:** `v0.0.1/AAASM-29/tokio_runtime_init`
**All commands run from the worktree root unless stated otherwise.**

---

## Task 1: Add `tokio-util` dependency

**Files:**
- Modify: `aa-runtime/Cargo.toml`

- [ ] **Step 1: Add `tokio-util` to `[dependencies]`**

Open `aa-runtime/Cargo.toml`. The `[dependencies]` section currently reads:

```toml
[dependencies]
aa-core  = { path = "../aa-core" }
aa-proto = { path = "../aa-proto" }
tokio    = { version = "1", features = ["full"] }
```

Add one line for `tokio-util`:

```toml
[dependencies]
aa-core    = { path = "../aa-core" }
aa-proto   = { path = "../aa-proto" }
tokio      = { version = "1", features = ["full"] }
tokio-util = { version = "0.7", features = ["rt"] }
```

- [ ] **Step 2: Verify workspace compiles**

```bash
cargo build -p aa-runtime
```

Expected: builds without errors (only the lib stub compiles).

- [ ] **Step 3: Commit**

```bash
git add aa-runtime/Cargo.toml
git commit -m "🔧 (aa-runtime): Add tokio-util dependency with rt feature"
```

---

## Task 2: Add `tracing` dependency

**Files:**
- Modify: `aa-runtime/Cargo.toml`

- [ ] **Step 1: Add `tracing` to `[dependencies]`**

```toml
[dependencies]
aa-core    = { path = "../aa-core" }
aa-proto   = { path = "../aa-proto" }
tokio      = { version = "1", features = ["full"] }
tokio-util = { version = "0.7", features = ["rt"] }
tracing    = "0.1"
```

- [ ] **Step 2: Verify workspace compiles**

```bash
cargo build -p aa-runtime
```

Expected: builds without errors.

- [ ] **Step 3: Commit**

```bash
git add aa-runtime/Cargo.toml
git commit -m "🔧 (aa-runtime): Add tracing dependency"
```

---

## Task 3: Add `tracing-subscriber` dependency

**Files:**
- Modify: `aa-runtime/Cargo.toml`

- [ ] **Step 1: Add `tracing-subscriber` to `[dependencies]`**

```toml
[dependencies]
aa-core              = { path = "../aa-core" }
aa-proto             = { path = "../aa-proto" }
tokio                = { version = "1", features = ["full"] }
tokio-util           = { version = "0.7", features = ["rt"] }
tracing              = "0.1"
tracing-subscriber   = { version = "0.3", features = ["json", "env-filter"] }
```

- [ ] **Step 2: Verify workspace compiles**

```bash
cargo build -p aa-runtime
```

Expected: builds without errors.

- [ ] **Step 3: Commit**

```bash
git add aa-runtime/Cargo.toml
git commit -m "🔧 (aa-runtime): Add tracing-subscriber with json and env-filter features"
```

---

## Task 4: Add `config` module stub

**Files:**
- Create: `aa-runtime/src/config.rs`
- Modify: `aa-runtime/src/lib.rs`

- [ ] **Step 1: Create empty `config.rs`**

Create `aa-runtime/src/config.rs` with only a module-level doc comment:

```rust
//! Runtime configuration loaded from environment variables.
```

- [ ] **Step 2: Declare `config` module in `lib.rs`**

The current `lib.rs` is:

```rust
//! Tokio async runtime wrapper and agent lifecycle management.
//!
//! This crate wraps `tokio` to provide a consistent async execution environment
//! for Agent Assembly components. It handles runtime initialization, shutdown
//! coordination, and lifecycle hooks.
```

Replace the entire file with:

```rust
//! Tokio async runtime wrapper and agent lifecycle management.
//!
//! This crate wraps `tokio` to provide a consistent async execution environment
//! for Agent Assembly components. It handles runtime initialization, shutdown
//! coordination, and lifecycle hooks.

pub mod config;
```

- [ ] **Step 3: Verify workspace compiles**

```bash
cargo build -p aa-runtime
```

Expected: builds without errors.

- [ ] **Step 4: Commit**

```bash
git add aa-runtime/src/config.rs aa-runtime/src/lib.rs
git commit -m "✨ (aa-runtime): Add config module declaration to lib.rs"
```

---

## Task 5: Add `runtime` module stub

**Files:**
- Create: `aa-runtime/src/runtime.rs`
- Modify: `aa-runtime/src/lib.rs`

- [ ] **Step 1: Create empty `runtime.rs`**

Create `aa-runtime/src/runtime.rs`:

```rust
//! Tokio runtime initialisation and structured task lifecycle management.
```

- [ ] **Step 2: Add `runtime` module to `lib.rs`**

```rust
//! Tokio async runtime wrapper and agent lifecycle management.
//!
//! This crate wraps `tokio` to provide a consistent async execution environment
//! for Agent Assembly components. It handles runtime initialization, shutdown
//! coordination, and lifecycle hooks.

pub mod config;
pub mod runtime;
```

- [ ] **Step 3: Verify workspace compiles**

```bash
cargo build -p aa-runtime
```

- [ ] **Step 4: Commit**

```bash
git add aa-runtime/src/runtime.rs aa-runtime/src/lib.rs
git commit -m "✨ (aa-runtime): Add runtime module declaration to lib.rs"
```

---

## Task 6: Add `lifecycle` module stub

**Files:**
- Create: `aa-runtime/src/lifecycle.rs`
- Modify: `aa-runtime/src/lib.rs`

- [ ] **Step 1: Create empty `lifecycle.rs`**

Create `aa-runtime/src/lifecycle.rs`:

```rust
//! Signal handling and graceful shutdown coordination.
```

- [ ] **Step 2: Add `lifecycle` module to `lib.rs`**

```rust
//! Tokio async runtime wrapper and agent lifecycle management.
//!
//! This crate wraps `tokio` to provide a consistent async execution environment
//! for Agent Assembly components. It handles runtime initialization, shutdown
//! coordination, and lifecycle hooks.

pub mod config;
pub mod lifecycle;
pub mod runtime;
```

- [ ] **Step 3: Verify workspace compiles**

```bash
cargo build -p aa-runtime
```

- [ ] **Step 4: Commit**

```bash
git add aa-runtime/src/lifecycle.rs aa-runtime/src/lib.rs
git commit -m "✨ (aa-runtime): Add lifecycle module declaration to lib.rs"
```

---

## Task 7: Add `ipc` stub module (for AAASM-30)

**Files:**
- Create: `aa-runtime/src/ipc/mod.rs`
- Modify: `aa-runtime/src/lib.rs`

- [ ] **Step 1: Create `ipc/mod.rs`**

```bash
mkdir -p aa-runtime/src/ipc
```

Create `aa-runtime/src/ipc/mod.rs`:

```rust
//! Unix domain socket IPC server — implemented in AAASM-30.
```

- [ ] **Step 2: Add `ipc` module to `lib.rs`**

```rust
//! Tokio async runtime wrapper and agent lifecycle management.
//!
//! This crate wraps `tokio` to provide a consistent async execution environment
//! for Agent Assembly components. It handles runtime initialization, shutdown
//! coordination, and lifecycle hooks.

pub mod config;
pub mod ipc;
pub mod lifecycle;
pub mod runtime;
```

- [ ] **Step 3: Verify workspace compiles**

```bash
cargo build -p aa-runtime
```

- [ ] **Step 4: Commit**

```bash
git add aa-runtime/src/ipc/mod.rs aa-runtime/src/lib.rs
git commit -m "✨ (aa-runtime): Add ipc stub module for AAASM-30"
```

---

## Task 8: Add `pipeline` stub module (for AAASM-31)

**Files:**
- Create: `aa-runtime/src/pipeline/mod.rs`
- Modify: `aa-runtime/src/lib.rs`

- [ ] **Step 1: Create `pipeline/mod.rs`**

```bash
mkdir -p aa-runtime/src/pipeline
```

Create `aa-runtime/src/pipeline/mod.rs`:

```rust
//! Event aggregation pipeline — implemented in AAASM-31.
```

- [ ] **Step 2: Add `pipeline` module to `lib.rs`**

```rust
//! Tokio async runtime wrapper and agent lifecycle management.
//!
//! This crate wraps `tokio` to provide a consistent async execution environment
//! for Agent Assembly components. It handles runtime initialization, shutdown
//! coordination, and lifecycle hooks.

pub mod config;
pub mod ipc;
pub mod lifecycle;
pub mod pipeline;
pub mod runtime;
```

- [ ] **Step 3: Verify workspace compiles**

```bash
cargo build -p aa-runtime
```

- [ ] **Step 4: Commit**

```bash
git add aa-runtime/src/pipeline/mod.rs aa-runtime/src/lib.rs
git commit -m "✨ (aa-runtime): Add pipeline stub module for AAASM-31"
```

---

## Task 9: Add `health` stub module (for AAASM-32)

**Files:**
- Create: `aa-runtime/src/health.rs`
- Modify: `aa-runtime/src/lib.rs`

- [ ] **Step 1: Create `health.rs`**

Create `aa-runtime/src/health.rs`:

```rust
//! HTTP health check and Prometheus metrics endpoint — implemented in AAASM-32.
```

- [ ] **Step 2: Add `health` module to `lib.rs`**

```rust
//! Tokio async runtime wrapper and agent lifecycle management.
//!
//! This crate wraps `tokio` to provide a consistent async execution environment
//! for Agent Assembly components. It handles runtime initialization, shutdown
//! coordination, and lifecycle hooks.

pub mod config;
pub mod health;
pub mod ipc;
pub mod lifecycle;
pub mod pipeline;
pub mod runtime;
```

- [ ] **Step 3: Verify workspace compiles**

```bash
cargo build -p aa-runtime
```

- [ ] **Step 4: Commit**

```bash
git add aa-runtime/src/health.rs aa-runtime/src/lib.rs
git commit -m "✨ (aa-runtime): Add health stub module for AAASM-32"
```

---

## Task 10: Add `main.rs` binary entry point stub

**Files:**
- Create: `aa-runtime/src/main.rs`

- [ ] **Step 1: Create `main.rs` stub**

Create `aa-runtime/src/main.rs`:

```rust
//! `aa-runtime` sidecar binary entry point.

fn main() {
    // Tracing and runtime wired in subsequent tasks.
}
```

- [ ] **Step 2: Verify binary builds**

```bash
cargo build -p aa-runtime --bins
```

Expected: builds. A binary named `aa-runtime` should appear in `target/debug/`.

- [ ] **Step 3: Commit**

```bash
git add aa-runtime/src/main.rs
git commit -m "✨ (aa-runtime): Add main.rs binary entry point stub"
```

---

## Task 11: Add `RuntimeConfig` struct with `worker_threads` field

**Files:**
- Modify: `aa-runtime/src/config.rs`

- [ ] **Step 1: Add the struct**

Replace the entire `config.rs` with:

```rust
//! Runtime configuration loaded from environment variables.

/// Configuration for the `aa-runtime` sidecar process.
///
/// All fields are populated by [`RuntimeConfig::from_env`].
#[derive(Debug, Clone)]
pub struct RuntimeConfig {
    /// Number of Tokio worker threads.
    ///
    /// Read from `AA_RUNTIME_WORKER_THREADS`. Defaults to `0`, which tells
    /// Tokio to use one thread per logical CPU.
    pub worker_threads: usize,
}
```

- [ ] **Step 2: Verify workspace compiles**

```bash
cargo build -p aa-runtime
```

- [ ] **Step 3: Commit**

```bash
git add aa-runtime/src/config.rs
git commit -m "✨ (aa-runtime/config): Add RuntimeConfig struct with worker_threads field"
```

---

## Task 12: Add `shutdown_timeout_secs` field to `RuntimeConfig`

**Files:**
- Modify: `aa-runtime/src/config.rs`

- [ ] **Step 1: Add the field**

```rust
//! Runtime configuration loaded from environment variables.

/// Configuration for the `aa-runtime` sidecar process.
///
/// All fields are populated by [`RuntimeConfig::from_env`].
#[derive(Debug, Clone)]
pub struct RuntimeConfig {
    /// Number of Tokio worker threads.
    ///
    /// Read from `AA_RUNTIME_WORKER_THREADS`. Defaults to `0`, which tells
    /// Tokio to use one thread per logical CPU.
    pub worker_threads: usize,

    /// Maximum seconds to wait for in-flight tasks to complete during shutdown.
    ///
    /// Read from `AA_RUNTIME_SHUTDOWN_TIMEOUT_SECS`. Defaults to `30`.
    pub shutdown_timeout_secs: u64,
}
```

- [ ] **Step 2: Verify workspace compiles**

```bash
cargo build -p aa-runtime
```

- [ ] **Step 3: Commit**

```bash
git add aa-runtime/src/config.rs
git commit -m "✨ (aa-runtime/config): Add shutdown_timeout_secs field to RuntimeConfig"
```

---

## Task 13: Add `RuntimeConfig::from_env()` constructor

**Files:**
- Modify: `aa-runtime/src/config.rs`

- [ ] **Step 1: Implement `from_env()`**

```rust
//! Runtime configuration loaded from environment variables.

/// Configuration for the `aa-runtime` sidecar process.
///
/// All fields are populated by [`RuntimeConfig::from_env`].
#[derive(Debug, Clone)]
pub struct RuntimeConfig {
    /// Number of Tokio worker threads.
    ///
    /// Read from `AA_RUNTIME_WORKER_THREADS`. Defaults to `0`, which tells
    /// Tokio to use one thread per logical CPU.
    pub worker_threads: usize,

    /// Maximum seconds to wait for in-flight tasks to complete during shutdown.
    ///
    /// Read from `AA_RUNTIME_SHUTDOWN_TIMEOUT_SECS`. Defaults to `30`.
    pub shutdown_timeout_secs: u64,
}

impl RuntimeConfig {
    /// Build configuration from environment variables, falling back to defaults.
    ///
    /// # Env vars
    ///
    /// | Variable | Type | Default |
    /// |---|---|---|
    /// | `AA_RUNTIME_WORKER_THREADS` | `usize` | `0` (Tokio picks per-CPU) |
    /// | `AA_RUNTIME_SHUTDOWN_TIMEOUT_SECS` | `u64` | `30` |
    ///
    /// Invalid values are silently ignored and the default is used instead.
    pub fn from_env() -> Self {
        let worker_threads = std::env::var("AA_RUNTIME_WORKER_THREADS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(0);

        let shutdown_timeout_secs = std::env::var("AA_RUNTIME_SHUTDOWN_TIMEOUT_SECS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(30);

        Self {
            worker_threads,
            shutdown_timeout_secs,
        }
    }
}
```

- [ ] **Step 2: Verify workspace compiles**

```bash
cargo build -p aa-runtime
```

- [ ] **Step 3: Commit**

```bash
git add aa-runtime/src/config.rs
git commit -m "✨ (aa-runtime/config): Add RuntimeConfig::from_env() constructor"
```

---

## Task 14: Add `wait_for_shutdown_signal()` async function skeleton

**Files:**
- Modify: `aa-runtime/src/lifecycle.rs`

- [ ] **Step 1: Add the function skeleton**

```rust
//! Signal handling and graceful shutdown coordination.

/// Waits until the process receives a shutdown signal (SIGTERM or SIGINT).
///
/// Returns as soon as either signal fires. Callers should then trigger
/// cooperative cancellation on all tracked tasks.
pub async fn wait_for_shutdown_signal() {
    // SIGTERM and SIGINT handlers added in subsequent steps.
    std::future::pending::<()>().await
}
```

- [ ] **Step 2: Verify workspace compiles**

```bash
cargo build -p aa-runtime
```

- [ ] **Step 3: Commit**

```bash
git add aa-runtime/src/lifecycle.rs
git commit -m "✨ (aa-runtime/lifecycle): Add wait_for_shutdown_signal() async function"
```

---

## Task 15: Add SIGTERM handler to `wait_for_shutdown_signal()`

**Files:**
- Modify: `aa-runtime/src/lifecycle.rs`

- [ ] **Step 1: Add SIGTERM branch**

```rust
//! Signal handling and graceful shutdown coordination.

/// Waits until the process receives a shutdown signal (SIGTERM or SIGINT).
///
/// Returns as soon as either signal fires. Callers should then trigger
/// cooperative cancellation on all tracked tasks.
pub async fn wait_for_shutdown_signal() {
    let sigterm = sigterm();

    tokio::select! {
        _ = sigterm => {
            tracing::info!("received SIGTERM — initiating graceful shutdown");
        }
    }
}

/// Returns a future that resolves on the first SIGTERM.
///
/// On non-Unix platforms this future never resolves (SIGTERM is Unix-only).
async fn sigterm() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut stream = signal(SignalKind::terminate())
            .expect("failed to install SIGTERM handler");
        stream.recv().await;
    }
    #[cfg(not(unix))]
    {
        std::future::pending::<()>().await
    }
}
```

- [ ] **Step 2: Verify workspace compiles**

```bash
cargo build -p aa-runtime
```

- [ ] **Step 3: Commit**

```bash
git add aa-runtime/src/lifecycle.rs
git commit -m "✨ (aa-runtime/lifecycle): Add SIGTERM handler inside shutdown signal listener"
```

---

## Task 16: Add SIGINT handler to `wait_for_shutdown_signal()`

**Files:**
- Modify: `aa-runtime/src/lifecycle.rs`

- [ ] **Step 1: Add SIGINT branch to the `select!`**

```rust
//! Signal handling and graceful shutdown coordination.

/// Waits until the process receives a shutdown signal (SIGTERM or SIGINT).
///
/// Returns as soon as either signal fires. Callers should then trigger
/// cooperative cancellation on all tracked tasks.
pub async fn wait_for_shutdown_signal() {
    let sigterm = sigterm();
    let sigint = tokio::signal::ctrl_c();

    tokio::select! {
        _ = sigterm => {
            tracing::info!("received SIGTERM — initiating graceful shutdown");
        }
        result = sigint => {
            match result {
                Ok(()) => tracing::info!("received SIGINT (Ctrl-C) — initiating graceful shutdown"),
                Err(e) => tracing::error!("SIGINT handler error: {e}"),
            }
        }
    }
}

/// Returns a future that resolves on the first SIGTERM.
///
/// On non-Unix platforms this future never resolves (SIGTERM is Unix-only).
async fn sigterm() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut stream = signal(SignalKind::terminate())
            .expect("failed to install SIGTERM handler");
        stream.recv().await;
    }
    #[cfg(not(unix))]
    {
        std::future::pending::<()>().await
    }
}
```

- [ ] **Step 2: Verify workspace compiles**

```bash
cargo build -p aa-runtime
```

- [ ] **Step 3: Commit**

```bash
git add aa-runtime/src/lifecycle.rs
git commit -m "✨ (aa-runtime/lifecycle): Add SIGINT handler inside shutdown signal listener"
```

---

## Task 17: Add `run()` async function skeleton in `runtime.rs`

**Files:**
- Modify: `aa-runtime/src/runtime.rs`

- [ ] **Step 1: Add the skeleton**

```rust
//! Tokio runtime initialisation and structured task lifecycle management.

use crate::config::RuntimeConfig;

/// Start the runtime and block until graceful shutdown completes.
///
/// This is the main async entry point called from `main()`. It creates the
/// structured concurrency primitives, spawns subsystem tasks, waits for a
/// shutdown signal, then drains all tasks within the configured timeout.
pub async fn run(_config: RuntimeConfig) {
    tracing::info!("aa-runtime starting");
    tracing::info!("aa-runtime stopped");
}
```

- [ ] **Step 2: Re-export `run` from `lib.rs`**

Add `pub use runtime::run;` to `lib.rs`:

```rust
//! Tokio async runtime wrapper and agent lifecycle management.
//!
//! This crate wraps `tokio` to provide a consistent async execution environment
//! for Agent Assembly components. It handles runtime initialization, shutdown
//! coordination, and lifecycle hooks.

pub mod config;
pub mod health;
pub mod ipc;
pub mod lifecycle;
pub mod pipeline;
pub mod runtime;

pub use runtime::run;
```

- [ ] **Step 3: Verify workspace compiles**

```bash
cargo build -p aa-runtime
```

- [ ] **Step 4: Commit**

```bash
git add aa-runtime/src/runtime.rs aa-runtime/src/lib.rs
git commit -m "✨ (aa-runtime/runtime): Add run() async function skeleton"
```

---

## Task 18: Add `TaskTracker` and `CancellationToken` init in `run()`

**Files:**
- Modify: `aa-runtime/src/runtime.rs`

- [ ] **Step 1: Wire in the structured concurrency primitives**

```rust
//! Tokio runtime initialisation and structured task lifecycle management.

use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;

use crate::config::RuntimeConfig;

/// Start the runtime and block until graceful shutdown completes.
///
/// This is the main async entry point called from `main()`. It creates the
/// structured concurrency primitives, spawns subsystem tasks, waits for a
/// shutdown signal, then drains all tasks within the configured timeout.
pub async fn run(_config: RuntimeConfig) {
    tracing::info!("aa-runtime starting");

    let tracker = TaskTracker::new();
    let token = CancellationToken::new();

    tracing::info!(
        tasks = tracker.len(),
        "structured concurrency primitives initialised"
    );

    // Shutdown sequence added in the next task.
    drop(token);
    tracker.close();
    tracker.wait().await;

    tracing::info!("aa-runtime stopped");
}
```

- [ ] **Step 2: Verify workspace compiles**

```bash
cargo build -p aa-runtime
```

- [ ] **Step 3: Commit**

```bash
git add aa-runtime/src/runtime.rs
git commit -m "✨ (aa-runtime/runtime): Add TaskTracker and CancellationToken init in run()"
```

---

## Task 19: Add graceful shutdown sequence with timeout in `run()`

**Files:**
- Modify: `aa-runtime/src/runtime.rs`

- [ ] **Step 1: Implement the full shutdown sequence**

```rust
//! Tokio runtime initialisation and structured task lifecycle management.

use std::time::Duration;

use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;

use crate::config::RuntimeConfig;
use crate::lifecycle::wait_for_shutdown_signal;

/// Start the runtime and block until graceful shutdown completes.
///
/// This is the main async entry point called from `main()`. It creates the
/// structured concurrency primitives, spawns subsystem tasks, waits for a
/// shutdown signal, then drains all tasks within the configured timeout.
pub async fn run(config: RuntimeConfig) {
    tracing::info!("aa-runtime starting");

    let tracker = TaskTracker::new();
    let token = CancellationToken::new();

    tracing::info!("structured concurrency primitives initialised");

    // Subsystem tasks (ipc, pipeline, health) are spawned here in later tickets.
    // Each receives a cloned `token` and a `tracker.token()` guard.

    // Wait for an OS shutdown signal.
    wait_for_shutdown_signal().await;

    // Signal all tasks to stop cooperatively.
    token.cancel();
    tracing::info!("cancellation token fired — draining tasks");

    // Stop accepting new task registrations.
    tracker.close();

    // Wait for all tasks to complete, with a hard timeout.
    let timeout = Duration::from_secs(config.shutdown_timeout_secs);
    if tokio::time::timeout(timeout, tracker.wait()).await.is_err() {
        tracing::error!(
            timeout_secs = config.shutdown_timeout_secs,
            "shutdown timeout exceeded — forcing exit"
        );
    } else {
        tracing::info!("all tasks completed cleanly");
    }

    tracing::info!("aa-runtime stopped");
}
```

- [ ] **Step 2: Verify workspace compiles**

```bash
cargo build -p aa-runtime
```

- [ ] **Step 3: Commit**

```bash
git add aa-runtime/src/runtime.rs
git commit -m "✨ (aa-runtime/runtime): Add graceful shutdown sequence with timeout in run()"
```

---

## Task 20: Wire manual Tokio runtime entry with configurable `worker_threads`

**Files:**
- Modify: `aa-runtime/src/main.rs`

- [ ] **Step 1: Replace the stub with a manual runtime builder**

Using `#[tokio::main]` and then calling `Builder::new_multi_thread().build()` inside it would panic
("Cannot start a runtime from within a runtime"). The correct approach is a plain sync `fn main()`
that always builds the runtime manually:

```rust
//! `aa-runtime` sidecar binary entry point.

fn main() {
    let config = aa_runtime::config::RuntimeConfig::from_env();

    // Build the Tokio multi-thread runtime.
    // When worker_threads == 0, Builder uses one thread per logical CPU (Tokio default).
    let mut builder = tokio::runtime::Builder::new_multi_thread();
    builder.enable_all();

    if config.worker_threads > 0 {
        builder.worker_threads(config.worker_threads);
    }

    builder
        .build()
        .expect("failed to build Tokio runtime")
        .block_on(aa_runtime::run(config));
}
```

- [ ] **Step 2: Verify binary builds and runs**

```bash
cargo build -p aa-runtime --bins
./target/debug/aa-runtime &
sleep 1
kill -TERM $!
wait $!
```

Expected: process starts, logs startup, then logs graceful shutdown after SIGTERM.

- [ ] **Step 3: Commit**

```bash
git add aa-runtime/src/main.rs
git commit -m "✨ (aa-runtime): Wire manual Tokio runtime entry with configurable worker_threads"
```

---

## Task 21: Initialize tracing JSON subscriber in `main`

**Files:**
- Modify: `aa-runtime/src/main.rs`

- [ ] **Step 1: Add `init_tracing()` and call it first in `main()`**

Tracing must be initialised before any async work (and before the runtime is built), so it lives
in the sync portion of `main()`:

```rust
//! `aa-runtime` sidecar binary entry point.

fn init_tracing() {
    use tracing_subscriber::{fmt, prelude::*, EnvFilter};

    tracing_subscriber::registry()
        .with(EnvFilter::from_default_env())
        .with(fmt::layer().json())
        .init();
}

fn main() {
    init_tracing();

    let config = aa_runtime::config::RuntimeConfig::from_env();

    tracing::info!(
        worker_threads = config.worker_threads,
        shutdown_timeout_secs = config.shutdown_timeout_secs,
        "configuration loaded"
    );

    let mut builder = tokio::runtime::Builder::new_multi_thread();
    builder.enable_all();

    if config.worker_threads > 0 {
        builder.worker_threads(config.worker_threads);
    }

    builder
        .build()
        .expect("failed to build Tokio runtime")
        .block_on(aa_runtime::run(config));
}
```

- [ ] **Step 2: Verify binary builds and emits JSON logs**

```bash
cargo build -p aa-runtime --bins
RUST_LOG=info ./target/debug/aa-runtime &
PID=$!
sleep 1
kill -TERM $PID
wait $PID
```

Expected: JSON log lines like `{"timestamp":"...","level":"INFO","message":"configuration loaded",...}` then shutdown logs, then process exits 0.

- [ ] **Step 3: Commit**

```bash
git add aa-runtime/src/main.rs
git commit -m "✨ (aa-runtime): Initialize tracing JSON subscriber in main"
```

---

## Task 22: Add unit tests for `RuntimeConfig::from_env()`

**Files:**
- Modify: `aa-runtime/src/config.rs`

- [ ] **Step 1: Add tests module at the bottom of `config.rs`**

Append to the end of `aa-runtime/src/config.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_when_env_vars_absent() {
        // Ensure neither var is set for this test.
        std::env::remove_var("AA_RUNTIME_WORKER_THREADS");
        std::env::remove_var("AA_RUNTIME_SHUTDOWN_TIMEOUT_SECS");

        let config = RuntimeConfig::from_env();

        assert_eq!(config.worker_threads, 0);
        assert_eq!(config.shutdown_timeout_secs, 30);
    }

    #[test]
    fn reads_worker_threads_from_env() {
        std::env::set_var("AA_RUNTIME_WORKER_THREADS", "4");
        std::env::remove_var("AA_RUNTIME_SHUTDOWN_TIMEOUT_SECS");

        let config = RuntimeConfig::from_env();

        assert_eq!(config.worker_threads, 4);
        assert_eq!(config.shutdown_timeout_secs, 30);

        std::env::remove_var("AA_RUNTIME_WORKER_THREADS");
    }

    #[test]
    fn reads_shutdown_timeout_from_env() {
        std::env::remove_var("AA_RUNTIME_WORKER_THREADS");
        std::env::set_var("AA_RUNTIME_SHUTDOWN_TIMEOUT_SECS", "60");

        let config = RuntimeConfig::from_env();

        assert_eq!(config.worker_threads, 0);
        assert_eq!(config.shutdown_timeout_secs, 60);

        std::env::remove_var("AA_RUNTIME_SHUTDOWN_TIMEOUT_SECS");
    }

    #[test]
    fn falls_back_to_default_on_invalid_value() {
        std::env::set_var("AA_RUNTIME_WORKER_THREADS", "not-a-number");
        std::env::set_var("AA_RUNTIME_SHUTDOWN_TIMEOUT_SECS", "abc");

        let config = RuntimeConfig::from_env();

        assert_eq!(config.worker_threads, 0);
        assert_eq!(config.shutdown_timeout_secs, 30);

        std::env::remove_var("AA_RUNTIME_WORKER_THREADS");
        std::env::remove_var("AA_RUNTIME_SHUTDOWN_TIMEOUT_SECS");
    }
}
```

- [ ] **Step 2: Run the tests**

```bash
cargo nextest run -p aa-runtime --test-threads=1
```

The `--test-threads=1` flag is important — these tests mutate environment variables and must not run concurrently.

Expected: 4 tests pass.

- [ ] **Step 3: Commit**

```bash
git add aa-runtime/src/config.rs
git commit -m "✅ (aa-runtime/config): Add unit tests for RuntimeConfig::from_env()"
```

---

## Task 23: Add integration test for graceful shutdown under synthetic load

**Files:**
- Modify: `aa-runtime/src/runtime.rs`

- [ ] **Step 1: Add integration test module at the bottom of `runtime.rs`**

Append to the end of `aa-runtime/src/runtime.rs`:

```rust
#[cfg(test)]
mod tests {
    use std::time::Duration;

    use tokio_util::sync::CancellationToken;
    use tokio_util::task::TaskTracker;

    /// Verifies the structured concurrency primitives drain cleanly under load.
    ///
    /// Spawns N tasks that loop until the cancellation token fires, then
    /// cancels the token and asserts all tasks complete within the timeout.
    #[tokio::test]
    async fn graceful_shutdown_drains_all_tasks() {
        const TASK_COUNT: usize = 10;
        const TIMEOUT: Duration = Duration::from_secs(5);

        let tracker = TaskTracker::new();
        let token = CancellationToken::new();

        // Spawn synthetic load tasks that honor the cancellation token.
        for i in 0..TASK_COUNT {
            let child_token = token.clone();
            tracker.spawn(async move {
                loop {
                    tokio::select! {
                        _ = child_token.cancelled() => {
                            break;
                        }
                        _ = tokio::time::sleep(Duration::from_millis(10)) => {
                            // Simulate work.
                        }
                    }
                }
                tracing::debug!(task = i, "task completed cleanly");
            });
        }

        // Trigger shutdown.
        token.cancel();
        tracker.close();

        // All tasks must complete within the timeout — no leaks.
        tokio::time::timeout(TIMEOUT, tracker.wait())
            .await
            .expect("tasks did not complete within timeout");
    }

    /// Verifies that shutdown timeout enforcement works when tasks ignore cancellation.
    #[tokio::test]
    async fn shutdown_timeout_fires_when_tasks_hang() {
        let tracker = TaskTracker::new();
        let token = CancellationToken::new();

        // Spawn a task that ignores cancellation and sleeps forever.
        tracker.spawn(async move {
            let _token = token; // hold token to prevent drop-based cancellation
            tokio::time::sleep(Duration::from_secs(3600)).await;
        });

        tracker.close();

        // Drain with a very short timeout — must expire.
        let result = tokio::time::timeout(Duration::from_millis(100), tracker.wait()).await;
        assert!(result.is_err(), "expected timeout but tasks completed");
    }
}
```

- [ ] **Step 2: Run the tests**

```bash
cargo nextest run -p aa-runtime
```

Expected: both tests pass. `graceful_shutdown_drains_all_tasks` completes well within 5 seconds. `shutdown_timeout_fires_when_tasks_hang` completes in ~100ms.

- [ ] **Step 3: Run `cargo clippy` to catch any lint issues**

```bash
cargo clippy -p aa-runtime --all-targets -- -D warnings
```

Expected: no warnings.

- [ ] **Step 4: Run `cargo fmt` to ensure formatting**

```bash
cargo fmt -p aa-runtime -- --check
```

Expected: no diff.

- [ ] **Step 5: Commit**

```bash
git add aa-runtime/src/runtime.rs
git commit -m "✅ (aa-runtime/runtime): Add integration test for graceful shutdown under synthetic load"
```

---

## Final Verification

- [ ] **Run the full workspace test suite**

```bash
cargo nextest run --workspace --test-threads=1
```

Expected: all tests pass across all workspace crates.

- [ ] **Run full clippy**

```bash
cargo clippy --all-targets --all-features -- -D warnings
```

Expected: zero warnings.

- [ ] **Run full fmt check**

```bash
cargo fmt --all -- --check
```

Expected: no diff.

- [ ] **Smoke-test the binary with SIGINT**

```bash
RUST_LOG=info cargo run -p aa-runtime &
PID=$!
sleep 1
kill -INT $PID
wait $PID
echo "Exit code: $?"
```

Expected: JSON log lines showing startup → SIGINT received → shutdown → `aa-runtime stopped`. Exit code `0`.

---

## PR

Once all tasks are complete and CI is green:

**Branch:** `v0.0.1/AAASM-29/tokio_runtime_init`
**PR title:** `[AAASM-29] ✨ (aa-runtime): Bootstrap Tokio runtime init with graceful shutdown`
**PR body:** follows `.github/PULL_REQUEST_TEMPLATE.md`
