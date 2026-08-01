//! The launch-environment obligation, machine-checked (AAASM-5330).
//!
//! # Why this file exists
//!
//! [`LaunchableTool::build_launch_command`] documents that the environment set
//! on the returned command is part of the contract and must reach the spawned
//! child. Prose alone is what the caller in AAASM-5327 was already missing: it
//! rebuilt the child from the command's program and arguments, discarded every
//! variable the adapter had set — `NODE_EXTRA_CA_CERTS` included, without which
//! the proxy cannot terminate the tool's TLS — and broke no rule that had been
//! written down. Writing the rule down stops the *next* caller only if something
//! checks it, so this file checks it.
//!
//! # Why the harness spawns a real child
//!
//! The obligation is about the child's environment, not about the shape of the
//! `Command` a caller happens to hold. Asserting over
//! [`Command::get_envs`](std::process::Command::get_envs) would only re-read the
//! caller's own instructions back to itself, and would in particular be unable
//! to tell "this variable was removed" from "this variable was never mentioned
//! and is being inherited". [`CallerBehaviour`] therefore ends in a real spawn
//! and the assertions are made against what the process actually saw.
//!
//! # Why the violations are fixtures rather than a mutation exercise
//!
//! [`CallerBehaviour`] carries the two ways a caller gets this wrong as first-
//! class variants, and the tests assert both that a conforming caller delivers
//! the environment *and* that each violating one does not. A guard that only
//! ever exercises the passing path cannot distinguish a conforming caller from a
//! violating one, which is the failure mode this whole ticket is about.
//!
//! Unix-only: the harness reads the child's environment out of `/usr/bin/env`,
//! and there is no Windows target in this workspace's CI.

#![cfg(unix)]

use std::collections::BTreeMap;
use std::process::Command;

use aa_devtool_contract::{AdapterError, LaunchSpec, LaunchableTool};

/// Prints its own environment, one `NAME=VALUE` per line. Present on every
/// platform this workspace builds for.
const ENV_PROGRAM: &str = "/usr/bin/env";

/// Where an earlier plan step materialised the proxy CA. The literal value does
/// not matter; that the child sees *this* value and not the caller's does.
const CA_PATH: &str = "/home/dev/.aa/ca/aasm-ca.pem";

/// A variable the fixture adapter removes. Prefixed so a stray value in the
/// developer's own shell cannot make the removal assertion pass or fail by
/// accident.
const DISABLED_VAR: &str = "AASM_5330_TOOL_FEATURE";

/// What the caller sets before the adapter's environment is merged in. Two of
/// the three collide with the adapter on purpose.
fn caller_environment() -> BTreeMap<String, String> {
    BTreeMap::from([
        // The caller's guess at the CA path is stale — this is the collision
        // that AAASM-5327 turned into an ungoverned session.
        (
            "NODE_EXTRA_CA_CERTS".to_string(),
            "/etc/ssl/certs/ca-bundle.crt".to_string(),
        ),
        // The gateway hands out a bare `host:port`; only the adapter knows its
        // tool needs a URL (AAASM-5324).
        ("HTTPS_PROXY".to_string(), "127.0.0.1:8080".to_string()),
        // The adapter removes this one. A caller that flattens the removal to an
        // empty value leaves the tool a variable it may still honour.
        (DISABLED_VAR.to_string(), "1".to_string()),
        // Nothing touches this one: the adapter is not the sole source of the
        // child's environment.
        ("AASM_5330_SESSION_ID".to_string(), "session-42".to_string()),
    ])
}

// ---------------------------------------------------------------------------
// The adapter under contract.
// ---------------------------------------------------------------------------

/// A `LaunchableTool` shaped like the Claude Code one: it sets the CA variable
/// its tool's runtime needs, normalises the proxy address into the URL form an
/// HTTP client accepts, and unsets a variable to switch a tool behaviour off.
struct EnvBearingTool;

impl LaunchableTool for EnvBearingTool {
    fn build_launch_command(&self, spec: &LaunchSpec) -> Result<Command, AdapterError> {
        let mut command = Command::new(ENV_PROGRAM);
        command.args(&spec.tool_args);
        command.env("NODE_EXTRA_CA_CERTS", CA_PATH);
        if let Some(proxy) = &spec.proxy_addr {
            let url = if proxy.starts_with("http") {
                proxy.clone()
            } else {
                format!("http://{proxy}")
            };
            command.env("HTTPS_PROXY", url);
        }
        command.env_remove(DISABLED_VAR);
        for (name, value) in &spec.env {
            command.env(name, value);
        }
        Ok(command)
    }
}

// ---------------------------------------------------------------------------
// The caller-shaped harness.
// ---------------------------------------------------------------------------

/// How a caller treats the environment on the command the adapter handed back.
#[derive(Debug, Clone, Copy)]
enum CallerBehaviour {
    /// Honours the contract: the caller's own environment first, the adapter's
    /// on top, `None` applied as a removal.
    Conforming,
    /// The pre-AAASM-5327 `spawn_and_wait`: rebuild from program and arguments,
    /// keep the caller's environment, drop the adapter's entirely.
    DropsAdapterEnvironment,
    /// Subtler, and the reason `None` is spelled out in the trait docs: every
    /// name is carried across, but a removal is flattened into an empty value
    /// the tool may still read.
    FlattensRemovalToEmpty,
}

/// Run `command` the way `behaviour` says a caller would, and return the
/// environment the child process actually observed.
fn observed_child_environment(command: Command, behaviour: CallerBehaviour) -> BTreeMap<String, String> {
    // Every variant reconstructs the child the way the real caller does — from
    // the program and arguments — so that dropping the environment is a state
    // the harness can genuinely reach rather than one it merely describes.
    let mut child = Command::new(command.get_program());
    child.args(command.get_args());
    child.envs(caller_environment());

    match behaviour {
        CallerBehaviour::Conforming => {
            for (name, value) in command.get_envs() {
                match value {
                    Some(value) => child.env(name, value),
                    None => child.env_remove(name),
                };
            }
        }
        CallerBehaviour::DropsAdapterEnvironment => {}
        CallerBehaviour::FlattensRemovalToEmpty => {
            for (name, value) in command.get_envs() {
                child.env(name, value.unwrap_or_default());
            }
        }
    }

    let output = child.output().expect("the env program must be spawnable");
    assert!(output.status.success(), "the env program exited with {}", output.status);
    String::from_utf8(output.stdout)
        .expect("the env program's output must be UTF-8")
        .lines()
        .filter_map(|line| line.split_once('='))
        .map(|(name, value)| (name.to_string(), value.to_string()))
        .collect()
}

/// The launch this whole contract exists for: a governed run through a local
/// proxy, with the CA the plan materialised.
fn governed_launch(behaviour: CallerBehaviour) -> BTreeMap<String, String> {
    let spec = LaunchSpec::new("agent-1").through_proxy("127.0.0.1:8080");
    let command = EnvBearingTool
        .build_launch_command(&spec)
        .expect("building the launch command must succeed");
    observed_child_environment(command, behaviour)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn a_conforming_caller_delivers_the_adapters_environment_to_the_spawned_child() {
    let child = governed_launch(CallerBehaviour::Conforming);
    assert_eq!(
        child.get("NODE_EXTRA_CA_CERTS").map(String::as_str),
        Some(CA_PATH),
        "the CA variable is the only thing that makes the tool's runtime trust \
         the proxy; without it the launch is inspected by nothing"
    );
}

#[test]
fn a_caller_that_rebuilds_from_program_and_args_alone_is_caught() {
    // The AAASM-5327 shape. The child still gets a plausible-looking
    // `NODE_EXTRA_CA_CERTS` from the caller, which is why the bug survived
    // review: the variable is present, it is simply not the proxy's CA.
    let child = governed_launch(CallerBehaviour::DropsAdapterEnvironment);
    assert_eq!(
        child.get("NODE_EXTRA_CA_CERTS").map(String::as_str),
        Some("/etc/ssl/certs/ca-bundle.crt"),
        "this assertion failing would mean the harness cannot express the \
         violation, and the conforming test above would prove nothing"
    );
    assert_eq!(
        child.get("HTTPS_PROXY").map(String::as_str),
        Some("127.0.0.1:8080"),
        "the adapter's normalisation is lost with the rest of its environment"
    );
    assert!(
        child.contains_key(DISABLED_VAR),
        "and the variable the adapter unset comes back"
    );
}

#[test]
fn a_none_env_value_is_a_removal_and_not_an_empty_value() {
    let child = governed_launch(CallerBehaviour::Conforming);
    assert_eq!(
        child.get(DISABLED_VAR),
        None,
        "the adapter unset this to switch a tool behaviour off"
    );

    // The flattening caller passes the CA assertion and still gets this wrong,
    // which is why the two are stated separately in the trait docs.
    let flattened = governed_launch(CallerBehaviour::FlattensRemovalToEmpty);
    assert_eq!(flattened.get("NODE_EXTRA_CA_CERTS").map(String::as_str), Some(CA_PATH));
    assert_eq!(
        flattened.get(DISABLED_VAR).map(String::as_str),
        Some(""),
        "an empty-but-present variable is one the tool may still read and honour"
    );
}

#[test]
fn the_adapters_value_wins_where_it_collides_with_the_callers() {
    let child = governed_launch(CallerBehaviour::Conforming);
    assert_eq!(
        child.get("HTTPS_PROXY").map(String::as_str),
        Some("http://127.0.0.1:8080"),
        "only the adapter knows its tool needs a URL rather than the gateway's \
         bare host:port"
    );
}

#[test]
fn a_launch_spec_variable_overrides_the_adapters_own() {
    // The other collision axis, and it resolves the other way: `LaunchSpec::env`
    // is an argument to the adapter rather than a competing source, so it is how
    // a caller pins a CA for one run without editing what the install recorded.
    // An adapter that applied its own values last would silently ignore the
    // request.
    const PINNED: &str = "/tmp/pinned-ca.pem";
    let spec = LaunchSpec::new("agent-1")
        .through_proxy("127.0.0.1:8080")
        .with_env("NODE_EXTRA_CA_CERTS", PINNED);
    let command = EnvBearingTool
        .build_launch_command(&spec)
        .expect("building the launch command must succeed");
    let child = observed_child_environment(command, CallerBehaviour::Conforming);

    assert_eq!(child.get("NODE_EXTRA_CA_CERTS").map(String::as_str), Some(PINNED));
}

#[test]
fn the_callers_own_variables_still_reach_the_child() {
    // The merge is a union, not a replacement: an adapter that assumed it owned
    // the whole environment would be relying on something the contract does not
    // promise.
    let child = governed_launch(CallerBehaviour::Conforming);
    assert_eq!(
        child.get("AASM_5330_SESSION_ID").map(String::as_str),
        Some("session-42")
    );
}
