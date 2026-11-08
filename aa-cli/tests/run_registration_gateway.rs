//! AAASM-5323 conformance: the CLI cannot register on weaker terms than the SDK,
//! and neither can anyone replaying what the CLI sent.
//!
//! # What "conformance" has to mean here
//!
//! A test that asserted "the CLI registered successfully" would prove nothing
//! about a bypass, because it never attempts one. So every case below either
//! submits a real, complete registration to the real
//! `AgentLifecycleServiceImpl` and expects acceptance, or takes the **literal
//! bytes the CLI sent** — captured off the wire by
//! [`gateway_support::TestGateway::start_recording`] — degrades exactly one
//! property of them, resubmits, and expects a refusal.
//!
//! Degrading captured bytes rather than hand-building a request matters: a
//! hand-built "bad request" can fail for a reason unrelated to the property
//! under test (a malformed DID, a missing field), and then the refusal proves
//! only that the fixture was wrong. Here the baseline is a request the gateway
//! *did* accept, so a refusal after changing one field is attributable to that
//! field.
//!
//! The complementary end-to-end claim — that the `aasm` binary starts no tool
//! when registration fails — is in
//! `aa-integration-tests/tests/cli_run_grpc_registration.rs`.

use std::sync::{Arc, Mutex};

use aa_cli::commands::run_registration::{self, SessionDescriptor};
use aa_proto::assembly::agent::v1::agent_lifecycle_service_client::AgentLifecycleServiceClient;
use aa_proto::assembly::agent::v1::{ChallengeRequest, RegisterRequest};
use aa_proto::assembly::common::v1::AgentId as ProtoAgentId;
use aa_sdk_client::gateway::{build_challenge_request, build_register_request};
use aa_sdk_client::{AgentKeypair, AssemblyConfig};

mod gateway_support;
use gateway_support::{GatewayEnv, TestGateway};

const TEAM: &str = "team-a";

fn descriptor<'a>(agent_id: &'a str, governance_level: &'a str) -> SessionDescriptor<'a> {
    SessionDescriptor {
        agent_id,
        name: "claude_code",
        version: "2.1.999",
        team_id: Some(TEAM),
        parent_agent_id: None,
        enforcement_mode: aa_core::EnforcementMode::Enforce,
        governance_level,
    }
}

/// An `AssemblyConfig` an SDK agent would be configured with for `agent_id` —
/// the same input the CLI takes, so the two surfaces are comparable.
fn sdk_config(agent_id: &str) -> AssemblyConfig {
    AssemblyConfig {
        agent_id: agent_id.to_string(),
        socket_path: None,
        gateway_endpoint: None,
        team_id: Some(TEAM.to_string()),
        parent_agent_id: None,
        sdk_version: None,
        // Each test binary keeps its enrolments in its own directory rather than
        // the developer's real `~/.aasm`, and the CLI under test is pointed at
        // the same one by `AASM_STATE_DIR` so both surfaces read one key.
        identity_dir: Some(identity_dir()),
        org_id: None,
        registration_key: None,
    }
}

/// One temporary identity store per test process, shared by every case in it.
///
/// Shared rather than per-test on purpose: several cases below assert that the
/// CLI and an SDK configured with the same identifier arrive at the *same*
/// identity, which is a statement about one stored key and is unprovable if each
/// call enrols its own.
fn identity_dir() -> String {
    // Exactly where the store resolves `${AASM_STATE_DIR}/identity` to, so the
    // CLI (which reads the environment) and these configs (which are explicit)
    // name one directory and therefore one key.
    gateway_support::state_dir()
        .join("identity")
        .to_string_lossy()
        .into_owned()
}

/// Submit `request` to `endpoint` exactly as a client would.
async fn submit(endpoint: &str, request: RegisterRequest) -> Result<(), tonic::Status> {
    let mut client = AgentLifecycleServiceClient::connect(endpoint.to_string())
        .await
        .expect("the test gateway must be reachable");
    client.register(request).await.map(|_| ())
}

/// Like [`submit`], returning the credential token the gateway issued.
async fn submit_token(endpoint: &str, request: RegisterRequest) -> Result<String, tonic::Status> {
    let mut client = AgentLifecycleServiceClient::connect(endpoint.to_string())
        .await
        .expect("the test gateway must be reachable");
    client
        .register(request)
        .await
        .map(|response| response.into_inner().credential_token)
}

/// Obtain a genuine, fresh nonce for `config` from `endpoint`.
async fn fresh_nonce(endpoint: &str, config: &AssemblyConfig) -> Vec<u8> {
    let mut client = AgentLifecycleServiceClient::connect(endpoint.to_string())
        .await
        .expect("the test gateway must be reachable");
    let challenge: ChallengeRequest = build_challenge_request(config).expect("the agent must have a durable identity");
    client
        .request_challenge(challenge)
        .await
        .expect("a well-formed challenge request must be answered")
        .into_inner()
        .nonce
}

// ── the baseline: a real registration is accepted ──────────────────────────

/// The registration the CLI performs is accepted by the real gateway, and lands
/// in the registry under the identity it derived. Without this every refusal
/// below could be the gateway refusing everything.
#[tokio::test(flavor = "multi_thread")]
async fn the_cli_registers_with_the_real_gateway() -> anyhow::Result<()> {
    let gateway = TestGateway::start().await?;
    let _env = GatewayEnv::point_at(gateway.endpoint());

    let registration = run_registration::register(descriptor("ops-laptop", "L2Enforce"))
        .await
        .expect("a complete registration must be accepted by the real gateway");

    assert_eq!(
        registration.registration_did,
        run_registration::registration_did("ops-laptop"),
        "the session must be registered under the identity the identifier derives"
    );
    assert_eq!(registration.team_id.as_deref(), Some(TEAM));

    let records = gateway.registry().list();
    assert_eq!(records.len(), 1, "exactly one agent should be registered");
    let record = &records[0];
    assert_eq!(
        hex::encode(record.agent_id),
        registration.registration_id,
        "the record must be filed under the key the CLI reports"
    );
    assert_eq!(
        record.name, "claude_code",
        "the launched tool must be named in the registry"
    );
    assert_eq!(
        record.version, "2.1.999",
        "the detected tool version must reach the gateway, not a placeholder"
    );

    // And the registry key the CLI reports is the one the record is filed under,
    // so `AA_REGISTRATION_ID` addresses something.
    assert_eq!(
        registration.registration_id.len(),
        32,
        "the API only parses a 32-hex-character agent id"
    );
    assert!(
        gateway
            .registry()
            .get(
                &hex::decode(&registration.registration_id)?
                    .try_into()
                    .expect("16 bytes")
            )
            .is_some(),
        "the reported registration_id must resolve to the record that was just created"
    );
    Ok(())
}

// ── bypass attempts against the CLI's own captured bytes ───────────────────

/// **Bypass attempt: register without proving key possession.**
///
/// Takes the request the CLI actually sent, pairs it with a genuine fresh nonce
/// (so the refusal cannot be blamed on a stale one) and blanks the possession
/// proof. Everything else — DID, public key, name, version, team — is byte-for-
/// byte what the gateway accepted moments earlier.
#[tokio::test(flavor = "multi_thread")]
async fn a_registration_without_a_possession_proof_is_refused() -> anyhow::Result<()> {
    let seen: Arc<Mutex<Vec<RegisterRequest>>> = Arc::default();
    let gateway = TestGateway::start_recording(Arc::clone(&seen)).await?;
    let _env = GatewayEnv::point_at(gateway.endpoint());

    run_registration::register(descriptor("proofless", "L2Enforce"))
        .await
        .expect("the baseline must be accepted, or the mutation below proves nothing");
    let captured = seen.lock().unwrap()[0].clone();

    let config = sdk_config("proofless");
    let mut forged = captured.clone();
    forged.registration_nonce = fresh_nonce(gateway.endpoint(), &config).await;
    forged.possession_proof = Vec::new();

    let status = submit(gateway.endpoint(), forged)
        .await
        .expect_err("a registration with no possession proof must be refused");

    assert_eq!(
        status.code(),
        tonic::Code::Unauthenticated,
        "an unproven key is an authentication failure, not a validation one: {status:?}"
    );
    assert!(
        status.message().contains("possession_proof"),
        "the refusal must name the missing proof: {}",
        status.message()
    );
    assert_eq!(
        gateway.registry().list().len(),
        1,
        "only the baseline agent may exist; the forged registration must not have created a record"
    );
    Ok(())
}

/// **Bypass attempt: replay the CLI's registration verbatim.**
///
/// The whole request, unmodified, resubmitted. This is the attack a possession
/// proof over a *deterministic* value would not stop, and the reason the proof
/// signs a server-issued nonce instead.
#[tokio::test(flavor = "multi_thread")]
async fn replaying_the_clis_own_registration_is_refused() -> anyhow::Result<()> {
    let seen: Arc<Mutex<Vec<RegisterRequest>>> = Arc::default();
    let gateway = TestGateway::start_recording(Arc::clone(&seen)).await?;
    let _env = GatewayEnv::point_at(gateway.endpoint());

    run_registration::register(descriptor("replayed", "L2Enforce"))
        .await
        .expect("the baseline must be accepted, or there is nothing to replay");
    let captured = seen.lock().unwrap()[0].clone();

    let status = submit(gateway.endpoint(), captured.clone())
        .await
        .expect_err("a replayed registration must be refused");

    assert_eq!(status.code(), tonic::Code::Unauthenticated, "{status:?}");
    assert!(
        status.message().contains("already-used") || status.message().contains("unknown"),
        "the refusal must be about the spent nonce, not something incidental: {}",
        status.message()
    );

    // Replaying again is still refused — the nonce is gone, not merely rotated.
    assert!(submit(gateway.endpoint(), captured).await.is_err());
    Ok(())
}

/// **Bypass attempt: knowing the victim's identifier is not enough (AAASM-5332).**
///
/// This is the ticket's core acceptance criterion, attempted for real against
/// the real gateway. The attacker is given every public fact about the victim —
/// the operator-facing agent id, which appears in audit records, topology views
/// and on the dashboard, plus the `did:key` it registered under — and tries the
/// break that worked before AAASM-5332: reconstruct the private key by hashing
/// the identifier, then present a genuine signature made with it.
///
/// It fails at the DID↔key binding, because the victim's DID now names a
/// randomly generated key rather than `SHA-256(agent_id)`. The registry is
/// checked afterwards so a refusal cannot be confused with a refusal that still
/// left a record behind.
#[tokio::test(flavor = "multi_thread")]
async fn knowing_the_victims_identifier_does_not_let_an_attacker_register_as_it() -> anyhow::Result<()> {
    let gateway = TestGateway::start().await?;
    let _env = GatewayEnv::point_at(gateway.endpoint());

    // The victim registers normally; the attacker observes what is public.
    let victim = run_registration::register(descriptor("finance-bot", "L2Enforce")).await?;
    let public_identifier = victim.agent_id.clone();
    let public_did = victim.registration_did.clone();

    // The pre-AAASM-5332 derivation, applied to the public identifier. This is
    // precisely the computation that used to yield the victim's private key.
    let reconstructed = AgentKeypair::derive_transport_key(&public_identifier);
    assert_ne!(
        reconstructed.did_key(),
        public_did,
        "the identifier still derives the victim's DID, so the key behind it is still public"
    );

    // A challenge for the attacker's own derived identity — the gateway issues
    // it, because the attacker does hold that key. The nonce is then aimed at
    // the victim's DID, which is the attack.
    let attacker_config = sdk_config("attacker-5332");
    let nonce = fresh_nonce(gateway.endpoint(), &attacker_config).await;

    let forged = RegisterRequest {
        agent_id: Some(ProtoAgentId {
            org_id: String::new(),
            team_id: TEAM.to_string(),
            agent_id: public_did.clone(),
        }),
        name: "claude_code".to_string(),
        framework: "aasm-run".to_string(),
        version: "2.1.999".to_string(),
        public_key: reconstructed.public_key_hex(),
        possession_proof: reconstructed.sign(&nonce).to_vec(),
        registration_nonce: nonce,
        ..Default::default()
    };

    let status = submit(gateway.endpoint(), forged)
        .await
        .expect_err("an identity reconstructed from the public agent id must be refused");
    assert_eq!(status.code(), tonic::Code::Unauthenticated, "{status:?}");

    // Exactly one record — the victim's own. The attacker created nothing.
    let records = gateway.registry().list();
    assert_eq!(
        records.len(),
        1,
        "the forged registration must not have produced a record"
    );
    Ok(())
}

/// **Bypass attempt: use the CLI's identity with an attacker's key.**
///
/// Presents the victim's `did:key` paired with the attacker's own public key and
/// a *valid* proof under that key. Only the DID↔key binding stands between this
/// and a squatted identity (AAASM-4787).
#[tokio::test(flavor = "multi_thread")]
async fn registering_the_clis_did_under_a_foreign_key_is_refused() -> anyhow::Result<()> {
    let gateway = TestGateway::start().await?;
    let _env = GatewayEnv::point_at(gateway.endpoint());

    let victim_did = run_registration::registration_did("ops-laptop");
    let attacker = AgentKeypair::derive_transport_key("attacker");

    // A challenge for the attacker's *own* identity, which the gateway will
    // issue: the attacker holds that key. The nonce is then redirected at the
    // victim's DID, which is the actual attack.
    let attacker_config = sdk_config("attacker");
    let nonce = fresh_nonce(gateway.endpoint(), &attacker_config).await;

    let squat = RegisterRequest {
        agent_id: Some(ProtoAgentId {
            org_id: String::new(),
            team_id: TEAM.to_string(),
            agent_id: victim_did.clone(),
        }),
        name: "claude_code".to_string(),
        framework: "aasm-run".to_string(),
        version: "2.1.999".to_string(),
        public_key: attacker.public_key_hex(),
        possession_proof: attacker.sign(&nonce).to_vec(),
        registration_nonce: nonce,
        ..Default::default()
    };

    let status = submit(gateway.endpoint(), squat)
        .await
        .expect_err("a DID paired with a foreign key must be refused");

    assert_eq!(status.code(), tonic::Code::Unauthenticated, "{status:?}");
    assert!(
        status.message().contains("did:key"),
        "the refusal must name the binding that failed: {}",
        status.message()
    );
    assert!(
        gateway.registry().list().is_empty(),
        "no record may exist for a DID nobody proved they own"
    );
    Ok(())
}

// ── parity: neither surface is on easier terms than the other ──────────────

/// Equivalent inputs, equivalent outcomes — asserted in both directions, and the
/// re-bind rule pinned from both sides (AAASM-6447).
///
/// Forward: the SDK configured with the identifier the CLI already registered
/// resolves to the CLI's record rather than creating a second one, which is a
/// stronger statement than "both were accepted": it shows the two surfaces are one
/// agent in the registry, which is what a single identity contract has to mean. The
/// CLI registers with no operator key, so its record has no organization, but both
/// surfaces hold one random durable key for the identifier, and the CLI's request
/// declared it (`durable_identity_key`), so the SDK process that proves possession
/// of that key is re-bound to the CLI's record and handed the CLI's own credential.
///
/// Authorized half: an SDK presenting an operator key bound to an organization
/// registers, and a *later process* presenting that key again re-binds to the same
/// record and credential. The two keyed registrations are one agent, distinct from
/// the CLI's org-less one.
///
/// Backward: an SDK request degraded exactly as the CLI's was is refused by the
/// same check with the same code and the same message. Without this half, a
/// gateway that accepted everything would satisfy the forward half.
#[tokio::test(flavor = "multi_thread")]
async fn the_cli_and_the_sdk_get_the_same_verdicts() -> anyhow::Result<()> {
    let key = aa_auth::api_key::ApiKey::generate();
    let entry = aa_auth::api_key::ApiKeyEntry {
        id: "cli-parity".into(),
        key_hash: key.hash().expect("hash the operator key"),
        scopes: vec![aa_auth::scope::Scope::Read],
        created_at: 0,
        expires_at: None,
        label: None,
        team_id: None,
        org_id: Some("acme".into()),
        key_lookup: Some(key.lookup()),
    };
    let binder =
        aa_gateway::service::org_binding::OrgBinder::new(Arc::new(aa_auth::api_key::ApiKeyStore::from_entries(vec![
            entry,
        ])));
    let gateway = TestGateway::start_with_binder(binder).await?;
    let _env = GatewayEnv::point_at(gateway.endpoint());

    // The CLI's path: accepted.
    let cli = run_registration::register(descriptor("shared-identity", "L2Enforce"))
        .await
        .expect("the CLI must be accepted");
    let cli_token = gateway
        .registry()
        .list()
        .iter()
        .map(|r| r.credential_token.clone())
        .next()
        .expect("the CLI's record exists");

    // The SDK's path, same identifier and no operator key. The CLI and the SDK
    // hold one durable key for one identifier, so this is the same agent: the later
    // process proves possession of the key the CLI registered with and is re-bound
    // to that record (AAASM-6447), not filed beside it and not refused.
    let config = sdk_config("shared-identity");
    let nonce = fresh_nonce(gateway.endpoint(), &config).await;
    let sdk = build_register_request(&config, "sdk-agent".into(), "langgraph".into(), &nonce)
        .expect("the SDK agent must have a durable identity");
    assert_eq!(
        sdk.agent_id.as_ref().expect("agent_id is set").agent_id,
        cli.registration_did,
        "the two surfaces must derive one identity from one identifier"
    );
    let sdk_token = submit_token(gateway.endpoint(), sdk)
        .await
        .expect("the SDK process holds the CLI's key and must re-bind to its record");
    assert_eq!(
        sdk_token, cli_token,
        "re-binding returns the CLI record's own credential, not a new one"
    );
    assert_eq!(
        gateway.registry().list().len(),
        1,
        "one identifier must produce one agent, whichever surface registered it: {:?}",
        gateway
            .registry()
            .list()
            .iter()
            .map(|r| hex::encode(r.agent_id))
            .collect::<Vec<_>>()
    );

    // Authorized half: with an org-bound operator key an SDK process registers,
    // and the next process of the same agent re-binds to it.
    let keyed = sdk_config("keyed-identity");
    let registration_key = aa_sdk_client::RegistrationKey::new(key.as_str());
    let mut tokens = Vec::new();
    for _ in 0..2 {
        let mut client = aa_sdk_client::gateway::GatewayRegistrationClient::connect(gateway.endpoint().to_string())
            .await
            .expect("the test gateway must be reachable");
        let challenge = client
            .request_challenge(build_challenge_request(&keyed).expect("durable identity"))
            .await
            .expect("challenge");
        let request = build_register_request(&keyed, "sdk-agent".into(), "langgraph".into(), &challenge.nonce)
            .expect("durable identity");
        let response = client
            .register_with_key(request, Some(&registration_key))
            .await
            .expect("an operator-authorized process must register and re-bind");
        assert_eq!(response.org_id.as_deref(), Some("acme"));
        tokens.push(response.credential_token);
    }
    assert_eq!(
        tokens[0], tokens[1],
        "the later process re-binds to the same credential"
    );
    assert_ne!(tokens[0], cli_token, "the keyed agent is not the CLI's org-less agent");
    assert_eq!(
        gateway.registry().list().len(),
        2,
        "the CLI's agent and one keyed agent, no more"
    );

    // And the SDK is refused by exactly the check that refuses the CLI. A fresh
    // identifier, so the collision above cannot be what answers here.
    let other = sdk_config("sdk-only-identity");
    let mut proofless = build_register_request(
        &other,
        "sdk-agent".into(),
        "langgraph".into(),
        &fresh_nonce(gateway.endpoint(), &other).await,
    )
    .expect("the SDK agent must have a durable identity");
    proofless.possession_proof = Vec::new();
    let status = submit(gateway.endpoint(), proofless)
        .await
        .expect_err("the SDK must be refused without a proof, exactly as the CLI is");
    assert_eq!(status.code(), tonic::Code::Unauthenticated, "{status:?}");
    assert!(status.message().contains("possession_proof"), "{}", status.message());
    Ok(())
}

/// The default keyless quickstart across a process restart (AAASM-6447): each
/// process builds its configuration afresh and reads the agent's key back from the
/// identity directory, as a restarted process does. The agent keeps one identity
/// and one record, and is handed the credential it already had.
#[tokio::test(flavor = "multi_thread")]
async fn a_keyless_sdk_agent_keeps_one_identity_across_a_process_restart() -> anyhow::Result<()> {
    let gateway = TestGateway::start().await?;
    let mut seen = Vec::new();
    for _process in 0..3 {
        let config = sdk_config("restarted-keyless-agent");
        let nonce = fresh_nonce(gateway.endpoint(), &config).await;
        let request = build_register_request(&config, "sdk-agent".into(), "langgraph".into(), &nonce)
            .expect("the SDK agent must have a durable identity");
        let did = request.agent_id.as_ref().expect("agent_id is set").agent_id.clone();
        let token = submit_token(gateway.endpoint(), request)
            .await
            .expect("every process of the agent registers or re-binds");
        seen.push((did, token));
    }
    assert!(
        seen.iter().all(|s| s == &seen[0]),
        "one agent id and one credential across restarts: {seen:?}"
    );
    assert_eq!(gateway.registry().list().len(), 1, "a restart is not a second agent");
    Ok(())
}

/// Possession of the key is the whole authorization. The same identifier with a
/// different key (a fresh identity directory, a second machine, an attacker who
/// knows the label) is another did, so another agent: it registers on its own and
/// the first agent's record and credential are untouched and never disclosed.
#[tokio::test(flavor = "multi_thread")]
async fn the_same_identifier_with_another_key_is_a_separate_agent_not_a_takeover() -> anyhow::Result<()> {
    let gateway = TestGateway::start().await?;
    let owner = sdk_config("contested-label");
    let owner_token = submit_token(
        gateway.endpoint(),
        build_register_request(
            &owner,
            "sdk-agent".into(),
            "langgraph".into(),
            &fresh_nonce(gateway.endpoint(), &owner).await,
        )
        .expect("durable identity"),
    )
    .await
    .expect("the owner registers");

    let mut elsewhere = sdk_config("contested-label");
    elsewhere.identity_dir = Some(
        std::env::temp_dir()
            .join(format!("aa-cli-other-holder-{}", std::process::id()))
            .to_string_lossy()
            .into_owned(),
    );
    let _ = std::fs::remove_dir_all(elsewhere.identity_dir.as_deref().expect("set above"));
    let request = build_register_request(
        &elsewhere,
        "sdk-agent".into(),
        "langgraph".into(),
        &fresh_nonce(gateway.endpoint(), &elsewhere).await,
    )
    .expect("durable identity");
    let other_token = submit_token(gateway.endpoint(), request)
        .await
        .expect("another key is another agent and registers on its own");
    assert_ne!(
        other_token, owner_token,
        "the other holder never receives the owner's credential"
    );
    assert_eq!(gateway.registry().list().len(), 2);
    Ok(())
}

/// The CLI must not hold on to a nonce between registrations. Two runs of the
/// same identity produce two distinct nonces and two distinct proofs — if it
/// cached one, the second run's request would be a replay of the first and the
/// gateway would refuse it.
#[tokio::test(flavor = "multi_thread")]
async fn the_cli_takes_a_fresh_challenge_for_every_registration() -> anyhow::Result<()> {
    let seen: Arc<Mutex<Vec<RegisterRequest>>> = Arc::default();
    let gateway = TestGateway::start_recording(Arc::clone(&seen)).await?;
    let _env = GatewayEnv::point_at(gateway.endpoint());

    let first = run_registration::register(descriptor("repeat-runner", "L2Enforce")).await?;
    run_registration::deregister(&first, "test").await;
    run_registration::register(descriptor("repeat-runner", "L2Enforce"))
        .await
        .expect("a second run must be accepted; a cached nonce would be refused as a replay");

    let requests = seen.lock().unwrap().clone();
    assert_eq!(requests.len(), 2);
    assert_ne!(
        requests[0].registration_nonce, requests[1].registration_nonce,
        "the CLI reused a nonce across runs, so its second request is a replay of its first"
    );
    assert_ne!(
        requests[0].possession_proof, requests[1].possession_proof,
        "a proof that does not change between runs is a proof that can be replayed"
    );
    assert_eq!(
        requests[0].public_key, requests[1].public_key,
        "the identity itself must be stable across runs — that is what joins the audit trail up"
    );
    Ok(())
}
