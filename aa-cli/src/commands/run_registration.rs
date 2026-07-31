//! Governed gateway registration for `aasm run` (AAASM-5323).
//!
//! # The failure this exists to remove
//!
//! `aasm run` used to register by `POST /api/v1/agents`. No such route exists —
//! `aa-api`'s router mounts `get(agents::list_agents)` and nothing else on that
//! path — so every launch died on `HTTP 405` and the tool was never started.
//!
//! Adding the missing route was rejected. The CLI's request body carried a tool
//! name, a version and some free-form identifiers; it carried no key, no
//! challenge and no proof. A gateway that accepted it would be minting a
//! `credential_token` for whoever could reach the port, which is precisely the
//! gate `AgentLifecycleService.Register` spends three checks closing:
//!
//! * a non-empty, well-formed Ed25519 `public_key`;
//! * `enforce_did_key_binding` — the `did:key` being registered must embed that
//!   exact key, so a caller cannot squat a victim's DID with its own keypair
//!   (AAASM-4787);
//! * `verify_possession_proof` over a **server-issued, single-use, time-bound**
//!   nonce obtained from `RequestChallenge` (AAASM-3591 / AAASM-3866).
//!
//! Serving the CLI over a second, weaker route would have meant one product with
//! two registration contracts, the weaker of which is reachable by anything that
//! can speak HTTP. So `aasm run` registers through the *same* gRPC handshake the
//! SDKs use, built by the *same* code in `aa-sdk-client` — there is one contract
//! and one gate, and the CLI is on the near side of it like everything else.
//!
//! # What is deliberately not here
//!
//! No trusted-operator shortcut. `aasm run` is the operator's own tool, run on
//! the operator's own machine, and none of that is an argument for a weaker
//! identity: the process this command launches is exactly the software the gate
//! exists to govern, and it inherits whatever authority the launch was granted.
//!
//! No local decision about whether a registration is acceptable. This module
//! builds a request, submits it, and reports what the gateway said. Every
//! verdict is the gateway's.

use std::fmt;

use aa_proto::assembly::agent::v1::{DeregisterRequest, RegisterRequest};
use aa_proto::assembly::common::v1::AgentId as ProtoAgentId;
use aa_sdk_client::gateway::{build_challenge_request, build_register_request, GatewayRegistrationClient};
use aa_sdk_client::{AssemblyConfig, SdkClientError};

/// The `framework` a CLI-launched session registers under.
///
/// The SDKs register the agent framework in this field (`langgraph`, `crewai`,
/// …). A dev tool launched by `aasm run` has no such framework; what the field
/// can honestly say is *which surface performed the registration*, so the
/// gateway registry and the audit trail can tell a governed launch apart from an
/// SDK-instrumented agent without inferring it from the name.
const LAUNCH_FRAMEWORK: &str = "aasm-run";

/// A registration the gateway accepted, and the identity it was accepted under.
#[derive(Clone)]
pub struct GovernedRegistration {
    /// The operator-facing identifier the keypair (and therefore the DID) is
    /// derived from. This is the value handed to the launched tool as
    /// `AA_AGENT_ID`, and it is what makes the correlation in
    /// [`registration_did`](Self::registration_did) reproducible: anything that
    /// derives from this identifier — an SDK inside the launched tool, a later
    /// `aasm run` for the same agent — arrives at the same DID.
    pub agent_id: String,
    /// The `did:key` the gateway registered, and the identity every audit record
    /// for this session is attributed to.
    pub registration_did: String,
    /// The gateway's own registry key for this agent, hex-encoded.
    ///
    /// Computed with the gateway's own [`proto_agent_id_to_key`] rather than
    /// invented locally, so it is the key that actually indexes the record and
    /// the id `GET`/`DELETE /api/v1/agents/{id}` accept — both of which require
    /// exactly 32 hex characters, which is why the dashed UUID this field used
    /// to hold could never have addressed anything.
    ///
    /// [`proto_agent_id_to_key`]: aa_gateway::registry::convert::proto_agent_id_to_key
    pub registration_id: String,
    /// The team the gateway scoped the registration to — its echo of the
    /// request, not the request itself.
    pub team_id: Option<String>,
    /// Credential minted by the gateway for this registration.
    ///
    /// Private, and never placed in the launched tool's environment. It
    /// authenticates *as the registered agent*; handing it to the child would
    /// give the governed process the ability to speak for its own governance
    /// record, and would additionally expose it through `ps`, `/proc`, and the
    /// `--dry-run` environment dump.
    credential_token: String,
    /// Where the accepted registration lives, so the teardown reaches the same
    /// gateway that issued the token.
    endpoint: String,
}

/// Why a session could not be registered.
///
/// Every variant is a refusal: a launch that reaches one of these must not
/// happen. Messages name the endpoint and the gateway's own reason so an
/// operator can act on them, and carry no key material and no credential token.
#[derive(Debug)]
pub enum RegistrationError {
    /// The gateway's gRPC endpoint could not be reached at all.
    GatewayUnreachable { endpoint: String },
    /// The gateway refused to issue a registration challenge.
    ChallengeRefused { endpoint: String, reason: String },
    /// The gateway refused the registration itself.
    RegistrationRefused { endpoint: String, reason: String },
}

impl std::error::Error for RegistrationError {}

impl fmt::Display for RegistrationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::GatewayUnreachable { endpoint } => write!(
                f,
                "the governance gateway at {endpoint} is unreachable, so this session cannot be \
                 registered. Start one with `aasm gateway start`, or point `AA_GATEWAY_ENDPOINT` \
                 at the right gRPC endpoint (note: the gRPC port, not the `--api-url` HTTP one)"
            ),
            Self::ChallengeRefused { endpoint, reason } => write!(
                f,
                "the gateway at {endpoint} refused to issue a registration challenge: {reason}"
            ),
            Self::RegistrationRefused { endpoint, reason } => write!(
                f,
                "the gateway at {endpoint} refused this session's registration: {reason}"
            ),
        }
    }
}

/// What the launched session is registering *about* — the descriptive half of
/// the request, none of which the gate consults.
pub struct SessionDescriptor<'a> {
    /// Operator-facing agent identity to derive the keypair and DID from.
    pub agent_id: &'a str,
    /// Human-readable name for the registry (the dev tool being launched).
    pub name: &'a str,
    /// Detected version of the launched tool.
    pub version: &'a str,
    /// Team to scope the registration to.
    pub team_id: Option<&'a str>,
    /// Agent this session declares as its parent, from `--root-agent`.
    ///
    /// `RegisterRequest` has no root field: the gateway derives `root_agent_id`
    /// from the parent chain server-side, so the parent is the only place a
    /// declared lineage can be expressed. A parent the gateway does not know is
    /// an `InvalidArgument` and therefore a refusal — an unverifiable lineage
    /// claim must not be silently dropped into a successful launch.
    pub parent_agent_id: Option<&'a str>,
    /// Enforcement posture the operator asked for.
    pub enforcement_mode: aa_core::EnforcementMode,
    /// Governance level the adapter detected, carried as registry metadata.
    pub governance_level: &'a str,
}

/// Resolve the gateway gRPC endpoint this session registers against.
///
/// Deliberately the SDK's own resolution (`AA_GATEWAY_ENDPOINT`, else
/// `http://127.0.0.1:50051`) rather than a CLI-specific knob: two surfaces that
/// resolved the gateway differently could reach different gateways from the same
/// environment and produce different authorization outcomes for identical
/// inputs, which is exactly the divergence one contract is supposed to prevent.
///
/// Note this is *not* `--api-url`. That flag names the `:8080` HTTP/OpenAPI
/// surface the read-only `aasm` subcommands query; registration is a gRPC call
/// to `AgentLifecycleService`.
pub fn gateway_endpoint() -> String {
    sdk_config("", None, None).resolve_gateway_endpoint()
}

/// The `AssemblyConfig` an SDK would build for this identity.
///
/// Registration identity comes from exactly one place for both surfaces: the
/// `did:key` and `public_key` are derived here by `aa-sdk-client` from
/// `agent_id`, so a CLI launch and an SDK agent configured with the same
/// identifier register as the same DID under the same key.
fn sdk_config(agent_id: &str, team_id: Option<&str>, parent_agent_id: Option<&str>) -> AssemblyConfig {
    AssemblyConfig {
        agent_id: agent_id.to_string(),
        socket_path: None,
        gateway_endpoint: None,
        team_id: team_id.map(str::to_string),
        parent_agent_id: parent_agent_id.map(str::to_string),
        sdk_version: None,
    }
}

/// The `did:key` a given operator-facing identifier registers as.
pub fn registration_did(agent_id: &str) -> String {
    sdk_config(agent_id, None, None).registration_did()
}

/// The gateway's registry key for `(team, did)`, hex-encoded.
pub fn registry_id(team_id: Option<&str>, did: &str) -> String {
    hex::encode(aa_gateway::registry::convert::proto_agent_id_to_key(&ProtoAgentId {
        org_id: String::new(),
        team_id: team_id.unwrap_or_default().to_string(),
        agent_id: did.to_string(),
    }))
}

/// Map the CLI's enforcement posture onto the proto enum.
fn proto_enforcement_mode(mode: aa_core::EnforcementMode) -> i32 {
    use aa_proto::assembly::common::v1::EnforcementMode as Proto;
    match mode {
        aa_core::EnforcementMode::Enforce => Proto::Enforce as i32,
        aa_core::EnforcementMode::Observe => Proto::Observe as i32,
        aa_core::EnforcementMode::Disabled => Proto::Disabled as i32,
    }
}

/// Build the exact `RegisterRequest` this session submits.
///
/// Separate from [`register`] so the tests can assert on the request the CLI
/// actually sends. A test that rebuilt it would be asserting against its own
/// copy, which can agree with itself while having drifted from this one — the
/// shape of a fixture that cannot express the state it is supposed to catch.
fn build_session_request(desc: &SessionDescriptor<'_>, nonce: &[u8]) -> RegisterRequest {
    let config = sdk_config(desc.agent_id, desc.team_id, desc.parent_agent_id);
    let mut request = build_register_request(&config, desc.name.to_string(), LAUNCH_FRAMEWORK.to_string(), nonce);
    // Descriptive fields only. `build_register_request` owns every field the
    // gate reads (agent_id, public_key, registration_nonce, possession_proof);
    // overwriting any of those here would be the second implementation of the
    // identity contract this module exists to avoid.
    request.version = desc.version.to_string();
    request.enforcement_mode = proto_enforcement_mode(desc.enforcement_mode);
    request
        .metadata
        .insert("governance_level".to_string(), desc.governance_level.to_string());
    request
}

/// Register this session with the gateway over gRPC.
///
/// Performs the full handshake in one pass: request a challenge, sign the nonce
/// it returns, and submit the proof with the registration. The nonce never
/// outlives the call and is never written anywhere, so this path has nothing to
/// replay — and the gateway burns it on consumption regardless, before it even
/// checks the signature.
pub async fn register(desc: SessionDescriptor<'_>) -> Result<GovernedRegistration, RegistrationError> {
    let endpoint = gateway_endpoint();
    let config = sdk_config(desc.agent_id, desc.team_id, desc.parent_agent_id);

    let mut client = GatewayRegistrationClient::connect(endpoint.clone())
        .await
        .map_err(|_| RegistrationError::GatewayUnreachable {
            endpoint: endpoint.clone(),
        })?;

    let challenge = client
        .request_challenge(build_challenge_request(&config))
        .await
        .map_err(|e| RegistrationError::ChallengeRefused {
            endpoint: endpoint.clone(),
            reason: reason_of(e),
        })?;

    let request = build_session_request(&desc, &challenge.nonce);
    let did = config.registration_did();
    let response = client
        .register(request)
        .await
        .map_err(|e| RegistrationError::RegistrationRefused {
            endpoint: endpoint.clone(),
            reason: reason_of(e),
        })?;

    let team_id = response.team_id.or_else(|| desc.team_id.map(str::to_string));
    Ok(GovernedRegistration {
        registration_id: registry_id(team_id.as_deref(), &did),
        agent_id: desc.agent_id.to_string(),
        registration_did: did,
        team_id,
        credential_token: response.credential_token,
        endpoint,
    })
}

/// Release a registration over the same gRPC service that issued it,
/// authenticated by the credential token it minted.
///
/// Best-effort by design: the session is already over, and a gateway that has
/// gone away or has already swept the agent leaves nothing for the caller to do.
pub async fn deregister(registration: &GovernedRegistration, reason: &str) {
    let Ok(mut client) = GatewayRegistrationClient::connect(registration.endpoint.clone()).await else {
        return;
    };
    let _ = client
        .deregister(DeregisterRequest {
            agent_id: Some(ProtoAgentId {
                org_id: String::new(),
                team_id: registration.team_id.clone().unwrap_or_default(),
                agent_id: registration.registration_did.clone(),
            }),
            credential_token: registration.credential_token.clone(),
            reason: reason.to_string(),
        })
        .await;
}

/// The gateway's stated reason, or a stand-in when the transport failed before
/// one could be returned.
fn reason_of(e: SdkClientError) -> String {
    match e {
        SdkClientError::RegisterFailed(msg) if !msg.is_empty() => msg,
        other => other.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aa_sdk_client::AgentKeypair;
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};

    fn descriptor<'a>(agent_id: &'a str, team: Option<&'a str>) -> SessionDescriptor<'a> {
        SessionDescriptor {
            agent_id,
            name: "claude_code",
            version: "2.1.999",
            team_id: team,
            parent_agent_id: None,
            enforcement_mode: aa_core::EnforcementMode::Enforce,
            governance_level: "L0Discover",
        }
    }

    /// The whole point of routing the CLI through `aa-sdk-client`: the identity
    /// the CLI registers under is the identity the SDK derives from the same
    /// identifier. If these ever diverge the two surfaces are separate agents to
    /// the gateway, and nothing about "one contract" survives.
    #[test]
    fn the_cli_registers_under_the_same_did_as_the_sdk_for_the_same_identifier() {
        for id in ["ops-laptop", "team-a/bot", "did:key:z6MkfoobarNotDerived"] {
            assert_eq!(
                registration_did(id),
                aa_sdk_client::agent_id_to_did_key(id),
                "the CLI must not derive its own identity for `{id}`"
            );
        }
    }

    /// The pair the CLI submits must satisfy the gateway's own checks: a
    /// well-formed `did:key`, and a DID that embeds the very key `public_key`
    /// names (`enforce_did_key_binding`, AAASM-4787). Asserted by calling the
    /// gateway's functions rather than by re-deriving the rules here — a
    /// re-derivation could agree with itself while disagreeing with the gate.
    #[test]
    fn the_submitted_pair_passes_the_gateways_own_identity_checks() {
        use aa_gateway::registry::convert::{assert_did_key_binds_public_key, validate_proto_agent_id};

        let desc = descriptor("binding-check", Some("team-a"));
        let request = build_session_request(&desc, b"nonce-bytes-for-the-binding-check");
        let proto_id = request.agent_id.as_ref().expect("agent_id is set");

        validate_proto_agent_id(proto_id).expect("the gateway must accept the submitted agent_id");
        assert_did_key_binds_public_key(&proto_id.agent_id, &request.public_key)
            .expect("the DID and the public_key must encode the same key, or the pair is refused");

        // The binding is what makes the DID unsquattable, so a mismatched key
        // must be refused by the same check — proving the check is live rather
        // than vacuously satisfied by whatever was passed in.
        let foreign = AgentKeypair::derive("somebody-else").public_key_hex();
        assert!(
            assert_did_key_binds_public_key(&proto_id.agent_id, &foreign).is_err(),
            "a DID paired with a foreign key must be refused; if this passes, the binding check \
             is not actually comparing anything"
        );
    }

    /// The possession proof must be a real signature over the *server's* nonce.
    /// A proof over anything else — most of all over the public, deterministic
    /// `agent_id` — is precomputable by anyone who knows the id.
    #[test]
    fn the_possession_proof_signs_the_server_nonce_and_verifies_under_the_public_key() {
        let desc = descriptor("proof-check", None);
        let nonce = b"a-server-issued-nonce-32-bytes!!".to_vec();
        let request = build_session_request(&desc, &nonce);

        assert_eq!(
            request.registration_nonce, nonce,
            "the server's nonce must be returned verbatim"
        );
        assert_eq!(request.possession_proof.len(), 64, "an Ed25519 signature is 64 bytes");

        let key_bytes: [u8; 32] = hex::decode(&request.public_key)
            .expect("public_key is hex")
            .try_into()
            .expect("public_key is 32 bytes");
        let verifying = VerifyingKey::from_bytes(&key_bytes).expect("a valid Ed25519 key");
        let signature = Signature::from_bytes(&request.possession_proof.clone().try_into().expect("64-byte signature"));

        verifying
            .verify(&nonce, &signature)
            .expect("the proof must verify over the nonce the gateway issued");
        assert!(
            verifying.verify(desc.agent_id.as_bytes(), &signature).is_err(),
            "the proof must not be a signature over the public agent id — that value is \
             deterministic and knowable in advance, so a proof over it is replayable"
        );
    }

    /// A fresh challenge per registration is what makes the proof unrepeatable.
    /// The same identity registering twice must sign two different nonces, or
    /// the second request is byte-identical to the first and replayable.
    #[test]
    fn two_registrations_of_one_identity_produce_different_proofs() {
        let desc = descriptor("replay-check", None);
        let first = build_session_request(&desc, b"first-server-issued-nonce-value!");
        let second = build_session_request(&desc, b"second-server-issued-nonce-valu");

        assert_eq!(
            first.public_key, second.public_key,
            "the identity is stable across runs — that is what keeps the audit trail joined up"
        );
        assert_ne!(
            first.possession_proof, second.possession_proof,
            "a proof that does not change with the nonce is a proof that can be replayed"
        );
    }

    /// The keypair the proof is made with is the one the DID names, so the
    /// signature the CLI produces is the signature the SDK would produce.
    #[test]
    fn the_cli_signs_with_the_same_key_the_sdk_would() {
        let nonce = b"shared-nonce";
        let desc = descriptor("parity-check", None);
        let cli = build_session_request(&desc, nonce);
        let sdk = build_register_request(
            &sdk_config("parity-check", None, None),
            "any-name".to_string(),
            "langgraph".to_string(),
            nonce,
        );

        assert_eq!(cli.public_key, sdk.public_key);
        assert_eq!(
            cli.possession_proof, sdk.possession_proof,
            "the two surfaces must present the same proof for the same identity and nonce"
        );
        assert_eq!(AgentKeypair::derive("parity-check").public_key_hex(), cli.public_key);
    }

    /// The registry id must be the gateway's own key for the registered
    /// identity: 32 hex characters, which is the only shape
    /// `GET`/`DELETE /api/v1/agents/{id}` will parse.
    #[test]
    fn the_registry_id_is_the_gateways_own_key_in_the_shape_the_api_accepts() {
        let did = registration_did("registry-id-check");
        let id = registry_id(Some("team-a"), &did);

        assert_eq!(id.len(), 32, "the API rejects anything that is not 32 hex characters");
        assert!(id.chars().all(|c| c.is_ascii_hexdigit()));
        assert_eq!(
            id,
            hex::encode(aa_gateway::registry::convert::proto_agent_id_to_key(&ProtoAgentId {
                org_id: String::new(),
                team_id: "team-a".to_string(),
                agent_id: did,
            })),
            "the id must be computed by the gateway's own function, not re-derived here"
        );
    }

    /// The team scopes the key, so two teams' registrations of the same
    /// identifier are distinct records rather than one shared one.
    #[test]
    fn the_registry_id_is_scoped_by_team() {
        let did = registration_did("scoping-check");
        assert_ne!(registry_id(Some("team-a"), &did), registry_id(Some("team-b"), &did));
        assert_ne!(registry_id(None, &did), registry_id(Some("team-a"), &did));
    }

    /// `--observe` must reach the gateway as a *claim*, not as a local decision.
    /// The gateway drops weakening claims from self-registering agents
    /// (AAASM-4121); that verdict is its to make, and sending nothing would hide
    /// the operator's request from it entirely.
    #[test]
    fn the_operators_enforcement_posture_is_sent_for_the_gateway_to_adjudicate() {
        use aa_proto::assembly::common::v1::EnforcementMode as Proto;
        assert_eq!(
            proto_enforcement_mode(aa_core::EnforcementMode::Enforce),
            Proto::Enforce as i32
        );
        assert_eq!(
            proto_enforcement_mode(aa_core::EnforcementMode::Observe),
            Proto::Observe as i32
        );
        assert_eq!(
            proto_enforcement_mode(aa_core::EnforcementMode::Disabled),
            Proto::Disabled as i32
        );
        assert_ne!(
            proto_enforcement_mode(aa_core::EnforcementMode::Observe),
            Proto::Unspecified as i32,
            "sending UNSPECIFIED would silently discard the operator's request rather than \
             letting the gateway rule on it"
        );
    }

    /// The endpoint is the gRPC one, resolved the way the SDK resolves it.
    #[test]
    fn the_gateway_endpoint_defaults_to_the_grpc_port_and_honours_the_sdk_env_var() {
        let _guard = crate::test_support::env_guard();
        let prior = std::env::var("AA_GATEWAY_ENDPOINT").ok();

        std::env::remove_var("AA_GATEWAY_ENDPOINT");
        let default = gateway_endpoint();

        std::env::set_var("AA_GATEWAY_ENDPOINT", "http://10.0.0.9:60000");
        let overridden = gateway_endpoint();

        match prior {
            Some(v) => std::env::set_var("AA_GATEWAY_ENDPOINT", v),
            None => std::env::remove_var("AA_GATEWAY_ENDPOINT"),
        }

        assert_eq!(default, aa_sdk_client::config::DEFAULT_GATEWAY_ENDPOINT);
        assert!(
            default.ends_with(":50051"),
            "registration is a gRPC call; the :8080 HTTP surface cannot serve it. Got {default}"
        );
        assert_eq!(overridden, "http://10.0.0.9:60000");
    }

    /// A refusal must say which gateway refused and what it said, so an operator
    /// is not left inferring it from an exit code.
    #[test]
    fn refusals_name_the_endpoint_and_the_gateways_reason() {
        let unreachable = RegistrationError::GatewayUnreachable {
            endpoint: "http://127.0.0.1:50051".into(),
        };
        assert!(unreachable.to_string().contains("http://127.0.0.1:50051"));
        assert!(unreachable.to_string().contains("unreachable"));

        let refused = RegistrationError::RegistrationRefused {
            endpoint: "http://127.0.0.1:50051".into(),
            reason: "possession_proof did not verify against public_key".into(),
        };
        assert!(refused.to_string().contains("possession_proof did not verify"));

        let challenge = RegistrationError::ChallengeRefused {
            endpoint: "http://127.0.0.1:50051".into(),
            reason: "agent_id is not a did:key DID".into(),
        };
        assert!(challenge.to_string().contains("agent_id is not a did:key DID"));
    }
}
