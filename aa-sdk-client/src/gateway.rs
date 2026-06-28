//! Direct gateway gRPC client for agent registration (AAASM-3396).
//!
//! Per ADR 0004, the SDK enforcement path is SDK → `aa-sdk-client` → core.
//! `CheckAction` reaches the gateway via the `aa-runtime` UDS forward and stays
//! that way. The one gap this module closes is **registration**: nothing on the
//! SDK path called `AgentLifecycleService.Register`, so the gateway never issued
//! a `credential_token` — and a registered agent's later `CheckAction` would be
//! denied by the gateway's `validate_credential_token` for lacking one.
//!
//! This module gives `aa-sdk-client` a *direct* gRPC client to the gateway's
//! `AgentLifecycleService.Register` RPC. The returned `credential_token` is held
//! by the [`AssemblyClient`](crate::client::AssemblyClient) and attached to
//! subsequent `CheckActionRequest`s (see `query_policy`).

use aa_proto::assembly::agent::v1::agent_lifecycle_service_client::AgentLifecycleServiceClient;
use aa_proto::assembly::agent::v1::{ChallengeRequest, ChallengeResponse, RegisterRequest, RegisterResponse};
use aa_proto::assembly::common::v1::AgentId as ProtoAgentId;
use tonic::transport::Channel;

use crate::config::AssemblyConfig;
use crate::error::SdkClientError;
use crate::keypair::AgentKeypair;

/// Thin wrapper over the generated `AgentLifecycleServiceClient`, scoped to the
/// SDK's only direct gateway call: `Register`.
pub struct GatewayRegistrationClient {
    client: AgentLifecycleServiceClient<Channel>,
}

impl GatewayRegistrationClient {
    /// Connect to the gateway gRPC endpoint (e.g. `"http://127.0.0.1:50051"`).
    pub async fn connect(endpoint: String) -> Result<Self, SdkClientError> {
        let client = AgentLifecycleServiceClient::connect(endpoint)
            .await
            .map_err(|_| SdkClientError::GatewayUnreachable)?;
        Ok(Self { client })
    }

    /// Call `AgentLifecycleService.RequestChallenge` to obtain a fresh
    /// server-issued possession-proof nonce (AAASM-3866). The agent signs the
    /// returned `nonce` and submits it via [`build_register_request`] so the
    /// gateway can verify possession over an unpredictable value rather than the
    /// public, deterministic `agent_id`.
    pub async fn request_challenge(&mut self, request: ChallengeRequest) -> Result<ChallengeResponse, SdkClientError> {
        let resp = self
            .client
            .request_challenge(request)
            .await
            .map_err(|status| SdkClientError::RegisterFailed(status.message().to_string()))?;
        Ok(resp.into_inner())
    }

    /// Call `AgentLifecycleService.Register` and return the response.
    pub async fn register(&mut self, request: RegisterRequest) -> Result<RegisterResponse, SdkClientError> {
        let resp = self
            .client
            .register(request)
            .await
            .map_err(|status| SdkClientError::RegisterFailed(status.message().to_string()))?;
        Ok(resp.into_inner())
    }
}

/// Build the `ChallengeRequest` for the registration possession-proof handshake
/// (AAASM-3866).
///
/// Derives the same deterministic [`AgentKeypair`] as [`build_register_request`]
/// so the `agent_id` + `public_key` the challenge is bound to match the ones the
/// agent later registers with.
pub fn build_challenge_request(config: &AssemblyConfig) -> ChallengeRequest {
    let keypair = AgentKeypair::derive(&config.agent_id);
    ChallengeRequest {
        agent_id: Some(ProtoAgentId {
            org_id: String::new(),
            team_id: config.team_id.clone().unwrap_or_default(),
            agent_id: config.registration_did(),
        }),
        public_key: keypair.public_key_hex(),
    }
}

/// Build the `RegisterRequest` the gateway requires from the SDK config.
///
/// Derives a deterministic [`AgentKeypair`] from `config.agent_id` so the
/// `agent_id` did:key and the `public_key` hex encode the *same* valid Ed25519
/// key — both of which the gateway validates at registration.
///
/// `nonce` is the server-issued challenge from [`build_challenge_request`] +
/// `request_challenge` (AAASM-3866); the possession proof signs it (not the
/// public, deterministic did:key) so the proof cannot be precomputed or
/// replayed.
pub fn build_register_request(
    config: &AssemblyConfig,
    name: String,
    framework: String,
    nonce: &[u8],
) -> RegisterRequest {
    let keypair = AgentKeypair::derive(&config.agent_id);
    let registration_did = config.registration_did();

    // AAASM-3591 / AAASM-3866: prove possession of the private key by signing the
    // server-issued nonce. The gateway verifies this over the same nonce before
    // minting a credential_token.
    let possession_proof = keypair.sign(nonce).to_vec();

    RegisterRequest {
        agent_id: Some(ProtoAgentId {
            org_id: String::new(),
            team_id: config.team_id.clone().unwrap_or_default(),
            agent_id: registration_did,
        }),
        name,
        framework,
        version: env!("CARGO_PKG_VERSION").to_string(),
        public_key: keypair.public_key_hex(),
        parent_agent_id: config.parent_agent_id.clone(),
        possession_proof,
        registration_nonce: nonce.to_vec(),
        ..Default::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(agent_id: &str) -> AssemblyConfig {
        AssemblyConfig {
            agent_id: agent_id.to_string(),
            socket_path: None,
            gateway_endpoint: None,
            team_id: None,
            parent_agent_id: None,
            sdk_version: None,
        }
    }

    const TEST_NONCE: &[u8] = &[7u8; 32];

    #[test]
    fn register_request_carries_did_and_consistent_public_key() {
        let config = cfg("my-agent");
        let req = build_register_request(&config, "My Agent".into(), "custom".into(), TEST_NONCE);

        let agent_id = req.agent_id.expect("agent_id must be set");
        assert!(agent_id.agent_id.starts_with("did:key:z"), "got {}", agent_id.agent_id);
        assert_eq!(req.name, "My Agent");
        assert_eq!(req.framework, "custom");

        // public_key must be 64 hex chars (32-byte Ed25519 key) — the gateway
        // rejects anything else.
        assert_eq!(req.public_key.len(), 64);

        // The did:key and the public_key must encode the same key.
        let pk_bytes = hex::decode(&req.public_key).unwrap();
        let did_payload = bs58::decode(agent_id.agent_id.strip_prefix("did:key:z").unwrap())
            .into_vec()
            .unwrap();
        assert_eq!(&did_payload[2..], pk_bytes.as_slice());
    }

    #[test]
    fn register_request_signs_the_server_nonce() {
        // AAASM-3866: the proof must verify as an Ed25519 signature over the
        // server-issued nonce (not the agent_id), and the nonce must be echoed
        // back so the gateway can re-derive the signed payload.
        use ed25519_dalek::{Signature, VerifyingKey};

        let config = cfg("my-agent");
        let req = build_register_request(&config, "My Agent".into(), "custom".into(), TEST_NONCE);

        assert_eq!(req.registration_nonce, TEST_NONCE);

        let pk_bytes: [u8; 32] = hex::decode(&req.public_key).unwrap().try_into().unwrap();
        let vk = VerifyingKey::from_bytes(&pk_bytes).unwrap();
        let sig = Signature::from_bytes(&req.possession_proof.as_slice().try_into().unwrap());
        // Verifies over the nonce …
        assert!(vk.verify_strict(TEST_NONCE, &sig).is_ok());
        // … and NOT over the did:key (the old, replayable challenge).
        let did = req.agent_id.unwrap().agent_id;
        assert!(vk.verify_strict(did.as_bytes(), &sig).is_err());
    }

    #[test]
    fn challenge_request_binds_same_did_and_public_key_as_register() {
        let config = cfg("my-agent");
        let challenge = build_challenge_request(&config);
        let req = build_register_request(&config, "My Agent".into(), "custom".into(), TEST_NONCE);

        assert_eq!(challenge.agent_id, req.agent_id);
        assert_eq!(challenge.public_key, req.public_key);
    }

    #[test]
    fn register_request_forwards_team_id_and_parent_agent_id() {
        let mut config = cfg("child-agent");
        config.team_id = Some("team-payments".into());
        config.parent_agent_id = Some("11111111-2222-3333-4444-555555555555".into());

        let req = build_register_request(&config, "Child".into(), "custom".into(), TEST_NONCE);

        assert_eq!(req.agent_id.expect("agent_id must be set").team_id, "team-payments");
        assert_eq!(
            req.parent_agent_id.as_deref(),
            Some("11111111-2222-3333-4444-555555555555")
        );
    }

    #[test]
    fn register_request_omits_lineage_when_unset() {
        let config = cfg("root-agent");
        let req = build_register_request(&config, "Root".into(), "custom".into(), TEST_NONCE);

        assert_eq!(req.agent_id.expect("agent_id must be set").team_id, "");
        assert_eq!(req.parent_agent_id, None);
    }
}
