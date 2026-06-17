//! Optional gRPC client for forwarding policy checks to `aa-gateway`.
//!
//! When the runtime is configured with a `gateway_endpoint`, policy queries
//! are forwarded over gRPC to the governance gateway instead of being
//! evaluated locally. This enables the full 7-stage policy pipeline.

use aa_proto::assembly::policy::v1::policy_service_client::PolicyServiceClient;
use aa_proto::assembly::policy::v1::{CheckActionRequest, CheckActionResponse};
use tonic::transport::Channel;

/// gRPC client wrapper for the governance gateway's `PolicyService`.
pub struct GatewayClient {
    client: PolicyServiceClient<Channel>,
}

impl GatewayClient {
    /// Connect to the gateway at the given endpoint.
    ///
    /// `endpoint` should be a URI like `"http://127.0.0.1:50051"` (TCP) or
    /// a UDS path handled by a custom connector.
    pub async fn connect(endpoint: &str) -> Result<Self, tonic::transport::Error> {
        let client = PolicyServiceClient::connect(endpoint.to_string()).await?;
        Ok(Self { client })
    }

    /// Forward a `CheckActionRequest` to the gateway and return the response.
    pub async fn check_action(&mut self, req: CheckActionRequest) -> Result<CheckActionResponse, tonic::Status> {
        let resp = self.client.check_action(req).await?;
        Ok(resp.into_inner())
    }

    /// Build a client over a **lazy** channel to `endpoint` without connecting.
    ///
    /// Used by the AAASM-3110 fail-closed test to obtain a `GatewayClient`
    /// whose `check_action` is guaranteed to fail (the endpoint never listens),
    /// exercising the gateway-unreachable path without standing up a server.
    #[cfg(test)]
    pub(crate) fn connect_lazy(endpoint: &'static str) -> Self {
        let channel = Channel::from_static(endpoint).connect_lazy();
        Self {
            client: PolicyServiceClient::new(channel),
        }
    }
}
