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

    /// Build a client over a **lazy** channel to an owned `endpoint` without
    /// connecting eagerly (AAASM-3430).
    ///
    /// Used by the runtime when the gateway endpoint is configured but the
    /// initial eager [`connect`](Self::connect) fails: the runtime must not
    /// silently fall back to permissive local evaluation. A lazy client lets
    /// the pipeline's fail-closed path (AAASM-3110) deny checks while the
    /// gateway is unreachable, and recover automatically once it comes up.
    ///
    /// Returns `None` if `endpoint` is not a valid URI.
    pub fn connect_lazy_owned(endpoint: &str) -> Option<Self> {
        let channel = Channel::from_shared(endpoint.to_string()).ok()?.connect_lazy();
        Some(Self {
            client: PolicyServiceClient::new(channel),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn connect_lazy_owned_accepts_valid_uri() {
        // `connect_lazy` requires a tokio reactor in scope.
        assert!(GatewayClient::connect_lazy_owned("http://127.0.0.1:50051").is_some());
    }

    #[test]
    fn connect_lazy_owned_rejects_invalid_uri() {
        // An empty endpoint is not a valid URI and must not yield a client —
        // the runtime must surface None rather than degrade to local allow.
        assert!(GatewayClient::connect_lazy_owned("").is_none());
    }
}
