//! Tonic server adapter for [`InvalidationHub`].
//!
//! [`InvalidationServiceImpl`] wraps a shared [`InvalidationHub`] and implements
//! the generated `assembly.gateway.v1.InvalidationService` trait. The Subscribe
//! RPC reads the Assembly's opening `SubscribeInitial`, replays anything missed
//! since `last_seq_seen`, then streams live events; subsequent `SubscribeAck`
//! messages on the client→server half trim the replay ring.

use std::pin::Pin;
use std::sync::Arc;

use tokio::sync::broadcast::error::RecvError;
use tokio_stream::Stream;
use tonic::{Request, Response, Status, Streaming};

use aa_proto::assembly::gateway::v1::invalidation_service_server::InvalidationService;
use aa_proto::assembly::gateway::v1::{subscribe_request::Kind, InvalidationEvent, SubscribeRequest};

use super::InvalidationHub;
use crate::iam::VerifiedCaller;

/// gRPC adapter exposing an [`InvalidationHub`] over the bidi-streaming
/// `InvalidationService`. Clone-cheap: holds only an `Arc` to the shared hub.
#[derive(Clone)]
pub struct InvalidationServiceImpl {
    hub: Arc<InvalidationHub>,
}

impl InvalidationServiceImpl {
    /// Wrap a shared hub for serving. The same hub is shared with the policy
    /// mutation path so `broadcast_policy_invalidated` reaches these streams.
    pub fn new(hub: Arc<InvalidationHub>) -> Self {
        Self { hub }
    }
}

#[tonic::async_trait]
impl InvalidationService for InvalidationServiceImpl {
    type SubscribeStream = Pin<Box<dyn Stream<Item = Result<InvalidationEvent, Status>> + Send + 'static>>;

    /// Open the persistent push-invalidation stream for one Assembly.
    ///
    /// The first inbound message must carry the `assembly_id` (and, for a
    /// resubscribe, `SubscribeInitial.last_seq_seen`). The hub replays missed
    /// events, then live events are forwarded until the client disconnects. A
    /// background task drains `SubscribeAck`s to advance the replay low-water
    /// mark.
    async fn subscribe(
        &self,
        request: Request<Streaming<SubscribeRequest>>,
    ) -> Result<Response<Self::SubscribeStream>, Status> {
        // The fail-closed auth interceptor (AAASM-3828) injects the verified
        // caller; capture its team so the hub scopes tenant-bound events to this
        // subscriber's tenant (AAASM-3890). A missing caller yields `None`, which
        // restricts the subscriber to global events only (fail-closed).
        let tenant = request
            .extensions()
            .get::<VerifiedCaller>()
            .and_then(|caller| caller.team_id.clone());

        let mut inbound = request.into_inner();

        let Some(first) = inbound.message().await? else {
            return Err(Status::invalid_argument(
                "stream closed before initial SubscribeRequest",
            ));
        };
        if first.assembly_id.is_empty() {
            return Err(Status::invalid_argument("assembly_id is required"));
        }
        let assembly_id = first.assembly_id;
        let last_seq_seen = match first.kind {
            Some(Kind::Initial(initial)) => initial.last_seq_seen,
            // An Ack (or no kind) as the opener carries no resume point; treat
            // it as a cold subscription.
            _ => 0,
        };

        // AAASM-3997: the hub keys subscribers by `(tenant, assembly_id)`, so a
        // cross-tenant `assembly_id` clash yields an independent slot rather than
        // hijacking (or being denied service by) another tenant's subscription.
        // The `tenant` is also needed to trim the correct ring on Ack below.
        let tenant_for_ack = tenant.clone();
        let handle = self.hub.subscribe(assembly_id.clone(), tenant, last_seq_seen).map_err(
            |super::SubscribeError::TenantMismatch| {
                Status::permission_denied("assembly_id is registered to a different tenant")
            },
        )?;

        // Drain client→server Acks so the hub can trim each subscriber's ring.
        let hub = Arc::clone(&self.hub);
        tokio::spawn(async move {
            while let Ok(Some(message)) = inbound.message().await {
                if let Some(Kind::Ack(ack)) = message.kind {
                    hub.ack(tenant_for_ack.as_deref(), &assembly_id, ack.seq);
                }
            }
        });

        let super::SubscriptionHandle { replay, mut receiver } = handle;
        let stream = async_stream::try_stream! {
            for event in replay {
                yield event;
            }
            loop {
                match receiver.recv().await {
                    Ok(event) => yield event,
                    // Lagged: the live channel overflowed. Skip the gap; the
                    // client reconciles by reconnecting with last_seq_seen.
                    Err(RecvError::Lagged(_)) => continue,
                    Err(RecvError::Closed) => break,
                }
            }
        };

        Ok(Response::new(Box::pin(stream)))
    }
}
