//! Control-channel client used by `aa-runtime` to drive the privileged loader
//! daemon (AAASM-3604).
//!
//! `aa-runtime` holds NO BPF privilege; it asks the daemon to perform probe
//! lifecycle operations over this connection. A single request → single
//! response round-trip per call keeps the client trivial and stateless.

use std::path::Path;

use tokio::net::UnixStream;

use super::codec::{read_frame, write_frame};
use super::protocol::{ControlRequest, ControlResponse, PathRuleWire, ProbeSet};
use crate::error::EbpfError;

/// A connection to the privileged `aa-ebpf-loaderd` control socket.
pub struct LoaderControlClient {
    stream: UnixStream,
}

impl LoaderControlClient {
    /// Connect to the daemon's control socket at `path`.
    pub async fn connect(path: impl AsRef<Path>) -> Result<Self, EbpfError> {
        let stream = UnixStream::connect(path.as_ref()).await?;
        Ok(Self { stream })
    }

    /// Send one request and await the single response.
    async fn request(&mut self, req: &ControlRequest) -> Result<ControlResponse, EbpfError> {
        write_frame(&mut self.stream, req).await?;
        read_frame(&mut self.stream)
            .await?
            .ok_or_else(|| EbpfError::EventParse("control connection closed before response".into()))
    }

    /// Map an [`ControlResponse::Error`] onto an `Err`; treat `Ok`/`Pong` as success.
    fn into_result(resp: ControlResponse) -> Result<(), EbpfError> {
        match resp {
            ControlResponse::Ok | ControlResponse::Pong => Ok(()),
            ControlResponse::Error { message } => Err(EbpfError::ProgramLoad(message)),
        }
    }

    /// Ask the daemon to load + attach a probe set for `target_pid`.
    pub async fn load_probe_set(&mut self, set: ProbeSet, target_pid: u32) -> Result<(), EbpfError> {
        let resp = self.request(&ControlRequest::LoadProbeSet { set, target_pid }).await?;
        Self::into_result(resp)
    }

    /// Replace the path deny/allow map with `rules`.
    pub async fn update_path_map(&mut self, rules: Vec<PathRuleWire>) -> Result<(), EbpfError> {
        let resp = self.request(&ControlRequest::UpdatePathMap { rules }).await?;
        Self::into_result(resp)
    }

    /// Detach + unload a probe set.
    pub async fn detach(&mut self, set: ProbeSet) -> Result<(), EbpfError> {
        let resp = self.request(&ControlRequest::Detach { set }).await?;
        Self::into_result(resp)
    }

    /// Liveness check.
    pub async fn ping(&mut self) -> Result<(), EbpfError> {
        let resp = self.request(&ControlRequest::Ping).await?;
        Self::into_result(resp)
    }
}
