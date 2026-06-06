//! Client-side IPC codec for the aa-runtime socket protocol.
//!
//! Wire format (matches aa-runtime's codec):
//!   `[1-byte tag][prost varint length][prost-encoded payload]`
//!
//! The SDK client *writes* inbound tags (SDK → runtime):
//!   1 = PolicyQuery  (CheckActionRequest)
//!   2 = EventReport  (AuditEvent)
//!   3 = ApprovalResponse (ApprovalDecision)
//!   4 = Heartbeat    (tag byte only, no length/payload)
//!
//! The SDK client *reads* outbound tags (runtime → SDK):
//!   1 = PolicyResponse   (CheckActionResponse)
//!   2 = ApprovalDecision (ApprovalDecision)
//!   3 = Ack              (zero-length payload)
//!   4 = ViolationAlert   (PolicyViolation)

use prost::Message;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

// ── Tag constants (same as aa-runtime/src/ipc/codec.rs) ──────────────────────

// Inbound tags (SDK → runtime) — we write these.
pub const TAG_POLICY_QUERY: u8 = 1;
pub const TAG_EVENT_REPORT: u8 = 2;
#[allow(dead_code)]
pub const TAG_APPROVAL_RESPONSE: u8 = 3;
pub const TAG_HEARTBEAT: u8 = 4;

// Outbound tags (runtime → SDK) — we read these.
#[allow(dead_code)]
pub const TAG_POLICY_RESPONSE: u8 = 1;
#[allow(dead_code)]
pub const TAG_APPROVAL_DECISION: u8 = 2;
pub const TAG_ACK: u8 = 3;
#[allow(dead_code)]
pub const TAG_VIOLATION_ALERT: u8 = 4;

/// Errors that can occur during codec operations.
#[derive(Debug)]
pub enum CodecError {
    Io(std::io::Error),
    UnknownTag(u8),
    DecodeError(prost::DecodeError),
}

impl std::fmt::Display for CodecError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CodecError::Io(e) => write!(f, "IO error: {e}"),
            CodecError::UnknownTag(t) => write!(f, "unknown response tag: {t}"),
            CodecError::DecodeError(e) => write!(f, "prost decode error: {e}"),
        }
    }
}

impl From<std::io::Error> for CodecError {
    fn from(e: std::io::Error) -> Self {
        CodecError::Io(e)
    }
}

impl From<prost::DecodeError> for CodecError {
    fn from(e: prost::DecodeError) -> Self {
        CodecError::DecodeError(e)
    }
}

/// A response received from aa-runtime.
#[derive(Debug)]
#[allow(dead_code)] // Variants used as the protocol expands (AAASM-49+).
pub enum RuntimeResponse {
    Ack,
    PolicyResponse(aa_proto::assembly::policy::v1::CheckActionResponse),
    ApprovalDecision(aa_proto::assembly::event::v1::ApprovalDecision),
    ViolationAlert(aa_proto::assembly::audit::v1::PolicyViolation),
}

/// Write a heartbeat frame (tag byte only, no payload).
pub async fn write_heartbeat<W>(writer: &mut W) -> Result<(), CodecError>
where
    W: AsyncWriteExt + Unpin,
{
    writer.write_u8(TAG_HEARTBEAT).await?;
    writer.flush().await?;
    Ok(())
}

/// Write an event report frame.
pub async fn write_event_report<W>(
    writer: &mut W,
    event: &aa_proto::assembly::audit::v1::AuditEvent,
) -> Result<(), CodecError>
where
    W: AsyncWriteExt + Unpin,
{
    writer.write_u8(TAG_EVENT_REPORT).await?;
    let payload = event.encode_to_vec();
    write_length_delimited(writer, &payload).await?;
    writer.flush().await?;
    Ok(())
}

/// Write a policy query frame.
#[allow(dead_code)] // Used when policy checks are wired up (AAASM-49+).
pub async fn write_policy_query<W>(
    writer: &mut W,
    request: &aa_proto::assembly::policy::v1::CheckActionRequest,
) -> Result<(), CodecError>
where
    W: AsyncWriteExt + Unpin,
{
    writer.write_u8(TAG_POLICY_QUERY).await?;
    let payload = request.encode_to_vec();
    write_length_delimited(writer, &payload).await?;
    writer.flush().await?;
    Ok(())
}

/// Read one response frame from aa-runtime.
pub async fn read_response<R>(reader: &mut R) -> Result<RuntimeResponse, CodecError>
where
    R: AsyncReadExt + Unpin,
{
    let tag = reader.read_u8().await?;

    match tag {
        TAG_ACK => {
            let _bytes = read_length_delimited(reader).await?;
            Ok(RuntimeResponse::Ack)
        }
        TAG_POLICY_RESPONSE => {
            let bytes = read_length_delimited(reader).await?;
            let msg = aa_proto::assembly::policy::v1::CheckActionResponse::decode(bytes.as_ref())?;
            Ok(RuntimeResponse::PolicyResponse(msg))
        }
        TAG_APPROVAL_DECISION => {
            let bytes = read_length_delimited(reader).await?;
            let msg = aa_proto::assembly::event::v1::ApprovalDecision::decode(bytes.as_ref())?;
            Ok(RuntimeResponse::ApprovalDecision(msg))
        }
        TAG_VIOLATION_ALERT => {
            let bytes = read_length_delimited(reader).await?;
            let msg = aa_proto::assembly::audit::v1::PolicyViolation::decode(bytes.as_ref())?;
            Ok(RuntimeResponse::ViolationAlert(msg))
        }
        other => Err(CodecError::UnknownTag(other)),
    }
}

// ── Helpers ──────────────────────────────────────────────────────────────────

async fn read_length_delimited<R>(reader: &mut R) -> Result<Vec<u8>, CodecError>
where
    R: AsyncReadExt + Unpin,
{
    let len = read_varint(reader).await? as usize;
    let mut buf = vec![0u8; len];
    reader.read_exact(&mut buf).await?;
    Ok(buf)
}

async fn write_length_delimited<W>(writer: &mut W, bytes: &[u8]) -> Result<(), CodecError>
where
    W: AsyncWriteExt + Unpin,
{
    write_varint(writer, bytes.len() as u64).await?;
    writer.write_all(bytes).await?;
    Ok(())
}

async fn read_varint<R>(reader: &mut R) -> Result<u64, CodecError>
where
    R: AsyncReadExt + Unpin,
{
    let mut result: u64 = 0;
    let mut shift = 0u32;
    loop {
        let byte = reader.read_u8().await?;
        result |= ((byte & 0x7F) as u64) << shift;
        if byte & 0x80 == 0 {
            break;
        }
        shift += 7;
        if shift >= 64 {
            return Err(CodecError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "varint too long",
            )));
        }
    }
    Ok(result)
}

async fn write_varint<W>(writer: &mut W, mut value: u64) -> Result<(), CodecError>
where
    W: AsyncWriteExt + Unpin,
{
    loop {
        let byte = (value & 0x7F) as u8;
        value >>= 7;
        if value == 0 {
            writer.write_u8(byte).await?;
            break;
        } else {
            writer.write_u8(byte | 0x80).await?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[tokio::test]
    async fn heartbeat_write_produces_single_tag_byte() {
        let mut buf = Vec::new();
        write_heartbeat(&mut buf).await.unwrap();
        assert_eq!(buf, vec![TAG_HEARTBEAT]);
    }

    #[tokio::test]
    async fn ack_response_round_trip() {
        // Ack wire format: [TAG_ACK][varint 0]
        let wire = vec![TAG_ACK, 0x00];
        let mut cursor = Cursor::new(wire);
        let resp = read_response(&mut cursor).await.unwrap();
        assert!(matches!(resp, RuntimeResponse::Ack));
    }

    #[tokio::test]
    async fn event_report_encodes_correctly() {
        let event = aa_proto::assembly::audit::v1::AuditEvent {
            event_id: "evt-42".to_string(),
            ..Default::default()
        };
        let mut buf = Vec::new();
        write_event_report(&mut buf, &event).await.unwrap();
        assert_eq!(buf[0], TAG_EVENT_REPORT);
    }

    #[tokio::test]
    async fn policy_query_encodes_correctly() {
        let req = aa_proto::assembly::policy::v1::CheckActionRequest {
            trace_id: "trace-1".to_string(),
            ..Default::default()
        };
        let mut buf = Vec::new();
        write_policy_query(&mut buf, &req).await.unwrap();
        assert_eq!(buf[0], TAG_POLICY_QUERY);
    }

    #[tokio::test]
    async fn unknown_tag_returns_error() {
        let wire = vec![99u8, 0x00];
        let mut cursor = Cursor::new(wire);
        let result = read_response(&mut cursor).await;
        assert!(matches!(result, Err(CodecError::UnknownTag(99))));
    }
}
