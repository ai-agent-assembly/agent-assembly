//! Length-framed binary codec for the DI-API socket (ADR 0030 §5.1).
//!
//! Deliberately the *same* framing discipline as [`crate::ipc::codec`] —
//! `[1-byte tag][prost varint length][prost payload]`, with the same
//! pre-allocation bound — so there is one framing implementation to review
//! rather than two. What differs is only the message set behind the tags, and
//! that difference is the point: this socket's tags name DI-API messages, and
//! the SDK socket's tags name policy and audit messages. Neither codec can
//! decode the other's frames, so a DI client that somehow reached the SDK
//! socket would still be speaking a language nothing there parses.
//!
//! Inbound tags (client → runtime):
//!   1 = Hello
//!   2 = Request
//!
//! Outbound tags (runtime → client):
//!   1 = HelloAck
//!   2 = Incompatible
//!   3 = Response
//!   4 = Denied

use prost::Message;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use aa_proto::assembly::devint::v1 as wire;

/// Client → runtime: the version-negotiation opener.
pub const TAG_HELLO: u8 = 1;
/// Client → runtime: a verb invocation.
pub const TAG_REQUEST: u8 = 2;

/// Runtime → client: negotiation succeeded (supported or degraded).
pub const TAG_HELLO_ACK: u8 = 1;
/// Runtime → client: negotiation failed; the connection closes after this.
pub const TAG_INCOMPATIBLE: u8 = 2;
/// Runtime → client: a verb's data-minimised result.
pub const TAG_RESPONSE: u8 = 3;
/// Runtime → client: the request was refused.
pub const TAG_DENIED: u8 = 4;

/// Maximum accepted length-delimited payload, in bytes (1 MiB).
///
/// The length prefix is attacker-controlled, so it is bounded *before*
/// allocating — the AAASM-3132 lesson, applied to this socket too. The bound is
/// deliberately far tighter than the SDK socket's 8 MiB: no legitimate DI-API
/// frame carries bulk data, because no DI-API type can hold any (§5.5). A
/// request that needs more than a megabyte is not a request this API serves.
pub const MAX_FRAME_LEN: usize = 1024 * 1024;

/// A decoded client → runtime frame.
#[derive(Debug)]
pub enum DiFrame {
    /// The negotiation opener.
    Hello(wire::Hello),
    /// A verb invocation.
    Request(wire::Request),
}

/// A runtime → client frame.
#[derive(Debug)]
pub enum DiResponseFrame {
    /// Negotiation succeeded.
    HelloAck(wire::HelloAck),
    /// Negotiation failed; nothing further will be served.
    Incompatible(wire::Incompatible),
    /// A verb result.
    Response(Box<wire::Response>),
    /// A refusal.
    Denied(wire::Denied),
}

/// Errors from framing a DI-API message.
///
/// Hand-written, matching [`crate::ipc::codec::CodecError`].
#[derive(Debug)]
pub enum DiCodecError {
    /// Transport failure.
    Io(std::io::Error),
    /// A tag outside the closed set. Rejected rather than skipped — an
    /// unrecognised frame is not a frame to ignore and keep reading past.
    UnknownTag(u8),
    /// The payload was not valid for its tag.
    Decode(prost::DecodeError),
    /// The length prefix exceeded [`MAX_FRAME_LEN`], rejected before any
    /// allocation.
    FrameTooLarge {
        /// What was claimed.
        len: usize,
        /// The bound.
        max: usize,
    },
}

impl std::fmt::Display for DiCodecError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DiCodecError::Io(e) => write!(f, "DI-API IO error: {e}"),
            DiCodecError::UnknownTag(t) => write!(f, "unknown DI-API frame tag: {t}"),
            DiCodecError::Decode(e) => write!(f, "DI-API decode error: {e}"),
            DiCodecError::FrameTooLarge { len, max } => {
                write!(f, "DI-API frame length {len} exceeds maximum {max}")
            }
        }
    }
}

impl std::error::Error for DiCodecError {}

impl From<std::io::Error> for DiCodecError {
    fn from(e: std::io::Error) -> Self {
        DiCodecError::Io(e)
    }
}

impl From<prost::DecodeError> for DiCodecError {
    fn from(e: prost::DecodeError) -> Self {
        DiCodecError::Decode(e)
    }
}

/// Read one client → runtime frame.
pub async fn read_frame<R>(reader: &mut R) -> Result<DiFrame, DiCodecError>
where
    R: AsyncReadExt + Unpin,
{
    let tag = reader.read_u8().await?;
    let bytes = read_length_delimited(reader).await?;
    match tag {
        TAG_HELLO => Ok(DiFrame::Hello(wire::Hello::decode(bytes.as_ref())?)),
        TAG_REQUEST => Ok(DiFrame::Request(wire::Request::decode(bytes.as_ref())?)),
        other => Err(DiCodecError::UnknownTag(other)),
    }
}

/// Write one runtime → client frame.
pub async fn write_frame<W>(writer: &mut W, frame: DiResponseFrame) -> Result<(), DiCodecError>
where
    W: AsyncWriteExt + Unpin,
{
    let (tag, body) = match frame {
        DiResponseFrame::HelloAck(m) => (TAG_HELLO_ACK, m.encode_to_vec()),
        DiResponseFrame::Incompatible(m) => (TAG_INCOMPATIBLE, m.encode_to_vec()),
        DiResponseFrame::Response(m) => (TAG_RESPONSE, m.encode_to_vec()),
        DiResponseFrame::Denied(m) => (TAG_DENIED, m.encode_to_vec()),
    };
    let mut out = Vec::with_capacity(1 + 10 + body.len());
    out.push(tag);
    prost::encoding::encode_varint(body.len() as u64, &mut out);
    out.extend_from_slice(&body);
    writer.write_all(&out).await?;
    writer.flush().await?;
    Ok(())
}

/// Write one client → runtime frame. Used by the reference client and by tests
/// that need to speak the wire directly.
pub async fn write_client_frame<W>(writer: &mut W, frame: DiFrame) -> Result<(), DiCodecError>
where
    W: AsyncWriteExt + Unpin,
{
    let (tag, body) = match frame {
        DiFrame::Hello(m) => (TAG_HELLO, m.encode_to_vec()),
        DiFrame::Request(m) => (TAG_REQUEST, m.encode_to_vec()),
    };
    let mut out = Vec::with_capacity(1 + 10 + body.len());
    out.push(tag);
    prost::encoding::encode_varint(body.len() as u64, &mut out);
    out.extend_from_slice(&body);
    writer.write_all(&out).await?;
    writer.flush().await?;
    Ok(())
}

/// Read one runtime → client frame. The client half of [`write_frame`].
pub async fn read_response_frame<R>(reader: &mut R) -> Result<DiResponseFrame, DiCodecError>
where
    R: AsyncReadExt + Unpin,
{
    let tag = reader.read_u8().await?;
    let bytes = read_length_delimited(reader).await?;
    match tag {
        TAG_HELLO_ACK => Ok(DiResponseFrame::HelloAck(wire::HelloAck::decode(bytes.as_ref())?)),
        TAG_INCOMPATIBLE => Ok(DiResponseFrame::Incompatible(wire::Incompatible::decode(
            bytes.as_ref(),
        )?)),
        TAG_RESPONSE => Ok(DiResponseFrame::Response(Box::new(wire::Response::decode(
            bytes.as_ref(),
        )?))),
        TAG_DENIED => Ok(DiResponseFrame::Denied(wire::Denied::decode(bytes.as_ref())?)),
        other => Err(DiCodecError::UnknownTag(other)),
    }
}

/// Read a prost varint length prefix and exactly that many bytes.
///
/// The length is checked against [`MAX_FRAME_LEN`] *before* the buffer is
/// allocated, so a peer claiming a multi-gigabyte payload cannot force the
/// allocation as a trivial local DoS.
async fn read_length_delimited<R>(reader: &mut R) -> Result<Vec<u8>, DiCodecError>
where
    R: AsyncReadExt + Unpin,
{
    let mut len: u64 = 0;
    let mut shift = 0u32;
    loop {
        let byte = reader.read_u8().await?;
        len |= u64::from(byte & 0x7F) << shift;
        if byte & 0x80 == 0 {
            break;
        }
        shift += 7;
        if shift >= 64 {
            return Err(DiCodecError::FrameTooLarge {
                len: usize::MAX,
                max: MAX_FRAME_LEN,
            });
        }
    }
    let len = usize::try_from(len).unwrap_or(usize::MAX);
    if len > MAX_FRAME_LEN {
        return Err(DiCodecError::FrameTooLarge {
            len,
            max: MAX_FRAME_LEN,
        });
    }
    let mut buf = vec![0u8; len];
    reader.read_exact(&mut buf).await?;
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hello() -> wire::Hello {
        wire::Hello {
            client_name: "vscode-aasm".to_string(),
            client_version: "1.4.0".to_string(),
            di_api_versions: vec![1, 2],
            lifecycle_schema_versions: vec![1],
        }
    }

    #[tokio::test]
    async fn a_hello_round_trips() {
        let mut buf = Vec::new();
        write_client_frame(&mut buf, DiFrame::Hello(hello())).await.unwrap();
        let mut cursor = std::io::Cursor::new(buf);
        match read_frame(&mut cursor).await.unwrap() {
            DiFrame::Hello(decoded) => assert_eq!(decoded, hello()),
            other => panic!("expected Hello, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn a_request_round_trips() {
        let request = wire::Request {
            request_id: 7,
            verb: wire::Verb::Status as i32,
            capability_token: "a".repeat(64),
            tool_id: "claude-code".to_string(),
            ..Default::default()
        };
        let mut buf = Vec::new();
        write_client_frame(&mut buf, DiFrame::Request(request.clone()))
            .await
            .unwrap();
        let mut cursor = std::io::Cursor::new(buf);
        match read_frame(&mut cursor).await.unwrap() {
            DiFrame::Request(decoded) => assert_eq!(decoded, request),
            other => panic!("expected Request, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn every_server_frame_round_trips() {
        let frames = vec![
            DiResponseFrame::HelloAck(wire::HelloAck {
                di_api_version: 2,
                ..Default::default()
            }),
            DiResponseFrame::Incompatible(wire::Incompatible {
                reason: "old".to_string(),
                ..Default::default()
            }),
            DiResponseFrame::Response(Box::new(wire::Response {
                request_id: 3,
                ..Default::default()
            })),
            DiResponseFrame::Denied(wire::Denied {
                code: wire::DenyCode::Unauthenticated as i32,
                ..Default::default()
            }),
        ];
        for frame in frames {
            let expected_tag = match &frame {
                DiResponseFrame::HelloAck(_) => TAG_HELLO_ACK,
                DiResponseFrame::Incompatible(_) => TAG_INCOMPATIBLE,
                DiResponseFrame::Response(_) => TAG_RESPONSE,
                DiResponseFrame::Denied(_) => TAG_DENIED,
            };
            let mut buf = Vec::new();
            write_frame(&mut buf, frame).await.unwrap();
            assert_eq!(buf[0], expected_tag);
            let mut cursor = std::io::Cursor::new(buf);
            read_response_frame(&mut cursor).await.expect("decodes");
        }
    }

    #[tokio::test]
    async fn an_unknown_tag_is_rejected_not_skipped() {
        let mut buf = vec![0xEE_u8];
        prost::encoding::encode_varint(0, &mut buf);
        let mut cursor = std::io::Cursor::new(buf);
        match read_frame(&mut cursor).await {
            Err(DiCodecError::UnknownTag(0xEE)) => {}
            other => panic!("expected UnknownTag, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn an_oversized_length_is_rejected_before_allocating() {
        let mut buf = vec![TAG_REQUEST];
        // A 4 GiB claim. Nothing is allocated for it.
        prost::encoding::encode_varint(4 * 1024 * 1024 * 1024, &mut buf);
        let mut cursor = std::io::Cursor::new(buf);
        match read_frame(&mut cursor).await {
            Err(DiCodecError::FrameTooLarge { max, .. }) => assert_eq!(max, MAX_FRAME_LEN),
            other => panic!("expected FrameTooLarge, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn a_large_but_valid_frame_is_still_read() {
        // The bound must not clip legitimate traffic, or it is a DoS against
        // the honest client rather than the hostile one.
        let request = wire::Request {
            request_id: 1,
            verb: wire::Verb::Status as i32,
            capability_token: "a".repeat(64),
            tool_id: "x".repeat(100_000),
            ..Default::default()
        };
        let mut buf = Vec::new();
        write_client_frame(&mut buf, DiFrame::Request(request)).await.unwrap();
        assert!(buf.len() > 100_000 && buf.len() < MAX_FRAME_LEN);
        let mut cursor = std::io::Cursor::new(buf);
        assert!(matches!(read_frame(&mut cursor).await, Ok(DiFrame::Request(_))));
    }

    #[tokio::test]
    async fn a_malformed_payload_fails_to_decode() {
        let mut buf = vec![TAG_HELLO];
        let body = vec![0xFF_u8; 8];
        prost::encoding::encode_varint(body.len() as u64, &mut buf);
        buf.extend_from_slice(&body);
        let mut cursor = std::io::Cursor::new(buf);
        assert!(matches!(read_frame(&mut cursor).await, Err(DiCodecError::Decode(_))));
    }

    #[tokio::test]
    async fn a_sdk_ipc_frame_does_not_decode_as_a_di_frame() {
        // The two sockets carry disjoint message sets. An SDK policy-query
        // frame arriving here must not silently parse into something this
        // service would act on.
        use aa_proto::assembly::policy::v1::CheckActionRequest;
        let policy_query = CheckActionRequest {
            action_type: 3,
            ..Default::default()
        };
        let body = policy_query.encode_to_vec();
        // Tag 1 on this socket means Hello, not PolicyQuery.
        let mut buf = vec![TAG_HELLO];
        prost::encoding::encode_varint(body.len() as u64, &mut buf);
        buf.extend_from_slice(&body);
        let mut cursor = std::io::Cursor::new(buf);
        let decoded = read_frame(&mut cursor).await;
        match decoded {
            // Either it fails to decode, or it decodes as a Hello offering no
            // usable version — never as a policy query, because this codec has
            // no variant that could hold one.
            Err(_) => {}
            Ok(DiFrame::Hello(h)) => assert!(h.di_api_versions.is_empty()),
            Ok(other) => panic!("unexpected frame {other:?}"),
        }
    }
}
