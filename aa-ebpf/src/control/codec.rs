//! Length-prefixed JSON framing for the control channel (AAASM-3604).
//!
//! Each message is a 4-byte big-endian length followed by that many bytes of
//! JSON. A hard cap rejects oversized frames so a malformed/hostile peer
//! cannot exhaust memory.

use serde::de::DeserializeOwned;
use serde::Serialize;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::error::EbpfError;

/// Maximum accepted frame size (1 MiB). Control messages are tiny; anything
/// larger is treated as malformed.
pub const MAX_FRAME_LEN: usize = 1024 * 1024;

/// Serialize `msg` as JSON and write it length-prefixed to `w`.
pub async fn write_frame<W, T>(w: &mut W, msg: &T) -> Result<(), EbpfError>
where
    W: AsyncWrite + Unpin,
    T: Serialize,
{
    let body = serde_json::to_vec(msg).map_err(|e| EbpfError::EventParse(format!("encode: {e}")))?;
    if body.len() > MAX_FRAME_LEN {
        return Err(EbpfError::EventParse(format!(
            "control frame too large: {} > {MAX_FRAME_LEN}",
            body.len()
        )));
    }
    let len = (body.len() as u32).to_be_bytes();
    w.write_all(&len).await?;
    w.write_all(&body).await?;
    w.flush().await?;
    Ok(())
}

/// Read one length-prefixed JSON frame from `r`, returning `Ok(None)` on a
/// clean EOF at a frame boundary.
pub async fn read_frame<R, T>(r: &mut R) -> Result<Option<T>, EbpfError>
where
    R: AsyncRead + Unpin,
    T: DeserializeOwned,
{
    let mut len_buf = [0u8; 4];
    match r.read_exact(&mut len_buf).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(EbpfError::Io(e)),
    }
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > MAX_FRAME_LEN {
        return Err(EbpfError::EventParse(format!(
            "control frame too large: {len} > {MAX_FRAME_LEN}"
        )));
    }
    let mut body = vec![0u8; len];
    r.read_exact(&mut body).await?;
    let msg = serde_json::from_slice(&body).map_err(|e| EbpfError::EventParse(format!("decode: {e}")))?;
    Ok(Some(msg))
}
#[cfg(test)]
mod tests {
    use super::super::protocol::{ControlRequest, ControlResponse};
    use super::*;

    #[tokio::test]
    async fn round_trips_a_request() {
        let req = ControlRequest::Ping;
        let mut buf = Vec::new();
        write_frame(&mut buf, &req).await.unwrap();

        let mut cursor = std::io::Cursor::new(buf);
        let back: Option<ControlRequest> = read_frame(&mut cursor).await.unwrap();
        assert_eq!(back, Some(req));
    }

}
