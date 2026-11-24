//! Length-prefixed frames and size-bucket padding.

use futures::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use std::io;

/// Largest frame body (a Noise message is at most 65535 bytes).
pub const MAX_FRAME: usize = u16::MAX as usize;

/// Plaintext sizes after padding; hides exact packet lengths from relays and observers.
/// The largest fits the MTU (see [`crate::circuit::MTU`]).
pub const PAD_BUCKETS: [usize; 4] = [256, 512, 1024, 1362];

/// Largest packet that fits the biggest bucket (2 bytes go to the length prefix).
pub const MAX_PADDED_PACKET: usize = PAD_BUCKETS[PAD_BUCKETS.len() - 1] - 2;

pub async fn write_frame<W: AsyncWrite + Unpin>(w: &mut W, body: &[u8]) -> io::Result<()> {
    let len = u16::try_from(body.len()).map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "frame too large"))?;
    let mut frame = Vec::with_capacity(2 + body.len());
    frame.extend_from_slice(&len.to_be_bytes());
    frame.extend_from_slice(body);
    w.write_all(&frame).await?;
    w.flush().await
}

/// Reads one frame. A clean close before the length prefix yields `Ok(None)`.
pub async fn read_frame<R: AsyncRead + Unpin>(r: &mut R) -> io::Result<Option<Vec<u8>>> {
    let mut body = Vec::new();
    Ok(read_frame_into(r, &mut body).await?.then_some(body))
}

/// Like [`read_frame`], into `body` (reused across frames); `false` on a clean close.
pub async fn read_frame_into<R: AsyncRead + Unpin>(r: &mut R, body: &mut Vec<u8>) -> io::Result<bool> {
    let mut len = [0u8; 2];
    match r.read_exact(&mut len).await {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(false),
        Err(e) => return Err(e),
    }
    body.resize(u16::from_be_bytes(len) as usize, 0);
    r.read_exact(body).await?;
    Ok(true)
}

/// `[u16 length][packet][zero padding]`, padded to the smallest fitting bucket.
pub fn pad(packet: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    pad_into(packet, &mut out).then_some(out)
}

/// Like [`pad`], into `out` (reused across packets); `false` if the packet is too large.
pub fn pad_into(packet: &[u8], out: &mut Vec<u8>) -> bool {
    let needed = packet.len() + 2;
    let Some(&bucket) = PAD_BUCKETS.iter().find(|&&b| b >= needed) else {
        return false;
    };
    out.clear();
    out.extend_from_slice(&(packet.len() as u16).to_be_bytes());
    out.extend_from_slice(packet);
    out.resize(bucket, 0);
    true
}

pub fn unpad(padded: &[u8]) -> Option<&[u8]> {
    let len = u16::from_be_bytes(padded.get(..2)?.try_into().ok()?) as usize;
    padded.get(2..2 + len)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pads_to_buckets_and_round_trips() {
        for (len, bucket) in [(0, 256), (10, 256), (254, 256), (255, 512), (1024, 1362), (MAX_PADDED_PACKET, 1362)] {
            let packet = vec![0xAB; len];
            let padded = pad(&packet).unwrap();
            assert_eq!(padded.len(), bucket, "len {len}");
            assert_eq!(unpad(&padded).unwrap(), packet.as_slice());
        }
        assert!(pad(&vec![0; MAX_PADDED_PACKET + 1]).is_none());
    }

    #[test]
    fn reused_buffers_hold_no_leftovers() {
        let mut out = Vec::new();
        assert!(pad_into(&[0xFF; 900], &mut out));
        assert!(pad_into(b"hi", &mut out));
        assert_eq!(out.len(), 256);
        assert_eq!(unpad(&out).unwrap(), b"hi");
        assert!(out[4..].iter().all(|&b| b == 0), "padding is zeros, not the previous packet");
    }

    #[tokio::test]
    async fn frames_read_into_one_buffer() {
        let mut wire = Vec::new();
        write_frame(&mut wire, &[1; 300]).await.unwrap();
        write_frame(&mut wire, &[2; 3]).await.unwrap();
        let mut reader = futures::io::Cursor::new(wire);
        let mut body = Vec::new();
        assert!(read_frame_into(&mut reader, &mut body).await.unwrap());
        assert_eq!(body, [1; 300]);
        assert!(read_frame_into(&mut reader, &mut body).await.unwrap());
        assert_eq!(body, [2; 3]);
        assert!(!read_frame_into(&mut reader, &mut body).await.unwrap(), "clean end");
    }

    #[test]
    fn unpad_rejects_bad_length() {
        let mut padded = pad(b"hi").unwrap();
        padded[0..2].copy_from_slice(&5000u16.to_be_bytes());
        assert!(unpad(&padded).is_none());
    }
}
