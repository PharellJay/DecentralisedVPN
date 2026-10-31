//! Length-prefixed frames and size-bucket padding.

use futures::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use std::io;

/// Largest frame body (a Noise message is at most 65535 bytes).
pub const MAX_FRAME: usize = u16::MAX as usize;

/// Plaintext sizes after padding; hides exact packet lengths from relays and observers.
pub const PAD_BUCKETS: [usize; 4] = [256, 512, 1024, 1500];

/// Largest packet that fits the biggest bucket (2 bytes go to the length prefix).
pub const MAX_PADDED_PACKET: usize = PAD_BUCKETS[PAD_BUCKETS.len() - 1] - 2;

pub async fn write_frame<W: AsyncWrite + Unpin>(w: &mut W, body: &[u8]) -> io::Result<()> {
    let len = u16::try_from(body.len()).map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "frame too large"))?;
    w.write_all(&len.to_be_bytes()).await?;
    w.write_all(body).await?;
    w.flush().await
}

/// Reads one frame. A clean close before the length prefix yields `Ok(None)`.
pub async fn read_frame<R: AsyncRead + Unpin>(r: &mut R) -> io::Result<Option<Vec<u8>>> {
    let mut len = [0u8; 2];
    match r.read_exact(&mut len).await {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }
    let mut body = vec![0u8; u16::from_be_bytes(len) as usize];
    r.read_exact(&mut body).await?;
    Ok(Some(body))
}

/// `[u16 length][packet][zero padding]`, padded to the smallest fitting bucket.
pub fn pad(packet: &[u8]) -> Option<Vec<u8>> {
    let needed = packet.len() + 2;
    let bucket = *PAD_BUCKETS.iter().find(|&&b| b >= needed)?;
    let mut out = Vec::with_capacity(bucket);
    out.extend_from_slice(&(packet.len() as u16).to_be_bytes());
    out.extend_from_slice(packet);
    out.resize(bucket, 0);
    Some(out)
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
        for (len, bucket) in [(0, 256), (10, 256), (254, 256), (255, 512), (1400, 1500), (MAX_PADDED_PACKET, 1500)] {
            let packet = vec![0xAB; len];
            let padded = pad(&packet).unwrap();
            assert_eq!(padded.len(), bucket, "len {len}");
            assert_eq!(unpad(&padded).unwrap(), packet.as_slice());
        }
        assert!(pad(&vec![0; MAX_PADDED_PACKET + 1]).is_none());
    }

    #[test]
    fn unpad_rejects_bad_length() {
        let mut padded = pad(b"hi").unwrap();
        padded[0..2].copy_from_slice(&5000u16.to_be_bytes());
        assert!(unpad(&padded).is_none());
    }
}
