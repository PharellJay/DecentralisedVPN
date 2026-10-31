//! The client⇄exit Noise_NK tunnel, run through an in-memory "relay" that records,
//! tampers with or replays frames. The relay sees exactly what a real entry relay
//! sees: the spliced byte stream.

use std::io;
use std::net::Ipv4Addr;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use dvpn::circuit::{CircuitError, Tunnel, client_handshake, exit_handshake};
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream, ReadBuf};

const SECRET: &[u8] = b"TOP-SECRET-PAYLOAD-1234";

/// futures-io adapter over a tokio duplex pipe.
struct Compat(DuplexStream);

impl futures::AsyncRead for Compat {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut [u8]) -> Poll<io::Result<usize>> {
        let mut rb = ReadBuf::new(buf);
        match tokio::io::AsyncRead::poll_read(Pin::new(&mut self.0), cx, &mut rb) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(rb.filled().len())),
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl futures::AsyncWrite for Compat {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        tokio::io::AsyncWrite::poll_write(Pin::new(&mut self.0), cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        tokio::io::AsyncWrite::poll_flush(Pin::new(&mut self.0), cx)
    }
    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        tokio::io::AsyncWrite::poll_shutdown(Pin::new(&mut self.0), cx)
    }
}

#[derive(Clone, Copy)]
enum Meddle {
    None,
    /// Flip one bit in the client→exit frame with this index.
    FlipBit(usize),
    /// Send the client→exit frame with this index twice.
    Replay(usize),
}

/// Frames seen by the relay, per direction.
#[derive(Default)]
struct Seen {
    to_exit: Vec<Vec<u8>>,
    to_client: Vec<Vec<u8>>,
}

async fn forward(
    mut from: impl tokio::io::AsyncRead + Unpin,
    mut to: impl tokio::io::AsyncWrite + Unpin,
    seen: Arc<Mutex<Seen>>, to_exit: bool, meddle: Meddle) {
    let mut index = 0;
    loop {
        let mut len = [0u8; 2];
        if from.read_exact(&mut len).await.is_err() {
            break;
        }
        let mut body = vec![0u8; u16::from_be_bytes(len) as usize];
        if from.read_exact(&mut body).await.is_err() {
            break;
        }
        {
            let mut seen = seen.lock().unwrap();
            if to_exit { &mut seen.to_exit } else { &mut seen.to_client }.push(body.clone());
        }
        let mut copies = 1;
        if to_exit {
            match meddle {
                Meddle::FlipBit(i) if i == index => {
                    let mid = body.len() / 2;
                    body[mid] ^= 0x01;
                }
                Meddle::Replay(i) if i == index => copies = 2,
                _ => {}
            }
        }
        for _ in 0..copies {
            if to.write_all(&len).await.is_err() || to.write_all(&body).await.is_err() {
                return;
            }
        }
        index += 1;
    }
    let _ = to.shutdown().await;
}

/// Connects a client and an exit through a recording relay.
async fn tunnel_pair(
    client_key: Option<[u8; 32]>,
    meddle: Meddle,
) -> (Result<Tunnel, CircuitError>, Result<Tunnel, CircuitError>, Arc<Mutex<Seen>>) {
    let params = dvpn::identity::NOISE_PARAMS.parse().unwrap();
    let exit_keys = snow::Builder::new(params).generate_keypair().unwrap();
    let exit_public: [u8; 32] = exit_keys.public.as_slice().try_into().unwrap();

    let (client_end, relay_left) = tokio::io::duplex(64 * 1024);
    let (relay_right, exit_end) = tokio::io::duplex(64 * 1024);
    let (left_read, left_write) = tokio::io::split(relay_left);
    let (right_read, right_write) = tokio::io::split(relay_right);
    let seen = Arc::new(Mutex::new(Seen::default()));
    tokio::spawn(forward(left_read, right_write, seen.clone(), true, meddle));
    tokio::spawn(forward(right_read, left_write, seen.clone(), false, Meddle::None));

    let key_used_by_client = client_key.unwrap_or(exit_public);
    let exit_private = exit_keys.private.clone();
    let (client, exit) = tokio::join!(
        client_handshake(Compat(client_end), &key_used_by_client),
        exit_handshake(Compat(exit_end), &exit_private, Ipv4Addr::new(10, 77, 0, 2), None),
    );
    (client, exit, seen)
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

#[tokio::test]
async fn relay_cannot_decrypt_payload() {
    let (client, exit, seen) = tunnel_pair(None, Meddle::None).await;
    let (mut client, mut exit) = (client.unwrap(), exit.unwrap());
    assert_eq!(client.assigned_ip, Ipv4Addr::new(10, 77, 0, 2));

    // Different packet sizes, all carrying the secret, both directions.
    let packets: Vec<Vec<u8>> = [0usize, 50, 200]
        .iter()
        .map(|&extra| [SECRET, &vec![b'x'; extra]].concat())
        .collect();
    for packet in &packets {
        client.tx.send(packet).await.unwrap();
        assert_eq!(exit.rx.recv().await.unwrap().unwrap(), *packet);
        exit.tx.send(packet).await.unwrap();
        assert_eq!(client.rx.recv().await.unwrap().unwrap(), *packet);
    }

    let seen = seen.lock().unwrap();
    let all: Vec<&Vec<u8>> = seen.to_exit.iter().chain(&seen.to_client).collect();
    assert!(all.len() >= 2 + 2 * packets.len(), "relay saw {} frames", all.len());
    for frame in &all {
        assert!(!contains(frame, SECRET), "plaintext visible to the relay");
        assert!(!contains(frame, b"xxxxxxxx"), "plaintext visible to the relay");
    }
    // Padding: every data frame for packets under 254 bytes has the same size.
    let data_sizes: Vec<usize> = seen.to_exit[1..].iter().map(Vec::len).collect();
    assert!(data_sizes.iter().all(|&s| s == 256 + 16), "data frame sizes leak lengths: {data_sizes:?}");
}

#[tokio::test]
async fn tampered_packet_is_rejected() {
    // Frame 0 is the handshake; frame 1 is the first data packet.
    let (client, exit, _) = tunnel_pair(None, Meddle::FlipBit(1)).await;
    let (mut client, mut exit) = (client.unwrap(), exit.unwrap());
    client.tx.send(SECRET).await.unwrap();
    assert!(matches!(exit.rx.recv().await, Err(CircuitError::Integrity)));
}

#[tokio::test]
async fn replayed_packet_is_rejected() {
    let (client, exit, _) = tunnel_pair(None, Meddle::Replay(1)).await;
    let (mut client, mut exit) = (client.unwrap(), exit.unwrap());
    client.tx.send(SECRET).await.unwrap();
    assert_eq!(exit.rx.recv().await.unwrap().unwrap(), SECRET);
    assert!(matches!(exit.rx.recv().await, Err(CircuitError::Integrity)));
}

#[tokio::test]
async fn impostor_exit_cannot_complete_handshake() {
    // The client expects a different exit key than the one this "exit" holds.
    let (client, exit, _) = tunnel_pair(Some([42; 32]), Meddle::None).await;
    assert!(exit.is_err(), "exit accepted a handshake meant for another key");
    assert!(client.is_err(), "client trusted an exit with the wrong key");
}

#[tokio::test]
async fn oversized_packet_is_refused() {
    let (client, _exit, _) = tunnel_pair(None, Meddle::None).await;
    let mut client = client.unwrap();
    let too_big = vec![0u8; dvpn::circuit::MTU as usize + 1];
    assert!(matches!(client.tx.send(&too_big).await, Err(CircuitError::PacketTooLarge)));
}
