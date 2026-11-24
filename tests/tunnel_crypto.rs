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
    tunnel_pair_expecting(client_key, None, meddle).await
}

/// Like [`tunnel_pair`], with the client expecting exit `client_exit` (by default the
/// exit's real peer ID).
async fn tunnel_pair_expecting(
    client_key: Option<[u8; 32]>,
    client_exit: Option<libp2p::PeerId>,
    meddle: Meddle,
) -> (Result<Tunnel, CircuitError>, Result<Tunnel, CircuitError>, Arc<Mutex<Seen>>) {
    let exit_id = libp2p::PeerId::random();
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
    let exit_seen_by_client = client_exit.unwrap_or(exit_id);
    let (client, exit) = tokio::join!(
        client_handshake(Compat(client_end), &exit_seen_by_client, &key_used_by_client),
        exit_handshake(Compat(exit_end), &exit_id, std::slice::from_ref(&exit_private), Ipv4Addr::new(10, 77, 0, 2), None),
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
async fn handshake_is_bound_to_the_exits_peer_id() {
    // Right key, but the client meant to reach another exit (e.g. a record reusing the key).
    let (client, exit, _) = tunnel_pair_expecting(None, Some(libp2p::PeerId::random()), Meddle::None).await;
    assert!(exit.is_err() || client.is_err(), "handshake completed for the wrong exit");
}

#[tokio::test]
async fn keys_are_renewed_during_long_sessions() {
    let (client, exit, _) = tunnel_pair(None, Meddle::None).await;
    let (mut client, mut exit) = (client.unwrap(), exit.unwrap());
    // Past two key changes in each direction; every packet still arrives intact.
    let rounds = 2 * dvpn::circuit::REKEY_EVERY + 3;
    let sender = tokio::spawn(async move {
        for i in 0..rounds {
            client.tx.send(&i.to_be_bytes()).await.unwrap();
        }
        client
    });
    for i in 0..rounds {
        assert_eq!(exit.rx.recv().await.unwrap().unwrap(), i.to_be_bytes());
    }
    let mut client = sender.await.unwrap();
    exit.tx.send(SECRET).await.unwrap();
    assert_eq!(client.rx.recv().await.unwrap().unwrap(), SECRET);
}

#[tokio::test]
async fn oversized_packet_is_refused() {
    let (client, _exit, _) = tunnel_pair(None, Meddle::None).await;
    let mut client = client.unwrap();
    let too_big = vec![0u8; dvpn::circuit::MTU as usize + 1];
    assert!(matches!(client.tx.send(&too_big).await, Err(CircuitError::PacketTooLarge)));
}

/// Throughput of the stream path alone (PERF-01), over an in-memory pipe:
/// `cargo test --release --test tunnel_crypto -- --ignored --nocapture throughput`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "benchmark"]
async fn throughput() {
    const PACKETS: usize = 200_000;
    let exit_id = libp2p::PeerId::random();
    let params = dvpn::identity::NOISE_PARAMS.parse().unwrap();
    let keys = snow::Builder::new(params).generate_keypair().unwrap();
    let public: [u8; 32] = keys.public.as_slice().try_into().unwrap();
    let (client_end, exit_end) = tokio::io::duplex(256 * 1024);
    let (client, exit) = tokio::join!(
        client_handshake(Compat(client_end), &exit_id, &public),
        exit_handshake(Compat(exit_end), &exit_id, std::slice::from_ref(&keys.private), Ipv4Addr::new(10, 77, 0, 2), None),
    );
    let (mut client, mut exit) = (client.unwrap(), exit.unwrap());
    let packet = vec![0x45; 1300];
    let start = std::time::Instant::now();
    let sender = tokio::spawn(async move {
        for _ in 0..PACKETS {
            client.tx.send(&packet).await.unwrap();
        }
        client
    });
    for _ in 0..PACKETS {
        assert_eq!(exit.rx.recv().await.unwrap().unwrap().len(), 1300);
    }
    let elapsed = start.elapsed();
    drop(sender.await.unwrap());
    let mbit = (PACKETS * 1300 * 8) as f64 / elapsed.as_secs_f64() / 1e6;
    eprintln!("{PACKETS} packets in {elapsed:.2?}: {mbit:.0} Mbit/s, {:.2} µs/packet", elapsed.as_secs_f64() * 1e6 / PACKETS as f64);
}

/// An exit that replaced its key still accepts clients holding a record with the old
/// one, and refuses a key it never had.
#[tokio::test]
async fn exit_accepts_the_key_it_just_replaced() {
    let exit_id = libp2p::PeerId::random();
    let keys = dvpn::identity::ExitKeys::with_lifetimes(std::time::Duration::ZERO, std::time::Duration::from_secs(3600)).unwrap();
    let old_public = keys.public();
    assert!(keys.rotate_if_due());
    let stranger = dvpn::identity::ExitStaticKey::generate().unwrap().public;
    for (client_key, accepted) in [(keys.public(), true), (old_public, true), (stranger, false)] {
        let (client_end, exit_end) = tokio::io::duplex(64 * 1024);
        let candidates = keys.candidates();
        let (client, exit) = tokio::join!(
            client_handshake(Compat(client_end), &exit_id, &client_key),
            exit_handshake(Compat(exit_end), &exit_id, &candidates, Ipv4Addr::new(10, 77, 0, 2), None),
        );
        assert_eq!(exit.is_ok(), accepted);
        if accepted {
            let (mut client, mut exit) = (client.unwrap(), exit.unwrap());
            client.tx.send(SECRET).await.unwrap();
            assert_eq!(exit.rx.recv().await.unwrap().unwrap(), SECRET);
        }
    }
}
