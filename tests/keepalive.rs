//! Tunnel keepalives, on an in-memory pipe with tokio's paused clock: an idle tunnel
//! stays up, an exit that silently stops answering is detected, and an exit drops a
//! client that silently disappears.

use std::future::pending;
use std::io;
use std::net::Ipv4Addr;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;

use dvpn::circuit::{EXIT_IDLE_TIMEOUT, ExitSession, KEEPALIVE_TIMEOUT, Tunnel, client_handshake, exit_handshake};
use dvpn::client::pump;
use dvpn::device::PacketDevice;
use dvpn::exit::{self, ExitOptions};
use dvpn::policy::ExitPolicy;
use libp2p::PeerId;
use tokio::io::{DuplexStream, ReadBuf};
use tokio::sync::mpsc;
use tokio::time::{Instant, sleep, timeout};

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

/// A device with no traffic: the tunnel is idle.
struct IdleDevice;

impl PacketDevice for IdleDevice {
    async fn recv(&self, _buf: &mut [u8]) -> io::Result<usize> {
        pending().await
    }
    async fn send(&self, packet: &[u8]) -> io::Result<usize> {
        Ok(packet.len())
    }
}

async fn tunnel_pair() -> (Tunnel, Tunnel) {
    let params = dvpn::identity::NOISE_PARAMS.parse().unwrap();
    let keys = snow::Builder::new(params).generate_keypair().unwrap();
    let public: [u8; 32] = keys.public.as_slice().try_into().unwrap();
    let (client_end, exit_end) = tokio::io::duplex(64 * 1024);
    let (client, exit) = tokio::join!(
        client_handshake(Compat(client_end), &public),
        exit_handshake(Compat(exit_end), &keys.private, Ipv4Addr::new(10, 77, 0, 2), None),
    );
    (client.unwrap(), exit.unwrap())
}

/// Runs `exit` through the real exit forwarder; returns its active-session counter.
async fn serve(exit: Tunnel) -> (Arc<AtomicUsize>, mpsc::Sender<ExitSession>) {
    let active = Arc::new(AtomicUsize::new(0));
    let (sessions_tx, sessions) = mpsc::channel(1);
    sessions_tx
        .send(ExitSession {
            via_peer: PeerId::random(),
            tunnel: exit,
        })
        .await
        .unwrap();
    let options = Arc::new(ExitOptions {
        policy: ExitPolicy::new(std::iter::empty(), vec![25]),
        rate_mbps: 0,
    });
    tokio::spawn(exit::forward(Arc::new(IdleDevice), sessions, options, active.clone()));
    (active, sessions_tx)
}

#[tokio::test(start_paused = true)]
async fn idle_tunnel_stays_up_while_the_exit_answers_keepalives() {
    let (mut client, exit) = tunnel_pair().await;
    let (active, _sessions) = serve(exit).await;

    let result = timeout(Duration::from_secs(300), pump(&IdleDevice, &mut client)).await;
    assert!(result.is_err(), "client gave up on a live exit: {:#}", result.unwrap());
    assert_eq!(active.load(Ordering::Relaxed), 1, "exit dropped a live client");
}

#[tokio::test(start_paused = true)]
async fn client_detects_an_exit_that_stops_answering() {
    // The exit's end stays open but never answers, as when its host loses power.
    let (mut client, mut exit) = tunnel_pair().await;

    let started = Instant::now();
    let error = timeout(Duration::from_secs(120), pump(&IdleDevice, &mut client))
        .await
        .expect("client never noticed the silent exit");
    let took = started.elapsed();
    assert!(error.to_string().contains("stopped responding"), "{error:#}");
    assert!(
        took >= KEEPALIVE_TIMEOUT && took <= KEEPALIVE_TIMEOUT + Duration::from_secs(6),
        "noticed after {took:?}"
    );

    // What the client sent meanwhile were keepalives: empty packets.
    let sent = timeout(Duration::from_secs(1), exit.rx.recv()).await.expect("client sent no keepalive");
    assert_eq!(sent.unwrap(), Some(Vec::new()));
}

#[tokio::test(start_paused = true)]
async fn exit_drops_a_client_that_goes_silent() {
    let (_client, exit) = tunnel_pair().await;
    let (active, _sessions) = serve(exit).await;

    sleep(EXIT_IDLE_TIMEOUT - Duration::from_secs(1)).await;
    assert_eq!(active.load(Ordering::Relaxed), 1, "session dropped too early");
    sleep(Duration::from_secs(2)).await;
    assert_eq!(active.load(Ordering::Relaxed), 0, "silent session still holds a slot");
}
