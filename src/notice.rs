//! The exit notice: a web page on a dedicated exit's IP address that explains what the
//! machine is, for whoever looks it up after seeing traffic from it (an abuse desk, a
//! site operator). Tor exits do the same. It answers every request with the same page
//! and reads nothing but the request head.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tracing::{debug, info};

/// Connections served at once; more wait.
const MAX_CONNECTIONS: usize = 32;
/// The most of a request that is read before answering.
const MAX_REQUEST: usize = 8 * 1024;
const READ_TIMEOUT: Duration = Duration::from_secs(5);
/// Longer contacts are cut, so the page stays a page.
const MAX_CONTACT: usize = 200;

/// The notice page, with `contact` (escaped) if given.
pub fn page(contact: Option<&str>) -> String {
    let contact = match contact.map(str::trim).filter(|c| !c.is_empty()) {
        Some(contact) => format!(
            "<p>To reach the operator of this exit, for example about abuse: <strong>{}</strong></p>",
            escape(&contact.chars().take(MAX_CONTACT).collect::<String>())
        ),
        None => String::new(),
    };
    format!(
        r#"<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>This is a dvpn exit</title>
<style>body{{font:16px/1.5 system-ui,sans-serif;max-width:40em;margin:3em auto;padding:0 1em;color:#222}}</style>
</head>
<body>
<h1>This is a dvpn exit</h1>
<p>This computer is an exit of <strong>dvpn</strong>, a decentralised peer-to-peer VPN.
Traffic you see from this address was sent by people using dvpn, not by the operator
of this computer.</p>
<p>Each user's traffic reaches this exit through a relay, encrypted, so this exit
can't tell who sent it, and it keeps no logs of what passes through. Blocking this
address blocks the dvpn users who happen to use it, not the people who sent the
traffic.</p>
<p>The exit refuses outgoing mail (SMTP) and connections into private networks.</p>
{contact}
</body>
</html>
"#
    )
}

fn escape(text: &str) -> String {
    text.chars()
        .map(|c| match c {
            '<' => "&lt;".to_string(),
            '>' => "&gt;".to_string(),
            '&' => "&amp;".to_string(),
            '"' => "&quot;".to_string(),
            '\'' => "&#39;".to_string(),
            c => c.to_string(),
        })
        .collect()
}

/// Binds `addr` for [`serve`]. Port 80 needs root (or `CAP_NET_BIND_SERVICE`).
pub async fn bind(addr: SocketAddr) -> anyhow::Result<TcpListener> {
    TcpListener::bind(addr).await.with_context(|| format!("serving the exit notice on {addr}"))
}

/// Answers every connection on `listener` with `page`, until the listener fails.
pub async fn serve(listener: TcpListener, page: String) {
    if let Ok(addr) = listener.local_addr() {
        info!("exit notice on http://{addr}");
    }
    let response: Arc<[u8]> = format!(
        "HTTP/1.0 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\n\
         Cache-Control: max-age=3600\r\nX-Content-Type-Options: nosniff\r\nConnection: close\r\n\r\n{page}",
        page.len()
    )
    .into_bytes()
    .into();
    let slots = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    loop {
        let Ok(slot) = slots.clone().acquire_owned().await else {
            return;
        };
        let Ok((mut stream, _)) = listener.accept().await else {
            return;
        };
        let response = response.clone();
        tokio::spawn(async move {
            let _slot = slot;
            // Reads the request head (or gives up), so the client sees a clean answer.
            let mut head = Vec::new();
            let mut buf = [0u8; 1024];
            let read = tokio::time::timeout(READ_TIMEOUT, async {
                while head.len() < MAX_REQUEST && !head.windows(4).any(|w| w == b"\r\n\r\n") {
                    match stream.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => head.extend_from_slice(&buf[..n]),
                    }
                }
            })
            .await;
            if read.is_err() {
                debug!("exit notice: request timed out");
            }
            let _ = stream.write_all(&response).await;
            let _ = stream.shutdown().await;
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_contact_is_escaped_and_optional() {
        let page = page(Some("abuse@example.org <script>"));
        assert!(page.contains("abuse@example.org &lt;script&gt;"));
        assert!(!page.contains("<script>"));
        assert!(!super::page(None).contains("To reach the operator"));
        assert!(!super::page(Some("  ")).contains("To reach the operator"));
    }

    #[tokio::test]
    async fn answers_any_request_with_the_page() {
        let listener = bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(serve(listener, page(Some("ops@example.org"))));
        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        stream.write_all(b"GET /whatever HTTP/1.1\r\nHost: x\r\n\r\n").await.unwrap();
        let mut answer = String::new();
        stream.read_to_string(&mut answer).await.unwrap();
        assert!(answer.starts_with("HTTP/1.0 200 OK\r\n"));
        assert!(answer.contains("This is a dvpn exit"));
        assert!(answer.contains("ops@example.org"));
    }
}
