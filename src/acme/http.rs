//! A minimal HTTPS/1.1 client for the ACME protocol, layered on the existing
//! BoringSSL client connector (`boringtls::client_connect`, verified against the
//! system CA bundle) over monoio TCP. One request per connection
//! (`Connection: close`), which is plenty for ACME's low request volume and
//! avoids chunked/keep-alive bookkeeping.

use std::net::ToSocketAddrs;

use anyhow::{Context, Result, anyhow, bail};
use futures::channel::oneshot;
use monoio::io::{AsyncReadRent, AsyncWriteRentExt};
use monoio::net::TcpStream;
use url::Url;

use crate::boringtls::client_connect;
use crate::thread_pool::DNS_TP;

const USER_AGENT: &str = "zeroserve-acme/1";
const MAX_RESPONSE: usize = 4 * 1024 * 1024;

pub struct HttpResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl HttpResponse {
    /// Case-insensitive header lookup (first match).
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    pub fn json(&self) -> Result<serde_json::Value> {
        serde_json::from_slice(&self.body).context("parsing ACME JSON response")
    }

    /// True for any 2xx status.
    pub fn is_success(&self) -> bool {
        (200..300).contains(&self.status)
    }
}

async fn resolve(host: &str, port: u16) -> Result<Vec<std::net::SocketAddr>> {
    let host_owned = host.to_string();
    let (tx, rx) = oneshot::channel();
    DNS_TP.spawn(move || {
        let resolved = (host_owned.as_str(), port)
            .to_socket_addrs()
            .map(|it| it.collect::<Vec<_>>());
        let _ = tx.send(resolved);
    });
    let addrs = rx
        .await
        .map_err(|_| anyhow!("DNS resolver dropped"))?
        .with_context(|| format!("resolving ACME host {host:?}"))?;
    if addrs.is_empty() {
        bail!("ACME host {host:?} resolved to no addresses");
    }
    Ok(addrs)
}

/// Perform a single HTTPS request. `body`/`content_type` are sent when present
/// (ACME POSTs use `application/jose+json`).
pub async fn request(
    method: &str,
    url: &str,
    content_type: Option<&str>,
    body: Option<&[u8]>,
) -> Result<HttpResponse> {
    let parsed = Url::parse(url).with_context(|| format!("invalid ACME URL {url:?}"))?;
    if parsed.scheme() != "https" {
        bail!("ACME URL {url:?} is not https");
    }
    let host = parsed
        .host_str()
        .ok_or_else(|| anyhow!("ACME URL {url:?} has no host"))?
        .to_string();
    let port = parsed.port().unwrap_or(443);
    let mut path = parsed.path().to_string();
    if let Some(q) = parsed.query() {
        path.push('?');
        path.push_str(q);
    }
    if path.is_empty() {
        path.push('/');
    }

    let addrs = resolve(&host, port).await?;
    let sock = TcpStream::connect(&addrs[..])
        .await
        .with_context(|| format!("connecting to ACME host {host}:{port}"))?;
    let _ = sock.set_nodelay(true);
    let mut tls = client_connect(sock, &host)
        .await
        .with_context(|| format!("TLS handshake with ACME host {host}"))?;

    // The Host header must carry the port for non-default ports: ACME servers
    // (e.g. Pebble) build the directory's resource URLs from it.
    let host_header = match parsed.port() {
        Some(p) => format!("{host}:{p}"),
        None => host.clone(),
    };
    let mut req = format!(
        "{method} {path} HTTP/1.1\r\nHost: {host_header}\r\nUser-Agent: {USER_AGENT}\r\nAccept: */*\r\nConnection: close\r\n"
    );
    if let Some(ct) = content_type {
        req.push_str(&format!("Content-Type: {ct}\r\n"));
    }
    let body = body.unwrap_or(&[]);
    req.push_str(&format!("Content-Length: {}\r\n\r\n", body.len()));

    let mut wire = req.into_bytes();
    wire.extend_from_slice(body);
    let (res, _) = tls.write_all(wire).await;
    res.context("sending ACME request")?;

    // Read the whole response until the server closes the connection.
    let mut acc: Vec<u8> = Vec::new();
    loop {
        let buf = vec![0u8; 16 * 1024];
        let (res, buf) = tls.read(buf).await;
        let n = res.context("reading ACME response")?;
        if n == 0 {
            break;
        }
        acc.extend_from_slice(&buf[..n]);
        if acc.len() > MAX_RESPONSE {
            bail!("ACME response exceeded {MAX_RESPONSE} bytes");
        }
    }

    parse_response(&acc)
}

fn parse_response(raw: &[u8]) -> Result<HttpResponse> {
    let split = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| anyhow!("malformed ACME response: no header terminator"))?;
    let head = std::str::from_utf8(&raw[..split]).context("non-UTF8 ACME response headers")?;
    let body = raw[split + 4..].to_vec();

    let mut lines = head.split("\r\n");
    let status_line = lines.next().ok_or_else(|| anyhow!("empty ACME response"))?;
    let status: u16 = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| anyhow!("unparseable ACME status line {status_line:?}"))?;

    let mut headers = Vec::new();
    for line in lines {
        if let Some((name, value)) = line.split_once(':') {
            headers.push((name.trim().to_string(), value.trim().to_string()));
        }
    }

    Ok(HttpResponse {
        status,
        headers,
        body,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_status_headers_and_body() {
        let raw = b"HTTP/1.1 201 Created\r\nReplay-Nonce: abc123\r\nLocation: https://acme/acct/1\r\nContent-Type: application/json\r\n\r\n{\"status\":\"valid\"}";
        let resp = parse_response(raw).unwrap();
        assert_eq!(resp.status, 201);
        assert_eq!(resp.header("replay-nonce"), Some("abc123"));
        assert_eq!(resp.header("Location"), Some("https://acme/acct/1"));
        assert_eq!(resp.json().unwrap()["status"], "valid");
    }
}
