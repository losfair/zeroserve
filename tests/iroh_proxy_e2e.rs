#![cfg(feature = "iroh-proxy")]

use std::{
    fs,
    io::{BufRead, BufReader, ErrorKind, Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::mpsc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use bytes::Bytes;
use iroh::{
    Endpoint, RelayMode, SecretKey,
    endpoint::{RecvStream, SendStream, presets},
};

const DUMBPIPE_ALPN: &[u8] = b"DUMBPIPEV0";
const DUMBPIPE_HANDSHAKE: &[u8] = b"hello";

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn zeroserve_reverse_proxies_to_real_iroh_http_server_streaming_response() {
    let (_server, node_id, direct_addr) = start_iroh_http_server().await;

    let temp = TempDir::new("zeroserve-iroh-proxy-e2e");
    let script = temp.path().join("proxy.c");
    write_proxy_script(
        &script,
        &format!("iroh://{node_id}/base?addr={direct_addr}&fixed=1"),
        None,
    );

    let mut zeroserve = ChildGuard::new(spawn_zeroserve(&script));
    let port = wait_for_http_port(zeroserve.child_mut());

    let warmup = http_get_all(port, "/warmup", Duration::from_secs(45));
    assert!(warmup.contains("204"), "warmup response: {warmup}");

    let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("connect zeroserve");
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("set short read timeout");
    stream
        .write_all(
            b"GET /stream-check?client=1 HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        )
        .expect("write request");

    let mut first_window = Vec::new();
    let mut buf = [0u8; 512];
    while !String::from_utf8_lossy(&first_window).contains("first\n") {
        let n = stream
            .read(&mut buf)
            .expect("first response chunk should arrive before delayed second chunk");
        assert!(n > 0, "connection closed before first iroh response chunk");
        first_window.extend_from_slice(&buf[..n]);
    }
    let first_text = String::from_utf8_lossy(&first_window);
    assert!(first_text.contains("209"), "response head: {first_text}");
    assert!(
        first_text.contains("x-iroh-path: /base/stream-check"),
        "response head: {first_text}"
    );
    assert!(
        first_text.contains("x-iroh-query: fixed=1&client=1"),
        "response head: {first_text}"
    );

    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("set long read timeout");
    let mut rest = Vec::new();
    stream.read_to_end(&mut rest).expect("read remaining body");
    let full = format!("{}{}", first_text, String::from_utf8_lossy(&rest));
    assert!(full.contains("second\n"), "full response: {full}");

    zeroserve.stop();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn zeroserve_streams_request_bodies_to_real_iroh_http_server() {
    let (_server, node_id, direct_addr) = start_iroh_http_server().await;

    let temp = TempDir::new("zeroserve-iroh-proxy-body-e2e");
    let script = temp.path().join("proxy.c");
    write_proxy_script(
        &script,
        &format!("iroh://{node_id}/base?addr={direct_addr}&fixed=1"),
        None,
    );

    let mut zeroserve = ChildGuard::new(spawn_zeroserve(&script));
    let port = wait_for_http_port(zeroserve.child_mut());

    let chunks = vec![vec![b'a'; 1024]; 64];
    let response = http_post_chunked(
        port,
        "/echo-body?client=body",
        &chunks,
        Duration::from_secs(45),
    );
    assert!(response.contains("211"), "response: {response}");
    assert!(
        response.contains("x-iroh-path: /base/echo-body"),
        "response: {response}"
    );
    assert!(
        response.contains("x-iroh-query: fixed=1&client=body"),
        "response: {response}"
    );
    assert!(
        response.contains("x-iroh-body-len: 65536"),
        "response: {response}"
    );
    assert!(response.contains("len=65536"), "response: {response}");

    zeroserve.stop();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn zeroserve_streams_iroh_response_before_request_body_finishes() {
    let (_server, node_id, direct_addr) = start_iroh_http_server().await;

    let temp = TempDir::new("zeroserve-iroh-proxy-full-duplex-e2e");
    let script = temp.path().join("proxy.c");
    write_proxy_script(
        &script,
        &format!("iroh://{node_id}/base?addr={direct_addr}&fixed=1"),
        None,
    );

    let mut zeroserve = ChildGuard::new(spawn_zeroserve(&script));
    let port = wait_for_http_port(zeroserve.child_mut());

    let warmup = http_get_all(port, "/warmup", Duration::from_secs(45));
    assert!(warmup.contains("204"), "warmup response: {warmup}");

    let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("connect zeroserve");
    stream
        .set_read_timeout(Some(Duration::from_secs(20)))
        .expect("set read timeout");
    stream
        .write_all(
            b"POST /early-response?client=duplex HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n\r\n400\r\n",
        )
        .expect("write request head and first chunk size");
    stream
        .write_all(&vec![b'a'; 1024])
        .expect("write first chunk body");
    stream.write_all(b"\r\n").expect("finish first chunk");

    let early = read_until(&mut stream, b"early\n");
    assert!(early.contains("213"), "early response head: {early}");
    assert!(
        early.contains("early\n"),
        "response should arrive before request body finishes: {early}"
    );

    stream
        .write_all(b"400\r\n")
        .expect("write second chunk size");
    stream
        .write_all(&vec![b'b'; 1024])
        .expect("write second chunk body");
    stream
        .write_all(b"\r\n0\r\n\r\n")
        .expect("finish chunked request");
    let done = read_until(&mut stream, b"len=2048\n");
    assert!(done.contains("len=2048\n"), "full response: {done}");

    zeroserve.stop();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn zeroserve_reverse_proxies_h2_clients_to_real_iroh_http_server() {
    let (_server, node_id, direct_addr) = start_iroh_http_server().await;

    let temp = TempDir::new("zeroserve-iroh-proxy-h2-e2e");
    let script = temp.path().join("proxy.c");
    write_proxy_script(
        &script,
        &format!("iroh://{node_id}/base?addr={direct_addr}&fixed=1"),
        None,
    );

    let mut zeroserve = ChildGuard::new(spawn_zeroserve(&script));
    let port = wait_for_http_port(zeroserve.child_mut());

    let response = h2_get(port, "/h2-check?client=h2").await;
    assert_eq!(response.status(), http::StatusCode::from_u16(209).unwrap());
    assert_eq!(
        response.headers().get("x-iroh-path").unwrap(),
        "/base/h2-check"
    );
    assert_eq!(
        response.headers().get("x-iroh-query").unwrap(),
        "fixed=1&client=h2"
    );

    zeroserve.stop();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn zeroserve_iroh_proxy_rejects_too_large_chunked_request_body() {
    let (_server, node_id, direct_addr) = start_iroh_http_server().await;

    let temp = TempDir::new("zeroserve-iroh-proxy-limit-e2e");
    let script = temp.path().join("proxy.c");
    write_proxy_script(
        &script,
        &format!("iroh://{node_id}/base?addr={direct_addr}&fixed=1"),
        Some(4),
    );

    let mut zeroserve = ChildGuard::new(spawn_zeroserve(&script));
    let port = wait_for_http_port(zeroserve.child_mut());

    let response = http_post_chunked(
        port,
        "/echo-body?client=limit",
        &[b"abc".to_vec(), b"def".to_vec()],
        Duration::from_secs(45),
    );
    assert!(
        response.contains("413"),
        "too-large response should be 413: {response}"
    );

    zeroserve.stop();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn zeroserve_iroh_proxy_tunnels_websocket_upgrade_bytes() {
    let (_server, node_id, direct_addr) = start_iroh_http_server().await;

    let temp = TempDir::new("zeroserve-iroh-proxy-upgrade-e2e");
    let script = temp.path().join("proxy.c");
    write_proxy_script(
        &script,
        &format!("iroh://{node_id}/base?addr={direct_addr}&fixed=1"),
        None,
    );

    let mut zeroserve = ChildGuard::new(spawn_zeroserve(&script));
    let port = wait_for_http_port(zeroserve.child_mut());

    let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("connect zeroserve");
    stream
        .set_read_timeout(Some(Duration::from_secs(20)))
        .expect("set read timeout");
    stream
        .write_all(
            b"GET /ws HTTP/1.1\r\nHost: localhost\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n",
        )
        .expect("write upgrade request");

    let response_head = read_until(&mut stream, b"\r\n\r\n");
    assert!(
        response_head.contains("101"),
        "upgrade response should be 101: {response_head}"
    );
    assert!(
        response_head
            .to_ascii_lowercase()
            .contains("upgrade: websocket"),
        "upgrade response should preserve upgrade headers: {response_head}"
    );

    stream
        .write_all(b"ping-over-iroh")
        .expect("write websocket bytes");
    let echoed = read_until(&mut stream, b"echo:ping-over-iroh");
    assert!(
        echoed.contains("echo:ping-over-iroh"),
        "websocket echo: {echoed}"
    );

    zeroserve.stop();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn zeroserve_iroh_proxy_returns_gateway_error_for_dead_endpoint() {
    let bogus_node_id = iroh::SecretKey::generate().public().to_string();

    let temp = TempDir::new("zeroserve-iroh-proxy-dead-e2e");
    let script = temp.path().join("proxy.c");
    write_proxy_script(
        &script,
        &format!("iroh://{bogus_node_id}/base?addr=127.0.0.1:1&fixed=1"),
        None,
    );

    let mut zeroserve = ChildGuard::new(spawn_zeroserve(&script));
    let port = wait_for_http_port(zeroserve.child_mut());

    let response = http_get_all(port, "/dead", Duration::from_secs(45));
    assert!(
        response.contains("502"),
        "dead endpoint response should be 502: {response}"
    );

    zeroserve.stop();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn zeroserve_reverse_proxies_through_real_dumbpipe_listen_tcp() {
    let Some(dumbpipe) = dumbpipe_bin() else {
        eprintln!("skipping real dumbpipe e2e: set DUMBPIPE_BIN or install dumbpipe on PATH");
        return;
    };

    let (backend_addr, backend_request_rx) = start_single_request_http_backend();
    let secret = SecretKey::generate();
    let secret_hex = hex_encode_32(&secret.to_bytes());
    let node_id = secret.public().to_string();
    let iroh_addr = format!("127.0.0.1:{}", unused_tcp_port());

    let mut dumbpipe = ChildGuard::new(
        Command::new(dumbpipe)
            .arg("listen-tcp")
            .arg("--host")
            .arg(backend_addr.to_string())
            .arg("--ipv4-addr")
            .arg(&iroh_addr)
            .env("IROH_SECRET", &secret_hex)
            .env_remove("RUST_LOG")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn dumbpipe listen-tcp"),
    );
    wait_for_dumbpipe_listen_tcp(dumbpipe.child_mut());

    let temp = TempDir::new("zeroserve-iroh-proxy-real-dumbpipe-e2e");
    let script = temp.path().join("proxy.c");
    write_proxy_script(
        &script,
        &format!("iroh://{node_id}/via-dumbpipe?addr={iroh_addr}&fixed=1"),
        None,
    );

    let mut zeroserve = ChildGuard::new(spawn_zeroserve(&script));
    let port = wait_for_http_port(zeroserve.child_mut());

    let response = http_get_all(port, "/real?client=dumbpipe", Duration::from_secs(45));
    assert!(response.contains("217"), "response: {response}");
    assert!(
        response.contains(
            "dumbpipe backend saw GET /via-dumbpipe/real?fixed=1&client=dumbpipe HTTP/1.1"
        ),
        "response: {response}"
    );
    let backend_request = backend_request_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("backend received request through dumbpipe");
    assert!(
        backend_request.starts_with("GET /via-dumbpipe/real?fixed=1&client=dumbpipe HTTP/1.1"),
        "backend request: {backend_request}"
    );

    zeroserve.stop();
    dumbpipe.stop();
}

struct IrohHttpServer {
    _endpoint: Endpoint,
    accept_task: tokio::task::JoinHandle<()>,
}

impl Drop for IrohHttpServer {
    fn drop(&mut self) {
        self.accept_task.abort();
    }
}

async fn start_iroh_http_server() -> (IrohHttpServer, String, std::net::SocketAddr) {
    let endpoint = Endpoint::builder(presets::Minimal)
        .relay_mode(RelayMode::Disabled)
        .clear_ip_transports()
        .bind_addr("127.0.0.1:0")
        .expect("configure iroh loopback bind")
        .alpns(vec![DUMBPIPE_ALPN.to_vec()])
        .bind()
        .await
        .expect("bind iroh endpoint");
    let node_id = endpoint.id().to_string();
    let direct_addr = endpoint
        .addr()
        .ip_addrs()
        .next()
        .copied()
        .expect("iroh endpoint has a direct address");
    let accept_endpoint = endpoint.clone();
    let accept_task = tokio::spawn(async move {
        while let Some(incoming) = accept_endpoint.accept().await {
            let accepting = match incoming.accept() {
                Ok(accepting) => accepting,
                Err(_) => continue,
            };
            tokio::spawn(async move {
                let Ok(conn) = accepting.await else {
                    return;
                };
                while let Ok((send, recv)) = conn.accept_bi().await {
                    tokio::spawn(async move {
                        let _ = handle_dumbpipe_http_stream(send, recv).await;
                    });
                }
            });
        }
    });
    (
        IrohHttpServer {
            _endpoint: endpoint,
            accept_task,
        },
        node_id,
        direct_addr,
    )
}

async fn handle_dumbpipe_http_stream(
    mut send: SendStream,
    mut recv: RecvStream,
) -> anyhow::Result<()> {
    let mut handshake = [0u8; 5];
    recv.read_exact(&mut handshake)
        .await
        .map_err(|err| anyhow::anyhow!("read dumbpipe handshake: {err}"))?;
    anyhow::ensure!(
        handshake == DUMBPIPE_HANDSHAKE,
        "invalid dumbpipe handshake"
    );

    let mut reader = TestHttpReader::new(recv);
    let request = reader.read_request_head().await?;
    if request.path == "/base/warmup" {
        write_response(&mut send, 204, &[("content-length", "0")], &[]).await?;
    } else if request.path == "/base/ws" {
        write_websocket_echo_response(&mut send, &mut reader).await?;
    } else if request.path == "/base/early-response" {
        write_early_response_then_read_body(&mut send, &mut reader, &request.headers).await?;
    } else if request.path == "/base/echo-body" {
        let len = reader.read_request_body_len(&request.headers).await?;
        let body = format!("len={len}\n");
        let len_header = len.to_string();
        let content_length = body.len().to_string();
        write_response(
            &mut send,
            211,
            &[
                ("content-type", "text/plain"),
                ("x-iroh-path", &request.path),
                ("x-iroh-query", &request.query),
                ("x-iroh-body-len", &len_header),
                ("content-length", &content_length),
            ],
            body.as_bytes(),
        )
        .await?;
    } else {
        write_chunked_streaming_response(&mut send, &request.path, &request.query).await?;
    }
    send.finish().expect("finish iroh response stream");
    Ok(())
}

struct TestRequest {
    path: String,
    query: String,
    headers: Vec<(String, String)>,
}

struct TestHttpReader {
    recv: RecvStream,
    buffer: Vec<u8>,
    eof: bool,
}

impl TestHttpReader {
    fn new(recv: RecvStream) -> Self {
        Self {
            recv,
            buffer: Vec::new(),
            eof: false,
        }
    }

    async fn read_request_head(&mut self) -> anyhow::Result<TestRequest> {
        loop {
            if let Some(head_end) = find_subslice(&self.buffer, b"\r\n\r\n") {
                let rest = self.buffer.split_off(head_end + 4);
                let mut head = std::mem::replace(&mut self.buffer, rest);
                head.truncate(head_end);
                let head = std::str::from_utf8(&head)?;
                let mut lines = head.split("\r\n");
                let request_line = lines.next().expect("request line exists");
                let mut request_parts = request_line.split_whitespace();
                let _method = request_parts.next().expect("request method exists");
                let target = request_parts.next().expect("request target exists");
                let (path, query) = target
                    .split_once('?')
                    .map(|(path, query)| (path.to_string(), query.to_string()))
                    .unwrap_or_else(|| (target.to_string(), String::new()));
                let mut headers = Vec::new();
                for line in lines {
                    if let Some((name, value)) = line.split_once(':') {
                        headers.push((name.trim().to_ascii_lowercase(), value.trim().to_string()));
                    }
                }
                return Ok(TestRequest {
                    path,
                    query,
                    headers,
                });
            }
            anyhow::ensure!(self.buffer.len() < 64 * 1024, "request head too large");
            anyhow::ensure!(self.read_more().await?, "request ended before head");
        }
    }

    async fn read_request_body_len(
        &mut self,
        headers: &[(String, String)],
    ) -> anyhow::Result<usize> {
        if headers.iter().any(|(name, value)| {
            name == "transfer-encoding"
                && value
                    .split(',')
                    .any(|part| part.trim().eq_ignore_ascii_case("chunked"))
        }) {
            self.read_chunked_body_len().await
        } else if let Some((_, value)) = headers.iter().find(|(name, _)| name == "content-length") {
            self.read_fixed_body_len(value.parse()?).await
        } else {
            self.read_until_eof_len().await
        }
    }

    async fn read_fixed_body_len(&mut self, mut remaining: usize) -> anyhow::Result<usize> {
        let mut len = 0usize;
        while remaining > 0 {
            let chunk = self.next_chunk(remaining.min(8192)).await?;
            let Some(chunk) = chunk else {
                anyhow::bail!("request body ended early");
            };
            remaining -= chunk.len();
            len += chunk.len();
        }
        Ok(len)
    }

    async fn read_chunked_body_len(&mut self) -> anyhow::Result<usize> {
        let mut len = 0usize;
        loop {
            let line = self.read_line().await?;
            let size = usize::from_str_radix(
                std::str::from_utf8(&line)?
                    .split_once(';')
                    .map_or(std::str::from_utf8(&line)?, |(size, _)| size)
                    .trim(),
                16,
            )?;
            if size == 0 {
                loop {
                    if self.read_line().await?.is_empty() {
                        return Ok(len);
                    }
                }
            }
            len += self.read_fixed_body_len(size).await?;
            self.consume_exact(2).await?;
        }
    }

    async fn read_until_eof_len(&mut self) -> anyhow::Result<usize> {
        let mut len = 0usize;
        while let Some(chunk) = self.next_chunk(8192).await? {
            len += chunk.len();
        }
        Ok(len)
    }

    async fn read_line(&mut self) -> anyhow::Result<Vec<u8>> {
        loop {
            if let Some(end) = find_subslice(&self.buffer, b"\r\n") {
                let rest = self.buffer.split_off(end + 2);
                let mut line = std::mem::replace(&mut self.buffer, rest);
                line.truncate(end);
                return Ok(line);
            }
            anyhow::ensure!(self.buffer.len() < 8192, "line too large");
            anyhow::ensure!(self.read_more().await?, "request ended in line");
        }
    }

    async fn consume_exact(&mut self, mut len: usize) -> anyhow::Result<()> {
        while len > 0 {
            if !self.buffer.is_empty() {
                let take = len.min(self.buffer.len());
                self.buffer.drain(..take);
                len -= take;
            } else {
                anyhow::ensure!(self.read_more().await?, "request ended early");
            }
        }
        Ok(())
    }

    async fn next_chunk(&mut self, max_len: usize) -> anyhow::Result<Option<Bytes>> {
        if !self.buffer.is_empty() {
            let take = max_len.min(self.buffer.len());
            let chunk = Bytes::copy_from_slice(&self.buffer[..take]);
            self.buffer.drain(..take);
            return Ok(Some(chunk));
        }
        if self.eof {
            return Ok(None);
        }
        match self.recv.read_chunk(max_len).await {
            Ok(Some(chunk)) => Ok(Some(chunk.bytes)),
            Ok(None) => {
                self.eof = true;
                Ok(None)
            }
            Err(err) => Err(anyhow::anyhow!("read iroh request chunk: {err}")),
        }
    }

    async fn read_more(&mut self) -> anyhow::Result<bool> {
        if self.eof {
            return Ok(false);
        }
        let mut buf = [0u8; 8192];
        match self.recv.read(&mut buf).await {
            Ok(Some(n)) => {
                self.buffer.extend_from_slice(&buf[..n]);
                Ok(true)
            }
            Ok(None) => {
                self.eof = true;
                Ok(false)
            }
            Err(err) => Err(anyhow::anyhow!("read iroh request: {err}")),
        }
    }
}

async fn write_response(
    send: &mut SendStream,
    status: u16,
    headers: &[(&str, &str)],
    body: &[u8],
) -> anyhow::Result<()> {
    let mut head = format!("HTTP/1.1 {status} test\r\n");
    for (name, value) in headers {
        head.push_str(name);
        head.push_str(": ");
        head.push_str(value);
        head.push_str("\r\n");
    }
    head.push_str("\r\n");
    send.write_all(head.as_bytes()).await?;
    send.write_all(body).await?;
    Ok(())
}

async fn write_chunked_streaming_response(
    send: &mut SendStream,
    path: &str,
    query: &str,
) -> anyhow::Result<()> {
    let head = format!(
        "HTTP/1.1 209 test\r\ncontent-type: text/plain\r\nx-iroh-path: {path}\r\nx-iroh-query: {query}\r\ntransfer-encoding: chunked\r\n\r\n"
    );
    send.write_all(head.as_bytes()).await?;
    send.write_all(b"6\r\nfirst\n\r\n").await?;
    tokio::time::sleep(Duration::from_secs(5)).await;
    send.write_all(b"7\r\nsecond\n\r\n0\r\n\r\n").await?;
    Ok(())
}

async fn write_websocket_echo_response(
    send: &mut SendStream,
    reader: &mut TestHttpReader,
) -> anyhow::Result<()> {
    send.write_all(
        b"HTTP/1.1 101 Switching Protocols\r\nconnection: upgrade\r\nupgrade: websocket\r\n\r\n",
    )
    .await?;
    while let Some(chunk) = reader.next_chunk(8192).await? {
        send.write_all(b"echo:").await?;
        send.write_all(&chunk).await?;
    }
    Ok(())
}

async fn write_early_response_then_read_body(
    send: &mut SendStream,
    reader: &mut TestHttpReader,
    headers: &[(String, String)],
) -> anyhow::Result<()> {
    send.write_all(
        b"HTTP/1.1 213 test\r\ncontent-type: text/plain\r\ntransfer-encoding: chunked\r\n\r\n6\r\nearly\n\r\n",
    )
    .await?;
    let len = reader.read_request_body_len(headers).await?;
    let body = format!("len={len}\n");
    let chunk = format!("{:x}\r\n{body}\r\n0\r\n\r\n", body.len());
    send.write_all(chunk.as_bytes()).await?;
    Ok(())
}

fn write_proxy_script(script: &Path, backend: &str, body_limit: Option<usize>) {
    let limit = body_limit
        .map(|limit| format!("  zs_req_body_limit({limit});\n"))
        .unwrap_or_default();
    fs::write(
        script,
        format!(
            "#include <zeroserve.h>\n\nZS_ENTRY\nzs_u64 entry(void) {{\n{limit}  const char backend[] = \"{backend}\";\n  zs_reverse_proxy(backend, sizeof(backend) - 1);\n  return 0;\n}}\n"
        ),
    )
    .expect("write proxy script");
}

fn spawn_zeroserve(script: &Path) -> Child {
    let exe = env!("CARGO_BIN_EXE_zeroserve");
    Command::new(exe)
        .arg("--addr")
        .arg("127.0.0.1:0")
        .arg("--disable-ns-isolation")
        .arg("--disable-request-logging")
        .arg("--iroh-proxy")
        .arg("--iroh-disable-networking")
        .arg(script)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn zeroserve")
}

fn wait_for_http_port(child: &mut Child) -> u16 {
    let stderr = child.stderr.take().expect("stderr is piped");
    let (tx, rx) = mpsc::channel::<String>();
    std::thread::spawn(move || {
        let mut reader = BufReader::new(stderr);
        loop {
            let mut line = String::new();
            match reader.read_line(&mut line) {
                Ok(0) | Err(_) => return,
                Ok(_) => {
                    if tx.send(line).is_err() {
                        for line in reader.lines().map_while(Result::ok) {
                            eprintln!("[zeroserve] {line}");
                        }
                        return;
                    }
                }
            }
        }
    });

    let deadline = std::time::Instant::now() + Duration::from_secs(20);
    let mut captured = String::new();
    loop {
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        assert!(
            !remaining.is_zero(),
            "timed out waiting for zeroserve listen line; stderr:\n{captured}"
        );
        let line = rx.recv_timeout(remaining).unwrap_or_else(|_| {
            panic!("zeroserve exited or stopped logging before listening; stderr:\n{captured}")
        });
        captured.push_str(&line);
        if let Some(port) = parse_listen_port(&line) {
            return port;
        }
    }
}

fn wait_for_dumbpipe_listen_tcp(child: &mut Child) {
    let stderr = child.stderr.take().expect("stderr is piped");
    let (tx, rx) = mpsc::channel::<String>();
    std::thread::spawn(move || {
        let mut reader = BufReader::new(stderr);
        loop {
            let mut line = String::new();
            match reader.read_line(&mut line) {
                Ok(0) | Err(_) => return,
                Ok(_) => {
                    if tx.send(line).is_err() {
                        for line in reader.lines().map_while(Result::ok) {
                            eprintln!("[dumbpipe] {line}");
                        }
                        return;
                    }
                }
            }
        }
    });

    let deadline = std::time::Instant::now() + Duration::from_secs(20);
    let mut captured = String::new();
    loop {
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        assert!(
            !remaining.is_zero(),
            "timed out waiting for dumbpipe listen-tcp ticket; stderr:\n{captured}"
        );
        let line = rx.recv_timeout(remaining).unwrap_or_else(|_| {
            panic!("dumbpipe exited or stopped logging before ticket; stderr:\n{captured}")
        });
        let ready = line.contains("dumbpipe connect-tcp ");
        captured.push_str(&line);
        if ready {
            return;
        }
    }
}

fn start_single_request_http_backend() -> (SocketAddr, mpsc::Receiver<String>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind dumbpipe backend");
    let addr = listener.local_addr().expect("backend local addr");
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept dumbpipe backend request");
        stream
            .set_read_timeout(Some(Duration::from_secs(20)))
            .expect("set backend read timeout");
        let mut request = Vec::new();
        let mut buf = [0u8; 512];
        while !request.windows(4).any(|window| window == b"\r\n\r\n") {
            let n = stream.read(&mut buf).expect("read backend request");
            assert!(n > 0, "backend connection closed before request head");
            request.extend_from_slice(&buf[..n]);
        }
        let request_text = String::from_utf8_lossy(&request).into_owned();
        let request_line = request_text.lines().next().unwrap_or_default().to_string();
        tx.send(request_text).expect("send backend request");
        let body = format!("dumbpipe backend saw {request_line}\n");
        let response = format!(
            "HTTP/1.1 217 Dumbpipe\r\ncontent-type: text/plain\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
            body.len()
        );
        stream
            .write_all(response.as_bytes())
            .expect("write backend response");
    });
    (addr, rx)
}

fn dumbpipe_bin() -> Option<PathBuf> {
    if let Ok(path) = std::env::var("DUMBPIPE_BIN")
        && !path.is_empty()
    {
        return Some(PathBuf::from(path));
    }
    std::env::var_os("PATH").and_then(|paths| {
        std::env::split_paths(&paths)
            .map(|path| path.join("dumbpipe"))
            .find(|path| path.is_file())
    })
}

fn unused_tcp_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .expect("bind unused tcp port")
        .local_addr()
        .expect("unused tcp local addr")
        .port()
}

fn hex_encode_32(bytes: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(64);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

fn parse_listen_port(line: &str) -> Option<u16> {
    let marker = "listening on http://";
    let rest = line.split_once(marker)?.1;
    let port = rest
        .rsplit_once(':')?
        .1
        .chars()
        .take_while(|ch| ch.is_ascii_digit())
        .collect::<String>();
    port.parse().ok()
}

fn http_get_all(port: u16, path: &str, timeout: Duration) -> String {
    http_request_all(
        port,
        format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n").as_bytes(),
        timeout,
    )
}

fn http_post_chunked(port: u16, path: &str, chunks: &[Vec<u8>], timeout: Duration) -> String {
    let mut request = format!(
        "POST {path} HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n"
    )
    .into_bytes();
    for chunk in chunks {
        write!(&mut request, "{:x}\r\n", chunk.len()).expect("write chunk size");
        request.extend_from_slice(chunk);
        request.extend_from_slice(b"\r\n");
    }
    request.extend_from_slice(b"0\r\n\r\n");
    http_request_all(port, &request, timeout)
}

fn http_request_all(port: u16, request: &[u8], timeout: Duration) -> String {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("connect zeroserve");
    stream
        .set_read_timeout(Some(timeout))
        .expect("set read timeout");
    stream.write_all(request).expect("write request");
    let mut out = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        match stream.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                out.extend_from_slice(&buf[..n]);
                if response_is_complete(&out) {
                    break;
                }
            }
            Err(err) if err.kind() == ErrorKind::WouldBlock && !out.is_empty() => break,
            Err(err) => panic!("read response: {err}"),
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn read_until(stream: &mut TcpStream, needle: &[u8]) -> String {
    let mut out = Vec::new();
    let mut buf = [0u8; 512];
    while !out.windows(needle.len()).any(|window| window == needle) {
        let n = stream.read(&mut buf).expect("read from stream");
        assert!(n > 0, "stream closed before delimiter");
        out.extend_from_slice(&buf[..n]);
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn response_is_complete(response: &[u8]) -> bool {
    let Some(head_end) = find_subslice(response, b"\r\n\r\n") else {
        return false;
    };
    let body_start = head_end + 4;
    let head = String::from_utf8_lossy(&response[..head_end]);
    for line in head.lines().skip(1) {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        if name.eq_ignore_ascii_case("content-length")
            && let Ok(len) = value.trim().parse::<usize>()
        {
            return response.len().saturating_sub(body_start) >= len;
        }
        if name.eq_ignore_ascii_case("transfer-encoding")
            && value
                .split(',')
                .any(|part| part.trim().eq_ignore_ascii_case("chunked"))
        {
            return response[body_start..].windows(5).any(|w| w == b"0\r\n\r\n");
        }
    }
    false
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

async fn h2_get(port: u16, path: &str) -> http::Response<h2::RecvStream> {
    let stream = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("connect zeroserve h2c");
    let (mut client, connection) = h2::client::handshake(stream).await.expect("h2c handshake");
    tokio::spawn(async move {
        let _ = connection.await;
    });
    let request = http::Request::builder()
        .method("GET")
        .uri(path)
        .header("host", "localhost")
        .body(())
        .expect("build h2 request");
    let (response, _) = client.send_request(request, true).expect("send h2 request");
    response.await.expect("h2 response")
}

struct TempDir {
    path: PathBuf,
}

impl TempDir {
    fn new(prefix: &str) -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock after epoch")
            .as_nanos();
        let path = std::env::temp_dir().join(format!("{prefix}-{}-{nonce}", std::process::id()));
        fs::create_dir_all(&path).expect("create temp dir");
        Self { path }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

struct ChildGuard {
    child: Option<Child>,
}

impl ChildGuard {
    fn new(child: Child) -> Self {
        Self { child: Some(child) }
    }

    fn child_mut(&mut self) -> &mut Child {
        self.child.as_mut().expect("child exists")
    }

    fn stop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        self.stop();
    }
}
