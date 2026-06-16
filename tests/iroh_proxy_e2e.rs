#![cfg(feature = "iroh-proxy")]

use std::{
    convert::Infallible,
    fs,
    io::{BufRead, BufReader, ErrorKind, Read, Write},
    net::TcpStream,
    path::{Path, PathBuf},
    pin::Pin,
    process::{Child, Command, Stdio},
    sync::mpsc,
    task::{Context, Poll},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use bytes::Bytes;
use http_body::Frame;
use http_body_util::BodyExt;
use iroh_http_core::{Body, IrohEndpoint, NetworkingOptions, NodeOptions, ServeOptions, serve};
use tower::Service;

#[derive(Clone)]
struct DelayedStreamingService;

impl Service<hyper::Request<Body>> for DelayedStreamingService {
    type Response = hyper::Response<Body>;
    type Error = Infallible;
    type Future =
        Pin<Box<dyn std::future::Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: hyper::Request<Body>) -> Self::Future {
        let path = req.uri().path().to_string();
        let query = req.uri().query().unwrap_or("").to_string();
        Box::pin(async move {
            if path == "/base/warmup" {
                return Ok(hyper::Response::builder()
                    .status(204)
                    .body(Body::empty())
                    .expect("static response is valid"));
            }
            if path == "/base/echo-body" {
                let mut len = 0usize;
                let mut body = req.into_body();
                while let Some(frame) = body.frame().await {
                    let frame = frame.expect("request body frame is readable");
                    if let Ok(chunk) = frame.into_data() {
                        len += chunk.len();
                    }
                }
                return Ok(hyper::Response::builder()
                    .status(211)
                    .header("content-type", "text/plain")
                    .header("x-iroh-path", path)
                    .header("x-iroh-query", query)
                    .header("x-iroh-body-len", len.to_string())
                    .body(Body::full(Bytes::from(format!("len={len}\n"))))
                    .expect("static response is valid"));
            }
            Ok(hyper::Response::builder()
                .status(209)
                .header("content-type", "text/plain")
                .header("x-iroh-path", path)
                .header("x-iroh-query", query)
                .body(Body::new(DelayedBody::default()))
                .expect("static response is valid"))
        })
    }
}

#[derive(Default)]
struct DelayedBody {
    state: u8,
    sleep: Option<Pin<Box<tokio::time::Sleep>>>,
}

impl http_body::Body for DelayedBody {
    type Data = Bytes;
    type Error = std::io::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        loop {
            match self.state {
                0 => {
                    self.state = 1;
                    self.sleep = Some(Box::pin(tokio::time::sleep(Duration::from_secs(5))));
                    return Poll::Ready(Some(Ok(Frame::data(Bytes::from_static(b"first\n")))));
                }
                1 => {
                    let sleep = self.sleep.as_mut().expect("sleep exists in state 1");
                    if sleep.as_mut().poll(cx).is_pending() {
                        return Poll::Pending;
                    }
                    self.state = 2;
                    return Poll::Ready(Some(Ok(Frame::data(Bytes::from_static(b"second\n")))));
                }
                _ => return Poll::Ready(None),
            }
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn zeroserve_reverse_proxies_to_real_iroh_http_server_streaming_response() {
    let (server_ep, node_id, direct_addr) = bind_iroh_endpoint().await;
    let _serve = serve(
        server_ep.clone(),
        ServeOptions::default(),
        DelayedStreamingService,
    );

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
    let (server_ep, node_id, direct_addr) = bind_iroh_endpoint().await;
    let _serve = serve(
        server_ep.clone(),
        ServeOptions::default(),
        DelayedStreamingService,
    );

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
async fn zeroserve_reverse_proxies_h2_clients_to_real_iroh_http_server() {
    let (server_ep, node_id, direct_addr) = bind_iroh_endpoint().await;
    let _serve = serve(
        server_ep.clone(),
        ServeOptions::default(),
        DelayedStreamingService,
    );

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
    let (server_ep, node_id, direct_addr) = bind_iroh_endpoint().await;
    let _serve = serve(
        server_ep.clone(),
        ServeOptions::default(),
        DelayedStreamingService,
    );

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
async fn zeroserve_iroh_proxy_rejects_upgrade_requests_with_501() {
    let (server_ep, node_id, direct_addr) = bind_iroh_endpoint().await;
    let _serve = serve(
        server_ep.clone(),
        ServeOptions::default(),
        DelayedStreamingService,
    );

    let temp = TempDir::new("zeroserve-iroh-proxy-upgrade-e2e");
    let script = temp.path().join("proxy.c");
    write_proxy_script(
        &script,
        &format!("iroh://{node_id}/base?addr={direct_addr}&fixed=1"),
        None,
    );

    let mut zeroserve = ChildGuard::new(spawn_zeroserve(&script));
    let port = wait_for_http_port(zeroserve.child_mut());

    let response = http_request_all(
        port,
        b"GET /ws HTTP/1.1\r\nHost: localhost\r\nConnection: Upgrade, close\r\nUpgrade: websocket\r\n\r\n",
        Duration::from_secs(20),
    );
    assert!(
        response.contains("501"),
        "upgrade response should be 501: {response}"
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

async fn bind_iroh_endpoint() -> (IrohEndpoint, String, std::net::SocketAddr) {
    let server_ep = IrohEndpoint::bind(NodeOptions {
        networking: NetworkingOptions {
            disabled: true,
            bind_addrs: vec!["127.0.0.1:0".to_string()],
            ..Default::default()
        },
        ..Default::default()
    })
    .await
    .expect("bind iroh endpoint");
    let node_id = server_ep.node_id().to_string();
    let direct_addr = server_ep
        .raw()
        .addr()
        .ip_addrs()
        .next()
        .copied()
        .expect("iroh endpoint has a direct address");
    (server_ep, node_id, direct_addr)
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
