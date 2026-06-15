#![cfg(feature = "iroh-proxy")]

use std::{
    convert::Infallible,
    fs,
    io::{BufRead, BufReader, Read, Write},
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
    let _serve = serve(
        server_ep.clone(),
        ServeOptions::default(),
        DelayedStreamingService,
    );

    let temp = TempDir::new("zeroserve-iroh-proxy-e2e");
    let script = temp.path().join("proxy.c");
    fs::write(
        &script,
        format!(
            "#include <zeroserve.h>\n\nZS_ENTRY\nzs_u64 entry(void) {{\n  const char backend[] = \"iroh://{}/base?addr={}&fixed=1\";\n  zs_reverse_proxy(backend, sizeof(backend) - 1);\n  return 0;\n}}\n",
            node_id, direct_addr
        ),
    )
    .expect("write proxy script");

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
    let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("connect zeroserve");
    stream
        .set_read_timeout(Some(timeout))
        .expect("set read timeout");
    write!(
        stream,
        "GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
    )
    .expect("write request");
    let mut out = String::new();
    stream.read_to_string(&mut out).expect("read response");
    out
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
