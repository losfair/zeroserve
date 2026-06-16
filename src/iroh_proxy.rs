use ::http::{HeaderMap, StatusCode};
use anyhow::{Result, anyhow};
use bytes::Bytes;

use crate::config::StaticConfig;

#[derive(Clone, Debug)]
#[cfg_attr(not(feature = "iroh-proxy"), allow(dead_code))]
pub(crate) struct IrohTarget {
    pub(crate) node_id: String,
    pub(crate) direct_addrs: Vec<std::net::SocketAddr>,
}

#[derive(Debug)]
#[cfg_attr(not(feature = "iroh-proxy"), allow(dead_code))]
pub(crate) struct IrohProxyRequest {
    pub(crate) target: IrohTarget,
    pub(crate) method: String,
    pub(crate) uri: String,
    pub(crate) headers: HeaderMap,
    pub(crate) body: RequestBody,
}

#[derive(Debug)]
pub(crate) struct IrohProxyResponse {
    pub(crate) status: StatusCode,
    pub(crate) headers: HeaderMap,
    pub(crate) body: ResponseBody,
}

#[cfg(feature = "iroh-proxy")]
#[derive(Debug)]
pub(crate) struct RequestBodySender(futures::channel::mpsc::Sender<Result<Bytes, String>>);

#[cfg(feature = "iroh-proxy")]
#[derive(Debug)]
pub(crate) struct RequestBody(futures::channel::mpsc::Receiver<Result<Bytes, String>>);

#[cfg(feature = "iroh-proxy")]
#[derive(Debug)]
pub(crate) struct ResponseBody(futures::channel::mpsc::Receiver<Result<Bytes, String>>);

#[cfg(not(feature = "iroh-proxy"))]
#[derive(Debug)]
pub(crate) struct RequestBodySender;

#[cfg(not(feature = "iroh-proxy"))]
#[derive(Debug)]
pub(crate) struct RequestBody;

#[cfg(not(feature = "iroh-proxy"))]
#[derive(Debug)]
pub(crate) struct ResponseBody;

#[cfg(feature = "iroh-proxy")]
mod enabled {
    use super::*;
    use std::{
        io,
        path::Path,
        pin::Pin,
        sync::{Arc, OnceLock, mpsc as std_mpsc},
        task::{Context, Poll},
        time::Duration,
    };

    use anyhow::{Context as AnyhowContext, bail};
    use futures::{
        SinkExt, Stream, StreamExt,
        channel::{mpsc, oneshot},
    };
    use http_body::Frame;
    use http_body_util::BodyExt;
    use iroh_http_core::{Body, IrohEndpoint, NetworkingOptions, NodeOptions, StackConfig};
    use tokio::sync::Semaphore;

    const REQUEST_BODY_CHANNEL_CAPACITY: usize = 32;
    const RESPONSE_BODY_CHANNEL_CAPACITY: usize = 32;
    const COMMAND_CHANNEL_CAPACITY: usize = 1024;
    const MAX_CONCURRENT_FETCHES: usize = 256;

    static CLIENT: OnceLock<IrohProxyClient> = OnceLock::new();

    struct IrohProxyClient {
        tx: std_mpsc::SyncSender<Command>,
    }

    struct Command {
        request: IrohProxyRequest,
        tx: oneshot::Sender<Result<IrohProxyResponse, String>>,
    }

    struct RequestChannelBody {
        rx: mpsc::Receiver<Result<Bytes, String>>,
    }

    impl http_body::Body for RequestChannelBody {
        type Data = Bytes;
        type Error = io::Error;

        fn poll_frame(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
        ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
            match Stream::poll_next(Pin::new(&mut self.rx), cx) {
                Poll::Ready(Some(Ok(chunk))) => Poll::Ready(Some(Ok(Frame::data(chunk)))),
                Poll::Ready(Some(Err(err))) => Poll::Ready(Some(Err(io::Error::other(err)))),
                Poll::Ready(None) => Poll::Ready(None),
                Poll::Pending => Poll::Pending,
            }
        }
    }

    pub(crate) fn init(config: &StaticConfig) -> Result<()> {
        if !config.iroh_proxy {
            return Ok(());
        }
        if CLIENT.get().is_some() {
            return Ok(());
        }

        let key = match config.iroh_secret_key.as_deref() {
            Some(path) => Some(load_or_create_secret_key(path)?),
            None => None,
        };

        let mut node_options = NodeOptions::default();
        node_options.key = key;
        if config.iroh_disable_networking {
            node_options.networking = NetworkingOptions {
                disabled: true,
                bind_addrs: vec!["127.0.0.1:0".to_string()],
                ..Default::default()
            };
        }

        let (cmd_tx, cmd_rx) = std_mpsc::sync_channel::<Command>(COMMAND_CHANNEL_CAPACITY);
        let (ready_tx, ready_rx) = std::sync::mpsc::channel::<Result<String, String>>();
        std::thread::Builder::new()
            .name("zeroserve-iroh-proxy".to_string())
            .spawn(move || {
                let runtime = match tokio::runtime::Builder::new_multi_thread()
                    .worker_threads(1)
                    .enable_all()
                    .build()
                {
                    Ok(runtime) => runtime,
                    Err(err) => {
                        let _ = ready_tx.send(Err(format!("failed to build Tokio runtime: {err}")));
                        return;
                    }
                };

                let endpoint = match runtime.block_on(IrohEndpoint::bind(node_options)) {
                    Ok(endpoint) => endpoint,
                    Err(err) => {
                        let _ = ready_tx.send(Err(format!("failed to bind iroh endpoint: {err}")));
                        return;
                    }
                };
                let node_id = endpoint.node_id().to_string();
                let _ = ready_tx.send(Ok(node_id));
                let handle = runtime.handle().clone();
                let semaphore = Arc::new(Semaphore::new(MAX_CONCURRENT_FETCHES));

                while let Ok(command) = cmd_rx.recv() {
                    let endpoint = endpoint.clone();
                    let semaphore = semaphore.clone();
                    handle.spawn(async move {
                        let permit = match semaphore.acquire_owned().await {
                            Ok(permit) => permit,
                            Err(_) => {
                                let _ = command
                                    .tx
                                    .send(Err("iroh proxy concurrency limiter closed".to_string()));
                                return;
                            }
                        };
                        let _permit = permit;
                        let result = fetch_on_tokio(&endpoint, command.request)
                            .await
                            .map_err(|err| err.to_string());
                        let _ = command.tx.send(result);
                    });
                }
            })
            .map_err(|err| anyhow!("failed to spawn iroh proxy thread: {err}"))?;

        let node_id = ready_rx
            .recv()
            .map_err(|err| anyhow!("iroh proxy thread stopped during startup: {err}"))?
            .map_err(|err| anyhow!(err))?;
        CLIENT
            .set(IrohProxyClient { tx: cmd_tx })
            .map_err(|_| anyhow!("iroh proxy already initialized"))?;
        eprintln!("iroh proxy enabled: local node id {node_id}");
        Ok(())
    }

    pub(crate) fn request_body_channel() -> (RequestBodySender, RequestBody) {
        let (tx, rx) = mpsc::channel(REQUEST_BODY_CHANNEL_CAPACITY);
        (RequestBodySender(tx), RequestBody(rx))
    }

    pub(crate) async fn send_request_body_chunk(
        sender: &mut RequestBodySender,
        chunk: Bytes,
    ) -> Result<()> {
        sender
            .0
            .send(Ok(chunk))
            .await
            .map_err(|err| anyhow!("iroh request body channel closed: {err}"))
    }

    pub(crate) async fn send_request_body_error(sender: &mut RequestBodySender, error: String) {
        let _ = sender.0.send(Err(error)).await;
    }

    pub(crate) fn start_fetch(request: IrohProxyRequest) -> Result<IrohFetch> {
        let client = CLIENT
            .get()
            .ok_or_else(|| anyhow!("iroh proxy transport is not enabled"))?;
        let (tx, rx) = oneshot::channel();
        client
            .tx
            .try_send(Command { request, tx })
            .map_err(|err| match err {
                std_mpsc::TrySendError::Full(_) => anyhow!("too many queued iroh proxy requests"),
                std_mpsc::TrySendError::Disconnected(_) => {
                    anyhow!("iroh proxy thread is not running")
                }
            })?;
        Ok(IrohFetch { rx })
    }

    pub(crate) struct IrohFetch {
        rx: oneshot::Receiver<Result<IrohProxyResponse, String>>,
    }

    impl IrohFetch {
        pub(crate) async fn response(self) -> Result<IrohProxyResponse> {
            self.rx
                .await
                .map_err(|_| anyhow!("iroh proxy fetch was cancelled"))?
                .map_err(|err| anyhow!(err))
        }
    }

    pub(crate) async fn next_response_body_chunk(body: &mut ResponseBody) -> Result<Option<Bytes>> {
        match body.0.next().await {
            Some(Ok(chunk)) => Ok(Some(chunk)),
            Some(Err(err)) => Err(anyhow!(err)),
            None => Ok(None),
        }
    }

    async fn fetch_on_tokio(
        endpoint: &IrohEndpoint,
        request: IrohProxyRequest,
    ) -> Result<IrohProxyResponse> {
        let mut addr = iroh::EndpointAddr::new(parse_node_id(&request.target.node_id)?);
        for direct_addr in request.target.direct_addrs {
            addr = addr.with_ip_addr(direct_addr);
        }

        let mut hyper_request = hyper::Request::builder()
            .method(request.method.as_str())
            .uri(request.uri.as_str())
            .body(Body::new(RequestChannelBody { rx: request.body.0 }))
            .map_err(|err| anyhow!("failed to build iroh HTTP request: {err}"))?;
        *hyper_request.headers_mut() = request.headers;

        let cfg = StackConfig::default().with_timeout(Some(Duration::from_secs(30)));
        let response = iroh_http_core::fetch_request(endpoint, &addr, hyper_request, &cfg)
            .await
            .map_err(|err| anyhow!("iroh fetch failed: {err}"))?;
        let (parts, body) = response.into_parts();
        let (mut body_tx, body_rx) =
            mpsc::channel::<Result<Bytes, String>>(RESPONSE_BODY_CHANNEL_CAPACITY);
        let response = IrohProxyResponse {
            status: parts.status,
            headers: parts.headers,
            body: ResponseBody(body_rx),
        };
        tokio::spawn(async move {
            let mut body = body;
            loop {
                match body.frame().await {
                    Some(Ok(frame)) => {
                        match frame.into_data() {
                            Ok(chunk) => {
                                if body_tx.send(Ok(chunk)).await.is_err() {
                                    return;
                                }
                            }
                            Err(_) => {
                                // Trailer frames are intentionally ignored for the v1 iroh proxy.
                            }
                        }
                    }
                    Some(Err(err)) => {
                        let _ = body_tx
                            .send(Err(format!("failed to read iroh response body: {err}")))
                            .await;
                        return;
                    }
                    None => return,
                }
            }
        });
        Ok(response)
    }

    fn parse_node_id(value: &str) -> Result<iroh::EndpointId> {
        if let Ok(parsed) = value.parse::<iroh::EndpointId>() {
            return Ok(parsed);
        }
        let decoded = base32::decode(base32::Alphabet::Rfc4648Lower { padding: false }, value)
            .ok_or_else(|| anyhow!("invalid iroh node id"))?;
        let bytes: [u8; 32] = decoded
            .try_into()
            .map_err(|_| anyhow!("invalid iroh node id length"))?;
        iroh::EndpointId::from_bytes(&bytes).map_err(|err| anyhow!("invalid iroh node id: {err}"))
    }

    fn load_or_create_secret_key(path: &Path) -> Result<[u8; 32]> {
        if path.exists() {
            tighten_secret_key_permissions(path)?;
            let raw = std::fs::read_to_string(path).map_err(|err| {
                anyhow!("failed to read iroh secret key {}: {err}", path.display())
            })?;
            return parse_secret_key(raw.trim());
        }

        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|err| {
                anyhow!(
                    "failed to create iroh secret key directory {}: {err}",
                    parent.display()
                )
            })?;
        }
        let key = iroh_http_core::generate_secret_key()
            .map_err(|err| anyhow!("failed to generate iroh secret key: {err}"))?;
        match write_secret_key(path, &key) {
            Ok(key) => Ok(key),
            Err(err)
                if err
                    .downcast_ref::<std::io::Error>()
                    .is_some_and(|err| err.kind() == std::io::ErrorKind::AlreadyExists) =>
            {
                load_or_create_secret_key(path)
            }
            Err(err) => Err(err),
        }
    }

    fn write_secret_key(path: &Path, key: &[u8; 32]) -> Result<[u8; 32]> {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;

        let encoded = hex_encode(key);
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .with_context(|| format!("failed to create iroh secret key {}", path.display()))?;
        file.write_all(format!("{encoded}\n").as_bytes())
            .map_err(|err| anyhow!("failed to write iroh secret key {}: {err}", path.display()))?;
        Ok(*key)
    }

    fn tighten_secret_key_permissions(path: &Path) -> Result<()> {
        use std::os::unix::fs::PermissionsExt;

        let metadata = std::fs::metadata(path).map_err(|err| {
            anyhow!(
                "failed to inspect iroh secret key permissions {}: {err}",
                path.display()
            )
        })?;
        let mode = metadata.permissions().mode();
        if mode & 0o077 != 0 {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).map_err(
                |err| {
                    anyhow!(
                        "failed to restrict iroh secret key permissions {}: {err}",
                        path.display()
                    )
                },
            )?;
        }
        Ok(())
    }

    fn parse_secret_key(value: &str) -> Result<[u8; 32]> {
        let value = value.trim();
        if value.len() != 64 {
            bail!("iroh secret key must be 64 lowercase hex characters");
        }
        let mut out = [0u8; 32];
        let bytes = value.as_bytes();
        for index in 0..32 {
            let high = hex_value(bytes[index * 2]).ok_or_else(|| anyhow!("invalid hex digit"))?;
            let low =
                hex_value(bytes[index * 2 + 1]).ok_or_else(|| anyhow!("invalid hex digit"))?;
            out[index] = (high << 4) | low;
        }
        Ok(out)
    }

    fn hex_encode(bytes: &[u8; 32]) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut out = String::with_capacity(64);
        for byte in bytes {
            out.push(HEX[(byte >> 4) as usize] as char);
            out.push(HEX[(byte & 0x0f) as usize] as char);
        }
        out
    }

    fn hex_value(byte: u8) -> Option<u8> {
        match byte {
            b'0'..=b'9' => Some(byte - b'0'),
            b'a'..=b'f' => Some(byte - b'a' + 10),
            b'A'..=b'F' => Some(byte - b'A' + 10),
            _ => None,
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::{
            os::unix::fs::PermissionsExt,
            time::{SystemTime, UNIX_EPOCH},
        };

        #[test]
        fn load_or_create_secret_key_creates_file_private_to_owner() {
            let dir = temp_dir("zeroserve-iroh-key-create");
            let path = dir.join("secret.key");
            let key = load_or_create_secret_key(&path).expect("create key");
            assert_eq!(key.len(), 32);
            let mode = std::fs::metadata(&path)
                .expect("metadata")
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o600);
            let _ = std::fs::remove_dir_all(dir);
        }

        #[test]
        fn load_or_create_secret_key_tightens_existing_file_permissions() {
            let dir = temp_dir("zeroserve-iroh-key-existing");
            let path = dir.join("secret.key");
            let key = [7u8; 32];
            std::fs::write(&path, format!("{}\n", hex_encode(&key))).expect("write key");
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644))
                .expect("loosen permissions");

            let loaded = load_or_create_secret_key(&path).expect("load key");
            assert_eq!(loaded, key);
            let mode = std::fs::metadata(&path)
                .expect("metadata")
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o600);
            let _ = std::fs::remove_dir_all(dir);
        }

        fn temp_dir(prefix: &str) -> std::path::PathBuf {
            let nonce = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("system clock after epoch")
                .as_nanos();
            let path =
                std::env::temp_dir().join(format!("{prefix}-{}-{nonce}", std::process::id()));
            std::fs::create_dir_all(&path).expect("create temp dir");
            path
        }
    }
}

#[cfg(not(feature = "iroh-proxy"))]
mod disabled {
    use super::*;

    pub(crate) fn init(_config: &StaticConfig) -> Result<()> {
        Ok(())
    }

    pub(crate) fn request_body_channel() -> (RequestBodySender, RequestBody) {
        (RequestBodySender, RequestBody)
    }

    pub(crate) async fn send_request_body_chunk(
        _sender: &mut RequestBodySender,
        _chunk: Bytes,
    ) -> Result<()> {
        Err(anyhow!(
            "iroh proxy transport requires building zeroserve with the `iroh-proxy` feature"
        ))
    }

    pub(crate) async fn send_request_body_error(_sender: &mut RequestBodySender, _error: String) {}

    pub(crate) struct IrohFetch;

    pub(crate) fn start_fetch(_request: IrohProxyRequest) -> Result<IrohFetch> {
        Err(anyhow!(
            "iroh proxy transport requires building zeroserve with the `iroh-proxy` feature"
        ))
    }

    impl IrohFetch {
        pub(crate) async fn response(self) -> Result<IrohProxyResponse> {
            Err(anyhow!(
                "iroh proxy transport requires building zeroserve with the `iroh-proxy` feature"
            ))
        }
    }

    pub(crate) async fn next_response_body_chunk(
        _body: &mut ResponseBody,
    ) -> Result<Option<Bytes>> {
        Err(anyhow!(
            "iroh proxy transport requires building zeroserve with the `iroh-proxy` feature"
        ))
    }
}

#[cfg(not(feature = "iroh-proxy"))]
pub(crate) use disabled::{
    init, next_response_body_chunk, request_body_channel, send_request_body_chunk,
    send_request_body_error, start_fetch,
};
#[cfg(feature = "iroh-proxy")]
pub(crate) use enabled::{
    init, next_response_body_chunk, request_body_channel, send_request_body_chunk,
    send_request_body_error, start_fetch,
};
