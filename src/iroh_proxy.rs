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
    pub(crate) upgraded: bool,
}

#[cfg(feature = "iroh-proxy")]
#[derive(Clone, Debug)]
pub(crate) struct RequestBodySender(futures::channel::mpsc::Sender<Result<Bytes, String>>);

#[cfg(feature = "iroh-proxy")]
#[derive(Debug)]
pub(crate) struct RequestBody(futures::channel::mpsc::Receiver<Result<Bytes, String>>);

#[cfg(feature = "iroh-proxy")]
#[derive(Debug)]
pub(crate) struct ResponseBody(futures::channel::mpsc::Receiver<Result<Bytes, String>>);

#[cfg(not(feature = "iroh-proxy"))]
#[derive(Clone, Debug)]
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
        path::Path,
        sync::{Arc, OnceLock, mpsc as std_mpsc},
        time::Duration,
    };

    use anyhow::{Context as AnyhowContext, bail};
    use futures::{
        SinkExt, StreamExt,
        channel::{mpsc, oneshot},
    };
    use iroh::{
        Endpoint, RelayMode, SecretKey,
        endpoint::{RecvStream, SendStream, presets},
    };
    use tokio::sync::Semaphore;

    const REQUEST_BODY_CHANNEL_CAPACITY: usize = 32;
    const RESPONSE_BODY_CHANNEL_CAPACITY: usize = 32;
    const COMMAND_CHANNEL_CAPACITY: usize = 1024;
    const MAX_CONCURRENT_FETCHES: usize = 256;
    const FETCH_TIMEOUT: Duration = Duration::from_secs(30);
    const MAX_RESPONSE_HEAD_BYTES: usize = 64 * 1024;
    const IROH_SECRET_KEY_ENV: &str = "ZEROSERVE_IROH_SECRET_KEY";
    const DUMBPIPE_ALPN: &[u8] = b"DUMBPIPEV0";
    const DUMBPIPE_HANDSHAKE: &[u8] = b"hello";

    static CLIENT: OnceLock<IrohProxyClient> = OnceLock::new();

    struct IrohProxyClient {
        tx: std_mpsc::SyncSender<Command>,
    }

    struct Command {
        request: IrohProxyRequest,
        tx: oneshot::Sender<Result<IrohProxyResponse, String>>,
    }

    pub(crate) fn init(config: &StaticConfig) -> Result<()> {
        if !config.iroh_proxy {
            return Ok(());
        }
        if CLIENT.get().is_some() {
            return Ok(());
        }

        let key = resolve_secret_key(config.iroh_secret_key.as_deref())?;
        let disable_networking = config.iroh_disable_networking;

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

                let endpoint = match runtime.block_on(bind_endpoint(key, disable_networking)) {
                    Ok(endpoint) => endpoint,
                    Err(err) => {
                        let _ = ready_tx.send(Err(format!("failed to bind iroh endpoint: {err}")));
                        return;
                    }
                };
                let node_id = endpoint.id().to_string();
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
        endpoint: &Endpoint,
        request: IrohProxyRequest,
    ) -> Result<IrohProxyResponse> {
        let mut addr = iroh::EndpointAddr::new(parse_node_id(&request.target.node_id)?);
        for direct_addr in &request.target.direct_addrs {
            addr = addr.with_ip_addr(*direct_addr);
        }

        let conn = tokio::time::timeout(FETCH_TIMEOUT, endpoint.connect(addr, DUMBPIPE_ALPN))
            .await
            .map_err(|_| anyhow!("iroh connect timed out"))?
            .map_err(|err| anyhow!("iroh connect failed: {err}"))?;
        let (send, recv) = tokio::time::timeout(FETCH_TIMEOUT, conn.open_bi())
            .await
            .map_err(|_| anyhow!("iroh stream open timed out"))?
            .map_err(|err| anyhow!("iroh stream open failed: {err}"))?;

        let _request_writer = start_http1_request(send, request)
            .await
            .map_err(|err| anyhow!("failed to write dumbpipe HTTP/1 request: {err}"))?;

        let mut reader = IrohResponseReader::new(recv);
        let (status, headers) = tokio::time::timeout(FETCH_TIMEOUT, reader.read_response_head())
            .await
            .map_err(|_| anyhow!("iroh response head timed out"))??;
        let content_length = response_content_length(&headers)?;
        let chunked = response_is_chunked(&headers);
        let upgraded = status == StatusCode::SWITCHING_PROTOCOLS;
        let has_body = upgraded || raw_status_allows_body(status);
        let (mut body_tx, body_rx) =
            mpsc::channel::<Result<Bytes, String>>(RESPONSE_BODY_CHANNEL_CAPACITY);
        let response = IrohProxyResponse {
            status,
            headers,
            body: ResponseBody(body_rx),
            upgraded,
        };
        tokio::spawn(async move {
            if !has_body {
                return;
            }
            let result = if upgraded {
                reader.stream_until_eof(&mut body_tx).await
            } else if chunked {
                reader.stream_chunked_body(&mut body_tx).await
            } else if let Some(len) = content_length {
                reader.stream_content_length_body(len, &mut body_tx).await
            } else {
                reader.stream_until_eof(&mut body_tx).await
            };
            if let Err(err) = result {
                let _ = body_tx
                    .send(Err(format!(
                        "failed to read dumbpipe HTTP/1 response body: {err}"
                    )))
                    .await;
            }
        });
        Ok(response)
    }

    async fn bind_endpoint(key: Option<SecretKey>, disable_networking: bool) -> Result<Endpoint> {
        let key = key.unwrap_or_else(SecretKey::generate);
        let mut builder = if disable_networking {
            Endpoint::builder(presets::Minimal)
                .clear_ip_transports()
                .bind_addr("127.0.0.1:0")
                .map_err(|err| anyhow!("failed to configure iroh loopback bind: {err}"))?
        } else {
            Endpoint::builder(presets::N0).relay_mode(RelayMode::Default)
        };
        builder = builder.secret_key(key);
        builder = builder.alpns(vec![DUMBPIPE_ALPN.to_vec()]);
        builder
            .bind()
            .await
            .map_err(|err| anyhow!("failed to bind iroh endpoint: {err}"))
    }

    async fn start_http1_request(
        mut send: SendStream,
        mut request: IrohProxyRequest,
    ) -> Result<tokio::task::JoinHandle<Result<()>>> {
        send.write_all(DUMBPIPE_HANDSHAKE)
            .await
            .map_err(|err| anyhow!("failed to write dumbpipe handshake: {err}"))?;

        let method_allows_body = !matches!(request.method.as_str(), "GET" | "HEAD");
        let chunk_request_body =
            method_allows_body && !request.headers.contains_key(::http::header::CONTENT_LENGTH);
        let mut head = Vec::with_capacity(1024);
        head.extend_from_slice(request.method.as_bytes());
        head.extend_from_slice(b" ");
        head.extend_from_slice(request.uri.as_bytes());
        head.extend_from_slice(b" HTTP/1.1\r\n");
        for (name, value) in request.headers.iter() {
            if chunk_request_body && name == ::http::header::TRANSFER_ENCODING {
                continue;
            }
            head.extend_from_slice(name.as_str().as_bytes());
            head.extend_from_slice(b": ");
            head.extend_from_slice(value.as_bytes());
            head.extend_from_slice(b"\r\n");
        }
        if chunk_request_body {
            head.extend_from_slice(b"transfer-encoding: chunked\r\n");
        }
        head.extend_from_slice(b"\r\n");
        send.write_all(&head)
            .await
            .map_err(|err| anyhow!("failed to write HTTP/1 request head: {err}"))?;

        Ok(tokio::spawn(async move {
            write_http1_request_body(&mut send, &mut request.body, chunk_request_body).await?;
            send.finish()
                .map_err(|err| anyhow!("failed to finish iroh request stream: {err}"))
        }))
    }

    async fn write_http1_request_body(
        send: &mut SendStream,
        body: &mut RequestBody,
        chunk_request_body: bool,
    ) -> Result<()> {
        while let Some(chunk) = body.0.next().await {
            let chunk = chunk.map_err(|err| anyhow!("request body stream failed: {err}"))?;
            if chunk_request_body {
                let prefix = format!("{:x}\r\n", chunk.len());
                send.write_all(prefix.as_bytes())
                    .await
                    .map_err(|err| anyhow!("failed to write request chunk size: {err}"))?;
                send.write_all(&chunk)
                    .await
                    .map_err(|err| anyhow!("failed to write request chunk: {err}"))?;
                send.write_all(b"\r\n")
                    .await
                    .map_err(|err| anyhow!("failed to finish request chunk: {err}"))?;
            } else {
                send.write_all(&chunk)
                    .await
                    .map_err(|err| anyhow!("failed to write request body: {err}"))?;
            }
        }
        if chunk_request_body {
            send.write_all(b"0\r\n\r\n")
                .await
                .map_err(|err| anyhow!("failed to finish chunked request body: {err}"))?;
        }
        Ok(())
    }

    struct IrohResponseReader {
        recv: RecvStream,
        buffer: Vec<u8>,
        eof: bool,
    }

    impl IrohResponseReader {
        fn new(recv: RecvStream) -> Self {
            Self {
                recv,
                buffer: Vec::new(),
                eof: false,
            }
        }

        async fn read_response_head(&mut self) -> Result<(StatusCode, HeaderMap)> {
            loop {
                if let Some(head_end) = find_subslice(&self.buffer, b"\r\n\r\n") {
                    let rest = self.buffer.split_off(head_end + 4);
                    let mut head = std::mem::replace(&mut self.buffer, rest);
                    head.truncate(head_end);
                    return parse_response_head(&head);
                }
                if self.buffer.len() >= MAX_RESPONSE_HEAD_BYTES {
                    bail!("iroh response head exceeded {MAX_RESPONSE_HEAD_BYTES} bytes");
                }
                if !self.read_more().await? {
                    bail!("iroh response ended before response head completed");
                }
            }
        }

        async fn stream_content_length_body(
            &mut self,
            mut remaining: usize,
            tx: &mut mpsc::Sender<Result<Bytes, String>>,
        ) -> Result<()> {
            while remaining > 0 {
                let chunk = self.next_body_chunk(remaining.min(16 * 1024)).await?;
                let Some(chunk) = chunk else {
                    bail!("iroh response ended before content-length body completed");
                };
                remaining = remaining.saturating_sub(chunk.len());
                if tx.send(Ok(chunk)).await.is_err() {
                    return Ok(());
                }
            }
            Ok(())
        }

        async fn stream_until_eof(
            &mut self,
            tx: &mut mpsc::Sender<Result<Bytes, String>>,
        ) -> Result<()> {
            while let Some(chunk) = self.next_body_chunk(16 * 1024).await? {
                if tx.send(Ok(chunk)).await.is_err() {
                    return Ok(());
                }
            }
            Ok(())
        }

        async fn stream_chunked_body(
            &mut self,
            tx: &mut mpsc::Sender<Result<Bytes, String>>,
        ) -> Result<()> {
            loop {
                let line = self.read_line(8192).await?;
                let size = parse_chunk_size(&line)?;
                if size == 0 {
                    self.consume_trailers().await?;
                    return Ok(());
                }
                let mut remaining = size;
                while remaining > 0 {
                    let chunk = self.next_body_chunk(remaining.min(16 * 1024)).await?;
                    let Some(chunk) = chunk else {
                        bail!("iroh response ended in chunk body");
                    };
                    remaining = remaining.saturating_sub(chunk.len());
                    if tx.send(Ok(chunk)).await.is_err() {
                        return Ok(());
                    }
                }
                self.consume_exact(2).await?;
            }
        }

        async fn read_line(&mut self, max_len: usize) -> Result<Vec<u8>> {
            loop {
                if let Some(end) = find_subslice(&self.buffer, b"\r\n") {
                    let rest = self.buffer.split_off(end + 2);
                    let mut line = std::mem::replace(&mut self.buffer, rest);
                    line.truncate(end);
                    return Ok(line);
                }
                if self.buffer.len() >= max_len {
                    bail!("HTTP/1 line exceeded {max_len} bytes");
                }
                if !self.read_more().await? {
                    bail!("iroh response ended in HTTP/1 line");
                }
            }
        }

        async fn consume_trailers(&mut self) -> Result<()> {
            loop {
                let line = self.read_line(MAX_RESPONSE_HEAD_BYTES).await?;
                if line.is_empty() {
                    return Ok(());
                }
                // Trailer fields are intentionally ignored for the v1 iroh proxy.
            }
        }

        async fn consume_exact(&mut self, mut len: usize) -> Result<()> {
            while len > 0 {
                if !self.buffer.is_empty() {
                    let take = len.min(self.buffer.len());
                    self.buffer.drain(..take);
                    len -= take;
                    continue;
                }
                if !self.read_more().await? {
                    bail!("iroh response ended early");
                }
            }
            Ok(())
        }

        async fn next_body_chunk(&mut self, max_len: usize) -> Result<Option<Bytes>> {
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
                Err(err) => Err(anyhow!("iroh stream read failed: {err}")),
            }
        }

        async fn read_more(&mut self) -> Result<bool> {
            if self.eof {
                return Ok(false);
            }
            let mut chunk = [0u8; 8192];
            match self.recv.read(&mut chunk).await {
                Ok(Some(n)) => {
                    self.buffer.extend_from_slice(&chunk[..n]);
                    Ok(true)
                }
                Ok(None) => {
                    self.eof = true;
                    Ok(false)
                }
                Err(err) => Err(anyhow!("iroh stream read failed: {err}")),
            }
        }
    }

    fn parse_response_head(head: &[u8]) -> Result<(StatusCode, HeaderMap)> {
        let head = std::str::from_utf8(head)
            .map_err(|err| anyhow!("iroh response head is not valid utf-8: {err}"))?;
        let mut lines = head.split("\r\n");
        let status_line = lines
            .next()
            .ok_or_else(|| anyhow!("iroh response missing status line"))?;
        let mut parts = status_line.splitn(3, ' ');
        let version = parts
            .next()
            .ok_or_else(|| anyhow!("iroh response missing HTTP version"))?;
        if !matches!(version, "HTTP/1.0" | "HTTP/1.1") {
            bail!("iroh response used unsupported HTTP version {version}");
        }
        let status = parts
            .next()
            .ok_or_else(|| anyhow!("iroh response missing status code"))?
            .parse::<u16>()
            .map_err(|err| anyhow!("iroh response status is invalid: {err}"))?;
        let status = StatusCode::from_u16(status)
            .map_err(|err| anyhow!("iroh response status is invalid: {err}"))?;
        let mut headers = HeaderMap::new();
        for line in lines {
            if line.is_empty() {
                continue;
            }
            let Some((name, value)) = line.split_once(':') else {
                bail!("iroh response contains malformed header line");
            };
            let name = ::http::header::HeaderName::from_bytes(name.trim().as_bytes())
                .map_err(|err| anyhow!("iroh response header name is invalid: {err}"))?;
            let value = ::http::HeaderValue::from_bytes(value.trim_start().as_bytes())
                .map_err(|err| anyhow!("iroh response header value is invalid: {err}"))?;
            headers.append(name, value);
        }
        Ok((status, headers))
    }

    fn response_content_length(headers: &HeaderMap) -> Result<Option<usize>> {
        let Some(value) = headers.get(::http::header::CONTENT_LENGTH) else {
            return Ok(None);
        };
        let value = value
            .to_str()
            .map_err(|err| anyhow!("iroh response content-length is invalid: {err}"))?;
        value
            .parse::<usize>()
            .map(Some)
            .map_err(|err| anyhow!("iroh response content-length is invalid: {err}"))
    }

    fn response_is_chunked(headers: &HeaderMap) -> bool {
        headers
            .get(::http::header::TRANSFER_ENCODING)
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| {
                value
                    .split(',')
                    .any(|part| part.trim().eq_ignore_ascii_case("chunked"))
            })
    }

    fn raw_status_allows_body(status: StatusCode) -> bool {
        !(status.is_informational()
            || matches!(status, StatusCode::NO_CONTENT | StatusCode::NOT_MODIFIED))
    }

    fn parse_chunk_size(line: &[u8]) -> Result<usize> {
        let line = std::str::from_utf8(line)
            .map_err(|err| anyhow!("chunk size line is not valid utf-8: {err}"))?;
        let size = line.split_once(';').map_or(line, |(size, _)| size).trim();
        usize::from_str_radix(size, 16).map_err(|err| anyhow!("chunk size line is invalid: {err}"))
    }

    fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
        haystack.windows(needle.len()).position(|w| w == needle)
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

    fn resolve_secret_key(path: Option<&Path>) -> Result<Option<SecretKey>> {
        let env_value = match std::env::var(IROH_SECRET_KEY_ENV) {
            Ok(value) => Some(value),
            Err(std::env::VarError::NotPresent) => None,
            Err(std::env::VarError::NotUnicode(_)) => {
                bail!("{IROH_SECRET_KEY_ENV} must be valid unicode")
            }
        };
        resolve_secret_key_with_env(path, env_value.as_deref())
    }

    fn resolve_secret_key_with_env(
        path: Option<&Path>,
        env_value: Option<&str>,
    ) -> Result<Option<SecretKey>> {
        if let Some(path) = path {
            return load_or_create_secret_key(path).map(Some);
        }
        env_value.map(parse_secret_key).transpose()
    }

    fn load_or_create_secret_key(path: &Path) -> Result<SecretKey> {
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
        let key = SecretKey::generate();
        match write_secret_key(path, &key.to_bytes()) {
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

    fn write_secret_key(path: &Path, key: &[u8; 32]) -> Result<SecretKey> {
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
        Ok(SecretKey::from_bytes(key))
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

    fn parse_secret_key(value: &str) -> Result<SecretKey> {
        let value = value.trim();
        if value.len() != 64 {
            bail!("iroh secret key must be 64 hex characters");
        }
        let mut out = [0u8; 32];
        let bytes = value.as_bytes();
        for index in 0..32 {
            let high = hex_value(bytes[index * 2]).ok_or_else(|| anyhow!("invalid hex digit"))?;
            let low =
                hex_value(bytes[index * 2 + 1]).ok_or_else(|| anyhow!("invalid hex digit"))?;
            out[index] = (high << 4) | low;
        }
        Ok(SecretKey::from_bytes(&out))
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
            assert_eq!(key.to_bytes().len(), 32);
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
            assert_eq!(loaded.to_bytes(), key);
            let mode = std::fs::metadata(&path)
                .expect("metadata")
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o600);
            let _ = std::fs::remove_dir_all(dir);
        }

        #[test]
        fn resolve_secret_key_uses_env_when_no_file_path_is_configured() {
            let key = [9u8; 32];
            let loaded =
                resolve_secret_key_with_env(None, Some(&hex_encode(&key))).expect("load env key");
            assert_eq!(loaded.expect("key exists").to_bytes(), key);
        }

        #[test]
        fn resolve_secret_key_prefers_file_path_over_env() {
            let dir = temp_dir("zeroserve-iroh-key-precedence");
            let path = dir.join("secret.key");
            let file_key = [11u8; 32];
            let env_key = [12u8; 32];
            std::fs::write(&path, format!("{}\n", hex_encode(&file_key))).expect("write key");

            let loaded = resolve_secret_key_with_env(Some(&path), Some(&hex_encode(&env_key)))
                .expect("load key")
                .expect("key exists");
            assert_eq!(loaded.to_bytes(), file_key);
            let _ = std::fs::remove_dir_all(dir);
        }

        #[test]
        fn resolve_secret_key_returns_none_for_ephemeral_default() {
            let loaded = resolve_secret_key_with_env(None, None).expect("resolve key");
            assert!(loaded.is_none());
        }

        #[test]
        fn parse_secret_key_rejects_non_hex_encodings() {
            assert!(parse_secret_key(&"a".repeat(43)).is_err());
            assert!(parse_secret_key(&"z".repeat(64)).is_err());
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
