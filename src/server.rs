use std::{
    cell::{Cell, RefCell},
    collections::HashMap,
    io::{ErrorKind, Write as _},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs},
    os::fd::AsRawFd,
    path::{Path, PathBuf},
    rc::Rc,
    sync::Arc,
    time::{Duration, Instant},
};

use ::http::{
    Method, StatusCode, Uri,
    header::{HeaderName, HeaderValue},
};
use anyhow::{Context, Result, anyhow};
use bytes::Bytes;
use futures::{
    channel::oneshot,
    future::{self, FutureExt},
};
use monoio::{
    BufResult,
    buf::SliceMut,
    io::{
        AsyncReadRent, AsyncReadRentExt, AsyncWriteRent, AsyncWriteRentExt, IntoPollIo, Split,
        Splitable,
    },
    net::{TcpListener, TcpStream, UnixStream},
};
use monoio_compat::StreamWrapper;
use url::Url;

use crate::{
    boringtls::{AcceptOutcome, BoringStream},
    config::StaticConfig,
    http::h1::{self, HttpError, Request, RequestHead, StreamHint},
    hupwatch::HupWatcher,
    iroh_proxy::{IrohProxyRequest, IrohTarget},
    logging::async_log,
    pool::{self, PoolKey, PooledConnection},
    script::{
        BodyReadError, BodySource, ConnectionInfo, HeaderChange, RequestId, ScriptOutcome,
        ScriptRequest, ScriptResponse, ScriptRuntime, header_pattern_matches,
    },
    shared::{SharedState, read_tar_entry, stream_fs_file, stream_tar_entry},
    site::{NormalizedPath, guess_mime, normalize_request_path},
    thread_pool::DNS_TP,
};

type HttpBody = h1::Body;

const H2_PREFACE: &[u8; 24] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
const PROXY_WRITE_BATCH_SIZE: usize = 64 * 1024;

mod caddy;

use caddy::ResponseHookState;

use std::cell::RefCell as StdRefCell;

type H1BodyState<R> = Rc<StdRefCell<Option<(h1::H1Connection<R>, h1::Body)>>>;

#[derive(Clone, Copy)]
struct H1SendOutcome {
    keep_client: bool,
    status: u16,
}

fn create_h1_body_source<R: AsyncReadRent + 'static>(
    reader: h1::H1Connection<R>,
    body: h1::Body,
    max_buffered_body_size: usize,
) -> (BodySource, H1BodyState<R>) {
    let state: H1BodyState<R> = Rc::new(StdRefCell::new(Some((reader, body))));
    let state_clone = state.clone();

    let max_size = Rc::new(Cell::new(max_buffered_body_size));
    let max_size_for_reader = max_size.clone();
    let body_source = BodySource::new(
        Box::pin(async move {
            let (mut reader, mut body) = state_clone
                .borrow_mut()
                .take()
                .ok_or(BodyReadError::ReadError)?;

            let mut buf = Vec::new();
            loop {
                match body.next_data(&mut reader).await {
                    Some(Ok(chunk)) => {
                        if buf.len() + chunk.len() > max_size_for_reader.get() {
                            *state_clone.borrow_mut() = Some((reader, body));
                            return Err(BodyReadError::TooLarge);
                        }
                        buf.extend_from_slice(&chunk);
                    }
                    Some(Err(_)) => {
                        *state_clone.borrow_mut() = Some((reader, body));
                        return Err(BodyReadError::ReadError);
                    }
                    None => break,
                }
            }

            *state_clone.borrow_mut() = Some((reader, body));
            Ok(buf)
        }),
        max_size,
    );

    (body_source, state)
}

type H2BodyState = Rc<StdRefCell<Option<h2::RecvStream>>>;

fn create_h2_body_source(
    body: h2::RecvStream,
    max_buffered_body_size: usize,
) -> (BodySource, H2BodyState) {
    let state: H2BodyState = Rc::new(StdRefCell::new(Some(body)));
    let state_clone = state.clone();

    let max_size = Rc::new(Cell::new(max_buffered_body_size));
    let max_size_for_reader = max_size.clone();
    let body_source = BodySource::new(
        Box::pin(async move {
            let mut body = state_clone
                .borrow_mut()
                .take()
                .ok_or(BodyReadError::ReadError)?;

            let mut buf = Vec::new();
            while let Some(chunk) = body.data().await {
                let chunk = chunk.map_err(|_| BodyReadError::ReadError)?;
                if buf.len() + chunk.len() > max_size_for_reader.get() {
                    *state_clone.borrow_mut() = Some(body);
                    return Err(BodyReadError::TooLarge);
                }
                buf.extend_from_slice(&chunk);
                body.flow_control()
                    .release_capacity(chunk.len())
                    .map_err(|_| BodyReadError::ReadError)?;
            }

            // Body fully consumed, no need to restore
            Ok(buf)
        }),
        max_size,
    );

    (body_source, state)
}

enum StaticBody {
    Empty,
    Bytes(Vec<u8>),
    File {
        entry: Arc<crate::site::TarEntry>,
        range: Option<ByteRange>,
    },
    FsFile {
        path: PathBuf,
        size: u64,
        range: Option<ByteRange>,
    },
}

#[derive(Clone, Copy)]
struct ByteRange {
    start: u64,
    len: u64,
}

struct StaticResponse {
    status: StatusCode,
    headers: ::http::HeaderMap,
    body: StaticBody,
    head_only: bool,
    site: Arc<crate::site::Site>,
}

pub async fn amain(
    shared: Arc<SharedState>,
    script_runtime: Rc<ScriptRuntime>,
    hup: Arc<HupWatcher>,
    http_listener: std::net::TcpListener,
    tls_listener: Option<std::net::TcpListener>,
) -> Result<()> {
    if let Some(tls_listener) = tls_listener {
        let tls_state = shared.clone();
        let script_runtime = script_runtime.clone();
        let hup = hup.clone();
        monoio::spawn(async move {
            if let Err(err) = run_tls_listener(tls_state, script_runtime, hup, tls_listener).await {
                eprintln!("TLS listener stopped: {err:?}");
            }
        });
    }

    run_http_listener(shared, script_runtime, hup, http_listener).await
}

async fn run_http_listener(
    shared: Arc<SharedState>,
    script_runtime: Rc<ScriptRuntime>,
    hup: Arc<HupWatcher>,
    http_listener: std::net::TcpListener,
) -> Result<()> {
    let listener = TcpListener::from_std(http_listener)?;
    let local = listener.local_addr()?;
    loop {
        let (stream, addr) = listener.accept().await?;
        if stream.set_nodelay(true).is_err() {
            continue;
        }
        let conn_hup = hup.wait(stream.as_raw_fd())?;
        let state = shared.clone();
        let script_runtime = script_runtime.clone();
        monoio::spawn(async move {
            let mut stream = stream;
            let peer = if state.config.enable_proxy_protocol {
                match read_proxy_protocol_peer(&mut stream, addr, &state.config).await {
                    Ok(peer) => peer,
                    Err(err) => {
                        eprintln!(
                            "dropping http connection {addr} due to invalid PROXY header: {err}"
                        );
                        return;
                    }
                }
            } else {
                addr
            };
            if let Err(err) =
                handle_http_connection(conn_hup, stream, peer, local, state, script_runtime).await
            {
                async_log(
                    format!(
                        "[listener] connection {} over http closed with error: {err:?}",
                        peer
                    )
                    .into_bytes(),
                )
                .await;
            }
        });
    }
}

async fn handle_http_connection(
    mut hup: impl Future<Output = ()> + Unpin + 'static,
    stream: TcpStream,
    peer: std::net::SocketAddr,
    local: std::net::SocketAddr,
    shared: Arc<SharedState>,
    script_runtime: Rc<ScriptRuntime>,
) -> Result<()> {
    let conn = ConnectionInfo::default();
    if is_h2c_preface(&stream).await? {
        return handle_h2c_connection(hup, stream, peer, local, shared, script_runtime, conn).await;
    }

    handle_h1_connection(
        &mut hup,
        stream,
        peer,
        local,
        shared,
        Scheme::Http,
        script_runtime,
        conn,
    )
    .await
}

async fn run_tls_listener(
    shared: Arc<SharedState>,
    script_runtime: Rc<ScriptRuntime>,
    hup: Arc<HupWatcher>,
    tls_listener: std::net::TcpListener,
) -> Result<()> {
    let listener = TcpListener::from_std(tls_listener)?;
    let local = listener.local_addr()?;
    loop {
        let (stream, peer) = listener.accept().await?;
        if stream.set_nodelay(true).is_err() {
            continue;
        }
        let mut conn_hup = hup.wait(stream.as_raw_fd())?;
        let state = shared.clone();
        let script_runtime = script_runtime.clone();
        monoio::spawn(async move {
            let mut stream = stream;
            let reported_peer = if state.config.enable_proxy_protocol {
                match read_proxy_protocol_peer(&mut stream, peer, &state.config).await {
                    Ok(addr) => addr,
                    Err(err) => {
                        eprintln!(
                            "dropping TLS connection {peer} due to invalid PROXY header: {err}"
                        );
                        return;
                    }
                }
            } else {
                peer
            };
            let tls_state = match state.tls.load_full() {
                Some(runtime) => runtime,
                None => {
                    eprintln!("dropping TLS connection {reported_peer} due to missing TLS config");
                    return;
                }
            };
            // BoringSSL terminates ECH natively (inner-ClientHello decryption,
            // ServerHello acceptance signal, retry_configs on rejection), so the
            // listener just does a normal accept and reads the negotiated state.
            // In the `--caddy` flow the handshake pauses at the ClientHello so
            // the site's eBPF TLS section can select the certificate by path;
            // the runtime resolves it through its in-memory certificate cache.
            let accepted = if tls_state.script_certificates {
                let selector_runtime = script_runtime.clone();
                let site = state.site.load_full();
                let tls_runtime = tls_state.clone();
                tls_state
                    .acceptor
                    .accept_with_cert_selector(stream, move |sni| async move {
                        selector_runtime
                            .select_tls_certificate(site, tls_runtime, sni, reported_peer, local)
                            .await
                    })
                    .await
            } else {
                tls_state.acceptor.accept(stream).await
            };
            match accepted {
                Ok(AcceptOutcome::Relay {
                    target,
                    prelude,
                    io,
                }) => {
                    // ECH "don't stick out" fallback: a client reached one of our
                    // ECH public names without a decryptable inner ClientHello,
                    // and we hold no certificate for that name. Transparently
                    // relay the raw TLS connection to the real public-name server.
                    if let Err(err) = relay_tls_connection(io, &target, prelude).await {
                        async_log(
                            format!(
                                "[listener] ECH relay of {reported_peer} to {target:?} failed: {err:?}\n"
                            )
                            .into_bytes(),
                        )
                        .await;
                    }
                }
                Ok(AcceptOutcome::Stream(tls_stream)) => {
                    let alpn = tls_stream
                        .alpn_protocol()
                        .and_then(|p| String::from_utf8(p).ok());
                    let is_h2 = matches!(alpn.as_deref(), Some("h2"));
                    let ech_ok = tls_stream.ech_accepted();
                    let ech_accepted = if tls_state.ech_enabled {
                        Some(ech_ok)
                    } else {
                        None
                    };
                    // Prefer the actual outer SNI the client sent (recovered
                    // from the wire ClientHello); fall back to the configured
                    // public name only when it is unambiguous and parsing failed.
                    let outer_sni = if ech_ok {
                        tls_stream
                            .outer_server_name()
                            .or_else(|| tls_state.ech_public_name.clone())
                    } else {
                        None
                    };
                    let conn =
                        caddy::tls_connection_info(&tls_stream, alpn, outer_sni, ech_accepted);
                    if is_h2 {
                        let io = StreamWrapper::new(tls_stream);
                        if let Err(err) = handle_h2_connection(
                            conn_hup,
                            io,
                            reported_peer,
                            local,
                            state,
                            script_runtime,
                            Scheme::Https,
                            conn,
                        )
                        .await
                        {
                            async_log(
                                format!(
                                    "[listener] connection {} over h2/tls closed with error: {err:?}",
                                    reported_peer
                                )
                                .into_bytes(),
                            )
                            .await;
                        }
                    } else if let Err(err) = handle_h1_connection_unsplit_fast(
                        &mut conn_hup,
                        tls_stream,
                        reported_peer,
                        local,
                        state,
                        Scheme::Https,
                        script_runtime,
                        conn,
                    )
                    .await
                    {
                        async_log(
                            format!(
                                "[listener] connection {} over tls closed with error: {err:?}",
                                reported_peer
                            )
                            .into_bytes(),
                        )
                        .await;
                    }
                }
                Err(err) => log_tls_error(reported_peer, &err),
            }
        });
    }
}

fn log_tls_error(peer: std::net::SocketAddr, error: &anyhow::Error) {
    // Suppress the routine peer-disconnect noise; surface real failures.
    for cause in error.chain() {
        if let Some(io_err) = cause.downcast_ref::<std::io::Error>() {
            if io_err.kind() == ErrorKind::ConnectionReset
                || io_err.kind() == ErrorKind::UnexpectedEof
            {
                return;
            }
        }
    }
    eprintln!("TLS handshake with {peer} failed: {error:?}");
}

/// Transparently relay a raw TCP connection to the real public-name server on
/// port 443 (the ECH "don't stick out" fallback). The buffered `prelude` — the
/// ClientHello bytes already read off the wire during the aborted handshake — is
/// replayed to the upstream first, then both directions are spliced until either
/// side closes. The relay is byte-for-byte, so the client's connection is
/// indistinguishable from a normal direct connection to the public name.
async fn relay_tls_connection(client: TcpStream, target: &str, prelude: Vec<u8>) -> Result<()> {
    const RELAY_PORT: u16 = 443;

    // Resolve the public name off the runtime thread (blocking getaddrinfo).
    let host = target.to_string();
    let (tx, rx) = oneshot::channel();
    DNS_TP.spawn(move || {
        let resolved = (host.as_str(), RELAY_PORT)
            .to_socket_addrs()
            .map(|it| it.collect::<Vec<_>>());
        let _ = tx.send(resolved);
    });
    let addrs = rx
        .await
        .map_err(|_| anyhow!("DNS resolver dropped"))?
        .with_context(|| format!("resolving ECH relay target {target:?}"))?;
    if addrs.is_empty() {
        return Err(anyhow!(
            "ECH relay target {target:?} resolved to no addresses"
        ));
    }

    let mut upstream = TcpStream::connect(&addrs[..])
        .await
        .with_context(|| format!("connecting to ECH relay target {target:?}"))?;
    let _ = upstream.set_nodelay(true);

    // Replay the bytes the client already sent (the ClientHello) before splicing.
    if !prelude.is_empty() {
        let (res, _) = upstream.write_all(prelude).await;
        res.context("replaying buffered ClientHello to ECH relay target")?;
    }

    let (client_r, client_w) = client.into_split();
    let (upstream_r, upstream_w) = upstream.into_split();
    monoio::join!(
        relay_copy(client_r, upstream_w),
        relay_copy(upstream_r, client_w)
    );
    Ok(())
}

/// Copy bytes from `reader` to `writer` until EOF or error, then shut the
/// writer down. Errors are swallowed: one relay half closing is routine.
async fn relay_copy<R, W>(mut reader: R, mut writer: W)
where
    R: AsyncReadRent,
    W: AsyncWriteRent,
{
    // Scope the `IoBuf` trait locally so its `slice` method doesn't shadow
    // `bytes::Bytes::slice` elsewhere in this module.
    use monoio::buf::IoBuf;
    let mut buf = vec![0u8; 16 * 1024];
    loop {
        let (res, b) = reader.read(buf).await;
        buf = b;
        let n = match res {
            Ok(0) | Err(_) => break,
            Ok(n) => n,
        };
        let (res, slice) = writer.write_all(buf.slice(0..n)).await;
        buf = slice.into_inner();
        if res.is_err() {
            break;
        }
    }
    let _ = writer.shutdown().await;
}

async fn is_h2c_preface(stream: &TcpStream) -> std::io::Result<bool> {
    let mut buf = [0u8; 24];
    loop {
        stream.readable(false).await?;
        let n = unsafe {
            libc::recv(
                stream.as_raw_fd(),
                buf.as_mut_ptr().cast(),
                buf.len(),
                libc::MSG_PEEK,
            )
        };
        if n == 0 {
            return Ok(false);
        }
        if n < 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() == ErrorKind::Interrupted || err.kind() == ErrorKind::WouldBlock {
                continue;
            }
            return Err(err);
        }
        let n = n as usize;
        let slice = &buf[..n];
        if !H2_PREFACE.starts_with(slice) {
            return Ok(false);
        }
        if n >= H2_PREFACE.len() {
            return Ok(true);
        }
    }
}

async fn handle_h1_connection<IO, H>(
    hup: &mut H,
    io: IO,
    peer: std::net::SocketAddr,
    local: std::net::SocketAddr,
    shared: Arc<SharedState>,
    scheme: Scheme,
    script_runtime: Rc<ScriptRuntime>,
    connection: ConnectionInfo,
) -> Result<()>
where
    IO: AsyncReadRent + AsyncWriteRent + Split + 'static,
    H: Future<Output = ()> + Unpin + 'static,
{
    let (r, mut w) = io.into_split();
    let reader = h1::H1Connection::new(r);
    handle_h1_split_loop(
        hup,
        reader,
        &mut w,
        peer,
        local,
        shared,
        scheme,
        script_runtime,
        connection,
    )
    .await
}

async fn handle_h1_connection_unsplit_fast<IO, H>(
    hup: &mut H,
    io: IO,
    peer: std::net::SocketAddr,
    local: std::net::SocketAddr,
    shared: Arc<SharedState>,
    scheme: Scheme,
    script_runtime: Rc<ScriptRuntime>,
    connection: ConnectionInfo,
) -> Result<()>
where
    IO: AsyncReadRent + AsyncWriteRent + Split + 'static,
    H: Future<Output = ()> + Unpin + 'static,
{
    let mut conn = h1::H1Connection::new(io);
    loop {
        let result = conn.next_request().await;
        let request = match result {
            Ok(Some(request)) => request,
            Ok(None) => break,
            Err(err) => {
                if matches!(err, HttpError::Io(ref x) if x.kind() == ErrorKind::ConnectionReset
                    || x.kind() == ErrorKind::UnexpectedEof)
                    || matches!(err, HttpError::UnexpectedEof)
                {
                    break;
                }
                eprintln!(
                    "{} request from {peer} could not be parsed: {err}",
                    scheme.as_str()
                );
                break;
            }
        };

        match try_handle_simple_h1_proxy_unsplit(
            request,
            &mut conn,
            &shared,
            &script_runtime,
            peer,
            local,
            scheme,
            hup,
            &connection,
        )
        .await
        {
            SimpleH1ProxyResult::Handled(continue_conn) => {
                if !continue_conn {
                    break;
                }
            }
            SimpleH1ProxyResult::Fallback(request) => {
                let Some((io, leftover)) = conn.take_io() else {
                    break;
                };
                let (r, mut w) = io.into_split();
                let reader = h1::H1Connection::with_buffer(r, leftover);
                let (continue_conn, reader) = handle_request(
                    request,
                    reader,
                    &shared,
                    &script_runtime,
                    peer,
                    local,
                    scheme,
                    &mut w,
                    hup,
                    &connection,
                )
                .await;
                if continue_conn {
                    handle_h1_split_loop(
                        hup,
                        reader,
                        &mut w,
                        peer,
                        local,
                        shared,
                        scheme,
                        script_runtime,
                        connection,
                    )
                    .await?;
                }
                break;
            }
        }
    }
    Ok(())
}

async fn handle_h1_split_loop<R, W, H>(
    hup: &mut H,
    mut reader: h1::H1Connection<R>,
    w: &mut W,
    peer: std::net::SocketAddr,
    local: std::net::SocketAddr,
    shared: Arc<SharedState>,
    scheme: Scheme,
    script_runtime: Rc<ScriptRuntime>,
    connection: ConnectionInfo,
) -> Result<()>
where
    R: AsyncReadRent + 'static,
    W: AsyncWriteRent,
    H: Future<Output = ()> + Unpin + 'static,
{
    loop {
        let result = reader.next_request().await;
        let request = match result {
            Ok(Some(request)) => request,
            Ok(None) => break,
            Err(err) => {
                if matches!(err, HttpError::Io(ref x) if x.kind() == ErrorKind::ConnectionReset
                    || x.kind() == ErrorKind::UnexpectedEof)
                    || matches!(err, HttpError::UnexpectedEof)
                {
                    break;
                }
                eprintln!(
                    "{} request from {peer} could not be parsed: {err}",
                    scheme.as_str()
                );
                break;
            }
        };

        let (continue_conn, returned_reader) = handle_request(
            request,
            reader,
            &shared,
            &script_runtime,
            peer,
            local,
            scheme,
            w,
            hup,
            &connection,
        )
        .await;
        reader = returned_reader;
        if !continue_conn {
            break;
        }
    }
    Ok(())
}

enum SimpleH1ProxyResult {
    Handled(bool),
    Fallback(Request),
}

async fn try_handle_simple_h1_proxy_unsplit<IO, H>(
    req: Request,
    conn: &mut h1::H1Connection<IO>,
    shared: &Arc<SharedState>,
    script_runtime: &Rc<ScriptRuntime>,
    peer: std::net::SocketAddr,
    local: std::net::SocketAddr,
    scheme: Scheme,
    interrupt: &mut H,
    connection: &ConnectionInfo,
) -> SimpleH1ProxyResult
where
    IO: AsyncReadRent + AsyncWriteRent,
    H: Future<Output = ()> + Unpin,
{
    let (mut head, body) = req.into_parts();
    if !matches!(body.hint(), StreamHint::None) {
        return SimpleH1ProxyResult::Fallback(Request::from_parts(head, body));
    }
    if !shared.config.disable_request_logging
        || !shared.config.validate_hostnames.is_empty()
        || !matches!(head.method, Method::GET | Method::HEAD)
        || request_authority_sni_mismatch(&head, connection)
    {
        return SimpleH1ProxyResult::Fallback(Request::from_parts(head, h1::Body::None));
    }

    head.tls = matches!(scheme, Scheme::Https);
    let head_only = head.method == Method::HEAD;
    let original_head = head.clone();
    let request_id = RequestId::new();
    let Some(normalized_path) = normalize_request_path(head.uri.path()) else {
        return SimpleH1ProxyResult::Fallback(Request::from_parts(original_head, h1::Body::None));
    };
    let script_request = build_script_request(
        request_id.clone(),
        &head,
        peer,
        local,
        scheme,
        &normalized_path,
        Vec::new(),
        connection.clone(),
    );
    let body_source = BodySource::empty();
    let script_outcome = monoio::select! {
        x = script_runtime.run_request(shared.site.load_full(), script_request, body_source) => x,
        _ = &mut *interrupt => {
            async_log(format!("[handle] {}: interrupted\n", request_id).into_bytes()).await;
            return SimpleH1ProxyResult::Handled(false);
        }
    };
    let script_outcome = match script_outcome {
        Ok(outcome) => outcome,
        Err(err) => {
            async_log(format!("[handle] {}: script runtime: {:?}\n", request_id, err).into_bytes())
                .await;
            ScriptOutcome::from_request(build_script_request(
                request_id.clone(),
                &head,
                peer,
                local,
                scheme,
                &normalized_path,
                Vec::new(),
                connection.clone(),
            ))
        }
    };

    if let Err(err) = apply_script_request(&mut head, &script_outcome.request) {
        async_log(
            format!(
                "[handle] {}: script request update: {:?}\n",
                request_id, err
            )
            .into_bytes(),
        )
        .await;
        return SimpleH1ProxyResult::Fallback(Request::from_parts(original_head, h1::Body::None));
    }
    if script_outcome.request.uri_changed()
        && normalized_script_request_path(&script_outcome.request).is_none()
    {
        return SimpleH1ProxyResult::Fallback(Request::from_parts(original_head, h1::Body::None));
    }

    let hook_state = if script_outcome.response_hooks.is_empty() {
        None
    } else {
        Some(ResponseHookState::from_outcome(
            script_runtime,
            shared,
            &script_outcome,
        ))
    };
    let encode_state = script_outcome.encode.clone().map(|config| {
        crate::helpers::compress::EncodeState::from_request_headers(config, &head.headers)
    });
    if script_outcome.abort {
        return SimpleH1ProxyResult::Handled(false);
    }
    let Some(proxy_url) = script_outcome.reverse_proxy.as_deref() else {
        return SimpleH1ProxyResult::Fallback(Request::from_parts(original_head, h1::Body::None));
    };
    let simple_target = cached_backend_target(proxy_url);
    if caddy::has_error_routes(&script_outcome)
        || matches!(
            simple_target.as_ref().map(|target| target.scheme),
            Ok(BackendScheme::Iroh)
        )
        || !can_use_simple_proxy_fast_path(
            &head,
            &h1::Body::None,
            h1::is_websocket_upgrade_request(&head),
            Some(&script_outcome.early_response_headers),
            &script_outcome.metadata,
            hook_state.as_ref(),
            script_outcome.request.proxy_method(),
            script_outcome.request.proxy_uri(),
            script_outcome.request.proxy_headers(),
            encode_state.as_ref(),
        )
    {
        return SimpleH1ProxyResult::Fallback(Request::from_parts(original_head, h1::Body::None));
    }

    let res = match conn.io_mut() {
        Ok(w) => {
            reverse_proxy_simple_request(
                proxy_url,
                &head,
                w,
                head_only,
                peer,
                scheme,
                caddy_uses_default_forwarded(
                    &script_outcome.metadata,
                    hook_state.as_ref(),
                    script_outcome.caddy_default_forwarded,
                ),
            )
            .await
        }
        Err(err) => Err(anyhow!("client connection missing io: {err}")),
    };
    match res {
        Ok(proxy_outcome) => {
            log_caddy_access(
                shared,
                &head,
                peer,
                scheme,
                proxy_outcome.send.status,
                &script_outcome.metadata,
            )
            .await;
            SimpleH1ProxyResult::Handled(proxy_outcome.send.keep_client)
        }
        Err(err) => {
            async_log(format!("[handle] {}: reverse proxy: {:?}\n", request_id, err).into_bytes())
                .await;
            let send_outcome = match conn.io_mut() {
                Ok(w) => {
                    send_fixed(
                        w,
                        bad_gateway(),
                        Some(&script_outcome.early_response_headers),
                        &script_outcome.metadata,
                        hook_state.as_ref(),
                    )
                    .await
                }
                Err(_) => H1SendOutcome {
                    keep_client: false,
                    status: StatusCode::BAD_GATEWAY.as_u16(),
                },
            };
            log_caddy_access(
                shared,
                &head,
                peer,
                scheme,
                send_outcome.status,
                &script_outcome.metadata,
            )
            .await;
            SimpleH1ProxyResult::Handled(send_outcome.keep_client)
        }
    }
}

async fn handle_h2c_connection(
    hup: impl Future<Output = ()> + Unpin + 'static,
    stream: TcpStream,
    peer: std::net::SocketAddr,
    local: std::net::SocketAddr,
    shared: Arc<SharedState>,
    script_runtime: Rc<ScriptRuntime>,
    connection: ConnectionInfo,
) -> Result<()> {
    let io = stream
        .into_poll_io()
        .map_err(|err| anyhow!("failed to enable h2 poll-io: {err}"))?;
    handle_h2_connection(
        hup,
        io,
        peer,
        local,
        shared,
        script_runtime,
        Scheme::Http,
        connection,
    )
    .await
}

async fn handle_h2_connection<IO>(
    hup: impl Future<Output = ()> + Unpin + 'static,
    io: IO,
    peer: std::net::SocketAddr,
    local: std::net::SocketAddr,
    shared: Arc<SharedState>,
    script_runtime: Rc<ScriptRuntime>,
    scheme: Scheme,
    conn_info: ConnectionInfo,
) -> Result<()>
where
    IO: monoio::io::poll_io::AsyncRead + monoio::io::poll_io::AsyncWrite + Unpin + 'static,
{
    let mut connection = h2::server::handshake(io)
        .await
        .map_err(|err| anyhow!("h2 handshake failed: {err}"))?;
    let (_local_hup_tx, local_hup_rx) = oneshot::channel::<()>();
    let hup = futures::future::select(local_hup_rx, hup)
        .map(|_| ())
        .shared();

    loop {
        let mut hup_wait = hup.clone();
        let next = monoio::select! {
            res = connection.accept() => res,
            _ = &mut hup_wait => {
                return Ok(());
            }
        };

        let Some(result) = next else {
            break;
        };
        let (request, respond) = match result {
            Ok(value) => value,
            Err(err) => {
                eprintln!("h2 connection error from {peer}: {err:?}");
                break;
            }
        };
        let state = shared.clone();
        let script_runtime = script_runtime.clone();
        let hup = hup.clone();
        let scheme = scheme;
        let conn_for_request = conn_info.clone();
        monoio::spawn(async move {
            if let Err(err) = handle_h2_request(
                request,
                respond,
                state,
                script_runtime,
                peer,
                local,
                scheme,
                hup,
                conn_for_request,
            )
            .await
            {
                async_log(
                    format!("[h2] stream {} closed with error: {err:?}\n", peer).into_bytes(),
                )
                .await;
            }
        });
    }
    Ok(())
}

async fn handle_request<R: AsyncReadRent + 'static>(
    req: Request,
    reader: h1::H1Connection<R>,
    shared: &Arc<SharedState>,
    script_runtime: &Rc<ScriptRuntime>,
    peer: std::net::SocketAddr,
    local: std::net::SocketAddr,
    scheme: Scheme,
    w: &mut impl AsyncWriteRent,
    interrupt: &mut (impl Future<Output = ()> + Unpin),
    connection: &ConnectionInfo,
) -> (bool, h1::H1Connection<R>) {
    let request_id = RequestId::new();
    let (mut head, body) = req.into_parts();
    head.tls = matches!(scheme, Scheme::Https);
    if !shared.config.disable_request_logging {
        log_request(&request_id, peer, scheme, &head.method, &head.uri).await;
    }
    let head_only = head.method == Method::HEAD;
    let transfer_encodings = if body.is_chunked() {
        vec!["chunked".to_string()]
    } else {
        Vec::new()
    };

    let (body_source, body_state) =
        create_h1_body_source(reader, body, shared.config.max_buffered_body_size);

    if request_authority_sni_mismatch(&head, connection) {
        let (mut reader, mut body) = body_state.borrow_mut().take().unwrap();
        drain_payload(&mut reader, &mut body).await;
        send_fixed(w, misdirected_request(), None, &HashMap::new(), None).await;
        return (true, reader);
    }

    // Validate hostname if configured
    if !shared.config.validate_hostnames.is_empty() {
        let host = head
            .headers
            .get(::http::header::HOST)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        if !is_valid_hostname(host, &shared.config.validate_hostnames) {
            let (mut reader, mut body) = body_state.borrow_mut().take().unwrap();
            drain_payload(&mut reader, &mut body).await;
            send_fixed(w, misdirected_request(), None, &HashMap::new(), None).await;
            return (true, reader);
        }
    }

    // Normalize the path once for the entire request pipeline
    let Some(normalized_path) = normalize_request_path(head.uri.path()) else {
        // Invalid path (e.g., path traversal escape attempt)
        let (mut reader, mut body) = body_state.borrow_mut().take().unwrap();
        drain_payload(&mut reader, &mut body).await;
        send_fixed(w, bad_request(), None, &HashMap::new(), None).await;
        return (true, reader);
    };

    let script_request = build_script_request(
        request_id.clone(),
        &head,
        peer,
        local,
        scheme,
        &normalized_path,
        transfer_encodings,
        connection.clone(),
    );
    let script_request_fallback = script_request.clone();
    let script_outcome = monoio::select! {
        x = script_runtime.run_request(shared.site.load_full(), script_request, body_source.clone()) => x,
        _ = &mut *interrupt => {
          async_log(format!("[handle] {}: interrupted\n", request_id).into_bytes()).await;
          let (reader, _) = body_state.borrow_mut().take().unwrap();
          return (false, reader);
        }
    };
    let script_outcome = match script_outcome {
        Ok(outcome) => outcome,
        Err(err) => {
            async_log(format!("[handle] {}: script runtime: {:?}\n", request_id, err).into_bytes())
                .await;
            ScriptOutcome::from_request(script_request_fallback)
        }
    };

    if let Err(err) = apply_script_request(&mut head, &script_outcome.request) {
        async_log(
            format!(
                "[handle] {}: script request update: {:?}\n",
                request_id, err
            )
            .into_bytes(),
        )
        .await;
    }

    // Recalculate normalized path if the URI was changed by script
    let normalized_path = if script_outcome.request.uri_changed() {
        match normalized_script_request_path(&script_outcome.request) {
            Some(path) => path,
            None => {
                // Invalid path after script modification
                let (mut reader, mut body) = body_state.borrow_mut().take().unwrap();
                drain_payload(&mut reader, &mut body).await;
                send_fixed(w, bad_request(), None, &HashMap::new(), None).await;
                return (true, reader);
            }
        }
    } else {
        normalized_path
    };
    let hook_state = ResponseHookState::from_outcome(script_runtime, shared, &script_outcome);
    let encode_state = script_outcome.encode.clone().map(|config| {
        crate::helpers::compress::EncodeState::from_request_headers(config, &head.headers)
    });

    // Take reader and body back from shared state
    let (mut reader, mut body) = body_state.borrow_mut().take().unwrap();

    if script_outcome.abort {
        return (false, reader);
    }

    if let Some(proxy_url) = script_outcome.reverse_proxy.as_deref() {
        if !caddy::has_error_routes(&script_outcome)
            && can_use_simple_proxy_fast_path(
                &head,
                &body,
                h1::is_websocket_upgrade_request(&head),
                Some(&script_outcome.early_response_headers),
                &script_outcome.metadata,
                Some(&hook_state),
                script_outcome.request.proxy_method(),
                script_outcome.request.proxy_uri(),
                script_outcome.request.proxy_headers(),
                encode_state.as_ref(),
            )
        {
            let res = reverse_proxy_request(
                proxy_url,
                head.clone(),
                body,
                &mut reader,
                w,
                head_only,
                peer,
                scheme,
                Some(&script_outcome.early_response_headers),
                &script_outcome.metadata,
                Some(&hook_state),
                script_outcome.request.proxy_method(),
                script_outcome.request.proxy_uri(),
                script_outcome.request.proxy_headers(),
                script_outcome.request_body_limit,
                script_outcome.caddy_reverse_proxy,
                script_outcome.caddy_default_forwarded,
                encode_state.as_ref(),
            )
            .await;
            return match res {
                Ok(proxy_outcome) => {
                    log_caddy_access(
                        shared,
                        &head,
                        peer,
                        scheme,
                        proxy_outcome.send.status,
                        &script_outcome.metadata,
                    )
                    .await;
                    (proxy_outcome.send.keep_client, reader)
                }
                Err(err) => {
                    async_log(
                        format!("[handle] {}: reverse proxy: {:?}\n", request_id, err).into_bytes(),
                    )
                    .await;
                    let send_outcome = send_fixed(
                        w,
                        bad_gateway(),
                        Some(&script_outcome.early_response_headers),
                        &script_outcome.metadata,
                        Some(&hook_state),
                    )
                    .await;
                    log_caddy_access(
                        shared,
                        &head,
                        peer,
                        scheme,
                        send_outcome.status,
                        &script_outcome.metadata,
                    )
                    .await;
                    (send_outcome.keep_client, reader)
                }
            };
        }
        let response_started = Cell::new(false);
        let mut tracked_w = TrackedWriter {
            inner: w,
            started: &response_started,
        };
        let res = monoio::select! {
            x = reverse_proxy_request(
                proxy_url,
                head.clone(),
                body,
                &mut reader,
                &mut tracked_w,
                head_only,
                peer,
                scheme,
                Some(&script_outcome.early_response_headers),
                &script_outcome.metadata,
                Some(&hook_state),
                script_outcome.request.proxy_method(),
                script_outcome.request.proxy_uri(),
                script_outcome.request.proxy_headers(),
                script_outcome.request_body_limit,
                script_outcome.caddy_reverse_proxy,
                script_outcome.caddy_default_forwarded,
                encode_state.as_ref(),
            ) => x,
            _ = &mut *interrupt => Err(anyhow::anyhow!("interrupted")),
        };
        match res {
            Ok(proxy_outcome) => {
                if proxy_outcome.continue_request {
                    let (continued, mut reader, mut body) = caddy::continue_h1_request(
                        request_id.clone(),
                        script_runtime,
                        shared,
                        &hook_state,
                        &script_outcome,
                        &body_state,
                        &body_source,
                        reader,
                        proxy_outcome.preserved_body,
                    )
                    .await;
                    if let Err(err) = apply_script_request(&mut head, &continued.request) {
                        async_log(
                            format!(
                                "[handle] {}: continued script request update: {:?}\n",
                                request_id, err
                            )
                            .into_bytes(),
                        )
                        .await;
                    }
                    let normalized_path = match normalized_script_request_path(&continued.request) {
                        Some(path) => path,
                        None => {
                            drain_payload(&mut reader, &mut body).await;
                            let send_outcome =
                                send_fixed(w, bad_request(), None, &continued.metadata, None).await;
                            log_caddy_access(
                                shared,
                                &head,
                                peer,
                                scheme,
                                send_outcome.status,
                                &continued.metadata,
                            )
                            .await;
                            return (send_outcome.keep_client, reader);
                        }
                    };
                    let continued_hook_state =
                        ResponseHookState::from_outcome(script_runtime, shared, &continued);
                    if continued.abort {
                        return (false, reader);
                    }
                    if let Some(proxy_url) = continued.reverse_proxy.as_deref() {
                        let continued_encode_state = continued.encode.clone().map(|config| {
                            crate::helpers::compress::EncodeState::from_request_headers(
                                config,
                                &head.headers,
                            )
                        });
                        let res = reverse_proxy_request(
                            proxy_url,
                            head.clone(),
                            body,
                            &mut reader,
                            w,
                            head_only,
                            peer,
                            scheme,
                            Some(&continued.early_response_headers),
                            &continued.metadata,
                            Some(&continued_hook_state),
                            continued.request.proxy_method(),
                            continued.request.proxy_uri(),
                            continued.request.proxy_headers(),
                            continued.request_body_limit,
                            continued.caddy_reverse_proxy,
                            continued.caddy_default_forwarded,
                            continued_encode_state.as_ref(),
                        )
                        .await;
                        return match res {
                            Ok(outcome) => {
                                if !outcome.continue_request {
                                    log_caddy_access(
                                        shared,
                                        &head,
                                        peer,
                                        scheme,
                                        outcome.send.status,
                                        &continued.metadata,
                                    )
                                    .await;
                                }
                                (outcome.send.keep_client, reader)
                            }
                            Err(err) => {
                                async_log(
                                    format!(
                                        "[handle] {}: continued reverse proxy: {:?}\n",
                                        request_id, err
                                    )
                                    .into_bytes(),
                                )
                                .await;
                                (false, reader)
                            }
                        };
                    }
                    if let Some(send_outcome) = caddy::try_serve_file_server_response_h1(
                        &head,
                        shared,
                        head_only,
                        peer,
                        &mut reader,
                        &mut body,
                        w,
                        &continued,
                        &continued_hook_state,
                        &normalized_path,
                    )
                    .await
                    {
                        log_caddy_access(
                            shared,
                            &head,
                            peer,
                            scheme,
                            send_outcome.status,
                            &continued.metadata,
                        )
                        .await;
                        return (send_outcome.keep_client, reader);
                    }
                    if let Some(response) = continued.response.clone() {
                        drain_payload(&mut reader, &mut body).await;
                        let continued_encode_state = continued.encode.clone().map(|config| {
                            crate::helpers::compress::EncodeState::from_request_headers(
                                config,
                                &head.headers,
                            )
                        });
                        let send_outcome = send_script_response(
                            w,
                            response,
                            head_only,
                            &continued.metadata,
                            Some(&continued_hook_state),
                            continued_encode_state.as_ref(),
                        )
                        .await;
                        log_caddy_access(
                            shared,
                            &head,
                            peer,
                            scheme,
                            send_outcome.status,
                            &continued.metadata,
                        )
                        .await;
                        return (send_outcome.keep_client, reader);
                    }
                    match head.method {
                        Method::GET | Method::HEAD => {
                            drain_payload(&mut reader, &mut body).await;
                            if let Some(send_outcome) = serve_static(
                                &head,
                                shared,
                                head_only,
                                peer,
                                w,
                                Some(&continued.early_response_headers),
                                &continued.metadata,
                                Some(&continued_hook_state),
                                &normalized_path,
                            )
                            .await
                            {
                                log_caddy_access(
                                    shared,
                                    &head,
                                    peer,
                                    scheme,
                                    send_outcome.status,
                                    &continued.metadata,
                                )
                                .await;
                                return (send_outcome.keep_client, reader);
                            }
                            let send_outcome = send_fixed(
                                w,
                                not_found(),
                                Some(&continued.early_response_headers),
                                &continued.metadata,
                                Some(&continued_hook_state),
                            )
                            .await;
                            log_caddy_access(
                                shared,
                                &head,
                                peer,
                                scheme,
                                send_outcome.status,
                                &continued.metadata,
                            )
                            .await;
                            return (send_outcome.keep_client, reader);
                        }
                        _ => {
                            drain_payload(&mut reader, &mut body).await;
                            let send_outcome = send_fixed(
                                w,
                                method_not_allowed(),
                                Some(&continued.early_response_headers),
                                &continued.metadata,
                                Some(&continued_hook_state),
                            )
                            .await;
                            log_caddy_access(
                                shared,
                                &head,
                                peer,
                                scheme,
                                send_outcome.status,
                                &continued.metadata,
                            )
                            .await;
                            return (send_outcome.keep_client, reader);
                        }
                    }
                }
                log_caddy_access(
                    shared,
                    &head,
                    peer,
                    scheme,
                    proxy_outcome.send.status,
                    &script_outcome.metadata,
                )
                .await;
                return (proxy_outcome.send.keep_client, reader);
            }
            Err(err) => {
                async_log(
                    format!("[handle] {}: reverse proxy: {:?}\n", request_id, err).into_bytes(),
                )
                .await;
                if response_started.get() {
                    // Part of the upstream response already reached the
                    // client; writing an error response now would corrupt
                    // the H1 framing, so close the connection instead.
                    return (false, reader);
                }
                if !caddy::has_error_routes(&script_outcome) {
                    let send_outcome = send_fixed(
                        w,
                        bad_gateway(),
                        Some(&script_outcome.early_response_headers),
                        &script_outcome.metadata,
                        Some(&hook_state),
                    )
                    .await;
                    log_caddy_access(
                        shared,
                        &head,
                        peer,
                        scheme,
                        send_outcome.status,
                        &script_outcome.metadata,
                    )
                    .await;
                    return (send_outcome.keep_client, reader);
                }
                caddy::set_proxy_error_metadata(&script_outcome, &err.to_string());
                let (continued, mut reader, mut body) = caddy::continue_h1_request(
                    request_id.clone(),
                    script_runtime,
                    shared,
                    &hook_state,
                    &script_outcome,
                    &body_state,
                    &body_source,
                    reader,
                    None,
                )
                .await;
                if let Err(err) = apply_script_request(&mut head, &continued.request) {
                    async_log(
                        format!(
                            "[handle] {}: proxy error script request update: {:?}\n",
                            request_id, err
                        )
                        .into_bytes(),
                    )
                    .await;
                }
                let normalized_path = match normalized_script_request_path(&continued.request) {
                    Some(path) => path,
                    None => {
                        let send_outcome =
                            send_fixed(w, bad_request(), None, &continued.metadata, None).await;
                        log_caddy_access(
                            shared,
                            &head,
                            peer,
                            scheme,
                            send_outcome.status,
                            &continued.metadata,
                        )
                        .await;
                        return (send_outcome.keep_client, reader);
                    }
                };
                let continued_hook_state =
                    ResponseHookState::from_outcome(script_runtime, shared, &continued);
                if continued.abort {
                    return (false, reader);
                }
                if let Some(proxy_url) = continued.reverse_proxy.as_deref() {
                    let continued_encode_state = continued.encode.clone().map(|config| {
                        crate::helpers::compress::EncodeState::from_request_headers(
                            config,
                            &head.headers,
                        )
                    });
                    let res = reverse_proxy_request(
                        proxy_url,
                        head.clone(),
                        body,
                        &mut reader,
                        w,
                        head_only,
                        peer,
                        scheme,
                        Some(&continued.early_response_headers),
                        &continued.metadata,
                        Some(&continued_hook_state),
                        continued.request.proxy_method(),
                        continued.request.proxy_uri(),
                        continued.request.proxy_headers(),
                        continued.request_body_limit,
                        continued.caddy_reverse_proxy,
                        continued.caddy_default_forwarded,
                        continued_encode_state.as_ref(),
                    )
                    .await;
                    return match res {
                        Ok(outcome) => {
                            if !outcome.continue_request {
                                log_caddy_access(
                                    shared,
                                    &head,
                                    peer,
                                    scheme,
                                    outcome.send.status,
                                    &continued.metadata,
                                )
                                .await;
                            }
                            (outcome.send.keep_client, reader)
                        }
                        Err(err) => {
                            async_log(
                                format!(
                                    "[handle] {}: proxy error continued reverse proxy: {:?}\n",
                                    request_id, err
                                )
                                .into_bytes(),
                            )
                            .await;
                            (false, reader)
                        }
                    };
                }
                if let Some(send_outcome) = caddy::try_serve_file_server_response_h1(
                    &head,
                    shared,
                    head_only,
                    peer,
                    &mut reader,
                    &mut body,
                    w,
                    &continued,
                    &continued_hook_state,
                    &normalized_path,
                )
                .await
                {
                    log_caddy_access(
                        shared,
                        &head,
                        peer,
                        scheme,
                        send_outcome.status,
                        &continued.metadata,
                    )
                    .await;
                    return (send_outcome.keep_client, reader);
                }
                if let Some(response) = continued.response.clone() {
                    let continued_encode_state = continued.encode.clone().map(|config| {
                        crate::helpers::compress::EncodeState::from_request_headers(
                            config,
                            &head.headers,
                        )
                    });
                    let send_outcome = send_script_response(
                        w,
                        response,
                        head_only,
                        &continued.metadata,
                        Some(&continued_hook_state),
                        continued_encode_state.as_ref(),
                    )
                    .await;
                    log_caddy_access(
                        shared,
                        &head,
                        peer,
                        scheme,
                        send_outcome.status,
                        &continued.metadata,
                    )
                    .await;
                    return (send_outcome.keep_client, reader);
                }
                match head.method {
                    Method::GET | Method::HEAD => {
                        if let Some(send_outcome) = serve_static(
                            &head,
                            shared,
                            head_only,
                            peer,
                            w,
                            Some(&continued.early_response_headers),
                            &continued.metadata,
                            Some(&continued_hook_state),
                            &normalized_path,
                        )
                        .await
                        {
                            log_caddy_access(
                                shared,
                                &head,
                                peer,
                                scheme,
                                send_outcome.status,
                                &continued.metadata,
                            )
                            .await;
                            return (send_outcome.keep_client, reader);
                        }
                        let send_outcome = send_fixed(
                            w,
                            bad_gateway(),
                            Some(&continued.early_response_headers),
                            &continued.metadata,
                            Some(&continued_hook_state),
                        )
                        .await;
                        log_caddy_access(
                            shared,
                            &head,
                            peer,
                            scheme,
                            send_outcome.status,
                            &continued.metadata,
                        )
                        .await;
                        return (send_outcome.keep_client, reader);
                    }
                    _ => {
                        let send_outcome = send_fixed(
                            w,
                            bad_gateway(),
                            Some(&continued.early_response_headers),
                            &continued.metadata,
                            Some(&continued_hook_state),
                        )
                        .await;
                        log_caddy_access(
                            shared,
                            &head,
                            peer,
                            scheme,
                            send_outcome.status,
                            &continued.metadata,
                        )
                        .await;
                        return (send_outcome.keep_client, reader);
                    }
                }
            }
        }
    }

    if let Some(send_outcome) = caddy::try_serve_file_server_response_h1(
        &head,
        shared,
        head_only,
        peer,
        &mut reader,
        &mut body,
        w,
        &script_outcome,
        &hook_state,
        &normalized_path,
    )
    .await
    {
        log_caddy_access(
            shared,
            &head,
            peer,
            scheme,
            send_outcome.status,
            &script_outcome.metadata,
        )
        .await;
        return (send_outcome.keep_client, reader);
    }

    if let Some(response) = script_outcome.response.clone() {
        drain_payload(&mut reader, &mut body).await;
        let send_outcome = send_script_response(
            w,
            response,
            head_only,
            &script_outcome.metadata,
            Some(&hook_state),
            encode_state.as_ref(),
        )
        .await;
        log_caddy_access(
            shared,
            &head,
            peer,
            scheme,
            send_outcome.status,
            &script_outcome.metadata,
        )
        .await;
        return (send_outcome.keep_client, reader);
    }

    drain_payload(&mut reader, &mut body).await;

    match head.method {
        Method::GET | Method::HEAD => {
            if let Some(send_outcome) = serve_static(
                &head,
                shared,
                head_only,
                peer,
                w,
                Some(&script_outcome.early_response_headers),
                &script_outcome.metadata,
                Some(&hook_state),
                &normalized_path,
            )
            .await
            {
                log_caddy_access(
                    shared,
                    &head,
                    peer,
                    scheme,
                    send_outcome.status,
                    &script_outcome.metadata,
                )
                .await;
                return (send_outcome.keep_client, reader);
            }
            let send_outcome = send_fixed(
                w,
                not_found(),
                Some(&script_outcome.early_response_headers),
                &script_outcome.metadata,
                Some(&hook_state),
            )
            .await;
            log_caddy_access(
                shared,
                &head,
                peer,
                scheme,
                send_outcome.status,
                &script_outcome.metadata,
            )
            .await;
            return (send_outcome.keep_client, reader);
        }
        _ => {
            let send_outcome = send_fixed(
                w,
                method_not_allowed(),
                Some(&script_outcome.early_response_headers),
                &script_outcome.metadata,
                Some(&hook_state),
            )
            .await;
            log_caddy_access(
                shared,
                &head,
                peer,
                scheme,
                send_outcome.status,
                &script_outcome.metadata,
            )
            .await;
            return (send_outcome.keep_client, reader);
        }
    }
}

async fn handle_h2_request<H>(
    request: ::http::Request<h2::RecvStream>,
    mut respond: h2::server::SendResponse<Bytes>,
    shared: Arc<SharedState>,
    script_runtime: Rc<ScriptRuntime>,
    peer: std::net::SocketAddr,
    local: std::net::SocketAddr,
    scheme: Scheme,
    hup: future::Shared<H>,
    connection: ConnectionInfo,
) -> Result<()>
where
    H: Future<Output = ()> + Unpin + 'static,
{
    let request_id = RequestId::new();
    let (parts, body) = request.into_parts();
    let mut headers = parts.headers;
    h1::normalize_cookie_headers(&mut headers);

    let mut head = RequestHead {
        method: parts.method,
        uri: parts.uri,
        version: ::http::Version::HTTP_2,
        headers,
        tls: matches!(scheme, Scheme::Https),
    };
    ensure_host_header(&mut head);
    let head_only = head.method == Method::HEAD;

    if request_authority_sni_mismatch(&head, &connection) {
        send_h2_bytes_response(
            &mut respond,
            StatusCode::MISDIRECTED_REQUEST,
            "text/plain; charset=utf-8",
            b"Misdirected Request".to_vec(),
            head_only,
            None,
            &HashMap::new(),
            None,
        )
        .await?;
        return Ok(());
    }

    if !shared.config.disable_request_logging {
        log_request(&request_id, peer, scheme, &head.method, &head.uri).await;
    }

    // Validate hostname if configured
    if !shared.config.validate_hostnames.is_empty() {
        let host = request_authority_or_host(&head).unwrap_or("");
        if !is_valid_hostname(host, &shared.config.validate_hostnames) {
            send_h2_bytes_response(
                &mut respond,
                StatusCode::MISDIRECTED_REQUEST,
                "text/plain; charset=utf-8",
                b"Misdirected Request".to_vec(),
                head_only,
                None,
                &HashMap::new(),
                None,
            )
            .await?;
            return Ok(());
        }
    }

    let (body_source, body_state) =
        create_h2_body_source(body, shared.config.max_buffered_body_size);

    // Normalize the path once for the entire request pipeline
    let Some(normalized_path) = normalize_request_path(head.uri.path()) else {
        // Invalid path (e.g., path traversal escape attempt)
        send_h2_bytes_response(
            &mut respond,
            StatusCode::BAD_REQUEST,
            "text/plain; charset=utf-8",
            b"Bad Request".to_vec(),
            head_only,
            None,
            &HashMap::new(),
            None,
        )
        .await?;
        return Ok(());
    };

    let script_request = build_script_request(
        request_id.clone(),
        &head,
        peer,
        local,
        scheme,
        &normalized_path,
        Vec::new(),
        connection.clone(),
    );
    let mut hup_wait = hup.clone();
    let script_outcome = monoio::select! {
        x = script_runtime.run_request(shared.site.load_full(), script_request, body_source.clone()) => x,
        _ = &mut hup_wait => {
          async_log(format!("[handle] {}: interrupted\n", request_id).into_bytes()).await;
          return Ok(());
        }
    };
    let script_outcome = match script_outcome {
        Ok(outcome) => outcome,
        Err(err) => {
            async_log(format!("[handle] {}: script runtime: {:?}\n", request_id, err).into_bytes())
                .await;
            ScriptOutcome::from_request(build_script_request(
                request_id.clone(),
                &head,
                peer,
                local,
                scheme,
                &normalized_path,
                Vec::new(),
                connection,
            ))
        }
    };

    if let Err(err) = apply_script_request(&mut head, &script_outcome.request) {
        async_log(
            format!(
                "[handle] {}: script request update: {:?}\n",
                request_id, err
            )
            .into_bytes(),
        )
        .await;
    }

    // Recalculate normalized path if the URI was changed by script
    let normalized_path = if script_outcome.request.uri_changed() {
        match normalized_script_request_path(&script_outcome.request) {
            Some(path) => path,
            None => {
                // Invalid path after script modification
                send_h2_bytes_response(
                    &mut respond,
                    StatusCode::BAD_REQUEST,
                    "text/plain; charset=utf-8",
                    b"Bad Request".to_vec(),
                    head_only,
                    None,
                    &HashMap::new(),
                    None,
                )
                .await?;
                return Ok(());
            }
        }
    } else {
        normalized_path
    };
    let hook_state = ResponseHookState::from_outcome(&script_runtime, &shared, &script_outcome);
    let encode_state = script_outcome.encode.clone().map(|config| {
        crate::helpers::compress::EncodeState::from_request_headers(config, &head.headers)
    });

    if script_outcome.abort {
        return Ok(());
    }

    if let Some(proxy_url) = script_outcome.reverse_proxy.as_deref() {
        // Take body from state - may be None if script consumed it
        let body = body_state.borrow_mut().take();
        if let Some(body) = body {
            let mut hup_wait = hup.clone();
            let res = monoio::select! {
                x = reverse_proxy_request_h2(
                    &proxy_url,
                    head.clone(),
                    body,
                    &mut respond,
                    head_only,
                    peer,
                    scheme,
                    Some(&script_outcome.early_response_headers),
                    &script_outcome.metadata,
                    Some(&hook_state),
                    script_outcome.request.proxy_method(),
                    script_outcome.request.proxy_uri(),
                    script_outcome.request.proxy_headers(),
                    script_outcome.request_body_limit,
                    script_outcome.caddy_reverse_proxy,
                    script_outcome.caddy_default_forwarded,
                    encode_state.as_ref(),
                ) => x,
                _ = &mut hup_wait => Err(anyhow::anyhow!("interrupted")),
            };
            match res {
                Ok(proxy_outcome) => {
                    if proxy_outcome.continue_request {
                        let (continued, body) = caddy::continue_h2_request(
                            request_id.clone(),
                            &script_runtime,
                            &shared,
                            &hook_state,
                            &script_outcome,
                            &body_state,
                            &body_source,
                            proxy_outcome.preserved_body,
                        )
                        .await;
                        if let Err(err) = apply_script_request(&mut head, &continued.request) {
                            async_log(
                                format!(
                                    "[handle] {}: continued script request update: {:?}\n",
                                    request_id, err
                                )
                                .into_bytes(),
                            )
                            .await;
                        }
                        let normalized_path =
                            match normalized_script_request_path(&continued.request) {
                                Some(path) => path,
                                None => {
                                    let status = send_h2_bytes_response(
                                        &mut respond,
                                        StatusCode::BAD_REQUEST,
                                        "text/plain; charset=utf-8",
                                        b"Bad Request".to_vec(),
                                        head_only,
                                        None,
                                        &continued.metadata,
                                        None,
                                    )
                                    .await?;
                                    log_caddy_access(
                                        &shared,
                                        &head,
                                        peer,
                                        scheme,
                                        status,
                                        &continued.metadata,
                                    )
                                    .await;
                                    return Ok(());
                                }
                            };
                        let continued_hook_state =
                            ResponseHookState::from_outcome(&script_runtime, &shared, &continued);
                        if continued.abort {
                            return Ok(());
                        }
                        if let Some(proxy_url) = continued.reverse_proxy.as_deref() {
                            if let Some(body) = body {
                                let continued_encode_state =
                                    continued.encode.clone().map(|config| {
                                        crate::helpers::compress::EncodeState::from_request_headers(
                                            config,
                                            &head.headers,
                                        )
                                    });
                                let res = reverse_proxy_request_h2(
                                    proxy_url,
                                    head.clone(),
                                    body,
                                    &mut respond,
                                    head_only,
                                    peer,
                                    scheme,
                                    Some(&continued.early_response_headers),
                                    &continued.metadata,
                                    Some(&continued_hook_state),
                                    continued.request.proxy_method(),
                                    continued.request.proxy_uri(),
                                    continued.request.proxy_headers(),
                                    continued.request_body_limit,
                                    continued.caddy_reverse_proxy,
                                    continued.caddy_default_forwarded,
                                    continued_encode_state.as_ref(),
                                )
                                .await;
                                match res {
                                    Ok(outcome) => {
                                        if !outcome.continue_request
                                            && let Some(status) = outcome.status
                                        {
                                            log_caddy_access(
                                                &shared,
                                                &head,
                                                peer,
                                                scheme,
                                                status,
                                                &continued.metadata,
                                            )
                                            .await;
                                        }
                                    }
                                    Err(err) => {
                                        async_log(
                                            format!(
                                                "[handle] {}: continued reverse proxy: {:?}\n",
                                                request_id, err
                                            )
                                            .into_bytes(),
                                        )
                                        .await;
                                    }
                                }
                            } else {
                                async_log(
                                    format!(
                                        "[handle] {}: continued reverse proxy skipped - body already consumed\n",
                                        request_id
                                    )
                                    .into_bytes(),
                                )
                                .await;
                            }
                            return Ok(());
                        }
                        if let Some(status) = caddy::try_serve_file_server_response_h2(
                            &head,
                            &shared,
                            head_only,
                            &mut respond,
                            &continued,
                            &continued_hook_state,
                            &normalized_path,
                        )
                        .await?
                        {
                            log_caddy_access(
                                &shared,
                                &head,
                                peer,
                                scheme,
                                status,
                                &continued.metadata,
                            )
                            .await;
                            return Ok(());
                        }
                        if let Some(response) = continued.response.clone() {
                            let continued_encode_state = continued.encode.clone().map(|config| {
                                crate::helpers::compress::EncodeState::from_request_headers(
                                    config,
                                    &head.headers,
                                )
                            });
                            let status = send_script_response_h2(
                                &mut respond,
                                response,
                                head_only,
                                &continued.metadata,
                                Some(&continued_hook_state),
                                continued_encode_state.as_ref(),
                            )
                            .await?;
                            log_caddy_access(
                                &shared,
                                &head,
                                peer,
                                scheme,
                                status,
                                &continued.metadata,
                            )
                            .await;
                            return Ok(());
                        }
                        match head.method {
                            Method::GET | Method::HEAD => {
                                if let Some(status) = serve_static_h2(
                                    &head,
                                    &shared,
                                    head_only,
                                    &mut respond,
                                    Some(&continued.early_response_headers),
                                    &continued.metadata,
                                    Some(&continued_hook_state),
                                    &normalized_path,
                                )
                                .await?
                                {
                                    log_caddy_access(
                                        &shared,
                                        &head,
                                        peer,
                                        scheme,
                                        status,
                                        &continued.metadata,
                                    )
                                    .await;
                                } else {
                                    let status = send_h2_response(
                                        &mut respond,
                                        not_found(),
                                        head_only,
                                        Some(&continued.early_response_headers),
                                        &continued.metadata,
                                        Some(&continued_hook_state),
                                    )
                                    .await?;
                                    log_caddy_access(
                                        &shared,
                                        &head,
                                        peer,
                                        scheme,
                                        status,
                                        &continued.metadata,
                                    )
                                    .await;
                                }
                            }
                            _ => {
                                let status = send_h2_response(
                                    &mut respond,
                                    method_not_allowed(),
                                    head_only,
                                    Some(&continued.early_response_headers),
                                    &continued.metadata,
                                    Some(&continued_hook_state),
                                )
                                .await?;
                                log_caddy_access(
                                    &shared,
                                    &head,
                                    peer,
                                    scheme,
                                    status,
                                    &continued.metadata,
                                )
                                .await;
                            }
                        }
                    } else if let Some(status) = proxy_outcome.status {
                        log_caddy_access(
                            &shared,
                            &head,
                            peer,
                            scheme,
                            status,
                            &script_outcome.metadata,
                        )
                        .await;
                    }
                }
                Err(err) => {
                    async_log(
                        format!("[handle] {}: reverse proxy: {:?}\n", request_id, err).into_bytes(),
                    )
                    .await;
                }
            }
        } else {
            async_log(
                format!(
                    "[handle] {}: reverse proxy skipped - body already consumed\n",
                    request_id
                )
                .into_bytes(),
            )
            .await;
        }
        return Ok(());
    }

    if let Some(status) = caddy::try_serve_file_server_response_h2(
        &head,
        &shared,
        head_only,
        &mut respond,
        &script_outcome,
        &hook_state,
        &normalized_path,
    )
    .await?
    {
        log_caddy_access(
            &shared,
            &head,
            peer,
            scheme,
            status,
            &script_outcome.metadata,
        )
        .await;
        return Ok(());
    }

    if let Some(response) = script_outcome.response.clone() {
        let status = send_script_response_h2(
            &mut respond,
            response,
            head_only,
            &script_outcome.metadata,
            Some(&hook_state),
            encode_state.as_ref(),
        )
        .await?;
        log_caddy_access(
            &shared,
            &head,
            peer,
            scheme,
            status,
            &script_outcome.metadata,
        )
        .await;
        return Ok(());
    }

    match head.method {
        Method::GET | Method::HEAD => {
            if let Some(status) = serve_static_h2(
                &head,
                &shared,
                head_only,
                &mut respond,
                Some(&script_outcome.early_response_headers),
                &script_outcome.metadata,
                Some(&hook_state),
                &normalized_path,
            )
            .await?
            {
                log_caddy_access(
                    &shared,
                    &head,
                    peer,
                    scheme,
                    status,
                    &script_outcome.metadata,
                )
                .await;
            } else {
                let status = send_h2_response(
                    &mut respond,
                    not_found(),
                    head_only,
                    Some(&script_outcome.early_response_headers),
                    &script_outcome.metadata,
                    Some(&hook_state),
                )
                .await?;
                log_caddy_access(
                    &shared,
                    &head,
                    peer,
                    scheme,
                    status,
                    &script_outcome.metadata,
                )
                .await;
            }
        }
        _ => {
            let status = send_h2_response(
                &mut respond,
                method_not_allowed(),
                head_only,
                Some(&script_outcome.early_response_headers),
                &script_outcome.metadata,
                Some(&hook_state),
            )
            .await?;
            log_caddy_access(
                &shared,
                &head,
                peer,
                scheme,
                status,
                &script_outcome.metadata,
            )
            .await;
        }
    }

    Ok(())
}

fn ensure_content_length(res: &mut ::http::Response<Bytes>) {
    if !res.headers().contains_key(::http::header::CONTENT_LENGTH)
        && !res
            .headers()
            .contains_key(::http::header::TRANSFER_ENCODING)
    {
        let length = ::http::HeaderValue::from_str(&res.body().len().to_string())
            .unwrap_or_else(|_| ::http::HeaderValue::from_static("0"));
        res.headers_mut()
            .insert(::http::header::CONTENT_LENGTH, length);
    }
}

fn ensure_static_content_length(response: &mut StaticResponse) {
    if response
        .headers
        .contains_key(::http::header::CONTENT_LENGTH)
        || response
            .headers
            .contains_key(::http::header::TRANSFER_ENCODING)
    {
        return;
    }
    let len = match &response.body {
        StaticBody::Empty => 0,
        StaticBody::Bytes(body) => body.len() as u64,
        StaticBody::File { entry, range } => range.map(|range| range.len).unwrap_or(entry.size),
        StaticBody::FsFile { size, range, .. } => range.map(|range| range.len).unwrap_or(*size),
    };
    let value = ::http::HeaderValue::from_str(&len.to_string())
        .unwrap_or_else(|_| ::http::HeaderValue::from_static("0"));
    response
        .headers
        .insert(::http::header::CONTENT_LENGTH, value);
}

fn status_allows_body(status: StatusCode) -> bool {
    !status.is_informational()
        && !matches!(status, StatusCode::NO_CONTENT | StatusCode::NOT_MODIFIED)
}

fn raw_status_allows_body(status: u16) -> bool {
    !(100..200).contains(&status) && status != 204 && status != 304
}

fn strip_no_body_headers(headers: &mut ::http::HeaderMap) {
    headers.remove(::http::header::CONTENT_LENGTH);
    headers.remove(::http::header::TRANSFER_ENCODING);
}

async fn send_fixed(
    w: &mut impl AsyncWriteRent,
    mut res: ::http::Response<Bytes>,
    early_response_headers: Option<&::http::HeaderMap>,
    metadata: &HashMap<String, String>,
    hook_state: Option<&ResponseHookState<'_>>,
) -> H1SendOutcome {
    let hook_outcome =
        caddy::prepare_fixed_response(&mut res, early_response_headers, metadata, hook_state).await;
    let _ = hook_outcome.continue_request;
    let send_body = status_allows_body(res.status());
    if !send_body {
        strip_no_body_headers(res.headers_mut());
    }
    let (parts, body) = res.into_parts();
    let continue_conn = !connection_has_close(&parts.headers);
    if send_body && !body.is_empty() {
        let _ = write_response_head_and_body_raw(
            w,
            parts.status.as_u16(),
            &parts.headers,
            body.to_vec(),
        )
        .await;
    } else {
        let _ = write_response_head(w, parts.status, &parts.headers).await;
    }
    let _ = w.flush().await;
    H1SendOutcome {
        keep_client: continue_conn,
        status: parts.status.as_u16(),
    }
}

fn ensure_host_header(head: &mut RequestHead) {
    if head.headers.contains_key(::http::header::HOST) {
        return;
    }
    let Some(authority) = head.uri.authority() else {
        return;
    };
    if let Ok(value) = HeaderValue::from_str(authority.as_str()) {
        head.headers.insert(::http::header::HOST, value);
    }
}

fn request_authority_or_host(head: &RequestHead) -> Option<&str> {
    head.uri
        .authority()
        .map(|authority| authority.as_str())
        .or_else(|| {
            head.headers
                .get(::http::header::HOST)
                .and_then(|value| value.to_str().ok())
        })
}

fn request_authority_sni_mismatch(head: &RequestHead, connection: &ConnectionInfo) -> bool {
    let Some(sni) = connection.inner_sni.as_deref() else {
        return false;
    };
    let Some(authority) = request_authority_or_host(head) else {
        return true;
    };
    !same_hostname(authority, sni)
}

async fn send_h2_response(
    respond: &mut h2::server::SendResponse<Bytes>,
    mut res: ::http::Response<Bytes>,
    head_only: bool,
    early_response_headers: Option<&::http::HeaderMap>,
    metadata: &HashMap<String, String>,
    hook_state: Option<&ResponseHookState<'_>>,
) -> Result<u16> {
    let hook_outcome =
        caddy::prepare_fixed_response(&mut res, early_response_headers, metadata, hook_state).await;
    let _ = hook_outcome.continue_request;
    let send_body = status_allows_body(res.status());
    if !send_body {
        strip_no_body_headers(res.headers_mut());
    }
    strip_hop_headers(res.headers_mut(), false);
    let (parts, body) = res.into_parts();
    let mut head = ::http::Response::builder()
        .status(parts.status)
        .version(::http::Version::HTTP_2)
        .body(())
        .map_err(|err| anyhow!("failed to build h2 response: {err}"))?;
    *head.headers_mut() = parts.headers;
    let end_stream = head_only || !send_body || body.is_empty();
    let mut stream = respond.send_response(head, end_stream)?;
    if !end_stream {
        send_h2_data(&mut stream, body, true).await?;
    }
    Ok(parts.status.as_u16())
}

async fn send_h2_response_with_prepared_headers(
    respond: &mut h2::server::SendResponse<Bytes>,
    mut res: ::http::Response<Bytes>,
    head_only: bool,
) -> Result<()> {
    ensure_content_length(&mut res);
    if !status_allows_body(res.status()) {
        strip_no_body_headers(res.headers_mut());
    }
    strip_hop_headers(res.headers_mut(), false);
    let (parts, body) = res.into_parts();
    let mut head = ::http::Response::builder()
        .status(parts.status)
        .version(::http::Version::HTTP_2)
        .body(())
        .map_err(|err| anyhow!("failed to build h2 response: {err}"))?;
    *head.headers_mut() = parts.headers;
    let end_stream = head_only || body.is_empty();
    let mut stream = respond.send_response(head, end_stream)?;
    if !end_stream {
        send_h2_data(&mut stream, body, true).await?;
    }
    Ok(())
}

async fn send_h2_bytes_response(
    respond: &mut h2::server::SendResponse<Bytes>,
    status: StatusCode,
    content_type: &str,
    body: Vec<u8>,
    head_only: bool,
    early_response_headers: Option<&::http::HeaderMap>,
    metadata: &HashMap<String, String>,
    hook_state: Option<&ResponseHookState<'_>>,
) -> Result<u16> {
    let headers = build_base_headers(body.len() as u64, content_type);
    let mut res = ::http::Response::builder()
        .status(status)
        .body(Bytes::from(body))
        .map_err(|err| anyhow!("failed to build h2 response: {err}"))?;
    *res.headers_mut() = headers;
    send_h2_response(
        respond,
        res,
        head_only,
        early_response_headers,
        metadata,
        hook_state,
    )
    .await
}

async fn send_script_response_h2(
    respond: &mut h2::server::SendResponse<Bytes>,
    response: ScriptResponse,
    head_only: bool,
    metadata: &HashMap<String, String>,
    hook_state: Option<&ResponseHookState<'_>>,
    encode: Option<&crate::helpers::compress::EncodeState>,
) -> Result<u16> {
    let mut status =
        StatusCode::from_u16(response.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    let mut headers = response
        .content_type
        .as_deref()
        .map(|content_type| build_base_headers(response.body.len() as u64, content_type))
        .unwrap_or_else(|| {
            let mut headers = ::http::HeaderMap::new();
            if let Ok(value) = ::http::HeaderValue::from_str(&response.body.len().to_string()) {
                headers.insert(::http::header::CONTENT_LENGTH, value);
            }
            headers
        });
    append_script_response_headers(&mut headers, &response.headers);
    let body = response.body;
    let hook_outcome =
        caddy::prepare_script_response_headers(status, &mut headers, metadata, hook_state).await;
    let _ = hook_outcome.continue_request;
    status = hook_outcome.status;
    let send_body = status_allows_body(status);
    if !send_body {
        strip_no_body_headers(&mut headers);
    }
    strip_hop_headers(&mut headers, false);
    let mut body = if send_body { body } else { Vec::new() };
    // Streaming response compression (Caddy `encode` handler), buffered case.
    if send_body && let Some(state) = encode {
        if let Some(chosen) = state.decide(status.as_u16(), &headers, Some(body.len() as u64)) {
            if head_only {
                crate::helpers::compress::apply_encoding_headers(&mut headers, &chosen.name);
            } else if let Ok(compressed) =
                crate::helpers::compress::BodyEncoder::compress_buffer(chosen.spec, &body)
            {
                crate::helpers::compress::apply_encoding_headers(&mut headers, &chosen.name);
                if let Ok(value) = ::http::HeaderValue::from_str(&compressed.len().to_string()) {
                    headers.insert(::http::header::CONTENT_LENGTH, value);
                }
                body = compressed;
            }
        }
    }
    let mut res = ::http::Response::builder()
        .status(status)
        .body(Bytes::from(body))
        .map_err(|err| anyhow!("failed to build h2 response: {err}"))?;
    *res.headers_mut() = headers;
    send_h2_response_with_prepared_headers(respond, res, head_only).await?;
    Ok(status.as_u16())
}

async fn send_h2_data(
    stream: &mut h2::SendStream<Bytes>,
    data: Bytes,
    end_stream: bool,
) -> Result<()> {
    if data.is_empty() {
        if end_stream {
            stream.send_data(Bytes::new(), true)?;
        }
        return Ok(());
    }

    let mut offset = 0;
    while offset < data.len() {
        let remaining = data.len() - offset;
        stream.reserve_capacity(remaining);
        let capacity = future::poll_fn(|cx| stream.poll_capacity(cx)).await;
        let capacity = match capacity {
            Some(Ok(value)) => value,
            Some(Err(err)) => return Err(anyhow!("h2 capacity error: {err}")),
            None => return Err(anyhow!("h2 stream closed")),
        };
        if capacity == 0 {
            // yield to event loop
            monoio::time::sleep(Duration::from_millis(0)).await;
            continue;
        }
        let to_send = remaining.min(capacity);
        let chunk = data.slice(offset..offset + to_send);
        let is_last = offset + to_send == data.len();
        stream.send_data(chunk, end_stream && is_last)?;
        offset += to_send;
    }
    Ok(())
}

async fn drain_payload<R: AsyncReadRent>(reader: &mut h1::H1Connection<R>, body: &mut h1::Body) {
    loop {
        match body.next_data(reader).await {
            Some(Ok(_)) => continue,
            Some(Err(_)) => break,
            None => break,
        }
    }
}

async fn prepare_static_response(
    head: &RequestHead,
    shared: &Arc<SharedState>,
    head_only: bool,
    metadata: &HashMap<String, String>,
    normalized_path: &NormalizedPath,
) -> Option<StaticResponse> {
    let site = shared.site.load_full();
    let entry = site.lookup(
        normalized_path,
        &shared.config.index_file,
        shared.config.try_html,
    )?;
    let mime = guess_mime(&entry.path);

    if should_template_replace(mime, metadata) {
        let response = match read_tar_entry(entry.clone(), &site).await {
            Ok(body) => {
                let rendered = match std::str::from_utf8(&body) {
                    Ok(text) => apply_template(text, metadata).into_bytes(),
                    Err(_) => body,
                };
                let headers = build_base_headers(rendered.len() as u64, mime);
                StaticResponse {
                    status: StatusCode::OK,
                    headers,
                    body: StaticBody::Bytes(rendered),
                    head_only,
                    site,
                }
            }
            Err(err) => {
                eprintln!("failed to render {}: {:?}", entry.path, err);
                let headers = build_base_headers(
                    b"Internal Server Error".len() as u64,
                    "text/plain; charset=utf-8",
                );
                StaticResponse {
                    status: StatusCode::INTERNAL_SERVER_ERROR,
                    headers,
                    body: StaticBody::Bytes(b"Internal Server Error".to_vec()),
                    head_only,
                    site,
                }
            }
        };
        return Some(response);
    }

    if not_modified_by_request(&head.headers, &entry.etag, entry.mtime) {
        let headers = not_modified_headers(&entry.etag, entry.mtime);
        return Some(StaticResponse {
            status: StatusCode::NOT_MODIFIED,
            headers,
            body: StaticBody::Empty,
            head_only: true,
            site,
        });
    }

    let mut headers = build_base_headers(entry.size, mime);
    headers.insert(::http::header::ETAG, etag_header_value(&entry.etag));
    insert_last_modified(&mut headers, entry.mtime);
    headers.insert(
        ::http::header::ACCEPT_RANGES,
        ::http::HeaderValue::from_static("bytes"),
    );
    let (status, range) =
        apply_static_range(head, &mut headers, entry.size, &entry.etag, entry.mtime);
    Some(StaticResponse {
        status,
        headers,
        body: StaticBody::File { entry, range },
        head_only,
        site,
    })
}

async fn send_static_response_h1(
    w: &mut impl AsyncWriteRent,
    shared: &Arc<SharedState>,
    peer: std::net::SocketAddr,
    mut response: StaticResponse,
    early_response_headers: Option<&::http::HeaderMap>,
    metadata: &HashMap<String, String>,
    hook_state: Option<&ResponseHookState<'_>>,
) -> H1SendOutcome {
    let hook_outcome = caddy::prepare_static_response_headers_raw_h1(
        &mut response,
        early_response_headers,
        metadata,
        hook_state,
    )
    .await;
    let _ = hook_outcome.continue_request;
    let status = hook_outcome.status;
    let send_body = raw_status_allows_body(status);
    if !send_body {
        strip_no_body_headers(&mut response.headers);
    }
    send_prepared_static_response_h1(w, shared, peer, response, status, send_body, None).await
}

async fn send_prepared_static_response_h1(
    w: &mut impl AsyncWriteRent,
    shared: &Arc<SharedState>,
    peer: std::net::SocketAddr,
    mut response: StaticResponse,
    status: u16,
    send_body: bool,
    encode: Option<&crate::helpers::compress::EncodeState>,
) -> H1SendOutcome {
    // Streaming response compression (Caddy `encode` handler). File bodies have
    // a known length, so the minimum_length gate is exact and no read-ahead is
    // needed. Byte-range responses are served uncompressed (a compressed stream
    // is not byte-rangeable), matching Caddy dropping Accept-Ranges on encode.
    let body_range_present = matches!(
        &response.body,
        StaticBody::File { range: Some(_), .. } | StaticBody::FsFile { range: Some(_), .. }
    );
    let chosen = if send_body && !body_range_present {
        encode.and_then(|state| {
            let len = static_body_len(&response.body);
            state.decide(status, &response.headers, Some(len))
        })
    } else {
        None
    };
    if let Some(chosen) = chosen {
        crate::helpers::compress::apply_encoding_headers(&mut response.headers, &chosen.name);
        if response.head_only {
            let _ = write_response_head_raw(w, status, &response.headers).await;
            let _ = w.flush().await;
            return H1SendOutcome {
                keep_client: !connection_has_close(&response.headers),
                status,
            };
        }
        response.headers.insert(
            ::http::header::TRANSFER_ENCODING,
            ::http::HeaderValue::from_static("chunked"),
        );
        let continue_conn = !connection_has_close(&response.headers);
        let _ = write_response_head_raw(w, status, &response.headers).await;
        match write_static_body_compressed_h1(w, shared, &response, chosen.spec).await {
            Ok(()) => {
                let _ = w.flush().await;
            }
            Err(e) => {
                if e.kind() != ErrorKind::ConnectionReset && e.kind() != ErrorKind::BrokenPipe {
                    eprintln!("aborting stream with {} due to io error: {:?}", peer, e);
                    let _ = w.shutdown().await;
                    return H1SendOutcome {
                        keep_client: false,
                        status,
                    };
                }
            }
        }
        return H1SendOutcome {
            keep_client: continue_conn,
            status,
        };
    }

    let continue_conn = !connection_has_close(&response.headers);
    if response.head_only || !send_body {
        let _ = write_response_head_raw(w, status, &response.headers).await;
        let _ = w.flush().await;
        return H1SendOutcome {
            keep_client: continue_conn,
            status,
        };
    }

    match response.body {
        StaticBody::Empty => {
            let _ = write_response_head_raw(w, status, &response.headers).await;
            let _ = w.flush().await;
        }
        StaticBody::Bytes(body) => {
            if !body.is_empty() {
                let _ = write_response_head_and_body_raw(w, status, &response.headers, body).await;
            } else {
                let _ = write_response_head_raw(w, status, &response.headers).await;
            }
            let _ = w.flush().await;
        }
        StaticBody::File { entry, range } => {
            let _ = write_response_head_raw(w, status, &response.headers).await;
            let stream_result = if let Some(range) = range {
                crate::shared::stream_tar_entry_range(
                    entry.clone(),
                    &response.site,
                    range.start,
                    range.len,
                    shared.config.chunk_size,
                    w,
                )
                .await
            } else {
                stream_tar_entry(entry.clone(), &response.site, shared.config.chunk_size, w).await
            };
            match stream_result {
                Ok(()) => {
                    let _ = w.flush().await;
                }
                Err(e) => {
                    if e.kind() != ErrorKind::ConnectionReset && e.kind() != ErrorKind::BrokenPipe {
                        eprintln!("aborting stream with {} due to io error: {:?}", peer, e);
                        let _ = w.shutdown().await;
                        return H1SendOutcome {
                            keep_client: false,
                            status,
                        };
                    }
                }
            };
        }
        StaticBody::FsFile { path, size, range } => {
            let _ = write_response_head_raw(w, status, &response.headers).await;
            let stream_result = stream_fs_file(
                &path,
                range.map(|range| range.start).unwrap_or(0),
                range.map(|range| range.len).unwrap_or(size),
                shared.config.chunk_size,
                w,
            )
            .await;
            match stream_result {
                Ok(()) => {
                    let _ = w.flush().await;
                }
                Err(e) => {
                    if e.kind() != ErrorKind::ConnectionReset && e.kind() != ErrorKind::BrokenPipe {
                        eprintln!("aborting stream with {} due to io error: {:?}", peer, e);
                        let _ = w.shutdown().await;
                        return H1SendOutcome {
                            keep_client: false,
                            status,
                        };
                    }
                }
            };
        }
    }
    H1SendOutcome {
        keep_client: continue_conn,
        status,
    }
}

/// The byte length of a static body's full content (ignoring ranges, which are
/// not compressed).
fn static_body_len(body: &StaticBody) -> u64 {
    match body {
        StaticBody::Empty => 0,
        StaticBody::Bytes(bytes) => bytes.len() as u64,
        StaticBody::File { entry, range } => range.map(|r| r.len).unwrap_or(entry.size),
        StaticBody::FsFile { size, range, .. } => range.map(|r| r.len).unwrap_or(*size),
    }
}

/// Stream a (non-range) static body to the client compressed with `spec`,
/// framed as HTTP/1.1 chunks. File bodies are read in chunks and fed through the
/// encoder so large files do not need to be buffered in full.
async fn write_static_body_compressed_h1(
    w: &mut impl AsyncWriteRent,
    shared: &Arc<SharedState>,
    response: &StaticResponse,
    spec: crate::helpers::compress::EncoderSpec,
) -> std::io::Result<()> {
    use crate::helpers::compress::BodyEncoder;

    fn map_io(e: h1::HttpError) -> std::io::Error {
        std::io::Error::other(e.to_string())
    }
    let mut enc = BodyEncoder::new(spec)?;

    match &response.body {
        StaticBody::Empty => {}
        StaticBody::Bytes(bytes) => {
            let out = enc.push(bytes)?;
            if !out.is_empty() {
                h1::write_chunk(w, &out).await.map_err(map_io)?;
            }
        }
        StaticBody::File { entry, .. } => {
            // Tar entries are backed by an mmap; read the full entry then
            // compress. (Range bodies are never routed here.)
            let bytes = crate::shared::read_tar_entry(entry.clone(), &response.site).await?;
            let out = enc.push(&bytes)?;
            if !out.is_empty() {
                h1::write_chunk(w, &out).await.map_err(map_io)?;
            }
        }
        StaticBody::FsFile { path, size, .. } => {
            let file = monoio::fs::File::open(path).await?;
            let chunk_size = shared.config.chunk_size;
            let mut remaining = *size;
            let mut offset = 0u64;
            let mut buffer = vec![0u8; chunk_size];
            while remaining > 0 {
                let read_len = remaining.min(chunk_size as u64) as usize;
                let view = monoio::buf::SliceMut::new(buffer, 0, read_len);
                let (res, view) = file.read_at(view, offset).await;
                buffer = view.into_inner();
                let n = res?;
                if n == 0 {
                    return Err(std::io::Error::from(std::io::ErrorKind::InvalidData));
                }
                let out = enc.push(&buffer[..n])?;
                if !out.is_empty() {
                    h1::write_chunk(w, &out).await.map_err(map_io)?;
                    let _ = w.flush().await;
                }
                remaining -= n as u64;
                offset += n as u64;
            }
        }
    }

    let tail = enc.finish()?;
    if !tail.is_empty() {
        h1::write_chunk(w, &tail).await.map_err(map_io)?;
    }
    h1::write_chunk_end(w).await.map_err(map_io)?;
    Ok(())
}

async fn serve_static(
    head: &RequestHead,
    shared: &Arc<SharedState>,
    head_only: bool,
    peer: std::net::SocketAddr,
    w: &mut impl AsyncWriteRent,
    early_response_headers: Option<&::http::HeaderMap>,
    metadata: &HashMap<String, String>,
    hook_state: Option<&ResponseHookState<'_>>,
    normalized_path: &NormalizedPath,
) -> Option<H1SendOutcome> {
    let response =
        prepare_static_response(head, shared, head_only, metadata, normalized_path).await?;
    Some(
        send_static_response_h1(
            w,
            shared,
            peer,
            response,
            early_response_headers,
            metadata,
            hook_state,
        )
        .await,
    )
}

async fn serve_static_h2(
    head: &RequestHead,
    shared: &Arc<SharedState>,
    head_only: bool,
    respond: &mut h2::server::SendResponse<Bytes>,
    early_response_headers: Option<&::http::HeaderMap>,
    metadata: &HashMap<String, String>,
    hook_state: Option<&ResponseHookState<'_>>,
    normalized_path: &NormalizedPath,
) -> Result<Option<u16>> {
    let response =
        match prepare_static_response(head, shared, head_only, metadata, normalized_path).await {
            Some(response) => response,
            None => return Ok(None),
        };
    let status = send_static_response_h2(
        respond,
        shared,
        response,
        early_response_headers,
        metadata,
        hook_state,
    )
    .await?;
    Ok(Some(status))
}

async fn send_static_response_h2(
    respond: &mut h2::server::SendResponse<Bytes>,
    shared: &Arc<SharedState>,
    mut response: StaticResponse,
    early_response_headers: Option<&::http::HeaderMap>,
    metadata: &HashMap<String, String>,
    hook_state: Option<&ResponseHookState<'_>>,
) -> Result<u16> {
    let hook_outcome = caddy::prepare_static_response_headers(
        &mut response,
        early_response_headers,
        metadata,
        hook_state,
    )
    .await;
    let _ = hook_outcome.continue_request;
    let send_body = status_allows_body(response.status);
    if !send_body {
        strip_no_body_headers(&mut response.headers);
    }
    let status = response.status.as_u16();
    send_prepared_static_response_h2(respond, shared, response, send_body, None).await?;
    Ok(status)
}

async fn send_prepared_static_response_h2(
    respond: &mut h2::server::SendResponse<Bytes>,
    shared: &Arc<SharedState>,
    mut response: StaticResponse,
    send_body: bool,
    encode: Option<&crate::helpers::compress::EncodeState>,
) -> Result<()> {
    strip_hop_headers(&mut response.headers, false);

    // Streaming response compression (Caddy `encode` handler). Range bodies are
    // served uncompressed; full bodies have a known length so the
    // minimum_length gate is exact.
    let body_range_present = matches!(
        &response.body,
        StaticBody::File { range: Some(_), .. } | StaticBody::FsFile { range: Some(_), .. }
    );
    let chosen = if send_body && !response.head_only && !body_range_present {
        encode.and_then(|state| {
            let len = static_body_len(&response.body);
            state.decide(response.status.as_u16(), &response.headers, Some(len))
        })
    } else {
        None
    };
    if let Some(chosen) = &chosen {
        crate::helpers::compress::apply_encoding_headers(&mut response.headers, &chosen.name);
    }

    let mut head = ::http::Response::builder()
        .status(response.status)
        .version(::http::Version::HTTP_2)
        .body(())
        .map_err(|err| anyhow!("failed to build h2 response: {err}"))?;
    *head.headers_mut() = response.headers;

    let body_is_empty = match &response.body {
        StaticBody::Empty => true,
        StaticBody::Bytes(body) => body.is_empty(),
        StaticBody::File { entry, range } => {
            range.map(|range| range.len).unwrap_or(entry.size) == 0
        }
        StaticBody::FsFile { size, range, .. } => {
            range.map(|range| range.len).unwrap_or(*size) == 0
        }
    };
    let end_stream = response.head_only || !send_body || body_is_empty;
    let mut stream = respond.send_response(head, end_stream)?;
    if end_stream {
        return Ok(());
    }

    if let Some(chosen) = chosen {
        return write_static_body_compressed_h2(
            &mut stream,
            shared,
            &response.body,
            &response.site,
            chosen.spec,
        )
        .await;
    }

    match response.body {
        StaticBody::Empty => Ok(()),
        StaticBody::Bytes(body) => send_h2_data(&mut stream, Bytes::from(body), true).await,
        StaticBody::File { entry, range } => {
            stream_tar_entry_h2(
                entry,
                &response.site,
                range,
                shared.config.chunk_size,
                &mut stream,
            )
            .await
        }
        StaticBody::FsFile { path, size, range } => {
            stream_fs_file_h2(
                &path,
                range.map(|range| range.start).unwrap_or(0),
                range.map(|range| range.len).unwrap_or(size),
                shared.config.chunk_size,
                &mut stream,
            )
            .await
        }
    }
}

/// Stream a (non-range) static body over HTTP/2 compressed with `spec`.
async fn write_static_body_compressed_h2(
    stream: &mut h2::SendStream<Bytes>,
    shared: &Arc<SharedState>,
    body: &StaticBody,
    site: &Arc<crate::site::Site>,
    spec: crate::helpers::compress::EncoderSpec,
) -> Result<()> {
    use crate::helpers::compress::BodyEncoder;
    let mut enc = BodyEncoder::new(spec).map_err(|err| anyhow!("encoder init failed: {err}"))?;
    match body {
        StaticBody::Empty => {}
        StaticBody::Bytes(bytes) => {
            let out = enc
                .push(bytes)
                .map_err(|err| anyhow!("compression failed: {err}"))?;
            if !out.is_empty() {
                send_h2_data(stream, Bytes::from(out), false).await?;
            }
        }
        StaticBody::File { entry, .. } => {
            let bytes = crate::shared::read_tar_entry(entry.clone(), site).await?;
            let out = enc
                .push(&bytes)
                .map_err(|err| anyhow!("compression failed: {err}"))?;
            if !out.is_empty() {
                send_h2_data(stream, Bytes::from(out), false).await?;
            }
        }
        StaticBody::FsFile { path, size, .. } => {
            let file = monoio::fs::File::open(path).await?;
            let chunk_size = shared.config.chunk_size;
            let mut remaining = *size;
            let mut offset = 0u64;
            let mut buffer = vec![0u8; chunk_size];
            while remaining > 0 {
                let read_len = remaining.min(chunk_size as u64) as usize;
                let view = monoio::buf::SliceMut::new(buffer, 0, read_len);
                let (res, view) = file.read_at(view, offset).await;
                buffer = view.into_inner();
                let n = res?;
                if n == 0 {
                    return Err(anyhow!("unexpected EOF reading {}", path.display()));
                }
                let out = enc
                    .push(&buffer[..n])
                    .map_err(|err| anyhow!("compression failed: {err}"))?;
                if !out.is_empty() {
                    send_h2_data(stream, Bytes::from(out), false).await?;
                }
                remaining -= n as u64;
                offset += n as u64;
            }
        }
    }
    let tail = enc
        .finish()
        .map_err(|err| anyhow!("compression finish failed: {err}"))?;
    send_h2_data(stream, Bytes::from(tail), true).await
}

async fn stream_tar_entry_h2(
    entry: Arc<crate::site::TarEntry>,
    site: &Arc<crate::site::Site>,
    range: Option<ByteRange>,
    chunk_size: usize,
    stream: &mut h2::SendStream<Bytes>,
) -> Result<()> {
    let file = crate::shared::get_tar_file(site)?;
    let mut remaining = range.map(|range| range.len).unwrap_or(entry.size);
    let mut offset = entry.offset + range.map(|range| range.start).unwrap_or(0);
    let mut buffer = vec![0u8; chunk_size];
    while remaining > 0 {
        let read_len = remaining.min(chunk_size as u64) as usize;
        let view = monoio::buf::SliceMut::new(buffer, 0, read_len);
        let (res, view) = file.read_at(view, offset).await;
        buffer = view.into_inner();
        let n = res?;
        if n == 0 {
            return Err(anyhow!("h2 static stream failed: empty read"));
        }
        let is_last = remaining == n as u64;
        let data = Bytes::copy_from_slice(&buffer[..n]);
        send_h2_data(stream, data, is_last).await?;
        remaining -= n as u64;
        offset += n as u64;
    }
    Ok(())
}

async fn stream_fs_file_h2(
    path: &Path,
    start: u64,
    len: u64,
    chunk_size: usize,
    stream: &mut h2::SendStream<Bytes>,
) -> Result<()> {
    let file = monoio::fs::File::open(path).await?;
    let mut remaining = len;
    let mut offset = start;
    let mut buffer = vec![0u8; chunk_size];
    while remaining > 0 {
        let read_len = remaining.min(chunk_size as u64) as usize;
        let view = monoio::buf::SliceMut::new(buffer, 0, read_len);
        let (res, view) = file.read_at(view, offset).await;
        buffer = view.into_inner();
        let n = res?;
        if n == 0 {
            return Err(anyhow!("h2 filesystem stream failed: empty read"));
        }
        let is_last = remaining == n as u64;
        let data = Bytes::copy_from_slice(&buffer[..n]);
        send_h2_data(stream, data, is_last).await?;
        remaining -= n as u64;
        offset += n as u64;
    }
    Ok(())
}

fn should_template_replace(content_type: &str, metadata: &HashMap<String, String>) -> bool {
    !metadata.is_empty()
        && (content_type == "text/html"
            || content_type.starts_with("text/html;")
            || content_type == "application/xml")
}

fn apply_template(body: &str, metadata: &HashMap<String, String>) -> String {
    const START_TAG: &str = "<zs-meta>";
    const END_TAG: &str = "</zs-meta>";
    let mut out = String::with_capacity(body.len());
    let mut rest = body;
    while let Some(start) = rest.find(START_TAG) {
        let (before, after_start) = rest.split_at(start);
        out.push_str(before);
        let after_start = &after_start[START_TAG.len()..];
        if let Some(end) = after_start.find(END_TAG) {
            let raw_key = &after_start[..end];
            let key = raw_key.trim();
            if let Some(value) = metadata.get(key) {
                out.push_str(value);
            }
            rest = &after_start[end + END_TAG.len()..];
        } else {
            out.push_str(START_TAG);
            out.push_str(after_start);
            rest = "";
            break;
        }
    }
    out.push_str(rest);
    out
}

fn build_base_headers(content_length: u64, content_type: &str) -> ::http::HeaderMap {
    let mut headers = ::http::HeaderMap::new();
    let length = HeaderValue::from_str(&content_length.to_string())
        .unwrap_or_else(|_| HeaderValue::from_static("0"));
    headers.insert(::http::header::CONTENT_LENGTH, length);
    headers.insert(
        ::http::header::SERVER,
        HeaderValue::from_static(crate::SERVER_HEADER),
    );
    let content_type = HeaderValue::from_str(content_type)
        .unwrap_or_else(|_| HeaderValue::from_static("application/octet-stream"));
    headers.insert(::http::header::CONTENT_TYPE, content_type);
    headers
}

fn if_none_match_matches(headers: &::http::HeaderMap, etag: &str) -> bool {
    // A resource with no entity tag has no concrete validator: it must never
    // match a specific `If-None-Match` tag (only `*`, which matches any current
    // representation). Pass an empty actual tag rather than the `""` that
    // `response_etag_string` would synthesize for an empty etag.
    let actual = if etag.is_empty() {
        String::new()
    } else {
        response_etag_string(etag).unwrap_or_default()
    };
    if_none_match_matches_response(headers, &actual)
}

fn if_none_match_matches_response(headers: &::http::HeaderMap, actual_etag: &str) -> bool {
    let value = match headers.get(::http::header::IF_NONE_MATCH) {
        Some(value) => value,
        None => return false,
    };
    let value = match value.to_str() {
        Ok(value) => value,
        Err(_) => return false,
    };
    if value.trim() == "*" {
        return true;
    }
    if actual_etag.is_empty() {
        return false;
    }
    let mut rest = value;
    loop {
        rest = rest.trim();
        if rest.is_empty() {
            break;
        }
        if let Some(after_comma) = rest.strip_prefix(',') {
            rest = after_comma;
            continue;
        }
        if rest.starts_with('*') {
            return true;
        }
        let Some((candidate, after_candidate)) = scan_entity_tag(rest) else {
            break;
        };
        if etag_weak_match(candidate, actual_etag) {
            return true;
        }
        rest = after_candidate;
    }
    false
}

fn if_match_condition_response(headers: &::http::HeaderMap, actual_etag: &str) -> Option<bool> {
    let value = headers
        .get(::http::header::IF_MATCH)
        .and_then(|value| value.to_str().ok())?;
    if value.trim().is_empty() {
        return None;
    }
    let mut rest = value;
    loop {
        rest = rest.trim();
        if rest.is_empty() {
            break;
        }
        if let Some(after_comma) = rest.strip_prefix(',') {
            rest = after_comma;
            continue;
        }
        if rest.starts_with('*') {
            return Some(true);
        }
        let Some((candidate, after_candidate)) = scan_entity_tag(rest) else {
            break;
        };
        if etag_strong_match(candidate, actual_etag) {
            return Some(true);
        }
        rest = after_candidate;
    }
    Some(false)
}

fn if_unmodified_since_condition(headers: &::http::HeaderMap, last_modified: u64) -> Option<bool> {
    if last_modified == 0 {
        return None;
    }
    let value = headers
        .get(::http::header::IF_UNMODIFIED_SINCE)
        .and_then(|value| value.to_str().ok())?;
    let value = parse_http_date(value)?;
    let last_modified = i64::try_from(last_modified).ok()?;
    Some(last_modified <= value)
}

fn response_etag_string(etag: &str) -> Option<String> {
    etag_header_value(etag).to_str().ok().map(ToOwned::to_owned)
}

fn scan_entity_tag(value: &str) -> Option<(&str, &str)> {
    let value = value.trim();
    let start = if value.starts_with("W/") { 2 } else { 0 };
    let bytes = value.as_bytes();
    if bytes.get(start) != Some(&b'"') {
        return None;
    }
    for idx in (start + 1)..bytes.len() {
        match bytes[idx] {
            b'\x21' | b'\x23'..=b'\x7e' | b'\x80'..=u8::MAX => {}
            b'"' => return Some((&value[..=idx], &value[(idx + 1)..])),
            _ => return None,
        }
    }
    None
}

fn etag_strong_match(candidate: &str, actual: &str) -> bool {
    candidate == actual && actual.starts_with('"')
}

fn etag_weak_match(candidate: &str, actual: &str) -> bool {
    candidate.strip_prefix("W/").unwrap_or(candidate) == actual.strip_prefix("W/").unwrap_or(actual)
}

fn not_modified_by_request(headers: &::http::HeaderMap, etag: &str, last_modified: u64) -> bool {
    if headers.contains_key(::http::header::IF_NONE_MATCH) {
        return if_none_match_matches(headers, etag);
    }
    if_modified_since_matches(headers, last_modified)
}

fn if_modified_since_matches(headers: &::http::HeaderMap, last_modified: u64) -> bool {
    if last_modified == 0 {
        return false;
    }
    let Some(value) = headers
        .get(::http::header::IF_MODIFIED_SINCE)
        .and_then(|value| value.to_str().ok())
    else {
        return false;
    };
    let Some(value) = parse_http_date(value) else {
        return false;
    };
    let Ok(last_modified) = i64::try_from(last_modified) else {
        return false;
    };
    last_modified <= value
}

fn not_modified_headers(etag: &str, last_modified: u64) -> ::http::HeaderMap {
    let mut headers = ::http::HeaderMap::new();
    headers.insert(
        ::http::header::SERVER,
        HeaderValue::from_static(crate::SERVER_HEADER),
    );
    if !etag.is_empty() {
        headers.insert(::http::header::ETAG, etag_header_value(etag));
    }
    // RFC 7232 4.1 / Go's writeNotModified: a 304 carries Last-Modified only as
    // a fallback when there is no ETag. When an ETag is present, omit it.
    if etag.is_empty() {
        insert_last_modified(&mut headers, last_modified);
    }
    headers.insert(
        ::http::header::CONTENT_LENGTH,
        HeaderValue::from_static("0"),
    );
    headers
}

fn precondition_failed_headers(etag: &str, last_modified: u64) -> ::http::HeaderMap {
    let mut headers = ::http::HeaderMap::new();
    headers.insert(
        ::http::header::SERVER,
        HeaderValue::from_static(crate::SERVER_HEADER),
    );
    if !etag.is_empty() {
        headers.insert(::http::header::ETAG, etag_header_value(etag));
    }
    insert_last_modified(&mut headers, last_modified);
    headers.insert(
        ::http::header::CONTENT_LENGTH,
        HeaderValue::from_static("0"),
    );
    headers
}

fn insert_last_modified(headers: &mut ::http::HeaderMap, last_modified: u64) {
    if last_modified == 0 {
        return;
    }
    if let Ok(value) = HeaderValue::from_str(&http_date(last_modified)) {
        headers.insert(::http::header::LAST_MODIFIED, value);
    }
}

fn http_date(secs: u64) -> String {
    match chrono::DateTime::from_timestamp(secs as i64, 0) {
        Some(value) => value.format("%a, %d %b %Y %H:%M:%S GMT").to_string(),
        None => "Thu, 01 Jan 1970 00:00:00 GMT".to_string(),
    }
}

/// Parse an HTTP-date the way Go's `http.ParseTime` (and therefore Caddy) does:
/// accept IMF-fixdate, RFC 850, and ANSI C asctime, and — crucially — ignore the
/// leading day-of-week token rather than validating it against the date. Returns
/// the time as Unix seconds. Using `chrono`'s RFC 2822 parser here would reject
/// otherwise-valid dates whose weekday name does not match the calendar day,
/// which Go accepts.
fn parse_http_date(value: &str) -> Option<i64> {
    use chrono::{NaiveDateTime, TimeZone, Utc};

    fn to_unix(dt: NaiveDateTime) -> i64 {
        Utc.from_utc_datetime(&dt).timestamp()
    }

    let value = value.trim();
    // IMF-fixdate ("Mon, 02 Jan 2006 15:04:05 GMT") and RFC 850
    // ("Monday, 02-Jan-06 15:04:05 GMT") both carry the weekday before a
    // comma; drop it and parse the remainder.
    if let Some((_, rest)) = value.split_once(", ") {
        let rest = rest.trim();
        if let Ok(dt) = NaiveDateTime::parse_from_str(rest, "%d %b %Y %H:%M:%S GMT") {
            return Some(to_unix(dt));
        }
        if let Ok(dt) = NaiveDateTime::parse_from_str(rest, "%d-%b-%y %H:%M:%S GMT") {
            return Some(to_unix(dt));
        }
    }
    // ANSI C asctime ("Mon Jan _2 15:04:05 2006"): weekday is the first
    // space-separated token.
    if let Some((_, rest)) = value.split_once(' ') {
        if let Ok(dt) = NaiveDateTime::parse_from_str(rest.trim_start(), "%b %e %H:%M:%S %Y") {
            return Some(to_unix(dt));
        }
    }
    None
}

fn apply_static_range(
    head: &RequestHead,
    headers: &mut ::http::HeaderMap,
    total: u64,
    etag: &str,
    last_modified: u64,
) -> (StatusCode, Option<ByteRange>) {
    let Some(range) = head.headers.get(::http::header::RANGE) else {
        return (StatusCode::OK, None);
    };
    if !if_range_allows_range(&head.headers, etag, last_modified) {
        return (StatusCode::OK, None);
    }
    let Ok(range) = range.to_str() else {
        return (StatusCode::OK, None);
    };
    let Some(spec) = range.trim().strip_prefix("bytes=") else {
        return (StatusCode::OK, None);
    };
    if spec.contains(',') {
        return (StatusCode::OK, None);
    }
    let Some((start, end)) = spec.split_once('-') else {
        return (StatusCode::OK, None);
    };
    let parsed = if start.is_empty() {
        let Ok(suffix) = end.trim().parse::<u64>() else {
            return (StatusCode::OK, None);
        };
        if suffix == 0 {
            None
        } else if suffix >= total {
            Some((0, total.saturating_sub(1)))
        } else {
            Some((total - suffix, total.saturating_sub(1)))
        }
    } else {
        let Ok(start) = start.trim().parse::<u64>() else {
            return (StatusCode::OK, None);
        };
        let end = if end.trim().is_empty() {
            total.saturating_sub(1)
        } else {
            let Ok(end) = end.trim().parse::<u64>() else {
                return (StatusCode::OK, None);
            };
            end
        };
        Some((start, end))
    };
    let Some((start, end)) = parsed else {
        return unsatisfiable_range(headers, total);
    };
    if total == 0 || start >= total || end < start {
        return unsatisfiable_range(headers, total);
    }
    let end = end.min(total - 1);
    let len = end - start + 1;
    if let Ok(value) = HeaderValue::from_str(&len.to_string()) {
        headers.insert(::http::header::CONTENT_LENGTH, value);
    }
    if let Ok(value) = HeaderValue::from_str(&format!("bytes {start}-{end}/{total}")) {
        headers.insert(::http::header::CONTENT_RANGE, value);
    }
    (StatusCode::PARTIAL_CONTENT, Some(ByteRange { start, len }))
}

fn if_range_allows_range(headers: &::http::HeaderMap, etag: &str, last_modified: u64) -> bool {
    let Some(value) = headers
        .get(::http::header::IF_RANGE)
        .and_then(|value| value.to_str().ok())
    else {
        return true;
    };
    let value = value.trim();
    if value.is_empty() {
        return false;
    }
    if value.starts_with("W/") {
        return false;
    }
    let quoted = format!("\"{etag}\"");
    if !etag.is_empty() && (value == etag || value == quoted) {
        return true;
    }
    if last_modified == 0 {
        return false;
    }
    let Some(value) = parse_http_date(value) else {
        return false;
    };
    let Ok(last_modified) = i64::try_from(last_modified) else {
        return false;
    };
    // RFC 7233: the range is served only when the validator is an exact match.
    // Go's `checkIfRange` compares the dates for equality (not "not modified
    // since"), so a date that merely post-dates the file still drops the range.
    last_modified == value
}

fn unsatisfiable_range(
    headers: &mut ::http::HeaderMap,
    total: u64,
) -> (StatusCode, Option<ByteRange>) {
    set_unsatisfiable_range(headers, total);
    (
        StatusCode::RANGE_NOT_SATISFIABLE,
        Some(ByteRange { start: 0, len: 0 }),
    )
}

fn set_unsatisfiable_range(headers: &mut ::http::HeaderMap, total: u64) {
    headers.insert(
        ::http::header::CONTENT_LENGTH,
        HeaderValue::from_static("0"),
    );
    if let Ok(value) = HeaderValue::from_str(&format!("bytes */{total}")) {
        headers.insert(::http::header::CONTENT_RANGE, value);
    }
}

/// Outcome of evaluating a `Range` request the way Go's `http.ServeContent`
/// (and therefore Caddy's file server) does — minus multi-range support.
enum CaddyRangeOutcome {
    /// Serve the whole body unchanged (no range, ignored range, empty file, or
    /// an unsupported multi-range request).
    Full,
    /// `206 Partial Content` with a single content range.
    Single(ByteRange),
    /// `416 Range Not Satisfiable`; the bytes are the error message body.
    Unsatisfiable(Vec<u8>),
}

enum RangeParse {
    /// Malformed syntax → `416` with no `Content-Range`.
    Invalid,
    /// All ranges fell beyond the file → `416` with `Content-Range: bytes */N`.
    NoOverlap,
    /// Parsed (possibly empty) set of satisfiable `(start, len)` ranges.
    Ranges(Vec<(u64, u64)>),
}

/// Parse the portion of a `Range` header after `bytes=`, replicating Go's
/// `net/http.parseRange` byte-for-byte (including its handling of suffix ranges,
/// out-of-range starts, and clamping).
fn parse_byte_range_spec(spec: &str, size: u64) -> RangeParse {
    let mut ranges: Vec<(u64, u64)> = Vec::new();
    let mut no_overlap = false;
    for raw in spec.split(',') {
        let ra = raw.trim();
        if ra.is_empty() {
            continue;
        }
        let Some((start, end)) = ra.split_once('-') else {
            return RangeParse::Invalid;
        };
        let (start, end) = (start.trim(), end.trim());
        if start.is_empty() {
            // suffix-length form: bytes=-N
            if end.is_empty() || end.starts_with('-') {
                return RangeParse::Invalid;
            }
            let Ok(mut i) = end.parse::<u64>() else {
                return RangeParse::Invalid;
            };
            if i > size {
                i = size;
            }
            let r_start = size - i;
            ranges.push((r_start, size - r_start));
        } else {
            let Ok(i) = start.parse::<u64>() else {
                return RangeParse::Invalid;
            };
            if i >= size {
                // Begins at or beyond the end of the content: does not overlap.
                no_overlap = true;
                continue;
            }
            let r_len = if end.is_empty() {
                size - i
            } else {
                let Ok(mut j) = end.parse::<u64>() else {
                    return RangeParse::Invalid;
                };
                if i > j {
                    return RangeParse::Invalid;
                }
                if j >= size {
                    j = size - 1;
                }
                j - i + 1
            };
            ranges.push((i, r_len));
        }
    }
    if no_overlap && ranges.is_empty() {
        return RangeParse::NoOverlap;
    }
    RangeParse::Ranges(ranges)
}

/// Apply Caddy/Go `http.ServeContent` range semantics for a single byte range,
/// mutating `headers` to match the chosen outcome. `etag`/`last_modified` gate
/// `If-Range` (pass `""`/`0` for a file without useful validators).
///
/// Multi-range requests are intentionally unsupported: rather than emitting a
/// `multipart/byteranges` body (see CADDY_COMPAT.md), the `Range` header is
/// ignored and the full representation is served with `200 OK`, which RFC 7233
/// section 3.1 explicitly permits.
fn apply_caddy_range(
    head: &RequestHead,
    headers: &mut ::http::HeaderMap,
    size: u64,
    etag: &str,
    last_modified: u64,
) -> CaddyRangeOutcome {
    let Some(range) = head.headers.get(::http::header::RANGE) else {
        return CaddyRangeOutcome::Full;
    };
    // Go only honors Range/If-Range for GET and HEAD.
    if !matches!(head.method, Method::GET | Method::HEAD) {
        return CaddyRangeOutcome::Full;
    }
    if !if_range_allows_range(&head.headers, etag, last_modified) {
        return CaddyRangeOutcome::Full;
    }
    let Ok(range) = range.to_str() else {
        return make_unsatisfiable(headers, b"invalid range\n".to_vec(), None);
    };
    let Some(spec) = range.trim().strip_prefix("bytes=") else {
        return make_unsatisfiable(headers, b"invalid range\n".to_vec(), None);
    };
    match parse_byte_range_spec(spec, size) {
        RangeParse::Invalid => make_unsatisfiable(headers, b"invalid range\n".to_vec(), None),
        RangeParse::NoOverlap => {
            if size == 0 {
                // Some clients add a Range to every request; for an empty file
                // ignore it and serve 200 rather than 416 (matches Go).
                CaddyRangeOutcome::Full
            } else {
                make_unsatisfiable(
                    headers,
                    b"invalid range: failed to overlap\n".to_vec(),
                    Some(size),
                )
            }
        }
        RangeParse::Ranges(ranges) => {
            if ranges.is_empty() {
                return CaddyRangeOutcome::Full;
            }
            let sum: u64 = ranges.iter().map(|(_, len)| *len).sum();
            if sum > size {
                // The ranges total more than the file: likely an attack or a
                // confused client. Ignore the range and serve the whole body.
                return CaddyRangeOutcome::Full;
            }
            if ranges.len() == 1 {
                let (start, len) = ranges[0];
                let end = start as i64 + len as i64 - 1;
                if let Ok(value) = HeaderValue::from_str(&len.to_string()) {
                    headers.insert(::http::header::CONTENT_LENGTH, value);
                }
                if let Ok(value) = HeaderValue::from_str(&format!("bytes {start}-{end}/{size}")) {
                    headers.insert(::http::header::CONTENT_RANGE, value);
                }
                CaddyRangeOutcome::Single(ByteRange { start, len })
            } else {
                // Multiple ranges would require a multipart/byteranges body,
                // which zeroserve does not generate. Ignore the Range header
                // and serve the full representation (RFC 7233 section 3.1).
                CaddyRangeOutcome::Full
            }
        }
    }
}

/// Rewrite `headers` for a `416` error body the way Go's `serveError`/`Error` do:
/// drop validators, encoding, and cache headers; force the `text/plain` content
/// type plus `nosniff`; and set or clear `Content-Range`.
fn make_unsatisfiable(
    headers: &mut ::http::HeaderMap,
    body: Vec<u8>,
    content_range_total: Option<u64>,
) -> CaddyRangeOutcome {
    headers.remove(::http::header::ETAG);
    headers.remove(::http::header::LAST_MODIFIED);
    headers.remove(::http::header::ACCEPT_RANGES);
    headers.remove(::http::header::CONTENT_ENCODING);
    headers.remove(::http::header::CACHE_CONTROL);
    headers.insert(
        ::http::header::CONTENT_TYPE,
        HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    headers.insert(
        ::http::header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    match content_range_total {
        Some(total) => {
            if let Ok(value) = HeaderValue::from_str(&format!("bytes */{total}")) {
                headers.insert(::http::header::CONTENT_RANGE, value);
            }
        }
        None => {
            headers.remove(::http::header::CONTENT_RANGE);
        }
    }
    if let Ok(value) = HeaderValue::from_str(&body.len().to_string()) {
        headers.insert(::http::header::CONTENT_LENGTH, value);
    }
    CaddyRangeOutcome::Unsatisfiable(body)
}

fn etag_header_value(etag: &str) -> HeaderValue {
    if is_entity_tag_header_value(etag) {
        return HeaderValue::from_str(etag).unwrap_or_else(|_| HeaderValue::from_static("\"\""));
    }
    let mut value = String::with_capacity(etag.len() + 2);
    value.push('"');
    value.push_str(etag);
    value.push('"');
    HeaderValue::from_str(&value).unwrap_or_else(|_| HeaderValue::from_static("\"\""))
}

fn is_entity_tag_header_value(value: &str) -> bool {
    (value.starts_with('"') || value.starts_with("W/\"")) && value.ends_with('"')
}

fn build_script_request(
    request_id: RequestId,
    head: &RequestHead,
    peer: std::net::SocketAddr,
    local: std::net::SocketAddr,
    scheme: Scheme,
    normalized_path: &NormalizedPath,
    transfer_encodings: Vec<String>,
    connection: ConnectionInfo,
) -> ScriptRequest {
    let mut headers = HashMap::with_capacity(head.headers.len());
    let mut header_values = HashMap::<String, Vec<String>>::with_capacity(head.headers.len());
    for (name, value) in head.headers.iter() {
        let Ok(value) = value.to_str() else {
            continue;
        };
        let lower_name = name.as_str().to_ascii_lowercase();
        let value = value.to_string();
        headers.insert(lower_name.clone(), value.clone());
        header_values.entry(lower_name).or_default().push(value);
    }

    // Convert NormalizedPath to sanitized + urlencoded path string (with leading /).
    // Script matchers/placeholders need to preserve the trailing slash hint.
    let encoded_path = normalized_path.encoded_path_with_dir_hint();

    let query = head.uri.query().unwrap_or("").to_string();
    let mut query_param_values = HashMap::new();
    if !query.is_empty() {
        for (key, value) in url::form_urlencoded::parse(query.as_bytes()) {
            query_param_values
                .entry(key.into_owned())
                .or_insert_with(Vec::new)
                .push(value.into_owned());
        }
    }
    let query_params = query_param_values
        .iter()
        .filter_map(|(key, values)| values.first().map(|value| (key.clone(), value.clone())))
        .collect();

    // Build URI from re-encoded normalized path + original query
    let uri = match head.uri.query() {
        Some(q) => format!("{}?{}", encoded_path, q),
        None => encoded_path.clone(),
    };
    let (proto_major, proto_minor) = match head.version {
        ::http::Version::HTTP_09 => (0, 9),
        ::http::Version::HTTP_10 => (1, 0),
        ::http::Version::HTTP_11 => (1, 1),
        ::http::Version::HTTP_2 => (2, 0),
        ::http::Version::HTTP_3 => (3, 0),
        _ => (0, 0),
    };

    let mut request = ScriptRequest {
        request_id,
        start_time: std::time::Instant::now(),
        method: head.method.as_str().to_string(),
        original_method: head.method.as_str().to_string(),
        path: encoded_path.clone(),
        original_path: encoded_path,
        normalized_path: normalized_path.relative().to_string(),
        uri: uri.clone(),
        original_uri: uri,
        query: query.clone(),
        original_query: query,
        scheme: scheme.as_str().to_string(),
        proto_major,
        proto_minor,
        peer: peer.to_string(),
        local: local.to_string(),
        headers,
        header_values,
        transfer_encodings,
        query_params,
        query_param_values,
        caddy_query_params: HashMap::new(),
        caddy_query_valid: true,
        connection,
        proxy_method: None,
        proxy_uri: None,
        proxy_headers: None,
        uri_changed: false,
        method_changed: false,
        header_changes: Vec::new(),
    };
    caddy::populate_request_fields(&mut request);
    request
}

fn apply_script_request(head: &mut RequestHead, request: &ScriptRequest) -> Result<()> {
    if request.method_changed() {
        head.method = Method::from_bytes(request.method.as_bytes())
            .map_err(|err| anyhow!("invalid script method: {err}"))?;
    }

    if request.uri_changed() {
        caddy::apply_request_uri(head, request)?;
    }

    if request.header_changes().is_empty() {
        return Ok(());
    }

    for change in request.header_changes() {
        match change {
            HeaderChange::Set(name, value) => {
                let Ok(header_name) = HeaderName::from_bytes(name.as_bytes()) else {
                    continue;
                };
                let Ok(header_value) = HeaderValue::from_str(value) else {
                    continue;
                };
                head.headers.insert(header_name, header_value);
            }
            HeaderChange::Append(name, value) => {
                let Ok(header_name) = HeaderName::from_bytes(name.as_bytes()) else {
                    continue;
                };
                let Ok(header_value) = HeaderValue::from_str(value) else {
                    continue;
                };
                head.headers.append(header_name, header_value);
            }
            HeaderChange::Remove(name) => {
                let Ok(header_name) = HeaderName::from_bytes(name.as_bytes()) else {
                    continue;
                };
                head.headers.remove(&header_name);
            }
            HeaderChange::RemovePattern(pattern) => {
                let names = head
                    .headers
                    .keys()
                    .filter(|name| header_pattern_matches(name.as_str(), pattern))
                    .cloned()
                    .collect::<Vec<_>>();
                for name in names {
                    head.headers.remove(name);
                }
            }
            HeaderChange::Clear => {
                head.headers.clear();
            }
        }
    }
    Ok(())
}

fn normalized_script_request_path(request: &ScriptRequest) -> Option<NormalizedPath> {
    normalize_request_path(&request.path)
}

async fn send_script_response(
    w: &mut impl AsyncWriteRent,
    response: ScriptResponse,
    head_only: bool,
    metadata: &HashMap<String, String>,
    hook_state: Option<&ResponseHookState<'_>>,
    encode: Option<&crate::helpers::compress::EncodeState>,
) -> H1SendOutcome {
    let mut status = if (100..=999).contains(&response.status) {
        response.status
    } else {
        StatusCode::INTERNAL_SERVER_ERROR.as_u16()
    };
    let mut headers = response
        .content_type
        .as_deref()
        .map(|content_type| build_base_headers(response.body.len() as u64, content_type))
        .unwrap_or_else(|| {
            let mut headers = ::http::HeaderMap::new();
            if let Ok(value) = ::http::HeaderValue::from_str(&response.body.len().to_string()) {
                headers.insert(::http::header::CONTENT_LENGTH, value);
            }
            headers
        });
    append_script_response_headers(&mut headers, &response.headers);
    let mut body = response.body;
    status =
        caddy::prepare_script_response_raw_h1_headers(status, &mut headers, metadata, hook_state)
            .await
            .status;
    let send_body = raw_status_allows_body(status);
    if !send_body {
        strip_no_body_headers(&mut headers);
    }
    // Streaming response compression (Caddy `encode` handler). The body is
    // fully buffered here, so we compress it in one shot and report the exact
    // compressed length. On HEAD we still advertise the encoding but send no
    // body, matching Caddy.
    let mut encoded = false;
    if send_body && let Some(state) = encode {
        if let Some(chosen) = state.decide(status, &headers, Some(body.len() as u64)) {
            if head_only {
                crate::helpers::compress::apply_encoding_headers(&mut headers, &chosen.name);
                encoded = true;
            } else if let Ok(compressed) =
                crate::helpers::compress::BodyEncoder::compress_buffer(chosen.spec, &body)
            {
                crate::helpers::compress::apply_encoding_headers(&mut headers, &chosen.name);
                if let Ok(value) = ::http::HeaderValue::from_str(&compressed.len().to_string()) {
                    headers.insert(::http::header::CONTENT_LENGTH, value);
                }
                body = compressed;
                encoded = true;
            }
        }
    }
    if !encoded
        && !headers.contains_key(::http::header::CONTENT_LENGTH)
        && !headers.contains_key(::http::header::TRANSFER_ENCODING)
        && send_body
    {
        if let Ok(value) = ::http::HeaderValue::from_str(&body.len().to_string()) {
            headers.insert(::http::header::CONTENT_LENGTH, value);
        }
    }
    let continue_conn = !response.force_close && !connection_has_close(&headers);
    if !head_only && send_body && !body.is_empty() {
        let _ = write_response_head_and_body_raw(w, status, &headers, body).await;
    } else {
        let _ = write_response_head_raw(w, status, &headers).await;
    }
    let _ = w.flush().await;
    H1SendOutcome {
        keep_client: continue_conn,
        status,
    }
}

/// Append helper-provided response headers (`ScriptResponse::headers`) onto a
/// response. `Content-Type` and `Content-Length` replace the defaults;
/// everything else is appended so repeated names such as `Set-Cookie` are all
/// emitted.
fn append_script_response_headers(headers: &mut ::http::HeaderMap, extra: &[(String, String)]) {
    for (name, value) in extra {
        let Ok(header_name) = HeaderName::from_bytes(name.as_bytes()) else {
            continue;
        };
        let Ok(header_value) = HeaderValue::from_str(value) else {
            continue;
        };
        if header_name == ::http::header::CONTENT_TYPE
            || header_name == ::http::header::CONTENT_LENGTH
        {
            headers.insert(header_name, header_value);
        } else {
            headers.append(header_name, header_value);
        }
    }
}

async fn reverse_proxy_request(
    backend_url: &str,
    mut head: RequestHead,
    mut body: HttpBody,
    reader: &mut h1::H1Connection<impl AsyncReadRent>,
    w: &mut impl AsyncWriteRent,
    head_only: bool,
    peer: std::net::SocketAddr,
    scheme: Scheme,
    early_response_headers: Option<&::http::HeaderMap>,
    metadata: &HashMap<String, String>,
    hook_state: Option<&ResponseHookState<'_>>,
    proxy_method: Option<&str>,
    proxy_uri: Option<&str>,
    proxy_headers: Option<&::http::HeaderMap>,
    request_body_limit: Option<usize>,
    caddy_reverse_proxy: bool,
    caddy_default_forwarded: bool,
    encode: Option<&crate::helpers::compress::EncodeState>,
) -> Result<ProxyOutcome> {
    let target = match cached_backend_target(backend_url) {
        Ok(target) => target,
        Err(err) => {
            drain_payload(reader, &mut body).await;
            return Err(err);
        }
    };
    if let Some(method) = proxy_method {
        head.method = Method::from_bytes(method.as_bytes())
            .map_err(|err| anyhow!("invalid proxy method override: {err}"))?;
    }
    let send_request_body = !matches!(head.method, Method::GET | Method::HEAD)
        && !matches!(proxy_method, Some("GET" | "HEAD"));
    if let Some(uri) = proxy_uri {
        head.uri = uri
            .parse()
            .map_err(|err| anyhow!("invalid proxy uri override: {err}"))?;
    }
    let uri = match build_backend_uri(&target, &head.uri) {
        Ok(uri) => uri,
        Err(err) => {
            drain_payload(reader, &mut body).await;
            return Err(err);
        }
    };
    if send_request_body && request_body_content_length_exceeds(&head.headers, request_body_limit) {
        drain_payload(reader, &mut body).await;
        return Ok(ProxyOutcome {
            reuse_backend: false,
            send: send_fixed(
                w,
                payload_too_large(),
                early_response_headers,
                metadata,
                hook_state,
            )
            .await,
            continue_request: false,
            preserved_body: None,
        });
    }

    if matches!(target.scheme, BackendScheme::Iroh) {
        head.uri = uri;
        return reverse_proxy_iroh_request(
            &target,
            head,
            body,
            reader,
            w,
            head_only,
            peer,
            scheme,
            early_response_headers,
            metadata,
            hook_state,
            proxy_headers,
            request_body_limit,
            caddy_reverse_proxy,
            caddy_default_forwarded,
        )
        .await;
    }

    let is_ws_request = h1::is_websocket_upgrade_request(&head);
    if can_use_simple_proxy_fast_path(
        &head,
        &body,
        is_ws_request,
        early_response_headers,
        metadata,
        hook_state,
        proxy_method,
        proxy_uri,
        proxy_headers,
        encode,
    ) {
        return match reverse_proxy_simple_request(
            backend_url,
            &head,
            w,
            head_only,
            peer,
            scheme,
            caddy_uses_default_forwarded(metadata, hook_state, caddy_default_forwarded),
        )
        .await
        {
            Ok(outcome) => Ok(outcome),
            Err(err) => {
                drain_payload(reader, &mut body).await;
                Err(err)
            }
        };
    }
    let mut headers = proxy_headers.cloned().unwrap_or(head.headers);
    caddy::prepare_reverse_proxy_request_headers_h1(
        &mut headers,
        if send_request_body {
            &body
        } else {
            &h1::Body::None
        },
        is_ws_request,
        peer,
        scheme,
        metadata,
        hook_state,
        caddy_reverse_proxy,
        caddy_default_forwarded,
    );

    head.uri = uri;
    head.headers = headers;
    head.version = ::http::Version::HTTP_11;

    let pool_key = target.pool_key();
    let mut conn = match pool::take_connection(&pool_key) {
        Some(conn) => conn,
        None => match connect_backend(&target).await {
            Ok(conn) => conn,
            Err(err) => {
                drain_payload(reader, &mut body).await;
                return Err(err);
            }
        },
    };

    let outcome = match &mut conn {
        PooledConnection::Http(codec) => {
            proxy_over_connection(
                codec,
                head,
                body,
                reader,
                w,
                head_only,
                early_response_headers,
                metadata,
                hook_state,
                is_ws_request,
                send_request_body,
                request_body_limit,
                encode,
            )
            .await?
        }
        PooledConnection::Https(codec) => {
            proxy_over_connection(
                codec,
                head,
                body,
                reader,
                w,
                head_only,
                early_response_headers,
                metadata,
                hook_state,
                is_ws_request,
                send_request_body,
                request_body_limit,
                encode,
            )
            .await?
        }
        PooledConnection::Unix(codec) => {
            proxy_over_connection(
                codec,
                head,
                body,
                reader,
                w,
                head_only,
                early_response_headers,
                metadata,
                hook_state,
                is_ws_request,
                send_request_body,
                request_body_limit,
                encode,
            )
            .await?
        }
    };

    if outcome.reuse_backend {
        pool::return_connection(pool_key, conn);
    }

    Ok(outcome)
}

async fn reverse_proxy_simple_request(
    backend_url: &str,
    head: &RequestHead,
    w: &mut impl AsyncWriteRent,
    _head_only: bool,
    peer: std::net::SocketAddr,
    scheme: Scheme,
    caddy_default_forwarded: bool,
) -> Result<ProxyOutcome> {
    let target = cached_backend_target(backend_url)?;
    let request_head =
        encode_simple_proxy_request_head(head, &target, peer, scheme, caddy_default_forwarded)?;
    let pool_key = target.pool_key();
    let mut conn = match pool::take_connection(&pool_key) {
        Some(conn) => conn,
        None => connect_backend(&target).await?,
    };
    let outcome = match &mut conn {
        PooledConnection::Http(codec) => {
            proxy_simple_over_connection(codec, request_head, w).await?
        }
        PooledConnection::Https(codec) => {
            proxy_simple_over_connection(codec, request_head, w).await?
        }
        PooledConnection::Unix(codec) => {
            proxy_simple_over_connection(codec, request_head, w).await?
        }
    };
    if outcome.reuse_backend {
        pool::return_connection(pool_key, conn);
    }
    Ok(outcome)
}

fn can_use_simple_proxy_fast_path(
    head: &RequestHead,
    body: &HttpBody,
    is_ws_request: bool,
    early_response_headers: Option<&::http::HeaderMap>,
    metadata: &HashMap<String, String>,
    hook_state: Option<&ResponseHookState<'_>>,
    proxy_method: Option<&str>,
    proxy_uri: Option<&str>,
    proxy_headers: Option<&::http::HeaderMap>,
    encode: Option<&crate::helpers::compress::EncodeState>,
) -> bool {
    matches!(head.method, Method::GET)
        && matches!(body.hint(), StreamHint::None)
        && !is_ws_request
        && proxy_method.is_none()
        && proxy_uri.is_none()
        && proxy_headers.is_none()
        && can_use_raw_fixed_proxy_response(
            early_response_headers,
            metadata,
            hook_state,
            false,
            false,
            encode,
        )
}

async fn proxy_simple_over_connection<IO>(
    conn: &mut h1::H1Connection<IO>,
    request_head: Vec<u8>,
    w: &mut impl AsyncWriteRent,
) -> Result<ProxyOutcome>
where
    IO: AsyncReadRent + AsyncWriteRent,
{
    let (res, _) = conn
        .io_mut()
        .map_err(|err| anyhow!("proxy backend missing io: {err}"))?
        .write_all(request_head)
        .await;
    res.map_err(|err| anyhow!("failed to send proxy request head: {err}"))?;

    let response = match conn.next_response_fast().await {
        Ok(Some(h1::ResponseRead::RawFixed(raw))) => {
            let status = raw.status;
            let can_reuse = raw.can_reuse;
            let mut head = raw.head;
            let mut body = raw.body;
            collect_proxy_body_into(conn, &mut body, &mut head).await?;
            write_raw_response(w, head).await?;
            let _ = w.flush().await;
            return Ok(ProxyOutcome {
                reuse_backend: can_reuse,
                send: H1SendOutcome {
                    keep_client: true,
                    status,
                },
                continue_request: false,
                preserved_body: None,
            });
        }
        Ok(Some(h1::ResponseRead::Parsed(resp))) => resp,
        Ok(None) => return Err(anyhow!("proxy backend closed without response")),
        Err(err) => return Err(anyhow!("failed to read proxy response: {err}")),
    };

    let (resp_head, mut resp_body) = response.into_parts();
    let status = resp_head.status.as_u16();
    let can_reuse = should_reuse_proxy_connection(resp_head.version, &resp_head.headers);
    let mut headers = resp_head.headers;
    strip_hop_headers(&mut headers, false);
    let body_hint = resp_body.hint();
    let send_body = should_send_proxy_body_raw(status, body_hint, false);
    if send_body {
        apply_proxy_response_headers(&mut headers, body_hint, send_body);
    } else if !raw_status_allows_body(status) {
        strip_no_body_headers(&mut headers);
    } else {
        apply_proxy_response_headers(&mut headers, body_hint, send_body);
    }
    write_response_head_raw(w, status, &headers).await?;
    if send_body {
        forward_proxy_body(w, conn, &mut resp_body).await?;
    } else {
        drain_proxy_payload(conn, &mut resp_body).await?;
    }
    let _ = w.flush().await;
    Ok(ProxyOutcome {
        reuse_backend: can_reuse,
        send: H1SendOutcome {
            keep_client: true,
            status,
        },
        continue_request: false,
        preserved_body: None,
    })
}

fn caddy_uses_default_forwarded(
    metadata: &HashMap<String, String>,
    hook_state: Option<&ResponseHookState<'_>>,
    caddy_default_forwarded: bool,
) -> bool {
    caddy::reverse_proxy_uses_default_forwarded(metadata, hook_state, caddy_default_forwarded)
}

fn encode_simple_proxy_request_head(
    head: &RequestHead,
    target: &BackendTarget,
    peer: std::net::SocketAddr,
    scheme: Scheme,
    caddy_default_forwarded: bool,
) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(512);
    out.extend_from_slice(head.method.as_str().as_bytes());
    out.extend_from_slice(b" ");
    append_backend_uri(&mut out, target, &head.uri);
    out.extend_from_slice(b" HTTP/1.1\r\n");
    for (name, value) in head.headers.iter() {
        let name_str = name.as_str();
        if is_simple_proxy_skip_request_header(name_str, caddy_default_forwarded) {
            continue;
        }
        if name_str.eq_ignore_ascii_case("te")
            && !value.to_str().ok().is_some_and(|value| {
                value
                    .split(',')
                    .any(|part| part.trim().eq_ignore_ascii_case("trailers"))
            })
        {
            continue;
        }
        out.extend_from_slice(name_str.as_bytes());
        out.extend_from_slice(b": ");
        if name_str.eq_ignore_ascii_case("te") {
            out.extend_from_slice(b"trailers");
        } else {
            out.extend_from_slice(value.as_bytes());
        }
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(b"x-forwarded-for: ");
    let _ = write!(&mut out, "{}", peer.ip());
    out.extend_from_slice(b"\r\nx-forwarded-proto: ");
    out.extend_from_slice(scheme.as_str().as_bytes());
    out.extend_from_slice(b"\r\nx-forwarded-host: ");
    if let Some(host) = head
        .headers
        .get(::http::header::HOST)
        .and_then(|value| value.to_str().ok())
    {
        out.extend_from_slice(host.as_bytes());
    }
    out.extend_from_slice(b"\r\n\r\n");
    Ok(out)
}

fn append_backend_uri(out: &mut Vec<u8>, target: &BackendTarget, req_uri: &Uri) {
    let base = target.base_path.trim_end_matches('/');
    let req_path = req_uri.path();
    let req_path = if req_path.is_empty() { "/" } else { req_path };
    if base.is_empty() || base == "/" {
        out.extend_from_slice(req_path.as_bytes());
    } else {
        out.extend_from_slice(base.as_bytes());
        out.extend_from_slice(b"/");
        out.extend_from_slice(req_path.trim_start_matches('/').as_bytes());
    }
    match (target.base_query.as_deref(), req_uri.query()) {
        (Some(base), Some(extra)) if !base.is_empty() && !extra.is_empty() => {
            out.extend_from_slice(b"?");
            out.extend_from_slice(base.as_bytes());
            out.extend_from_slice(b"&");
            out.extend_from_slice(extra.as_bytes());
        }
        (Some(base), _) if !base.is_empty() => {
            out.extend_from_slice(b"?");
            out.extend_from_slice(base.as_bytes());
        }
        (_, Some(extra)) if !extra.is_empty() => {
            out.extend_from_slice(b"?");
            out.extend_from_slice(extra.as_bytes());
        }
        _ => {}
    }
}

fn is_simple_proxy_skip_request_header(name: &str, caddy_default_forwarded: bool) -> bool {
    name.eq_ignore_ascii_case("alt-svc")
        || name.eq_ignore_ascii_case("connection")
        || name.eq_ignore_ascii_case("proxy-connection")
        || name.eq_ignore_ascii_case("proxy-authenticate")
        || name.eq_ignore_ascii_case("proxy-authorization")
        || name.eq_ignore_ascii_case("keep-alive")
        || name.eq_ignore_ascii_case("trailer")
        || name.eq_ignore_ascii_case("transfer-encoding")
        || name.eq_ignore_ascii_case("upgrade")
        || name.eq_ignore_ascii_case("content-length")
        || (caddy_default_forwarded
            && (name.eq_ignore_ascii_case("x-forwarded-for")
                || name.eq_ignore_ascii_case("x-forwarded-proto")
                || name.eq_ignore_ascii_case("x-forwarded-host")))
}

struct H2ProxyOutcome {
    continue_request: bool,
    preserved_body: Option<h2::RecvStream>,
    status: Option<u16>,
}

async fn reverse_proxy_request_h2(
    backend_url: &str,
    mut head: RequestHead,
    body: h2::RecvStream,
    respond: &mut h2::server::SendResponse<Bytes>,
    head_only: bool,
    peer: std::net::SocketAddr,
    scheme: Scheme,
    early_response_headers: Option<&::http::HeaderMap>,
    metadata: &HashMap<String, String>,
    hook_state: Option<&ResponseHookState<'_>>,
    proxy_method: Option<&str>,
    proxy_uri: Option<&str>,
    proxy_headers: Option<&::http::HeaderMap>,
    request_body_limit: Option<usize>,
    caddy_reverse_proxy: bool,
    caddy_default_forwarded: bool,
    encode: Option<&crate::helpers::compress::EncodeState>,
) -> Result<H2ProxyOutcome> {
    let target = match cached_backend_target(backend_url) {
        Ok(target) => target,
        Err(err) => {
            return Err(err);
        }
    };
    if let Some(method) = proxy_method {
        head.method = Method::from_bytes(method.as_bytes())
            .map_err(|err| anyhow!("invalid proxy method override: {err}"))?;
    }
    let send_request_body = !matches!(head.method, Method::GET | Method::HEAD)
        && !matches!(proxy_method, Some("GET" | "HEAD"));
    if let Some(uri) = proxy_uri {
        head.uri = uri
            .parse()
            .map_err(|err| anyhow!("invalid proxy uri override: {err}"))?;
    }
    let uri = match build_backend_uri(&target, &head.uri) {
        Ok(uri) => uri,
        Err(err) => {
            return Err(err);
        }
    };
    if send_request_body && request_body_content_length_exceeds(&head.headers, request_body_limit) {
        let status = send_h2_response(
            respond,
            payload_too_large(),
            head_only,
            early_response_headers,
            metadata,
            hook_state,
        )
        .await?;
        return Ok(H2ProxyOutcome {
            continue_request: false,
            preserved_body: None,
            status: Some(status),
        });
    }

    if matches!(target.scheme, BackendScheme::Iroh) {
        head.uri = uri;
        return reverse_proxy_iroh_request_h2(
            &target,
            head,
            body,
            respond,
            head_only,
            peer,
            scheme,
            early_response_headers,
            metadata,
            hook_state,
            proxy_headers,
            request_body_limit,
            caddy_reverse_proxy,
            caddy_default_forwarded,
        )
        .await;
    }

    let has_body = send_request_body && !body.is_end_stream();
    let mut headers = proxy_headers.cloned().unwrap_or(head.headers);
    let chunked = caddy::prepare_reverse_proxy_request_headers_h2(
        &mut headers,
        has_body,
        peer,
        scheme,
        metadata,
        hook_state,
        caddy_reverse_proxy,
        caddy_default_forwarded,
    );

    head.uri = uri;
    head.headers = headers;
    head.version = ::http::Version::HTTP_11;

    let pool_key = target.pool_key();
    let mut conn = match pool::take_connection(&pool_key) {
        Some(conn) => conn,
        None => match connect_backend(&target).await {
            Ok(conn) => conn,
            Err(err) => {
                return Err(err);
            }
        },
    };

    let outcome = match &mut conn {
        PooledConnection::Http(codec) => {
            proxy_over_connection_h2(
                codec,
                head,
                body,
                respond,
                head_only,
                early_response_headers,
                metadata,
                hook_state,
                chunked,
                send_request_body,
                request_body_limit,
                encode,
            )
            .await?
        }
        PooledConnection::Https(codec) => {
            proxy_over_connection_h2(
                codec,
                head,
                body,
                respond,
                head_only,
                early_response_headers,
                metadata,
                hook_state,
                chunked,
                send_request_body,
                request_body_limit,
                encode,
            )
            .await?
        }
        PooledConnection::Unix(codec) => {
            proxy_over_connection_h2(
                codec,
                head,
                body,
                respond,
                head_only,
                early_response_headers,
                metadata,
                hook_state,
                chunked,
                send_request_body,
                request_body_limit,
                encode,
            )
            .await?
        }
    };

    if outcome.reuse_backend {
        pool::return_connection(pool_key, conn);
    }

    Ok(H2ProxyOutcome {
        continue_request: outcome.continue_request,
        preserved_body: outcome.preserved_body,
        status: outcome.status,
    })
}

async fn reverse_proxy_iroh_request<R>(
    target: &BackendTarget,
    mut head: RequestHead,
    mut body: HttpBody,
    reader: &mut h1::H1Connection<R>,
    w: &mut impl AsyncWriteRent,
    head_only: bool,
    peer: std::net::SocketAddr,
    scheme: Scheme,
    early_response_headers: Option<&::http::HeaderMap>,
    metadata: &HashMap<String, String>,
    hook_state: Option<&ResponseHookState<'_>>,
    proxy_headers: Option<&::http::HeaderMap>,
    request_body_limit: Option<usize>,
    caddy_reverse_proxy: bool,
    caddy_default_forwarded: bool,
) -> Result<ProxyOutcome>
where
    R: AsyncReadRent,
{
    let is_ws_request = h1::is_websocket_upgrade_request(&head);
    let client_connection_close = connection_has_close(&head.headers);
    let send_request_body = !matches!(head.method, Method::GET | Method::HEAD);
    let mut headers = proxy_headers.cloned().unwrap_or(head.headers);
    caddy::prepare_reverse_proxy_request_headers_h1(
        &mut headers,
        if send_request_body {
            &body
        } else {
            &h1::Body::None
        },
        is_ws_request,
        peer,
        scheme,
        metadata,
        hook_state,
        caddy_reverse_proxy,
        caddy_default_forwarded,
    );

    prepare_streaming_iroh_request_headers(
        &mut headers,
        send_request_body,
        &target.host,
        is_ws_request,
    )?;
    head.headers = headers;
    let (mut body_tx, request_body) = crate::iroh_proxy::request_body_channel();
    let fetch = crate::iroh_proxy::start_fetch(IrohProxyRequest {
        target: target
            .iroh
            .clone()
            .ok_or_else(|| anyhow!("iroh backend missing target metadata"))?,
        method: head.method.as_str().to_string(),
        uri: head.uri.to_string(),
        headers: head.headers,
        body: request_body,
    })?;

    if is_ws_request {
        let response = fetch.response().await?;
        if response.upgraded {
            return tunnel_iroh_websocket_h1(
                reader,
                w,
                response,
                body_tx,
                early_response_headers,
                metadata,
                hook_state,
            )
            .await;
        }
        drop(body_tx);
        let send = send_iroh_response_h1(
            w,
            response,
            head_only,
            client_connection_close,
            early_response_headers,
            metadata,
            hook_state,
        )
        .await?;
        return Ok(ProxyOutcome {
            reuse_backend: false,
            send,
            continue_request: false,
            preserved_body: None,
        });
    }

    let mut upload_tx = body_tx.clone();
    let upload = async move {
        if send_request_body {
            stream_h1_request_body_to_iroh(reader, &mut body, &mut upload_tx, request_body_limit)
                .await
        } else {
            drain_payload(reader, &mut body).await;
            Ok(StreamRequestBodyOutcome::Complete)
        }
    };
    let response_send = async {
        let response = fetch.response().await?;
        send_iroh_response_h1(
            w,
            response,
            head_only,
            client_connection_close,
            early_response_headers,
            metadata,
            hook_state,
        )
        .await
    };
    let body_too_large = {
        match future::select(Box::pin(response_send), Box::pin(upload)).await {
            future::Either::Left((send, upload)) => {
                drop(upload);
                drop(body_tx);
                let mut send = send?;
                send.keep_client = false;
                return Ok(ProxyOutcome {
                    reuse_backend: false,
                    send,
                    continue_request: false,
                    preserved_body: None,
                });
            }
            future::Either::Right((upload, response_send)) => match upload? {
                StreamRequestBodyOutcome::Complete => {
                    drop(body_tx);
                    let send = response_send.await?;
                    return Ok(ProxyOutcome {
                        reuse_backend: false,
                        send,
                        continue_request: false,
                        preserved_body: None,
                    });
                }
                StreamRequestBodyOutcome::TooLarge => {
                    drop(response_send);
                    crate::iroh_proxy::send_request_body_error(
                        &mut body_tx,
                        "request body exceeded configured limit".to_string(),
                    )
                    .await;
                    drop(body_tx);
                    true
                }
            },
        }
    };
    if body_too_large {
        let send = send_fixed(
            w,
            payload_too_large(),
            early_response_headers,
            metadata,
            hook_state,
        )
        .await;
        return Ok(ProxyOutcome {
            reuse_backend: false,
            send,
            continue_request: false,
            preserved_body: None,
        });
    }
    unreachable!("iroh proxy body race always returns or reports too-large")
}

async fn tunnel_iroh_websocket_h1<R: AsyncReadRent>(
    reader: &mut h1::H1Connection<R>,
    w: &mut impl AsyncWriteRent,
    mut response: crate::iroh_proxy::IrohProxyResponse,
    body_tx: crate::iroh_proxy::RequestBodySender,
    early_response_headers: Option<&::http::HeaderMap>,
    metadata: &HashMap<String, String>,
    hook_state: Option<&ResponseHookState<'_>>,
) -> Result<ProxyOutcome> {
    let mut headers = response.headers;
    strip_hop_headers(&mut headers, true);
    let hook_outcome = caddy::prepare_reverse_proxy_raw_h1_response_headers(
        hook_state,
        response.status,
        None,
        &mut headers,
        None,
        early_response_headers,
        metadata,
    )
    .await;
    let status = hook_outcome.status;
    write_response_head_raw(w, status, &headers).await?;
    let _ = w.flush().await;

    let (client_io, client_leftover) = reader
        .take_io()
        .ok_or_else(|| anyhow!("client missing io for iroh websocket"))?;
    let client_to_upstream = copy_client_raw_to_iroh(client_io, client_leftover, body_tx);
    let upstream_to_client = copy_iroh_response_body_raw(w, &mut response.body);
    let (res_a, res_b) = futures::future::join(client_to_upstream, upstream_to_client).await;
    res_a?;
    res_b?;
    Ok(ProxyOutcome {
        reuse_backend: false,
        send: H1SendOutcome {
            keep_client: false,
            status,
        },
        continue_request: false,
        preserved_body: None,
    })
}

async fn reverse_proxy_iroh_request_h2(
    target: &BackendTarget,
    mut head: RequestHead,
    mut body: h2::RecvStream,
    respond: &mut h2::server::SendResponse<Bytes>,
    head_only: bool,
    peer: std::net::SocketAddr,
    scheme: Scheme,
    early_response_headers: Option<&::http::HeaderMap>,
    metadata: &HashMap<String, String>,
    hook_state: Option<&ResponseHookState<'_>>,
    proxy_headers: Option<&::http::HeaderMap>,
    request_body_limit: Option<usize>,
    caddy_reverse_proxy: bool,
    caddy_default_forwarded: bool,
) -> Result<H2ProxyOutcome> {
    let send_request_body = !matches!(head.method, Method::GET | Method::HEAD);
    let has_body = send_request_body && !body.is_end_stream();
    let mut headers = proxy_headers.cloned().unwrap_or(head.headers);
    caddy::prepare_reverse_proxy_request_headers_h2(
        &mut headers,
        has_body,
        peer,
        scheme,
        metadata,
        hook_state,
        caddy_reverse_proxy,
        caddy_default_forwarded,
    );

    prepare_streaming_iroh_request_headers(&mut headers, send_request_body, &target.host, false)?;
    head.headers = headers;
    let (mut body_tx, request_body) = crate::iroh_proxy::request_body_channel();
    let fetch = crate::iroh_proxy::start_fetch(IrohProxyRequest {
        target: target
            .iroh
            .clone()
            .ok_or_else(|| anyhow!("iroh backend missing target metadata"))?,
        method: head.method.as_str().to_string(),
        uri: head.uri.to_string(),
        headers: head.headers,
        body: request_body,
    })?;

    let mut upload_tx = body_tx.clone();
    let upload = async move {
        if send_request_body {
            stream_h2_request_body_to_iroh(&mut body, &mut upload_tx, request_body_limit).await
        } else {
            Ok(StreamRequestBodyOutcome::Complete)
        }
    };
    let response_send = async {
        let response = fetch.response().await?;
        let status = response.status.as_u16();
        send_iroh_response_h2(
            respond,
            response,
            head_only,
            early_response_headers,
            metadata,
            hook_state,
        )
        .await?;
        Ok::<u16, anyhow::Error>(status)
    };
    let body_too_large = {
        match future::select(Box::pin(response_send), Box::pin(upload)).await {
            future::Either::Left((status, upload)) => {
                drop(upload);
                drop(body_tx);
                return Ok(H2ProxyOutcome {
                    continue_request: false,
                    preserved_body: None,
                    status: Some(status?),
                });
            }
            future::Either::Right((upload, response_send)) => match upload? {
                StreamRequestBodyOutcome::Complete => {
                    drop(body_tx);
                    let status = response_send.await?;
                    return Ok(H2ProxyOutcome {
                        continue_request: false,
                        preserved_body: None,
                        status: Some(status),
                    });
                }
                StreamRequestBodyOutcome::TooLarge => {
                    drop(response_send);
                    crate::iroh_proxy::send_request_body_error(
                        &mut body_tx,
                        "request body exceeded configured limit".to_string(),
                    )
                    .await;
                    drop(body_tx);
                    true
                }
            },
        }
    };
    if body_too_large {
        let status = send_h2_response(
            respond,
            payload_too_large(),
            head_only,
            early_response_headers,
            metadata,
            hook_state,
        )
        .await?;
        return Ok(H2ProxyOutcome {
            continue_request: false,
            preserved_body: None,
            status: Some(status),
        });
    }
    unreachable!("iroh proxy body race always returns or reports too-large")
}

enum StreamRequestBodyOutcome {
    Complete,
    TooLarge,
}

async fn stream_h1_request_body_to_iroh<R: AsyncReadRent>(
    reader: &mut h1::H1Connection<R>,
    body: &mut h1::Body,
    sender: &mut crate::iroh_proxy::RequestBodySender,
    limit: Option<usize>,
) -> Result<StreamRequestBodyOutcome> {
    let mut bytes_seen = 0usize;
    while let Some(chunk) = body.next_data(reader).await {
        let chunk = chunk.map_err(|err| anyhow!("failed to read request body: {err}"))?;
        bytes_seen = bytes_seen.saturating_add(chunk.len());
        if limit.is_some_and(|limit| bytes_seen > limit) {
            drain_payload(reader, body).await;
            return Ok(StreamRequestBodyOutcome::TooLarge);
        }
        crate::iroh_proxy::send_request_body_chunk(sender, chunk).await?;
    }
    Ok(StreamRequestBodyOutcome::Complete)
}

async fn stream_h2_request_body_to_iroh(
    body: &mut h2::RecvStream,
    sender: &mut crate::iroh_proxy::RequestBodySender,
    limit: Option<usize>,
) -> Result<StreamRequestBodyOutcome> {
    let mut bytes_seen = 0usize;
    while let Some(chunk) = body.data().await {
        let chunk = chunk.map_err(|err| anyhow!("failed to read h2 request body: {err}"))?;
        bytes_seen = bytes_seen.saturating_add(chunk.len());
        if limit.is_some_and(|limit| bytes_seen > limit) {
            return Ok(StreamRequestBodyOutcome::TooLarge);
        }
        body.flow_control()
            .release_capacity(chunk.len())
            .map_err(|err| anyhow!("failed to release h2 request body capacity: {err}"))?;
        crate::iroh_proxy::send_request_body_chunk(sender, chunk).await?;
    }
    Ok(StreamRequestBodyOutcome::Complete)
}

fn prepare_streaming_iroh_request_headers(
    headers: &mut ::http::HeaderMap,
    has_body: bool,
    fallback_host: &str,
    keep_upgrade: bool,
) -> Result<()> {
    strip_hop_headers(headers, keep_upgrade);
    headers.remove(::http::header::TRANSFER_ENCODING);
    if !has_body {
        headers.remove(::http::header::CONTENT_LENGTH);
    }
    if !headers.contains_key(::http::header::HOST) {
        let value = ::http::HeaderValue::from_str(fallback_host)
            .map_err(|err| anyhow!("invalid iroh host header: {err}"))?;
        headers.insert(::http::header::HOST, value);
    }
    Ok(())
}

async fn send_iroh_response_h1(
    w: &mut impl AsyncWriteRent,
    mut response: crate::iroh_proxy::IrohProxyResponse,
    head_only: bool,
    client_connection_close: bool,
    early_response_headers: Option<&::http::HeaderMap>,
    metadata: &HashMap<String, String>,
    hook_state: Option<&ResponseHookState<'_>>,
) -> Result<H1SendOutcome> {
    let mut headers = response.headers;
    strip_hop_headers(&mut headers, false);
    let hook_outcome = caddy::prepare_reverse_proxy_raw_h1_response_headers(
        hook_state,
        response.status,
        None,
        &mut headers,
        None,
        early_response_headers,
        metadata,
    )
    .await;
    let status = hook_outcome.status;
    let send_body = raw_status_allows_body(status) && !head_only;
    if !send_body {
        strip_no_body_headers(&mut headers);
    }

    let chunked = send_body
        && !headers.contains_key(::http::header::CONTENT_LENGTH)
        && !headers.contains_key(::http::header::TRANSFER_ENCODING);
    if chunked {
        headers.insert(
            ::http::header::TRANSFER_ENCODING,
            ::http::HeaderValue::from_static("chunked"),
        );
    }

    write_response_head_raw(w, status, &headers).await?;
    if !send_body {
        drain_iroh_response_body(&mut response.body).await;
        let _ = w.flush().await;
        return Ok(H1SendOutcome {
            keep_client: !client_connection_close && !connection_has_close(&headers),
            status,
        });
    }

    while let Some(chunk) = crate::iroh_proxy::next_response_body_chunk(&mut response.body).await? {
        if chunked {
            h1::write_chunk(w, chunk.as_ref())
                .await
                .map_err(|err| anyhow!("failed to write iroh response chunk: {err}"))?;
        } else {
            let (res, _) = w.write_all(chunk.to_vec()).await;
            res.map_err(|err| anyhow!("failed to write iroh response body: {err}"))?;
        }
    }
    if chunked {
        h1::write_chunk_end(w)
            .await
            .map_err(|err| anyhow!("failed to finish iroh response chunks: {err}"))?;
    }
    let _ = w.flush().await;
    Ok(H1SendOutcome {
        keep_client: !client_connection_close && !connection_has_close(&headers),
        status,
    })
}

async fn send_iroh_response_h2(
    respond: &mut h2::server::SendResponse<Bytes>,
    mut response: crate::iroh_proxy::IrohProxyResponse,
    head_only: bool,
    early_response_headers: Option<&::http::HeaderMap>,
    metadata: &HashMap<String, String>,
    hook_state: Option<&ResponseHookState<'_>>,
) -> Result<()> {
    let mut headers = response.headers;
    strip_hop_headers(&mut headers, false);
    headers.remove(::http::header::TRANSFER_ENCODING);
    let hook_outcome = caddy::prepare_reverse_proxy_response_headers(
        hook_state,
        response.status,
        None,
        &mut headers,
        None,
        early_response_headers,
        metadata,
    )
    .await;
    let status = hook_outcome.status;
    let send_body = status_allows_body(status) && !head_only;
    if !send_body {
        strip_no_body_headers(&mut headers);
    }

    let mut head = ::http::Response::builder()
        .status(status)
        .version(::http::Version::HTTP_2)
        .body(())
        .map_err(|err| anyhow!("failed to build h2 iroh response: {err}"))?;
    *head.headers_mut() = headers;
    let mut next = if send_body {
        crate::iroh_proxy::next_response_body_chunk(&mut response.body).await?
    } else {
        drain_iroh_response_body(&mut response.body).await;
        None
    };
    let end_stream = next.is_none();
    let mut stream = respond.send_response(head, end_stream)?;
    while let Some(chunk) = next {
        next = crate::iroh_proxy::next_response_body_chunk(&mut response.body).await?;
        send_h2_data(&mut stream, chunk, next.is_none()).await?;
    }
    Ok(())
}

async fn drain_iroh_response_body(body: &mut crate::iroh_proxy::ResponseBody) {
    loop {
        match crate::iroh_proxy::next_response_body_chunk(body).await {
            Ok(Some(_)) => continue,
            Ok(None) | Err(_) => return,
        }
    }
}

async fn copy_iroh_response_body_raw(
    w: &mut impl AsyncWriteRent,
    body: &mut crate::iroh_proxy::ResponseBody,
) -> Result<()> {
    while let Some(chunk) = crate::iroh_proxy::next_response_body_chunk(body).await? {
        let (res, _) = w.write_all(chunk.to_vec()).await;
        res.map_err(|err| anyhow!("failed to write iroh tunnel bytes: {err}"))?;
        let _ = w.flush().await;
    }
    Ok(())
}

async fn copy_client_raw_to_iroh<R: AsyncReadRent>(
    mut reader: R,
    pending: Vec<u8>,
    mut sender: crate::iroh_proxy::RequestBodySender,
) -> Result<()> {
    if !pending.is_empty() {
        crate::iroh_proxy::send_request_body_chunk(&mut sender, Bytes::from(pending)).await?;
    }

    let mut buf = vec![0u8; 8 * 1024];
    loop {
        let (res, next_buf) = reader.read(buf).await;
        buf = next_buf;
        let n = res.map_err(|err| anyhow!("failed to read websocket client bytes: {err}"))?;
        if n == 0 {
            drop(sender);
            return Ok(());
        }
        crate::iroh_proxy::send_request_body_chunk(&mut sender, Bytes::copy_from_slice(&buf[..n]))
            .await?;
    }
}

pub(crate) async fn connect_backend(target: &BackendTarget) -> Result<PooledConnection> {
    if matches!(target.scheme, BackendScheme::Iroh) {
        return Err(anyhow!(
            "iroh backends are request-stream transports and cannot use the HTTP/1 connection pool"
        ));
    }
    if matches!(target.scheme, BackendScheme::Unix) {
        return connect_unix_backend(&target.host).await;
    }

    thread_local! {
        static DNS_CACHE: RefCell<mini_moka::unsync::Cache<String, Arc<Vec<SocketAddr>>>> =
            RefCell::new(mini_moka::unsync::CacheBuilder::new(128)
                .time_to_live(Duration::from_secs(60))
                .build());
    }
    let addr = target.authority();
    let addr = match DNS_CACHE.with(|x| x.borrow_mut().get(&addr).cloned()) {
        Some(x) => x,
        None => {
            let (tx, rx) = oneshot::channel();
            DNS_TP.spawn(move || {
                let resolved = addr.to_socket_addrs();
                let _ = tx.send((addr, resolved));
            });
            let (k, v) = rx.await?;
            let v = v
                .with_context(|| "failed to resolve dns name")?
                .into_iter()
                .collect::<Vec<_>>();
            let v = Arc::new(v);
            DNS_CACHE.with(|x| x.borrow_mut().insert(k, v.clone()));
            v
        }
    };
    let stream = TcpStream::connect(&addr[..]).await.and_then(|x| {
        x.set_nodelay(true)?;
        Ok(x)
    });
    let stream = match stream {
        Ok(stream) => stream,
        Err(err) => return Err(anyhow!("failed to connect to backend: {err}")),
    };

    match target.scheme {
        BackendScheme::Http => Ok(PooledConnection::Http(h1::H1Connection::new(stream))),
        BackendScheme::Https => {
            let tls_stream = connect_tls(stream, &target.host).await?;
            Ok(PooledConnection::Https(h1::H1Connection::new(tls_stream)))
        }
        BackendScheme::Unix => unreachable!("unix backend targets are returned before DNS"),
        BackendScheme::Iroh => unreachable!("iroh backend targets are returned before DNS"),
    }
}

async fn connect_unix_backend(path: &str) -> Result<PooledConnection> {
    UnixStream::connect(path)
        .await
        .map(|stream| PooledConnection::Unix(h1::H1Connection::new(stream)))
        .map_err(|err| anyhow!("failed to connect to unix backend {path:?}: {err}"))
}

async fn connect_tls(stream: TcpStream, host: &str) -> Result<BoringStream<TcpStream>> {
    crate::boringtls::client_connect(stream, host)
        .await
        .map_err(|err| anyhow!("TLS handshake failed: {err}"))
}

struct ProxyOutcome {
    reuse_backend: bool,
    send: H1SendOutcome,
    continue_request: bool,
    preserved_body: Option<HttpBody>,
}

async fn proxy_over_connection<IO, R>(
    conn: &mut h1::H1Connection<IO>,
    head: RequestHead,
    mut body: HttpBody,
    reader: &mut h1::H1Connection<R>,
    w: &mut impl AsyncWriteRent,
    head_only: bool,
    early_response_headers: Option<&::http::HeaderMap>,
    metadata: &HashMap<String, String>,
    hook_state: Option<&ResponseHookState<'_>>,
    is_ws_request: bool,
    send_request_body: bool,
    request_body_limit: Option<usize>,
    encode: Option<&crate::helpers::compress::EncodeState>,
) -> Result<ProxyOutcome>
where
    IO: AsyncReadRent + AsyncWriteRent + Split,
    R: AsyncReadRent,
{
    let roundtrip_start = hook_state
        .as_ref()
        .is_some_and(|state| state.has_hooks())
        .then(Instant::now);
    h1::write_request_head(conn.io_mut()?, &head)
        .await
        .map_err(|err| anyhow!("failed to send proxy request head: {err}"))?;
    if send_request_body {
        match forward_request_body(conn, reader, &mut body, request_body_limit).await {
            Ok(()) => {}
            Err(ProxyRequestBodyError::TooLarge) => {
                return Ok(ProxyOutcome {
                    reuse_backend: false,
                    send: send_fixed(
                        w,
                        payload_too_large(),
                        early_response_headers,
                        metadata,
                        hook_state,
                    )
                    .await,
                    continue_request: false,
                    preserved_body: None,
                });
            }
            Err(ProxyRequestBodyError::Other(err)) => {
                return Err(anyhow!("failed to send proxy request body: {err}"));
            }
        }
    }

    let response = if can_use_raw_fixed_proxy_response(
        early_response_headers,
        metadata,
        hook_state,
        is_ws_request,
        head_only,
        encode,
    ) {
        match conn.next_response_fast().await {
            Ok(Some(h1::ResponseRead::RawFixed(raw))) => {
                let status = raw.status;
                let can_reuse = raw.can_reuse;
                let mut head = raw.head;
                let mut body = raw.body;
                collect_proxy_body_into(conn, &mut body, &mut head).await?;
                write_raw_response(w, head).await?;
                let _ = w.flush().await;
                return Ok(ProxyOutcome {
                    reuse_backend: can_reuse,
                    send: H1SendOutcome {
                        keep_client: true,
                        status,
                    },
                    continue_request: false,
                    preserved_body: None,
                });
            }
            Ok(Some(h1::ResponseRead::Parsed(resp))) => resp,
            Ok(None) => return Err(anyhow!("proxy backend closed without response")),
            Err(err) => return Err(anyhow!("failed to read proxy response: {err}")),
        }
    } else {
        match conn.next_response().await {
            Ok(Some(resp)) => resp,
            Ok(None) => return Err(anyhow!("proxy backend closed without response")),
            Err(err) => return Err(anyhow!("failed to read proxy response: {err}")),
        }
    };
    let upstream_latency = roundtrip_start.map(|start| start.elapsed());

    let (resp_head, mut resp_body) = response.into_parts();
    let status = resp_head.status;
    let mut can_reuse = should_reuse_proxy_connection(resp_head.version, &resp_head.headers);
    let is_ws_response = is_ws_request && h1::is_websocket_upgrade_response(&resp_head);
    let mut headers = resp_head.headers;
    if is_ws_response {
        strip_hop_headers(&mut headers, true);
    } else {
        strip_hop_headers(&mut headers, false);
    }
    let body_hint = resp_body.hint();
    let fixed_content_length = if matches!(body_hint, StreamHint::Fixed) {
        headers.get(::http::header::CONTENT_LENGTH).cloned()
    } else {
        None
    };
    if resp_body.is_eof() {
        can_reuse = false;
    }

    if is_ws_response {
        let hook_outcome = caddy::prepare_reverse_proxy_raw_h1_response_headers(
            hook_state,
            status,
            Some(&resp_head.status_text),
            &mut headers,
            upstream_latency,
            early_response_headers,
            metadata,
        )
        .await;
        let raw_status = hook_outcome.status;
        write_response_head_raw(w, raw_status, &headers).await?;
        let _ = w.flush().await;

        let (backend_io, backend_leftover) = conn
            .take_io()
            .ok_or_else(|| anyhow!("proxy backend missing io"))?;
        let (client_io, client_leftover) = reader
            .take_io()
            .ok_or_else(|| anyhow!("client missing io for websocket"))?;
        tunnel_websocket(client_io, w, backend_io, client_leftover, backend_leftover).await?;
        return Ok(ProxyOutcome {
            reuse_backend: false,
            send: H1SendOutcome {
                keep_client: false,
                status: raw_status,
            },
            continue_request: false,
            preserved_body: None,
        });
    }

    let pre_hook_send_body = should_send_proxy_body(status, body_hint, head_only);
    apply_proxy_response_headers(&mut headers, body_hint, pre_hook_send_body);
    let hook_outcome = caddy::prepare_reverse_proxy_raw_h1_response_headers(
        hook_state,
        status,
        Some(&resp_head.status_text),
        &mut headers,
        upstream_latency,
        early_response_headers,
        metadata,
    )
    .await;
    let raw_status = hook_outcome.status;
    if hook_outcome.continue_request {
        if !head_only {
            drain_proxy_payload(conn, &mut resp_body).await?;
        }
        let _ = w.flush().await;
        return Ok(ProxyOutcome {
            reuse_backend: can_reuse,
            send: H1SendOutcome {
                keep_client: true,
                status: raw_status,
            },
            continue_request: true,
            preserved_body: if send_request_body { None } else { Some(body) },
        });
    }
    if !send_request_body {
        drain_payload(reader, &mut body).await;
    }
    let send_body = should_send_proxy_body_raw(raw_status, body_hint, head_only);
    if send_body {
        apply_proxy_response_headers(&mut headers, body_hint, send_body);
        restore_fixed_proxy_content_length(&mut headers, body_hint, fixed_content_length.as_ref());
        // Streaming response compression (Caddy `encode` handler). The upstream
        // body is forwarded through a gzip/zstd encoder and re-framed as chunked
        // since the compressed length is unknown ahead of time.
        if !head_only && let Some(state) = encode {
            let content_length = headers
                .get(::http::header::CONTENT_LENGTH)
                .and_then(|v| v.to_str().ok())
                .and_then(|s| s.parse::<u64>().ok());
            if let Some(chosen) = state.decide(raw_status, &headers, content_length) {
                forward_proxy_body_encoded(
                    w,
                    conn,
                    &mut resp_body,
                    &mut headers,
                    raw_status,
                    chosen,
                    state.min_length(),
                )
                .await?;
                let _ = w.flush().await;
                return Ok(ProxyOutcome {
                    reuse_backend: can_reuse,
                    send: H1SendOutcome {
                        keep_client: true,
                        status: raw_status,
                    },
                    continue_request: false,
                    preserved_body: None,
                });
            }
        }
    } else if !raw_status_allows_body(raw_status) {
        strip_no_body_headers(&mut headers);
    } else {
        apply_proxy_response_headers(&mut headers, body_hint, send_body);
    }

    if send_body && !head_only && encode.is_none() && matches!(body_hint, StreamHint::Fixed) {
        let body = collect_proxy_body(conn, &mut resp_body).await?;
        write_response_head_and_body_raw(w, raw_status, &headers, body).await?;
        let _ = w.flush().await;
        return Ok(ProxyOutcome {
            reuse_backend: can_reuse,
            send: H1SendOutcome {
                keep_client: true,
                status: raw_status,
            },
            continue_request: false,
            preserved_body: None,
        });
    }

    write_response_head_raw(w, raw_status, &headers).await?;

    if !send_body {
        if !head_only {
            drain_proxy_payload(conn, &mut resp_body).await?;
        }
        let _ = w.flush().await;
        return Ok(ProxyOutcome {
            reuse_backend: can_reuse,
            send: H1SendOutcome {
                keep_client: true,
                status: raw_status,
            },
            continue_request: false,
            preserved_body: None,
        });
    }

    forward_proxy_body(w, conn, &mut resp_body).await?;
    let _ = w.flush().await;
    Ok(ProxyOutcome {
        reuse_backend: can_reuse,
        send: H1SendOutcome {
            keep_client: true,
            status: raw_status,
        },
        continue_request: false,
        preserved_body: None,
    })
}

async fn proxy_over_connection_h2<IO>(
    conn: &mut h1::H1Connection<IO>,
    head: RequestHead,
    mut body: h2::RecvStream,
    respond: &mut h2::server::SendResponse<Bytes>,
    head_only: bool,
    early_response_headers: Option<&::http::HeaderMap>,
    metadata: &HashMap<String, String>,
    hook_state: Option<&ResponseHookState<'_>>,
    chunked: bool,
    send_request_body: bool,
    request_body_limit: Option<usize>,
    encode: Option<&crate::helpers::compress::EncodeState>,
) -> Result<H2ProxyConnectionOutcome>
where
    IO: AsyncReadRent + AsyncWriteRent + Split,
{
    let roundtrip_start = hook_state
        .as_ref()
        .is_some_and(|state| state.has_hooks())
        .then(Instant::now);
    h1::write_request_head(conn.io_mut()?, &head)
        .await
        .map_err(|err| anyhow!("failed to send proxy request head: {err}"))?;
    if send_request_body {
        match forward_h2_request_body(conn, &mut body, chunked, request_body_limit).await {
            Ok(()) => {}
            Err(ProxyRequestBodyError::TooLarge) => {
                send_h2_response(
                    respond,
                    payload_too_large(),
                    head_only,
                    early_response_headers,
                    metadata,
                    hook_state,
                )
                .await?;
                return Ok(H2ProxyConnectionOutcome {
                    reuse_backend: false,
                    continue_request: false,
                    preserved_body: None,
                    status: Some(StatusCode::PAYLOAD_TOO_LARGE.as_u16()),
                });
            }
            Err(ProxyRequestBodyError::Other(err)) => {
                return Err(anyhow!("failed to send proxy request body: {err}"));
            }
        }
    }

    let response = match conn.next_response().await {
        Ok(Some(resp)) => resp,
        Ok(None) => return Err(anyhow!("proxy backend closed without response")),
        Err(err) => return Err(anyhow!("failed to read proxy response: {err}")),
    };
    let upstream_latency = roundtrip_start.map(|start| start.elapsed());

    let (resp_head, mut resp_body) = response.into_parts();
    let mut status = resp_head.status;
    let mut can_reuse = should_reuse_proxy_connection(resp_head.version, &resp_head.headers);
    let mut headers = resp_head.headers;
    strip_hop_headers(&mut headers, false);
    let body_hint = resp_body.hint();
    let fixed_content_length = if matches!(body_hint, StreamHint::Fixed) {
        headers.get(::http::header::CONTENT_LENGTH).cloned()
    } else {
        None
    };
    if resp_body.is_eof() {
        can_reuse = false;
    }

    let pre_hook_send_body = should_send_proxy_body(status, body_hint, head_only);
    apply_proxy_response_headers(&mut headers, body_hint, pre_hook_send_body);
    headers.remove(::http::header::TRANSFER_ENCODING);
    let hook_outcome = caddy::prepare_reverse_proxy_response_headers(
        hook_state,
        status,
        None,
        &mut headers,
        upstream_latency,
        early_response_headers,
        metadata,
    )
    .await;
    status = hook_outcome.status;
    if hook_outcome.continue_request {
        if !head_only {
            drain_proxy_payload(conn, &mut resp_body).await?;
        }
        return Ok(H2ProxyConnectionOutcome {
            reuse_backend: can_reuse,
            continue_request: true,
            preserved_body: if send_request_body { None } else { Some(body) },
            status: Some(status.as_u16()),
        });
    }
    let send_body = should_send_proxy_body(status, body_hint, head_only);
    if send_body {
        apply_proxy_response_headers(&mut headers, body_hint, send_body);
        restore_fixed_proxy_content_length(&mut headers, body_hint, fixed_content_length.as_ref());
    } else if !status_allows_body(status) {
        strip_no_body_headers(&mut headers);
    } else {
        apply_proxy_response_headers(&mut headers, body_hint, send_body);
    }
    // Streaming response compression (Caddy `encode` handler). HTTP/2 frames the
    // body as DATA frames, so there is no Content-Length to maintain.
    let chosen_encoding = if send_body && !head_only {
        encode.and_then(|state| {
            let content_length = headers
                .get(::http::header::CONTENT_LENGTH)
                .and_then(|v| v.to_str().ok())
                .and_then(|s| s.parse::<u64>().ok());
            state
                .decide(status.as_u16(), &headers, content_length)
                .map(|chosen| (chosen, state.min_length()))
        })
    } else {
        None
    };
    if let Some((chosen, _)) = &chosen_encoding {
        crate::helpers::compress::apply_encoding_headers(&mut headers, &chosen.name);
    }
    headers.remove(::http::header::TRANSFER_ENCODING);
    let mut head = ::http::Response::builder()
        .status(status)
        .version(::http::Version::HTTP_2)
        .body(())
        .map_err(|err| anyhow!("failed to build h2 response: {err}"))?;
    *head.headers_mut() = headers;
    let end_stream = !send_body;
    let mut stream = respond.send_response(head, end_stream)?;

    if !send_body {
        if !head_only {
            drain_proxy_payload(conn, &mut resp_body).await?;
        }
        return Ok(H2ProxyConnectionOutcome {
            reuse_backend: can_reuse,
            continue_request: false,
            preserved_body: None,
            status: Some(status.as_u16()),
        });
    }

    if let Some((chosen, _min_length)) = chosen_encoding {
        forward_proxy_body_h2_encoded(&mut stream, conn, &mut resp_body, chosen).await?;
    } else {
        forward_proxy_body_h2(&mut stream, conn, &mut resp_body).await?;
    }
    Ok(H2ProxyConnectionOutcome {
        reuse_backend: can_reuse,
        continue_request: false,
        preserved_body: None,
        status: Some(status.as_u16()),
    })
}

struct H2ProxyConnectionOutcome {
    reuse_backend: bool,
    continue_request: bool,
    preserved_body: Option<h2::RecvStream>,
    status: Option<u16>,
}

fn should_reuse_proxy_connection(version: ::http::Version, headers: &::http::HeaderMap) -> bool {
    if version != ::http::Version::HTTP_11 {
        return false;
    }
    !connection_has_close(headers)
}

fn can_use_raw_fixed_proxy_response(
    early_response_headers: Option<&::http::HeaderMap>,
    metadata: &HashMap<String, String>,
    hook_state: Option<&ResponseHookState<'_>>,
    is_ws_request: bool,
    head_only: bool,
    encode: Option<&crate::helpers::compress::EncodeState>,
) -> bool {
    !is_ws_request
        && !head_only
        && encode.is_none()
        && early_response_headers.is_none_or(::http::HeaderMap::is_empty)
        && hook_state.is_none_or(|state| !state.has_hooks())
        && !metadata
            .keys()
            .any(|key| key.starts_with("zs.response.header."))
}

fn connection_has_close(headers: &::http::HeaderMap) -> bool {
    headers
        .get(::http::header::CONNECTION)
        .and_then(|value| value.to_str().ok())
        .map(|value| {
            value
                .split(',')
                .any(|token| token.trim().eq_ignore_ascii_case("close"))
        })
        .unwrap_or(false)
}

fn should_send_proxy_body(status: StatusCode, body_hint: StreamHint, head_only: bool) -> bool {
    should_send_proxy_body_raw(status.as_u16(), body_hint, head_only)
}

fn should_send_proxy_body_raw(status: u16, body_hint: StreamHint, head_only: bool) -> bool {
    if head_only {
        return false;
    }
    if !raw_status_allows_body(status) {
        return false;
    }
    !matches!(body_hint, StreamHint::None)
}

fn apply_proxy_response_headers(
    headers: &mut ::http::HeaderMap,
    body_hint: StreamHint,
    send_body: bool,
) {
    if !send_body {
        headers.remove(::http::header::TRANSFER_ENCODING);
        return;
    }

    match body_hint {
        StreamHint::None => {
            headers.remove(::http::header::CONTENT_LENGTH);
            headers.remove(::http::header::TRANSFER_ENCODING);
        }
        StreamHint::Fixed => {
            headers.remove(::http::header::TRANSFER_ENCODING);
        }
        StreamHint::Stream => {
            headers.remove(::http::header::CONTENT_LENGTH);
            headers.insert(
                ::http::header::TRANSFER_ENCODING,
                ::http::HeaderValue::from_static("chunked"),
            );
        }
    }
}

fn restore_fixed_proxy_content_length(
    headers: &mut ::http::HeaderMap,
    body_hint: StreamHint,
    content_length: Option<&::http::HeaderValue>,
) {
    if !matches!(body_hint, StreamHint::Fixed)
        || headers.contains_key(::http::header::CONTENT_LENGTH)
    {
        return;
    }
    if let Some(value) = content_length {
        headers.insert(::http::header::CONTENT_LENGTH, value.clone());
    }
}

fn apply_proxy_request_headers(headers: &mut ::http::HeaderMap, body: &h1::Body) {
    if matches!(body.hint(), StreamHint::None) {
        headers.remove(::http::header::CONTENT_LENGTH);
        headers.remove(::http::header::TRANSFER_ENCODING);
    } else if body.is_chunked() {
        headers.remove(::http::header::CONTENT_LENGTH);
        headers.insert(
            ::http::header::TRANSFER_ENCODING,
            ::http::HeaderValue::from_static("chunked"),
        );
    } else {
        headers.remove(::http::header::TRANSFER_ENCODING);
    }
}

fn apply_proxy_request_headers_h2(headers: &mut ::http::HeaderMap, has_body: bool) -> bool {
    if !has_body {
        headers.remove(::http::header::CONTENT_LENGTH);
        headers.remove(::http::header::TRANSFER_ENCODING);
        return false;
    }
    if h1::content_length(headers).is_some() {
        headers.remove(::http::header::TRANSFER_ENCODING);
        return false;
    }
    headers.remove(::http::header::CONTENT_LENGTH);
    headers.insert(
        ::http::header::TRANSFER_ENCODING,
        ::http::HeaderValue::from_static("chunked"),
    );
    true
}

fn request_body_content_length_exceeds(
    headers: &::http::HeaderMap,
    request_body_limit: Option<usize>,
) -> bool {
    let Some(limit) = request_body_limit else {
        return false;
    };
    headers
        .get(::http::header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok())
        .is_some_and(|len| len > limit as u64)
}

enum ProxyRequestBodyError {
    TooLarge,
    Other(anyhow::Error),
}

fn add_limited_request_body_bytes(
    bytes_seen: &mut usize,
    chunk_len: usize,
    request_body_limit: Option<usize>,
) -> Result<(), ProxyRequestBodyError> {
    let Some(limit) = request_body_limit else {
        return Ok(());
    };
    *bytes_seen = bytes_seen.saturating_add(chunk_len);
    if *bytes_seen > limit {
        return Err(ProxyRequestBodyError::TooLarge);
    }
    Ok(())
}

async fn forward_h2_request_body<IO>(
    conn: &mut h1::H1Connection<IO>,
    body: &mut h2::RecvStream,
    chunked: bool,
    request_body_limit: Option<usize>,
) -> Result<(), ProxyRequestBodyError>
where
    IO: AsyncWriteRent,
{
    if body.is_end_stream() {
        return Ok(());
    }

    let mut bytes_seen = 0usize;
    if chunked {
        while let Some(chunk) = body.data().await {
            let chunk = chunk.map_err(|err| {
                ProxyRequestBodyError::Other(anyhow!("proxy request body read failed: {err}"))
            })?;
            add_limited_request_body_bytes(&mut bytes_seen, chunk.len(), request_body_limit)?;
            let io = conn
                .io_mut()
                .map_err(|err| ProxyRequestBodyError::Other(anyhow!("{err}")))?;
            h1::write_chunk(io, chunk.as_ref()).await.map_err(|err| {
                ProxyRequestBodyError::Other(anyhow!("failed to write proxy body chunk: {err}"))
            })?;
            let _ = body.flow_control().release_capacity(chunk.len());
        }
        let io = conn
            .io_mut()
            .map_err(|err| ProxyRequestBodyError::Other(anyhow!("{err}")))?;
        h1::write_chunk_end(io).await.map_err(|err| {
            ProxyRequestBodyError::Other(anyhow!("failed to write proxy body end: {err}"))
        })?;
    } else {
        while let Some(chunk) = body.data().await {
            let chunk = chunk.map_err(|err| {
                ProxyRequestBodyError::Other(anyhow!("proxy request body read failed: {err}"))
            })?;
            add_limited_request_body_bytes(&mut bytes_seen, chunk.len(), request_body_limit)?;
            let io = conn
                .io_mut()
                .map_err(|err| ProxyRequestBodyError::Other(anyhow!("{err}")))?;
            let (res, _) = io.write_all(chunk.to_vec()).await;
            res.map_err(|err| {
                ProxyRequestBodyError::Other(anyhow!("failed to write proxy body: {err}"))
            })?;
            let _ = body.flow_control().release_capacity(chunk.len());
        }
    }
    let io = conn
        .io_mut()
        .map_err(|err| ProxyRequestBodyError::Other(anyhow!("{err}")))?;
    let _ = io.flush().await;
    Ok(())
}

async fn forward_proxy_body_h2<IO>(
    stream: &mut h2::SendStream<Bytes>,
    conn: &mut h1::H1Connection<IO>,
    body: &mut h1::Body,
) -> Result<()>
where
    IO: AsyncReadRent,
{
    let mut sent_any = false;
    let mut next = body.next_data(conn).await;
    while let Some(chunk) = next {
        let chunk = chunk.map_err(|err| anyhow!("proxy body read failed: {err}"))?;
        next = body.next_data(conn).await;
        let is_last = next.is_none();
        send_h2_data(stream, chunk, is_last).await?;
        sent_any = true;
    }
    if !sent_any {
        send_h2_data(stream, Bytes::new(), true).await?;
    }
    Ok(())
}

/// Forward an upstream response body over HTTP/2 while applying streaming
/// compression (Caddy `encode`). The `Content-Encoding` header has already been
/// set on the response, so this just compresses each chunk into DATA frames and
/// closes the stream with the encoder's trailing bytes.
async fn forward_proxy_body_h2_encoded<IO>(
    stream: &mut h2::SendStream<Bytes>,
    conn: &mut h1::H1Connection<IO>,
    body: &mut h1::Body,
    chosen: crate::helpers::compress::ChosenEncoding,
) -> Result<()>
where
    IO: AsyncReadRent,
{
    let mut enc = crate::helpers::compress::BodyEncoder::new(chosen.spec)
        .map_err(|err| anyhow!("encoder init failed: {err}"))?;
    while let Some(chunk) = body.next_data(conn).await {
        let chunk = chunk.map_err(|err| anyhow!("proxy body read failed: {err}"))?;
        let out = enc
            .push(chunk.as_ref())
            .map_err(|err| anyhow!("compression failed: {err}"))?;
        if !out.is_empty() {
            send_h2_data(stream, Bytes::from(out), false).await?;
        }
    }
    let tail = enc
        .finish()
        .map_err(|err| anyhow!("compression finish failed: {err}"))?;
    // Always send a final frame (possibly empty) to close the stream.
    send_h2_data(stream, Bytes::from(tail), true).await?;
    Ok(())
}

async fn write_response_head(
    w: &mut impl AsyncWriteRent,
    status: StatusCode,
    headers: &::http::HeaderMap,
) -> Result<()> {
    write_response_head_raw(w, status.as_u16(), headers).await
}

async fn write_response_head_raw(
    w: &mut impl AsyncWriteRent,
    status: u16,
    headers: &::http::HeaderMap,
) -> Result<()> {
    let buf = encode_response_head_raw(status, headers);
    let (res, _) = w.write_all(buf).await;
    res.map_err(|err| anyhow!("failed to write proxy response head: {err}"))?;
    Ok(())
}

async fn write_response_head_and_body_raw(
    w: &mut impl AsyncWriteRent,
    status: u16,
    headers: &::http::HeaderMap,
    body: Vec<u8>,
) -> Result<()> {
    const COALESCE_LIMIT: usize = 16 * 1024;
    let mut buf = encode_response_head_raw(status, headers);
    if buf.len() + body.len() <= COALESCE_LIMIT {
        buf.extend_from_slice(&body);
        let (res, _) = w.write_all(buf).await;
        res.map_err(|err| anyhow!("failed to write proxy response: {err}"))?;
    } else {
        let (res, _) = w.write_all(buf).await;
        res.map_err(|err| anyhow!("failed to write proxy response head: {err}"))?;
        let (res, _) = w.write_all(body).await;
        res.map_err(|err| anyhow!("failed to write proxy response body: {err}"))?;
    }
    Ok(())
}

async fn write_raw_response(w: &mut impl AsyncWriteRent, response: Vec<u8>) -> Result<()> {
    let (res, _) = w.write_all(response).await;
    res.map_err(|err| anyhow!("failed to write proxy response: {err}"))?;
    Ok(())
}

fn encode_response_head_raw(status: u16, headers: &::http::HeaderMap) -> Vec<u8> {
    let reason = StatusCode::from_u16(status)
        .ok()
        .and_then(|status| status.canonical_reason());
    let mut buf = Vec::new();
    match reason {
        Some(reason) => {
            buf.extend_from_slice(format!("HTTP/1.1 {status:03} {reason}\r\n").as_bytes());
        }
        None => {
            buf.extend_from_slice(
                format!("HTTP/1.1 {status:03} status code {status}\r\n").as_bytes(),
            );
        }
    }
    for (name, value) in headers.iter() {
        buf.extend_from_slice(name.as_str().as_bytes());
        buf.extend_from_slice(b": ");
        buf.extend_from_slice(value.as_bytes());
        buf.extend_from_slice(b"\r\n");
    }
    buf.extend_from_slice(b"\r\n");
    buf
}

async fn forward_request_body<IO, R>(
    conn: &mut h1::H1Connection<IO>,
    reader: &mut h1::H1Connection<R>,
    body: &mut h1::Body,
    request_body_limit: Option<usize>,
) -> Result<(), ProxyRequestBodyError>
where
    IO: AsyncWriteRent,
    R: AsyncReadRent,
{
    match body.hint() {
        StreamHint::None => return Ok(()),
        StreamHint::Stream if body.is_eof() => {
            return Err(ProxyRequestBodyError::Other(anyhow!(
                "proxy request body missing length"
            )));
        }
        _ => {}
    }

    let mut bytes_seen = 0usize;
    if body.is_chunked() {
        while let Some(chunk) = body.next_data(reader).await {
            let chunk = chunk.map_err(|err| {
                ProxyRequestBodyError::Other(anyhow!("proxy request body read failed: {err}"))
            })?;
            add_limited_request_body_bytes(&mut bytes_seen, chunk.len(), request_body_limit)?;
            let io = conn
                .io_mut()
                .map_err(|err| ProxyRequestBodyError::Other(anyhow!("{err}")))?;
            h1::write_chunk(io, chunk.as_ref()).await.map_err(|err| {
                ProxyRequestBodyError::Other(anyhow!("failed to write proxy body chunk: {err}"))
            })?;
        }
        let io = conn
            .io_mut()
            .map_err(|err| ProxyRequestBodyError::Other(anyhow!("{err}")))?;
        h1::write_chunk_end(io).await.map_err(|err| {
            ProxyRequestBodyError::Other(anyhow!("failed to write proxy body end: {err}"))
        })?;
    } else {
        while let Some(chunk) = body.next_data(reader).await {
            let chunk = chunk.map_err(|err| {
                ProxyRequestBodyError::Other(anyhow!("proxy request body read failed: {err}"))
            })?;
            add_limited_request_body_bytes(&mut bytes_seen, chunk.len(), request_body_limit)?;
            let io = conn
                .io_mut()
                .map_err(|err| ProxyRequestBodyError::Other(anyhow!("{err}")))?;
            let (res, _) = io.write_all(chunk.to_vec()).await;
            res.map_err(|err| {
                ProxyRequestBodyError::Other(anyhow!("failed to write proxy body: {err}"))
            })?;
        }
    }
    let io = conn
        .io_mut()
        .map_err(|err| ProxyRequestBodyError::Other(anyhow!("{err}")))?;
    let _ = io.flush().await;
    Ok(())
}

async fn drain_proxy_payload<IO>(conn: &mut h1::H1Connection<IO>, body: &mut h1::Body) -> Result<()>
where
    IO: AsyncReadRent,
{
    while let Some(chunk) = body.next_data(conn).await {
        chunk.map_err(|err| anyhow!("proxy body read failed: {err}"))?;
    }
    Ok(())
}

async fn collect_proxy_body<IO>(
    conn: &mut h1::H1Connection<IO>,
    body: &mut h1::Body,
) -> Result<Vec<u8>>
where
    IO: AsyncReadRent,
{
    let mut out = Vec::new();
    while let Some(chunk) = body.next_data(conn).await {
        let chunk = chunk.map_err(|err| anyhow!("proxy body read failed: {err}"))?;
        out.extend_from_slice(chunk.as_ref());
    }
    Ok(out)
}

async fn collect_proxy_body_into<IO>(
    conn: &mut h1::H1Connection<IO>,
    body: &mut h1::Body,
    out: &mut Vec<u8>,
) -> Result<()>
where
    IO: AsyncReadRent,
{
    while let Some(chunk) = body.next_data(conn).await {
        let chunk = chunk.map_err(|err| anyhow!("proxy body read failed: {err}"))?;
        out.extend_from_slice(chunk.as_ref());
    }
    Ok(())
}

/// Client writer wrapper that records whether any response bytes were
/// written (or may have been written — the flag is set before the IO await,
/// so a future dropped mid-write still counts). Error paths use this to tell
/// whether the connection can still carry a fresh error response or must be
/// closed to avoid corrupting H1 framing.
struct TrackedWriter<'a, W> {
    inner: &'a mut W,
    started: &'a Cell<bool>,
}

impl<W: AsyncWriteRent> AsyncWriteRent for TrackedWriter<'_, W> {
    async fn write<T: monoio::buf::IoBuf>(&mut self, buf: T) -> BufResult<usize, T> {
        self.started.set(true);
        self.inner.write(buf).await
    }

    async fn writev<T: monoio::buf::IoVecBuf>(&mut self, buf_vec: T) -> BufResult<usize, T> {
        self.started.set(true);
        self.inner.writev(buf_vec).await
    }

    async fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush().await
    }

    async fn shutdown(&mut self) -> std::io::Result<()> {
        self.inner.shutdown().await
    }
}

async fn forward_proxy_body<IO>(
    w: &mut impl AsyncWriteRent,
    conn: &mut h1::H1Connection<IO>,
    body: &mut h1::Body,
) -> Result<()>
where
    IO: AsyncReadRent,
{
    let rechunk = match body.hint() {
        StreamHint::None => return Ok(()),
        StreamHint::Fixed => false,
        StreamHint::Stream => true,
    };
    let mut batch: Vec<u8> = Vec::with_capacity(PROXY_WRITE_BATCH_SIZE);
    loop {
        let room = PROXY_WRITE_BATCH_SIZE.saturating_sub(batch.len());
        match body.try_drain_into(conn, &mut batch, room, rechunk) {
            Ok(h1::TryBodyData::Copied) => {
                if batch.len() >= PROXY_WRITE_BATCH_SIZE {
                    write_proxy_body_batch(w, &mut batch, rechunk).await?;
                }
            }
            Ok(h1::TryBodyData::NeedRead) => {
                // Flush everything pending to the client before blocking on
                // the upstream, so a stalled upstream never delays delivery.
                if !batch.is_empty() {
                    write_proxy_body_batch(w, &mut batch, rechunk).await?;
                    continue;
                }
                body.fill(conn, PROXY_WRITE_BATCH_SIZE)
                    .await
                    .map_err(|err| anyhow!("proxy body read failed: {err}"))?;
            }
            Ok(h1::TryBodyData::Done) => break,
            Err(err) => return Err(anyhow!("proxy body read failed: {err}")),
        }
    }
    if rechunk {
        batch.extend_from_slice(b"0\r\n\r\n");
    }
    write_proxy_body_batch(w, &mut batch, false).await?;
    Ok(())
}

async fn write_proxy_body_batch(
    w: &mut impl AsyncWriteRent,
    batch: &mut Vec<u8>,
    flush: bool,
) -> Result<()> {
    if batch.is_empty() {
        return Ok(());
    }
    let pending = std::mem::take(batch);
    let (res, mut pending) = w.write_all(pending).await;
    res.map_err(|err| anyhow!("failed to write proxy body: {err}"))?;
    pending.clear();
    *batch = pending;
    if flush {
        let _ = w.flush().await;
    }
    Ok(())
}

/// Forward an upstream response body while applying streaming compression
/// (Caddy `encode`). Output is HTTP/1.1 chunked since the compressed length is
/// not known ahead of time. The response head is written here (after deciding
/// the final framing). For unknown-length (streamed) upstreams, reads ahead up
/// to `min_length` bytes to honor the minimum-length gate: if the whole body is
/// at or below `min_length`, it is sent uncompressed with a fixed length.
async fn forward_proxy_body_encoded<IO>(
    w: &mut impl AsyncWriteRent,
    conn: &mut h1::H1Connection<IO>,
    body: &mut h1::Body,
    headers: &mut ::http::HeaderMap,
    raw_status: u16,
    chosen: crate::helpers::compress::ChosenEncoding,
    min_length: usize,
) -> Result<()>
where
    IO: AsyncReadRent,
{
    use crate::helpers::compress::{BodyEncoder, apply_encoding_headers};

    let streamed = matches!(body.hint(), StreamHint::Stream);
    let mut prebuf: Vec<u8> = Vec::new();
    if streamed {
        // Read ahead until we exceed minimum_length or hit EOF.
        let mut eof = false;
        while prebuf.len() <= min_length {
            match body.next_data(conn).await {
                Some(chunk) => {
                    let chunk = chunk.map_err(|err| anyhow!("proxy body read failed: {err}"))?;
                    prebuf.extend_from_slice(chunk.as_ref());
                }
                None => {
                    eof = true;
                    break;
                }
            }
        }
        if eof && prebuf.len() <= min_length {
            // Below the threshold: send uncompressed with a known length.
            headers.remove(::http::header::TRANSFER_ENCODING);
            if let Ok(value) = ::http::HeaderValue::from_str(&prebuf.len().to_string()) {
                headers.insert(::http::header::CONTENT_LENGTH, value);
            }
            write_response_head_raw(w, raw_status, headers).await?;
            if !prebuf.is_empty() {
                let (res, _) = w.write_all(prebuf).await;
                res.map_err(|err| anyhow!("failed to write proxy body: {err}"))?;
            }
            return Ok(());
        }
    }

    // Commit to compression: chunked transfer with the encoding headers.
    apply_encoding_headers(headers, &chosen.name);
    headers.remove(::http::header::TRANSFER_ENCODING);
    headers.insert(
        ::http::header::TRANSFER_ENCODING,
        ::http::HeaderValue::from_static("chunked"),
    );
    write_response_head_raw(w, raw_status, headers).await?;

    let mut enc =
        BodyEncoder::new(chosen.spec).map_err(|err| anyhow!("encoder init failed: {err}"))?;
    if !prebuf.is_empty() {
        let out = enc
            .push(&prebuf)
            .map_err(|err| anyhow!("compression failed: {err}"))?;
        if !out.is_empty() {
            h1::write_chunk(w, &out)
                .await
                .map_err(|err| anyhow!("failed to write proxy body chunk: {err}"))?;
            let _ = w.flush().await;
        }
    }
    while let Some(chunk) = body.next_data(conn).await {
        let chunk = chunk.map_err(|err| anyhow!("proxy body read failed: {err}"))?;
        let out = enc
            .push(chunk.as_ref())
            .map_err(|err| anyhow!("compression failed: {err}"))?;
        if !out.is_empty() {
            h1::write_chunk(w, &out)
                .await
                .map_err(|err| anyhow!("failed to write proxy body chunk: {err}"))?;
            let _ = w.flush().await;
        }
    }
    let tail = enc
        .finish()
        .map_err(|err| anyhow!("compression finish failed: {err}"))?;
    if !tail.is_empty() {
        h1::write_chunk(w, &tail)
            .await
            .map_err(|err| anyhow!("failed to write proxy body chunk: {err}"))?;
    }
    h1::write_chunk_end(w)
        .await
        .map_err(|err| anyhow!("failed to write proxy body end: {err}"))?;
    Ok(())
}

async fn tunnel_websocket<R, IO>(
    client_read: R,
    client_write: impl AsyncWriteRent,
    backend_io: IO,
    client_leftover: Vec<u8>,
    backend_leftover: Vec<u8>,
) -> Result<()>
where
    R: AsyncReadRent,
    IO: AsyncReadRent + AsyncWriteRent + Split,
{
    let (backend_read, backend_write) = backend_io.into_split();
    let client_to_backend = copy_stream(client_read, backend_write, client_leftover);
    let backend_to_client = copy_stream(backend_read, client_write, backend_leftover);
    let (res_a, res_b) = futures::future::join(client_to_backend, backend_to_client).await;
    res_a?;
    res_b?;
    Ok(())
}

async fn copy_stream<R, W>(mut reader: R, mut writer: W, pending: Vec<u8>) -> Result<()>
where
    R: AsyncReadRent,
    W: AsyncWriteRent,
{
    if !pending.is_empty() {
        let (res, _) = writer.write_all(pending).await;
        res.map_err(|err| anyhow!("failed to write websocket buffer: {err}"))?;
    }

    let mut buf = vec![0u8; 8 * 1024];
    loop {
        let (res, next_buf) = futures::future::join(reader.read(buf), writer.flush())
            .await
            .0;
        buf = next_buf;
        let n = res.map_err(|err| anyhow!("websocket read failed: {err}"))?;
        if n == 0 {
            let _ = writer.shutdown().await;
            return Ok(());
        }
        let view = monoio::buf::Slice::new(buf, 0, n);
        let (res, view) = writer.write_all(view).await;
        buf = view.into_inner();
        res.map_err(|err| anyhow!("websocket write failed: {err}"))?;
    }
}

fn strip_hop_headers(headers: &mut ::http::HeaderMap, keep_upgrade: bool) {
    strip_hop_headers_inner(headers, keep_upgrade, false);
}

fn strip_proxy_request_hop_headers(
    headers: &mut ::http::HeaderMap,
    keep_upgrade: bool,
    preserve_te_trailers: bool,
) {
    strip_hop_headers_inner(headers, keep_upgrade, preserve_te_trailers);
}

fn strip_hop_headers_inner(
    headers: &mut ::http::HeaderMap,
    keep_upgrade: bool,
    preserve_te_trailers: bool,
) {
    let connection_values = headers
        .get_all(::http::header::CONNECTION)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .map(str::to_string)
        .collect::<Vec<_>>();
    if !connection_values.is_empty() {
        let mut saw_upgrade = false;
        for name in connection_values
            .iter()
            .flat_map(|value| value.split(',').map(str::trim))
        {
            if name.is_empty() {
                continue;
            }
            if keep_upgrade && name.eq_ignore_ascii_case("upgrade") {
                saw_upgrade = true;
                continue;
            }
            let name = name.to_ascii_lowercase();
            headers.remove(name.as_str());
        }
        if keep_upgrade {
            if saw_upgrade {
                headers.insert(
                    ::http::header::CONNECTION,
                    ::http::HeaderValue::from_static("upgrade"),
                );
            } else {
                headers.remove(::http::header::CONNECTION);
            }
        }
    }

    let keep_te_trailers =
        preserve_te_trailers && header_values_contain_token(headers, "te", "trailers");
    for name in [
        "alt-svc",
        "connection",
        "proxy-connection",
        "proxy-authenticate",
        "proxy-authorization",
        "keep-alive",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
    ] {
        if keep_upgrade && (name == "connection" || name == "upgrade") {
            continue;
        }
        if name == "te" && keep_te_trailers {
            headers.insert("te", ::http::HeaderValue::from_static("trailers"));
            continue;
        }
        headers.remove(name);
    }
}

fn header_values_contain_token(headers: &::http::HeaderMap, name: &str, token: &str) -> bool {
    headers.get_all(name).iter().any(|value| {
        value.to_str().ok().is_some_and(|value| {
            value
                .split(',')
                .map(str::trim)
                .any(|part| part.eq_ignore_ascii_case(token))
        })
    })
}

#[derive(Clone, Copy)]
pub(crate) enum BackendScheme {
    Http,
    Https,
    Unix,
    Iroh,
}

#[derive(Clone)]
pub(crate) struct BackendTarget {
    pub(crate) scheme: BackendScheme,
    pub(crate) host: String,
    pub(crate) is_ipv6: bool,
    pub(crate) port: u16,
    pub(crate) base_path: String,
    pub(crate) base_query: Option<String>,
    pub(crate) iroh: Option<IrohTarget>,
    pool_key: PoolKey,
}

impl BackendTarget {
    fn authority(&self) -> String {
        format_host_port(&self.host, self.port, self.is_ipv6)
    }

    fn pool_key(&self) -> PoolKey {
        self.pool_key.clone()
    }
}

fn cached_backend_target(raw: &str) -> Result<BackendTarget> {
    thread_local! {
        static BACKEND_TARGET_CACHE: RefCell<HashMap<String, BackendTarget>> =
            RefCell::new(HashMap::new());
    }
    if let Some(target) = BACKEND_TARGET_CACHE.with(|cache| cache.borrow().get(raw).cloned()) {
        return Ok(target);
    }
    let target = parse_backend_target(raw)?;
    BACKEND_TARGET_CACHE.with(|cache| {
        cache.borrow_mut().insert(raw.to_string(), target.clone());
    });
    Ok(target)
}

pub(crate) fn parse_backend_target(raw: &str) -> Result<BackendTarget> {
    if let Some(path) = raw.strip_prefix("unix/") {
        if path.is_empty() {
            return Err(anyhow!("backend unix socket path is empty"));
        }
        return Ok(BackendTarget {
            scheme: BackendScheme::Unix,
            host: path.to_string(),
            is_ipv6: false,
            port: 0,
            base_path: String::new(),
            base_query: None,
            iroh: None,
            pool_key: PoolKey::unix(path.to_string()),
        });
    }
    let url = Url::parse(raw).map_err(|err| anyhow!("invalid backend url: {err}"))?;
    if url.scheme() == "iroh" {
        let node_id = url
            .host_str()
            .ok_or_else(|| anyhow!("iroh backend url missing node id"))?
            .to_string();
        if node_id.is_empty() {
            return Err(anyhow!("iroh backend node id is empty"));
        }
        let direct_addrs = url
            .query_pairs()
            .filter_map(|(key, value)| (key == "addr").then_some(value))
            .map(|value| {
                value
                    .parse::<std::net::SocketAddr>()
                    .map_err(|err| anyhow!("invalid iroh backend addr {value:?}: {err}"))
            })
            .collect::<Result<Vec<_>>>()?;
        let base_query = url
            .query_pairs()
            .filter(|(key, _)| key != "addr")
            .map(|(key, value)| {
                if value.is_empty() {
                    key.into_owned()
                } else {
                    format!("{key}={value}")
                }
            })
            .collect::<Vec<_>>();
        let base_query = if base_query.is_empty() {
            None
        } else {
            Some(base_query.join("&"))
        };
        return Ok(BackendTarget {
            scheme: BackendScheme::Iroh,
            host: node_id.clone(),
            is_ipv6: false,
            port: 0,
            base_path: url.path().to_string(),
            base_query,
            iroh: Some(IrohTarget {
                node_id: node_id.clone(),
                direct_addrs,
            }),
            pool_key: PoolKey::new(format!("iroh:{node_id}"), 0, false),
        });
    }
    let scheme = match url.scheme() {
        "http" => BackendScheme::Http,
        "https" => BackendScheme::Https,
        other => return Err(anyhow!("unsupported backend scheme: {other}")),
    };
    let host = url
        .host()
        .ok_or_else(|| anyhow!("backend url missing host"))?;
    let (host, is_ipv6) = match host {
        url::Host::Domain(name) => (name.to_string(), false),
        url::Host::Ipv4(addr) => (addr.to_string(), false),
        url::Host::Ipv6(addr) => (addr.to_string(), true),
    };
    let port = url
        .port_or_known_default()
        .ok_or_else(|| anyhow!("backend url missing port"))?;
    let base_path = url.path().to_string();
    let base_query = url.query().map(|q| q.to_string());

    let pool_key = PoolKey::new(host.clone(), port, matches!(scheme, BackendScheme::Https));

    Ok(BackendTarget {
        scheme,
        host,
        is_ipv6,
        port,
        base_path,
        base_query,
        iroh: None,
        pool_key,
    })
}

fn build_backend_uri(target: &BackendTarget, req_uri: &Uri) -> Result<Uri> {
    let req_path = req_uri.path();
    let base_path = &target.base_path;
    let path = join_paths(base_path, req_path);
    let query = merge_queries(target.base_query.as_deref(), req_uri.query());
    let mut out = path;
    if let Some(query) = query {
        out.push('?');
        out.push_str(&query);
    }
    out.parse()
        .map_err(|err| anyhow!("invalid proxy path: {err}"))
}

fn join_paths(base: &str, path: &str) -> String {
    let base = base.trim_end_matches('/');
    let path = if path.is_empty() { "/" } else { path };
    if base.is_empty() || base == "/" {
        path.to_string()
    } else {
        format!("{}/{}", base, path.trim_start_matches('/'))
    }
}

fn merge_queries(base: Option<&str>, extra: Option<&str>) -> Option<String> {
    match (base, extra) {
        (Some(base), Some(extra)) if !base.is_empty() && !extra.is_empty() => {
            Some(format!("{base}&{extra}"))
        }
        (Some(base), _) if !base.is_empty() => Some(base.to_string()),
        (_, Some(extra)) if !extra.is_empty() => Some(extra.to_string()),
        _ => None,
    }
}

fn format_host_port(host: &str, port: u16, is_ipv6: bool) -> String {
    if is_ipv6 {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

fn not_found() -> ::http::Response<Bytes> {
    text_response(StatusCode::NOT_FOUND, "Not Found")
}

fn bad_request() -> ::http::Response<Bytes> {
    text_response(StatusCode::BAD_REQUEST, "Bad Request")
}

fn payload_too_large() -> ::http::Response<Bytes> {
    text_response(StatusCode::PAYLOAD_TOO_LARGE, "Request Entity Too Large")
}

fn bad_gateway() -> ::http::Response<Bytes> {
    ::http::Response::builder()
        .status(StatusCode::BAD_GATEWAY)
        .header(::http::header::SERVER, crate::SERVER_HEADER)
        .header(::http::header::CONTENT_LENGTH, "0")
        .body(Bytes::new())
        .unwrap()
}

fn method_not_allowed() -> ::http::Response<Bytes> {
    text_response(StatusCode::METHOD_NOT_ALLOWED, "Method Not Allowed")
}

fn text_response(status: StatusCode, body: &str) -> ::http::Response<Bytes> {
    ::http::Response::builder()
        .status(status)
        .header(::http::header::SERVER, crate::SERVER_HEADER)
        .header(::http::header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .header(::http::header::CONTENT_LENGTH, body.len().to_string())
        .body(Bytes::copy_from_slice(body.as_bytes()))
        .unwrap()
}

fn misdirected_request() -> ::http::Response<Bytes> {
    text_response(StatusCode::MISDIRECTED_REQUEST, "Misdirected Request")
}

fn is_valid_hostname(host: &str, allowed: &[String]) -> bool {
    if allowed.is_empty() {
        return true;
    }
    let host_without_port = hostname_without_port(host);
    // Case-insensitive comparison
    let host_lower = host_without_port.to_ascii_lowercase();
    allowed
        .iter()
        .any(|allowed| hostname_without_port(allowed).to_ascii_lowercase() == host_lower)
}

fn same_hostname(left: &str, right: &str) -> bool {
    hostname_without_port(left).eq_ignore_ascii_case(hostname_without_port(right))
}

fn hostname_without_port(host: &str) -> &str {
    if host.starts_with('[') {
        // IPv6 literal: [::1] or [2001:db8::1]:8080
        return host
            .split("]:")
            .next()
            .map(|s| s.trim_start_matches('[').trim_end_matches(']'))
            .unwrap_or(host);
    }
    // IPv4 or hostname: strip :port. Bare IPv6 literals are configuration-only
    // values in normal use and are left intact.
    if host.matches(':').count() > 1 {
        host
    } else {
        host.split(':').next().unwrap_or(host)
    }
}

async fn log_request(
    request_id: &RequestId,
    peer: std::net::SocketAddr,
    scheme: Scheme,
    method: &Method,
    uri: &Uri,
) {
    async_log(
        format!(
            "[request] {}: {} {} {} {}\n",
            request_id,
            scheme.as_str(),
            peer,
            method,
            uri
        )
        .into_bytes(),
    )
    .await
}

async fn log_caddy_access(
    shared: &Arc<SharedState>,
    head: &RequestHead,
    peer: std::net::SocketAddr,
    scheme: Scheme,
    status: u16,
    metadata: &HashMap<String, String>,
) {
    if !shared.config.expose_filesystem {
        return;
    }
    if metadata.get("http.vars.log_skip").is_some_and(|value| {
        matches!(
            value.as_str(),
            "true" | "1" | "yes" | "on" | "True" | "TRUE"
        )
    }) {
        return;
    }
    let Some(file) = metadata.get("zs.caddy.access_log.file") else {
        return;
    };
    if file.is_empty() {
        return;
    }
    let logger_name = metadata
        .get("zs.caddy.access_log.name")
        .map(String::as_str)
        .unwrap_or("default");
    let line = serde_json::json!({
        "logger": logger_name,
        "status": status,
        "method": head.method.as_str(),
        "uri": head.uri.to_string(),
        "proto": format!("{:?}", head.version),
        "remote_ip": peer.ip().to_string(),
        "remote_port": peer.port(),
        "scheme": scheme.as_str(),
    })
    .to_string()
        + "\n";
    shared
        .file_logger
        .write(PathBuf::from(file), line.into_bytes());
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Scheme {
    Http,
    Https,
}

impl Scheme {
    fn as_str(&self) -> &'static str {
        match self {
            Scheme::Http => "http",
            Scheme::Https => "https",
        }
    }
}

const MAX_PROXY_LINE_LEN: usize = 108;

async fn read_proxy_protocol_peer(
    stream: &mut TcpStream,
    fallback: std::net::SocketAddr,
    config: &StaticConfig,
) -> Result<std::net::SocketAddr> {
    let mut line: Vec<u8> = Vec::with_capacity(MAX_PROXY_LINE_LEN);

    if !config.debug_proxy_protocol_disable_fast_path {
        stream.readable(false).await?;

        // fast path: peek socket buffer
        unsafe {
            let n = libc::recv(
                stream.as_raw_fd(),
                line.as_mut_ptr().cast(),
                line.capacity(),
                libc::MSG_PEEK,
            );
            if n > 0 {
                let n = n as usize;
                assert!(n <= line.capacity());
                line.set_len(n);
            }
        }
        if !line.is_empty() {
            let len = line
                .windows(2)
                .enumerate()
                .find(|x| x.1 == b"\r\n")
                .map(|x| x.0);
            if let Some(len) = len {
                let output = parse_proxy_protocol_v1(&line[..len], fallback);
                // consume the buffer
                let (res, _) = stream.read_exact(SliceMut::new(line, 0, len + 2)).await;
                res?;
                return output;
            }
        }

        line.clear();
    }

    let mut buffer = Box::new([0u8; 1]);
    while line.len() < MAX_PROXY_LINE_LEN {
        let (res, buf) = stream.read_exact(buffer).await;
        buffer = buf;
        res.map_err(|e| anyhow!("failed to read PROXY header: {e}"))?;
        let byte = buffer[0];
        line.push(byte);
        let len = line.len();
        if len >= 2 && line[len - 2] == b'\r' && line[len - 1] == b'\n' {
            return parse_proxy_protocol_v1(&line, fallback);
        }
    }
    Err(anyhow!(
        "PROXY header exceeded {MAX_PROXY_LINE_LEN} bytes before newline"
    ))
}

fn parse_proxy_protocol_v1(
    header: &[u8],
    fallback: std::net::SocketAddr,
) -> Result<std::net::SocketAddr> {
    let header = std::str::from_utf8(header).context("PROXY header must be valid ASCII")?;
    let header = header.trim_end_matches("\r\n");
    let mut parts = header.split_whitespace();
    let prefix = parts
        .next()
        .ok_or_else(|| anyhow!("received empty PROXY header"))?;
    if prefix != "PROXY" {
        return Err(anyhow!("invalid PROXY header prefix: {prefix}"));
    }
    let family = parts
        .next()
        .ok_or_else(|| anyhow!("missing PROXY protocol family"))?;
    match family {
        "UNKNOWN" => Ok(fallback),
        "TCP4" | "TCP6" => {
            let src_ip = parts
                .next()
                .ok_or_else(|| anyhow!("missing source address in PROXY header"))?;
            let _dst_ip = parts
                .next()
                .ok_or_else(|| anyhow!("missing destination address in PROXY header"))?;
            let src_port = parts
                .next()
                .ok_or_else(|| anyhow!("missing source port in PROXY header"))?;
            let _dst_port = parts
                .next()
                .ok_or_else(|| anyhow!("missing destination port in PROXY header"))?;
            let port: u16 = src_port
                .parse()
                .map_err(|e| anyhow!("invalid source port in PROXY header: {e}"))?;
            let addr = if family == "TCP4" {
                let ip: Ipv4Addr = src_ip
                    .parse()
                    .map_err(|e| anyhow!("invalid IPv4 in PROXY header: {e}"))?;
                std::net::SocketAddr::new(IpAddr::V4(ip), port)
            } else {
                let ip: Ipv6Addr = src_ip
                    .parse()
                    .map_err(|e| anyhow!("invalid IPv6 in PROXY header: {e}"))?;
                std::net::SocketAddr::new(IpAddr::V6(ip), port)
            };
            Ok(addr)
        }
        other => Err(anyhow!("unsupported PROXY protocol family: {other}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request_head(headers: ::http::HeaderMap) -> RequestHead {
        RequestHead {
            method: Method::GET,
            uri: "/".parse().unwrap(),
            version: ::http::Version::HTTP_11,
            headers,
            tls: false,
        }
    }

    #[test]
    fn malformed_and_multi_ranges_are_ignored() {
        for value in ["bytes=0-1,3-4", "bytes=abc-9"] {
            let mut headers = ::http::HeaderMap::new();
            headers.insert(::http::header::RANGE, value.parse().unwrap());
            let head = request_head(headers);
            let mut response_headers = ::http::HeaderMap::new();
            let (status, range) = apply_static_range(&head, &mut response_headers, 10, "etag", 0);
            assert_eq!(status, StatusCode::OK);
            assert!(range.is_none());
            assert!(!response_headers.contains_key(::http::header::CONTENT_RANGE));
        }
    }

    #[test]
    fn unsatisfiable_single_range_returns_416() {
        let mut headers = ::http::HeaderMap::new();
        headers.insert(::http::header::RANGE, "bytes=99-100".parse().unwrap());
        let head = request_head(headers);
        let mut response_headers = ::http::HeaderMap::new();
        let (status, range) = apply_static_range(&head, &mut response_headers, 10, "etag", 0);
        assert_eq!(status, StatusCode::RANGE_NOT_SATISFIABLE);
        assert_eq!(
            response_headers
                .get(::http::header::CONTENT_RANGE)
                .and_then(|value| value.to_str().ok()),
            Some("bytes */10")
        );
        assert!(range.is_some());
    }

    #[test]
    fn hop_headers_strip_full_standard_list() {
        let mut headers = ::http::HeaderMap::new();
        for name in [
            "Alt-Svc",
            "Connection",
            "Proxy-Connection",
            "Proxy-Authenticate",
            "Proxy-Authorization",
            "Keep-Alive",
            "TE",
            "Trailer",
            "Transfer-Encoding",
            "Upgrade",
        ] {
            headers.insert(
                ::http::header::HeaderName::from_bytes(name.as_bytes()).unwrap(),
                "value".parse().unwrap(),
            );
        }

        strip_hop_headers(&mut headers, false);

        for name in [
            "alt-svc",
            "connection",
            "proxy-connection",
            "proxy-authenticate",
            "proxy-authorization",
            "keep-alive",
            "te",
            "trailer",
            "transfer-encoding",
            "upgrade",
        ] {
            assert!(!headers.contains_key(name), "{name} should be stripped");
        }

        let mut headers = ::http::HeaderMap::new();
        headers.append(::http::header::CONNECTION, "X-First".parse().unwrap());
        headers.append(::http::header::CONNECTION, "X-Second".parse().unwrap());
        headers.insert("x-first", "one".parse().unwrap());
        headers.insert("x-second", "two".parse().unwrap());

        strip_hop_headers(&mut headers, false);

        assert!(!headers.contains_key("x-first"));
        assert!(!headers.contains_key("x-second"));
    }

    #[test]
    fn parse_backend_target_accepts_unix_socket_dials() {
        let target = parse_backend_target("unix//run/docker.sock").unwrap();
        assert!(matches!(target.scheme, BackendScheme::Unix));
        assert_eq!(target.host, "/run/docker.sock");
        assert_eq!(target.port, 0);
        assert_eq!(target.base_path, "");
        assert_eq!(target.base_query, None);
        assert_eq!(
            build_backend_uri(&target, &"/v1.41/info?pretty=1".parse().unwrap()).unwrap(),
            "/v1.41/info?pretty=1"
        );

        let target = parse_backend_target("unix/relative.sock").unwrap();
        assert!(matches!(target.scheme, BackendScheme::Unix));
        assert_eq!(target.host, "relative.sock");
    }

    #[test]
    fn etag_header_value_preserves_sidecar_entity_tags() {
        assert_eq!(etag_header_value("abc").to_str().unwrap(), "\"abc\"");
        assert_eq!(
            etag_header_value("\"sidecar\"").to_str().unwrap(),
            "\"sidecar\""
        );
        assert_eq!(
            etag_header_value("W/\"sidecar\"").to_str().unwrap(),
            "W/\"sidecar\""
        );
    }

    #[test]
    fn empty_etags_do_not_match_empty_entity_tag_headers() {
        let mut headers = ::http::HeaderMap::new();
        headers.insert(::http::header::IF_NONE_MATCH, "\"\"".parse().unwrap());
        assert!(!if_none_match_matches(&headers, ""));

        headers.insert(::http::header::IF_NONE_MATCH, "*".parse().unwrap());
        assert!(if_none_match_matches(&headers, ""));

        let not_modified = not_modified_headers("", 100);
        assert!(!not_modified.contains_key(::http::header::ETAG));

        let precondition_failed = precondition_failed_headers("", 100);
        assert!(!precondition_failed.contains_key(::http::header::ETAG));
    }
}
