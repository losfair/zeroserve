use super::*;
use std::{
    cell::RefCell,
    collections::{BTreeMap, HashMap},
    fs,
    path::{Path, PathBuf},
    rc::Rc,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use ::http::{HeaderName, HeaderValue, Method, StatusCode};
use bytes::Bytes;

use crate::{
    boringtls::BoringStream,
    caddy_file::{
        file_hidden as caddy_file_hidden, fs_file_hidden as caddy_fs_file_hidden,
        join_file_path as join_caddy_file_path,
    },
    http::h1::RequestHead,
    script::{
        CaddyFileServer, ConnectionInfo, RawResponseHookOutcome, ResponseHook, ResponseHookOutcome,
        ScriptOutcome, ScriptRequest, ScriptRuntime,
    },
    shared::{SharedState, read_fs_file},
    site::{NormalizedPath, Site},
};

#[derive(Clone, Copy)]
pub(super) enum EarlyHeaderMerge {
    Overlay,
    PreserveStaticValidators,
    Prepend,
}

impl Default for EarlyHeaderMerge {
    fn default() -> Self {
        Self::Overlay
    }
}

struct CaddyStaticResponse {
    response: StaticResponse,
    header_merge: EarlyHeaderMerge,
}

struct CaddyEtag {
    value: String,
    sidecar: bool,
}

impl CaddyEtag {
    fn computed(value: String) -> Self {
        Self {
            value,
            sidecar: false,
        }
    }

    fn sidecar(value: String) -> Self {
        Self {
            value,
            sidecar: true,
        }
    }

    fn as_str(&self) -> &str {
        &self.value
    }

    fn header_value(&self) -> HeaderValue {
        if self.sidecar {
            HeaderValue::from_str(&self.value).unwrap_or_else(|_| HeaderValue::from_static("\"\""))
        } else {
            etag_header_value(&self.value)
        }
    }
}

impl CaddyStaticResponse {
    fn overlay(response: StaticResponse) -> Self {
        Self {
            response,
            header_merge: EarlyHeaderMerge::Overlay,
        }
    }

    fn preserve_static_validators(response: StaticResponse) -> Self {
        Self {
            response,
            header_merge: EarlyHeaderMerge::PreserveStaticValidators,
        }
    }
}

pub(super) struct ResponseHookState<'a> {
    pub(super) script_runtime: &'a Rc<ScriptRuntime>,
    pub(super) site: Arc<Site>,
    pub(super) request: Rc<RefCell<ScriptRequest>>,
    pub(super) metadata: Rc<RefCell<HashMap<String, String>>>,
    pub(super) caddy_maps: Rc<RefCell<Vec<crate::script::CaddyMapConfig>>>,
    pub(super) hooks: &'a [ResponseHook],
}

impl<'a> ResponseHookState<'a> {
    pub(super) fn from_outcome(
        script_runtime: &'a Rc<ScriptRuntime>,
        shared: &Arc<SharedState>,
        outcome: &'a ScriptOutcome,
    ) -> Self {
        Self {
            script_runtime,
            site: shared.site.load_full(),
            request: outcome.request_shared.clone(),
            metadata: outcome.metadata_shared.clone(),
            caddy_maps: outcome.caddy_maps_shared.clone(),
            hooks: &outcome.response_hooks,
        }
    }

    pub(super) async fn run(
        &self,
        status: StatusCode,
        headers: &mut ::http::HeaderMap,
    ) -> ResponseHookOutcome {
        self.populate_intercept_metadata(status.as_u16(), headers);
        let mut outcome = self
            .script_runtime
            .run_response_hooks(
                self.site.clone(),
                self.request.clone(),
                self.metadata.clone(),
                self.caddy_maps.clone(),
                self.hooks,
                status,
                headers,
            )
            .await;
        apply_metadata_response_headers(headers, &self.metadata.borrow());
        outcome.status = StatusCode::from_u16(outcome.status.as_u16()).unwrap_or(status);
        outcome
    }

    pub(super) async fn run_raw_h1_outcome(
        &self,
        status: u16,
        headers: &mut ::http::HeaderMap,
    ) -> RawResponseHookOutcome {
        self.populate_intercept_metadata(status, headers);
        let outcome = self
            .script_runtime
            .run_response_hooks_raw(
                self.site.clone(),
                self.request.clone(),
                self.metadata.clone(),
                self.caddy_maps.clone(),
                self.hooks,
                status,
                headers,
            )
            .await;
        apply_metadata_response_headers(headers, &self.metadata.borrow());
        outcome
    }

    fn populate_intercept_metadata(&self, status: u16, headers: &::http::HeaderMap) {
        let mut metadata = self.metadata.borrow_mut();
        metadata.retain(|key, _| !key.starts_with("http.intercept.header."));
        metadata.insert("http.intercept.status_code".to_string(), status.to_string());

        let mut grouped = BTreeMap::<String, Vec<String>>::new();
        for (name, value) in headers.iter() {
            let Ok(value) = value.to_str() else {
                continue;
            };
            grouped
                .entry(name.as_str().to_string())
                .or_default()
                .push(value.to_string());
        }
        for (name, values) in grouped {
            let joined = values.join(",");
            metadata.insert(format!("http.intercept.header.{name}"), joined.clone());
            metadata.insert(
                format!(
                    "http.intercept.header.{}",
                    caddy_canonical_header_name(&name)
                ),
                joined,
            );
        }
    }
}

pub(super) fn set_proxy_error_metadata(outcome: &ScriptOutcome, message: &str) {
    outcome.request_shared.borrow_mut().restore_original_uri();
    let mut metadata = outcome.metadata_shared.borrow_mut();
    metadata.insert("http.error.status_code".to_string(), "502".to_string());
    metadata.insert(
        "http.error.status_text".to_string(),
        "Bad Gateway".to_string(),
    );
    metadata.insert("http.error.message".to_string(), message.to_string());
    metadata.insert("http.error".to_string(), message.to_string());
}

pub(super) fn has_error_routes(outcome: &ScriptOutcome) -> bool {
    outcome
        .metadata_shared
        .borrow()
        .get("zs.caddy.has_error_routes")
        .is_some_and(|value| value == "1")
}

pub(super) async fn continue_h1_request<R: AsyncReadRent + 'static>(
    request_id: Ulid,
    script_runtime: &Rc<ScriptRuntime>,
    shared: &Arc<SharedState>,
    hook_state: &ResponseHookState<'_>,
    previous: &ScriptOutcome,
    body_state: &H1BodyState<R>,
    body_source: &BodySource,
    reader: h1::H1Connection<R>,
    preserved_body: Option<h1::Body>,
) -> (ScriptOutcome, h1::H1Connection<R>, h1::Body) {
    hook_state.request.borrow_mut().clear_proxy_overrides();
    match preserved_body {
        Some(preserved_body) => {
            *body_state.borrow_mut() = Some((reader, preserved_body));
            let continued = continue_request_with_body_source(
                request_id,
                script_runtime,
                shared,
                hook_state,
                previous,
                body_source.clone(),
            )
            .await;
            let (restored_reader, restored_body) = body_state.borrow_mut().take().unwrap();
            (continued, restored_reader, restored_body)
        }
        None => {
            let continued = continue_request_with_body_source(
                request_id,
                script_runtime,
                shared,
                hook_state,
                previous,
                BodySource::empty(),
            )
            .await;
            (continued, reader, h1::Body::None)
        }
    }
}

pub(super) async fn continue_h2_request(
    request_id: Ulid,
    script_runtime: &Rc<ScriptRuntime>,
    shared: &Arc<SharedState>,
    hook_state: &ResponseHookState<'_>,
    previous: &ScriptOutcome,
    body_state: &H2BodyState,
    body_source: &BodySource,
    preserved_body: Option<h2::RecvStream>,
) -> (ScriptOutcome, Option<h2::RecvStream>) {
    hook_state.request.borrow_mut().clear_proxy_overrides();
    match preserved_body {
        Some(body) => {
            *body_state.borrow_mut() = Some(body);
            let continued = continue_request_with_body_source(
                request_id,
                script_runtime,
                shared,
                hook_state,
                previous,
                body_source.clone(),
            )
            .await;
            (continued, body_state.borrow_mut().take())
        }
        None => {
            let continued = continue_request_with_body_source(
                request_id,
                script_runtime,
                shared,
                hook_state,
                previous,
                BodySource::empty(),
            )
            .await;
            (continued, None)
        }
    }
}

async fn continue_request_with_body_source(
    request_id: Ulid,
    script_runtime: &Rc<ScriptRuntime>,
    shared: &Arc<SharedState>,
    hook_state: &ResponseHookState<'_>,
    previous: &ScriptOutcome,
    body_source: BodySource,
) -> ScriptOutcome {
    match script_runtime
        .run_request_with_state(
            shared.site.load_full(),
            hook_state.request.clone(),
            previous.metadata_shared.clone(),
            previous.caddy_maps_shared.clone(),
            body_source,
        )
        .await
    {
        Ok(outcome) => outcome,
        Err(err) => {
            async_log(
                format!(
                    "[handle] {}: continued script runtime: {:?}\n",
                    request_id, err
                )
                .into_bytes(),
            )
            .await;
            ScriptOutcome::from_request(hook_state.request.borrow().clone())
        }
    }
}

pub(super) fn apply_early_response_headers_with_mode(
    headers: &mut ::http::HeaderMap,
    early_response_headers: &::http::HeaderMap,
    mode: EarlyHeaderMerge,
) {
    for header_name in early_response_headers.keys() {
        let values = early_response_headers
            .get_all(header_name)
            .iter()
            .cloned()
            .collect::<Vec<_>>();
        if values.is_empty() {
            continue;
        }
        if header_name == ::http::header::CONTENT_LENGTH {
            continue;
        }

        match mode {
            EarlyHeaderMerge::Overlay => {
                if header_name == ::http::header::CONTENT_TYPE
                    || header_name == ::http::header::ETAG
                    || !headers.contains_key(header_name)
                {
                    headers.remove(header_name);
                }
                for value in values {
                    headers.append(header_name.clone(), value);
                }
            }
            EarlyHeaderMerge::PreserveStaticValidators => {
                if headers.contains_key(header_name)
                    && (header_name == ::http::header::ETAG
                        || header_name == ::http::header::LAST_MODIFIED
                        || header_name == ::http::header::ACCEPT_RANGES
                        || header_name == ::http::header::CONTENT_RANGE)
                {
                    continue;
                }
                if header_name == ::http::header::CONTENT_TYPE || !headers.contains_key(header_name)
                {
                    headers.remove(header_name);
                }
                if header_name == ::http::header::VARY {
                    let existing = headers
                        .get_all(header_name)
                        .iter()
                        .cloned()
                        .collect::<Vec<_>>();
                    headers.remove(header_name);
                    for value in values {
                        headers.append(header_name.clone(), value);
                    }
                    for value in existing {
                        headers.append(header_name.clone(), value);
                    }
                } else {
                    for value in values {
                        headers.append(header_name.clone(), value);
                    }
                }
            }
            EarlyHeaderMerge::Prepend => {
                let existing = headers
                    .get_all(header_name)
                    .iter()
                    .cloned()
                    .collect::<Vec<_>>();
                headers.remove(header_name);
                for value in values {
                    headers.append(header_name.clone(), value);
                }
                for value in existing {
                    headers.append(header_name.clone(), value);
                }
            }
        }
    }
}

pub(super) fn apply_response_headers(
    headers: &mut ::http::HeaderMap,
    early_response_headers: Option<&::http::HeaderMap>,
    metadata: &HashMap<String, String>,
) {
    apply_response_headers_with_mode(
        headers,
        early_response_headers,
        metadata,
        EarlyHeaderMerge::Overlay,
    );
}

pub(super) fn apply_response_headers_with_mode(
    headers: &mut ::http::HeaderMap,
    early_response_headers: Option<&::http::HeaderMap>,
    metadata: &HashMap<String, String>,
    mode: EarlyHeaderMerge,
) {
    if let Some(early_response_headers) = early_response_headers {
        apply_early_response_headers_with_mode(headers, early_response_headers, mode);
    }
    apply_metadata_response_headers(headers, metadata);
}

const RESPONSE_HEADER_PREFIX: &str = "zs.response.header.";

fn apply_metadata_response_headers(
    headers: &mut ::http::HeaderMap,
    metadata: &HashMap<String, String>,
) {
    for (key, value) in metadata {
        let Some(header_name) = key.strip_prefix(RESPONSE_HEADER_PREFIX) else {
            continue;
        };
        let header_name = header_name.trim();
        if header_name.is_empty() {
            continue;
        }
        let Ok(header_name) = HeaderName::from_bytes(header_name.as_bytes()) else {
            continue;
        };
        let Ok(header_value) = HeaderValue::from_str(value) else {
            continue;
        };
        headers.insert(header_name, header_value);
    }
}

pub(super) async fn prepare_fixed_response(
    res: &mut ::http::Response<Bytes>,
    early_response_headers: Option<&::http::HeaderMap>,
    metadata: &HashMap<String, String>,
    hook_state: Option<&ResponseHookState<'_>>,
) -> ResponseHookOutcome {
    apply_response_headers(res.headers_mut(), early_response_headers, metadata);
    super::ensure_content_length(res);
    let outcome = run_response_hooks(res.status(), res.headers_mut(), hook_state).await;
    *res.status_mut() = outcome.status;
    outcome
}

pub(super) async fn prepare_static_response_headers_raw_h1(
    response: &mut StaticResponse,
    early_response_headers: Option<&::http::HeaderMap>,
    metadata: &HashMap<String, String>,
    hook_state: Option<&ResponseHookState<'_>>,
) -> RawResponseHookOutcome {
    prepare_static_response_headers_raw_h1_with_mode(
        response,
        early_response_headers,
        metadata,
        hook_state,
        EarlyHeaderMerge::Overlay,
    )
    .await
}

async fn prepare_static_response_headers_raw_h1_with_mode(
    response: &mut StaticResponse,
    early_response_headers: Option<&::http::HeaderMap>,
    metadata: &HashMap<String, String>,
    hook_state: Option<&ResponseHookState<'_>>,
    header_merge: EarlyHeaderMerge,
) -> RawResponseHookOutcome {
    apply_response_headers_with_mode(
        &mut response.headers,
        early_response_headers,
        metadata,
        header_merge,
    );
    super::ensure_static_content_length(response);
    run_raw_h1_response_hooks(response.status.as_u16(), &mut response.headers, hook_state).await
}

pub(super) async fn prepare_static_response_headers(
    response: &mut StaticResponse,
    early_response_headers: Option<&::http::HeaderMap>,
    metadata: &HashMap<String, String>,
    hook_state: Option<&ResponseHookState<'_>>,
) -> ResponseHookOutcome {
    prepare_static_response_headers_with_mode(
        response,
        early_response_headers,
        metadata,
        hook_state,
        EarlyHeaderMerge::Overlay,
    )
    .await
}

async fn prepare_static_response_headers_with_mode(
    response: &mut StaticResponse,
    early_response_headers: Option<&::http::HeaderMap>,
    metadata: &HashMap<String, String>,
    hook_state: Option<&ResponseHookState<'_>>,
    header_merge: EarlyHeaderMerge,
) -> ResponseHookOutcome {
    apply_response_headers_with_mode(
        &mut response.headers,
        early_response_headers,
        metadata,
        header_merge,
    );
    super::ensure_static_content_length(response);
    let outcome = run_response_hooks(response.status, &mut response.headers, hook_state).await;
    response.status = outcome.status;
    outcome
}

pub(super) async fn run_response_hooks(
    status: StatusCode,
    headers: &mut ::http::HeaderMap,
    hook_state: Option<&ResponseHookState<'_>>,
) -> ResponseHookOutcome {
    if let Some(hook_state) = hook_state {
        hook_state.run(status, headers).await
    } else {
        ResponseHookOutcome {
            status,
            continue_request: false,
        }
    }
}

pub(super) async fn run_raw_h1_response_hooks(
    status: u16,
    headers: &mut ::http::HeaderMap,
    hook_state: Option<&ResponseHookState<'_>>,
) -> RawResponseHookOutcome {
    if let Some(hook_state) = hook_state {
        hook_state.run_raw_h1_outcome(status, headers).await
    } else {
        RawResponseHookOutcome {
            status,
            continue_request: false,
        }
    }
}

pub(super) fn tls_connection_info<IO>(
    tls_stream: &BoringStream<IO>,
    alpn: Option<String>,
    outer_sni: Option<String>,
    ech_accepted: Option<bool>,
) -> ConnectionInfo {
    ConnectionInfo {
        tls: true,
        tls_handshake_complete: true,
        alpn,
        inner_sni: tls_stream.server_name(),
        outer_sni,
        ech_accepted,
        tls_version: Some(tls_stream.caddy_tls_version()),
        tls_cipher_suite: tls_stream.caddy_tls_cipher_suite(),
        tls_resumed: Some(tls_stream.tls_session_reused()),
        tls_client_ja4: tls_stream.ja4_fingerprint(),
        tls_client_cert_der: tls_stream.peer_certificate_der(),
        tls_client_chain_der: tls_stream.peer_certificate_chain_der(),
    }
}

pub(super) fn populate_reverse_proxy_response_state(
    hook_state: Option<&ResponseHookState<'_>>,
    status: StatusCode,
    raw_status_text: Option<&str>,
    headers: &mut ::http::HeaderMap,
    upstream_latency: Duration,
) {
    populate_reverse_proxy_response_metadata(
        hook_state,
        status,
        raw_status_text,
        headers,
        upstream_latency,
    );
}

pub(super) async fn prepare_reverse_proxy_raw_h1_response_headers(
    hook_state: Option<&ResponseHookState<'_>>,
    status: StatusCode,
    raw_status_text: Option<&str>,
    headers: &mut ::http::HeaderMap,
    upstream_latency: Duration,
    early_response_headers: Option<&::http::HeaderMap>,
    metadata: &HashMap<String, String>,
) -> RawResponseHookOutcome {
    populate_reverse_proxy_response_state(
        hook_state,
        status,
        raw_status_text,
        headers,
        upstream_latency,
    );
    let outcome = run_raw_h1_response_hooks(status.as_u16(), headers, hook_state).await;
    apply_response_headers_with_mode(
        headers,
        early_response_headers,
        metadata,
        EarlyHeaderMerge::Prepend,
    );
    outcome
}

pub(super) async fn prepare_reverse_proxy_response_headers(
    hook_state: Option<&ResponseHookState<'_>>,
    status: StatusCode,
    raw_status_text: Option<&str>,
    headers: &mut ::http::HeaderMap,
    upstream_latency: Duration,
    early_response_headers: Option<&::http::HeaderMap>,
    metadata: &HashMap<String, String>,
) -> ResponseHookOutcome {
    populate_reverse_proxy_response_state(
        hook_state,
        status,
        raw_status_text,
        headers,
        upstream_latency,
    );
    let outcome = run_response_hooks(status, headers, hook_state).await;
    apply_response_headers_with_mode(
        headers,
        early_response_headers,
        metadata,
        EarlyHeaderMerge::Prepend,
    );
    outcome
}

pub(super) async fn prepare_script_response_raw_h1_headers(
    status: u16,
    headers: &mut ::http::HeaderMap,
    metadata: &HashMap<String, String>,
    hook_state: Option<&ResponseHookState<'_>>,
) -> RawResponseHookOutcome {
    apply_metadata_response_headers(headers, metadata);
    run_raw_h1_response_hooks(status, headers, hook_state).await
}

pub(super) async fn prepare_script_response_headers(
    status: StatusCode,
    headers: &mut ::http::HeaderMap,
    metadata: &HashMap<String, String>,
    hook_state: Option<&ResponseHookState<'_>>,
) -> ResponseHookOutcome {
    apply_metadata_response_headers(headers, metadata);
    run_response_hooks(status, headers, hook_state).await
}

pub(super) fn populate_reverse_proxy_response_metadata(
    hook_state: Option<&ResponseHookState<'_>>,
    status: StatusCode,
    raw_status_text: Option<&str>,
    headers: &::http::HeaderMap,
    upstream_latency: Duration,
) {
    let Some(hook_state) = hook_state else {
        return;
    };
    let mut metadata = hook_state.metadata.borrow_mut();
    metadata.retain(|key, _| !key.starts_with("http.reverse_proxy.header."));
    metadata.insert(
        "http.reverse_proxy.status_code".to_string(),
        status.as_u16().to_string(),
    );
    let status_text = raw_status_text
        .filter(|status_text| !status_text.is_empty())
        .map(str::to_string)
        .or_else(|| {
            status
                .canonical_reason()
                .map(|reason| format!("{} {}", status.as_u16(), reason))
        })
        .unwrap_or_else(|| status.as_u16().to_string());
    metadata.insert("http.reverse_proxy.status_text".to_string(), status_text);
    metadata.insert(
        "http.reverse_proxy.upstream.latency".to_string(),
        caddy_duration_string(upstream_latency),
    );
    metadata.insert(
        "http.reverse_proxy.upstream.latency_ms".to_string(),
        caddy_duration_ms_string(upstream_latency),
    );

    let mut grouped = BTreeMap::<String, Vec<String>>::new();
    for (name, value) in headers.iter() {
        let Ok(value) = value.to_str() else {
            continue;
        };
        grouped
            .entry(name.as_str().to_string())
            .or_default()
            .push(value.to_string());
    }
    for (name, values) in grouped {
        let joined = values.join(",");
        metadata.insert(format!("http.reverse_proxy.header.{name}"), joined.clone());
        metadata.insert(
            format!(
                "http.reverse_proxy.header.{}",
                caddy_canonical_header_name(&name)
            ),
            joined,
        );
    }
}

fn caddy_duration_string(duration: Duration) -> String {
    let nanos = duration.as_nanos();
    if nanos < 1_000 {
        return format!("{nanos}ns");
    }
    if nanos < 1_000_000 {
        return caddy_duration_decimal(nanos, 1_000, "\u{00b5}s");
    }
    if nanos < 1_000_000_000 {
        return caddy_duration_decimal(nanos, 1_000_000, "ms");
    }
    if nanos < 60_000_000_000 {
        return caddy_duration_decimal(nanos, 1_000_000_000, "s");
    }
    if nanos < 3_600_000_000_000 {
        let minutes = nanos / 60_000_000_000;
        let rest = nanos % 60_000_000_000;
        if rest == 0 {
            format!("{minutes}m")
        } else {
            format!(
                "{minutes}m{}",
                caddy_duration_decimal(rest, 1_000_000_000, "s")
            )
        }
    } else {
        let hours = nanos / 3_600_000_000_000;
        let rest = nanos % 3_600_000_000_000;
        if rest == 0 {
            format!("{hours}h")
        } else {
            format!(
                "{hours}h{}",
                caddy_duration_string(Duration::from_nanos(rest as u64))
            )
        }
    }
}

fn caddy_duration_ms_string(duration: Duration) -> String {
    let millis = duration.as_secs_f64() * 1e3;
    let mut out = format!("{millis:.6}");
    while out.contains('.') && out.ends_with('0') {
        out.pop();
    }
    if out.ends_with('.') {
        out.pop();
    }
    out
}

fn caddy_duration_decimal(nanos: u128, unit: u128, suffix: &str) -> String {
    let whole = nanos / unit;
    let frac = nanos % unit;
    if frac == 0 {
        return format!("{whole}{suffix}");
    }
    let width = match unit {
        1_000 => 3,
        1_000_000 => 6,
        1_000_000_000 => 9,
        _ => 9,
    };
    let mut frac = format!("{frac:0width$}");
    while frac.ends_with('0') {
        frac.pop();
    }
    format!("{whole}.{frac}{suffix}")
}

pub(super) fn caddy_proxy_metadata_value(
    metadata: &HashMap<String, String>,
    hook_state: Option<&ResponseHookState<'_>>,
    key: &str,
) -> Option<String> {
    hook_state
        .and_then(|hook_state| hook_state.metadata.borrow().get(key).cloned())
        .or_else(|| metadata.get(key).cloned())
}

pub(super) struct RequestQueryParams {
    pub(super) values: HashMap<String, Vec<String>>,
    pub(super) valid: bool,
}

fn request_query_params(query: &str) -> RequestQueryParams {
    let (values, valid) = crate::script::parse_caddy_query_params(query);
    RequestQueryParams { values, valid }
}

pub(super) fn populate_request_fields(request: &mut ScriptRequest) {
    let caddy_query = request_query_params(&request.query);
    request.caddy_query_params = caddy_query.values;
    request.caddy_query_valid = caddy_query.valid;
}

pub(super) fn apply_request_uri(head: &mut RequestHead, request: &ScriptRequest) -> Result<()> {
    let wire_uri = script_request_wire_uri(request);
    let uri: Uri = wire_uri
        .parse()
        .map_err(|err| anyhow!("invalid script uri: {err}"))?;
    head.uri = uri;
    Ok(())
}

fn script_request_wire_uri(request: &ScriptRequest) -> String {
    let request_uri = &request.uri;
    if request_uri.is_empty() || request_uri == "?" {
        "/".to_string()
    } else if request_uri.starts_with('?') {
        format!("/{request_uri}")
    } else {
        request_uri.to_string()
    }
}

pub(super) fn reverse_proxy_uses_caddy_headers(
    metadata: &HashMap<String, String>,
    hook_state: Option<&ResponseHookState<'_>>,
) -> bool {
    caddy_proxy_metadata_value(metadata, hook_state, "zs.caddy.reverse_proxy").as_deref()
        == Some("1")
}

pub(super) fn prepare_reverse_proxy_request_headers_h1(
    headers: &mut ::http::HeaderMap,
    body: &h1::Body,
    websocket: bool,
    peer: std::net::SocketAddr,
    scheme: Scheme,
    metadata: &HashMap<String, String>,
    hook_state: Option<&ResponseHookState<'_>>,
) {
    strip_reverse_proxy_request_headers(headers, websocket, metadata, hook_state);
    super::apply_proxy_request_headers(headers, body);
    finish_reverse_proxy_request_headers(headers, peer, scheme, metadata, hook_state);
}

pub(super) fn prepare_reverse_proxy_request_headers_h2(
    headers: &mut ::http::HeaderMap,
    has_body: bool,
    peer: std::net::SocketAddr,
    scheme: Scheme,
    metadata: &HashMap<String, String>,
    hook_state: Option<&ResponseHookState<'_>>,
) -> bool {
    strip_reverse_proxy_request_headers(headers, false, metadata, hook_state);
    let chunked = super::apply_proxy_request_headers_h2(headers, has_body);
    finish_reverse_proxy_request_headers(headers, peer, scheme, metadata, hook_state);
    chunked
}

fn strip_reverse_proxy_request_headers(
    headers: &mut ::http::HeaderMap,
    websocket: bool,
    metadata: &HashMap<String, String>,
    hook_state: Option<&ResponseHookState<'_>>,
) {
    super::strip_proxy_request_hop_headers(
        headers,
        websocket,
        reverse_proxy_uses_caddy_headers(metadata, hook_state),
    );
}

fn finish_reverse_proxy_request_headers(
    headers: &mut ::http::HeaderMap,
    peer: std::net::SocketAddr,
    scheme: Scheme,
    metadata: &HashMap<String, String>,
    hook_state: Option<&ResponseHookState<'_>>,
) {
    apply_reverse_proxy_request_defaults(headers, metadata, hook_state);
    apply_reverse_proxy_forwarded_headers(headers, peer, scheme, metadata, hook_state);
}

fn apply_reverse_proxy_forwarded_headers(
    headers: &mut ::http::HeaderMap,
    peer: std::net::SocketAddr,
    scheme: Scheme,
    metadata: &HashMap<String, String>,
    hook_state: Option<&ResponseHookState<'_>>,
) {
    if !reverse_proxy_uses_caddy_headers(metadata, hook_state) {
        apply_caddy_forwarded_headers(headers, peer, scheme);
    }
}

fn apply_reverse_proxy_request_defaults(
    headers: &mut ::http::HeaderMap,
    metadata: &HashMap<String, String>,
    hook_state: Option<&ResponseHookState<'_>>,
) {
    if !headers.contains_key(::http::header::USER_AGENT) {
        headers.insert(
            ::http::header::USER_AGENT,
            ::http::HeaderValue::from_static(""),
        );
    }
    let compression_off =
        caddy_proxy_metadata_value(metadata, hook_state, "zs.caddy.reverse_proxy.compression")
            .as_deref()
            == Some("off");
    if !compression_off && !headers.contains_key(::http::header::ACCEPT_ENCODING) {
        headers.insert(
            ::http::header::ACCEPT_ENCODING,
            ::http::HeaderValue::from_static("gzip"),
        );
    }
}

fn caddy_canonical_header_name(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    let mut upper = true;
    for ch in name.chars() {
        if ch == '-' {
            out.push(ch);
            upper = true;
        } else if upper {
            out.extend(ch.to_uppercase());
            upper = false;
        } else {
            out.extend(ch.to_lowercase());
        }
    }
    out
}

pub(super) fn apply_caddy_forwarded_headers(
    headers: &mut ::http::HeaderMap,
    peer: std::net::SocketAddr,
    scheme: Scheme,
) {
    if let Ok(value) = ::http::HeaderValue::from_str(&peer.ip().to_string()) {
        headers.append("x-forwarded-for", value);
    }
    if !headers.contains_key("x-forwarded-proto")
        && let Ok(value) = ::http::HeaderValue::from_str(scheme.as_str())
    {
        headers.insert("x-forwarded-proto", value);
    }
    let host = headers
        .get(::http::header::HOST)
        .and_then(|value| value.to_str().ok())
        .map(str::to_string);
    if !headers.contains_key("x-forwarded-host")
        && let Some(host) = host
        && let Ok(value) = ::http::HeaderValue::from_str(&host)
    {
        headers.insert("x-forwarded-host", value);
    }
}

fn caddy_precondition_response(
    head: &RequestHead,
    etag: &CaddyEtag,
    last_modified: u64,
) -> Option<(StatusCode, ::http::HeaderMap)> {
    let etag_header = etag
        .header_value()
        .to_str()
        .map(str::to_string)
        .unwrap_or_default();
    if let Some(matched) = if_match_condition_response(&head.headers, &etag_header) {
        if !matched {
            return Some((
                StatusCode::PRECONDITION_FAILED,
                caddy_precondition_failed_headers(etag, last_modified),
            ));
        }
    } else if let Some(matched) = if_unmodified_since_condition(&head.headers, last_modified) {
        if !matched {
            return Some((
                StatusCode::PRECONDITION_FAILED,
                caddy_precondition_failed_headers(etag, last_modified),
            ));
        }
    }

    if head.headers.contains_key(::http::header::IF_NONE_MATCH) {
        if if_none_match_matches_response(&head.headers, &etag_header) {
            if matches!(head.method, Method::GET | Method::HEAD) {
                return Some((
                    StatusCode::NOT_MODIFIED,
                    caddy_not_modified_headers(etag, last_modified),
                ));
            }
            return Some((
                StatusCode::PRECONDITION_FAILED,
                caddy_precondition_failed_headers(etag, last_modified),
            ));
        }
    } else if matches!(head.method, Method::GET | Method::HEAD)
        && if_modified_since_matches(&head.headers, last_modified)
    {
        return Some((
            StatusCode::NOT_MODIFIED,
            caddy_not_modified_headers(etag, last_modified),
        ));
    }

    None
}

fn caddy_not_modified_headers(etag: &CaddyEtag, last_modified: u64) -> ::http::HeaderMap {
    let mut headers = not_modified_headers(etag.as_str(), last_modified);
    replace_caddy_validator_etag(&mut headers, etag);
    headers
}

fn caddy_precondition_failed_headers(etag: &CaddyEtag, last_modified: u64) -> ::http::HeaderMap {
    let mut headers = precondition_failed_headers(etag.as_str(), last_modified);
    replace_caddy_validator_etag(&mut headers, etag);
    headers
}

#[allow(clippy::too_many_arguments)]
async fn serve_caddy_file_server_h1(
    head: &RequestHead,
    shared: &Arc<SharedState>,
    head_only: bool,
    peer: std::net::SocketAddr,
    w: &mut impl AsyncWriteRent,
    early_response_headers: Option<&::http::HeaderMap>,
    metadata: &HashMap<String, String>,
    hook_state: Option<&ResponseHookState<'_>>,
    normalized_path: &NormalizedPath,
    config: &CaddyFileServer,
    request: &ScriptRequest,
    encode: Option<&crate::helpers::compress::EncodeState>,
) -> H1SendOutcome {
    let Some(caddy_response) = prepare_caddy_file_server_response(
        head,
        shared,
        head_only,
        metadata,
        normalized_path,
        config,
        request,
    )
    .await
    else {
        let mut response = caddy_file_server_not_found_static_response(shared.site.load_full());
        apply_response_headers_with_mode(
            &mut response.headers,
            early_response_headers,
            metadata,
            EarlyHeaderMerge::Overlay,
        );
        super::ensure_static_content_length(&mut response);
        let status = response.status.as_u16();
        let send_body = raw_status_allows_body(status);
        if !send_body {
            strip_no_body_headers(&mut response.headers);
        }
        return send_prepared_static_response_h1(
            w, shared, peer, response, status, send_body, None,
        )
        .await;
    };
    if matches!(
        caddy_response.header_merge,
        EarlyHeaderMerge::PreserveStaticValidators
    ) && !matches!(head.method, Method::GET | Method::HEAD)
        && !metadata.contains_key("http.error.status_code")
    {
        return send_fixed(
            w,
            file_server_method_not_allowed(),
            early_response_headers,
            metadata,
            hook_state,
        )
        .await;
    }
    let mut response = caddy_response.response;
    let hook_outcome = prepare_static_response_headers_raw_h1_with_mode(
        &mut response,
        early_response_headers,
        metadata,
        hook_state,
        caddy_response.header_merge,
    )
    .await;
    let _ = hook_outcome.continue_request;
    let status = hook_outcome.status;
    let send_body = raw_status_allows_body(status);
    if !send_body {
        strip_no_body_headers(&mut response.headers);
    }
    send_prepared_static_response_h1(w, shared, peer, response, status, send_body, encode).await
}

pub(super) async fn try_serve_file_server_response_h1<R, W>(
    head: &RequestHead,
    shared: &Arc<SharedState>,
    head_only: bool,
    peer: std::net::SocketAddr,
    reader: &mut h1::H1Connection<R>,
    body: &mut h1::Body,
    w: &mut W,
    outcome: &ScriptOutcome,
    hook_state: &ResponseHookState<'_>,
    normalized_path: &NormalizedPath,
) -> Option<H1SendOutcome>
where
    R: AsyncReadRent + 'static,
    W: AsyncWriteRent,
{
    let Some(config) = &outcome.file_server else {
        return None;
    };
    super::drain_payload(reader, body).await;
    let encode_state = outcome.encode.clone().map(|config| {
        crate::helpers::compress::EncodeState::from_request_headers(config, &head.headers)
    });
    Some(
        serve_caddy_file_server_h1(
            head,
            shared,
            head_only,
            peer,
            w,
            Some(&outcome.early_response_headers),
            &outcome.metadata,
            Some(hook_state),
            normalized_path,
            config,
            &outcome.request,
            encode_state.as_ref(),
        )
        .await,
    )
}

pub(super) async fn try_serve_file_server_response_h2(
    head: &RequestHead,
    shared: &Arc<SharedState>,
    head_only: bool,
    respond: &mut h2::server::SendResponse<Bytes>,
    outcome: &ScriptOutcome,
    hook_state: &ResponseHookState<'_>,
    normalized_path: &NormalizedPath,
) -> Result<Option<u16>> {
    let Some(config) = &outcome.file_server else {
        return Ok(None);
    };
    let encode_state = outcome.encode.clone().map(|config| {
        crate::helpers::compress::EncodeState::from_request_headers(config, &head.headers)
    });
    let status = serve_caddy_file_server_h2(
        head,
        shared,
        head_only,
        respond,
        Some(&outcome.early_response_headers),
        &outcome.metadata,
        Some(hook_state),
        normalized_path,
        config,
        &outcome.request,
        encode_state.as_ref(),
    )
    .await?;
    Ok(Some(status))
}

#[allow(clippy::too_many_arguments)]
async fn serve_caddy_file_server_h2(
    head: &RequestHead,
    shared: &Arc<SharedState>,
    head_only: bool,
    respond: &mut h2::server::SendResponse<Bytes>,
    early_response_headers: Option<&::http::HeaderMap>,
    metadata: &HashMap<String, String>,
    hook_state: Option<&ResponseHookState<'_>>,
    normalized_path: &NormalizedPath,
    config: &CaddyFileServer,
    request: &ScriptRequest,
    encode: Option<&crate::helpers::compress::EncodeState>,
) -> Result<u16> {
    let Some(caddy_response) = prepare_caddy_file_server_response(
        head,
        shared,
        head_only,
        metadata,
        normalized_path,
        config,
        request,
    )
    .await
    else {
        let mut response = caddy_file_server_not_found_static_response(shared.site.load_full());
        apply_response_headers_with_mode(
            &mut response.headers,
            early_response_headers,
            metadata,
            EarlyHeaderMerge::Overlay,
        );
        super::ensure_static_content_length(&mut response);
        let send_body = status_allows_body(response.status);
        if !send_body {
            strip_no_body_headers(&mut response.headers);
        }
        let status = response.status.as_u16();
        send_prepared_static_response_h2(respond, shared, response, send_body, None).await?;
        return Ok(status);
    };
    if matches!(
        caddy_response.header_merge,
        EarlyHeaderMerge::PreserveStaticValidators
    ) && !matches!(head.method, Method::GET | Method::HEAD)
        && !metadata.contains_key("http.error.status_code")
    {
        let status = send_h2_response(
            respond,
            file_server_method_not_allowed(),
            head_only,
            early_response_headers,
            metadata,
            hook_state,
        )
        .await?;
        return Ok(status);
    }
    let mut response = caddy_response.response;
    let hook_outcome = prepare_static_response_headers_with_mode(
        &mut response,
        early_response_headers,
        metadata,
        hook_state,
        caddy_response.header_merge,
    )
    .await;
    let _ = hook_outcome.continue_request;
    let send_body = status_allows_body(response.status);
    if !send_body {
        strip_no_body_headers(&mut response.headers);
    }
    let status = response.status.as_u16();
    send_prepared_static_response_h2(respond, shared, response, send_body, encode).await?;
    Ok(status)
}

fn file_server_method_not_allowed() -> ::http::Response<Bytes> {
    let mut response = method_not_allowed();
    response.headers_mut().insert(
        ::http::header::ALLOW,
        ::http::HeaderValue::from_static("GET, HEAD"),
    );
    response
}

async fn prepare_caddy_file_server_response(
    head: &RequestHead,
    shared: &Arc<SharedState>,
    head_only: bool,
    metadata: &HashMap<String, String>,
    normalized_path: &NormalizedPath,
    config: &CaddyFileServer,
    request: &ScriptRequest,
) -> Option<CaddyStaticResponse> {
    let config = expand_caddy_file_server_config(config, metadata);
    let config = &config;
    if !config.fs.is_empty()
        && config.fs != "file"
        && config.fs != "default"
        && config.fs != "{http.vars.fs}"
    {
        return None;
    }
    let site = shared.site.load_full();
    let indexes = config
        .index_names
        .clone()
        .unwrap_or_else(|| vec!["index.html".to_string(), "index.txt".to_string()]);
    let root =
        normalize_caddy_file_root(&config.root, caddy_fs_name_forces_filesystem(&config.fs))?;
    if let CaddyFileRoot::Fs(root) = &root {
        if !shared.config.expose_filesystem {
            return None;
        }
        return prepare_caddy_fs_file_server_response(
            head,
            head_only,
            metadata,
            normalized_path,
            config,
            root,
            &indexes,
            site,
            request,
        )
        .await;
    }
    let CaddyFileRoot::Tar(root) = root else {
        unreachable!();
    };
    let rel = join_caddy_file_path(&root, normalized_path.relative())?;
    let canonical = config.canonical_uris.unwrap_or(true);

    let mut implicit_index = false;
    let mut browse_dir = None;
    let entry = if let Some(entry) = get_site_entry(&site, &rel) {
        Some(entry)
    } else if site.directories.contains(&rel) || normalized_path.dir_hint() || rel.is_empty() {
        let mut found = None;
        for index in &indexes {
            let index_path = join_caddy_file_path(&rel, index)?;
            if caddy_file_hidden(&index_path, &config.hide) {
                continue;
            }
            if let Some(entry) = get_site_entry(&site, &index_path) {
                implicit_index = true;
                found = Some(entry);
                break;
            }
        }
        if found.is_none() {
            browse_dir = Some(rel.clone());
        }
        found
    } else {
        return None;
    };

    if let Some(dir) = browse_dir {
        config.browse.as_ref()?;
        if caddy_file_hidden(&dir, &config.hide) {
            return None;
        }
        if caddy_browse_redirect_allowed(request) && !request.original_path.ends_with('/') {
            return Some(CaddyStaticResponse::overlay(redirect_static_response(
                caddy_redirect_path(&request.original_path, head.uri.query(), true),
                site,
            )));
        }
        return prepare_caddy_browse_response(head, head_only, site, &dir, config);
    }

    let entry = entry?;

    if caddy_file_hidden(&entry.path, &config.hide) {
        return None;
    }

    if canonical && caddy_canonical_redirect_allowed(request) {
        let path = &request.original_path;
        if implicit_index && !path.ends_with('/') {
            return Some(CaddyStaticResponse::overlay(redirect_static_response(
                caddy_redirect_path(path, head.uri.query(), true),
                site,
            )));
        }
        if !implicit_index && path.ends_with('/') && path.len() > 1 {
            return Some(CaddyStaticResponse::overlay(redirect_static_response(
                caddy_redirect_path(path, head.uri.query(), false),
                site,
            )));
        }
    }

    let status = match caddy_file_server_status(config, metadata) {
        Ok(status) => status,
        Err(_) => {
            return Some(CaddyStaticResponse::overlay(
                internal_server_error_static_response(site),
            ));
        }
    };
    prepare_static_entry_response(head, head_only, site, entry, status, config).await
}

pub(super) fn expand_caddy_file_server_config(
    config: &CaddyFileServer,
    metadata: &HashMap<String, String>,
) -> CaddyFileServer {
    let mut config = config.clone();
    config.fs = if config.fs.is_empty() {
        expand_metadata_placeholders("{http.vars.fs}", metadata)
    } else {
        expand_metadata_placeholders(&config.fs, metadata)
    };
    config.root = if config.root.is_empty() {
        let root = expand_metadata_placeholders("{http.vars.root}", metadata);
        if root.is_empty() {
            ".".to_string()
        } else {
            root
        }
    } else {
        expand_metadata_placeholders(&config.root, metadata)
    };
    for value in &mut config.hide {
        *value = expand_metadata_placeholders(value, metadata);
    }
    if let Some(index_names) = &mut config.index_names {
        for value in index_names {
            *value = expand_metadata_placeholders(value, metadata);
        }
    }
    config
}

pub(super) enum CaddyFileRoot {
    Tar(String),
    Fs(PathBuf),
}

async fn prepare_caddy_fs_file_server_response(
    head: &RequestHead,
    head_only: bool,
    metadata: &HashMap<String, String>,
    normalized_path: &NormalizedPath,
    config: &CaddyFileServer,
    root: &Path,
    indexes: &[String],
    site: Arc<Site>,
    request: &ScriptRequest,
) -> Option<CaddyStaticResponse> {
    let canonical = config.canonical_uris.unwrap_or(true);
    let rel = normalized_path.relative();
    let mut path = caddy_fs_join(root, rel)?;
    let mut logical = join_caddy_file_path("", rel)?;
    let mut meta = match caddy_fs_metadata_response(&path, &site) {
        Ok(meta) => meta,
        Err(response) => return Some(CaddyStaticResponse::overlay(response)),
    };

    let mut implicit_index = false;
    let mut browse_dir = None;
    if meta.is_dir() {
        let mut found = None;
        for index in indexes {
            let index_path = caddy_fs_join(&path, index)?;
            let index_logical = join_caddy_file_path(&logical, index)?;
            if caddy_fs_file_hidden(&index_logical, &index_path, &config.hide) {
                continue;
            }
            let Ok(index_meta) = fs::metadata(&index_path) else {
                continue;
            };
            if index_meta.is_file() {
                found = Some((index_path, index_logical, index_meta));
                break;
            }
        }
        if let Some((index_path, index_logical, index_meta)) = found {
            path = index_path;
            logical = index_logical;
            meta = index_meta;
            implicit_index = true;
        } else {
            browse_dir = Some((path.clone(), logical.clone()));
        }
    }

    if let Some((dir_path, dir_logical)) = browse_dir {
        config.browse.as_ref()?;
        if caddy_fs_file_hidden(&dir_logical, &dir_path, &config.hide) {
            return None;
        }
        if caddy_browse_redirect_allowed(request) && !request.original_path.ends_with('/') {
            return Some(CaddyStaticResponse::overlay(redirect_static_response(
                caddy_redirect_path(&request.original_path, head.uri.query(), true),
                site,
            )));
        }
        return prepare_caddy_fs_browse_response(head, head_only, site, &dir_path, config);
    }

    if !meta.is_file() || caddy_fs_file_hidden(&logical, &path, &config.hide) {
        return None;
    }

    if canonical && caddy_canonical_redirect_allowed(request) {
        let request_path = &request.original_path;
        if implicit_index && !request_path.ends_with('/') {
            return Some(CaddyStaticResponse::overlay(redirect_static_response(
                caddy_redirect_path(request_path, head.uri.query(), true),
                site,
            )));
        }
        if !implicit_index && request_path.ends_with('/') && request_path.len() > 1 {
            return Some(CaddyStaticResponse::overlay(redirect_static_response(
                caddy_redirect_path(request_path, head.uri.query(), false),
                site,
            )));
        }
    }

    let status = match caddy_file_server_status(config, metadata) {
        Ok(status) => status,
        Err(_) => {
            return Some(CaddyStaticResponse::overlay(
                internal_server_error_static_response(site),
            ));
        }
    };
    prepare_fs_entry_response(head, head_only, site, path, meta, status, config).await
}

fn caddy_file_server_status(
    config: &CaddyFileServer,
    metadata: &HashMap<String, String>,
) -> Result<StatusCode, ()> {
    let Some(code_template) = config.status_code.as_deref() else {
        return Ok(metadata
            .get("http.error.status_code")
            .and_then(|status| status.parse::<u16>().ok())
            .and_then(|status| StatusCode::from_u16(status).ok())
            .unwrap_or(StatusCode::OK));
    };
    let code = expand_metadata_placeholders(code_template, metadata);
    if code.is_empty() {
        return Err(());
    }
    let code = code.parse::<u16>().map_err(|_| ())?;
    if code == 0 {
        return Ok(StatusCode::OK);
    }
    StatusCode::from_u16(code).map_err(|_| ())
}

fn expand_metadata_placeholders(input: &str, metadata: &HashMap<String, String>) -> String {
    let mut out = String::with_capacity(input.len());
    let mut rest = input;
    while let Some(start) = rest.find('{') {
        let (before, after_start) = rest.split_at(start);
        out.push_str(before);
        let after_start = &after_start[1..];
        if let Some(end) = after_start.find('}') {
            let key = &after_start[..end];
            if let Some(value) = metadata.get(key) {
                out.push_str(value);
            }
            rest = &after_start[end + 1..];
        } else {
            out.push('{');
            out.push_str(after_start);
            rest = "";
            break;
        }
    }
    out.push_str(rest);
    out
}

fn caddy_fs_metadata_response(
    path: &Path,
    site: &Arc<Site>,
) -> Result<fs::Metadata, StaticResponse> {
    fs::metadata(path).map_err(|err| match err.kind() {
        std::io::ErrorKind::NotFound | std::io::ErrorKind::NotADirectory => {
            caddy_file_server_not_found_static_response(site.clone())
        }
        std::io::ErrorKind::PermissionDenied => forbidden_static_response(site.clone()),
        std::io::ErrorKind::InvalidInput => bad_request_static_response(site.clone()),
        _ => internal_server_error_static_response(site.clone()),
    })
}

fn caddy_fs_open_response(path: &Path, site: &Arc<Site>) -> Result<(), StaticResponse> {
    std::fs::File::open(path)
        .map(|_| ())
        .map_err(|err| match err.kind() {
            std::io::ErrorKind::NotFound | std::io::ErrorKind::NotADirectory => {
                caddy_file_server_not_found_static_response(site.clone())
            }
            std::io::ErrorKind::PermissionDenied => forbidden_static_response(site.clone()),
            std::io::ErrorKind::InvalidInput => bad_request_static_response(site.clone()),
            _ => internal_server_error_static_response(site.clone()),
        })
}

async fn prepare_static_entry_response(
    head: &RequestHead,
    head_only: bool,
    site: Arc<Site>,
    entry: Arc<crate::site::TarEntry>,
    status: StatusCode,
    config: &CaddyFileServer,
) -> Option<CaddyStaticResponse> {
    let mime = caddy_file_content_type(&entry.path);
    let (body_entry, content_encoding) =
        select_caddy_precompressed_entry(head, &site, &entry, config)
            .unwrap_or((entry.clone(), None));
    let etag = match caddy_entry_etag(&site, &body_entry, config).await {
        Ok(etag) => etag,
        Err(_) => {
            return Some(CaddyStaticResponse::overlay(
                internal_server_error_static_response(site),
            ));
        }
    };
    let use_validators = caddy_useful_mod_time(body_entry.mtime);

    if use_validators
        && let Some((precondition_status, mut headers)) =
            caddy_precondition_response(head, &etag, body_entry.mtime)
    {
        replace_caddy_validator_etag(&mut headers, &etag);
        insert_caddy_file_vary_header(&mut headers);
        insert_precondition_content_type(&mut headers, precondition_status, mime);
        let status = caddy_status_override(status, precondition_status, &mut headers);
        return Some(CaddyStaticResponse::preserve_static_validators(
            StaticResponse {
                status,
                headers,
                body: StaticBody::Empty,
                head_only: true,
                site,
            },
        ));
    }

    let mut headers = build_caddy_file_headers(body_entry.size, mime);
    insert_caddy_validator_headers(&mut headers, &etag, body_entry.mtime);
    headers.insert(
        ::http::header::ACCEPT_RANGES,
        ::http::HeaderValue::from_static("bytes"),
    );
    insert_caddy_file_vary_header(&mut headers);
    if let Some(content_encoding) = content_encoding {
        headers.insert(
            ::http::header::CONTENT_ENCODING,
            ::http::HeaderValue::from_static(content_encoding),
        );
    }
    let (range_etag, range_last_modified) = if use_validators {
        (etag.as_str(), body_entry.mtime)
    } else {
        ("", 0)
    };
    let outcome = super::apply_caddy_range(
        head,
        &mut headers,
        body_entry.size,
        range_etag,
        range_last_modified,
    );
    let (range_status, body) = match outcome {
        super::CaddyRangeOutcome::Full => (
            StatusCode::OK,
            StaticBody::File {
                entry: body_entry,
                range: None,
            },
        ),
        super::CaddyRangeOutcome::Single(range) => (
            StatusCode::PARTIAL_CONTENT,
            StaticBody::File {
                entry: body_entry,
                range: Some(range),
            },
        ),
        super::CaddyRangeOutcome::Unsatisfiable(message) => (
            StatusCode::RANGE_NOT_SATISFIABLE,
            StaticBody::Bytes(message),
        ),
    };
    let status = if status != StatusCode::OK {
        status
    } else if range_status != StatusCode::OK {
        range_status
    } else {
        status
    };
    Some(CaddyStaticResponse::preserve_static_validators(
        StaticResponse {
            status,
            headers,
            body,
            head_only,
            site,
        },
    ))
}

async fn prepare_fs_entry_response(
    head: &RequestHead,
    head_only: bool,
    site: Arc<Site>,
    path: PathBuf,
    meta: fs::Metadata,
    status: StatusCode,
    config: &CaddyFileServer,
) -> Option<CaddyStaticResponse> {
    let mime = caddy_file_content_type(path.to_string_lossy().as_ref());
    let (body_path, body_meta, content_encoding) =
        select_caddy_precompressed_fs_file(head, &path, config).unwrap_or((path, meta, None));
    if let Err(response) = caddy_fs_open_response(&body_path, &site) {
        return Some(CaddyStaticResponse::overlay(response));
    }
    let etag = match caddy_fs_etag(&body_path, &body_meta, config).await {
        Ok(etag) => etag,
        Err(_) => {
            return Some(CaddyStaticResponse::overlay(
                internal_server_error_static_response(site),
            ));
        }
    };
    let size = body_meta.len();
    let last_modified = body_meta
        .modified()
        .ok()
        .and_then(system_time_secs)
        .unwrap_or(0);
    let use_validators = caddy_useful_mod_time(last_modified);

    if use_validators
        && let Some((precondition_status, mut headers)) =
            caddy_precondition_response(head, &etag, last_modified)
    {
        replace_caddy_validator_etag(&mut headers, &etag);
        insert_caddy_file_vary_header(&mut headers);
        insert_precondition_content_type(&mut headers, precondition_status, mime);
        let status = caddy_status_override(status, precondition_status, &mut headers);
        return Some(CaddyStaticResponse::preserve_static_validators(
            StaticResponse {
                status,
                headers,
                body: StaticBody::Empty,
                head_only: true,
                site,
            },
        ));
    }

    let mut headers = build_caddy_file_headers(size, mime);
    insert_caddy_validator_headers(&mut headers, &etag, last_modified);
    headers.insert(
        ::http::header::ACCEPT_RANGES,
        ::http::HeaderValue::from_static("bytes"),
    );
    insert_caddy_file_vary_header(&mut headers);
    if let Some(content_encoding) = content_encoding {
        headers.insert(
            ::http::header::CONTENT_ENCODING,
            ::http::HeaderValue::from_static(content_encoding),
        );
    }
    let (range_etag, range_last_modified) = if use_validators {
        (etag.as_str(), last_modified)
    } else {
        ("", 0)
    };
    let outcome =
        super::apply_caddy_range(head, &mut headers, size, range_etag, range_last_modified);
    let (range_status, body) = match outcome {
        super::CaddyRangeOutcome::Full => (
            StatusCode::OK,
            StaticBody::FsFile {
                path: body_path,
                size,
                range: None,
            },
        ),
        super::CaddyRangeOutcome::Single(range) => (
            StatusCode::PARTIAL_CONTENT,
            StaticBody::FsFile {
                path: body_path,
                size,
                range: Some(range),
            },
        ),
        super::CaddyRangeOutcome::Unsatisfiable(message) => (
            StatusCode::RANGE_NOT_SATISFIABLE,
            StaticBody::Bytes(message),
        ),
    };
    let status = if status != StatusCode::OK {
        status
    } else if range_status != StatusCode::OK {
        range_status
    } else {
        status
    };
    Some(CaddyStaticResponse::preserve_static_validators(
        StaticResponse {
            status,
            headers,
            body,
            head_only,
            site,
        },
    ))
}

fn insert_caddy_file_vary_header(headers: &mut ::http::HeaderMap) {
    headers.append(
        ::http::header::VARY,
        ::http::HeaderValue::from_static("Accept-Encoding"),
    );
}

fn build_caddy_file_headers(content_length: u64, content_type: Option<&str>) -> ::http::HeaderMap {
    if let Some(content_type) = content_type {
        return build_base_headers(content_length, content_type);
    }
    let mut headers = ::http::HeaderMap::new();
    let length = HeaderValue::from_str(&content_length.to_string())
        .unwrap_or_else(|_| HeaderValue::from_static("0"));
    headers.insert(::http::header::CONTENT_LENGTH, length);
    headers.insert(
        ::http::header::SERVER,
        HeaderValue::from_static(crate::SERVER_HEADER),
    );
    headers
}

fn caddy_file_content_type(path: &str) -> Option<&'static str> {
    match Path::new(path)
        .extension()
        .and_then(|s| s.to_str())
        .map(|ext| ext.to_ascii_lowercase())
        .as_deref()
    {
        Some("html") | Some("htm") => Some("text/html; charset=utf-8"),
        Some("css") => Some("text/css; charset=utf-8"),
        Some("js") | Some("mjs") => Some("text/javascript; charset=utf-8"),
        Some("json") => Some("application/json"),
        Some("png") => Some("image/png"),
        Some("jpg") | Some("jpeg") => Some("image/jpeg"),
        Some("gif") => Some("image/gif"),
        Some("svg") => Some("image/svg+xml"),
        Some("wasm") => Some("application/wasm"),
        Some("txt") => Some("text/plain; charset=utf-8"),
        Some("xml") => Some("text/xml; charset=utf-8"),
        Some("ico") => Some("image/vnd.microsoft.icon"),
        Some("webp") => Some("image/webp"),
        Some("avif") => Some("image/avif"),
        Some("woff") => Some("font/woff"),
        Some("woff2") => Some("font/woff2"),
        Some("pdf") => Some("application/pdf"),
        Some("md") => Some("text/markdown; charset=utf-8"),
        Some("gz") => Some("application/gzip"),
        _ => None,
    }
}

fn caddy_status_override(
    configured: StatusCode,
    actual: StatusCode,
    headers: &mut ::http::HeaderMap,
) -> StatusCode {
    if configured == StatusCode::OK {
        return actual;
    }
    headers.remove(::http::header::CONTENT_LENGTH);
    configured
}

fn select_caddy_precompressed_entry(
    head: &RequestHead,
    site: &Arc<Site>,
    entry: &Arc<crate::site::TarEntry>,
    config: &CaddyFileServer,
) -> Option<(Arc<crate::site::TarEntry>, Option<&'static str>)> {
    if config.precompressed.is_empty() {
        return None;
    }
    for encoding in accepted_caddy_precompressed_encodings(head, config) {
        let suffix = match encoding.as_str() {
            "gzip" => ".gz",
            "br" => ".br",
            "zstd" => ".zst",
            _ => continue,
        };
        if !config.precompressed.contains_key(&encoding) {
            continue;
        }
        let sidecar = format!("{}{}", entry.path, suffix);
        let Some(sidecar) = get_site_entry(site, &sidecar) else {
            continue;
        };
        let content_encoding = match encoding.as_str() {
            "gzip" => "gzip",
            "br" => "br",
            "zstd" => "zstd",
            _ => continue,
        };
        return Some((sidecar, Some(content_encoding)));
    }
    None
}

fn select_caddy_precompressed_fs_file(
    head: &RequestHead,
    path: &Path,
    config: &CaddyFileServer,
) -> Option<(PathBuf, fs::Metadata, Option<&'static str>)> {
    if config.precompressed.is_empty() {
        return None;
    }
    for encoding in accepted_caddy_precompressed_encodings(head, config) {
        let suffix = match encoding.as_str() {
            "gzip" => ".gz",
            "br" => ".br",
            "zstd" => ".zst",
            _ => continue,
        };
        if !config.precompressed.contains_key(&encoding) {
            continue;
        }
        let sidecar = PathBuf::from(format!("{}{}", path.to_string_lossy(), suffix));
        let Ok(meta) = fs::metadata(&sidecar) else {
            continue;
        };
        if !meta.is_file() {
            continue;
        }
        let content_encoding = match encoding.as_str() {
            "gzip" => "gzip",
            "br" => "br",
            "zstd" => "zstd",
            _ => continue,
        };
        return Some((sidecar, meta, Some(content_encoding)));
    }
    None
}

pub(super) fn accepted_caddy_precompressed_encodings(
    head: &RequestHead,
    config: &CaddyFileServer,
) -> Vec<String> {
    if head
        .headers
        .get("sec-websocket-key")
        .is_some_and(|value| !value.is_empty())
    {
        return Vec::new();
    }

    let Some(value) = head
        .headers
        .get(::http::header::ACCEPT_ENCODING)
        .and_then(|value| value.to_str().ok())
    else {
        return Vec::new();
    };

    #[derive(Clone)]
    struct EncodingPreference {
        encoding: String,
        q: f64,
        prefer_order: usize,
    }

    let preferred_order = config
        .precompressed_order
        .iter()
        .map(|encoding| encoding.to_ascii_lowercase())
        .collect::<Vec<_>>();
    let mut prefs = Vec::new();
    for raw in value.split(',') {
        let parts = raw.split(';').collect::<Vec<_>>();
        let encoding = parts
            .first()
            .map(|part| part.trim().to_ascii_lowercase())
            .unwrap_or_default();

        let mut q = 1.0;
        if let Some(part) = parts.get(1) {
            let q_part = part.trim().to_ascii_lowercase();
            if let Some(q_value) = q_part.strip_prefix("q=")
                && let Ok(parsed) = q_value.parse::<f64>()
                && (0.0..=1.0).contains(&parsed)
            {
                q = parsed;
            }
        }
        if q < 0.00001 {
            continue;
        }

        let prefer_order = preferred_order
            .iter()
            .position(|preferred| preferred == &encoding)
            .map(|idx| preferred_order.len() - idx)
            .unwrap_or(0);
        prefs.push(EncodingPreference {
            encoding,
            q,
            prefer_order,
        });
    }

    prefs.sort_by(|a, b| {
        if (a.q - b.q).abs() < 0.00001 {
            b.prefer_order.cmp(&a.prefer_order)
        } else {
            b.q.partial_cmp(&a.q).unwrap_or(std::cmp::Ordering::Equal)
        }
    });

    prefs.into_iter().map(|pref| pref.encoding).collect()
}

fn caddy_file_server_not_found_static_response(site: Arc<Site>) -> StaticResponse {
    let mut headers = ::http::HeaderMap::new();
    headers.insert(
        ::http::header::SERVER,
        ::http::HeaderValue::from_static(crate::SERVER_HEADER),
    );
    headers.insert(
        ::http::header::CONTENT_LENGTH,
        ::http::HeaderValue::from_static("0"),
    );
    StaticResponse {
        status: StatusCode::NOT_FOUND,
        headers,
        body: StaticBody::Empty,
        head_only: false,
        site,
    }
}

fn internal_server_error_static_response(site: Arc<Site>) -> StaticResponse {
    StaticResponse {
        status: StatusCode::INTERNAL_SERVER_ERROR,
        headers: build_base_headers(
            b"Internal Server Error".len() as u64,
            "text/plain; charset=utf-8",
        ),
        body: StaticBody::Bytes(b"Internal Server Error".to_vec()),
        head_only: false,
        site,
    }
}

fn bad_request_static_response(site: Arc<Site>) -> StaticResponse {
    StaticResponse {
        status: StatusCode::BAD_REQUEST,
        headers: build_base_headers(b"Bad Request".len() as u64, "text/plain; charset=utf-8"),
        body: StaticBody::Bytes(b"Bad Request".to_vec()),
        head_only: false,
        site,
    }
}

fn forbidden_static_response(site: Arc<Site>) -> StaticResponse {
    StaticResponse {
        status: StatusCode::FORBIDDEN,
        headers: build_base_headers(b"Forbidden".len() as u64, "text/plain; charset=utf-8"),
        body: StaticBody::Bytes(b"Forbidden".to_vec()),
        head_only: false,
        site,
    }
}

fn prepare_caddy_browse_response(
    head: &RequestHead,
    head_only: bool,
    site: Arc<Site>,
    dir: &str,
    config: &CaddyFileServer,
) -> Option<CaddyStaticResponse> {
    let browse = config.browse.as_ref()?;
    if !browse.template_file.is_empty() {
        return None;
    }

    let mut items = caddy_browse_items(&site, dir, config);
    let last_modified = caddy_browse_last_modified(site.directory_mtimes.get(dir).copied(), &items);
    let browse_params = caddy_browse_params(head, browse);
    apply_caddy_browse_sort(&mut items, &browse_params);

    let accept = head
        .headers
        .get_all(::http::header::ACCEPT)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .collect::<Vec<_>>()
        .join(",")
        .to_ascii_lowercase();

    let (offset, limit) = caddy_browse_window(head, browse, items.len());
    let end = limit
        .map(|limit| offset.saturating_add(limit).min(items.len()))
        .unwrap_or(items.len());
    let items = items[offset..end].to_vec();

    let (body, content_type) = if accept.contains("application/json") {
        let mut body = serde_json::to_vec(&items).ok()?;
        body.push(b'\n');
        (body, "application/json; charset=utf-8")
    } else if accept.contains("text/plain") {
        (
            caddy_browse_text(&items).into_bytes(),
            "text/plain; charset=utf-8",
        )
    } else {
        (
            caddy_browse_html(head.uri.path(), &items).into_bytes(),
            "text/html; charset=utf-8",
        )
    };

    let mut headers = ::http::HeaderMap::new();
    headers.insert(
        ::http::header::VARY,
        ::http::HeaderValue::from_static("Accept, Accept-Encoding"),
    );
    if caddy_browse_if_modified_since(head, last_modified) {
        headers.insert(
            ::http::header::CONTENT_LENGTH,
            ::http::HeaderValue::from_static("0"),
        );
        return Some(CaddyStaticResponse::overlay(StaticResponse {
            status: StatusCode::NOT_MODIFIED,
            headers,
            body: StaticBody::Empty,
            head_only,
            site,
        }));
    }
    headers.extend(build_base_headers(body.len() as u64, content_type));
    if let Ok(value) = ::http::HeaderValue::from_str(&http_date(last_modified)) {
        headers.insert(::http::header::LAST_MODIFIED, value);
    }
    append_caddy_browse_cookies(&mut headers, head, &browse_params);
    Some(CaddyStaticResponse::overlay(StaticResponse {
        status: StatusCode::OK,
        headers,
        body: StaticBody::Bytes(body),
        head_only,
        site,
    }))
}

fn prepare_caddy_fs_browse_response(
    head: &RequestHead,
    head_only: bool,
    site: Arc<Site>,
    dir: &Path,
    config: &CaddyFileServer,
) -> Option<CaddyStaticResponse> {
    let browse = config.browse.as_ref()?;
    if !browse.template_file.is_empty() {
        return None;
    }

    let parent_meta = match fs::metadata(dir) {
        Ok(meta) => meta,
        Err(err) if err.kind() == std::io::ErrorKind::PermissionDenied => {
            return Some(CaddyStaticResponse::overlay(forbidden_static_response(
                site,
            )));
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return None,
        Err(_) => {
            return Some(CaddyStaticResponse::overlay(
                internal_server_error_static_response(site),
            ));
        }
    };
    let mut items = match caddy_fs_browse_items(dir, config) {
        Ok(items) => items,
        Err(err) if err.kind() == std::io::ErrorKind::PermissionDenied => {
            return Some(CaddyStaticResponse::overlay(forbidden_static_response(
                site,
            )));
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return None,
        Err(_) => {
            return Some(CaddyStaticResponse::overlay(
                internal_server_error_static_response(site),
            ));
        }
    };
    let parent_mtime = parent_meta.modified().ok().and_then(system_time_secs);
    let last_modified = caddy_browse_last_modified(parent_mtime, &items);
    let browse_params = caddy_browse_params(head, browse);
    apply_caddy_browse_sort(&mut items, &browse_params);
    let accept = head
        .headers
        .get_all(::http::header::ACCEPT)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .collect::<Vec<_>>()
        .join(",")
        .to_ascii_lowercase();

    let (offset, limit) = caddy_browse_window(head, browse, items.len());
    let end = limit
        .map(|limit| offset.saturating_add(limit).min(items.len()))
        .unwrap_or(items.len());
    let items = items[offset..end].to_vec();

    let (body, content_type) = if accept.contains("application/json") {
        let mut body = serde_json::to_vec(&items).ok()?;
        body.push(b'\n');
        (body, "application/json; charset=utf-8")
    } else if accept.contains("text/plain") {
        (
            caddy_browse_text(&items).into_bytes(),
            "text/plain; charset=utf-8",
        )
    } else {
        (
            caddy_browse_html(head.uri.path(), &items).into_bytes(),
            "text/html; charset=utf-8",
        )
    };

    let mut headers = ::http::HeaderMap::new();
    headers.insert(
        ::http::header::VARY,
        ::http::HeaderValue::from_static("Accept, Accept-Encoding"),
    );
    if caddy_browse_if_modified_since(head, last_modified) {
        headers.insert(
            ::http::header::CONTENT_LENGTH,
            ::http::HeaderValue::from_static("0"),
        );
        return Some(CaddyStaticResponse::overlay(StaticResponse {
            status: StatusCode::NOT_MODIFIED,
            headers,
            body: StaticBody::Empty,
            head_only,
            site,
        }));
    }
    headers.extend(build_base_headers(body.len() as u64, content_type));
    if let Ok(value) = ::http::HeaderValue::from_str(&http_date(last_modified)) {
        headers.insert(::http::header::LAST_MODIFIED, value);
    }
    append_caddy_browse_cookies(&mut headers, head, &browse_params);
    Some(CaddyStaticResponse::overlay(StaticResponse {
        status: StatusCode::OK,
        headers,
        body: StaticBody::Bytes(body),
        head_only,
        site,
    }))
}

#[derive(Clone, serde::Serialize)]
struct CaddyBrowseItem {
    name: String,
    size: i64,
    url: String,
    mod_time: String,
    mode: u32,
    is_dir: bool,
    is_symlink: bool,
    #[serde(skip_serializing_if = "String::is_empty")]
    symlink_path: String,
    #[serde(skip)]
    mtime_secs: u64,
    #[serde(skip)]
    mtime_nanos: u128,
}

fn caddy_browse_items(
    site: &Arc<Site>,
    dir: &str,
    config: &CaddyFileServer,
) -> Vec<CaddyBrowseItem> {
    enum BrowseCandidate<'a> {
        Dir {
            child: String,
            directory: &'a str,
        },
        File {
            child: String,
            entry: &'a crate::site::TarEntry,
        },
    }

    let prefix = if dir.is_empty() {
        String::new()
    } else {
        format!("{}/", dir.trim_end_matches('/'))
    };
    let mut items = Vec::new();
    let mut names = std::collections::HashSet::new();
    let read_limit = caddy_browse_read_limit(config.browse.as_ref());
    let mut candidates = Vec::new();

    for directory in &site.directories {
        if directory == dir {
            continue;
        }
        let Some(child) = direct_caddy_browse_child(&prefix, directory) else {
            continue;
        };
        if !names.insert(format!("{child}/")) {
            continue;
        }
        candidates.push(BrowseCandidate::Dir {
            child: child.to_string(),
            directory,
        });
    }

    for entry in site.entries.values() {
        let Some(child) = direct_caddy_browse_child(&prefix, &entry.path) else {
            continue;
        };
        if !names.insert(child.to_string()) {
            continue;
        }
        candidates.push(BrowseCandidate::File {
            child: child.to_string(),
            entry,
        });
    }

    // Caddy applies browse.file_limit to fs.ReadDir order before browse sorting.
    // Packed sites do not have a filesystem directory order, so use a stable
    // order here and let apply_caddy_browse_sort handle user-visible sorting.
    candidates.sort_by(|a, b| {
        let a = match a {
            BrowseCandidate::Dir { child, .. } | BrowseCandidate::File { child, .. } => child,
        };
        let b = match b {
            BrowseCandidate::Dir { child, .. } | BrowseCandidate::File { child, .. } => child,
        };
        b.cmp(a)
    });

    for (idx, candidate) in candidates.into_iter().enumerate() {
        if read_limit.is_some_and(|limit| idx >= limit) {
            break;
        }
        match candidate {
            BrowseCandidate::Dir { child, directory } => {
                if caddy_file_hidden(&child, &config.hide) {
                    continue;
                }
                let mtime = site.directory_mtimes.get(directory).copied().unwrap_or(0);
                items.push(CaddyBrowseItem {
                    name: format!("{child}/"),
                    size: 0,
                    url: caddy_browse_item_url(&format!("{child}/")),
                    mod_time: unix_time_rfc3339(mtime),
                    mode: 0o755,
                    is_dir: true,
                    is_symlink: false,
                    symlink_path: String::new(),
                    mtime_secs: mtime,
                    mtime_nanos: u128::from(mtime) * 1_000_000_000,
                });
            }
            BrowseCandidate::File { child, entry } => {
                if caddy_file_hidden(&child, &config.hide) {
                    continue;
                }
                items.push(CaddyBrowseItem {
                    name: child.to_string(),
                    size: entry.size as i64,
                    url: caddy_browse_item_url(&child),
                    mod_time: unix_time_rfc3339(entry.mtime),
                    mode: 0o644,
                    is_dir: false,
                    is_symlink: false,
                    symlink_path: String::new(),
                    mtime_secs: entry.mtime,
                    mtime_nanos: u128::from(entry.mtime) * 1_000_000_000,
                });
            }
        }
    }

    items
}

fn caddy_fs_browse_items(
    dir: &Path,
    config: &CaddyFileServer,
) -> std::io::Result<Vec<CaddyBrowseItem>> {
    let entries = fs::read_dir(dir)?;
    let read_limit = caddy_browse_read_limit(config.browse.as_ref());
    let mut items = Vec::new();
    for (idx, entry) in entries.flatten().enumerate() {
        if read_limit.is_some_and(|limit| idx >= limit) {
            break;
        }
        let name = entry.file_name().to_string_lossy().to_string();
        let path = entry.path();
        if name.is_empty() || caddy_file_hidden(&name, &config.hide) {
            continue;
        }
        let symlink_meta = fs::symlink_metadata(&path).ok();
        let is_symlink = symlink_meta
            .as_ref()
            .map(|meta| meta.file_type().is_symlink())
            .unwrap_or(false);
        let symlink_path = if is_symlink
            && config
                .browse
                .as_ref()
                .is_some_and(|browse| browse.reveal_symlinks)
        {
            fs::read_link(&path)
                .ok()
                .map(|path| path.to_string_lossy().replace('\\', "/"))
                .unwrap_or_default()
        } else {
            String::new()
        };
        let Ok(meta) = fs::metadata(&path) else {
            continue;
        };
        let is_dir = meta.is_dir();
        let browse_name = if is_dir {
            format!("{name}/")
        } else {
            name.clone()
        };
        let modified_time = meta.modified().ok();
        let modified = modified_time.and_then(system_time_secs).unwrap_or(0);
        let modified_nanos = modified_time.and_then(system_time_nanos).unwrap_or(0);
        items.push(CaddyBrowseItem {
            name: browse_name.clone(),
            size: if is_dir { 0 } else { meta.len() as i64 },
            url: caddy_browse_item_url(&browse_name),
            mod_time: unix_time_nanos_rfc3339(modified_nanos),
            mode: caddy_fs_mode(&meta),
            is_dir,
            is_symlink,
            symlink_path,
            mtime_secs: modified,
            mtime_nanos: modified_nanos,
        });
    }
    Ok(items)
}

pub(super) fn caddy_browse_read_limit(
    browse: Option<&crate::script::CaddyFileBrowse>,
) -> Option<usize> {
    const DEFAULT_DIR_ENTRY_LIMIT: usize = 10_000;
    match browse.map(|browse| browse.file_limit).unwrap_or(0) {
        0 => Some(DEFAULT_DIR_ENTRY_LIMIT),
        n if n > 0 => usize::try_from(n).ok(),
        _ => None,
    }
}

fn caddy_browse_last_modified(parent_mtime: Option<u64>, items: &[CaddyBrowseItem]) -> u64 {
    items
        .iter()
        .map(|item| item.mtime_secs)
        .chain(parent_mtime)
        .max()
        .unwrap_or(0)
}

fn caddy_browse_if_modified_since(head: &RequestHead, last_modified: u64) -> bool {
    if last_modified == 0 {
        return false;
    }
    let Some(value) = head
        .headers
        .get(::http::header::IF_MODIFIED_SINCE)
        .and_then(|value| value.to_str().ok())
    else {
        return false;
    };
    let Ok(value) = chrono::DateTime::parse_from_rfc2822(value) else {
        return false;
    };
    let Ok(last_modified) = i64::try_from(last_modified) else {
        return false;
    };
    last_modified <= value.timestamp()
}

fn direct_caddy_browse_child<'a>(prefix: &str, path: &'a str) -> Option<&'a str> {
    let rest = if prefix.is_empty() {
        path
    } else {
        path.strip_prefix(prefix)?
    };
    if rest.is_empty() || rest.contains('/') {
        None
    } else {
        Some(rest)
    }
}

struct CaddyBrowseParams {
    sort: String,
    order: String,
    set_sort_cookie: bool,
    set_order_cookie: bool,
}

fn caddy_browse_params(
    head: &RequestHead,
    browse: &crate::script::CaddyFileBrowse,
) -> CaddyBrowseParams {
    let query = caddy_query_map(head);
    let mut sort = String::new();
    let mut order = String::new();
    for item in browse.sort_options.iter().take(2) {
        match item.as_str() {
            "name" | "namedirfirst" | "size" | "time" => sort = item.clone(),
            "asc" | "desc" => order = item.clone(),
            _ => {}
        }
    }
    if let Some(value) = query.get("sort").filter(|value| !value.is_empty()) {
        sort = value.clone();
    }
    if let Some(value) = query.get("order").filter(|value| !value.is_empty()) {
        order = value.clone();
    }

    let mut set_sort_cookie = false;
    match sort.as_str() {
        "" => {
            sort = caddy_browse_cookie(head, "sort").unwrap_or_else(|| "namedirfirst".to_string());
        }
        "name" | "namedirfirst" | "size" | "time" => {
            set_sort_cookie = true;
        }
        _ => {}
    }

    let mut set_order_cookie = false;
    match order.as_str() {
        "" => {
            order = caddy_browse_cookie(head, "order").unwrap_or_else(|| "asc".to_string());
        }
        "asc" | "desc" => {
            set_order_cookie = true;
        }
        _ => {}
    }

    CaddyBrowseParams {
        sort,
        order,
        set_sort_cookie,
        set_order_cookie,
    }
}

fn apply_caddy_browse_sort(items: &mut [CaddyBrowseItem], params: &CaddyBrowseParams) {
    items.sort_by(|a, b| {
        let ord = match params.sort.as_str() {
            "namedirfirst" => b
                .is_dir
                .cmp(&a.is_dir)
                .then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase())),
            "size" => {
                let a_size = if a.is_dir {
                    i64::from(i32::MIN)
                } else {
                    a.size
                };
                let b_size = if b.is_dir {
                    i64::from(i32::MIN)
                } else {
                    b.size
                };
                if a.is_dir && b.is_dir {
                    a.name.to_lowercase().cmp(&b.name.to_lowercase())
                } else {
                    a_size.cmp(&b_size)
                }
            }
            "time" => a.mtime_nanos.cmp(&b.mtime_nanos),
            "name" => a.name.to_lowercase().cmp(&b.name.to_lowercase()),
            _ => std::cmp::Ordering::Equal,
        };
        if params.order == "desc" {
            ord.reverse()
        } else {
            ord
        }
    });
}

fn append_caddy_browse_cookies(
    headers: &mut ::http::HeaderMap,
    head: &RequestHead,
    params: &CaddyBrowseParams,
) {
    if params.set_sort_cookie {
        append_caddy_browse_cookie(headers, head, "sort", &params.sort);
    }
    if params.set_order_cookie {
        append_caddy_browse_cookie(headers, head, "order", &params.order);
    }
}

fn append_caddy_browse_cookie(
    headers: &mut ::http::HeaderMap,
    head: &RequestHead,
    name: &str,
    value: &str,
) {
    let mut cookie = format!("{name}={value}; HttpOnly; SameSite=Lax");
    if head.tls {
        cookie.push_str("; Secure");
    }
    if let Ok(value) = ::http::HeaderValue::from_str(&cookie) {
        headers.append(::http::header::SET_COOKIE, value);
    }
}

fn caddy_browse_cookie(head: &RequestHead, name: &str) -> Option<String> {
    for value in head.headers.get_all(::http::header::COOKIE) {
        let Ok(value) = value.to_str() else {
            continue;
        };
        for cookie in value.split(';') {
            let cookie = cookie.trim();
            let Some((cookie_name, cookie_value)) = cookie.split_once('=') else {
                continue;
            };
            if cookie_name.trim() == name {
                return Some(cookie_value.trim().to_string());
            }
        }
    }
    None
}

fn caddy_browse_window(
    head: &RequestHead,
    _browse: &crate::script::CaddyFileBrowse,
    item_count: usize,
) -> (usize, Option<usize>) {
    let query = caddy_query_map(head);
    let mut offset = query
        .get("offset")
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(0);
    if offset == 0 || offset > item_count {
        offset = 0;
    }
    let remaining = item_count.saturating_sub(offset);
    let mut limit = query
        .get("limit")
        .and_then(|value| value.parse::<usize>().ok());
    if limit.is_some_and(|limit| limit == 0 || limit > remaining) {
        limit = None;
    }
    (offset, limit)
}

fn caddy_query_map(head: &RequestHead) -> HashMap<String, String> {
    let mut params = HashMap::new();
    if let Some(query) = head.uri.query() {
        for (key, value) in url::form_urlencoded::parse(query.as_bytes()) {
            params.entry(key.into_owned()).or_insert(value.into_owned());
        }
    }
    params
}

fn caddy_browse_text(items: &[CaddyBrowseItem]) -> String {
    let mut out = String::from("Name\tSize\tModified\n----\t----\t--------\n");
    for item in items {
        out.push_str(&format!(
            "{}\t{}\t{}\n",
            item.name,
            caddy_human_ibytes(item.size),
            caddy_human_mod_time(item.mtime_secs)
        ));
    }
    out
}

fn caddy_human_ibytes(size: i64) -> String {
    let mut value = if size < 0 { 0.0 } else { size as f64 };
    let units = ["B", "KiB", "MiB", "GiB", "TiB", "PiB", "EiB"];
    let mut unit = 0usize;
    while value >= 1024.0 && unit + 1 < units.len() {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{} B", value as u64)
    } else {
        format!("{value:.1} {}", units[unit])
    }
}

fn caddy_human_mod_time(secs: u64) -> String {
    match chrono::DateTime::from_timestamp(secs as i64, 0) {
        Some(dt) => dt.format("%B %-d, %Y at %H:%M:%S").to_string(),
        None => String::new(),
    }
}

fn caddy_browse_html(path: &str, items: &[CaddyBrowseItem]) -> String {
    let mut out = String::new();
    out.push_str("<!doctype html><html><head><meta charset=\"utf-8\"><title>");
    out.push_str(&html_escape(path));
    out.push_str("</title></head><body><h1>");
    out.push_str(&html_escape(path));
    out.push_str("</h1><ul>");
    for item in items {
        out.push_str("<li><a href=\"");
        out.push_str(&html_escape(&item.url));
        out.push_str("\">");
        out.push_str(&html_escape(&item.name));
        out.push_str("</a></li>");
    }
    out.push_str("</ul></body></html>");
    out
}

fn caddy_browse_item_url(name: &str) -> String {
    let mut out = String::from("./");
    for byte in name.as_bytes() {
        match *byte {
            b'A'..=b'Z'
            | b'a'..=b'z'
            | b'0'..=b'9'
            | b'-'
            | b'.'
            | b'_'
            | b'~'
            | b'!'
            | b'$'
            | b'&'
            | b'\''
            | b'('
            | b')'
            | b'*'
            | b'+'
            | b','
            | b';'
            | b'='
            | b':'
            | b'@'
            | b'/' => out.push(*byte as char),
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

fn html_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

fn unix_time_rfc3339(secs: u64) -> String {
    match chrono::DateTime::from_timestamp(secs as i64, 0) {
        Some(value) => value.format("%Y-%m-%dT%H:%M:%SZ").to_string(),
        None => "1970-01-01T00:00:00Z".to_string(),
    }
}

fn unix_time_nanos_rfc3339(nanos: u128) -> String {
    let secs = nanos / 1_000_000_000;
    let subsec_nanos = (nanos % 1_000_000_000) as u32;
    let Ok(secs) = i64::try_from(secs) else {
        return "1970-01-01T00:00:00Z".to_string();
    };
    match chrono::DateTime::from_timestamp(secs, subsec_nanos) {
        Some(value) => value.to_rfc3339_opts(chrono::SecondsFormat::AutoSi, true),
        None => "1970-01-01T00:00:00Z".to_string(),
    }
}

fn http_date(secs: u64) -> String {
    match chrono::DateTime::from_timestamp(secs as i64, 0) {
        Some(value) => value.format("%a, %d %b %Y %H:%M:%S GMT").to_string(),
        None => "Thu, 01 Jan 1970 00:00:00 GMT".to_string(),
    }
}

fn get_site_entry(site: &Arc<Site>, path: &str) -> Option<Arc<crate::site::TarEntry>> {
    if path.starts_with(".zeroserve/") {
        return None;
    }
    site.entries.get(path).cloned()
}

pub(super) fn normalize_caddy_file_root(
    root: &str,
    force_filesystem: bool,
) -> Option<CaddyFileRoot> {
    let root = root.trim();
    if force_filesystem {
        return Some(CaddyFileRoot::Fs(PathBuf::from(if root.is_empty() {
            "."
        } else {
            root
        })));
    }
    if root.is_empty() || root == "." || root == "{http.vars.root}" {
        return Some(CaddyFileRoot::Tar(String::new()));
    }
    if root.contains('{') || root.contains('}') {
        return None;
    }
    let path = Path::new(root);
    if path.is_absolute() {
        return Some(CaddyFileRoot::Fs(path.to_path_buf()));
    }
    let root = root.trim_matches('/');
    if root.is_empty() {
        Some(CaddyFileRoot::Tar(String::new()))
    } else {
        normalize_request_path(&format!("/{root}"))
            .map(|path| CaddyFileRoot::Tar(path.relative().to_string()))
    }
}

pub(super) fn caddy_fs_name_forces_filesystem(fs_name: &str) -> bool {
    fs_name == "file" || fs_name == "default"
}

fn caddy_fs_join(root: &Path, rel: &str) -> Option<PathBuf> {
    let mut path = root.to_path_buf();
    for component in rel.split('/') {
        if component.is_empty() {
            continue;
        }
        if component == "." || component == ".." {
            return None;
        }
        path.push(component);
    }
    // Caddy's default file server follows symlinks; this join only rejects
    // textual traversal and leaves symlink policy to the filesystem backend.
    Some(path)
}

fn caddy_redirect_path(path: &str, query: Option<&str>, add_slash: bool) -> String {
    let mut path = path.to_string();
    if add_slash {
        path.push('/');
    } else if path.len() > 1 && path.ends_with('/') {
        path.pop();
    }
    while path.starts_with("//") {
        path.remove(0);
    }
    if let Some(query) = query {
        path.push('?');
        path.push_str(query);
    }
    path
}

fn caddy_canonical_redirect_allowed(request: &ScriptRequest) -> bool {
    caddy_url_path_base(&request.original_path) == caddy_url_path_base(&request.path)
}

fn caddy_browse_redirect_allowed(request: &ScriptRequest) -> bool {
    request.path.is_empty() || caddy_canonical_redirect_allowed(request)
}

fn caddy_url_path_base(path: &str) -> &str {
    let path = path.trim_end_matches('/');
    if path.is_empty() {
        return "/";
    }
    path.rsplit('/').next().unwrap_or(path)
}

fn redirect_static_response(location: String, site: Arc<Site>) -> StaticResponse {
    let mut headers = ::http::HeaderMap::new();
    headers.insert(
        ::http::header::SERVER,
        HeaderValue::from_static(crate::SERVER_HEADER),
    );
    headers.insert(
        ::http::header::CONTENT_LENGTH,
        HeaderValue::from_static("0"),
    );
    if let Ok(location) = HeaderValue::from_str(&location) {
        headers.insert(::http::header::LOCATION, location);
    }
    StaticResponse {
        status: StatusCode::PERMANENT_REDIRECT,
        headers,
        body: StaticBody::Empty,
        head_only: true,
        site,
    }
}

async fn caddy_entry_etag(
    site: &Arc<Site>,
    entry: &Arc<crate::site::TarEntry>,
    config: &CaddyFileServer,
) -> Result<CaddyEtag, ()> {
    for suffix in &config.etag_file_extensions {
        let sidecar = format!("{}{}", entry.path, suffix);
        let Some(sidecar) = get_site_entry(site, &sidecar) else {
            continue;
        };
        let bytes = read_tar_entry(sidecar, site).await.map_err(|_| ())?;
        let etag = String::from_utf8_lossy(&bytes).replace('\n', "");
        return Ok(CaddyEtag::sidecar(etag));
    }
    Ok(CaddyEtag::computed(entry.etag.clone()))
}

async fn caddy_fs_etag(
    path: &Path,
    meta: &fs::Metadata,
    config: &CaddyFileServer,
) -> Result<CaddyEtag, ()> {
    for suffix in &config.etag_file_extensions {
        let sidecar = PathBuf::from(format!("{}{}", path.to_string_lossy(), suffix));
        let bytes = match read_fs_file(&sidecar).await {
            Ok(bytes) => bytes,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => continue,
            Err(_) => return Err(()),
        };
        let etag = String::from_utf8_lossy(&bytes).replace('\n', "");
        return Ok(CaddyEtag::sidecar(etag));
    }
    Ok(CaddyEtag::computed(caddy_calculate_fs_etag(meta)))
}

fn caddy_calculate_fs_etag(meta: &fs::Metadata) -> String {
    let Some(modified) = meta.modified().ok().and_then(system_time_nanos) else {
        return String::new();
    };
    if !caddy_useful_mod_time((modified / 1_000_000_000) as u64) {
        return String::new();
    }
    format!(
        "\"{}{}\"",
        format_base36(modified),
        format_base36(u128::from(meta.len()))
    )
}

fn format_base36(mut value: u128) -> String {
    if value == 0 {
        return "0".to_string();
    }
    let mut digits = Vec::new();
    while value > 0 {
        let digit = (value % 36) as u8;
        digits.push(match digit {
            0..=9 => b'0' + digit,
            _ => b'a' + (digit - 10),
        });
        value /= 36;
    }
    digits.reverse();
    String::from_utf8(digits).unwrap_or_default()
}

fn system_time_nanos(value: SystemTime) -> Option<u128> {
    value
        .duration_since(UNIX_EPOCH)
        .ok()
        .map(|duration| duration.as_nanos())
}

fn system_time_secs(value: SystemTime) -> Option<u64> {
    value
        .duration_since(UNIX_EPOCH)
        .ok()
        .map(|duration| duration.as_secs())
}

fn caddy_useful_mod_time(secs: u64) -> bool {
    secs != 0 && secs != 1
}

fn insert_caddy_validator_headers(
    headers: &mut ::http::HeaderMap,
    etag: &CaddyEtag,
    last_modified: u64,
) {
    if !caddy_useful_mod_time(last_modified) {
        return;
    }
    if !etag.value.is_empty() {
        headers.insert(::http::header::ETAG, etag.header_value());
    }
    insert_last_modified(headers, last_modified);
}

fn replace_caddy_validator_etag(headers: &mut ::http::HeaderMap, etag: &CaddyEtag) {
    if !etag.value.is_empty() && headers.contains_key(::http::header::ETAG) {
        headers.insert(::http::header::ETAG, etag.header_value());
    }
}

/// A `412 Precondition Failed` keeps the file's Content-Type (Go reaches the
/// failure via a bare `WriteHeader`, leaving the already-set header in place),
/// whereas a `304 Not Modified` drops it (Go's `writeNotModified` deletes it).
fn insert_precondition_content_type(
    headers: &mut ::http::HeaderMap,
    precondition_status: StatusCode,
    mime: Option<&str>,
) {
    if precondition_status != StatusCode::PRECONDITION_FAILED {
        return;
    }
    if let Some(mime) = mime
        && let Ok(value) = ::http::HeaderValue::from_str(mime)
    {
        headers.insert(::http::header::CONTENT_TYPE, value);
    }
}

#[cfg(unix)]
fn caddy_fs_mode(meta: &fs::Metadata) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    meta.permissions().mode()
}

#[cfg(not(unix))]
fn caddy_fs_mode(meta: &fs::Metadata) -> u32 {
    if meta.is_dir() { 0o755 } else { 0o644 }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

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
    fn caddy_file_preconditions_reject_failed_if_match() {
        let mut headers = ::http::HeaderMap::new();
        headers.insert(::http::header::IF_MATCH, "\"other\"".parse().unwrap());
        let head = request_head(headers);
        let (status, response_headers) =
            caddy_precondition_response(&head, &CaddyEtag::computed("etag".into()), 100)
                .expect("precondition response");

        assert_eq!(status, StatusCode::PRECONDITION_FAILED);
        assert_eq!(
            response_headers
                .get(::http::header::ETAG)
                .and_then(|value| value.to_str().ok()),
            Some("\"etag\"")
        );
    }

    #[test]
    fn caddy_file_preconditions_require_strong_if_match_etag() {
        let mut headers = ::http::HeaderMap::new();
        headers.insert(::http::header::IF_MATCH, "W/\"etag\"".parse().unwrap());
        let head = request_head(headers);

        let (status, _) =
            caddy_precondition_response(&head, &CaddyEtag::computed("etag".into()), 100)
                .expect("precondition response");

        assert_eq!(status, StatusCode::PRECONDITION_FAILED);
    }

    #[test]
    fn caddy_file_preconditions_reject_stale_if_unmodified_since() {
        let mut headers = ::http::HeaderMap::new();
        headers.insert(
            ::http::header::IF_UNMODIFIED_SINCE,
            "Thu, 01 Jan 1970 00:00:01 GMT".parse().unwrap(),
        );
        let head = request_head(headers);

        let (status, _) =
            caddy_precondition_response(&head, &CaddyEtag::computed("etag".into()), 100)
                .expect("precondition response");

        assert_eq!(status, StatusCode::PRECONDITION_FAILED);
    }

    #[test]
    fn caddy_file_preconditions_do_not_match_bare_sidecar_etags() {
        let mut headers = ::http::HeaderMap::new();
        headers.insert(
            ::http::header::IF_NONE_MATCH,
            "\"sidecar\"".parse().unwrap(),
        );
        let head = request_head(headers);

        assert!(
            caddy_precondition_response(&head, &CaddyEtag::sidecar("sidecar".into()), 100)
                .is_none()
        );

        let mut headers = ::http::HeaderMap::new();
        headers.insert(::http::header::IF_MATCH, "\"other\"".parse().unwrap());
        let head = request_head(headers);
        let (status, response_headers) =
            caddy_precondition_response(&head, &CaddyEtag::sidecar("sidecar".into()), 100)
                .expect("precondition response");

        assert_eq!(status, StatusCode::PRECONDITION_FAILED);
        assert_eq!(
            response_headers
                .get(::http::header::ETAG)
                .and_then(|value| value.to_str().ok()),
            Some("sidecar")
        );
    }

    #[test]
    fn precompressed_q_values_sort_before_server_preference() {
        let mut headers = ::http::HeaderMap::new();
        headers.insert(
            ::http::header::ACCEPT_ENCODING,
            "deflate;q=0.8, gzip;q=0.4, br;q=0.2, zstd".parse().unwrap(),
        );
        let head = request_head(headers);
        let config = crate::script::CaddyFileServer {
            precompressed_order: vec!["gzip".to_string()],
            ..Default::default()
        };
        assert_eq!(
            accepted_caddy_precompressed_encodings(&head, &config),
            vec![
                "zstd".to_string(),
                "deflate".to_string(),
                "gzip".to_string(),
                "br".to_string(),
            ]
        );
    }

    #[test]
    fn precompressed_server_preference_breaks_equal_q_ties() {
        let mut headers = ::http::HeaderMap::new();
        headers.insert(
            ::http::header::ACCEPT_ENCODING,
            "deflate, gzip, br, zstd".parse().unwrap(),
        );
        let head = request_head(headers);
        let config = crate::script::CaddyFileServer {
            precompressed_order: vec!["zstd".to_string(), "br".to_string(), "gzip".to_string()],
            ..Default::default()
        };
        assert_eq!(
            accepted_caddy_precompressed_encodings(&head, &config),
            vec![
                "zstd".to_string(),
                "br".to_string(),
                "gzip".to_string(),
                "deflate".to_string(),
            ]
        );
    }

    #[test]
    fn precompressed_filters_zero_q_and_websocket_handshakes() {
        let mut headers = ::http::HeaderMap::new();
        headers.insert(
            ::http::header::ACCEPT_ENCODING,
            "gzip;q=0.5, br;q=0, zstd;q=1".parse().unwrap(),
        );
        let config = crate::script::CaddyFileServer::default();
        assert_eq!(
            accepted_caddy_precompressed_encodings(&request_head(headers.clone()), &config),
            vec!["zstd".to_string(), "gzip".to_string()]
        );

        headers.insert("sec-websocket-key", "test".parse().unwrap());
        assert!(accepted_caddy_precompressed_encodings(&request_head(headers), &config).is_empty());

        let mut headers = ::http::HeaderMap::new();
        headers.insert(::http::header::ACCEPT_ENCODING, "gzip".parse().unwrap());
        headers.insert("sec-websocket-key", "".parse().unwrap());
        assert_eq!(
            accepted_caddy_precompressed_encodings(&request_head(headers), &config),
            vec!["gzip".to_string()]
        );
    }

    #[test]
    fn precompressed_uses_first_accept_encoding_header_like_caddy() {
        let mut headers = ::http::HeaderMap::new();
        headers.append(::http::header::ACCEPT_ENCODING, "gzip".parse().unwrap());
        headers.append(::http::header::ACCEPT_ENCODING, "br".parse().unwrap());
        let head = request_head(headers);
        let config = crate::script::CaddyFileServer::default();
        assert_eq!(
            accepted_caddy_precompressed_encodings(&head, &config),
            vec!["gzip".to_string()]
        );
    }

    #[test]
    fn explicit_caddy_file_filesystem_forces_filesystem_roots() {
        match normalize_caddy_file_root("public", false).unwrap() {
            CaddyFileRoot::Tar(root) => assert_eq!(root, "public"),
            CaddyFileRoot::Fs(root) => panic!("unexpected filesystem root: {root:?}"),
        }

        match normalize_caddy_file_root("public", true).unwrap() {
            CaddyFileRoot::Fs(root) => assert_eq!(root, PathBuf::from("public")),
            CaddyFileRoot::Tar(root) => panic!("unexpected tar root: {root:?}"),
        }

        assert!(caddy_fs_name_forces_filesystem("default"));
        assert!(caddy_fs_name_forces_filesystem("file"));
        assert!(!caddy_fs_name_forces_filesystem(""));

        match normalize_caddy_file_root(".", true).unwrap() {
            CaddyFileRoot::Fs(root) => assert_eq!(root, PathBuf::from(".")),
            CaddyFileRoot::Tar(root) => panic!("unexpected tar root: {root:?}"),
        }
    }

    #[test]
    fn caddy_file_server_response_config_expands_placeholders() {
        let config = crate::script::CaddyFileServer {
            fs: "{http.vars.fs}".to_string(),
            root: "sites/{http.vars.tenant}".to_string(),
            hide: vec!["{http.vars.secret}".to_string()],
            index_names: Some(vec!["{http.vars.index}".to_string()]),
            etag_file_extensions: vec!["{http.vars.etag_ext}".to_string()],
            status_code: Some("{http.vars.status}".to_string()),
            ..Default::default()
        };
        let metadata = HashMap::from([
            ("http.vars.fs".to_string(), "file".to_string()),
            ("http.vars.tenant".to_string(), "alpha".to_string()),
            ("http.vars.secret".to_string(), "private.txt".to_string()),
            ("http.vars.index".to_string(), "home.html".to_string()),
            ("http.vars.etag_ext".to_string(), ".etag".to_string()),
            ("http.vars.status".to_string(), "203".to_string()),
        ]);

        let config = expand_caddy_file_server_config(&config, &metadata);

        assert_eq!(config.fs, "file");
        assert_eq!(config.root, "sites/alpha");
        assert_eq!(config.hide, vec!["private.txt"]);
        assert_eq!(config.index_names, Some(vec!["home.html".to_string()]));
        assert_eq!(config.etag_file_extensions, vec!["{http.vars.etag_ext}"]);
        assert_eq!(config.status_code.as_deref(), Some("{http.vars.status}"));
    }

    #[test]
    fn caddy_file_redirect_path_matches_caddy_slash_semantics() {
        assert_eq!(
            caddy_redirect_path("/file.txt//", Some("x=1"), false),
            "/file.txt/?x=1"
        );
        assert_eq!(caddy_redirect_path("//dir", Some("x=1"), true), "/dir/?x=1");
    }

    #[test]
    fn caddy_browse_read_limit_follows_caddy_defaults() {
        assert_eq!(caddy_browse_read_limit(None), Some(10_000));
        assert_eq!(
            caddy_browse_read_limit(Some(&crate::script::CaddyFileBrowse::default())),
            Some(10_000)
        );
        assert_eq!(
            caddy_browse_read_limit(Some(&crate::script::CaddyFileBrowse {
                file_limit: 7,
                ..Default::default()
            })),
            Some(7)
        );
        assert_eq!(
            caddy_browse_read_limit(Some(&crate::script::CaddyFileBrowse {
                file_limit: -1,
                ..Default::default()
            })),
            None
        );
    }

    #[test]
    fn caddy_hide_path_patterns_hide_exact_paths_and_descendants() {
        let hide = vec![
            "secret.txt".to_string(),
            "priv?.txt".to_string(),
            "public/static/private".to_string(),
        ];
        assert!(caddy_file_hidden("public/static/secret.txt", &hide));
        assert!(caddy_file_hidden("public/static/priv8.txt", &hide));
        assert!(caddy_file_hidden("public/static/private", &hide));
        assert!(caddy_file_hidden("public/static/private/nested.txt", &hide));
        assert!(!caddy_file_hidden("public/static/file.txt", &hide));
        assert!(!caddy_file_hidden("public/static/private-ish.txt", &hide));

        let hide = vec!["/public/static/private".to_string()];
        assert!(!caddy_file_hidden("public/static/private", &hide));
    }

    #[test]
    fn caddy_file_content_type_omits_unknown_extensions() {
        for (path, expected) in [
            ("public/static/index.html", "text/html; charset=utf-8"),
            ("public/static/app.js", "text/javascript; charset=utf-8"),
            ("public/static/app.mjs", "text/javascript; charset=utf-8"),
            ("public/static/data.json", "application/json"),
            ("public/static/feed.xml", "text/xml; charset=utf-8"),
            ("public/static/favicon.ico", "image/vnd.microsoft.icon"),
            ("public/static/image.webp", "image/webp"),
            ("public/static/image.avif", "image/avif"),
            ("public/static/font.woff2", "font/woff2"),
            ("public/static/file.txt", "text/plain; charset=utf-8"),
            ("public/static/doc.md", "text/markdown; charset=utf-8"),
            ("public/static/doc.pdf", "application/pdf"),
        ] {
            assert_eq!(caddy_file_content_type(path), Some(expected), "{path}");
        }
        assert_eq!(
            caddy_file_content_type("public/static/no-type.caddyunknown"),
            None
        );
        assert_eq!(caddy_file_content_type("public/static/app.js.map"), None);
    }

    #[test]
    fn caddy_forwarded_headers_append_peer_ip() {
        let mut headers = ::http::HeaderMap::new();
        headers.insert("x-forwarded-for", "198.51.100.1".parse().unwrap());
        let peer = "127.0.0.1:1234".parse().unwrap();
        apply_caddy_forwarded_headers(&mut headers, peer, Scheme::Http);
        let values = headers
            .get_all("x-forwarded-for")
            .iter()
            .filter_map(|value| value.to_str().ok())
            .collect::<Vec<_>>();
        assert_eq!(values, vec!["198.51.100.1", "127.0.0.1"]);
    }
}
