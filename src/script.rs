use std::{
    any::{Any, TypeId},
    cell::{Cell, RefCell},
    collections::HashMap,
    fmt,
    pin::Pin,
    rc::Rc,
    sync::Arc,
    task::Poll,
    time::{Duration, Instant},
};

use ::http::{
    Method, Uri,
    header::{HeaderName, HeaderValue},
};
use anyhow::{Context, bail};
use async_ebpf::{
    helpers::{Helper, write_cstr as write_cstr_snprintf},
    program::{
        GlobalEnv, HelperScope, MutableUserMemory, PreemptionEnabled, Program,
        ProgramEventListener, ProgramLoader, ThreadEnv, TimesliceConfig, Timeslicer,
        UnboundProgram,
    },
};
use boring::ssl::SslContext;
use futures::{FutureExt, channel::oneshot};
use monoio::fs::File;
use serde::Deserialize;
use ulid::Ulid;
use url::form_urlencoded;

use crate::helpers;
use crate::{
    json::JsonRef,
    logging::async_log,
    site::{Site, normalize_request_path},
    thread_pool::CPU_TP,
    tls::{TlsCertSelect, TlsRuntime},
};

const SCRIPT_ENTRYPOINT: &str = "zeroserve.request";
const SCRIPT_TLS_ENTRYPOINT: &str = "zeroserve.tls";
/// Prefix for the per-function code sections that expose a script to inter-script
/// calls. A callee exports `zeroserve.call.<name>` sections; `zs_call` resolves
/// `<name>` against this prefix.
pub(crate) const SCRIPT_CALL_SECTION_PREFIX: &str = "zeroserve.call.";
/// Prefix for the load-time init sections. A script exports
/// `zeroserve.init.<name>` sections that the host runs once at load time to read
/// back a JSON configuration handle (e.g. `zeroserve.init.acme_config`).
pub(crate) const SCRIPT_INIT_SECTION_PREFIX: &str = "zeroserve.init.";
const MAX_EXTERNAL_OBJECTS: usize = 32;
/// Maximum depth of nested `zs_call` invocations. Bounds runaway recursion
/// (script A calling B calling A …) and the total memory a single request can
/// fan out across script contexts.
pub(crate) const MAX_CALL_DEPTH: usize = 8;

type BodyReaderFuture = Pin<Box<dyn std::future::Future<Output = Result<Vec<u8>, BodyReadError>>>>;

#[derive(Clone, Default)]
pub(crate) struct RequestId(Rc<RefCell<Option<Ulid>>>);

impl RequestId {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    pub(crate) fn get(&self) -> Ulid {
        let mut id = self.0.borrow_mut();
        *id.get_or_insert_with(Ulid::new)
    }
}

impl From<Ulid> for RequestId {
    fn from(value: Ulid) -> Self {
        Self(Rc::new(RefCell::new(Some(value))))
    }
}

impl fmt::Debug for RequestId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl fmt::Display for RequestId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.get().fmt(f)
    }
}

pub enum BodyReadError {
    TooLarge,
    ReadError,
}

enum BodySourceState {
    Pending(BodyReaderFuture),
    Ready(Vec<u8>),
    TooLarge,
    Empty,
}

#[derive(Clone)]
pub struct BodySource {
    inner: Rc<RefCell<BodySourceState>>,
    max_size: Rc<Cell<usize>>,
}

impl BodySource {
    pub fn new(reader: BodyReaderFuture, max_size: Rc<Cell<usize>>) -> Self {
        Self {
            inner: Rc::new(RefCell::new(BodySourceState::Pending(reader))),
            max_size,
        }
    }

    pub(crate) fn empty() -> Self {
        Self {
            inner: Rc::new(RefCell::new(BodySourceState::Empty)),
            max_size: Rc::new(Cell::new(0)),
        }
    }

    pub fn set_max_size(&self, max_size: usize) {
        let current = self.max_size.get();
        if current == 0 || max_size < current {
            self.max_size.set(max_size);
        }
    }

    pub async fn read(&self) -> Result<Vec<u8>, ()> {
        {
            let state = self.inner.borrow();
            match &*state {
                BodySourceState::Ready(bytes) => return Ok(bytes.clone()),
                BodySourceState::TooLarge | BodySourceState::Empty => return Err(()),
                BodySourceState::Pending(_) => {}
            }
        }

        let future = {
            let mut state = self.inner.borrow_mut();
            match std::mem::replace(&mut *state, BodySourceState::Empty) {
                BodySourceState::Pending(f) => f,
                other => {
                    *state = other;
                    return Err(());
                }
            }
        };

        let result = future.await;

        let mut state = self.inner.borrow_mut();
        match result {
            Ok(bytes) => {
                *state = BodySourceState::Ready(bytes.clone());
                Ok(bytes)
            }
            Err(BodyReadError::TooLarge) => {
                *state = BodySourceState::TooLarge;
                Err(())
            }
            Err(BodyReadError::ReadError) => {
                *state = BodySourceState::Empty;
                Err(())
            }
        }
    }
}

static SCRIPT_HELPERS: &[(&str, Helper)] = &[
    ("zs_log", helpers::h_log),
    ("zs_now_ms", helpers::h_now_ms),
    ("zs_version", helpers::h_version),
    ("zs_env_get", helpers::h_env_get),
    ("zs_getrandom", helpers::h_getrandom),
    ("zs_sha256", helpers::h_sha256),
    ("zs_hmac_sha256", helpers::h_hmac_sha256),
    ("zs_base64_encode", helpers::h_base64_encode),
    (
        "zs_base64_decode_in_place",
        helpers::h_base64_decode_in_place,
    ),
    ("zs_hex_encode", helpers::h_hex_encode),
    ("zs_hex_decode_in_place", helpers::h_hex_decode_in_place),
    ("memcpy", helpers::h_memcpy),
    ("memset", helpers::h_memset),
    ("zs_memcpy", helpers::h_memcpy),
    ("zs_memcmp", helpers::h_memcmp),
    ("zs_memset", helpers::h_memset),
    ("zs_json_parse", helpers::h_json_parse),
    ("zs_load_static_json", helpers::h_load_static_json),
    ("zs_load_file_metadata", helpers::h_load_file_metadata),
    ("zs_json_reset", helpers::h_json_reset),
    ("zs_json_get", helpers::h_json_get),
    ("zs_json_array_get", helpers::h_json_array_get),
    ("zs_json_read_string", helpers::h_json_read_string),
    ("zs_json_read_i64", helpers::h_json_read_i64),
    ("zs_json_read_bool", helpers::h_json_read_bool),
    ("zs_json_new_object", helpers::h_json_new_object),
    ("zs_json_new_array", helpers::h_json_new_array),
    ("zs_json_clone", helpers::h_json_clone),
    ("zs_json_type", helpers::h_json_type),
    ("zs_json_len", helpers::h_json_len),
    ("zs_json_set", helpers::h_json_set),
    ("zs_json_remove", helpers::h_json_remove),
    ("zs_json_array_push", helpers::h_json_array_push),
    ("zs_json_array_set", helpers::h_json_array_set),
    ("zs_json_set_string", helpers::h_json_set_string),
    ("zs_json_set_i64", helpers::h_json_set_i64),
    ("zs_json_set_bool", helpers::h_json_set_bool),
    ("zs_json_set_null", helpers::h_json_set_null),
    ("zs_json_respond", helpers::h_json_respond),
    ("zs_object_free", helpers::h_object_free),
    ("zs_call", helpers::h_call),
    ("zs_res_hook", helpers::h_res_hook),
    ("zs_res_hooks_clear", helpers::h_res_hooks_clear),
    ("zs_req_method", helpers::h_req_method),
    ("zs_req_set_method", helpers::h_req_set_method),
    ("zs_caddy_rewrite_method", helpers::h_caddy_rewrite_method),
    ("zs_req_path", helpers::h_req_path),
    ("zs_req_normalized_path", helpers::h_req_normalized_path),
    (
        "zs_caddy_path_regexp_subject",
        helpers::h_caddy_path_regexp_subject,
    ),
    ("zs_req_uri", helpers::h_req_uri),
    ("zs_req_set_uri", helpers::h_req_set_uri),
    ("zs_req_query", helpers::h_req_query),
    ("zs_caddy_rewrite_uri", helpers::h_caddy_rewrite_uri),
    ("zs_req_rewrite_uri", helpers::h_req_rewrite_uri),
    ("zs_req_rewrite_query", helpers::h_req_rewrite_query),
    ("zs_req_scheme", helpers::h_req_scheme),
    ("zs_req_proto_major", helpers::h_req_proto_major),
    ("zs_req_proto_minor", helpers::h_req_proto_minor),
    ("zs_req_peer", helpers::h_req_peer),
    ("zs_req_is_tls", helpers::h_req_is_tls),
    (
        "zs_req_tls_handshake_complete",
        helpers::h_req_tls_handshake_complete,
    ),
    ("zs_caddy_tls_certificate", helpers::h_caddy_tls_certificate),
    ("zs_caddy_tls_client_auth", helpers::h_caddy_tls_client_auth),
    ("zs_req_remote_ip_matches", helpers::h_req_remote_ip_matches),
    (
        "zs_caddy_remote_ip_matches",
        helpers::h_caddy_remote_ip_matches,
    ),
    (
        "zs_caddy_client_ip_matches",
        helpers::h_caddy_client_ip_matches,
    ),
    (
        "zs_caddy_reverse_proxy_forwarded",
        helpers::h_caddy_reverse_proxy_forwarded,
    ),
    (
        "zs_caddy_reverse_proxy_request_headers",
        helpers::h_caddy_reverse_proxy_request_headers,
    ),
    ("zs_caddy_vars_set", helpers::h_caddy_vars_set),
    ("zs_caddy_vars_match", helpers::h_caddy_vars_match),
    (
        "zs_caddy_vars_match_expanded_keys",
        helpers::h_caddy_vars_match_expanded_keys,
    ),
    (
        "zs_caddy_vars_regexp_match",
        helpers::h_caddy_vars_regexp_match,
    ),
    (
        "zs_caddy_vars_regexp_match_expanded_keys",
        helpers::h_caddy_vars_regexp_match_expanded_keys,
    ),
    ("zs_caddy_map", helpers::h_caddy_map),
    (
        "zs_caddy_response_headers",
        helpers::h_caddy_response_headers,
    ),
    ("zs_caddy_encode", helpers::h_caddy_encode),
    ("zs_caddy_path_match", helpers::h_caddy_path_match),
    (
        "zs_caddy_path_match_multi",
        helpers::h_caddy_path_match_multi,
    ),
    ("zs_caddy_query_match", helpers::h_caddy_query_match),
    ("zs_caddy_query_present", helpers::h_caddy_query_present),
    ("zs_caddy_query_empty", helpers::h_caddy_query_empty),
    ("zs_caddy_header_match", helpers::h_caddy_header_match),
    (
        "zs_caddy_header_match_expanded",
        helpers::h_caddy_header_match_expanded,
    ),
    ("zs_caddy_header_present", helpers::h_caddy_header_present),
    (
        "zs_caddy_header_present_expanded",
        helpers::h_caddy_header_present_expanded,
    ),
    (
        "zs_caddy_header_regexp_match",
        helpers::h_caddy_header_regexp_match,
    ),
    (
        "zs_caddy_header_regexp_match_expanded",
        helpers::h_caddy_header_regexp_match_expanded,
    ),
    (
        "zs_caddy_req_header_first_prefix",
        helpers::h_caddy_req_header_first_prefix,
    ),
    ("zs_caddy_regex_match", helpers::h_caddy_regex_match),
    ("zs_caddy_expr_in", helpers::h_caddy_expr_in),
    ("zs_caddy_expr_eq", helpers::h_caddy_expr_eq),
    ("zs_caddy_file_match", helpers::h_caddy_file_match),
    ("zs_caddy_expand", helpers::h_caddy_expand),
    ("zs_caddy_expand_known", helpers::h_caddy_expand_known),
    ("zs_connection_info", helpers::h_connection_info),
    ("zs_req_header", helpers::h_req_header),
    ("zs_req_set_header", helpers::h_req_set_header),
    ("zs_req_append_header", helpers::h_req_append_header),
    ("zs_req_delete_header", helpers::h_req_delete_header),
    ("zs_req_replace_header", helpers::h_req_replace_header),
    ("zs_req_query_param", helpers::h_req_query_param),
    (
        "zs_req_query_param_matches",
        helpers::h_req_query_param_matches,
    ),
    ("zs_req_body_limit", helpers::h_req_body_limit),
    ("zs_req_body_json", helpers::h_req_body_json),
    ("zs_meta_get", helpers::h_meta_get),
    ("zs_meta_set", helpers::h_meta_set),
    ("zs_res_replace_header", helpers::h_res_replace_header),
    ("zs_res_status", helpers::h_res_status),
    ("zs_res_set_status", helpers::h_res_set_status),
    ("zs_res_header", helpers::h_res_header),
    ("zs_res_continue_request", helpers::h_res_continue_request),
    (
        "zs_caddy_res_header_match",
        helpers::h_caddy_res_header_match,
    ),
    (
        "zs_caddy_res_header_present",
        helpers::h_caddy_res_header_present,
    ),
    (
        "zs_caddy_copy_response_headers",
        helpers::h_caddy_copy_response_headers,
    ),
    ("zs_response_pending", helpers::h_response_pending),
    ("zs_response_clear", helpers::h_response_clear),
    ("zs_abort", helpers::h_abort),
    ("zs_respond", helpers::h_respond),
    ("zs_caddy_respond", helpers::h_caddy_respond),
    ("zs_caddy_respond_static", helpers::h_caddy_respond_static),
    ("zs_caddy_set_error", helpers::h_caddy_set_error),
    (
        "zs_caddy_adopt_call_result",
        helpers::h_caddy_adopt_call_result,
    ),
    ("zs_caddy_basic_auth", helpers::h_caddy_basic_auth),
    (
        "zs_caddy_reverse_proxy_url",
        helpers::h_caddy_reverse_proxy_url,
    ),
    (
        "zs_caddy_reverse_proxy_rewrite",
        helpers::h_caddy_reverse_proxy_rewrite,
    ),
    ("zs_reverse_proxy", helpers::h_reverse_proxy),
    ("zs_file_server", helpers::h_file_server),
    (
        "zs_aws_v4_authorization_header",
        helpers::h_aws_v4_authorization_header,
    ),
    ("zs_aws_v4_presigned_url", helpers::h_aws_v4_presigned_url),
    ("zs_rate_limit", helpers::h_rate_limit),
    ("zs_oidc_begin_login", helpers::h_oidc_begin_login),
    ("zs_oidc_handle_callback", helpers::h_oidc_handle_callback),
    ("zs_oidc_session_verify", helpers::h_oidc_session_verify),
    ("zs_oidc_logout", helpers::h_oidc_logout),
    (
        "zs_vici_eap_identity_by_ip",
        helpers::h_vici_eap_identity_by_ip,
    ),
];

static HELPER_TABLES: &[&[(&str, Helper)]] = &[SCRIPT_HELPERS];

/// Observed state of the underlying connection at the moment the request
/// arrived. Exposed to scripts via `zs_connection_info` so they can react to
/// TLS / ECH posture without re-parsing transport-layer details.
#[derive(Clone, Debug, Default)]
pub struct ConnectionInfo {
    /// True when the request was received over TLS.
    pub tls: bool,
    /// True when TLS is complete for this request. Plaintext requests are false.
    pub tls_handshake_complete: bool,
    /// Negotiated ALPN protocol (e.g. "h2", "http/1.1"). `None` when ALPN
    /// was not used or the connection is plaintext.
    pub alpn: Option<String>,
    /// The server name BoringSSL is serving: the inner (real, protected) SNI
    /// when ECH was accepted, otherwise the cleartext SNI. `None` if the
    /// client sent no SNI or the connection is plaintext.
    pub inner_sni: Option<String>,
    /// The cleartext outer SNI — the ECH public name — when ECH was accepted
    /// on this connection. `None` for plain TLS, rejected ECH, or when the
    /// configured public name is ambiguous.
    pub outer_sni: Option<String>,
    /// `None` when the server has no ECH keys loaded; otherwise whether
    /// BoringSSL accepted ECH on this connection (decrypted the inner
    /// ClientHello). `Some(false)` covers both "client offered a stale/no
    /// config" and "client did not offer ECH".
    pub ech_accepted: Option<bool>,
    /// TLS protocol version name in Caddy placeholder form (e.g. "tls1.3").
    /// `None` for plaintext connections.
    pub tls_version: Option<String>,
    /// RFC-standard TLS cipher suite name selected for the connection.
    /// `None` for plaintext connections or if BoringSSL has no active cipher.
    pub tls_cipher_suite: Option<String>,
    /// Whether this TLS connection resumed a previous session. `None` for
    /// plaintext connections.
    pub tls_resumed: Option<bool>,
    /// JA4 TLS client fingerprint computed from the ClientHello. `None` for
    /// plaintext connections or if the ClientHello could not be parsed.
    pub tls_client_ja4: Option<String>,
    /// DER-encoded leaf client certificate, if the TLS peer presented one.
    pub tls_client_cert_der: Option<Vec<u8>>,
    /// DER-encoded peer certificate chain as sent by the client.
    pub tls_client_chain_der: Vec<Vec<u8>>,
}

#[derive(Clone, Debug)]
pub struct ScriptRequest {
    pub request_id: RequestId,
    pub start_time: Instant,
    pub method: String,
    pub original_method: String,
    pub path: String,
    pub original_path: String,
    pub(crate) normalized_path: String,
    pub uri: String,
    pub original_uri: String,
    pub query: String,
    pub original_query: String,
    pub scheme: String,
    pub proto_major: u8,
    pub proto_minor: u8,
    pub peer: String,
    pub local: String,
    pub headers: HashMap<String, String>,
    pub(crate) header_values: HashMap<String, Vec<String>>,
    pub(crate) transfer_encodings: Vec<String>,
    pub query_params: HashMap<String, String>,
    pub(crate) query_param_values: HashMap<String, Vec<String>>,
    pub(crate) caddy_query_params: HashMap<String, Vec<String>>,
    pub(crate) caddy_query_valid: bool,
    pub connection: ConnectionInfo,
    pub(crate) proxy_method: Option<String>,
    pub(crate) proxy_uri: Option<String>,
    pub(crate) proxy_headers: Option<::http::HeaderMap>,
    pub(crate) uri_changed: bool,
    pub(crate) method_changed: bool,
    pub(crate) header_changes: Vec<HeaderChange>,
}

#[derive(Clone, Debug)]
pub(crate) enum HeaderChange {
    Set(String, String),
    Append(String, String),
    Remove(String),
    RemovePattern(String),
    Clear,
}

#[derive(Clone, Debug)]
pub(crate) struct ResponseHook {
    pub script: String,
    pub func: String,
    pub input: serde_json::Value,
}

#[derive(Clone, Debug)]
pub(crate) struct ResponseContext {
    pub status: u16,
    pub headers: ::http::HeaderMap,
    pub original_headers: ::http::HeaderMap,
    pub continue_request: bool,
}

#[derive(Clone, Debug, Default, serde::Deserialize)]
pub(crate) struct CaddyMapConfig {
    #[serde(default)]
    pub source: String,
    #[serde(default)]
    pub destinations: Vec<String>,
    #[serde(default)]
    pub mappings: Vec<CaddyMapEntry>,
    #[serde(default)]
    pub defaults: Vec<String>,
}

#[derive(Clone, Debug, Default, serde::Deserialize)]
pub(crate) struct CaddyMapEntry {
    #[serde(default)]
    pub input: String,
    #[serde(default)]
    pub input_regexp: String,
    #[serde(default)]
    pub outputs: Vec<serde_json::Value>,
}

impl ScriptRequest {
    /// A synthetic request for the pre-handshake TLS section run: only the
    /// connection addresses and the ClientHello SNI are known — the TLS
    /// handshake (and any HTTP request) has not happened yet.
    pub(crate) fn for_tls_handshake(
        peer: std::net::SocketAddr,
        local: std::net::SocketAddr,
        sni: Option<String>,
    ) -> Self {
        ScriptRequest {
            request_id: RequestId::new(),
            start_time: Instant::now(),
            method: String::new(),
            original_method: String::new(),
            path: String::new(),
            original_path: String::new(),
            normalized_path: String::new(),
            uri: String::new(),
            original_uri: String::new(),
            query: String::new(),
            original_query: String::new(),
            scheme: "https".to_string(),
            proto_major: 0,
            proto_minor: 0,
            peer: peer.to_string(),
            local: local.to_string(),
            headers: HashMap::new(),
            header_values: HashMap::new(),
            transfer_encodings: Vec::new(),
            query_params: HashMap::new(),
            query_param_values: HashMap::new(),
            caddy_query_params: HashMap::new(),
            caddy_query_valid: true,
            connection: ConnectionInfo {
                tls: true,
                tls_handshake_complete: false,
                inner_sni: sni,
                ..ConnectionInfo::default()
            },
            proxy_method: None,
            proxy_uri: None,
            proxy_headers: None,
            uri_changed: false,
            method_changed: false,
            header_changes: Vec::new(),
        }
    }

    pub fn header(&self, name: &str) -> Option<&str> {
        if name.bytes().all(|b| !b.is_ascii_uppercase()) {
            self.headers.get(name).map(String::as_str)
        } else {
            let name = name.to_ascii_lowercase();
            self.headers.get(&name).map(String::as_str)
        }
    }

    pub fn query_param(&self, name: &str) -> Option<&str> {
        self.query_param_values
            .get(name)
            .and_then(|values| values.first())
            .map(String::as_str)
    }

    pub fn query_param_matches(&self, name: &str, value: &str) -> bool {
        self.query_param_values
            .get(name)
            .is_some_and(|values| value == "*" || values.iter().any(|candidate| candidate == value))
    }

    pub fn set_method(&mut self, method: &str) -> Result<(), ()> {
        let method = method.trim();
        if method.is_empty() {
            return Err(());
        }
        let parsed = Method::from_bytes(method.as_bytes()).map_err(|_| ())?;
        self.method = parsed.as_str().to_string();
        self.method_changed = true;
        Ok(())
    }

    pub fn set_proxy_method(&mut self, method: &str) -> Result<(), ()> {
        let method = method.trim();
        if method.is_empty() {
            return Err(());
        }
        let parsed = Method::from_bytes(method.as_bytes()).map_err(|_| ())?;
        self.proxy_method = Some(parsed.as_str().to_string());
        Ok(())
    }

    pub fn set_proxy_uri(&mut self, uri: &str) -> Result<(), ()> {
        let uri = uri.trim();
        if uri.is_empty() {
            return Err(());
        }
        let _: Uri = uri.parse().map_err(|_| ())?;
        self.proxy_uri = Some(uri.to_string());
        Ok(())
    }

    pub fn set_proxy_headers(&mut self, headers: ::http::HeaderMap) {
        self.proxy_headers = Some(headers);
    }

    pub(crate) fn clear_proxy_overrides(&mut self) {
        self.proxy_method = None;
        self.proxy_uri = None;
        self.proxy_headers = None;
    }

    pub(crate) fn restore_original_uri(&mut self) {
        self.uri = self.original_uri.clone();
        self.path = self.original_path.clone();
        self.query = self.original_query.clone();
        self.query_params = parse_query_params(&self.query);
        self.query_param_values = parse_query_param_values(&self.query);
        let (caddy_query_params, caddy_query_valid) = parse_caddy_query_params(&self.query);
        self.caddy_query_params = caddy_query_params;
        self.caddy_query_valid = caddy_query_valid;
        self.uri_changed = true;
        self.clear_proxy_overrides();
    }

    pub fn set_uri(&mut self, uri: &str) -> Result<(), ()> {
        let uri = uri.trim();
        if uri.is_empty() {
            return Err(());
        }
        let (path, query) = if let Some(parts) = split_relative_request_target(uri) {
            parts
        } else {
            match uri.parse::<Uri>() {
                Ok(parsed) => {
                    let mut path = parsed.path().to_string();
                    if path.is_empty() && !uri.starts_with('?') {
                        let end = uri.find(['?', '#']).unwrap_or(uri.len());
                        path = uri[..end].to_string();
                    }
                    (path, parsed.query().unwrap_or("").to_string())
                }
                Err(_) => return Err(()),
            }
        };
        self.uri = if query.is_empty() {
            path.clone()
        } else {
            format!("{path}?{query}")
        };
        self.path = path;
        self.normalized_path = normalize_request_path(&self.path)
            .map(|path| path.relative().to_string())
            .unwrap_or_else(|| self.path.trim_start_matches('/').to_string());
        self.query = query.clone();
        self.query_params = parse_query_params(&query);
        self.query_param_values = parse_query_param_values(&query);
        let (caddy_query_params, caddy_query_valid) = parse_caddy_query_params(&query);
        self.caddy_query_params = caddy_query_params;
        self.caddy_query_valid = caddy_query_valid;
        self.uri_changed = true;
        Ok(())
    }

    pub fn set_query(&mut self, query: &str) -> Result<(), ()> {
        self.uri = if query.is_empty() {
            self.path.clone()
        } else {
            format!("{}?{}", self.path, query)
        };
        self.query = query.to_string();
        self.query_params = parse_query_params(query);
        self.query_param_values = parse_query_param_values(query);
        let (caddy_query_params, caddy_query_valid) = parse_caddy_query_params(query);
        self.caddy_query_params = caddy_query_params;
        self.caddy_query_valid = caddy_query_valid;
        self.uri_changed = true;
        Ok(())
    }

    pub fn set_path(&mut self, path: &str) -> Result<(), ()> {
        let uri = if self.query.is_empty() {
            path.to_string()
        } else {
            format!("{}?{}", path, self.query)
        };
        self.uri = uri;
        self.path = path.to_string();
        self.normalized_path = normalize_request_path(&self.path)
            .map(|path| path.relative().to_string())
            .unwrap_or_else(|| self.path.trim_start_matches('/').to_string());
        self.uri_changed = true;
        Ok(())
    }

    pub fn set_header(&mut self, name: &str, value: Option<&str>) -> Result<(), ()> {
        let name = name.trim();
        if name.is_empty() {
            return Err(());
        }
        let name = name.to_ascii_lowercase();
        if HeaderName::from_bytes(name.as_bytes()).is_err() {
            return Err(());
        }
        match value {
            Some(value) => {
                if HeaderValue::from_str(value).is_err() {
                    return Err(());
                }
                let value = value.to_string();
                self.headers.insert(name.clone(), value.clone());
                self.header_values.insert(name.clone(), vec![value.clone()]);
                self.header_changes.push(HeaderChange::Set(name, value));
            }
            None => {
                self.headers.remove(&name);
                self.header_values.remove(&name);
                self.header_changes.push(HeaderChange::Remove(name));
            }
        }
        Ok(())
    }

    pub fn append_header(&mut self, name: &str, value: &str) -> Result<(), ()> {
        let name = name.trim();
        if name.is_empty() {
            return Err(());
        }
        let name = name.to_ascii_lowercase();
        if HeaderName::from_bytes(name.as_bytes()).is_err() || HeaderValue::from_str(value).is_err()
        {
            return Err(());
        }
        let value = value.to_string();
        if name == "host" {
            self.headers.insert(name.clone(), value.clone());
            self.header_values
                .entry(name.clone())
                .or_default()
                .push(value.clone());
            self.header_changes.push(HeaderChange::Set(name, value));
            return Ok(());
        }
        self.headers
            .entry(name.clone())
            .and_modify(|existing| {
                existing.push(',');
                existing.push_str(&value);
            })
            .or_insert_with(|| value.clone());
        self.header_values
            .entry(name.clone())
            .or_default()
            .push(value.clone());
        self.header_changes.push(HeaderChange::Append(name, value));
        Ok(())
    }

    pub fn delete_header_pattern(&mut self, pattern: &str) -> Result<(), ()> {
        let pattern = pattern.trim().to_ascii_lowercase();
        if pattern.is_empty() {
            return Err(());
        }
        if pattern == "*" {
            self.headers.clear();
            self.header_values.clear();
            self.header_changes.push(HeaderChange::Clear);
            return Ok(());
        }
        self.headers
            .retain(|name, _| !header_pattern_matches(name, &pattern));
        self.header_values
            .retain(|name, _| !header_pattern_matches(name, &pattern));
        self.header_changes
            .push(HeaderChange::RemovePattern(pattern));
        Ok(())
    }

    pub fn replace_header(
        &mut self,
        name: &str,
        search: &str,
        replacement: &str,
    ) -> Result<(), ()> {
        let name = name.trim();
        if name.is_empty() {
            return Err(());
        }
        let targets = if name == "*" {
            self.headers.keys().cloned().collect::<Vec<_>>()
        } else {
            let name = name.to_ascii_lowercase();
            if HeaderName::from_bytes(name.as_bytes()).is_err() {
                return Err(());
            }
            self.headers
                .keys()
                .filter(|existing| existing.eq_ignore_ascii_case(&name))
                .cloned()
                .collect::<Vec<_>>()
        };
        for target in targets {
            let values = self
                .header_values
                .get(&target)
                .cloned()
                .or_else(|| self.headers.get(&target).cloned().map(|value| vec![value]));
            let Some(values) = values else {
                continue;
            };
            let values = values
                .into_iter()
                .map(|value| value.replace(search, replacement))
                .filter(|value| HeaderValue::from_str(value).is_ok())
                .collect::<Vec<_>>();
            if values.is_empty() {
                continue;
            }
            if target == "host" {
                let value = values.last().cloned().ok_or(())?;
                self.headers.insert(target.clone(), value.clone());
                self.header_values.insert(target.clone(), values);
                self.header_changes.push(HeaderChange::Set(target, value));
                continue;
            }
            self.headers.insert(target.clone(), values.join(","));
            self.header_values.insert(target.clone(), values.clone());
            self.header_changes
                .push(HeaderChange::Remove(target.clone()));
            for value in values {
                self.header_changes
                    .push(HeaderChange::Append(target.clone(), value));
            }
        }
        Ok(())
    }

    pub fn replace_header_regex(
        &mut self,
        name: &str,
        search: &regex::Regex,
        replacement: &str,
    ) -> Result<(), ()> {
        let name = name.trim();
        if name.is_empty() {
            return Err(());
        }
        let targets = if name == "*" {
            self.headers.keys().cloned().collect::<Vec<_>>()
        } else {
            let name = name.to_ascii_lowercase();
            if HeaderName::from_bytes(name.as_bytes()).is_err() {
                return Err(());
            }
            self.headers
                .keys()
                .filter(|existing| existing.eq_ignore_ascii_case(&name))
                .cloned()
                .collect::<Vec<_>>()
        };
        for target in targets {
            let values = self
                .header_values
                .get(&target)
                .cloned()
                .or_else(|| self.headers.get(&target).cloned().map(|value| vec![value]));
            let Some(values) = values else {
                continue;
            };
            let values = values
                .into_iter()
                .map(|value| search.replace_all(&value, replacement).into_owned())
                .filter(|value| HeaderValue::from_str(value).is_ok())
                .collect::<Vec<_>>();
            if values.is_empty() {
                continue;
            }
            if target == "host" {
                let value = values.last().cloned().ok_or(())?;
                self.headers.insert(target.clone(), value.clone());
                self.header_values.insert(target.clone(), values);
                self.header_changes.push(HeaderChange::Set(target, value));
                continue;
            }
            self.headers.insert(target.clone(), values.join(","));
            self.header_values.insert(target.clone(), values.clone());
            self.header_changes
                .push(HeaderChange::Remove(target.clone()));
            for value in values {
                self.header_changes
                    .push(HeaderChange::Append(target.clone(), value));
            }
        }
        Ok(())
    }

    pub(crate) fn uri_changed(&self) -> bool {
        self.uri_changed
    }

    pub(crate) fn method_changed(&self) -> bool {
        self.method_changed
    }

    pub(crate) fn proxy_method(&self) -> Option<&str> {
        self.proxy_method.as_deref()
    }

    pub(crate) fn proxy_uri(&self) -> Option<&str> {
        self.proxy_uri.as_deref()
    }

    pub(crate) fn proxy_headers(&self) -> Option<&::http::HeaderMap> {
        self.proxy_headers.as_ref()
    }

    pub(crate) fn header_changes(&self) -> &[HeaderChange] {
        &self.header_changes
    }
}

pub(crate) fn split_relative_request_target(uri: &str) -> Option<(String, String)> {
    if uri.starts_with('/') || uri.starts_with('?') || uri.contains("://") {
        return None;
    }
    let without_fragment = uri.split_once('#').map_or(uri, |(before, _)| before);
    let (path, query) = without_fragment
        .split_once('?')
        .map_or((without_fragment, ""), |(path, query)| (path, query));
    if path.is_empty() {
        return None;
    }
    Some((path.to_string(), query.to_string()))
}

fn parse_query_params(query: &str) -> HashMap<String, String> {
    parse_query_param_values(query)
        .into_iter()
        .filter_map(|(key, mut values)| values.drain(..).next().map(|value| (key, value)))
        .collect()
}

fn parse_query_param_values(query: &str) -> HashMap<String, Vec<String>> {
    let mut query_params = HashMap::new();
    if !query.is_empty() {
        for (key, value) in form_urlencoded::parse(query.as_bytes()) {
            query_params
                .entry(key.into_owned())
                .or_insert_with(Vec::new)
                .push(value.into_owned());
        }
    }
    query_params
}

pub(crate) fn parse_caddy_query_params(query: &str) -> (HashMap<String, Vec<String>>, bool) {
    let mut query_params = HashMap::new();
    let mut valid = true;
    if query.is_empty() {
        return (query_params, valid);
    }
    for pair in query.split('&') {
        if pair.is_empty() {
            continue;
        }
        if pair.contains(';') {
            valid = false;
            continue;
        }
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        let Some(key) = caddy_query_unescape(key) else {
            valid = false;
            continue;
        };
        let Some(value) = caddy_query_unescape(value) else {
            valid = false;
            continue;
        };
        query_params.entry(key).or_insert_with(Vec::new).push(value);
    }
    (query_params, valid)
}

fn caddy_query_unescape(value: &str) -> Option<String> {
    let mut out = Vec::with_capacity(value.len());
    let bytes = value.as_bytes();
    let mut i = 0usize;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b'%' => {
                if i + 2 >= bytes.len() {
                    return None;
                }
                let high = hex_value(bytes[i + 1])?;
                let low = hex_value(bytes[i + 2])?;
                out.push((high << 4) | low);
                i += 3;
            }
            byte => {
                out.push(byte);
                i += 1;
            }
        }
    }
    Some(String::from_utf8_lossy(&out).into_owned())
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

pub(crate) fn header_pattern_matches(name: &str, pattern: &str) -> bool {
    let name = name.to_ascii_lowercase();
    let pattern = pattern.to_ascii_lowercase();
    if pattern.starts_with('*') && pattern.ends_with('*') && pattern.len() >= 2 {
        name.contains(&pattern[1..pattern.len() - 1])
    } else if let Some(suffix) = pattern.strip_prefix('*') {
        name.ends_with(suffix)
    } else if let Some(prefix) = pattern.strip_suffix('*') {
        name.starts_with(prefix)
    } else {
        name == pattern
    }
}

#[derive(Clone, Debug)]
pub struct ScriptResponse {
    pub status: u16,
    pub body: Vec<u8>,
    pub content_type: Option<String>,
    pub force_close: bool,
    /// Extra response headers set by a helper (e.g. `Location`, `Set-Cookie`).
    /// Emitted in order with `HeaderMap::append`, so repeated names (multiple
    /// `Set-Cookie`) are preserved.
    pub headers: Vec<(String, String)>,
}

#[derive(Clone, Debug, Default, serde::Deserialize)]
pub(crate) struct CaddyFileBrowse {
    #[serde(default)]
    pub template_file: String,
    #[serde(default)]
    pub reveal_symlinks: bool,
    #[serde(default, rename = "sort")]
    pub sort_options: Vec<String>,
    #[serde(default)]
    pub file_limit: i64,
}

fn deserialize_caddy_file_browse<'de, D>(
    deserializer: D,
) -> Result<Option<CaddyFileBrowse>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = Option::<serde_json::Value>::deserialize(deserializer)?;
    match value {
        None | Some(serde_json::Value::Null) | Some(serde_json::Value::Bool(false)) => Ok(None),
        Some(serde_json::Value::Bool(true)) => Ok(Some(CaddyFileBrowse::default())),
        Some(value @ serde_json::Value::Object(_)) => serde_json::from_value(value)
            .map(Some)
            .map_err(serde::de::Error::custom),
        Some(other) => Err(serde::de::Error::custom(format!(
            "invalid file_server browse value: {other}"
        ))),
    }
}

fn deserialize_weak_string_option<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = Option::<serde_json::Value>::deserialize(deserializer)?;
    match value {
        None | Some(serde_json::Value::Null) => Ok(None),
        Some(serde_json::Value::String(value)) => Ok(Some(value)),
        Some(serde_json::Value::Number(value)) => Ok(Some(value.to_string())),
        Some(other) => serde_json::to_string(&other)
            .map(Some)
            .map_err(serde::de::Error::custom),
    }
}

#[derive(Clone, Debug, Default, serde::Deserialize)]
pub(crate) struct CaddyFileServer {
    #[serde(default)]
    pub fs: String,
    #[serde(default)]
    pub root: String,
    #[serde(default)]
    pub hide: Vec<String>,
    #[serde(default)]
    pub index_names: Option<Vec<String>>,
    #[serde(default, deserialize_with = "deserialize_caddy_file_browse")]
    pub browse: Option<CaddyFileBrowse>,
    #[serde(default)]
    pub canonical_uris: Option<bool>,
    #[serde(default, deserialize_with = "deserialize_weak_string_option")]
    pub status_code: Option<String>,
    #[serde(default)]
    pub pass_thru: bool,
    #[serde(default)]
    pub etag_file_extensions: Vec<String>,
    #[serde(default)]
    pub precompressed: HashMap<String, serde_json::Value>,
    #[serde(default)]
    pub precompressed_order: Vec<String>,
}

#[derive(Debug)]
pub struct ScriptOutcome {
    pub request: ScriptRequest,
    pub request_shared: Rc<RefCell<ScriptRequest>>,
    pub metadata: HashMap<String, String>,
    pub metadata_shared: Rc<RefCell<HashMap<String, String>>>,
    pub caddy_maps_shared: Rc<RefCell<Vec<CaddyMapConfig>>>,
    pub early_response_headers: ::http::HeaderMap,
    pub response_hooks: Vec<ResponseHook>,
    pub abort: bool,
    pub response: Option<ScriptResponse>,
    pub request_body_limit: Option<usize>,
    pub reverse_proxy: Option<String>,
    pub caddy_reverse_proxy: bool,
    pub caddy_default_forwarded: bool,
    pub file_server: Option<CaddyFileServer>,
    /// Streaming response compression requested by an `encode` handler, applied
    /// by the response-writing path against the request's `Accept-Encoding`.
    pub encode: Option<crate::helpers::compress::EncodeConfig>,
}

impl ScriptOutcome {
    pub(crate) fn from_request(request: ScriptRequest) -> Self {
        let request_shared = Rc::new(RefCell::new(request.clone()));
        ScriptOutcome {
            request,
            request_shared,
            metadata: HashMap::new(),
            metadata_shared: Rc::new(RefCell::new(HashMap::new())),
            caddy_maps_shared: Rc::new(RefCell::new(Vec::new())),
            early_response_headers: ::http::HeaderMap::new(),
            response_hooks: Vec::new(),
            abort: false,
            response: None,
            request_body_limit: None,
            reverse_proxy: None,
            caddy_reverse_proxy: false,
            caddy_default_forwarded: false,
            file_server: None,
            encode: None,
        }
    }
}

pub struct ScriptExecutionContext {
    /// The live request, shared by reference across an inter-script call chain:
    /// a callee sees the caller's request and its mutations (set_header/set_uri)
    /// propagate back to the caller and out to the wire.
    pub request: Rc<RefCell<ScriptRequest>>,
    pub body_source: BodySource,
    /// The per-request metadata map, shared by reference across a call chain so a
    /// callee's `zs_meta_set` is visible to the caller.
    pub metadata: Rc<RefCell<HashMap<String, String>>>,
    pub caddy_maps: Rc<RefCell<Vec<CaddyMapConfig>>>,
    pub early_response_headers: Rc<RefCell<::http::HeaderMap>>,
    pub response_hooks: Rc<RefCell<Vec<ResponseHook>>>,
    pub response_context: Option<Rc<RefCell<ResponseContext>>>,
    pub abort: bool,
    pub response: Option<ScriptResponse>,
    pub request_body_limit: Rc<Cell<Option<usize>>>,
    pub reverse_proxy: Option<String>,
    pub caddy_reverse_proxy: bool,
    pub caddy_default_forwarded: bool,
    pub file_server: Option<CaddyFileServer>,
    /// Streaming response compression config recorded by `zs_caddy_encode`.
    pub encode: Option<crate::helpers::compress::EncodeConfig>,
    pub script_name: String,
    pub log_buffer: Vec<u8>,
    pub external_objects: ObjectRegistry,
    pub error: String,
    pub memory_footprint_bytes: u64,
    pub max_memory_footprint: u64,
    pub expose_filesystem: bool,
    pub site: Arc<Site>,
    /// All loaded scripts on this thread, shared so helpers (notably `zs_call`)
    /// can resolve and invoke another script by name.
    pub scripts: Rc<Vec<(String, Program)>>,
    /// Thread environment, needed to arm preemption when running a callee.
    pub t: ThreadEnv,
    /// Current inter-script call nesting depth. The top-level request runs at
    /// depth 0; each `zs_call` increments it for the callee.
    pub call_depth: usize,
    /// Runtime cache for Caddy-generated helpers that intentionally defer host
    /// filesystem reads until request time.
    pub caddy_file_cache: Rc<RefCell<HashMap<String, Vec<u8>>>>,
    /// Present only during the pre-handshake TLS section run (`--caddy`
    /// script-selected certificates): the certificate selection state for the
    /// in-flight handshake. `None` for request-phase runs — TLS helpers that
    /// act at handshake time use this to tell the phases apart. Not propagated
    /// to `zs_call` callees.
    pub tls_select: Option<Rc<TlsCertSelect>>,
}

impl ScriptExecutionContext {
    /// Build the execution context for a `zs_call` callee. The input JSON value
    /// is installed as external object handle `1` — the handle the callee's
    /// `zeroserve.call.<name>` entrypoint receives as its argument.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn for_call(
        input: serde_json::Value,
        request: Rc<RefCell<ScriptRequest>>,
        body_source: BodySource,
        metadata: Rc<RefCell<HashMap<String, String>>>,
        caddy_maps: Rc<RefCell<Vec<CaddyMapConfig>>>,
        early_response_headers: Rc<RefCell<::http::HeaderMap>>,
        response_hooks: Rc<RefCell<Vec<ResponseHook>>>,
        response_context: Option<Rc<RefCell<ResponseContext>>>,
        request_body_limit: Rc<Cell<Option<usize>>>,
        script_name: String,
        site: Arc<Site>,
        scripts: Rc<Vec<(String, Program)>>,
        t: ThreadEnv,
        max_memory_footprint: u64,
        expose_filesystem: bool,
        call_depth: usize,
        caddy_file_cache: Rc<RefCell<HashMap<String, Vec<u8>>>>,
    ) -> Self {
        let input_mem = helpers::estimate_json_memory_usage(&input) as u64;
        let mut external_objects = ObjectRegistry {
            next_idx: 2,
            objects: HashMap::new(),
        };
        external_objects
            .objects
            .insert(1, Box::new(JsonRef::new(input)));
        ScriptExecutionContext {
            request,
            body_source,
            metadata,
            caddy_maps,
            early_response_headers,
            response_hooks,
            response_context,
            abort: false,
            response: None,
            request_body_limit,
            reverse_proxy: None,
            caddy_reverse_proxy: false,
            caddy_default_forwarded: false,
            file_server: None,
            encode: None,
            script_name,
            log_buffer: vec![],
            external_objects,
            error: String::new(),
            memory_footprint_bytes: input_mem,
            max_memory_footprint,
            expose_filesystem,
            site,
            scripts,
            t,
            call_depth,
            caddy_file_cache,
            tls_select: None,
        }
    }

    /// Build the execution context for a load-time `zeroserve.init.<name>`
    /// section. There is no live request, so a synthetic one is installed and
    /// the object table starts empty (init sections take no input handle).
    pub(crate) fn for_init(
        script_name: String,
        site: Arc<Site>,
        scripts: Rc<Vec<(String, Program)>>,
        t: ThreadEnv,
        max_memory_footprint: u64,
        expose_filesystem: bool,
        caddy_file_cache: Rc<RefCell<HashMap<String, Vec<u8>>>>,
    ) -> Self {
        let addr = std::net::SocketAddr::from(([0, 0, 0, 0], 0));
        ScriptExecutionContext {
            request: Rc::new(RefCell::new(ScriptRequest::for_tls_handshake(
                addr, addr, None,
            ))),
            body_source: BodySource::empty(),
            metadata: Rc::new(RefCell::new(HashMap::new())),
            caddy_maps: Rc::new(RefCell::new(Vec::new())),
            early_response_headers: Rc::new(RefCell::new(::http::HeaderMap::new())),
            response_hooks: Rc::new(RefCell::new(Vec::new())),
            response_context: None,
            abort: false,
            response: None,
            request_body_limit: Rc::new(Cell::new(None)),
            reverse_proxy: None,
            caddy_reverse_proxy: false,
            caddy_default_forwarded: false,
            file_server: None,
            encode: None,
            script_name,
            log_buffer: vec![],
            external_objects: ObjectRegistry {
                next_idx: 1,
                objects: HashMap::new(),
            },
            error: String::new(),
            memory_footprint_bytes: 0,
            max_memory_footprint,
            expose_filesystem,
            site,
            scripts,
            t,
            call_depth: 0,
            caddy_file_cache,
            tls_select: None,
        }
    }

    pub fn extobj<T: Any>(&mut self, idx: u64) -> Result<&mut T, ()> {
        self.external_objects
            .objects
            .get_mut(&idx)
            .ok_or(())
            .and_then(|x| x.downcast_mut().ok_or(()))
            .inspect_err(|()| self.error = format!("invalid external object index {}", idx))
    }

    pub fn alloc_extobj(&mut self, x: impl Any) -> Result<u64, ()> {
        if self.external_objects.objects.len() >= MAX_EXTERNAL_OBJECTS {
            self.error = format!("external object limit exceeded ({})", MAX_EXTERNAL_OBJECTS);
            return Err(());
        }

        let idx = self.external_objects.next_idx;
        self.external_objects.next_idx += 1;
        self.external_objects.objects.insert(idx, Box::new(x));
        Ok(idx as u64)
    }

    pub fn alloc_memory_footprint(&mut self, n: u64) -> Result<(), ()> {
        if self.memory_footprint_bytes.saturating_add(n) > self.max_memory_footprint {
            self.error = format!(
                "memory footprint limit exceeded ({} bytes) while allocating {} bytes",
                self.max_memory_footprint, n,
            );
            return Err(());
        }
        self.memory_footprint_bytes += n;
        Ok(())
    }

    pub(crate) fn abort_and_clear_outputs(&mut self) {
        self.abort = true;
        self.response = None;
        self.reverse_proxy = None;
        self.caddy_reverse_proxy = false;
        self.caddy_default_forwarded = false;
        self.file_server = None;
        self.encode = None;
    }
}

pub struct ObjectRegistry {
    next_idx: u64,
    objects: HashMap<u64, Box<dyn Any>>,
}

impl ObjectRegistry {
    pub fn insert(&mut self, idx: u64, obj: Box<dyn Any>) {
        self.objects.insert(idx, obj);
    }

    pub fn remove(&mut self, idx: u64) -> bool {
        self.objects.remove(&idx).is_some()
    }
}

pub struct ScriptRuntime {
    t: ThreadEnv,
    scripts: RefCell<Rc<Vec<(String, Program)>>>,
    caddy_file_cache: Rc<RefCell<HashMap<String, Vec<u8>>>>,
    max_memory_footprint: u64,
    expose_filesystem: bool,
    code_size_limit: usize,
    require_static_region_analysis: bool,
}

#[derive(Clone, Debug)]
pub struct ScriptRuntimeConfig {
    pub preempt_timer_interval: Duration,
    pub max_memory_footprint: u64,
    pub expose_filesystem: bool,
    /// JIT code zone size per loaded program, in bytes (a non-zero multiple
    /// of 64 KiB that fits in u32).
    pub code_size_limit: usize,
    pub require_static_region_analysis: bool,
}

impl ScriptRuntime {
    pub unsafe fn new(config: ScriptRuntimeConfig) -> Self {
        let g = unsafe { GlobalEnv::new() };
        let t = g.init_thread(config.preempt_timer_interval);
        let scripts = RefCell::new(Rc::new(Vec::new()));
        ScriptRuntime {
            t,
            scripts,
            caddy_file_cache: Rc::new(RefCell::new(HashMap::new())),
            max_memory_footprint: config.max_memory_footprint,
            expose_filesystem: config.expose_filesystem,
            code_size_limit: config.code_size_limit,
            require_static_region_analysis: config.require_static_region_analysis,
        }
    }

    async fn load_site_scripts(&self, site: Arc<Site>) -> anyhow::Result<Vec<(String, Program)>> {
        let pl = Arc::new(
            ProgramLoader::new(
                &mut rand::thread_rng(),
                Arc::new(EventListener),
                HELPER_TABLES,
            )
            .with_code_size_limit(self.code_size_limit)
            .require_static_region_analysis(self.require_static_region_analysis),
        );
        let file = site
            .tar_file
            .try_clone()
            .and_then(File::from_std)
            .with_context(|| "failed to prepare tar file")?;

        let script_entries: Vec<(String, Arc<_>)> = site
            .entries
            .iter()
            .filter_map(|(path, entry)| {
                let name = path.strip_prefix(".zeroserve/scripts/")?;
                if !name.ends_with(".o") {
                    return None;
                }
                Some((name.to_string(), entry.clone()))
            })
            .collect();

        let loaded_scripts =
            futures::future::join_all(script_entries.into_iter().map(|(name, entry)| {
                let file = &file;
                let pl = pl.clone();
                async move {
                    let size = usize::try_from(entry.size)
                        .with_context(|| format!("script '{}' is too large to load", name))?;
                    let (res, buf) = file.read_exact_at(vec![0u8; size], entry.offset).await;
                    res.with_context(|| format!("failed to read script '{}'", name))?;
                    let prog_len = buf.len();
                    let (tx, rx) = oneshot::channel();
                    CPU_TP.spawn(move || {
                        let _ = tx.send(pl.load(&mut rand::thread_rng(), &buf));
                    });
                    let prog = rx.await.with_context(|| {
                        format!("script loader exited before loading '{}'", name)
                    })?;
                    let prog = match prog {
                        Ok(x) => x,
                        Err(err) => bail!(
                            "failed to load script '{}' ({} bytes): {:?}",
                            name,
                            prog_len,
                            err
                        ),
                    };
                    async_log(
                        format!("compiled script '{}' ({} bytes)\n", name, prog_len).into_bytes(),
                    )
                    .await;
                    Ok::<(String, UnboundProgram), anyhow::Error>((name, prog))
                }
            }))
            .await;

        let mut scripts = Vec::with_capacity(loaded_scripts.len());
        for script in loaded_scripts {
            let (name, program): (String, UnboundProgram) = script?;
            scripts.push((name, program.pin_to_current_thread(self.t)));
        }
        scripts.sort_by(|a, b| a.0.cmp(&b.0));
        Ok(scripts)
    }

    pub(crate) async fn load_scripts_from_sites(
        &self,
        sites: &[Arc<Site>],
    ) -> anyhow::Result<Rc<Vec<(String, Program)>>> {
        let mut scripts = Vec::new();
        for site in sites {
            scripts.extend(self.load_site_scripts(site.clone()).await?);
        }
        Ok(Rc::new(scripts))
    }

    pub(crate) fn install_scripts(&self, scripts: Rc<Vec<(String, Program)>>) {
        *self.scripts.borrow_mut() = scripts;
        self.caddy_file_cache.borrow_mut().clear();
    }

    /// Run only the `zeroserve.tls` script sections to choose a certificate
    /// for an in-flight TLS handshake (the `--caddy` script-selected flow).
    /// Runs once per connection while the handshake is paused at the
    /// ClientHello, so only the connection addresses and SNI are populated.
    /// Returns `Ok(None)` when no policy selected a certificate (serve the
    /// default identity, if any) and `Err` when a script aborted or failed
    /// (reject the connection).
    pub(crate) async fn select_tls_certificate(
        &self,
        site: Arc<Site>,
        tls: Arc<TlsRuntime>,
        sni: Option<String>,
        peer: std::net::SocketAddr,
        local: std::net::SocketAddr,
    ) -> anyhow::Result<(Option<SslContext>, bool)> {
        let scripts = (*self.scripts.borrow()).clone();
        // Fallback used whenever the site's TLS scripts (if any) select nothing:
        // a `--cert-dir` certificate covering the SNI is preferred, then an ACME
        // (`--acme-dir`) live certificate. cert-dir wins so a name covered there
        // is never served over ACME.
        let runtime = tls.clone();
        let fallback_sni = sni.clone();
        let static_fallback = move || {
            let sni = fallback_sni.as_ref()?;
            runtime
                .cert_dir_context_for_sni(sni)
                .or_else(|| runtime.acme_certs.as_ref()?.live_for_sni(sni))
        };
        if !scripts
            .iter()
            .any(|(_, program)| program.has_section(SCRIPT_TLS_ENTRYPOINT))
        {
            return Ok((static_fallback(), false));
        }

        let select = Rc::new(TlsCertSelect {
            runtime: tls,
            chosen: RefCell::new(None),
            request_client_cert: Cell::new(false),
        });
        let request = Rc::new(RefCell::new(ScriptRequest::for_tls_handshake(
            peer, local, sni,
        )));
        let metadata: Rc<RefCell<HashMap<String, String>>> = Rc::new(RefCell::new(HashMap::new()));
        let caddy_maps: Rc<RefCell<Vec<CaddyMapConfig>>> = Rc::new(RefCell::new(Vec::new()));
        let timeslice = default_timeslice();
        let preemption = PreemptionEnabled::new(self.t);

        for (name, program) in scripts.iter() {
            if !program.has_section(SCRIPT_TLS_ENTRYPOINT) {
                continue;
            }
            let mut ctx = ScriptExecutionContext {
                request: request.clone(),
                body_source: BodySource::empty(),
                metadata: metadata.clone(),
                caddy_maps: caddy_maps.clone(),
                early_response_headers: Rc::new(RefCell::new(::http::HeaderMap::new())),
                response_hooks: Rc::new(RefCell::new(Vec::new())),
                response_context: None,
                abort: false,
                response: None,
                request_body_limit: Rc::new(Cell::new(None)),
                reverse_proxy: None,
                caddy_reverse_proxy: false,
                caddy_default_forwarded: false,
                file_server: None,
                encode: None,
                script_name: name.clone(),
                log_buffer: vec![],
                external_objects: ObjectRegistry {
                    next_idx: 1,
                    objects: HashMap::new(),
                },
                error: String::new(),
                memory_footprint_bytes: 0,
                max_memory_footprint: self.max_memory_footprint,
                expose_filesystem: self.expose_filesystem,
                site: site.clone(),
                scripts: scripts.clone(),
                t: self.t,
                call_depth: 0,
                caddy_file_cache: self.caddy_file_cache.clone(),
                tls_select: Some(select.clone()),
            };
            let mut resources: [&mut dyn Any; 1] = [&mut ctx];
            let run = program
                .run(
                    &timeslice,
                    &MonoioTimeslicer,
                    SCRIPT_TLS_ENTRYPOINT,
                    &mut resources,
                    &[],
                    &preemption,
                )
                .await;
            if let Err(err) = run {
                bail!(
                    "script '{}' TLS section failed: {:?} ({})",
                    name,
                    err,
                    if ctx.error.is_empty() {
                        "no details"
                    } else {
                        ctx.error.as_str()
                    }
                );
            }
            if ctx.abort {
                bail!("script '{name}' aborted TLS certificate selection");
            }
            if select.chosen.borrow().is_some() {
                break;
            }
        }

        let chosen = select.chosen.borrow_mut().take().or_else(static_fallback);
        Ok((chosen, select.request_client_cert.get()))
    }

    /// Run every loaded script's `zeroserve.init.<name>` section once and
    /// collect the JSON value each returns. Used at load time to read
    /// configuration back from the site's scripts (e.g. `acme_config`). The run
    /// uses a synthetic context with no live request, so request-bound helpers
    /// are inert; JSON, env, log, and crypto helpers work normally.
    pub(crate) async fn run_init_section(
        &self,
        site: Arc<Site>,
        name: &str,
    ) -> anyhow::Result<Vec<(String, serde_json::Value)>> {
        let section = format!("{}{}", SCRIPT_INIT_SECTION_PREFIX, name);
        let scripts = (*self.scripts.borrow()).clone();
        let timeslice = default_timeslice();
        let preemption = PreemptionEnabled::new(self.t);
        let mut out = Vec::new();
        for (script_name, program) in scripts.iter() {
            if !program.has_section(&section) {
                continue;
            }
            let mut ctx = ScriptExecutionContext::for_init(
                script_name.clone(),
                site.clone(),
                scripts.clone(),
                self.t,
                self.max_memory_footprint,
                self.expose_filesystem,
                self.caddy_file_cache.clone(),
            );
            let ret = {
                let mut resources: [&mut dyn Any; 1] = [&mut ctx];
                program
                    .run(
                        &timeslice,
                        &MonoioTimeslicer,
                        &section,
                        &mut resources,
                        &[],
                        &preemption,
                    )
                    .await
            };
            let ret = ret.map_err(|err| {
                anyhow::anyhow!(
                    "script '{}' init section '{}' failed: {:?} ({})",
                    script_name,
                    section,
                    err,
                    if ctx.error.is_empty() {
                        "no details"
                    } else {
                        ctx.error.as_str()
                    }
                )
            })?;
            if ret < 0 {
                bail!(
                    "script '{}' init section '{}' returned error {}",
                    script_name,
                    section,
                    ret
                );
            }
            let value = ctx
                .extobj::<JsonRef>(ret as u64)
                .map_err(|_| {
                    anyhow::anyhow!(
                        "script '{}' init section '{}' returned an invalid JSON handle",
                        script_name,
                        section
                    )
                })?
                .view(|v| v.clone())
                .map_err(|_| {
                    anyhow::anyhow!(
                        "script '{}' init section '{}' returned an unreadable JSON handle",
                        script_name,
                        section
                    )
                })?;
            out.push((script_name.clone(), value));
        }
        Ok(out)
    }

    pub async fn run_request(
        &self,
        site: Arc<Site>,
        request: ScriptRequest,
        body_source: BodySource,
    ) -> anyhow::Result<ScriptOutcome> {
        let timeslice = default_timeslice();
        let scripts = (*self.scripts.borrow()).clone();
        let outcome = run_request_scripts(
            self.t,
            scripts,
            site,
            request,
            body_source,
            &timeslice,
            &MonoioTimeslicer,
            self.max_memory_footprint,
            self.expose_filesystem,
            self.caddy_file_cache.clone(),
        )
        .await;
        Ok(outcome)
    }

    pub(crate) async fn run_request_with_state(
        &self,
        site: Arc<Site>,
        request: Rc<RefCell<ScriptRequest>>,
        metadata: Rc<RefCell<HashMap<String, String>>>,
        caddy_maps: Rc<RefCell<Vec<CaddyMapConfig>>>,
        body_source: BodySource,
    ) -> anyhow::Result<ScriptOutcome> {
        let timeslice = default_timeslice();
        let scripts = (*self.scripts.borrow()).clone();
        let outcome = run_request_scripts_with_state(
            self.t,
            scripts,
            site,
            request,
            metadata,
            caddy_maps,
            body_source,
            &timeslice,
            &MonoioTimeslicer,
            self.max_memory_footprint,
            self.expose_filesystem,
            self.caddy_file_cache.clone(),
        )
        .await;
        Ok(outcome)
    }

    pub(crate) async fn run_response_hooks(
        &self,
        site: Arc<Site>,
        request: Rc<RefCell<ScriptRequest>>,
        metadata: Rc<RefCell<HashMap<String, String>>>,
        caddy_maps: Rc<RefCell<Vec<CaddyMapConfig>>>,
        hooks: &[ResponseHook],
        status: ::http::StatusCode,
        headers: &mut ::http::HeaderMap,
    ) -> ResponseHookOutcome {
        let raw = self
            .run_response_hooks_raw(
                site,
                request,
                metadata,
                caddy_maps,
                hooks,
                status.as_u16(),
                headers,
            )
            .await;
        ResponseHookOutcome {
            status: ::http::StatusCode::from_u16(raw.status).unwrap_or(status),
            continue_request: raw.continue_request,
        }
    }

    pub(crate) async fn run_response_hooks_raw(
        &self,
        site: Arc<Site>,
        request: Rc<RefCell<ScriptRequest>>,
        metadata: Rc<RefCell<HashMap<String, String>>>,
        caddy_maps: Rc<RefCell<Vec<CaddyMapConfig>>>,
        hooks: &[ResponseHook],
        status: u16,
        headers: &mut ::http::HeaderMap,
    ) -> RawResponseHookOutcome {
        if hooks.is_empty() {
            return RawResponseHookOutcome {
                status,
                continue_request: false,
            };
        }

        let timeslice = default_timeslice();
        let scripts = (*self.scripts.borrow()).clone();
        let response_hooks: Rc<RefCell<Vec<ResponseHook>>> = Rc::new(RefCell::new(Vec::new()));
        let response_context = Rc::new(RefCell::new(ResponseContext {
            status,
            headers: headers.clone(),
            original_headers: headers.clone(),
            continue_request: false,
        }));
        let preemption = PreemptionEnabled::new(self.t);

        for hook in hooks {
            let section = format!("{}{}", SCRIPT_CALL_SECTION_PREFIX, hook.func);
            let Some((_, program)) = scripts.iter().find(|(name, _)| {
                name == &hook.script || name.strip_suffix(".o") == Some(hook.script.as_str())
            }) else {
                async_log(
                    format!(
                        "[script_runtime] response hook '{}.{}' skipped: script not found\n",
                        hook.script, hook.func
                    )
                    .into_bytes(),
                )
                .await;
                continue;
            };
            if !program.has_section(&section) {
                async_log(
                    format!(
                        "[script_runtime] response hook '{}.{}' skipped: function not found\n",
                        hook.script, hook.func
                    )
                    .into_bytes(),
                )
                .await;
                continue;
            }

            let mut ctx = ScriptExecutionContext::for_call(
                hook.input.clone(),
                request.clone(),
                BodySource::empty(),
                metadata.clone(),
                caddy_maps.clone(),
                Rc::new(RefCell::new(::http::HeaderMap::new())),
                response_hooks.clone(),
                Some(response_context.clone()),
                Rc::new(Cell::new(None)),
                hook.script.clone(),
                site.clone(),
                scripts.clone(),
                self.t,
                self.max_memory_footprint,
                self.expose_filesystem,
                0,
                self.caddy_file_cache.clone(),
            );
            let mut resources: [&mut dyn Any; 1] = [&mut ctx];
            let before_hook = response_context.borrow().clone();
            if let Err(err) = program
                .run(
                    &timeslice,
                    &MonoioTimeslicer,
                    &section,
                    &mut resources,
                    &1u64.to_le_bytes(),
                    &preemption,
                )
                .await
            {
                *response_context.borrow_mut() = before_hook;
                async_log(
                    format!(
                        "[script_runtime] response hook '{}.{}' failed: {:?} ({})\n",
                        hook.script,
                        hook.func,
                        err,
                        if ctx.error.is_empty() {
                            "no details"
                        } else {
                            ctx.error.as_str()
                        }
                    )
                    .into_bytes(),
                )
                .await;
            }
        }

        let response_context = response_context.borrow();
        *headers = response_context.headers.clone();
        let status = if (100..=999).contains(&response_context.status) {
            response_context.status
        } else {
            status
        };
        RawResponseHookOutcome {
            status,
            continue_request: response_context.continue_request,
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct ResponseHookOutcome {
    pub status: ::http::StatusCode,
    pub continue_request: bool,
}

#[derive(Clone, Debug)]
pub(crate) struct RawResponseHookOutcome {
    pub status: u16,
    pub continue_request: bool,
}

/// The default timeslice budget shared by the top-level request entrypoint and
/// `zs_call` callees: throttle after 20ms of uninterrupted CPU, yield after 1ms.
pub(crate) fn default_timeslice() -> TimesliceConfig {
    TimesliceConfig {
        max_run_time_before_throttle: Duration::from_millis(20),
        max_run_time_before_yield: Duration::from_millis(1),
        throttle_duration: Duration::from_millis(100),
    }
}

async fn run_request_scripts(
    t: ThreadEnv,
    scripts: Rc<Vec<(String, Program)>>,
    site: Arc<Site>,
    request: ScriptRequest,
    body_source: BodySource,
    timeslice: &TimesliceConfig,
    timeslicer: &impl Timeslicer,
    max_memory_footprint: u64,
    expose_filesystem: bool,
    caddy_file_cache: Rc<RefCell<HashMap<String, Vec<u8>>>>,
) -> ScriptOutcome {
    let request = Rc::new(RefCell::new(request));
    let metadata: Rc<RefCell<HashMap<String, String>>> = Rc::new(RefCell::new(HashMap::new()));
    let caddy_maps: Rc<RefCell<Vec<CaddyMapConfig>>> = Rc::new(RefCell::new(Vec::new()));
    run_request_scripts_with_state(
        t,
        scripts,
        site,
        request,
        metadata,
        caddy_maps,
        body_source,
        timeslice,
        timeslicer,
        max_memory_footprint,
        expose_filesystem,
        caddy_file_cache,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn run_request_scripts_with_state(
    t: ThreadEnv,
    scripts: Rc<Vec<(String, Program)>>,
    site: Arc<Site>,
    request: Rc<RefCell<ScriptRequest>>,
    metadata: Rc<RefCell<HashMap<String, String>>>,
    caddy_maps: Rc<RefCell<Vec<CaddyMapConfig>>>,
    body_source: BodySource,
    timeslice: &TimesliceConfig,
    timeslicer: &impl Timeslicer,
    max_memory_footprint: u64,
    expose_filesystem: bool,
    caddy_file_cache: Rc<RefCell<HashMap<String, Vec<u8>>>>,
) -> ScriptOutcome {
    if scripts.is_empty() {
        let request_value = request.borrow().clone();
        let metadata_value = metadata.borrow().clone();
        return ScriptOutcome {
            request: request_value,
            request_shared: request.clone(),
            metadata: metadata_value,
            metadata_shared: metadata.clone(),
            caddy_maps_shared: caddy_maps.clone(),
            early_response_headers: ::http::HeaderMap::new(),
            response_hooks: Vec::new(),
            abort: false,
            response: None,
            request_body_limit: None,
            reverse_proxy: None,
            caddy_reverse_proxy: false,
            caddy_default_forwarded: false,
            file_server: None,
            encode: None,
        };
    }

    // The request and metadata are shared by reference for the whole request:
    // each script (and any `zs_call` callee it spawns) holds a clone of these
    // `Rc`s, so mutations are seen by every later script and propagate out.
    let early_response_headers: Rc<RefCell<::http::HeaderMap>> =
        Rc::new(RefCell::new(::http::HeaderMap::new()));
    let response_hooks: Rc<RefCell<Vec<ResponseHook>>> = Rc::new(RefCell::new(Vec::new()));
    let request_body_limit: Rc<Cell<Option<usize>>> = Rc::new(Cell::new(None));
    let mut response: Option<ScriptResponse> = None;
    let mut reverse_proxy: Option<String> = None;
    let mut caddy_reverse_proxy = false;
    let mut caddy_default_forwarded = false;
    let mut encode: Option<crate::helpers::compress::EncodeConfig> = None;
    let preemption = PreemptionEnabled::new(t);

    'sections: for section in [SCRIPT_ENTRYPOINT] {
        for (name, program) in scripts.iter() {
            if !program.has_section(section) {
                continue;
            }

            let mut ctx = ScriptExecutionContext {
                request: request.clone(),
                body_source: body_source.clone(),
                metadata: metadata.clone(),
                caddy_maps: caddy_maps.clone(),
                early_response_headers: early_response_headers.clone(),
                response_hooks: response_hooks.clone(),
                response_context: None,
                abort: false,
                response: None,
                request_body_limit: request_body_limit.clone(),
                reverse_proxy: None,
                caddy_reverse_proxy: false,
                caddy_default_forwarded: false,
                file_server: None,
                encode: None,
                script_name: name.clone(),
                log_buffer: vec![],
                external_objects: ObjectRegistry {
                    next_idx: 1,
                    objects: HashMap::new(),
                },
                error: String::new(),
                memory_footprint_bytes: 0,
                max_memory_footprint,
                expose_filesystem,
                site: site.clone(),
                scripts: scripts.clone(),
                t,
                call_depth: 0,
                caddy_file_cache: caddy_file_cache.clone(),
                tls_select: None,
            };
            let mut resources: [&mut dyn Any; 1] = [&mut ctx];
            let run = program
                .run(
                    timeslice,
                    timeslicer,
                    section,
                    &mut resources,
                    &[],
                    &preemption,
                )
                .await;

            if let Err(err) = run {
                async_log(
                    format!(
                        "[script_runtime] script '{}' section '{}' failed: {:?} ({})\n",
                        name,
                        section,
                        err,
                        if ctx.error.is_empty() {
                            "no details"
                        } else {
                            ctx.error.as_str()
                        }
                    )
                    .into_bytes(),
                )
                .await;
                return ScriptOutcome {
                    request: request.borrow().clone(),
                    request_shared: request.clone(),
                    metadata: metadata.borrow().clone(),
                    metadata_shared: metadata.clone(),
                    caddy_maps_shared: caddy_maps.clone(),
                    early_response_headers: early_response_headers.borrow().clone(),
                    response_hooks: response_hooks.borrow().clone(),
                    abort: false,
                    response: Some(ScriptResponse {
                        status: 500,
                        body: vec![],
                        content_type: Some("text/plain; charset=utf-8".to_string()),
                        force_close: false,
                        headers: Vec::new(),
                    }),
                    request_body_limit: request_body_limit.get(),
                    reverse_proxy: None,
                    caddy_reverse_proxy: false,
                    caddy_default_forwarded: false,
                    file_server: None,
                    encode: None,
                };
            }
            if ctx.abort {
                return ScriptOutcome {
                    request: request.borrow().clone(),
                    request_shared: request.clone(),
                    metadata: metadata.borrow().clone(),
                    metadata_shared: metadata.clone(),
                    caddy_maps_shared: caddy_maps.clone(),
                    early_response_headers: early_response_headers.borrow().clone(),
                    response_hooks: response_hooks.borrow().clone(),
                    abort: true,
                    response,
                    request_body_limit: request_body_limit.get(),
                    reverse_proxy,
                    caddy_reverse_proxy,
                    caddy_default_forwarded,
                    file_server: None,
                    encode: None,
                };
            }
            // An `encode` handler runs before the response producer in the same
            // route entry; carry its config forward to whichever producer wins.
            if let Some(ctx_encode) = ctx.encode.take() {
                encode = Some(ctx_encode);
            }
            if let Some(script_response) = ctx.response {
                response = Some(script_response);
                break 'sections;
            }
            if let Some(proxy_url) = ctx.reverse_proxy {
                reverse_proxy = Some(proxy_url);
                caddy_reverse_proxy = ctx.caddy_reverse_proxy;
                caddy_default_forwarded = ctx.caddy_default_forwarded;
                break 'sections;
            }
            if let Some(file_server) = ctx.file_server {
                return ScriptOutcome {
                    request: request.borrow().clone(),
                    request_shared: request.clone(),
                    metadata: metadata.borrow().clone(),
                    metadata_shared: metadata.clone(),
                    caddy_maps_shared: caddy_maps.clone(),
                    early_response_headers: early_response_headers.borrow().clone(),
                    response_hooks: response_hooks.borrow().clone(),
                    abort: false,
                    response,
                    request_body_limit: request_body_limit.get(),
                    reverse_proxy,
                    caddy_reverse_proxy,
                    caddy_default_forwarded,
                    file_server: Some(file_server),
                    encode,
                };
            }
        }
    }

    ScriptOutcome {
        request: request.borrow().clone(),
        request_shared: request.clone(),
        metadata: metadata.borrow().clone(),
        metadata_shared: metadata.clone(),
        caddy_maps_shared: caddy_maps.clone(),
        early_response_headers: early_response_headers.borrow().clone(),
        response_hooks: response_hooks.borrow().clone(),
        abort: false,
        response,
        request_body_limit: request_body_limit.get(),
        reverse_proxy,
        caddy_reverse_proxy,
        caddy_default_forwarded,
        file_server: None,
        encode,
    }
}

pub fn with_ectx<R>(
    scope: &async_ebpf::program::HelperScope,
    f: impl FnOnce(&mut ScriptExecutionContext) -> Result<R, ()>,
) -> Result<R, ()> {
    scope.with_resource_mut(|res: Result<&mut ScriptExecutionContext, ()>| match res {
        Ok(ctx) => f(ctx),
        Err(_) => Err(()),
    })
}

pub fn read_utf8<'a>(
    scope: &'a async_ebpf::program::HelperScope,
    ptr: u64,
    len: u64,
) -> Result<&'a str, ()> {
    if len == 0 {
        return Ok("");
    }
    let data = scope.user_memory(ptr, len)?;
    std::str::from_utf8(&data).map_err(|_| ())
}

/// Cache key: the parsed type plus the script-side data pointer and length.
type JsonParseCacheKey = (TypeId, u64, u64);

/// Per-program cache of host-side parsed JSON, keyed by
/// `(target type, data pointer, data length)`. Stored via `Program::data`, so
/// the program identity is implicit in the map and the cache is dropped with
/// the program when a hot reload installs fresh scripts. Only pointers into
/// the program's frozen data region are cached: that memory is read-only for
/// the program's lifetime, so the raw `(ptr, len)` key uniquely identifies
/// the JSON text without comparing bytes.
#[derive(Default)]
pub(crate) struct JsonParseCache {
    entries: RefCell<HashMap<JsonParseCacheKey, Rc<dyn Any>>>,
}

/// Generous bound on distinct cached configs per program; generated Caddy
/// middleware passes well under this many static JSON arguments. Beyond it,
/// parses stay correct but uncached.
const MAX_JSON_PARSE_CACHE_ENTRIES: usize = 4096;

/// Parse JSON passed by a script, caching the parsed value when the bytes
/// live in the program's immutable data region — the common case: generated
/// middleware passes `.rodata` string literals, re-parsed on every request
/// without this cache. Writable (stack) data parses fresh on every call.
///
/// Immutability is detected with the scope's own memory validation: memory
/// that dereferences for read but not for write can only be the data region,
/// which is frozen read-only when the program is loaded. The write probe must
/// be the first dereference of `ptr` in the calling helper — an earlier read
/// of an overlapping range would fail the probe by overlap and misclassify
/// stack bytes as immutable.
pub(crate) fn parse_json_cached<T>(
    scope: &async_ebpf::program::HelperScope,
    ptr: u64,
    len: u64,
) -> Result<Rc<T>, ()>
where
    T: serde::de::DeserializeOwned + 'static,
{
    if let Ok(data) = scope.user_memory_mut(ptr, len) {
        // Writable memory is the script stack: its contents change between
        // runs, so parse without caching (the view doubles as the source).
        let text = std::str::from_utf8(&data).map_err(|_| ())?;
        return serde_json::from_str(text).map(Rc::new).map_err(|_| ());
    }

    let text = read_utf8(scope, ptr, len)?;
    let cache = scope.program.data::<JsonParseCache>();
    let key = (TypeId::of::<T>(), ptr, len);
    if let Some(hit) = cache.entries.borrow().get(&key) {
        return hit.clone().downcast::<T>().map_err(|_| ());
    }
    let parsed = Rc::new(serde_json::from_str::<T>(text).map_err(|_| ())?);
    let mut entries = cache.entries.borrow_mut();
    if entries.len() < MAX_JSON_PARSE_CACHE_ENTRIES {
        entries.insert(key, parsed.clone() as Rc<dyn Any>);
    }
    Ok(parsed)
}

pub fn deref_and_write_cstr(
    scope: &async_ebpf::program::HelperScope,
    out_ptr: u64,
    out_len: u64,
    value: &str,
) -> Result<u64, ()> {
    let mut out = scope.user_memory_mut(out_ptr, out_len)?;
    Ok(write_cstr(&[value.as_bytes()], &mut out))
}

fn write_cstr(input: &[&[u8]], output: &mut MutableUserMemory) -> u64 {
    write_cstr_snprintf(input, output).min(output.len() as u64)
}

pub(crate) struct MonoioTimeslicer;

impl Timeslicer for MonoioTimeslicer {
    fn sleep(&self, duration: Duration) -> impl Future<Output = ()> {
        monoio::time::sleep(duration)
    }

    fn yield_now(&self) -> impl Future<Output = ()> {
        let yielded = Cell::new(false);
        std::future::poll_fn(move |cx| {
            if yielded.replace(true) {
                Poll::Ready(())
            } else {
                cx.waker().wake_by_ref();
                Poll::Pending
            }
        })
    }
}

struct EventListener;

impl ProgramEventListener for EventListener {
    fn did_throttle(&self, scope: &HelperScope) -> Option<Pin<Box<dyn Future<Output = ()>>>> {
        with_ectx(scope, |ctx| {
            let msg = format!(
                "[script_runtime] {}: {}: throttling\n",
                ctx.request.borrow().request_id,
                ctx.script_name
            );
            Ok(Some(async_log(msg.into_bytes()).boxed_local()))
        })
        .unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request_with_repeated_header(values: &[&str]) -> ScriptRequest {
        let mut headers = HashMap::new();
        headers.insert("x-test".to_string(), values.join(","));
        let mut header_values = HashMap::new();
        header_values.insert(
            "x-test".to_string(),
            values.iter().map(|value| value.to_string()).collect(),
        );
        ScriptRequest {
            request_id: RequestId::new(),
            start_time: Instant::now(),
            method: "GET".to_string(),
            original_method: "GET".to_string(),
            path: "/".to_string(),
            original_path: "/".to_string(),
            normalized_path: String::new(),
            uri: "/".to_string(),
            original_uri: "/".to_string(),
            query: String::new(),
            original_query: String::new(),
            scheme: "http".to_string(),
            proto_major: 1,
            proto_minor: 1,
            peer: "127.0.0.1:12345".to_string(),
            local: "127.0.0.1:80".to_string(),
            headers,
            header_values,
            transfer_encodings: Vec::new(),
            query_params: HashMap::new(),
            query_param_values: HashMap::new(),
            caddy_query_params: HashMap::new(),
            caddy_query_valid: true,
            connection: ConnectionInfo::default(),
            proxy_method: None,
            proxy_uri: None,
            proxy_headers: None,
            uri_changed: false,
            method_changed: false,
            header_changes: Vec::new(),
        }
    }

    #[test]
    fn replace_header_preserves_repeated_values() {
        let mut request = request_with_repeated_header(&["raw-one", "raw-two"]);
        request
            .replace_header("X-Test", "raw", "cooked")
            .expect("replace succeeds");

        assert_eq!(
            request.header_values.get("x-test").unwrap(),
            &vec!["cooked-one".to_string(), "cooked-two".to_string()]
        );
        assert_eq!(
            request.headers.get("x-test").map(String::as_str),
            Some("cooked-one,cooked-two")
        );
        assert!(matches!(
            &request.header_changes[0],
            HeaderChange::Remove(name) if name == "x-test"
        ));
        assert!(matches!(
            &request.header_changes[1],
            HeaderChange::Append(name, value) if name == "x-test" && value == "cooked-one"
        ));
        assert!(matches!(
            &request.header_changes[2],
            HeaderChange::Append(name, value) if name == "x-test" && value == "cooked-two"
        ));
    }

    #[test]
    fn replace_header_regex_preserves_repeated_values() {
        let mut request = request_with_repeated_header(&["raw-one", "raw-two"]);
        let regex = regex::Regex::new("raw-(.*)").unwrap();
        request
            .replace_header_regex("X-Test", &regex, "cooked-$1")
            .expect("replace succeeds");

        assert_eq!(
            request.header_values.get("x-test").unwrap(),
            &vec!["cooked-one".to_string(), "cooked-two".to_string()]
        );
        assert!(matches!(
            &request.header_changes[0],
            HeaderChange::Remove(name) if name == "x-test"
        ));
        assert!(matches!(
            &request.header_changes[1],
            HeaderChange::Append(name, value) if name == "x-test" && value == "cooked-one"
        ));
        assert!(matches!(
            &request.header_changes[2],
            HeaderChange::Append(name, value) if name == "x-test" && value == "cooked-two"
        ));
    }

    #[test]
    fn set_uri_preserves_relative_path_request_targets() {
        let mut request = request_with_repeated_header(&[]);

        request.set_uri("leaf.txt").expect("relative URI works");
        assert_eq!(request.uri, "leaf.txt");
        assert_eq!(request.path, "leaf.txt");
        assert_eq!(request.query, "");

        request
            .set_uri("nested/leaf.txt?x=1")
            .expect("relative URI with query works");
        assert_eq!(request.uri, "nested/leaf.txt?x=1");
        assert_eq!(request.path, "nested/leaf.txt");
        assert_eq!(request.query, "x=1");

        request
            .set_uri("nested/leaf.txt?x=1#frag")
            .expect("relative URI with fragment works");
        assert_eq!(request.uri, "nested/leaf.txt?x=1");
        assert_eq!(request.path, "nested/leaf.txt");
        assert_eq!(request.query, "x=1");
    }
}
