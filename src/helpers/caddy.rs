use std::{
    collections::{BTreeMap, HashMap},
    fs,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    path::{Path, PathBuf},
    str::FromStr,
    time::UNIX_EPOCH,
};

use argon2::{Argon2, PasswordHash, PasswordVerifier};
use async_ebpf::program::HelperScope;
use base64ct::{Base64, Encoding};
use boring::{
    stack::Stack,
    x509::{
        X509, X509StoreContext,
        store::{X509Store, X509StoreBuilder},
    },
};
use regex::Regex;

use crate::caddy_file::{
    display_path as caddy_file_match_display_path, file_hidden as caddy_file_hidden,
    fs_file_hidden as caddy_fs_file_hidden, glob_match, join_file_path as join_caddy_file_path,
    path_glob_match as caddy_path_glob_match,
};
use crate::script::{
    CaddyFileServer, ScriptResponse, deref_and_write_cstr, header_pattern_matches, read_utf8,
    split_relative_request_target, with_ectx,
};

#[derive(Default, serde::Deserialize)]
struct CaddyTlsClientAuthConfig {
    mode: String,
    #[serde(default)]
    trusted_ca_certs: Vec<String>,
}

pub fn h_caddy_rewrite_method(
    scope: &HelperScope,
    method_ptr: u64,
    method_len: u64,
    _: u64,
    _: u64,
    _: u64,
) -> Result<u64, ()> {
    let method_template = read_utf8(scope, method_ptr, method_len)?;
    with_ectx(scope, |ctx| {
        let method = expand_caddy_placeholders(ctx, method_template)?.to_ascii_uppercase();
        ctx.request.borrow_mut().set_method(&method)?;
        Ok(0)
    })
}

pub fn h_caddy_tls_client_auth(
    scope: &HelperScope,
    config_ptr: u64,
    config_len: u64,
    _: u64,
    _: u64,
    _: u64,
) -> Result<u64, ()> {
    let config = read_utf8(scope, config_ptr, config_len)?;
    let config: CaddyTlsClientAuthConfig = serde_json::from_str(config).map_err(|_| ())?;
    with_ectx(scope, |ctx| {
        let request = ctx.request.borrow();
        let conn = &request.connection;
        if !conn.tls || !conn.tls_handshake_complete {
            return Ok(0);
        }
        let Some(leaf_der) = conn.tls_client_cert_der.as_ref() else {
            return Ok(if config.mode == "verify_if_given" {
                1
            } else {
                0
            });
        };
        match config.mode.as_str() {
            "request" | "require" => Ok(1),
            "verify_if_given" | "require_and_verify" => {
                let verified = verify_caddy_client_cert(
                    leaf_der,
                    &conn.tls_client_chain_der,
                    &config.trusted_ca_certs,
                )?;
                Ok(verified as u64)
            }
            _ => Err(()),
        }
    })
}

fn verify_caddy_client_cert(
    leaf_der: &[u8],
    chain_der: &[Vec<u8>],
    trusted_ca_certs: &[String],
) -> Result<bool, ()> {
    let store = caddy_client_auth_store(trusted_ca_certs)?;
    let leaf = X509::from_der(leaf_der).map_err(|_| ())?;
    let mut chain = Stack::new().map_err(|_| ())?;
    for cert_der in chain_der {
        let cert = X509::from_der(cert_der).map_err(|_| ())?;
        if cert.to_der().map_err(|_| ())? != leaf_der {
            chain.push(cert).map_err(|_| ())?;
        }
    }
    X509StoreContext::new()
        .map_err(|_| ())?
        .init(&store, &leaf, &chain, |store_ctx| {
            Ok(store_ctx.verify_cert().unwrap_or(false))
        })
        .map_err(|_| ())
}

fn caddy_client_auth_store(trusted_ca_certs: &[String]) -> Result<X509Store, ()> {
    let mut builder = X509StoreBuilder::new().map_err(|_| ())?;
    for cert in trusted_ca_certs {
        let der = Base64::decode_vec(cert).map_err(|_| ())?;
        builder
            .add_cert(X509::from_der(&der).map_err(|_| ())?)
            .map_err(|_| ())?;
    }
    Ok(builder.build())
}

pub fn h_caddy_path_regexp_subject(
    scope: &HelperScope,
    out_ptr: u64,
    out_len: u64,
    _: u64,
    _: u64,
    _: u64,
) -> Result<u64, ()> {
    with_ectx(scope, |ctx| {
        let request = ctx.request.borrow();
        let decoded = caddy_percent_decode_path(&request.path).ok_or(())?;
        let cleaned = clean_path_caddy(&decoded, true);
        deref_and_write_cstr(scope, out_ptr, out_len, &cleaned)
    })
}

pub fn h_req_rewrite_uri(
    scope: &HelperScope,
    ops_ptr: u64,
    ops_len: u64,
    _: u64,
    _: u64,
    _: u64,
) -> Result<u64, ()> {
    let ops = read_utf8(scope, ops_ptr, ops_len)?;
    let ops: CaddyUriRewriteOps = serde_json::from_str(ops).map_err(|_| ())?;
    with_ectx(scope, |ctx| {
        let mut request = ctx.request.borrow().clone();
        apply_caddy_uri_ops(ctx, &mut request, &ops)?;
        *ctx.request.borrow_mut() = request;
        Ok(0)
    })
}

pub fn h_caddy_rewrite_uri(
    scope: &HelperScope,
    uri_ptr: u64,
    uri_len: u64,
    _: u64,
    _: u64,
    _: u64,
) -> Result<u64, ()> {
    let uri_template = read_utf8(scope, uri_ptr, uri_len)?;
    with_ectx(scope, |ctx| {
        let mut request = ctx.request.borrow().clone();
        apply_caddy_uri_template(ctx, &mut request, uri_template)?;
        *ctx.request.borrow_mut() = request;
        Ok(0)
    })
}

#[derive(Default, serde::Deserialize)]
struct CaddyUriRewriteOps {
    #[serde(default)]
    strip_path_prefix: String,
    #[serde(default)]
    strip_path_suffix: String,
    #[serde(default)]
    uri_substring: Vec<CaddyUriSubstringReplacement>,
    #[serde(default)]
    path_regexp: Vec<CaddyPathRegexpReplacement>,
}

#[derive(serde::Deserialize)]
struct CaddyUriSubstringReplacement {
    #[serde(default)]
    find: String,
    #[serde(default)]
    replace: String,
    #[serde(default)]
    limit: i64,
}

#[derive(serde::Deserialize)]
struct CaddyPathRegexpReplacement {
    #[serde(default)]
    find: String,
    #[serde(default)]
    replace: String,
}

fn apply_caddy_uri_ops(
    ctx: &crate::script::ScriptExecutionContext,
    request: &mut crate::script::ScriptRequest,
    ops: &CaddyUriRewriteOps,
) -> Result<(), ()> {
    let mut path = request.path.clone();
    let mut query = request.query.clone();

    if !ops.strip_path_prefix.is_empty() {
        let mut prefix = expand_caddy_placeholders(ctx, &ops.strip_path_prefix)?;
        if !prefix.starts_with('/') {
            prefix.insert(0, '/');
        }
        let merge_slashes = !prefix.contains("//");
        path = trim_path_prefix_caddy(&clean_path_caddy(&path, merge_slashes), &prefix);
    }

    if !ops.strip_path_suffix.is_empty() {
        let suffix = expand_caddy_placeholders(ctx, &ops.strip_path_suffix)?;
        let merge_slashes = !suffix.contains("//");
        let cleaned = clean_path_caddy(&path, merge_slashes);
        path = reverse_string(&trim_path_prefix_caddy(
            &reverse_string(&cleaned),
            &reverse_string(&suffix),
        ));
    }

    for replacement in &ops.uri_substring {
        if replacement.find.is_empty() {
            continue;
        }
        let merge_slashes = !replacement.find.contains("//");
        let find = expand_caddy_placeholders(ctx, &replacement.find)?;
        let replace = expand_caddy_placeholders(ctx, &replacement.replace)?;
        path = replace_with_limit(
            &clean_path_caddy(&path, merge_slashes),
            &find,
            &replace,
            replacement.limit,
        );
        query = replace_with_limit(&query, &find, &replace, replacement.limit);
    }

    for replacement in &ops.path_regexp {
        if replacement.find.is_empty() {
            continue;
        }
        let Ok(regex) = caddy_regex(&replacement.find) else {
            continue;
        };
        let replace = expand_caddy_placeholders(ctx, &replacement.replace)?;
        path = regex.replace_all(&path, replace.as_str()).into_owned();
    }

    request.set_path(&path)?;
    request.set_query(&query)?;
    Ok(())
}

fn apply_caddy_uri_template(
    ctx: &crate::script::ScriptExecutionContext,
    request: &mut crate::script::ScriptRequest,
    uri_template: &str,
) -> Result<(), ()> {
    let (path_template, query_template) = split_caddy_rewrite_uri_template(uri_template);

    let mut new_path = None;
    let mut new_query = None;

    if let Some(path_template) = path_template {
        let path_template = escape_caddy_rewrite_path_placeholders(ctx, path_template)?;
        let expanded = expand_caddy_placeholders(ctx, &path_template)?;
        if let Some((path, injected_query)) = expanded.split_once('?') {
            new_path = Some(path.to_string());
            if query_template.is_none() || query_template.is_some_and(str::is_empty) {
                let injected_query = injected_query.replace('{', "%7B").replace('}', "%7D");
                new_query = Some(caddy_build_rewrite_query(ctx, &injected_query)?);
            }
        } else {
            new_path = Some(expanded);
        }
    }

    if let Some(query_template) = query_template
        && (!query_template.is_empty() || new_query.is_none())
    {
        new_query = Some(caddy_build_rewrite_query(ctx, query_template)?);
    }

    match (new_path, new_query) {
        (Some(path), Some(query)) => {
            let uri = if query.is_empty() {
                path
            } else {
                format!("{path}?{query}")
            };
            request.set_uri(&uri)?;
        }
        (Some(path), None) => {
            request.set_path(&path)?;
        }
        (None, Some(query)) => {
            request.set_query(&query)?;
        }
        (None, None) => {}
    }
    Ok(())
}

fn split_caddy_rewrite_uri_template(uri_template: &str) -> (Option<&str>, Option<&str>) {
    let mut path_start = None;
    let mut path_end = None;
    let mut query_start = None;
    let mut query_end = None;

    for (idx, ch) in uri_template.char_indices() {
        match ch {
            '?' if query_start.is_none() => {
                path_end = Some(idx);
                query_start = Some(idx + 1);
            }
            '#' => {
                if query_start.is_none() {
                    path_end = Some(idx);
                } else {
                    query_end = Some(idx);
                }
                break;
            }
            _ if path_start.is_none() && query_start.is_none() => {
                path_start = Some(idx);
            }
            _ => {}
        }
    }

    if path_start.is_some() && path_end.is_none() {
        path_end = Some(uri_template.len());
    }
    if query_start.is_some() && query_end.is_none() {
        query_end = Some(uri_template.len());
    }

    let path_template = path_start
        .zip(path_end)
        .and_then(|(start, end)| (start < end).then_some(&uri_template[start..end]));
    let query_template = query_start
        .zip(query_end)
        .map(|(start, end)| &uri_template[start..end]);
    (path_template, query_template)
}

fn escape_caddy_rewrite_path_placeholders(
    ctx: &crate::script::ScriptExecutionContext,
    path: &str,
) -> Result<String, ()> {
    let mut path = path.to_string();
    if path.contains("{http.request.uri.path}") {
        let escaped = ctx.request.borrow().path.clone();
        path = path.replace("{http.request.uri.path}", &escaped);
    }
    if path.contains("{http.matchers.file.relative}") {
        if let Some(relative) = resolve_caddy_placeholder_value(ctx, "http.matchers.file.relative")
        {
            let escaped = caddy_rewrite_path_file_relative_placeholder(&relative);
            path = path.replace("{http.matchers.file.relative}", &escaped);
        }
    }
    Ok(path)
}

fn caddy_rewrite_path_file_relative_placeholder(relative: &str) -> String {
    caddy_path_escape_preserving_slashes(&slash_path_with_leading(relative))
}

fn caddy_build_rewrite_query(
    ctx: &crate::script::ScriptExecutionContext,
    mut query: &str,
) -> Result<String, ()> {
    let mut out = String::new();
    let mut wrote_value = true;
    while !query.is_empty() {
        let next_eq = query.find('=');
        let next_amp = query.find('&');
        let amp_is_next = match (next_amp, next_eq) {
            (Some(amp), Some(eq)) => amp < eq,
            (Some(_), None) => true,
            _ => false,
        };
        let end = if amp_is_next {
            next_amp.unwrap()
        } else {
            next_eq.unwrap_or(query.len())
        };
        let component = &query[..end];
        let component = expand_caddy_query_component(ctx, component, wrote_value)?;

        if end < query.len() {
            query = &query[end + 1..];
        } else {
            query = "";
        }

        if wrote_value {
            if !out.is_empty() && !component.is_empty() {
                out.push('&');
            }
        } else {
            out.push('=');
        }
        out.push_str(&component);
        wrote_value = amp_is_next;
    }
    Ok(out)
}

fn expand_caddy_query_component(
    ctx: &crate::script::ScriptExecutionContext,
    input: &str,
    raw_query_placeholder: bool,
) -> Result<String, ()> {
    let mut out = String::with_capacity(input.len());
    let mut last = 0usize;
    let mut cursor = 0usize;
    while let Some(relative_start) = input[cursor..].find('{') {
        let start = cursor + relative_start;
        let after_start = start + 1;
        let Some(relative_end) = input[after_start..].find('}') else {
            break;
        };
        let end = after_start + relative_end;
        let key = &input[after_start..end];
        out.push_str(&input[last..start]);
        if raw_query_placeholder && key == "http.request.uri.query" {
            out.push_str(&ctx.request.borrow().query);
        } else if let Some(value) = resolve_caddy_placeholder_value(ctx, key) {
            out.push_str(&caddy_query_escape(&value));
        }
        last = end + 1;
        cursor = end + 1;
    }
    out.push_str(&input[last..]);
    Ok(out)
}

fn replace_with_limit(value: &str, find: &str, replace: &str, limit: i64) -> String {
    if find.is_empty() {
        let limit = if limit <= 0 { -1 } else { limit };
        if replace.is_empty() {
            return value.to_string();
        }
        let mut out = String::with_capacity(value.len() + replace.len());
        let mut replacements = 0i64;
        out.push_str(replace);
        replacements += 1;
        for ch in value.chars() {
            out.push(ch);
            if limit < 0 || replacements < limit {
                out.push_str(replace);
                replacements += 1;
            }
        }
        return out;
    }
    if limit <= 0 {
        value.replace(find, replace)
    } else {
        value.replacen(find, replace, limit as usize)
    }
}

fn trim_path_prefix_caddy(path: &str, prefix: &str) -> String {
    let path_bytes = path.as_bytes();
    let mut path_idx = 0usize;
    for prefix_ch in prefix.chars() {
        if path_idx >= path.len() {
            return path.to_string();
        };
        let mut path_ch = path[path_idx..].chars().next().unwrap();
        let mut path_ch_len = path_ch.len_utf8();
        if path_bytes[path_idx] == b'%' && prefix_ch != '%' && path_idx + 2 < path.len() {
            let Some(decoded) = caddy_percent_decode_triplet(&path_bytes[path_idx..path_idx + 3])
            else {
                return path.to_string();
            };
            path_ch = decoded as char;
            path_ch_len = 3;
        }
        if !path_ch.eq_ignore_ascii_case(&prefix_ch) {
            return path.to_string();
        }
        path_idx += path_ch_len;
    }
    path[path_idx..].to_string()
}

fn reverse_string(value: &str) -> String {
    value.chars().rev().collect()
}

fn clean_path_caddy(path: &str, collapse_slashes: bool) -> String {
    if !collapse_slashes {
        return clean_path_preserving_double_slashes(path);
    }
    clean_path_preserve_trailing(path)
}

fn clean_path_preserving_double_slashes(path: &str) -> String {
    const TMP: char = '\u{10ffff}';
    let mut expanded = String::with_capacity(path.len());
    let mut previous_slash = false;
    for ch in path.chars() {
        if ch == '/' && previous_slash {
            expanded.push(TMP);
        }
        expanded.push(ch);
        previous_slash = ch == '/';
    }
    clean_path_preserve_trailing(&expanded).replace(TMP, "")
}

fn clean_path_preserve_trailing(path: &str) -> String {
    let trailing_slash = path.ends_with('/');
    let absolute = path.starts_with('/');
    let mut parts = Vec::new();
    for part in path.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            other => parts.push(other),
        }
    }
    let mut out = String::new();
    if absolute {
        out.push('/');
    }
    out.push_str(&parts.join("/"));
    if out.is_empty() {
        out.push('.');
    }
    if absolute && out == "." {
        out = "/".to_string();
    }
    if out != "/" && trailing_slash {
        out.push('/');
    }
    out
}

pub fn h_req_rewrite_query(
    scope: &HelperScope,
    ops_ptr: u64,
    ops_len: u64,
    _: u64,
    _: u64,
    _: u64,
) -> Result<u64, ()> {
    let ops = read_utf8(scope, ops_ptr, ops_len)?;
    let ops: CaddyQueryOps = serde_json::from_str(ops).map_err(|_| ())?;
    with_ectx(scope, |ctx| {
        let mut request = ctx.request.borrow().clone();
        apply_caddy_query_ops(ctx, &mut request, &ops)?;
        ctx.request.borrow_mut().set_query(&request.query)?;
        Ok(0)
    })
}

fn apply_caddy_query_ops(
    ctx: &crate::script::ScriptExecutionContext,
    request: &mut crate::script::ScriptRequest,
    ops: &CaddyQueryOps,
) -> Result<(), ()> {
    apply_caddy_query_ops_with_expanders(
        request,
        ops,
        |value| expand_caddy_placeholders(ctx, value),
        |value| expand_known_caddy_placeholders(ctx, value),
    )
}

fn apply_caddy_query_ops_with_expanders(
    request: &mut crate::script::ScriptRequest,
    ops: &CaddyQueryOps,
    expand_all: impl Fn(&str) -> Result<String, ()>,
    expand_known: impl Fn(&str) -> Result<String, ()>,
) -> Result<(), ()> {
    let query = rewrite_caddy_query_with_expanders(&request.query, ops, expand_all, expand_known)?;
    request.set_query(&query)?;
    Ok(())
}

fn rewrite_caddy_query_with_expanders(
    query: &str,
    ops: &CaddyQueryOps,
    expand_all: impl Fn(&str) -> Result<String, ()>,
    expand_known: impl Fn(&str) -> Result<String, ()>,
) -> Result<String, ()> {
    let mut values: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for (key, value) in url::form_urlencoded::parse(query.as_bytes()) {
        values
            .entry(key.into_owned())
            .or_default()
            .push(value.into_owned());
    }

    for op in &ops.rename {
        let key = expand_all(&op.key)?;
        let val = expand_all(&op.val)?;
        if key.is_empty() || val.is_empty() || key == val {
            continue;
        }
        let Some(original) = values.remove(&key) else {
            continue;
        };
        values.insert(val, original);
    }

    for op in &ops.set {
        let key = expand_all(&op.key)?;
        if key.is_empty() {
            continue;
        }
        let val = expand_all(&op.val)?;
        values.insert(key, vec![val]);
    }

    for op in &ops.add {
        let key = expand_all(&op.key)?;
        if key.is_empty() {
            continue;
        }
        let val = expand_all(&op.val)?;
        values.entry(key).or_default().push(val);
    }

    for replacement in &ops.replace {
        let _key = expand_all(&replacement.key)?;
        let search = expand_known(&replacement.search)?;
        let replace = expand_known(&replacement.replace)?;
        let regex = if replacement.search_regexp.is_empty() {
            None
        } else {
            Some(caddy_regex(&replacement.search_regexp).map_err(|_| ())?)
        };
        for vals in values.values_mut() {
            for value in vals {
                *value = replace_caddy_query_value(value, &search, &replace, regex.as_ref());
            }
        }
    }

    for key in &ops.delete {
        let key = expand_all(key)?;
        if !key.is_empty() {
            values.remove(&key);
        }
    }

    let mut serializer = url::form_urlencoded::Serializer::new(String::new());
    for (key, vals) in values {
        for value in vals {
            serializer.append_pair(&key, &value);
        }
    }
    Ok(serializer.finish())
}

fn replace_caddy_query_value(
    value: &str,
    search: &str,
    replace: &str,
    regex: Option<&Regex>,
) -> String {
    if let Some(regex) = regex {
        regex.replace_all(value, replace).into_owned()
    } else {
        value.replace(search, replace)
    }
}

#[derive(Default, serde::Deserialize)]
struct CaddyQueryOps {
    #[serde(default)]
    rename: Vec<CaddyQueryOp>,
    #[serde(default)]
    set: Vec<CaddyQueryOp>,
    #[serde(default)]
    add: Vec<CaddyQueryOp>,
    #[serde(default)]
    replace: Vec<CaddyQueryReplacement>,
    #[serde(default)]
    delete: Vec<String>,
}

#[derive(serde::Deserialize)]
struct CaddyQueryOp {
    #[serde(default)]
    key: String,
    #[serde(default)]
    val: String,
}

#[derive(serde::Deserialize)]
struct CaddyQueryReplacement {
    #[serde(default)]
    key: String,
    #[serde(default)]
    search: String,
    #[serde(default)]
    search_regexp: String,
    #[serde(default)]
    replace: String,
}

pub fn h_req_remote_ip_matches(
    scope: &HelperScope,
    ranges_ptr: u64,
    ranges_len: u64,
    _: u64,
    _: u64,
    _: u64,
) -> Result<u64, ()> {
    let ranges = read_utf8(scope, ranges_ptr, ranges_len)?;
    let ranges: Vec<String> = serde_json::from_str(ranges).map_err(|_| ())?;
    with_ectx(scope, |ctx| {
        let peer = ctx.request.borrow().peer.clone();
        let (peer_ip, peer_zone) = parse_caddy_ip_zone(&peer).ok_or(())?;
        for range in &ranges {
            if caddy_ip_range_matches(peer_ip, &peer_zone, range)? {
                return Ok(1);
            }
        }
        Ok(0)
    })
}

pub fn h_caddy_remote_ip_matches(
    scope: &HelperScope,
    ranges_ptr: u64,
    ranges_len: u64,
    _: u64,
    _: u64,
    _: u64,
) -> Result<u64, ()> {
    let ranges = read_utf8(scope, ranges_ptr, ranges_len)?;
    let ranges: Vec<String> = serde_json::from_str(ranges).map_err(|_| ())?;
    with_ectx(scope, |ctx| {
        let peer = ctx.request.borrow().peer.clone();
        let (peer_ip, peer_zone) = parse_caddy_ip_zone(&peer).ok_or(())?;
        for range in &ranges {
            let range = expand_caddy_placeholders(ctx, range)?;
            if caddy_ip_range_matches(peer_ip, &peer_zone, &range).unwrap_or(false) {
                return Ok(1);
            }
        }
        Ok(0)
    })
}

#[derive(Debug, Default, serde::Deserialize)]
struct CaddyClientIpMatchConfig {
    #[serde(default)]
    ranges: Vec<String>,
    #[serde(default)]
    trusted_ranges: Vec<String>,
    #[serde(default)]
    headers: Vec<String>,
    #[serde(default)]
    strict: bool,
    #[serde(default)]
    trusted_unix: bool,
}

#[derive(Debug, Default, serde::Deserialize)]
struct CaddyReverseProxyForwardedConfig {
    #[serde(default)]
    trusted_proxies: Vec<String>,
    #[serde(default)]
    server_trusted_proxies: Vec<String>,
    #[serde(default)]
    server_trusted_unix: bool,
}

pub fn h_caddy_client_ip_matches(
    scope: &HelperScope,
    config_ptr: u64,
    config_len: u64,
    _: u64,
    _: u64,
    _: u64,
) -> Result<u64, ()> {
    let config = read_utf8(scope, config_ptr, config_len)?;
    let config: CaddyClientIpMatchConfig = serde_json::from_str(config).map_err(|_| ())?;
    with_ectx(scope, |ctx| {
        let client_ip = {
            let request = ctx.request.borrow();
            caddy_resolved_client_ip(&request.peer, &request.header_values, &config)?
        };
        let (client_ip, client_zone) = parse_caddy_ip_zone(&client_ip).ok_or(())?;
        for range in &config.ranges {
            let range = expand_caddy_placeholders(ctx, range)?;
            if caddy_ip_range_matches(client_ip, &client_zone, &range).unwrap_or(false) {
                return Ok(1);
            }
        }
        Ok(0)
    })
}

fn caddy_resolved_client_ip(
    peer: &str,
    headers: &HashMap<String, Vec<String>>,
    config: &CaddyClientIpMatchConfig,
) -> Result<String, ()> {
    if peer == "@" {
        if !config.trusted_unix {
            return Ok(String::new());
        }
        if config.strict {
            return Ok(caddy_strict_untrusted_client_ip(
                headers,
                &config.headers,
                &config.trusted_ranges,
                "@",
            ));
        }
        return Ok(caddy_trusted_real_client_ip(headers, &config.headers, "@"));
    }

    let (peer_ip, _) = parse_caddy_ip_zone(peer).ok_or(())?;
    let peer = peer_ip.to_string();
    if config.trusted_ranges.is_empty() {
        return Ok(peer);
    }
    let trusted = config
        .trusted_ranges
        .iter()
        .any(|range| caddy_ip_range_matches(peer_ip, "", range).unwrap_or(false));
    if !trusted {
        return Ok(peer);
    }
    if config.strict {
        Ok(caddy_strict_untrusted_client_ip(
            headers,
            &config.headers,
            &config.trusted_ranges,
            &peer,
        ))
    } else {
        Ok(caddy_trusted_real_client_ip(
            headers,
            &config.headers,
            &peer,
        ))
    }
}

fn caddy_trusted_real_client_ip(
    headers: &HashMap<String, Vec<String>>,
    names: &[String],
    fallback: &str,
) -> String {
    for part in caddy_client_ip_header_parts(headers, names) {
        if let Some(ip) = caddy_header_ip_part(&part) {
            return ip;
        }
    }
    fallback.to_string()
}

fn caddy_strict_untrusted_client_ip(
    headers: &HashMap<String, Vec<String>>,
    names: &[String],
    trusted_ranges: &[String],
    fallback: &str,
) -> String {
    for name in names {
        let values = headers
            .get(&name.to_ascii_lowercase())
            .cloned()
            .unwrap_or_default();
        let joined = values.join(",");
        for part in joined.split(',').rev() {
            let Some(ip) = caddy_header_ip_part(part) else {
                continue;
            };
            let Some((parsed, _)) = parse_caddy_ip_zone(&ip) else {
                continue;
            };
            let trusted = trusted_ranges
                .iter()
                .any(|range| caddy_ip_range_matches(parsed, "", range).unwrap_or(false));
            if !trusted {
                return parsed.to_string();
            }
        }
    }
    fallback.to_string()
}

pub fn h_caddy_reverse_proxy_forwarded(
    scope: &HelperScope,
    config_ptr: u64,
    config_len: u64,
    _: u64,
    _: u64,
    _: u64,
) -> Result<u64, ()> {
    let config = read_utf8(scope, config_ptr, config_len)?;
    let config: CaddyReverseProxyForwardedConfig = serde_json::from_str(config).map_err(|_| ())?;
    with_ectx(scope, |ctx| {
        let mut headers = caddy_proxy_headers(ctx);
        let host = caddy_header_map_last_value(&headers, "host").unwrap_or_default();
        let request = ctx.request.borrow();
        let scheme = request.scheme.clone();
        let (client_ip, trusted) = caddy_reverse_proxy_client_ip_and_trust(
            &request.peer,
            &config.trusted_proxies,
            &config.server_trusted_proxies,
            config.server_trusted_unix,
        );
        drop(request);

        let (xff_prior, xff_ok) = caddy_header_map_all_values(&headers, "X-Forwarded-For");
        if trusted && xff_ok && !xff_prior.is_empty() {
            let value = if client_ip.is_empty() {
                xff_prior
            } else {
                format!("{xff_prior}, {client_ip}")
            };
            caddy_header_map_set(&mut headers, "X-Forwarded-For", &value)?;
        } else if !client_ip.is_empty() {
            caddy_header_map_set(&mut headers, "X-Forwarded-For", &client_ip)?;
        } else {
            caddy_header_map_remove(&mut headers, "X-Forwarded-For");
        }

        let (xfp_prior, xfp_ok) =
            caddy_header_map_last_value_with_ok(&headers, "X-Forwarded-Proto");
        let proto = if trusted && xfp_ok && !xfp_prior.is_empty() {
            xfp_prior
        } else {
            scheme
        };
        caddy_header_map_set(&mut headers, "X-Forwarded-Proto", &proto)?;

        let (xfh_prior, xfh_ok) = caddy_header_map_last_value_with_ok(&headers, "X-Forwarded-Host");
        let forwarded_host = if trusted && xfh_ok && !xfh_prior.is_empty() {
            xfh_prior
        } else {
            host
        };
        caddy_header_map_set(&mut headers, "X-Forwarded-Host", &forwarded_host)?;
        ctx.request.borrow_mut().set_proxy_headers(headers);
        Ok(0)
    })
}

pub fn h_caddy_reverse_proxy_request_headers(
    scope: &HelperScope,
    ops_ptr: u64,
    ops_len: u64,
    _: u64,
    _: u64,
    _: u64,
) -> Result<u64, ()> {
    let ops = read_utf8(scope, ops_ptr, ops_len)?;
    let ops: serde_json::Value = serde_json::from_str(ops).map_err(|_| ())?;
    with_ectx(scope, |ctx| {
        let mut headers = caddy_proxy_headers(ctx);
        apply_caddy_header_ops_value(ctx, &mut headers, &ops)?;
        ctx.request.borrow_mut().set_proxy_headers(headers);
        Ok(0)
    })
}

fn caddy_proxy_headers(ctx: &crate::script::ScriptExecutionContext) -> ::http::HeaderMap {
    let request = ctx.request.borrow();
    if let Some(headers) = request.proxy_headers() {
        return headers.clone();
    }
    let mut headers = ::http::HeaderMap::new();
    for (name, values) in &request.header_values {
        let Ok(header_name) = ::http::header::HeaderName::from_bytes(name.as_bytes()) else {
            continue;
        };
        for value in values {
            let Ok(header_value) = ::http::header::HeaderValue::from_str(value) else {
                continue;
            };
            headers.append(header_name.clone(), header_value);
        }
    }
    headers
}

fn caddy_header_map_set(
    headers: &mut ::http::HeaderMap,
    name: &str,
    value: &str,
) -> Result<(), ()> {
    let header_name = ::http::header::HeaderName::from_bytes(name.as_bytes()).map_err(|_| ())?;
    let header_value = ::http::header::HeaderValue::from_str(value).map_err(|_| ())?;
    headers.insert(header_name, header_value);
    Ok(())
}

fn caddy_header_map_remove(headers: &mut ::http::HeaderMap, name: &str) {
    if let Ok(header_name) = ::http::header::HeaderName::from_bytes(name.as_bytes()) {
        headers.remove(header_name);
    }
}

fn caddy_header_map_all_values(headers: &::http::HeaderMap, name: &str) -> (String, bool) {
    let Ok(header_name) = ::http::header::HeaderName::from_bytes(name.as_bytes()) else {
        return (String::new(), false);
    };
    if !headers.contains_key(&header_name) {
        return (String::new(), false);
    }
    let mut values = Vec::new();
    for value in headers.get_all(header_name) {
        let Ok(value) = value.to_str() else {
            return (String::new(), false);
        };
        values.push(value);
    }
    (values.join(", "), true)
}

fn caddy_header_map_last_value(headers: &::http::HeaderMap, name: &str) -> Option<String> {
    let Ok(header_name) = ::http::header::HeaderName::from_bytes(name.as_bytes()) else {
        return None;
    };
    let mut last = None;
    for value in headers.get_all(header_name) {
        let Ok(value) = value.to_str() else {
            return None;
        };
        last = Some(value.to_string());
    }
    last
}

fn caddy_header_map_last_value_with_ok(headers: &::http::HeaderMap, name: &str) -> (String, bool) {
    match caddy_header_map_last_value(headers, name) {
        Some(value) => (value, true),
        None => (String::new(), false),
    }
}

fn caddy_reverse_proxy_client_ip_and_trust(
    peer: &str,
    handler_ranges: &[String],
    server_ranges: &[String],
    server_trusted_unix: bool,
) -> (String, bool) {
    if peer == "@" {
        return (String::new(), server_trusted_unix);
    }
    let Some((peer_ip, _)) = parse_caddy_ip_zone(peer) else {
        return (String::new(), false);
    };
    let trusted = handler_ranges
        .iter()
        .chain(server_ranges)
        .any(|range| caddy_ip_range_matches(peer_ip, "", range).unwrap_or(false));
    (peer_ip.to_string(), trusted)
}

fn caddy_client_ip_header_parts(
    headers: &HashMap<String, Vec<String>>,
    names: &[String],
) -> Vec<String> {
    let mut values = Vec::new();
    for name in names {
        if let Some(header_values) = headers.get(&name.to_ascii_lowercase()) {
            values.extend(header_values.iter().cloned());
        }
    }
    values
        .join(",")
        .split(',')
        .map(str::to_string)
        .collect::<Vec<_>>()
}

fn caddy_header_ip_part(part: &str) -> Option<String> {
    let part = part.trim();
    let host = SocketAddr::from_str(part)
        .map(|addr| addr.ip().to_string())
        .unwrap_or_else(|_| part.to_string());
    let (host, _) = host.split_once('%').unwrap_or((&host, ""));
    let ip = host.trim().parse::<IpAddr>().ok()?;
    Some(ip.to_string())
}

fn parse_caddy_ip_zone(value: &str) -> Option<(IpAddr, String)> {
    let ip = if let Ok(addr) = SocketAddr::from_str(value) {
        addr.ip().to_string()
    } else {
        value.to_string()
    };
    let (ip, zone) = ip
        .split_once('%')
        .map(|(ip, zone)| (ip.to_string(), zone.to_string()))
        .unwrap_or_else(|| (ip, String::new()));
    Some((ip.parse().ok()?, zone))
}

fn caddy_ip_range_matches(peer_ip: IpAddr, peer_zone: &str, range: &str) -> Result<bool, ()> {
    let (range, zone) = range
        .split_once('%')
        .map(|(range, zone)| (range, zone))
        .unwrap_or((range, ""));
    if !zone.is_empty() && zone != peer_zone {
        return Ok(false);
    }
    if let Some((addr, prefix_len)) = range.split_once('/') {
        let addr = addr.parse::<IpAddr>().map_err(|_| ())?;
        let prefix_len = prefix_len.parse::<u8>().map_err(|_| ())?;
        return Ok(ip_prefix_contains(addr, prefix_len, peer_ip));
    }
    let addr = range.parse::<IpAddr>().map_err(|_| ())?;
    Ok(addr == peer_ip)
}

pub fn h_caddy_vars_set(
    scope: &HelperScope,
    vars_ptr: u64,
    vars_len: u64,
    _: u64,
    _: u64,
    _: u64,
) -> Result<u64, ()> {
    let vars = read_utf8(scope, vars_ptr, vars_len)?;
    let vars: BTreeMap<String, serde_json::Value> = serde_json::from_str(vars).map_err(|_| ())?;
    with_ectx(scope, |ctx| {
        let mut expanded_vars = Vec::new();
        for (key, value) in vars {
            let key = expand_caddy_placeholders(ctx, &key)?;
            let value = match value {
                serde_json::Value::String(value) => expand_caddy_placeholders(ctx, &value)?,
                other => caddy_var_value_to_string(&other),
            };
            expanded_vars.push((key, value));
        }
        let allocated = expanded_vars
            .iter()
            .map(|(key, value)| {
                u64::try_from("http.vars.".len() + key.len() + value.len()).unwrap_or(u64::MAX)
                    + if key == "http.auth.user.id" {
                        u64::try_from(key.len() + value.len()).unwrap_or(u64::MAX)
                    } else {
                        0
                    }
            })
            .fold(0u64, u64::saturating_add);
        ctx.alloc_memory_footprint(allocated)?;
        let mut metadata = ctx.metadata.borrow_mut();
        for (key, value) in expanded_vars {
            metadata.insert(format!("http.vars.{key}"), value.clone());
            if key == "http.auth.user.id" {
                metadata.insert(key, value);
            }
        }
        Ok(0)
    })
}

pub fn h_caddy_vars_match(
    scope: &HelperScope,
    vars_ptr: u64,
    vars_len: u64,
    _: u64,
    _: u64,
    _: u64,
) -> Result<u64, ()> {
    let vars = read_utf8(scope, vars_ptr, vars_len)?;
    let vars: BTreeMap<String, Vec<String>> = serde_json::from_str(vars).map_err(|_| ())?;
    if vars.is_empty() {
        return Ok(1);
    }
    with_ectx(scope, |ctx| caddy_vars_match(ctx, vars, false))
}

pub fn h_caddy_vars_match_expanded_keys(
    scope: &HelperScope,
    vars_ptr: u64,
    vars_len: u64,
    _: u64,
    _: u64,
    _: u64,
) -> Result<u64, ()> {
    let vars = read_utf8(scope, vars_ptr, vars_len)?;
    let vars: BTreeMap<String, Vec<String>> = serde_json::from_str(vars).map_err(|_| ())?;
    if vars.is_empty() {
        return Ok(1);
    }
    with_ectx(scope, |ctx| caddy_vars_match(ctx, vars, true))
}

fn caddy_vars_match(
    ctx: &mut crate::script::ScriptExecutionContext,
    vars: BTreeMap<String, Vec<String>>,
    expand_keys: bool,
) -> Result<u64, ()> {
    for (key, values) in vars {
        let key = if expand_keys {
            expand_caddy_placeholders(ctx, &key)?
        } else {
            key
        };
        let actual = caddy_vars_value(ctx, &key);
        for value in values {
            let value = expand_caddy_placeholders(ctx, &value)?;
            if value == actual {
                return Ok(1);
            }
        }
    }
    Ok(0)
}

pub fn h_caddy_vars_regexp_match(
    scope: &HelperScope,
    vars_ptr: u64,
    vars_len: u64,
    _: u64,
    _: u64,
    _: u64,
) -> Result<u64, ()> {
    let vars = read_utf8(scope, vars_ptr, vars_len)?;
    let vars: BTreeMap<String, CaddyRegexMatch> = serde_json::from_str(vars).map_err(|_| ())?;
    with_ectx(scope, |ctx| caddy_vars_regexp_match(ctx, vars, false))
}

pub fn h_caddy_vars_regexp_match_expanded_keys(
    scope: &HelperScope,
    vars_ptr: u64,
    vars_len: u64,
    _: u64,
    _: u64,
    _: u64,
) -> Result<u64, ()> {
    let vars = read_utf8(scope, vars_ptr, vars_len)?;
    let vars: BTreeMap<String, CaddyRegexMatch> = serde_json::from_str(vars).map_err(|_| ())?;
    with_ectx(scope, |ctx| caddy_vars_regexp_match(ctx, vars, true))
}

fn caddy_vars_regexp_match(
    ctx: &mut crate::script::ScriptExecutionContext,
    vars: BTreeMap<String, CaddyRegexMatch>,
    expand_keys: bool,
) -> Result<u64, ()> {
    for (key, config) in vars {
        let key = if expand_keys {
            expand_caddy_placeholders(ctx, &key)?
        } else {
            key
        };
        let value = caddy_vars_value(ctx, &key);
        if caddy_regex_match_and_store(ctx, &value, &config)? {
            return Ok(1);
        }
    }
    Ok(0)
}

fn caddy_vars_value(ctx: &crate::script::ScriptExecutionContext, key: &str) -> String {
    if let Some(key) = caddy_placeholder_key(key) {
        resolve_caddy_placeholder(ctx, key)
    } else {
        ctx.metadata
            .borrow()
            .get(&format!("http.vars.{key}"))
            .cloned()
            .unwrap_or_default()
    }
}

fn caddy_placeholder_key(key: &str) -> Option<&str> {
    (key.starts_with('{') && key.ends_with('}') && key.matches('{').count() == 1)
        .then(|| key.trim_matches(|ch| ch == '{' || ch == '}'))
}

pub fn h_caddy_map(
    scope: &HelperScope,
    config_ptr: u64,
    config_len: u64,
    _: u64,
    _: u64,
    _: u64,
) -> Result<u64, ()> {
    let config = read_utf8(scope, config_ptr, config_len)?;
    let mut config: crate::script::CaddyMapConfig = serde_json::from_str(config).map_err(|_| ())?;
    normalize_caddy_map_config(&mut config)?;
    with_ectx(scope, |ctx| {
        ctx.caddy_maps.borrow_mut().push(config);
        Ok(0)
    })
}

fn normalize_caddy_map_config(config: &mut crate::script::CaddyMapConfig) -> Result<(), ()> {
    for dest in &mut config.destinations {
        if !dest.starts_with('{') || dest.matches('{').count() != 1 {
            return Err(());
        }
        *dest = dest.trim_matches(|ch| ch == '{' || ch == '}').to_string();
    }
    if !config.defaults.is_empty() && config.defaults.len() != config.destinations.len() {
        return Err(());
    }
    let mut seen = std::collections::HashSet::new();
    for mapping in &config.mappings {
        if !mapping.input.is_empty() && !mapping.input_regexp.is_empty() {
            return Err(());
        }
        if mapping.outputs.len() != config.destinations.len() {
            return Err(());
        }
        let input = if mapping.input_regexp.is_empty() {
            &mapping.input
        } else {
            caddy_regex(&mapping.input_regexp).map_err(|_| ())?;
            &mapping.input_regexp
        };
        if !seen.insert(input.clone()) {
            return Err(());
        }
    }
    Ok(())
}

pub fn h_caddy_path_match(
    scope: &HelperScope,
    pattern_ptr: u64,
    pattern_len: u64,
    _: u64,
    _: u64,
    _: u64,
) -> Result<u64, ()> {
    let pattern = read_utf8(scope, pattern_ptr, pattern_len)?;
    with_ectx(scope, |ctx| {
        let pattern = expand_caddy_placeholders(ctx, &pattern.to_ascii_lowercase())?;
        let encoded_path = ctx.request.borrow().path.to_ascii_lowercase();
        Ok(caddy_match_path(&encoded_path, &pattern)? as u64)
    })
}

pub fn h_caddy_query_match(
    scope: &HelperScope,
    name_ptr: u64,
    name_len: u64,
    value_ptr: u64,
    value_len: u64,
    _: u64,
) -> Result<u64, ()> {
    let name_template = read_utf8(scope, name_ptr, name_len)?;
    let value_template = read_utf8(scope, value_ptr, value_len)?;
    with_ectx(scope, |ctx| {
        let name = expand_caddy_placeholders(ctx, name_template)?;
        let value = expand_caddy_placeholders(ctx, value_template)?;
        let request = ctx.request.borrow();
        if !request.caddy_query_valid {
            return Ok(0);
        }
        Ok(request.caddy_query_params.get(&name).is_some_and(|values| {
            value == "*" || values.iter().any(|candidate| candidate == &value)
        }) as u64)
    })
}

pub fn h_caddy_query_present(
    scope: &HelperScope,
    name_ptr: u64,
    name_len: u64,
    _: u64,
    _: u64,
    _: u64,
) -> Result<u64, ()> {
    let name_template = read_utf8(scope, name_ptr, name_len)?;
    with_ectx(scope, |ctx| {
        let name = expand_caddy_placeholders(ctx, name_template)?;
        let request = ctx.request.borrow();
        if !request.caddy_query_valid {
            return Ok(0);
        }
        Ok(request.caddy_query_params.contains_key(&name) as u64)
    })
}

pub fn h_caddy_query_empty(
    scope: &HelperScope,
    _: u64,
    _: u64,
    _: u64,
    _: u64,
    _: u64,
) -> Result<u64, ()> {
    with_ectx(scope, |ctx| {
        let request = ctx.request.borrow();
        Ok(request.caddy_query_params.is_empty() as u64)
    })
}

pub fn h_caddy_header_match(
    scope: &HelperScope,
    name_ptr: u64,
    name_len: u64,
    value_ptr: u64,
    value_len: u64,
    _: u64,
) -> Result<u64, ()> {
    let name = read_utf8(scope, name_ptr, name_len)?;
    let value_template = read_utf8(scope, value_ptr, value_len)?;
    with_ectx(scope, |ctx| {
        let allowed = expand_caddy_placeholders(ctx, value_template)?;
        let values = caddy_request_header_values(ctx, &name);
        Ok(values
            .iter()
            .any(|actual| caddy_header_value_match(actual, &allowed)) as u64)
    })
}

pub fn h_caddy_header_match_expanded(
    scope: &HelperScope,
    name_ptr: u64,
    name_len: u64,
    value_ptr: u64,
    value_len: u64,
    _: u64,
) -> Result<u64, ()> {
    let name_template = read_utf8(scope, name_ptr, name_len)?;
    let value_template = read_utf8(scope, value_ptr, value_len)?;
    with_ectx(scope, |ctx| {
        let name = expand_caddy_placeholders(ctx, name_template)?;
        let allowed = expand_caddy_placeholders(ctx, value_template)?;
        let values = caddy_request_header_values(ctx, &name);
        Ok(values
            .iter()
            .any(|actual| caddy_header_value_match(actual, &allowed)) as u64)
    })
}

pub fn h_caddy_header_present(
    scope: &HelperScope,
    name_ptr: u64,
    name_len: u64,
    _: u64,
    _: u64,
    _: u64,
) -> Result<u64, ()> {
    let name = read_utf8(scope, name_ptr, name_len)?;
    with_ectx(scope, |ctx| {
        Ok(!caddy_request_header_values(ctx, &name).is_empty() as u64)
    })
}

pub fn h_caddy_header_present_expanded(
    scope: &HelperScope,
    name_ptr: u64,
    name_len: u64,
    _: u64,
    _: u64,
    _: u64,
) -> Result<u64, ()> {
    let name_template = read_utf8(scope, name_ptr, name_len)?;
    with_ectx(scope, |ctx| {
        let name = expand_caddy_placeholders(ctx, name_template)?;
        Ok(!caddy_request_header_values(ctx, &name).is_empty() as u64)
    })
}

pub fn h_caddy_header_regexp_match(
    scope: &HelperScope,
    name_ptr: u64,
    name_len: u64,
    config_ptr: u64,
    config_len: u64,
    _: u64,
) -> Result<u64, ()> {
    let name = read_utf8(scope, name_ptr, name_len)?;
    let config = read_utf8(scope, config_ptr, config_len)?;
    let config: CaddyRegexMatch = serde_json::from_str(config).map_err(|_| ())?;
    with_ectx(scope, |ctx| {
        let values = caddy_request_header_values(ctx, &name);
        for value in values {
            if caddy_regex_match_and_store(ctx, &value, &config)? {
                return Ok(1);
            }
        }
        Ok(0)
    })
}

pub fn h_caddy_header_regexp_match_expanded(
    scope: &HelperScope,
    name_ptr: u64,
    name_len: u64,
    config_ptr: u64,
    config_len: u64,
    _: u64,
) -> Result<u64, ()> {
    let name_template = read_utf8(scope, name_ptr, name_len)?;
    let config = read_utf8(scope, config_ptr, config_len)?;
    let config: CaddyRegexMatch = serde_json::from_str(config).map_err(|_| ())?;
    with_ectx(scope, |ctx| {
        let name = expand_caddy_placeholders(ctx, name_template)?;
        let values = caddy_request_header_values(ctx, &name);
        for value in values {
            if caddy_regex_match_and_store(ctx, &value, &config)? {
                return Ok(1);
            }
        }
        Ok(0)
    })
}

pub fn h_caddy_req_header_first_prefix(
    scope: &HelperScope,
    name_ptr: u64,
    name_len: u64,
    prefix_ptr: u64,
    prefix_len: u64,
    _: u64,
) -> Result<u64, ()> {
    let name = read_utf8(scope, name_ptr, name_len)?;
    let prefix = read_utf8(scope, prefix_ptr, prefix_len)?;
    with_ectx(scope, |ctx| {
        let name = name.to_ascii_lowercase();
        let request = ctx.request.borrow();
        let Some(first) = request
            .header_values
            .get(&name)
            .and_then(|values| values.first())
        else {
            return Ok(0);
        };
        Ok(first.starts_with(prefix) as u64)
    })
}

fn caddy_request_header_values(
    ctx: &crate::script::ScriptExecutionContext,
    name: &str,
) -> Vec<String> {
    let name = name.to_ascii_lowercase();
    let request = ctx.request.borrow();
    if name == "host" {
        return request
            .headers
            .get("host")
            .cloned()
            .map(|value| vec![value])
            .unwrap_or_default();
    }
    if name == "transfer-encoding"
        && !request.header_values.contains_key("transfer-encoding")
        && !request.transfer_encodings.is_empty()
    {
        return request.transfer_encodings.clone();
    }
    request
        .header_values
        .get(&name)
        .cloned()
        .unwrap_or_default()
}

fn caddy_header_value_match(actual: &str, allowed: &str) -> bool {
    if allowed == "*" {
        true
    } else if allowed.starts_with('*') && allowed.ends_with('*') && allowed.len() >= 2 {
        actual.contains(&allowed[1..allowed.len() - 1])
    } else if let Some(suffix) = allowed.strip_prefix('*') {
        actual.ends_with(suffix)
    } else if let Some(prefix) = allowed.strip_suffix('*') {
        actual.starts_with(prefix)
    } else {
        actual == allowed
    }
}

fn caddy_match_path(encoded_path: &str, pattern: &str) -> Result<bool, ()> {
    if pattern == "*" {
        return Ok(true);
    }
    let merge_slashes = !pattern.contains("//");
    if pattern.contains('%') {
        let escaped_path = clean_path_caddy(encoded_path, merge_slashes);
        let Some(hybrid_path) = caddy_escaped_path_match_subject(&escaped_path, pattern) else {
            return Ok(false);
        };
        let pattern = pattern.replace("%*", "*");
        return Ok(caddy_http_path_glob_match(&pattern, &hybrid_path));
    }

    let Some(decoded_path) = caddy_percent_decode_path(encoded_path) else {
        return Ok(false);
    };
    let decoded_path = decoded_path.to_ascii_lowercase();
    let cleaned_path = clean_path_caddy(&decoded_path, merge_slashes);
    Ok(caddy_match_cleaned_path(&cleaned_path, pattern))
}

fn caddy_match_cleaned_path(path: &str, pattern: &str) -> bool {
    let star_count = pattern.as_bytes().iter().filter(|&&ch| ch == b'*').count();
    if star_count == 2 && pattern.starts_with('*') && pattern.ends_with('*') {
        return path.contains(&pattern[1..pattern.len() - 1]);
    }
    if star_count == 1 && pattern.starts_with('*') {
        return path.ends_with(&pattern[1..]);
    }
    if star_count == 1 && pattern.ends_with('*') {
        return path.starts_with(&pattern[..pattern.len() - 1]);
    }
    caddy_http_path_glob_match(pattern, path)
}

fn caddy_http_path_glob_match(pattern: &str, value: &str) -> bool {
    let pattern_parts = pattern.split('/').collect::<Vec<_>>();
    let value_parts = value.split('/').collect::<Vec<_>>();
    pattern_parts.len() == value_parts.len()
        && pattern_parts
            .iter()
            .zip(value_parts.iter())
            .all(|(pattern, value)| glob_match(pattern, value))
}

fn caddy_escaped_path_match_subject(escaped_path: &str, pattern: &str) -> Option<String> {
    let path = escaped_path.as_bytes();
    let pat = pattern.as_bytes();
    let mut out = String::new();
    let mut pi = 0usize;
    let mut i = 0usize;
    while pi < pat.len() && i < path.len() {
        let mut path_ch = escaped_path[i..].chars().next()?;
        let mut path_ch_len = path_ch.len_utf8();
        let mut escaped_path_ch = String::new();
        if path[i] == b'%' && i + 2 < path.len() {
            let triplet = &path[i..i + 3];
            let decoded = caddy_percent_decode_triplet(triplet)?;
            escaped_path_ch = triplet
                .iter()
                .map(|byte| (*byte as char).to_ascii_lowercase())
                .collect();
            path_ch = decoded as char;
            path_ch_len = 1;
            i += 2;
        }

        match pat[pi] {
            b'%' => {
                if pi + 2 < pat.len() && pat[pi + 1] != b'*' {
                    out.push_str(&escaped_path_ch);
                    i += 1;
                    pi += 2;
                } else {
                    pi += 1;
                    caddy_escaped_path_wildcard(
                        escaped_path,
                        pattern,
                        &mut out,
                        &mut i,
                        pi,
                        false,
                    )?;
                }
            }
            b'*' => {
                caddy_escaped_path_wildcard(escaped_path, pattern, &mut out, &mut i, pi, true)?;
            }
            _ => {
                out.push(path_ch);
                i += path_ch_len;
            }
        }
        pi += 1;
    }
    Some(out.to_ascii_lowercase())
}

fn caddy_escaped_path_wildcard(
    escaped_path: &str,
    pattern: &str,
    out: &mut String,
    path_idx: &mut usize,
    pattern_idx: usize,
    decode: bool,
) -> Option<()> {
    let remaining = &escaped_path[*path_idx..];
    let until = if pattern_idx < pattern.len() - 1 {
        let next = pattern.as_bytes()[pattern_idx + 1];
        remaining.as_bytes().iter().position(|&ch| ch == next)?
    } else {
        remaining.len()
    };
    if until == 0 {
        return Some(());
    }
    let next = &remaining[..until];
    if decode {
        let decoded = caddy_percent_decode_path(next)?;
        out.push_str(&decoded);
    } else {
        out.push_str(next);
    }
    *path_idx += until;
    Some(())
}

fn caddy_percent_decode_path(input: &str) -> Option<String> {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0usize;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            if i + 2 >= bytes.len() {
                return None;
            }
            out.push(caddy_percent_decode_triplet(&bytes[i..i + 3])?);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).ok()
}

fn caddy_percent_decode_triplet(input: &[u8]) -> Option<u8> {
    if input.len() != 3 || input[0] != b'%' {
        return None;
    }
    Some((hex_value(input[1])? << 4) | hex_value(input[2])?)
}

fn hex_value(ch: u8) -> Option<u8> {
    match ch {
        b'0'..=b'9' => Some(ch - b'0'),
        b'a'..=b'f' => Some(ch - b'a' + 10),
        b'A'..=b'F' => Some(ch - b'A' + 10),
        _ => None,
    }
}

pub fn h_caddy_regex_match(
    scope: &HelperScope,
    input_ptr: u64,
    input_len: u64,
    config_ptr: u64,
    config_len: u64,
    _: u64,
) -> Result<u64, ()> {
    let input = read_utf8(scope, input_ptr, input_len)?;
    let config = read_utf8(scope, config_ptr, config_len)?;
    let config: CaddyRegexMatch = serde_json::from_str(config).map_err(|_| ())?;
    with_ectx(scope, |ctx| {
        Ok(caddy_regex_match_and_store(ctx, input, &config)? as u64)
    })
}

pub fn h_caddy_expr_in(
    scope: &HelperScope,
    input_ptr: u64,
    input_len: u64,
    values_ptr: u64,
    values_len: u64,
    _: u64,
) -> Result<u64, ()> {
    let input = read_utf8(scope, input_ptr, input_len)?;
    let values = read_utf8(scope, values_ptr, values_len)?;
    let values: Vec<String> = serde_json::from_str(values).map_err(|_| ())?;
    with_ectx(scope, |ctx| {
        let input = expand_caddy_placeholders(ctx, input)?;
        for value in values {
            if input == expand_caddy_placeholders(ctx, &value)? {
                return Ok(1);
            }
        }
        Ok(0)
    })
}

pub fn h_caddy_expr_eq(
    scope: &HelperScope,
    left_ptr: u64,
    left_len: u64,
    right_ptr: u64,
    right_len: u64,
    _: u64,
) -> Result<u64, ()> {
    let left = read_utf8(scope, left_ptr, left_len)?;
    let right = read_utf8(scope, right_ptr, right_len)?;
    with_ectx(scope, |ctx| {
        let left = expand_caddy_placeholders(ctx, left)?;
        let right = expand_caddy_placeholders(ctx, right)?;
        Ok((left == right) as u64)
    })
}

pub fn h_caddy_file_match(
    scope: &HelperScope,
    config_ptr: u64,
    config_len: u64,
    _: u64,
    _: u64,
    _: u64,
) -> Result<u64, ()> {
    let config = read_utf8(scope, config_ptr, config_len)?;
    let config: CaddyFileMatcher = serde_json::from_str(config).map_err(|_| ())?;
    with_ectx(scope, |ctx| Ok(caddy_file_match(ctx, &config)? as u64))
}

#[derive(Default, serde::Deserialize)]
struct CaddyFileMatcher {
    #[serde(default)]
    fs: String,
    #[serde(default)]
    root: String,
    #[serde(default)]
    try_files: Option<Vec<String>>,
    #[serde(default)]
    try_policy: String,
    #[serde(default)]
    split_path: Vec<String>,
}

#[derive(Clone)]
struct CaddyFileCandidate {
    fullpath: String,
    relative: String,
    remainder: String,
    wants_dir: bool,
    root: CaddyFileMatcherRoot,
}

#[derive(Clone)]
enum CaddyFileMatcherRoot {
    Tar(String),
    Fs(PathBuf),
}

struct CaddyFileStat {
    is_dir: bool,
    size: u64,
    mtime: u64,
}

fn caddy_file_match(
    ctx: &mut crate::script::ScriptExecutionContext,
    config: &CaddyFileMatcher,
) -> Result<bool, ()> {
    let fs_name = expand_caddy_defaulted_placeholder(ctx, &config.fs, "{http.vars.fs}", "")?;
    if !fs_name.is_empty() && fs_name != "file" && fs_name != "default" {
        return Ok(false);
    }
    let root = expand_caddy_defaulted_placeholder(ctx, &config.root, "{http.vars.root}", ".")?;
    let root_config = caddy_file_matcher_root(&root, caddy_fs_name_forces_filesystem(&fs_name));
    if matches!(root_config, CaddyFileMatcherRoot::Fs(_)) && !ctx.expose_filesystem {
        return Ok(false);
    }
    let try_files = config
        .try_files
        .clone()
        .unwrap_or_else(|| vec!["{http.request.uri.path}".to_string()]);

    match config.try_policy.as_str() {
        "" | "first_exist" | "first_exist_fallback" => {
            let fallback_idx = (config.try_policy == "first_exist_fallback"
                && !try_files.is_empty())
            .then_some(try_files.len() - 1);
            for (idx, pattern) in try_files.iter().enumerate() {
                if let Some(status) = caddy_file_matcher_error_pattern(pattern) {
                    caddy_file_matcher_set_error(ctx, status);
                    return Ok(false);
                }
                for candidate in
                    caddy_file_matcher_candidates(ctx, config, root_config.clone(), pattern)?
                {
                    if Some(idx) == fallback_idx {
                        set_caddy_file_match_placeholders(ctx, &candidate, false);
                        return Ok(true);
                    }
                    if let Some(stat) = caddy_file_matcher_stat(ctx, &candidate, true) {
                        set_caddy_file_match_placeholders(ctx, &candidate, stat.is_dir);
                        return Ok(true);
                    }
                }
            }
            Ok(false)
        }
        "largest_size" | "smallest_size" | "most_recently_modified" => {
            let mut selected: Option<(CaddyFileCandidate, CaddyFileStat)> = None;
            for pattern in &try_files {
                for candidate in
                    caddy_file_matcher_candidates(ctx, config, root_config.clone(), pattern)?
                {
                    let Some(stat) = caddy_file_matcher_stat(ctx, &candidate, false) else {
                        continue;
                    };
                    let replace = match config.try_policy.as_str() {
                        "largest_size" => selected
                            .as_ref()
                            .map_or(stat.size > 0, |(_, current)| stat.size > current.size),
                        "smallest_size" => selected.as_ref().is_none_or(|(_, current)| {
                            current.size == 0 || stat.size < current.size
                        }),
                        "most_recently_modified" => selected
                            .as_ref()
                            .is_none_or(|(_, current)| stat.mtime > current.mtime),
                        _ => false,
                    };
                    if replace {
                        selected = Some((candidate, stat));
                    }
                }
            }
            if let Some((candidate, stat)) = selected {
                set_caddy_file_match_placeholders(ctx, &candidate, stat.is_dir);
                Ok(true)
            } else {
                Ok(false)
            }
        }
        _ => Err(()),
    }
}

fn caddy_file_matcher_root(root: &str, force_filesystem: bool) -> CaddyFileMatcherRoot {
    let root = root.trim();
    if force_filesystem {
        CaddyFileMatcherRoot::Fs(PathBuf::from(if root.is_empty() { "." } else { root }))
    } else if Path::new(root).is_absolute() {
        CaddyFileMatcherRoot::Fs(PathBuf::from(root))
    } else if root.is_empty() || root == "." {
        CaddyFileMatcherRoot::Tar(String::new())
    } else {
        CaddyFileMatcherRoot::Tar(root.trim_matches('/').to_string())
    }
}

fn caddy_fs_name_forces_filesystem(fs_name: &str) -> bool {
    fs_name == "file" || fs_name == "default"
}

fn caddy_file_matcher_candidates(
    ctx: &crate::script::ScriptExecutionContext,
    config: &CaddyFileMatcher,
    root_config: CaddyFileMatcherRoot,
    pattern: &str,
) -> Result<Vec<CaddyFileCandidate>, ()> {
    let expanded = expand_caddy_file_matcher_placeholders(ctx, pattern)?;
    let mut before_split = clean_path_no_trailing(&expanded);
    let (split_part, remainder) = first_caddy_file_split(&before_split, &config.split_path);
    before_split = split_part;
    if pattern.ends_with('/') && !before_split.ends_with('/') {
        before_split.push('/');
    }
    let wants_dir = before_split.ends_with('/');
    let pattern_has_static_glob = caddy_glob_pattern_outside_placeholders(pattern);
    let mut candidates = Vec::new();
    match &root_config {
        CaddyFileMatcherRoot::Tar(root) => {
            let Some(fullpath) = join_caddy_file_path(root, &before_split) else {
                return Ok(candidates);
            };
            if pattern_has_static_glob || caddy_glob_pattern_outside_placeholders(&fullpath) {
                for entry in ctx.site.entries.values() {
                    if caddy_path_glob_match(&fullpath, &entry.path) {
                        let relative = caddy_file_match_relative(root, &entry.path);
                        candidates.push(CaddyFileCandidate {
                            fullpath: entry.path.clone(),
                            relative,
                            remainder: remainder.clone(),
                            wants_dir,
                            root: root_config.clone(),
                        });
                    }
                }
                for directory in &ctx.site.directories {
                    if caddy_path_glob_match(&fullpath, directory) {
                        let relative = caddy_file_match_relative(root, directory);
                        candidates.push(CaddyFileCandidate {
                            fullpath: directory.clone(),
                            relative,
                            remainder: remainder.clone(),
                            wants_dir,
                            root: root_config.clone(),
                        });
                    }
                }
                candidates.sort_by(|a, b| a.fullpath.cmp(&b.fullpath));
                return Ok(candidates);
            }
            let fullpath = caddy_file_unescape_glob_literals(&fullpath);
            let relative = caddy_file_match_relative(root, &fullpath);
            candidates.push(CaddyFileCandidate {
                fullpath,
                relative,
                remainder,
                wants_dir,
                root: root_config.clone(),
            });
        }
        CaddyFileMatcherRoot::Fs(root_path) => {
            let Some(path) = caddy_fs_match_join(root_path, &before_split) else {
                return Ok(candidates);
            };
            let fullpath = caddy_file_match_display_path(&path);
            if pattern_has_static_glob || caddy_glob_pattern_outside_placeholders(&fullpath) {
                let paths = if pattern_has_static_glob
                    && !caddy_glob_pattern_outside_placeholders(&caddy_file_match_display_path(
                        root_path,
                    )) {
                    caddy_fs_glob_pattern(root_path, &path)
                        .map(|pattern| caddy_fs_glob_candidates(root_path, &pattern))
                        .unwrap_or_default()
                } else {
                    caddy_fs_full_glob_candidates(&fullpath)
                };
                for path in paths {
                    let fullpath = caddy_file_match_display_path(&path);
                    let relative = caddy_fs_relative(root_path, &path);
                    candidates.push(CaddyFileCandidate {
                        fullpath,
                        relative,
                        remainder: remainder.clone(),
                        wants_dir,
                        root: root_config.clone(),
                    });
                }
                candidates.sort_by(|a, b| a.fullpath.cmp(&b.fullpath));
                return Ok(candidates);
            }
            let fullpath = caddy_file_unescape_glob_literals(&fullpath);
            let relative = caddy_file_match_relative_from_root(
                &caddy_file_match_display_path(root_path),
                &fullpath,
            );
            candidates.push(CaddyFileCandidate {
                fullpath,
                relative,
                remainder,
                wants_dir,
                root: root_config.clone(),
            });
        }
    }
    Ok(candidates)
}

fn caddy_fs_glob_pattern(root: &Path, pattern: &Path) -> Option<String> {
    let relative = pattern.strip_prefix(root).ok()?;
    Some(slash_path_with_leading(&relative.to_string_lossy()))
}

fn caddy_file_match_relative_from_root(root: &str, fullpath: &str) -> String {
    fullpath.strip_prefix(root).unwrap_or(fullpath).to_string()
}

fn expand_caddy_file_matcher_placeholders(
    ctx: &crate::script::ScriptExecutionContext,
    input: &str,
) -> Result<String, ()> {
    let mut out = String::with_capacity(input.len());
    let mut last = 0usize;
    let mut cursor = 0usize;
    while let Some(relative_start) = input[cursor..].find('{') {
        let start = cursor + relative_start;
        let after_start = start + 1;
        let Some(relative_end) = input[after_start..].find('}') else {
            break;
        };
        let end = after_start + relative_end;
        let key = &input[after_start..end];
        let value = if key == "http.request.uri.path" {
            caddy_percent_decode_path(&ctx.request.borrow().path)
        } else {
            resolve_caddy_placeholder_value(ctx, key)
        };
        if let Some(value) = value {
            out.push_str(&input[last..start]);
            out.push_str(&caddy_file_glob_escape(&value));
            last = end + 1;
            cursor = end + 1;
        } else {
            out.push_str(&input[last..start]);
            last = end + 1;
            cursor = end + 1;
        }
    }
    out.push_str(&input[last..]);
    Ok(out)
}

fn caddy_file_glob_escape(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '*' | '[' | '?' | '\\' => {
                out.push('\\');
                out.push(ch);
            }
            _ => out.push(ch),
        }
    }
    out
}

fn caddy_file_unescape_glob_literals(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    let mut chars = value.chars();
    while let Some(ch) = chars.next() {
        if ch == '\\' {
            match chars.next() {
                Some(next @ ('*' | '[' | '?' | '\\')) => out.push(next),
                Some(next) => {
                    out.push(ch);
                    out.push(next);
                }
                None => out.push(ch),
            }
        } else {
            out.push(ch);
        }
    }
    out
}

fn caddy_fs_glob_candidates(root: &Path, pattern: &str) -> Vec<PathBuf> {
    let mut candidates = Vec::new();
    caddy_fs_collect_glob_candidates(root, root, pattern, &mut candidates);
    candidates
}

fn caddy_fs_full_glob_candidates(pattern: &str) -> Vec<PathBuf> {
    let pattern = pattern.replace('\\', "/");
    let start = if pattern.starts_with('/') {
        PathBuf::from("/")
    } else {
        PathBuf::from(".")
    };
    let parts = pattern
        .trim_start_matches('/')
        .split('/')
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>();
    let mut candidates = Vec::new();
    caddy_fs_collect_full_glob_candidates(&start, &parts, 0, &mut candidates);
    candidates
}

fn caddy_fs_collect_full_glob_candidates(
    current: &Path,
    parts: &[&str],
    idx: usize,
    candidates: &mut Vec<PathBuf>,
) {
    if idx >= parts.len() {
        if current.exists() {
            candidates.push(current.to_path_buf());
        }
        return;
    }

    let part = parts[idx];
    if caddy_glob_pattern_outside_placeholders(part) {
        let Ok(entries) = fs::read_dir(current) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
                continue;
            };
            if glob_match(part, name) {
                caddy_fs_collect_full_glob_candidates(&path, parts, idx + 1, candidates);
            }
        }
    } else {
        caddy_fs_collect_full_glob_candidates(&current.join(part), parts, idx + 1, candidates);
    }
}

fn caddy_fs_collect_glob_candidates(
    root: &Path,
    current: &Path,
    pattern: &str,
    candidates: &mut Vec<PathBuf>,
) {
    let Ok(entries) = fs::read_dir(current) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let relative = caddy_fs_relative(root, &path);
        if caddy_path_glob_match(pattern, &relative) {
            candidates.push(path.clone());
        }
        if path.is_dir() {
            caddy_fs_collect_glob_candidates(root, &path, pattern, candidates);
        }
    }
}

fn caddy_fs_relative(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .map(|path| slash_path_with_leading(&path.to_string_lossy()))
        .unwrap_or_else(|_| slash_path_with_leading(&caddy_file_match_display_path(path)))
}

fn clean_path_no_trailing(path: &str) -> String {
    let mut cleaned = clean_path_preserve_trailing(path);
    if cleaned.len() > 1 && cleaned.ends_with('/') {
        cleaned.pop();
    }
    cleaned
}

fn first_caddy_file_split(path: &str, split_path: &[String]) -> (String, String) {
    for split in split_path {
        if let Some(idx) = index_fold(path, split) {
            let pos = idx + split.len();
            if pos != path.len() && !path[pos..].starts_with('/') {
                continue;
            }
            return (path[..pos].to_string(), path[pos..].to_string());
        }
    }
    (path.to_string(), String::new())
}

fn index_fold(haystack: &str, needle: &str) -> Option<usize> {
    (0..haystack.len()).find(|idx| {
        idx + needle.len() < haystack.len()
            && haystack[*idx..]
                .get(..needle.len())
                .is_some_and(|s| s.eq_ignore_ascii_case(needle))
    })
}

fn caddy_file_matcher_stat(
    ctx: &crate::script::ScriptExecutionContext,
    candidate: &CaddyFileCandidate,
    strict: bool,
) -> Option<CaddyFileStat> {
    match &candidate.root {
        CaddyFileMatcherRoot::Tar(_) => {
            if let Some(entry) = ctx
                .site
                .entries
                .get(candidate.fullpath.trim_end_matches('/'))
            {
                if strict && candidate.wants_dir {
                    return None;
                }
                return Some(CaddyFileStat {
                    is_dir: false,
                    size: entry.size,
                    mtime: entry.mtime,
                });
            }
            let dir = candidate.fullpath.trim_matches('/').to_string();
            if ctx.site.directories.contains(&dir) {
                if strict && !candidate.wants_dir {
                    return None;
                }
                return Some(CaddyFileStat {
                    is_dir: true,
                    size: 0,
                    mtime: ctx.site.directory_mtimes.get(&dir).copied().unwrap_or(0),
                });
            }
            None
        }
        CaddyFileMatcherRoot::Fs(_) => {
            let path = PathBuf::from(&candidate.fullpath);
            let meta = fs::metadata(path).ok()?;
            if strict && candidate.wants_dir != meta.is_dir() {
                return None;
            }
            let mtime = meta
                .modified()
                .ok()
                .and_then(|time| time.duration_since(UNIX_EPOCH).ok())
                .map(|duration| duration.as_secs())
                .unwrap_or(0);
            Some(CaddyFileStat {
                is_dir: meta.is_dir(),
                size: meta.len(),
                mtime,
            })
        }
    }
}

fn set_caddy_file_match_placeholders(
    ctx: &crate::script::ScriptExecutionContext,
    candidate: &CaddyFileCandidate,
    is_dir: bool,
) {
    let mut metadata = ctx.metadata.borrow_mut();
    metadata.insert(
        "http.matchers.file.relative".to_string(),
        candidate.relative.replace('\\', "/"),
    );
    metadata.insert(
        "http.matchers.file.absolute".to_string(),
        candidate.fullpath.replace('\\', "/"),
    );
    metadata.insert(
        "http.matchers.file.remainder".to_string(),
        candidate.remainder.replace('\\', "/"),
    );
    metadata.insert(
        "http.matchers.file.type".to_string(),
        if is_dir { "directory" } else { "file" }.to_string(),
    );
}

fn caddy_file_match_relative(root: &str, fullpath: &str) -> String {
    if root.is_empty() {
        return fullpath.trim_matches('/').to_string();
    }
    let relative = fullpath
        .strip_prefix(root.trim_matches('/'))
        .unwrap_or(fullpath)
        .trim_matches('/')
        .to_string();
    slash_path_with_leading(&relative)
}

fn slash_path_with_leading(path: &str) -> String {
    let path = path.replace('\\', "/");
    if path.starts_with('/') {
        path
    } else {
        format!("/{path}")
    }
}

fn caddy_fs_match_join(root: &Path, rel: &str) -> Option<PathBuf> {
    let rel = rel.trim_start_matches('/');
    if rel.split('/').any(|part| part == "..") {
        return None;
    }
    Some(root.join(rel))
}

fn caddy_file_matcher_error_pattern(pattern: &str) -> Option<u16> {
    if let Some(status) = pattern.strip_prefix('=') {
        status
            .parse::<u16>()
            .ok()
            .filter(|status| *status != 103 && (100..=999).contains(status))
    } else {
        None
    }
}

fn caddy_file_matcher_set_error(ctx: &mut crate::script::ScriptExecutionContext, status: u16) {
    let status_text = ::http::StatusCode::from_u16(status)
        .ok()
        .and_then(|status| status.canonical_reason())
        .unwrap_or("");
    let mut metadata = ctx.metadata.borrow_mut();
    metadata.insert("http.error.status_code".to_string(), status.to_string());
    metadata.insert(
        "http.error.status_text".to_string(),
        status_text.to_string(),
    );
    metadata.insert("http.error.message".to_string(), String::new());
    metadata.insert("http.error".to_string(), String::new());
}

fn caddy_regex_match_and_store(
    ctx: &mut crate::script::ScriptExecutionContext,
    input: &str,
    config: &CaddyRegexMatch,
) -> Result<bool, ()> {
    if !config.name.is_empty() && !is_caddy_regex_name(&config.name) {
        return Err(());
    }
    let regex = caddy_regex(&config.pattern).map_err(|_| ())?;
    let Some(captures) = regex.captures(input) else {
        return Ok(false);
    };
    let mut metadata = ctx.metadata.borrow_mut();
    for index in 0..captures.len() {
        let value = captures
            .get(index)
            .map(|capture| capture.as_str())
            .unwrap_or("");
        let key_suffix = format!(".{index}");
        if !config.name.is_empty() {
            metadata.insert(
                format!("http.regexp.{}{}", config.name, key_suffix),
                value.to_string(),
            );
        }
        metadata.insert(format!("http.regexp{key_suffix}"), value.to_string());
    }
    for (index, name) in regex.capture_names().enumerate() {
        if index == 0 {
            continue;
        }
        let Some(name) = name else {
            continue;
        };
        let value = captures
            .get(index)
            .map(|capture| capture.as_str())
            .unwrap_or("");
        let key_suffix = format!(".{name}");
        if !config.name.is_empty() {
            metadata.insert(
                format!("http.regexp.{}{}", config.name, key_suffix),
                value.to_string(),
            );
        }
        metadata.insert(format!("http.regexp{key_suffix}"), value.to_string());
    }
    Ok(true)
}

fn caddy_regex(pattern: &str) -> Result<Regex, regex::Error> {
    Regex::new(&caddy_go_regexp_for_rust(pattern))
}

fn caddy_go_regexp_for_rust(pattern: &str) -> String {
    let mut out = String::with_capacity(pattern.len());
    let mut chars = pattern.char_indices().peekable();
    while let Some((idx, ch)) = chars.next() {
        if ch == '\\' {
            out.push(ch);
            if let Some((_, escaped)) = chars.next() {
                out.push(escaped);
            }
            continue;
        }
        if ch != '{' {
            out.push(ch);
            continue;
        }
        let after_start = idx + ch.len_utf8();
        let Some(relative_end) = pattern[after_start..].find('}') else {
            out.push_str("\\{");
            continue;
        };
        let end = after_start + relative_end;
        let body = &pattern[after_start..end];
        if caddy_go_regexp_repeat_quantifier(body) {
            out.push('{');
            out.push_str(body);
            out.push('}');
        } else {
            out.push_str("\\{");
            out.push_str(body);
            out.push_str("\\}");
        }
        while chars.peek().is_some_and(|(next_idx, _)| *next_idx <= end) {
            chars.next();
        }
    }
    out
}

fn caddy_go_regexp_repeat_quantifier(body: &str) -> bool {
    if body.is_empty() {
        return false;
    }
    let Some((first, second)) = body.split_once(',') else {
        return body.chars().all(|ch| ch.is_ascii_digit());
    };
    !first.is_empty()
        && first.chars().all(|ch| ch.is_ascii_digit())
        && second.chars().all(|ch| ch.is_ascii_digit())
}

#[derive(Default, serde::Deserialize)]
struct CaddyRegexMatch {
    #[serde(default)]
    name: String,
    #[serde(default)]
    pattern: String,
}

fn is_caddy_regex_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .chars()
            .any(|ch| ch == '_' || ch.is_ascii_alphanumeric())
}

pub fn h_caddy_expand(
    scope: &HelperScope,
    input_ptr: u64,
    input_len: u64,
    out_ptr: u64,
    out_len: u64,
    _: u64,
) -> Result<u64, ()> {
    let input = read_utf8(scope, input_ptr, input_len)?;
    with_ectx(scope, |ctx| {
        let expanded = expand_caddy_placeholders(ctx, input)?;
        deref_and_write_cstr(scope, out_ptr, out_len, &expanded)
    })
}

pub fn h_caddy_expand_known(
    scope: &HelperScope,
    input_ptr: u64,
    input_len: u64,
    out_ptr: u64,
    out_len: u64,
    _: u64,
) -> Result<u64, ()> {
    let input = read_utf8(scope, input_ptr, input_len)?;
    with_ectx(scope, |ctx| {
        let expanded = expand_known_caddy_placeholders(ctx, input)?;
        deref_and_write_cstr(scope, out_ptr, out_len, &expanded)
    })
}

fn expand_caddy_placeholders(
    ctx: &crate::script::ScriptExecutionContext,
    input: &str,
) -> Result<String, ()> {
    expand_caddy_placeholders_inner(ctx, input, true)
}

fn expand_known_caddy_placeholders(
    ctx: &crate::script::ScriptExecutionContext,
    input: &str,
) -> Result<String, ()> {
    expand_caddy_placeholders_inner(ctx, input, false)
}

fn expand_caddy_placeholders_inner(
    ctx: &crate::script::ScriptExecutionContext,
    input: &str,
    unknown_as_empty: bool,
) -> Result<String, ()> {
    let mut out = String::with_capacity(input.len());
    let mut last = 0usize;
    let mut cursor = 0usize;
    let bytes = input.as_bytes();
    while let Some(relative_start) = bytes[cursor..]
        .iter()
        .position(|byte| *byte == b'{' || *byte == b'}')
    {
        let start = cursor + relative_start;
        if start > 0 && bytes[start - 1] == b'\\' {
            out.push_str(&input[last..start - 1]);
            last = start;
            cursor = start + 1;
            continue;
        }
        if bytes[start] != b'{' {
            cursor = start + 1;
            continue;
        }
        let after_start = start + 1;
        let mut end_cursor = after_start;
        let end = loop {
            let Some(relative_end) = input[end_cursor..].find('}') else {
                break None;
            };
            let end = end_cursor + relative_end;
            if end > 0 && bytes[end - 1] == b'\\' {
                end_cursor = end + 1;
                continue;
            }
            break Some(end);
        };
        let Some(end) = end else {
            break;
        };
        let key = &input[after_start..end];
        if let Some(value) = resolve_caddy_placeholder_value(ctx, key) {
            out.push_str(&input[last..start]);
            out.push_str(&value);
            last = end + 1;
            cursor = end + 1;
        } else if unknown_as_empty {
            out.push_str(&input[last..start]);
            last = end + 1;
            cursor = end + 1;
        } else {
            cursor = after_start;
        }
    }
    out.push_str(&input[last..]);
    Ok(out)
}

fn resolve_caddy_placeholder(ctx: &crate::script::ScriptExecutionContext, key: &str) -> String {
    resolve_caddy_placeholder_value(ctx, key).unwrap_or_default()
}

fn resolve_caddy_placeholder_value(
    ctx: &crate::script::ScriptExecutionContext,
    key: &str,
) -> Option<String> {
    if key.is_empty() {
        return None;
    }
    if let Some(value) = ctx.metadata.borrow().get(key).cloned() {
        return Some(value);
    }
    if let Some(name) = key.strip_prefix("http.response.header.") {
        return Some(resolve_caddy_response_header(ctx, name));
    }
    let request = ctx.request.borrow();
    let hostport = request.header("host").unwrap_or("");
    let (host, port) = split_caddy_host_port(hostport);
    let (local_host, local_port) = split_caddy_host_port(&request.local);
    let (remote_host, remote_port) = split_caddy_host_port(&request.peer);
    let (active_path, active_query) =
        caddy_active_request_uri_parts(&request.uri, &request.path, &request.query);
    Some(match key {
        "http.request.method" => request.method.clone(),
        "http.request.scheme" => request.scheme.clone(),
        "http.request.host" => host,
        "http.request.port" => port,
        "http.request.hostport" => hostport.to_string(),
        "http.request.uri" => request.uri.clone(),
        "http.request.uri_escaped" => caddy_query_escape(&request.uri),
        "http.request.uri.path" => active_path.clone(),
        "http.request.uri.path_escaped" => caddy_query_escape(&active_path),
        "http.request.uri.query" => active_query.clone(),
        "http.request.uri.query_escaped" => caddy_query_escape(&active_query),
        "http.request.uri.prefixed_query" => {
            if active_query.is_empty() {
                String::new()
            } else {
                format!("?{active_query}")
            }
        }
        "http.request.orig_method" => request.original_method.clone(),
        "http.request.orig_uri" => request.original_uri.clone(),
        "http.request.orig_uri.path" => request.original_path.clone(),
        "http.request.orig_uri.path.file" => caddy_path_file(&request.original_path),
        "http.request.orig_uri.path.dir" => caddy_path_dir(&request.original_path),
        "http.request.orig_uri.query" => request.original_query.clone(),
        "http.request.orig_uri.prefixed_query" => {
            if request.original_query.is_empty() {
                String::new()
            } else {
                format!("?{}", request.original_query)
            }
        }
        "http.request.local" => request.local.clone(),
        "http.request.local.host" => local_host,
        "http.request.local.port" => local_port,
        "http.request.remote" => request.peer.clone(),
        "http.request.remote.host" => remote_host,
        "http.request.remote.port" => remote_port,
        "http.request.proto" => format!("HTTP/{}.{}", request.proto_major, request.proto_minor),
        "http.request.proto_name" | "http.request.proto.name" => match request.proto_major {
            1 => format!("HTTP/{}.{}", request.proto_major, request.proto_minor),
            2 => "HTTP/2".to_string(),
            3 => "HTTP/3".to_string(),
            _ => format!("HTTP/{}.{}", request.proto_major, request.proto_minor),
        },
        "http.request.duration" => caddy_duration_string(request.start_time.elapsed()),
        "http.request.duration_ms" => caddy_duration_ms_string(request.start_time.elapsed()),
        "http.request.uuid" => request.request_id.to_string(),
        "http.request.tls.proto" => request.connection.alpn.clone().unwrap_or_default(),
        "http.request.tls.proto_mutual" => {
            if request.connection.tls {
                "true".to_string()
            } else {
                String::new()
            }
        }
        "http.request.tls.version" => request.connection.tls_version.clone().unwrap_or_default(),
        "http.request.tls.cipher_suite" => request
            .connection
            .tls_cipher_suite
            .clone()
            .unwrap_or_default(),
        "http.request.tls.resumed" => request
            .connection
            .tls_resumed
            .map(|resumed| resumed.to_string())
            .unwrap_or_default(),
        "http.request.tls.server_name" => request.connection.inner_sni.clone().unwrap_or_default(),
        "http.request.tls.ech" => request
            .connection
            .ech_accepted
            .map(|accepted| accepted.to_string())
            .unwrap_or_default(),
        "http.shutting_down" => "false".to_string(),
        "http.time_until_shutdown" => String::new(),
        _ => {
            let prefixed =
                resolve_prefixed_caddy_placeholder(&request, &ctx.metadata.borrow(), key);
            drop(request);
            return prefixed.or_else(|| resolve_caddy_map_placeholder(ctx, key));
        }
    })
}

fn caddy_duration_string(duration: std::time::Duration) -> String {
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
                caddy_duration_string(std::time::Duration::from_nanos(rest as u64))
            )
        }
    }
}

fn caddy_duration_ms_string(duration: std::time::Duration) -> String {
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

fn resolve_caddy_map_placeholder(
    ctx: &crate::script::ScriptExecutionContext,
    key: &str,
) -> Option<String> {
    let maps = ctx.caddy_maps.borrow().clone();
    for config in maps {
        let Some(dest_idx) = config.destinations.iter().position(|dest| dest == key) else {
            continue;
        };
        let input = expand_caddy_placeholders_inner(ctx, &config.source, true).ok()?;
        for mapping in &config.mappings {
            let Some(output) = mapping.outputs.get(dest_idx) else {
                continue;
            };
            if output.is_null() {
                continue;
            }
            let output = caddy_map_output_to_string(output);
            if !mapping.input_regexp.is_empty() {
                let Ok(regex) = caddy_regex(&mapping.input_regexp) else {
                    continue;
                };
                let Some(captures) = regex.captures(&input) else {
                    continue;
                };
                let mut expanded = String::new();
                captures.expand(&output, &mut expanded);
                return Some(expanded);
            }
            if input == mapping.input {
                return expand_caddy_placeholders_inner(ctx, &output, true).ok();
            }
        }
        if let Some(default) = config.defaults.get(dest_idx) {
            return expand_caddy_placeholders_inner(ctx, default, true).ok();
        }
        return Some(String::new());
    }
    None
}

fn caddy_map_output_to_string(value: &serde_json::Value) -> String {
    caddy_var_value_to_string(value)
}

fn caddy_active_request_uri_parts(
    uri: &str,
    fallback_path: &str,
    fallback_query: &str,
) -> (String, String) {
    if let Some((path, query)) = split_relative_request_target(uri) {
        return (path, query);
    }
    if let Ok(parsed) = uri.parse::<::http::Uri>() {
        return (
            parsed.path().to_string(),
            parsed.query().unwrap_or("").to_string(),
        );
    }
    let rest = uri.split_once('#').map_or(uri, |(value, _)| value);
    if let Some((path, query)) = rest.split_once('?') {
        let path = if path.is_empty() { fallback_path } else { path };
        return (path.to_string(), query.to_string());
    }
    if rest.is_empty() {
        (fallback_path.to_string(), fallback_query.to_string())
    } else {
        (rest.to_string(), String::new())
    }
}

fn resolve_caddy_response_header(
    ctx: &crate::script::ScriptExecutionContext,
    name: &str,
) -> String {
    let Some(response_context) = &ctx.response_context else {
        return String::new();
    };
    let Ok(header_name) = ::http::header::HeaderName::from_bytes(name.as_bytes()) else {
        return String::new();
    };
    response_context
        .borrow()
        .headers
        .get_all(header_name)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .collect::<Vec<_>>()
        .join(",")
}

fn split_caddy_host_port(value: &str) -> (String, String) {
    if value.is_empty() {
        return (String::new(), String::new());
    }
    if let Ok(addr) = SocketAddr::from_str(value) {
        return (addr.ip().to_string(), addr.port().to_string());
    }
    if let Some(rest) = value.strip_prefix('[') {
        if let Some(end) = rest.find(']') {
            let host = &rest[..end];
            let after = &rest[end + 1..];
            if let Some(port) = after.strip_prefix(':') {
                return (host.to_string(), port.to_string());
            }
            return (host.to_string(), String::new());
        }
    }
    if value.matches(':').count() == 1 {
        let (host, port) = value.rsplit_once(':').unwrap_or((value, ""));
        return (host.to_string(), port.to_string());
    }
    (value.to_string(), String::new())
}

fn caddy_query_escape(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char);
            }
            b' ' => out.push('+'),
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

fn caddy_path_escape_preserving_slashes(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char);
            }
            b'/' => out.push('/'),
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

fn caddy_request_cookie(header: &str, name: &str) -> String {
    let header = caddy_trim_ascii_space(header);
    for part in header.split(';') {
        let part = caddy_trim_ascii_space(part);
        if part.is_empty() {
            continue;
        }
        let (cookie_name, value) = part.split_once('=').unwrap_or((part, ""));
        let cookie_name = caddy_trim_ascii_space(cookie_name);
        if !caddy_cookie_name_valid(cookie_name) {
            continue;
        }
        let Some(value) = caddy_cookie_value(value) else {
            continue;
        };
        if cookie_name.eq_ignore_ascii_case(name) {
            return value.to_string();
        }
    }
    String::new()
}

fn caddy_trim_ascii_space(value: &str) -> &str {
    value.trim_matches(|ch| matches!(ch, '\t' | '\n' | '\x0b' | '\x0c' | '\r' | ' '))
}

fn caddy_cookie_name_valid(name: &str) -> bool {
    !name.is_empty() && name.bytes().all(caddy_cookie_name_byte_valid)
}

fn caddy_cookie_name_byte_valid(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
        )
}

fn caddy_cookie_value(value: &str) -> Option<&str> {
    if value.len() >= 2 && value.starts_with('"') && value.ends_with('"') {
        caddy_cookie_raw_value(&value[1..value.len() - 1])
    } else {
        caddy_cookie_raw_value(value)
    }
}

fn caddy_cookie_raw_value(value: &str) -> Option<&str> {
    value
        .bytes()
        .all(caddy_cookie_value_byte_valid)
        .then_some(value)
}

fn caddy_cookie_value_byte_valid(byte: u8) -> bool {
    (0x20..0x7f).contains(&byte) && !matches!(byte, b'"' | b';' | b'\\')
}

fn caddy_request_path_part(path: &str, index: usize) -> String {
    let mut parts = path.split('/').collect::<Vec<_>>();
    if parts.first().is_some_and(|part| part.is_empty()) {
        parts.remove(0);
    }
    parts.get(index).copied().unwrap_or("").to_string()
}

fn caddy_request_path_placeholder(path: &str, suffix: &str, original: bool) -> Option<String> {
    match suffix {
        "file" if !original => Some(caddy_path_file(path)),
        "dir" if !original => Some(caddy_path_dir(path)),
        "file.base" if !original => Some(caddy_path_file_base(path)),
        "file.ext" if !original => Some(caddy_path_file_ext(path)),
        "file" if original => Some(caddy_path_file(path)),
        "dir" if original => Some(caddy_path_dir(path)),
        _ => suffix
            .parse::<usize>()
            .ok()
            .map(|index| caddy_request_path_part(path, index)),
    }
}

fn resolve_prefixed_caddy_placeholder(
    request: &crate::script::ScriptRequest,
    metadata: &std::collections::HashMap<String, String>,
    key: &str,
) -> Option<String> {
    let (active_path, active_query) =
        caddy_active_request_uri_parts(&request.uri, &request.path, &request.query);
    if let Some(name) = key.strip_prefix("http.request.header.") {
        return Some(request.header(name).unwrap_or("").to_string());
    }
    if let Some(name) = key.strip_prefix("http.request.cookie.") {
        return Some(caddy_request_cookie(
            request.header("cookie").unwrap_or(""),
            name,
        ));
    }
    if let Some(mask) = key.strip_prefix("http.request.remote.host/") {
        return Some(caddy_remote_host_prefix(&request.peer, mask));
    }
    if let Some(name) = key.strip_prefix("http.request.uri.query.") {
        return Some(
            url::form_urlencoded::parse(active_query.as_bytes())
                .find_map(|(key, value)| (key == name).then(|| value.into_owned()))
                .unwrap_or_default(),
        );
    }
    if let Some(name) = key.strip_prefix("http.vars.") {
        return Some(
            metadata
                .get(&format!("http.vars.{name}"))
                .cloned()
                .unwrap_or_default(),
        );
    }
    if let Some(index) = key.strip_prefix("http.request.host.labels.") {
        let Ok(index) = index.parse::<usize>() else {
            return None;
        };
        let (host, _) = split_caddy_host_port(request.header("host").unwrap_or(""));
        return Some(
            host.split('.')
                .rev()
                .nth(index)
                .unwrap_or("")
                .to_ascii_lowercase(),
        );
    }
    if let Some(suffix) = key.strip_prefix("http.request.uri.path.") {
        return caddy_request_path_placeholder(&active_path, suffix, false);
    }
    if let Some(suffix) = key.strip_prefix("http.request.orig_uri.path.") {
        return caddy_request_path_placeholder(&request.original_path, suffix, true);
    }
    None
}

fn caddy_path_file(path: &str) -> String {
    path.rsplit_once('/')
        .map(|(_, file)| file)
        .unwrap_or(path)
        .to_string()
}

fn caddy_path_dir(path: &str) -> String {
    path.rfind('/')
        .map(|idx| path[..idx + 1].to_string())
        .unwrap_or_default()
}

fn caddy_path_file_base(path: &str) -> String {
    let base = caddy_go_path_base(path);
    let ext = caddy_path_file_ext(path);
    base.strip_suffix(&ext).unwrap_or(&base).to_string()
}

fn caddy_path_file_ext(path: &str) -> String {
    let start = path.rfind('/').map_or(0, |idx| idx + 1);
    let file = &path[start..];
    file.rfind('.')
        .map(|idx| file[idx..].to_string())
        .unwrap_or_default()
}

fn caddy_go_path_base(path: &str) -> String {
    if path.is_empty() {
        return ".".to_string();
    }
    let trimmed = path.trim_end_matches('/');
    if trimmed.is_empty() {
        return "/".to_string();
    }
    trimmed
        .rsplit_once('/')
        .map(|(_, file)| file)
        .unwrap_or(trimmed)
        .to_string()
}

fn caddy_var_value_to_string(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::Null => String::new(),
        serde_json::Value::Bool(value) => value.to_string(),
        serde_json::Value::Number(value) => value.to_string(),
        serde_json::Value::String(value) => value.clone(),
        serde_json::Value::Array(values) => {
            let values = values
                .iter()
                .map(caddy_var_value_to_string)
                .collect::<Vec<_>>()
                .join(" ");
            format!("[{values}]")
        }
        serde_json::Value::Object(values) => {
            let values = values
                .iter()
                .map(|(key, value)| format!("{key}:{}", caddy_var_value_to_string(value)))
                .collect::<Vec<_>>()
                .join(" ");
            format!("map[{values}]")
        }
    }
}

fn caddy_remote_host_prefix(peer: &str, mask: &str) -> String {
    let (host, _) = split_caddy_host_port(peer);
    let host_without_zone = host.split_once('%').map(|(host, _)| host).unwrap_or(&host);
    let Ok(addr) = host_without_zone.parse::<IpAddr>() else {
        return host;
    };
    let (v4_bits, v6_bits) = mask.split_once(',').unwrap_or((mask, mask));
    let bits = match addr {
        IpAddr::V4(_) => v4_bits.parse::<u8>().ok().filter(|bits| *bits <= 32),
        IpAddr::V6(_) => v6_bits.parse::<u8>().ok().filter(|bits| *bits <= 128),
    };
    let Some(bits) = bits else {
        return host;
    };
    match addr {
        IpAddr::V4(addr) => {
            let mask = if bits == 0 {
                0
            } else {
                u32::MAX << (32 - bits)
            };
            format!("{}/{}", Ipv4Addr::from(u32::from(addr) & mask), bits)
        }
        IpAddr::V6(addr) => {
            let mask = if bits == 0 {
                0
            } else {
                u128::MAX << (128 - bits)
            };
            format!("{}/{}", Ipv6Addr::from(u128::from(addr) & mask), bits)
        }
    }
}

fn ip_prefix_contains(prefix_addr: IpAddr, prefix_len: u8, candidate: IpAddr) -> bool {
    match (prefix_addr, candidate) {
        (IpAddr::V4(prefix), IpAddr::V4(candidate)) if prefix_len <= 32 => {
            let mask = if prefix_len == 0 {
                0
            } else {
                u32::MAX << (32 - prefix_len)
            };
            (u32::from(prefix) & mask) == (u32::from(candidate) & mask)
        }
        (IpAddr::V6(prefix), IpAddr::V6(candidate)) if prefix_len <= 128 => {
            let mask = if prefix_len == 0 {
                0
            } else {
                u128::MAX << (128 - prefix_len)
            };
            (u128::from(prefix) & mask) == (u128::from(candidate) & mask)
        }
        _ => false,
    }
}

pub fn h_req_replace_header(
    scope: &HelperScope,
    op_ptr: u64,
    op_len: u64,
    _: u64,
    _: u64,
    _: u64,
) -> Result<u64, ()> {
    let op = read_utf8(scope, op_ptr, op_len)?;
    let op: CaddyHeaderReplacement = serde_json::from_str(op).map_err(|_| ())?;
    with_ectx(scope, |ctx| {
        let op = expand_caddy_header_replacement(ctx, &op)?;
        if !op.search_regexp.is_empty() {
            let Ok(regex) = caddy_regex(&op.search_regexp) else {
                return Ok(0);
            };
            ctx.request
                .borrow_mut()
                .replace_header_regex(&op.name, &regex, &op.replace)?;
        } else {
            ctx.request
                .borrow_mut()
                .replace_header(&op.name, &op.search, &op.replace)?;
        }
        Ok(0)
    })
}

#[derive(serde::Deserialize)]
struct CaddyHeaderReplacement {
    #[serde(default)]
    name: String,
    #[serde(default)]
    search: String,
    #[serde(default)]
    search_regexp: String,
    #[serde(default)]
    replace: String,
}

fn expand_caddy_header_replacement(
    ctx: &mut crate::script::ScriptExecutionContext,
    op: &CaddyHeaderReplacement,
) -> Result<CaddyHeaderReplacement, ()> {
    Ok(CaddyHeaderReplacement {
        name: expand_known_caddy_placeholders(ctx, &op.name)?,
        search: expand_known_caddy_placeholders(ctx, &op.search)?,
        search_regexp: expand_known_caddy_placeholders(ctx, &op.search_regexp)?,
        replace: expand_known_caddy_placeholders(ctx, &op.replace)?,
    })
}

pub fn h_res_replace_header(
    scope: &HelperScope,
    op_ptr: u64,
    op_len: u64,
    _: u64,
    _: u64,
    _: u64,
) -> Result<u64, ()> {
    let op = read_utf8(scope, op_ptr, op_len)?;
    let op: CaddyHeaderReplacement = serde_json::from_str(op).map_err(|_| ())?;
    with_ectx(scope, |ctx| {
        let op = expand_caddy_header_replacement(ctx, &op)?;
        let name = op.name.as_str();
        if name.is_empty() {
            return Err(());
        }
        let regex = if op.search_regexp.is_empty() {
            None
        } else {
            match caddy_regex(&op.search_regexp) {
                Ok(regex) => Some(regex),
                Err(_) => return Ok(0),
            }
        };
        let Some(response_context) = &ctx.response_context else {
            return Err(());
        };
        if name != "*" && ::http::header::HeaderName::from_bytes(name.as_bytes()).is_err() {
            return Err(());
        }
        let mut response_context = response_context.borrow_mut();
        let targets = response_context
            .headers
            .keys()
            .filter(|header_name| name == "*" || header_name.as_str().eq_ignore_ascii_case(name))
            .cloned()
            .collect::<Vec<_>>();
        for target in targets {
            let values = response_context
                .headers
                .get_all(&target)
                .iter()
                .filter_map(|value| value.to_str().ok())
                .map(|value| {
                    if let Some(regex) = &regex {
                        regex.replace_all(value, op.replace.as_str()).into_owned()
                    } else {
                        value.replace(&op.search, &op.replace)
                    }
                })
                .collect::<Vec<_>>();
            response_context.headers.remove(&target);
            for value in values {
                let header_value = match ::http::header::HeaderValue::from_str(&value) {
                    Ok(value) => value,
                    Err(_) => continue,
                };
                response_context
                    .headers
                    .append(target.clone(), header_value);
            }
        }
        Ok(0)
    })
}

pub fn h_caddy_response_headers(
    scope: &HelperScope,
    ops_ptr: u64,
    ops_len: u64,
    _: u64,
    _: u64,
    _: u64,
) -> Result<u64, ()> {
    let ops = read_utf8(scope, ops_ptr, ops_len)?;
    let ops: serde_json::Value = serde_json::from_str(ops).map_err(|_| ())?;
    with_ectx(scope, |ctx| {
        if let Some(response_context) = ctx.response_context.clone() {
            let mut headers = {
                let response_context = response_context.borrow();
                response_context.headers.clone()
            };
            apply_caddy_header_ops_value(ctx, &mut headers, &ops)?;
            response_context.borrow_mut().headers = headers;
        } else {
            let mut headers = ctx.early_response_headers.borrow().clone();
            apply_caddy_header_ops_value(ctx, &mut headers, &ops)?;
            *ctx.early_response_headers.borrow_mut() = headers;
        }
        Ok(0)
    })
}

/// `zs_caddy_encode`: record the Caddy-compatible streaming response
/// compression config for this request. The actual gzip/zstd encoding is
/// applied by the response-writing path against the request `Accept-Encoding`.
pub fn h_caddy_encode(
    scope: &HelperScope,
    config_ptr: u64,
    config_len: u64,
    _: u64,
    _: u64,
    _: u64,
) -> Result<u64, ()> {
    let config = read_utf8(scope, config_ptr, config_len)?;
    let raw: crate::helpers::compress::EncodeConfigRaw =
        serde_json::from_str(config).map_err(|_| ())?;
    with_ectx(scope, |ctx| {
        // resolve() yields None only if no usable encoder is configured; in
        // that case leave any existing config untouched.
        if let Some(resolved) = crate::helpers::compress::EncodeConfig::resolve(&raw) {
            ctx.encode = Some(resolved);
        }
        Ok(0)
    })
}

fn apply_caddy_header_ops_value(
    ctx: &mut crate::script::ScriptExecutionContext,
    headers: &mut ::http::HeaderMap,
    ops: &serde_json::Value,
) -> Result<(), ()> {
    let ops = ops.as_object().ok_or(())?;
    if let Some(delete) = ops.get("delete").and_then(serde_json::Value::as_array) {
        for name in delete {
            let Some(name) = name.as_str() else {
                continue;
            };
            let name = expand_known_caddy_placeholders(ctx, name)?;
            if name == "*" {
                headers.clear();
            }
        }
    }
    if let Some(add) = ops.get("add").and_then(serde_json::Value::as_object) {
        for (name, values) in add {
            let name = expand_known_caddy_placeholders(ctx, name)?;
            let Ok(header_name) = ::http::header::HeaderName::from_bytes(name.as_bytes()) else {
                continue;
            };
            let Some(values) = values.as_array() else {
                continue;
            };
            for value in values {
                let Some(value) = value.as_str() else {
                    continue;
                };
                let value = expand_known_caddy_placeholders(ctx, value)?;
                let Ok(header_value) = ::http::header::HeaderValue::from_str(&value) else {
                    continue;
                };
                headers.append(header_name.clone(), header_value);
            }
        }
    }
    if let Some(set) = ops.get("set").and_then(serde_json::Value::as_object) {
        for (name, values) in set {
            let name = expand_known_caddy_placeholders(ctx, name)?;
            let Ok(header_name) = ::http::header::HeaderName::from_bytes(name.as_bytes()) else {
                continue;
            };
            let Some(values) = values.as_array() else {
                continue;
            };
            let mut joined = Vec::new();
            for value in values {
                let Some(value) = value.as_str() else {
                    continue;
                };
                joined.push(expand_known_caddy_placeholders(ctx, value)?);
            }
            let Ok(header_value) = ::http::header::HeaderValue::from_str(&joined.join(",")) else {
                continue;
            };
            headers.insert(header_name, header_value);
        }
    }
    if let Some(delete) = ops.get("delete").and_then(serde_json::Value::as_array) {
        for name in delete {
            let Some(name) = name.as_str() else {
                continue;
            };
            let name = expand_known_caddy_placeholders(ctx, name)?.to_ascii_lowercase();
            if name == "*" {
                continue;
            }
            let names = headers
                .keys()
                .filter(|header_name| header_pattern_matches(header_name.as_str(), &name))
                .cloned()
                .collect::<Vec<_>>();
            for name in names {
                headers.remove(name);
            }
        }
    }
    if let Some(replace) = ops.get("replace").and_then(serde_json::Value::as_object) {
        for (name, replacements) in replace {
            let Some(replacements) = replacements.as_array() else {
                continue;
            };
            for replacement in replacements {
                let mut op = CaddyHeaderReplacement {
                    name: name.clone(),
                    search: replacement
                        .get("search")
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or("")
                        .to_string(),
                    search_regexp: replacement
                        .get("search_regexp")
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or("")
                        .to_string(),
                    replace: replacement
                        .get("replace")
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or("")
                        .to_string(),
                };
                op = expand_caddy_header_replacement(ctx, &op)?;
                apply_caddy_header_replacement(headers, &op)?;
            }
        }
    }
    Ok(())
}

fn apply_caddy_header_replacement(
    headers: &mut ::http::HeaderMap,
    op: &CaddyHeaderReplacement,
) -> Result<(), ()> {
    let name = op.name.as_str();
    if name.is_empty() {
        return Ok(());
    }
    let regex = if op.search_regexp.is_empty() {
        None
    } else {
        match caddy_regex(&op.search_regexp) {
            Ok(regex) => Some(regex),
            Err(_) => return Ok(()),
        }
    };
    if name != "*" && ::http::header::HeaderName::from_bytes(name.as_bytes()).is_err() {
        return Ok(());
    }
    let targets = headers
        .keys()
        .filter(|header_name| name == "*" || header_name.as_str().eq_ignore_ascii_case(name))
        .cloned()
        .collect::<Vec<_>>();
    for target in targets {
        let values = headers
            .get_all(&target)
            .iter()
            .filter_map(|value| value.to_str().ok())
            .map(|value| {
                if let Some(regex) = &regex {
                    regex.replace_all(value, op.replace.as_str()).into_owned()
                } else {
                    value.replace(&op.search, &op.replace)
                }
            })
            .collect::<Vec<_>>();
        headers.remove(&target);
        for value in values {
            let Ok(header_value) = ::http::header::HeaderValue::from_str(&value) else {
                continue;
            };
            headers.append(target.clone(), header_value);
        }
    }
    Ok(())
}

pub fn h_caddy_res_header_match(
    scope: &HelperScope,
    name_ptr: u64,
    name_len: u64,
    value_ptr: u64,
    value_len: u64,
    _: u64,
) -> Result<u64, ()> {
    let name = read_utf8(scope, name_ptr, name_len)?;
    let value = read_utf8(scope, value_ptr, value_len)?;
    with_ectx(scope, |ctx| {
        let Some(response_context) = &ctx.response_context else {
            return Err(());
        };
        let Ok(header_name) = ::http::header::HeaderName::from_bytes(name.as_bytes()) else {
            return Ok(0);
        };
        let response_context = response_context.borrow();
        Ok(response_context
            .headers
            .get_all(header_name)
            .iter()
            .filter_map(|actual| actual.to_str().ok())
            .any(|actual| caddy_header_value_match(actual, &value)) as u64)
    })
}

pub fn h_caddy_res_header_present(
    scope: &HelperScope,
    name_ptr: u64,
    name_len: u64,
    _: u64,
    _: u64,
    _: u64,
) -> Result<u64, ()> {
    let name = read_utf8(scope, name_ptr, name_len)?;
    with_ectx(scope, |ctx| {
        let Some(response_context) = &ctx.response_context else {
            return Err(());
        };
        let Ok(header_name) = ::http::header::HeaderName::from_bytes(name.as_bytes()) else {
            return Ok(0);
        };
        Ok(response_context.borrow().headers.contains_key(header_name) as u64)
    })
}

#[derive(Debug, Default, serde::Deserialize)]
struct CaddyCopyResponseHeaders {
    #[serde(default, deserialize_with = "deserialize_null_vec")]
    include: Vec<String>,
    #[serde(default, deserialize_with = "deserialize_null_vec")]
    exclude: Vec<String>,
}

fn deserialize_null_vec<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Ok(<Option<Vec<String>> as serde::Deserialize>::deserialize(deserializer)?.unwrap_or_default())
}

pub fn h_caddy_copy_response_headers(
    scope: &HelperScope,
    config_ptr: u64,
    config_len: u64,
    _: u64,
    _: u64,
    _: u64,
) -> Result<u64, ()> {
    let config = read_utf8(scope, config_ptr, config_len)?;
    let config: CaddyCopyResponseHeaders = serde_json::from_str(config).map_err(|_| ())?;
    if !config.include.is_empty() && !config.exclude.is_empty() {
        return Err(());
    }
    let include_configured = !config.include.is_empty();
    let include = config
        .include
        .iter()
        .filter_map(|name| ::http::header::HeaderName::from_bytes(name.as_bytes()).ok())
        .collect::<Vec<_>>();
    let exclude = config
        .exclude
        .iter()
        .filter_map(|name| ::http::header::HeaderName::from_bytes(name.as_bytes()).ok())
        .collect::<Vec<_>>();
    with_ectx(scope, |ctx| {
        let Some(response_context) = &ctx.response_context else {
            return Err(());
        };
        let mut response_context = response_context.borrow_mut();
        let original = response_context.original_headers.clone();
        for name in original.keys() {
            if include_configured && !include.iter().any(|include| include == name) {
                continue;
            }
            if exclude.iter().any(|exclude| exclude == name) {
                continue;
            }
            for value in original.get_all(name).iter() {
                response_context.headers.append(name.clone(), value.clone());
            }
        }
        Ok(0)
    })
}

pub fn h_caddy_respond(
    scope: &HelperScope,
    status_ptr: u64,
    status_len: u64,
    body_ptr: u64,
    body_len: u64,
    _: u64,
) -> Result<u64, ()> {
    let status_template = read_utf8(scope, status_ptr, status_len)?;
    let body_template = read_utf8(scope, body_ptr, body_len)?;
    with_ectx(scope, |ctx| {
        if ctx.response_context.is_some() {
            ctx.error =
                "zs_caddy_respond is not supported from response hooks because it rewrites response bodies"
                    .to_string();
            return Err(());
        }
        let status = expand_caddy_status_code(ctx, status_template, 200, false)?;
        if status == 103 {
            ctx.error = "static_response.status_code 103 Early Hints cannot be represented exactly"
                .to_string();
            return Err(());
        }
        let body = expand_known_caddy_placeholders(ctx, body_template)?;
        let mut headers = Vec::new();
        let mut first_content_type = None::<String>;
        let mut extra_content_types = Vec::new();
        let early_response_headers = ctx.early_response_headers.borrow().clone();
        for header_name in early_response_headers.keys() {
            if header_name == ::http::header::CONTENT_LENGTH {
                continue;
            }
            for value in early_response_headers.get_all(header_name) {
                let value = value.to_str().map_err(|_| ())?.to_string();
                if header_name == ::http::header::CONTENT_TYPE {
                    if first_content_type.is_none() {
                        first_content_type = Some(value);
                    } else {
                        extra_content_types.push(value);
                    }
                } else {
                    headers.push((header_name.as_str().to_string(), value));
                }
            }
        }
        let first_content_type_was_explicit = first_content_type
            .as_ref()
            .is_some_and(|value| !value.is_empty());
        let content_type = match first_content_type {
            Some(value) if !value.is_empty() => Some(value),
            _ => caddy_static_response_content_type(&body),
        };
        if first_content_type_was_explicit {
            for value in extra_content_types {
                if !value.is_empty() {
                    headers.push(("content-type".to_string(), value));
                }
            }
        }
        ctx.alloc_memory_footprint(
            body.len() as u64
                + headers
                    .iter()
                    .map(|(name, value)| name.len() + value.len())
                    .sum::<usize>() as u64,
        )?;
        ctx.response = Some(ScriptResponse {
            status,
            body: body.into_bytes(),
            content_type,
            force_close: false,
            headers,
        });
        Ok(0)
    })
}

#[derive(Debug, Default, serde::Deserialize)]
struct CaddyStaticResponseConfig {
    #[serde(default)]
    body: String,
    #[serde(default)]
    headers: HashMap<String, Vec<String>>,
    #[serde(default)]
    close: bool,
}

pub fn h_caddy_respond_static(
    scope: &HelperScope,
    status_ptr: u64,
    status_len: u64,
    config_ptr: u64,
    config_len: u64,
    _: u64,
) -> Result<u64, ()> {
    let status_template = read_utf8(scope, status_ptr, status_len)?;
    let config = read_utf8(scope, config_ptr, config_len)?;
    let config: CaddyStaticResponseConfig = serde_json::from_str(config).map_err(|_| ())?;
    with_ectx(scope, |ctx| {
        if ctx.response_context.is_some() {
            ctx.error =
                "zs_caddy_respond_static is not supported from response hooks because it rewrites response bodies"
                    .to_string();
            return Err(());
        }
        let status = expand_caddy_status_code(ctx, status_template, 200, false)?;
        if status == 103 {
            ctx.error = "static_response.status_code 103 Early Hints cannot be represented exactly"
                .to_string();
            return Err(());
        }
        let body = expand_known_caddy_placeholders(ctx, &config.body)?;
        let mut headers = Vec::new();
        let mut first_content_type = None::<String>;
        let mut extra_content_types = Vec::new();

        let early_response_headers = ctx.early_response_headers.borrow().clone();
        for header_name in early_response_headers.keys() {
            if header_name == ::http::header::CONTENT_LENGTH {
                continue;
            }
            for value in early_response_headers.get_all(header_name) {
                let value = value.to_str().map_err(|_| ())?.to_string();
                if header_name == ::http::header::CONTENT_TYPE {
                    if first_content_type.is_none() {
                        first_content_type = Some(value);
                    } else {
                        extra_content_types.push(value);
                    }
                } else {
                    headers.push((header_name.as_str().to_string(), value));
                }
            }
        }

        if config.close {
            headers.push(("connection".to_string(), "close".to_string()));
        }

        for (name, values) in &config.headers {
            let name = expand_caddy_placeholders(ctx, name)?;
            let name = name.trim();
            if name.is_empty() {
                continue;
            }
            let Ok(header_name) = ::http::header::HeaderName::from_bytes(name.as_bytes()) else {
                continue;
            };
            headers.retain(|(existing, _)| !existing.eq_ignore_ascii_case(header_name.as_str()));
            if header_name == ::http::header::CONTENT_TYPE {
                first_content_type = None;
                extra_content_types.clear();
            }
            for value in values {
                let value = expand_caddy_placeholders(ctx, value)?;
                if header_name == ::http::header::CONTENT_TYPE {
                    if first_content_type.is_none() {
                        first_content_type = Some(value);
                    } else {
                        extra_content_types.push(value);
                    }
                } else {
                    headers.push((header_name.as_str().to_string(), value));
                }
            }
        }

        let first_content_type_was_explicit = first_content_type
            .as_ref()
            .is_some_and(|value| !value.is_empty());
        let content_type = if body.is_empty() {
            first_content_type.filter(|value| !value.is_empty())
        } else {
            match first_content_type {
                Some(value) if !value.is_empty() => Some(value),
                _ => caddy_static_response_content_type(&body),
            }
        };
        if first_content_type_was_explicit {
            for value in extra_content_types {
                if !value.is_empty() {
                    headers.push(("content-type".to_string(), value));
                }
            }
        }

        ctx.alloc_memory_footprint(
            body.len() as u64
                + headers
                    .iter()
                    .map(|(name, value)| name.len() + value.len())
                    .sum::<usize>() as u64,
        )?;
        ctx.response = Some(ScriptResponse {
            status,
            body: body.into_bytes(),
            content_type,
            force_close: config.close,
            headers,
        });
        Ok(0)
    })
}

fn expand_caddy_status_code(
    ctx: &crate::script::ScriptExecutionContext,
    status_template: &str,
    default: u16,
    allow_zero: bool,
) -> Result<u16, ()> {
    let status = if status_template.is_empty() {
        default.to_string()
    } else {
        expand_caddy_placeholders(ctx, status_template)?
    };
    let status = status.parse::<u16>().map_err(|_| ())?;
    if status == 0 && allow_zero {
        return Ok(status);
    }
    if !(100..=999).contains(&status) {
        return Err(());
    }
    Ok(status)
}

pub fn h_caddy_set_error(
    scope: &HelperScope,
    status_ptr: u64,
    status_len: u64,
    message_ptr: u64,
    message_len: u64,
    _: u64,
) -> Result<u64, ()> {
    let status_template = read_utf8(scope, status_ptr, status_len)?;
    let message_template = read_utf8(scope, message_ptr, message_len)?;
    with_ectx(scope, |ctx| {
        let status_code = expand_caddy_status_code(ctx, status_template, 500, false)?;
        let status = status_code.to_string();
        let status_text = ::http::StatusCode::from_u16(status_code)
            .ok()
            .and_then(|status| status.canonical_reason())
            .unwrap_or("");
        let message = expand_known_caddy_placeholders(ctx, message_template)?;
        let mut metadata = ctx.metadata.borrow_mut();
        metadata.insert("http.error.status_code".to_string(), status);
        metadata.insert(
            "http.error.status_text".to_string(),
            status_text.to_string(),
        );
        metadata.insert("http.error.message".to_string(), message.clone());
        metadata.insert("http.error".to_string(), message);
        Ok(0)
    })
}

#[derive(Debug, serde::Deserialize)]
struct CaddyBasicAuthConfig {
    #[serde(default)]
    hash: CaddyBasicAuthHash,
    #[serde(default)]
    accounts: Vec<CaddyBasicAuthAccount>,
    #[serde(default)]
    realm: String,
}

#[derive(Debug, serde::Deserialize)]
struct CaddyBasicAuthHash {
    #[serde(default = "default_caddy_basic_auth_algorithm")]
    algorithm: String,
}

impl Default for CaddyBasicAuthHash {
    fn default() -> Self {
        Self {
            algorithm: default_caddy_basic_auth_algorithm(),
        }
    }
}

fn default_caddy_basic_auth_algorithm() -> String {
    "bcrypt".to_string()
}

#[derive(Debug, serde::Deserialize)]
struct CaddyBasicAuthAccount {
    username: String,
    password: String,
}

pub fn h_caddy_basic_auth(
    scope: &HelperScope,
    config_ptr: u64,
    config_len: u64,
    _: u64,
    _: u64,
    _: u64,
) -> Result<u64, ()> {
    let config = read_utf8(scope, config_ptr, config_len)?;
    let config: CaddyBasicAuthConfig = serde_json::from_str(config).map_err(|_| ())?;
    with_ectx(scope, |ctx| {
        let credentials = ctx
            .request
            .borrow()
            .header_values
            .get("authorization")
            .and_then(|values| values.first())
            .map(String::as_str)
            .and_then(parse_basic_auth_credentials);
        let mut provider_error = None::<String>;
        let authed_user = if let Some((username, plaintext)) = credentials {
            let account = config
                .accounts
                .iter()
                .find(|account| account.username == username);
            let hash = account
                .map(|account| account.password.as_str())
                .unwrap_or_else(|| caddy_basic_auth_fake_hash(&config.hash.algorithm));
            let password_hash = caddy_basic_auth_password_hash(hash)?;
            match caddy_basic_auth_verify(&config.hash.algorithm, &password_hash, &plaintext) {
                Ok(true) if account.is_some() => Some(username),
                Ok(_) => None,
                Err(err) => {
                    provider_error = Some(err);
                    None
                }
            }
        } else {
            None
        };

        if let Some(username) = authed_user {
            let key = "http.auth.user.id";
            ctx.alloc_memory_footprint((key.len() + username.len()) as u64)?;
            ctx.metadata.borrow_mut().insert(key.to_string(), username);
            return Ok(1);
        }

        caddy_basic_auth_prompt(ctx, &config.realm, provider_error)?;
        Ok(0)
    })
}

fn parse_basic_auth_credentials(header: &str) -> Option<(String, Vec<u8>)> {
    if header.len() < 6 {
        return None;
    }
    let (scheme, encoded) = header.split_at(6);
    if !scheme.eq_ignore_ascii_case("Basic ") {
        return None;
    }
    let decoded = Base64::decode_vec(encoded).ok()?;
    let separator = decoded.iter().position(|byte| *byte == b':')?;
    let username = String::from_utf8(decoded[..separator].to_vec()).ok()?;
    Some((username, decoded[separator + 1..].to_vec()))
}

fn caddy_basic_auth_password_hash(configured: &str) -> Result<Vec<u8>, ()> {
    if configured.starts_with('$') {
        Ok(configured.as_bytes().to_vec())
    } else {
        Base64::decode_vec(configured).map_err(|_| ())
    }
}

fn caddy_basic_auth_verify(algorithm: &str, hash: &[u8], plaintext: &[u8]) -> Result<bool, String> {
    match algorithm {
        "bcrypt" => {
            let hash = std::str::from_utf8(hash).map_err(|err| err.to_string())?;
            bcrypt::verify(plaintext, hash).map_err(|err| err.to_string())
        }
        "argon2id" => {
            let hash = std::str::from_utf8(hash).map_err(|err| err.to_string())?;
            let parsed = PasswordHash::new(hash).map_err(|err| err.to_string())?;
            if parsed.algorithm.as_str() != "argon2id" {
                return Err(format!("unsupported variant: {}", parsed.algorithm));
            }
            Ok(Argon2::default()
                .verify_password(plaintext, &parsed)
                .is_ok())
        }
        _ => Err(format!("unsupported hash algorithm: {algorithm}")),
    }
}

fn caddy_basic_auth_fake_hash(algorithm: &str) -> &'static str {
    match algorithm {
        "argon2id" => {
            "$argon2id$v=19$m=47104,t=1,p=1$P2nzckEdTZ3bxCiBCkRTyA$xQL3Z32eo5jKl7u5tcIsnEKObYiyNZQQf5/4sAau6Pg"
        }
        _ => "$2a$14$X3ulqf/iGxnf1k6oMZ.RZeJUoqI9PX2PM4rS5lkIKJXduLGXGPrt6",
    }
}

fn caddy_basic_auth_prompt(
    ctx: &mut crate::script::ScriptExecutionContext,
    realm: &str,
    provider_error: Option<String>,
) -> Result<(), ()> {
    let realm = if realm.is_empty() {
        "restricted"
    } else {
        realm
    };
    let challenge = format!("Basic realm=\"{realm}\"");
    let header_value = ::http::HeaderValue::from_str(&challenge).map_err(|_| ())?;
    ctx.alloc_memory_footprint(challenge.len() as u64 + 64)?;
    ctx.early_response_headers
        .borrow_mut()
        .insert(::http::header::WWW_AUTHENTICATE, header_value);
    let mut metadata = ctx.metadata.borrow_mut();
    metadata.insert("http.error.status_code".to_string(), "401".to_string());
    metadata.insert(
        "http.error.status_text".to_string(),
        "Unauthorized".to_string(),
    );
    metadata.insert(
        "http.error.message".to_string(),
        "not authenticated".to_string(),
    );
    metadata.insert("http.error".to_string(), "not authenticated".to_string());
    if let Some(provider_error) = provider_error {
        metadata.insert("http.auth.http_basic.error".to_string(), provider_error);
    }
    Ok(())
}

fn caddy_static_response_content_type(body: &str) -> Option<String> {
    if body.is_empty() {
        return None;
    }
    let content = body.trim();
    if content.len() > 2
        && ((content.starts_with('{') && content.ends_with('}'))
            || (content.starts_with('[') && content.ends_with(']')))
        && serde_json::from_str::<serde_json::Value>(content).is_ok()
    {
        Some("application/json".to_string())
    } else {
        Some("text/plain; charset=utf-8".to_string())
    }
}

pub fn h_caddy_reverse_proxy_url(
    scope: &HelperScope,
    url_template_ptr: u64,
    url_template_len: u64,
    out_ptr: u64,
    out_len: u64,
    _: u64,
) -> Result<u64, ()> {
    let url_template = read_utf8(scope, url_template_ptr, url_template_len)?;
    with_ectx(scope, |ctx| {
        let url = expand_caddy_placeholders(ctx, url_template)?;
        set_caddy_reverse_proxy_placeholders(ctx, &url);
        deref_and_write_cstr(scope, out_ptr, out_len, &url)
    })
}

pub fn h_caddy_reverse_proxy_rewrite(
    scope: &HelperScope,
    config_ptr: u64,
    config_len: u64,
    _: u64,
    _: u64,
    _: u64,
) -> Result<u64, ()> {
    let config = read_utf8(scope, config_ptr, config_len)?;
    let config: CaddyReverseProxyRewrite = serde_json::from_str(config).map_err(|_| ())?;
    with_ectx(scope, |ctx| {
        let mut proxy_request = ctx.request.borrow().clone();
        if !config.method.is_empty() {
            let method = expand_caddy_placeholders(ctx, &config.method)?.to_ascii_uppercase();
            proxy_request.set_method(&method)?;
        }
        if !config.uri.is_empty() {
            apply_caddy_uri_template(ctx, &mut proxy_request, &config.uri)?;
        }
        apply_caddy_uri_ops(ctx, &mut proxy_request, &config.uri_ops)?;
        if let Some(query) = &config.query {
            apply_caddy_query_ops(ctx, &mut proxy_request, query)?;
        }

        let mut request = ctx.request.borrow_mut();
        request.set_proxy_method(&proxy_request.method)?;
        request.set_proxy_uri(&proxy_request.uri)?;
        Ok(0)
    })
}

#[derive(Default, serde::Deserialize)]
struct CaddyReverseProxyRewrite {
    #[serde(default)]
    method: String,
    #[serde(default)]
    uri: String,
    #[serde(flatten)]
    uri_ops: CaddyUriRewriteOps,
    #[serde(default)]
    query: Option<CaddyQueryOps>,
}

fn set_caddy_reverse_proxy_placeholders(ctx: &crate::script::ScriptExecutionContext, url: &str) {
    let mut metadata = ctx.metadata.borrow_mut();
    if let Ok(parsed) = ::url::Url::parse(url) {
        let host = parsed.host_str().unwrap_or("").to_string();
        let port = parsed
            .port_or_known_default()
            .map(|port| port.to_string())
            .unwrap_or_default();
        let hostport = caddy_reverse_proxy_hostport(&parsed);
        metadata.insert(
            "http.reverse_proxy.upstream.address".to_string(),
            hostport.clone(),
        );
        metadata.insert("http.reverse_proxy.upstream.hostport".to_string(), hostport);
        metadata.insert("http.reverse_proxy.upstream.host".to_string(), host);
        metadata.insert("http.reverse_proxy.upstream.port".to_string(), port);
    } else {
        metadata.insert(
            "http.reverse_proxy.upstream.address".to_string(),
            String::new(),
        );
        metadata.insert(
            "http.reverse_proxy.upstream.hostport".to_string(),
            String::new(),
        );
        metadata.insert(
            "http.reverse_proxy.upstream.host".to_string(),
            String::new(),
        );
        metadata.insert(
            "http.reverse_proxy.upstream.port".to_string(),
            String::new(),
        );
    }
    metadata.insert(
        "http.reverse_proxy.upstream.requests".to_string(),
        "0".to_string(),
    );
    metadata.insert(
        "http.reverse_proxy.upstream.max_requests".to_string(),
        "0".to_string(),
    );
    metadata.insert(
        "http.reverse_proxy.upstream.fails".to_string(),
        "0".to_string(),
    );
}

fn caddy_reverse_proxy_hostport(parsed: &::url::Url) -> String {
    let Some(host) = parsed.host() else {
        return String::new();
    };
    let Some(port) = parsed.port_or_known_default() else {
        return host.to_string();
    };
    format!("{host}:{port}")
}

pub fn h_file_server(
    scope: &HelperScope,
    config_ptr: u64,
    config_len: u64,
    _: u64,
    _: u64,
    _: u64,
) -> Result<u64, ()> {
    let config = read_utf8(scope, config_ptr, config_len)?;
    let config: CaddyFileServer = serde_json::from_str(config).map_err(|_| ())?;
    with_ectx(scope, |ctx| {
        if ctx.response.is_some() || ctx.reverse_proxy.is_some() || ctx.file_server.is_some() {
            return Err(());
        }
        let Some(config) = expand_caddy_file_server_config(ctx, config)? else {
            return Ok(0);
        };
        if caddy_file_server_unsupported_fs(&config.fs) {
            caddy_file_matcher_set_error(ctx, 404);
            return Ok(2);
        }
        if config.pass_thru {
            let path = ctx.request.borrow().normalized_path.clone();
            if !caddy_file_server_would_handle(ctx, &config, &path) {
                return Ok(1);
            }
        }
        ctx.file_server = Some(config);
        Ok(0)
    })
}

fn expand_caddy_file_server_config(
    ctx: &mut crate::script::ScriptExecutionContext,
    mut config: CaddyFileServer,
) -> Result<Option<CaddyFileServer>, ()> {
    config.fs = expand_caddy_defaulted_placeholder(ctx, &config.fs, "{http.vars.fs}", "")?;
    config.root = expand_caddy_defaulted_placeholder(ctx, &config.root, "{http.vars.root}", ".")?;
    for value in &mut config.hide {
        *value = expand_caddy_placeholders(ctx, value)?;
    }
    if let Some(index_names) = &mut config.index_names {
        for value in index_names {
            *value = expand_caddy_placeholders(ctx, value)?;
        }
    }
    if let Some(status_code) = &mut config.status_code {
        *status_code = expand_caddy_placeholders(ctx, status_code)?;
        let Ok(code) = status_code.parse::<u16>() else {
            ctx.response = Some(ScriptResponse {
                status: 500,
                body: Vec::new(),
                content_type: None,
                force_close: false,
                headers: Vec::new(),
            });
            return Ok(None);
        };
        if code == 103 || (code != 0 && ::http::StatusCode::from_u16(code).is_err()) {
            return Err(());
        }
    }
    Ok(Some(config))
}

fn expand_caddy_defaulted_placeholder(
    ctx: &crate::script::ScriptExecutionContext,
    configured: &str,
    default_template: &str,
    missing_fallback: &str,
) -> Result<String, ()> {
    if configured.is_empty() {
        let expanded = expand_caddy_placeholders_inner(ctx, default_template, true)?;
        if expanded.is_empty() {
            Ok(missing_fallback.to_string())
        } else {
            Ok(expanded)
        }
    } else {
        expand_caddy_placeholders(ctx, configured)
    }
}

fn caddy_file_server_would_handle(
    ctx: &crate::script::ScriptExecutionContext,
    config: &CaddyFileServer,
    path: &str,
) -> bool {
    if caddy_file_server_unsupported_fs(&config.fs) {
        return false;
    }
    let root = caddy_file_matcher_root(&config.root, caddy_fs_name_forces_filesystem(&config.fs));
    match root {
        CaddyFileMatcherRoot::Tar(root) => {
            caddy_tar_file_server_would_handle(ctx, config, path, &root)
        }
        CaddyFileMatcherRoot::Fs(root) => {
            ctx.expose_filesystem && caddy_fs_file_server_would_handle(config, path, &root)
        }
    }
}

fn caddy_file_server_unsupported_fs(fs: &str) -> bool {
    !fs.is_empty() && fs != "file" && fs != "default" && fs != "{http.vars.fs}"
}

fn caddy_tar_file_server_would_handle(
    ctx: &crate::script::ScriptExecutionContext,
    config: &CaddyFileServer,
    path: &str,
    root: &str,
) -> bool {
    let Some(rel) = join_caddy_file_path(root, path) else {
        return false;
    };
    if let Some(entry) = ctx.site.entries.get(&rel) {
        return !caddy_file_hidden(&entry.path, &config.hide);
    }
    if !ctx.site.directories.contains(&rel) && !path.is_empty() {
        return false;
    }

    let indexes = config
        .index_names
        .clone()
        .unwrap_or_else(|| vec!["index.html".to_string(), "index.txt".to_string()]);
    for index in indexes {
        let Some(index_path) = join_caddy_file_path(&rel, &index) else {
            continue;
        };
        if caddy_file_hidden(&index_path, &config.hide) {
            continue;
        }
        if let Some(entry) = ctx.site.entries.get(&index_path) {
            return !caddy_file_hidden(&entry.path, &config.hide);
        }
    }

    config.browse.is_some() && !caddy_file_hidden(&rel, &config.hide)
}

fn caddy_fs_file_server_would_handle(config: &CaddyFileServer, path: &str, root: &Path) -> bool {
    let Some(mut candidate) = caddy_fs_match_join(root, path) else {
        return false;
    };
    let mut meta = match fs::metadata(&candidate) {
        Ok(meta) => meta,
        Err(err) => {
            return !matches!(
                err.kind(),
                std::io::ErrorKind::NotFound | std::io::ErrorKind::NotADirectory
            );
        }
    };

    let indexes = config
        .index_names
        .clone()
        .unwrap_or_else(|| vec!["index.html".to_string(), "index.txt".to_string()]);

    let logical = join_caddy_file_path("", path).unwrap_or_else(|| path.to_string());
    if meta.is_dir() {
        for index in indexes {
            let Some(index_path) = caddy_fs_match_join(&candidate, &index) else {
                continue;
            };
            let index_logical = join_caddy_file_path(&logical, &index).unwrap_or(index);
            if caddy_fs_file_hidden(&index_logical, &index_path, &config.hide) {
                continue;
            }
            let Ok(index_meta) = fs::metadata(&index_path) else {
                continue;
            };
            if index_meta.is_file() {
                candidate = index_path;
                meta = index_meta;
                break;
            }
        }
        if meta.is_dir() {
            return config.browse.is_some()
                && !caddy_fs_file_hidden(&logical, &candidate, &config.hide);
        }
    }

    meta.is_file() && !caddy_fs_file_hidden(&logical, &candidate, &config.hide)
}

fn caddy_glob_pattern_outside_placeholders(value: &str) -> bool {
    let mut in_placeholder = false;
    let mut escaped = false;
    for ch in value.chars() {
        if escaped {
            escaped = false;
            continue;
        }
        match ch {
            '\\' => escaped = true,
            '{' => in_placeholder = true,
            '}' => in_placeholder = false,
            '*' | '?' | '[' if !in_placeholder => return true,
            _ => {}
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rewrite_caddy_query_without_placeholders(query: &str, ops: &CaddyQueryOps) -> String {
        rewrite_caddy_query_with_expanders(
            query,
            ops,
            |value| Ok(value.to_string()),
            |value| Ok(value.to_string()),
        )
        .unwrap()
    }

    fn caddy_placeholder_request() -> crate::script::ScriptRequest {
        let mut headers = std::collections::HashMap::new();
        headers.insert("host".to_string(), "api.Example.test:8080".to_string());
        crate::script::ScriptRequest {
            request_id: ulid::Ulid::new(),
            start_time: std::time::Instant::now(),
            method: "GET".to_string(),
            original_method: "GET".to_string(),
            path: "/one/two".to_string(),
            original_path: "/orig/one".to_string(),
            normalized_path: "one/two".to_string(),
            uri: "/one/two?x=1".to_string(),
            original_uri: "/orig/one?before=1".to_string(),
            query: "x=1".to_string(),
            original_query: "before=1".to_string(),
            scheme: "http".to_string(),
            proto_major: 1,
            proto_minor: 1,
            peer: "127.0.0.1:12345".to_string(),
            local: "127.0.0.1:80".to_string(),
            headers,
            header_values: std::collections::HashMap::new(),
            transfer_encodings: Vec::new(),
            query_params: std::collections::HashMap::new(),
            query_param_values: std::collections::HashMap::new(),
            caddy_query_params: std::collections::HashMap::new(),
            caddy_query_valid: true,
            connection: crate::script::ConnectionInfo::default(),
            proxy_method: None,
            proxy_uri: None,
            proxy_headers: None,
            uri_changed: false,
            method_changed: false,
            header_changes: Vec::new(),
        }
    }

    #[test]
    fn escaped_path_subject_rejects_bad_percent_triplet_before_utf8_without_panic() {
        assert_eq!(caddy_escaped_path_match_subject("/%aé", "/%a*"), None);
    }

    #[test]
    fn escaped_path_subject_keeps_raw_utf8_on_char_boundaries() {
        assert_eq!(
            caddy_escaped_path_match_subject("/é/x", "/*/x").as_deref(),
            Some("/é/x")
        );
    }

    #[test]
    fn caddy_escaped_path_match_uses_glob_rules_without_fast_prefix_match() {
        assert!(caddy_match_path("/bands/ac%2fdc", "/bands/%*").unwrap());
        assert!(!caddy_match_path("/bands/ac/dc", "/bands/%*").unwrap());
    }

    #[test]
    fn caddy_path_match_follows_escaped_slash_semantics() {
        assert!(caddy_match_path("/foo%2Fbar/baz", "/foo%2fbar/baz").unwrap());
        assert!(!caddy_match_path("/foo/bar/baz", "/foo%2fbar/baz").unwrap());
        assert!(caddy_match_path("/foo%2fbar/baz", "/foo/bar/baz").unwrap());
        assert!(caddy_match_path("/bands/ac%2fdc/t.n.t", "/bands/%*/%*").unwrap());
        assert!(!caddy_match_path("/bands/ac%2fdc/t.n.t", "/bands/*/*").unwrap());
        assert!(!caddy_match_path("/bands/ac/dc/t.n.t", "/bands/%*/%*").unwrap());
        assert!(!caddy_match_path("/bands/ac/dc", "/bands/%*").unwrap());
        assert!(caddy_match_path("/foo///bar", "/foo/%*//bar").unwrap());
        assert!(caddy_match_path("/foo//%2fbar", "/foo/%*//bar").unwrap());
    }

    #[test]
    fn caddy_path_glob_preserves_trailing_and_double_slashes() {
        assert!(!caddy_match_path("/foo/bar", "/foo/bar/").unwrap());
        assert!(caddy_match_path("/foo/bar/", "/foo/bar/").unwrap());
        assert!(!caddy_match_path("/foo", "//foo").unwrap());
        assert!(caddy_match_path("//foo", "//foo").unwrap());
    }

    #[test]
    fn caddy_path_glob_rejects_invalid_patterns() {
        assert!(!caddy_match_path("/bad/[", "/bad/[").unwrap());
        assert!(!caddy_match_path("/bad/trail\\", "/bad/trail\\").unwrap());
        assert!(!caddy_match_path("/bad/-", "/bad/[-]").unwrap());
        assert!(!caddy_match_path("/bad/-", "/bad/[a-]").unwrap());
    }

    #[test]
    fn caddy_path_glob_uses_go_class_syntax() {
        assert!(caddy_match_path("/class/!", "/class/[!]").unwrap());
        assert!(!caddy_match_path("/class/x", "/class/[!]").unwrap());
        assert!(caddy_match_path("/class/x", "/class/[^a]").unwrap());
        assert!(caddy_match_path("/class/-", "/class/[\\-]").unwrap());
        assert!(caddy_match_path("/class/-", "/class/[a\\-]").unwrap());
    }

    #[test]
    fn caddy_rewrite_trim_prefix_matches_escaped_path_semantics() {
        assert_eq!(trim_path_prefix_caddy("/a%2Fb/c/d", "/a/b/c"), "/d");
        assert_eq!(trim_path_prefix_caddy("/a%2fb/c/d", "/a%2Fb/c"), "/d");
        assert_eq!(trim_path_prefix_caddy("/a/b/c/d", "/a%2Fb/c"), "/a/b/c/d");
        assert_eq!(trim_path_prefix_caddy("/a/b/c/d", "//a%2Fb/c"), "/a/b/c/d");
    }

    #[test]
    fn caddy_rewrite_strip_suffix_uses_expanded_double_slash_semantics() {
        let path = "/api/foo//bar";
        let suffix = "foo//bar";
        let cleaned = clean_path_caddy(path, !suffix.contains("//"));
        let stripped = reverse_string(&trim_path_prefix_caddy(
            &reverse_string(&cleaned),
            &reverse_string(suffix),
        ));
        assert_eq!(stripped, "/api/");
    }

    #[test]
    fn caddy_rewrite_path_escape_preserves_slashes() {
        assert_eq!(
            caddy_path_escape_preserving_slashes("/dir/literal?name #1.txt"),
            "/dir/literal%3Fname%20%231.txt"
        );
    }

    #[test]
    fn caddy_rewrite_empty_substring_find_uses_default_replace_all_limit() {
        assert_eq!(replace_with_limit("abc", "", "-", 0), "-a-b-c-");
        assert_eq!(replace_with_limit("abc", "", "-", -1), "-a-b-c-");
        assert_eq!(replace_with_limit("abc", "", "-", 2), "-a-bc");
    }

    #[test]
    fn caddy_cookie_placeholder_follows_go_request_cookie_parsing() {
        assert_eq!(
            caddy_request_cookie("Foo=first; foo=second", "foo"),
            "first"
        );
        assert_eq!(caddy_request_cookie("empty; next=value", "empty"), "");
        assert_eq!(caddy_request_cookie("first=; next=value", "next"), "value");
        assert_eq!(
            caddy_request_cookie(" spaced = bar ; next=value", "spaced"),
            " bar"
        );
        assert_eq!(
            caddy_request_cookie("quoted=\"bar baz\"; next=value", "quoted"),
            "bar baz"
        );
        assert_eq!(
            caddy_request_cookie("quoted= \"bar baz\" ; next=value", "quoted"),
            ""
        );
        assert_eq!(
            caddy_request_cookie("bad name=skip; good=value", "good"),
            "value"
        );
        assert_eq!(
            caddy_request_cookie("bad=\"unterminated; good=value", "good"),
            "value"
        );
    }

    #[test]
    fn caddy_invalid_indexed_placeholders_remain_unknown() {
        let request = caddy_placeholder_request();
        let metadata = std::collections::HashMap::new();

        assert_eq!(
            resolve_prefixed_caddy_placeholder(&request, &metadata, "http.request.host.labels.0")
                .as_deref(),
            Some("test")
        );
        assert_eq!(
            resolve_prefixed_caddy_placeholder(&request, &metadata, "http.request.host.labels.99")
                .as_deref(),
            Some("")
        );
        assert_eq!(
            resolve_prefixed_caddy_placeholder(&request, &metadata, "http.request.host.labels.x"),
            None
        );
        assert_eq!(
            resolve_prefixed_caddy_placeholder(&request, &metadata, "http.request.uri.path.1")
                .as_deref(),
            Some("two")
        );
        assert_eq!(
            resolve_prefixed_caddy_placeholder(&request, &metadata, "http.request.uri.path.99")
                .as_deref(),
            Some("")
        );
        assert_eq!(
            resolve_prefixed_caddy_placeholder(&request, &metadata, "http.request.uri.path.x"),
            None
        );
        assert_eq!(
            resolve_prefixed_caddy_placeholder(&request, &metadata, "http.request.orig_uri.path.0")
                .as_deref(),
            Some("orig")
        );
        assert_eq!(
            resolve_prefixed_caddy_placeholder(
                &request,
                &metadata,
                "http.request.orig_uri.path.file.base"
            ),
            None
        );
    }

    #[test]
    fn caddy_query_replace_named_key_matches_all_values() {
        let ops = CaddyQueryOps {
            replace: vec![CaddyQueryReplacement {
                key: "target".to_string(),
                search: "raw".to_string(),
                replace: "cooked".to_string(),
                search_regexp: String::new(),
            }],
            ..Default::default()
        };

        assert_eq!(
            rewrite_caddy_query_without_placeholders("target=raw&other=raw&target=raw2", &ops),
            "other=cooked&target=cooked&target=cooked2"
        );
    }

    #[test]
    fn caddy_query_regex_replace_named_key_matches_all_values() {
        let ops = CaddyQueryOps {
            replace: vec![CaddyQueryReplacement {
                key: "target".to_string(),
                search_regexp: "a+".to_string(),
                replace: "x".to_string(),
                search: String::new(),
            }],
            ..Default::default()
        };

        assert_eq!(
            rewrite_caddy_query_without_placeholders("target=aa&other=baaa", &ops),
            "other=bx&target=x"
        );
    }

    #[test]
    fn caddy_rewrite_path_file_relative_placeholder_is_origin_form() {
        assert_eq!(
            caddy_rewrite_path_file_relative_placeholder("test.php"),
            "/test.php"
        );
        assert_eq!(
            caddy_rewrite_path_file_relative_placeholder("/test.php"),
            "/test.php"
        );
        assert_eq!(
            caddy_rewrite_path_file_relative_placeholder("dir/has space.php"),
            "/dir/has%20space.php"
        );
    }

    #[test]
    fn caddy_forwarded_header_lookup_distinguishes_absent_and_empty() {
        let mut headers = ::http::HeaderMap::new();

        assert_eq!(
            caddy_header_map_all_values(&headers, "X-Forwarded-For"),
            (String::new(), false)
        );
        assert_eq!(
            caddy_header_map_last_value_with_ok(&headers, "X-Forwarded-Proto"),
            (String::new(), false)
        );

        headers.insert("X-Forwarded-For", ::http::HeaderValue::from_static(""));
        headers.insert("X-Forwarded-Proto", ::http::HeaderValue::from_static(""));

        assert_eq!(
            caddy_header_map_all_values(&headers, "X-Forwarded-For"),
            (String::new(), true)
        );
        assert_eq!(
            caddy_header_map_last_value_with_ok(&headers, "X-Forwarded-Proto"),
            (String::new(), true)
        );
    }

    #[test]
    fn caddy_path_file_and_dir_follow_go_path_split() {
        assert_eq!(caddy_path_file("leaf.txt"), "leaf.txt");
        assert_eq!(caddy_path_dir("leaf.txt"), "");
        assert_eq!(caddy_path_file_base("leaf.txt"), "leaf");
        assert_eq!(caddy_path_file_ext("leaf.txt"), ".txt");
        assert_eq!(caddy_path_file("dir/leaf.txt"), "leaf.txt");
        assert_eq!(caddy_path_dir("dir/leaf.txt"), "dir/");
        assert_eq!(caddy_path_file("/dir/leaf.txt"), "leaf.txt");
        assert_eq!(caddy_path_dir("/dir/leaf.txt"), "/dir/");
        assert_eq!(caddy_path_file("/dir/"), "");
        assert_eq!(caddy_path_dir("/dir/"), "/dir/");
        assert_eq!(caddy_path_file_base("/dir/"), "dir");
        assert_eq!(caddy_path_file_ext("/dir/"), "");
        assert_eq!(caddy_path_file_base("/foo/bar.tar.gz"), "bar.tar");
        assert_eq!(caddy_path_file_ext("/foo/bar.tar.gz"), ".gz");
        assert_eq!(caddy_path_file_base(".profile"), "");
        assert_eq!(caddy_path_file_ext(".profile"), ".profile");
        assert_eq!(caddy_path_file_base(""), ".");
        assert_eq!(caddy_path_file_ext(""), "");
        assert_eq!(caddy_path_file("/"), "");
        assert_eq!(caddy_path_dir("/"), "/");
        assert_eq!(caddy_path_file_base("/"), "/");
        assert_eq!(caddy_path_file_ext("/"), "");
    }

    #[test]
    fn caddy_file_hide_path_prefix_hides_descendants() {
        let hide = vec!["public/assets/private".to_string()];
        assert!(caddy_file_hidden("public/assets/private", &hide));
        assert!(caddy_file_hidden("public/assets/private/nested.txt", &hide));
        assert!(!caddy_file_hidden("public/assets/private-ish.txt", &hide));

        let hide = vec!["/public/assets/private".to_string()];
        assert!(!caddy_file_hidden("public/assets/private", &hide));
    }

    #[test]
    fn explicit_caddy_file_matcher_filesystem_forces_filesystem_roots() {
        match caddy_file_matcher_root("public", false) {
            CaddyFileMatcherRoot::Tar(root) => assert_eq!(root, "public"),
            CaddyFileMatcherRoot::Fs(root) => panic!("unexpected filesystem root: {root:?}"),
        }

        match caddy_file_matcher_root("/", false) {
            CaddyFileMatcherRoot::Fs(root) => assert_eq!(root, PathBuf::from("/")),
            CaddyFileMatcherRoot::Tar(root) => panic!("unexpected tar root: {root:?}"),
        }

        match caddy_file_matcher_root("public", true) {
            CaddyFileMatcherRoot::Fs(root) => assert_eq!(root, PathBuf::from("public")),
            CaddyFileMatcherRoot::Tar(root) => panic!("unexpected tar root: {root:?}"),
        }

        assert!(caddy_fs_name_forces_filesystem("default"));
        assert!(caddy_fs_name_forces_filesystem("file"));
        assert!(!caddy_fs_name_forces_filesystem(""));
    }

    #[test]
    fn caddy_file_matcher_placeholder_values_are_glob_safe() {
        assert_eq!(
            caddy_file_glob_escape("/literal[abc]*?.txt"),
            "/literal\\[abc]\\*\\?.txt"
        );
        assert_eq!(
            caddy_file_unescape_glob_literals("/literal\\[abc]\\*\\?.txt"),
            "/literal[abc]*?.txt"
        );
        assert!(glob_match(
            &caddy_file_glob_escape("literal[abc].txt"),
            "literal[abc].txt"
        ));
        assert!(!glob_match(
            &caddy_file_glob_escape("literal[abc].txt"),
            "literala.txt"
        ));
    }

    #[test]
    fn caddy_file_split_path_follows_current_caddy_search_bounds() {
        let split_path = vec![".php".to_string()];
        assert_eq!(
            first_caddy_file_split("/index.php", &split_path),
            ("/index.php".to_string(), String::new())
        );
        assert_eq!(
            first_caddy_file_split("/index.php/foo", &split_path),
            ("/index.php".to_string(), "/foo".to_string())
        );
    }

    #[test]
    fn caddy_reverse_proxy_hostport_includes_default_scheme_ports() {
        assert_eq!(
            caddy_reverse_proxy_hostport(&::url::Url::parse("http://example.test").unwrap()),
            "example.test:80"
        );
        assert_eq!(
            caddy_reverse_proxy_hostport(&::url::Url::parse("https://example.test").unwrap()),
            "example.test:443"
        );
        assert_eq!(
            caddy_reverse_proxy_hostport(&::url::Url::parse("http://[::1]").unwrap()),
            "[::1]:80"
        );
        assert_eq!(
            caddy_reverse_proxy_hostport(&::url::Url::parse("http://example.test:8080").unwrap()),
            "example.test:8080"
        );
    }

    #[test]
    fn copy_response_headers_config_accepts_null_lists() {
        let config: CaddyCopyResponseHeaders =
            serde_json::from_str(r#"{"include":null,"exclude":null}"#).unwrap();
        assert!(config.include.is_empty());
        assert!(config.exclude.is_empty());
    }

    #[test]
    fn remote_host_prefix_strips_ipv6_zone_for_parse_and_falls_back_on_bad_mask() {
        assert_eq!(
            caddy_remote_host_prefix("[fe80::1%eth0]:443", "64"),
            "fe80::/64"
        );
        assert_eq!(
            caddy_remote_host_prefix("[fe80::1%eth0]:443", "bad"),
            "fe80::1%eth0"
        );
    }
}
