//! Per-directive Caddyfile handlers, ported from `httpcaddyfile/builtins.go` and
//! the module `UnmarshalCaddyfile`/`parseCaddyfile` functions in
//! `modules/caddyhttp`. Also hosts the directive ordering, route sorting, and
//! subroute building (`directives.go`, `httptype.go`).

use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;

use anyhow::{Result, bail};
use serde_json::{Map, Value, json};

use super::matchers;
use super::{ConfigValue, Counter, Helper, Route, RouteOrSub, Subroute};
use crate::caddyfile::address::join_host_port;
use crate::caddyfile::dispenser::Dispenser;
use crate::caddyfile::token::Token;

/// The canonical order in which directives are applied within an HTTP route.
/// Port of `defaultDirectiveOrder`.
pub const DIRECTIVE_ORDER: &[&str] = &[
    "tracing",
    "map",
    "vars",
    "fs",
    "root",
    "log_append",
    "skip_log",
    "log_skip",
    "log_name",
    "log",
    "header",
    "copy_response_headers",
    "request_body",
    "zeroserve_call",
    "redir",
    "method",
    "rewrite",
    "uri",
    "try_files",
    "basicauth",
    "basic_auth",
    "forward_auth",
    "request_header",
    "encode",
    "push",
    "intercept",
    "templates",
    "invoke",
    "handle",
    "handle_path",
    "route",
    "abort",
    "error",
    "copy_response",
    "respond",
    "metrics",
    "reverse_proxy",
    "php_fastcgi",
    "file_server",
    "acme_server",
];

/// Normalizes a directive name for sorting. Port of `normalizeDirectiveName`.
pub fn normalize_directive_name(directive: &str) -> String {
    if directive == "handle_path" {
        "handle".to_string()
    } else {
        directive.to_string()
    }
}

fn directive_position(dir: &str, order: &[String]) -> usize {
    order.iter().position(|d| d == dir).unwrap_or(usize::MAX)
}

/// Dispatches a directive to its handler, returning `None` if the directive is
/// unrecognized.
pub fn dispatch(dir: &str, h: &mut Helper) -> Result<Option<Vec<ConfigValue>>> {
    let out = match dir {
        // Handler-directives (RegisterHandlerDirective): matcher handled here.
        "respond" => handler_directive(h, parse_respond)?,
        "error" => handler_directive(h, parse_error)?,
        "abort" => handler_directive(h, parse_abort)?,
        "redir" => handler_directive(h, parse_redir)?,
        "vars" => handler_directive(h, parse_vars)?,
        "map" => handler_directive(h, parse_map)?,
        "log_append" => handler_directive(h, parse_log_append)?,
        "tracing" => handler_directive(h, parse_tracing)?,
        "basicauth" | "basic_auth" => handler_directive_helper(h, parse_basic_auth)?,
        "skip_log" | "log_skip" => handler_directive_helper(h, parse_log_skip)?,
        "log_name" => handler_directive(h, parse_log_name)?,
        "request_body" => handler_directive(h, parse_request_body)?,
        "zeroserve_call" => handler_directive(h, parse_zeroserve_call)?,
        "file_server" => handler_directive_helper(h, parse_file_server)?,
        "reverse_proxy" => handler_directive_helper(h, parse_reverse_proxy)?,
        "forward_auth" => parse_forward_auth(h)?,
        "method" => handler_directive(h, parse_method)?,
        "uri" => handler_directive(h, parse_uri)?,
        "fs" => handler_directive(h, parse_fs)?,
        "intercept" => handler_directive_helper(h, parse_intercept)?,
        "copy_response" => handler_directive(h, parse_copy_response)?,
        "copy_response_headers" => handler_directive(h, parse_copy_response_headers)?,
        "encode" => handler_directive(h, parse_encode)?,
        "templates" => handler_directive(h, parse_templates)?,
        "metrics" => handler_directive(h, parse_metrics)?,
        "push" => handler_directive(h, parse_push)?,
        "invoke" => handler_directive(h, parse_invoke)?,
        "acme_server" => handler_directive_helper(h, parse_acme_server)?,

        // Full directives (RegisterDirective): own matcher handling / multi-route.
        "header" => parse_header(h)?,
        "request_header" => parse_request_header(h)?,
        "rewrite" => parse_rewrite(h)?,
        "try_files" => parse_try_files(h)?,
        "root" => parse_root(h)?,
        "php_fastcgi" => parse_php_fastcgi(h)?,
        "bind" => parse_bind(h)?,
        "tls" => parse_tls(h)?,
        "log" => parse_log(h)?,
        // handle/route are handler-directives: the wrapper extracts the matcher.
        "handle" => handler_directive_helper(h, parse_handle)?,
        "route" => handler_directive_helper(h, parse_route)?,
        "handle_path" => parse_handle_path(h)?,
        "handle_errors" => parse_handle_errors(h)?,

        _ => return Ok(None),
    };
    Ok(Some(out))
}

/// Wraps a handler-producing setup fn: consumes the directive, extracts an
/// optional matcher, then wraps the handler in a route. Port of
/// `RegisterHandlerDirective`.
fn handler_directive(
    h: &mut Helper,
    setup: fn(&mut Dispenser) -> Result<Value>,
) -> Result<Vec<ConfigValue>> {
    h.d.next();
    let matcher = h.extract_matcher_set()?;
    let handler = setup(&mut h.d)?;
    Ok(h.new_route(matcher, handler))
}

/// Like [`handler_directive`] but the setup needs the full [`Helper`] (e.g.
/// `handle`/`route`, which recurse into sub-directives needing the group counter
/// and matcher definitions).
fn handler_directive_helper(
    h: &mut Helper,
    setup: fn(&mut Helper) -> Result<Value>,
) -> Result<Vec<ConfigValue>> {
    h.d.next();
    let matcher = h.extract_matcher_set()?;
    let handler = setup(h)?;
    Ok(h.new_route(matcher, handler))
}

// --- static responses ---------------------------------------------------------

fn parse_respond(d: &mut Dispenser) -> Result<Value> {
    d.next();
    let args = d.remaining_args();
    let mut status = String::new();
    let mut body = String::new();
    match args.len() {
        1 => {
            if is_status_code(&args[0]) {
                status = args[0].clone();
            } else {
                body = args[0].clone();
            }
        }
        2 => {
            body = args[0].clone();
            status = args[1].clone();
        }
        _ => return Err(d.arg_err()),
    }
    let mut close = false;
    while d.next_block(0) {
        match d.val().as_str() {
            "body" => {
                if !body.is_empty() {
                    bail!("body already specified");
                }
                if !d.all_args(&mut [&mut body]) {
                    return Err(d.arg_err());
                }
            }
            "close" => {
                if close {
                    bail!("close already specified");
                }
                close = true;
            }
            other => bail!("unrecognized subdirective '{other}'"),
        }
    }
    let mut m = Map::new();
    m.insert("handler".into(), json!("static_response"));
    if !status.is_empty() {
        m.insert("status_code".into(), weak_string(&status));
    }
    if !body.is_empty() {
        m.insert("body".into(), json!(body));
    }
    if close {
        m.insert("close".into(), json!(true));
    }
    Ok(Value::Object(m))
}

fn parse_error(d: &mut Dispenser) -> Result<Value> {
    d.next();
    let args = d.remaining_args();
    let mut status = String::new();
    let mut error = String::new();
    match args.len() {
        1 => {
            if is_status_code(&args[0]) {
                status = args[0].clone();
            } else {
                error = args[0].clone();
            }
        }
        2 => {
            error = args[0].clone();
            status = args[1].clone();
        }
        _ => return Err(d.arg_err()),
    }
    while d.next_block(0) {
        match d.val().as_str() {
            "message" => {
                if !error.is_empty() {
                    bail!("message already specified");
                }
                if !d.all_args(&mut [&mut error]) {
                    return Err(d.arg_err());
                }
            }
            other => bail!("unrecognized subdirective '{other}'"),
        }
    }
    let mut m = Map::new();
    m.insert("handler".into(), json!("error"));
    if !error.is_empty() {
        m.insert("error".into(), json!(error));
    }
    if !status.is_empty() {
        m.insert("status_code".into(), weak_string(&status));
    }
    Ok(Value::Object(m))
}

fn parse_abort(d: &mut Dispenser) -> Result<Value> {
    d.next();
    if d.next() || d.next_block(0) {
        return Err(d.arg_err());
    }
    Ok(json!({ "handler": "static_response", "abort": true }))
}

fn parse_redir(d: &mut Dispenser) -> Result<Value> {
    d.next();
    if !d.next_arg() {
        return Err(d.arg_err());
    }
    let to = d.val();
    let mut code = if d.next_arg() { d.val() } else { String::new() };
    let mut body = String::new();
    let mut header: Option<(String, String)> = None;

    match code.as_str() {
        "permanent" => code = "301".into(),
        "temporary" | "" => code = "302".into(),
        "html" => {
            let safe = html_escape(&to);
            body = format!(
                "<!DOCTYPE html>\n<html>\n\t<head>\n\t\t<title>Redirecting...</title>\n\t\t<script>window.location.replace(\"{safe}\");</script>\n\t\t<meta http-equiv=\"refresh\" content=\"0; URL='{safe}'\">\n\t</head>\n\t<body>Redirecting to <a href=\"{safe}\">{safe}</a>...</body>\n</html>\n"
            );
            header = Some(("Content-Type".into(), "text/html; charset=utf-8".into()));
            code = "200".into();
        }
        c => {
            if c.starts_with('{') {
                // placeholder, allow
            } else {
                let n: i64 = c.parse().map_err(|_| {
                    d.errf(format!(
                        "Not a supported redir code type or not valid integer: '{c}'"
                    ))
                })?;
                if n < 300 || (n > 399 && n != 401) {
                    bail!("Redir code not in the 3xx range or 401: '{n}'");
                }
            }
        }
    }

    if code != "200" {
        header = Some(("Location".into(), to.clone()));
    }

    let mut m = Map::new();
    m.insert("handler".into(), json!("static_response"));
    m.insert("status_code".into(), weak_string(&code));
    if let Some((k, v)) = header {
        m.insert("headers".into(), json!({ k: [v] }));
    }
    if !body.is_empty() {
        m.insert("body".into(), json!(body));
    }
    Ok(Value::Object(m))
}

fn parse_zeroserve_call(d: &mut Dispenser) -> Result<Value> {
    d.next();
    let args = d.remaining_args();
    if args.len() != 2 {
        return Err(d.arg_err());
    }
    let script = args[0].clone();
    let function = args[1].clone();

    let mut config = Map::new();
    while d.next_block(0) {
        let key = d.val();
        let values = d.remaining_args();
        let value = match values.len() {
            0 => Value::Bool(true),
            1 => Value::String(values[0].clone()),
            _ => Value::Array(values.into_iter().map(Value::String).collect()),
        };
        config.insert(key, value);
    }

    let mut m = Map::new();
    m.insert("handler".into(), json!("zeroserve_call"));
    m.insert("script".into(), json!(script));
    m.insert("function".into(), json!(function));
    if !config.is_empty() {
        m.insert("config".into(), Value::Object(config));
    }
    Ok(Value::Object(m))
}

// --- vars / map / request_body ------------------------------------------------

fn parse_vars(d: &mut Dispenser) -> Result<Value> {
    d.next();
    let mut m = Map::new();
    m.insert("handler".into(), json!("vars"));

    let mut next_var = |d: &mut Dispenser, header_line: bool| -> Result<()> {
        if header_line && !d.next_arg() {
            return Ok(());
        }
        let name = d.val();
        if !d.next_arg() {
            return Err(d.arg_err());
        }
        let value = scalar_val(d);
        m.insert(name, value);
        if d.next_arg() {
            return Err(d.arg_err());
        }
        Ok(())
    };
    next_var(d, true)?;
    while d.next_block(0) {
        next_var(d, false)?;
    }
    Ok(Value::Object(m))
}

fn parse_map(d: &mut Dispenser) -> Result<Value> {
    d.next();
    if !d.next_arg() {
        return Err(d.arg_err());
    }
    let source = d.val();
    let destinations = d.remaining_args();
    if destinations.is_empty() {
        bail!("missing destination argument(s)");
    }
    for dest in &destinations {
        if let Some(shorthand) = matchers::was_replaced_placeholder_shorthand(dest) {
            bail!("destination {shorthand} conflicts with a Caddyfile placeholder shorthand");
        }
    }
    let mut mappings: Vec<Value> = Vec::new();
    let mut defaults: Vec<String> = Vec::new();
    while d.next_block(0) {
        if d.val() == "default" {
            if !defaults.is_empty() {
                bail!("defaults already defined");
            }
            defaults = d.remaining_args();
            while defaults.len() < destinations.len() {
                defaults.push(String::new());
            }
            continue;
        }
        let input = d.val();
        let mut outs: Vec<Value> = Vec::new();
        while d.next_arg() {
            let v = scalar_val(d);
            if v == json!("-") {
                outs.push(Value::Null);
            } else {
                outs.push(v);
            }
        }
        if outs.len() > destinations.len() {
            bail!("too many outputs");
        }
        while outs.len() < destinations.len() {
            outs.push(Value::Null);
        }
        let mut mapping = Map::new();
        if let Some(rx) = input.strip_prefix('~') {
            mapping.insert("input_regexp".into(), json!(rx));
        } else {
            mapping.insert("input".into(), json!(input));
        }
        mapping.insert("outputs".into(), Value::Array(outs));
        mappings.push(Value::Object(mapping));
    }
    let mut m = Map::new();
    m.insert("handler".into(), json!("map"));
    m.insert("source".into(), json!(source));
    m.insert("destinations".into(), json!(destinations));
    if !mappings.is_empty() {
        m.insert("mappings".into(), Value::Array(mappings));
    }
    if !defaults.is_empty() {
        m.insert("defaults".into(), json!(defaults));
    }
    Ok(Value::Object(m))
}

fn parse_log_append(d: &mut Dispenser) -> Result<Value> {
    d.next();
    if !d.next_arg() {
        return Err(d.arg_err());
    }
    let mut key = d.val();
    if !d.next_arg() {
        return Err(d.arg_err());
    }
    let value = d.val();
    let early = key.starts_with('<') && key.len() > 1;
    if early {
        key = key[1..].to_string();
    }
    let mut m = Map::new();
    m.insert("handler".into(), json!("log_append"));
    m.insert("key".into(), json!(key));
    m.insert("value".into(), json!(value));
    if early {
        m.insert("early".into(), json!(true));
    }
    Ok(Value::Object(m))
}

fn parse_log_skip(h: &mut Helper) -> Result<Value> {
    h.d.next();
    if h.d.val() == "skip_log" {
        h.warn("the 'skip_log' directive is deprecated, please use 'log_skip' instead");
    }
    if h.d.next_arg() {
        return Err(h.d.arg_err());
    }
    if h.d.next_block(0) {
        bail!("log_skip directive does not accept blocks");
    }
    Ok(json!({ "handler": "vars", "log_skip": true }))
}

fn parse_log_name(d: &mut Dispenser) -> Result<Value> {
    d.next();
    let names = d.remaining_args();
    Ok(json!({
        "handler": "vars",
        "access_logger_names": if names.is_empty() { Value::Null } else { json!(names) }
    }))
}

fn parse_log(h: &mut Helper) -> Result<Vec<ConfigValue>> {
    h.d.next();
    if h.d.count_remaining_args() > 1 {
        return Err(h.d.arg_err());
    }
    let logger_name =
        h.d.remaining_args()
            .into_iter()
            .next()
            .unwrap_or_else(|| "default".to_string());
    let mut output_file: Option<String> = None;
    let mut format: Option<String> = None;
    while h.d.next_block(0) {
        match h.d.val().as_str() {
            "hostnames" => {
                if h.d.remaining_args().is_empty() {
                    return Err(h.d.arg_err());
                }
            }
            "output" => {
                if !h.d.next_arg() {
                    return Err(h.d.arg_err());
                }
                let output = h.d.val();
                let args = h.d.remaining_args();
                if output == "file"
                    && let Some(filename) = args.first()
                {
                    output_file = Some(filename.clone());
                }
                consume_nested_block(&mut h.d);
            }
            "format" => {
                if !h.d.next_arg() {
                    return Err(h.d.arg_err());
                }
                format = Some(h.d.val());
                h.d.remaining_args();
                consume_nested_block(&mut h.d);
            }
            "core" => {
                if !h.d.next_arg() {
                    return Err(h.d.arg_err());
                }
                h.d.remaining_args();
                consume_nested_block(&mut h.d);
            }
            "sampling" => parse_log_sampling(h.d.new_from_next_segment())?,
            "level" => {
                if !h.d.next_arg() {
                    return Err(h.d.arg_err());
                }
                if h.d.next_arg() {
                    return Err(h.d.arg_err());
                }
            }
            "no_hostname" => {
                if h.d.next_arg() {
                    return Err(h.d.arg_err());
                }
            }
            "include" => bail!("include is not allowed in the log directive"),
            "exclude" => bail!("exclude is not allowed in the log directive"),
            other => bail!("unrecognized subdirective: {other}"),
        }
    }
    if let Some(file) = output_file {
        let mut handler = Map::new();
        handler.insert("handler".into(), json!("caddy_access_log"));
        handler.insert("logger_name".into(), json!(logger_name));
        handler.insert("file".into(), json!(file));
        if let Some(format) = format {
            handler.insert("format".into(), json!(format));
        }
        return Ok(h.new_route(None, Value::Object(handler)));
    }
    h.warn(
        "site log directive is accepted but configured outside zeroserve's eBPF request-processing surface",
    );
    Ok(Vec::new())
}

fn parse_log_sampling(mut d: Dispenser) -> Result<()> {
    d.next();
    while d.next_arg() {}
    let nesting = d.nesting();
    while d.next_block(nesting) {
        match d.val().as_str() {
            "interval" | "first" | "thereafter" => {
                if !d.next_arg() {
                    return Err(d.arg_err());
                }
                if d.next_arg() {
                    return Err(d.arg_err());
                }
            }
            other => bail!("unrecognized subdirective: {other}"),
        }
    }
    Ok(())
}

fn parse_bind(h: &mut Helper) -> Result<Vec<ConfigValue>> {
    h.d.next();
    h.d.remaining_args();
    while h.d.next_block(0) {
        match h.d.val().as_str() {
            "protocols" => {
                if h.d.remaining_args().is_empty() {
                    bail!("protocols requires one or more arguments");
                }
            }
            other => bail!("unknown subdirective: {other}"),
        }
    }
    h.warn(
        "site bind directive is accepted but configured outside zeroserve's eBPF request-processing surface",
    );
    Ok(Vec::new())
}

fn parse_tls(h: &mut Helper) -> Result<Vec<ConfigValue>> {
    h.d.next();
    let first_line = h.d.remaining_args();
    if first_line.len() > 2 {
        return Err(h.d.arg_err());
    }
    let mut cert_policies = Vec::<Value>::new();
    if let [arg] = first_line.as_slice()
        && arg != "internal"
        && arg != "force_automate"
        && arg != "off"
        && !arg.contains('@')
    {
        bail!("single argument must be 'internal', 'force_automate', 'off', or an email address");
    }
    if let [cert, key] = first_line.as_slice() {
        cert_policies.push(tls_certificate_policy(cert, key));
    }
    // ACME automation intent captured for the generated
    // `zeroserve.init.acme_config` section (see caddy_compile.rs).
    let mut acme_internal = false;
    let mut acme_issuer = false;
    let mut acme_skip = false;
    let mut acme_email: Option<String> = None;
    let mut acme_ca: Option<String> = None;
    let mut acme_eab: Option<(String, String)> = None;
    if let [arg] = first_line.as_slice() {
        match arg.as_str() {
            "internal" => acme_internal = true,
            "force_automate" => acme_issuer = true,
            // `tls off`: exclude this site from automatic HTTPS (ACME). It is
            // served from a `--cert`/`--key` default identity or `--cert-dir`.
            "off" => acme_skip = true,
            // Guarded above to be an email address.
            _ => acme_email = Some(arg.clone()),
        }
    }
    let mut has_block = false;
    let mut dns_provider_set = h.options.tls_dns_provider_configured;
    let mut dns_options_set = Vec::<String>::new();
    let mut policies = Vec::<Value>::new();
    while h.d.next_block(0) {
        has_block = true;
        let subdirective = h.d.val();
        match subdirective.as_str() {
            "protocols" => {
                parse_tls_protocols(&mut h.d)?;
            }
            "ciphers" => parse_tls_ciphers(&mut h.d)?,
            "curves" => parse_tls_curves(&mut h.d)?,
            "alpn" => {
                parse_one_or_more_args(&mut h.d)?;
            }
            "load" => {
                let args = h.d.remaining_args();
                if args.len() == 2 {
                    cert_policies.push(tls_certificate_policy(&args[0], &args[1]));
                } else if !args.is_empty() {
                    h.warn(
                        "ignoring tls 'load' without an explicit certificate/key pair: zeroserve only supports Caddyfile TLS file certificates",
                    );
                }
            }
            "resolvers" => {
                parse_one_or_more_args(&mut h.d)?;
                dns_options_set.push("resolvers".to_string());
            }
            "client_auth" => {
                if let Some(policy) = parse_tls_client_auth(h.d.new_from_next_segment())? {
                    policies.push(policy);
                }
            }
            "ca" => {
                let args = parse_exact_args(&mut h.d, 1)?;
                acme_ca = Some(args[0].clone());
            }
            "ca_root" | "key_type" | "dns_challenge_override_domain" | "insecure_secrets_log" => {
                parse_exact_args(&mut h.d, 1)?;
            }
            "propagation_delay" | "dns_ttl" => {
                let args = parse_exact_args(&mut h.d, 1)?;
                parse_tls_duration(&args[0], &subdirective)?;
                dns_options_set.push(subdirective);
            }
            "propagation_timeout" => {
                let args = parse_exact_args(&mut h.d, 1)?;
                if args[0] != "-1" {
                    parse_tls_duration(&args[0], "propagation_timeout")?;
                }
                dns_options_set.push("propagation_timeout".to_string());
            }
            "issuer" => {
                if !h.d.next_arg() {
                    return Err(h.d.arg_err());
                }
                let issuer = h.d.val();
                if !is_supported_tls_issuer(&issuer) {
                    bail!(
                        "getting module named 'tls.issuance.{issuer}': module not registered: tls.issuance.{issuer}"
                    );
                }
                if issuer == "acme" {
                    acme_issuer = true;
                } else if issuer == "internal" {
                    acme_internal = true;
                }
                h.d.remaining_args();
            }
            "get_certificate" => {
                if !h.d.next_arg() {
                    return Err(h.d.arg_err());
                }
                let manager = h.d.val();
                if !is_supported_tls_certificate_manager(&manager) {
                    bail!(
                        "getting module named 'tls.get_certificate.{manager}': module not registered: tls.get_certificate.{manager}"
                    );
                }
                h.d.remaining_args();
            }
            "eab" => {
                let args = parse_exact_args(&mut h.d, 2)?;
                acme_eab = Some((args[0].clone(), args[1].clone()));
            }
            "dns" => {
                // zeroserve does not perform automatic certificate issuance, so an
                // ACME DNS-01 challenge provider is accepted but ignored rather than
                // requiring the provider module to be registered.
                if h.d.next_arg() {
                    let provider = h.d.val();
                    h.d.remaining_args();
                    let nesting = h.d.nesting();
                    while h.d.next_block(nesting) {
                        h.d.remaining_args();
                    }
                    h.warn(format!(
                        "ignoring tls 'dns {provider}': zeroserve does not perform automatic certificate issuance"
                    ));
                } else if !dns_provider_set {
                    return Err(h.d.arg_err());
                }
                dns_provider_set = true;
            }
            "on_demand" | "reuse_private_keys" | "force_automate" => {
                parse_exact_args(&mut h.d, 0)?;
            }
            "renewal_window_ratio" => {
                if !h.d.next_arg() {
                    return Err(h.d.arg_err());
                }
                let ratio =
                    h.d.val()
                        .parse::<f64>()
                        .map_err(|e| h.d.errf(format!("parsing renewal_window_ratio: {e}")))?;
                if ratio <= 0.0 || ratio >= 1.0 {
                    bail!("renewal_window_ratio must be between 0 and 1 (exclusive)");
                }
                if h.d.next_arg() {
                    return Err(h.d.arg_err());
                }
            }
            other => bail!("unknown subdirective: {other}"),
        }
    }
    if !dns_options_set.is_empty() && !dns_provider_set {
        bail!(
            "setting DNS challenge options [{}] requires a DNS provider (set with the 'dns' subdirective or 'acme_dns' global option)",
            dns_options_set.join(", ")
        );
    }
    if first_line.is_empty() && !has_block {
        return Err(h.d.arg_err());
    }
    policies.extend(cert_policies);
    let mut out: Vec<ConfigValue> = Vec::new();
    if acme_skip {
        h.warn("site 'tls off': excluded from automatic HTTPS (ACME)");
    } else if policies.is_empty() {
        h.warn(
            "site tls directive is accepted but configured outside zeroserve's eBPF request-processing surface",
        );
    } else {
        h.warn(
            "site tls directive generated middleware for supported TLS policy in the zeroserve TLS eBPF section",
        );
        out.extend(policies.into_iter().map(|policy| ConfigValue {
            class: "tls_connection_policy".into(),
            directive: "tls".into(),
            value: RouteOrSub::Json(policy),
        }));
    }
    // Record ACME automation intent (email / ca / eab / internal) so the Caddy
    // compiler can emit `zeroserve.init.acme_config` scoped to this site's
    // hostnames.
    if acme_internal
        || acme_issuer
        || acme_email.is_some()
        || acme_ca.is_some()
        || acme_eab.is_some()
    {
        let mut obj = serde_json::Map::new();
        obj.insert("internal".into(), json!(acme_internal));
        if let Some(email) = acme_email {
            obj.insert("email".into(), json!(email));
        }
        if let Some(ca) = acme_ca {
            obj.insert("ca".into(), json!(ca));
        }
        if let Some((key_id, mac_key)) = acme_eab {
            obj.insert(
                "eab".into(),
                json!({ "key_id": key_id, "mac_key": mac_key }),
            );
        }
        out.push(ConfigValue {
            class: "acme_automation".into(),
            directive: "tls".into(),
            value: RouteOrSub::Json(Value::Object(obj)),
        });
    }
    // `tls off`: mark the site's hostnames to be skipped by automatic HTTPS.
    if acme_skip {
        out.push(ConfigValue {
            class: "acme_automation".into(),
            directive: "tls".into(),
            value: RouteOrSub::Json(json!({ "skip": true })),
        });
    }
    Ok(out)
}

fn tls_certificate_policy(cert: &str, key: &str) -> Value {
    json!({
        "certificate_selection": {
            "certificate": cert,
            "key": key,
        }
    })
}

fn parse_tls_client_auth(mut d: Dispenser) -> Result<Option<Value>> {
    d.next();
    d.remaining_args();
    let nesting = d.nesting();
    let mut has_trusted_ca = false;
    let mut has_trust_pool = false;
    let mut auth = Map::new();
    let mut ca_certs = Vec::<Value>::new();
    let mut ca_cert_files = Vec::<Value>::new();
    while d.next_block(nesting) {
        let subdirective = d.val();
        match subdirective.as_str() {
            "mode" => {
                let args = parse_exact_args(&mut d, 1)?;
                auth.insert("mode".into(), json!(args[0]));
            }
            "trusted_ca_cert" => {
                if has_trust_pool {
                    bail!(
                        "cannot specify both 'trust_pool' and 'trusted_ca_cert' or 'trusted_ca_cert_file'"
                    );
                }
                let args = parse_exact_args(&mut d, 1)?;
                ca_certs.push(json!(args[0]));
                has_trusted_ca = true;
            }
            "trusted_ca_cert_file" => {
                if has_trust_pool {
                    bail!(
                        "cannot specify both 'trust_pool' and 'trusted_ca_cert' or 'trusted_ca_cert_file'"
                    );
                }
                let args = parse_exact_args(&mut d, 1)?;
                ca_cert_files.push(json!(args[0]));
                has_trusted_ca = true;
            }
            "trusted_leaf_cert" | "trusted_leaf_cert_file" => {
                parse_exact_args(&mut d, 1)?;
            }
            "trust_pool" => {
                if has_trusted_ca {
                    bail!(
                        "cannot specify both 'trust_pool' and 'trusted_ca_cert' or 'trusted_ca_cert_file'"
                    );
                }
                if !d.next_arg() {
                    return Err(d.arg_err());
                }
                let provider = d.val();
                if !is_supported_tls_ca_pool_source(&provider) {
                    bail!(
                        "getting module named 'tls.ca_pool.source.{provider}': module not registered: tls.ca_pool.source.{provider}"
                    );
                }
                if provider == "inline" {
                    for cert in d.remaining_args() {
                        ca_certs.push(json!(cert));
                    }
                } else {
                    d.remaining_args();
                }
                has_trust_pool = true;
            }
            "verifier" => {
                if !d.next_arg() {
                    return Err(d.arg_err());
                }
                let verifier = d.val();
                if verifier != "leaf" {
                    bail!(
                        "getting module named 'tls.client_auth.verifier.{verifier}': module not registered: tls.client_auth.verifier.{verifier}"
                    );
                }
                d.remaining_args();
            }
            other => bail!("unknown subdirective for client_auth: {other}"),
        }
    }
    if !ca_certs.is_empty() || !ca_cert_files.is_empty() {
        auth.insert(
            "ca".into(),
            json!({
                "provider": "inline",
                "trusted_ca_certs": ca_certs,
                "trusted_ca_cert_files": ca_cert_files,
            }),
        );
    }
    if auth.is_empty() {
        Ok(None)
    } else {
        Ok(Some(
            json!({ "client_authentication": Value::Object(auth) }),
        ))
    }
}

fn parse_tls_protocols(d: &mut Dispenser) -> Result<()> {
    let args = d.remaining_args();
    if args.is_empty() {
        bail!("protocols requires one or two arguments");
    }
    for protocol in args.iter().take(2) {
        if !matches!(protocol.as_str(), "tls1.2" | "tls1.3") {
            bail!("wrong protocol name or protocol not supported: '{protocol}'");
        }
    }
    Ok(())
}

fn parse_tls_ciphers(d: &mut Dispenser) -> Result<()> {
    for cipher in d.remaining_args() {
        if !is_supported_tls_cipher(&cipher) {
            bail!("wrong cipher suite name or cipher suite not supported: '{cipher}'");
        }
    }
    Ok(())
}

fn parse_tls_curves(d: &mut Dispenser) -> Result<()> {
    for curve in d.remaining_args() {
        if !matches!(
            curve.as_str(),
            "x25519mlkem768" | "x25519" | "secp256r1" | "secp384r1" | "secp521r1"
        ) {
            bail!("Wrong curve name or curve not supported: '{curve}'");
        }
    }
    Ok(())
}

fn is_supported_tls_cipher(cipher: &str) -> bool {
    matches!(
        cipher,
        "TLS_AES_128_GCM_SHA256"
            | "TLS_AES_256_GCM_SHA384"
            | "TLS_CHACHA20_POLY1305_SHA256"
            | "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"
            | "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
            | "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"
            | "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"
            | "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256"
            | "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256"
    )
}

fn is_supported_tls_issuer(issuer: &str) -> bool {
    matches!(issuer, "acme" | "internal" | "zerossl")
}

fn is_supported_tls_certificate_manager(manager: &str) -> bool {
    matches!(manager, "http" | "tailscale")
}

fn is_supported_tls_ca_pool_source(provider: &str) -> bool {
    matches!(
        provider,
        "combined"
            | "file"
            | "http"
            | "inline"
            | "pki_intermediate"
            | "pki_root"
            | "storage"
            | "system"
    )
}

fn parse_tls_duration(raw: &str, label: &str) -> Result<i64> {
    if raw.parse::<i64>().is_ok() {
        bail!("invalid {label} duration {raw}: time: missing unit in duration \"{raw}\"");
    }
    if !raw.chars().any(|c| c.is_ascii_digit()) {
        bail!("invalid {label} duration {raw}: time: invalid duration \"{raw}\"");
    }
    parse_duration_ns(raw).map_err(|e| anyhow::anyhow!("invalid {label} duration {raw}: {e}"))
}

fn parse_exact_args(d: &mut Dispenser, expected: usize) -> Result<Vec<String>> {
    let args = d.remaining_args();
    if args.len() != expected {
        return Err(d.arg_err());
    }
    Ok(args)
}

fn parse_one_or_more_args(d: &mut Dispenser) -> Result<Vec<String>> {
    let args = d.remaining_args();
    if args.is_empty() {
        return Err(d.arg_err());
    }
    Ok(args)
}

fn parse_one_or_two_args(d: &mut Dispenser) -> Result<Vec<String>> {
    let args = d.remaining_args();
    if args.is_empty() || args.len() > 2 {
        return Err(d.arg_err());
    }
    Ok(args)
}

fn parse_tracing(d: &mut Dispenser) -> Result<Value> {
    d.next();
    if d.next_arg() {
        return Err(d.arg_err());
    }
    let mut m = Map::new();
    m.insert("handler".into(), json!("tracing"));
    m.insert("span".into(), json!(""));
    let mut span_attributes = Map::new();
    while d.next_block(0) {
        match d.val().as_str() {
            "span" => {
                if !d.next_arg() {
                    return Err(d.arg_err());
                }
                m.insert("span".into(), json!(d.val()));
                if d.next_arg() {
                    return Err(d.arg_err());
                }
            }
            "span_attributes" => {
                if d.next_arg() {
                    return Err(d.arg_err());
                }
                let nesting = d.nesting();
                while d.next_block(nesting) {
                    let key = d.val();
                    if !d.next_arg() {
                        return Err(d.arg_err());
                    }
                    span_attributes.insert(key, json!(d.val()));
                    if d.next_arg() {
                        return Err(d.arg_err());
                    }
                }
            }
            _ => return Err(d.arg_err()),
        }
    }
    if !span_attributes.is_empty() {
        m.insert("span_attributes".into(), Value::Object(span_attributes));
    }
    Ok(Value::Object(m))
}

fn parse_basic_auth(h: &mut Helper) -> Result<Value> {
    h.d.next();
    if h.d.val() == "basicauth" {
        h.warn("the 'basicauth' directive is deprecated, please use 'basic_auth' instead");
    }
    let args = h.d.remaining_args();
    let (algorithm, realm) = match args.as_slice() {
        [] => ("bcrypt".to_string(), None),
        [algorithm] => (algorithm.clone(), None),
        [algorithm, realm] => (algorithm.clone(), Some(realm.clone())),
        _ => return Err(h.d.arg_err()),
    };
    if algorithm != "bcrypt" && algorithm != "argon2id" {
        bail!("unrecognized hash algorithm: {algorithm}");
    }

    let mut accounts = Vec::<Value>::new();
    while h.d.next_block(0) {
        let username = h.d.val();
        let password = if h.d.next_arg() {
            h.d.val()
        } else {
            String::new()
        };
        if h.d.next_arg() {
            return Err(h.d.arg_err());
        }
        if username.is_empty() || password.is_empty() {
            bail!("username and password cannot be empty or missing");
        }
        accounts.push(json!({
            "username": username,
            "password": password,
        }));
    }

    let mut provider = Map::new();
    provider.insert("hash".into(), json!({ "algorithm": algorithm }));
    provider.insert("hash_cache".into(), json!({}));
    if !accounts.is_empty() {
        provider.insert("accounts".into(), Value::Array(accounts));
    }
    if let Some(realm) = realm {
        provider.insert("realm".into(), json!(realm));
    }

    Ok(json!({
        "handler": "authentication",
        "providers": {
            "http_basic": Value::Object(provider),
        }
    }))
}

fn parse_request_body(d: &mut Dispenser) -> Result<Value> {
    d.next();
    let mut m = Map::new();
    m.insert("handler".into(), json!("request_body"));
    while d.next_block(0) {
        match d.val().as_str() {
            "max_size" => {
                let mut s = String::new();
                if !d.all_args(&mut [&mut s]) {
                    return Err(d.arg_err());
                }
                m.insert("max_size".into(), json!(parse_bytes(&s)?));
            }
            "read_timeout" => {
                let mut s = String::new();
                if !d.all_args(&mut [&mut s]) {
                    return Err(d.arg_err());
                }
                m.insert("read_timeout".into(), json!(parse_go_duration_ns(&s)?));
            }
            "write_timeout" => {
                let mut s = String::new();
                if !d.all_args(&mut [&mut s]) {
                    return Err(d.arg_err());
                }
                m.insert("write_timeout".into(), json!(parse_go_duration_ns(&s)?));
            }
            "set" => {
                let mut s = String::new();
                if !d.all_args(&mut [&mut s]) {
                    return Err(d.arg_err());
                }
                m.insert("set".into(), json!(s));
            }
            other => bail!("unrecognized request_body subdirective '{other}'"),
        }
    }
    Ok(Value::Object(m))
}

// --- file_server --------------------------------------------------------------

fn parse_file_server(h: &mut Helper) -> Result<Value> {
    let d = &mut h.d;
    d.next();
    let caddyfile_hides = h
        .caddyfiles
        .iter()
        .filter_map(|file| caddyfile_hide_path(file))
        .collect::<Vec<_>>();
    let mut m = Map::new();
    m.insert("handler".into(), json!("file_server"));

    let args = d.remaining_args();
    let mut browse: Option<Map<String, Value>> = None;
    match args.len() {
        0 => {}
        1 if args[0] == "browse" => browse = Some(Map::new()),
        _ => return Err(d.arg_err()),
    }

    while d.next_block(0) {
        match d.val().as_str() {
            "fs" => {
                if !d.next_arg() {
                    return Err(d.arg_err());
                }
                if m.contains_key("fs") {
                    bail!("file system already specified");
                }
                m.insert("fs".into(), json!(d.val()));
            }
            "hide" => {
                let hide = d.remaining_args();
                if hide.is_empty() {
                    return Err(d.arg_err());
                }
                m.insert("hide".into(), json!(hide));
            }
            "index" => {
                let index = d.remaining_args();
                if index.is_empty() {
                    return Err(d.arg_err());
                }
                m.insert("index_names".into(), json!(index));
            }
            "etag_file_extensions" => {
                let extensions = d.remaining_args();
                if extensions.is_empty() {
                    return Err(d.arg_err());
                }
                m.insert("etag_file_extensions".into(), json!(extensions));
            }
            "root" => {
                let mut root = String::new();
                if !d.all_args(&mut [&mut root]) {
                    return Err(d.arg_err());
                }
                m.insert("root".into(), json!(root));
            }
            "browse" => {
                if browse.is_some() {
                    bail!("browsing is already configured");
                }
                let mut b = Map::new();
                let mut tpl = String::new();
                if d.args(&mut [&mut tpl]) {
                    b.insert("template_file".into(), json!(tpl));
                }
                let browse_nesting = d.nesting();
                while d.next_block(browse_nesting) {
                    match d.val().as_str() {
                        "reveal_symlinks" => {
                            if b.get("reveal_symlinks").and_then(Value::as_bool) == Some(true) {
                                bail!("Symlinks path reveal is already enabled");
                            }
                            b.insert("reveal_symlinks".into(), json!(true));
                        }
                        "sort" => {
                            let opts = b
                                .entry("sort")
                                .or_insert_with(|| Value::Array(Vec::new()))
                                .as_array_mut()
                                .expect("file_server browse sort is always an array");
                            while d.next_arg() {
                                let opt = d.val();
                                match opt.as_str() {
                                    "name" | "namedirfirst" | "size" | "time" | "asc" | "desc" => {
                                        opts.push(json!(opt))
                                    }
                                    _ => bail!("unknown sort option '{opt}'"),
                                }
                            }
                        }
                        "file_limit" => {
                            let fl = d.remaining_args();
                            if fl.len() != 1 {
                                bail!("file_limit should have an integer value");
                            }
                            if b.contains_key("file_limit") {
                                bail!("file_limit is already enabled");
                            }
                            b.insert(
                                "file_limit".into(),
                                json!(fl[0].parse::<i64>().unwrap_or(0)),
                            );
                        }
                        other => bail!("unknown subdirective '{other}'"),
                    }
                }
                browse = Some(b);
            }
            "status" => {
                if !d.next_arg() {
                    return Err(d.arg_err());
                }
                m.insert("status_code".into(), weak_string(&d.val()));
            }
            "disable_canonical_uris" => {
                if d.next_arg() {
                    return Err(d.arg_err());
                }
                m.insert("canonical_uris".into(), json!(false));
            }
            "pass_thru" => {
                if d.next_arg() {
                    return Err(d.arg_err());
                }
                m.insert("pass_thru".into(), json!(true));
            }
            "precompressed" => {
                let order = d.remaining_args();
                let order = if order.is_empty() {
                    vec!["br".to_string(), "zstd".to_string(), "gzip".to_string()]
                } else {
                    order
                };
                let mut precompressed = Map::new();
                for format in &order {
                    match format.as_str() {
                        "br" | "zstd" | "gzip" => {
                            precompressed.insert(format.clone(), json!({}));
                        }
                        other => bail!(
                            "getting module named 'http.precompressed.{other}': module not registered: http.precompressed.{other}"
                        ),
                    }
                }
                m.insert("precompressed".into(), Value::Object(precompressed));
                m.insert("precompressed_order".into(), json!(order));
            }
            other => bail!("unknown subdirective '{other}'"),
        }
    }
    if let Some(b) = browse {
        m.insert("browse".into(), Value::Object(b));
    }
    for caddyfile_hide in caddyfile_hides {
        let hide = m
            .entry("hide")
            .or_insert_with(|| Value::Array(Vec::new()))
            .as_array_mut()
            .expect("file_server hide is always an array");
        if !caddyfile_hidden_by_patterns(&caddyfile_hide, hide) {
            hide.push(json!(caddyfile_hide));
        }
    }
    Ok(Value::Object(m))
}

fn caddyfile_hide_path(file: &str) -> Option<String> {
    if file.is_empty() {
        return None;
    }
    let mut file = file.replace('\\', "/");
    if !file.contains('/') {
        file = format!("./{file}");
    }
    Some(file)
}

fn caddyfile_hidden_by_patterns(file: &str, hide: &[Value]) -> bool {
    let components = file.split('/').collect::<Vec<_>>();
    for pattern in hide.iter().filter_map(Value::as_str) {
        let pattern = pattern.replace('\\', "/");
        if !pattern.contains('/') {
            if components
                .iter()
                .any(|component| caddyfile_simple_glob_match(&pattern, component))
            {
                return true;
            }
        } else if file == pattern
            || file
                .strip_prefix(&pattern)
                .is_some_and(|rest| rest.starts_with('/'))
        {
            return true;
        }
        if caddyfile_path_glob_match(&pattern, file) {
            return true;
        }
    }
    false
}

fn caddyfile_path_glob_match(pattern: &str, value: &str) -> bool {
    let pattern_parts = pattern.split('/').collect::<Vec<_>>();
    let value_parts = value.split('/').collect::<Vec<_>>();
    pattern_parts.len() == value_parts.len()
        && pattern_parts
            .iter()
            .zip(value_parts)
            .all(|(pattern, value)| caddyfile_simple_glob_match(pattern, value))
}

fn caddyfile_simple_glob_match(pattern: &str, value: &str) -> bool {
    let pattern = pattern.as_bytes();
    let value = value.as_bytes();
    let mut memo = std::collections::HashMap::new();
    caddyfile_simple_glob_match_inner(pattern, value, 0, 0, &mut memo)
}

fn caddyfile_simple_glob_match_inner(
    pattern: &[u8],
    value: &[u8],
    pi: usize,
    vi: usize,
    memo: &mut std::collections::HashMap<(usize, usize), bool>,
) -> bool {
    if let Some(result) = memo.get(&(pi, vi)) {
        return *result;
    }
    let result = if pi == pattern.len() {
        vi == value.len()
    } else {
        match pattern[pi] {
            b'*' => {
                caddyfile_simple_glob_match_inner(pattern, value, pi + 1, vi, memo)
                    || (vi < value.len()
                        && caddyfile_simple_glob_match_inner(pattern, value, pi, vi + 1, memo))
            }
            b'?' => {
                vi < value.len()
                    && caddyfile_simple_glob_match_inner(pattern, value, pi + 1, vi + 1, memo)
            }
            ch => {
                vi < value.len()
                    && ch == value[vi]
                    && caddyfile_simple_glob_match_inner(pattern, value, pi + 1, vi + 1, memo)
            }
        }
    };
    memo.insert((pi, vi), result);
    result
}

fn parse_copy_response_headers(d: &mut Dispenser) -> Result<Value> {
    d.next();
    let mut m = Map::new();
    m.insert("handler".into(), json!("copy_response_headers"));
    let args = d.remaining_args();
    if !args.is_empty() {
        return Err(d.arg_err());
    }
    while d.next_block(0) {
        let key = d.val();
        match key.as_str() {
            "include" | "exclude" => {
                let values = d.remaining_args();
                append_string_values(&mut m, &key, values);
            }
            other => bail!("unrecognized copy_response_headers subdirective '{other}'"),
        }
    }
    Ok(Value::Object(m))
}

fn parse_copy_response(d: &mut Dispenser) -> Result<Value> {
    d.next();
    let args = d.remaining_args();
    match args.as_slice() {
        [] => {}
        [status] if is_positive_integer(status) => {
            let _ = weak_string(status);
            bail!(
                "copy_response handler copies upstream response bodies and is not supported by zeroserve Caddy middleware"
            );
        }
        _ => {}
    }
    while d.next_block(0) {
        match d.val().as_str() {
            "status" => {
                if !d.next_arg() {
                    return Err(d.arg_err());
                }
                let _ = weak_string(&d.val());
            }
            other => bail!("unrecognized copy_response subdirective '{other}'"),
        }
    }
    bail!(
        "copy_response handler copies upstream response bodies and is not supported by zeroserve Caddy middleware"
    )
}

fn parse_encode(d: &mut Dispenser) -> Result<Value> {
    d.next();
    let mut encodings = Map::new();
    let mut prefer = Vec::<String>::new();
    let remaining_args = d.remaining_args();
    let mut m = Map::new();
    m.insert("handler".into(), json!("encode"));

    while d.next_block(0) {
        match d.val().as_str() {
            "minimum_length" => {
                if !d.next_arg() {
                    return Err(d.arg_err());
                }
                let min_length = d
                    .val()
                    .parse::<i64>()
                    .map_err(|e| d.errf(format!("bad minimum_length '{}': {e}", d.val())))?;
                m.insert("minimum_length".into(), json!(min_length));
            }
            "match" => {
                m.insert("match".into(), parse_inline_response_matcher(d)?);
            }
            name => {
                let encoding = parse_encoder_module(d, name)?;
                encodings.insert(name.to_string(), encoding);
                prefer.push(name.to_string());
            }
        }
    }

    let remaining_args = if prefer.is_empty() && remaining_args.is_empty() {
        vec!["zstd".to_string(), "gzip".to_string()]
    } else {
        remaining_args
    };
    for name in remaining_args {
        validate_encoder_module_name(&name)?;
        encodings.insert(name.clone(), Value::Object(Map::new()));
        prefer.push(name);
    }
    if !encodings.is_empty() {
        m.insert("encodings".into(), Value::Object(encodings));
    }
    if !prefer.is_empty() {
        m.insert("prefer".into(), json!(prefer));
    }
    Ok(Value::Object(m))
}

fn parse_encoder_module(d: &mut Dispenser, name: &str) -> Result<Value> {
    match name {
        "gzip" => parse_gzip_encoder(d),
        "zstd" => parse_zstd_encoder(d),
        _ => bail!("finding encoder module '': module not registered: http.encoders.{name}"),
    }
}

fn validate_encoder_module_name(name: &str) -> Result<()> {
    match name {
        "gzip" | "zstd" => Ok(()),
        _ => bail!("finding encoder module '': module not registered: http.encoders.{name}"),
    }
}

fn parse_gzip_encoder(d: &mut Dispenser) -> Result<Value> {
    let mut m = Map::new();
    if d.next_arg() {
        let level = d.val();
        let level = level
            .parse::<i64>()
            .map_err(|e| d.errf(format!("bad gzip level '{}': {e}", level)))?;
        m.insert("level".into(), json!(level));
        let _ = d.remaining_args();
    }
    Ok(Value::Object(m))
}

fn parse_zstd_encoder(d: &mut Dispenser) -> Result<Value> {
    let mut m = Map::new();
    let args = d.remaining_args();
    match args.as_slice() {
        [] => {}
        [level] => {
            validate_zstd_level(level, d)?;
            m.insert("level".into(), json!(level));
        }
        _ => return Err(d.arg_err()),
    }

    let nesting = d.nesting();
    while d.next_block(nesting) {
        match d.val().as_str() {
            "level" => {
                let args = d.remaining_args();
                let [level] = args.as_slice() else {
                    return Err(d.arg_err());
                };
                if m.contains_key("level") {
                    bail!("compression level already specified");
                }
                validate_zstd_level(level, d)?;
                m.insert("level".into(), json!(level));
            }
            "disable_checksum" => {
                if d.next_arg() {
                    return Err(d.arg_err());
                }
                if m.contains_key("checksum") {
                    bail!("checksum already specified");
                }
                m.insert("checksum".into(), json!(false));
            }
            other => bail!("unknown subdirective '{other}'"),
        }
    }
    Ok(Value::Object(m))
}

fn validate_zstd_level(level: &str, d: &Dispenser) -> Result<()> {
    match level {
        "fastest" | "better" | "best" | "default" => Ok(()),
        _ => Err(d.err(
            "unexpected compression level, use one of 'fastest', 'better', 'best', 'default'",
        )),
    }
}

fn parse_inline_response_matcher(d: &mut Dispenser) -> Result<Value> {
    let mut matcher = Map::new();
    let mut headers = Map::new();
    let mut statuses = Vec::<Value>::new();
    let args = d.remaining_args();
    match args.as_slice() {
        [] => {
            let nesting = d.nesting();
            while d.next_block(nesting) {
                match d.val().as_str() {
                    "status" => {
                        let args = d.remaining_args();
                        if args.is_empty() {
                            return Err(d.arg_err());
                        }
                        for status in args {
                            statuses.push(Value::from(parse_response_status_match(&status, d)?));
                        }
                    }
                    "header" => parse_response_header_matcher_line(d, &mut headers)?,
                    other => bail!("unrecognized response matcher {other}"),
                }
            }
        }
        [kind, rest @ ..] if kind == "status" => {
            if rest.is_empty() {
                return Err(d.arg_err());
            }
            for status in rest {
                statuses.push(Value::from(parse_response_status_match(status, d)?));
            }
        }
        [kind, field] if kind == "header" => {
            let Some(field) = field.strip_prefix('!') else {
                bail!("malformed header matcher: expected both field and value");
            };
            if field.is_empty() {
                bail!("malformed header matcher: must have field name following ! character");
            }
            headers.insert(field.to_string(), Value::Null);
        }
        [kind, field, value] if kind == "header" => {
            headers.insert(canonical_header_key(field), json!([value]));
        }
        _ => return Err(d.arg_err()),
    }
    if !statuses.is_empty() {
        matcher.insert("status_code".into(), Value::Array(statuses));
    }
    if !headers.is_empty() {
        matcher.insert("headers".into(), Value::Object(headers));
    }
    Ok(Value::Object(matcher))
}

fn parse_templates(d: &mut Dispenser) -> Result<Value> {
    d.next();
    let args = d.remaining_args();
    if !args.is_empty() {
        return Err(d.arg_err());
    }
    let mut m = Map::new();
    m.insert("handler".into(), json!("templates"));

    while d.next_block(0) {
        match d.val().as_str() {
            "mime" => {
                let types = d.remaining_args();
                if types.is_empty() {
                    return Err(d.arg_err());
                }
                m.insert("mime_types".into(), json!(types));
            }
            "between" => {
                let delimiters = d.remaining_args();
                if delimiters.len() != 2 {
                    return Err(d.arg_err());
                }
                m.insert("delimiters".into(), json!(delimiters));
            }
            "root" => {
                let mut root = String::new();
                if !d.all_args(&mut [&mut root]) {
                    return Err(d.arg_err());
                }
                m.insert("file_root".into(), json!(root));
            }
            "extensions" => {
                if d.next_arg() {
                    return Err(d.arg_err());
                }
                let nesting = d.nesting();
                if d.next_block(nesting) {
                    let name = d.val();
                    let args = d.remaining_args();
                    if !args.is_empty() {
                        return Err(d.arg_err());
                    }
                    bail!(
                        "getting module named 'http.handlers.templates.functions.{name}': module not registered: http.handlers.templates.functions.{name}"
                    );
                }
            }
            _ => {}
        }
    }
    bail!(
        "templates handler rewrites response bodies and is not supported by zeroserve Caddy middleware"
    )
}

fn parse_metrics(d: &mut Dispenser) -> Result<Value> {
    d.next();
    let args = d.remaining_args();
    if !args.is_empty() {
        return Err(d.arg_err());
    }
    let mut m = Map::new();
    m.insert("handler".into(), json!("metrics"));
    while d.next_block(0) {
        match d.val().as_str() {
            "disable_openmetrics" => {
                if d.next_arg() {
                    return Err(d.arg_err());
                }
                m.insert("disable_openmetrics".into(), json!(true));
            }
            other => bail!("unrecognized metrics subdirective {other:?}"),
        }
    }
    Ok(Value::Object(m))
}

fn parse_acme_server(h: &mut Helper) -> Result<Value> {
    h.d.next();
    let args = h.d.remaining_args();
    if !args.is_empty() {
        return Err(h.d.arg_err());
    }
    let mut m = Map::new();
    m.insert("handler".into(), json!("acme_server"));
    let mut policy = Map::new();

    while h.d.next_block(0) {
        match h.d.val().as_str() {
            "ca" => {
                let mut ca = String::new();
                if !h.d.all_args(&mut [&mut ca]) {
                    return Err(h.d.arg_err());
                }
                h.ensure_pki_ca(&ca);
                m.insert("ca".into(), json!(ca));
            }
            "lifetime" => {
                if !h.d.next_arg() {
                    return Err(h.d.arg_err());
                }
                m.insert("lifetime".into(), json!(parse_duration_ns(&h.d.val())?));
            }
            "resolvers" => {
                let resolvers = h.d.remaining_args();
                if resolvers.is_empty() {
                    bail!("must specify at least one resolver address");
                }
                m.insert("resolvers".into(), json!(resolvers));
            }
            "challenges" => {
                let challenges = h.d.remaining_args();
                append_string_values(&mut m, "challenges", challenges);
            }
            "allow_wildcard_names" => {
                policy.insert("allow_wildcard_names".into(), json!(true));
            }
            "allow" => {
                policy.insert("allow".into(), parse_acme_rule_set(&mut h.d, "allow")?);
            }
            "deny" => {
                policy.insert("deny".into(), parse_acme_rule_set(&mut h.d, "deny")?);
            }
            "sign_with_root" => {
                if h.d.next_arg() {
                    return Err(h.d.arg_err());
                }
                m.insert("sign_with_root".into(), json!(true));
            }
            other => bail!("unrecognized ACME server directive: {other}"),
        }
    }
    if !policy.is_empty() {
        m.insert("policy".into(), Value::Object(policy));
    }
    Ok(Value::Object(m))
}

fn parse_acme_rule_set(d: &mut Dispenser, label: &str) -> Result<Value> {
    let mut rule = Map::new();
    let nesting = d.nesting();
    while d.next_block(nesting) {
        if d.count_remaining_args() == 0 {
            return Err(d.arg_err());
        }
        match d.val().as_str() {
            "domains" => {
                append_string_values(&mut rule, "domains", d.remaining_args());
            }
            "ip_ranges" => {
                append_string_values(&mut rule, "ip_ranges", d.remaining_args());
            }
            other => bail!("unrecognized '{label}' subdirective: {other}"),
        }
    }
    Ok(Value::Object(rule))
}

fn append_string_values(map: &mut Map<String, Value>, key: &str, values: Vec<String>) {
    if values.is_empty() {
        return;
    }
    let entry = map
        .entry(key.to_string())
        .or_insert_with(|| Value::Array(Vec::new()));
    let array = entry
        .as_array_mut()
        .expect("append_string_values only appends to array fields");
    array.extend(values.into_iter().map(Value::String));
}

fn parse_invoke(d: &mut Dispenser) -> Result<Value> {
    d.next();
    let mut name = String::new();
    if !d.all_args(&mut [&mut name]) {
        return Err(d.arg_err());
    }
    if d.next_block(0) {
        return Err(d.arg_err());
    }
    Ok(json!({ "handler": "invoke", "name": name }))
}

fn parse_php_fastcgi(h: &mut Helper) -> Result<Vec<ConfigValue>> {
    h.d.next();
    let matcher = h.extract_matcher_set()?;
    h.d.next();

    let mut transport = Map::new();
    transport.insert("protocol".into(), json!("fastcgi"));
    let mut extensions = vec![".php".to_string()];
    let mut index_file = "index.php".to_string();
    let mut try_files: Option<Vec<String>> = None;
    let mut headers = HeadersHandler::default();
    let mut rewrite = Map::new();
    let mut upstreams = Vec::new();
    let mut common_scheme = String::new();
    let mut trusted_proxies = Vec::<String>::new();
    let mut load_balancing: Option<Map<String, Value>> = None;
    let mut health_checks: Option<Map<String, Value>> = None;
    let mut dynamic_upstreams: Option<Value> = None;
    let mut runtime = Map::new();
    let mut verbose_logs = false;
    let mut response_matchers = HashMap::<String, Value>::new();
    let mut handle_response = Vec::<PendingResponseHandler>::new();

    for up in h.d.remaining_args() {
        append_upstream(&up, &mut upstreams, &mut common_scheme)?;
    }
    while h.d.next_block(0) {
        let sub = h.d.val();
        if sub.starts_with('@') {
            parse_response_matcher_definition(&mut h.d, &mut response_matchers)?;
            continue;
        }
        match sub.as_str() {
            "root" => {
                if !h.d.next_arg() {
                    return Err(h.d.arg_err());
                }
                transport.insert("root".into(), json!(h.d.val()));
            }
            "split" => {
                extensions = h.d.remaining_args();
                if extensions.is_empty() {
                    return Err(h.d.arg_err());
                }
                transport.insert("split_path".into(), json!(extensions.clone()));
            }
            "env" => {
                let args = h.d.remaining_args();
                let [key, value] = args.as_slice() else {
                    return Err(h.d.arg_err());
                };
                let entry = transport
                    .entry("env")
                    .or_insert_with(|| Value::Object(Map::new()));
                let Some(env) = entry.as_object_mut() else {
                    bail!("malformed php_fastcgi env map");
                };
                env.insert(key.clone(), json!(value));
            }
            "index" => {
                let args = h.d.remaining_args();
                let [index] = args.as_slice() else {
                    return Err(h.d.arg_err());
                };
                index_file = index.clone();
            }
            "try_files" => {
                let args = h.d.remaining_args();
                if args.is_empty() {
                    return Err(h.d.arg_err());
                }
                try_files = Some(args);
            }
            "resolve_root_symlink" => {
                let _ = h.d.remaining_args();
                transport.insert("resolve_root_symlink".into(), json!(true));
            }
            "dial_timeout" | "read_timeout" | "write_timeout" => {
                let key = h.d.val();
                if !h.d.next_arg() {
                    return Err(h.d.arg_err());
                }
                transport.insert(key, json!(parse_duration_ns(&h.d.val())?));
            }
            "capture_stderr" => {
                let _ = h.d.remaining_args();
                transport.insert("capture_stderr".into(), json!(true));
            }
            "header_up" => {
                let args = h.d.remaining_args();
                apply_header_args(&mut headers.request_ops(), args, &h.d)?;
            }
            "header_down" => {
                let args = h.d.remaining_args();
                let ops = headers.response_ops();
                apply_header_args(ops, args, &h.d)?;
            }
            "rewrite" => {
                let args = h.d.remaining_args();
                let [uri] = args.as_slice() else {
                    return Err(h.d.arg_err());
                };
                rewrite.insert("uri".into(), json!(uri));
            }
            "method" => {
                if !h.d.next_arg() {
                    return Err(h.d.arg_err());
                }
                rewrite.insert("method".into(), json!(h.d.val()));
                if h.d.next_arg() {
                    return Err(h.d.arg_err());
                }
            }
            "replace_status" => {
                let args = h.d.remaining_args();
                let pending = parse_replace_status_args(&args, &h.d)?;
                handle_response.push(pending);
            }
            "handle_response" => {
                let args = h.d.remaining_args();
                let pending = parse_handle_response_block(h, &args)?;
                handle_response.push(pending);
            }
            "to" => {
                for up in h.d.remaining_args() {
                    append_upstream(&up, &mut upstreams, &mut common_scheme)?;
                }
            }
            "dynamic" => {
                if dynamic_upstreams.is_some() {
                    bail!("dynamic upstreams already specified");
                }
                if !h.d.next_arg() {
                    return Err(h.d.arg_err());
                }
                dynamic_upstreams = Some(parse_dynamic_upstream_source(&mut h.d)?);
            }
            "lb_policy" => {
                if !h.d.next_arg() {
                    return Err(h.d.arg_err());
                }
                let selection_policy = parse_reverse_proxy_selection_policy(&mut h.d)?;
                load_balancing
                    .get_or_insert_with(Map::new)
                    .insert("selection_policy".into(), selection_policy);
            }
            "lb_retries" => {
                if !h.d.next_arg() {
                    return Err(h.d.arg_err());
                }
                let raw = h.d.val();
                let n: i64 = raw
                    .parse()
                    .map_err(|e| h.d.errf(format!("bad lb_retries number '{raw}': {e}")))?;
                if h.d.next_arg() {
                    return Err(h.d.arg_err());
                }
                load_balancing
                    .get_or_insert_with(Map::new)
                    .insert("retries".into(), json!(n));
            }
            "lb_try_duration" => {
                if !h.d.next_arg() {
                    return Err(h.d.arg_err());
                }
                let value = parse_duration_ns(&h.d.val())?;
                if h.d.next_arg() {
                    return Err(h.d.arg_err());
                }
                load_balancing
                    .get_or_insert_with(Map::new)
                    .insert("try_duration".into(), json!(value));
            }
            "lb_try_interval" => {
                if !h.d.next_arg() {
                    return Err(h.d.arg_err());
                }
                let value = parse_duration_ns(&h.d.val())?;
                if h.d.next_arg() {
                    return Err(h.d.arg_err());
                }
                load_balancing
                    .get_or_insert_with(Map::new)
                    .insert("try_interval".into(), json!(value));
            }
            "lb_retry_match" => {
                let matcher = matchers::parse_nested_matcher_set(&mut h.d)
                    .map_err(|e| h.d.errf(format!("failed to parse lb_retry_match: {e}")))?;
                load_balancing
                    .get_or_insert_with(Map::new)
                    .entry("retry_match")
                    .or_insert_with(|| Value::Array(Vec::new()))
                    .as_array_mut()
                    .expect("reverse_proxy retry_match must remain an array")
                    .push(matcher);
            }
            "health_uri"
            | "health_path"
            | "health_method"
            | "health_request_body"
            | "health_body" => {
                let key = match h.d.val().as_str() {
                    "health_uri" => "uri",
                    "health_path" => "path",
                    "health_method" => "method",
                    "health_request_body" => "body",
                    "health_body" => "expect_body",
                    _ => unreachable!(),
                };
                if !h.d.next_arg() {
                    return Err(h.d.arg_err());
                }
                let value = h.d.val();
                if h.d.next_arg() {
                    return Err(h.d.arg_err());
                }
                reverse_proxy_active_health(&mut health_checks).insert(key.into(), json!(value));
            }
            "health_upstream" => {
                if !h.d.next_arg() {
                    return Err(h.d.arg_err());
                }
                let upstream = h.d.val();
                validate_health_upstream(&upstream, &h.d)?;
                if h.d.next_arg() {
                    return Err(h.d.arg_err());
                }
                reverse_proxy_active_health(&mut health_checks)
                    .insert("upstream".into(), json!(upstream));
            }
            "health_port" => {
                if reverse_proxy_active_health(&mut health_checks).contains_key("upstream") {
                    bail!(
                        "the 'health_port' subdirective is ignored if 'health_upstream' is used!"
                    );
                }
                if !h.d.next_arg() {
                    return Err(h.d.arg_err());
                }
                let raw = h.d.val();
                let value: i64 = raw
                    .parse()
                    .map_err(|e| h.d.errf(format!("bad port number '{raw}': {e}")))?;
                if h.d.next_arg() {
                    return Err(h.d.arg_err());
                }
                reverse_proxy_active_health(&mut health_checks).insert("port".into(), json!(value));
            }
            "health_headers" => {
                let mut headers = Map::new();
                let nesting = h.d.nesting();
                while h.d.next_block(nesting) {
                    let key = h.d.val();
                    let mut values = h.d.remaining_args();
                    if values.is_empty() {
                        values.push(String::new());
                    }
                    headers
                        .entry(key)
                        .or_insert_with(|| Value::Array(Vec::new()))
                        .as_array_mut()
                        .expect("health header values must remain an array")
                        .extend(values.into_iter().map(Value::String));
                }
                reverse_proxy_active_health(&mut health_checks)
                    .insert("headers".into(), Value::Object(headers));
            }
            "health_interval" | "health_timeout" => {
                let key = if h.d.val() == "health_interval" {
                    "interval"
                } else {
                    "timeout"
                };
                if !h.d.next_arg() {
                    return Err(h.d.arg_err());
                }
                let value = parse_duration_ns(&h.d.val())?;
                if h.d.next_arg() {
                    return Err(h.d.arg_err());
                }
                reverse_proxy_active_health(&mut health_checks).insert(key.into(), json!(value));
            }
            "health_status" => {
                if !h.d.next_arg() {
                    return Err(h.d.arg_err());
                }
                let value = parse_reverse_proxy_health_status(&h.d.val(), &h.d)?;
                if h.d.next_arg() {
                    return Err(h.d.arg_err());
                }
                reverse_proxy_active_health(&mut health_checks)
                    .insert("expect_status".into(), json!(value));
            }
            "health_follow_redirects" => {
                if h.d.next_arg() {
                    return Err(h.d.arg_err());
                }
                reverse_proxy_active_health(&mut health_checks)
                    .insert("follow_redirects".into(), json!(true));
            }
            "health_passes" | "health_fails" => {
                let key = if h.d.val() == "health_passes" {
                    "passes"
                } else {
                    "fails"
                };
                if !h.d.next_arg() {
                    return Err(h.d.arg_err());
                }
                let raw = h.d.val();
                let value: i64 = raw
                    .parse()
                    .map_err(|e| h.d.errf(format!("invalid {key} count '{raw}': {e}")))?;
                if h.d.next_arg() {
                    return Err(h.d.arg_err());
                }
                reverse_proxy_active_health(&mut health_checks).insert(key.into(), json!(value));
            }
            "max_fails" => {
                if !h.d.next_arg() {
                    return Err(h.d.arg_err());
                }
                let raw = h.d.val();
                let value: i64 = raw
                    .parse()
                    .map_err(|e| h.d.errf(format!("invalid maximum fail count '{raw}': {e}")))?;
                if h.d.next_arg() {
                    return Err(h.d.arg_err());
                }
                reverse_proxy_passive_health(&mut health_checks)
                    .insert("max_fails".into(), json!(value));
            }
            "fail_duration" => {
                if !h.d.next_arg() {
                    return Err(h.d.arg_err());
                }
                let value = parse_duration_ns(&h.d.val())?;
                if h.d.next_arg() {
                    return Err(h.d.arg_err());
                }
                reverse_proxy_passive_health(&mut health_checks)
                    .insert("fail_duration".into(), json!(value));
            }
            "unhealthy_request_count" => {
                if !h.d.next_arg() {
                    return Err(h.d.arg_err());
                }
                let raw = h.d.val();
                let value: i64 = raw.parse().map_err(|e| {
                    h.d.errf(format!("invalid maximum connection count '{raw}': {e}"))
                })?;
                if h.d.next_arg() {
                    return Err(h.d.arg_err());
                }
                reverse_proxy_passive_health(&mut health_checks)
                    .insert("unhealthy_request_count".into(), json!(value));
            }
            "unhealthy_status" => {
                let args = h.d.remaining_args();
                if args.is_empty() {
                    return Err(h.d.arg_err());
                }
                let mut statuses = Vec::new();
                for arg in args {
                    statuses.push(json!(parse_reverse_proxy_health_status(&arg, &h.d)?));
                }
                reverse_proxy_passive_health(&mut health_checks)
                    .insert("unhealthy_status".into(), Value::Array(statuses));
            }
            "unhealthy_latency" => {
                if !h.d.next_arg() {
                    return Err(h.d.arg_err());
                }
                let value = parse_duration_ns(&h.d.val())?;
                if h.d.next_arg() {
                    return Err(h.d.arg_err());
                }
                reverse_proxy_passive_health(&mut health_checks)
                    .insert("unhealthy_latency".into(), json!(value));
            }
            "flush_interval" => {
                if !h.d.next_arg() {
                    return Err(h.d.arg_err());
                }
                runtime.insert(
                    "flush_interval".into(),
                    json!(parse_duration_ns(&h.d.val())?),
                );
                if h.d.next_arg() {
                    return Err(h.d.arg_err());
                }
            }
            "request_buffers" | "response_buffers" | "stream_buffer_size" => {
                let key = h.d.val();
                if !h.d.next_arg() {
                    return Err(h.d.arg_err());
                }
                runtime.insert(key, json!(parse_proxy_buffer_size(&h.d.val())?));
                if h.d.next_arg() {
                    return Err(h.d.arg_err());
                }
            }
            "stream_timeout" | "stream_close_delay" => {
                let key = h.d.val();
                if !h.d.next_arg() {
                    return Err(h.d.arg_err());
                }
                runtime.insert(key, json!(parse_duration_ns(&h.d.val())?));
                if h.d.next_arg() {
                    return Err(h.d.arg_err());
                }
            }
            "trusted_proxies" => {
                while h.d.next_arg() {
                    if h.d.val() == "private_ranges" {
                        trusted_proxies
                            .extend(private_ranges_cidr().into_iter().map(str::to_string));
                    } else {
                        trusted_proxies.push(h.d.val());
                    }
                }
            }
            "verbose_logs" => {
                if verbose_logs {
                    bail!("verbose_logs already specified");
                }
                if h.d.next_arg() {
                    return Err(h.d.arg_err());
                }
                verbose_logs = true;
            }
            "transport" => bail!("transport already specified"),
            other => bail!("unsupported php_fastcgi subdirective '{other}'"),
        }
    }

    if upstreams.is_empty() && dynamic_upstreams.is_none() {
        bail!("php_fastcgi requires at least one upstream");
    }
    transport
        .entry("split_path")
        .or_insert_with(|| json!(extensions.clone()));

    let mut routes = Vec::<Route>::new();
    if index_file != "off" {
        let dir_index = format!("{{http.request.uri.path}}/{index_file}");
        let selected_try_files = try_files.unwrap_or_else(|| {
            vec![
                "{http.request.uri.path}".to_string(),
                dir_index.clone(),
                index_file.clone(),
            ]
        });
        let try_policy = if selected_try_files.last().is_some_and(|last| {
            extensions
                .iter()
                .any(|extension| last.ends_with(extension.as_str()))
        }) {
            "first_exist_fallback"
        } else {
            ""
        };
        let dir_redir = selected_try_files.iter().any(|file| file == &dir_index);

        if dir_redir {
            routes.push(Route {
                matcher_sets: vec![json!({
                    "file": { "try_files": [dir_index] },
                    "not": [{ "path": ["*/"] }]
                })],
                handlers: vec![json!({
                    "handler": "static_response",
                    "status_code": 308,
                    "headers": {
                        "Location": ["{http.request.orig_uri.path}/{http.request.orig_uri.prefixed_query}"]
                    }
                })],
                ..Default::default()
            });
        }

        let mut file_matcher = json!({
            "try_files": selected_try_files,
            "split_path": transport["split_path"].clone()
        });
        if !try_policy.is_empty() {
            file_matcher["try_policy"] = json!(try_policy);
        }
        routes.push(Route {
            matcher_sets: vec![json!({ "file": file_matcher })],
            handlers: vec![json!({
                "handler": "rewrite",
                "uri": "{http.matchers.file.relative}"
            })],
            ..Default::default()
        });
    }

    let php_paths = extensions
        .iter()
        .map(|ext| format!("*{ext}"))
        .collect::<Vec<_>>();
    let mut proxy = Map::new();
    proxy.insert("handler".into(), json!("reverse_proxy"));
    proxy.insert("upstreams".into(), Value::Array(upstreams));
    proxy.insert("transport".into(), Value::Object(transport));
    if let Some(headers) = headers.to_json() {
        proxy.insert("headers".into(), headers);
    }
    if !rewrite.is_empty() {
        proxy.insert("rewrite".into(), Value::Object(rewrite));
    }
    if let Some(lb) = load_balancing {
        proxy.insert("load_balancing".into(), Value::Object(lb));
    }
    if let Some(health_checks) = health_checks {
        proxy.insert("health_checks".into(), Value::Object(health_checks));
    }
    if let Some(dynamic_upstreams) = dynamic_upstreams {
        proxy.insert("dynamic_upstreams".into(), dynamic_upstreams);
    }
    if !trusted_proxies.is_empty() {
        proxy.insert("trusted_proxies".into(), json!(trusted_proxies));
    }
    if !runtime.is_empty() {
        proxy.extend(runtime);
    }
    if verbose_logs {
        proxy.insert("verbose_logs".into(), json!(true));
    }
    let handle_response = resolve_pending_response_handlers(handle_response, &response_matchers)?;
    if !handle_response.is_empty() {
        proxy.insert("handle_response".into(), Value::Array(handle_response));
    }
    routes.push(Route {
        matcher_sets: vec![json!({ "path": php_paths })],
        handlers: vec![Value::Object(proxy)],
        ..Default::default()
    });

    let subroute = Subroute {
        routes,
        errors: Vec::new(),
    };
    if matcher.is_none() {
        Ok(vec![ConfigValue {
            class: "route".into(),
            directive: "php_fastcgi".into(),
            value: RouteOrSub::Sub(subroute),
        }])
    } else {
        let matcher_sets = matcher.map(|m| vec![m]).unwrap_or_default();
        Ok(vec![ConfigValue {
            class: "route".into(),
            directive: "php_fastcgi".into(),
            value: RouteOrSub::Route(Route {
                matcher_sets,
                handlers: vec![subroute.to_handler_json()],
                ..Default::default()
            }),
        }])
    }
}

// --- reverse_proxy (common subset) -------------------------------------------

fn parse_reverse_proxy(h: &mut Helper) -> Result<Value> {
    h.d.next();
    parse_reverse_proxy_inner(h, ReverseProxyShortcut::None)
}

fn parse_forward_auth(h: &mut Helper) -> Result<Vec<ConfigValue>> {
    h.d.next();
    let matcher = h.extract_matcher_set()?;
    h.d.next();
    let handler = parse_reverse_proxy_inner(h, ReverseProxyShortcut::ForwardAuth)?;
    Ok(h.new_route(matcher, handler))
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ReverseProxyShortcut {
    None,
    ForwardAuth,
}

fn parse_reverse_proxy_inner(h: &mut Helper, shortcut: ReverseProxyShortcut) -> Result<Value> {
    let mut upstreams: Vec<Value> = Vec::new();
    let mut common_scheme = String::new();
    let mut headers = HeadersHandler::default();
    let mut rewrite = Map::new();
    let mut load_balancing: Option<Map<String, Value>> = None;
    let mut health_checks: Option<Map<String, Value>> = None;
    let mut dynamic_upstreams: Option<Value> = None;
    let mut runtime = Map::new();
    let mut transport: Option<Value> = None;
    let mut trusted_proxies = Vec::<String>::new();
    let mut verbose_logs = false;
    let mut forward_auth_uri: Option<String> = None;
    let mut forward_auth_copy_headers = HashMap::<String, String>::new();
    let mut response_matchers = HashMap::<String, Value>::new();
    let mut handle_response = Vec::<PendingResponseHandler>::new();

    if shortcut == ReverseProxyShortcut::ForwardAuth {
        append_header(
            &mut headers.request_ops().set,
            "X-Forwarded-Method",
            "{http.request.method}",
        );
        append_header(
            &mut headers.request_ops().set,
            "X-Forwarded-Uri",
            "{http.request.uri}",
        );
        rewrite.insert("method".into(), json!("GET"));
    }

    for up in h.d.remaining_args() {
        append_upstream(&up, &mut upstreams, &mut common_scheme)?;
    }

    while h.d.next_block(0) {
        let sub = h.d.val();
        if sub.starts_with('@') {
            parse_response_matcher_definition(&mut h.d, &mut response_matchers)?;
            continue;
        }
        match sub.as_str() {
            "to" => {
                let args = h.d.remaining_args();
                if args.is_empty() {
                    return Err(h.d.arg_err());
                }
                for up in args {
                    append_upstream(&up, &mut upstreams, &mut common_scheme)?;
                }
            }
            "dynamic" => {
                if dynamic_upstreams.is_some() {
                    bail!("dynamic upstreams already specified");
                }
                if !h.d.next_arg() {
                    return Err(h.d.arg_err());
                }
                dynamic_upstreams = Some(parse_dynamic_upstream_source(&mut h.d)?);
            }
            "header_up" => {
                let args = h.d.remaining_args();
                apply_header_args(&mut headers.request_ops(), args, &h.d)?;
            }
            "header_down" => {
                let args = h.d.remaining_args();
                let ops = headers.response_ops();
                apply_header_args(ops, args, &h.d)?;
            }
            "method" => {
                if !h.d.next_arg() {
                    return Err(h.d.arg_err());
                }
                rewrite.insert("method".into(), json!(h.d.val()));
                if h.d.next_arg() {
                    return Err(h.d.arg_err());
                }
            }
            "rewrite" => {
                if !h.d.next_arg() {
                    return Err(h.d.arg_err());
                }
                rewrite.insert("uri".into(), json!(h.d.val()));
                if h.d.next_arg() {
                    return Err(h.d.arg_err());
                }
            }
            "uri" if shortcut == ReverseProxyShortcut::ForwardAuth => {
                if !h.d.next_arg() {
                    return Err(h.d.arg_err());
                }
                forward_auth_uri = Some(h.d.val());
                if h.d.next_arg() {
                    return Err(h.d.arg_err());
                }
            }
            "copy_headers" if shortcut == ReverseProxyShortcut::ForwardAuth => {
                let mut args = h.d.remaining_args();
                let nesting = h.d.nesting();
                while h.d.next_block(nesting) {
                    args.push(h.d.val());
                    if h.d.next_arg() {
                        return Err(h.d.arg_err());
                    }
                }
                if args.is_empty() {
                    return Err(h.d.arg_err());
                }
                for header in args {
                    if let Some((from, to)) = header.split_once('>') {
                        if from.is_empty() || to.is_empty() {
                            return Err(h.d.arg_err());
                        }
                        forward_auth_copy_headers.insert(from.to_string(), to.to_string());
                    } else {
                        forward_auth_copy_headers.insert(header.clone(), header);
                    }
                }
            }
            "replace_status" => {
                let args = h.d.remaining_args();
                let pending = parse_replace_status_args(&args, &h.d)?;
                handle_response.push(pending);
            }
            "handle_response" => {
                let args = h.d.remaining_args();
                let pending = parse_handle_response_block(h, &args)?;
                handle_response.push(pending);
            }
            "lb_policy" => {
                if !h.d.next_arg() {
                    return Err(h.d.arg_err());
                }
                let selection_policy = parse_reverse_proxy_selection_policy(&mut h.d)?;
                load_balancing
                    .get_or_insert_with(Map::new)
                    .insert("selection_policy".into(), selection_policy);
            }
            "lb_retries" => {
                if !h.d.next_arg() {
                    return Err(h.d.arg_err());
                }
                let raw = h.d.val();
                let n: i64 = raw
                    .parse()
                    .map_err(|e| h.d.errf(format!("bad lb_retries number '{raw}': {e}")))?;
                if h.d.next_arg() {
                    return Err(h.d.arg_err());
                }
                load_balancing
                    .get_or_insert_with(Map::new)
                    .insert("retries".into(), json!(n));
            }
            "lb_try_duration" => {
                if !h.d.next_arg() {
                    return Err(h.d.arg_err());
                }
                let value = parse_duration_ns(&h.d.val())?;
                if h.d.next_arg() {
                    return Err(h.d.arg_err());
                }
                load_balancing
                    .get_or_insert_with(Map::new)
                    .insert("try_duration".into(), json!(value));
            }
            "lb_try_interval" => {
                if !h.d.next_arg() {
                    return Err(h.d.arg_err());
                }
                let value = parse_duration_ns(&h.d.val())?;
                if h.d.next_arg() {
                    return Err(h.d.arg_err());
                }
                load_balancing
                    .get_or_insert_with(Map::new)
                    .insert("try_interval".into(), json!(value));
            }
            "lb_retry_match" => {
                let matcher = matchers::parse_nested_matcher_set(&mut h.d)
                    .map_err(|e| h.d.errf(format!("failed to parse lb_retry_match: {e}")))?;
                load_balancing
                    .get_or_insert_with(Map::new)
                    .entry("retry_match")
                    .or_insert_with(|| Value::Array(Vec::new()))
                    .as_array_mut()
                    .expect("reverse_proxy retry_match must remain an array")
                    .push(matcher);
            }
            "health_uri"
            | "health_path"
            | "health_method"
            | "health_request_body"
            | "health_body" => {
                let key = match sub.as_str() {
                    "health_uri" => "uri",
                    "health_path" => "path",
                    "health_method" => "method",
                    "health_request_body" => "body",
                    "health_body" => "expect_body",
                    _ => unreachable!(),
                };
                if !h.d.next_arg() {
                    return Err(h.d.arg_err());
                }
                let value = h.d.val();
                if h.d.next_arg() {
                    return Err(h.d.arg_err());
                }
                reverse_proxy_active_health(&mut health_checks).insert(key.into(), json!(value));
            }
            "health_upstream" => {
                if !h.d.next_arg() {
                    return Err(h.d.arg_err());
                }
                let upstream = h.d.val();
                validate_health_upstream(&upstream, &h.d)?;
                if h.d.next_arg() {
                    return Err(h.d.arg_err());
                }
                reverse_proxy_active_health(&mut health_checks)
                    .insert("upstream".into(), json!(upstream));
            }
            "health_port" => {
                if reverse_proxy_active_health(&mut health_checks).contains_key("upstream") {
                    bail!(
                        "the 'health_port' subdirective is ignored if 'health_upstream' is used!"
                    );
                }
                if !h.d.next_arg() {
                    return Err(h.d.arg_err());
                }
                let raw = h.d.val();
                let value: i64 = raw
                    .parse()
                    .map_err(|e| h.d.errf(format!("bad port number '{raw}': {e}")))?;
                if h.d.next_arg() {
                    return Err(h.d.arg_err());
                }
                reverse_proxy_active_health(&mut health_checks).insert("port".into(), json!(value));
            }
            "health_headers" => {
                let mut headers = Map::new();
                let nesting = h.d.nesting();
                while h.d.next_block(nesting) {
                    let key = h.d.val();
                    let mut values = h.d.remaining_args();
                    if values.is_empty() {
                        values.push(String::new());
                    }
                    headers
                        .entry(key)
                        .or_insert_with(|| Value::Array(Vec::new()))
                        .as_array_mut()
                        .expect("health header values must remain an array")
                        .extend(values.into_iter().map(Value::String));
                }
                reverse_proxy_active_health(&mut health_checks)
                    .insert("headers".into(), Value::Object(headers));
            }
            "health_interval" | "health_timeout" => {
                let key = if sub == "health_interval" {
                    "interval"
                } else {
                    "timeout"
                };
                if !h.d.next_arg() {
                    return Err(h.d.arg_err());
                }
                let value = parse_duration_ns(&h.d.val())?;
                if h.d.next_arg() {
                    return Err(h.d.arg_err());
                }
                reverse_proxy_active_health(&mut health_checks).insert(key.into(), json!(value));
            }
            "health_status" => {
                if !h.d.next_arg() {
                    return Err(h.d.arg_err());
                }
                let value = parse_reverse_proxy_health_status(&h.d.val(), &h.d)?;
                if h.d.next_arg() {
                    return Err(h.d.arg_err());
                }
                reverse_proxy_active_health(&mut health_checks)
                    .insert("expect_status".into(), json!(value));
            }
            "health_follow_redirects" => {
                if h.d.next_arg() {
                    return Err(h.d.arg_err());
                }
                reverse_proxy_active_health(&mut health_checks)
                    .insert("follow_redirects".into(), json!(true));
            }
            "health_passes" | "health_fails" => {
                let key = if sub == "health_passes" {
                    "passes"
                } else {
                    "fails"
                };
                if !h.d.next_arg() {
                    return Err(h.d.arg_err());
                }
                let raw = h.d.val();
                let value: i64 = raw
                    .parse()
                    .map_err(|e| h.d.errf(format!("invalid {key} count '{raw}': {e}")))?;
                if h.d.next_arg() {
                    return Err(h.d.arg_err());
                }
                reverse_proxy_active_health(&mut health_checks).insert(key.into(), json!(value));
            }
            "max_fails" => {
                if !h.d.next_arg() {
                    return Err(h.d.arg_err());
                }
                let raw = h.d.val();
                let value: i64 = raw
                    .parse()
                    .map_err(|e| h.d.errf(format!("invalid maximum fail count '{raw}': {e}")))?;
                if h.d.next_arg() {
                    return Err(h.d.arg_err());
                }
                reverse_proxy_passive_health(&mut health_checks)
                    .insert("max_fails".into(), json!(value));
            }
            "fail_duration" => {
                if !h.d.next_arg() {
                    return Err(h.d.arg_err());
                }
                let value = parse_duration_ns(&h.d.val())?;
                if h.d.next_arg() {
                    return Err(h.d.arg_err());
                }
                reverse_proxy_passive_health(&mut health_checks)
                    .insert("fail_duration".into(), json!(value));
            }
            "unhealthy_request_count" => {
                if !h.d.next_arg() {
                    return Err(h.d.arg_err());
                }
                let raw = h.d.val();
                let value: i64 = raw.parse().map_err(|e| {
                    h.d.errf(format!("invalid maximum connection count '{raw}': {e}"))
                })?;
                if h.d.next_arg() {
                    return Err(h.d.arg_err());
                }
                reverse_proxy_passive_health(&mut health_checks)
                    .insert("unhealthy_request_count".into(), json!(value));
            }
            "unhealthy_status" => {
                let args = h.d.remaining_args();
                if args.is_empty() {
                    return Err(h.d.arg_err());
                }
                let mut statuses = Vec::new();
                for arg in args {
                    statuses.push(json!(parse_reverse_proxy_health_status(&arg, &h.d)?));
                }
                reverse_proxy_passive_health(&mut health_checks)
                    .insert("unhealthy_status".into(), Value::Array(statuses));
            }
            "unhealthy_latency" => {
                if !h.d.next_arg() {
                    return Err(h.d.arg_err());
                }
                let value = parse_duration_ns(&h.d.val())?;
                if h.d.next_arg() {
                    return Err(h.d.arg_err());
                }
                reverse_proxy_passive_health(&mut health_checks)
                    .insert("unhealthy_latency".into(), json!(value));
            }
            "flush_interval" => {
                if !h.d.next_arg() {
                    return Err(h.d.arg_err());
                }
                runtime.insert(
                    "flush_interval".into(),
                    json!(parse_duration_ns(&h.d.val())?),
                );
                if h.d.next_arg() {
                    return Err(h.d.arg_err());
                }
            }
            "request_buffers" | "response_buffers" | "stream_buffer_size" => {
                let key = h.d.val();
                if !h.d.next_arg() {
                    return Err(h.d.arg_err());
                }
                runtime.insert(key, json!(parse_proxy_buffer_size(&h.d.val())?));
                if h.d.next_arg() {
                    return Err(h.d.arg_err());
                }
            }
            "stream_timeout" | "stream_close_delay" => {
                let key = h.d.val();
                if !h.d.next_arg() {
                    return Err(h.d.arg_err());
                }
                runtime.insert(key, json!(parse_duration_ns(&h.d.val())?));
                if h.d.next_arg() {
                    return Err(h.d.arg_err());
                }
            }
            "trusted_proxies" => {
                while h.d.next_arg() {
                    if h.d.val() == "private_ranges" {
                        trusted_proxies
                            .extend(private_ranges_cidr().into_iter().map(str::to_string));
                    } else {
                        trusted_proxies.push(h.d.val());
                    }
                }
            }
            "verbose_logs" => {
                if verbose_logs {
                    bail!("verbose_logs already specified");
                }
                if h.d.next_arg() {
                    return Err(h.d.arg_err());
                }
                verbose_logs = true;
            }
            "transport" => {
                if transport.is_some() {
                    bail!("transport already specified");
                }
                transport = Some(parse_reverse_proxy_transport(&mut h.d)?);
            }
            other => bail!("unrecognized subdirective {other}"),
        }
    }

    if shortcut == ReverseProxyShortcut::ForwardAuth {
        let Some(forward_auth_uri) = forward_auth_uri else {
            bail!("the 'uri' subdirective is required");
        };
        if !rewrite.contains_key("uri") {
            rewrite.insert("uri".into(), json!(forward_auth_uri));
        }
        handle_response.push(forward_auth_response_handler(forward_auth_copy_headers));
    }

    let mut m = Map::new();
    m.insert("handler".into(), json!("reverse_proxy"));
    if !upstreams.is_empty() {
        m.insert("upstreams".into(), Value::Array(upstreams));
    }
    if let Some(h) = headers.to_json() {
        m.insert("headers".into(), h);
    }
    if !rewrite.is_empty() {
        // reverse_proxy nests rewrite options under "rewrite" (no handler key).
        m.insert("rewrite".into(), Value::Object(rewrite));
    }
    if let Some(lb) = load_balancing {
        m.insert("load_balancing".into(), Value::Object(lb));
    }
    if let Some(health_checks) = health_checks {
        m.insert("health_checks".into(), Value::Object(health_checks));
    }
    if let Some(dynamic_upstreams) = dynamic_upstreams {
        m.insert("dynamic_upstreams".into(), dynamic_upstreams);
    }
    if !runtime.is_empty() {
        m.extend(runtime);
    }
    if !trusted_proxies.is_empty() {
        m.insert("trusted_proxies".into(), json!(trusted_proxies));
    }
    if verbose_logs {
        m.insert("verbose_logs".into(), json!(true));
    }
    let handle_response = resolve_pending_response_handlers(handle_response, &response_matchers)?;
    if !handle_response.is_empty() {
        m.insert("handle_response".into(), Value::Array(handle_response));
    }
    if let Some(transport) = transport.or_else(|| transport_for_scheme(&common_scheme)) {
        m.insert("transport".into(), transport);
    }
    Ok(Value::Object(m))
}

fn reverse_proxy_passive_health(
    health_checks: &mut Option<Map<String, Value>>,
) -> &mut Map<String, Value> {
    let health_checks = health_checks.get_or_insert_with(Map::new);
    health_checks
        .entry("passive")
        .or_insert_with(|| Value::Object(Map::new()))
        .as_object_mut()
        .expect("reverse_proxy passive health must remain an object")
}

fn reverse_proxy_active_health(
    health_checks: &mut Option<Map<String, Value>>,
) -> &mut Map<String, Value> {
    let health_checks = health_checks.get_or_insert_with(Map::new);
    health_checks
        .entry("active")
        .or_insert_with(|| Value::Object(Map::new()))
        .as_object_mut()
        .expect("reverse_proxy active health must remain an object")
}

fn parse_reverse_proxy_selection_policy(d: &mut Dispenser) -> Result<Value> {
    let policy = d.val();
    let mut m = Map::new();
    m.insert("policy".into(), json!(policy));
    match policy.as_str() {
        "random" | "least_conn" | "round_robin" | "first" | "ip_hash" | "client_ip_hash"
        | "uri_hash" => {
            if d.next_arg() {
                return Err(d.arg_err());
            }
        }
        "weighted_round_robin" => {
            let args = d.remaining_args();
            if args.is_empty() {
                return Err(d.arg_err());
            }
            let mut weights = Vec::new();
            for raw in args {
                let value: i64 = raw
                    .parse()
                    .map_err(|e| d.errf(format!("invalid weight value '{raw}': {e}")))?;
                if value < 0 {
                    bail!("invalid weight value '{raw}': weight should be non-negative");
                }
                weights.push(value);
            }
            m.insert("weights".into(), json!(weights));
        }
        "random_choose" => {
            if !d.next_arg() {
                return Err(d.arg_err());
            }
            let raw = d.val();
            let choose: i64 = raw
                .parse()
                .map_err(|e| d.errf(format!("invalid choice value '{raw}': {e}")))?;
            m.insert("choose".into(), json!(choose));
            if d.next_arg() {
                return Err(d.arg_err());
            }
        }
        "query" => {
            if !d.next_arg() {
                return Err(d.arg_err());
            }
            m.insert("key".into(), json!(d.val()));
            if d.next_arg() {
                return Err(d.arg_err());
            }
            parse_selection_policy_fallback_block(d, &mut m)?;
        }
        "header" => {
            if !d.next_arg() {
                return Err(d.arg_err());
            }
            m.insert("field".into(), json!(d.val()));
            if d.next_arg() {
                return Err(d.arg_err());
            }
            parse_selection_policy_fallback_block(d, &mut m)?;
        }
        "cookie" => {
            let args = d.remaining_args();
            match args.as_slice() {
                [] => {}
                [name] => {
                    m.insert("name".into(), json!(name));
                }
                [name, secret] => {
                    m.insert("name".into(), json!(name));
                    m.insert("secret".into(), json!(secret));
                }
                _ => return Err(d.arg_err()),
            }
            parse_cookie_selection_policy_block(d, &mut m)?;
        }
        other => bail!("unrecognized selection policy '{other}'"),
    }
    Ok(Value::Object(m))
}

fn parse_selection_policy_fallback_block(
    d: &mut Dispenser,
    m: &mut Map<String, Value>,
) -> Result<()> {
    let nesting = d.nesting();
    while d.next_block(nesting) {
        match d.val().as_str() {
            "fallback" => {
                if !d.next_arg() {
                    return Err(d.arg_err());
                }
                if m.contains_key("fallback") {
                    bail!("fallback selection policy already specified");
                }
                let fallback = parse_reverse_proxy_selection_policy(d)?;
                m.insert("fallback".into(), fallback);
            }
            other => bail!("unrecognized option '{other}'"),
        }
    }
    Ok(())
}

fn parse_cookie_selection_policy_block(
    d: &mut Dispenser,
    m: &mut Map<String, Value>,
) -> Result<()> {
    let nesting = d.nesting();
    while d.next_block(nesting) {
        match d.val().as_str() {
            "fallback" => {
                if !d.next_arg() {
                    return Err(d.arg_err());
                }
                if m.contains_key("fallback") {
                    bail!("fallback selection policy already specified");
                }
                let fallback = parse_reverse_proxy_selection_policy(d)?;
                m.insert("fallback".into(), fallback);
            }
            "max_age" => {
                if !d.next_arg() {
                    return Err(d.arg_err());
                }
                if m.contains_key("max_age") {
                    bail!("cookie max_age already specified");
                }
                let raw = d.val();
                let max_age = parse_duration_ns(&raw)
                    .map_err(|_| d.errf(format!("invalid duration: {raw}")))?;
                if max_age <= 0 {
                    bail!("invalid duration: {raw}, max_age should be non-zero and positive");
                }
                m.insert("max_age".into(), json!(max_age));
                if d.next_arg() {
                    return Err(d.arg_err());
                }
            }
            other => bail!("unrecognized option '{other}'"),
        }
    }
    Ok(())
}

fn parse_reverse_proxy_health_status(value: &str, d: &Dispenser) -> Result<i64> {
    let status = if value.len() == 3 && value.ends_with("xx") {
        &value[..1]
    } else {
        value
    };
    status
        .parse::<i64>()
        .map_err(|e| d.errf(format!("bad status value '{value}': {e}")))
}

fn validate_health_upstream(value: &str, d: &Dispenser) -> Result<()> {
    let Some((_, port)) = value.rsplit_once(':') else {
        bail!("health_upstream is malformed '{value}'");
    };
    port.parse::<u16>()
        .map_err(|e| d.errf(format!("bad port number '{value}': {e}")))?;
    Ok(())
}

#[derive(Debug)]
struct PendingResponseHandler {
    matcher: Option<String>,
    match_value: Option<Value>,
    routes: Option<Vec<Value>>,
    status_code: Option<Value>,
}

fn forward_auth_response_handler(copy_headers: HashMap<String, String>) -> PendingResponseHandler {
    let mut routes = vec![json!({ "handle": [{ "handler": "vars" }] })];
    let mut headers = copy_headers.into_iter().collect::<Vec<_>>();
    headers.sort_by(|(a, _), (b, _)| a.cmp(b));

    for (from, to) in headers {
        let to = canonical_header_key(&to);
        let from = canonical_header_key(&from);
        let placeholder = format!("http.reverse_proxy.header.{from}");
        let placeholder_braced = format!("{{{placeholder}}}");
        routes.push(json!({
            "handle": [{
                "handler": "headers",
                "request": { "delete": [to] }
            }]
        }));
        routes.push(json!({
            "match": [{
                "not": [{
                    "vars": { placeholder_braced: [""] }
                }]
            }],
            "handle": [{
                "handler": "headers",
                "request": { "set": { to: [format!("{{{placeholder}}}")] } }
            }]
        }));
    }

    PendingResponseHandler {
        matcher: None,
        match_value: Some(json!({ "status_code": [2] })),
        routes: Some(routes),
        status_code: None,
    }
}

fn parse_response_matcher_definition(
    d: &mut Dispenser,
    response_matchers: &mut HashMap<String, Value>,
) -> Result<()> {
    let name = d.val();
    let stored_name = if name == "match" {
        "@match".to_string()
    } else if name.starts_with('@') && name.len() > 1 {
        name.clone()
    } else {
        return Err(d.arg_err());
    };
    if response_matchers.contains_key(&stored_name) {
        bail!("response matcher is defined more than once: {stored_name}");
    }

    let mut matcher = Map::new();
    let mut headers = Map::new();
    let mut statuses = Vec::<Value>::new();
    let nesting = d.nesting();
    while d.next_arg() || d.next_block(nesting) {
        match d.val().as_str() {
            "status" => {
                let args = d.remaining_args();
                if args.is_empty() {
                    return Err(d.arg_err());
                }
                for status in args {
                    statuses.push(json!(parse_response_status_match(&status, d)?));
                }
            }
            "header" => {
                parse_response_header_matcher_line(d, &mut headers)?;
            }
            other => bail!("unrecognized response matcher {other}"),
        }
    }
    if !statuses.is_empty() {
        matcher.insert("status_code".into(), Value::Array(statuses));
    }
    if !headers.is_empty() {
        matcher.insert("headers".into(), Value::Object(headers));
    }
    response_matchers.insert(stored_name, Value::Object(matcher));
    Ok(())
}

fn parse_response_status_match(status: &str, d: &Dispenser) -> Result<i64> {
    if status.len() == 3 && status.ends_with("xx") {
        return status[..1]
            .parse::<i64>()
            .map_err(|e| d.errf(format!("bad status value '{status}': {e}")));
    }
    status
        .parse::<i64>()
        .map_err(|e| d.errf(format!("bad status value '{status}': {e}")))
}

fn parse_response_header_matcher_line(
    d: &mut Dispenser,
    headers: &mut Map<String, Value>,
) -> Result<()> {
    if !d.next_arg() {
        bail!("malformed header matcher: expected field");
    }
    let mut field = d.val();
    if let Some(stripped) = field.strip_prefix('!') {
        if stripped.is_empty() {
            bail!("malformed header matcher: must have field name following ! character");
        }
        field = stripped.to_string();
        headers.insert(field, Value::Null);
        if d.next_arg() {
            bail!("malformed header matcher: null matching headers cannot have a field value");
        }
        return Ok(());
    }
    if !d.next_arg() {
        bail!("malformed header matcher: expected both field and value");
    }
    let value = d.val();
    let field = canonical_header_key(&field);
    let entry = headers
        .entry(field)
        .or_insert_with(|| Value::Array(Vec::new()));
    if entry.is_null() {
        *entry = Value::Array(Vec::new());
    }
    let values = entry
        .as_array_mut()
        .expect("response header matcher values are arrays after null promotion");
    values.push(json!(value));
    Ok(())
}

fn parse_replace_status_args(args: &[String], d: &Dispenser) -> Result<PendingResponseHandler> {
    let (matcher, status) = match args {
        [status] => (None, status),
        [matcher, status] if matcher.starts_with('@') => (Some(matcher.clone()), status),
        _ => return Err(d.arg_err()),
    };
    Ok(PendingResponseHandler {
        matcher,
        match_value: None,
        routes: None,
        status_code: Some(weak_string(status)),
    })
}

fn parse_handle_response_block(h: &mut Helper, args: &[String]) -> Result<PendingResponseHandler> {
    let matcher = match args {
        [] => None,
        [matcher] if matcher.starts_with('@') => Some(matcher.clone()),
        [_] => bail!("must use a named response matcher, starting with '@'"),
        _ => bail!("too many arguments for 'handle_response': {args:?}"),
    };
    let subroute = parse_current_block_as_subroute(h)?;
    Ok(PendingResponseHandler {
        matcher,
        match_value: None,
        routes: Some(subroute.routes.iter().map(Route::to_json).collect()),
        status_code: None,
    })
}

fn resolve_pending_response_handlers(
    pending: Vec<PendingResponseHandler>,
    response_matchers: &HashMap<String, Value>,
) -> Result<Vec<Value>> {
    let mut with_matchers = Vec::new();
    let mut without_matchers = Vec::new();
    for pending in pending {
        let mut handler = Map::new();
        if let Some(name) = pending.matcher {
            let matcher = response_matchers.get(&name).cloned().ok_or_else(|| {
                anyhow::anyhow!(
                    "no named response matcher defined with name '{}'",
                    &name[1..]
                )
            })?;
            handler.insert("match".into(), matcher);
        }
        if let Some(match_value) = pending.match_value {
            handler.insert("match".into(), match_value);
        }
        if let Some(routes) = pending.routes {
            handler.insert("routes".into(), Value::Array(routes));
        }
        if let Some(status_code) = pending.status_code {
            handler.insert("status_code".into(), status_code);
        }
        if handler.contains_key("match") {
            with_matchers.push(Value::Object(handler));
        } else {
            without_matchers.push(Value::Object(handler));
        }
    }
    with_matchers.extend(without_matchers);
    Ok(with_matchers)
}

fn parse_reverse_proxy_transport(d: &mut Dispenser) -> Result<Value> {
    if !d.next_arg() {
        return Err(d.arg_err());
    }
    let protocol = d.val();
    match protocol.as_str() {
        "http" => parse_reverse_proxy_http_transport(d),
        "fastcgi" => parse_reverse_proxy_fastcgi_transport(d),
        other => {
            let args = d.remaining_args();
            if !args.is_empty() {
                return Err(d.arg_err());
            }
            let mut m = Map::new();
            m.insert("protocol".into(), json!(other));
            consume_nested_block(d);
            Ok(Value::Object(m))
        }
    }
}

fn parse_reverse_proxy_fastcgi_transport(d: &mut Dispenser) -> Result<Value> {
    let args = d.remaining_args();
    if !args.is_empty() {
        return Err(d.arg_err());
    }
    let mut m = Map::new();
    m.insert("protocol".into(), json!("fastcgi"));
    let nesting = d.nesting();
    while d.next_block(nesting) {
        match d.val().as_str() {
            "split" => {
                let split_path = d.remaining_args();
                if split_path.is_empty() {
                    return Err(d.arg_err());
                }
                m.insert("split_path".into(), json!(split_path));
            }
            _ => {
                let _ = d.remaining_args();
                consume_nested_block(d);
            }
        }
    }
    Ok(Value::Object(m))
}

fn parse_reverse_proxy_http_transport(d: &mut Dispenser) -> Result<Value> {
    let args = d.remaining_args();
    if !args.is_empty() {
        return Err(d.arg_err());
    }
    let mut m = Map::new();
    m.insert("protocol".into(), json!("http"));
    let mut tls = Map::new();
    let nesting = d.nesting();
    while d.next_block(nesting) {
        match d.val().as_str() {
            "tls" => {
                if d.next_arg() {
                    return Err(d.arg_err());
                }
                m.insert("tls".into(), Value::Object(tls.clone()));
            }
            "tls_server_name" => {
                if !d.next_arg() {
                    return Err(d.arg_err());
                }
                tls.insert("server_name".into(), json!(d.val()));
                m.insert("tls".into(), Value::Object(tls.clone()));
                let _ = d.remaining_args();
            }
            "tls_insecure_skip_verify" => {
                if d.next_arg() {
                    return Err(d.arg_err());
                }
                tls.insert("insecure_skip_verify".into(), json!(true));
                m.insert("tls".into(), Value::Object(tls.clone()));
            }
            "tls_timeout" => {
                if !d.next_arg() {
                    return Err(d.arg_err());
                }
                tls.insert(
                    "handshake_timeout".into(),
                    json!(parse_duration_ns(&d.val())?),
                );
                m.insert("tls".into(), Value::Object(tls.clone()));
                let _ = d.remaining_args();
            }
            "tls_client_auth" => {
                let args = d.remaining_args();
                match args.as_slice() {
                    [automate] => {
                        tls.insert("client_certificate_automate".into(), json!(automate));
                    }
                    [cert, key] => {
                        tls.insert("client_certificate_file".into(), json!(cert));
                        tls.insert("client_certificate_key_file".into(), json!(key));
                    }
                    _ => return Err(d.arg_err()),
                }
                m.insert("tls".into(), Value::Object(tls.clone()));
            }
            "tls_trusted_ca_certs" => {
                let files = d.remaining_args();
                if files.is_empty() {
                    return Err(d.arg_err());
                }
                tls.insert("root_ca_pem_files".into(), json!(files));
                m.insert("tls".into(), Value::Object(tls.clone()));
            }
            "tls_curves" | "tls_except_ports" | "versions" | "resolvers" => {
                let key = match d.val().as_str() {
                    "tls_curves" => "curves".to_string(),
                    "tls_except_ports" => "except_ports".to_string(),
                    other => other.to_string(),
                };
                let values = d.remaining_args();
                if values.is_empty() {
                    return Err(d.arg_err());
                }
                if key == "resolvers" {
                    m.insert("resolver".into(), json!({ "addresses": values }));
                } else if key == "versions" {
                    m.insert(key.into(), json!(values));
                } else {
                    tls.insert(key.into(), json!(values));
                    m.insert("tls".into(), Value::Object(tls.clone()));
                }
            }
            "read_buffer" | "write_buffer" | "max_response_header" => {
                let key = match d.val().as_str() {
                    "read_buffer" => "read_buffer_size",
                    "write_buffer" => "write_buffer_size",
                    "max_response_header" => "max_response_header_size",
                    _ => unreachable!(),
                };
                if !d.next_arg() {
                    return Err(d.arg_err());
                }
                m.insert(key.into(), json!(parse_proxy_buffer_size(&d.val())?));
                let _ = d.remaining_args();
            }
            "read_timeout"
            | "write_timeout"
            | "dial_timeout"
            | "dial_fallback_delay"
            | "response_header_timeout"
            | "expect_continue_timeout" => {
                let key = match d.val().as_str() {
                    "dial_fallback_delay" => "dial_fallback_delay".to_string(),
                    other => other.to_string(),
                };
                if !d.next_arg() {
                    return Err(d.arg_err());
                }
                let val = d.val();
                m.insert(key.into(), json!(parse_duration_ns(&val)?));
                let _ = d.remaining_args();
            }
            "keepalive" => {
                if !d.next_arg() {
                    return Err(d.arg_err());
                }
                let val = d.val();
                if val == "off" {
                    reverse_proxy_keep_alive(&mut m).insert("enabled".into(), json!(false));
                } else {
                    reverse_proxy_keep_alive(&mut m)
                        .insert("idle_timeout".into(), json!(parse_duration_ns(&val)?));
                }
                let _ = d.remaining_args();
            }
            "keepalive_interval" => {
                if !d.next_arg() {
                    return Err(d.arg_err());
                }
                reverse_proxy_keep_alive(&mut m)
                    .insert("probe_interval".into(), json!(parse_duration_ns(&d.val())?));
                let _ = d.remaining_args();
            }
            "keepalive_idle_conns" | "keepalive_idle_conns_per_host" => {
                let key = match d.val().as_str() {
                    "keepalive_idle_conns" => "max_idle_conns",
                    "keepalive_idle_conns_per_host" => "max_idle_conns_per_host",
                    _ => unreachable!(),
                };
                if !d.next_arg() {
                    return Err(d.arg_err());
                }
                let raw = d.val();
                let value: i64 = raw
                    .parse()
                    .map_err(|e| d.errf(format!("bad integer value '{raw}': {e}")))?;
                reverse_proxy_keep_alive(&mut m).insert(key.into(), json!(value));
                let _ = d.remaining_args();
            }
            "compression" => {
                if d.next_arg() {
                    if d.val() == "off" {
                        m.insert("compression".into(), json!(false));
                    }
                    let _ = d.remaining_args();
                }
            }
            "proxy_protocol" => {
                if !d.next_arg() {
                    return Err(d.arg_err());
                }
                let protocol = d.val();
                match protocol.as_str() {
                    "v1" | "v2" => {}
                    other => bail!("invalid proxy protocol version '{other}'"),
                }
                m.insert("proxy_protocol".into(), json!(protocol));
                let _ = d.remaining_args();
            }
            "forward_proxy_url" => {
                if !d.next_arg() {
                    return Err(d.arg_err());
                }
                m.insert(
                    "network_proxy".into(),
                    json!({"from": "url", "url": d.val()}),
                );
                let _ = d.remaining_args();
            }
            "network_proxy" => {
                if !d.next_arg() {
                    return Err(d.arg_err());
                }
                let source = d.val();
                let mut proxy = Map::new();
                proxy.insert("from".into(), json!(source));
                match source.as_str() {
                    "url" => {
                        if !d.next_arg() {
                            return Err(d.arg_err());
                        }
                        proxy.insert("url".into(), json!(d.val()));
                        if d.next_arg() {
                            return Err(d.arg_err());
                        }
                    }
                    "none" => {
                        if d.next_arg() {
                            return Err(d.arg_err());
                        }
                    }
                    _ => {
                        let args = d.remaining_args();
                        if !args.is_empty() {
                            proxy.insert("args".into(), json!(args));
                        }
                        consume_nested_block(d);
                    }
                }
                m.insert("network_proxy".into(), Value::Object(proxy));
            }
            "tls_renegotiation" => {
                if !d.next_arg() {
                    return Err(d.arg_err());
                }
                let value = d.val();
                match value.as_str() {
                    "never" | "once" | "freely" => {}
                    _ => return Err(d.arg_err()),
                }
                tls.insert("renegotiation".into(), json!(value));
                m.insert("tls".into(), Value::Object(tls.clone()));
                let _ = d.remaining_args();
            }
            "max_conns_per_host" => {
                if !d.next_arg() {
                    return Err(d.arg_err());
                }
                let raw = d.val();
                let value: i64 = raw
                    .parse()
                    .map_err(|e| d.errf(format!("bad integer value '{raw}': {e}")))?;
                m.insert("max_conns_per_host".into(), json!(value));
                let _ = d.remaining_args();
            }
            "local_address" => {
                if !d.next_arg() {
                    return Err(d.arg_err());
                }
                m.insert("local_address".into(), json!(d.val()));
                let _ = d.remaining_args();
            }
            "tls_trust_pool" => {
                let key = d.val();
                let values = d.remaining_args();
                if values.is_empty() {
                    return Err(d.arg_err());
                }
                m.insert(key, json!(values));
                consume_nested_block(d);
            }
            other => bail!("unrecognized http transport subdirective '{other}'"),
        }
    }
    Ok(Value::Object(m))
}

fn reverse_proxy_keep_alive(transport: &mut Map<String, Value>) -> &mut Map<String, Value> {
    transport
        .entry("keep_alive")
        .or_insert_with(|| Value::Object(Map::new()))
        .as_object_mut()
        .expect("reverse_proxy keep_alive must remain an object")
}

fn parse_dynamic_upstream_source(d: &mut Dispenser) -> Result<Value> {
    let source = d.val();
    let mut m = match source.as_str() {
        "srv" => parse_dynamic_srv_upstreams(d)?,
        "a" => parse_dynamic_a_upstreams(d)?,
        "multi" => parse_dynamic_multi_upstreams(d)?,
        other => bail!("unrecognized dynamic upstream source '{other}'"),
    };
    m.insert("source".into(), json!(source));
    Ok(Value::Object(m))
}

fn parse_dynamic_srv_upstreams(d: &mut Dispenser) -> Result<Map<String, Value>> {
    let args = d.remaining_args();
    if args.len() > 1 {
        return Err(d.arg_err());
    }
    let mut m = Map::new();
    if let Some(name) = args.first() {
        m.insert("name".into(), json!(name));
    }

    let nesting = d.nesting();
    while d.next_block(nesting) {
        match d.val().as_str() {
            "service" => {
                insert_single_dynamic_arg(d, &mut m, "service", "srv service")?;
            }
            "proto" => {
                insert_single_dynamic_arg(d, &mut m, "proto", "srv proto")?;
            }
            "name" => {
                insert_single_dynamic_arg(d, &mut m, "name", "srv name")?;
            }
            "refresh" => {
                insert_dynamic_duration(d, &mut m, "refresh", "parsing refresh interval duration")?;
            }
            "resolvers" => {
                insert_dynamic_resolvers(d, &mut m)?;
            }
            "dial_timeout" => {
                insert_dynamic_duration(d, &mut m, "dial_timeout", "bad timeout value")?;
            }
            "dial_fallback_delay" => {
                insert_dynamic_duration(d, &mut m, "dial_fallback_delay", "bad delay value")?;
            }
            "grace_period" => {
                insert_dynamic_duration(d, &mut m, "grace_period", "bad grace period value")?;
            }
            other => bail!("unrecognized srv option '{other}'"),
        }
    }
    Ok(m)
}

fn parse_dynamic_a_upstreams(d: &mut Dispenser) -> Result<Map<String, Value>> {
    let args = d.remaining_args();
    if args.len() > 2 {
        return Err(d.arg_err());
    }
    let mut m = Map::new();
    if let Some(name) = args.first() {
        m.insert("name".into(), json!(name));
    }
    if let Some(port) = args.get(1) {
        m.insert("port".into(), json!(port));
    }

    let nesting = d.nesting();
    while d.next_block(nesting) {
        match d.val().as_str() {
            "name" => {
                insert_single_dynamic_arg(d, &mut m, "name", "a name")?;
            }
            "port" => {
                insert_single_dynamic_arg(d, &mut m, "port", "a port")?;
            }
            "refresh" => {
                insert_dynamic_duration(d, &mut m, "refresh", "parsing refresh interval duration")?;
            }
            "resolvers" => {
                insert_dynamic_resolvers(d, &mut m)?;
            }
            "dial_timeout" => {
                insert_dynamic_duration(d, &mut m, "dial_timeout", "bad timeout value")?;
            }
            "dial_fallback_delay" => {
                insert_dynamic_duration(d, &mut m, "dial_fallback_delay", "bad delay value")?;
            }
            "versions" => {
                let args = d.remaining_args();
                if args.is_empty() {
                    bail!("must specify at least one version");
                }
                let mut versions = Map::new();
                for arg in args {
                    match arg.as_str() {
                        "ipv4" => {
                            versions.insert("ipv4".into(), json!(true));
                        }
                        "ipv6" => {
                            versions.insert("ipv6".into(), json!(true));
                        }
                        other => bail!("unsupported version: '{other}'"),
                    };
                }
                m.insert("versions".into(), Value::Object(versions));
            }
            other => bail!("unrecognized a option '{other}'"),
        }
    }
    Ok(m)
}

fn parse_dynamic_multi_upstreams(d: &mut Dispenser) -> Result<Map<String, Value>> {
    if d.next_arg() {
        return Err(d.arg_err());
    }
    let mut sources = Vec::new();
    let nesting = d.nesting();
    while d.next_block(nesting) {
        sources.push(parse_dynamic_upstream_source(d)?);
    }
    let mut m = Map::new();
    if !sources.is_empty() {
        m.insert("sources".into(), Value::Array(sources));
    }
    Ok(m)
}

fn insert_single_dynamic_arg(
    d: &mut Dispenser,
    m: &mut Map<String, Value>,
    key: &str,
    label: &str,
) -> Result<()> {
    if !d.next_arg() {
        return Err(d.arg_err());
    }
    if m.contains_key(key) {
        bail!("{label} has already been specified");
    }
    m.insert(key.into(), json!(d.val()));
    Ok(())
}

fn insert_dynamic_duration(
    d: &mut Dispenser,
    m: &mut Map<String, Value>,
    key: &str,
    label: &str,
) -> Result<()> {
    if !d.next_arg() {
        return Err(d.arg_err());
    }
    let raw = d.val();
    let value = parse_go_duration_ns(&raw).map_err(|e| d.errf(format!("{label}: {e}")))?;
    m.insert(key.into(), json!(value));
    Ok(())
}

fn insert_dynamic_resolvers(d: &mut Dispenser, m: &mut Map<String, Value>) -> Result<()> {
    let addresses = d.remaining_args();
    if addresses.is_empty() {
        bail!("must specify at least one resolver address");
    }
    m.insert("resolver".into(), json!({ "addresses": addresses }));
    Ok(())
}

fn consume_nested_block(d: &mut Dispenser) {
    let nesting = d.nesting();
    while d.next_block(nesting) {}
}

fn append_upstream(addr: &str, out: &mut Vec<Value>, common_scheme: &mut String) -> Result<()> {
    let parsed = parse_upstream_dial_address(addr)?;
    match parsed.scheme.as_str() {
        "wss" => bail!("the scheme wss:// is only supported in browsers; use https:// instead"),
        "ws" => bail!("the scheme ws:// is only supported in browsers; use http:// instead"),
        "https" | "http" | "h2c" | "" => {}
        other => bail!("unsupported URL scheme {other}://"),
    }
    if !common_scheme.is_empty() && parsed.scheme != *common_scheme {
        bail!(
            "for now, all proxy upstreams must use the same scheme (transport protocol); expecting '{common_scheme}://' but got '{}://'",
            parsed.scheme
        );
    }
    *common_scheme = parsed.scheme.clone();

    if parsed.replaceable_port() || parsed.is_unix() || !parsed.ranged_port() {
        out.push(json!({ "dial": parsed.dial_addr() }));
    } else {
        let (start, end) = parse_caddy_port_range(&parsed.port)?;
        for port in start..=end {
            out.push(json!({ "dial": join_network_address("", &parsed.host, &port.to_string()) }));
        }
    }
    Ok(())
}

fn transport_for_scheme(scheme: &str) -> Option<Value> {
    match scheme {
        "https" => Some(json!({ "protocol": "http", "tls": {} })),
        "h2c" => Some(json!({ "protocol": "http", "versions": ["h2c"] })),
        _ => None,
    }
}

#[derive(Debug)]
struct ParsedUpstreamAddr {
    network: String,
    scheme: String,
    host: String,
    port: String,
}

impl ParsedUpstreamAddr {
    fn dial_addr(&self) -> String {
        if !self.network.is_empty() {
            return join_network_address(&self.network, &self.host, &self.port);
        }
        if self.port.is_empty() && self.host.contains('{') {
            self.host.clone()
        } else {
            join_host_port(&self.host, &self.port)
        }
    }

    fn ranged_port(&self) -> bool {
        self.port.contains('-')
    }

    fn replaceable_port(&self) -> bool {
        self.port.contains('{') && self.port.contains('}')
    }

    fn is_unix(&self) -> bool {
        is_unix_network(&self.network)
    }
}

fn parse_upstream_dial_address(addr: &str) -> Result<ParsedUpstreamAddr> {
    let (mut network, mut scheme, host, port) = if addr.contains("://") {
        if addr.contains('{') {
            bail!(
                "due to parsing difficulties, placeholders are not allowed when an upstream address contains a scheme"
            );
        }
        let (url, port) = parse_upstream_url(addr)?;
        let after_scheme = addr.split_once("://").map(|(_, rest)| rest).unwrap_or(addr);
        if after_scheme.contains('/')
            || after_scheme.contains('?')
            || after_scheme.contains('#')
            || url.query().is_some()
            || url.fragment().is_some()
        {
            bail!(
                "for now, URLs for proxy upstreams only support scheme, host, and port components"
            );
        }

        let scheme = url.scheme().to_string();
        if scheme == "http" && port.as_deref() == Some("443") {
            bail!(
                "upstream address has conflicting scheme (http://) and port (:443, the HTTPS port)"
            );
        }
        if scheme == "https" && port.as_deref() == Some("80") {
            bail!(
                "upstream address has conflicting scheme (https://) and port (:80, the HTTP port)"
            );
        }
        if scheme == "h2c" && port.as_deref() == Some("443") {
            bail!(
                "upstream address has conflicting scheme (h2c://) and port (:443, the HTTPS port)"
            );
        }

        let port = port.unwrap_or_else(|| match scheme.as_str() {
            "" | "http" | "h2c" => "80".to_string(),
            "https" => "443".to_string(),
            _ => String::new(),
        });
        (
            String::new(),
            scheme,
            url.host_str().unwrap_or("").to_string(),
            port,
        )
    } else {
        let (network, host, mut port) = split_network_address(addr)
            .unwrap_or_else(|| (String::new(), addr.to_string(), String::new()));
        if port.is_empty()
            && !host.contains('{')
            && !is_unix_network(&network)
            && !is_fd_network(&network)
        {
            port = "80".to_string();
        }
        (network, String::new(), host, port)
    };

    if network == "unix+h2c" {
        network = "unix".to_string();
        scheme = "h2c".to_string();
    }

    Ok(ParsedUpstreamAddr {
        network,
        scheme,
        host,
        port,
    })
}

fn parse_upstream_url(addr: &str) -> Result<(url::Url, Option<String>)> {
    match url::Url::parse(addr) {
        Ok(url) => {
            let port = url.port().map(|port| port.to_string());
            Ok((url, port))
        }
        Err(err) => {
            if !err.to_string().contains("invalid port") || !addr.contains('-') {
                bail!("parsing upstream URL: {err}");
            }
            let index = addr
                .rfind(':')
                .ok_or_else(|| anyhow::anyhow!("parsing upstream URL: {err}"))?;
            let port_range = &addr[index + 1..];
            if port_range.matches('-').count() != 1 {
                bail!("parsing upstream URL: parse \"{addr}\": port range invalid: {port_range}");
            }
            let mut replaced = addr.to_string();
            replaced.replace_range(index + 1.., "0");
            let url = url::Url::parse(&replaced)
                .map_err(|err| anyhow::anyhow!("parsing upstream URL: {err}"))?;
            Ok((url, Some(port_range.to_string())))
        }
    }
}

fn split_network_address(addr: &str) -> Option<(String, String, String)> {
    let (network, hostport) = match addr.split_once('/') {
        Some((before, after)) => (before.trim().to_lowercase(), after),
        None => (String::new(), addr),
    };
    if is_unix_network(&network) || is_fd_network(&network) {
        return Some((network, hostport.to_string(), String::new()));
    }
    let (host, port) = split_host_port_for_network_address(hostport)?;
    Some((network, host, port))
}

fn split_host_port_for_network_address(value: &str) -> Option<(String, String)> {
    if value.is_empty() {
        return Some((String::new(), String::new()));
    }
    if let Some(rest) = value.strip_prefix('[') {
        let close = rest.find(']')?;
        let host = &rest[..close];
        let after = &rest[close + 1..];
        if let Some(port) = after.strip_prefix(':') {
            return Some((host.to_string(), port.to_string()));
        }
        return Some((host.to_string(), String::new()));
    }
    match (value.find(':'), value.rfind(':')) {
        (Some(first), Some(last)) if first == last => {
            Some((value[..first].to_string(), value[first + 1..].to_string()))
        }
        (None, None) => Some((value.to_string(), String::new())),
        _ => Some((value.to_string(), String::new())),
    }
}

fn parse_caddy_port_range(port: &str) -> Result<(u16, u16)> {
    let (start, end) = port
        .split_once('-')
        .ok_or_else(|| anyhow::anyhow!("invalid port range: {port}"))?;
    let start = start
        .parse::<u16>()
        .map_err(|err| anyhow::anyhow!("invalid start port: {err}"))?;
    let end = end
        .parse::<u16>()
        .map_err(|err| anyhow::anyhow!("invalid end port: {err}"))?;
    if end < start {
        bail!("end port must not be less than start port");
    }
    Ok((start, end))
}

fn join_network_address(network: &str, host: &str, port: &str) -> String {
    let mut out = String::new();
    if !network.is_empty() {
        out.push_str(network);
        out.push('/');
    }
    if (host != "" && port == "") || is_unix_network(network) || is_fd_network(network) {
        out.push_str(host);
    } else if !port.is_empty() {
        out.push_str(&join_host_port(host, port));
    }
    out
}

fn is_unix_network(network: &str) -> bool {
    matches!(network, "unix" | "unixgram" | "unixpacket" | "unix+h2c")
}

fn is_fd_network(network: &str) -> bool {
    network == "fd"
}

fn parse_proxy_buffer_size(s: &str) -> Result<i64> {
    if s == "unlimited" {
        Ok(-1)
    } else {
        parse_bytes(s)
    }
}

fn private_ranges_cidr() -> [&'static str; 6] {
    [
        "192.168.0.0/16",
        "172.16.0.0/12",
        "10.0.0.0/8",
        "127.0.0.1/8",
        "fd00::/8",
        "::1",
    ]
}

// --- method / uri / fs / intercept -------------------------------------------

fn parse_method(d: &mut Dispenser) -> Result<Value> {
    d.next();
    if !d.next_arg() {
        return Err(d.arg_err());
    }
    let method = d.val();
    if d.next_arg() {
        return Err(d.arg_err());
    }
    Ok(json!({ "handler": "rewrite", "method": method }))
}

fn parse_uri(d: &mut Dispenser) -> Result<Value> {
    d.next();
    let args = d.remaining_args();
    if args.is_empty() {
        return Err(d.arg_err());
    }
    let mut m = Map::new();
    m.insert("handler".into(), json!("rewrite"));
    match args[0].as_str() {
        "strip_prefix" => {
            if args.len() != 2 {
                return Err(d.arg_err());
            }
            m.insert("strip_path_prefix".into(), json!(args[1]));
        }
        "strip_suffix" => {
            if args.len() != 2 {
                return Err(d.arg_err());
            }
            m.insert("strip_path_suffix".into(), json!(args[1]));
        }
        "replace" => {
            let (find, replace, lim) = match args.len() {
                3 => (args[1].clone(), args[2].clone(), 0),
                4 => (
                    args[1].clone(),
                    args[2].clone(),
                    args[3]
                        .parse::<i64>()
                        .map_err(|e| d.errf(format!("limit must be an integer; invalid: {e}")))?,
                ),
                _ => return Err(d.arg_err()),
            };
            let mut sub = Map::new();
            sub.insert("find".into(), json!(find));
            sub.insert("replace".into(), json!(replace));
            if lim != 0 {
                sub.insert("limit".into(), json!(lim));
            }
            m.insert("uri_substring".into(), json!([Value::Object(sub)]));
        }
        "path_regexp" => {
            if args.len() != 3 {
                return Err(d.arg_err());
            }
            m.insert(
                "path_regexp".into(),
                json!([{ "find": args[1], "replace": args[2] }]),
            );
        }
        "query" => {
            if args.len() > 4 {
                return Err(d.arg_err());
            }
            let mut query = Map::new();
            let has_args = args.len() > 1;
            if has_args {
                apply_uri_query_ops(&mut query, &args[1..], d)?;
            }
            while d.next_block(0) {
                if has_args {
                    bail!("Cannot specify uri query rewrites in both argument and block");
                }
                let mut query_args = vec![d.val()];
                query_args.extend(d.remaining_args());
                apply_uri_query_ops(&mut query, &query_args, d)?;
            }
            m.insert("query".into(), Value::Object(query));
        }
        other => bail!("unrecognized URI manipulation '{other}'"),
    }
    Ok(Value::Object(m))
}

fn apply_uri_query_ops(
    query: &mut Map<String, Value>,
    args: &[String],
    d: &Dispenser,
) -> Result<()> {
    if args.is_empty() {
        return Err(d.arg_err());
    }
    let key = &args[0];
    if let Some(param) = key.strip_prefix('-') {
        if args.len() != 1 {
            return Err(d.arg_err());
        }
        append_query_string(query, "delete", param.trim_start_matches('-'));
    } else if let Some(param) = key.strip_prefix('+') {
        if args.len() != 2 {
            return Err(d.arg_err());
        }
        append_query_key_val(query, "add", param.trim_start_matches('+'), &args[1]);
    } else if key.contains('>') {
        if args.len() != 1 {
            return Err(d.arg_err());
        }
        let mut parts = key.split('>');
        let from = parts.next().unwrap_or_default();
        let to = parts.next().unwrap_or_default();
        append_query_key_val(query, "rename", from, to);
    } else if args.len() == 3 {
        append_query_replace(query, key, &args[1], &args[2]);
    } else {
        if args.len() != 2 {
            return Err(d.arg_err());
        }
        append_query_key_val(query, "set", key, &args[1]);
    }
    Ok(())
}

fn append_query_key_val(query: &mut Map<String, Value>, op: &str, key: &str, val: &str) {
    query
        .entry(op.to_string())
        .or_insert_with(|| Value::Array(Vec::new()))
        .as_array_mut()
        .unwrap()
        .push(json!({ "key": key, "val": val }));
}

fn append_query_replace(query: &mut Map<String, Value>, key: &str, search: &str, replace: &str) {
    query
        .entry("replace".to_string())
        .or_insert_with(|| Value::Array(Vec::new()))
        .as_array_mut()
        .unwrap()
        .push(json!({ "key": key, "search_regexp": search, "replace": replace }));
}

fn append_query_string(query: &mut Map<String, Value>, op: &str, value: &str) {
    query
        .entry(op.to_string())
        .or_insert_with(|| Value::Array(Vec::new()))
        .as_array_mut()
        .unwrap()
        .push(json!(value));
}

fn parse_fs(d: &mut Dispenser) -> Result<Value> {
    d.next();
    if !d.next_arg() {
        return Err(d.arg_err());
    }
    let fs = d.val();
    if d.next_arg() {
        return Err(d.arg_err());
    }
    Ok(json!({ "handler": "vars", "fs": fs }))
}

fn parse_intercept(h: &mut Helper) -> Result<Value> {
    h.d.next();
    if h.d.next_arg() {
        return Err(h.d.arg_err());
    }

    let mut response_matchers = HashMap::<String, Value>::new();
    let mut handle_response = Vec::<PendingResponseHandler>::new();
    while h.d.next_block(0) {
        if h.d.val().starts_with('@') {
            parse_response_matcher_definition(&mut h.d, &mut response_matchers)?;
            continue;
        }

        match h.d.val().as_str() {
            "handle_response" => {
                let args = h.d.remaining_args();
                if args.len() == 2 {
                    bail!(
                        "configuring 'handle_response' for status code replacement is no longer supported. Use 'replace_status' instead."
                    );
                }
                let pending = parse_handle_response_block(h, &args)?;
                handle_response.push(pending);
            }
            "replace_status" => {
                let args = h.d.remaining_args();
                let pending = parse_replace_status_args(&args, &h.d)?;
                let nesting = h.d.nesting();
                if h.d.next_block(nesting) {
                    bail!(
                        "cannot define routes for 'replace_status', use 'handle_response' instead."
                    );
                }
                handle_response.push(pending);
            }
            other => bail!("unrecognized subdirective {other}"),
        }
    }

    let mut m = Map::new();
    m.insert("handler".into(), json!("intercept"));
    let handle_response = resolve_pending_response_handlers(handle_response, &response_matchers)?;
    if !handle_response.is_empty() {
        m.insert("handle_response".into(), Value::Array(handle_response));
    }
    Ok(Value::Object(m))
}

fn parse_push(d: &mut Dispenser) -> Result<Value> {
    d.next();
    let mut resources = Vec::<Value>::new();
    let mut headers = HeaderOps::default();

    if d.next_arg() {
        resources.push(json!({ "target": d.val() }));
    }

    while d.next_block(0) {
        match d.val().as_str() {
            "headers" => {
                if d.next_arg() {
                    return Err(d.arg_err());
                }
                let nesting = d.nesting();
                while d.next_block(nesting) {
                    let mut args = vec![d.val()];
                    args.extend(d.remaining_args());
                    apply_header_args(&mut headers, args, d)?;
                }
            }
            "GET" | "HEAD" => {
                let method = d.val();
                if !d.next_arg() {
                    return Err(d.arg_err());
                }
                let target = d.val();
                resources.push(json!({ "method": method, "target": target }));
            }
            _ => {
                resources.push(json!({ "target": d.val() }));
            }
        }
    }

    let mut m = Map::new();
    m.insert("handler".into(), json!("push"));
    if !resources.is_empty() {
        m.insert("resources".into(), Value::Array(resources));
    }
    if let Some(headers) = headers.to_json() {
        m.insert("headers".into(), headers);
    }
    Ok(Value::Object(m))
}

// --- headers (full directives) ------------------------------------------------

#[derive(Default)]
struct HeaderOps {
    set: Map<String, Value>,
    add: Map<String, Value>,
    delete: Vec<String>,
    replace: Map<String, Value>,
}

impl HeaderOps {
    fn to_json(&self) -> Option<Value> {
        if self.set.is_empty()
            && self.add.is_empty()
            && self.delete.is_empty()
            && self.replace.is_empty()
        {
            return None;
        }
        let mut m = Map::new();
        if !self.set.is_empty() {
            m.insert("set".into(), Value::Object(self.set.clone()));
        }
        if !self.add.is_empty() {
            m.insert("add".into(), Value::Object(self.add.clone()));
        }
        if !self.delete.is_empty() {
            m.insert("delete".into(), json!(self.delete));
        }
        if !self.replace.is_empty() {
            m.insert("replace".into(), Value::Object(self.replace.clone()));
        }
        Some(Value::Object(m))
    }
}

#[derive(Default)]
struct HeadersHandler {
    request: HeaderOps,
    response: HeaderOps,
    deferred: bool,
    require: Option<Value>,
}

impl HeadersHandler {
    fn request_ops(&mut self) -> &mut HeaderOps {
        &mut self.request
    }
    fn response_ops(&mut self) -> &mut HeaderOps {
        &mut self.response
    }
    fn to_json(&self) -> Option<Value> {
        let req = self.request.to_json();
        let resp = self.response.to_json();
        if req.is_none() && resp.is_none() {
            return None;
        }
        let mut m = Map::new();
        if let Some(r) = req {
            m.insert("request".into(), r);
        }
        if let Some(r) = resp {
            m.insert("response".into(), r);
        }
        Some(Value::Object(m))
    }
}

fn append_header(map: &mut Map<String, Value>, field: &str, value: &str) {
    map.entry(field.to_string())
        .or_insert_with(|| Value::Array(Vec::new()))
        .as_array_mut()
        .unwrap()
        .push(json!(value));
}

/// Applies a header operation. Port of `applyHeaderOp` (`is_response`/`deferred`
/// and `require` handled by the caller's flags).
fn apply_header_op(
    ops: &mut HeaderOps,
    field: &str,
    value: &str,
    replacement: Option<&str>,
    deferred: &mut bool,
    require: &mut Option<Value>,
    is_response: bool,
) -> Result<()> {
    if let Some(stripped) = field.strip_prefix('+') {
        append_header(&mut ops.add, &canonical_header_key(stripped), value);
    } else if let Some(stripped) = field.strip_prefix('-') {
        ops.delete.push(stripped.to_string());
        if is_response {
            *deferred = true;
        }
    } else if let Some(stripped) = field.strip_prefix('?') {
        if !is_response {
            bail!(
                "{field}: the default header modifier ('?') can only be used on response headers; for conditional manipulation of request headers, use matchers"
            );
        }
        let req = require.get_or_insert_with(|| json!({ "headers": {} }));
        req["headers"][stripped] = Value::Null;
        ops.set
            .insert(canonical_header_key(stripped), json!([value]));
    } else if let Some(repl) = replacement {
        if field.starts_with('>') && is_response {
            *deferred = true;
        }
        let f = field.trim_start_matches(['+', '-', '?', '>']);
        ops.replace
            .entry(f.to_string())
            .or_insert_with(|| Value::Array(Vec::new()))
            .as_array_mut()
            .unwrap()
            .push(json!({ "search_regexp": value, "replace": repl }));
    } else if let Some(stripped) = field.strip_prefix('>') {
        ops.set
            .insert(canonical_header_key(stripped), json!([value]));
        if is_response {
            *deferred = true;
        }
    } else {
        ops.set.insert(canonical_header_key(field), json!([value]));
    }
    Ok(())
}

/// Canonicalizes a header field name the way Go's `textproto.CanonicalMIMEHeaderKey`
/// (used by `http.Header.Set`/`Add`) does: e.g. `x-real-ip` -> `X-Real-Ip`. If
/// the key contains a non-token byte (e.g. a `{placeholder}`), it is returned
/// unchanged, matching Go.
pub(crate) fn canonical_header_key(s: &str) -> String {
    fn is_token_byte(b: u8) -> bool {
        b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b)
    }
    if s.is_empty() || !s.bytes().all(is_token_byte) {
        return s.to_string();
    }
    let mut out = String::with_capacity(s.len());
    let mut upper = true;
    for c in s.chars() {
        out.push(if upper {
            c.to_ascii_uppercase()
        } else {
            c.to_ascii_lowercase()
        });
        upper = c == '-';
    }
    out
}

/// Applies the `header_up`/`header_down` arg forms (1, 2 or 3 args).
fn apply_header_args(ops: &mut HeaderOps, args: Vec<String>, d: &Dispenser) -> Result<()> {
    let mut dummy_deferred = false;
    let mut dummy_require = None;
    match args.len() {
        1 => apply_header_op(
            ops,
            &args[0],
            "",
            None,
            &mut dummy_deferred,
            &mut dummy_require,
            false,
        ),
        2 => apply_header_op(
            ops,
            &args[0],
            &args[1],
            None,
            &mut dummy_deferred,
            &mut dummy_require,
            false,
        ),
        3 => apply_header_op(
            ops,
            &args[0],
            &args[1],
            Some(&args[2]),
            &mut dummy_deferred,
            &mut dummy_require,
            false,
        ),
        _ => Err(d.arg_err()),
    }
}

fn parse_header(h: &mut Helper) -> Result<Vec<ConfigValue>> {
    h.d.next();
    let matcher = h.extract_matcher_set()?;
    h.d.next(); // consume directive name (matcher parsing reset)

    let mut handler = HeadersHandler::default();
    let mut with_require = HeadersHandler::default();

    let mut has_args = false;
    if h.d.next_arg() {
        has_args = true;
        let field = h.d.val();
        let value = if h.d.next_arg() {
            h.d.val()
        } else {
            String::new()
        };
        let replacement = if h.d.next_arg() {
            Some(h.d.val())
        } else {
            None
        };
        apply_header_op(
            &mut handler.response,
            &field,
            &value,
            replacement.as_deref(),
            &mut handler.deferred,
            &mut handler.require,
            true,
        )?;
        if !handler.response.delete.is_empty() {
            handler.deferred = true;
        }
    }

    while h.d.next_block(0) {
        let field = h.d.val();
        if field == "defer" {
            handler.deferred = true;
            continue;
        }
        if field == "match" {
            let mut response_matchers = HashMap::new();
            let mut d = h.d.new_from_next_segment();
            d.next();
            parse_response_matcher_definition(&mut d, &mut response_matchers)?;
            handler.require = response_matchers.remove("@match");
            continue;
        }
        if has_args {
            bail!("cannot specify headers in both arguments and block");
        }
        let field = field.strip_suffix(':').unwrap_or(&field).to_string();
        let value = if h.d.next_arg() {
            h.d.val()
        } else {
            String::new()
        };
        let replacement = if h.d.next_arg() {
            Some(h.d.val())
        } else {
            None
        };
        let target = if field.starts_with('?') {
            &mut with_require
        } else {
            &mut handler
        };
        let (deferred, require) = (&mut target.deferred, &mut target.require);
        apply_header_op(
            &mut target.response,
            &field,
            &value,
            replacement.as_deref(),
            deferred,
            require,
            true,
        )?;
    }

    let mut out = Vec::new();
    if let Some(v) = build_headers_json(&handler) {
        out.extend(h.new_route(matcher.clone(), v));
    }
    if let Some(v) = build_headers_json(&with_require) {
        out.extend(h.new_route(matcher, v));
    }
    Ok(out)
}

fn build_headers_json(h: &HeadersHandler) -> Option<Value> {
    let resp = h.response.to_json();
    if resp.is_none() && h.require.is_none() && !h.deferred {
        return None;
    }
    let mut response = match resp {
        Some(Value::Object(m)) => m,
        _ => Map::new(),
    };
    if h.deferred {
        response.insert("deferred".into(), json!(true));
    }
    if let Some(req) = &h.require {
        response.insert("require".into(), req.clone());
    }
    if response.is_empty() {
        return None;
    }
    Some(json!({ "handler": "headers", "response": Value::Object(response) }))
}

fn parse_request_header(h: &mut Helper) -> Result<Vec<ConfigValue>> {
    h.d.next();
    let matcher = h.extract_matcher_set()?;
    h.d.next();

    if !h.d.next_arg() {
        return Err(h.d.arg_err());
    }
    let field = h.d.val();
    let field = field.strip_suffix(':').unwrap_or(&field).to_string();
    let value = if h.d.next_arg() {
        h.d.val()
    } else {
        String::new()
    };
    let replacement = if h.d.next_arg() {
        let r = h.d.val();
        if h.d.next_arg() {
            return Err(h.d.arg_err());
        }
        Some(r)
    } else {
        None
    };

    let mut ops = HeaderOps::default();
    let mut deferred = false;
    let mut require = None;
    apply_header_op(
        &mut ops,
        &field,
        &value,
        replacement.as_deref(),
        &mut deferred,
        &mut require,
        false,
    )?;

    let req = ops.to_json().unwrap_or_else(|| json!({}));
    let handler = json!({ "handler": "headers", "request": req });
    Ok(h.new_route(matcher, handler))
}

// --- rewrite / root -----------------------------------------------------------

fn parse_rewrite(h: &mut Helper) -> Result<Vec<ConfigValue>> {
    h.d.next();
    let count = h.d.count_remaining_args();
    if count == 0 {
        bail!("too few arguments; must have at least a rewrite URI");
    }
    if count > 2 {
        bail!("too many arguments; should only be a matcher and a URI");
    }
    if count == 1 {
        if !h.d.next_arg() {
            return Err(h.d.arg_err());
        }
        let uri = h.d.val();
        return Ok(h.new_route(None, json!({ "handler": "rewrite", "uri": uri })));
    }
    let matcher = h.extract_matcher_set()?;
    h.d.next();
    h.d.next();
    let uri = h.d.val();
    Ok(h.new_route(matcher, json!({ "handler": "rewrite", "uri": uri })))
}

fn parse_try_files(h: &mut Helper) -> Result<Vec<ConfigValue>> {
    h.d.next();
    let try_files = h.d.remaining_args();
    if try_files.is_empty() {
        return Err(h.d.arg_err());
    }

    let mut try_policy = String::new();
    while h.d.next_block(0) {
        match h.d.val().as_str() {
            "policy" => {
                if !try_policy.is_empty() {
                    bail!("try policy already configured");
                }
                if !h.d.next_arg() {
                    return Err(h.d.arg_err());
                }
                try_policy = h.d.val();
                match try_policy.as_str() {
                    "first_exist"
                    | "first_exist_fallback"
                    | "largest_size"
                    | "smallest_size"
                    | "most_recently_modified" => {}
                    other => bail!("unrecognized try policy: {other}"),
                }
            }
            _ => {}
        }
    }

    let make_route = |try_files: Vec<String>, user_query: &str| {
        let mut file = Map::new();
        file.insert("try_files".into(), json!(try_files));
        if !try_policy.is_empty() {
            file.insert("try_policy".into(), json!(try_policy));
        }
        let matcher = json!({ "file": Value::Object(file) });
        h.new_route(
            Some(matcher),
            json!({ "handler": "rewrite", "uri": format!("{{http.matchers.file.relative}}{user_query}") }),
        )
    };

    let mut result = Vec::new();
    let mut pending = Vec::new();
    for item in try_files {
        if let Some(idx) = item.find('?') {
            if !pending.is_empty() {
                result.extend(make_route(std::mem::take(&mut pending), ""));
            }
            result.extend(make_route(vec![item[..idx].to_string()], &item[idx..]));
        } else {
            pending.push(item);
        }
    }
    if !pending.is_empty() {
        result.extend(make_route(pending, ""));
    }

    if result.len() > 1 {
        let group = h.next_group();
        for route in &mut result {
            if let RouteOrSub::Route(route) = &mut route.value {
                route.group = group.clone();
            }
        }
    }
    Ok(result)
}

fn parse_root(h: &mut Helper) -> Result<Vec<ConfigValue>> {
    h.d.next();
    let count = h.d.count_remaining_args();
    if count == 0 {
        bail!("too few arguments; must have at least a root path");
    }
    if count > 2 {
        bail!("too many arguments; should only be a matcher and a path");
    }
    if count == 1 {
        if !h.d.next_arg() {
            return Err(h.d.arg_err());
        }
        let root = h.d.val();
        h.block_state
            .borrow_mut()
            .insert("root".to_string(), root.clone());
        return Ok(h.new_route(None, json!({ "handler": "vars", "root": root })));
    }
    let matcher = h.extract_matcher_set()?;
    h.d.next();
    if !h.d.next_arg() {
        return Err(h.d.arg_err());
    }
    let root = h.d.val();
    if matcher.is_none() {
        h.block_state
            .borrow_mut()
            .insert("root".to_string(), root.clone());
    }
    Ok(h.new_route(matcher, json!({ "handler": "vars", "root": root })))
}

// --- handle / route / handle_path / handle_errors ----------------------------

/// `handle` setup (matcher already extracted by the handler-directive wrapper).
/// Port of `parseHandle` -> `ParseSegmentAsSubroute`.
fn parse_handle(h: &mut Helper) -> Result<Value> {
    Ok(parse_segment_as_subroute(h)?.to_handler_json())
}

/// `route` setup. Port of `parseRoute` (build subroute without re-sorting).
fn parse_route(h: &mut Helper) -> Result<Value> {
    let all = parse_segment_as_config(h)?;
    Ok(
        build_subroute(all, &h.counter.clone(), false, &h.options.directive_order)?
            .to_handler_json(),
    )
}

fn parse_handle_path(h: &mut Helper) -> Result<Vec<ConfigValue>> {
    h.d.next();
    if !h.d.next_arg() {
        return Err(h.d.arg_err());
    }
    let path = h.d.val();
    if !path.starts_with('/') {
        bail!("path matcher must begin with '/', got {path}");
    }
    let strip = if let Some(p) = path.strip_suffix("/*") {
        p.to_string()
    } else if let Some(p) = path.strip_suffix('*') {
        p.to_string()
    } else {
        path.clone()
    };

    h.d.reset();
    h.d.next();
    let mut sub = parse_segment_as_subroute(h)?;

    // Prepend a route that strips the prefix, then wrap the whole subroute under
    // the path matcher (mirrors parseCaddyfileHandlePath).
    let strip_route = Route {
        handlers: vec![json!({ "handler": "rewrite", "strip_path_prefix": strip })],
        ..Default::default()
    };
    sub.routes.insert(0, strip_route);

    let path_matcher = json!({ "path": [path] });
    Ok(h.new_route(Some(path_matcher), sub.to_handler_json()))
}

fn parse_handle_errors(h: &mut Helper) -> Result<Vec<ConfigValue>> {
    h.d.next();
    let args = h.d.remaining_args();
    let mut expression = String::new();
    if !args.is_empty() {
        let mut codes: Vec<String> = Vec::new();
        for val in &args {
            if val.len() != 3 {
                bail!("bad status value '{val}'");
            }
            if let Some(prefix) = val.strip_suffix("xx") {
                prefix
                    .parse::<i64>()
                    .map_err(|e| h.d.errf(format!("bad status value '{val}': {e}")))?;
                if !expression.is_empty() {
                    expression.push_str(" || ");
                }
                expression.push_str(&format!(
                    "{{http.error.status_code}} >= {prefix}00 && {{http.error.status_code}} <= {prefix}99"
                ));
                continue;
            }
            val.parse::<i64>()
                .map_err(|e| h.d.errf(format!("bad status value '{val}': {e}")))?;
            codes.push(val.clone());
        }
        if !codes.is_empty() {
            if !expression.is_empty() {
                expression.push_str(" || ");
            }
            expression.push_str(&format!(
                "{{http.error.status_code}} in [{}]",
                codes.join(", ")
            ));
        }
        h.d.reset();
        h.d.next();
        h.d.remaining_args();
        h.d.prev();
    } else {
        h.d.prev();
    }

    let sub = parse_segment_as_subroute(h)?;
    let wrapping = Route {
        handlers: vec![sub.to_handler_json()],
        ..Default::default()
    };
    let mut error_subroute = Subroute {
        routes: vec![wrapping],
        ..Default::default()
    };
    if !expression.is_empty() {
        error_subroute.routes[0].matcher_sets = vec![json!({ "expression": expression })];
    }
    Ok(vec![ConfigValue {
        class: "error_route".into(),
        directive: "handle_errors".into(),
        value: RouteOrSub::Sub(error_subroute),
    }])
}

/// Parses a directive's block as a subroute. Port of `ParseSegmentAsSubroute`.
fn parse_segment_as_subroute(h: &mut Helper) -> Result<Subroute> {
    let all = parse_segment_as_config(h)?;
    build_subroute(all, &h.counter, true, &h.options.directive_order)
}

fn parse_current_block_as_subroute(h: &mut Helper) -> Result<Subroute> {
    let nesting = h.d.nesting();
    let mut segments = Vec::new();
    while h.d.next_block(nesting) {
        segments.push(h.d.next_segment());
    }
    let all = config_values_from_segments(h, segments)?;
    build_subroute(all, &h.counter, true, &h.options.directive_order)
}

/// Parses a directive's sub-block: each line is itself a directive. Port of
/// `parseSegmentAsConfig`.
fn parse_segment_as_config(h: &mut Helper) -> Result<Vec<ConfigValue>> {
    let mut all: Vec<ConfigValue> = Vec::new();

    while h.d.next() {
        if h.d.next_arg() {
            return Err(h.d.arg_err());
        }
        // Slice into top-level sub-segments.
        let mut segments: Vec<Vec<crate::caddyfile::token::Token>> = Vec::new();
        let nesting = h.d.nesting();
        while h.d.next_block(nesting) {
            segments.push(h.d.next_segment());
        }

        all.extend(config_values_from_segments(h, segments)?);
    }
    Ok(all)
}

fn config_values_from_segments(
    h: &Helper,
    mut segments: Vec<Vec<Token>>,
) -> Result<Vec<ConfigValue>> {
    // Augment matcher defs from this scope.
    let mut matcher_defs = h.matcher_defs.clone();
    let mut i = 0;
    while i < segments.len() {
        if segments[i].first().is_some_and(|t| t.text.starts_with('@')) {
            let mut md = Dispenser::new(segments[i].clone());
            matchers::parse_matcher_definitions(&mut md, &mut matcher_defs)?;
            segments.remove(i);
        } else {
            i += 1;
        }
    }

    let block_state = Rc::new(RefCell::new(h.block_state.borrow().clone()));
    let mut all = Vec::new();
    for seg in segments {
        let dir = seg.first().map(|t| t.text.clone()).unwrap_or_default();
        let mut sub = h.with_dispenser(Dispenser::new(seg));
        sub.matcher_defs = matcher_defs.clone();
        sub.block_state = block_state.clone();
        let Some(results) = dispatch(&dir, &mut sub)? else {
            bail!(
                "unrecognized directive: {dir} - are you sure your Caddyfile structure (nesting and braces) is correct?"
            );
        };
        let norm = normalize_directive_name(&dir);
        for mut r in results {
            r.directive = norm.clone();
            all.push(r);
        }
    }
    Ok(all)
}

// --- route sorting + subroute building ---------------------------------------

/// Sorts routes by directive order, then by path-matcher specificity. Port of
/// `sortRoutes`.
pub fn sort_routes(routes: &mut [ConfigValue], order: &[String]) {
    let mut indexed = routes
        .iter()
        .cloned()
        .enumerate()
        .collect::<Vec<(usize, ConfigValue)>>();
    indexed.sort_by(|(a_idx, a), (b_idx, b)| {
        if a.directive != b.directive {
            return directive_position(&a.directive, order)
                .cmp(&directive_position(&b.directive, order));
        }
        let ar = match &a.value {
            RouteOrSub::Route(r) => r,
            _ => return std::cmp::Ordering::Equal,
        };
        let br = match &b.value {
            RouteOrSub::Route(r) => r,
            _ => return std::cmp::Ordering::Equal,
        };
        let ord = sort_by_path(ar, br);
        if a.directive == "vars" {
            match ord {
                std::cmp::Ordering::Equal => b_idx.cmp(a_idx),
                _ => ord.reverse(),
            }
        } else {
            match ord {
                std::cmp::Ordering::Equal => a_idx.cmp(b_idx),
                _ => ord,
            }
        }
    });
    for (slot, (_, value)) in routes.iter_mut().zip(indexed) {
        *slot = value;
    }
}

fn single_path(route: &Route) -> Option<String> {
    if route.matcher_sets.len() != 1 {
        return None;
    }
    let p = route.matcher_sets[0].get("path")?.as_array()?;
    if p.len() == 1 {
        p[0].as_str().map(|s| s.to_string())
    } else {
        None
    }
}

fn sort_by_path(a: &Route, b: &Route) -> std::cmp::Ordering {
    use std::cmp::Ordering;
    let ap = single_path(a);
    let bp = single_path(b);
    if let (Some(ap), Some(bp)) = (&ap, &bp) {
        let at = ap.strip_suffix('*').unwrap_or(ap);
        let bt = bp.strip_suffix('*').unwrap_or(bp);
        if at == bt {
            return ap.len().cmp(&bp.len()); // shorter (more specific) first
        }
        if at.len() == bt.len() {
            return at.cmp(bt);
        }
        return bt.len().cmp(&at.len()); // longer trimmed first
    }
    // Routes with a matcher sort before those without.
    let a_has = !a.matcher_sets.is_empty();
    let b_has = !b.matcher_sets.is_empty();
    if a_has && !b_has {
        Ordering::Less
    } else if !a_has && b_has {
        Ordering::Greater
    } else {
        Ordering::Equal
    }
}

/// Builds a subroute from config values, applying ordering and mutually
/// exclusive grouping. Port of `buildSubroute`.
pub fn build_subroute(
    mut routes: Vec<ConfigValue>,
    counter: &Rc<RefCell<Counter>>,
    needs_sorting: bool,
    order: &[String],
) -> Result<Subroute> {
    if needs_sorting {
        for v in &routes {
            if directive_position(&v.directive, order) == usize::MAX {
                bail!(
                    "directive '{}' is not an ordered HTTP handler, so it cannot be used here - try placing within a route block or using the order global option",
                    v.directive
                );
            }
        }
        sort_routes(&mut routes, order);
    }

    // Mutually-exclusive directive groups (deterministic key order).
    let me_dirs = ["handle", "rewrite", "root"];
    let mut group_names: std::collections::HashMap<&str, String> = std::collections::HashMap::new();
    for &dir in &me_dirs {
        let count = routes.iter().filter(|r| r.directive == dir).count();
        if count > 1 || dir == "rewrite" {
            group_names.insert(dir, counter.borrow_mut().next_group());
        }
    }

    let mut sub = Subroute::default();
    for r in routes {
        match r.value {
            RouteOrSub::Sub(s) => {
                // A subroute config value with only routes: inline its routes.
                sub.routes.extend(s.routes);
            }
            RouteOrSub::Route(mut route) => {
                if let Some(g) = group_names.get(r.directive.as_str()) {
                    route.group = g.clone();
                }
                sub.routes.push(route);
            }
            RouteOrSub::Json(_) => {
                bail!(
                    "non-route config value '{}' cannot be used in an HTTP subroute",
                    r.directive
                );
            }
        }
    }

    consolidate_routes(&mut sub.routes);
    Ok(sub)
}

/// Merges adjacent routes with identical matchers/terminal/group. Port of
/// `consolidateRoutes`.
pub fn consolidate_routes(routes: &mut Vec<Route>) {
    let mut i = 0;
    while i + 1 < routes.len() {
        if routes[i].matcher_sets == routes[i + 1].matcher_sets
            && routes[i].terminal == routes[i + 1].terminal
            && routes[i].group == routes[i + 1].group
        {
            let next = routes.remove(i + 1);
            routes[i].handlers.extend(next.handlers);
        } else {
            i += 1;
        }
    }
}

// --- small helpers ------------------------------------------------------------

fn is_status_code(s: &str) -> bool {
    s.len() == 3 && s.parse::<u32>().map(|n| n > 0).unwrap_or(false)
}

fn is_positive_integer(s: &str) -> bool {
    s.parse::<i64>().map(|n| n > 0).unwrap_or(false)
}

/// Renders a Caddy `WeakString`: a JSON bool for `true`/`false`, a JSON number
/// for a plain integer, otherwise a JSON string. Port of `WeakString.MarshalJSON`.
fn weak_string(s: &str) -> Value {
    match s {
        "true" => json!(true),
        "false" => json!(false),
        _ => match s.parse::<i64>() {
            Ok(n) => json!(n),
            Err(_) => json!(s),
        },
    }
}

fn scalar_val(d: &Dispenser) -> Value {
    let text = d.val();
    if d.token().quoted() {
        return json!(text);
    }
    if let Ok(n) = text.parse::<i64>() {
        return json!(n);
    }
    if let Ok(f) = text.parse::<f64>() {
        return json!(f);
    }
    match text.as_str() {
        "true" => return json!(true),
        "false" => return json!(false),
        _ => {}
    }
    json!(text)
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&#34;")
        .replace('\'', "&#39;")
}

/// Parses a byte size like `10MB`, `512KiB`, `1024`. Decimal units are powers of
/// 1000; `*iB` units are powers of 1024 (matching go-humanize ParseBytes).
pub fn parse_bytes(s: &str) -> Result<i64> {
    let s = s.trim();
    let split = s.find(|c: char| c.is_alphabetic()).unwrap_or(s.len());
    let (num, unit) = s.split_at(split);
    let num: f64 = num
        .trim()
        .parse()
        .map_err(|_| anyhow::anyhow!("parsing max_size: invalid number '{num}'"))?;
    let mult: f64 = match unit.trim().to_ascii_lowercase().as_str() {
        "" | "b" => 1.0,
        "kb" | "k" => 1e3,
        "mb" | "m" => 1e6,
        "gb" | "g" => 1e9,
        "tb" | "t" => 1e12,
        "kib" => 1024.0,
        "mib" => 1024f64.powi(2),
        "gib" => 1024f64.powi(3),
        "tib" => 1024f64.powi(4),
        other => bail!("parsing max_size: unknown unit '{other}'"),
    };
    Ok((num * mult) as i64)
}

/// Parses a Go-style duration (e.g. `10s`, `1m30s`, `250ms`) into nanoseconds.
pub fn parse_duration_ns(s: &str) -> Result<i64> {
    let s = s.trim();
    if s.is_empty() {
        bail!("empty duration");
    }
    if let Ok(n) = s.parse::<i64>() {
        // Bare integer: Caddy treats Duration JSON as nanoseconds, but Caddyfile
        // requires a unit; a bare number is unusual. Treat as nanoseconds.
        return Ok(n);
    }
    let mut total: f64 = 0.0;
    let mut num = String::new();
    let mut unit = String::new();
    let flush = |num: &mut String, unit: &mut String, total: &mut f64| -> Result<()> {
        if num.is_empty() {
            return Ok(());
        }
        let v: f64 = num
            .parse()
            .map_err(|_| anyhow::anyhow!("invalid duration number"))?;
        let mult = match unit.as_str() {
            "ns" => 1.0,
            "us" | "µs" => 1e3,
            "ms" => 1e6,
            "s" => 1e9,
            "m" => 60e9,
            "h" => 3600e9,
            "d" => 86400e9,
            other => bail!("unknown duration unit '{other}'"),
        };
        *total += v * mult;
        num.clear();
        unit.clear();
        Ok(())
    };
    for c in s.chars() {
        if c.is_ascii_digit() || c == '.' {
            if !unit.is_empty() {
                flush(&mut num, &mut unit, &mut total)?;
            }
            num.push(c);
        } else {
            unit.push(c);
        }
    }
    flush(&mut num, &mut unit, &mut total)?;
    Ok(total as i64)
}

fn parse_go_duration_ns(s: &str) -> Result<i64> {
    let s = s.trim();
    if s.is_empty() {
        bail!("empty duration");
    }
    if s.parse::<f64>().is_ok() {
        bail!("time: missing unit in duration \"{s}\"");
    }

    let (sign, rest) = if let Some(rest) = s.strip_prefix('-') {
        (-1.0, rest)
    } else if let Some(rest) = s.strip_prefix('+') {
        (1.0, rest)
    } else {
        (1.0, s)
    };
    if rest.is_empty() {
        bail!("time: invalid duration \"{s}\"");
    }

    let chars = rest.char_indices().collect::<Vec<_>>();
    let mut idx = 0usize;
    let mut total = 0.0f64;
    while idx < chars.len() {
        let number_start = chars[idx].0;
        while idx < chars.len() {
            let ch = chars[idx].1;
            if ch.is_ascii_digit() || ch == '.' {
                idx += 1;
            } else {
                break;
            }
        }
        if idx == chars.len() || chars[idx].0 == number_start {
            bail!("time: invalid duration \"{s}\"");
        }
        let number_end = chars[idx].0;
        let value: f64 = rest[number_start..number_end]
            .parse()
            .map_err(|_| anyhow::anyhow!("time: invalid duration \"{s}\""))?;

        let unit_start = chars[idx].0;
        while idx < chars.len() {
            let ch = chars[idx].1;
            if ch.is_ascii_alphabetic() || ch == 'µ' || ch == 'μ' {
                idx += 1;
            } else {
                break;
            }
        }
        let unit_end = if idx < chars.len() {
            chars[idx].0
        } else {
            rest.len()
        };
        let unit = &rest[unit_start..unit_end];
        let mult = match unit {
            "ns" => 1.0,
            "us" | "µs" | "μs" => 1e3,
            "ms" => 1e6,
            "s" => 1e9,
            "m" => 60e9,
            "h" => 3600e9,
            "" => bail!("time: missing unit in duration \"{s}\""),
            other => bail!("unknown duration unit '{other}'"),
        };
        total += value * mult;
    }

    Ok((sign * total) as i64)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::caddyfile::adapter::{Counter, Helper, options::Options};
    use crate::caddyfile::lexer::tokenize;

    fn helper(input: &str) -> Helper {
        Helper {
            d: Dispenser::new(tokenize(input, "Caddyfile").unwrap()),
            matcher_defs: HashMap::new(),
            warnings: Rc::new(RefCell::new(Vec::new())),
            extra_apps: Rc::new(RefCell::new(Map::new())),
            counter: Rc::new(RefCell::new(Counter::default())),
            options: Rc::new(Options::default()),
            block_state: Rc::new(RefCell::new(HashMap::new())),
            caddyfiles: vec!["Caddyfile".to_string()],
        }
    }

    #[test]
    fn root_updates_block_state_only_without_matcher() {
        let mut h = helper("root /srv/site");
        dispatch("root", &mut h).unwrap().unwrap();
        assert_eq!(
            h.block_state.borrow().get("root").map(String::as_str),
            Some("/srv/site")
        );

        let mut h = helper("root /assets* /srv/assets");
        dispatch("root", &mut h).unwrap().unwrap();
        assert!(h.block_state.borrow().get("root").is_none());
    }

    #[test]
    fn nested_blocks_inherit_block_state_without_leaking_changes() {
        let h = helper("");
        h.block_state
            .borrow_mut()
            .insert("root".to_string(), "/outer".to_string());

        config_values_from_segments(&h, vec![tokenize("root /inner", "Caddyfile").unwrap()])
            .unwrap();

        assert_eq!(
            h.block_state.borrow().get("root").map(String::as_str),
            Some("/outer")
        );
    }

    #[test]
    fn request_body_timeouts_require_go_duration_units_like_caddy() {
        for input in [
            "request_body {\n  read_timeout 1\n}",
            "request_body {\n  write_timeout 1d\n}",
        ] {
            let mut h = helper(input);
            assert!(
                dispatch("request_body", &mut h)
                    .unwrap_err()
                    .to_string()
                    .contains("duration")
            );
        }
    }

    #[test]
    fn request_body_timeouts_parse_go_durations_like_caddy() {
        let mut h = helper("request_body {\n  read_timeout -1s\n  write_timeout 1m30.5s\n}");
        let out = dispatch("request_body", &mut h).unwrap().unwrap();
        let RouteOrSub::Route(route) = &out[0].value else {
            panic!("expected route");
        };
        assert_eq!(route.handlers[0]["read_timeout"], json!(-1_000_000_000i64));
        assert_eq!(route.handlers[0]["write_timeout"], json!(90_500_000_000i64));
    }
}
