//! Global options parsing, a pragmatic port of `httpcaddyfile/options.go` and
//! `serveroptions.go`. Only options that influence the `apps.http` surface that
//! zeroserve's compiler consumes are mapped to JSON; the rest (TLS/PKI/admin/
//! logging automation) are accepted and reported as warnings rather than
//! failing the adaptation.

use std::collections::{BTreeMap, HashSet};

use anyhow::{Result, bail};
use serde_json::{Map, Value, json};

use crate::caddyfile::dispenser::Dispenser;
use crate::caddyfile::parser::ServerBlock;

/// Adapted global options.
#[derive(Debug)]
pub struct Options {
    pub http_port: Option<i64>,
    pub https_port: Option<i64>,
    pub directive_order: Vec<String>,
    pub tls_dns_provider_configured: bool,
    /// Fields merged into every server object (e.g. from the `servers` block).
    pub server_fields: Map<String, Value>,
    /// Global `servers <listener> { name <name> }` mappings.
    pub server_names: BTreeMap<String, String>,
    /// Extra top-level apps produced by global options.
    pub extra_apps: Map<String, Value>,
    /// ACME account contact from the global `email` option.
    pub acme_email: Option<String>,
    /// ACME directory URL from the global `acme_ca` option.
    pub acme_ca: Option<String>,
    /// External account binding `(key_id, mac_key)` from the global `acme_eab`.
    pub acme_eab: Option<(String, String)>,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            http_port: None,
            https_port: None,
            directive_order: super::handlers::DIRECTIVE_ORDER
                .iter()
                .map(|dir| dir.to_string())
                .collect(),
            tls_dns_provider_configured: false,
            server_fields: Map::new(),
            server_names: BTreeMap::new(),
            extra_apps: Map::new(),
            acme_email: None,
            acme_ca: None,
            acme_eab: None,
        }
    }
}

impl Options {
    /// Merges server-level option fields into a server JSON object.
    pub fn apply_to_server(&self, srv: &mut Map<String, Value>, _warnings: &mut Vec<String>) {
        for (k, v) in &self.server_fields {
            srv.entry(k.clone()).or_insert_with(|| v.clone());
        }
    }
}

/// Evaluates the global options block (if any) into [`Options`].
pub fn evaluate_global_options(
    block: Option<ServerBlock>,
    warnings: &mut Vec<String>,
) -> Result<Options> {
    let mut opts = Options::default();
    let Some(block) = block else {
        return Ok(opts);
    };

    let mut global_log_names = HashSet::new();
    for seg in &block.segments {
        let name = seg.first().map(|t| t.text.clone()).unwrap_or_default();
        let mut d = Dispenser::new(seg.clone());
        d.next(); // consume option name
        match name.as_str() {
            "http_port" => {
                opts.http_port = Some(parse_port_option(&mut d, "http_port")?);
            }
            "https_port" => {
                opts.https_port = Some(parse_port_option(&mut d, "https_port")?);
            }
            "order" => parse_order(&mut d, &mut opts.directive_order)?,
            "servers" => parse_servers(
                &mut d,
                &mut opts.server_fields,
                &mut opts.server_names,
                warnings,
            )?,
            "filesystem" => parse_filesystem(&mut d, &mut opts.extra_apps, warnings)?,
            // Options outside zeroserve's eBPF request-processing surface.
            "debug" | "local_certs" | "skip_install_trust" => {
                warn_unsupported_global_option(&name, warnings);
            }
            // ACME account contact and directory URL: captured so the Caddy
            // compiler can emit a `zeroserve.init.acme_config` section.
            "email" => {
                let value = required_arg(&mut d, &name)?;
                reject_extra_args(&mut d)?;
                opts.acme_email = Some(value);
            }
            "acme_ca" => {
                let value = required_arg(&mut d, &name)?;
                reject_extra_args(&mut d)?;
                opts.acme_ca = Some(value);
            }
            "default_sni" | "fallback_sni" | "acme_ca_root" | "key_type" => {
                parse_unsupported_single_string_option(&mut d, &name)?;
                warn_unsupported_global_option(&name, warnings);
            }
            "grace_period" | "shutdown_delay" | "renew_interval" | "ocsp_interval"
            | "cert_lifetime" => {
                parse_unsupported_duration_option(&mut d, &name)?;
                warn_unsupported_global_option(&name, warnings);
            }
            "admin" => {
                parse_unsupported_admin_option(&mut d)?;
                warn_unsupported_global_option(&name, warnings);
            }
            "auto_https" => {
                parse_unsupported_auto_https_option(&mut d)?;
                warn_unsupported_global_option(&name, warnings);
            }
            "default_bind" => {
                parse_unsupported_default_bind_option(&mut d)?;
                warn_unsupported_global_option(&name, warnings);
            }
            "storage_check" | "persist_config" | "ocsp_stapling" => {
                let expected = "off";
                let value = required_arg(&mut d, &name)?;
                reject_extra_args(&mut d)?;
                if value != expected {
                    match name.as_str() {
                        "storage_check" => bail!("storage_check must be 'off'"),
                        "persist_config" => bail!("persist_config must be 'off'"),
                        "ocsp_stapling" => bail!("invalid argument '{value}'"),
                        _ => unreachable!(),
                    }
                }
                warn_unsupported_global_option(&name, warnings);
            }
            "storage_clean_interval" => {
                parse_unsupported_storage_clean_interval_option(&mut d)?;
                warn_unsupported_global_option(&name, warnings);
            }
            "tls_resolvers" => {
                if d.remaining_args().is_empty() {
                    return Err(d.arg_err());
                }
                warn_unsupported_global_option(&name, warnings);
            }
            "renewal_window_ratio" => {
                parse_unsupported_renewal_window_ratio_option(&mut d)?;
                warn_unsupported_global_option(&name, warnings);
            }
            "pki" => {
                parse_unsupported_pki_option(&mut d)?;
                warn_unsupported_global_option(&name, warnings);
            }
            "events" => {
                parse_unsupported_events_option(&mut d)?;
                warn_unsupported_global_option(&name, warnings);
            }
            "metrics" => {
                parse_unsupported_metrics_option(&mut d)?;
                warn_unsupported_global_option(&name, warnings);
            }
            "log" => {
                parse_unsupported_global_log_option(&mut d, &mut global_log_names)?;
                warn_unsupported_global_option(&name, warnings);
            }
            "storage" => {
                parse_unsupported_module_option(&mut d, "storage")?;
                warn_unsupported_global_option(&name, warnings);
            }
            "acme_dns" => {
                parse_unsupported_dns_option(&mut d, true)?;
                opts.tls_dns_provider_configured = true;
                warn_unsupported_global_option(&name, warnings);
            }
            "dns" => {
                parse_unsupported_dns_option(&mut d, false)?;
                opts.tls_dns_provider_configured = true;
                warn_unsupported_global_option(&name, warnings);
            }
            "cert_issuer" => {
                parse_unsupported_module_option(&mut d, "cert_issuer")?;
                warn_unsupported_global_option(&name, warnings);
            }
            "acme_eab" => {
                opts.acme_eab = parse_acme_eab_option(&mut d)?;
            }
            "on_demand_tls" => {
                parse_unsupported_on_demand_tls_option(&mut d)?;
                warn_unsupported_global_option(&name, warnings);
            }
            "preferred_chains" => {
                parse_unsupported_preferred_chains_option(&mut d)?;
                warn_unsupported_global_option(&name, warnings);
            }
            "ech" => {
                parse_unsupported_ech_option(&mut d)?;
                warn_unsupported_global_option(&name, warnings);
            }
            other => bail!("unrecognized global option: {other}"),
        }
    }
    Ok(opts)
}

fn warn_unsupported_global_option(name: &str, warnings: &mut Vec<String>) {
    warnings.push(format!(
        "global option '{name}' is accepted but configured outside zeroserve's eBPF request-processing surface"
    ));
}

fn parse_unsupported_single_string_option(d: &mut Dispenser, name: &str) -> Result<()> {
    required_arg(d, name)?;
    reject_extra_args(d)
}

fn parse_unsupported_duration_option(d: &mut Dispenser, name: &str) -> Result<()> {
    let raw = required_arg(d, name)?;
    super::handlers::parse_duration_ns(&raw).map_err(|err| d.errf(err.to_string()))?;
    Ok(())
}

fn parse_unsupported_storage_clean_interval_option(d: &mut Dispenser) -> Result<()> {
    let raw = required_arg(d, "storage_clean_interval")?;
    reject_extra_args(d)?;
    if raw != "off" {
        super::handlers::parse_duration_ns(&raw).map_err(|err| {
            d.errf(format!(
                "failed to parse storage_clean_interval, must be a duration or 'off' {err}"
            ))
        })?;
    }
    Ok(())
}

fn parse_unsupported_renewal_window_ratio_option(d: &mut Dispenser) -> Result<()> {
    let raw = required_arg(d, "renewal_window_ratio")?;
    let ratio = raw
        .parse::<f64>()
        .map_err(|err| d.errf(format!("parsing renewal_window_ratio: {err}")))?;
    if ratio <= 0.0 || ratio >= 1.0 {
        bail!("renewal_window_ratio must be between 0 and 1 (exclusive)");
    }
    reject_extra_args(d)
}

fn parse_unsupported_auto_https_option(d: &mut Dispenser) -> Result<()> {
    let values = d.remaining_args();
    if values.is_empty() {
        return Err(d.arg_err());
    }
    for value in values {
        match value.as_str() {
            "off" | "disable_redirects" | "disable_certs" | "ignore_loaded_certs" => {}
            _ => bail!(
                "auto_https must be one of 'off', 'disable_redirects', 'disable_certs', or 'ignore_loaded_certs'"
            ),
        }
    }
    Ok(())
}

fn parse_unsupported_admin_option(d: &mut Dispenser) -> Result<()> {
    if d.next_arg() {
        let listen_address = d.val();
        if listen_address == "off" {
            if d.next() {
                bail!("No more option is allowed after turning off admin config");
            }
            return Ok(());
        }
        if d.next_arg() {
            return Err(d.arg_err());
        }
    }

    while d.next_block(0) {
        match d.val().as_str() {
            "enforce_origin" => {}
            "origins" => {
                d.remaining_args();
            }
            other => bail!("unrecognized parameter '{other}'"),
        }
    }
    Ok(())
}

fn parse_unsupported_default_bind_option(d: &mut Dispenser) -> Result<()> {
    d.remaining_args();
    while d.next_block(0) {
        match d.val().as_str() {
            "protocols" => {
                let protocols = d.remaining_args();
                if protocols.is_empty() {
                    bail!("protocols requires one or more arguments");
                }
            }
            other => bail!("unknown subdirective: {other}"),
        }
    }
    Ok(())
}

fn parse_unsupported_events_option(d: &mut Dispenser) -> Result<()> {
    if d.next_arg() {
        return Err(d.arg_err());
    }
    while d.next_block(0) {
        match d.val().as_str() {
            "on" => {
                if !d.next_arg() {
                    return Err(d.arg_err());
                }
                let _event_name = d.val();
                if !d.next_arg() {
                    return Err(d.arg_err());
                }
                // The remaining same-line/block tokens belong to the handler
                // module. The generated middleware does not consume this app,
                // but this preserves Caddy's required event/handler shape.
                d.remaining_args();
                let nesting = d.nesting();
                while d.next_block(nesting) {
                    d.remaining_args();
                }
            }
            _ => return Err(d.arg_err()),
        }
    }
    Ok(())
}

fn parse_unsupported_pki_option(d: &mut Dispenser) -> Result<()> {
    if d.next_arg() {
        return Err(d.arg_err());
    }
    while d.next_block(0) {
        match d.val().as_str() {
            "ca" => parse_unsupported_pki_ca(d)?,
            other => bail!("unrecognized pki option '{other}'"),
        }
    }
    Ok(())
}

fn parse_unsupported_pki_ca(d: &mut Dispenser) -> Result<()> {
    if d.next_arg() && d.next_arg() {
        return Err(d.arg_err());
    }
    let nesting = d.nesting();
    while d.next_block(nesting) {
        match d.val().as_str() {
            "name" | "root_cn" | "intermediate_cn" => parse_one_arg(d)?,
            "intermediate_lifetime" | "maintenance_interval" => {
                let raw = required_arg(d, d.val().as_str())?;
                super::handlers::parse_duration_ns(&raw).map_err(|err| d.errf(err.to_string()))?;
                reject_extra_args(d)?;
            }
            "renewal_window_ratio" => {
                let raw = required_arg(d, "renewal_window_ratio")?;
                let ratio = raw
                    .parse::<f64>()
                    .map_err(|err| d.errf(format!("parsing renewal_window_ratio: {err}")))?;
                if ratio <= 0.0 || ratio > 1.0 {
                    bail!("renewal_window_ratio must be a number in (0, 1], got {raw}");
                }
                reject_extra_args(d)?;
            }
            "root" => parse_unsupported_pki_key_pair(d, "root")?,
            "intermediate" => parse_unsupported_pki_key_pair(d, "intermediate")?,
            other => bail!("unrecognized pki ca option '{other}'"),
        }
    }
    Ok(())
}

fn parse_unsupported_pki_key_pair(d: &mut Dispenser, label: &str) -> Result<()> {
    if d.next_arg() {
        return Err(d.arg_err());
    }
    let nesting = d.nesting();
    while d.next_block(nesting) {
        match d.val().as_str() {
            "cert" | "key" | "format" => parse_one_arg(d)?,
            other => bail!("unrecognized pki ca {label} option '{other}'"),
        }
    }
    Ok(())
}

fn parse_one_arg(d: &mut Dispenser) -> Result<()> {
    if !d.next_arg() {
        return Err(d.arg_err());
    }
    reject_extra_args(d)
}

fn parse_unsupported_metrics_option(d: &mut Dispenser) -> Result<()> {
    d.remaining_args();
    while d.next_block(0) {
        match d.val().as_str() {
            "per_host" | "observe_catchall_hosts" | "otlp" => {
                d.remaining_args();
            }
            other => bail!("unrecognized servers option '{other}'"),
        }
    }
    Ok(())
}

fn parse_unsupported_global_log_option(
    d: &mut Dispenser,
    global_log_names: &mut HashSet<String>,
) -> Result<()> {
    let log_name = if d.next_arg() {
        let name = d.val();
        if d.next_arg() {
            return Err(d.arg_err());
        }
        name
    } else {
        "default".to_string()
    };
    if !global_log_names.insert(log_name.clone()) {
        bail!("duplicate global log option for: {log_name}");
    }

    while d.next_block(0) {
        match d.val().as_str() {
            "hostnames" => bail!("hostnames is not allowed in the log global options"),
            "output" | "core" | "format" => {
                if !d.next_arg() {
                    return Err(d.arg_err());
                }
                d.remaining_args();
                let nesting = d.nesting();
                while d.next_block(nesting) {
                    d.remaining_args();
                }
            }
            "sampling" => parse_global_log_sampling(d)?,
            "level" => parse_one_arg(d)?,
            "include" | "exclude" => {
                d.remaining_args();
            }
            "no_hostname" => {
                if d.next_arg() {
                    return Err(d.arg_err());
                }
            }
            other => bail!("unrecognized subdirective: {other}"),
        }
    }
    Ok(())
}

fn parse_global_log_sampling(d: &mut Dispenser) -> Result<()> {
    d.remaining_args();
    let nesting = d.nesting();
    while d.next_block(nesting) {
        match d.val().as_str() {
            "interval" => {
                if !d.next_arg() {
                    return Err(d.arg_err());
                }
                let raw = d.val();
                super::handlers::parse_duration_ns(&raw)
                    .map_err(|err| d.errf(format!("failed to parse interval: {err}")))?;
                d.remaining_args();
            }
            "first" => parse_global_log_sampling_int(d, "first")?,
            "thereafter" => parse_global_log_sampling_int(d, "thereafter")?,
            other => bail!("unrecognized subdirective: {other}"),
        }
    }
    Ok(())
}

fn parse_global_log_sampling_int(d: &mut Dispenser, field: &str) -> Result<()> {
    if !d.next_arg() {
        return Err(d.arg_err());
    }
    let raw = d.val();
    raw.parse::<i64>()
        .map_err(|err| d.errf(format!("failed to parse {field}: {err}")))?;
    d.remaining_args();
    Ok(())
}

fn parse_unsupported_module_option(d: &mut Dispenser, label: &str) -> Result<()> {
    if !d.next_arg() {
        return Err(d.arg_err());
    }
    consume_unsupported_module_config(d, label);
    Ok(())
}

fn parse_unsupported_dns_option(d: &mut Dispenser, acme_dns: bool) -> Result<()> {
    if !d.next_arg() {
        if acme_dns {
            return Ok(());
        }
        return Err(d.arg_err());
    }
    consume_unsupported_module_config(d, if acme_dns { "acme_dns" } else { "dns" });
    Ok(())
}

fn consume_unsupported_module_config(d: &mut Dispenser, _label: &str) {
    d.remaining_args();
    let nesting = d.nesting();
    while d.next_block(nesting) {
        d.remaining_args();
    }
}

/// Parse `acme_eab { key_id <kid>  mac_key <key> }`, returning the pair when
/// both are present so the compiler can emit it into the ACME config.
fn parse_acme_eab_option(d: &mut Dispenser) -> Result<Option<(String, String)>> {
    if d.next_arg() {
        return Err(d.arg_err());
    }
    let mut key_id: Option<String> = None;
    let mut mac_key: Option<String> = None;
    while d.next_block(0) {
        match d.val().as_str() {
            field @ ("key_id" | "mac_key") => {
                if !d.next_arg() {
                    return Err(d.arg_err());
                }
                let value = d.val();
                d.remaining_args();
                if field == "key_id" {
                    key_id = Some(value);
                } else {
                    mac_key = Some(value);
                }
            }
            other => bail!("unrecognized parameter '{other}'"),
        }
    }
    Ok(match (key_id, mac_key) {
        (Some(k), Some(m)) => Some((k, m)),
        _ => None,
    })
}

fn parse_unsupported_on_demand_tls_option(d: &mut Dispenser) -> Result<()> {
    if d.next_arg() {
        return Err(d.arg_err());
    }
    let mut has_permission = false;
    let nesting = d.nesting();
    while d.next_block(nesting) {
        match d.val().as_str() {
            "ask" => {
                if !d.next_arg() {
                    return Err(d.arg_err());
                }
                if has_permission {
                    bail!("on-demand TLS permission module (or 'ask') already specified");
                }
                has_permission = true;
                d.remaining_args();
            }
            "permission" => {
                if !d.next_arg() {
                    return Err(d.arg_err());
                }
                if has_permission {
                    bail!("on-demand TLS permission module (or 'ask') already specified");
                }
                has_permission = true;
                consume_unsupported_module_config(d, "on_demand_tls.permission");
            }
            "interval" => bail!(
                "the on_demand_tls 'interval' option is no longer supported, remove it from your config"
            ),
            "burst" => bail!(
                "the on_demand_tls 'burst' option is no longer supported, remove it from your config"
            ),
            other => bail!("unrecognized parameter '{other}'"),
        }
    }
    if !has_permission {
        bail!("expected at least one config parameter for on_demand_tls");
    }
    Ok(())
}

fn parse_unsupported_preferred_chains_option(d: &mut Dispenser) -> Result<()> {
    let mut has_root_common_name = false;
    let mut has_any_common_name = false;

    if d.next_arg() {
        let arg = d.val();
        if arg != "smallest" {
            bail!("Invalid argument '{arg}'");
        }
        if d.next_arg() {
            return Err(d.arg_err());
        }
        if d.next_block(d.nesting()) {
            bail!("No more options are accepted when using the 'smallest' option");
        }
        return Ok(());
    }

    let nesting = d.nesting();
    while d.next_block(nesting) {
        match d.val().as_str() {
            "root_common_name" => {
                let values = d.remaining_args();
                if values.is_empty() {
                    return Err(d.arg_err());
                }
                if has_any_common_name {
                    bail!("Can't set root_common_name when any_common_name is already set");
                }
                has_root_common_name = true;
            }
            "any_common_name" => {
                let values = d.remaining_args();
                if values.is_empty() {
                    return Err(d.arg_err());
                }
                if has_root_common_name {
                    bail!("Can't set any_common_name when root_common_name is already set");
                }
                has_any_common_name = true;
            }
            other => bail!("Received unrecognized parameter '{other}'"),
        }
    }
    if !has_root_common_name && !has_any_common_name {
        bail!("No options for preferred_chains received");
    }
    Ok(())
}

fn parse_unsupported_ech_option(d: &mut Dispenser) -> Result<()> {
    if d.remaining_args().is_empty() {
        return Err(d.arg_err());
    }
    let nesting = d.nesting();
    while d.next_block(nesting) {
        match d.val().as_str() {
            "dns" => {
                if !d.next_arg() {
                    return Err(d.arg_err());
                }
                consume_unsupported_module_config(d, "ech.dns");
            }
            other => bail!("ech: unrecognized subdirective '{other}'"),
        }
    }
    Ok(())
}

fn parse_port_option(d: &mut Dispenser, label: &str) -> Result<i64> {
    let port = required_arg(d, label)?;
    reject_extra_args(d)?;
    port.parse::<i64>()
        .map_err(|err| d.errf(format!("converting port '{port}' to integer value: {err}")))
}

fn parse_order(d: &mut Dispenser, order: &mut Vec<String>) -> Result<()> {
    let dir_name = required_arg(d, "directive name")?;
    if !is_registered_directive(&dir_name) {
        bail!("{dir_name} is not a registered directive");
    }
    let pos = required_arg(d, "positional")?;

    order.retain(|dir| dir != &dir_name);

    match pos.as_str() {
        "first" => {
            reject_extra_args(d)?;
            order.insert(0, dir_name);
        }
        "last" => {
            reject_extra_args(d)?;
            order.push(dir_name);
        }
        "before" | "after" => {
            let other_dir = required_arg(d, "other directive")?;
            reject_extra_args(d)?;
            let Some(idx) = order.iter().position(|dir| dir == &other_dir) else {
                bail!("directive '{other_dir}' not found");
            };
            let insert_at = if pos == "after" { idx + 1 } else { idx };
            order.insert(insert_at, dir_name);
        }
        other => bail!("unknown positional '{other}'"),
    }
    Ok(())
}

fn required_arg(d: &mut Dispenser, what: &str) -> Result<String> {
    if d.next_arg() {
        Ok(d.val())
    } else {
        bail!("missing {what}");
    }
}

fn reject_extra_args(d: &mut Dispenser) -> Result<()> {
    if d.next_arg() {
        bail!("unexpected argument '{}'", d.val());
    }
    Ok(())
}

fn is_registered_directive(name: &str) -> bool {
    super::handlers::DIRECTIVE_ORDER
        .iter()
        .any(|&dir| dir == name)
}

fn parse_filesystem(
    d: &mut Dispenser,
    apps: &mut Map<String, Value>,
    warnings: &mut Vec<String>,
) -> Result<()> {
    let name = required_arg(d, "filesystem name")?;
    let backend = required_arg(d, "filesystem backend")?;
    let mut file_system = Map::new();
    file_system.insert("backend".to_string(), json!(backend));

    // Filesystem modules are opaque to the generated middleware surface. Caddy
    // delegates the remaining tokens/block to the selected caddy.fs module; we
    // preserve the app/backend shape so downstream compilation can reject the
    // configured backend explicitly instead of failing adaptation.
    let nesting = d.nesting();
    while d.next_block(nesting) {
        skip_current_block(d);
    }

    let app = apps
        .entry("caddy.filesystems".to_string())
        .or_insert_with(|| json!({ "filesystems": [] }));
    let app = app
        .as_object_mut()
        .expect("caddy.filesystems app is always an object");
    let filesystems = app
        .entry("filesystems".to_string())
        .or_insert_with(|| Value::Array(Vec::new()))
        .as_array_mut()
        .expect("caddy.filesystems filesystems is always an array");
    filesystems.push(json!({
        "name": name,
        "file_system": Value::Object(file_system),
    }));
    warnings.push(
        "global option 'filesystem' is accepted but configured outside zeroserve's eBPF request-processing surface"
            .to_string(),
    );
    Ok(())
}

/// Parses a subset of the `servers { ... }` block (timeouts and protocols) into
/// server JSON fields.
fn parse_servers(
    d: &mut Dispenser,
    fields: &mut Map<String, Value>,
    names: &mut BTreeMap<String, String>,
    warnings: &mut Vec<String>,
) -> Result<()> {
    let listener_address = if d.next_arg() {
        let address = d.val();
        reject_extra_args(d)?;
        warnings.push(format!(
            "servers listener address '{address}' is accepted but listener-specific server option scoping is outside zeroserve's eBPF request-processing surface"
        ));
        Some(address)
    } else {
        None
    };

    while d.next_block(0) {
        match d.val().as_str() {
            "name" => {
                if listener_address.is_none() {
                    bail!("cannot set a name for a server without a listener address");
                }
                if !d.next_arg() {
                    bail!("missing server name");
                }
                names.insert(listener_address.clone().unwrap(), d.val());
                reject_extra_args(d)?;
                warnings.push(
                    "servers.name is accepted but configured outside zeroserve's eBPF request-processing surface"
                        .to_string(),
                );
            }
            "listener_wrappers" | "packet_conn_wrappers" => {
                let option = d.val();
                warnings.push(format!(
                    "servers.{option} is accepted but configured outside zeroserve's eBPF request-processing surface"
                ));
                skip_current_block(d);
            }
            "timeouts" => {
                let timeouts_nesting = d.nesting();
                while d.next_block(timeouts_nesting) {
                    let key = d.val();
                    let json_key = match key.as_str() {
                        "read_body" => "read_timeout",
                        "read_header" => "read_header_timeout",
                        "write" => "write_timeout",
                        "idle" => "idle_timeout",
                        _ => bail!("unrecognized timeouts option '{key}'"),
                    };
                    if !d.next_arg() {
                        return Err(d.arg_err());
                    }
                    let ns = super::handlers::parse_duration_ns(&d.val())
                        .map_err(|err| d.errf(format!("parsing {key} timeout duration: {err}")))?;
                    fields.insert(json_key.to_string(), json!(ns));
                }
            }
            "keepalive_interval" | "keepalive_idle" => {
                let key = d.val();
                let json_key = match key.as_str() {
                    "keepalive_interval" => "keepalive_interval",
                    "keepalive_idle" => "keepalive_idle",
                    _ => unreachable!(),
                };
                if !d.next_arg() {
                    bail!("missing {key} duration");
                }
                let ns = super::handlers::parse_duration_ns(&d.val())?;
                reject_extra_args(d)?;
                fields.insert(json_key.to_string(), json!(ns));
            }
            "keepalive_count" => {
                if !d.next_arg() {
                    bail!("missing keepalive_count");
                }
                let count = d
                    .val()
                    .parse::<i64>()
                    .map_err(|err| d.errf(format!("parsing keepalive count int: {err}")))?;
                reject_extra_args(d)?;
                fields.insert("keepalive_count".to_string(), json!(count));
            }
            "enable_full_duplex" => {
                reject_extra_args(d)?;
                fields.insert("enable_full_duplex".to_string(), json!(true));
            }
            "protocols" => {
                let protos = d.remaining_args();
                let mut seen = Vec::<String>::new();
                for proto in &protos {
                    match proto.as_str() {
                        "h1" | "h2" | "h2c" | "h3" => {}
                        _ => bail!("unknown protocol '{proto}': expected h1, h2, h2c, or h3"),
                    }
                    if seen.iter().any(|seen| seen == proto) {
                        bail!("protocol {proto} specified more than once");
                    }
                    seen.push(proto.clone());
                }
                reject_nested_block(d)?;
                if !protos.is_empty() {
                    fields.insert("protocols".to_string(), json!(protos));
                }
            }
            "trusted_proxies" => parse_server_trusted_proxies(d, fields)?,
            "trusted_proxies_strict" => {
                reject_extra_args(d)?;
                fields.insert("trusted_proxies_strict".to_string(), json!(1));
            }
            "trusted_proxies_unix" => {
                reject_extra_args(d)?;
                fields.insert("trusted_proxies_unix".to_string(), json!(true));
            }
            "client_ip_headers" => {
                let headers = d.remaining_args();
                let mut seen = Vec::<String>::new();
                for header in &headers {
                    if seen.iter().any(|seen| seen == header) {
                        bail!("client IP header {header} specified more than once");
                    }
                    seen.push(header.clone());
                }
                reject_nested_block(d)?;
                fields.insert("client_ip_headers".to_string(), json!(headers));
            }
            "max_header_size" => {
                let raw = required_arg(d, "max_header_size")?;
                reject_extra_args(d)?;
                let n = super::handlers::parse_bytes(&raw)
                    .map_err(|err| d.errf(format!("parsing max_header_size: {err}")))?;
                fields.insert("max_header_bytes".to_string(), json!(n));
            }
            "strict_sni_host" => {
                let value = if d.next_arg() {
                    let value = d.val();
                    if value != "on" && value != "insecure_off" {
                        bail!(
                            "strict_sni_host only supports 'on' or 'insecure_off', got '{value}'"
                        );
                    }
                    reject_extra_args(d)?;
                    value != "insecure_off"
                } else {
                    true
                };
                fields.insert("strict_sni_host".to_string(), json!(value));
            }
            "log_credentials" => {
                reject_extra_args(d)?;
                insert_server_log_field(fields, "should_log_credentials", true);
            }
            "metrics" => {
                warnings.push(
                    "servers.metrics is accepted but configured outside zeroserve's eBPF request-processing surface"
                        .to_string(),
                );
                let metrics_nesting = d.nesting();
                while d.next_block(metrics_nesting) {
                    match d.val().as_str() {
                        "per_host" => reject_extra_args(d)?,
                        other => bail!("unrecognized metrics option '{other}'"),
                    }
                }
            }
            "trace" => {
                reject_extra_args(d)?;
                insert_server_log_field(fields, "trace", true);
            }
            "0rtt" => {
                if !d.next_arg() {
                    bail!("missing 0rtt argument");
                }
                let value = d.val();
                if value != "off" {
                    bail!("unsupported 0rtt argument '{value}' (only 'off' is supported)");
                }
                reject_extra_args(d)?;
                fields.insert("allow_0rtt".to_string(), json!(false));
            }
            other => bail!("unrecognized servers option '{other}'"),
        }
    }
    Ok(())
}

fn reject_nested_block(d: &mut Dispenser) -> Result<()> {
    let nesting = d.nesting();
    if d.next_block(nesting) {
        return Err(d.arg_err());
    }
    Ok(())
}

fn skip_current_block(d: &mut Dispenser) {
    let nesting = d.nesting();
    while d.next_block(nesting) {}
}

fn insert_server_log_field(fields: &mut Map<String, Value>, key: &str, value: bool) {
    let logs = fields
        .entry("logs".to_string())
        .or_insert_with(|| Value::Object(Map::new()));
    if let Some(logs) = logs.as_object_mut() {
        logs.insert(key.to_string(), json!(value));
    }
}

fn parse_server_trusted_proxies(d: &mut Dispenser, fields: &mut Map<String, Value>) -> Result<()> {
    if !d.next_arg() {
        bail!("trusted_proxies expects an IP range source module name as its first argument");
    }
    let source = d.val();
    let ranges = d.remaining_args();
    fields.insert(
        "trusted_proxies".to_string(),
        json!({ "source": source, "ranges": ranges }),
    );
    Ok(())
}
