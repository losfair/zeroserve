use std::{
    collections::{BTreeMap, BTreeSet, HashSet},
    fs,
    net::IpAddr,
    path::MAIN_SEPARATOR,
};

use anyhow::{Context, Result, anyhow, bail};
use base64ct::{Base64, Encoding};
use regex::Regex;
use serde::Deserialize;
use serde_json::{Map, Value, json};

#[derive(Debug, Deserialize)]
struct CaddyConfig {
    #[serde(default, deserialize_with = "deserialize_null_default")]
    apps: Apps,
    #[serde(default, deserialize_with = "deserialize_present_value")]
    logging: Option<Value>,
}

#[derive(Debug, Default, Deserialize)]
struct Apps {
    http: Option<HttpApp>,
    #[serde(flatten)]
    extra: Map<String, Value>,
}

#[derive(Debug, Deserialize)]
struct HttpApp {
    #[serde(default, deserialize_with = "deserialize_null_default")]
    servers: BTreeMap<String, HttpServer>,
    #[serde(flatten)]
    extra: Map<String, Value>,
}

#[derive(Debug, Deserialize)]
struct HttpServer {
    #[serde(default, deserialize_with = "deserialize_null_default")]
    routes: Vec<Route>,
    #[serde(default, deserialize_with = "deserialize_null_default")]
    named_routes: BTreeMap<String, Route>,
    #[serde(default)]
    errors: Option<HttpErrorConfig>,
    #[serde(
        default,
        rename = "trusted_proxies",
        deserialize_with = "deserialize_present_value"
    )]
    trusted_proxies_raw: Option<Value>,
    #[serde(default, deserialize_with = "deserialize_present_value")]
    client_ip_headers: Option<Value>,
    #[serde(default, deserialize_with = "deserialize_present_value")]
    trusted_proxies_strict: Option<Value>,
    #[serde(default, deserialize_with = "deserialize_present_value")]
    trusted_proxies_unix: Option<Value>,
    #[serde(default, deserialize_with = "deserialize_null_default")]
    tls_connection_policies: Vec<TlsConnectionPolicy>,
    #[serde(flatten)]
    extra: Map<String, Value>,
}

#[derive(Debug, Clone, Deserialize)]
struct TlsConnectionPolicy {
    #[serde(
        default,
        rename = "match",
        deserialize_with = "deserialize_null_default"
    )]
    match_: Option<TlsConnectionMatch>,
    #[serde(default, deserialize_with = "deserialize_present_value")]
    client_authentication: Option<Value>,
    #[serde(flatten)]
    extra: Map<String, Value>,
}

#[derive(Debug, Clone, Default, Deserialize)]
struct TlsConnectionMatch {
    #[serde(default, deserialize_with = "deserialize_null_default")]
    sni: Vec<String>,
    #[serde(flatten)]
    extra: Map<String, Value>,
}

#[derive(Debug, Clone, Default)]
struct ClientIpConfig {
    trusted_ranges: Vec<String>,
    headers: Vec<String>,
    strict: bool,
    trusted_unix: bool,
}

#[derive(Debug, Default, Deserialize)]
struct HttpErrorConfig {
    #[serde(default, deserialize_with = "deserialize_null_default")]
    routes: Vec<Route>,
    #[serde(flatten)]
    extra: Map<String, Value>,
}

impl HttpServer {
    fn client_ip_config(&self) -> Result<Option<ClientIpConfig>> {
        let has_client_ip_options = self.client_ip_headers.is_some()
            || self.trusted_proxies_strict.is_some()
            || self.trusted_proxies_unix.is_some();
        let trusted_ranges = if let Some(trusted_proxies) = &self.trusted_proxies_raw {
            static_trusted_proxy_ranges(trusted_proxies)?
        } else {
            if !has_client_ip_options {
                return Ok(None);
            }
            Vec::new()
        };
        let headers = match &self.client_ip_headers {
            Some(headers) if headers.is_null() => vec!["X-Forwarded-For".to_string()],
            Some(headers) => strict_string_array(headers, "server.client_ip_headers")?,
            None => vec!["X-Forwarded-For".to_string()],
        };
        let strict = match &self.trusted_proxies_strict {
            Some(Value::Null) | None => false,
            Some(Value::Number(value)) => value.as_u64().unwrap_or_default() > 0,
            Some(_) => bail!("server.trusted_proxies_strict must be an integer"),
        };
        let trusted_unix = match &self.trusted_proxies_unix {
            Some(Value::Null) | None => false,
            Some(value) => value
                .as_bool()
                .ok_or_else(|| anyhow!("server.trusted_proxies_unix must be a boolean"))?,
        };
        Ok(Some(ClientIpConfig {
            trusted_ranges,
            headers,
            strict,
            trusted_unix,
        }))
    }
}

#[derive(Debug, Clone, Deserialize)]
struct Route {
    #[serde(default)]
    group: Option<String>,
    #[serde(
        default,
        rename = "match",
        deserialize_with = "deserialize_null_default"
    )]
    matcher_sets: Vec<MatcherSet>,
    #[serde(
        default,
        rename = "handle",
        deserialize_with = "deserialize_null_default"
    )]
    handlers: Vec<Handler>,
    #[serde(default, deserialize_with = "deserialize_null_default")]
    terminal: bool,
    #[serde(flatten)]
    extra: Map<String, Value>,
}

type MatcherSet = Map<String, Value>;

#[derive(Clone, Copy, PartialEq, Eq)]
enum MatcherEvalPhase {
    Captures,
    Plain,
    SetsError,
}

#[derive(Debug, Clone, Deserialize)]
struct Handler {
    handler: String,
    #[serde(flatten)]
    config: Map<String, Value>,
}

#[derive(Debug, Clone, Deserialize)]
struct ResponseHandlerConfig {
    #[serde(default, deserialize_with = "deserialize_null_default")]
    routes: Option<Vec<Route>>,
}

#[derive(Debug, Clone, Default)]
struct AccessLogConfig {
    default_logger_name: Option<String>,
    files: BTreeMap<String, String>,
}

impl AccessLogConfig {
    fn merge(&mut self, other: AccessLogConfig) {
        if self.default_logger_name.is_none() {
            self.default_logger_name = other.default_logger_name;
        }
        self.files.extend(other.files);
    }
}

fn deserialize_null_default<'de, D, T>(deserializer: D) -> std::result::Result<T, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Default + Deserialize<'de>,
{
    Ok(Option::<T>::deserialize(deserializer)?.unwrap_or_default())
}

fn deserialize_present_value<'de, D>(
    deserializer: D,
) -> std::result::Result<Option<Value>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Value::deserialize(deserializer).map(Some)
}

fn route_vec_from_value(value: &Value, label: &str) -> Result<Vec<Route>> {
    if value.is_null() {
        Ok(Vec::new())
    } else {
        serde_json::from_value(value.clone()).with_context(|| label.to_string())
    }
}

/// Compile a Caddy JSON config, discarding any warnings about configuration
/// that lives outside zeroserve's eBPF surface. Convenience wrapper used by the
/// test suite; callers that surface warnings (e.g. the CLI) use
/// [`compile_caddy_json_collecting`].
#[cfg(test)]
pub fn compile_caddy_json(source: &str) -> Result<String> {
    compile_caddy_json_collecting(source).map(|(code, _warnings)| code)
}

/// Compile a Caddy JSON config, returning the generated script alongside any
/// warnings for fields that are configured outside zeroserve's eBPF
/// request-processing surface (listener binding, TLS termination, transport
/// tuning, logging). Such fields are ignored rather than failing the compile.
pub fn compile_caddy_json_collecting(source: &str) -> Result<(String, Vec<String>)> {
    let config: CaddyConfig = serde_json::from_str(source).context("invalid Caddy JSON")?;
    let mut warnings: Vec<String> = Vec::new();
    let logging_config = config.logging.as_ref();
    for (name, app) in &config.apps.extra {
        if ignorable_caddy_app(name) {
            warnings.push(format!(
                "ignoring Caddy app {name:?}: configured outside zeroserve's eBPF request-processing surface"
            ));
        } else if name == "caddy.filesystems" {
            validate_caddy_filesystems_app(app, &mut warnings)?;
        } else {
            bail!("unsupported Caddy app {name:?}");
        }
    }
    let http = config.apps.http.context("Caddy config has no apps.http")?;
    validate_http_app_fields(&http, &mut warnings)?;
    if http.servers.len() > 1 {
        bail!(
            "Caddy configs with multiple HTTP servers depend on listener selection outside zeroserve's eBPF surface"
        );
    }
    let mut routes = Vec::new();
    let mut tls_connection_policies = Vec::new();
    let mut access_log_config = AccessLogConfig::default();
    for (server_name, server) in http.servers {
        let server_access_log_config = access_log_config_for_server(logging_config, &server.extra)?;
        access_log_config.merge(server_access_log_config);
        validate_http_server_fields(&server, &server_name, &mut warnings)?;
        for (idx, policy) in server.tls_connection_policies.iter().enumerate() {
            validate_tls_connection_policy(
                policy,
                &format!("server {server_name} tls policy {idx}"),
            )?;
        }
        tls_connection_policies.extend(server.tls_connection_policies.clone());
        if let Some(errors) = &server.errors {
            validate_http_error_fields(errors, &server_name)?;
            validate_error_routes(&errors.routes, &format!("server {server_name} error route"))?;
        }
        let client_ip_config = server.client_ip_config()?;
        let named_routes = server.named_routes.clone();
        let error_routes = server
            .errors
            .as_ref()
            .map(|errors| errors.routes.clone())
            .unwrap_or_default();
        for (name, route) in &named_routes {
            validate_route_fields(route, &format!("named route {name:?}"))?;
        }
        for (idx, route) in server.routes.into_iter().enumerate() {
            validate_route_fields(&route, &format!("server {server_name} route {idx}"))?;
            routes.push(CompiledRoute {
                server_name: server_name.clone(),
                route_index: idx,
                route,
                client_ip_config: client_ip_config.clone(),
                named_routes: named_routes.clone(),
                error_routes: error_routes.clone(),
            });
        }
    }
    let mut generator = Generator::default();
    generator.access_log_config = access_log_config;
    generator.tls_connection_policies = tls_connection_policies;
    generator.emit_preamble();

    let mut groups = BTreeMap::<String, usize>::new();
    for compiled in &routes {
        collect_route_groups(&mut groups, &compiled.route)?;
        for route in &compiled.error_routes {
            collect_route_groups(&mut groups, route)?;
        }
        for route in compiled.named_routes.values() {
            collect_route_groups(&mut groups, route)?;
        }
    }
    if groups.len() > 32 {
        bail!("Caddy route groups exceed generated eBPF middleware limit of 32");
    }
    generator.route_groups = groups;

    generator.emit_tls_entrypoint()?;

    generator.line("ZS_ENTRY");
    generator.line("zs_u64 entry(void) {");
    generator.indent += 1;
    generator.emit_access_log_config();
    if !generator.route_groups.is_empty() {
        generator.line("int route_groups[32];");
        generator.line("zs_memset(route_groups, 0, sizeof(route_groups));");
    }
    for compiled in &routes {
        generator.client_ip_config = compiled.client_ip_config.clone();
        generator.named_routes = compiled.named_routes.clone();
        generator.error_routes = compiled.error_routes.clone();
        generator.blank();
        generator.line(&format!(
            "/* server {}, route {} */",
            c_comment(&compiled.server_name),
            compiled.route_index
        ));
        if !generator.error_routes.is_empty() {
            generator.line("zs_meta_set(ZS_STR(\"zs.caddy.has_error_routes\"), ZS_STR(\"1\"));");
            generator.emit_pending_matcher_error()?;
        }
        let matched = generator.emit_route_match(&compiled.route)?;
        if route_match_can_set_error(&compiled.route) {
            let match_id = generator.next_id();
            generator.line(&format!("int route_match_{match_id} = ({matched});"));
            generator.emit_pending_matcher_error()?;
            generator.line(&format!("if (route_match_{match_id}) {{"));
        } else {
            generator.line(&format!("if ({matched}) {{"));
        }
        generator.indent += 1;
        generator.line("if (zs_response_pending() != 0) return 0;");

        let grouped = generator.emit_route_group_guard(&compiled.route, "route")?;

        let terminal = compiled.route.terminal;
        let stopped = generator.emit_handlers(&compiled.route.handlers)?;
        if terminal && !stopped {
            generator.emit_terminal_empty_handler("route");
        }

        if grouped {
            generator.indent -= 1;
            generator.line("}");
        }

        generator.indent -= 1;
        generator.line("}");
        generator.line("else if (zs_response_pending() != 0) {");
        generator.indent += 1;
        generator.line("zs_response_clear();");
        generator.indent -= 1;
        generator.line("}");
    }

    generator.blank();
    generator.line("/* Caddy emptyHandler: unrouted requests receive 200 OK. */");
    generator.line("zs_caddy_respond_static(\"200\", 3, \"{}\", 2);");
    generator.line("return 0;");
    generator.indent -= 1;
    generator.line("}");
    generator.finish_response_hook();
    for warning in generator.ignored_warnings {
        if !warnings.contains(&warning) {
            warnings.push(warning);
        }
    }
    Ok((generator.out, warnings))
}

struct CompiledRoute {
    server_name: String,
    route_index: usize,
    route: Route,
    client_ip_config: Option<ClientIpConfig>,
    named_routes: BTreeMap<String, Route>,
    error_routes: Vec<Route>,
}

#[derive(Default)]
struct Generator {
    out: String,
    indent: usize,
    tmp_id: usize,
    warnings: Vec<String>,
    /// Warnings for fields that are configured outside zeroserve's eBPF surface
    /// and are ignored rather than failing the compile. Surfaced to stderr by
    /// the caller, not embedded in the generated script.
    ignored_warnings: Vec<String>,
    response_hooks: Vec<Vec<String>>,
    current_response_hook: Option<usize>,
    access_log_config: AccessLogConfig,
    tls_connection_policies: Vec<TlsConnectionPolicy>,
    client_ip_config: Option<ClientIpConfig>,
    named_routes: BTreeMap<String, Route>,
    error_routes: Vec<Route>,
    route_groups: BTreeMap<String, usize>,
    in_error_route: bool,
    error_routes_fallthrough: bool,
}

impl Generator {
    fn emit_preamble(&mut self) {
        self.line("#include <zeroserve_caddy.h>");
        self.blank();
    }

    fn emit_access_log_config(&mut self) {
        for (name, file) in self.access_log_config.files.clone() {
            let key = format!("zs.caddy.access_log.file.{name}");
            self.line(&format!(
                "zs_meta_set({}, {}, {}, {});",
                c_str(&key),
                key.len(),
                c_str(&file),
                file.len()
            ));
        }
        if let Some(name) = self.access_log_config.default_logger_name.clone()
            && let Some(file) = self.access_log_config.files.get(&name).cloned()
        {
            self.emit_access_log_file(&name, &file);
        } else if let Some(file) = self.access_log_config.files.get("default").cloned() {
            self.emit_access_log_file("default", &file);
        }
    }

    fn emit_access_log_file(&mut self, name: &str, file: &str) {
        self.line(&format!(
            "zs_meta_set(ZS_STR(\"zs.caddy.access_log.name\"), {}, {});",
            c_str(name),
            name.len()
        ));
        self.line(&format!(
            "zs_meta_set(ZS_STR(\"zs.caddy.access_log.file\"), {}, {});",
            c_str(file),
            file.len()
        ));
    }

    fn emit_tls_entrypoint(&mut self) -> Result<()> {
        let policies = self
            .tls_connection_policies
            .iter()
            .filter(|policy| policy.client_authentication.is_some())
            .cloned()
            .collect::<Vec<_>>();
        if policies.is_empty() {
            return Ok(());
        }

        self.line("ZS_TLS_ENTRY");
        self.line("zs_u64 caddy_tls(void) {");
        self.indent += 1;
        self.line("char caddy_tls_sni[256];");
        self.line(&format!(
            "zs_s64 caddy_tls_sni_len = zs_caddy_expand({}, {}, caddy_tls_sni, sizeof(caddy_tls_sni));",
            c_str("{http.request.tls.server_name}"),
            "{http.request.tls.server_name}".len()
        ));
        self.line("if (caddy_tls_sni_len < 0) caddy_tls_sni_len = 0;");

        for policy in policies {
            let auth = normalize_tls_client_auth(policy.client_authentication.as_ref().unwrap())?;
            let auth = serde_json::to_string(&auth)?;
            let condition = tls_policy_sni_condition(&policy);
            self.line(&format!("if ({condition}) {{"));
            self.indent += 1;
            self.line(&format!(
                "if (zs_caddy_tls_client_auth({}, {}) == 0) {{",
                c_str(&auth),
                auth.len()
            ));
            self.indent += 1;
            self.line("zs_abort();");
            self.line("return 0;");
            self.indent -= 1;
            self.line("}");
            self.indent -= 1;
            self.line("}");
        }

        self.line("return 0;");
        self.indent -= 1;
        self.line("}");
        self.blank();
        Ok(())
    }

    fn emit_terminal_empty_handler(&mut self, label: &str) {
        if self.in_error_route {
            self.line(&format!(
                "/* Caddy terminal {label} reached errorEmptyHandler. */"
            ));
            self.line("zs_caddy_respond(\"{http.error.status_code}\", 24, \"\", 0);");
        } else {
            self.line(&format!(
                "/* Caddy terminal {label} reached emptyHandler. */"
            ));
            self.line("zs_caddy_respond_static(\"200\", 3, \"{}\", 2);");
        }
        self.line("return 0;");
    }

    fn emit_route_match(&mut self, route: &Route) -> Result<String> {
        if route.matcher_sets.is_empty() {
            return Ok("1".to_string());
        }
        let mut set_exprs = Vec::new();
        for set in &route.matcher_sets {
            set_exprs.push(self.emit_matcher_set(set)?);
        }
        Ok(format!("({})", set_exprs.join(" || ")))
    }

    fn emit_matcher_set(&mut self, set: &MatcherSet) -> Result<String> {
        if set.is_empty() {
            return Ok("1".to_string());
        }
        let mut exprs = Vec::new();
        for phase in [
            MatcherEvalPhase::Captures,
            MatcherEvalPhase::Plain,
            MatcherEvalPhase::SetsError,
        ] {
            for (name, value) in set {
                if matcher_eval_phase(name, value) == phase {
                    exprs.push(self.emit_matcher(name, value)?);
                }
            }
        }
        Ok(format!("({})", exprs.join(" && ")))
    }

    fn emit_matcher(&mut self, name: &str, value: &Value) -> Result<String> {
        match name {
            "method" => self.emit_string_list_match("method", "zs_req_method", value, false),
            "path" => self.emit_path_match(value),
            "path_regexp" => self.emit_path_regexp_match(value),
            "host" => self.emit_host_match(value),
            "header" => self.emit_header_match(value),
            "header_regexp" => self.emit_header_regexp_match(value),
            "query" => self.emit_query_match(value),
            "remote_ip" => self.emit_remote_ip_match(value),
            "file" => self.emit_file_match(value),
            "vars" => self.emit_vars_match(value),
            "vars_regexp" => self.emit_vars_regexp_match(value),
            "client_ip" => {
                if let Some(config) = self.client_ip_config.clone() {
                    self.emit_client_ip_match(value, &config)
                } else {
                    self.emit_remote_ip_match(value)
                }
            }
            "expression" => {
                validate_expression_matcher(value)?;
                self.emit_expression_match(value)
                    .context("unsupported http.matchers.expression")
            }
            "not" => {
                let sets = value
                    .as_array()
                    .ok_or_else(|| anyhow!("http.matchers.not must be an array"))?;
                if sets.is_empty() {
                    return Ok("1".to_string());
                }
                let mut exprs = Vec::new();
                for set in sets {
                    let obj = set
                        .as_object()
                        .ok_or_else(|| anyhow!("http.matchers.not entries must be matcher sets"))?;
                    exprs.push(self.emit_matcher_set(obj)?);
                }
                Ok(format!("!({})", exprs.join(" || ")))
            }
            "protocol" => self.emit_protocol_match(value),
            "tls" => self.emit_tls_match(value),
            other => bail!("unsupported Caddy matcher {other:?}"),
        }
    }

    fn emit_string_list_match(
        &mut self,
        label: &str,
        helper: &str,
        value: &Value,
        glob: bool,
    ) -> Result<String> {
        let values = strict_string_array(value, label)?;
        if values.is_empty() {
            return Ok("(0)".to_string());
        }
        let id = self.next_id();
        self.code_line(&format!("char {label}_{id}[512];"));
        self.code_line(&format!(
            "zs_s64 {label}_{id}_raw = {helper}({label}_{id}, sizeof({label}_{id}));"
        ));
        self.code_line(&format!(
            "zs_u64 {label}_{id}_len = zs_caddy_clamp_len({label}_{id}_raw, sizeof({label}_{id}));"
        ));
        let mut checks = Vec::new();
        for v in values {
            checks.push(if glob && v.contains('*') {
                format!(
                    "zs_caddy_glob({label}_{id}, {label}_{id}_len, {}, {})",
                    c_str(&v),
                    v.len()
                )
            } else {
                format!(
                    "zs_caddy_eq({label}_{id}, {label}_{id}_len, {}, {})",
                    c_str(&v),
                    v.len()
                )
            });
        }
        Ok(format!("({})", checks.join(" || ")))
    }

    fn emit_path_match(&mut self, value: &Value) -> Result<String> {
        let values = strict_string_array(value, "path")?;
        if values.is_empty() {
            return Ok("(0)".to_string());
        }
        let mut checks = Vec::new();
        for value in values {
            checks.push(format!(
                "zs_caddy_path_match({}, {})",
                c_str(&value),
                value.len()
            ));
        }
        Ok(format!("({})", checks.join(" || ")))
    }

    fn emit_host_match(&mut self, value: &Value) -> Result<String> {
        let values = strict_string_array(value, "host")?;
        if values.is_empty() {
            return Ok("(0)".to_string());
        }
        let id = self.next_id();
        self.code_line(&format!("char host_{id}[256];"));
        self.code_line(&format!(
            "zs_s64 host_{id}_raw = zs_req_header(ZS_STR(\"host\"), host_{id}, sizeof(host_{id}));"
        ));
        self.code_line(&format!(
            "zs_u64 host_{id}_len = zs_caddy_clamp_len(host_{id}_raw, sizeof(host_{id}));"
        ));
        self.code_line(&format!(
            "host_{id}_len = zs_caddy_host_normalize(host_{id}, host_{id}_len);"
        ));
        let mut checks = Vec::new();
        let mut seen_hosts = BTreeSet::new();
        for value in values {
            if contains_placeholder(&value) {
                let normalized = caddy_normalize_host_pattern(&value)?;
                if !seen_hosts.insert(normalized.to_ascii_lowercase()) {
                    bail!("duplicate host matcher entry {value:?}");
                }
                let pat_id = self.next_id();
                self.code_line(&format!("char host_pat_{pat_id}[256];"));
                self.code_line(&format!(
                    "zs_s64 host_pat_{pat_id}_raw = zs_caddy_expand({}, {}, host_pat_{pat_id}, sizeof(host_pat_{pat_id}));",
                    c_str(&value),
                    value.len()
                ));
                self.code_line(&format!(
                    "zs_u64 host_pat_{pat_id}_len = zs_caddy_clamp_len(host_pat_{pat_id}_raw, sizeof(host_pat_{pat_id}));"
                ));
                checks.push(format!(
                    "(host_pat_{pat_id}_raw >= 0 && zs_caddy_host_match(host_{id}, host_{id}_len, host_pat_{pat_id}, host_pat_{pat_id}_len))"
                ));
            } else {
                let normalized = caddy_normalize_host_pattern(&value)?;
                if !seen_hosts.insert(normalized.to_ascii_lowercase()) {
                    bail!("duplicate host matcher entry {value:?}");
                }
                let host = if caddy_host_fuzzy(&normalized) {
                    normalized
                } else {
                    normalized.to_ascii_lowercase()
                };
                checks.push(format!(
                    "zs_caddy_host_match(host_{id}, host_{id}_len, {}, {})",
                    c_str(&host),
                    host.len()
                ));
            }
        }
        Ok(format!("(host_{id}_raw >= 0 && ({}))", checks.join(" || ")))
    }

    fn emit_path_regexp_match(&mut self, value: &Value) -> Result<String> {
        let config = regex_match_config(value, "path_regexp")?;
        let config_json = serde_json::to_string(&config)?;
        let id = self.next_id();
        self.code_line(&format!("char path_re_{id}[512];"));
        self.code_line(&format!(
            "zs_s64 path_re_{id}_raw = zs_caddy_path_regexp_subject(path_re_{id}, sizeof(path_re_{id}));"
        ));
        self.code_line(&format!(
            "zs_u64 path_re_{id}_len = zs_caddy_clamp_len(path_re_{id}_raw, sizeof(path_re_{id}));"
        ));
        Ok(format!(
            "(path_re_{id}_raw >= 0 && zs_caddy_regex_match(path_re_{id}, path_re_{id}_len, {}, {}) != 0)",
            c_str(&config_json),
            config_json.len()
        ))
    }

    fn emit_header_list_match(
        &mut self,
        header: &str,
        value: &Value,
        fold_value: bool,
        helper: &str,
    ) -> Result<String> {
        let values = match value {
            Value::Null => Vec::new(),
            _ => strict_string_array(value, "header value")?,
        };
        let mut checks = Vec::new();
        for value in values {
            let matcher = if fold_value && !contains_placeholder(&value) {
                let id = self.next_id();
                self.code_line(&format!("char header_{id}[1024];"));
                self.code_line(&format!(
                    "zs_s64 header_{id}_raw = zs_req_header({}, {}, header_{id}, sizeof(header_{id}));",
                    c_str(header),
                    header.len()
                ));
                self.code_line(&format!(
                    "zs_u64 header_{id}_len = zs_caddy_clamp_len(header_{id}_raw, sizeof(header_{id}));"
                ));
                if value == "*" {
                    format!("header_{id}_raw >= 0")
                } else {
                    format!(
                        "zs_caddy_eq_fold(header_{id}, header_{id}_len, {}, {})",
                        c_str(&value),
                        value.len()
                    )
                }
            } else {
                format!(
                    "({helper}({}, {}, {}, {}) != 0)",
                    c_str(header),
                    header.len(),
                    c_str(&value),
                    value.len()
                )
            };
            checks.push(matcher);
        }
        Ok(format!("({})", checks.join(" || ")))
    }

    fn emit_header_match(&mut self, value: &Value) -> Result<String> {
        self.emit_header_match_with_helpers(
            value,
            "zs_caddy_header_match",
            "zs_caddy_header_present",
        )
    }

    fn emit_header_match_with_helpers(
        &mut self,
        value: &Value,
        helper: &str,
        present_helper: &str,
    ) -> Result<String> {
        let obj = value
            .as_object()
            .ok_or_else(|| anyhow!("http.matchers.header must be an object"))?;
        if obj.is_empty() {
            return Ok("1".to_string());
        }
        let mut checks = Vec::new();
        for (name, values) in obj {
            if values.is_null() {
                checks.push(format!(
                    "({present_helper}({}, {}) == 0)",
                    c_str(name),
                    name.len()
                ));
            } else if values.as_array().is_some_and(|a| a.is_empty()) {
                checks.push(format!(
                    "({present_helper}({}, {}) != 0)",
                    c_str(name),
                    name.len()
                ));
            } else {
                checks.push(self.emit_header_list_match(name, values, false, helper)?);
            }
        }
        Ok(format!("({})", checks.join(" && ")))
    }

    fn emit_expression_match(&mut self, value: &Value) -> Result<String> {
        let (expr, name) = if let Some(expr) = value.as_str() {
            (expr, "")
        } else {
            (
                value
                    .get("expr")
                    .and_then(Value::as_str)
                    .ok_or_else(|| anyhow!("expr is required"))?,
                value.get("name").and_then(Value::as_str).unwrap_or(""),
            )
        };
        let mut parser = ExpressionParser::new(expr)?;
        let ast = parser.parse()?;
        self.emit_expression_ast(&ast, name)
    }

    fn emit_expression_ast(
        &mut self,
        ast: &ExpressionAst,
        default_regex_name: &str,
    ) -> Result<String> {
        match ast {
            ExpressionAst::Bool(value) => Ok(if *value {
                "1".to_string()
            } else {
                "0".to_string()
            }),
            ExpressionAst::And(left, right) => Ok(format!(
                "({} && {})",
                self.emit_expression_ast(left, default_regex_name)?,
                self.emit_expression_ast(right, default_regex_name)?
            )),
            ExpressionAst::Or(left, right) => Ok(format!(
                "({} || {})",
                self.emit_expression_ast(left, default_regex_name)?,
                self.emit_expression_ast(right, default_regex_name)?
            )),
            ExpressionAst::Not(inner) => Ok(format!(
                "!({})",
                self.emit_expression_ast(inner, default_regex_name)?
            )),
            ExpressionAst::Eq(left, right) => {
                self.emit_expression_string_compare(left, right, true)
            }
            ExpressionAst::Ne(left, right) => {
                self.emit_expression_string_compare(left, right, false)
            }
            ExpressionAst::Matches(left, pattern) => {
                self.emit_expression_string_matches(left, pattern)
            }
            ExpressionAst::In(left, values) => self.emit_expression_string_in(left, values),
            ExpressionAst::NumericCompare { left, op, right } => {
                self.emit_expression_numeric_compare(left, *op, right)
            }
            ExpressionAst::Call { name, args } => {
                self.emit_expression_call(name, args, default_regex_name)
            }
        }
    }

    fn emit_expression_string_compare(
        &mut self,
        left: &str,
        right: &str,
        equal: bool,
    ) -> Result<String> {
        let cmp = format!(
            "(zs_caddy_expr_eq({}, {}, {}, {}) != 0)",
            c_str(left),
            left.len(),
            c_str(right),
            right.len()
        );
        Ok(if equal { cmp } else { format!("!({cmp})") })
    }

    fn emit_expression_numeric_compare(
        &mut self,
        left: &str,
        op: NumericCompareOp,
        right: &str,
    ) -> Result<String> {
        let id = self.next_id();
        self.code_line(&format!("char expr_num_left_{id}[32];"));
        self.code_line(&format!("char expr_num_right_{id}[32];"));
        self.code_line(&format!(
            "zs_s64 expr_num_left_{id}_raw = zs_caddy_expand({}, {}, expr_num_left_{id}, sizeof(expr_num_left_{id}));",
            c_str(left),
            left.len()
        ));
        self.code_line(&format!(
            "zs_s64 expr_num_right_{id}_raw = zs_caddy_expand({}, {}, expr_num_right_{id}, sizeof(expr_num_right_{id}));",
            c_str(right),
            right.len()
        ));
        self.code_line(&format!(
            "zs_u64 expr_num_left_{id}_len = zs_caddy_clamp_len(expr_num_left_{id}_raw, sizeof(expr_num_left_{id}));"
        ));
        self.code_line(&format!(
            "zs_u64 expr_num_right_{id}_len = zs_caddy_clamp_len(expr_num_right_{id}_raw, sizeof(expr_num_right_{id}));"
        ));
        self.code_line(&format!(
            "zs_s64 expr_num_left_{id}_value = expr_num_left_{id}_raw >= 0 ? zs_caddy_parse_u16(expr_num_left_{id}, expr_num_left_{id}_len) : -1;"
        ));
        self.code_line(&format!(
            "zs_s64 expr_num_right_{id}_value = expr_num_right_{id}_raw >= 0 ? zs_caddy_parse_u16(expr_num_right_{id}, expr_num_right_{id}_len) : -1;"
        ));
        let cmp = match op {
            NumericCompareOp::Gt => ">",
            NumericCompareOp::Ge => ">=",
            NumericCompareOp::Lt => "<",
            NumericCompareOp::Le => "<=",
        };
        Ok(format!(
            "(expr_num_left_{id}_value >= 0 && expr_num_right_{id}_value >= 0 && expr_num_left_{id}_value {cmp} expr_num_right_{id}_value)"
        ))
    }

    fn emit_expression_string_in(&mut self, left: &str, values: &[String]) -> Result<String> {
        if values.is_empty() {
            return Ok("0".to_string());
        }
        let values = serde_json::to_string(values)?;
        Ok(format!(
            "(zs_caddy_expr_in({}, {}, {}, {}) != 0)",
            c_str(left),
            left.len(),
            c_str(&values),
            values.len()
        ))
    }

    fn emit_expression_string_matches(&mut self, left: &str, pattern: &str) -> Result<String> {
        let mut config = Map::new();
        config.insert("pattern".to_string(), Value::String(pattern.to_string()));
        let config = regex_match_config(&Value::Object(config), "expression.matches")?;
        let config_json = serde_json::to_string(&config)?;
        let id = self.next_id();
        self.code_line(&format!("char expr_match_left_{id}[512];"));
        self.code_line(&format!(
            "zs_s64 expr_match_left_{id}_raw = zs_caddy_expand({}, {}, expr_match_left_{id}, sizeof(expr_match_left_{id}));",
            c_str(left),
            left.len()
        ));
        self.code_line(&format!(
            "zs_u64 expr_match_left_{id}_len = zs_caddy_clamp_len(expr_match_left_{id}_raw, sizeof(expr_match_left_{id}));"
        ));
        Ok(format!(
            "(expr_match_left_{id}_raw >= 0 && zs_caddy_regex_match(expr_match_left_{id}, expr_match_left_{id}_len, {}, {}) != 0)",
            c_str(&config_json),
            config_json.len()
        ))
    }

    fn emit_expression_call(
        &mut self,
        name: &str,
        args: &[ExpressionArg],
        default_regex_name: &str,
    ) -> Result<String> {
        match name {
            "method" => self.emit_expression_string_list_call("method", args, |this, value| {
                this.emit_string_list_match("method", "zs_req_method", value, false)
            }),
            "path" => self.emit_expression_string_list_call("path", args, |this, value| {
                this.emit_path_match(value)
            }),
            "path_regexp" => {
                let value = expression_regexp_arg("path_regexp", args, default_regex_name)?;
                self.emit_path_regexp_match(&value)
            }
            "host" => self.emit_expression_string_list_call("host", args, |this, value| {
                this.emit_host_match(value)
            }),
            "remote_ip" => {
                self.emit_expression_string_list_call("remote_ip", args, |this, value| {
                    let ranges = value
                        .as_array()
                        .expect("expression string list is always an array")
                        .iter()
                        .cloned()
                        .collect::<Vec<_>>();
                    let mut obj = Map::new();
                    obj.insert("ranges".to_string(), Value::Array(ranges));
                    this.emit_remote_ip_match(&Value::Object(obj))
                })
            }
            "client_ip" => {
                let config = self.client_ip_config.clone();
                self.emit_expression_string_list_call("client_ip", args, move |this, value| {
                    let ranges = value
                        .as_array()
                        .expect("expression string list is always an array")
                        .iter()
                        .cloned()
                        .collect::<Vec<_>>();
                    let mut obj = Map::new();
                    obj.insert("ranges".to_string(), Value::Array(ranges));
                    if let Some(config) = &config {
                        this.emit_client_ip_match(&Value::Object(obj), config)
                    } else {
                        this.emit_remote_ip_match(&Value::Object(obj))
                    }
                })
            }
            "protocol" => {
                if args.len() != 1 {
                    bail!("protocol() requires one string argument");
                }
                let ExpressionArg::String(value) = &args[0] else {
                    bail!("protocol() only supports a string argument");
                };
                self.emit_protocol_match(&Value::String(value.to_ascii_lowercase()))
            }
            "header" => {
                let value = expression_single_map_arg("header", args)?;
                self.emit_header_match_with_helpers(
                    &value,
                    "zs_caddy_header_match_expanded",
                    "zs_caddy_header_present_expanded",
                )
            }
            "header_regexp" => {
                let (field, value) =
                    expression_field_regexp_arg("header_regexp", args, default_regex_name)?;
                let mut obj = Map::new();
                obj.insert(field, value);
                self.emit_header_regexp_match_with_helper(
                    &Value::Object(obj),
                    "zs_caddy_header_regexp_match_expanded",
                )
            }
            "query" => {
                let value = expression_single_map_arg("query", args)?;
                self.emit_query_match(&value)
            }
            "vars" => {
                let value = expression_single_map_arg("vars", args)?;
                self.emit_vars_match_with_helper(&value, "zs_caddy_vars_match_expanded_keys")
            }
            "vars_regexp" => {
                let (key, value) =
                    expression_field_regexp_arg("vars_regexp", args, default_regex_name)?;
                let mut obj = Map::new();
                obj.insert(key, value);
                self.emit_vars_regexp_match_with_helper(
                    &Value::Object(obj),
                    "zs_caddy_vars_regexp_match_expanded_keys",
                )
            }
            "file" => {
                let value = expression_file_matcher_arg(args)?;
                self.emit_file_match(&value)
            }
            other => bail!("unsupported expression matcher call {other:?}"),
        }
    }

    fn emit_expression_string_list_call(
        &mut self,
        name: &str,
        args: &[ExpressionArg],
        emit: impl FnOnce(&mut Self, &Value) -> Result<String>,
    ) -> Result<String> {
        if args.is_empty() {
            bail!("{name}() requires at least one string argument");
        }
        let mut values = Vec::new();
        for arg in args {
            let ExpressionArg::String(value) = arg else {
                bail!("{name}() only supports string arguments");
            };
            values.push(Value::String(value.clone()));
        }
        emit(self, &Value::Array(values))
    }

    fn emit_header_regexp_match(&mut self, value: &Value) -> Result<String> {
        self.emit_header_regexp_match_with_helper(value, "zs_caddy_header_regexp_match")
    }

    fn emit_header_regexp_match_with_helper(
        &mut self,
        value: &Value,
        helper: &str,
    ) -> Result<String> {
        let obj = value
            .as_object()
            .ok_or_else(|| anyhow!("http.matchers.header_regexp must be an object"))?;
        if obj.is_empty() {
            return Ok("1".to_string());
        }
        let mut checks = Vec::new();
        for (name, matcher) in obj {
            let config = regex_match_config(matcher, "header_regexp")?;
            let config_json = serde_json::to_string(&config)?;
            checks.push(format!(
                "({helper}({}, {}, {}, {}) != 0)",
                c_str(name),
                name.len(),
                c_str(&config_json),
                config_json.len()
            ));
        }
        Ok(format!("({})", checks.join(" && ")))
    }

    fn emit_query_match(&mut self, value: &Value) -> Result<String> {
        let obj = value
            .as_object()
            .ok_or_else(|| anyhow!("http.matchers.query must be an object"))?;
        if obj.is_empty() {
            return Ok("(zs_caddy_query_empty() != 0)".to_string());
        }
        let mut checks = Vec::new();
        for (name, values) in obj {
            if values.is_null() {
                checks.push("(0)".to_string());
            } else {
                let values = strict_string_array(values, "query value")?;
                if values.is_empty() {
                    checks.push("(0)".to_string());
                    continue;
                }
                let mut value_checks = Vec::new();
                for value in values {
                    value_checks.push(format!(
                        "zs_caddy_query_match({}, {}, {}, {})",
                        c_str(name),
                        name.len(),
                        c_str(&value),
                        value.len()
                    ));
                }
                checks.push(format!("({})", value_checks.join(" || ")));
            }
        }
        Ok(format!("({})", checks.join(" && ")))
    }

    fn emit_remote_ip_match(&mut self, value: &Value) -> Result<String> {
        let obj = value
            .as_object()
            .ok_or_else(|| anyhow!("http.matchers.remote_ip must be an object"))?;
        validate_object_fields(obj, &["ranges"], "http.matchers.remote_ip")?;
        let ranges = value
            .get("ranges")
            .and_then(Value::as_array)
            .ok_or_else(|| anyhow!("http.matchers.remote_ip requires a ranges array"))?;
        let mut emitted = Vec::new();
        let mut dynamic = false;
        for range in ranges {
            let range = range
                .as_str()
                .ok_or_else(|| anyhow!("http.matchers.remote_ip ranges must be strings"))?;
            if contains_placeholder(range) {
                dynamic = true;
            } else {
                validate_ip_range(range)
                    .with_context(|| format!("invalid remote_ip range {range:?}"))?;
            }
            emitted.push(Value::String(range.to_string()));
        }
        let ranges = serde_json::to_string(&Value::Array(emitted))?;
        let helper = if dynamic {
            "zs_caddy_remote_ip_matches"
        } else {
            "zs_req_remote_ip_matches"
        };
        self.emit_ip_matcher_early_data_guard()?;
        Ok(format!(
            "({helper}({}, {}) != 0)",
            c_str(&ranges),
            ranges.len()
        ))
    }

    fn emit_client_ip_match(&mut self, value: &Value, config: &ClientIpConfig) -> Result<String> {
        let obj = value
            .as_object()
            .ok_or_else(|| anyhow!("http.matchers.client_ip must be an object"))?;
        validate_object_fields(obj, &["ranges"], "http.matchers.client_ip")?;
        let ranges = value
            .get("ranges")
            .and_then(Value::as_array)
            .ok_or_else(|| anyhow!("http.matchers.client_ip requires a ranges array"))?;
        let mut emitted_ranges = Vec::new();
        for range in ranges {
            let range = range
                .as_str()
                .ok_or_else(|| anyhow!("http.matchers.client_ip ranges must be strings"))?;
            if !contains_placeholder(range) {
                validate_ip_range(range)
                    .with_context(|| format!("invalid client_ip range {range:?}"))?;
            }
            emitted_ranges.push(Value::String(range.to_string()));
        }
        let mut emitted = Map::new();
        emitted.insert("ranges".to_string(), Value::Array(emitted_ranges));
        emitted.insert(
            "trusted_ranges".to_string(),
            Value::Array(
                config
                    .trusted_ranges
                    .iter()
                    .cloned()
                    .map(Value::String)
                    .collect(),
            ),
        );
        emitted.insert(
            "headers".to_string(),
            Value::Array(config.headers.iter().cloned().map(Value::String).collect()),
        );
        emitted.insert("strict".to_string(), Value::Bool(config.strict));
        emitted.insert("trusted_unix".to_string(), Value::Bool(config.trusted_unix));
        let config = serde_json::to_string(&Value::Object(emitted))?;
        self.emit_ip_matcher_early_data_guard()?;
        Ok(format!(
            "(zs_caddy_client_ip_matches({}, {}) != 0)",
            c_str(&config),
            config.len()
        ))
    }

    fn emit_ip_matcher_early_data_guard(&mut self) -> Result<()> {
        self.line("if (zs_req_is_tls() != 0 && zs_req_tls_handshake_complete() == 0) {");
        self.indent += 1;
        self.line(
            "zs_caddy_set_error(\"425\", 3, \"TLS handshake not complete, remote IP cannot be verified\", 56);",
        );
        if !self.error_routes.is_empty() && !self.in_error_route {
            self.emit_error_routes()?;
            self.line("if (zs_response_pending() == 0) {");
            self.indent += 1;
            self.line("zs_caddy_respond(\"425\", 3, \"\", 0);");
            self.indent -= 1;
            self.line("}");
        } else {
            self.line("zs_caddy_respond(\"425\", 3, \"\", 0);");
        }
        self.line("return 0;");
        self.indent -= 1;
        self.line("}");
        Ok(())
    }

    fn emit_file_match(&mut self, value: &Value) -> Result<String> {
        validate_file_matcher(value)?;
        let value = normalize_file_matcher(value)?;
        let config = serde_json::to_string(&value)?;
        Ok(format!(
            "(zs_caddy_file_match({}, {}) != 0)",
            c_str(&config),
            config.len()
        ))
    }

    fn emit_vars_match(&mut self, value: &Value) -> Result<String> {
        self.emit_vars_match_with_helper(value, "zs_caddy_vars_match")
    }

    fn emit_vars_match_with_helper(&mut self, value: &Value, helper: &str) -> Result<String> {
        let obj = value
            .as_object()
            .ok_or_else(|| anyhow!("http.matchers.vars must be an object"))?;
        let mut emitted = Map::new();
        for (key, values) in obj {
            let values = strict_string_array(values, "vars matcher value")?;
            emitted.insert(
                key.to_string(),
                Value::Array(values.into_iter().map(Value::String).collect()),
            );
        }
        let emitted = serde_json::to_string(&Value::Object(emitted))?;
        Ok(format!(
            "({helper}({}, {}) != 0)",
            c_str(&emitted),
            emitted.len()
        ))
    }

    fn emit_vars_regexp_match(&mut self, value: &Value) -> Result<String> {
        self.emit_vars_regexp_match_with_helper(value, "zs_caddy_vars_regexp_match")
    }

    fn emit_vars_regexp_match_with_helper(
        &mut self,
        value: &Value,
        helper: &str,
    ) -> Result<String> {
        let obj = value
            .as_object()
            .ok_or_else(|| anyhow!("http.matchers.vars_regexp must be an object"))?;
        let mut emitted = Map::new();
        for (key, matcher) in obj {
            emitted.insert(key.to_string(), regex_match_config(matcher, "vars_regexp")?);
        }
        let emitted = serde_json::to_string(&Value::Object(emitted))?;
        Ok(format!(
            "({helper}({}, {}) != 0)",
            c_str(&emitted),
            emitted.len()
        ))
    }

    fn emit_protocol_match(&mut self, value: &Value) -> Result<String> {
        let protocol = value
            .as_str()
            .ok_or_else(|| anyhow!("http.matchers.protocol must be a string"))?;
        let expr = match protocol {
            "grpc" => {
                "(zs_caddy_req_header_first_prefix(ZS_STR(\"content-type\"), ZS_STR(\"application/grpc\")) != 0)".to_string()
            }
            "https" => "(zs_req_is_tls() != 0)".to_string(),
            "http" => "(zs_req_is_tls() == 0)".to_string(),
            "http/1.0" => "(zs_req_proto_major() == 1 && zs_req_proto_minor() == 0)".to_string(),
            "http/1.0+" => "(zs_req_proto_major() >= 1)".to_string(),
            "http/1.1" => "(zs_req_proto_major() == 1 && zs_req_proto_minor() == 1)".to_string(),
            "http/1.1+" => {
                "((zs_req_proto_major() > 1) || (zs_req_proto_major() == 1 && zs_req_proto_minor() >= 1))".to_string()
            }
            "http/2" => "(zs_req_proto_major() == 2)".to_string(),
            "http/2+" => "(zs_req_proto_major() >= 2)".to_string(),
            "http/3" => "(zs_req_proto_major() == 3)".to_string(),
            "http/3+" => "(zs_req_proto_major() >= 3)".to_string(),
            _ => "0".to_string(),
        };
        Ok(expr)
    }

    fn emit_tls_match(&mut self, value: &Value) -> Result<String> {
        let obj = value
            .as_object()
            .ok_or_else(|| anyhow!("http.matchers.tls must be an object"))?;
        if obj.keys().any(|key| key != "handshake_complete") {
            bail!("unsupported http.matchers.tls field");
        }
        let mut checks = vec!["(zs_req_is_tls() != 0)".to_string()];
        if let Some(handshake_complete) = obj.get("handshake_complete") {
            let handshake_complete = handshake_complete
                .as_bool()
                .ok_or_else(|| anyhow!("http.matchers.tls.handshake_complete must be a boolean"))?;
            if !handshake_complete {
                bail!(
                    "http.matchers.tls.handshake_complete=false matches QUIC early data, which zeroserve does not expose to generated eBPF middleware"
                );
            }
            checks.push("(zs_req_tls_handshake_complete() != 0)".to_string());
        }
        Ok(format!("({})", checks.join(" && ")))
    }

    fn emit_handlers(&mut self, handlers: &[Handler]) -> Result<bool> {
        let mut terminal = false;
        for handler in handlers {
            if terminal {
                self.warn(format!(
                    "handler {:?} follows a terminal handler and is unreachable",
                    handler.handler
                ));
                continue;
            }
            terminal = self.emit_handler(handler)?;
        }
        Ok(terminal)
    }

    fn route_group_id(&self, route: &Route) -> Result<Option<usize>> {
        let Some(group) = &route.group else {
            return Ok(None);
        };
        self.route_groups
            .get(group)
            .copied()
            .map(Some)
            .ok_or_else(|| anyhow!("internal missing Caddy route group {group:?}"))
    }

    fn emit_route_group_guard(&mut self, route: &Route, label: &str) -> Result<bool> {
        let Some(group_id) = self.route_group_id(route)? else {
            return Ok(false);
        };
        self.line(&format!("if (route_groups[{group_id}]) {{"));
        self.indent += 1;
        self.line(&format!(
            "/* Caddy {label} group already satisfied; skip this route. */"
        ));
        self.indent -= 1;
        self.line("} else {");
        self.indent += 1;
        self.line(&format!("route_groups[{group_id}] = 1;"));
        let key = caddy_route_group_meta_key(group_id);
        self.line(&format!(
            "zs_meta_set({}, {}, ZS_STR(\"1\"));",
            c_str(&key),
            key.len()
        ));
        Ok(true)
    }

    fn emit_subroute_routes(&mut self, routes: &[Route]) -> Result<bool> {
        for route in routes {
            self.emit_subroute_route(route)?;
        }
        Ok(false)
    }

    fn emit_subroute_route(&mut self, route: &Route) -> Result<()> {
        validate_route_fields(route, "subroute route")?;
        let matched = self.emit_route_match(route)?;
        if route_match_can_set_error(route) {
            let match_id = self.next_id();
            self.line(&format!("int subroute_match_{match_id} = ({matched});"));
            self.emit_pending_matcher_error()?;
            self.line(&format!("if (subroute_match_{match_id}) {{"));
        } else {
            self.line(&format!("if ({matched}) {{"));
        }
        self.indent += 1;
        self.line("if (zs_response_pending() != 0) return 0;");
        let grouped = self.emit_route_group_guard(route, "subroute")?;

        let terminal = self.emit_handlers(&route.handlers)?;
        if route.terminal && !terminal {
            self.emit_terminal_empty_handler("subroute");
        }

        if grouped {
            self.indent -= 1;
            self.line("}");
        }
        self.indent -= 1;
        self.line("}");
        self.line("else if (zs_response_pending() != 0) {");
        self.indent += 1;
        self.line("zs_response_clear();");
        self.indent -= 1;
        self.line("}");
        Ok(())
    }

    fn emit_handler(&mut self, handler: &Handler) -> Result<bool> {
        match handler.handler.as_str() {
            "static_response" => self.emit_static_response(handler),
            "error" => self.emit_static_error(handler),
            "headers" => self.emit_headers(handler),
            "rewrite" => self.emit_rewrite(handler),
            "request_body" => self.emit_request_body(handler),
            "reverse_proxy" => self.emit_reverse_proxy(handler),
            "intercept" => self.emit_intercept(handler),
            "file_server" => self.emit_file_server(handler),
            "vars" => self.emit_vars(handler),
            "map" => self.emit_map(handler),
            "invoke" => self.emit_invoke(handler),
            "caddy_access_log" => self.emit_caddy_access_log(handler),
            "log_append" => self.emit_ignored_observability_handler(
                handler,
                &["key", "value", "early"],
                "log_append",
                "access-log field append",
            ),
            "tracing" => self.emit_ignored_observability_handler(
                handler,
                &["span", "span_attributes"],
                "tracing",
                "OpenTelemetry tracing",
            ),
            "push" => self.emit_push(handler),
            "metrics" => bail!(
                "metrics handler serves Prometheus metrics and cannot be represented by generated eBPF middleware"
            ),
            "encode" => self.emit_encode(handler),
            "templates" => bail!(
                "{} handler rewrites response bodies and is not supported by generated Caddy middleware",
                handler.handler
            ),
            "copy_response" => bail!(
                "copy_response handler copies upstream response bodies and is not supported by generated Caddy middleware"
            ),
            "copy_response_headers" => bail!(
                "copy_response_headers is only meaningful inside reverse_proxy handle_response routes"
            ),
            "authentication" => self.emit_authentication(handler),
            "acme_server" => bail!(
                "acme_server handler depends on Caddy ACME certificate runtime outside zeroserve's eBPF request-processing surface"
            ),
            "subroute" => {
                let routes = match handler.config.get("routes") {
                    Some(value) => route_vec_from_value(value, "invalid subroute routes")?,
                    None => Vec::new(),
                };
                let error_routes = if let Some(errors) = handler
                    .config
                    .get("errors")
                    .filter(|value| !value.is_null())
                {
                    let errors: HttpErrorConfig = serde_json::from_value(errors.clone())
                        .context("invalid subroute errors")?;
                    validate_error_routes(&errors.routes, "subroute error route")?;
                    errors.routes
                } else {
                    Vec::new()
                };
                for (idx, route) in routes.iter().enumerate() {
                    validate_route_fields(route, &format!("subroute route {idx}"))?;
                }
                let previous_error_routes = std::mem::replace(&mut self.error_routes, error_routes);
                let previous_fallthrough = self.error_routes_fallthrough;
                self.error_routes_fallthrough = true;
                let result = self.emit_subroute_routes(&routes);
                self.error_routes = previous_error_routes;
                self.error_routes_fallthrough = previous_fallthrough;
                result
            }
            other => bail!("unsupported Caddy handler {other:?}"),
        }
    }

    fn emit_push(&mut self, handler: &Handler) -> Result<bool> {
        validate_push_handler(handler)?;
        let warning =
            "ignoring push handler: HTTP/2 server push is outside zeroserve's eBPF request-processing surface"
                .to_string();
        if !self.ignored_warnings.contains(&warning) {
            self.ignored_warnings.push(warning);
        }
        Ok(false)
    }

    fn emit_ignored_observability_handler(
        &mut self,
        handler: &Handler,
        supported: &[&str],
        label: &str,
        reason: &str,
    ) -> Result<bool> {
        validate_object_fields(&handler.config, supported, label)?;
        let warning = format!(
            "ignoring {label} handler: {reason} is outside zeroserve's eBPF request-processing surface"
        );
        if !self.ignored_warnings.contains(&warning) {
            self.ignored_warnings.push(warning);
        }
        Ok(false)
    }

    fn emit_invoke(&mut self, handler: &Handler) -> Result<bool> {
        validate_object_fields(&handler.config, &["name"], "invoke")?;
        let name = handler
            .config
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or("");
        let route = self
            .named_routes
            .get(name)
            .cloned()
            .ok_or_else(|| missing_named_route_error(name))?;
        validate_route_fields(&route, &format!("named route {name:?}"))?;

        self.line(&format!("/* invoke named route {} */", c_comment(name)));
        let matched = self.emit_route_match(&route)?;
        if route_match_can_set_error(&route) {
            let match_id = self.next_id();
            self.line(&format!("int invoke_match_{match_id} = ({matched});"));
            self.emit_pending_matcher_error()?;
            self.line(&format!("if (invoke_match_{match_id}) {{"));
        } else {
            self.line(&format!("if ({matched}) {{"));
        }
        self.indent += 1;
        self.line("if (zs_response_pending() != 0) return 0;");
        let grouped = self.emit_route_group_guard(&route, "named route")?;
        let terminal = self.emit_handlers(&route.handlers)?;
        if route.terminal && !terminal {
            self.emit_terminal_empty_handler("named route");
        }
        if grouped {
            self.indent -= 1;
            self.line("}");
        }
        self.indent -= 1;
        self.line("}");
        self.line("else if (zs_response_pending() != 0) {");
        self.indent += 1;
        self.line("zs_response_clear();");
        self.indent -= 1;
        self.line("}");
        Ok(false)
    }

    fn emit_static_response(&mut self, handler: &Handler) -> Result<bool> {
        validate_static_response_fields(&handler.config)?;
        if bool_field(&handler.config, "abort") {
            self.line("zs_abort();");
            self.line("return 0;");
            return Ok(true);
        }
        let body = handler
            .config
            .get("body")
            .and_then(Value::as_str)
            .unwrap_or("");
        let status = handler
            .config
            .get("status_code")
            .and_then(weak_string)
            .unwrap_or_else(|| {
                if self.in_error_route {
                    "{http.error.status_code}".to_string()
                } else {
                    String::new()
                }
            });
        if is_decimal_status_literal(&status) {
            let parsed = status
                .parse::<u64>()
                .context("static_response.status_code must be an integer or placeholder string")?;
            if parsed == 103 {
                bail!(
                    "static_response.status_code 103 Early Hints cannot be represented exactly by zeroserve responses"
                );
            }
            if !(100..=999).contains(&parsed) {
                bail!("static_response.status_code must be 100..999");
            }
        }
        let mut config = Map::new();
        config.insert("body".to_string(), Value::String(body.to_string()));
        if bool_field(&handler.config, "close") {
            config.insert("close".to_string(), Value::Bool(true));
        }
        if let Some(headers) = handler.config.get("headers")
            && !headers.is_null()
        {
            config.insert(
                "headers".to_string(),
                normalize_static_response_headers(headers)?,
            );
        }
        let config = serde_json::to_string(&Value::Object(config))?;
        self.line(&format!(
            "zs_caddy_respond_static({}, {}, {}, {});",
            c_str(&status),
            status.len(),
            c_str(&config),
            config.len()
        ));
        self.line("return 0;");
        Ok(true)
    }

    fn emit_static_error(&mut self, handler: &Handler) -> Result<bool> {
        validate_static_error_fields(&handler.config)?;
        let mut status = handler
            .config
            .get("status_code")
            .and_then(weak_string)
            .unwrap_or_else(|| "500".to_string());
        if status.is_empty() {
            status = "500".to_string();
        }
        if is_decimal_status_literal(&status) {
            let parsed = status
                .parse::<u64>()
                .context("error.status_code must be an integer or placeholder string")?;
            if parsed == 103 {
                bail!(
                    "error.status_code 103 Early Hints cannot be represented exactly by zeroserve responses"
                );
            }
            if !(100..=999).contains(&parsed) {
                bail!("error.status_code must be 100..999");
            }
        }
        if !self.error_routes.is_empty() {
            let message = handler
                .config
                .get("error")
                .and_then(Value::as_str)
                .unwrap_or("");
            self.line(&format!(
                "zs_caddy_set_error({}, {}, {}, {});",
                c_str(&status),
                status.len(),
                c_str(message),
                message.len()
            ));
            self.emit_error_routes()?;
            if self.error_routes_fallthrough {
                self.line("if (zs_response_pending() != 0) return 0;");
                return Ok(false);
            }
            self.line("if (zs_response_pending() == 0) {");
            self.indent += 1;
            self.line(&format!(
                "zs_caddy_respond({}, {}, \"\", 0);",
                c_str(&status),
                status.len()
            ));
            self.indent -= 1;
            self.line("}");
            self.line("return 0;");
            return Ok(true);
        }
        self.line(&format!(
            "zs_caddy_respond({}, {}, \"\", 0);",
            c_str(&status),
            status.len()
        ));
        self.line("return 0;");
        Ok(true)
    }

    fn emit_authentication(&mut self, handler: &Handler) -> Result<bool> {
        let config = normalize_http_basic_auth_config(&handler.config)?;
        if let Some(config) = &config {
            let result = format!("zs_caddy_basic_auth_result_{}", self.next_id());
            self.line(&format!(
                "zs_s64 {result} = zs_caddy_basic_auth({}, {});",
                c_str(&config),
                config.len()
            ));
            self.line(&format!("if ({result} == 0) {{"));
            self.indent += 1;
        } else {
            self.line("zs_caddy_set_error(\"401\", 3, \"not authenticated\", 17);");
        }
        if !self.error_routes.is_empty() {
            self.emit_error_routes()?;
            self.line("if (zs_response_pending() == 0) {");
            self.indent += 1;
            self.line("zs_caddy_respond(\"{http.error.status_code}\", 24, \"\", 0);");
            self.indent -= 1;
            self.line("}");
        } else {
            self.line("zs_caddy_respond(\"{http.error.status_code}\", 24, \"\", 0);");
        }
        self.line("return 0;");
        if config.is_some() {
            self.indent -= 1;
            self.line("}");
        }
        Ok(false)
    }

    fn emit_error_routes(&mut self) -> Result<()> {
        let routes = self.error_routes.clone();
        let previous = self.in_error_route;
        if !previous {
            self.line("zs_res_hooks_clear();");
        }
        self.in_error_route = true;
        for (idx, route) in routes.iter().enumerate() {
            self.line(&format!("/* server error route {idx} */"));
            let matched = self.emit_route_match(route)?;
            self.line(&format!("if ({matched}) {{"));
            self.indent += 1;
            self.line("if (zs_response_pending() != 0) return 0;");
            let grouped = self.emit_route_group_guard(route, "server error route")?;
            let terminal = route.terminal;
            let stopped = self.emit_handlers(&route.handlers)?;
            if terminal && !stopped {
                self.line("if (zs_response_pending() == 0) {");
                self.indent += 1;
                self.line("zs_caddy_respond(\"{http.error.status_code}\", 24, \"\", 0);");
                self.indent -= 1;
                self.line("}");
                self.line("return 0;");
            }
            if grouped {
                self.indent -= 1;
                self.line("}");
            }
            self.indent -= 1;
            self.line("}");
            self.line("else if (zs_response_pending() != 0) {");
            self.indent += 1;
            self.line("zs_response_clear();");
            self.indent -= 1;
            self.line("}");
        }
        self.in_error_route = previous;
        Ok(())
    }

    fn emit_pending_matcher_error(&mut self) -> Result<()> {
        let id = self.next_id();
        self.line(&format!("char matcher_error_status_{id}[4];"));
        self.line(&format!(
            "zs_s64 matcher_error_status_{id}_raw = zs_meta_get(ZS_STR(\"http.error.status_code\"), matcher_error_status_{id}, sizeof(matcher_error_status_{id}));"
        ));
        self.line(&format!("if (matcher_error_status_{id}_raw > 0) {{"));
        self.indent += 1;
        self.line(&format!(
            "zs_u64 matcher_error_status_{id}_len = zs_caddy_clamp_len(matcher_error_status_{id}_raw, sizeof(matcher_error_status_{id}));"
        ));
        if !self.error_routes.is_empty() && !self.in_error_route {
            self.emit_error_routes()?;
            self.line("if (zs_response_pending() == 0) {");
            self.indent += 1;
            self.line(&format!(
                "zs_caddy_respond(matcher_error_status_{id}, matcher_error_status_{id}_len, \"\", 0);"
            ));
            self.indent -= 1;
            self.line("}");
        } else {
            self.line(&format!(
                "zs_caddy_respond(matcher_error_status_{id}, matcher_error_status_{id}_len, \"\", 0);"
            ));
        }
        self.line("return 0;");
        self.indent -= 1;
        self.line("}");
        Ok(())
    }

    /// Emit the `encode` handler. The actual streaming compression happens in
    /// the native runtime (gzip/zstd cannot be expressed in eBPF middleware), so
    /// the compiler validates and normalizes the config and hands it to the
    /// `zs_caddy_encode` helper, which records it for the response path.
    fn emit_encode(&mut self, handler: &Handler) -> Result<bool> {
        let config = normalize_encode_config(handler)?;
        let config = serde_json::to_string(&config)?;
        self.line(&format!(
            "zs_caddy_encode({}, {});",
            c_str(&config),
            config.len()
        ));
        Ok(false)
    }

    fn emit_headers(&mut self, handler: &Handler) -> Result<bool> {
        validate_headers_handler(handler)?;
        if let Some(request) = handler.config.get("request")
            && !request.is_null()
        {
            let request = normalize_header_ops(request, HeaderTarget::Request)?;
            self.emit_header_ops(&request, HeaderTarget::Request)?;
        }
        if let Some(response) = handler.config.get("response")
            && !response.is_null()
        {
            let response = normalize_header_ops(response, HeaderTarget::Response)?;
            let obj = response
                .as_object()
                .ok_or_else(|| anyhow!("headers.response must be an object"))?;
            if !obj.get("require").is_some_and(|value| !value.is_null())
                && !bool_field(obj, "deferred")
            {
                let config = serde_json::to_string(&response)?;
                self.line(&format!(
                    "zs_caddy_response_headers({}, {});",
                    c_str(&config),
                    config.len()
                ));
                return Ok(false);
            }
            let hook = self.begin_response_hook();
            let require = if let Some(require) = obj.get("require") {
                if require.is_null() {
                    None
                } else {
                    Some(self.emit_response_require(require)?)
                }
            } else {
                None
            };
            if let Some(require) = &require {
                self.response_line(&format!("if ({require}) {{"));
            }
            self.emit_caddy_response_header_ops(&response)?;
            if require.is_some() {
                self.response_line("}");
            }
            self.end_response_hook(hook);
        }
        Ok(false)
    }

    fn emit_caddy_response_header_ops(&mut self, value: &Value) -> Result<()> {
        let config = serde_json::to_string(value)?;
        self.response_line(&format!(
            "zs_caddy_response_headers({}, {});",
            c_str(&config),
            config.len()
        ));
        Ok(())
    }

    fn emit_response_require(&mut self, value: &Value) -> Result<String> {
        let obj = value
            .as_object()
            .ok_or_else(|| anyhow!("headers.response.require must be an object"))?;
        let mut checks = Vec::new();
        for key in obj.keys() {
            if key != "status_code" && key != "headers" {
                bail!("unsupported response matcher {key:?}");
            }
        }
        if let Some(statuses) = obj.get("status_code")
            && !statuses.is_null()
        {
            checks.push(self.emit_response_status_match(statuses)?);
        }
        if let Some(headers) = obj.get("headers")
            && !headers.is_null()
        {
            checks.push(self.emit_response_header_match(headers)?);
        }
        if checks.is_empty() {
            Ok("1".to_string())
        } else {
            Ok(format!("({})", checks.join(" && ")))
        }
    }

    fn emit_response_status_match(&mut self, value: &Value) -> Result<String> {
        let statuses = int_array(value, "headers.response.require.status_code")?;
        if statuses.is_empty() {
            return Ok("(0)".to_string());
        }
        let id = self.next_id();
        self.response_line(&format!("zs_s64 res_status_{id} = zs_res_status();"));
        let mut checks = Vec::new();
        for status in statuses {
            if (1..100).contains(&status) {
                let lower = status.saturating_mul(100);
                let upper = status.saturating_add(1).saturating_mul(100);
                checks.push(format!(
                    "(res_status_{id} == {status} || (res_status_{id} >= {lower} && res_status_{id} < {upper}))"
                ));
            } else {
                checks.push(format!("(res_status_{id} == {status})"));
            }
        }
        Ok(format!("({})", checks.join(" || ")))
    }

    fn emit_response_header_match(&mut self, value: &Value) -> Result<String> {
        let obj = value
            .as_object()
            .ok_or_else(|| anyhow!("headers.response.require.headers must be an object"))?;
        if obj.is_empty() {
            return Ok("1".to_string());
        }
        let mut checks = Vec::new();
        for (name, values) in obj {
            if values.is_null() {
                checks.push(format!(
                    "(zs_caddy_res_header_present({}, {}) == 0)",
                    c_str(name),
                    name.len()
                ));
            } else if values.as_array().is_some_and(|a| a.is_empty()) {
                checks.push(format!(
                    "(zs_caddy_res_header_present({}, {}) != 0)",
                    c_str(name),
                    name.len()
                ));
            } else {
                checks.push(self.emit_response_header_list_match(name, values)?);
            }
        }
        Ok(format!("({})", checks.join(" && ")))
    }

    fn emit_response_header_list_match(&mut self, name: &str, values: &Value) -> Result<String> {
        let values = strict_string_array(values, "headers.response.require header value")?;
        let mut checks = Vec::new();
        for value in values {
            checks.push(format!(
                "(zs_caddy_res_header_match({}, {}, {}, {}) != 0)",
                c_str(name),
                name.len(),
                c_str(&value),
                value.len()
            ));
        }
        Ok(format!("({})", checks.join(" || ")))
    }

    fn emit_header_ops(&mut self, value: &Value, target: HeaderTarget) -> Result<()> {
        let obj = value
            .as_object()
            .ok_or_else(|| anyhow!("header operations must be an object"))?;
        let deletes = if let Some(delete) = obj.get("delete") {
            string_array(delete, "headers.delete")?
        } else {
            Vec::new()
        };
        for name in &deletes {
            if name == "*" || contains_placeholder(name) {
                self.emit_delete_header_if_star(target, name, PlaceholderExpansion::Known)?;
            }
        }
        if let Some(add) = obj.get("add") {
            let add = add
                .as_object()
                .ok_or_else(|| anyhow!("headers.add must be an object"))?;
            for (name, values) in add {
                for value in string_array(values, "headers.add value")? {
                    self.emit_append_header(target, name, &value, PlaceholderExpansion::Known)?;
                }
            }
        }
        if let Some(set) = obj.get("set") {
            let set = set
                .as_object()
                .ok_or_else(|| anyhow!("headers.set must be an object"))?;
            for (name, values) in set {
                let joined = string_array(values, "headers.set value")?.join(",");
                self.emit_set_header(target, name, &joined, PlaceholderExpansion::Known)?;
            }
        }
        for name in &deletes {
            if contains_placeholder(name) {
                self.emit_delete_header_unless_star(target, name, PlaceholderExpansion::Known)?;
            } else if name != "*" {
                self.emit_delete_header(target, name, PlaceholderExpansion::Known)?;
            }
        }
        if let Some(replace) = obj.get("replace") {
            let replace = replace
                .as_object()
                .ok_or_else(|| anyhow!("headers.replace must be an object"))?;
            for (name, replacements) in replace {
                let replacements = replacements
                    .as_array()
                    .ok_or_else(|| anyhow!("headers.replace values must be arrays"))?;
                for replacement in replacements {
                    self.emit_replace_header(target, name, replacement)?;
                }
            }
        }
        Ok(())
    }

    fn emit_set_header(
        &mut self,
        target: HeaderTarget,
        name: &str,
        value: &str,
        expansion: PlaceholderExpansion,
    ) -> Result<()> {
        self.begin_header_op_scope(target);
        let name = self.emit_maybe_expanded(target, "header_name", name, expansion)?;
        let value = self.emit_maybe_expanded(target, "header_value", value, expansion)?;
        match target {
            HeaderTarget::Request => self.request_header_line(&format!(
                "zs_req_set_header({}, {}, {}, {});",
                name.ptr, name.len, value.ptr, value.len
            )),
            HeaderTarget::Response => {
                bail!("response header set operations must use Caddy ops JSON")
            }
        }
        self.end_header_op_scope(target);
        Ok(())
    }

    fn emit_append_header(
        &mut self,
        target: HeaderTarget,
        name: &str,
        value: &str,
        expansion: PlaceholderExpansion,
    ) -> Result<()> {
        self.begin_header_op_scope(target);
        let name = self.emit_maybe_expanded(target, "header_name", name, expansion)?;
        let value = self.emit_maybe_expanded(target, "header_value", value, expansion)?;
        match target {
            HeaderTarget::Request => self.request_header_line(&format!(
                "zs_req_append_header({}, {}, {}, {});",
                name.ptr, name.len, value.ptr, value.len
            )),
            HeaderTarget::Response => {
                bail!("response header add operations must use Caddy ops JSON")
            }
        }
        self.end_header_op_scope(target);
        Ok(())
    }

    fn emit_delete_header(
        &mut self,
        target: HeaderTarget,
        pattern: &str,
        expansion: PlaceholderExpansion,
    ) -> Result<()> {
        self.begin_header_op_scope(target);
        let pattern = self.emit_maybe_expanded(target, "header_pattern", pattern, expansion)?;
        match target {
            HeaderTarget::Request => self.request_header_line(&format!(
                "zs_req_delete_header({}, {});",
                pattern.ptr, pattern.len
            )),
            HeaderTarget::Response => {
                bail!("response header delete operations must use Caddy ops JSON")
            }
        }
        self.end_header_op_scope(target);
        Ok(())
    }

    fn emit_delete_header_if_star(
        &mut self,
        target: HeaderTarget,
        pattern: &str,
        expansion: PlaceholderExpansion,
    ) -> Result<()> {
        self.emit_conditional_delete_header(target, pattern, expansion, true)
    }

    fn emit_delete_header_unless_star(
        &mut self,
        target: HeaderTarget,
        pattern: &str,
        expansion: PlaceholderExpansion,
    ) -> Result<()> {
        self.emit_conditional_delete_header(target, pattern, expansion, false)
    }

    fn emit_conditional_delete_header(
        &mut self,
        target: HeaderTarget,
        pattern: &str,
        expansion: PlaceholderExpansion,
        only_star: bool,
    ) -> Result<()> {
        self.begin_header_op_scope(target);
        let pattern = self.emit_maybe_expanded(target, "header_pattern", pattern, expansion)?;
        let condition = format!(
            "{}zs_caddy_eq({}, {}, \"*\", 1)",
            if only_star { "" } else { "!" },
            pattern.ptr,
            pattern.len
        );
        match target {
            HeaderTarget::Request => {
                self.request_header_line(&format!("if ({condition}) {{"));
                if self.current_response_hook.is_none() {
                    self.indent += 1;
                }
                self.request_header_line(&format!(
                    "zs_req_delete_header({}, {});",
                    pattern.ptr, pattern.len
                ));
                if self.current_response_hook.is_none() {
                    self.indent -= 1;
                }
                self.request_header_line("}");
            }
            HeaderTarget::Response => {
                bail!("response header delete operations must use Caddy ops JSON")
            }
        }
        self.end_header_op_scope(target);
        Ok(())
    }

    fn begin_header_op_scope(&mut self, target: HeaderTarget) {
        match target {
            HeaderTarget::Request => {
                self.request_header_line("{");
                if self.current_response_hook.is_none() {
                    self.indent += 1;
                }
            }
            HeaderTarget::Response => {
                self.response_line("{");
            }
        }
    }

    fn end_header_op_scope(&mut self, target: HeaderTarget) {
        match target {
            HeaderTarget::Request => {
                if self.current_response_hook.is_none() {
                    self.indent -= 1;
                }
                self.request_header_line("}");
            }
            HeaderTarget::Response => {
                self.response_line("}");
            }
        }
    }

    fn emit_maybe_expanded(
        &mut self,
        target: HeaderTarget,
        label: &str,
        value: &str,
        expansion: PlaceholderExpansion,
    ) -> Result<CArg> {
        if !contains_placeholder(value) {
            return Ok(CArg {
                ptr: c_str(value),
                len: value.len().to_string(),
            });
        }
        let id = self.next_id();
        let buffer = format!("{label}_{id}");
        let raw = format!("{label}_{id}_raw");
        let len = format!("{label}_{id}_len");
        let emit = format!("char {buffer}[512];");
        let helper = match expansion {
            PlaceholderExpansion::Known => "zs_caddy_expand_known",
        };
        let call = format!(
            "zs_s64 {raw} = {helper}({}, {}, {buffer}, sizeof({buffer}));",
            c_str(value),
            value.len()
        );
        let clamp = format!("zs_u64 {len} = zs_caddy_clamp_len({raw}, sizeof({buffer}));");
        match target {
            HeaderTarget::Request => {
                self.request_header_line(&emit);
                self.request_header_line(&call);
                self.request_header_line(&clamp);
            }
            HeaderTarget::Response => {
                self.response_line(&emit);
                self.response_line(&call);
                self.response_line(&clamp);
            }
        }
        Ok(CArg { ptr: buffer, len })
    }

    fn emit_replace_header(
        &mut self,
        target: HeaderTarget,
        name: &str,
        replacement: &Value,
    ) -> Result<()> {
        let replacement = replacement
            .as_object()
            .ok_or_else(|| anyhow!("headers.replace entries must be objects"))?;
        let search = replacement
            .get("search")
            .and_then(Value::as_str)
            .unwrap_or("");
        let replace = replacement
            .get("replace")
            .and_then(Value::as_str)
            .unwrap_or("");
        let search_regexp = replacement
            .get("search_regexp")
            .and_then(Value::as_str)
            .unwrap_or("");
        if replacement
            .get("search")
            .and_then(Value::as_str)
            .is_some_and(|value| !value.is_empty())
            && replacement
                .get("search_regexp")
                .and_then(Value::as_str)
                .is_some_and(|value| !value.is_empty())
        {
            bail!("headers.replace cannot specify both search and search_regexp");
        }
        if !search_regexp.is_empty() && !contains_caddy_placeholder(search_regexp) {
            caddy_regex(search_regexp).context("invalid headers.replace.search_regexp")?;
        }
        let mut op = Map::new();
        op.insert("name".to_string(), Value::String(name.to_string()));
        op.insert("search".to_string(), Value::String(search.to_string()));
        op.insert(
            "search_regexp".to_string(),
            Value::String(search_regexp.to_string()),
        );
        op.insert("replace".to_string(), Value::String(replace.to_string()));
        let op = serde_json::to_string(&Value::Object(op))?;
        match target {
            HeaderTarget::Request => self.request_header_line(&format!(
                "zs_req_replace_header({}, {});",
                c_str(&op),
                op.len()
            )),
            HeaderTarget::Response => self.response_line(&format!(
                "zs_res_replace_header({}, {});",
                c_str(&op),
                op.len()
            )),
        }
        Ok(())
    }

    fn emit_rewrite(&mut self, handler: &Handler) -> Result<bool> {
        validate_rewrite_fields(&handler.config)?;
        if let Some(method) = handler.config.get("method").and_then(Value::as_str) {
            if contains_placeholder(method) {
                self.line(&format!(
                    "zs_caddy_rewrite_method({}, {});",
                    c_str(method),
                    method.len()
                ));
            } else {
                let method = method.to_ascii_uppercase();
                self.line(&format!(
                    "zs_req_set_method({}, {});",
                    c_str(&method),
                    method.len()
                ));
            }
        }
        if let Some(uri) = handler.config.get("uri").and_then(Value::as_str) {
            if contains_placeholder(uri) || uri.contains('?') || uri.contains('#') {
                self.line(&format!(
                    "zs_caddy_rewrite_uri({}, {});",
                    c_str(uri),
                    uri.len()
                ));
            } else {
                self.line(&format!(
                    "zs_caddy_set_path_preserve_query({}, {});",
                    c_str(uri),
                    uri.len()
                ));
            }
        }
        if handler.config.contains_key("strip_path_prefix")
            || handler.config.contains_key("strip_path_suffix")
            || handler.config.contains_key("uri_substring")
            || handler.config.contains_key("path_regexp")
        {
            let op = self.rewrite_uri_ops(handler)?;
            let op = serde_json::to_string(&Value::Object(op))?;
            self.line(&format!(
                "zs_req_rewrite_uri({}, {});",
                c_str(&op),
                op.len()
            ));
        }
        if let Some(query) = handler.config.get("query") {
            validate_rewrite_query(query)?;
            let query = normalize_rewrite_query(query)?;
            let query = serde_json::to_string(&query)?;
            self.line(&format!(
                "zs_req_rewrite_query({}, {});",
                c_str(&query),
                query.len()
            ));
        }
        Ok(false)
    }

    fn rewrite_uri_ops(&self, handler: &Handler) -> Result<Map<String, Value>> {
        let mut op = Map::new();
        if let Some(prefix) = handler
            .config
            .get("strip_path_prefix")
            .and_then(Value::as_str)
        {
            op.insert(
                "strip_path_prefix".to_string(),
                Value::String(prefix.to_string()),
            );
        }
        if let Some(suffix) = handler
            .config
            .get("strip_path_suffix")
            .and_then(Value::as_str)
        {
            op.insert(
                "strip_path_suffix".to_string(),
                Value::String(suffix.to_string()),
            );
        }
        if let Some(values) = handler.config.get("uri_substring") {
            if !values.is_null() {
                let values = values
                    .as_array()
                    .ok_or_else(|| anyhow!("rewrite.uri_substring must be an array"))?;
                let mut emitted = Vec::new();
                for value in values {
                    let empty = Map::new();
                    let obj = if value.is_null() {
                        &empty
                    } else {
                        value.as_object().ok_or_else(|| {
                            anyhow!("rewrite.uri_substring entries must be objects")
                        })?
                    };
                    validate_object_fields(
                        obj,
                        &["find", "replace", "limit"],
                        "rewrite.uri_substring",
                    )?;
                    let find = obj
                        .get("find")
                        .filter(|value| !value.is_null())
                        .and_then(Value::as_str)
                        .unwrap_or("");
                    let replace = obj
                        .get("replace")
                        .filter(|value| !value.is_null())
                        .and_then(Value::as_str)
                        .unwrap_or("");
                    let limit = obj
                        .get("limit")
                        .filter(|value| !value.is_null())
                        .and_then(Value::as_i64)
                        .unwrap_or(0);
                    let mut item = Map::new();
                    item.insert("find".to_string(), Value::String(find.to_string()));
                    item.insert("replace".to_string(), Value::String(replace.to_string()));
                    item.insert(
                        "limit".to_string(),
                        Value::Number(serde_json::Number::from(limit)),
                    );
                    emitted.push(Value::Object(item));
                }
                op.insert("uri_substring".to_string(), Value::Array(emitted));
            }
        }
        if let Some(values) = handler.config.get("path_regexp") {
            if !values.is_null() {
                let values = values
                    .as_array()
                    .ok_or_else(|| anyhow!("rewrite.path_regexp must be an array"))?;
                let mut emitted = Vec::new();
                for value in values {
                    let obj = value
                        .as_object()
                        .ok_or_else(|| anyhow!("rewrite.path_regexp entries must be objects"))?;
                    validate_object_fields(obj, &["find", "replace"], "rewrite.path_regexp")?;
                    let find = obj
                        .get("find")
                        .filter(|value| !value.is_null())
                        .and_then(Value::as_str)
                        .unwrap_or("");
                    let replace = obj
                        .get("replace")
                        .filter(|value| !value.is_null())
                        .and_then(Value::as_str)
                        .unwrap_or("");
                    if find.is_empty() {
                        bail!("rewrite.path_regexp.find cannot be empty");
                    }
                    caddy_regex(find).context("invalid rewrite.path_regexp.find")?;
                    let mut item = Map::new();
                    item.insert("find".to_string(), Value::String(find.to_string()));
                    item.insert("replace".to_string(), Value::String(replace.to_string()));
                    emitted.push(Value::Object(item));
                }
                op.insert("path_regexp".to_string(), Value::Array(emitted));
            }
        }
        Ok(op)
    }

    fn emit_reverse_proxy(&mut self, handler: &Handler) -> Result<bool> {
        validate_reverse_proxy_fields(&handler.config, &mut self.ignored_warnings)?;
        let proxy_id = self.next_id();
        let skip_key = format!("zs.caddy.reverse_proxy.skip.{proxy_id}");
        self.line("{");
        self.indent += 1;
        self.line(&format!("char reverse_proxy_skip_{proxy_id}[2];"));
        self.line(&format!(
            "zs_s64 reverse_proxy_skip_{proxy_id}_raw = zs_meta_get({}, {}, reverse_proxy_skip_{proxy_id}, sizeof(reverse_proxy_skip_{proxy_id}));",
            c_str(&skip_key),
            skip_key.len()
        ));
        self.line(&format!(
            "if (reverse_proxy_skip_{proxy_id}_raw > 0 && zs_caddy_eq(reverse_proxy_skip_{proxy_id}, zs_caddy_clamp_len(reverse_proxy_skip_{proxy_id}_raw, sizeof(reverse_proxy_skip_{proxy_id})), \"1\", 1)) {{"
        ));
        self.indent += 1;
        self.line(&format!(
            "zs_meta_set({}, {}, ZS_STR(\"0\"));",
            c_str(&skip_key),
            skip_key.len()
        ));
        self.indent -= 1;
        self.line("} else {");
        self.indent += 1;
        let upstreams = handler
            .config
            .get("upstreams")
            .and_then(Value::as_array)
            .ok_or_else(|| anyhow!("reverse_proxy requires upstreams"))?;
        if upstreams.len() != 1 {
            bail!(
                "reverse_proxy with multiple upstreams needs load balancing not exposed by zeroserve"
            );
        }
        let dial = upstreams[0]
            .get("dial")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("reverse_proxy upstream missing dial"))?;
        let url = upstream_to_url(dial, handler.config.get("transport"))?;
        let headers = handler
            .config
            .get("headers")
            .filter(|value| !value.is_null());
        let handle_response = handler
            .config
            .get("handle_response")
            .filter(|value| !value.is_null());
        let transport_host_default = reverse_proxy_transport_sets_host(&url);
        if let Some(rewrite) = handler
            .config
            .get("rewrite")
            .filter(|value| !value.is_null())
        {
            self.emit_reverse_proxy_rewrite(rewrite)?;
        }
        let prepared_url = if contains_placeholder(&url)
            || headers.is_some()
            || handle_response.is_some()
            || transport_host_default
            || !self.response_hooks.is_empty()
        {
            let id = self.next_id();
            self.line("{");
            self.indent += 1;
            self.line(&format!("char reverse_proxy_url_{id}[512];"));
            self.line(&format!(
                "zs_s64 reverse_proxy_url_{id}_raw = zs_caddy_reverse_proxy_url({}, {}, reverse_proxy_url_{id}, sizeof(reverse_proxy_url_{id}));",
                c_str(&url),
                url.len()
            ));
            self.line(&format!(
                "zs_u64 reverse_proxy_url_{id}_len = zs_caddy_clamp_len(reverse_proxy_url_{id}_raw, sizeof(reverse_proxy_url_{id}));"
            ));
            self.line(&format!("if (reverse_proxy_url_{id}_raw <= 0) {{"));
            self.indent += 1;
            self.line("zs_respond(502, ZS_STR(\"Bad Gateway\"));");
            self.line("return 0;");
            self.indent -= 1;
            self.line("}");
            Some((
                format!("reverse_proxy_url_{id}"),
                format!("reverse_proxy_url_{id}_len"),
            ))
        } else {
            None
        };
        if let Some(handle_response) = handle_response {
            self.emit_reverse_proxy_handle_response(handle_response, &skip_key)?;
        }
        self.line("zs_meta_set(ZS_STR(\"zs.caddy.reverse_proxy\"), ZS_STR(\"1\"));");
        if reverse_proxy_transport_compression_off(handler.config.get("transport")) {
            self.line(
                "zs_meta_set(ZS_STR(\"zs.caddy.reverse_proxy.compression\"), ZS_STR(\"off\"));",
            );
        }
        self.emit_caddy_forwarded_headers(handler.config.get("trusted_proxies"))?;
        if transport_host_default {
            self.emit_reverse_proxy_transport_host_header()?;
        }
        if let Some(headers) = headers {
            self.emit_reverse_proxy_headers(headers)?;
        }
        if let Some((ptr, len)) = prepared_url {
            self.line(&format!("zs_reverse_proxy({ptr}, {len});"));
            self.line("return 0;");
            self.indent -= 1;
            self.line("}");
        } else {
            self.line(&format!(
                "zs_reverse_proxy({}, {});",
                c_str(&url),
                url.len()
            ));
            self.line("return 0;");
        }
        self.indent -= 1;
        self.line("}");
        self.indent -= 1;
        self.line("}");
        Ok(handle_response.is_none())
    }

    fn emit_reverse_proxy_rewrite(&mut self, value: &Value) -> Result<()> {
        let config = value
            .as_object()
            .ok_or_else(|| anyhow!("reverse_proxy.rewrite must be an object"))?;
        let rewrite = Handler {
            handler: "rewrite".to_string(),
            config: config.clone(),
        };
        if let Some(query) = rewrite.config.get("query") {
            validate_rewrite_query(query)?;
        }
        self.rewrite_uri_ops(&rewrite)?;
        let config = serde_json::to_string(value)?;
        self.line(&format!(
            "zs_caddy_reverse_proxy_rewrite({}, {});",
            c_str(&config),
            config.len()
        ));
        Ok(())
    }

    fn emit_reverse_proxy_headers(&mut self, value: &Value) -> Result<()> {
        let config = value
            .as_object()
            .ok_or_else(|| anyhow!("reverse_proxy.headers must be an object"))?;
        let headers_handler = Handler {
            handler: "headers".to_string(),
            config: config.clone(),
        };
        validate_headers_handler(&headers_handler)?;
        if let Some(request) = config.get("request") {
            let request = normalize_header_ops(request, HeaderTarget::Request)?;
            let request = serde_json::to_string(&request)?;
            self.line(&format!(
                "zs_caddy_reverse_proxy_request_headers({}, {});",
                c_str(&request),
                request.len()
            ));
        }
        let Some(response) = config.get("response") else {
            return Ok(());
        };
        let response = normalize_header_ops(response, HeaderTarget::Response)?;
        let obj = response
            .as_object()
            .ok_or_else(|| anyhow!("headers.response must be an object"))?;
        let hook = self.begin_response_hook();
        let require = if let Some(require) = obj.get("require") {
            Some(self.emit_response_require(require)?)
        } else {
            None
        };
        if let Some(require) = &require {
            self.response_line(&format!("if ({require}) {{"));
        }
        self.emit_caddy_response_header_ops(&response)?;
        if require.is_some() {
            self.response_line("}");
        }
        self.end_response_hook(hook);
        Ok(())
    }

    fn emit_reverse_proxy_transport_host_header(&mut self) -> Result<()> {
        let mut set = Map::new();
        set.insert(
            "Host".to_string(),
            Value::Array(vec![Value::String(
                "{http.reverse_proxy.upstream.hostport}".to_string(),
            )]),
        );
        let mut ops = Map::new();
        ops.insert("set".to_string(), Value::Object(set));
        let ops = serde_json::to_string(&Value::Object(ops))?;
        self.line(&format!(
            "zs_caddy_reverse_proxy_request_headers({}, {});",
            c_str(&ops),
            ops.len()
        ));
        Ok(())
    }

    fn emit_reverse_proxy_handle_response(&mut self, value: &Value, skip_key: &str) -> Result<()> {
        self.emit_status_handle_response(value, "reverse_proxy", Some(skip_key))
    }

    fn emit_intercept(&mut self, handler: &Handler) -> Result<bool> {
        for key in handler.config.keys() {
            if key != "handle_response" {
                bail!("unsupported intercept field {key:?}");
            }
        }
        let Some(handle_response) = handler
            .config
            .get("handle_response")
            .filter(|value| !value.is_null())
        else {
            return Ok(false);
        };
        self.emit_status_handle_response(handle_response, "intercept", None)?;
        Ok(false)
    }

    fn emit_status_handle_response(
        &mut self,
        value: &Value,
        label: &str,
        continue_skip_key: Option<&str>,
    ) -> Result<()> {
        let handlers = value
            .as_array()
            .ok_or_else(|| anyhow!("{label}.handle_response must be an array"))?;
        if handlers.is_empty() {
            return Ok(());
        }
        let hook = self.begin_response_hook();
        let done = format!("{}_status_done_{}", label, self.next_id());
        self.response_line(&format!("int {done} = 0;"));
        for handler in handlers {
            let obj = handler
                .as_object()
                .ok_or_else(|| anyhow!("{label}.handle_response entries must be objects"))?;
            for key in obj.keys() {
                if key != "match" && key != "status_code" && key != "routes" {
                    bail!("unsupported {label}.handle_response field {key:?}");
                }
            }
            let status = obj
                .get("status_code")
                .and_then(weak_string)
                .filter(|status| !status.is_empty());
            if let Some(status) = &status {
                self.validate_response_status_template(status, label)?;
            }
            let require = if let Some(matcher) = obj.get("match") {
                self.emit_response_require(matcher)?
            } else {
                "1".to_string()
            };
            self.response_line(&format!("if (!{done} && {require}) {{"));
            if let Some(status) = &status {
                if label == "intercept" {
                    let routes = obj.get("routes");
                    let status_is_literal_zero = is_decimal_status_literal(status)
                        && status.parse::<u16>().is_ok_and(|status| status == 0);
                    let routes_may_run = routes.is_some()
                        && (!is_decimal_status_literal(status) || status_is_literal_zero);
                    if routes_may_run {
                        if !status_is_literal_zero {
                            let warning =
                                "intercept.handle_response.status_code only runs routes when it expands to 0; nonzero status replacement is ignored to match Caddy"
                                    .to_string();
                            if !self.ignored_warnings.contains(&warning) {
                                self.ignored_warnings.push(warning);
                            }
                        }
                        let status_var = format!("intercept_status_{}", self.next_id());
                        self.response_line(&format!(
                            "  zs_s64 {status_var} = zs_caddy_response_status_value({}, {});",
                            c_str(status),
                            status.len()
                        ));
                        self.response_line(&format!("  if ({status_var} == 0) {{"));
                        if let Some(routes) = routes {
                            self.emit_handle_response_routes(routes, label)?;
                        }
                        self.response_line("  } else {");
                        self.response_line(
                            "    /* Caddy intercept replace_status is a nonzero no-op. */",
                        );
                        self.response_line("  }");
                    } else {
                        if !status_is_literal_zero {
                            let warning =
                                "ignoring intercept.handle_response.status_code: Caddy intercept replace_status is a nonzero no-op"
                                    .to_string();
                            if !self.ignored_warnings.contains(&warning) {
                                self.ignored_warnings.push(warning);
                            }
                        }
                        self.response_line(
                            "  /* Caddy intercept replace_status is a nonzero no-op. */",
                        );
                    }
                } else {
                    self.response_line(&format!(
                        "  zs_caddy_set_response_status({}, {});",
                        c_str(status),
                        status.len()
                    ));
                }
            } else if let Some(routes) = obj.get("routes") {
                let routes = route_vec_from_value(routes, "invalid handle_response routes")?;
                let replaces_body =
                    !routes.is_empty() && self.response_routes_replace_body(&routes)?;
                if continue_skip_key.is_some() && replaces_body {
                    bail!(
                        "{label}.handle_response routes replace response bodies and are not supported by generated Caddy middleware"
                    );
                }
                if continue_skip_key.is_some()
                    && !self.response_routes_are_request_continuation_only(&routes)?
                {
                    bail!(
                        "{label}.handle_response routes suppress upstream response bodies and are not supported by generated Caddy middleware"
                    );
                }
                self.emit_response_routes(&routes, label, None)?;
                if let Some(skip_key) = continue_skip_key {
                    let original_uri = "{http.request.orig_uri}";
                    self.response_line(&format!(
                        "  zs_caddy_rewrite_uri({}, {});",
                        c_str(original_uri),
                        original_uri.len()
                    ));
                    self.response_line(&format!(
                        "  zs_meta_set({}, {}, ZS_STR(\"1\"));",
                        c_str(skip_key),
                        skip_key.len()
                    ));
                    self.response_line("  zs_res_continue_request();");
                }
            } else if let Some(skip_key) = continue_skip_key {
                let original_uri = "{http.request.orig_uri}";
                self.response_line(&format!(
                    "  zs_caddy_rewrite_uri({}, {});",
                    c_str(original_uri),
                    original_uri.len()
                ));
                self.response_line(&format!(
                    "  zs_meta_set({}, {}, ZS_STR(\"1\"));",
                    c_str(skip_key),
                    skip_key.len()
                ));
                self.response_line("  zs_res_continue_request();");
            } else {
                bail!("{label}.handle_response without status_code requires routes");
            }
            self.response_line(&format!("  {done} = 1;"));
            self.response_line("}");
        }
        self.end_response_hook(hook);
        Ok(())
    }

    fn emit_handle_response_routes(&mut self, value: &Value, label: &str) -> Result<()> {
        let routes = route_vec_from_value(value, "invalid handle_response routes")?;
        self.emit_response_routes(&routes, label, None)
    }

    /// Whether any handler in these handle_response routes would replace the
    /// proxied response body (rather than just adjust headers/status or the
    /// request). These are the handlers `emit_response_routes` itself rejects;
    /// detecting them up front lets supported header-only/status hooks through
    /// while still rejecting body-replacing routes.
    fn response_routes_replace_body(&self, routes: &[Route]) -> Result<bool> {
        self.response_routes_replace_body_inner(routes, &mut HashSet::new())
    }

    fn response_routes_replace_body_inner(
        &self,
        routes: &[Route],
        visited_invokes: &mut HashSet<String>,
    ) -> Result<bool> {
        for route in routes {
            for handler in &route.handlers {
                match handler.handler.as_str() {
                    "copy_response" | "static_response" | "error" | "file_server" => {
                        return Ok(true);
                    }
                    "subroute" => {
                        if let Some(routes) = handler.config.get("routes") {
                            if !routes.is_null() {
                                let routes: Vec<Route> = serde_json::from_value(routes.clone())
                                    .context("invalid handle_response subroute")?;
                                if self
                                    .response_routes_replace_body_inner(&routes, visited_invokes)?
                                {
                                    return Ok(true);
                                }
                            }
                        }
                    }
                    "invoke" => {
                        let name = handler
                            .config
                            .get("name")
                            .and_then(Value::as_str)
                            .unwrap_or("");
                        if visited_invokes.insert(name.to_string()) {
                            if let Some(route) = self.named_routes.get(name) {
                                let replaces = self.response_routes_replace_body_inner(
                                    std::slice::from_ref(route),
                                    visited_invokes,
                                )?;
                                visited_invokes.remove(name);
                                if replaces {
                                    return Ok(true);
                                }
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
        Ok(false)
    }

    /// Whether these reverse_proxy handle_response routes only mutate request
    /// state before continuing the outer route, as Caddy's forward_auth shortcut
    /// does. Response-header/copy/status-only response routes in this position
    /// still suppress the upstream response body in Caddy, which zeroserve
    /// intentionally does not reproduce.
    fn response_routes_are_request_continuation_only(&self, routes: &[Route]) -> Result<bool> {
        self.response_routes_are_request_continuation_only_inner(routes, &mut HashSet::new())
    }

    fn response_routes_are_request_continuation_only_inner(
        &self,
        routes: &[Route],
        visited_invokes: &mut HashSet<String>,
    ) -> Result<bool> {
        for route in routes {
            for handler in &route.handlers {
                match handler.handler.as_str() {
                    "headers" => {
                        if handler
                            .config
                            .get("response")
                            .is_some_and(|value| !value.is_null())
                        {
                            return Ok(false);
                        }
                    }
                    "copy_response_headers" => {
                        validate_copy_response_headers_handler(handler)?;
                        return Ok(false);
                    }
                    "vars" | "map" | "log_append" | "tracing" => {}
                    "subroute" => {
                        if let Some(routes) = handler.config.get("routes") {
                            if !routes.is_null() {
                                let routes: Vec<Route> = serde_json::from_value(routes.clone())
                                    .context("invalid handle_response subroute")?;
                                if !self.response_routes_are_request_continuation_only_inner(
                                    &routes,
                                    visited_invokes,
                                )? {
                                    return Ok(false);
                                }
                            }
                        }
                    }
                    "invoke" => {
                        let name = handler
                            .config
                            .get("name")
                            .and_then(Value::as_str)
                            .unwrap_or("");
                        if visited_invokes.insert(name.to_string()) {
                            let continuation_only = if let Some(route) = self.named_routes.get(name)
                            {
                                self.response_routes_are_request_continuation_only_inner(
                                    std::slice::from_ref(route),
                                    visited_invokes,
                                )?
                            } else {
                                true
                            };
                            visited_invokes.remove(name);
                            if !continuation_only {
                                return Ok(false);
                            }
                        }
                    }
                    _ => return Ok(false),
                }
            }
        }
        Ok(true)
    }

    fn emit_response_routes(
        &mut self,
        routes: &[Route],
        label: &str,
        stop_var: Option<&str>,
    ) -> Result<()> {
        let done = format!("{}_route_done_{}", label, self.next_id());
        self.response_line(&format!("int {done} = 0;"));
        for (idx, route) in routes.iter().enumerate() {
            validate_route_fields(route, &format!("{label}.handle_response route {idx}"))?;
            let matched = self.emit_route_match(route)?;
            self.response_line(&format!("if (!{done} && {matched}) {{"));
            let grouped = self.emit_response_route_group_guard(route, label)?;
            let route_stop = format!("{}_route_stop_{}", label, self.next_id());
            self.response_line(&format!("int {route_stop} = 0;"));
            self.emit_response_route_handlers(&route.handlers, label, &route_stop)?;
            self.response_line(&format!("if ({route_stop}) {{"));
            self.response_line(&format!("  {done} = 1;"));
            if let Some(stop_var) = stop_var {
                self.response_line(&format!("  {stop_var} = 1;"));
            }
            self.response_line("}");
            if route.terminal {
                self.response_line(&format!("  {done} = 1;"));
                if let Some(stop_var) = stop_var {
                    self.response_line(&format!("  {stop_var} = 1;"));
                }
            }
            if grouped {
                self.response_line("}");
            }
            self.response_line("}");
        }
        Ok(())
    }

    fn emit_response_route_group_guard(&mut self, route: &Route, label: &str) -> Result<bool> {
        let Some(group_id) = self.route_group_id(route)? else {
            return Ok(false);
        };
        let key = caddy_route_group_meta_key(group_id);
        let id = self.next_id();
        self.response_line(&format!("char response_route_group_{id}[2];"));
        self.response_line(&format!(
            "zs_s64 response_route_group_{id}_raw = zs_meta_get({}, {}, response_route_group_{id}, sizeof(response_route_group_{id}));",
            c_str(&key),
            key.len()
        ));
        self.response_line(&format!("if (response_route_group_{id}_raw > 0) {{"));
        self.response_line(&format!(
            "  /* Caddy {label}.handle_response group already satisfied; skip this route. */"
        ));
        self.response_line("} else {");
        self.response_line(&format!(
            "  zs_meta_set({}, {}, ZS_STR(\"1\"));",
            c_str(&key),
            key.len()
        ));
        Ok(true)
    }

    fn emit_response_route_handlers(
        &mut self,
        handlers: &[Handler],
        label: &str,
        stop_var: &str,
    ) -> Result<()> {
        for handler in handlers {
            self.response_line(&format!("if (!{stop_var}) {{"));
            match handler.handler.as_str() {
                "headers" => self.emit_response_route_headers(handler, label)?,
                "copy_response_headers" => {
                    if label != "reverse_proxy" {
                        bail!(
                            "copy_response_headers is only meaningful inside reverse_proxy handle_response routes"
                        );
                    }
                    self.emit_copy_response_headers(handler)?;
                }
                "vars" => {
                    self.emit_vars(handler)?;
                }
                "map" => {
                    self.emit_map(handler)?;
                }
                "subroute" => {
                    self.emit_response_subroute(handler, label, stop_var)?;
                }
                "invoke" => {
                    self.emit_response_invoke(handler, label, stop_var)?;
                }
                "log_append" => {
                    self.emit_ignored_observability_handler(
                        handler,
                        &["key", "value", "early"],
                        "log_append",
                        "access-log field append",
                    )?;
                }
                "tracing" => {
                    self.emit_ignored_observability_handler(
                        handler,
                        &["span", "span_attributes"],
                        "tracing",
                        "OpenTelemetry tracing",
                    )?;
                }
                "copy_response" | "static_response" | "error" | "file_server" => bail!(
                    "{label}.handle_response routes rewrite response bodies and are not supported by generated Caddy middleware"
                ),
                other => bail!("unsupported {label}.handle_response route handler {other:?}"),
            }
            self.response_line("}");
        }
        Ok(())
    }

    fn emit_response_subroute(
        &mut self,
        handler: &Handler,
        label: &str,
        stop_var: &str,
    ) -> Result<()> {
        validate_object_fields(
            &handler.config,
            &["routes", "errors"],
            &format!("{label}.handle_response subroute"),
        )?;
        if handler
            .config
            .get("errors")
            .is_some_and(|value| !value.is_null())
        {
            bail!(
                "{label}.handle_response subroute errors cannot be represented during response processing"
            );
        }
        let routes = match handler.config.get("routes") {
            Some(value) if value.is_null() => Vec::new(),
            Some(value) => {
                serde_json::from_value(value.clone()).context("invalid handle_response subroute")?
            }
            None => Vec::new(),
        };
        self.emit_response_routes(&routes, label, Some(stop_var))
    }

    fn emit_response_invoke(
        &mut self,
        handler: &Handler,
        label: &str,
        stop_var: &str,
    ) -> Result<()> {
        validate_object_fields(&handler.config, &["name"], "invoke")?;
        let name = handler
            .config
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or("");
        let route = self
            .named_routes
            .get(name)
            .cloned()
            .ok_or_else(|| missing_named_route_error(name))?;
        self.response_line(&format!(
            "/* invoke named response route {} */",
            c_comment(name)
        ));
        self.emit_response_routes(std::slice::from_ref(&route), label, Some(stop_var))
    }

    fn emit_response_route_headers(&mut self, handler: &Handler, _label: &str) -> Result<()> {
        validate_headers_handler(handler)?;
        if let Some(request) = handler.config.get("request")
            && !request.is_null()
        {
            let request = normalize_header_ops(request, HeaderTarget::Request)?;
            self.emit_header_ops(&request, HeaderTarget::Request)?;
        }
        let Some(response) = handler
            .config
            .get("response")
            .filter(|value| !value.is_null())
        else {
            return Ok(());
        };
        let response = normalize_header_ops(response, HeaderTarget::Response)?;
        let obj = response
            .as_object()
            .ok_or_else(|| anyhow!("headers.response must be an object"))?;
        let require = if let Some(require) = obj.get("require") {
            Some(self.emit_response_require(require)?)
        } else {
            None
        };
        if let Some(require) = &require {
            self.response_line(&format!("if ({require}) {{"));
        }
        self.emit_caddy_response_header_ops(&response)?;
        if require.is_some() {
            self.response_line("}");
        }
        Ok(())
    }

    fn emit_copy_response_headers(&mut self, handler: &Handler) -> Result<()> {
        validate_copy_response_headers_handler(handler)?;
        let config = normalize_copy_response_headers_config(&handler.config)?;
        let config = serde_json::to_string(&config)?;
        self.response_line(&format!(
            "zs_caddy_copy_response_headers({}, {});",
            c_str(&config),
            config.len()
        ));
        Ok(())
    }

    fn validate_response_status_template(&self, status: &str, label: &str) -> Result<()> {
        if is_decimal_status_literal(status) {
            let status_value = status.parse::<u16>().with_context(|| {
                format!(
                    "{label}.handle_response.status_code must be an integer or placeholder string"
                )
            })?;
            if status_value == 103 {
                bail!(
                    "{label}.handle_response.status_code 103 Early Hints cannot be represented exactly by zeroserve responses"
                );
            }
            if status_value != 0 && !(100..=999).contains(&status_value) {
                bail!("{label}.handle_response.status_code must be 0 or 100..999");
            }
        }
        Ok(())
    }

    fn emit_caddy_forwarded_headers(&mut self, trusted_proxies: Option<&Value>) -> Result<()> {
        let trusted_proxies = reverse_proxy_trusted_proxy_ranges(trusted_proxies)?;
        let server_trusted_proxies = self
            .client_ip_config
            .as_ref()
            .map(|config| config.trusted_ranges.clone())
            .unwrap_or_default();
        let server_trusted_unix = self
            .client_ip_config
            .as_ref()
            .is_some_and(|config| config.trusted_unix);
        let mut config = Map::new();
        config.insert(
            "trusted_proxies".to_string(),
            Value::Array(trusted_proxies.into_iter().map(Value::String).collect()),
        );
        config.insert(
            "server_trusted_proxies".to_string(),
            Value::Array(
                server_trusted_proxies
                    .into_iter()
                    .map(Value::String)
                    .collect(),
            ),
        );
        config.insert(
            "server_trusted_unix".to_string(),
            Value::Bool(server_trusted_unix),
        );
        let config = serde_json::to_string(&Value::Object(config))?;
        self.line(&format!(
            "zs_caddy_reverse_proxy_forwarded({}, {});",
            c_str(&config),
            config.len()
        ));
        Ok(())
    }

    fn emit_request_body(&mut self, handler: &Handler) -> Result<bool> {
        validate_request_body_fields(&handler.config)?;
        for key in ["read_timeout", "write_timeout"] {
            if let Some(value) = handler.config.get(key).and_then(Value::as_i64)
                && value > 0
            {
                bail!("request_body.{key} cannot be represented by generated eBPF middleware");
            }
        }
        if handler
            .config
            .get("set")
            .is_some_and(|value| !value.is_null())
        {
            bail!(
                "request_body.set rewrites request bodies and is not supported by generated Caddy middleware"
            );
        }
        let Some(max_size) = handler
            .config
            .get("max_size")
            .filter(|value| !value.is_null())
        else {
            return Ok(false);
        };
        let max_size = max_size
            .as_i64()
            .ok_or_else(|| anyhow!("request_body.max_size must be an integer"))?;
        if max_size <= 0 {
            return Ok(false);
        }
        self.line(&format!("zs_req_body_limit({max_size});"));
        Ok(false)
    }

    fn emit_vars(&mut self, handler: &Handler) -> Result<bool> {
        let mut emitted = Map::new();
        for (key, value) in &handler.config {
            emitted.insert(key.clone(), value.clone());
        }
        if let Some(logger_names) = handler.config.get("access_logger_names") {
            self.emit_access_log_names(logger_names)?;
        }
        let emitted = serde_json::to_string(&Value::Object(emitted))?;
        self.code_line(&format!(
            "zs_caddy_vars_set({}, {});",
            c_str(&emitted),
            emitted.len()
        ));
        Ok(false)
    }

    fn emit_access_log_names(&mut self, value: &Value) -> Result<()> {
        if value.is_null() {
            self.emit_access_log_config();
            return Ok(());
        }
        let names = strict_string_array(value, "vars.access_logger_names")?;
        for name in names {
            if let Some(file) = self.access_log_config.files.get(&name).cloned() {
                self.emit_access_log_file(&name, &file);
                break;
            }
        }
        Ok(())
    }

    fn emit_caddy_access_log(&mut self, handler: &Handler) -> Result<bool> {
        validate_object_fields(
            &handler.config,
            &["handler", "logger_name", "file", "format"],
            "caddy_access_log",
        )?;
        let name = handler
            .config
            .get("logger_name")
            .and_then(Value::as_str)
            .unwrap_or("default");
        let file = handler
            .config
            .get("file")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("caddy_access_log.file must be a string"))?;
        self.emit_access_log_file(name, file);
        Ok(false)
    }

    fn emit_map(&mut self, handler: &Handler) -> Result<bool> {
        validate_map_handler(handler)?;
        let config = normalize_map_handler(handler)?;
        let config = serde_json::to_string(&config)?;
        let result = format!("zs_caddy_map_result_{}", self.next_id());
        self.code_line(&format!(
            "zs_s64 {result} = zs_caddy_map({}, {});",
            c_str(&config),
            config.len()
        ));
        self.code_line(&format!("if ({result} < 0) {{"));
        if self.current_response_hook.is_some() {
            self.response_line("  return input;");
        } else {
            self.line("  zs_respond(500, ZS_STR(\"Internal Server Error\"));");
            self.line("  return 0;");
        }
        self.code_line("}");
        Ok(false)
    }

    fn emit_file_server(&mut self, handler: &Handler) -> Result<bool> {
        validate_file_server_fields(&handler.config)?;
        if let Some(browse) = handler.config.get("browse") {
            validate_file_server_browse(browse)?;
        }
        if let Some(precompressed) = handler.config.get("precompressed") {
            validate_file_server_precompressed(precompressed)?;
        }
        if let Some(order) = handler.config.get("precompressed_order") {
            for encoding in header_string_array(order, "file_server.precompressed_order")? {
                validate_precompressed_order_encoding(&encoding)?;
            }
        }
        if let Some(fs) = handler.config.get("fs")
            && !fs.is_null()
        {
            let fs = fs
                .as_str()
                .ok_or_else(|| anyhow!("file_server.fs must be a string"))?;
            if !contains_placeholder(fs) && fs != "file" && fs != "default" {
                bail!(
                    "file_server.fs {fs:?} is not available in zeroserve's supported file-server surface"
                );
            }
        }
        for key in ["hide", "index_names", "etag_file_extensions"] {
            if let Some(values) = handler.config.get(key) {
                validate_header_string_array_strict(values, &format!("file_server.{key}"))?;
            }
        }

        let mut config = normalize_file_server_config(&handler.config)?;
        if let Some(status) = handler.config.get("status_code").and_then(weak_string) {
            if status.is_empty() {
                // Caddy's WeakString decodes JSON null to an empty string, which
                // these handlers treat as an omitted status override.
            } else if contains_placeholder(&status) || !is_decimal_status_literal(&status) {
                config.insert("status_code".to_string(), Value::String(status));
            } else {
                let status = status
                    .parse::<u64>()
                    .context("file_server.status_code must be an integer or integer string")?;
                if status == 103 {
                    bail!(
                        "file_server.status_code 103 Early Hints cannot be represented exactly by zeroserve responses"
                    );
                }
                if status != 0 && !(100..=999).contains(&status) {
                    bail!("file_server.status_code must be 0 or 100..999");
                }
                config.insert(
                    "status_code".to_string(),
                    Value::Number(serde_json::Number::from(status)),
                );
            }
        }
        let preflight_config = if !self.in_error_route
            && !bool_field(&handler.config, "pass_thru")
            && !self.error_routes.is_empty()
        {
            let mut preflight = config.clone();
            preflight.insert("pass_thru".to_string(), Value::Bool(true));
            Some(serde_json::to_string(&Value::Object(preflight))?)
        } else {
            None
        };
        let config = serde_json::to_string(&Value::Object(config))?;
        if bool_field(&handler.config, "pass_thru") {
            let result = format!("zs_caddy_file_server_result_{}", self.next_id());
            self.line(&format!(
                "zs_s64 {result} = zs_file_server({}, {});",
                c_str(&config),
                config.len()
            ));
            self.line(&format!("if ({result} == 0) {{"));
            self.indent += 1;
            self.line("return 0;");
            self.indent -= 1;
            self.line("}");
            self.line(&format!("else if ({result} == 2) {{"));
            self.indent += 1;
            self.emit_file_server_error_response()?;
            self.line("return 0;");
            self.indent -= 1;
            self.line("}");
            Ok(false)
        } else if let Some(preflight_config) = preflight_config {
            let result = format!("zs_caddy_file_server_result_{}", self.next_id());
            self.line(&format!(
                "zs_s64 {result} = zs_file_server({}, {});",
                c_str(&preflight_config),
                preflight_config.len()
            ));
            self.line(&format!("if ({result} == 0) {{"));
            self.indent += 1;
            self.line("return 0;");
            self.indent -= 1;
            self.line("}");
            self.line(&format!("if ({result} == 1) {{"));
            self.indent += 1;
            self.line("zs_caddy_set_error(\"404\", 3, \"\", 0);");
            self.indent -= 1;
            self.line("}");
            self.emit_file_server_error_response()?;
            self.line("return 0;");
            Ok(true)
        } else {
            let result = format!("zs_caddy_file_server_result_{}", self.next_id());
            self.line(&format!(
                "zs_s64 {result} = zs_file_server({}, {});",
                c_str(&config),
                config.len()
            ));
            self.line(&format!("if ({result} == 2) {{"));
            self.indent += 1;
            self.emit_file_server_error_response()?;
            self.indent -= 1;
            self.line("}");
            self.line("return 0;");
            Ok(true)
        }
    }

    fn emit_file_server_error_response(&mut self) -> Result<()> {
        if self.error_routes.is_empty() || self.in_error_route {
            self.line("zs_caddy_respond(\"{http.error.status_code}\", 24, \"\", 0);");
            return Ok(());
        }
        self.emit_error_routes()?;
        self.line("if (zs_response_pending() == 0) {");
        self.indent += 1;
        self.line("zs_caddy_respond(\"{http.error.status_code}\", 24, \"\", 0);");
        self.indent -= 1;
        self.line("}");
        Ok(())
    }

    fn next_id(&mut self) -> usize {
        let id = self.tmp_id;
        self.tmp_id += 1;
        id
    }

    fn warn(&mut self, warning: String) {
        if self.warnings.iter().all(|w| w != &warning) {
            self.line(&format!("/* warning: {} */", c_comment(&warning)));
            self.warnings.push(warning);
        }
    }

    fn line(&mut self, s: &str) {
        for _ in 0..self.indent {
            self.out.push_str("  ");
        }
        self.out.push_str(s);
        self.out.push('\n');
    }

    fn code_line(&mut self, s: &str) {
        if self.current_response_hook.is_some() {
            self.response_line(s);
        } else {
            self.line(s);
        }
    }

    fn request_header_line(&mut self, s: &str) {
        if self.current_response_hook.is_some() {
            self.response_line(s);
        } else {
            self.line(s);
        }
    }

    fn blank(&mut self) {
        self.out.push('\n');
    }

    fn response_line(&mut self, s: &str) {
        let hook = if let Some(hook) = self.current_response_hook {
            hook
        } else {
            let previous = self.begin_response_hook();
            let hook = self
                .current_response_hook
                .expect("begin_response_hook sets current hook");
            self.end_response_hook(previous);
            hook
        };
        self.response_hooks[hook].push(s.to_string());
    }

    fn finish_response_hook(&mut self) {
        for hook_id in 0..self.response_hooks.len() {
            self.blank();
            self.line(&format!(
                "ZS_CALL_ENTRY(caddy_response_{hook_id}, input) {{"
            ));
            self.indent += 1;
            self.line("(void)input;");
            let lines = std::mem::take(&mut self.response_hooks[hook_id]);
            for line in lines {
                self.line(&line);
            }
            self.line("return input;");
            self.indent -= 1;
            self.line("}");
        }
    }

    fn begin_response_hook(&mut self) -> Option<usize> {
        let hook_id = self.response_hooks.len();
        self.response_hooks.push(Vec::new());
        self.line(&format!(
            "zs_s64 zs_caddy_response_hook_input_{hook_id} = zs_json_new_object();"
        ));
        self.line(&format!(
            "zs_res_hook(ZS_STR(\"\"), ZS_STR(\"caddy_response_{hook_id}\"), zs_caddy_response_hook_input_{hook_id});"
        ));
        self.line(&format!(
            "zs_object_free(zs_caddy_response_hook_input_{hook_id});"
        ));
        self.current_response_hook.replace(hook_id)
    }

    fn end_response_hook(&mut self, previous: Option<usize>) {
        self.current_response_hook = previous;
    }
}

#[derive(Copy, Clone, PartialEq, Eq)]
enum HeaderTarget {
    Request,
    Response,
}

#[derive(Copy, Clone)]
enum PlaceholderExpansion {
    Known,
}

struct CArg {
    ptr: String,
    len: String,
}

fn regex_match_config(value: &Value, label: &str) -> Result<Value> {
    let obj = value
        .as_object()
        .ok_or_else(|| anyhow!("http.matchers.{label} entries must be objects"))?;
    validate_object_fields(obj, &["name", "pattern"], &format!("http.matchers.{label}"))?;
    let pattern = obj
        .get("pattern")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("http.matchers.{label} requires pattern"))?;
    caddy_regex(pattern).with_context(|| format!("invalid http.matchers.{label} pattern"))?;
    let name = obj.get("name").and_then(Value::as_str).unwrap_or("");
    if !name.is_empty() && !is_caddy_regex_name(name) {
        bail!("http.matchers.{label}.name must contain only word characters");
    }
    let mut emitted = Map::new();
    emitted.insert("pattern".to_string(), Value::String(pattern.to_string()));
    if !name.is_empty() {
        emitted.insert("name".to_string(), Value::String(name.to_string()));
    }
    Ok(Value::Object(emitted))
}

fn is_caddy_regex_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .chars()
            .any(|ch| ch == '_' || ch.is_ascii_alphanumeric())
}

fn caddy_route_group_meta_key(group_id: usize) -> String {
    format!("zs.caddy.route_group.{group_id}")
}

fn missing_named_route_error(name: &str) -> anyhow::Error {
    anyhow!("cannot invoke named route '{name}', which was not defined")
}

fn collect_route_groups(groups: &mut BTreeMap<String, usize>, route: &Route) -> Result<()> {
    if let Some(group) = &route.group {
        let next = groups.len();
        groups.entry(group.clone()).or_insert(next);
    }
    for handler in &route.handlers {
        match handler.handler.as_str() {
            "subroute" => {
                let Some(routes_value) = handler.config.get("routes") else {
                    continue;
                };
                let routes = route_vec_from_value(routes_value, "invalid subroute routes")?;
                for route in &routes {
                    collect_route_groups(groups, route)?;
                }
                let Some(errors_value) = handler
                    .config
                    .get("errors")
                    .filter(|value| !value.is_null())
                else {
                    continue;
                };
                let errors: HttpErrorConfig = serde_json::from_value(errors_value.clone())
                    .context("invalid subroute errors")?;
                for route in &errors.routes {
                    collect_route_groups(groups, route)?;
                }
            }
            "reverse_proxy" | "intercept" => {
                let Some(handle_response_value) = handler.config.get("handle_response") else {
                    continue;
                };
                if handle_response_value.is_null() {
                    continue;
                }
                let response_handlers: Vec<ResponseHandlerConfig> =
                    serde_json::from_value(handle_response_value.clone())
                        .context("invalid handle_response routes")?;
                for response_handler in &response_handlers {
                    if let Some(routes) = &response_handler.routes {
                        for route in routes {
                            collect_route_groups(groups, route)?;
                        }
                    }
                }
            }
            _ => {}
        }
    }
    Ok(())
}

fn validate_route_fields(route: &Route, label: &str) -> Result<()> {
    if let Some((key, _)) = route.extra.iter().next() {
        bail!("unsupported {label} field {key:?}");
    }
    if let Some(placeholder) = route_uses_unsupported_body_placeholder(route) {
        bail!(
            "{label} uses unsupported body placeholder {placeholder}: generated Caddy middleware does not support request/response body rewriting or body inspection"
        );
    }
    Ok(())
}

fn validate_error_routes(routes: &[Route], label: &str) -> Result<()> {
    for (idx, route) in routes.iter().enumerate() {
        validate_route_fields(route, &format!("{label} {idx}"))?;
        if route_contains_error_handler(route)? {
            bail!("{label} {idx} cannot contain nested error handlers");
        }
        if route_uses_unsupported_error_placeholder(route) {
            bail!(
                "{label} {idx} uses http.error placeholders with random IDs or stack traces that generated eBPF middleware cannot reproduce"
            );
        }
    }
    Ok(())
}

fn route_contains_error_handler(route: &Route) -> Result<bool> {
    for handler in &route.handlers {
        if handler.handler == "error" {
            return Ok(true);
        }
        if handler.handler == "subroute"
            && let Some(routes) = handler.config.get("routes")
        {
            let routes = route_vec_from_value(routes, "invalid subroute routes")?;
            for route in &routes {
                if route_contains_error_handler(route)? {
                    return Ok(true);
                }
            }
        }
    }
    Ok(false)
}

fn route_uses_unsupported_error_placeholder(route: &Route) -> bool {
    route
        .matcher_sets
        .iter()
        .any(map_uses_unsupported_error_placeholder)
        || route
            .handlers
            .iter()
            .any(handler_uses_unsupported_error_placeholder)
}

fn handler_uses_unsupported_error_placeholder(handler: &Handler) -> bool {
    value_uses_unsupported_error_placeholder(&Value::Object(handler.config.clone()))
}

fn map_uses_unsupported_error_placeholder(map: &Map<String, Value>) -> bool {
    value_uses_unsupported_error_placeholder(&Value::Object(map.clone()))
}

fn value_uses_unsupported_error_placeholder(value: &Value) -> bool {
    match value {
        Value::String(value) => {
            value.contains("{http.error}")
                || value.contains("{http.error.id}")
                || value.contains("{http.error.trace}")
        }
        Value::Array(values) => values.iter().any(value_uses_unsupported_error_placeholder),
        Value::Object(map) => map.iter().any(|(key, value)| {
            value_uses_unsupported_error_placeholder(&Value::String(key.clone()))
                || value_uses_unsupported_error_placeholder(value)
        }),
        _ => false,
    }
}

fn route_uses_unsupported_body_placeholder(route: &Route) -> Option<&'static str> {
    route
        .matcher_sets
        .iter()
        .find_map(map_uses_unsupported_body_placeholder)
        .or_else(|| {
            route
                .handlers
                .iter()
                .find_map(handler_uses_unsupported_body_placeholder)
        })
}

fn handler_uses_unsupported_body_placeholder(handler: &Handler) -> Option<&'static str> {
    value_uses_unsupported_body_placeholder(&Value::Object(handler.config.clone()))
}

fn map_uses_unsupported_body_placeholder(map: &Map<String, Value>) -> Option<&'static str> {
    value_uses_unsupported_body_placeholder(&Value::Object(map.clone()))
}

fn value_uses_unsupported_body_placeholder(value: &Value) -> Option<&'static str> {
    match value {
        Value::String(value) => string_uses_unsupported_body_placeholder(value),
        Value::Array(values) => values
            .iter()
            .find_map(value_uses_unsupported_body_placeholder),
        Value::Object(map) => map.iter().find_map(|(key, value)| {
            string_uses_unsupported_body_placeholder(key)
                .or_else(|| value_uses_unsupported_body_placeholder(value))
        }),
        _ => None,
    }
}

fn string_uses_unsupported_body_placeholder(value: &str) -> Option<&'static str> {
    let bytes = value.as_bytes();
    let mut cursor = 0usize;
    while let Some(relative_start) = bytes[cursor..].iter().position(|byte| *byte == b'{') {
        let start = cursor + relative_start;
        if start > 0 && bytes[start - 1] == b'\\' {
            cursor = start + 1;
            continue;
        }
        let after_start = start + 1;
        let Some(relative_end) = value[after_start..].find('}') else {
            return None;
        };
        let end = after_start + relative_end;
        let key = &value[after_start..end];
        match key {
            "http.request.body" => return Some("{http.request.body}"),
            "http.request.body_base64" => return Some("{http.request.body_base64}"),
            "http.response.body" => return Some("{http.response.body}"),
            "http.response.body_base64" => return Some("{http.response.body_base64}"),
            _ => cursor = end + 1,
        }
    }
    None
}

fn validate_map_handler(handler: &Handler) -> Result<()> {
    validate_object_fields(
        &handler.config,
        &["source", "destinations", "mappings", "defaults"],
        "map",
    )?;
    if let Some(source) = handler.config.get("source")
        && !source.is_null()
        && !source.is_string()
    {
        bail!("map.source must be a string");
    }
    let destinations = handler.config.get("destinations").map_or_else(
        || Ok(Vec::new()),
        |destinations| header_string_array(destinations, "map.destinations"),
    )?;
    for dest in &destinations {
        if !dest.starts_with('{') || dest.matches('{').count() != 1 {
            bail!("map.destinations entries must be single placeholders");
        }
    }
    if let Some(defaults) = handler.config.get("defaults") {
        let defaults = header_string_array(defaults, "map.defaults")?;
        if defaults.len() != destinations.len() {
            bail!("map.defaults count must match map.destinations");
        }
    }
    let mappings = match handler.config.get("mappings") {
        Some(value) if value.is_null() => &[][..],
        Some(value) => value
            .as_array()
            .map(Vec::as_slice)
            .ok_or_else(|| anyhow!("map.mappings must be an array"))?,
        None => &[],
    };
    let mut seen = std::collections::BTreeSet::new();
    for (index, mapping) in mappings.iter().enumerate() {
        let empty = Map::new();
        let mapping = if mapping.is_null() {
            &empty
        } else {
            mapping
                .as_object()
                .ok_or_else(|| anyhow!("map.mappings entries must be objects"))?
        };
        validate_object_fields(
            mapping,
            &["input", "input_regexp", "outputs"],
            "map.mappings",
        )?;
        for field in ["input", "input_regexp"] {
            if let Some(value) = mapping.get(field)
                && !value.is_null()
                && !value.is_string()
            {
                bail!("map.mappings.{field} must be a string");
            }
        }
        let input = mapping.get("input").and_then(Value::as_str).unwrap_or("");
        let input_regexp = mapping
            .get("input_regexp")
            .and_then(Value::as_str)
            .unwrap_or("");
        if !input.is_empty() && !input_regexp.is_empty() {
            bail!("map mapping {index} cannot specify both input and input_regexp");
        }
        let key = if input_regexp.is_empty() {
            input
        } else {
            caddy_regex(input_regexp).context("invalid map.mappings.input_regexp")?;
            input_regexp
        };
        if !seen.insert(key.to_string()) {
            bail!("map mapping {index} has duplicate input");
        }
        let outputs = match mapping.get("outputs") {
            Some(outputs) if outputs.is_null() => &[],
            Some(outputs) => outputs
                .as_array()
                .map(Vec::as_slice)
                .ok_or_else(|| anyhow!("map.mappings.outputs must be an array"))?,
            None => &[],
        };
        if outputs.len() != destinations.len() {
            bail!("map.mappings.outputs count must match map.destinations");
        }
    }
    Ok(())
}

fn normalize_map_handler(handler: &Handler) -> Result<Value> {
    let mut normalized = Map::new();
    if let Some(source) = handler.config.get("source")
        && !source.is_null()
    {
        normalized.insert("source".to_string(), source.clone());
    }
    if let Some(destinations) = handler.config.get("destinations")
        && !destinations.is_null()
    {
        normalized.insert(
            "destinations".to_string(),
            Value::Array(
                header_string_array(destinations, "map.destinations")?
                    .into_iter()
                    .map(Value::String)
                    .collect(),
            ),
        );
    }
    if let Some(defaults) = handler.config.get("defaults")
        && !defaults.is_null()
    {
        normalized.insert(
            "defaults".to_string(),
            Value::Array(
                header_string_array(defaults, "map.defaults")?
                    .into_iter()
                    .map(Value::String)
                    .collect(),
            ),
        );
    }
    if let Some(mappings) = handler.config.get("mappings")
        && !mappings.is_null()
    {
        let mappings = mappings
            .as_array()
            .ok_or_else(|| anyhow!("map.mappings must be an array"))?
            .iter()
            .map(|mapping| {
                let empty = Map::new();
                let mapping = if mapping.is_null() {
                    &empty
                } else {
                    mapping
                        .as_object()
                        .ok_or_else(|| anyhow!("map.mappings entries must be objects"))?
                };
                let mut item = Map::new();
                for field in ["input", "input_regexp"] {
                    if let Some(value) = mapping.get(field)
                        && !value.is_null()
                    {
                        item.insert(field.to_string(), value.clone());
                    }
                }
                if let Some(outputs) = mapping.get("outputs")
                    && !outputs.is_null()
                {
                    item.insert("outputs".to_string(), outputs.clone());
                }
                Ok(Value::Object(item))
            })
            .collect::<Result<Vec<_>>>()?;
        normalized.insert("mappings".to_string(), Value::Array(mappings));
    }
    Ok(Value::Object(normalized))
}

fn validate_file_matcher(value: &Value) -> Result<()> {
    let obj = value
        .as_object()
        .ok_or_else(|| anyhow!("http.matchers.file must be an object"))?;
    validate_object_fields(
        obj,
        &["fs", "root", "try_files", "try_policy", "split_path"],
        "http.matchers.file",
    )?;
    if let Some(fs) = obj.get("fs") {
        if !fs.is_null() {
            let fs = fs
                .as_str()
                .ok_or_else(|| anyhow!("file matcher fs must be a string"))?;
            if !contains_placeholder(fs) && fs != "file" && fs != "default" {
                bail!("file matcher fs {fs:?} is not available in zeroserve's supported surface");
            }
        }
    }
    for key in ["root", "try_policy"] {
        if let Some(value) = obj.get(key)
            && !value.is_null()
            && !value.is_string()
        {
            bail!("file matcher {key} must be a string");
        }
    }
    if let Some(policy) = obj.get("try_policy").and_then(Value::as_str) {
        match policy {
            ""
            | "first_exist"
            | "first_exist_fallback"
            | "largest_size"
            | "smallest_size"
            | "most_recently_modified" => {}
            _ => bail!("unsupported file matcher try_policy {policy:?}"),
        }
    }
    if let Some(try_files) = obj.get("try_files") {
        for pattern in header_string_array(try_files, "file matcher try_files")? {
            if pattern == "=103" {
                bail!(
                    "http.matchers.file try_files =103 Early Hints cannot be represented exactly by zeroserve responses"
                );
            }
        }
    }
    if let Some(split_path) = obj.get("split_path") {
        validate_header_string_array_strict(split_path, "file matcher split_path")?;
    }
    Ok(())
}

fn route_match_can_set_error(route: &Route) -> bool {
    for set in &route.matcher_sets {
        if matcher_set_can_set_error(set) {
            return true;
        }
    }
    false
}

fn matcher_set_can_set_error(set: &MatcherSet) -> bool {
    for (name, value) in set {
        if matcher_can_set_error(name, value) {
            return true;
        }
    }
    false
}

fn matcher_eval_phase(name: &str, value: &Value) -> MatcherEvalPhase {
    if matcher_can_set_error(name, value) {
        MatcherEvalPhase::SetsError
    } else if matcher_sets_captures(name) {
        MatcherEvalPhase::Captures
    } else {
        MatcherEvalPhase::Plain
    }
}

fn matcher_sets_captures(name: &str) -> bool {
    matches!(name, "path_regexp" | "header_regexp" | "vars_regexp")
}

fn matcher_can_set_error(name: &str, value: &Value) -> bool {
    match name {
        "file" => file_matcher_has_status_fallback(value),
        "expression" => expression_matcher_can_set_error(value),
        "not" => {
            let Some(sets) = value.as_array() else {
                return false;
            };
            for set in sets {
                let Some(obj) = set.as_object() else {
                    return false;
                };
                if matcher_set_can_set_error(obj) {
                    return true;
                }
            }
            false
        }
        _ => false,
    }
}

fn file_matcher_has_status_fallback(value: &Value) -> bool {
    let Some(obj) = value.as_object() else {
        return false;
    };
    let Some(try_files) = obj.get("try_files") else {
        return false;
    };
    let Ok(patterns) = header_string_array(try_files, "file matcher try_files") else {
        return false;
    };
    patterns
        .iter()
        .any(|pattern| file_matcher_status_fallback(pattern).is_some())
}

fn file_matcher_status_fallback(pattern: &str) -> Option<u16> {
    let status = pattern.strip_prefix('=')?.parse::<u16>().ok()?;
    (status != 103 && (100..=999).contains(&status)).then_some(status)
}

fn expression_matcher_can_set_error(value: &Value) -> bool {
    let expr = if let Some(expr) = value.as_str() {
        expr
    } else {
        let Some(expr) = value.get("expr").and_then(Value::as_str) else {
            return false;
        };
        expr
    };
    let Ok(mut parser) = ExpressionParser::new(expr) else {
        return false;
    };
    let Ok(ast) = parser.parse() else {
        return false;
    };
    expression_ast_can_set_error(&ast)
}

fn expression_ast_can_set_error(ast: &ExpressionAst) -> bool {
    match ast {
        ExpressionAst::And(left, right) | ExpressionAst::Or(left, right) => {
            expression_ast_can_set_error(left) || expression_ast_can_set_error(right)
        }
        ExpressionAst::Not(inner) => expression_ast_can_set_error(inner),
        ExpressionAst::Call { name, args } if name == "file" => {
            let Ok(value) = expression_file_matcher_arg(args) else {
                return false;
            };
            file_matcher_has_status_fallback(&value)
        }
        ExpressionAst::Bool(_)
        | ExpressionAst::Eq(_, _)
        | ExpressionAst::Ne(_, _)
        | ExpressionAst::Matches(_, _)
        | ExpressionAst::In(_, _)
        | ExpressionAst::NumericCompare { .. }
        | ExpressionAst::Call { .. } => false,
    }
}

fn normalize_file_matcher(value: &Value) -> Result<Value> {
    let obj = value
        .as_object()
        .ok_or_else(|| anyhow!("http.matchers.file must be an object"))?;
    let mut normalized = Map::new();
    for key in ["fs", "root", "try_policy"] {
        if let Some(value) = obj.get(key)
            && !value.is_null()
        {
            normalized.insert(key.to_string(), value.clone());
        }
    }
    for key in ["try_files", "split_path"] {
        if let Some(value) = obj.get(key)
            && !value.is_null()
        {
            normalized.insert(
                key.to_string(),
                Value::Array(
                    header_string_array(value, &format!("file matcher {key}"))?
                        .into_iter()
                        .map(Value::String)
                        .collect(),
                ),
            );
        }
    }
    Ok(Value::Object(normalized))
}

fn validate_expression_matcher(value: &Value) -> Result<()> {
    if value.is_string() {
        return Ok(());
    }
    let obj = value
        .as_object()
        .ok_or_else(|| anyhow!("http.matchers.expression must be a string or object"))?;
    validate_object_fields(obj, &["expr", "name"], "http.matchers.expression")?;
    match obj.get("expr") {
        Some(Value::String(_)) => {}
        Some(_) => bail!("http.matchers.expression.expr must be a string"),
        None => bail!("http.matchers.expression.expr is required"),
    }
    if let Some(name) = obj.get("name")
        && !name.is_string()
    {
        bail!("http.matchers.expression.name must be a string");
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ExpressionAst {
    Bool(bool),
    And(Box<ExpressionAst>, Box<ExpressionAst>),
    Or(Box<ExpressionAst>, Box<ExpressionAst>),
    Not(Box<ExpressionAst>),
    Eq(String, String),
    Ne(String, String),
    Matches(String, String),
    In(String, Vec<String>),
    NumericCompare {
        left: String,
        op: NumericCompareOp,
        right: String,
    },
    Call {
        name: String,
        args: Vec<ExpressionArg>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NumericCompareOp {
    Gt,
    Ge,
    Lt,
    Le,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ExpressionArg {
    String(String),
    Map(BTreeMap<String, Vec<String>>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ExpressionToken {
    Ident(String),
    String(String),
    LParen,
    RParen,
    LBrace,
    RBrace,
    LBracket,
    RBracket,
    Colon,
    Comma,
    Dot,
    Plus,
    Eq,
    Ne,
    Gt,
    Ge,
    Lt,
    Le,
    In,
    And,
    Or,
    Not,
    Number(String),
}

struct ExpressionParser {
    tokens: Vec<ExpressionToken>,
    pos: usize,
}

impl ExpressionParser {
    fn new(expr: &str) -> Result<Self> {
        Ok(Self {
            tokens: tokenize_expression(expr)?,
            pos: 0,
        })
    }

    fn parse(&mut self) -> Result<ExpressionAst> {
        let ast = self.parse_or()?;
        if self.peek().is_some() {
            bail!("trailing tokens");
        }
        Ok(ast)
    }

    fn parse_or(&mut self) -> Result<ExpressionAst> {
        let mut expr = self.parse_and()?;
        while self.consume(&ExpressionToken::Or) {
            let rhs = self.parse_and()?;
            expr = ExpressionAst::Or(Box::new(expr), Box::new(rhs));
        }
        Ok(expr)
    }

    fn parse_and(&mut self) -> Result<ExpressionAst> {
        let mut expr = self.parse_compare()?;
        while self.consume(&ExpressionToken::And) {
            let rhs = self.parse_compare()?;
            expr = ExpressionAst::And(Box::new(expr), Box::new(rhs));
        }
        Ok(expr)
    }

    fn parse_compare(&mut self) -> Result<ExpressionAst> {
        if matches!(
            self.peek(),
            Some(ExpressionToken::String(_) | ExpressionToken::Number(_))
        ) {
            let left = self.parse_numeric_expr()?;
            if self.consume(&ExpressionToken::Eq) {
                return Ok(ExpressionAst::Eq(left, self.parse_numeric_expr()?));
            }
            if self.consume(&ExpressionToken::Ne) {
                return Ok(ExpressionAst::Ne(left, self.parse_numeric_expr()?));
            }
            if self.consume(&ExpressionToken::Dot) {
                let Some(ExpressionToken::Ident(method)) = self.next() else {
                    bail!("expression string method requires method name");
                };
                if method != "matches" {
                    bail!("unsupported expression string method {method:?}");
                }
                self.expect(ExpressionToken::LParen)?;
                let pattern = self.parse_string_expr()?;
                self.expect(ExpressionToken::RParen)?;
                return Ok(ExpressionAst::Matches(left, pattern));
            }
            if self.consume(&ExpressionToken::In) {
                return Ok(ExpressionAst::In(left, self.parse_numeric_list()?));
            }
            if self.consume(&ExpressionToken::Gt) {
                return Ok(ExpressionAst::NumericCompare {
                    left,
                    op: NumericCompareOp::Gt,
                    right: self.parse_numeric_expr()?,
                });
            }
            if self.consume(&ExpressionToken::Ge) {
                return Ok(ExpressionAst::NumericCompare {
                    left,
                    op: NumericCompareOp::Ge,
                    right: self.parse_numeric_expr()?,
                });
            }
            if self.consume(&ExpressionToken::Lt) {
                return Ok(ExpressionAst::NumericCompare {
                    left,
                    op: NumericCompareOp::Lt,
                    right: self.parse_numeric_expr()?,
                });
            }
            if self.consume(&ExpressionToken::Le) {
                return Ok(ExpressionAst::NumericCompare {
                    left,
                    op: NumericCompareOp::Le,
                    right: self.parse_numeric_expr()?,
                });
            }
            bail!("expression value must be compared with ==, !=, in, >, >=, <, or <=");
        }
        self.parse_not()
    }

    fn parse_not(&mut self) -> Result<ExpressionAst> {
        if self.consume(&ExpressionToken::Not) {
            return Ok(ExpressionAst::Not(Box::new(self.parse_compare()?)));
        }
        self.parse_primary()
    }

    fn parse_primary(&mut self) -> Result<ExpressionAst> {
        if self.consume(&ExpressionToken::LParen) {
            let expr = self.parse_or()?;
            self.expect(ExpressionToken::RParen)?;
            return Ok(expr);
        }
        let Some(ExpressionToken::Ident(name)) = self.next() else {
            bail!("expected matcher call");
        };
        if name == "true" {
            return Ok(ExpressionAst::Bool(true));
        }
        if name == "false" {
            return Ok(ExpressionAst::Bool(false));
        }
        self.expect(ExpressionToken::LParen)?;
        let mut args = Vec::new();
        if !self.consume(&ExpressionToken::RParen) {
            loop {
                args.push(self.parse_arg()?);
                if self.consume(&ExpressionToken::RParen) {
                    break;
                }
                self.expect(ExpressionToken::Comma)?;
            }
        }
        Ok(ExpressionAst::Call { name, args })
    }

    fn parse_arg(&mut self) -> Result<ExpressionArg> {
        match self.peek() {
            Some(ExpressionToken::String(_)) => {
                Ok(ExpressionArg::String(self.parse_string_expr()?))
            }
            Some(ExpressionToken::LBrace) => {
                self.pos += 1;
                self.parse_map()
            }
            _ => bail!("expected string or object argument"),
        }
    }

    fn parse_map(&mut self) -> Result<ExpressionArg> {
        let mut map = BTreeMap::new();
        if self.consume(&ExpressionToken::RBrace) {
            return Ok(ExpressionArg::Map(map));
        }
        loop {
            if !matches!(self.peek(), Some(ExpressionToken::String(_))) {
                bail!("object keys must be strings");
            };
            let key = self.parse_string_expr()?;
            self.expect(ExpressionToken::Colon)?;
            let values = if matches!(self.peek(), Some(ExpressionToken::String(_))) {
                vec![self.parse_string_expr()?]
            } else {
                self.expect(ExpressionToken::LBracket)?;
                let mut values = Vec::new();
                if !self.consume(&ExpressionToken::RBracket) {
                    loop {
                        if !matches!(self.peek(), Some(ExpressionToken::String(_))) {
                            bail!("object array values must be strings");
                        };
                        values.push(self.parse_string_expr()?);
                        if self.consume(&ExpressionToken::RBracket) {
                            break;
                        }
                        self.expect(ExpressionToken::Comma)?;
                    }
                }
                values
            };
            map.insert(key, values);
            if self.consume(&ExpressionToken::RBrace) {
                break;
            }
            self.expect(ExpressionToken::Comma)?;
        }
        Ok(ExpressionArg::Map(map))
    }

    fn parse_string_expr(&mut self) -> Result<String> {
        let mut out = self.parse_string_atom()?;
        while self.consume(&ExpressionToken::Plus) {
            out.push_str(&self.parse_string_atom()?);
        }
        Ok(out)
    }

    fn parse_numeric_expr(&mut self) -> Result<String> {
        if matches!(self.peek(), Some(ExpressionToken::Number(_))) {
            let Some(ExpressionToken::Number(value)) = self.next() else {
                unreachable!("peeked Number");
            };
            return Ok(value);
        }
        self.parse_string_expr()
    }

    fn parse_string_atom(&mut self) -> Result<String> {
        match self.next() {
            Some(ExpressionToken::String(value)) => Ok(value),
            _ => bail!("expected string expression"),
        }
    }

    fn parse_numeric_list(&mut self) -> Result<Vec<String>> {
        self.expect(ExpressionToken::LBracket)?;
        let mut values = Vec::new();
        if self.consume(&ExpressionToken::RBracket) {
            return Ok(values);
        }
        loop {
            values.push(self.parse_numeric_expr()?);
            if self.consume(&ExpressionToken::RBracket) {
                break;
            }
            self.expect(ExpressionToken::Comma)?;
        }
        Ok(values)
    }

    fn peek(&self) -> Option<&ExpressionToken> {
        self.tokens.get(self.pos)
    }

    fn next(&mut self) -> Option<ExpressionToken> {
        let token = self.tokens.get(self.pos).cloned();
        if token.is_some() {
            self.pos += 1;
        }
        token
    }

    fn consume(&mut self, token: &ExpressionToken) -> bool {
        if self.peek() == Some(token) {
            self.pos += 1;
            true
        } else {
            false
        }
    }

    fn expect(&mut self, token: ExpressionToken) -> Result<()> {
        if self.consume(&token) {
            Ok(())
        } else {
            bail!("expected {token:?}");
        }
    }
}

fn tokenize_expression(expr: &str) -> Result<Vec<ExpressionToken>> {
    let mut tokens = Vec::new();
    let mut chars = expr.char_indices().peekable();
    while let Some((idx, ch)) = chars.next() {
        match ch {
            c if c.is_whitespace() => {}
            '(' => tokens.push(ExpressionToken::LParen),
            ')' => tokens.push(ExpressionToken::RParen),
            '{' => {
                if expression_brace_starts_map(&mut chars) {
                    tokens.push(ExpressionToken::LBrace);
                } else {
                    tokens.push(ExpressionToken::String(read_expression_placeholder(
                        expr, &mut chars, idx,
                    )?));
                }
            }
            '}' => tokens.push(ExpressionToken::RBrace),
            '[' => tokens.push(ExpressionToken::LBracket),
            ']' => tokens.push(ExpressionToken::RBracket),
            ':' => tokens.push(ExpressionToken::Colon),
            ',' => tokens.push(ExpressionToken::Comma),
            '.' => tokens.push(ExpressionToken::Dot),
            '+' => tokens.push(ExpressionToken::Plus),
            '=' => {
                if chars.next().is_some_and(|(_, next)| next == '=') {
                    tokens.push(ExpressionToken::Eq);
                } else {
                    bail!("expected == at byte {idx}");
                }
            }
            '!' => {
                if chars.peek().is_some_and(|(_, next)| *next == '=') {
                    chars.next();
                    tokens.push(ExpressionToken::Ne);
                } else {
                    tokens.push(ExpressionToken::Not);
                }
            }
            '>' => {
                if chars.peek().is_some_and(|(_, next)| *next == '=') {
                    chars.next();
                    tokens.push(ExpressionToken::Ge);
                } else {
                    tokens.push(ExpressionToken::Gt);
                }
            }
            '<' => {
                if chars.peek().is_some_and(|(_, next)| *next == '=') {
                    chars.next();
                    tokens.push(ExpressionToken::Le);
                } else {
                    tokens.push(ExpressionToken::Lt);
                }
            }
            '&' => {
                if chars.next().is_some_and(|(_, next)| next == '&') {
                    tokens.push(ExpressionToken::And);
                } else {
                    bail!("expected && at byte {idx}");
                }
            }
            '|' => {
                if chars.next().is_some_and(|(_, next)| next == '|') {
                    tokens.push(ExpressionToken::Or);
                } else {
                    bail!("expected || at byte {idx}");
                }
            }
            '\'' | '"' | '`' => tokens.push(ExpressionToken::String(read_expression_string(
                expr, &mut chars, ch, idx,
            )?)),
            c if c == '_' || c.is_ascii_alphabetic() => {
                let start = idx;
                let mut end = idx + ch.len_utf8();
                while let Some((next_idx, next)) = chars.peek().copied() {
                    if next == '_' || next.is_ascii_alphanumeric() {
                        chars.next();
                        end = next_idx + next.len_utf8();
                    } else {
                        break;
                    }
                }
                let ident = &expr[start..end];
                if ident == "in" {
                    tokens.push(ExpressionToken::In);
                } else {
                    tokens.push(ExpressionToken::Ident(ident.to_string()));
                }
            }
            c if c.is_ascii_digit() => {
                let start = idx;
                let mut end = idx + ch.len_utf8();
                while let Some((next_idx, next)) = chars.peek().copied() {
                    if next.is_ascii_digit() {
                        chars.next();
                        end = next_idx + next.len_utf8();
                    } else {
                        break;
                    }
                }
                tokens.push(ExpressionToken::Number(expr[start..end].to_string()));
            }
            _ => bail!("unsupported expression character {ch:?} at byte {idx}"),
        }
    }
    Ok(tokens)
}

fn read_expression_string(
    _expr: &str,
    chars: &mut std::iter::Peekable<std::str::CharIndices<'_>>,
    quote: char,
    start: usize,
) -> Result<String> {
    let mut out = String::new();
    while let Some((_, ch)) = chars.next() {
        if ch == quote {
            return Ok(out);
        }
        if quote == '`' {
            out.push(ch);
            continue;
        }
        if ch == '\\' {
            let Some((_, escaped)) = chars.next() else {
                bail!("unterminated escape in expression string");
            };
            match escaped {
                '\\' => out.push('\\'),
                '\'' => out.push('\''),
                '"' => out.push('"'),
                'n' => out.push('\n'),
                'r' => out.push('\r'),
                't' => out.push('\t'),
                '{' => out.push('{'),
                other => {
                    out.push('\\');
                    out.push(other);
                }
            }
        } else {
            out.push(ch);
        }
    }
    bail!("unterminated expression string starting at byte {start}");
}

fn expression_brace_starts_map(chars: &mut std::iter::Peekable<std::str::CharIndices<'_>>) -> bool {
    match chars.peek() {
        Some((_, ch)) => {
            ch.is_whitespace() || *ch == '\'' || *ch == '"' || *ch == '}' || *ch == '{'
        }
        None => true,
    }
}

fn read_expression_placeholder(
    expr: &str,
    chars: &mut std::iter::Peekable<std::str::CharIndices<'_>>,
    start: usize,
) -> Result<String> {
    while let Some((idx, ch)) = chars.next() {
        match ch {
            '}' => return Ok(expr[start..idx + 1].to_string()),
            '{' => bail!("nested placeholder in expression at byte {idx}"),
            _ => {}
        }
    }
    bail!("unterminated placeholder in expression starting at byte {start}");
}

fn expression_single_map_arg(name: &str, args: &[ExpressionArg]) -> Result<Value> {
    if args.len() != 1 {
        bail!("{name}() requires one object argument");
    }
    let ExpressionArg::Map(map) = &args[0] else {
        bail!("{name}() requires an object argument");
    };
    let mut obj = Map::new();
    for (key, values) in map {
        obj.insert(
            key.clone(),
            Value::Array(values.iter().cloned().map(Value::String).collect()),
        );
    }
    Ok(Value::Object(obj))
}

fn expression_regexp_arg(
    name: &str,
    args: &[ExpressionArg],
    default_regex_name: &str,
) -> Result<Value> {
    let strings = expression_string_args(name, args)?;
    let (capture_name, pattern) = match strings.as_slice() {
        [pattern] => (default_regex_name, pattern.as_str()),
        [capture_name, pattern] => (capture_name.as_str(), pattern.as_str()),
        _ => bail!("{name}() requires one pattern or name plus pattern"),
    };
    let capture_name = if capture_name.is_empty() {
        default_regex_name
    } else {
        capture_name
    };
    let mut obj = Map::new();
    obj.insert("pattern".to_string(), Value::String(pattern.to_string()));
    if !capture_name.is_empty() {
        obj.insert("name".to_string(), Value::String(capture_name.to_string()));
    }
    Ok(Value::Object(obj))
}

fn expression_field_regexp_arg(
    name: &str,
    args: &[ExpressionArg],
    default_regex_name: &str,
) -> Result<(String, Value)> {
    let strings = expression_string_args(name, args)?;
    let (capture_name, field, pattern) = match strings.as_slice() {
        [field, pattern] => (default_regex_name, field.as_str(), pattern.as_str()),
        [capture_name, field, pattern] => (capture_name.as_str(), field.as_str(), pattern.as_str()),
        _ => bail!("{name}() requires field plus pattern or name, field, and pattern"),
    };
    let capture_name = if capture_name.is_empty() {
        default_regex_name
    } else {
        capture_name
    };
    let mut obj = Map::new();
    obj.insert("pattern".to_string(), Value::String(pattern.to_string()));
    if !capture_name.is_empty() {
        obj.insert("name".to_string(), Value::String(capture_name.to_string()));
    }
    Ok((field.to_string(), Value::Object(obj)))
}

fn expression_file_matcher_arg(args: &[ExpressionArg]) -> Result<Value> {
    match args {
        [] => Ok(Value::Object(Map::new())),
        [ExpressionArg::Map(map)] => {
            let mut obj = Map::new();
            for (key, values) in map {
                match key.as_str() {
                    "try_files" | "split_path" => {
                        obj.insert(
                            key.clone(),
                            Value::Array(values.iter().cloned().map(Value::String).collect()),
                        );
                    }
                    "root" | "try_policy" => {
                        let Some(value) = values.first() else {
                            bail!("file() {key} requires a string value");
                        };
                        obj.insert(key.clone(), Value::String(value.clone()));
                    }
                    other => bail!("unsupported file() object key {other:?}"),
                }
            }
            Ok(Value::Object(obj))
        }
        _ => {
            let strings = expression_string_args("file", args)?;
            let mut obj = Map::new();
            obj.insert(
                "try_files".to_string(),
                Value::Array(strings.into_iter().map(Value::String).collect()),
            );
            Ok(Value::Object(obj))
        }
    }
}

fn expression_string_args(name: &str, args: &[ExpressionArg]) -> Result<Vec<String>> {
    let mut values = Vec::new();
    for arg in args {
        let ExpressionArg::String(value) = arg else {
            bail!("{name}() only supports string arguments");
        };
        values.push(value.clone());
    }
    Ok(values)
}

fn string_array(value: &Value, label: &str) -> Result<Vec<String>> {
    if let Some(s) = value.as_str() {
        return Ok(vec![s.to_string()]);
    }
    let arr = value
        .as_array()
        .ok_or_else(|| anyhow!("{label} must be a string or array of strings"))?;
    arr.iter()
        .map(|v| {
            v.as_str()
                .map(str::to_string)
                .ok_or_else(|| anyhow!("{label} must contain only strings"))
        })
        .collect()
}

fn strict_string_array(value: &Value, label: &str) -> Result<Vec<String>> {
    if value.is_null() {
        return Ok(Vec::new());
    }
    let arr = value
        .as_array()
        .ok_or_else(|| anyhow!("{label} must be an array of strings"))?;
    arr.iter()
        .map(|v| {
            v.as_str()
                .map(str::to_string)
                .ok_or_else(|| anyhow!("{label} must contain only strings"))
        })
        .collect()
}

fn int_array(value: &Value, label: &str) -> Result<Vec<i64>> {
    let values = if value.is_array() {
        value
            .as_array()
            .expect("checked is_array")
            .iter()
            .collect::<Vec<_>>()
    } else {
        vec![value]
    };
    values
        .into_iter()
        .map(|value| match value {
            Value::Number(number) => number
                .as_i64()
                .ok_or_else(|| anyhow!("{label} must contain integer values")),
            _ => bail!("{label} must be an integer or array of integers"),
        })
        .collect()
}

fn validate_ip_range(range: &str) -> Result<()> {
    let (range, _) = range.split_once('%').unwrap_or((range, ""));
    if let Some((addr, prefix)) = range.split_once('/') {
        let ip: IpAddr = addr
            .parse()
            .with_context(|| format!("invalid IP address {addr:?}"))?;
        let prefix = prefix
            .parse::<u8>()
            .with_context(|| format!("invalid CIDR prefix length {prefix:?}"))?;
        let max = if ip.is_ipv4() { 32 } else { 128 };
        if prefix > max {
            bail!("CIDR prefix length {prefix} exceeds {max}");
        }
        Ok(())
    } else {
        range
            .parse::<IpAddr>()
            .with_context(|| format!("invalid IP address {range:?}"))?;
        Ok(())
    }
}

fn validate_file_server_browse(value: &Value) -> Result<()> {
    match value {
        Value::Null => Ok(()),
        Value::Object(map) => {
            for key in map.keys() {
                match key.as_str() {
                    "template_file" | "reveal_symlinks" | "sort" | "file_limit" => {}
                    other => bail!("unsupported file_server.browse field {other:?}"),
                }
            }
            if map
                .get("template_file")
                .and_then(Value::as_str)
                .is_some_and(|value| !value.is_empty())
            {
                bail!("file_server.browse.template_file is not supported");
            }
            if let Some(sort) = map.get("sort") {
                let sort = header_string_array(sort, "file_server.browse.sort")?;
                for (idx, value) in sort.iter().enumerate() {
                    match idx {
                        0 => match value.as_str() {
                            "name" | "namedirfirst" | "size" | "time" => {}
                            _ => bail!(
                                "file_server.browse.sort first option must be name, namedirfirst, size, or time"
                            ),
                        },
                        1 => match value.as_str() {
                            "asc" | "desc" => {}
                            _ => bail!("file_server.browse.sort second option must be asc or desc"),
                        },
                        _ => bail!("file_server.browse.sort accepts at most two options"),
                    }
                }
            }
            if let Some(file_limit) = map.get("file_limit")
                && !file_limit.is_null()
                && file_limit.as_i64().is_none()
            {
                bail!("file_server.browse.file_limit must be an integer");
            }
            if let Some(template_file) = map.get("template_file")
                && !template_file.is_null()
                && !template_file.is_string()
            {
                bail!("file_server.browse.template_file must be a string");
            }
            if let Some(reveal_symlinks) = map.get("reveal_symlinks")
                && !reveal_symlinks.is_null()
                && !reveal_symlinks.is_boolean()
            {
                bail!("file_server.browse.reveal_symlinks must be a boolean");
            }
            Ok(())
        }
        _ => bail!("file_server.browse must be null or an object"),
    }
}

fn validate_file_server_fields(config: &Map<String, Value>) -> Result<()> {
    const SUPPORTED: &[&str] = &[
        "fs",
        "root",
        "hide",
        "index_names",
        "browse",
        "canonical_uris",
        "status_code",
        "pass_thru",
        "precompressed",
        "precompressed_order",
        "etag_file_extensions",
    ];
    for key in config.keys() {
        if !SUPPORTED.contains(&key.as_str()) {
            bail!("unsupported file_server field {key:?}");
        }
    }
    for key in ["fs", "root"] {
        if let Some(value) = config.get(key)
            && !value.is_null()
            && !value.is_string()
        {
            bail!("file_server.{key} must be a string");
        }
    }
    for key in ["canonical_uris", "pass_thru"] {
        if let Some(value) = config.get(key)
            && !value.is_null()
            && !value.is_boolean()
        {
            bail!("file_server.{key} must be a boolean");
        }
    }
    Ok(())
}

fn normalize_file_server_config(config: &Map<String, Value>) -> Result<Map<String, Value>> {
    let mut normalized = Map::new();
    for key in ["fs", "root"] {
        if let Some(value) = config.get(key)
            && !value.is_null()
        {
            normalized.insert(key.to_string(), value.clone());
        }
    }
    for key in [
        "hide",
        "index_names",
        "etag_file_extensions",
        "precompressed_order",
    ] {
        if let Some(value) = config.get(key)
            && !value.is_null()
        {
            normalized.insert(
                key.to_string(),
                Value::Array(
                    header_string_array(value, &format!("file_server.{key}"))?
                        .into_iter()
                        .map(Value::String)
                        .collect(),
                ),
            );
        }
    }
    if let Some(browse) = config.get("browse")
        && !browse.is_null()
    {
        normalized.insert("browse".to_string(), normalize_file_server_browse(browse)?);
    }
    if let Some(canonical) = config.get("canonical_uris")
        && !canonical.is_null()
    {
        normalized.insert("canonical_uris".to_string(), canonical.clone());
    }
    if config
        .get("pass_thru")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        normalized.insert("pass_thru".to_string(), Value::Bool(true));
    }
    if let Some(precompressed) = config.get("precompressed")
        && !precompressed.is_null()
    {
        normalized.insert(
            "precompressed".to_string(),
            normalize_file_server_precompressed(precompressed)?,
        );
    }
    Ok(normalized)
}

fn normalize_file_server_browse(value: &Value) -> Result<Value> {
    let obj = value
        .as_object()
        .ok_or_else(|| anyhow!("file_server.browse must be null or an object"))?;
    let mut normalized = Map::new();
    if let Some(sort) = obj.get("sort")
        && !sort.is_null()
    {
        normalized.insert(
            "sort".to_string(),
            Value::Array(
                header_string_array(sort, "file_server.browse.sort")?
                    .into_iter()
                    .map(Value::String)
                    .collect(),
            ),
        );
    }
    if let Some(file_limit) = obj.get("file_limit")
        && !file_limit.is_null()
    {
        normalized.insert("file_limit".to_string(), file_limit.clone());
    }
    if let Some(reveal) = obj.get("reveal_symlinks")
        && !reveal.is_null()
    {
        normalized.insert("reveal_symlinks".to_string(), reveal.clone());
    }
    Ok(Value::Object(normalized))
}

fn validate_rewrite_query(value: &Value) -> Result<()> {
    let obj = value
        .as_object()
        .ok_or_else(|| anyhow!("rewrite.query must be an object"))?;
    for key in obj.keys() {
        match key.as_str() {
            "rename" | "set" | "add" | "replace" | "delete" => {}
            other => bail!("unsupported rewrite.query field {other:?}"),
        }
    }
    for key in ["rename", "set", "add"] {
        if let Some(values) = obj.get(key) {
            if values.is_null() {
                continue;
            }
            let values = values
                .as_array()
                .ok_or_else(|| anyhow!("rewrite.query.{key} must be an array"))?;
            for value in values {
                let value = value
                    .as_object()
                    .ok_or_else(|| anyhow!("rewrite.query.{key} entries must be objects"))?;
                validate_object_fields(value, &["key", "val"], &format!("rewrite.query.{key}"))?;
                validate_rewrite_query_string_field(value, "key", key)?;
                validate_rewrite_query_string_field(value, "val", key)?;
            }
        }
    }
    if let Some(values) = obj.get("replace") {
        if values.is_null() {
            // Caddy JSON decodes null slices as nil; keep validating sibling fields.
        } else {
            let values = values
                .as_array()
                .ok_or_else(|| anyhow!("rewrite.query.replace must be an array"))?;
            for value in values {
                let value = value
                    .as_object()
                    .ok_or_else(|| anyhow!("rewrite.query.replace entries must be objects"))?;
                validate_object_fields(
                    value,
                    &["key", "search", "search_regexp", "replace"],
                    "rewrite.query.replace",
                )?;
                validate_rewrite_query_string_field(value, "key", "replace")?;
                validate_rewrite_query_string_field(value, "search", "replace")?;
                validate_rewrite_query_string_field(value, "replace", "replace")?;
                validate_rewrite_query_string_field(value, "search_regexp", "replace")?;
                if value
                    .get("search")
                    .and_then(Value::as_str)
                    .is_some_and(|value| !value.is_empty())
                    && value
                        .get("search_regexp")
                        .and_then(Value::as_str)
                        .is_some_and(|value| !value.is_empty())
                {
                    bail!("rewrite.query.replace cannot specify both search and search_regexp");
                }
                if let Some(search_regexp) = value.get("search_regexp").and_then(Value::as_str)
                    && !search_regexp.is_empty()
                {
                    caddy_regex(search_regexp)
                        .context("invalid rewrite.query.replace.search_regexp")?;
                }
            }
        }
    }
    if let Some(values) = obj.get("delete") {
        validate_header_string_array_strict(values, "rewrite.query.delete")?;
    }
    Ok(())
}

fn validate_rewrite_query_string_field(
    obj: &Map<String, Value>,
    field: &str,
    op: &str,
) -> Result<()> {
    if let Some(value) = obj.get(field) {
        if value.is_null() {
            return Ok(());
        }
        if value.as_str().is_none() {
            bail!("rewrite.query.{op}.{field} must be a string");
        }
    }
    Ok(())
}

fn normalize_rewrite_query(value: &Value) -> Result<Value> {
    let obj = value
        .as_object()
        .ok_or_else(|| anyhow!("rewrite.query must be an object"))?;
    let mut normalized = Map::new();
    for key in ["rename", "set", "add"] {
        if let Some(values) = obj.get(key) {
            if values.is_null() {
                continue;
            }
            let values = values
                .as_array()
                .ok_or_else(|| anyhow!("rewrite.query.{key} must be an array"))?
                .iter()
                .map(|value| {
                    let value = value
                        .as_object()
                        .ok_or_else(|| anyhow!("rewrite.query.{key} entries must be objects"))?;
                    let mut item = Map::new();
                    for field in ["key", "val"] {
                        item.insert(
                            field.to_string(),
                            Value::String(
                                value
                                    .get(field)
                                    .filter(|value| !value.is_null())
                                    .and_then(Value::as_str)
                                    .unwrap_or("")
                                    .to_string(),
                            ),
                        );
                    }
                    Ok(Value::Object(item))
                })
                .collect::<Result<Vec<_>>>()?;
            normalized.insert(key.to_string(), Value::Array(values));
        }
    }
    if let Some(values) = obj.get("replace") {
        if !values.is_null() {
            let values = values
                .as_array()
                .ok_or_else(|| anyhow!("rewrite.query.replace must be an array"))?
                .iter()
                .map(|value| {
                    let value = value
                        .as_object()
                        .ok_or_else(|| anyhow!("rewrite.query.replace entries must be objects"))?;
                    let mut item = Map::new();
                    for field in ["key", "search", "search_regexp", "replace"] {
                        item.insert(
                            field.to_string(),
                            Value::String(
                                value
                                    .get(field)
                                    .filter(|value| !value.is_null())
                                    .and_then(Value::as_str)
                                    .unwrap_or("")
                                    .to_string(),
                            ),
                        );
                    }
                    Ok(Value::Object(item))
                })
                .collect::<Result<Vec<_>>>()?;
            normalized.insert("replace".to_string(), Value::Array(values));
        }
    }
    if let Some(values) = obj.get("delete") {
        if !values.is_null() {
            normalized.insert(
                "delete".to_string(),
                Value::Array(
                    header_string_array(values, "rewrite.query.delete")?
                        .into_iter()
                        .map(Value::String)
                        .collect(),
                ),
            );
        }
    }
    Ok(Value::Object(normalized))
}

fn validate_file_server_precompressed(value: &Value) -> Result<()> {
    if value.is_null() {
        return Ok(());
    }
    let map = value
        .as_object()
        .ok_or_else(|| anyhow!("file_server.precompressed must be an object"))?;
    for (encoding, config) in map {
        validate_precompressed_encoding(encoding)?;
        let config = config
            .as_object()
            .ok_or_else(|| anyhow!("file_server.precompressed.{encoding} must be an object"))?;
        match encoding.as_str() {
            "gzip" => validate_gzip_precompressed_config(config)?,
            "br" => validate_object_fields(config, &[], "file_server.precompressed.br")?,
            "zstd" => validate_zstd_precompressed_config(config)?,
            _ => unreachable!("validated precompressed encoding"),
        }
    }
    Ok(())
}

fn normalize_file_server_precompressed(value: &Value) -> Result<Value> {
    let map = value
        .as_object()
        .ok_or_else(|| anyhow!("file_server.precompressed must be an object"))?;
    let mut normalized = Map::new();
    for (encoding, config) in map {
        let config = config
            .as_object()
            .ok_or_else(|| anyhow!("file_server.precompressed.{encoding} must be an object"))?;
        let mut item = Map::new();
        match encoding.as_str() {
            "gzip" => {
                if let Some(level) = config.get("level")
                    && !level.is_null()
                {
                    item.insert("level".to_string(), level.clone());
                }
            }
            "br" => {}
            "zstd" => {
                if let Some(level) = config.get("level")
                    && !level.is_null()
                {
                    item.insert("level".to_string(), level.clone());
                }
                if let Some(checksum) = config.get("checksum")
                    && !checksum.is_null()
                {
                    item.insert("checksum".to_string(), checksum.clone());
                }
            }
            _ => unreachable!("validated precompressed encoding"),
        }
        normalized.insert(encoding.clone(), Value::Object(item));
    }
    Ok(Value::Object(normalized))
}

fn validate_precompressed_encoding(encoding: &str) -> Result<()> {
    match encoding {
        "gzip" | "br" | "zstd" => Ok(()),
        _ => bail!("unsupported file_server precompressed encoding {encoding:?}"),
    }
}

fn validate_precompressed_order_encoding(encoding: &str) -> Result<()> {
    if encoding.is_empty() {
        Ok(())
    } else {
        validate_precompressed_encoding(encoding)
    }
}

fn validate_gzip_precompressed_config(config: &Map<String, Value>) -> Result<()> {
    validate_object_fields(config, &["level"], "file_server.precompressed.gzip")?;
    if let Some(level) = config.get("level") {
        if level.is_null() {
            return Ok(());
        }
        let level = level
            .as_i64()
            .ok_or_else(|| anyhow!("file_server.precompressed.gzip.level must be an integer"))?;
        if !(-2..=9).contains(&level) {
            bail!("file_server.precompressed.gzip.level must be -2..9");
        }
    }
    Ok(())
}

fn validate_zstd_precompressed_config(config: &Map<String, Value>) -> Result<()> {
    validate_object_fields(
        config,
        &["level", "checksum"],
        "file_server.precompressed.zstd",
    )?;
    if let Some(level) = config.get("level")
        && !level.is_null()
    {
        let Some(level) = level.as_str() else {
            bail!("file_server.precompressed.zstd.level must be a string");
        };
        match level {
            "fastest" | "better" | "best" | "default" => {}
            _ => bail!(
                "file_server.precompressed.zstd.level must be fastest, better, best, or default"
            ),
        }
    }
    if let Some(checksum) = config.get("checksum")
        && !checksum.is_null()
        && !checksum.is_boolean()
    {
        bail!("file_server.precompressed.zstd.checksum must be a boolean");
    }
    Ok(())
}

fn weak_string(value: &Value) -> Option<String> {
    match value {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        Value::Null => Some(String::new()),
        Value::Bool(_) | Value::Array(_) | Value::Object(_) => serde_json::to_string(value).ok(),
    }
}

fn is_decimal_status_literal(value: &str) -> bool {
    !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit())
}

fn bool_field(map: &Map<String, Value>, key: &str) -> bool {
    map.get(key).and_then(Value::as_bool).unwrap_or(false)
}

fn validate_object_fields(obj: &Map<String, Value>, supported: &[&str], label: &str) -> Result<()> {
    for key in obj.keys() {
        if !supported.contains(&key.as_str()) {
            bail!("unsupported {label} field {key:?}");
        }
    }
    Ok(())
}

/// Top-level Caddy apps whose configuration lives entirely outside zeroserve's
/// eBPF request-processing surface (TLS certificate/key management, the PKI/CA
/// subsystem, the event bus). They are meaningless to the compiler, so we warn
/// and ignore them rather than failing.
fn ignorable_caddy_app(name: &str) -> bool {
    matches!(name, "tls" | "pki" | "events")
}

/// HTTP app fields that configure Caddy's listener defaults, graceful shutdown,
/// or metrics. Generated middleware cannot observe or alter those runtime
/// concerns, so they are ignored with warnings.
fn ignorable_http_app_field(key: &str) -> bool {
    matches!(
        key,
        "http_port" | "https_port" | "grace_period" | "shutdown_delay" | "metrics"
    )
}

/// HTTP-server fields that configure listener binding, TLS termination, the
/// connection transport, or access logging — all of which live outside
/// zeroserve's eBPF request-processing surface. The eBPF script cannot observe
/// or alter them, so we warn and ignore rather than failing the compile.
fn ignorable_http_server_field(key: &str) -> bool {
    matches!(
        key,
        "listen"
            | "listener_wrappers"
            | "packet_conn_wrappers"
            | "tls_connection_policies"
            | "automatic_https"
            | "protocols"
            | "listen_protocols"
            | "strict_sni_host"
            | "read_timeout"
            | "read_header_timeout"
            | "write_timeout"
            | "idle_timeout"
            | "keepalive_interval"
            | "keepalive_idle"
            | "keepalive_count"
            | "enable_full_duplex"
            | "max_header_bytes"
            | "metrics"
            | "experimental_http3"
            | "allow_h2c"
            | "allow_0rtt"
    )
}

fn validate_http_app_fields(app: &HttpApp, warnings: &mut Vec<String>) -> Result<()> {
    for key in app.extra.keys() {
        if ignorable_http_app_field(key) {
            warnings.push(format!(
                "ignoring apps.http field {key:?}: configured outside zeroserve's eBPF request-processing surface"
            ));
        } else {
            bail!("unsupported apps.http field {key:?}");
        }
    }
    Ok(())
}

fn validate_caddy_filesystems_app(app: &Value, warnings: &mut Vec<String>) -> Result<()> {
    let obj = app
        .as_object()
        .ok_or_else(|| anyhow!("caddy.filesystems app must be an object"))?;
    validate_object_fields(obj, &["filesystems"], "caddy.filesystems")?;
    let Some(filesystems) = obj.get("filesystems") else {
        warnings.push(
            "ignoring empty caddy.filesystems app: configured outside zeroserve's eBPF request-processing surface"
                .to_string(),
        );
        return Ok(());
    };
    if filesystems.is_null() {
        warnings.push(
            "ignoring empty caddy.filesystems app: configured outside zeroserve's eBPF request-processing surface"
                .to_string(),
        );
        return Ok(());
    }
    let entries = filesystems
        .as_array()
        .ok_or_else(|| anyhow!("caddy.filesystems.filesystems must be an array"))?;
    for entry in entries {
        let entry = entry
            .as_object()
            .ok_or_else(|| anyhow!("caddy.filesystems.filesystems entries must be objects"))?;
        validate_object_fields(
            entry,
            &["name", "file_system"],
            "caddy.filesystems.filesystems",
        )?;
        if let Some(name) = entry.get("name")
            && !name.is_null()
            && !name.is_string()
        {
            bail!("caddy.filesystems.filesystems.name must be a string");
        }
        if let Some(file_system) = entry.get("file_system")
            && !file_system.is_null()
        {
            bail!(
                "Caddy filesystem modules cannot be represented by zeroserve's supported file-server surface"
            );
        }
    }
    warnings.push(
        "ignoring caddy.filesystems app without configured filesystem modules: configured outside zeroserve's eBPF request-processing surface"
            .to_string(),
    );
    Ok(())
}

fn access_log_config_for_server(
    logging: Option<&Value>,
    server_extra: &Map<String, Value>,
) -> Result<AccessLogConfig> {
    let mut config = AccessLogConfig::default();
    if let Some(logs) = server_extra.get("logs")
        && !logs.is_null()
    {
        let logs = logs
            .as_object()
            .ok_or_else(|| anyhow!("apps.http.servers.logs must be an object"))?;
        validate_object_fields(logs, &["default_logger_name"], "apps.http.servers.logs")?;
        if let Some(name) = logs.get("default_logger_name")
            && !name.is_null()
        {
            config.default_logger_name = Some(
                name.as_str()
                    .ok_or_else(|| {
                        anyhow!("apps.http.servers.logs.default_logger_name must be a string")
                    })?
                    .to_string(),
            );
        }
    }
    let Some(logging) = logging.filter(|value| !value.is_null()) else {
        return Ok(config);
    };
    let logging = logging
        .as_object()
        .ok_or_else(|| anyhow!("logging must be an object"))?;
    validate_object_fields(logging, &["logs"], "logging")?;
    let Some(logs) = logging.get("logs").filter(|value| !value.is_null()) else {
        return Ok(config);
    };
    let logs = logs
        .as_object()
        .ok_or_else(|| anyhow!("logging.logs must be an object"))?;
    for (name, logger) in logs {
        let logger = logger
            .as_object()
            .ok_or_else(|| anyhow!("logging.logs.{name} must be an object"))?;
        let Some(writer) = logger.get("writer").filter(|value| !value.is_null()) else {
            continue;
        };
        let writer = writer
            .as_object()
            .ok_or_else(|| anyhow!("logging.logs.{name}.writer must be an object"))?;
        let output = writer
            .get("output")
            .and_then(Value::as_str)
            .unwrap_or("stderr");
        if output != "file" {
            continue;
        }
        let Some(filename) = writer.get("filename").filter(|value| !value.is_null()) else {
            bail!("logging.logs.{name}.writer.filename is required for file output");
        };
        let filename = filename
            .as_str()
            .ok_or_else(|| anyhow!("logging.logs.{name}.writer.filename must be a string"))?;
        config.files.insert(name.clone(), filename.to_string());
    }
    Ok(config)
}

fn validate_http_server_fields(
    server: &HttpServer,
    server_name: &str,
    warnings: &mut Vec<String>,
) -> Result<()> {
    for key in server.extra.keys() {
        if key == "logs" {
            continue;
        }
        if ignorable_http_server_field(key) {
            warnings.push(format!(
                "ignoring apps.http.servers.{server_name} field {key:?}: configured outside zeroserve's eBPF request-processing surface"
            ));
        } else {
            bail!("unsupported apps.http.servers.{server_name} field {key:?}");
        }
    }
    Ok(())
}

fn validate_tls_connection_policy(policy: &TlsConnectionPolicy, label: &str) -> Result<()> {
    for key in policy.extra.keys() {
        if !matches!(
            key.as_str(),
            "certificate_selection" | "alpn" | "protocol_min" | "protocol_max"
        ) {
            bail!("unsupported {label} field {key:?}");
        }
    }
    if let Some(match_) = &policy.match_
        && let Some((key, _)) = match_.extra.iter().next()
    {
        bail!("unsupported {label}.match field {key:?}");
    }
    if let Some(auth) = &policy.client_authentication {
        normalize_tls_client_auth(auth)
            .with_context(|| format!("unsupported {label}.client_authentication"))?;
    }
    Ok(())
}

fn normalize_tls_client_auth(auth: &Value) -> Result<Value> {
    let obj = auth
        .as_object()
        .ok_or_else(|| anyhow!("client_authentication must be an object"))?;
    let mode = obj.get("mode").and_then(Value::as_str).unwrap_or("require");
    if !matches!(
        mode,
        "request" | "require" | "verify_if_given" | "require_and_verify"
    ) {
        bail!("unsupported client_authentication.mode {mode:?}");
    }
    if obj.get("verifier").is_some_and(|value| !value.is_null()) {
        bail!("custom client_authentication.verifier is not supported");
    }
    if obj
        .get("trusted_leaf_certs")
        .is_some_and(|value| !value.is_null())
    {
        bail!("client_authentication.trusted_leaf_certs is not supported");
    }
    if matches!(mode, "verify_if_given" | "require_and_verify") {
        let ca = obj
            .get("ca")
            .and_then(Value::as_object)
            .ok_or_else(|| anyhow!("verified client authentication requires ca"))?;
        let provider = ca
            .get("provider")
            .and_then(Value::as_str)
            .unwrap_or("inline");
        if provider != "inline" {
            bail!("unsupported client_authentication.ca provider {provider:?}");
        }
        let certs = ca
            .get("trusted_ca_certs")
            .and_then(Value::as_array)
            .ok_or_else(|| anyhow!("verified client authentication requires trusted_ca_certs"))?;
        if certs.is_empty() {
            bail!("verified client authentication requires at least one trusted_ca_cert");
        }
        for cert in certs {
            if !cert.is_string() {
                bail!("trusted_ca_certs entries must be base64 DER strings");
            }
        }
        Ok(json!({
            "mode": mode,
            "trusted_ca_certs": certs,
        }))
    } else {
        Ok(json!({ "mode": mode }))
    }
}

fn tls_policy_sni_condition(policy: &TlsConnectionPolicy) -> String {
    let Some(match_) = &policy.match_ else {
        return "1".to_string();
    };
    if match_.sni.is_empty() {
        return "1".to_string();
    }
    match_
        .sni
        .iter()
        .map(|sni| {
            format!(
                "(zs_caddy_eq_fold(caddy_tls_sni, zs_caddy_clamp_len(caddy_tls_sni_len, sizeof(caddy_tls_sni)), {}, {}) != 0)",
                c_str(sni),
                sni.len()
            )
        })
        .collect::<Vec<_>>()
        .join(" || ")
}

fn validate_http_error_fields(errors: &HttpErrorConfig, server_name: &str) -> Result<()> {
    if let Some((key, _)) = errors.extra.iter().next() {
        bail!("unsupported apps.http.servers.{server_name}.errors field {key:?}");
    }
    Ok(())
}

fn validate_static_response_fields(config: &Map<String, Value>) -> Result<()> {
    validate_object_fields(
        config,
        &["status_code", "headers", "body", "close", "abort"],
        "static_response",
    )?;
    if let Some(body) = config.get("body")
        && !body.is_null()
        && !body.is_string()
    {
        bail!("static_response.body must be a string");
    }
    for key in ["close", "abort"] {
        if let Some(value) = config.get(key)
            && !value.is_null()
            && !value.is_boolean()
        {
            bail!("static_response.{key} must be a boolean");
        }
    }
    if let Some(headers) = config.get("headers")
        && !headers.is_null()
    {
        let headers = headers
            .as_object()
            .ok_or_else(|| anyhow!("static_response.headers must be an object"))?;
        for values in headers.values() {
            if values.is_null() {
                continue;
            }
            let values = values
                .as_array()
                .ok_or_else(|| anyhow!("static_response.headers values must be arrays"))?;
            for value in values {
                if !value.is_null() && !value.is_string() {
                    bail!("static_response.headers values must contain only strings");
                }
            }
        }
    }
    Ok(())
}

fn validate_static_error_fields(config: &Map<String, Value>) -> Result<()> {
    validate_object_fields(config, &["error", "status_code"], "error")?;
    if let Some(message) = config.get("error")
        && !message.is_null()
        && !message.is_string()
    {
        bail!("error.error must be a string");
    }
    Ok(())
}

fn normalize_http_basic_auth_config(config: &Map<String, Value>) -> Result<Option<String>> {
    validate_object_fields(config, &["providers"], "authentication")?;
    let providers = match config.get("providers") {
        Some(Value::Null) | None => return Ok(None),
        Some(Value::Object(providers)) => providers,
        Some(_) => bail!("authentication.providers must be an object"),
    };
    if providers.is_empty() {
        return Ok(None);
    }
    if providers.len() != 1 || !providers.contains_key("http_basic") {
        bail!("authentication supports only the http_basic provider in generated Caddy middleware");
    }
    let provider = providers
        .get("http_basic")
        .and_then(Value::as_object)
        .ok_or_else(|| anyhow!("authentication.providers.http_basic must be an object"))?;
    validate_object_fields(
        provider,
        &["hash", "accounts", "realm", "hash_cache"],
        "authentication.providers.http_basic",
    )?;

    let algorithm = match provider.get("hash") {
        Some(Value::Null) | None => "bcrypt".to_string(),
        Some(Value::Object(hash)) => {
            validate_object_fields(
                hash,
                &["algorithm"],
                "authentication.providers.http_basic.hash",
            )?;
            match hash.get("algorithm") {
                Some(Value::Null) | None => "bcrypt".to_string(),
                Some(Value::String(algorithm)) => algorithm.clone(),
                Some(_) => {
                    bail!("authentication.providers.http_basic.hash.algorithm must be a string")
                }
            }
        }
        Some(_) => bail!("authentication.providers.http_basic.hash must be an object"),
    };
    if algorithm != "bcrypt" && algorithm != "argon2id" {
        bail!("authentication.providers.http_basic.hash.algorithm must be bcrypt or argon2id");
    }

    if let Some(hash_cache) = provider.get("hash_cache")
        && !hash_cache.is_null()
        && !hash_cache.is_object()
    {
        bail!("authentication.providers.http_basic.hash_cache must be an object");
    }

    let empty_accounts = Vec::new();
    let accounts = match provider.get("accounts") {
        Some(Value::Null) | None => &empty_accounts,
        Some(Value::Array(accounts)) => accounts,
        Some(_) => bail!("authentication.providers.http_basic.accounts must be an array"),
    };
    let mut normalized_accounts = BTreeMap::new();
    for (idx, account) in accounts.iter().enumerate() {
        let account = account.as_object().ok_or_else(|| {
            anyhow!("authentication.providers.http_basic.accounts.{idx} must be an object")
        })?;
        validate_object_fields(
            account,
            &["username", "password"],
            &format!("authentication.providers.http_basic.accounts.{idx}"),
        )?;
        let username = account
            .get("username")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                anyhow!(
                    "authentication.providers.http_basic.accounts.{idx}.username must be a string"
                )
            })?;
        let password = account
            .get("password")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                anyhow!(
                    "authentication.providers.http_basic.accounts.{idx}.password must be a string"
                )
            })?;
        if username.is_empty() || password.is_empty() {
            bail!(
                "authentication.providers.http_basic.accounts.{idx}.username and password are required"
            );
        }
        if normalized_accounts.contains_key(username) {
            bail!("authentication.providers.http_basic account username is not unique: {username}");
        }
        let username = caddy_provision_replace_all(username);
        let password = caddy_provision_replace_all(password);
        if username.is_empty() || password.is_empty() {
            bail!(
                "authentication.providers.http_basic.accounts.{idx}.username and password are required"
            );
        }
        if !password.starts_with('$') {
            Base64::decode_vec(&password).with_context(|| {
                format!(
                    "authentication.providers.http_basic.accounts.{idx}.password must be Modular Crypt Format or base64-encoded"
                )
            })?;
        }
        normalized_accounts.insert(username, password);
    }

    let realm = match provider.get("realm") {
        Some(Value::Null) | None => String::new(),
        Some(Value::String(realm)) => realm.clone(),
        Some(_) => bail!("authentication.providers.http_basic.realm must be a string"),
    };

    let normalized = serde_json::json!({
        "hash": { "algorithm": algorithm },
        "accounts": normalized_accounts
            .into_iter()
            .map(|(username, password)| serde_json::json!({
                "username": username,
                "password": password,
            }))
            .collect::<Vec<_>>(),
        "realm": realm,
    });
    Ok(Some(serde_json::to_string(&normalized)?))
}

fn normalize_static_response_headers(value: &Value) -> Result<Value> {
    let headers = value
        .as_object()
        .ok_or_else(|| anyhow!("static_response.headers must be an object"))?;
    let mut normalized = Map::new();
    for (name, values) in headers {
        let values = if values.is_null() {
            Vec::new()
        } else {
            values
                .as_array()
                .ok_or_else(|| anyhow!("static_response.headers values must be arrays"))?
                .iter()
                .map(|value| {
                    Ok(Value::String(if value.is_null() {
                        String::new()
                    } else {
                        value
                            .as_str()
                            .ok_or_else(|| {
                                anyhow!("static_response.headers values must contain only strings")
                            })?
                            .to_string()
                    }))
                })
                .collect::<Result<Vec<_>>>()?
        };
        normalized.insert(name.clone(), Value::Array(values));
    }
    Ok(Value::Object(normalized))
}

/// Validate the `encode` handler config and return a normalized JSON object
/// (without the `handler` key) to hand to the runtime. Mirrors the validation
/// Caddy performs in Provision/Validate for the encode handler and its gzip and
/// zstd encoder modules.
fn normalize_encode_config(handler: &Handler) -> Result<Value> {
    validate_object_fields(
        &handler.config,
        &["match", "minimum_length", "prefer", "encodings"],
        "encode",
    )?;
    let mut out = Map::new();

    if let Some(min) = handler.config.get("minimum_length")
        && !min.is_null()
    {
        let min = min
            .as_i64()
            .ok_or_else(|| anyhow!("encode.minimum_length must be an integer"))?;
        out.insert("minimum_length".to_string(), Value::from(min));
    }

    // Encoders: only gzip and zstd are supported (no brotli).
    let mut available: Vec<String> = Vec::new();
    if let Some(encodings) = handler.config.get("encodings")
        && !encodings.is_null()
    {
        let obj = encodings
            .as_object()
            .ok_or_else(|| anyhow!("encode.encodings must be an object"))?;
        let mut normalized = Map::new();
        for (name, config) in obj {
            let config = validate_encoder_config(name, config)?;
            normalized.insert(name.clone(), config);
            available.push(name.clone());
        }
        if !normalized.is_empty() {
            out.insert("encodings".to_string(), Value::Object(normalized));
        }
    }
    if available.is_empty() {
        bail!("encode handler requires at least one encoding (gzip or zstd)");
    }

    if let Some(prefer) = handler.config.get("prefer")
        && !prefer.is_null()
    {
        let prefer = strict_string_array(prefer, "encode.prefer")?;
        let mut seen = std::collections::HashSet::new();
        for name in &prefer {
            if !available.contains(name) {
                bail!("encode.prefer encoding {name:?} is not enabled in encodings");
            }
            if !seen.insert(name.clone()) {
                bail!("encode.prefer encoding {name:?} is duplicated");
            }
        }
        out.insert("prefer".to_string(), Value::from(prefer));
    }

    if let Some(matcher) = handler.config.get("match")
        && !matcher.is_null()
    {
        out.insert("match".to_string(), validate_encode_matcher(matcher)?);
    }

    Ok(Value::Object(out))
}

fn validate_encoder_config(name: &str, config: &Value) -> Result<Value> {
    let obj = match config {
        Value::Null => Map::new(),
        Value::Object(obj) => obj.clone(),
        _ => bail!("encode.encodings.{name} must be an object"),
    };
    match name {
        "gzip" => {
            validate_object_fields(&obj, &["level"], &format!("encode.encodings.{name}"))?;
            if let Some(level) = obj.get("level").filter(|v| !v.is_null()) {
                let level = level
                    .as_i64()
                    .ok_or_else(|| anyhow!("encode.encodings.gzip.level must be an integer"))?;
                // klauspost gzip: StatelessCompression(-3)..=BestCompression(9).
                if !(-3..=9).contains(&level) {
                    bail!("encode.encodings.gzip.level must be between -3 and 9");
                }
            }
            Ok(Value::Object(obj))
        }
        "zstd" => {
            validate_object_fields(
                &obj,
                &["level", "checksum"],
                &format!("encode.encodings.{name}"),
            )?;
            if let Some(level) = obj.get("level").filter(|v| !v.is_null()) {
                let level = level
                    .as_str()
                    .ok_or_else(|| anyhow!("encode.encodings.zstd.level must be a string"))?;
                if !matches!(level, "fastest" | "better" | "best" | "default") {
                    bail!(
                        "encode.encodings.zstd.level must be one of 'fastest', 'better', 'best', 'default'"
                    );
                }
            }
            if let Some(checksum) = obj.get("checksum").filter(|v| !v.is_null())
                && !checksum.is_boolean()
            {
                bail!("encode.encodings.zstd.checksum must be a boolean");
            }
            Ok(Value::Object(obj))
        }
        _ => bail!("unsupported encode encoding {name:?} (only gzip and zstd are supported)"),
    }
}

fn validate_encode_matcher(value: &Value) -> Result<Value> {
    let obj = value
        .as_object()
        .ok_or_else(|| anyhow!("encode.match must be an object"))?;
    validate_object_fields(obj, &["status_code", "headers"], "encode.match")?;
    if let Some(status) = obj.get("status_code").filter(|v| !v.is_null()) {
        int_array(status, "encode.match.status_code")?;
    }
    if let Some(headers) = obj.get("headers").filter(|v| !v.is_null()) {
        let headers = headers
            .as_object()
            .ok_or_else(|| anyhow!("encode.match.headers must be an object"))?;
        for (name, patterns) in headers {
            if !patterns.is_null() {
                strict_string_array(patterns, &format!("encode.match.headers.{name}"))?;
            }
        }
    }
    Ok(value.clone())
}

fn validate_headers_handler(handler: &Handler) -> Result<()> {
    validate_object_fields(&handler.config, &["request", "response"], "headers")?;
    if let Some(request) = handler.config.get("request")
        && !request.is_null()
    {
        validate_header_ops_fields(request, HeaderTarget::Request)?;
    }
    if let Some(response) = handler.config.get("response")
        && !response.is_null()
    {
        validate_header_ops_fields(response, HeaderTarget::Response)?;
    }
    Ok(())
}

fn validate_copy_response_headers_handler(handler: &Handler) -> Result<()> {
    validate_object_fields(
        &handler.config,
        &["include", "exclude"],
        "copy_response_headers",
    )?;
    let include = handler.config.get("include").map_or_else(
        || Ok(Vec::new()),
        |value| strict_string_array(value, "copy_response_headers.include"),
    )?;
    let exclude = handler.config.get("exclude").map_or_else(
        || Ok(Vec::new()),
        |value| strict_string_array(value, "copy_response_headers.exclude"),
    )?;
    if !include.is_empty() && !exclude.is_empty() {
        bail!("copy_response_headers cannot define both include and exclude");
    }
    Ok(())
}

fn normalize_copy_response_headers_config(config: &Map<String, Value>) -> Result<Value> {
    let mut normalized = Map::new();
    for key in ["include", "exclude"] {
        let values = config.get(key).map_or_else(
            || Ok(Vec::new()),
            |value| strict_string_array(value, &format!("copy_response_headers.{key}")),
        )?;
        if !values.is_empty() {
            normalized.insert(
                key.to_string(),
                Value::Array(values.into_iter().map(Value::String).collect()),
            );
        }
    }
    Ok(Value::Object(normalized))
}

fn validate_push_handler(handler: &Handler) -> Result<()> {
    validate_object_fields(&handler.config, &["resources", "headers"], "push")?;
    if let Some(resources) = handler.config.get("resources") {
        let resources = resources
            .as_array()
            .ok_or_else(|| anyhow!("push.resources must be an array"))?;
        for resource in resources {
            let resource = resource
                .as_object()
                .ok_or_else(|| anyhow!("push.resources entries must be objects"))?;
            validate_object_fields(resource, &["method", "target"], "push.resources")?;
            for key in ["method", "target"] {
                if let Some(value) = resource.get(key)
                    && !value.is_string()
                {
                    bail!("push.resources.{key} must be a string");
                }
            }
        }
    }
    if let Some(headers) = handler.config.get("headers") {
        validate_header_ops_fields(headers, HeaderTarget::Request)?;
    }
    Ok(())
}

fn validate_header_ops_fields(value: &Value, target: HeaderTarget) -> Result<()> {
    let label = match target {
        HeaderTarget::Request => "headers.request",
        HeaderTarget::Response => "headers.response",
    };
    let obj = value
        .as_object()
        .ok_or_else(|| anyhow!("{label} must be an object"))?;
    let supported = match target {
        HeaderTarget::Request => &["add", "set", "delete", "replace"][..],
        HeaderTarget::Response => &["add", "set", "delete", "replace", "require", "deferred"][..],
    };
    validate_object_fields(obj, supported, label)?;
    for key in ["add", "set"] {
        if let Some(headers) = obj.get(key) {
            if headers.is_null() {
                continue;
            }
            let headers = headers
                .as_object()
                .ok_or_else(|| anyhow!("{label}.{key} must be an object"))?;
            for values in headers.values() {
                if values.is_null() {
                    continue;
                }
                validate_header_string_array_strict(values, &format!("{label}.{key} value"))?;
            }
        }
    }
    if let Some(delete) = obj.get("delete") {
        if !delete.is_null() {
            validate_header_string_array_strict(delete, &format!("{label}.delete"))?;
        }
    }
    if let Some(replace) = obj.get("replace") {
        if replace.is_null() {
            // Caddy JSON decodes null maps as nil; keep validating sibling fields.
        } else {
            let replace = replace
                .as_object()
                .ok_or_else(|| anyhow!("{label}.replace must be an object"))?;
            for replacements in replace.values() {
                if replacements.is_null() {
                    continue;
                }
                let replacements = replacements
                    .as_array()
                    .ok_or_else(|| anyhow!("{label}.replace values must be arrays"))?;
                for replacement in replacements {
                    let replacement = replacement
                        .as_object()
                        .ok_or_else(|| anyhow!("{label}.replace entries must be objects"))?;
                    validate_object_fields(
                        replacement,
                        &["search", "search_regexp", "replace"],
                        &format!("{label}.replace"),
                    )?;
                    for field in ["search", "search_regexp", "replace"] {
                        if let Some(value) = replacement.get(field)
                            && !value.is_null()
                            && !value.is_string()
                        {
                            bail!("{label}.replace.{field} must be a string");
                        }
                    }
                    let search = replacement
                        .get("search")
                        .and_then(Value::as_str)
                        .unwrap_or("");
                    let search_regexp = replacement
                        .get("search_regexp")
                        .and_then(Value::as_str)
                        .unwrap_or("");
                    if !search.is_empty() && !search_regexp.is_empty() {
                        bail!("{label}.replace cannot specify both search and search_regexp");
                    }
                    if !search_regexp.is_empty() && !contains_caddy_placeholder(search_regexp) {
                        caddy_regex(search_regexp)
                            .with_context(|| format!("invalid {label}.replace.search_regexp"))?;
                    }
                }
            }
        }
    }
    if target == HeaderTarget::Response
        && let Some(deferred) = obj.get("deferred")
        && !deferred.is_null()
        && !deferred.is_boolean()
    {
        bail!("headers.response.deferred must be a boolean");
    }
    Ok(())
}

fn normalize_header_ops(value: &Value, target: HeaderTarget) -> Result<Value> {
    let label = match target {
        HeaderTarget::Request => "headers.request",
        HeaderTarget::Response => "headers.response",
    };
    let obj = value
        .as_object()
        .ok_or_else(|| anyhow!("{label} must be an object"))?;
    let mut normalized = Map::new();
    for key in ["add", "set"] {
        if let Some(headers) = obj.get(key)
            && !headers.is_null()
        {
            normalized.insert(
                key.to_string(),
                normalize_header_value_map(headers, &format!("{label}.{key}"))?,
            );
        }
    }
    if let Some(delete) = obj.get("delete")
        && !delete.is_null()
    {
        normalized.insert(
            "delete".to_string(),
            Value::Array(
                header_string_array(delete, &format!("{label}.delete"))?
                    .into_iter()
                    .map(Value::String)
                    .collect(),
            ),
        );
    }
    if let Some(replace) = obj.get("replace")
        && !replace.is_null()
    {
        normalized.insert(
            "replace".to_string(),
            normalize_header_replace_map(replace, &format!("{label}.replace"))?,
        );
    }
    if target == HeaderTarget::Response {
        if let Some(require) = obj.get("require")
            && !require.is_null()
        {
            normalized.insert("require".to_string(), require.clone());
        }
        if obj
            .get("deferred")
            .and_then(Value::as_bool)
            .unwrap_or(false)
        {
            normalized.insert("deferred".to_string(), Value::Bool(true));
        }
    }
    Ok(Value::Object(normalized))
}

fn normalize_header_value_map(value: &Value, label: &str) -> Result<Value> {
    let headers = value
        .as_object()
        .ok_or_else(|| anyhow!("{label} must be an object"))?;
    let mut normalized = Map::new();
    for (name, values) in headers {
        normalized.insert(
            name.clone(),
            Value::Array(
                header_string_array(values, &format!("{label} value"))?
                    .into_iter()
                    .map(Value::String)
                    .collect(),
            ),
        );
    }
    Ok(Value::Object(normalized))
}

fn normalize_header_replace_map(value: &Value, label: &str) -> Result<Value> {
    let replacements = value
        .as_object()
        .ok_or_else(|| anyhow!("{label} must be an object"))?;
    let mut normalized = Map::new();
    for (name, items) in replacements {
        let items = if items.is_null() {
            Vec::new()
        } else {
            items
                .as_array()
                .ok_or_else(|| anyhow!("{label} values must be arrays"))?
                .iter()
                .map(|item| {
                    let item = item
                        .as_object()
                        .ok_or_else(|| anyhow!("{label} entries must be objects"))?;
                    let mut normalized_item = Map::new();
                    for key in ["search", "search_regexp", "replace"] {
                        normalized_item.insert(
                            key.to_string(),
                            Value::String(
                                item.get(key)
                                    .filter(|value| !value.is_null())
                                    .and_then(Value::as_str)
                                    .unwrap_or("")
                                    .to_string(),
                            ),
                        );
                    }
                    Ok(Value::Object(normalized_item))
                })
                .collect::<Result<Vec<_>>>()?
        };
        normalized.insert(name.clone(), Value::Array(items));
    }
    Ok(Value::Object(normalized))
}

fn header_string_array(value: &Value, label: &str) -> Result<Vec<String>> {
    if value.is_null() {
        return Ok(Vec::new());
    }
    let values = value
        .as_array()
        .ok_or_else(|| anyhow!("{label} must be an array of strings"))?;
    values
        .iter()
        .map(|value| {
            if value.is_null() {
                Ok(String::new())
            } else {
                value
                    .as_str()
                    .map(str::to_string)
                    .ok_or_else(|| anyhow!("{label} must contain only strings"))
            }
        })
        .collect()
}

fn validate_header_string_array_strict(value: &Value, label: &str) -> Result<()> {
    header_string_array(value, label).map(|_| ())
}

fn validate_rewrite_fields(config: &Map<String, Value>) -> Result<()> {
    validate_object_fields(
        config,
        &[
            "method",
            "uri",
            "strip_path_prefix",
            "strip_path_suffix",
            "uri_substring",
            "path_regexp",
            "query",
        ],
        "rewrite",
    )?;
    for key in ["method", "uri", "strip_path_prefix", "strip_path_suffix"] {
        if let Some(value) = config.get(key)
            && !value.is_null()
            && !value.is_string()
        {
            bail!("rewrite.{key} must be a string");
        }
    }
    if let Some(values) = config.get("uri_substring") {
        if !values.is_null() {
            let values = values
                .as_array()
                .ok_or_else(|| anyhow!("rewrite.uri_substring must be an array"))?;
            for value in values {
                let empty = Map::new();
                let obj = if value.is_null() {
                    &empty
                } else {
                    value
                        .as_object()
                        .ok_or_else(|| anyhow!("rewrite.uri_substring entries must be objects"))?
                };
                validate_object_fields(
                    obj,
                    &["find", "replace", "limit"],
                    "rewrite.uri_substring",
                )?;
                for key in ["find", "replace"] {
                    if let Some(value) = obj.get(key)
                        && !value.is_null()
                        && !value.is_string()
                    {
                        bail!("rewrite.uri_substring.{key} must be a string");
                    }
                }
                if let Some(limit) = obj.get("limit")
                    && !limit.is_null()
                    && limit.as_i64().is_none()
                {
                    bail!("rewrite.uri_substring.limit must be an integer");
                }
            }
        }
    }
    if let Some(values) = config.get("path_regexp") {
        if !values.is_null() {
            let values = values
                .as_array()
                .ok_or_else(|| anyhow!("rewrite.path_regexp must be an array"))?;
            for value in values {
                let obj = value
                    .as_object()
                    .ok_or_else(|| anyhow!("rewrite.path_regexp entries must be objects"))?;
                validate_object_fields(obj, &["find", "replace"], "rewrite.path_regexp")?;
                for key in ["find", "replace"] {
                    if let Some(value) = obj.get(key)
                        && !value.is_null()
                        && !value.is_string()
                    {
                        bail!("rewrite.path_regexp.{key} must be a string");
                    }
                }
            }
        }
    }
    if let Some(query) = config.get("query") {
        validate_rewrite_query(query)?;
    }
    Ok(())
}

fn validate_request_body_fields(config: &Map<String, Value>) -> Result<()> {
    validate_object_fields(
        config,
        &["max_size", "read_timeout", "write_timeout", "set"],
        "request_body",
    )?;
    if let Some(max_size) = config.get("max_size")
        && !max_size.is_null()
        && max_size.as_i64().is_none()
    {
        bail!("request_body.max_size must be an integer");
    }
    for key in ["read_timeout", "write_timeout"] {
        if let Some(value) = config.get(key)
            && !value.is_null()
            && value.as_i64().is_none()
        {
            bail!("request_body.{key} must be an integer duration");
        }
    }
    if let Some(value) = config.get("set")
        && !value.is_null()
        && !value.is_string()
    {
        bail!("request_body.set must be a string");
    }
    Ok(())
}

fn static_trusted_proxy_ranges(value: &Value) -> Result<Vec<String>> {
    let obj = value
        .as_object()
        .ok_or_else(|| anyhow!("server.trusted_proxies must be an object"))?;
    validate_object_fields(obj, &["source", "ranges"], "server.trusted_proxies")?;
    let source = match obj.get("source") {
        Some(Value::String(source)) => source.as_str(),
        Some(_) => bail!("server.trusted_proxies.source must be a string"),
        None => "static",
    };
    if source != "static" {
        bail!(
            "server.trusted_proxies source {source:?} cannot be represented by generated eBPF middleware"
        );
    }
    let mut ranges = Vec::new();
    for range in obj.get("ranges").map_or(Ok(Vec::new()), |value| {
        strict_string_array(value, "server.trusted_proxies.ranges")
    })? {
        if range == "private_ranges" {
            ranges.extend(private_ranges_cidr().into_iter().map(str::to_string));
        } else {
            validate_ip_range(&range)
                .with_context(|| format!("invalid server.trusted_proxies range {range:?}"))?;
            ranges.push(range);
        }
    }
    Ok(ranges)
}

fn reverse_proxy_trusted_proxy_ranges(value: Option<&Value>) -> Result<Vec<String>> {
    let Some(value) = value else {
        return Ok(Vec::new());
    };
    let mut ranges = Vec::new();
    for range in strict_string_array(value, "reverse_proxy.trusted_proxies")? {
        if contains_placeholder(&range) {
            bail!("reverse_proxy.trusted_proxies placeholders are not supported");
        }
        validate_ip_range(&range)
            .with_context(|| format!("invalid reverse_proxy.trusted_proxies range {range:?}"))?;
        ranges.push(range);
    }
    Ok(ranges)
}

fn validate_reverse_proxy_fields(
    config: &Map<String, Value>,
    warnings: &mut Vec<String>,
) -> Result<()> {
    const SUPPORTED: &[&str] = &[
        "handler",
        "upstreams",
        "transport",
        "trusted_proxies",
        "headers",
        "rewrite",
        "handle_response",
    ];
    for key in config.keys() {
        if SUPPORTED.contains(&key.as_str()) {
            continue;
        }
        // zeroserve proxies to a single upstream (multiple upstreams are
        // rejected separately), so selection policy is a no-op here rather
        // than something we must reject. Retry controls still affect a single
        // upstream and are rejected by validate_reverse_proxy_load_balancing.
        if key == "load_balancing" {
            if config[key].is_null() {
                continue;
            }
            validate_reverse_proxy_load_balancing(&config[key], warnings)?;
            continue;
        }
        if key == "health_checks" {
            validate_noop_reverse_proxy_health_checks(&config[key])?;
            continue;
        }
        if key == "dynamic_upstreams" {
            validate_unsupported_reverse_proxy_raw_module(
                &config[key],
                "dynamic_upstreams",
                "dynamic upstream discovery",
            )?;
            continue;
        }
        if key == "circuit_breaker" {
            validate_unsupported_reverse_proxy_raw_module(
                &config[key],
                "circuit_breaker",
                "circuit breakers",
            )?;
            continue;
        }
        if ignorable_reverse_proxy_runtime_field(key) {
            let warning = format!(
                "ignoring reverse_proxy field {key:?}: configured outside zeroserve's eBPF request-processing surface"
            );
            if !warnings.contains(&warning) {
                warnings.push(warning);
            }
            continue;
        }
        bail!("unsupported reverse_proxy field {key:?}");
    }
    if let Some(transport) = config.get("transport") {
        validate_reverse_proxy_transport(transport, warnings)?;
    }
    if let Some(upstreams) = config.get("upstreams") {
        validate_reverse_proxy_upstreams(upstreams)?;
    }
    Ok(())
}

fn validate_unsupported_reverse_proxy_raw_module(
    value: &Value,
    field: &str,
    feature: &str,
) -> Result<()> {
    if value.is_null() {
        return Ok(());
    }
    bail!(
        "reverse_proxy.{field} configures {feature}, which cannot be represented by generated eBPF middleware"
    )
}

fn validate_noop_reverse_proxy_health_checks(value: &Value) -> Result<()> {
    let Value::Object(obj) = value else {
        if value.is_null() {
            return Ok(());
        }
        bail!("reverse_proxy.health_checks must be an object");
    };
    validate_object_fields(obj, &["active", "passive"], "reverse_proxy.health_checks")?;
    for key in ["active", "passive"] {
        let Some(section) = obj.get(key) else {
            continue;
        };
        if section.is_null() {
            continue;
        }
        let section = section
            .as_object()
            .ok_or_else(|| anyhow!("reverse_proxy.health_checks.{key} must be an object"))?;
        if !section.is_empty() {
            bail!(
                "reverse_proxy.health_checks.{key} configures upstream health checks, which cannot be represented by generated eBPF middleware"
            );
        }
    }
    Ok(())
}

fn validate_reverse_proxy_load_balancing(value: &Value, warnings: &mut Vec<String>) -> Result<()> {
    let obj = value
        .as_object()
        .ok_or_else(|| anyhow!("reverse_proxy.load_balancing must be an object"))?;
    validate_object_fields(
        obj,
        &[
            "selection_policy",
            "retries",
            "try_duration",
            "try_interval",
            "retry_match",
        ],
        "reverse_proxy.load_balancing",
    )?;
    for key in ["retries", "try_duration", "try_interval", "retry_match"] {
        if obj.contains_key(key) {
            let warning = format!(
                "ignoring reverse_proxy.load_balancing.{key}: retry behavior cannot be represented by generated eBPF middleware"
            );
            if !warnings.contains(&warning) {
                warnings.push(warning);
            }
        }
    }
    if let Some(selection_policy) = obj.get("selection_policy") {
        validate_reverse_proxy_selection_policy(selection_policy)?;
    }
    let warning = "ignoring reverse_proxy field \"load_balancing\": zeroserve proxies to a single upstream, so no load-balancing selection policy applies".to_string();
    if !warnings.contains(&warning) {
        warnings.push(warning);
    }
    Ok(())
}

fn validate_reverse_proxy_selection_policy(value: &Value) -> Result<()> {
    let obj = value.as_object().ok_or_else(|| {
        anyhow!("reverse_proxy.load_balancing.selection_policy must be an object")
    })?;
    let policy = obj.get("policy").and_then(Value::as_str).ok_or_else(|| {
        anyhow!("reverse_proxy.load_balancing.selection_policy.policy must be a string")
    })?;
    match policy {
        "random" | "least_conn" | "round_robin" | "first" | "ip_hash" | "client_ip_hash"
        | "uri_hash" => validate_object_fields(
            obj,
            &["policy"],
            "reverse_proxy.load_balancing.selection_policy",
        )?,
        "weighted_round_robin" => {
            validate_object_fields(
                obj,
                &["policy", "weights"],
                "reverse_proxy.load_balancing.selection_policy",
            )?;
            if let Some(weights) = obj.get("weights") {
                if weights.is_null() {
                    return Ok(());
                }
                let weights = weights.as_array().ok_or_else(|| {
                    anyhow!(
                        "reverse_proxy.load_balancing.selection_policy.weights must be an array"
                    )
                })?;
                for weight in weights {
                    let weight = weight
                        .as_i64()
                        .ok_or_else(|| anyhow!("reverse_proxy.load_balancing.selection_policy.weights must contain only integers"))?;
                    if weight < 0 {
                        bail!(
                            "reverse_proxy.load_balancing.selection_policy.weights must be non-negative"
                        );
                    }
                }
            }
        }
        "random_choose" => {
            validate_object_fields(
                obj,
                &["policy", "choose"],
                "reverse_proxy.load_balancing.selection_policy",
            )?;
            if let Some(choose) = obj.get("choose")
                && !choose.is_null()
                && choose.as_i64().is_none()
            {
                bail!("reverse_proxy.load_balancing.selection_policy.choose must be an integer");
            }
        }
        "query" => {
            validate_object_fields(
                obj,
                &["policy", "key", "fallback"],
                "reverse_proxy.load_balancing.selection_policy",
            )?;
            validate_optional_selection_policy_string(obj, "key")?;
            validate_optional_selection_policy_fallback(obj)?;
        }
        "header" => {
            validate_object_fields(
                obj,
                &["policy", "field", "fallback"],
                "reverse_proxy.load_balancing.selection_policy",
            )?;
            validate_optional_selection_policy_string(obj, "field")?;
            validate_optional_selection_policy_fallback(obj)?;
        }
        "cookie" => {
            validate_object_fields(
                obj,
                &["policy", "name", "secret", "max_age", "fallback"],
                "reverse_proxy.load_balancing.selection_policy",
            )?;
            validate_optional_selection_policy_string(obj, "name")?;
            validate_optional_selection_policy_string(obj, "secret")?;
            if let Some(max_age) = obj.get("max_age")
                && !max_age.is_null()
                && max_age.as_i64().is_none()
            {
                bail!("reverse_proxy.load_balancing.selection_policy.max_age must be an integer");
            }
            validate_optional_selection_policy_fallback(obj)?;
        }
        other => bail!(
            "reverse_proxy.load_balancing.selection_policy policy {other:?} is not available in zeroserve's supported Caddy surface"
        ),
    }
    Ok(())
}

fn validate_optional_selection_policy_string(obj: &Map<String, Value>, key: &str) -> Result<()> {
    if let Some(value) = obj.get(key)
        && !value.is_null()
        && value.as_str().is_none()
    {
        bail!("reverse_proxy.load_balancing.selection_policy.{key} must be a string");
    }
    Ok(())
}

fn validate_optional_selection_policy_fallback(obj: &Map<String, Value>) -> Result<()> {
    if let Some(fallback) = obj.get("fallback") {
        validate_reverse_proxy_selection_policy(fallback)?;
    }
    Ok(())
}

fn ignorable_reverse_proxy_runtime_field(key: &str) -> bool {
    matches!(
        key,
        "flush_interval"
            | "request_buffers"
            | "response_buffers"
            | "stream_timeout"
            | "stream_buffer_size"
            | "stream_close_delay"
            | "verbose_logs"
    )
}

fn validate_reverse_proxy_upstreams(value: &Value) -> Result<()> {
    let upstreams = value
        .as_array()
        .ok_or_else(|| anyhow!("reverse_proxy.upstreams must be an array"))?;
    for (index, upstream) in upstreams.iter().enumerate() {
        let upstream = upstream
            .as_object()
            .ok_or_else(|| anyhow!("reverse_proxy.upstreams[{index}] must be an object"))?;
        validate_object_fields(
            upstream,
            &["dial", "max_requests"],
            "reverse_proxy.upstreams",
        )?;
        if let Some(dial) = upstream.get("dial")
            && !dial.is_string()
        {
            bail!("reverse_proxy.upstreams.dial must be a string");
        }
        if let Some(max_requests) = upstream.get("max_requests")
            && !max_requests.is_null()
        {
            let max_requests = max_requests.as_i64().ok_or_else(|| {
                anyhow!("reverse_proxy.upstreams.max_requests must be an integer")
            })?;
            if max_requests != 0 {
                bail!(
                    "reverse_proxy.upstreams.max_requests limits concurrent upstream requests and cannot be represented by zs_reverse_proxy"
                );
            }
        }
    }
    Ok(())
}

fn validate_reverse_proxy_transport(value: &Value, warnings: &mut Vec<String>) -> Result<()> {
    let obj = value
        .as_object()
        .ok_or_else(|| anyhow!("reverse_proxy.transport must be an object"))?;
    let protocol = match obj.get("protocol") {
        Some(Value::String(protocol)) => protocol.as_str(),
        Some(_) => bail!("reverse_proxy.transport.protocol must be a string"),
        None => "http",
    };
    if protocol != "http" {
        bail!("reverse_proxy transport {protocol:?} cannot be represented by zs_reverse_proxy");
    }
    for key in obj.keys() {
        match key.as_str() {
            "protocol" | "tls" => {}
            other
                if unsupported_reverse_proxy_http_transport_field(other) && obj[key].is_null() => {}
            "compression" if obj[key] == Value::Bool(false) => {}
            other if ignorable_reverse_proxy_http_transport_field(other) => {
                let warning = format!(
                    "ignoring reverse_proxy.transport.{other}: transport tuning cannot be represented by generated eBPF middleware"
                );
                if !warnings.contains(&warning) {
                    warnings.push(warning);
                }
            }
            other => bail!("unsupported reverse_proxy.transport field {other:?}"),
        }
    }
    if let Some(tls) = obj.get("tls") {
        if tls.is_null() {
            return Ok(());
        }
        let tls = tls
            .as_object()
            .ok_or_else(|| anyhow!("reverse_proxy.transport.tls must be an object"))?;
        if !tls.is_empty() {
            bail!(
                "unsupported reverse_proxy.transport.tls fields: upstream TLS customization cannot be represented by zs_reverse_proxy"
            );
        }
    }
    Ok(())
}

fn ignorable_reverse_proxy_http_transport_field(key: &str) -> bool {
    matches!(
        key,
        "keep_alive"
            | "max_conns_per_host"
            | "dial_timeout"
            | "dial_fallback_delay"
            | "response_header_timeout"
            | "expect_continue_timeout"
            | "max_response_header_size"
            | "write_buffer_size"
            | "read_buffer_size"
            | "read_timeout"
            | "write_timeout"
    )
}

fn unsupported_reverse_proxy_http_transport_field(key: &str) -> bool {
    matches!(
        key,
        "resolver"
            | "keep_alive"
            | "compression"
            | "max_conns_per_host"
            | "proxy_protocol"
            | "forward_proxy_url"
            | "dial_timeout"
            | "dial_fallback_delay"
            | "response_header_timeout"
            | "expect_continue_timeout"
            | "max_response_header_size"
            | "write_buffer_size"
            | "read_buffer_size"
            | "read_timeout"
            | "write_timeout"
            | "versions"
            | "local_address"
            | "network_proxy"
    )
}

fn reverse_proxy_transport_compression_off(transport: Option<&Value>) -> bool {
    transport
        .and_then(Value::as_object)
        .and_then(|obj| obj.get("compression"))
        .is_some_and(|compression| compression == &Value::Bool(false))
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

fn contains_placeholder(s: &str) -> bool {
    s.contains('{') || s.contains('}')
}

fn contains_caddy_placeholder(s: &str) -> bool {
    let mut rest = s;
    while let Some(start) = rest.find('{') {
        let after_start = &rest[start + 1..];
        let Some(end) = after_start.find('}') else {
            return false;
        };
        if end > 0 {
            return true;
        }
        rest = &after_start[end + 1..];
    }
    false
}

fn caddy_provision_replace_all(input: &str) -> String {
    if !input.contains('{') && !input.contains('}') {
        return input.to_string();
    }

    let mut out = String::with_capacity(input.len());
    let mut last = 0;
    let mut i = 0;
    let bytes = input.as_bytes();
    let mut unclosed = 0;
    'scan: while i < bytes.len() {
        if i > 0 && bytes[i - 1] == b'\\' && matches!(bytes[i], b'{' | b'}') {
            out.push_str(&input[last..i - 1]);
            last = i;
            i += 1;
            continue;
        }
        if bytes[i] != b'{' {
            i += 1;
            continue;
        }
        if unclosed > 100 {
            return String::new();
        }

        let mut end = match input[i..].find('}') {
            Some(relative) => i + relative,
            None => {
                unclosed += 1;
                i += 1;
                continue;
            }
        };
        loop {
            if end == 0 || end >= bytes.len() - 1 || bytes[end - 1] != b'\\' {
                break;
            }
            match input[end + 1..].find('}') {
                Some(relative) => end += relative + 1,
                None => {
                    unclosed += 1;
                    i += 1;
                    continue 'scan;
                }
            }
        }

        out.push_str(&input[last..i]);
        let key = &input[i + 1..end];
        if let Some(value) = caddy_provision_placeholder_value(key) {
            out.push_str(&value);
        }
        i = end + 1;
        last = i;
    }

    out.push_str(&input[last..]);
    out
}

fn caddy_provision_placeholder_value(key: &str) -> Option<String> {
    if let Some(name) = key.strip_prefix("env.") {
        return Some(std::env::var(name).unwrap_or_default());
    }
    if let Some(filename) = key.strip_prefix("file.") {
        const MAX_FILE_PLACEHOLDER_SIZE: u64 = 1024 * 1024;
        let meta = fs::metadata(filename).ok()?;
        if meta.len() > MAX_FILE_PLACEHOLDER_SIZE {
            return Some(String::new());
        }
        let mut body = fs::read(filename).ok()?;
        if body.last() == Some(&b'\n') {
            body.pop();
        }
        if body.last() == Some(&b'\r') {
            body.pop();
        }
        return Some(String::from_utf8_lossy(&body).into_owned());
    }
    match key {
        "system.hostname" => Some(caddy_system_hostname().unwrap_or_default()),
        "system.slash" => Some(MAIN_SEPARATOR.to_string()),
        "system.os" => Some(caddy_go_os().to_string()),
        "system.wd" => Some(
            std::env::current_dir()
                .ok()
                .and_then(|path| path.into_os_string().into_string().ok())
                .unwrap_or_default(),
        ),
        "system.arch" => Some(caddy_go_arch().to_string()),
        "time.now" => {
            let now = chrono::Local::now();
            Some(now.format("%Y-%m-%d %H:%M:%S%.f %z").to_string())
        }
        "time.now.http" => Some(
            chrono::Utc::now()
                .format("%a, %d %b %Y %H:%M:%S GMT")
                .to_string(),
        ),
        "time.now.common_log" => Some(
            chrono::Local::now()
                .format("%d/%b/%Y:%H:%M:%S %z")
                .to_string(),
        ),
        _ => None,
    }
}

fn caddy_system_hostname() -> Option<String> {
    let mut buf = [0u8; 256];
    // SAFETY: `buf` is valid for writes of its full length and is NUL-terminated
    // below before conversion even when the hostname exactly fills the buffer.
    let rc = unsafe { libc::gethostname(buf.as_mut_ptr().cast(), buf.len()) };
    if rc != 0 {
        return None;
    }
    let len = buf.iter().position(|byte| *byte == 0).unwrap_or(buf.len());
    Some(String::from_utf8_lossy(&buf[..len]).into_owned())
}

fn caddy_go_os() -> &'static str {
    match std::env::consts::OS {
        "macos" => "darwin",
        other => other,
    }
}

fn caddy_go_arch() -> &'static str {
    match std::env::consts::ARCH {
        "x86_64" => "amd64",
        "x86" => "386",
        "aarch64" => "arm64",
        other => other,
    }
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

fn caddy_normalize_host_pattern(host: &str) -> Result<String> {
    idna::domain_to_ascii(host).with_context(|| format!("converting hostname {host:?} to ASCII"))
}

fn caddy_host_fuzzy(host: &str) -> bool {
    host.contains('*') || contains_placeholder(host)
}

fn upstream_to_url(dial: &str, transport: Option<&Value>) -> Result<String> {
    if dial.starts_with("http://") || dial.starts_with("https://") {
        if contains_placeholder(dial) {
            bail!("reverse_proxy upstream addresses with URL schemes cannot contain placeholders");
        }
        validate_caddy_upstream_url(dial)?;
        return Ok(dial.to_string());
    }
    if let Some((scheme, _)) = dial.split_once("://") {
        bail!("reverse_proxy upstream scheme {scheme:?} cannot be represented by zs_reverse_proxy");
    }
    if let Some((network, _)) = dial.split_once("//") {
        if matches!(
            network,
            "unix" | "unixgram" | "unixpacket" | "unix+h2c" | "fd"
        ) {
            bail!(
                "reverse_proxy upstream network {network:?} cannot be represented by zs_reverse_proxy"
            );
        }
    }
    let scheme = match transport.and_then(Value::as_object) {
        Some(obj) if obj.get("protocol").and_then(Value::as_str) == Some("http") => {
            if obj.get("tls").is_some_and(|tls| !tls.is_null()) {
                "https"
            } else {
                "http"
            }
        }
        Some(obj) if obj.get("protocol").and_then(Value::as_str) == Some("http_ntlm") => "http",
        Some(obj) => {
            bail!(
                "reverse_proxy transport {:?} cannot be represented by zs_reverse_proxy",
                obj.get("protocol")
                    .and_then(Value::as_str)
                    .unwrap_or("<missing>")
            )
        }
        None => "http",
    };
    Ok(format!("{scheme}://{dial}"))
}

fn reverse_proxy_transport_sets_host(url: &str) -> bool {
    url.starts_with("https://")
}

fn validate_caddy_upstream_url(dial: &str) -> Result<()> {
    let url = url::Url::parse(dial)
        .with_context(|| format!("parsing reverse_proxy upstream URL {dial:?}"))?;
    let after_scheme = dial.split_once("://").map(|(_, rest)| rest).unwrap_or(dial);
    if after_scheme.contains('/')
        || after_scheme.contains('?')
        || after_scheme.contains('#')
        || url.query().is_some()
        || url.fragment().is_some()
    {
        bail!("reverse_proxy upstream URLs only support scheme, host, and port components");
    }
    match (url.scheme(), url.port()) {
        ("http", Some(443)) => {
            bail!("reverse_proxy upstream has conflicting scheme \"http\" and HTTPS port 443")
        }
        ("https", Some(80)) => {
            bail!("reverse_proxy upstream has conflicting scheme \"https\" and HTTP port 80")
        }
        _ => {}
    }
    Ok(())
}

fn c_str(s: &str) -> String {
    let mut out = String::from("\"");
    for b in s.bytes() {
        match b {
            b'\\' => out.push_str("\\\\"),
            b'"' => out.push_str("\\\""),
            b'\n' => out.push_str("\\n"),
            b'\r' => out.push_str("\\r"),
            b'\t' => out.push_str("\\t"),
            0x20..=0x7e => out.push(b as char),
            _ => out.push_str(&format!("\\{b:03o}")),
        }
    }
    out.push('"');
    out
}

fn c_comment(s: &str) -> String {
    s.replace("*/", "* /")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn c_string_uses_bounded_octal_for_non_ascii() {
        assert_eq!(c_str("café1"), "\"caf\\303\\2511\"");
    }

    #[test]
    fn compiles_static_response_route() {
        let source = r#"{
          "apps": {"http": {"servers": {"srv0": {"routes": [{
            "match": [{"method": ["GET"], "path": ["/health"]}],
            "handle": [{"handler": "static_response", "status_code": 200, "body": "{\"ok\":true}"}],
            "terminal": true
          }]}}}}
        }"#;

        let c = compile_caddy_json(source).unwrap();
        assert!(c.contains("zs_req_method"));
        assert!(c.contains("zs_caddy_path_match(\"/health\""));
        assert!(c.contains("zs_caddy_respond_static(\"200\""));
        assert!(c.contains("ok"));
    }

    #[test]
    fn emits_caddy_empty_handler_default_response() {
        let source = r#"{
          "apps": {"http": {"servers": {"srv0": {}}}}
        }"#;

        let c = compile_caddy_json(source).unwrap();
        assert!(c.contains("Caddy emptyHandler"), "{c}");
        assert!(
            c.contains("zs_caddy_respond_static(\"200\", 3, \"{}\", 2);"),
            "{c}"
        );

        let source = r#"{
          "apps": {"http": {"servers": {"srv0": {"routes": [{
            "match": [{"path": ["/handled"]}],
            "handle": [{"handler": "static_response", "status_code": 204}],
            "terminal": true
          }]}}}}
        }"#;

        let c = compile_caddy_json(source).unwrap();
        assert!(c.contains("zs_caddy_path_match(\"/handled\""), "{c}");
        assert!(c.contains("Caddy emptyHandler"), "{c}");
    }

    #[test]
    fn emits_caddy_empty_handler_for_terminal_nonresponding_routes() {
        let source = r#"{
          "apps": {"http": {"servers": {"srv0": {"routes": [{
            "terminal": true,
            "handle": [{"handler": "headers", "request": {"set": {"X-Test": ["yes"]}}}]
          }]}}}}
        }"#;

        let c = compile_caddy_json(source).unwrap();
        assert!(
            c.contains("Caddy terminal route reached emptyHandler"),
            "{c}"
        );
        assert!(c.contains("zs_req_set_header(\"X-Test\""), "{c}");
        assert!(
            c.contains("zs_caddy_respond_static(\"200\", 3, \"{}\", 2);"),
            "{c}"
        );

        let source = r#"{
          "apps": {"http": {"servers": {"srv0": {"routes": [{
            "handle": [{"handler": "subroute", "routes": [{
              "terminal": true,
              "handle": [{"handler": "vars", "root": "/srv/site"}]
            }]}]
          }]}}}}
        }"#;

        let c = compile_caddy_json(source).unwrap();
        assert!(
            c.contains("Caddy terminal subroute reached emptyHandler"),
            "{c}"
        );
        assert!(c.contains("zs_caddy_vars_set"), "{c}");
    }

    #[test]
    fn emits_caddy_empty_handler_for_terminal_named_routes() {
        let source = r#"{
          "apps": {"http": {"servers": {"srv0": {
            "named_routes": {
              "shared": {
                "terminal": true,
                "handle": [{"handler": "headers", "request": {"set": {"X-Named": ["yes"]}}}]
              }
            },
            "routes": [{
              "handle": [
                {"handler": "invoke", "name": "shared"},
                {"handler": "static_response", "status_code": 204}
              ]
            }]
          }}}}
        }"#;

        let c = compile_caddy_json(source).unwrap();
        assert!(
            c.contains("Caddy terminal named route reached emptyHandler"),
            "{c}"
        );
        assert!(c.contains("zs_req_set_header(\"X-Named\""), "{c}");
        assert!(
            c.contains("zs_caddy_respond_static(\"200\", 3, \"{}\", 2);"),
            "{c}"
        );
    }

    #[test]
    fn emits_caddy_error_empty_handler_for_terminal_named_routes() {
        let source = r#"{
          "apps": {"http": {"servers": {"srv0": {
            "named_routes": {
              "shared": {
                "terminal": true,
                "handle": [{"handler": "headers", "request": {"set": {"X-Error-Named": ["yes"]}}}]
              }
            },
            "routes": [{
              "handle": [{"handler": "error", "status_code": 418}]
            }],
            "errors": {
              "routes": [{
                "handle": [{"handler": "invoke", "name": "shared"}]
              }]
            }
          }}}}
        }"#;

        let c = compile_caddy_json(source).unwrap();
        assert!(
            c.contains("Caddy terminal named route reached errorEmptyHandler"),
            "{c}"
        );
        assert!(c.contains("zs_req_set_header(\"X-Error-Named\""), "{c}");
        assert!(
            c.contains("zs_caddy_respond(\"{http.error.status_code}\", 24, \"\", 0);"),
            "{c}"
        );
    }

    #[test]
    fn emits_caddy_error_empty_handler_for_terminal_subroutes() {
        let source = r#"{
          "apps": {"http": {"servers": {"srv0": {
            "routes": [{
              "handle": [{"handler": "error", "status_code": 418}]
            }],
            "errors": {
              "routes": [{
                "handle": [{"handler": "subroute", "routes": [{
                  "terminal": true,
                  "handle": [{"handler": "vars", "root": "/srv/errors"}]
                }]}]
              }]
            }
          }}}}
        }"#;

        let c = compile_caddy_json(source).unwrap();
        assert!(
            c.contains("Caddy terminal subroute reached errorEmptyHandler"),
            "{c}"
        );
        assert!(c.contains("zs_caddy_vars_set"), "{c}");
        assert!(
            c.contains("zs_caddy_respond(\"{http.error.status_code}\", 24, \"\", 0);"),
            "{c}"
        );
    }

    #[test]
    fn compiles_static_response_abort() {
        let source = r#"{
          "apps": {"http": {"servers": {"srv0": {"routes": [{
            "handle": [{"handler": "static_response", "abort": true}]
          }]}}}}
        }"#;

        let c = compile_caddy_json(source).unwrap();
        assert!(c.contains("zs_abort();"));
        assert!(!c.contains("zs_caddy_respond("));
    }

    #[test]
    fn rejects_too_many_top_level_route_groups() {
        let routes = (0..33)
            .map(|idx| {
                serde_json::json!({
                    "group": format!("g{idx}"),
                    "handle": [{"handler": "static_response", "status_code": 204}]
                })
            })
            .collect::<Vec<_>>();
        let source = serde_json::json!({
            "apps": {"http": {"servers": {"srv0": {"routes": routes}}}}
        })
        .to_string();

        let err = compile_caddy_json(&source).unwrap_err().to_string();
        assert!(
            err.contains("Caddy route groups exceed generated eBPF middleware limit of 32"),
            "{err}"
        );
    }

    #[test]
    fn rejects_too_many_handle_response_route_groups() {
        let routes = (0..32)
            .map(|idx| {
                serde_json::json!({
                    "group": format!("g{idx}"),
                    "handle": [{"handler": "headers", "response": {"set": {"X-Test": ["yes"]}}}]
                })
            })
            .collect::<Vec<_>>();
        let source = serde_json::json!({
            "apps": {"http": {"servers": {"srv0": {"routes": [{
                "group": "top",
                "handle": [{"handler": "headers", "request": {"set": {"X-Test": ["yes"]}}}]
            }, {
                "handle": [{
                    "handler": "reverse_proxy",
                    "upstreams": [{"dial": "127.0.0.1:8081"}],
                    "handle_response": [{"match": {"status_code": [2]}, "routes": routes}]
                }]
            }]}}}}
        })
        .to_string();

        let err = compile_caddy_json(&source).unwrap_err().to_string();
        assert!(
            err.contains("Caddy route groups exceed generated eBPF middleware limit of 32"),
            "{err}"
        );
    }

    #[test]
    fn rejects_nonterminal_reverse_proxy_handle_response_routes_that_suppress_body() {
        let source = r#"{
          "apps": {"http": {"servers": {"srv0": {"routes": [{
            "handle": [{
              "handler": "reverse_proxy",
              "upstreams": [{"dial": "127.0.0.1:8081"}],
              "handle_response": [{"match": {"status_code": [2]}, "routes": [{
                "handle": [{"handler": "headers", "response": {"set": {"X-First": ["yes"]}}}]
              }, {
                "handle": [{"handler": "headers", "response": {"set": {"X-Second": ["yes"]}}}],
                "terminal": true
              }]}]
            }]
          }]}}}}
        }"#;

        let err = compile_caddy_json(source).unwrap_err().to_string();
        assert!(
            err.contains("reverse_proxy.handle_response routes suppress upstream response bodies"),
            "{err}"
        );
    }

    #[test]
    fn rejects_grouped_reverse_proxy_handle_response_routes_that_suppress_body() {
        let source = r#"{
          "apps": {"http": {"servers": {"srv0": {"routes": [{
            "handle": [{
              "handler": "reverse_proxy",
              "upstreams": [{"dial": "127.0.0.1:8081"}],
              "handle_response": [{"match": {"status_code": [2]}, "routes": [{
                "group": "choice",
                "handle": [{"handler": "headers", "response": {"set": {"X-First": ["yes"]}}}]
              }, {
                "group": "choice",
                "handle": [{"handler": "headers", "response": {"set": {"X-Second": ["yes"]}}}]
              }]}]
            }]
          }]}}}}
        }"#;

        let err = compile_caddy_json(source).unwrap_err().to_string();
        assert!(
            err.contains("reverse_proxy.handle_response routes suppress upstream response bodies"),
            "{err}"
        );
    }

    #[test]
    fn compiles_static_response_repeated_headers() {
        let source = r#"{
          "apps": {"http": {"servers": {"srv0": {"routes": [{
            "handle": [{"handler": "static_response", "status_code": 204, "headers": {
              "Set-Cookie": ["a=1", "b=2"]
            }}]
          }]}}}}
        }"#;

        let c = compile_caddy_json(source).unwrap();
        assert!(c.contains("zs_caddy_respond_static(\"204\""));
        assert!(c.contains("Set-Cookie"));
        assert!(c.contains("a=1"));
        assert!(c.contains("b=2"));
        assert!(!c.contains("\"a=1,b=2\""), "{c}");
    }

    #[test]
    fn compiles_case_sensitive_method_matcher() {
        let source = r#"{
          "apps": {"http": {"servers": {"srv0": {"routes": [{
            "match": [{"method": ["get"]}],
            "handle": [{"handler": "static_response", "status_code": 200, "body": "lower"}]
          }, {
            "handle": [{"handler": "static_response", "status_code": 404, "body": "fallback"}]
          }]}}}}
        }"#;

        let c = compile_caddy_json(source).unwrap();
        assert!(c.contains("zs_caddy_eq(method_"));
        assert!(!c.contains("zs_caddy_eq_fold(method_"), "{c}");
    }

    #[test]
    fn compiles_static_response_null_scalars_like_caddy_json() {
        let source = r#"{
          "apps": {"http": {"servers": {"srv0": {"routes": [{
            "handle": [{"handler": "static_response", "status_code": null, "body": null, "headers": null, "close": null, "abort": null}]
          }]}}}}
        }"#;

        let c = compile_caddy_json(source).unwrap();
        assert!(c.contains("zs_caddy_respond_static(\"\", 0"), "{c}");
        assert!(c.contains("\\\"body\\\":\\\"\\\""), "{c}");
        assert!(!c.contains("\\\"headers\\\""), "{c}");
        assert!(!c.contains("\\\"close\\\""), "{c}");
        assert!(!c.contains("zs_abort();"), "{c}");
    }

    #[test]
    fn compiles_static_response_null_header_values_like_caddy_json() {
        let source = r#"{
          "apps": {"http": {"servers": {"srv0": {"routes": [{
            "handle": [{"handler": "static_response", "headers": {"X-Empty": null, "X-Blank": [null], "X-Mixed": ["a", null, "b"]}}]
          }]}}}}
        }"#;

        let c = compile_caddy_json(source).unwrap();
        assert!(c.contains("\\\"X-Empty\\\":[]"), "{c}");
        assert!(c.contains("\\\"X-Blank\\\":[\\\"\\\"]"), "{c}");
        assert!(
            c.contains("\\\"X-Mixed\\\":[\\\"a\\\",\\\"\\\",\\\"b\\\"]"),
            "{c}"
        );
    }

    #[test]
    fn compiles_empty_string_list_matchers_as_never_match() {
        for (matcher, config) in [
            ("method", "[]"),
            ("method", "null"),
            ("path", "[]"),
            ("path", "null"),
            ("host", "[]"),
            ("host", "null"),
        ] {
            let source = format!(
                r#"{{
                  "apps": {{"http": {{"servers": {{"srv0": {{"routes": [{{
                    "match": [{{"{matcher}": {config}}}],
                    "handle": [{{"handler": "static_response", "status_code": 204}}]
                  }}]}}}}}}}}
                }}"#
            );

            let c = compile_caddy_json(&source).unwrap();
            assert!(c.contains("if ((((0)))) {"), "{matcher}: {c}");
            assert!(!c.contains("if ((())) {"), "{matcher}: {c}");
        }
    }

    #[test]
    fn rejects_unknown_supported_handler_fields() {
        for (handler, field, value, expected) in [
            (
                "static_response",
                "unknown",
                "true",
                "unsupported static_response field \"unknown\"",
            ),
            (
                "headers",
                "unknown",
                "true",
                "unsupported headers field \"unknown\"",
            ),
            (
                "request_body",
                "unknown",
                "true",
                "unsupported request_body field \"unknown\"",
            ),
            (
                "rewrite",
                "unknown",
                "true",
                "unsupported rewrite field \"unknown\"",
            ),
        ] {
            let source = format!(
                r#"{{
                  "apps": {{"http": {{"servers": {{"srv0": {{"routes": [{{
                    "handle": [{{"handler": "{handler}", "{field}": {value}}}]
                  }}]}}}}}}}}
                }}"#
            );

            let err = compile_caddy_json(&source).unwrap_err().to_string();
            assert!(err.contains(expected), "{handler}: {err}");
        }
    }

    #[test]
    fn rejects_invalid_static_response_field_types() {
        for (field, expected) in [
            (r#""body": 1"#, "static_response.body must be a string"),
            (
                r#""close": "yes""#,
                "static_response.close must be a boolean",
            ),
            (r#""abort": 1"#, "static_response.abort must be a boolean"),
            (
                r#""headers": []"#,
                "static_response.headers must be an object",
            ),
            (
                r#""headers": {"X-Test": "ok"}"#,
                "static_response.headers values must be arrays",
            ),
            (
                r#""headers": {"X-Test": [1]}"#,
                "static_response.headers values must contain only strings",
            ),
        ] {
            let source = format!(
                r#"{{
                  "apps": {{"http": {{"servers": {{"srv0": {{"routes": [{{
                    "handle": [{{"handler": "static_response", {field}}}]
                  }}]}}}}}}}}
                }}"#
            );

            let err = compile_caddy_json(&source).unwrap_err().to_string();
            assert!(err.contains(expected), "{field}: {err}");
        }
    }

    #[test]
    fn handles_caddy_weak_string_status_values() {
        let source = r#"{
          "apps": {"http": {"servers": {"srv0": {"routes": [{
            "handle": [{"handler": "static_response", "status_code": null, "body": "ok"}]
          }]}}}}
        }"#;
        let c = compile_caddy_json(source).unwrap();
        assert!(c.contains("zs_caddy_respond_static(\"\""), "{c}");

        let source = r#"{
          "apps": {"http": {"servers": {"srv0": {"routes": [{
            "handle": [{"handler": "static_response", "status_code": true, "body": "bad"}]
          }]}}}}
        }"#;
        let c = compile_caddy_json(source).unwrap();
        assert!(c.contains("zs_caddy_respond_static(\"true\""), "{c}");

        let source = r#"{
          "apps": {"http": {"servers": {"srv0": {"routes": [{
            "handle": [{"handler": "file_server", "status_code": true}]
          }]}}}}
        }"#;
        let c = compile_caddy_json(source).unwrap();
        assert!(c.contains("\\\"status_code\\\":\\\"true\\\""), "{c}");

        let source = r#"{
          "apps": {"http": {"servers": {"srv0": {"routes": [{
            "handle": [{"handler": "error", "status_code": true}]
          }]}}}}
        }"#;
        let c = compile_caddy_json(source).unwrap();
        assert!(c.contains("zs_caddy_respond(\"true\""), "{c}");
    }

    #[test]
    fn compiles_file_server_default_filesystem_alias() {
        let source = r#"{
          "apps": {"http": {"servers": {"srv0": {"routes": [{
            "handle": [{"handler": "file_server", "fs": "default", "root": "public"}]
          }]}}}}
        }"#;

        let c = compile_caddy_json(source).unwrap();
        assert!(c.contains("\\\"fs\\\":\\\"default\\\""), "{c}");
    }

    #[test]
    fn rejects_unknown_nested_header_and_rewrite_fields() {
        let source = r#"{
          "apps": {"http": {"servers": {"srv0": {"routes": [{
            "handle": [{"handler": "headers", "request": {"replace": {"X-Test": [{"search": "a", "unknown": true}]}}}]
          }]}}}}
        }"#;

        let err = compile_caddy_json(source).unwrap_err().to_string();
        assert!(err.contains("unsupported headers.request.replace field \"unknown\""));

        let source = r#"{
          "apps": {"http": {"servers": {"srv0": {"routes": [{
            "handle": [{"handler": "rewrite", "uri_substring": [{"find": "a", "replace": "b", "unknown": true}]}]
          }]}}}}
        }"#;

        let err = compile_caddy_json(source).unwrap_err().to_string();
        assert!(err.contains("unsupported rewrite.uri_substring field \"unknown\""));

        let source = r#"{
          "apps": {"http": {"servers": {"srv0": {"routes": [{
            "handle": [{"handler": "rewrite", "query": {"set": [{"key": "a", "val": "b", "unknown": true}]}}]
          }]}}}}
        }"#;

        let err = compile_caddy_json(source).unwrap_err().to_string();
        assert!(err.contains("unsupported rewrite.query.set field \"unknown\""));
    }

    #[test]
    fn rejects_invalid_header_operation_field_types() {
        for (target, field, expected) in [
            (
                "request",
                r#""add": {"X-Test": "ok"}"#,
                "headers.request.add value must be an array of strings",
            ),
            (
                "request",
                r#""set": {"X-Test": [1]}"#,
                "headers.request.set value must contain only strings",
            ),
            (
                "request",
                r#""delete": "X-Test""#,
                "headers.request.delete must be an array of strings",
            ),
            (
                "response",
                r#""add": {"X-Test": "ok"}"#,
                "headers.response.add value must be an array of strings",
            ),
            (
                "response",
                r#""set": {"X-Test": [1]}"#,
                "headers.response.set value must contain only strings",
            ),
            (
                "response",
                r#""delete": "X-Test""#,
                "headers.response.delete must be an array of strings",
            ),
            (
                "response",
                r#""require": {"headers": {"X-Test": "ok"}}"#,
                "headers.response.require header value must be an array of strings",
            ),
            (
                "response",
                r#""replace": null, "deferred": "true""#,
                "headers.response.deferred must be a boolean",
            ),
        ] {
            let source = format!(
                r#"{{
                  "apps": {{"http": {{"servers": {{"srv0": {{"routes": [{{
                    "handle": [{{"handler": "headers", "{target}": {{{field}}}}}]
                  }}]}}}}}}}}
                }}"#
            );
            let err = compile_caddy_json(&source).unwrap_err().to_string();
            assert!(err.contains(expected), "{target} {field}: {err}");
        }
    }

    #[test]
    fn rejects_invalid_header_replace_semantics_on_all_paths() {
        for (target, field, expected) in [
            (
                "request",
                r#""replace": {"X-Test": [{"search": "a", "search_regexp": "a+", "replace": "b"}]}"#,
                "headers.request.replace cannot specify both search and search_regexp",
            ),
            (
                "response",
                r#""replace": {"X-Test": [{"search": "a", "search_regexp": "a+", "replace": "b"}]}"#,
                "headers.response.replace cannot specify both search and search_regexp",
            ),
            (
                "response",
                r#""replace": {"X-Test": [{"search_regexp": "(", "replace": "b"}]}"#,
                "invalid headers.response.replace.search_regexp",
            ),
            (
                "request",
                r#""replace": {"X-Test": [{"search_regexp": "[", "replace": "b"}]}"#,
                "invalid headers.request.replace.search_regexp",
            ),
            (
                "response",
                r#""replace": {"X-Test": [{"search_regexp": "[", "replace": "b"}]}"#,
                "invalid headers.response.replace.search_regexp",
            ),
        ] {
            let source = format!(
                r#"{{
                  "apps": {{"http": {{"servers": {{"srv0": {{"routes": [{{
                    "handle": [{{"handler": "headers", "{target}": {{{field}}}}}]
                  }}]}}}}}}}}
                }}"#
            );
            let err = compile_caddy_json(&source).unwrap_err().to_string();
            assert!(err.contains(expected), "{target} {field}: {err}");
        }
    }

    #[test]
    fn rejects_invalid_request_body_field_types() {
        for (field, expected) in [
            (
                r#""max_size": "8""#,
                "request_body.max_size must be an integer",
            ),
            (
                r#""read_timeout": "1s""#,
                "request_body.read_timeout must be an integer duration",
            ),
            (
                r#""write_timeout": "1s""#,
                "request_body.write_timeout must be an integer duration",
            ),
            (r#""set": 1"#, "request_body.set must be a string"),
        ] {
            let source = format!(
                r#"{{
                  "apps": {{"http": {{"servers": {{"srv0": {{"routes": [{{
                    "handle": [{{"handler": "request_body", {field}}}]
                  }}]}}}}}}}}
                }}"#
            );
            let err = compile_caddy_json(&source).unwrap_err().to_string();
            assert!(err.contains(expected), "{field}: {err}");
        }
    }

    #[test]
    fn rejects_invalid_rewrite_field_types() {
        for (field, expected) in [
            (r#""method": 1"#, "rewrite.method must be a string"),
            (r#""uri": 1"#, "rewrite.uri must be a string"),
            (
                r#""strip_path_prefix": 1"#,
                "rewrite.strip_path_prefix must be a string",
            ),
            (
                r#""strip_path_suffix": 1"#,
                "rewrite.strip_path_suffix must be a string",
            ),
            (
                r#""uri_substring": {"find": "a"}"#,
                "rewrite.uri_substring must be an array",
            ),
            (
                r#""uri_substring": [{"find": 1}]"#,
                "rewrite.uri_substring.find must be a string",
            ),
            (
                r#""uri_substring": [{"replace": 1}]"#,
                "rewrite.uri_substring.replace must be a string",
            ),
            (
                r#""uri_substring": [{"limit": "1"}]"#,
                "rewrite.uri_substring.limit must be an integer",
            ),
            (
                r#""path_regexp": {"find": "a"}"#,
                "rewrite.path_regexp must be an array",
            ),
            (
                r#""path_regexp": [{"find": 1}]"#,
                "rewrite.path_regexp.find must be a string",
            ),
            (
                r#""path_regexp": [{"replace": 1}]"#,
                "rewrite.path_regexp.replace must be a string",
            ),
            (
                r#""query": {"delete": "gone"}"#,
                "rewrite.query.delete must be an array of strings",
            ),
        ] {
            let source = format!(
                r#"{{
                  "apps": {{"http": {{"servers": {{"srv0": {{"routes": [{{
                    "handle": [{{"handler": "rewrite", {field}}}]
                  }}]}}}}}}}}
                }}"#
            );
            let err = compile_caddy_json(&source).unwrap_err().to_string();
            assert!(err.contains(expected), "{field}: {err}");
        }
    }

    #[test]
    fn rejects_unknown_route_fields() {
        let source = r#"{
          "apps": {"http": {"servers": {"srv0": {"routes": [{
            "unknown": true,
            "handle": [{"handler": "static_response", "status_code": 204}]
          }]}}}}
        }"#;

        let err = compile_caddy_json(source).unwrap_err().to_string();
        assert!(err.contains("unsupported server srv0 route 0 field \"unknown\""));

        let source = r#"{
          "apps": {"http": {"servers": {"srv0": {"routes": [{
            "handle": [{"handler": "subroute", "routes": [{"unknown": true, "handle": [{"handler": "static_response", "status_code": 204}]}]}]
          }]}}}}
        }"#;

        let err = compile_caddy_json(source).unwrap_err().to_string();
        assert!(err.contains("unsupported subroute route 0 field \"unknown\""));
    }

    #[test]
    fn compiles_null_route_containers_like_caddy_json() {
        let source = r#"{
          "apps": {"http": {"servers": {"srv0": {
            "routes": [
              {"group": null, "match": null, "handle": null, "terminal": null},
              {"handle": [{"handler": "static_response", "status_code": 204}]}
            ],
            "named_routes": null,
            "errors": {"routes": null}
          }}}}
        }"#;

        let c = compile_caddy_json(source).unwrap();
        assert!(c.contains("zs_caddy_respond_static(\"204\""), "{c}");
    }

    #[test]
    fn compiles_null_subroute_route_containers_like_caddy_json() {
        let source = r#"{
          "apps": {"http": {"servers": {"srv0": {"routes": [{
            "handle": [
              {"handler": "subroute", "routes": null, "errors": null},
              {"handler": "subroute"},
              {"handler": "static_response", "status_code": 204}
            ]
          }]}}}}
        }"#;

        let c = compile_caddy_json(source).unwrap();
        assert!(c.contains("zs_caddy_respond_static(\"204\""), "{c}");
    }

    #[test]
    fn rejects_unknown_matcher_object_fields() {
        for (matcher, config, expected) in [
            (
                "remote_ip",
                r#"{"ranges": ["127.0.0.1"], "unknown": true}"#,
                "unsupported http.matchers.remote_ip field \"unknown\"",
            ),
            (
                "client_ip",
                r#"{"ranges": ["127.0.0.1"], "unknown": true}"#,
                "unsupported http.matchers.client_ip field \"unknown\"",
            ),
            (
                "path_regexp",
                r#"{"pattern": ".*", "unknown": true}"#,
                "unsupported http.matchers.path_regexp field \"unknown\"",
            ),
            (
                "header_regexp",
                r#"{"X-Test": {"pattern": ".*", "unknown": true}}"#,
                "unsupported http.matchers.header_regexp field \"unknown\"",
            ),
            (
                "file",
                r#"{"try_files": ["/index.html"], "unknown": true}"#,
                "unsupported http.matchers.file field \"unknown\"",
            ),
        ] {
            let source = format!(
                r#"{{
                  "apps": {{"http": {{"servers": {{"srv0": {{"trusted_proxies": {{"source": "static", "ranges": ["127.0.0.1"]}}, "routes": [{{
                    "match": [{{"{matcher}": {config}}}],
                    "handle": [{{"handler": "static_response", "status_code": 204}}]
                  }}]}}}}}}}}
                }}"#
            );

            let err = compile_caddy_json(&source).unwrap_err().to_string();
            assert!(err.contains(expected), "{matcher}: {err}");
        }
    }

    #[test]
    fn compiles_static_error_route_without_error_routes() {
        let source = r#"{
          "apps": {"http": {"servers": {"srv0": {"routes": [{
            "match": [{"path": ["/err"]}],
            "handle": [{"handler": "error", "status_code": "{http.vars.status}", "error": "not-body"}]
          }]}}}}
        }"#;

        let c = compile_caddy_json(source).unwrap();
        assert!(c.contains("zs_caddy_respond(\"{http.vars.status}\""));
        assert!(!c.contains("not-body"));
    }

    #[test]
    fn compiles_null_static_error_fields_as_caddy_defaults() {
        let source = r#"{
          "apps": {"http": {"servers": {"srv0": {"routes": [{
            "handle": [{"handler": "error", "status_code": null, "error": null}]
          }]}}}}
        }"#;

        let c = compile_caddy_json(source).unwrap();
        assert!(c.contains("zs_caddy_respond(\"500\", 3"), "{c}");
    }

    #[test]
    fn rejects_invalid_static_error_message_type() {
        let source = r#"{
          "apps": {"http": {"servers": {"srv0": {"routes": [{
            "handle": [{"handler": "error", "error": 1}]
          }]}}}}
        }"#;

        let err = compile_caddy_json(source).unwrap_err().to_string();
        assert!(err.contains("error.error must be a string"), "{err}");
    }

    #[test]
    fn rejects_invalid_static_error_status_codes() {
        for status in [99, 1000] {
            let source = format!(
                r#"{{
                  "apps": {{"http": {{"servers": {{"srv0": {{"routes": [{{
                    "handle": [{{"handler": "error", "status_code": {status}}}]
                  }}]}}}}}}}}
                }}"#
            );

            let err = compile_caddy_json(&source).unwrap_err().to_string();
            assert!(err.contains("error.status_code must be 100..999"), "{err}");
        }
    }

    #[test]
    fn compiles_case_folded_multi_wildcard_path_matcher() {
        let source = r#"{
          "apps": {"http": {"servers": {"srv0": {"routes": [{
            "match": [{"path": ["/Foo/*/Bar*", "/assets/app.[0-9]?.css", "/escaped/%20"]}],
            "handle": [{"handler": "static_response", "status_code": 204}]
          }]}}}}
        }"#;

        let c = compile_caddy_json(source).unwrap();
        assert!(c.contains("zs_caddy_path_match("));
        assert!(c.contains("\"/Foo/*/Bar*\""));
        assert!(c.contains("\"/assets/app.[0-9]?.css\""));
        assert!(c.contains("\"/escaped/%20\""));
    }

    #[test]
    fn compiles_regex_matcher_captures_and_header_placeholders() {
        let source = r#"{
          "apps": {"http": {"servers": {"srv0": {"routes": [{
            "match": [{"path_regexp": {"name": "slug", "pattern": "^/items/([a-z0-9-]+)$"}}],
            "handle": [{"handler": "headers", "response": {"deferred": true, "set": {"X-Slug": ["{http.regexp.slug.1}"]}}}]
          }]}}}}
        }"#;

        let c = compile_caddy_json(source).unwrap();
        assert!(c.contains("zs_caddy_path_regexp_subject("));
        assert!(c.contains("zs_caddy_regex_match("));
        assert!(c.contains("zs_caddy_response_headers("));
        assert!(c.contains("{http.regexp.slug.1}"));
    }

    #[test]
    fn compiles_capture_matchers_before_placeholder_consumers() {
        let source = r#"{
          "apps": {"http": {"servers": {"srv0": {"routes": [{
            "match": [{
              "file": {"try_files": ["{http.regexp.mdpath.1}/index.md"]},
              "header": {"Accept": ["*text/markdown*"]},
              "path_regexp": {"name": "mdpath", "pattern": "^(.+?)/?$"}
            }],
            "handle": [{"handler": "static_response", "status_code": 204}]
          }]}}}}
        }"#;

        let c = compile_caddy_json(source).unwrap();
        let regex_pos = c.find("zs_caddy_regex_match(").expect("regex matcher");
        let file_pos = c.find("zs_caddy_file_match(").expect("file matcher");
        assert!(
            regex_pos < file_pos,
            "capture-producing matcher must run before file matcher:\n{c}"
        );
    }

    #[test]
    fn compiles_regex_matcher_quantifiers_with_braces() {
        let source = r#"{
          "apps": {"http": {"servers": {"srv0": {"routes": [{
            "match": [{"path_regexp": {"name": "slashes", "pattern": "^/a/{2,}b$"}}],
            "handle": [{"handler": "static_response", "status_code": 204}]
          }]}}}}
        }"#;

        let c = compile_caddy_json(source).unwrap();
        assert!(c.contains("^/a/{2,}b$"));
        assert!(c.contains("zs_caddy_regex_match("));
    }

    #[test]
    fn compiles_empty_regex_matcher_pattern() {
        let source = r#"{
          "apps": {"http": {"servers": {"srv0": {"routes": [{
            "match": [{"path_regexp": {"name": "empty", "pattern": ""}}],
            "handle": [{"handler": "static_response", "status_code": 204}]
          }]}}}}
        }"#;

        let c = compile_caddy_json(source).unwrap();
        assert!(c.contains("\\\"pattern\\\":\\\"\\\""));
        assert!(c.contains("zs_caddy_regex_match("));
    }

    #[test]
    fn compiles_header_regexp_matcher() {
        let source = r#"{
          "apps": {"http": {"servers": {"srv0": {"routes": [{
            "match": [{"header_regexp": {"X-Token": {"name": "tok", "pattern": "^Bearer (.+)$"}}}],
            "handle": [{"handler": "static_response", "status_code": 204}]
          }]}}}}
        }"#;

        let c = compile_caddy_json(source).unwrap();
        assert!(c.contains("zs_caddy_header_regexp_match(\"X-Token\""));
    }

    #[test]
    fn compiles_empty_header_matcher_maps_as_true() {
        for matcher in ["header", "header_regexp"] {
            let source = format!(
                r#"{{
                  "apps": {{"http": {{"servers": {{"srv0": {{"routes": [{{
                    "match": [{{"{matcher}": {{}}}}],
                    "handle": [{{"handler": "static_response", "status_code": 204}}]
                  }}]}}}}}}}}
                }}"#
            );

            let c = compile_caddy_json(&source).unwrap();
            assert!(c.contains("if (((1))) {"), "{matcher}: {c}");
            assert!(!c.contains("if ((())) {"), "{matcher}: {c}");
        }
    }

    #[test]
    fn compiles_supported_expression_matcher_subset() {
        let source = r#"{
          "apps": {"http": {"servers": {"srv0": {"routes": [{
            "match": [{"expression": {
              "expr": "(path('/api/' + {http.request.uri.query.suffix}) && method('GET', 'POST') && query({'de' + {http.request.uri.query.key}: ['de' + {http.request.uri.query.debug}]})) || query({{http.vars.query_key}: '1'}) || (true && {http.request.uri.query.cmp} == 'ok') || ({http.request.uri.query.code} in ['200', '204']) || ({http.request.uri.query.mode} in ['debug', 'trace']) || {http.request.header.X-Request-Id}.matches('^[0-9A-F-]+$') || !{http.request.header.X-Request-Id}.matches('^blocked$') || path_regexp('^/named/(.+)$') || protocol('HTTPs') || (host('example.test') && protocol('http') && header({'X-' + {http.request.uri.query.header}: ['debug', 'trace']}) && vars({'mo' + {http.request.uri.query.var_key}: 'debug'})) || vars({'\\{http.vars.mode}': 'debug'}) || (path_regexp('slug', '^/expr/(.+)$') && header_regexp('tok', 'X-Token', '^Bearer (.+)$') && vars_regexp('mode', '{http.vars.mode}', '^debug$') && remote_ip('127.0.0.1') && client_ip('127.0.0.1') && file({http.request.uri.path}) && file({'try_files': ['/index.html'], 'try_policy': 'first_exist'}))",
              "name": "api"
            }}],
            "handle": [{"handler": "static_response", "status_code": 204}]
          }]}}}}
        }"#;

        let c = compile_caddy_json(source).unwrap();
        assert!(c.contains("zs_caddy_path_match("), "{c}");
        assert!(c.contains("/api/{http.request.uri.query.suffix}"), "{c}");
        assert!(c.contains("zs_req_method("), "{c}");
        assert!(c.contains("zs_caddy_query_match("), "{c}");
        assert!(c.contains("de{http.request.uri.query.key}"), "{c}");
        assert!(c.contains("de{http.request.uri.query.debug}"), "{c}");
        assert!(c.contains("zs_caddy_query_match(\"{http.vars.query_key}\""));
        assert!(c.contains("zs_caddy_expr_eq("), "{c}");
        assert!(c.contains("{http.request.uri.query.cmp}"), "{c}");
        assert!(c.contains("zs_caddy_expr_in("), "{c}");
        assert!(c.contains("{http.request.uri.query.code}"), "{c}");
        assert!(c.contains("{http.request.uri.query.mode}"), "{c}");
        assert!(c.contains("expr_match_left_"), "{c}");
        assert!(c.contains("{http.request.header.X-Request-Id}"), "{c}");
        assert!(c.contains("blocked"), "{c}");
        assert!(c.contains("zs_caddy_host_match("), "{c}");
        assert!(c.contains("zs_req_is_tls() != 0"), "{c}");
        assert!(c.contains("zs_req_is_tls() == 0"), "{c}");
        assert!(c.contains("zs_caddy_header_match_expanded("), "{c}");
        assert!(c.contains("X-{http.request.uri.query.header}"), "{c}");
        assert!(c.contains("zs_caddy_vars_match_expanded_keys("), "{c}");
        assert!(c.contains("mo{http.request.uri.query.var_key}"), "{c}");
        assert!(c.contains("{http.vars.mode}"), "{c}");
        assert!(!c.contains("\\\\{http.vars.mode}"), "{c}");
        assert!(c.contains("zs_caddy_regex_match("), "{c}");
        assert!(
            c.contains("zs_caddy_header_regexp_match_expanded(\"X-Token\""),
            "{c}"
        );
        assert!(
            c.contains("zs_caddy_vars_regexp_match_expanded_keys("),
            "{c}"
        );
        assert!(c.contains("zs_req_remote_ip_matches("), "{c}");
        assert!(c.contains("zs_caddy_file_match("), "{c}");
        assert!(c.contains("{http.request.uri.path}"), "{c}");
        assert!(c.contains("\\\"name\\\":\\\"api\\\""), "{c}");
    }

    #[test]
    fn compiles_backtick_expression_string_literals() {
        let source = r#"{
          "apps": {"http": {"servers": {"srv0": {"routes": [{
            "match": [{"expression": "method(`GET`) && {http.request.uri.query.mode} == `debug`"}],
            "handle": [{"handler": "static_response", "status_code": 204}]
          }]}}}}
        }"#;

        let c = compile_caddy_json(source).unwrap();
        assert!(c.contains("zs_req_method("), "{c}");
        assert!(c.contains("\"GET\", 3"), "{c}");
        assert!(c.contains("{http.request.uri.query.mode}"), "{c}");
        assert!(c.contains("debug"), "{c}");
    }

    #[test]
    fn compiles_numeric_expression_matcher_comparisons() {
        let source = r#"{
          "apps": {"http": {"servers": {"srv0": {"routes": [{
            "match": [{"expression": "{http.error.status_code} >= 400 && {http.error.status_code} <= 499 && 500 > {http.error.status_code} && 399 < {http.error.status_code} && {http.error.status_code} in [404, 410]"}],
            "handle": [{"handler": "static_response", "status_code": 204}]
          }]}}}}
        }"#;

        let c = compile_caddy_json(source).unwrap();
        assert!(c.contains("zs_caddy_parse_u16(expr_num_left_"), "{c}");
        assert!(c.contains("expr_num_left_"), "{c}");
        assert!(c.contains(" >= expr_num_right_"), "{c}");
        assert!(c.contains(" <= expr_num_right_"), "{c}");
        assert!(c.contains(" > expr_num_right_"), "{c}");
        assert!(c.contains(" < expr_num_right_"), "{c}");
        assert!(c.contains("[\\\"404\\\",\\\"410\\\"]"), "{c}");
    }

    #[test]
    fn rejects_unsupported_expression_cel() {
        for config in [
            r#""path('/api/*') ? method('GET') : method('POST')""#,
            r#""header({'X-Mode': dynamic})""#,
            r#""protocol('http', 'https')""#,
            r#""file({'fs': 'file', 'try_files': ['/index.html']})""#,
            r#""{http.request.uri.query.enabled} == true""#,
        ] {
            let source = format!(
                r#"{{
                  "apps": {{"http": {{"servers": {{"srv0": {{"routes": [{{
                    "match": [{{"expression": {config}}}],
                    "handle": [{{"handler": "static_response", "status_code": 204}}]
                  }}]}}}}}}}}
                }}"#
            );

            let err = compile_caddy_json(&source).unwrap_err().to_string();
            assert!(
                err.contains("unsupported http.matchers.expression"),
                "{config}: {err}"
            );
        }
    }

    #[test]
    fn rejects_invalid_expression_matcher_config() {
        for (config, expected) in [
            ("1", "http.matchers.expression must be a string or object"),
            (
                r#"{"name": "api"}"#,
                "http.matchers.expression.expr is required",
            ),
            (
                r#"{"expr": 1}"#,
                "http.matchers.expression.expr must be a string",
            ),
            (
                r#"{"expr": "true", "name": 1}"#,
                "http.matchers.expression.name must be a string",
            ),
            (
                r#"{"expr": "true", "unknown": true}"#,
                "unsupported http.matchers.expression field \"unknown\"",
            ),
        ] {
            let source = format!(
                r#"{{
                  "apps": {{"http": {{"servers": {{"srv0": {{"routes": [{{
                    "match": [{{"expression": {config}}}],
                    "handle": [{{"handler": "static_response", "status_code": 204}}]
                  }}]}}}}}}}}
                }}"#
            );

            let err = compile_caddy_json(&source).unwrap_err().to_string();
            assert!(err.contains(expected), "{config}: {err}");
        }
    }

    #[test]
    fn compiles_empty_not_matcher_as_true() {
        let source = r#"{
          "apps": {"http": {"servers": {"srv0": {"routes": [{
            "match": [{"not": []}],
            "handle": [{"handler": "static_response", "status_code": 204}]
          }]}}}}
        }"#;

        let c = compile_caddy_json(source).unwrap();
        assert!(!c.contains("!()"));
        assert!(c.contains("zs_caddy_respond_static("));
    }

    #[test]
    fn compiles_normalized_host_matcher() {
        let source = r#"{
          "apps": {"http": {"servers": {"srv0": {"routes": [{
            "handle": [{"handler": "vars", "host_pat": "*.Example.COM"}]
          }, {
            "match": [{"host": ["*.Example.COM", "{http.vars.host_pat}"]}],
            "handle": [{"handler": "static_response", "status_code": 204}]
          }]}}}}
        }"#;

        let c = compile_caddy_json(source).unwrap();
        assert!(c.contains("zs_caddy_host_normalize(host_"));
        assert!(c.contains("zs_caddy_host_match(host_"));
        assert!(c.contains("zs_caddy_expand(\"{http.vars.host_pat}\""));
        assert!(c.contains("\"*.example.com\""));
    }

    #[test]
    fn compiles_idna_host_matcher() {
        let source = r#"{
          "apps": {"http": {"servers": {"srv0": {"routes": [{
            "match": [{"host": ["exämple.com", "*.bücher.example"]}],
            "handle": [{"handler": "static_response", "status_code": 204}]
          }]}}}}
        }"#;

        let c = compile_caddy_json(source).unwrap();
        assert!(c.contains("\"xn--exmple-cua.com\""));
        assert!(c.contains("\"*.xn--bcher-kva.example\""));
    }

    #[test]
    fn rejects_duplicate_normalized_host_matcher() {
        let source = r#"{
          "apps": {"http": {"servers": {"srv0": {"routes": [{
            "match": [{"host": ["EXAMPLE.com", "example.com"]}],
            "handle": [{"handler": "static_response", "status_code": 204}]
          }]}}}}
        }"#;

        let err = compile_caddy_json(source).unwrap_err().to_string();
        assert!(err.contains("duplicate host matcher"));
    }

    #[test]
    fn compiles_remote_ip_matcher() {
        let source = r#"{
          "apps": {"http": {"servers": {"srv0": {"routes": [{
            "match": [{"remote_ip": {"ranges": ["127.0.0.0/8", "::1"]}}],
            "handle": [{"handler": "static_response", "status_code": 204}]
          }]}}}}
        }"#;

        let c = compile_caddy_json(source).unwrap();
        assert!(c.contains("zs_req_remote_ip_matches("));
        assert!(c.contains("127.0.0.0/8"));
        assert!(c.contains("zs_req_tls_handshake_complete() == 0"));
        assert!(c.contains("zs_caddy_set_error(\"425\""));
        assert!(c.contains("zs_caddy_respond(\"425\""));
    }

    #[test]
    fn compiles_remote_ip_matcher_placeholders() {
        let source = r#"{
          "apps": {"http": {"servers": {"srv0": {"routes": [{
            "match": [{"remote_ip": {"ranges": ["{http.request.header.X-Range}"]}}],
            "handle": [{"handler": "static_response", "status_code": 204}]
          }]}}}}
        }"#;

        let c = compile_caddy_json(source).unwrap();
        assert!(c.contains("zs_caddy_remote_ip_matches("));
        assert!(c.contains("{http.request.header.X-Range}"));
        assert!(c.contains("TLS handshake not complete, remote IP cannot be verified"));
    }

    #[test]
    fn compiles_client_ip_matcher_without_trusted_proxies() {
        let source = r#"{
          "apps": {"http": {"servers": {"srv0": {"routes": [{
            "match": [{"client_ip": {"ranges": ["127.0.0.0/8", "::1"]}}],
            "handle": [{"handler": "static_response", "status_code": 204}]
          }]}}}}
        }"#;

        let c = compile_caddy_json(source).unwrap();
        assert!(c.contains("zs_req_remote_ip_matches("));
        assert!(c.contains("127.0.0.0/8"));
        assert!(c.contains("zs_req_tls_handshake_complete() == 0"));
    }

    #[test]
    fn compiles_ip_matcher_early_data_error_routes() {
        let source = r#"{
          "apps": {"http": {"servers": {"srv0": {
            "errors": {"routes": [{"handle": [{"handler": "static_response", "body": "handled {http.error.status_code}"}]}]},
            "routes": [{
              "match": [{"remote_ip": {"ranges": ["127.0.0.0/8"]}}],
              "handle": [{"handler": "static_response", "status_code": 204}]
            }]
          }}}}
        }"#;

        let c = compile_caddy_json(source).unwrap();
        assert!(c.contains("zs_caddy_set_error(\"425\""), "{c}");
        assert!(c.contains("handled {http.error.status_code}"), "{c}");
        assert!(c.contains("if (zs_response_pending() == 0)"), "{c}");
    }

    #[test]
    fn compiles_client_ip_matcher_placeholders() {
        let source = r#"{
          "apps": {"http": {"servers": {"srv0": {"routes": [{
            "match": [{"client_ip": {"ranges": ["{http.request.header.X-Range}"]}}],
            "handle": [{"handler": "static_response", "status_code": 204}]
          }]}}}}
        }"#;

        let c = compile_caddy_json(source).unwrap();
        assert!(c.contains("zs_caddy_remote_ip_matches("));
        assert!(c.contains("{http.request.header.X-Range}"));
    }

    #[test]
    fn compiles_file_matcher() {
        let source = r#"{
          "apps": {"http": {"servers": {"srv0": {"routes": [{
            "handle": [{"handler": "vars", "root": "public"}]
          }, {
            "match": [{"file": {"try_files": ["{http.request.uri.path}", "{http.request.uri.path}/index.html", "/assets/app.[0-9]*.css"], "split_path": [".php"]}}],
            "handle": [{"handler": "static_response", "status_code": 204}]
          }]}}}}
        }"#;

        let c = compile_caddy_json(source).unwrap();
        assert!(c.contains("zs_caddy_file_match("));
        assert!(c.contains("app.[0-9]*.css"));
        assert!(c.contains("split_path"));
    }

    #[test]
    fn compiles_file_matcher_literal_placeholder_split_path() {
        let source = r#"{
          "apps": {"http": {"servers": {"srv0": {"routes": [{
            "match": [{"file": {"try_files": ["{http.request.uri.path}"], "split_path": ["{http.vars.ext}"]}}],
            "handle": [{"handler": "static_response", "status_code": 204}]
          }]}}}}
        }"#;

        let c = compile_caddy_json(source).unwrap();
        assert!(c.contains("{http.vars.ext}"));
    }

    #[test]
    fn compiles_file_matcher_null_fields_like_caddy_json() {
        let source = r#"{
          "apps": {"http": {"servers": {"srv0": {"routes": [{
            "match": [{"file": {
              "fs": null,
              "root": null,
              "try_policy": null,
              "try_files": [null],
              "split_path": [null]
            }}],
            "handle": [{"handler": "static_response", "status_code": 204}]
          }]}}}}
        }"#;

        let c = compile_caddy_json(source).unwrap();
        assert!(c.contains("zs_caddy_file_match("), "{c}");
        assert!(c.contains("\\\"try_files\\\":[\\\"\\\"]"), "{c}");
        assert!(c.contains("\\\"split_path\\\":[\\\"\\\"]"), "{c}");
        assert!(!c.contains("\\\"fs\\\""), "{c}");
        assert!(!c.contains("\\\"root\\\""), "{c}");
        assert!(!c.contains("\\\"try_policy\\\""), "{c}");
    }

    #[test]
    fn compiles_file_matcher_null_slices_as_caddy_defaults() {
        let source = r#"{
          "apps": {"http": {"servers": {"srv0": {"routes": [{
            "match": [{"file": {"try_files": null, "split_path": null}}],
            "handle": [{"handler": "static_response", "status_code": 204}]
          }]}}}}
        }"#;

        let c = compile_caddy_json(source).unwrap();
        assert!(c.contains("zs_caddy_file_match("), "{c}");
        assert!(!c.contains("\\\"try_files\\\""), "{c}");
        assert!(!c.contains("\\\"split_path\\\""), "{c}");
    }

    #[test]
    fn compiles_file_matcher_relative_root_glob() {
        let source = r#"{
          "apps": {"http": {"servers": {"srv0": {"routes": [{
            "match": [{"file": {"root": "sites/*", "try_files": ["/index.html"]}}],
            "handle": [{"handler": "static_response", "status_code": 204}]
          }]}}}}
        }"#;

        let c = compile_caddy_json(source).unwrap();
        assert!(c.contains("zs_caddy_file_match("));
        assert!(c.contains("sites/*"));
    }

    #[test]
    fn compiles_file_matcher_status_fallback() {
        let source = r#"{
          "apps": {"http": {"servers": {"srv0": {"routes": [{
            "match": [{"file": {"try_files": ["/missing.txt", "=410"]}}],
            "handle": [{"handler": "static_response", "status_code": 204}]
          }]}}}}
        }"#;

        let c = compile_caddy_json(source).unwrap();
        assert!(c.contains("zs_caddy_file_match("));
        assert!(c.contains("=410"));
    }

    #[test]
    fn compiles_file_matcher_default_filesystem_alias() {
        let source = r#"{
          "apps": {"http": {"servers": {"srv0": {"routes": [{
            "match": [{"file": {"fs": "default", "root": "public", "try_files": ["/index.html"]}}],
            "handle": [{"handler": "static_response", "status_code": 204}]
          }]}}}}
        }"#;

        let c = compile_caddy_json(source).unwrap();
        assert!(c.contains("\\\"fs\\\":\\\"default\\\""), "{c}");
    }

    #[test]
    fn rejects_file_matcher_early_hints_status_fallback() {
        let source = r#"{
          "apps": {"http": {"servers": {"srv0": {"routes": [{
            "match": [{"file": {"try_files": ["/missing.txt", "=103"]}}],
            "handle": [{"handler": "static_response", "status_code": 204}]
          }]}}}}
        }"#;

        let err = compile_caddy_json(source).unwrap_err().to_string();
        assert!(
            err.contains("http.matchers.file try_files =103 Early Hints"),
            "{err}"
        );
    }

    #[test]
    fn rejects_invalid_file_matcher_field_types() {
        for (field, expected) in [
            (
                r#""try_files": "/index.html""#,
                "file matcher try_files must be an array of strings",
            ),
            (
                r#""try_files": [1]"#,
                "file matcher try_files must contain only strings",
            ),
            (
                r#""split_path": ".php""#,
                "file matcher split_path must be an array of strings",
            ),
            (
                r#""split_path": [1]"#,
                "file matcher split_path must contain only strings",
            ),
            (r#""fs": 1"#, "file matcher fs must be a string"),
            (r#""root": 1"#, "file matcher root must be a string"),
            (
                r#""try_policy": 1"#,
                "file matcher try_policy must be a string",
            ),
        ] {
            let source = format!(
                r#"{{
                  "apps": {{"http": {{"servers": {{"srv0": {{"routes": [{{
                    "match": [{{"file": {{{field}}}}}],
                    "handle": [{{"handler": "static_response", "status_code": 204}}]
                  }}]}}}}}}}}
                }}"#
            );

            let err = compile_caddy_json(&source).unwrap_err().to_string();
            assert!(err.contains(expected), "{field}: {err}");
        }
    }

    #[test]
    fn compiles_file_matcher_absolute_root_glob() {
        let source = r#"{
          "apps": {"http": {"servers": {"srv0": {"routes": [{
            "match": [{"file": {"root": "/srv/*", "try_files": ["/index.html"]}}],
            "handle": [{"handler": "static_response", "status_code": 204}]
          }]}}}}
        }"#;

        let c = compile_caddy_json(source).unwrap();
        assert!(c.contains("zs_caddy_file_match("));
        assert!(c.contains("/srv/*"));
    }

    #[test]
    fn compiles_protocol_and_tls_matchers() {
        let source = r#"{
          "apps": {"http": {"servers": {"srv0": {"routes": [{
            "match": [{"protocol": "http/2+", "tls": {"handshake_complete": true}}],
            "handle": [{"handler": "static_response", "status_code": 204}]
          }]}}}}
        }"#;

        let c = compile_caddy_json(source).unwrap();
        assert!(c.contains("zs_req_proto_major() >= 2"));
        assert!(c.contains("zs_req_is_tls() != 0"));
        assert!(c.contains("zs_req_tls_handshake_complete() != 0"));
    }

    #[test]
    fn compiles_tls_client_auth_policy_to_tls_section() {
        let source = r#"{
          "apps": {"http": {"servers": {"srv0": {
            "tls_connection_policies": [{
              "match": {"sni": ["example.com"]},
              "client_authentication": {
                "mode": "require_and_verify",
                "ca": {
                  "provider": "inline",
                  "trusted_ca_certs": ["AA=="]
                }
              }
            }],
            "routes": [{"handle": [{"handler": "static_response", "body": "ok"}]}]
          }}}}
        }"#;

        let c = compile_caddy_json(source).unwrap();
        assert!(c.contains("ZS_TLS_ENTRY"), "{c}");
        assert!(c.contains("zs_caddy_tls_client_auth"), "{c}");
        assert!(c.contains("zs_abort();"), "{c}");
        assert!(c.contains("example.com"), "{c}");
    }

    #[test]
    fn rejects_unsupported_tls_client_auth_shapes() {
        let source = r#"{
          "apps": {"http": {"servers": {"srv0": {
            "tls_connection_policies": [{
              "client_authentication": {
                "mode": "require_and_verify",
                "verifier": {"module": "leaf"}
              }
            }],
            "routes": [{"handle": [{"handler": "static_response", "body": "ok"}]}]
          }}}}
        }"#;

        let err = compile_caddy_json(source).unwrap_err().to_string();
        assert!(err.contains("client_authentication"), "{err}");
    }

    #[test]
    fn rejects_tls_early_data_matcher() {
        let source = r#"{
          "apps": {"http": {"servers": {"srv0": {"routes": [{
            "match": [{"tls": {"handshake_complete": false}}],
            "handle": [{"handler": "static_response", "status_code": 204}]
          }]}}}}
        }"#;

        let err = compile_caddy_json(source).unwrap_err().to_string();
        assert!(err.contains("handshake_complete=false"));
    }

    #[test]
    fn compiles_client_ip_matcher_with_static_trusted_proxies() {
        let source = r#"{
          "apps": {"http": {"servers": {"srv0": {
          "trusted_proxies": {"source": "static", "ranges": ["127.0.0.1"]},
          "client_ip_headers": ["X-Forwarded-For", "CF-Connecting-IP"],
          "trusted_proxies_strict": 1,
          "routes": [{
            "match": [{"client_ip": {"ranges": ["203.0.113.0/24"]}}],
            "handle": [{"handler": "static_response", "status_code": 204}]
          }]}}}}
        }"#;

        let c = compile_caddy_json(source).unwrap();
        assert!(c.contains("zs_caddy_client_ip_matches("));
        assert!(c.contains("203.0.113.0/24"));
        assert!(c.contains("X-Forwarded-For"));
        assert!(c.contains("CF-Connecting-IP"));
        assert!(c.contains("\\\"strict\\\":true"));
    }

    #[test]
    fn compiles_client_ip_options_without_trusted_proxies_like_caddy() {
        let source = r#"{
          "apps": {"http": {"servers": {"srv0": {
          "client_ip_headers": ["X-Real-IP"],
          "trusted_proxies_strict": 1,
          "trusted_proxies_unix": true,
          "routes": [{
            "match": [{"client_ip": {"ranges": ["203.0.113.0/24"]}}],
            "handle": [{"handler": "static_response", "status_code": 204}]
          }, {
            "handle": [{"handler": "reverse_proxy", "upstreams": [{"dial": "127.0.0.1:8080"}]}]
          }]}}}}
        }"#;

        let c = compile_caddy_json(source).unwrap();
        assert!(c.contains("zs_caddy_client_ip_matches("), "{c}");
        assert!(c.contains("X-Real-IP"), "{c}");
        assert!(c.contains("\\\"strict\\\":true"), "{c}");
        assert!(c.contains("\\\"trusted_unix\\\":true"), "{c}");
        assert!(c.contains("\\\"trusted_ranges\\\":[]"), "{c}");
        assert!(c.contains("\\\"server_trusted_proxies\\\":[]"), "{c}");
        assert!(c.contains("\\\"server_trusted_unix\\\":true"), "{c}");
    }

    #[test]
    fn compiles_null_client_ip_options_like_caddy_json() {
        let source = r#"{
          "apps": {"http": {"servers": {"srv0": {
          "client_ip_headers": null,
          "trusted_proxies_strict": null,
          "trusted_proxies_unix": null,
          "routes": [{
            "match": [{"client_ip": {"ranges": ["203.0.113.0/24"]}}],
            "handle": [{"handler": "static_response", "status_code": 204}]
          }]}}}}
        }"#;

        let c = compile_caddy_json(source).unwrap();
        assert!(c.contains("zs_caddy_client_ip_matches("), "{c}");
        assert!(c.contains("X-Forwarded-For"), "{c}");
        assert!(c.contains("\\\"strict\\\":false"), "{c}");
        assert!(c.contains("\\\"trusted_unix\\\":false"), "{c}");
    }

    #[test]
    fn compiles_caddy_private_ranges_for_static_trusted_proxies() {
        let source = r#"{
          "apps": {"http": {"servers": {"srv0": {
          "trusted_proxies": {"source": "static", "ranges": ["private_ranges"]},
          "routes": [{
            "match": [{"client_ip": {"ranges": ["203.0.113.0/24"]}}],
            "handle": [{"handler": "static_response", "status_code": 204}]
          }]}}}}
        }"#;

        let c = compile_caddy_json(source).unwrap();
        for range in [
            "192.168.0.0/16",
            "172.16.0.0/12",
            "10.0.0.0/8",
            "127.0.0.1/8",
            "fd00::/8",
            "::1",
        ] {
            assert!(c.contains(range), "{range}: {c}");
        }
    }

    #[test]
    fn compiles_vars_handler_and_matcher() {
        let source = r#"{
          "apps": {"http": {"servers": {"srv0": {"routes": [{
            "handle": [
              {"handler": "vars", "feature": "on", "slot_{http.request.uri.path.1}": "{http.request.uri.path.1}"},
              {"handler": "subroute", "routes": [{
                "match": [{"vars": {"feature": ["on"], "{http.vars.slot_foo}": ["{http.request.uri.path.1}"]}}],
                "handle": [{"handler": "static_response", "status_code": 204}]
              }]}
            ]
          }]}}}}
        }"#;

        let c = compile_caddy_json(source).unwrap();
        assert!(c.contains("zs_caddy_vars_set("));
        assert!(c.contains("zs_caddy_vars_match("));
        assert!(c.contains("slot_{http.request.uri.path.1}"));
        assert!(c.contains("{http.vars.slot_foo}"));
    }

    #[test]
    fn compiles_vars_handler_json_values() {
        let source = r#"{
          "apps": {"http": {"servers": {"srv0": {"routes": [{
            "handle": [
              {"handler": "vars", "enabled": true, "count": 3, "items": ["a", "b"], "empty": null},
              {"handler": "subroute", "routes": [{
                "match": [{"vars": {"enabled": ["true"], "count": ["3"], "items": ["[a b]"], "empty": [""]}}],
                "handle": [{"handler": "static_response", "status_code": 204}]
              }]}
            ]
          }]}}}}
        }"#;

        let c = compile_caddy_json(source).unwrap();
        assert!(c.contains("\\\"enabled\\\":true"));
        assert!(c.contains("\\\"count\\\":3"));
        assert!(c.contains("\\\"items\\\":[\\\"a\\\",\\\"b\\\"]"));
        assert!(c.contains("\\\"empty\\\":null"));
    }

    #[test]
    fn rejects_scalar_vars_matcher_values() {
        let source = r#"{
          "apps": {"http": {"servers": {"srv0": {"routes": [{
            "match": [{"vars": {"feature": "on"}}],
            "handle": [{"handler": "static_response", "status_code": 204}]
          }]}}}}
        }"#;

        let err = compile_caddy_json(source).unwrap_err().to_string();
        assert!(
            err.contains("vars matcher value must be an array of strings"),
            "{err}"
        );
    }

    #[test]
    fn compiles_vars_regexp_matcher() {
        let source = r#"{
          "apps": {"http": {"servers": {"srv0": {"routes": [{
            "handle": [
              {"handler": "vars", "feature": "abc-123"},
              {"handler": "subroute", "routes": [{
                "match": [{"vars_regexp": {"feature": {"name": "feat", "pattern": "^([a-z]+)-([0-9]+)$"}}}],
                "handle": [{"handler": "headers", "response": {"deferred": true, "set": {"X-Feature": ["{http.regexp.feat.2}"]}}}]
              }]}
            ]
          }]}}}}
        }"#;

        let c = compile_caddy_json(source).unwrap();
        assert!(c.contains("zs_caddy_vars_regexp_match("));
        assert!(c.contains("zs_caddy_response_headers("));
        assert!(c.contains("{http.regexp.feat.2}"));
    }

    #[test]
    fn compiles_caddy_accepted_punctuated_regexp_names() {
        let source = r#"{
          "apps": {"http": {"servers": {"srv0": {"routes": [{
            "match": [{"path_regexp": {"name": "slot-name", "pattern": "^/items/([0-9]+)$"}}],
            "handle": [{"handler": "static_response", "body": "{http.regexp.slot-name.1}"}]
          }, {
            "handle": [
              {"handler": "vars", "feature": "release-42"},
              {"handler": "subroute", "routes": [{
                "match": [{"vars_regexp": {"feature": {"name": "feat-name", "pattern": "^release-([0-9]+)$"}}}],
                "handle": [{"handler": "static_response", "body": "{http.regexp.feat-name.1}"}]
              }]}
            ]
          }]}}}}
        }"#;

        let c = compile_caddy_json(source).unwrap();
        assert!(c.contains("slot-name"));
        assert!(c.contains("feat-name"));
    }

    #[test]
    fn compiles_empty_vars_matcher_maps() {
        for (matcher, helper) in [
            ("vars", "zs_caddy_vars_match"),
            ("vars_regexp", "zs_caddy_vars_regexp_match"),
        ] {
            let source = format!(
                r#"{{
                  "apps": {{"http": {{"servers": {{"srv0": {{"routes": [{{
                    "match": [{{"{matcher}": {{}}}}],
                    "handle": [{{"handler": "static_response", "status_code": 204}}]
                  }}]}}}}}}}}
                }}"#
            );

            let c = compile_caddy_json(&source).unwrap();
            assert!(
                c.contains(&format!("{helper}(\"{{}}\", 2)")),
                "{matcher}: {c}"
            );
        }
    }

    #[test]
    fn compiles_vars_regexp_literal_keys_with_placeholder_syntax() {
        let source = r#"{
          "apps": {"http": {"servers": {"srv0": {"routes": [{
            "handle": [
              {"handler": "vars", "slot_{http.request.uri.path.1}": "release-42"},
              {"handler": "subroute", "routes": [{
                "match": [{"vars_regexp": {"slot_{http.request.uri.path.1}": {"name": "slot", "pattern": "^release-([0-9]+)$"}}}],
                "handle": [{"handler": "static_response", "status_code": 204}]
              }]}
            ]
          }]}}}}
        }"#;

        let c = compile_caddy_json(source).unwrap();
        assert!(c.contains("slot_{http.request.uri.path.1}"));
        assert!(c.contains("zs_caddy_vars_regexp_match("));
    }

    #[test]
    fn compiles_map_handler() {
        let source = r#"{
          "apps": {"http": {"servers": {"srv0": {"routes": [{
            "handle": [
              {"handler": "map", "source": "{http.request.uri.path}", "destinations": ["{mapped}"], "mappings": [
                {"input": "/foo", "outputs": ["FOO"]},
                {"input_regexp": "^/bar/(.*)$", "outputs": ["BAR-$1"]}
              ], "defaults": ["default"]},
              {"handler": "static_response", "body": "{mapped}"}
            ]
          }]}}}}
        }"#;

        let c = compile_caddy_json(source).unwrap();
        assert!(c.contains("zs_caddy_map("));
        assert!(c.contains("{mapped}"));
    }

    #[test]
    fn compiles_map_handler_with_empty_source() {
        let source = r#"{
          "apps": {"http": {"servers": {"srv0": {"routes": [{
            "handle": [
              {"handler": "map", "destinations": ["{mapped}"], "mappings": [
                {"input": "", "outputs": ["EMPTY"]}
              ], "defaults": ["default"]},
              {"handler": "static_response", "body": "{mapped}"}
            ]
          }]}}}}
        }"#;

        let c = compile_caddy_json(source).unwrap();
        assert!(c.contains("zs_caddy_map("));
        assert!(c.contains("EMPTY"));
    }

    #[test]
    fn compiles_map_handler_with_empty_destinations() {
        let source = r#"{
          "apps": {"http": {"servers": {"srv0": {"routes": [{
            "handle": [
              {"handler": "map", "source": "{http.request.uri.path}", "mappings": [
                {"input": "/foo", "outputs": []}
              ]},
              {"handler": "static_response", "status_code": 204}
            ]
          }]}}}}
        }"#;

        let c = compile_caddy_json(source).unwrap();
        assert!(c.contains("zs_caddy_map("));
    }

    #[test]
    fn compiles_map_handler_with_omitted_outputs_and_empty_destinations() {
        let source = r#"{
          "apps": {"http": {"servers": {"srv0": {"routes": [{
            "handle": [
              {"handler": "map", "source": "{http.request.uri.path}", "mappings": [
                {"input": "/foo"}
              ]},
              {"handler": "static_response", "status_code": 204}
            ]
          }]}}}}
        }"#;

        let c = compile_caddy_json(source).unwrap();
        assert!(c.contains("zs_caddy_map("));
    }

    #[test]
    fn compiles_map_destinations_with_caddy_provisioning_rules() {
        let source = r#"{
          "apps": {"http": {"servers": {"srv0": {"routes": [{
            "handle": [
              {"handler": "map", "source": "{http.request.uri.path}", "destinations": ["{mapped"], "mappings": [
                {"input": "/foo", "outputs": ["FOO"]}
              ]},
              {"handler": "static_response", "body": "{mapped}"}
            ]
          }]}}}}
        }"#;

        let c = compile_caddy_json(source).unwrap();
        assert!(c.contains("zs_caddy_map("));
        assert!(c.contains("{mapped"));
    }

    #[test]
    fn compiles_map_null_fields_like_caddy_json() {
        let source = r#"{
          "apps": {"http": {"servers": {"srv0": {"routes": [{
            "handle": [
              {"handler": "map",
                "source": null,
                "destinations": null,
                "defaults": null,
                "mappings": [{"input": null, "input_regexp": null, "outputs": null}]
              },
              {"handler": "static_response", "status_code": 204}
            ]
          }]}}}}
        }"#;

        let c = compile_caddy_json(source).unwrap();
        assert!(c.contains("zs_caddy_map("), "{c}");
        assert!(!c.contains("\\\"source\\\""), "{c}");
        assert!(!c.contains("\\\"destinations\\\""), "{c}");
        assert!(!c.contains("\\\"defaults\\\""), "{c}");
        assert!(c.contains("\\\"mappings\\\":[{}]"), "{c}");
    }

    #[test]
    fn compiles_map_null_defaults_and_outputs_like_caddy_json() {
        let source = r#"{
          "apps": {"http": {"servers": {"srv0": {"routes": [{
            "handle": [
              {"handler": "map",
                "source": "{http.request.uri.path}",
                "destinations": ["{mapped}"],
                "defaults": [null],
                "mappings": [{"input": "/foo", "outputs": [null]}]
              },
              {"handler": "static_response", "body": "{mapped}"}
            ]
          }]}}}}
        }"#;

        let c = compile_caddy_json(source).unwrap();
        assert!(c.contains("zs_caddy_map("), "{c}");
        assert!(c.contains("\\\"defaults\\\":[\\\"\\\"]"), "{c}");
        assert!(c.contains("\\\"outputs\\\":[null]"), "{c}");
    }

    #[test]
    fn compiles_invoke_named_route() {
        let source = r#"{
          "apps": {"http": {"servers": {"srv0": {
            "named_routes": {
              "shared": {
                "match": [{"path": ["/hit"]}],
                "handle": [{"handler": "headers", "request": {"set": {"X-Invoked": ["yes"]}}}]
              }
            },
            "routes": [{
              "handle": [
                {"handler": "invoke", "name": "shared"},
                {"handler": "static_response", "status_code": 204}
              ]
            }]
          }}}}
        }"#;

        let c = compile_caddy_json(source).unwrap();
        assert!(c.contains("/* invoke named route shared */"), "{c}");
        assert!(c.contains("zs_caddy_path_match(\"/hit\""), "{c}");
        assert!(c.contains("zs_req_set_header(\"X-Invoked\""), "{c}");
        assert!(c.contains("zs_caddy_respond_static(\"204\""), "{c}");
    }

    #[test]
    fn rejects_missing_invoke_named_route() {
        let source = r#"{
          "apps": {"http": {"servers": {"srv0": {"routes": [{
            "handle": [{"handler": "invoke", "name": "missing"}]
          }]}}}}
        }"#;

        let err = compile_caddy_json(source).unwrap_err().to_string();
        assert!(
            err.contains("cannot invoke named route 'missing', which was not defined"),
            "{err}"
        );
    }

    #[test]
    fn rejects_unknown_invoke_fields() {
        let source = r#"{
          "apps": {"http": {"servers": {"srv0": {
            "named_routes": {"shared": {"handle": [{"handler": "static_response", "status_code": 204}]}},
            "routes": [{"handle": [{"handler": "invoke", "name": "shared", "unknown": true}]}]
          }}}}
        }"#;

        let err = compile_caddy_json(source).unwrap_err().to_string();
        assert!(
            err.contains("unsupported invoke field \"unknown\""),
            "{err}"
        );
    }

    #[test]
    fn rejects_unknown_map_handler_field() {
        let source = r#"{
          "apps": {"http": {"servers": {"srv0": {"routes": [{
            "handle": [
              {"handler": "map", "source": "{http.request.uri.path}", "destinations": ["{mapped}"], "unknown": true}
            ]
          }]}}}}
        }"#;

        let err = compile_caddy_json(source).unwrap_err().to_string();
        assert!(err.contains("unsupported map field \"unknown\""), "{err}");
    }

    #[test]
    fn rejects_unknown_map_mapping_field() {
        let source = r#"{
          "apps": {"http": {"servers": {"srv0": {"routes": [{
            "handle": [
              {"handler": "map", "source": "{http.request.uri.path}", "destinations": ["{mapped}"], "mappings": [
                {"input": "/foo", "outputs": ["FOO"], "unknown": true}
              ]}
            ]
          }]}}}}
        }"#;

        let err = compile_caddy_json(source).unwrap_err().to_string();
        assert!(
            err.contains("unsupported map.mappings field \"unknown\""),
            "{err}"
        );
    }

    #[test]
    fn error_routes_clear_pre_error_response_hooks() {
        let source = r#"{
          "apps": {"http": {"servers": {"srv0": {
            "routes": [{
              "handle": [
                {"handler": "headers", "response": {"deferred": true, "set": {"X-Outer": ["outer"]}}},
                {"handler": "error", "status_code": 404}
              ]
            }],
            "errors": {"routes": [{"handle": [
              {"handler": "static_response", "body": "handled"}
            ]}]}
          }}}}
        }"#;

        let c = compile_caddy_json(source).unwrap();
        let outer_hook = c.find("zs_res_hook(").unwrap();
        let clear = outer_hook + c[outer_hook..].find("zs_res_hooks_clear();").unwrap();
        let error_response = clear + c[clear..].find("handled").unwrap();
        assert!(outer_hook < clear, "{c}");
        assert!(clear < error_response, "{c}");
    }

    #[test]
    fn compiles_intercept_status_only_handle_response() {
        let source = r#"{
          "apps": {"http": {"servers": {"srv0": {"routes": [{
            "handle": [
              {"handler": "intercept", "handle_response": [{"match": {"status_code": [2]}, "status_code": "{http.vars.status}"}]},
              {"handler": "static_response", "status_code": 204, "body": "ok"}
            ]
          }]}}}}
        }"#;

        let (c, warnings) = compile_caddy_json_collecting(source).unwrap();
        assert!(
            warnings
                .iter()
                .any(|w| w.contains("Caddy intercept replace_status is a nonzero no-op")),
            "{warnings:?}"
        );
        assert!(c.contains("intercept_status_done_"));
        assert!(!c.contains("zs_caddy_set_response_status(\"{http.vars.status}\""));
        assert!(c.contains("zs_res_hook("));
    }

    #[test]
    fn compiles_caddyfile_intercept_response_handlers() {
        let (json, warnings) = crate::caddyfile::adapt(
            r#"example.com {
  intercept {
    @created {
      status 201
      header X-Origin app*
    }
    replace_status @created 202
    handle_response {
      header X-Intercept yes
    }
  }
  respond ok
}"#,
            "Caddyfile",
        )
        .unwrap();
        assert!(warnings.is_empty(), "{warnings:?}");
        let (c, warnings) = compile_caddy_json_collecting(&json.to_string()).unwrap();
        assert!(
            warnings
                .iter()
                .any(|w| w.contains("Caddy intercept replace_status is a nonzero no-op")),
            "{warnings:?}"
        );
        assert!(c.contains("intercept_status_done_"), "{c}");
        assert!(!c.contains("zs_caddy_set_response_status(\"202\""), "{c}");
        assert!(c.contains("zs_caddy_response_headers("), "{c}");
    }

    #[test]
    fn handle_response_status_code_takes_priority_over_routes() {
        let source = r#"{
          "apps": {"http": {"servers": {"srv0": {"routes": [{
            "handle": [
              {"handler": "intercept", "handle_response": [{"match": {"status_code": [2]}, "status_code": 299, "routes": [{"handle": [
                {"handler": "static_response", "status_code": 204, "body": "ignored"}
              ]}]}]},
              {"handler": "static_response", "status_code": 200, "body": "original"}
            ]
          }]}}}}
        }"#;

        let c = compile_caddy_json(source).unwrap();
        assert!(c.contains("Caddy intercept replace_status is a nonzero no-op"));
        assert!(!c.contains("zs_caddy_set_response_status(\"299\""));
        assert!(!c.contains("ignored"), "{c}");
    }

    #[test]
    fn compiles_null_handle_response_routes_like_caddy_json() {
        let source = r#"{
          "apps": {"http": {"servers": {"srv0": {"routes": [{
            "handle": [
              {"handler": "intercept", "handle_response": [{"match": {"status_code": [2]}, "routes": null}]},
              {"handler": "static_response", "status_code": 200, "body": "original"}
            ]
          }]}}}}
        }"#;

        let c = compile_caddy_json(source).unwrap();
        assert!(c.contains("intercept_status_done_"), "{c}");
        assert!(c.contains("zs_res_hook("), "{c}");
    }

    #[test]
    fn handle_response_status_zero_is_noop_but_takes_priority() {
        let source = r#"{
          "apps": {"http": {"servers": {"srv0": {"routes": [{
            "handle": [
              {"handler": "intercept", "handle_response": [
                {"match": {"status_code": [2]}, "status_code": 0},
                {"match": {"status_code": [2]}, "status_code": 299}
              ]},
              {"handler": "static_response", "status_code": 200, "body": "original"}
            ]
          }]}}}}
        }"#;

        let c = compile_caddy_json(source).unwrap();
        assert!(c.contains("Caddy intercept replace_status is a nonzero no-op"));
        assert!(!c.contains("zs_caddy_set_response_status(\"0\""));
        assert!(!c.contains("zs_caddy_set_response_status(\"299\""));
    }

    #[test]
    fn intercept_handle_response_status_zero_runs_routes() {
        let source = r#"{
          "apps": {"http": {"servers": {"srv0": {"routes": [{
            "handle": [
              {"handler": "intercept", "handle_response": [{
                "match": {"status_code": [2]},
                "status_code": 0,
                "routes": [{"handle": [
                  {"handler": "headers", "response": {"set": {"X-Intercept-Zero": ["yes"]}}}
                ]}]
              }]},
              {"handler": "static_response", "status_code": 200, "body": "original"}
            ]
          }]}}}}
        }"#;

        let (c, warnings) = compile_caddy_json_collecting(source).unwrap();
        assert!(warnings.is_empty(), "{warnings:?}");
        assert!(c.contains("zs_caddy_response_status_value(\"0\""));
        assert!(c.contains("if (intercept_status_"));
        assert!(c.contains("zs_caddy_response_headers("));
        assert!(!c.contains("zs_caddy_set_response_status(\"0\""));
    }

    #[test]
    fn rejects_handle_response_early_hints_status() {
        let source = r#"{
          "apps": {"http": {"servers": {"srv0": {"routes": [{
            "handle": [
              {"handler": "intercept", "handle_response": [{"match": {"status_code": [2]}, "status_code": 103}]},
              {"handler": "static_response", "status_code": 200}
            ]
          }]}}}}
        }"#;

        let err = compile_caddy_json(source).unwrap_err().to_string();
        assert!(
            err.contains("intercept.handle_response.status_code 103 Early Hints"),
            "{err}"
        );
    }

    #[test]
    fn rejects_intercept_handle_response_routes_that_rewrite_bodies() {
        let source = r#"{
          "apps": {"http": {"servers": {"srv0": {"routes": [{
            "handle": [
              {"handler": "intercept", "handle_response": [{"match": {"status_code": [2]}, "routes": [{"terminal": true, "handle": [
                {"handler": "headers", "response": {"deferred": true, "set": {"X-Handled": ["yes"]}}},
                {"handler": "static_response", "status_code": 204, "body": "handled"}
              ], "match": [{"path": ["/matched"]}]}]}]},
              {"handler": "static_response", "status_code": 200}
            ]
          }]}}}}
        }"#;

        let err = compile_caddy_json(source).unwrap_err().to_string();
        assert!(
            err.contains("intercept.handle_response routes rewrite response bodies"),
            "{err}"
        );
    }

    #[test]
    fn rejects_invalid_map_field_types() {
        for (field, expected) in [
            (
                r#""destinations": "{mapped}""#,
                "map.destinations must be an array of strings",
            ),
            (
                r#""destinations": [1]"#,
                "map.destinations must contain only strings",
            ),
            (
                r#""destinations": ["{mapped}"], "defaults": "default""#,
                "map.defaults must be an array of strings",
            ),
            (
                r#""destinations": ["{mapped}"], "defaults": [1]"#,
                "map.defaults must contain only strings",
            ),
            (
                r#""destinations": ["{mapped}"], "mappings": [{"input": "/foo"}]"#,
                "map.mappings.outputs count must match map.destinations",
            ),
            (
                r#""destinations": ["{mapped}"], "mappings": [{"input": 1, "outputs": ["one"]}]"#,
                "map.mappings.input must be a string",
            ),
            (
                r#""destinations": ["{mapped}"], "mappings": [{"input_regexp": 1, "outputs": ["one"]}]"#,
                "map.mappings.input_regexp must be a string",
            ),
            (r#""mappings": "bad""#, "map.mappings must be an array"),
        ] {
            let source = format!(
                r#"{{
                  "apps": {{"http": {{"servers": {{"srv0": {{"routes": [{{
                    "handle": [{{"handler": "map", "source": "{{http.request.uri.path}}", {field}}}]
                  }}]}}}}}}}}
                }}"#
            );

            let err = compile_caddy_json(&source).unwrap_err().to_string();
            assert!(err.contains(expected), "{field}: {err}");
        }
    }

    #[test]
    fn rejects_intercept_copy_response_headers_routes() {
        let source = r#"{
          "apps": {"http": {"servers": {"srv0": {"routes": [{
            "handle": [
              {"handler": "intercept", "handle_response": [{"match": {"status_code": [2]}, "routes": [{"terminal": true, "handle": [
                {"handler": "copy_response_headers", "include": ["X-Upstream"]}
              ]}]}]},
              {"handler": "static_response", "status_code": 200}
            ]
          }]}}}}
        }"#;

        let err = compile_caddy_json(source).unwrap_err().to_string();
        assert!(
            err.contains(
                "copy_response_headers is only meaningful inside reverse_proxy handle_response routes"
            ),
            "{err}"
        );
    }

    #[test]
    fn rejects_reverse_proxy_handle_response_header_routes() {
        // Caddy header-only handle_response routes suppress the upstream body.
        // zeroserve intentionally does not reproduce response body suppression,
        // so reject these routes instead of streaming the upstream body through.
        let source = r#"{
          "apps": {"http": {"servers": {"srv0": {"routes": [{
            "handle": [{
              "handler": "reverse_proxy",
              "upstreams": [{"dial": "127.0.0.1:8081"}],
              "handle_response": [{"match": {"status_code": [4]}, "routes": [{"handle": [
                {"handler": "headers", "response": {"delete": ["X-Copy-Me"]}},
                {"handler": "copy_response_headers", "include": ["X-Copy-Me"]},
                {"handler": "headers", "response": {"set": {"X-Handled": ["yes"]}}}
              ], "terminal": true}]}]
            }]
          }]}}}}
        }"#;

        let err = compile_caddy_json(source).unwrap_err().to_string();
        assert!(
            err.contains("reverse_proxy.handle_response routes suppress upstream response bodies"),
            "{err}"
        );
    }

    #[test]
    fn compiles_response_route_request_header_mutation_in_hook() {
        let source = r#"{
          "apps": {"http": {"servers": {"srv0": {"routes": [{
            "handle": [{
              "handler": "reverse_proxy",
              "upstreams": [{"dial": "127.0.0.1:8081"}],
              "handle_response": [{"match": {"status_code": [2]}, "routes": [{"handle": [
                {"handler": "headers", "request": {"delete": ["Remote-User"]}},
                {"handler": "headers", "request": {"set": {"Remote-User": ["{http.reverse_proxy.header.Remote-User}"]}}}
              ]}]}]
            }]
          }]}}}}
        }"#;

        let c = compile_caddy_json(source).unwrap();
        let hook_pos = c.find("ZS_CALL_ENTRY(caddy_response_0").unwrap();
        let hook = &c[hook_pos..];
        assert!(hook.contains("zs_req_delete_header(\"Remote-User\""), "{c}");
        assert!(hook.contains("zs_req_set_header(\"Remote-User\""), "{c}");
        assert!(hook.contains("zs_res_continue_request();"), "{c}");
        assert!(c.contains("zs.caddy.reverse_proxy.skip."), "{c}");
    }

    #[test]
    fn compiles_empty_reverse_proxy_handle_response_as_continue() {
        for handle_response in [
            r#"[{"match": {"status_code": [4]}}]"#,
            r#"[{"match": {"status_code": [4]}, "routes": null}]"#,
            r#"[{"match": {"status_code": [4]}, "routes": []}]"#,
        ] {
            let source = format!(
                r#"{{
                  "apps": {{"http": {{"servers": {{"srv0": {{"routes": [{{
                    "handle": [
                      {{"handler": "reverse_proxy", "upstreams": [{{"dial": "127.0.0.1:8080"}}], "handle_response": {handle_response}}},
                      {{"handler": "static_response", "status_code": 204}}
                    ]
                  }}]}}}}}}}}
                }}"#
            );

            let c = compile_caddy_json(&source).unwrap();
            assert!(c.contains("zs_res_continue_request();"), "{c}");
            assert!(c.contains("zs.caddy.reverse_proxy.skip."), "{c}");
        }
    }

    #[test]
    fn rejects_copy_response_headers_null_lists_without_body_copy() {
        // include/exclude both null means "copy all upstream headers", but a
        // Caddy handle_response route still suppresses the upstream body unless
        // copy_response is used. zeroserve does not implement either body
        // suppression or body copying.
        let source = r#"{
          "apps": {"http": {"servers": {"srv0": {"routes": [{
            "handle": [{
              "handler": "reverse_proxy",
              "upstreams": [{"dial": "127.0.0.1:8081"}],
              "handle_response": [{"match": {"status_code": [2]}, "routes": [{"handle": [
                {"handler": "copy_response_headers", "include": null, "exclude": null}
              ]}]}]
            }]
          }]}}}}
        }"#;

        let err = compile_caddy_json(source).unwrap_err().to_string();
        assert!(
            err.contains("reverse_proxy.handle_response routes suppress upstream response bodies"),
            "{err}"
        );
    }

    #[test]
    fn rejects_reverse_proxy_response_route_subroutes_that_suppress_body() {
        let source = r#"{
          "apps": {"http": {"servers": {"srv0": {"routes": [{
            "handle": [{
              "handler": "reverse_proxy",
              "upstreams": [{"dial": "127.0.0.1:8081"}],
              "handle_response": [{"match": {"status_code": [4]}, "routes": [{"handle": [{
                "handler": "subroute",
                "routes": [{"match": [{"path": ["/handled"]}], "handle": [
                  {"handler": "headers", "response": {"set": {"X-Handled": ["yes"]}}},
                  {"handler": "vars", "root": "public"}
                ], "terminal": true}]
              }], "terminal": true}]}]
            }]
          }]}}}}
        }"#;

        let err = compile_caddy_json(source).unwrap_err().to_string();
        assert!(
            err.contains("reverse_proxy.handle_response routes suppress upstream response bodies"),
            "{err}"
        );
    }

    #[test]
    fn rejects_response_route_subroute_errors() {
        let source = r#"{
          "apps": {"http": {"servers": {"srv0": {"routes": [{
            "handle": [{
              "handler": "intercept",
              "handle_response": [{"match": {"status_code": [2]}, "routes": [{"handle": [{
                "handler": "subroute",
                "routes": [],
                "errors": {"routes": [{"handle": [{"handler": "static_response", "body": "error"}]}]}
              }]}]}]
            }]
          }]}}}}
        }"#;

        let err = compile_caddy_json(source).unwrap_err().to_string();
        assert!(
            err.contains(
                "intercept.handle_response subroute errors cannot be represented during response processing"
            ),
            "{err}"
        );
    }

    #[test]
    fn rejects_reverse_proxy_response_route_invoke_that_suppresses_body() {
        let source = r#"{
          "apps": {"http": {"servers": {"srv0": {
            "named_routes": {"mark": {
              "match": [{"path": ["/handled"]}],
              "handle": [{"handler": "headers", "response": {"set": {"X-Invoked": ["yes"]}}}],
              "terminal": true
            }},
            "routes": [{
              "handle": [{
                "handler": "reverse_proxy",
                "upstreams": [{"dial": "127.0.0.1:8081"}],
                "handle_response": [{"match": {"status_code": [4]}, "routes": [{"handle": [
                  {"handler": "invoke", "name": "mark"},
                  {"handler": "headers", "response": {"set": {"X-After-Invoke": ["yes"]}}}
                ]}]}]
              }]
            }]
          }}}}
        }"#;

        let err = compile_caddy_json(source).unwrap_err().to_string();
        assert!(
            err.contains("reverse_proxy.handle_response routes suppress upstream response bodies"),
            "{err}"
        );
    }

    #[test]
    fn rejects_response_route_invoke_body_rewrites() {
        let source = r#"{
          "apps": {"http": {"servers": {"srv0": {
            "named_routes": {"body": {
              "handle": [{"handler": "static_response", "body": "replacement"}],
              "terminal": true
            }},
            "routes": [{
              "handle": [{
                "handler": "intercept",
                "handle_response": [{"match": {"status_code": [2]}, "routes": [{"handle": [
                  {"handler": "invoke", "name": "body"}
                ]}]}]
              }]
            }]
          }}}}
        }"#;

        let err = compile_caddy_json(source).unwrap_err().to_string();
        assert!(
            err.contains("intercept.handle_response routes rewrite response bodies"),
            "{err}"
        );
    }

    #[test]
    fn rejects_reverse_proxy_handle_response_routes() {
        let source = r#"{
          "apps": {"http": {"servers": {"srv0": {"routes": [{
            "handle": [{
              "handler": "reverse_proxy",
              "upstreams": [{"dial": "127.0.0.1:8081"}],
              "handle_response": [{"match": {"status_code": [4]}, "routes": [{"terminal": true, "handle": [
                {"handler": "copy_response_headers", "exclude": ["X-Secret"]},
                {"handler": "copy_response", "status_code": 299}
              ]}]}]
            }]
          }]}}}}
        }"#;

        let err = compile_caddy_json(source).unwrap_err().to_string();
        assert!(
            err.contains("reverse_proxy.handle_response routes replace response bodies"),
            "{err}"
        );
    }

    #[test]
    fn rejects_invalid_copy_response_headers_field_types() {
        for field in [r#""include": "X-Copy-Me""#, r#""exclude": "X-Secret""#] {
            let source = format!(
                r#"{{
                  "apps": {{"http": {{"servers": {{"srv0": {{"routes": [{{
                    "handle": [{{
                      "handler": "reverse_proxy",
                      "upstreams": [{{"dial": "127.0.0.1:8081"}}],
                      "handle_response": [{{"match": {{"status_code": [2]}}, "routes": [{{"terminal": true, "handle": [
                        {{"handler": "copy_response_headers", {field}}}
                      ]}}]}}]
                    }}]
                  }}]}}}}}}}}
                }}"#
            );

            let err = compile_caddy_json(&source).unwrap_err().to_string();
            assert!(
                err.contains("must be an array of strings"),
                "{field}: {err}"
            );
        }
    }

    #[test]
    fn rejects_copy_response_headers_include_and_exclude_like_caddy_validation() {
        let source = r#"{
          "apps": {"http": {"servers": {"srv0": {"routes": [{
            "handle": [{
              "handler": "reverse_proxy",
              "upstreams": [{"dial": "127.0.0.1:8081"}],
              "handle_response": [{"match": {"status_code": [2]}, "routes": [{"terminal": true, "handle": [
                {"handler": "copy_response_headers", "include": ["X-Copy-Me"], "exclude": ["X-Secret"]}
              ]}]}]
            }]
          }]}}}}
        }"#;

        let err = compile_caddy_json(source).unwrap_err().to_string();
        assert!(
            err.contains("copy_response_headers cannot define both include and exclude"),
            "{err}"
        );
    }

    #[test]
    fn compiles_subroute_error_routes() {
        let source = r#"{
          "apps": {"http": {"servers": {"srv0": {"routes": [{
            "handle": [{
              "handler": "subroute",
              "routes": [{"handle": [{"handler": "error", "status_code": 418}]}],
              "errors": {"routes": [{"handle": [{"handler": "static_response", "body": "handled {http.error.status_code}"}]}]}
            }]
          }]}}}}
        }"#;

        let c = compile_caddy_json(source).unwrap();
        assert!(c.contains("zs_caddy_set_error(\"418\""), "{c}");
        assert!(c.contains("handled {http.error.status_code}"), "{c}");
    }

    #[test]
    fn compiles_conditional_subroute_error_routes() {
        let source = r#"{
          "apps": {"http": {"servers": {"srv0": {"routes": [{
            "handle": [{
              "handler": "subroute",
              "routes": [{"handle": [{"handler": "error", "status_code": 418}]}],
              "errors": {"routes": [{"match": [{"path": ["/only"]}], "handle": [{"handler": "static_response", "status_code": 204}]}]}
            }]
          }]}}}}
        }"#;

        let c = compile_caddy_json(source).unwrap();
        assert!(c.contains("zs_caddy_set_error(\"418\""), "{c}");
        assert!(c.contains("zs_caddy_path_match(\"/only\""), "{c}");
    }

    #[test]
    fn compiles_grouped_subroute_routes() {
        let source = r#"{
          "apps": {"http": {"servers": {"srv0": {"routes": [{
            "handle": [{
              "handler": "subroute",
              "routes": [
                {"group": "choice", "handle": [{"handler": "headers", "request": {"set": {"X-Choice": ["first"]}}}]},
                {"group": "choice", "handle": [{"handler": "headers", "request": {"set": {"X-Choice": ["second"]}}}]},
                {"handle": [{"handler": "static_response", "status_code": 220, "body": "{http.request.header.X-Choice}"}]}
              ]
            }]
          }]}}}}
        }"#;

        let c = compile_caddy_json(source).unwrap();
        assert!(c.contains("route_groups"), "{c}");
        assert!(c.contains("zs_memset(route_groups"), "{c}");
        assert!(
            c.contains("Caddy subroute group already satisfied; skip this route."),
            "{c}"
        );
        assert!(c.contains("first"), "{c}");
        assert!(c.contains("second"), "{c}");
    }

    #[test]
    fn compiles_header_rewrite_proxy_route() {
        let source = r#"{
          "apps": {"http": {"servers": {"srv0": {"routes": [{
            "match": [{"host": ["example.com"], "query": {"debug": ["*"]}}],
            "handle": [
              {"handler": "headers", "request": {"set": {"X-Test": ["yes"]}}, "response": {"deferred": true, "set": {"Cache-Control": ["no-store"]}}},
              {"handler": "rewrite", "uri": "/upstream"},
              {"handler": "reverse_proxy", "upstreams": [{"dial": "127.0.0.1:9000"}]}
            ]
          }]}}}}
        }"#;

        let c = compile_caddy_json(source).unwrap();
        assert!(c.contains("zs_caddy_host_normalize(host_"));
        assert!(c.contains("zs_caddy_host_match(host_"));
        assert!(c.contains("zs_caddy_query_match(\"debug\""));
        assert!(c.contains("zs_req_set_header(\"X-Test\""));
        assert!(c.contains("zs_caddy_response_headers("));
        assert!(c.contains("zs_caddy_set_path_preserve_query(\"/upstream\""));
        assert!(c.contains("zs_caddy_reverse_proxy_forwarded("));
        assert!(c.contains("zs_caddy_reverse_proxy_url(\"http://127.0.0.1:9000\""));
        assert!(c.contains("zs_reverse_proxy(reverse_proxy_url_"));
    }

    #[test]
    fn compiles_headers_null_sections_as_omitted() {
        let source = r#"{
          "apps": {"http": {"servers": {"srv0": {"routes": [{
            "handle": [
              {"handler": "headers", "request": null, "response": null},
              {"handler": "static_response", "status_code": 204}
            ]
          }]}}}}
        }"#;

        let c = compile_caddy_json(source).unwrap();
        assert!(!c.contains("zs_req_set_header("), "{c}");
        assert!(!c.contains("zs_caddy_response_headers("), "{c}");
    }

    #[test]
    fn compiles_headers_null_values_like_caddy_json() {
        let source = r#"{
          "apps": {"http": {"servers": {"srv0": {"routes": [{
            "handle": [
              {"handler": "headers",
                "request": {"add": {"X-Empty": null}, "set": {"X-Blank": [null]}, "delete": [null], "replace": {"X-Replace": [{"search": null, "search_regexp": null, "replace": null}]}},
                "response": {"require": null, "deferred": null, "add": {"X-Resp": [null]}}
              },
              {"handler": "static_response", "status_code": 204}
            ]
          }]}}}}
        }"#;

        let c = compile_caddy_json(source).unwrap();
        assert!(
            c.contains("zs_req_set_header(\"X-Blank\", 7, \"\", 0);"),
            "{c}"
        );
        assert!(c.contains("\\\"X-Resp\\\":[\\\"\\\"]"), "{c}");
        assert!(c.contains("\\\"add\\\":{\\\"X-Resp\\\":[\\\"\\\"]}"), "{c}");
        assert!(!c.contains("\\\"require\\\""), "{c}");
        assert!(!c.contains("\\\"deferred\\\""), "{c}");
    }

    #[test]
    fn compiles_query_values_with_literal_stars() {
        let source = r#"{
          "apps": {"http": {"servers": {"srv0": {"routes": [{
            "match": [{"query": {"debug": ["*bar*"]}}],
            "handle": [{"handler": "static_response", "status_code": 204}]
          }]}}}}
        }"#;

        let c = compile_caddy_json(source).unwrap();
        assert!(c.contains("zs_caddy_query_match(\"debug\", 5, \"*bar*\", 5)"));
    }

    #[test]
    fn rejects_scalar_string_list_matcher_values() {
        for (matcher, expected) in [
            (r#""method": "GET""#, "method must be an array of strings"),
            (r#""path": "/foo""#, "path must be an array of strings"),
            (
                r#""host": "example.com""#,
                "host must be an array of strings",
            ),
            (
                r#""header": {"X-Test": "yes"}"#,
                "header value must be an array of strings",
            ),
            (
                r#""query": {"debug": "1"}"#,
                "query value must be an array of strings",
            ),
        ] {
            let source = format!(
                r#"{{
                  "apps": {{"http": {{"servers": {{"srv0": {{"routes": [{{
                    "match": [{{{matcher}}}],
                    "handle": [{{"handler": "static_response", "status_code": 204}}]
                  }}]}}}}}}}}
                }}"#
            );

            let err = compile_caddy_json(&source).unwrap_err().to_string();
            assert!(err.contains(expected), "{err}");
        }
    }

    #[test]
    fn compiles_query_null_as_never_match() {
        let source = r#"{
          "apps": {"http": {"servers": {"srv0": {"routes": [{
            "handle": [{"handler": "vars", "query_key": "debug"}]
          }, {
            "match": [{"query": {"{http.vars.query_key}": null}}],
            "handle": [{"handler": "static_response", "status_code": 204}]
          }]}}}}
        }"#;

        let c = compile_caddy_json(source).unwrap();
        assert!(c.contains("if (((((0))))) {"), "{c}");
        assert!(!c.contains("zs_caddy_query_present("), "{c}");
    }

    #[test]
    fn compiles_placeholder_expanded_query_and_header_matchers() {
        let source = r#"{
          "apps": {"http": {"servers": {"srv0": {"routes": [{
            "handle": [{"handler": "vars", "query_key": "debug", "query_value": "enabled", "header_value": "token-42"}]
          }, {
            "match": [{"query": {"{http.vars.query_key}": ["{http.vars.query_value}"]}, "header": {"X-Mode": ["{http.vars.header_value}"]}}],
            "handle": [{"handler": "static_response", "status_code": 204}]
          }]}}}}
        }"#;

        let c = compile_caddy_json(source).unwrap();
        assert!(c.contains("zs_caddy_query_match(\"{http.vars.query_key}\""));
        assert!(c.contains("zs_caddy_header_match(\"X-Mode\""));
        assert!(c.contains("\"{http.vars.header_value}\""));
    }

    #[test]
    fn compiles_reverse_proxy_upstream_placeholders() {
        let source = r#"{
          "apps": {"http": {"servers": {"srv0": {"routes": [{
            "handle": [
              {"handler": "vars", "backend": "127.0.0.1:9000", "origin_prefix": "ok", "proxy_status": "203"},
              {"handler": "reverse_proxy", "headers": {
                "request": {"set": {"X-Upstream": ["{http.reverse_proxy.upstream.hostport}"]}},
                "response": {"deferred": true, "set": {"X-Upstream-Status": ["{http.reverse_proxy.status_code}"], "X-Upstream-Origin": ["{http.reverse_proxy.header.X-Origin-Match}"]}}
              }, "handle_response": [{"match": {"status_code": [2], "headers": {"X-Origin-Match": ["ok*"]}}, "status_code": "{http.vars.proxy_status}"}], "upstreams": [{"dial": "{http.vars.backend}"}]}
            ]
          }]}}}}
        }"#;

        let c = compile_caddy_json(source).unwrap();
        assert!(c.contains("zs_caddy_reverse_proxy_url(\"http://{http.vars.backend}\""));
        assert!(c.contains("zs_caddy_reverse_proxy_request_headers("));
        assert!(c.contains("\\\"X-Upstream\\\""));
        assert!(c.contains("zs_caddy_response_headers("));
        assert!(c.contains("{http.reverse_proxy.header.X-Origin-Match}"));
        assert!(c.contains("ok*"));
        assert!(c.contains("zs_caddy_set_response_status(\"{http.vars.proxy_status}\""));
        assert!(c.contains("zs_reverse_proxy(reverse_proxy_url_"));
    }

    #[test]
    fn compiles_reverse_proxy_response_headers_with_null_values_like_caddy_json() {
        let source = r#"{
          "apps": {"http": {"servers": {"srv0": {"routes": [{
            "handle": [
              {"handler": "reverse_proxy", "headers": {
                "response": {
                  "add": {"X-Add": null},
                  "set": {"X-Set": [null]},
                  "delete": [null],
                  "replace": {"X-Replace": [{"search": null, "replace": null}]},
                  "deferred": true
                }
              }, "upstreams": [{"dial": "127.0.0.1:9000"}]}
            ]
          }]}}}}
        }"#;

        let c = compile_caddy_json(source).unwrap();
        assert!(c.contains("zs_caddy_response_headers("), "{c}");
        assert!(c.contains("\\\"X-Set\\\":[\\\"\\\"]"), "{c}");
        assert!(c.contains("\\\"X-Add\\\":[]"), "{c}");
        assert!(c.contains("\\\"delete\\\":[\\\"\\\"]"), "{c}");
        assert!(c.contains("\\\"search\\\":\\\"\\\""), "{c}");
        assert!(c.contains("\\\"replace\\\":\\\"\\\""), "{c}");
    }

    #[test]
    fn rejects_reverse_proxy_handle_response_upstream_placeholders_that_suppress_body() {
        let source = r#"{
          "apps": {"http": {"servers": {"srv0": {"routes": [{
            "handle": [{
              "handler": "reverse_proxy",
              "handle_response": [{
                "match": {"status_code": [2]},
                "routes": [{
                  "handle": [{"handler": "headers", "response": {"set": {"X-Upstream": ["{http.reverse_proxy.upstream.hostport}"]}}}],
                  "terminal": true
                }]
              }],
              "upstreams": [{"dial": "127.0.0.1:9000"}]
            }]
          }]}}}}
        }"#;

        let err = compile_caddy_json(source).unwrap_err().to_string();
        assert!(
            err.contains("reverse_proxy.handle_response routes suppress upstream response bodies"),
            "{err}"
        );
    }

    #[test]
    fn compiles_static_reverse_proxy_with_prior_response_hook_upstream_placeholders() {
        let source = r#"{
          "apps": {"http": {"servers": {"srv0": {"routes": [{
            "handle": [
              {"handler": "headers", "response": {"deferred": true, "set": {"X-Upstream": ["{http.reverse_proxy.upstream.hostport}"]}}},
              {"handler": "reverse_proxy", "upstreams": [{"dial": "127.0.0.1:9000"}]}
            ]
          }]}}}}
        }"#;

        let c = compile_caddy_json(source).unwrap();
        assert!(c.contains("zs_caddy_reverse_proxy_url(\"http://127.0.0.1:9000\""));
        assert!(c.contains("zs_caddy_response_headers("));
        assert!(c.contains("zs_reverse_proxy(reverse_proxy_url_"));
    }

    #[test]
    fn rejects_schemed_reverse_proxy_upstream_placeholders() {
        let source = r#"{
          "apps": {"http": {"servers": {"srv0": {"routes": [{
            "handle": [
              {"handler": "vars", "backend": "127.0.0.1:9000"},
              {"handler": "reverse_proxy", "upstreams": [{"dial": "http://{http.vars.backend}"}]}
            ]
          }]}}}}
        }"#;

        let err = compile_caddy_json(source).unwrap_err().to_string();
        assert!(
            err.contains("URL schemes cannot contain placeholders"),
            "{err}"
        );
    }

    #[test]
    fn compiles_headers_handler_with_replace_known_expansion() {
        let source = r#"{
          "apps": {"http": {"servers": {"srv0": {"routes": [{
            "handle": [
              {"handler": "headers", "response": {"deferred": true, "set": {"X-Unknown": ["known-{http.request.uri.path}-unknown-{missing.placeholder}"]}}},
              {"handler": "static_response", "status_code": 204}
            ]
          }]}}}}
        }"#;

        let c = compile_caddy_json(source).unwrap();
        assert!(c.contains("zs_caddy_response_headers("));
        assert!(c.contains("known-{http.request.uri.path}-unknown-{missing.placeholder}"));
        assert!(
            !c.contains(
                "zs_caddy_expand(\"known-{http.request.uri.path}-unknown-{missing.placeholder}\""
            ),
            "{c}"
        );
    }

    #[test]
    fn compiles_reverse_proxy_rewrite_uri() {
        let source = r#"{
          "apps": {"http": {"servers": {"srv0": {"routes": [{
            "handle": [
              {"handler": "reverse_proxy", "rewrite": {"uri": "/backend{http.request.uri.prefixed_query}"}, "upstreams": [{"dial": "127.0.0.1:9000"}]}
            ]
          }]}}}}
        }"#;

        let c = compile_caddy_json(source).unwrap();
        assert!(c.contains("zs_caddy_reverse_proxy_rewrite("));
        assert!(c.contains("\\\"uri\\\":\\\"/backend{http.request.uri.prefixed_query}\\\""));
        assert!(c.contains("zs_reverse_proxy(\"http://127.0.0.1:9000\""));
    }

    #[test]
    fn compiles_reverse_proxy_rewrite_before_upstream_placeholders() {
        let source = r#"{
          "apps": {"http": {"servers": {"srv0": {"routes": [{
            "handle": [
              {"handler": "reverse_proxy",
                "rewrite": {"uri": "/backend"},
                "headers": {"request": {"set": {"X-Upstream": ["{http.reverse_proxy.upstream.hostport}"]}}},
                "upstreams": [{"dial": "127.0.0.1:9000"}]
              }
            ]
          }]}}}}
        }"#;

        let c = compile_caddy_json(source).unwrap();
        let rewrite = c
            .find("zs_caddy_reverse_proxy_rewrite(")
            .unwrap_or_else(|| panic!("missing reverse proxy rewrite: {c}"));
        let upstream_url = c
            .find("zs_caddy_reverse_proxy_url(")
            .unwrap_or_else(|| panic!("missing upstream URL preparation: {c}"));
        assert!(rewrite < upstream_url, "{c}");
    }

    #[test]
    fn compiles_reverse_proxy_rewrite_method() {
        let source = r#"{
          "apps": {"http": {"servers": {"srv0": {"routes": [{
            "handle": [
              {"handler": "reverse_proxy", "rewrite": {"method": "GET"}, "upstreams": [{"dial": "127.0.0.1:9000"}]}
            ]
          }]}}}}
        }"#;

        let c = compile_caddy_json(source).unwrap();
        assert!(c.contains("zs_caddy_reverse_proxy_rewrite("));
        assert!(c.contains("\\\"method\\\":\\\"GET\\\""));
    }

    #[test]
    fn compiles_header_add_operations() {
        let source = r#"{
          "apps": {"http": {"servers": {"srv0": {"routes": [{
            "handle": [
              {"handler": "headers", "request": {"add": {"X-Trace": ["a", "b"]}}, "response": {"deferred": true, "add": {"Set-Cookie": ["a=1", "b=2"]}}},
              {"handler": "static_response", "status_code": 204}
            ]
          }]}}}}
        }"#;

        let c = compile_caddy_json(source).unwrap();
        assert!(c.contains("zs_req_append_header(\"X-Trace\", 7, \"a\", 1);"));
        assert!(c.contains("zs_req_append_header(\"X-Trace\", 7, \"b\", 1);"));
        assert!(c.contains("zs_caddy_response_headers("), "{c}");
    }

    #[test]
    fn compiles_header_delete_patterns() {
        let source = r#"{
          "apps": {"http": {"servers": {"srv0": {"routes": [{
            "handle": [
              {"handler": "headers", "request": {"delete": ["X-Debug-*"]}, "response": {"deferred": true, "delete": ["*", "*Secret*"]}},
              {"handler": "static_response", "status_code": 204}
            ]
          }]}}}}
        }"#;

        let c = compile_caddy_json(source).unwrap();
        assert!(c.contains("zs_req_delete_header(\"X-Debug-*\", 9);"));
        assert!(c.contains("zs_caddy_response_headers("), "{c}");
    }

    #[test]
    fn compiles_non_deferred_response_header_operations() {
        let source = r#"{
          "apps": {"http": {"servers": {"srv0": {"routes": [{
            "handle": [
              {"handler": "headers", "response": {"set": {"X-Late": ["yes"]}}},
              {"handler": "static_response", "status_code": 204}
            ]
          }]}}}}
        }"#;

        let c = compile_caddy_json(source).unwrap();
        assert!(c.contains("zs_caddy_response_headers("), "{c}");
        assert!(!c.contains("zs_res_hook("), "{c}");
    }

    #[test]
    fn compiles_header_replace_operations() {
        let source = r#"{
          "apps": {"http": {"servers": {"srv0": {"routes": [{
            "handle": [
              {"handler": "headers", "request": {"replace": {"X-Test": [{"search": "raw", "replace": "cooked"}]}}, "response": {"deferred": true, "replace": {"*": [{"search": "backend", "replace": "compiled"}]}}},
              {"handler": "static_response", "status_code": 204}
            ]
          }]}}}}
        }"#;

        let c = compile_caddy_json(source).unwrap();
        assert!(c.contains("zs_req_replace_header("));
        assert!(c.contains("zs_caddy_response_headers("));
        assert!(c.contains("\\\"search\\\":\\\"raw\\\""));
        assert!(c.contains("\\\"search\\\":\\\"backend\\\""));
    }

    #[test]
    fn compiles_header_replace_regex() {
        let source = r#"{
          "apps": {"http": {"servers": {"srv0": {"routes": [{
            "handle": [
              {"handler": "headers", "request": {"replace": {"X-Test": [{"search_regexp": "a+", "replace": "b"}]}}},
              {"handler": "static_response", "status_code": 204}
            ]
          }]}}}}
        }"#;

        let c = compile_caddy_json(source).unwrap();
        assert!(c.contains("zs_req_replace_header("));
        assert!(c.contains("\\\"search_regexp\\\":\\\"a+\\\""));
    }

    #[test]
    fn compiles_header_replace_regex_with_placeholder_syntax() {
        let source = r#"{
          "apps": {"http": {"servers": {"srv0": {"routes": [{
            "handle": [
              {"handler": "headers", "request": {"replace": {"X-Test": [{"search_regexp": "{http.vars.re}", "replace": "b"}]}}, "response": {"deferred": true, "replace": {"X-Test": [{"search_regexp": ":{http.request.local.port}", "replace": "b"}, {"search_regexp": "{1}", "replace": "c"}]}}},
              {"handler": "static_response", "status_code": 204}
            ]
          }]}}}}
        }"#;

        let c = compile_caddy_json(source).unwrap();
        assert!(c.contains("zs_req_replace_header("));
        assert!(c.contains("zs_caddy_response_headers("));
        assert!(c.contains("\\\"search_regexp\\\":\\\"{http.vars.re}\\\""));
        assert!(c.contains("\\\"search_regexp\\\":\\\":{http.request.local.port}\\\""));
        assert!(c.contains("\\\"search_regexp\\\":\\\"{1}\\\""));
    }

    #[test]
    fn compiles_conditional_response_headers() {
        let source = r#"{
          "apps": {"http": {"servers": {"srv0": {"routes": [{
            "handle": [
              {"handler": "headers", "response": {
                "deferred": true,
                "require": {
                  "status_code": [2],
                  "headers": {"X-Upstream": ["ok*"]}
                },
                "set": {"X-Matched": ["yes"]}
              }},
              {"handler": "static_response", "status_code": 204}
            ]
          }]}}}}
        }"#;

        let c = compile_caddy_json(source).unwrap();
        assert!(c.contains("zs_res_status()"));
        assert!(c.contains("zs_caddy_res_header_match(\"X-Upstream\""));
        assert!(c.contains("res_status_"));
        assert!(c.contains("zs_caddy_response_headers("));
    }

    #[test]
    fn compiles_response_header_matcher_literal_placeholder_syntax() {
        let source = r#"{
          "apps": {"http": {"servers": {"srv0": {"routes": [{
            "handle": [
              {"handler": "vars", "expected": "ok"},
              {"handler": "headers", "response": {
                "deferred": true,
                "require": {"headers": {"X-Upstream": ["{http.vars.expected}*"]}},
                "set": {"X-Matched": ["yes"]}
              }},
              {"handler": "static_response", "status_code": 204}
            ]
          }]}}}}
        }"#;

        let c = compile_caddy_json(source).unwrap();
        assert!(c.contains("zs_caddy_res_header_match(\"X-Upstream\""));
        assert!(c.contains("\"{http.vars.expected}*\""));
    }

    #[test]
    fn compiles_empty_response_header_matcher_as_true() {
        let source = r#"{
          "apps": {"http": {"servers": {"srv0": {"routes": [{
            "handle": [
              {"handler": "headers", "response": {
                "deferred": true,
                "require": {"status_code": [2], "headers": {}},
                "set": {"X-Matched": ["yes"]}
              }},
              {"handler": "static_response", "status_code": 204}
            ]
          }]}}}}
        }"#;

        let c = compile_caddy_json(source).unwrap();
        assert!(!c.contains("&& (()))"), "{c}");
        assert!(c.contains("&& 1))"), "{c}");
        assert!(c.contains("zs_caddy_response_headers("));
    }

    #[test]
    fn compiles_caddy_response_status_match_edge_values() {
        let source = r#"{
          "apps": {"http": {"servers": {"srv0": {"routes": [{
            "handle": [
              {"handler": "headers", "response": {
                "deferred": true,
                "require": {"status_code": [0, -1, 42]},
                "set": {"X-Matched": ["yes"]}
              }},
              {"handler": "static_response", "status_code": 204}
            ]
          }]}}}}
        }"#;

        let c = compile_caddy_json(source).unwrap();
        assert!(c.contains("res_status_"));
        assert!(c.contains("res_status_"));
        assert!(c.contains("res_status_") && c.contains("== 0"));
        assert!(c.contains("res_status_") && c.contains("== -1"));
        assert!(c.contains("res_status_") && c.contains("== 42"));
        assert!(!c.contains(">= 0 && res_status_"));
        assert!(!c.contains(">= -100 && res_status_"));
        assert!(c.contains(">= 4200 && res_status_"));
    }

    #[test]
    fn compiles_caddy_response_status_null_and_empty_like_caddy() {
        let null_source = r#"{
          "apps": {"http": {"servers": {"srv0": {"routes": [{
            "handle": [
              {"handler": "headers", "response": {
                "deferred": true,
                "require": {"status_code": null, "headers": null},
                "set": {"X-Matched": ["yes"]}
              }},
              {"handler": "static_response", "status_code": 204}
            ]
          }]}}}}
        }"#;
        let c = compile_caddy_json(null_source).unwrap();
        assert!(!c.contains("zs_res_status()"), "{c}");
        assert!(c.contains("zs_caddy_response_headers("), "{c}");

        let empty_source = r#"{
          "apps": {"http": {"servers": {"srv0": {"routes": [{
            "handle": [
              {"handler": "headers", "response": {
                "deferred": true,
                "require": {"status_code": []},
                "set": {"X-Matched": ["yes"]}
              }},
              {"handler": "static_response", "status_code": 204}
            ]
          }]}}}}
        }"#;
        let c = compile_caddy_json(empty_source).unwrap();
        assert!(c.contains("(0)"), "{c}");
        assert!(!c.contains("zs_res_status()"), "{c}");
    }

    #[test]
    fn rejects_string_response_status_matchers() {
        let source = r#"{
          "apps": {"http": {"servers": {"srv0": {"routes": [{
            "handle": [
              {"handler": "headers", "response": {
                "deferred": true,
                "require": {"status_code": ["2"]},
                "set": {"X-Matched": ["yes"]}
              }},
              {"handler": "static_response", "status_code": 204}
            ]
          }]}}}}
        }"#;

        let err = compile_caddy_json(source).unwrap_err().to_string();
        assert!(err.contains("headers.response.require.status_code must be an integer"));
    }

    #[test]
    fn compiles_header_presence_matchers() {
        let source = r#"{
          "apps": {"http": {"servers": {"srv0": {"routes": [{
            "match": [{"header": {"X-Missing": null, "X-Present": []}}],
            "handle": [{"handler": "static_response", "status_code": 204}]
          }]}}}}
        }"#;

        let c = compile_caddy_json(source).unwrap();
        assert!(c.contains("zs_caddy_header_present(\"X-Missing\""));
        assert!(c.contains("zs_caddy_header_present(\"X-Present\""));
        assert!(c.contains("== 0"));
        assert!(c.contains("!= 0"));
    }

    #[test]
    fn compiles_rewrite_method_and_query_only_uri() {
        let source = r#"{
          "apps": {"http": {"servers": {"srv0": {"routes": [{
            "handle": [
              {"handler": "rewrite", "method": "post", "uri": "?debug=1"},
              {"handler": "static_response", "status_code": 204}
            ]
          }]}}}}
        }"#;

        let c = compile_caddy_json(source).unwrap();
        assert!(c.contains("zs_req_set_method(\"POST\""));
        assert!(c.contains("zs_caddy_rewrite_uri(\"?debug=1\""));
    }

    #[test]
    fn compiles_rewrite_uri_placeholders() {
        let source = r#"{
          "apps": {"http": {"servers": {"srv0": {"routes": [{
            "handle": [
              {"handler": "rewrite", "uri": "{http.matchers.file.relative}?from={http.request.uri.path.1}"},
              {"handler": "static_response", "status_code": 204}
            ]
          }]}}}}
        }"#;

        let c = compile_caddy_json(source).unwrap();
        assert!(c.contains("zs_caddy_rewrite_uri("));
        assert!(c.contains("{http.matchers.file.relative}?from={http.request.uri.path.1}"));
    }

    #[test]
    fn compiles_rewrite_uri_fragment() {
        let source = r##"{
          "apps": {"http": {"servers": {"srv0": {"routes": [{
            "handle": [
              {"handler": "rewrite", "uri": "/target?x=1#frag"},
              {"handler": "static_response", "status_code": 204}
            ]
          }]}}}}
        }"##;

        let c = compile_caddy_json(source).unwrap();
        assert!(c.contains("zs_caddy_rewrite_uri("));
        assert!(c.contains("/target?x=1#frag"));
    }

    #[test]
    fn compiles_rewrite_operation_placeholders() {
        let source = r#"{
          "apps": {"http": {"servers": {"srv0": {"routes": [{
            "handle": [
              {"handler": "rewrite", "method": "{http.vars.method}", "strip_path_prefix": "{http.vars.prefix}", "strip_path_suffix": "{http.vars.suffix}", "uri_substring": [{"find": "{http.vars.find}", "replace": "{http.vars.replace}"}]},
              {"handler": "static_response", "status_code": 204}
            ]
          }]}}}}
        }"#;

        let c = compile_caddy_json(source).unwrap();
        assert!(c.contains("zs_caddy_rewrite_method(\"{http.vars.method}\""));
        assert!(c.contains("\\\"strip_path_prefix\\\":\\\"{http.vars.prefix}\\\""));
        assert!(c.contains("\\\"uri_substring\\\""));
    }

    #[test]
    fn compiles_rewrite_query_ops() {
        let source = r#"{
          "apps": {"http": {"servers": {"srv0": {"routes": [{
            "handle": [
              {"handler": "vars", "old_key": "old", "new_key": "new", "set_key": "mode", "set_value": "compiled", "add_key": "extra", "add_value": "1", "delete_key": "gone", "search_value": "raw", "replace_value": "cooked"},
              {"handler": "rewrite", "query": {
                "rename": [{"key": "{http.vars.old_key}", "val": "{http.vars.new_key}"}],
                "set": [{"key": "{http.vars.set_key}", "val": "{http.vars.set_value}"}],
                "add": [{"key": "{http.vars.add_key}", "val": "{http.vars.add_value}"}],
                "replace": [{"key": "*", "search": "{http.vars.search_value}", "replace": "{http.vars.replace_value}"}],
                "delete": ["{http.vars.delete_key}"]
              }},
              {"handler": "static_response", "status_code": 204}
            ]
          }]}}}}
        }"#;

        let c = compile_caddy_json(source).unwrap();
        assert!(c.contains("zs_req_rewrite_query("));
        assert!(c.contains("\\\"rename\\\""));
        assert!(c.contains("\\\"delete\\\""));
        assert!(c.contains("{http.vars.old_key}"));
        assert!(c.contains("{http.vars.replace_value}"));
    }

    #[test]
    fn compiles_caddyfile_uri_query_placeholders() {
        let (json, warnings) = crate::caddyfile::adapt(
            r#"example.com {
  vars {
    old_key old
    new_key new
    set_key mode
    set_value compiled
    add_key extra
    add_value 1
    delete_key gone
    search_value raw
    replace_value cooked
  }
  uri query {
    {http.vars.old_key}>{http.vars.new_key}
    {http.vars.set_key} {http.vars.set_value}
    +{http.vars.add_key} {http.vars.add_value}
    -{http.vars.delete_key}
    * {http.vars.search_value} {http.vars.replace_value}
  }
  respond ok
}"#,
            "Caddyfile",
        )
        .unwrap();
        assert!(warnings.is_empty(), "{warnings:?}");

        let c = compile_caddy_json(&json.to_string()).unwrap();
        assert!(c.contains("zs_req_rewrite_query("), "{c}");
        assert!(c.contains("{http.vars.old_key}"), "{c}");
        assert!(c.contains("{http.vars.new_key}"), "{c}");
        assert!(c.contains("{http.vars.set_value}"), "{c}");
        assert!(c.contains("{http.vars.replace_value}"), "{c}");
    }

    #[test]
    fn compiles_rewrite_query_null_ops_like_caddy_json() {
        let source = r#"{
          "apps": {"http": {"servers": {"srv0": {"routes": [{
            "handle": [
              {"handler": "rewrite", "query": {
                "rename": null,
                "set": [{"key": null, "val": null}],
                "add": null,
                "replace": [{"key": null, "search": null, "search_regexp": null, "replace": null}],
                "delete": [null]
              }},
              {"handler": "static_response", "status_code": 204}
            ]
          }]}}}}
        }"#;

        let c = compile_caddy_json(source).unwrap();
        assert!(c.contains("zs_req_rewrite_query("), "{c}");
        assert!(!c.contains("\\\"rename\\\""), "{c}");
        assert!(!c.contains("\\\"add\\\""), "{c}");
        assert!(
            c.contains("\\\"set\\\":[{\\\"key\\\":\\\"\\\",\\\"val\\\":\\\"\\\"}]"),
            "{c}"
        );
        assert!(c.contains("\\\"delete\\\":[\\\"\\\"]"), "{c}");
        assert!(c.contains("\\\"search_regexp\\\":\\\"\\\""), "{c}");
    }

    #[test]
    fn compiles_rewrite_uri_ops() {
        let source = r#"{
          "apps": {"http": {"servers": {"srv0": {"routes": [{
            "handle": [
              {"handler": "rewrite", "strip_path_prefix": "/api", "strip_path_suffix": ".json", "uri_substring": [{"find": "raw", "replace": "cooked", "limit": 1}], "path_regexp": [{"find": "/{2,}", "replace": "/"}]},
              {"handler": "static_response", "status_code": 204}
            ]
          }]}}}}
        }"#;

        let c = compile_caddy_json(source).unwrap();
        assert!(c.contains("zs_req_rewrite_uri("));
        assert!(c.contains("\\\"strip_path_prefix\\\":\\\"/api\\\""));
        assert!(c.contains("\\\"uri_substring\\\""));
        assert!(c.contains("\\\"path_regexp\\\""));
    }

    #[test]
    fn compiles_rewrite_uri_null_ops_like_caddy_json() {
        let source = r#"{
          "apps": {"http": {"servers": {"srv0": {"routes": [{
            "handle": [
              {"handler": "rewrite",
                "method": null,
                "uri": null,
                "strip_path_prefix": null,
                "strip_path_suffix": null,
                "uri_substring": [null, {"find": null, "replace": null, "limit": null}],
                "path_regexp": [{"find": "/+", "replace": null}]
              },
              {"handler": "static_response", "status_code": 204}
            ]
          }]}}}}
        }"#;

        let c = compile_caddy_json(source).unwrap();
        assert!(c.contains("zs_req_rewrite_uri("), "{c}");
        assert!(c.contains("\\\"uri_substring\\\""), "{c}");
        assert!(
            c.contains("\\\"find\\\":\\\"\\\",\\\"limit\\\":0,\\\"replace\\\":\\\"\\\""),
            "{c}"
        );
        assert!(c.contains("\\\"path_regexp\\\""), "{c}");
        assert!(c.contains("\\\"replace\\\":\\\"\\\""), "{c}");
    }

    #[test]
    fn compiles_rewrite_path_regexp_placeholder_syntax_as_literal_regex() {
        let source = r#"{
          "apps": {"http": {"servers": {"srv0": {"routes": [{
            "handle": [
              {"handler": "rewrite", "path_regexp": [{"find": "{http.vars.re}", "replace": "literal"}]},
              {"handler": "static_response", "status_code": 204}
            ]
          }]}}}}
        }"#;

        let c = compile_caddy_json(source).unwrap();
        assert!(c.contains("\\\"find\\\":\\\"{http.vars.re}\\\""), "{c}");
        assert!(c.contains("\\\"replace\\\":\\\"literal\\\""), "{c}");
    }

    #[test]
    fn compiles_rewrite_uri_null_slices_as_noops() {
        let source = r#"{
          "apps": {"http": {"servers": {"srv0": {"routes": [{
            "handle": [
              {"handler": "rewrite", "uri_substring": null, "path_regexp": null},
              {"handler": "static_response", "status_code": 204}
            ]
          }]}}}}
        }"#;

        let c = compile_caddy_json(source).unwrap();
        assert!(c.contains("zs_req_rewrite_uri("), "{c}");
        assert!(!c.contains("\\\"uri_substring\\\""), "{c}");
        assert!(!c.contains("\\\"path_regexp\\\""), "{c}");
    }

    #[test]
    fn compiles_rewrite_query_regex_replace() {
        let source = r#"{
          "apps": {"http": {"servers": {"srv0": {"routes": [{
            "handle": [
              {"handler": "rewrite", "query": {
                "replace": [
                  {"key": "*", "search_regexp": "a+", "replace": "b"},
                  {"key": "*", "search_regexp": "{http.vars.re}", "replace": "literal"}
                ]
              }},
              {"handler": "static_response", "status_code": 204}
            ]
          }]}}}}
        }"#;

        let c = compile_caddy_json(source).unwrap();
        assert!(c.contains("zs_req_rewrite_query("));
        assert!(c.contains("\\\"search_regexp\\\":\\\"a+\\\""));
        assert!(c.contains("\\\"search_regexp\\\":\\\"{http.vars.re}\\\""));
    }

    #[test]
    fn rejects_empty_rewrite_path_regexp_find() {
        let source = r#"{
          "apps": {"http": {"servers": {"srv0": {"routes": [{
            "handle": [
              {"handler": "rewrite", "path_regexp": [{"find": "", "replace": "/"}]},
              {"handler": "static_response", "status_code": 204}
            ]
          }]}}}}
        }"#;

        let err = compile_caddy_json(source).unwrap_err().to_string();
        assert!(
            err.contains("rewrite.path_regexp.find cannot be empty"),
            "{err}"
        );
    }

    #[test]
    fn rejects_invalid_rewrite_query_search_regexp() {
        let source = r#"{
          "apps": {"http": {"servers": {"srv0": {"routes": [{
            "handle": [
              {"handler": "rewrite", "query": {
                "replace": [{"key": "*", "search_regexp": "{1}", "replace": "b"}]
              }},
              {"handler": "static_response", "status_code": 204}
            ]
          }]}}}}
        }"#;

        let err = compile_caddy_json(source).unwrap_err().to_string();
        assert!(
            err.contains("invalid rewrite.query.replace.search_regexp"),
            "{err}"
        );
    }

    #[test]
    fn compiles_request_body_max_size() {
        let source = r#"{
          "apps": {"http": {"servers": {"srv0": {"routes": [{
            "handle": [
              {"handler": "request_body", "max_size": 8},
              {"handler": "static_response", "status_code": 204}
            ]
          }]}}}}
        }"#;

        let c = compile_caddy_json(source).unwrap();
        assert!(c.contains("zs_req_body_limit(8)"));
        assert!(!c.contains("zs_respond(413"), "{c}");
    }

    #[test]
    fn rejects_request_body_set() {
        let source = r#"{
          "apps": {"http": {"servers": {"srv0": {"routes": [{
            "handle": [
              {"handler": "request_body", "set": "fixed-{http.request.uri.path.1}"},
              {"handler": "static_response", "status_code": 204}
            ]
          }]}}}}
        }"#;

        let err = compile_caddy_json(source).unwrap_err().to_string();
        assert!(
            err.contains("request_body.set rewrites request bodies"),
            "{err}"
        );
    }

    #[test]
    fn rejects_positive_request_body_timeouts() {
        for (field, value) in [("read_timeout", "1"), ("write_timeout", "1")] {
            let source = format!(
                r#"{{
                  "apps": {{"http": {{"servers": {{"srv0": {{"routes": [{{
                    "handle": [
                      {{"handler": "request_body", "{field}": {value}}},
                      {{"handler": "static_response", "status_code": 204}}
                    ]
                  }}]}}}}}}}}
                }}"#
            );

            let err = compile_caddy_json(&source).unwrap_err().to_string();
            assert!(
                err.contains(&format!(
                    "request_body.{field} cannot be represented by generated eBPF middleware"
                )),
                "{field}: {err}"
            );
        }
    }

    #[test]
    fn compiles_non_positive_request_body_max_size_as_unlimited() {
        let source = r#"{
          "apps": {"http": {"servers": {"srv0": {"routes": [{
            "handle": [
              {"handler": "request_body", "max_size": -1},
              {"handler": "static_response", "status_code": 204}
            ]
          }]}}}}
        }"#;

        let c = compile_caddy_json(source).unwrap();
        assert!(!c.contains("zs_req_body_limit("), "{c}");
        assert!(!c.contains("zs_respond(413"), "{c}");
    }

    #[test]
    fn compiles_non_positive_request_body_timeouts_as_noops() {
        let source = r#"{
          "apps": {"http": {"servers": {"srv0": {"routes": [{
            "handle": [
              {"handler": "request_body", "read_timeout": 0, "write_timeout": -1},
              {"handler": "static_response", "status_code": 204}
            ]
          }]}}}}
        }"#;

        let c = compile_caddy_json(source).unwrap();
        assert!(!c.contains("request_body.read_timeout"), "{c}");
        assert!(!c.contains("request_body.write_timeout"), "{c}");
        assert!(c.contains("zs_caddy_respond_static(\"204\""), "{c}");
    }

    #[test]
    fn compiles_null_request_body_scalars_as_zero_values() {
        let source = r#"{
          "apps": {"http": {"servers": {"srv0": {"routes": [{
            "handle": [
              {"handler": "request_body", "max_size": null, "read_timeout": null, "write_timeout": null, "set": null},
              {"handler": "static_response", "status_code": 204}
            ]
          }]}}}}
        }"#;

        let c = compile_caddy_json(source).unwrap();
        assert!(!c.contains("zs_req_body_limit("), "{c}");
    }

    #[test]
    fn compiles_empty_query_matcher() {
        let source = r#"{
          "apps": {"http": {"servers": {"srv0": {"routes": [{
            "match": [{"query": {}}],
            "handle": [{"handler": "static_response", "status_code": 204}]
          }]}}}}
        }"#;

        let c = compile_caddy_json(source).unwrap();
        assert!(c.contains("zs_caddy_query_empty() != 0"));
    }

    #[test]
    fn compiles_empty_query_value_array_as_never_match() {
        let source = r#"{
          "apps": {"http": {"servers": {"srv0": {"routes": [{
            "match": [{"query": {"debug": []}}],
            "handle": [{"handler": "static_response", "status_code": 204}]
          }]}}}}
        }"#;

        let c = compile_caddy_json(source).unwrap();
        assert!(c.contains("if (((((0))))) {"), "{c}");
        assert!(!c.contains("if ((())) {"), "{c}");
    }

    #[test]
    fn clears_query_for_bare_question_mark_rewrite() {
        let source = r#"{
          "apps": {"http": {"servers": {"srv0": {"routes": [{
            "handle": [
              {"handler": "rewrite", "uri": "?"},
              {"handler": "static_response", "status_code": 204}
            ]
          }]}}}}
        }"#;

        let c = compile_caddy_json(source).unwrap();
        assert!(c.contains("zs_caddy_rewrite_uri(\"?\", 1);"));
    }

    #[test]
    fn warns_on_reverse_proxy_load_balancing_single_upstream() {
        let source = r#"{
          "apps": {"http": {"servers": {"srv0": {"routes": [{
            "handle": [{"handler": "reverse_proxy", "load_balancing": {"selection_policy": {"policy": "random"}}, "upstreams": [{"dial": "a:80"}]}]
          }]}}}}
        }"#;

        let (code, warnings) = compile_caddy_json_collecting(source).unwrap();
        assert!(
            warnings
                .iter()
                .any(|w| w.contains("ignoring reverse_proxy field \"load_balancing\"")),
            "{warnings:?}"
        );
        // The ignored field is not embedded in the generated script.
        assert!(!code.contains("warning:"), "{code}");
    }

    #[test]
    fn compiles_reverse_proxy_null_noop_fields_like_caddy_json() {
        let source = r#"{
          "apps": {"http": {"servers": {"srv0": {"routes": [{
            "handle": [{"handler": "reverse_proxy",
              "headers": null,
              "rewrite": null,
              "handle_response": null,
              "load_balancing": null,
              "health_checks": null,
              "dynamic_upstreams": null,
              "circuit_breaker": null,
              "trusted_proxies": null,
              "upstreams": [{"dial": "127.0.0.1:8080"}]
            }]
          }]}}}}
        }"#;

        let (code, warnings) = compile_caddy_json_collecting(source).unwrap();
        assert!(warnings.is_empty(), "{warnings:?}");
        assert!(
            code.contains("zs_reverse_proxy(\"http://127.0.0.1:8080\""),
            "{code}"
        );
        assert!(!code.contains("zs_caddy_reverse_proxy_rewrite("), "{code}");
        assert!(!code.contains("zs_caddy_header_op("), "{code}");
        assert!(!code.contains("zs_caddy_set_response_status("), "{code}");
    }

    #[test]
    fn compiles_noop_reverse_proxy_health_checks() {
        for health_checks in [
            "{}",
            r#"{"active": null, "passive": null}"#,
            r#"{"active": {}, "passive": {}}"#,
        ] {
            let source = format!(
                r#"{{
                  "apps": {{"http": {{"servers": {{"srv0": {{"routes": [{{
                    "handle": [{{"handler": "reverse_proxy", "health_checks": {health_checks}, "upstreams": [{{"dial": "127.0.0.1:8080"}}]}}]
                  }}]}}}}}}}}
                }}"#
            );

            let (code, warnings) = compile_caddy_json_collecting(&source)
                .unwrap_or_else(|err| panic!("{health_checks}: {err}"));
            assert!(warnings.is_empty(), "{health_checks}: {warnings:?}");
            assert!(code.contains("zs_reverse_proxy("), "{code}");
        }
    }

    #[test]
    fn rejects_configured_reverse_proxy_health_checks() {
        for (health_checks, expected) in [
            ("true", "reverse_proxy.health_checks must be an object"),
            (
                r#"{"active": true}"#,
                "reverse_proxy.health_checks.active must be an object",
            ),
            (
                r#"{"active": {"uri": "/"}}"#,
                "reverse_proxy.health_checks.active configures upstream health checks",
            ),
            (
                r#"{"passive": {"fail_duration": 1000000000}}"#,
                "reverse_proxy.health_checks.passive configures upstream health checks",
            ),
            (
                r#"{"unknown": {}}"#,
                "unsupported reverse_proxy.health_checks field \"unknown\"",
            ),
        ] {
            let source = format!(
                r#"{{
                  "apps": {{"http": {{"servers": {{"srv0": {{"routes": [{{
                    "handle": [{{"handler": "reverse_proxy", "health_checks": {health_checks}, "upstreams": [{{"dial": "127.0.0.1:8080"}}]}}]
                  }}]}}}}}}}}
                }}"#
            );

            let err = compile_caddy_json(&source).unwrap_err().to_string();
            assert!(err.contains(expected), "{health_checks}: {err}");
        }
    }

    #[test]
    fn warns_on_reverse_proxy_load_balancing_retry_controls() {
        for (field, value) in [
            ("retries", "1"),
            ("try_duration", "1000000000"),
            ("try_interval", "250000000"),
            ("retry_match", r#"[{"method": ["GET"]}]"#),
        ] {
            let source = format!(
                r#"{{
                  "apps": {{"http": {{"servers": {{"srv0": {{"routes": [{{
                    "handle": [{{"handler": "reverse_proxy", "load_balancing": {{"{field}": {value}}}, "upstreams": [{{"dial": "a:80"}}]}}]
                  }}]}}}}}}}}
                }}"#
            );

            let (_code, warnings) = compile_caddy_json_collecting(&source).unwrap();
            assert!(
                warnings.iter().any(|w| w.contains(&format!(
                    "ignoring reverse_proxy.load_balancing.{field}: retry behavior cannot be represented"
                ))),
                "{field}: {warnings:?}"
            );
        }
    }

    #[test]
    fn rejects_unknown_reverse_proxy_load_balancing_fields() {
        let source = r#"{
          "apps": {"http": {"servers": {"srv0": {"routes": [{
            "handle": [{"handler": "reverse_proxy", "load_balancing": {"unknown": true}, "upstreams": [{"dial": "a:80"}]}]
          }]}}}}
        }"#;

        let err = compile_caddy_json(source).unwrap_err().to_string();
        assert!(err.contains("unsupported reverse_proxy.load_balancing field \"unknown\""));
    }

    #[test]
    fn validates_ignored_reverse_proxy_selection_policy_like_caddy() {
        let source = r#"{
          "apps": {"http": {"servers": {"srv0": {"routes": [{
            "handle": [{"handler": "reverse_proxy", "load_balancing": {
              "selection_policy": {
                "policy": "header",
                "field": "X-Tenant",
                "fallback": {"policy": "cookie", "name": "lb", "secret": "secret", "max_age": 3600000000000}
              }
            }, "upstreams": [{"dial": "a:80"}]}]
          }]}}}}
        }"#;

        let (_, warnings) = compile_caddy_json_collecting(source).unwrap();
        assert!(
            warnings
                .iter()
                .any(|w| w.contains("ignoring reverse_proxy field \"load_balancing\"")),
            "{warnings:?}"
        );
    }

    #[test]
    fn rejects_invalid_ignored_reverse_proxy_selection_policy() {
        for (selection_policy, expected) in [
            (
                "null",
                "reverse_proxy.load_balancing.selection_policy must be an object",
            ),
            (
                r#"{"policy": "random", "unknown": true}"#,
                "unsupported reverse_proxy.load_balancing.selection_policy field \"unknown\"",
            ),
            (
                r#"{"policy": "weighted_round_robin", "weights": [1, -1]}"#,
                "reverse_proxy.load_balancing.selection_policy.weights must be non-negative",
            ),
            (
                r#"{"policy": "random_choose", "choose": "2"}"#,
                "reverse_proxy.load_balancing.selection_policy.choose must be an integer",
            ),
            (
                r#"{"policy": "header", "field": 1}"#,
                "reverse_proxy.load_balancing.selection_policy.field must be a string",
            ),
            (
                r#"{"policy": "header", "fallback": null}"#,
                "reverse_proxy.load_balancing.selection_policy must be an object",
            ),
            (
                r#"{"policy": "unknown"}"#,
                "reverse_proxy.load_balancing.selection_policy policy \"unknown\" is not available",
            ),
        ] {
            let source = format!(
                r#"{{
                  "apps": {{"http": {{"servers": {{"srv0": {{"routes": [{{
                    "handle": [{{"handler": "reverse_proxy", "load_balancing": {{"selection_policy": {selection_policy}}}, "upstreams": [{{"dial": "a:80"}}]}}]
                  }}]}}}}}}}}
                }}"#
            );

            let err = compile_caddy_json(&source).unwrap_err().to_string();
            assert!(
                err.contains(expected),
                "{selection_policy}: expected {expected:?}, got {err}"
            );
        }
    }

    #[test]
    fn warns_on_observability_only_handlers() {
        for (handler, config, expected) in [
            (
                "log_append",
                r#""key": "request_path", "value": "{http.request.uri.path}", "early": true"#,
                "ignoring log_append handler",
            ),
            (
                "tracing",
                r#""span": "request", "span_attributes": {"route": "{http.request.uri.path}"}"#,
                "ignoring tracing handler",
            ),
        ] {
            let source = format!(
                r#"{{
                  "apps": {{"http": {{"servers": {{"srv0": {{"routes": [{{
                    "handle": [
                      {{"handler": "{handler}", {config}}},
                      {{"handler": "static_response", "status_code": 204}}
                    ]
                  }}]}}}}}}}}
                }}"#
            );

            let (code, warnings) = compile_caddy_json_collecting(&source)
                .unwrap_or_else(|e| panic!("{handler} should warn, got: {e}"));
            assert!(
                warnings.iter().any(|w| w.contains(expected)),
                "{handler}: {warnings:?}"
            );
            assert!(
                code.contains("zs_caddy_respond_static(\"204\""),
                "{handler}: {code}"
            );
            assert!(!code.contains("warning:"), "{handler}: {code}");
        }
    }

    #[test]
    fn rejects_unknown_observability_handler_fields() {
        for handler in ["log_append", "tracing"] {
            let source = format!(
                r#"{{
                  "apps": {{"http": {{"servers": {{"srv0": {{"routes": [{{
                    "handle": [{{"handler": "{handler}", "unknown": true}}]
                  }}]}}}}}}}}
                }}"#
            );

            let err = compile_caddy_json(&source).unwrap_err().to_string();
            assert!(
                err.contains(&format!("unsupported {handler} field \"unknown\"")),
                "{handler}: {err}"
            );
        }
    }

    #[test]
    fn warns_on_push_handler() {
        let source = r#"{
          "apps": {"http": {"servers": {"srv0": {"routes": [{
            "handle": [
              {"handler": "push", "resources": [{"method": "GET", "target": "/app.js"}], "headers": {"set": {"X-Push": ["yes"]}}},
              {"handler": "static_response", "status_code": 204}
            ]
          }]}}}}
        }"#;

        let (code, warnings) = compile_caddy_json_collecting(source).unwrap();
        assert!(
            warnings.iter().any(|w| w.contains("ignoring push handler")),
            "{warnings:?}"
        );
        assert!(code.contains("zs_caddy_respond_static(\"204\""), "{code}");
        assert!(!code.contains("warning:"), "{code}");
    }

    #[test]
    fn rejects_invalid_push_handler_fields() {
        for (config, expected) in [
            (r#""unknown": true"#, "unsupported push field \"unknown\""),
            (
                r#""resources": {"target": "/app.js"}"#,
                "push.resources must be an array",
            ),
            (
                r#""resources": [{"target": "/app.js", "unknown": true}]"#,
                "unsupported push.resources field \"unknown\"",
            ),
            (
                r#""resources": [{"target": 1}]"#,
                "push.resources.target must be a string",
            ),
            (
                r#""headers": {"replace": {"X-Test": [{"search": "a", "unknown": true}]}}"#,
                "unsupported headers.request.replace field \"unknown\"",
            ),
            (
                r#""headers": {"replace": {"X-Test": [{"search": 1, "replace": "b"}]}}"#,
                "headers.request.replace.search must be a string",
            ),
            (
                r#""headers": {"replace": {"X-Test": [{"search_regexp": [], "replace": "b"}]}}"#,
                "headers.request.replace.search_regexp must be a string",
            ),
            (
                r#""headers": {"replace": {"X-Test": [{"search": "a", "replace": false}]}}"#,
                "headers.request.replace.replace must be a string",
            ),
        ] {
            let source = format!(
                r#"{{
                  "apps": {{"http": {{"servers": {{"srv0": {{"routes": [{{
                    "handle": [{{"handler": "push", {config}}}]
                  }}]}}}}}}}}
                }}"#
            );

            let err = compile_caddy_json(&source).unwrap_err().to_string();
            assert!(err.contains(expected), "{config}: {err}");
        }
    }

    #[test]
    fn rejects_known_out_of_surface_handlers_with_specific_errors() {
        for (handler, config, expected) in [
            (
                "metrics",
                r#""disable_openmetrics": true"#,
                "metrics handler serves Prometheus metrics",
            ),
            (
                "templates",
                r#""mime_types": ["text/html"]"#,
                "templates handler rewrites response bodies",
            ),
            (
                "copy_response",
                r#""status_code": 204"#,
                "copy_response handler copies upstream response bodies",
            ),
            (
                "copy_response_headers",
                r#""include": ["X-Upstream"]"#,
                "copy_response_headers is only meaningful inside reverse_proxy handle_response routes",
            ),
            (
                "acme_server",
                r#""ca": "local""#,
                "acme_server handler depends on Caddy ACME certificate runtime",
            ),
        ] {
            let source = format!(
                r#"{{
                  "apps": {{"http": {{"servers": {{"srv0": {{"routes": [{{
                    "handle": [{{"handler": "{handler}", {config}}}]
                  }}]}}}}}}}}
                }}"#
            );

            let err = compile_caddy_json(&source).unwrap_err().to_string();
            assert!(err.contains(expected), "{handler}: {err}");
        }
    }

    fn compile_encode(handle: &str) -> Result<String> {
        let source = format!(
            r#"{{
              "apps": {{"http": {{"servers": {{"srv0": {{"routes": [{{
                "handle": [{handle}]
              }}]}}}}}}}}
            }}"#
        );
        compile_caddy_json(&source)
    }

    #[test]
    fn compiles_encode_gzip() {
        let c = compile_encode(
            r#"{"handler": "encode", "encodings": {"gzip": {}}, "prefer": ["gzip"]}"#,
        )
        .unwrap();
        assert!(c.contains("zs_caddy_encode("), "{c}");
        assert!(c.contains("gzip"), "{c}");
    }

    #[test]
    fn compiles_encode_gzip_and_zstd_with_match_and_min_length() {
        let c = compile_encode(
            r#"{"handler": "encode",
                "encodings": {"gzip": {"level": 9}, "zstd": {"level": "best", "checksum": true}},
                "prefer": ["zstd", "gzip"],
                "minimum_length": 256,
                "match": {"status_code": [2], "headers": {"Content-Type": ["text/*"]}}}"#,
        )
        .unwrap();
        assert!(c.contains("zs_caddy_encode("), "{c}");
        // Normalized config is embedded as a C string literal.
        assert!(c.contains("minimum_length"), "{c}");
        assert!(c.contains("zstd"), "{c}");
    }

    #[test]
    fn compiles_encode_followed_by_static_response_is_non_terminal() {
        // encode does not terminate the route; the static_response after it
        // still gets emitted.
        let c = compile_encode(
            r#"{"handler": "encode", "encodings": {"gzip": {}}},
               {"handler": "static_response", "status_code": 200, "body": "hi"}"#,
        )
        .unwrap();
        assert!(c.contains("zs_caddy_encode("), "{c}");
        assert!(c.contains("zs_caddy_respond_static("), "{c}");
    }

    #[test]
    fn rejects_encode_unknown_encoder() {
        let err = compile_encode(r#"{"handler": "encode", "encodings": {"br": {}}}"#)
            .unwrap_err()
            .to_string();
        assert!(err.contains("unsupported encode encoding \"br\""), "{err}");
    }

    #[test]
    fn rejects_encode_without_encodings() {
        let err = compile_encode(r#"{"handler": "encode"}"#)
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("encode handler requires at least one encoding"),
            "{err}"
        );
    }

    #[test]
    fn rejects_encode_bad_levels_and_prefer() {
        let err = compile_encode(r#"{"handler": "encode", "encodings": {"gzip": {"level": 99}}}"#)
            .unwrap_err()
            .to_string();
        assert!(err.contains("gzip.level must be between -3 and 9"), "{err}");

        let err =
            compile_encode(r#"{"handler": "encode", "encodings": {"zstd": {"level": "turbo"}}}"#)
                .unwrap_err()
                .to_string();
        assert!(err.contains("zstd.level must be one of"), "{err}");

        let err = compile_encode(
            r#"{"handler": "encode", "encodings": {"gzip": {}}, "prefer": ["zstd"]}"#,
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("not enabled in encodings"), "{err}");

        let err = compile_encode(
            r#"{"handler": "encode", "encodings": {"gzip": {}}, "prefer": ["gzip", "gzip"]}"#,
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("is duplicated"), "{err}");
    }

    #[test]
    fn rejects_encode_unknown_field() {
        let err =
            compile_encode(r#"{"handler": "encode", "encodings": {"gzip": {}}, "bogus": true}"#)
                .unwrap_err()
                .to_string();
        assert!(err.contains("unsupported encode field \"bogus\""), "{err}");
    }

    #[test]
    fn compiles_encode_from_caddyfile() {
        // End-to-end: Caddyfile `encode gzip` -> JSON -> compiled C.
        let (config, _warnings) = crate::caddyfile::adapt(
            "example.com {\n  encode gzip\n  respond \"hi\"\n}",
            "Caddyfile",
        )
        .unwrap();
        let c = compile_caddy_json(&serde_json::to_string(&config).unwrap()).unwrap();
        assert!(c.contains("zs_caddy_encode("), "{c}");
    }

    #[test]
    fn rejects_unsupported_body_placeholders_in_supported_routes() {
        for (config, expected) in [
            (
                r#""handle": [{"handler": "static_response", "body": "{http.request.body}"}]"#,
                "{http.request.body}",
            ),
            (
                r#""match": [{"path": ["/{http.request.body_base64}"]}], "handle": [{"handler": "static_response"}]"#,
                "{http.request.body_base64}",
            ),
            (
                r#""handle": [{"handler": "headers", "response": {"set": {"X-Body": ["{http.response.body_base64}"]}}}]"#,
                "{http.response.body_base64}",
            ),
        ] {
            let source = format!(
                r#"{{
                  "apps": {{"http": {{"servers": {{"srv0": {{"routes": [{{
                    {config}
                  }}]}}}}}}}}
                }}"#
            );

            let err = compile_caddy_json(&source).unwrap_err().to_string();
            assert!(
                err.contains("unsupported body placeholder"),
                "{config}: {err}"
            );
            assert!(err.contains(expected), "{config}: {err}");
        }
    }

    #[test]
    fn allows_escaped_body_placeholder_literals() {
        let source = r#"{
          "apps": {"http": {"servers": {"srv0": {"routes": [{
            "handle": [{"handler": "static_response", "body": "\\{http.request.body}"}]
          }]}}}}
        }"#;

        let c = compile_caddy_json(source).unwrap();
        assert!(c.contains("\\\\\\{http.request.body}"), "{c}");
    }

    #[test]
    fn compiles_basic_authentication_handler() {
        let c = compile_caddy_json(
            r#"{
              "apps": {"http": {"servers": {"srv0": {"routes": [{
                "handle": [{
                  "handler": "authentication",
                  "providers": {
                    "http_basic": {
                      "hash": {"algorithm": "bcrypt"},
                      "realm": "Admin",
                      "accounts": [{
                        "username": "alice",
                        "password": "$2a$14$gqs5yvNgSqb/ksrUoam91ewSE1TjpYIgCuaiuZH395DQEPsiCVIei"
                      }]
                    }
                  }
                }, {
                  "handler": "static_response",
                  "body": "{http.auth.user.id}"
                }]
              }]}}}}
            }"#,
        )
        .unwrap();

        assert!(c.contains("zs_caddy_basic_auth("), "{c}");
        assert!(
            c.contains("zs_caddy_respond(\"{http.error.status_code}\""),
            "{c}"
        );
        assert!(c.contains("{http.auth.user.id}"), "{c}");
    }

    #[test]
    fn compiles_basic_authentication_provisioning_placeholders() {
        unsafe {
            std::env::set_var("ZS_CADDY_AUTH_USER", "env-alice");
        }
        let password_file = std::env::temp_dir().join(format!(
            "zeroserve-caddy-auth-password-{}",
            std::process::id()
        ));
        std::fs::write(
            &password_file,
            "$2a$14$gqs5yvNgSqb/ksrUoam91ewSE1TjpYIgCuaiuZH395DQEPsiCVIei\r\n",
        )
        .unwrap();

        let source = format!(
            r#"{{
              "apps": {{"http": {{"servers": {{"srv0": {{"routes": [{{
                "handle": [{{
                  "handler": "authentication",
                  "providers": {{
                    "http_basic": {{
                      "hash": {{"algorithm": "bcrypt"}},
                      "accounts": [{{
                        "username": "{{env.ZS_CADDY_AUTH_USER}}",
                        "password": "{{file.{}}}"
                      }}, {{
                        "username": "prefix-{{http.vars.missing}}",
                        "password": "$2a$14$gqs5yvNgSqb/ksrUoam91ewSE1TjpYIgCuaiuZH395DQEPsiCVIei"
                      }}]
                    }}
                  }}
                }}]
              }}]}}}}}}}}
            }}"#,
            password_file.display()
        );

        let c = compile_caddy_json(&source).unwrap();
        std::fs::remove_file(&password_file).ok();
        unsafe {
            std::env::remove_var("ZS_CADDY_AUTH_USER");
        }

        assert!(c.contains("env-alice"), "{c}");
        assert!(c.contains("prefix-"), "{c}");
        assert!(!c.contains("http.vars.missing"), "{c}");
        assert!(!c.contains("\\r\\n"), "{c}");
    }

    #[test]
    fn compiles_empty_authentication_as_unauthenticated() {
        let c = compile_caddy_json(
            r#"{
              "apps": {"http": {"servers": {"srv0": {"routes": [{
                "handle": [{"handler": "authentication", "providers": {}}]
              }]}}}}
            }"#,
        )
        .unwrap();

        assert!(c.contains("zs_caddy_set_error(\"401\""), "{c}");
        assert!(!c.contains("zs_caddy_basic_auth("), "{c}");
    }

    #[test]
    fn rejects_unsupported_authentication_providers() {
        let err = compile_caddy_json(
            r#"{
              "apps": {"http": {"servers": {"srv0": {"routes": [{
                "handle": [{
                  "handler": "authentication",
                  "providers": {"custom": {}}
                }]
              }]}}}}
            }"#,
        )
        .unwrap_err()
        .to_string();

        assert!(
            err.contains("supports only the http_basic provider"),
            "{err}"
        );
    }

    #[test]
    fn rejects_reverse_proxy_multiple_upstreams() {
        let source = r#"{
          "apps": {"http": {"servers": {"srv0": {"routes": [{
            "handle": [{"handler": "reverse_proxy", "load_balancing": {"selection_policy": {"policy": "random"}}, "upstreams": [{"dial": "a:80"}, {"dial": "b:80"}]}]
          }]}}}}
        }"#;

        let err = compile_caddy_json(source).unwrap_err().to_string();
        assert!(err.contains("multiple upstreams"), "{err}");
    }

    #[test]
    fn warns_on_reverse_proxy_runtime_fields() {
        for (field, value) in [
            ("flush_interval", "1000000000"),
            ("request_buffers", "1024"),
            ("response_buffers", "1024"),
            ("stream_timeout", "1000000000"),
            ("stream_buffer_size", "8192"),
            ("stream_close_delay", "1000000000"),
            ("verbose_logs", "true"),
        ] {
            let source = format!(
                r#"{{
                  "apps": {{"http": {{"servers": {{"srv0": {{"routes": [{{
                    "handle": [{{"handler": "reverse_proxy", "{field}": {value}, "upstreams": [{{"dial": "127.0.0.1:8080"}}]}}]
                  }}]}}}}}}}}
                }}"#
            );

            let (code, warnings) = compile_caddy_json_collecting(&source)
                .unwrap_or_else(|e| panic!("{field} should compile with a warning, got: {e}"));
            assert!(
                warnings
                    .iter()
                    .any(|w| w.contains(&format!("ignoring reverse_proxy field \"{field}\""))),
                "{field}: {warnings:?}"
            );
            assert!(code.contains("zs_reverse_proxy("), "{field}: {code}");
            assert!(!code.contains("warning:"), "{field}: {code}");
        }
    }

    #[test]
    fn rejects_unsupported_reverse_proxy_fields() {
        for (field, value, expected) in [
            (
                "circuit_breaker",
                r#"{}"#,
                "reverse_proxy.circuit_breaker configures circuit breakers",
            ),
            (
                "dynamic_upstreams",
                r#"{}"#,
                "reverse_proxy.dynamic_upstreams configures dynamic upstream discovery",
            ),
            (
                "unknown",
                "true",
                "unsupported reverse_proxy field \"unknown\"",
            ),
        ] {
            let source = format!(
                r#"{{
                  "apps": {{"http": {{"servers": {{"srv0": {{"routes": [{{
                    "handle": [{{"handler": "reverse_proxy", "{field}": {value}, "upstreams": [{{"dial": "127.0.0.1:8080"}}]}}]
                  }}]}}}}}}}}
                }}"#
            );

            let err = compile_caddy_json(&source).unwrap_err().to_string();
            assert!(err.contains(expected), "{field}: {err}");
        }
    }

    #[test]
    fn rejects_invalid_reverse_proxy_trusted_proxies_field_types() {
        for (value, expected) in [
            (
                r#""127.0.0.1/32""#,
                "reverse_proxy.trusted_proxies must be an array of strings",
            ),
            (
                r#"[1]"#,
                "reverse_proxy.trusted_proxies must contain only strings",
            ),
        ] {
            let source = format!(
                r#"{{
                  "apps": {{"http": {{"servers": {{"srv0": {{"routes": [{{
                    "handle": [{{"handler": "reverse_proxy", "trusted_proxies": {value}, "upstreams": [{{"dial": "127.0.0.1:8080"}}]}}]
                  }}]}}}}}}}}
                }}"#
            );

            let err = compile_caddy_json(&source).unwrap_err().to_string();
            assert!(err.contains(expected), "{value}: {err}");
        }
    }

    #[test]
    fn rejects_caddyfile_php_fastcgi_after_accepting_trusted_proxies() {
        let (json, warnings) = crate::caddyfile::adapt(
            r#"example.com {
  php_fastcgi localhost:9000 {
    trusted_proxies private_ranges 203.0.113.0/24
  }
}"#,
            "Caddyfile",
        )
        .unwrap();
        assert!(warnings.is_empty(), "{warnings:?}");
        let err = compile_caddy_json(&json.to_string())
            .unwrap_err()
            .to_string();
        assert!(
            err.contains(r#"reverse_proxy transport "fastcgi" cannot be represented"#),
            "{err}"
        );
    }

    #[test]
    fn warns_on_ignorable_reverse_proxy_transport_tuning_fields() {
        let source = r#"{
          "apps": {"http": {"servers": {"srv0": {"routes": [{
            "handle": [{"handler": "reverse_proxy",
              "transport": {
                "protocol": "http",
                "read_timeout": 1000000000,
                "write_timeout": 2000000000,
                "dial_timeout": 3000000000,
                "keep_alive": {"max_idle_conns": 10},
                "max_conns_per_host": 32
              },
              "upstreams": [{"dial": "127.0.0.1:8080"}]}]
          }]}}}}
        }"#;

        let (code, warnings) = compile_caddy_json_collecting(source).unwrap();
        assert!(code.contains("zs_reverse_proxy(\"http://127.0.0.1:8080\""));
        for field in [
            "read_timeout",
            "write_timeout",
            "dial_timeout",
            "keep_alive",
            "max_conns_per_host",
        ] {
            assert!(
                warnings
                    .iter()
                    .any(|w| { w.contains(&format!("ignoring reverse_proxy.transport.{field}")) }),
                "{warnings:?}"
            );
        }
    }

    #[test]
    fn warns_on_caddyfile_reverse_proxy_transport_timeout_and_keepalive_aliases() {
        let (json, adapter_warnings) = crate::caddyfile::adapt(
            r#"example.com {
  reverse_proxy 127.0.0.1:8080 {
    transport http {
      read_timeout 300s
      write_timeout 300s
      dial_timeout 30s
      keepalive 90s
      keepalive_idle_conns 10
      keepalive_idle_conns_per_host 5
      max_conns_per_host 0
    }
  }
}"#,
            "Caddyfile",
        )
        .unwrap();
        assert!(adapter_warnings.is_empty(), "{adapter_warnings:?}");

        let (code, compiler_warnings) = compile_caddy_json_collecting(&json.to_string()).unwrap();
        assert!(code.contains("zs_reverse_proxy(\"http://127.0.0.1:8080\""));
        for field in [
            "read_timeout",
            "write_timeout",
            "dial_timeout",
            "keep_alive",
            "max_conns_per_host",
        ] {
            assert!(
                compiler_warnings
                    .iter()
                    .any(|w| w.contains(&format!("ignoring reverse_proxy.transport.{field}"))),
                "{field}: {compiler_warnings:?}"
            );
        }
    }

    #[test]
    fn compiles_caddyfile_reverse_proxy_transport_compression_off() {
        let (json, adapter_warnings) = crate::caddyfile::adapt(
            r#"example.com {
  reverse_proxy 127.0.0.1:8080 {
    transport http {
      compression off
    }
  }
}"#,
            "Caddyfile",
        )
        .unwrap();
        assert!(adapter_warnings.is_empty(), "{adapter_warnings:?}");

        let (code, compiler_warnings) = compile_caddy_json_collecting(&json.to_string()).unwrap();
        assert!(
            !compiler_warnings
                .iter()
                .any(|warning| warning.contains("compression")),
            "{compiler_warnings:?}"
        );
        assert!(
            code.contains(
                "zs_meta_set(ZS_STR(\"zs.caddy.reverse_proxy.compression\"), ZS_STR(\"off\"));"
            ),
            "{code}"
        );
        assert!(code.contains("zs_reverse_proxy(\"http://127.0.0.1:8080\""));
    }

    #[test]
    fn compiles_null_reverse_proxy_http_transport_fields_like_caddy_json() {
        let source = r#"{
          "apps": {"http": {"servers": {"srv0": {"routes": [{
            "handle": [{"handler": "reverse_proxy",
              "transport": {
                "protocol": "http",
                "tls": null,
                "resolver": null,
                "keep_alive": null,
                "compression": null,
                "max_conns_per_host": null,
                "proxy_protocol": null,
                "forward_proxy_url": null,
                "dial_timeout": null,
                "dial_fallback_delay": null,
                "response_header_timeout": null,
                "expect_continue_timeout": null,
                "max_response_header_size": null,
                "write_buffer_size": null,
                "read_buffer_size": null,
                "read_timeout": null,
                "write_timeout": null,
                "versions": null,
                "local_address": null,
                "network_proxy": null
              },
              "upstreams": [{"dial": "127.0.0.1:8080"}]}]
          }]}}}}
        }"#;

        let (code, warnings) = compile_caddy_json_collecting(source).unwrap();
        assert!(warnings.is_empty(), "{warnings:?}");
        assert!(code.contains("zs_reverse_proxy(\"http://127.0.0.1:8080\""));
    }

    #[test]
    fn compiles_reverse_proxy_transport_tls_host_default_before_user_headers() {
        let source = r#"{
          "apps": {"http": {"servers": {"srv0": {"routes": [{
            "handle": [{"handler": "reverse_proxy",
              "transport": {"protocol": "http", "tls": {}},
              "headers": {"request": {"set": {"Host": ["custom.example"], "X-Test": ["ok"]}}},
              "upstreams": [{"dial": "127.0.0.1:8443"}]}]
          }]}}}}
        }"#;

        let c = compile_caddy_json(source).unwrap();
        assert!(c.contains("https://127.0.0.1:8443"), "{c}");
        let default_host = c
            .find("\\\"Host\\\":[\\\"{http.reverse_proxy.upstream.hostport}\\\"]")
            .unwrap_or_else(|| panic!("missing transport Host default: {c}"));
        let user_host = c
            .find("\\\"Host\\\":[\\\"custom.example\\\"]")
            .unwrap_or_else(|| panic!("missing user Host override: {c}"));
        assert!(
            default_host < user_host,
            "transport Host default must be emitted before user request headers: {c}"
        );
    }

    #[test]
    fn compiles_reverse_proxy_https_url_host_default() {
        let source = r#"{
          "apps": {"http": {"servers": {"srv0": {"routes": [{
            "handle": [{"handler": "reverse_proxy", "upstreams": [{"dial": "https://example.test"}]}]
          }]}}}}
        }"#;

        let c = compile_caddy_json(source).unwrap();
        assert!(
            c.contains("\\\"Host\\\":[\\\"{http.reverse_proxy.upstream.hostport}\\\"]"),
            "{c}"
        );
    }

    #[test]
    fn rejects_invalid_reverse_proxy_core_field_types() {
        for (handler, expected) in [
            (
                r#""transport": {"protocol": 1}, "upstreams": [{"dial": "127.0.0.1:8080"}]"#,
                "reverse_proxy.transport.protocol must be a string",
            ),
            (
                r#""upstreams": [{"dial": 1}]"#,
                "reverse_proxy.upstreams.dial must be a string",
            ),
        ] {
            let source = format!(
                r#"{{
                  "apps": {{"http": {{"servers": {{"srv0": {{"routes": [{{
                    "handle": [{{"handler": "reverse_proxy", {handler}}}]
                  }}]}}}}}}}}
                }}"#
            );

            let err = compile_caddy_json(&source).unwrap_err().to_string();
            assert!(err.contains(expected), "{handler}: {err}");
        }
    }

    #[test]
    fn rejects_reverse_proxy_upstream_schemes_outside_zeroserve_surface() {
        for (dial, expected) in [
            ("h2c://127.0.0.1:8080", "upstream scheme \"h2c\""),
            ("ws://127.0.0.1:8080", "upstream scheme \"ws\""),
            ("unix//var/run/backend.sock", "upstream network \"unix\""),
        ] {
            let source = format!(
                r#"{{
                  "apps": {{"http": {{"servers": {{"srv0": {{"routes": [{{
                    "handle": [{{"handler": "reverse_proxy", "upstreams": [{{"dial": "{dial}"}}]}}]
                  }}]}}}}}}}}
                }}"#
            );

            let err = compile_caddy_json(&source).unwrap_err().to_string();
            assert!(err.contains(expected), "{dial}: {err}");
        }
    }

    #[test]
    fn validates_caddy_reverse_proxy_upstream_url_components() {
        let source = r#"{
          "apps": {"http": {"servers": {"srv0": {"routes": [{
            "handle": [{"handler": "reverse_proxy", "upstreams": [{"dial": "https://example.test"}]}]
          }]}}}}
        }"#;

        let c = compile_caddy_json(source).unwrap();
        assert!(
            c.contains("zs_caddy_reverse_proxy_url(\"https://example.test\""),
            "{c}"
        );
        assert!(c.contains("zs_reverse_proxy(reverse_proxy_url_"), "{c}");
        assert!(
            c.contains("\\\"Host\\\":[\\\"{http.reverse_proxy.upstream.hostport}\\\"]"),
            "{c}"
        );

        for (dial, expected) in [
            (
                "http://example.test/",
                "only support scheme, host, and port components",
            ),
            (
                "http://example.test/path",
                "only support scheme, host, and port components",
            ),
            (
                "http://example.test?key=value",
                "only support scheme, host, and port components",
            ),
            (
                "http://example.test#frag",
                "only support scheme, host, and port components",
            ),
            (
                "http://example.test:443",
                "conflicting scheme \"http\" and HTTPS port 443",
            ),
            (
                "https://example.test:80",
                "conflicting scheme \"https\" and HTTP port 80",
            ),
        ] {
            let source = format!(
                r#"{{
                  "apps": {{"http": {{"servers": {{"srv0": {{"routes": [{{
                    "handle": [{{"handler": "reverse_proxy", "upstreams": [{{"dial": "{dial}"}}]}}]
                  }}]}}}}}}}}
                }}"#
            );

            let err = compile_caddy_json(&source).unwrap_err().to_string();
            assert!(err.contains(expected), "{dial}: {err}");
        }
    }

    #[test]
    fn rejects_unsupported_reverse_proxy_upstream_fields() {
        for field in ["unknown"] {
            let source = format!(
                r#"{{
                  "apps": {{"http": {{"servers": {{"srv0": {{"routes": [{{
                    "handle": [{{"handler": "reverse_proxy", "upstreams": [{{"dial": "127.0.0.1:8080", "{field}": 1}}]}}]
                  }}]}}}}}}}}
                }}"#
            );

            let err = compile_caddy_json(&source).unwrap_err().to_string();
            assert!(
                err.contains(&format!(
                    "unsupported reverse_proxy.upstreams field \"{field}\""
                )),
                "{field}: {err}"
            );
        }
    }

    #[test]
    fn compiles_noop_reverse_proxy_upstream_max_requests() {
        for max_requests in ["0", "null"] {
            let source = format!(
                r#"{{
                  "apps": {{"http": {{"servers": {{"srv0": {{"routes": [{{
                    "handle": [{{"handler": "reverse_proxy", "upstreams": [{{"dial": "127.0.0.1:8080", "max_requests": {max_requests}}}]}}]
                  }}]}}}}}}}}
                }}"#
            );

            let c = compile_caddy_json(&source)
                .unwrap_or_else(|err| panic!("max_requests {max_requests}: {err}"));
            assert!(c.contains("zs_reverse_proxy("), "{c}");
        }
    }

    #[test]
    fn rejects_representable_reverse_proxy_upstream_max_requests() {
        for (max_requests, expected) in [
            (
                "1",
                "reverse_proxy.upstreams.max_requests limits concurrent upstream requests",
            ),
            (
                r#""1""#,
                "reverse_proxy.upstreams.max_requests must be an integer",
            ),
        ] {
            let source = format!(
                r#"{{
                  "apps": {{"http": {{"servers": {{"srv0": {{"routes": [{{
                    "handle": [{{"handler": "reverse_proxy", "upstreams": [{{"dial": "127.0.0.1:8080", "max_requests": {max_requests}}}]}}]
                  }}]}}}}}}}}
                }}"#
            );

            let err = compile_caddy_json(&source).unwrap_err().to_string();
            assert!(err.contains(expected), "{max_requests}: {err}");
        }
    }

    #[test]
    fn rejects_custom_reverse_proxy_upstream_tls() {
        let source = r#"{
          "apps": {"http": {"servers": {"srv0": {"routes": [{
            "handle": [{"handler": "reverse_proxy", "transport": {"protocol": "http", "tls": {"server_name": "backend.example"}}, "upstreams": [{"dial": "127.0.0.1:8443"}]}]
          }]}}}}
        }"#;

        let err = compile_caddy_json(source).unwrap_err().to_string();
        assert!(err.contains("upstream TLS customization"));
    }

    #[test]
    fn compiles_file_server_route() {
        let source = r#"{
          "apps": {"http": {"servers": {"srv0": {"routes": [{
            "match": [{"path": ["/static*"]}],
            "handle": [{"handler": "file_server", "root": "public", "hide": ["secret.txt"], "index_names": ["index.txt"], "status_code": 203}]
          }]}}}}
        }"#;

        let c = compile_caddy_json(source).unwrap();
        assert!(c.contains("zs_file_server("));
        assert!(c.contains("\\\"root\\\":\\\"public\\\""));
        assert!(c.contains("\\\"status_code\\\":203"));
    }

    #[test]
    fn rejects_invalid_file_server_status_codes() {
        for status in [99, 1000] {
            let source = format!(
                r#"{{
                  "apps": {{"http": {{"servers": {{"srv0": {{"routes": [{{
                    "handle": [{{"handler": "file_server", "status_code": {status}}}]
                  }}]}}}}}}}}
                }}"#
            );

            let err = compile_caddy_json(&source).unwrap_err().to_string();
            assert!(
                err.contains("file_server.status_code must be 0 or 100..999"),
                "{err}"
            );
        }

        let source = r#"{
          "apps": {"http": {"servers": {"srv0": {"routes": [{
            "handle": [{"handler": "file_server", "status_code": 103}]
          }]}}}}
        }"#;

        let err = compile_caddy_json(source).unwrap_err().to_string();
        assert!(
            err.contains("file_server.status_code 103 Early Hints"),
            "{err}"
        );
    }

    #[test]
    fn compiles_file_server_status_zero_as_no_override() {
        let source = r#"{
          "apps": {"http": {"servers": {"srv0": {"routes": [{
            "handle": [{"handler": "file_server", "status_code": 0}]
          }]}}}}
        }"#;

        let c = compile_caddy_json(source).unwrap();
        assert!(c.contains("\\\"status_code\\\":0"), "{c}");
    }

    #[test]
    fn compiles_file_server_literal_glob_root() {
        let source = r#"{
          "apps": {"http": {"servers": {"srv0": {"routes": [{
            "handle": [{"handler": "file_server", "root": "star*root", "index_names": ["index.html"]}]
          }]}}}}
        }"#;

        let c = compile_caddy_json(source).unwrap();
        assert!(c.contains("zs_file_server("));
        assert!(c.contains("star*root"));
    }

    #[test]
    fn compiles_file_server_null_fields_like_caddy_json() {
        let source = r#"{
          "apps": {"http": {"servers": {"srv0": {"routes": [{
            "handle": [{"handler": "file_server",
              "fs": null,
              "root": null,
              "hide": [null],
              "index_names": [null],
              "etag_file_extensions": [null],
              "canonical_uris": null,
              "pass_thru": null,
              "browse": {
                "sort": null,
                "file_limit": null,
                "template_file": null,
                "reveal_symlinks": null
              },
              "precompressed": {
                "gzip": {"level": null},
                "br": {},
                "zstd": {"level": null, "checksum": null}
              },
              "precompressed_order": [null]
            }]
          }]}}}}
        }"#;

        let c = compile_caddy_json(source).unwrap();
        assert!(c.contains("zs_file_server("), "{c}");
        assert!(c.contains("\\\"hide\\\":[\\\"\\\"]"), "{c}");
        assert!(c.contains("\\\"index_names\\\":[\\\"\\\"]"), "{c}");
        assert!(c.contains("\\\"etag_file_extensions\\\":[\\\"\\\"]"), "{c}");
        assert!(c.contains("\\\"browse\\\":{}"), "{c}");
        assert!(c.contains("\\\"gzip\\\":{}"), "{c}");
        assert!(c.contains("\\\"zstd\\\":{}"), "{c}");
        assert!(c.contains("\\\"precompressed_order\\\":[\\\"\\\"]"), "{c}");
        assert!(!c.contains("\\\"fs\\\""), "{c}");
        assert!(!c.contains("\\\"root\\\""), "{c}");
        assert!(!c.contains("\\\"canonical_uris\\\""), "{c}");
        assert!(!c.contains("\\\"pass_thru\\\""), "{c}");
    }

    #[test]
    fn compiles_file_server_null_slices_as_caddy_defaults() {
        let source = r#"{
          "apps": {"http": {"servers": {"srv0": {"routes": [{
            "handle": [{"handler": "file_server",
              "hide": null,
              "index_names": null,
              "etag_file_extensions": null,
              "precompressed": null,
              "precompressed_order": null
            }]
          }]}}}}
        }"#;

        let c = compile_caddy_json(source).unwrap();
        assert!(c.contains("zs_file_server("), "{c}");
        assert!(!c.contains("\\\"hide\\\""), "{c}");
        assert!(!c.contains("\\\"index_names\\\""), "{c}");
        assert!(!c.contains("\\\"etag_file_extensions\\\""), "{c}");
        assert!(!c.contains("\\\"precompressed\\\""), "{c}");
        assert!(!c.contains("\\\"precompressed_order\\\""), "{c}");
    }

    #[test]
    fn rejects_invalid_file_server_browse_sort_order() {
        let source = r#"{
          "apps": {"http": {"servers": {"srv0": {"routes": [{
            "handle": [{"handler": "file_server", "browse": {"sort": ["asc", "name"]}}]
          }]}}}}
        }"#;

        let err = compile_caddy_json(source).unwrap_err().to_string();
        assert!(err.contains("first option"));
    }

    #[test]
    fn rejects_precompressed_sidecar_suffix_as_encoding_name() {
        for field in [
            r#""precompressed": {"zst": {}}"#,
            r#""precompressed_order": ["zst"]"#,
        ] {
            let source = format!(
                r#"{{
                  "apps": {{"http": {{"servers": {{"srv0": {{"routes": [{{
                    "handle": [{{"handler": "file_server", {field}}}]
                  }}]}}}}}}}}
                }}"#
            );

            let err = compile_caddy_json(&source).unwrap_err().to_string();
            assert!(
                err.contains("unsupported file_server precompressed encoding \"zst\""),
                "{err}"
            );
        }
    }

    #[test]
    fn rejects_caddyfile_filesystem_backends_after_adapting() {
        let (json, warnings) = crate::caddyfile::adapt(
            r#"{
  filesystem local disk /srv
}
example.com {
  file_server {
    fs local
  }
}"#,
            "Caddyfile",
        )
        .unwrap();
        assert!(
            warnings
                .iter()
                .any(|warning| warning.contains("global option 'filesystem'")),
            "{warnings:?}"
        );
        let err = compile_caddy_json(&json.to_string())
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("Caddy filesystem modules cannot be represented"),
            "{err}"
        );
    }

    #[test]
    fn validates_file_server_precompressed_module_configs() {
        let source = r#"{
          "apps": {"http": {"servers": {"srv0": {"routes": [{
            "handle": [{"handler": "file_server", "precompressed": {
              "gzip": {"level": 9},
              "br": {},
              "zstd": {"level": "best", "checksum": true}
            }}]
          }]}}}}
        }"#;

        let c = compile_caddy_json(source).unwrap();
        assert!(c.contains("\\\"precompressed\\\""));

        for (config, expected) in [
            (
                r#""precompressed": {"gzip": true}"#,
                "file_server.precompressed.gzip must be an object",
            ),
            (
                r#""precompressed": {"gzip": {"unknown": 1}}"#,
                "unsupported file_server.precompressed.gzip field \"unknown\"",
            ),
            (
                r#""precompressed": {"gzip": {"level": 10}}"#,
                "file_server.precompressed.gzip.level must be -2..9",
            ),
            (
                r#""precompressed": {"br": {"level": 1}}"#,
                "unsupported file_server.precompressed.br field \"level\"",
            ),
            (
                r#""precompressed": {"zstd": {"level": "bad"}}"#,
                "file_server.precompressed.zstd.level must be fastest, better, best, or default",
            ),
            (
                r#""precompressed": {"zstd": {"checksum": "true"}}"#,
                "file_server.precompressed.zstd.checksum must be a boolean",
            ),
        ] {
            let source = format!(
                r#"{{
                  "apps": {{"http": {{"servers": {{"srv0": {{"routes": [{{
                    "handle": [{{"handler": "file_server", {config}}}]
                  }}]}}}}}}}}
                }}"#
            );

            let err = compile_caddy_json(&source).unwrap_err().to_string();
            assert!(err.contains(expected), "{err}");
        }
    }

    #[test]
    fn rejects_unknown_file_server_fields() {
        let source = r#"{
          "apps": {"http": {"servers": {"srv0": {"routes": [{
            "handle": [{"handler": "file_server", "root": "public", "unknown": true}]
          }]}}}}
        }"#;

        let err = compile_caddy_json(source).unwrap_err().to_string();
        assert!(err.contains("unsupported file_server field \"unknown\""));
    }

    #[test]
    fn rejects_invalid_file_server_field_types() {
        for (field, expected) in [
            (r#""fs": 1"#, "file_server.fs must be a string"),
            (r#""root": 1"#, "file_server.root must be a string"),
            (
                r#""hide": "secret.txt""#,
                "file_server.hide must be an array of strings",
            ),
            (
                r#""index_names": "index.html""#,
                "file_server.index_names must be an array of strings",
            ),
            (
                r#""etag_file_extensions": ".etag""#,
                "file_server.etag_file_extensions must be an array of strings",
            ),
            (
                r#""canonical_uris": "false""#,
                "file_server.canonical_uris must be a boolean",
            ),
            (
                r#""pass_thru": "true""#,
                "file_server.pass_thru must be a boolean",
            ),
            (
                r#""precompressed_order": "gzip""#,
                "file_server.precompressed_order must be an array of strings",
            ),
        ] {
            let source = format!(
                r#"{{
                  "apps": {{"http": {{"servers": {{"srv0": {{"routes": [{{
                    "handle": [{{"handler": "file_server", {field}}}]
                  }}]}}}}}}}}
                }}"#
            );

            let err = compile_caddy_json(&source).unwrap_err().to_string();
            assert!(err.contains(expected), "{err}");
        }
    }

    #[test]
    fn validates_file_server_browse_fields() {
        let source = r#"{
          "apps": {"http": {"servers": {"srv0": {"routes": [{
            "handle": [{"handler": "file_server", "browse": {"file_limit": -1, "sort": ["name", "asc"]}}]
          }]}}}}
        }"#;

        let c = compile_caddy_json(source).unwrap();
        assert!(c.contains("\\\"file_limit\\\":-1"));

        let source = r#"{
          "apps": {"http": {"servers": {"srv0": {"routes": [{
            "handle": [{"handler": "file_server", "browse": {"reveal_symlinks": true}}]
          }]}}}}
        }"#;

        let c = compile_caddy_json(source).unwrap();
        assert!(c.contains("\\\"reveal_symlinks\\\":true"));

        let source = r#"{
          "apps": {"http": {"servers": {"srv0": {"routes": [{
            "handle": [{"handler": "file_server", "browse": {"unknown": true}}]
          }]}}}}
        }"#;

        let err = compile_caddy_json(source).unwrap_err().to_string();
        assert!(err.contains("unsupported file_server.browse field \"unknown\""));
    }

    #[test]
    fn compiles_caddyfile_file_server_browse_sort() {
        let (json, warnings) = crate::caddyfile::adapt(
            r#"example.com {
  file_server {
    browse {
      sort time desc
    }
  }
}"#,
            "Caddyfile",
        )
        .unwrap();
        assert!(warnings.is_empty(), "{warnings:?}");

        let c = compile_caddy_json(&json.to_string()).unwrap();
        assert!(
            c.contains("\\\"sort\\\":[\\\"time\\\",\\\"desc\\\"]"),
            "{c}"
        );
        assert!(!c.contains("sort_options"), "{c}");
    }

    #[test]
    fn rejects_invalid_file_server_browse_field_types() {
        let source = r#"{
          "apps": {"http": {"servers": {"srv0": {"routes": [{
            "handle": [{"handler": "file_server", "browse": true}]
          }]}}}}
        }"#;

        let err = compile_caddy_json(source).unwrap_err().to_string();
        assert!(err.contains("file_server.browse must be null or an object"));

        for (browse, expected) in [
            (
                r#""sort": "name""#,
                "file_server.browse.sort must be an array of strings",
            ),
            (
                r#""sort": [1]"#,
                "file_server.browse.sort must contain only strings",
            ),
            (
                r#""template_file": 1"#,
                "file_server.browse.template_file must be a string",
            ),
            (
                r#""reveal_symlinks": "true""#,
                "file_server.browse.reveal_symlinks must be a boolean",
            ),
        ] {
            let source = format!(
                r#"{{
                  "apps": {{"http": {{"servers": {{"srv0": {{"routes": [{{
                    "handle": [{{"handler": "file_server", "browse": {{{browse}}}}}]
                  }}]}}}}}}}}
                }}"#
            );

            let err = compile_caddy_json(&source).unwrap_err().to_string();
            assert!(err.contains(expected), "{err}");
        }
    }

    #[test]
    fn compiles_file_server_placeholders() {
        let source = r#"{
          "apps": {"http": {"servers": {"srv0": {"routes": [{
            "handle": [
              {"handler": "vars", "tenant": "{http.request.uri.path.1}", "index": "home.html", "status": "203"},
              {"handler": "rewrite", "uri": "/"},
              {"handler": "file_server", "fs": "{http.vars.fs}", "root": "sites/{http.vars.tenant}", "hide": ["{http.vars.secret}"], "index_names": ["{http.vars.index}"], "status_code": "{http.vars.status}"}
            ]
          }]}}}}
        }"#;

        let c = compile_caddy_json(source).unwrap();
        assert!(c.contains("zs_file_server("));
        assert!(c.contains("sites/{http.vars.tenant}"));
        assert!(c.contains("{http.vars.index}"));
        assert!(c.contains("\\\"status_code\\\":\\\"{http.vars.status}\\\""));
    }

    #[test]
    fn compiles_file_server_literal_etag_suffix_placeholders() {
        let source = r#"{
          "apps": {"http": {"servers": {"srv0": {"routes": [{
            "handle": [{"handler": "file_server", "root": "public", "etag_file_extensions": ["{http.vars.etag_ext}"]}]
          }]}}}}
        }"#;

        let c = compile_caddy_json(source).unwrap();
        assert!(c.contains("zs_file_server("));
        assert!(c.contains("{http.vars.etag_ext}"));
    }

    #[test]
    fn compiles_file_server_pass_thru() {
        let source = r#"{
          "apps": {"http": {"servers": {"srv0": {"routes": [{
            "handle": [
              {"handler": "file_server", "pass_thru": true},
              {"handler": "static_response", "body": "miss"}
            ]
          }]}}}}
        }"#;

        let c = compile_caddy_json(source).unwrap();
        assert!(c.contains("\\\"pass_thru\\\":true"));
        assert!(c.contains("zs_s64 zs_caddy_file_server_result_"));
        assert!(c.contains("else if (zs_caddy_file_server_result_"));
        assert!(c.contains("miss"));
    }

    #[test]
    fn compiles_file_server_miss_through_error_routes() {
        let source = r#"{
          "apps": {"http": {"servers": {"srv0": {
            "routes": [{"handle": [{"handler": "file_server"}]}],
            "errors": {"routes": [{"handle": [{"handler": "static_response", "body": "handled {http.error.status_code}"}]}]}
          }}}}
        }"#;

        let c = compile_caddy_json(source).unwrap();
        assert!(c.contains("\\\"pass_thru\\\":true"), "{c}");
        assert!(c.contains("zs_caddy_set_error(\"404\""), "{c}");
        assert!(c.contains("zs_caddy_file_server_result_"), "{c}");
        assert!(c.contains("handled {http.error.status_code}"), "{c}");
    }

    #[test]
    fn compiles_file_server_inside_error_routes_without_recursing() {
        let source = r#"{
          "apps": {"http": {"servers": {"srv0": {
            "routes": [{
              "match": [{"path": ["/boom"]}],
              "handle": [{"handler": "error", "status_code": 404}],
              "terminal": true
            }],
            "errors": {"routes": [{
              "handle": [
                {"handler": "rewrite", "uri": "/404.html"},
                {"handler": "file_server", "root": "public"}
              ]
            }]}
          }}}}
        }"#;

        let c = compile_caddy_json(source).unwrap();
        assert!(c.contains("zs_file_server("), "{c}");
        assert!(
            c.contains("zs_caddy_respond(\"{http.error.status_code}\""),
            "{c}"
        );
    }

    #[test]
    fn rejects_multiple_http_servers() {
        let source = r#"{
          "apps": {"http": {"servers": {
            "srv0": {"routes": [{"handle": [{"handler": "static_response", "body": "a"}]}]},
            "srv1": {"routes": [{"handle": [{"handler": "static_response", "body": "b"}]}]}
          }}}
        }"#;

        let err = compile_caddy_json(source).unwrap_err().to_string();
        assert!(err.contains("multiple HTTP servers"));
    }

    #[test]
    fn warns_on_non_ebpf_http_app_fields() {
        for (field, value) in [
            ("http_port", "8080"),
            ("https_port", "8443"),
            ("grace_period", r#""10s""#),
            ("shutdown_delay", r#""10s""#),
            ("metrics", r#"{}"#),
        ] {
            let source = format!(
                r#"{{
                  "apps": {{"http": {{
                    "{field}": {value},
                    "servers": {{"srv0": {{"routes": [{{"handle": [{{"handler": "static_response", "status_code": 204}}]}}]}}}}
                  }}}}
                }}"#
            );

            let (code, warnings) = compile_caddy_json_collecting(&source)
                .unwrap_or_else(|e| panic!("{field} should compile with a warning, got: {e}"));
            assert!(
                warnings
                    .iter()
                    .any(|w| w.contains(&format!("ignoring apps.http field \"{field}\""))),
                "{field}: {warnings:?}"
            );
            assert!(!code.contains("warning:"), "{field}: {code}");
        }
    }

    #[test]
    fn warns_on_non_ebpf_http_server_fields() {
        for (field, value) in [
            ("listen", r#"["127.0.0.1:8080"]"#),
            ("listener_wrappers", r#"[]"#),
            ("packet_conn_wrappers", r#"[]"#),
            ("automatic_https", r#"{"disable": true}"#),
            ("protocols", r#"["h1"]"#),
            ("listen_protocols", r#"[["127.0.0.1:8080", "h1"]]"#),
            ("strict_sni_host", r#"true"#),
            ("read_timeout", r#""10s""#),
            ("read_header_timeout", r#""10s""#),
            ("write_timeout", r#""10s""#),
            ("idle_timeout", r#""10s""#),
            ("keepalive_interval", r#""10s""#),
            ("keepalive_idle", r#""10s""#),
            ("keepalive_count", r#"10"#),
            ("enable_full_duplex", r#"true"#),
            ("max_header_bytes", r#"1024"#),
            ("metrics", r#"{}"#),
            ("experimental_http3", r#"true"#),
            ("allow_h2c", r#"true"#),
            ("allow_0rtt", r#"true"#),
        ] {
            let source = format!(
                r#"{{
                  "apps": {{"http": {{"servers": {{"srv0": {{
                    "{field}": {value},
                    "routes": [{{"handle": [{{"handler": "static_response", "status_code": 204}}]}}]
                  }}}}}}}}
                }}"#
            );

            let (code, warnings) = compile_caddy_json_collecting(&source)
                .unwrap_or_else(|e| panic!("{field} should compile with a warning, got: {e}"));
            assert!(
                warnings.iter().any(|w| w.contains(&format!(
                    "ignoring apps.http.servers.srv0 field \"{field}\""
                ))),
                "{field}: {warnings:?}"
            );
            // The ignored field is not embedded in the generated script.
            assert!(!code.contains("warning:"), "{field}: {code}");
        }
    }

    #[test]
    fn warns_on_non_ebpf_caddy_apps() {
        let source = r#"{
          "apps": {
            "tls": {"certificates": {"load_files": [{"certificate": "/c.pem", "key": "/k.pem"}]}},
            "http": {"servers": {"srv0": {"routes": [{"handle": [{"handler": "static_response", "status_code": 204}]}]}}}
          }
        }"#;

        let (_code, warnings) = compile_caddy_json_collecting(source).unwrap();
        assert!(
            warnings
                .iter()
                .any(|w| w.contains("ignoring Caddy app \"tls\"")),
            "{warnings:?}"
        );
    }

    #[test]
    fn accepts_noop_caddy_filesystem_app() {
        let source = r#"{
          "apps": {
            "caddy.filesystems": {"filesystems": [{"name": "default"}]},
            "http": {"servers": {"srv0": {"routes": [{"handle": [{"handler": "file_server", "fs": "default", "root": "public"}]}]}}}
          }
        }"#;

        let (code, warnings) = compile_caddy_json_collecting(source).unwrap();
        assert!(code.contains("zs_file_server("), "{code}");
        assert!(
            warnings
                .iter()
                .any(|warning| warning.contains("ignoring caddy.filesystems app")),
            "{warnings:?}"
        );
    }

    #[test]
    fn rejects_caddy_filesystem_modules() {
        let source = r#"{
          "apps": {
            "caddy.filesystems": {"filesystems": [{"name": "custom", "file_system": {"backend": "external"}}]},
            "http": {"servers": {"srv0": {"routes": [{"handle": [{"handler": "file_server", "fs": "custom"}]}]}}}
          }
        }"#;

        let err = compile_caddy_json(source).unwrap_err().to_string();
        assert!(
            err.contains("Caddy filesystem modules cannot be represented"),
            "{err}"
        );
    }

    #[test]
    fn rejects_invalid_caddy_filesystem_app_fields() {
        let source = r#"{
          "apps": {
            "caddy.filesystems": {"filesystems": [{"name": 1}]},
            "http": {"servers": {"srv0": {"routes": [{"handle": [{"handler": "static_response", "status_code": 204}]}]}}}
          }
        }"#;

        let err = compile_caddy_json(source).unwrap_err().to_string();
        assert!(
            err.contains("caddy.filesystems.filesystems.name must be a string"),
            "{err}"
        );
    }

    #[test]
    fn rejects_unsupported_server_trusted_proxies_fields() {
        let source = r#"{
          "apps": {"http": {"servers": {"srv0": {
            "trusted_proxies": {"source": "static", "ranges": ["127.0.0.1/32"], "unknown": true},
            "routes": [{"handle": [{"handler": "static_response", "status_code": 204}]}]
          }}}}
        }"#;

        let err = compile_caddy_json(source).unwrap_err().to_string();
        assert!(err.contains("unsupported server.trusted_proxies field \"unknown\""));
    }

    #[test]
    fn rejects_invalid_server_trusted_proxies_field_types() {
        for (field, expected) in [
            (
                r#""client_ip_headers": "X-Forwarded-For", "trusted_proxies": {"source": "static", "ranges": ["127.0.0.1/32"]}"#,
                "server.client_ip_headers must be an array of strings",
            ),
            (
                r#""trusted_proxies": {"source": 1, "ranges": ["127.0.0.1/32"]}"#,
                "server.trusted_proxies.source must be a string",
            ),
            (
                r#""trusted_proxies": {"source": "static", "ranges": "127.0.0.1/32"}"#,
                "server.trusted_proxies.ranges must be an array of strings",
            ),
            (
                r#""trusted_proxies": {"source": "static", "ranges": [1]}"#,
                "server.trusted_proxies.ranges must contain only strings",
            ),
            (
                r#""trusted_proxies": null"#,
                "server.trusted_proxies must be an object",
            ),
            (
                r#""trusted_proxies_strict": true, "trusted_proxies": {"source": "static", "ranges": ["127.0.0.1/32"]}"#,
                "server.trusted_proxies_strict must be an integer",
            ),
        ] {
            let source = format!(
                r#"{{
                  "apps": {{"http": {{"servers": {{"srv0": {{
                    {field},
                    "routes": [{{"handle": [{{"handler": "static_response", "status_code": 204}}]}}]
                  }}}}}}}}
                }}"#
            );

            let err = compile_caddy_json(&source).unwrap_err().to_string();
            assert!(err.contains(expected), "{field}: {err}");
        }
    }

    #[test]
    fn compiles_server_error_routes() {
        let source = r#"{
          "apps": {"http": {"servers": {"srv0": {
            "routes": [{"handle": [{"handler": "error", "status_code": 418}]}],
            "errors": {"routes": [{"handle": [{"handler": "static_response", "body": "handled {http.error.status_code} {http.error.status_text}"}]}]}
          }}}}
        }"#;

        let c = compile_caddy_json(source).unwrap();
        assert!(c.contains("zs_caddy_set_error(\"418\""), "{c}");
        assert!(
            c.contains("zs_caddy_respond_static(\"{http.error.status_code}\""),
            "{c}"
        );
        assert!(c.contains("handled {http.error.status_code}"), "{c}");
    }

    #[test]
    fn compiles_grouped_server_error_routes() {
        let source = r#"{
          "apps": {"http": {"servers": {"srv0": {
            "routes": [{"handle": [{"handler": "error", "status_code": 418}]}],
            "errors": {"routes": [
              {"group": "errors", "handle": [{"handler": "headers", "request": {"set": {"X-Error-Choice": ["first"]}}}]},
              {"group": "errors", "handle": [{"handler": "headers", "request": {"set": {"X-Error-Choice": ["second"]}}}]},
              {"handle": [{"handler": "static_response", "body": "{http.request.header.X-Error-Choice}"}]}
            ]}
          }}}}
        }"#;

        let c = compile_caddy_json(source).unwrap();
        assert!(
            c.contains("Caddy server error route group already satisfied; skip this route."),
            "{c}"
        );
        assert!(c.contains("route_groups"), "{c}");
        assert!(c.contains("X-Error-Choice"), "{c}");
    }

    #[test]
    fn compiles_grouped_subroute_error_routes() {
        let source = r#"{
          "apps": {"http": {"servers": {"srv0": {"routes": [{
            "handle": [{"handler": "subroute",
              "routes": [{"handle": [{"handler": "error", "status_code": 409, "error": "local"}]}],
              "errors": {"routes": [
                {"group": "sub_errors", "handle": [{"handler": "headers", "request": {"set": {"X-Sub-Error-Choice": ["first"]}}}]},
                {"group": "sub_errors", "handle": [{"handler": "headers", "request": {"set": {"X-Sub-Error-Choice": ["second"]}}}]},
                {"handle": [{"handler": "static_response", "body": "{http.request.header.X-Sub-Error-Choice}"}]}
              ]}
            }]
          }]}}}}
        }"#;

        let c = compile_caddy_json(source).unwrap();
        assert!(
            c.contains("Caddy server error route group already satisfied; skip this route."),
            "{c}"
        );
        assert!(c.contains("X-Sub-Error-Choice"), "{c}");
    }

    #[test]
    fn rejects_server_error_routes_with_unrepresentable_error_placeholders() {
        let source = r#"{
          "apps": {"http": {"servers": {"srv0": {
            "routes": [{"handle": [{"handler": "error", "status_code": 418}]}],
            "errors": {"routes": [{"handle": [{"handler": "static_response", "body": "{http.error.id}"}]}]}
          }}}}
        }"#;

        let err = compile_caddy_json(source).unwrap_err().to_string();
        assert!(err.contains("random IDs or stack traces"), "{err}");
    }

    #[test]
    fn rejects_nested_error_handlers_in_server_error_routes() {
        let source = r#"{
          "apps": {"http": {"servers": {"srv0": {
            "routes": [{"handle": [{"handler": "error", "status_code": 418}]}],
            "errors": {"routes": [{"handle": [{"handler": "error", "status_code": 500}]}]}
          }}}}
        }"#;

        let err = compile_caddy_json(source).unwrap_err().to_string();
        assert!(
            err.contains("cannot contain nested error handlers"),
            "{err}"
        );
    }

    #[test]
    fn rejects_unknown_server_errors_fields() {
        let source = r#"{
          "apps": {"http": {"servers": {"srv0": {
            "routes": [{"handle": [{"handler": "static_response", "status_code": 204}]}],
            "errors": {"unknown": true}
          }}}}
        }"#;

        let err = compile_caddy_json(source).unwrap_err().to_string();
        assert!(err.contains("unsupported apps.http.servers.srv0.errors field \"unknown\""));
    }
}
