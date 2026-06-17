//! Caddyfile -> Caddy JSON adapter, ported from `caddyconfig/httpcaddyfile`
//! (`ServerType.Setup`, `serversFromPairings`, `directives.go`). Each site
//! block's directive segments are evaluated into routes, sorted by the canonical
//! directive order, wrapped in a terminal subroute under the block's host/path
//! matchers, and assembled into `apps.http.servers.srvN.routes`.
//!
//! Scope note: TLS/PKI/auto-HTTPS apps are not reproduced (they fall outside
//! zeroserve's eBPF request-processing surface, which is what the downstream
//! `caddy_compile` consumes). Site blocks are paired into servers by derived
//! listener addresses, and the substantive `apps.http` route tree is produced
//! faithfully.

pub mod handlers;
pub mod matchers;
pub mod options;

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::rc::Rc;

use anyhow::{Result, bail};
use serde_json::{Map, Value, json};

use super::address::{Address, join_host_port, specificity};
use super::dispenser::Dispenser;
use super::parser::ServerBlock;
use super::token::Token;
use options::Options;

const MATCHER_PREFIX: &str = "@";
const DEFAULT_HTTP_PORT: i64 = 80;
const DEFAULT_HTTPS_PORT: i64 = 443;

/// Generates sequential `groupN` names, mirroring `httpcaddyfile.counter`.
#[derive(Default)]
pub struct Counter(pub i32);

impl Counter {
    pub fn next_group(&mut self) -> String {
        let name = format!("group{}", self.0);
        self.0 += 1;
        name
    }
}

/// A compiled HTTP route (`caddyhttp.Route`).
#[derive(Debug, Clone, Default)]
pub struct Route {
    pub matcher_sets: Vec<Value>,
    pub handlers: Vec<Value>,
    pub group: String,
    pub terminal: bool,
}

impl Route {
    pub fn to_json(&self) -> Value {
        let mut m = Map::new();
        if !self.group.is_empty() {
            m.insert("group".into(), json!(self.group));
        }
        if !self.matcher_sets.is_empty() {
            m.insert("match".into(), Value::Array(self.matcher_sets.clone()));
        }
        if !self.handlers.is_empty() {
            m.insert("handle".into(), Value::Array(self.handlers.clone()));
        }
        if self.terminal {
            m.insert("terminal".into(), json!(true));
        }
        Value::Object(m)
    }
}

/// A subroute handler (`caddyhttp.Subroute`).
#[derive(Debug, Clone, Default)]
pub struct Subroute {
    pub routes: Vec<Route>,
    pub errors: Vec<Route>,
}

impl Subroute {
    /// Serializes as a `subroute` handler JSON object.
    pub fn to_handler_json(&self) -> Value {
        let mut m = Map::new();
        m.insert("handler".into(), json!("subroute"));
        if !self.routes.is_empty() {
            m.insert(
                "routes".into(),
                Value::Array(self.routes.iter().map(Route::to_json).collect()),
            );
        }
        if !self.errors.is_empty() {
            m.insert(
                "errors".into(),
                json!({ "routes": self.errors.iter().map(Route::to_json).collect::<Vec<_>>() }),
            );
        }
        Value::Object(m)
    }
}

/// A value produced by a directive, placed in the server block's "pile" keyed by
/// class. Mirrors `httpcaddyfile.ConfigValue`.
#[derive(Debug, Clone)]
pub struct ConfigValue {
    pub class: String,
    pub directive: String,
    pub value: RouteOrSub,
}

#[derive(Debug, Clone)]
pub enum RouteOrSub {
    Route(Route),
    Sub(Subroute),
    Json(Value),
}

/// Shared adaptation context, threaded through directive handlers. Cheap to
/// clone (the maps are small / reference-counted).
#[derive(Clone)]
pub struct Helper {
    pub d: Dispenser,
    pub matcher_defs: HashMap<String, Value>,
    pub warnings: Rc<RefCell<Vec<String>>>,
    pub extra_apps: Rc<RefCell<Map<String, Value>>>,
    pub counter: Rc<RefCell<Counter>>,
    pub options: Rc<Options>,
    pub block_state: Rc<RefCell<HashMap<String, String>>>,
    pub caddyfiles: Vec<String>,
}

impl Helper {
    /// Replaces the dispenser, sharing all other context (for sub-segments).
    pub fn with_dispenser(&self, d: Dispenser) -> Helper {
        let mut h = self.clone();
        h.d = d;
        h
    }

    pub fn warn(&self, msg: impl Into<String>) {
        self.warnings.borrow_mut().push(msg.into());
    }

    pub fn ensure_pki_ca(&self, ca_id: &str) {
        let mut extra_apps = self.extra_apps.borrow_mut();
        let pki_app = extra_apps
            .entry("pki".to_string())
            .or_insert_with(|| json!({ "certificate_authorities": {} }));
        let pki_app = pki_app
            .as_object_mut()
            .expect("pki app side effect is always an object");
        let certificate_authorities = pki_app
            .entry("certificate_authorities".to_string())
            .or_insert_with(|| json!({}));
        let certificate_authorities = certificate_authorities
            .as_object_mut()
            .expect("pki certificate_authorities is always an object");
        certificate_authorities
            .entry(ca_id.to_string())
            .or_insert_with(|| json!({}));
    }

    pub fn next_group(&self) -> String {
        self.counter.borrow_mut().next_group()
    }

    /// Peeks the next token as a matcher. Port of `Helper.MatcherToken`.
    pub fn matcher_token(&mut self) -> Result<(Option<Value>, bool)> {
        if !self.d.next_arg() {
            return Ok((None, false));
        }
        matchers::matcher_set_from_matcher_token(&self.d.val(), &self.matcher_defs)
    }

    /// Extracts and removes a leading matcher token, then resets. Port of
    /// `Helper.ExtractMatcherSet`.
    pub fn extract_matcher_set(&mut self) -> Result<Option<Value>> {
        let (matcher, has) = self.matcher_token()?;
        if has {
            self.d.delete();
        }
        self.d.reset();
        Ok(matcher)
    }

    /// Wraps a handler in a route with an optional matcher set. Port of
    /// `Helper.NewRoute`.
    pub fn new_route(&self, matcher: Option<Value>, handler: Value) -> Vec<ConfigValue> {
        let matcher_sets = matcher.map(|m| vec![m]).unwrap_or_default();
        vec![ConfigValue {
            class: "route".into(),
            directive: String::new(),
            value: RouteOrSub::Route(Route {
                matcher_sets,
                handlers: vec![handler],
                ..Default::default()
            }),
        }]
    }
}

/// Adapts parsed server blocks into a Caddy JSON config value plus warnings.
pub fn adapt(blocks: Vec<ServerBlock>) -> Result<(Value, Vec<String>)> {
    let warnings = Rc::new(RefCell::new(Vec::<String>::new()));
    let counter = Rc::new(RefCell::new(Counter::default()));

    // Validate keys and split off the global options block (first block whose
    // keys are empty), exactly as Caddy classifies it.
    for block in &blocks {
        for (i, key) in block.keys.iter().enumerate() {
            if i == 0 && key.text.starts_with(MATCHER_PREFIX) {
                bail!(
                    "{}:{}: cannot define a matcher outside of a site block: '{}'",
                    key.file,
                    key.line,
                    key.text
                );
            }
        }
    }

    let mut site_blocks: Vec<ServerBlock> = Vec::new();
    let mut named_route_blocks: Vec<ServerBlock> = Vec::new();
    let mut global_block: Option<ServerBlock> = None;
    for (i, block) in blocks.into_iter().enumerate() {
        if block.keys.is_empty() {
            if i != 0 || global_block.is_some() {
                bail!(
                    "server block without any key is global configuration, and if used, it must be first"
                );
            }
            global_block = Some(block);
        } else if block.is_named_route {
            named_route_blocks.push(block);
        } else {
            site_blocks.push(block);
        }
    }

    for block in &site_blocks {
        if !block.has_braces
            && let Some(key) = block.keys.first()
            && is_registered_directive_name(&key.text)
        {
            bail!(
                "{}:{}: parsed '{}' as a site address, but it is a known directive; directives must appear in a site block",
                key.file,
                key.line,
                key.text
            );
        }
    }

    let options = Rc::new(options::evaluate_global_options(
        global_block,
        &mut warnings.borrow_mut(),
    )?);
    let extra_apps = Rc::new(RefCell::new(Map::<String, Value>::new()));

    let named_routes = build_named_routes(
        named_route_blocks,
        &options,
        &counter,
        &warnings,
        &extra_apps,
    )?;

    // Evaluate each site block into parsed keys + a pile of routes/error-routes.
    let mut compiled: Vec<CompiledBlock> = Vec::new();
    for block in site_blocks {
        let parsed_keys = block
            .keys
            .iter()
            .map(|k| Address::parse(&k.text))
            .collect::<Result<Vec<_>>>()?;
        let (routes, error_routes, tls_policies, acme_automation) =
            compile_block_routes(&block, &options, &counter, &warnings, &extra_apps)?;

        compiled.push(CompiledBlock {
            key_texts: block.keys_text(),
            bind_hosts: site_bind_hosts(&block),
            parsed_keys,
            routes,
            error_routes,
            tls_policies,
            acme_automation,
        });
    }

    if compiled
        .iter()
        .all(|c| c.routes.is_empty() && c.error_routes.is_empty())
    {
        // Still allow address-only configs to produce an (empty) server.
    }

    // Build the TLS automation app (ACME issuers) before `compiled` is consumed.
    let tls_app = build_tls_automation(&options, &compiled)?;

    let servers = build_servers(compiled, &options, &counter, &warnings, &named_routes)?;

    // Assemble the top-level config.
    let mut http_app = Map::new();
    if let Some(p) = options.http_port {
        http_app.insert("http_port".into(), json!(p));
    }
    if let Some(p) = options.https_port {
        http_app.insert("https_port".into(), json!(p));
    }
    http_app.insert("servers".into(), Value::Object(servers));

    let mut apps = options.extra_apps.clone();
    for (key, value) in extra_apps.borrow().iter() {
        apps.insert(key.clone(), value.clone());
    }
    if let Some(tls_app) = tls_app {
        apps.insert("tls".to_string(), tls_app);
    }
    apps.insert("http".to_string(), Value::Object(http_app));
    let config = json!({ "apps": Value::Object(apps) });
    let warns = Rc::try_unwrap(warnings)
        .map(RefCell::into_inner)
        .unwrap_or_default();
    Ok((config, warns))
}

/// Set `slot` to `value`, rejecting a different already-set value. The generated
/// `acme_config` is global (one CA/contact/EAB), so divergent per-site ACME
/// settings cannot be represented and are a hard error.
fn set_unique_acme_field(
    field: &str,
    slot: &mut Option<String>,
    value: Option<&str>,
) -> Result<()> {
    if let Some(v) = value {
        if let Some(existing) = slot
            && existing != v
        {
            bail!(
                "conflicting ACME {field} across sites ({existing:?} vs {v:?}); zeroserve issues all domains from a single ACME account, so {field} must be consistent"
            );
        }
        *slot = Some(v.to_string());
    }
    Ok(())
}

/// Build the `apps.tls` app holding ACME `automation.policies`, translating the
/// global `email`/`acme_ca`/`acme_eab` options and per-site `tls <email>` /
/// `tls internal` / `tls { ca/eab }` directives. Returns `Ok(None)` when the
/// config configures no ACME automation and no `internal` issuer. Errors when
/// sites set conflicting ACME settings. The Caddy compiler reads this to emit
/// `zeroserve.init.acme_config`.
fn build_tls_automation(
    options: &options::Options,
    compiled: &[CompiledBlock],
) -> Result<Option<Value>> {
    let mut acme_present = false;
    let mut email = options.acme_email.clone();
    let mut ca = options.acme_ca.clone();
    let mut eab = options.acme_eab.clone();
    if email.is_some() || ca.is_some() || eab.is_some() {
        acme_present = true;
    }

    let mut internal_subjects: Vec<String> = Vec::new();
    for block in compiled {
        let hosts: Vec<String> = block
            .parsed_keys
            .iter()
            .filter(|a| !a.host.is_empty())
            .map(|a| a.host.clone())
            .collect();
        for entry in &block.acme_automation {
            // `tls off` skip markers are handled in build_servers (emitted as
            // automatic_https.skip), not here.
            if entry.get("skip").and_then(Value::as_bool) == Some(true) {
                continue;
            }
            if entry.get("internal").and_then(Value::as_bool) == Some(true) {
                for host in &hosts {
                    if !internal_subjects.contains(host) {
                        internal_subjects.push(host.clone());
                    }
                }
                continue;
            }
            acme_present = true;
            set_unique_acme_field(
                "email",
                &mut email,
                entry.get("email").and_then(Value::as_str),
            )?;
            set_unique_acme_field("ca", &mut ca, entry.get("ca").and_then(Value::as_str))?;
            if let Some(e) = entry.get("eab") {
                let kid = e.get("key_id").and_then(Value::as_str);
                let mac = e.get("mac_key").and_then(Value::as_str);
                if let (Some(kid), Some(mac)) = (kid, mac) {
                    let new = (kid.to_string(), mac.to_string());
                    if let Some(existing) = &eab
                        && *existing != new
                    {
                        bail!(
                            "conflicting ACME external account binding across sites; zeroserve issues all domains from a single ACME account, so the EAB must be consistent"
                        );
                    }
                    eab = Some(new);
                }
            }
        }
    }

    let mut policies: Vec<Value> = Vec::new();
    if acme_present {
        let mut issuer = Map::new();
        issuer.insert("module".into(), json!("acme"));
        if let Some(ca) = &ca {
            issuer.insert("ca".into(), json!(ca));
        }
        if let Some(email) = &email {
            issuer.insert("email".into(), json!(email));
        }
        if let Some((kid, mac)) = &eab {
            issuer.insert(
                "external_account".into(),
                json!({ "key_id": kid, "mac_key": mac }),
            );
        }
        policies.push(json!({ "issuers": [Value::Object(issuer)] }));
    }
    if !internal_subjects.is_empty() {
        policies.push(json!({
            "subjects": internal_subjects,
            "issuers": [{ "module": "internal" }],
        }));
    }

    if policies.is_empty() {
        return Ok(None);
    }
    Ok(Some(json!({ "automation": { "policies": policies } })))
}

fn is_registered_directive_name(name: &str) -> bool {
    handlers::DIRECTIVE_ORDER.contains(&name)
        || matches!(
            name,
            "header" | "request_header" | "try_files" | "handle_errors" | "log" | "bind" | "tls"
        )
}

fn compile_block_routes(
    block: &ServerBlock,
    options: &Rc<options::Options>,
    counter: &Rc<RefCell<Counter>>,
    warnings: &Rc<RefCell<Vec<String>>>,
    extra_apps: &Rc<RefCell<Map<String, Value>>>,
) -> Result<(Vec<ConfigValue>, Vec<Subroute>, Vec<Value>, Vec<Value>)> {
    let segments: Vec<Vec<Token>> = block
        .segments
        .iter()
        .map(|seg| apply_segment_shorthands(seg))
        .collect();

    // Collect named matcher definitions for this block.
    let mut matcher_defs: HashMap<String, Value> = HashMap::new();
    for seg in &segments {
        if seg
            .first()
            .is_some_and(|t| t.text.starts_with(MATCHER_PREFIX))
        {
            let mut d = Dispenser::new(seg.clone());
            matchers::parse_matcher_definitions(&mut d, &mut matcher_defs)?;
        }
    }

    let block_state = Rc::new(RefCell::new(HashMap::new()));
    let caddyfiles = block
        .segments
        .iter()
        .flatten()
        .filter_map(|token| (!token.file.is_empty()).then(|| token.file.clone()))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    let mut routes: Vec<ConfigValue> = Vec::new();
    let mut error_routes: Vec<Subroute> = Vec::new();
    let mut tls_policies: Vec<Value> = Vec::new();
    let mut acme_automation: Vec<Value> = Vec::new();
    for seg in &segments {
        let dir = seg.first().map(|t| t.text.clone()).unwrap_or_default();
        if dir.starts_with(MATCHER_PREFIX) {
            continue; // matcher definitions handled above
        }

        let mut helper = Helper {
            d: Dispenser::new(seg.clone()),
            matcher_defs: matcher_defs.clone(),
            warnings: warnings.clone(),
            extra_apps: extra_apps.clone(),
            counter: counter.clone(),
            options: options.clone(),
            block_state: block_state.clone(),
            caddyfiles: caddyfiles.clone(),
        };

        let Some(results) = handlers::dispatch(&dir, &mut helper)? else {
            let tok = &seg[0];
            let hint = if !block.has_braces {
                "\nDid you mean to define a second site? If so, you must use curly braces around each site to separate their configurations."
            } else {
                ""
            };
            bail!(
                "{}:{}: unrecognized directive: {}{}",
                tok.file,
                tok.line,
                dir,
                hint
            );
        };

        let norm = handlers::normalize_directive_name(&dir);
        for mut result in results {
            result.directive = norm.clone();
            match result.class.as_str() {
                "error_route" => {
                    if let RouteOrSub::Sub(s) = result.value {
                        error_routes.push(s);
                    }
                }
                "tls_connection_policy" => {
                    if let RouteOrSub::Json(v) = result.value {
                        tls_policies.push(v);
                    }
                }
                "acme_automation" => {
                    if let RouteOrSub::Json(v) = result.value {
                        acme_automation.push(v);
                    }
                }
                _ => routes.push(result),
            }
        }
    }

    Ok((routes, error_routes, tls_policies, acme_automation))
}

fn apply_segment_shorthands(seg: &[Token]) -> Vec<Token> {
    seg.iter()
        .cloned()
        .map(|mut t| {
            t.text = matchers::apply_shorthands(&t.text);
            t
        })
        .collect()
}

fn build_named_routes(
    blocks: Vec<ServerBlock>,
    options: &Rc<options::Options>,
    counter: &Rc<RefCell<Counter>>,
    warnings: &Rc<RefCell<Vec<String>>>,
    extra_apps: &Rc<RefCell<Map<String, Value>>>,
) -> Result<Map<String, Value>> {
    let mut named_routes = Map::new();
    for block in blocks {
        let Some(name) = block.keys.first().map(|k| k.text.clone()) else {
            continue;
        };
        if named_routes.contains_key(&name) {
            bail!("cannot have duplicate named_routes: {name}");
        }

        let (routes, error_routes, _, _) =
            compile_block_routes(&block, options, counter, warnings, extra_apps)?;
        let mut subroute =
            handlers::build_subroute(routes, counter, true, &options.directive_order)?;
        for errors in error_routes {
            subroute.errors.extend(errors.routes);
        }

        let route = if subroute.errors.is_empty()
            && subroute.routes.len() == 1
            && subroute.routes[0].matcher_sets.is_empty()
        {
            subroute.routes[0].to_json()
        } else {
            json!({ "handle": [subroute.to_handler_json()] })
        };
        named_routes.insert(name, route);
    }
    Ok(named_routes)
}

struct CompiledBlock {
    key_texts: Vec<String>,
    bind_hosts: Vec<String>,
    parsed_keys: Vec<Address>,
    routes: Vec<ConfigValue>,
    error_routes: Vec<Subroute>,
    tls_policies: Vec<Value>,
    acme_automation: Vec<Value>,
}

#[derive(Debug, Clone)]
struct BlockPlacement {
    block_idx: usize,
    listen: Vec<String>,
    matcher_keys: Vec<Address>,
}

/// Groups site blocks into servers by their derived listen port and builds each
/// server's route list. Mirrors the substantive part of `serversFromPairings`.
fn build_servers(
    blocks: Vec<CompiledBlock>,
    options: &Options,
    counter: &Rc<RefCell<Counter>>,
    warnings: &Rc<RefCell<Vec<String>>>,
    named_routes: &Map<String, Value>,
) -> Result<Map<String, Value>> {
    let http_port = options.http_port.unwrap_or(DEFAULT_HTTP_PORT);
    let https_port = options.https_port.unwrap_or(DEFAULT_HTTPS_PORT);

    // Determine listen addresses per key and group placements by listener set.
    let mut groups: BTreeMap<String, Vec<usize>> = BTreeMap::new();
    let mut placements = Vec::<BlockPlacement>::new();
    for (idx, block) in blocks.iter().enumerate() {
        for placement in block_placements(idx, block, http_port, https_port) {
            let key = placement.listen.join(",");
            groups.entry(key).or_default().push(placements.len());
            placements.push(placement);
        }
    }

    detect_ambiguous_site_definitions(&blocks, &placements)?;

    // Sort blocks within each group by host/path specificity (most specific
    // first; catch-all last), mirroring serversFromPairings' stable sort.
    let mut servers = Map::new();
    for (srv_index, (_, mut placement_idxs)) in groups.into_iter().enumerate() {
        placement_idxs.sort_by(|&a, &b| {
            block_specificity_cmp(&placements[a].matcher_keys, &placements[b].matcher_keys)
        });

        let listen = placements[*placement_idxs.first().unwrap()].listen.clone();
        let mut routes: Vec<Value> = Vec::new();
        let mut error_routes: Vec<Value> = Vec::new();
        let mut tls_connection_policies: Vec<Value> = Vec::new();
        let mut skip_hosts: Vec<String> = Vec::new();

        for &placement_idx in &placement_idxs {
            let placement = &placements[placement_idx];
            let block = blocks[placement.block_idx].routes.clone();
            let err_subs = blocks[placement.block_idx].error_routes.clone();
            let tls_policies = blocks[placement.block_idx].tls_policies.clone();
            let matcher_sets = compile_encoded_matcher_sets(&placement.matcher_keys)?;
            let sni = tls_policy_sni_hosts(&placement.matcher_keys);

            // `tls off`: exclude this site's hostnames from automatic HTTPS.
            let skipped = blocks[placement.block_idx]
                .acme_automation
                .iter()
                .any(|e| e.get("skip").and_then(Value::as_bool) == Some(true));
            if skipped {
                for host in &sni {
                    if !skip_hosts.contains(host) {
                        skip_hosts.push(host.clone());
                    }
                }
            }

            let site_subroute =
                handlers::build_subroute(block, counter, true, &options.directive_order)?;
            append_subroute_to_route_list(
                &mut routes,
                &site_subroute,
                &matcher_sets,
                placement_idxs.len() == 1,
            );

            if !err_subs.is_empty() {
                let err_subs = sort_error_subroutes(err_subs);
                let mut merged = Subroute::default();
                for s in err_subs {
                    merged.routes.extend(s.routes);
                }
                append_subroute_to_route_list(&mut error_routes, &merged, &matcher_sets, true);
            }
            for policy in tls_policies {
                tls_connection_policies.push(scope_tls_policy_to_sni(policy, &sni));
            }
        }

        let mut srv = Map::new();
        if !listen.is_empty() {
            srv.insert("listen".into(), json!(listen));
        }
        if !routes.is_empty() {
            srv.insert("routes".into(), Value::Array(routes));
        }
        if !error_routes.is_empty() {
            srv.insert("errors".into(), json!({ "routes": error_routes }));
        }
        if !tls_connection_policies.is_empty() {
            srv.insert(
                "tls_connection_policies".into(),
                Value::Array(tls_connection_policies),
            );
        }
        if !skip_hosts.is_empty() {
            skip_hosts.sort();
            srv.insert("automatic_https".into(), json!({ "skip": skip_hosts }));
        }
        if !named_routes.is_empty() {
            srv.insert("named_routes".into(), Value::Object(named_routes.clone()));
        }
        options.apply_to_server(&mut srv, &mut warnings.borrow_mut());
        let name = listen
            .iter()
            .find_map(|addr| options.server_names.get(addr))
            .cloned()
            .unwrap_or_else(|| format!("srv{srv_index}"));
        servers.insert(name, Value::Object(srv));
    }

    Ok(servers)
}

fn detect_ambiguous_site_definitions(
    blocks: &[CompiledBlock],
    placements: &[BlockPlacement],
) -> Result<()> {
    for i in 0..placements.len() {
        for j in (i + 1)..placements.len() {
            if placements[i].block_idx == placements[j].block_idx {
                continue;
            }
            if !placements[i]
                .listen
                .iter()
                .any(|listen| placements[j].listen.contains(listen))
            {
                continue;
            }
            for key in &blocks[placements[i].block_idx].key_texts {
                if blocks[placements[j].block_idx].key_texts.contains(key) {
                    bail!("ambiguous site definition: {key}");
                }
            }
        }
    }
    Ok(())
}

fn block_placements(
    block_idx: usize,
    block: &CompiledBlock,
    http_port: i64,
    https_port: i64,
) -> Vec<BlockPlacement> {
    let mut by_listener = BTreeMap::<String, BlockPlacement>::new();
    for addr in &block.parsed_keys {
        let listen = listen_addrs_for_key(addr, &block.bind_hosts, http_port, https_port);
        let key = listen.join(",");
        let placement = by_listener.entry(key).or_insert_with(|| BlockPlacement {
            block_idx,
            listen,
            matcher_keys: Vec::new(),
        });
        placement.matcher_keys.push(addr.clone());
    }
    if by_listener.is_empty() {
        by_listener.insert(
            format!(":{https_port}"),
            BlockPlacement {
                block_idx,
                listen: vec![format!(":{https_port}")],
                matcher_keys: Vec::new(),
            },
        );
    }
    by_listener.into_values().collect()
}

fn site_bind_hosts(block: &ServerBlock) -> Vec<String> {
    let mut hosts = Vec::new();
    for segment in &block.segments {
        if segment.first().is_none_or(|token| token.text != "bind") {
            continue;
        }
        for token in segment.iter().skip(1) {
            if token.text == "{" {
                break;
            }
            if !hosts.contains(&token.text) {
                hosts.push(token.text.clone());
            }
        }
    }
    hosts
}

fn sort_error_subroutes(subroutes: Vec<Subroute>) -> Vec<Subroute> {
    let mut matched = Vec::new();
    let mut fallback = Vec::new();
    for subroute in subroutes {
        if subroute
            .routes
            .first()
            .is_some_and(|route| route.matcher_sets.is_empty())
        {
            fallback.push(subroute);
        } else {
            matched.push(subroute);
        }
    }
    matched.reverse();
    matched.extend(fallback);
    matched
}

fn listen_addrs_for_key(
    addr: &Address,
    bind_hosts: &[String],
    http_port: i64,
    https_port: i64,
) -> Vec<String> {
    let port = if !addr.port.is_empty() {
        addr.port.clone()
    } else if addr.scheme == "http" {
        http_port.to_string()
    } else if addr.scheme == "https" {
        https_port.to_string()
    } else {
        https_port.to_string()
    };
    let mut listen = if bind_hosts.is_empty() {
        vec![format!(":{port}")]
    } else {
        bind_hosts
            .iter()
            .map(|host| join_host_port(host, &port))
            .collect()
    };
    listen.sort();
    listen.dedup();
    listen
}

/// Comparison used to sort server blocks: most specific host (then path) first,
/// wildcard hosts less specific, catch-all (no host) last. Port of the stable
/// sort in `serversFromPairings`.
fn block_specificity_cmp(a: &[Address], b: &[Address]) -> std::cmp::Ordering {
    use std::cmp::Ordering;
    let (ai_host, ai_path, ai_wild) = longest_host_path(a);
    let (bi_host, bi_path, bi_wild) = longest_host_path(b);

    let ai_host_specificity = specificity(&ai_host);
    let bi_host_specificity = specificity(&bi_host);

    if ai_host_specificity == 0 && bi_host_specificity == 0 {
        return Ordering::Equal;
    }
    if ai_host_specificity == 0 {
        return Ordering::Greater; // catch-all goes last
    }
    if bi_host_specificity == 0 {
        return Ordering::Less;
    }
    if ai_wild != bi_wild {
        return if bi_wild && !ai_wild {
            Ordering::Less
        } else {
            Ordering::Greater
        };
    }
    if ai_host_specificity == bi_host_specificity {
        return bi_path.len().cmp(&ai_path.len());
    }
    bi_host_specificity.cmp(&ai_host_specificity)
}

fn longest_host_path(keys: &[Address]) -> (String, String, bool) {
    let mut longest_host = String::new();
    let mut longest_path = String::new();
    let mut wildcard = false;
    for addr in keys {
        if addr.host.contains('*') || addr.host.is_empty() {
            wildcard = true;
        }
        if specificity(&addr.host) > specificity(&longest_host) {
            longest_host = addr.host.clone();
        }
        if specificity(&addr.path) > specificity(&longest_path) {
            longest_path = addr.path.clone();
        }
    }
    (longest_host, longest_path, wildcard)
}

/// Builds the host/path matcher sets for a server block's keys. Port of
/// `compileEncodedMatcherSets`.
fn compile_encoded_matcher_sets(keys: &[Address]) -> Result<Vec<Value>> {
    struct Pair {
        hosts: Vec<String>,
        path: Option<String>,
    }
    let mut pairs: Vec<Pair> = Vec::new();
    let mut catch_all_hosts = false;

    for addr in keys {
        let chosen = match pairs
            .iter_mut()
            .find(|p| match (&p.path, addr.path.as_str()) {
                (None, "") => true,
                (Some(pp), ap) => pp == ap,
                _ => false,
            }) {
            Some(p) => p,
            None => {
                pairs.push(Pair {
                    hosts: Vec::new(),
                    path: if addr.path.is_empty() {
                        None
                    } else {
                        Some(addr.path.clone())
                    },
                });
                pairs.last_mut().unwrap()
            }
        };

        if addr.host.is_empty() && !catch_all_hosts {
            chosen.hosts.clear();
            catch_all_hosts = true;
        }
        if catch_all_hosts {
            continue;
        }
        if !addr.host.is_empty() && !chosen.hosts.contains(&addr.host) {
            chosen.hosts.push(addr.host.clone());
        }
    }

    let mut sets: Vec<Value> = Vec::new();
    for p in pairs {
        let mut m = Map::new();
        if !p.hosts.is_empty() {
            m.insert("host".into(), json!(p.hosts));
        }
        if let Some(path) = p.path {
            m.insert("path".into(), json!([path]));
        }
        if !m.is_empty() {
            sets.push(Value::Object(m));
        }
    }
    Ok(sets)
}

fn tls_policy_sni_hosts(keys: &[Address]) -> Vec<String> {
    let mut hosts = Vec::new();
    for addr in keys {
        if addr.host.is_empty() {
            return Vec::new();
        }
        if !hosts.contains(&addr.host) {
            hosts.push(addr.host.clone());
        }
    }
    hosts
}

fn scope_tls_policy_to_sni(mut policy: Value, sni: &[String]) -> Value {
    if sni.is_empty() {
        return policy;
    }
    let Some(obj) = policy.as_object_mut() else {
        return policy;
    };
    obj.insert("match".into(), json!({ "sni": sni }));
    policy
}

/// Appends a site's subroute to a server's route list, wrapping in a terminal
/// subroute when needed. Port of `appendSubrouteToRouteList`.
fn append_subroute_to_route_list(
    route_list: &mut Vec<Value>,
    subroute: &Subroute,
    matcher_sets: &[Value],
    single_block: bool,
) {
    if matcher_sets.is_empty() && subroute.routes.is_empty() && subroute.errors.is_empty() {
        return;
    }

    // If this is the only block and there's no key matcher, avoid wrapping
    // unless a host matcher appears inside (see Caddy issue #5124).
    let mut wrap = true;
    if matcher_sets.is_empty() && single_block {
        let has_host = subroute
            .routes
            .iter()
            .any(|r| r.matcher_sets.iter().any(|ms| ms.get("host").is_some()));
        wrap = has_host;
    }

    if wrap {
        let mut route = Route {
            terminal: true,
            ..Default::default()
        };
        if !matcher_sets.is_empty() {
            route.matcher_sets = matcher_sets.to_vec();
        }
        if !subroute.routes.is_empty() || !subroute.errors.is_empty() {
            route.handlers = vec![subroute.to_handler_json()];
        }
        if !route.matcher_sets.is_empty() || !route.handlers.is_empty() {
            route_list.push(route.to_json());
        }
    } else {
        for r in &subroute.routes {
            route_list.push(r.to_json());
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::caddyfile::adapt;
    use serde_json::{Value, json};
    use std::fs;

    fn routes(input: &str) -> Value {
        let (v, _) = adapt(input, "Caddyfile").unwrap();
        v["apps"]["http"]["servers"]["srv0"]["routes"].clone()
    }

    fn error_routes(input: &str) -> Value {
        let (v, _) = adapt(input, "Caddyfile").unwrap();
        v["apps"]["http"]["servers"]["srv0"]["errors"]["routes"].clone()
    }

    fn adapt_full(input: &str) -> (Value, Vec<String>) {
        adapt(input, "Caddyfile").unwrap()
    }

    fn adapt_err(input: &str) -> String {
        adapt(input, "Caddyfile").unwrap_err().to_string()
    }

    fn first_handler<'a>(value: &'a Value, name: &str) -> Option<&'a Value> {
        match value {
            Value::Object(map) if map.get("handler").and_then(Value::as_str) == Some(name) => {
                Some(value)
            }
            Value::Object(map) => map.values().find_map(|value| first_handler(value, name)),
            Value::Array(values) => values.iter().find_map(|value| first_handler(value, name)),
            _ => None,
        }
    }

    #[test]
    fn simple_respond() {
        let r = routes("example.com {\n  respond \"Hello\" 200\n}");
        assert_eq!(
            r,
            json!([{
                "match": [{"host": ["example.com"]}],
                "handle": [{
                    "handler": "subroute",
                    "routes": [{
                        "handle": [{"handler": "static_response", "status_code": 200, "body": "Hello"}]
                    }]
                }],
                "terminal": true
            }])
        );
    }

    #[test]
    fn respond_rejects_duplicate_close() {
        let err = adapt_err(
            r#"example.com {
  respond ok {
    close
    close
  }
}"#,
        );
        assert!(err.contains("close already specified"), "{err}");
    }

    #[test]
    fn zeroserve_call_directive_lowers_to_custom_handler() {
        let r = routes(
            r#"example.com {
  zeroserve_call auth authorize {
    scope admin
    flags one two
    enabled
  }
}"#,
        );
        let h = first_handler(&r, "zeroserve_call").unwrap();
        assert_eq!(h["script"], json!("auth"));
        assert_eq!(h["function"], json!("authorize"));
        assert_eq!(h["config"]["scope"], json!("admin"));
        assert_eq!(h["config"]["flags"], json!(["one", "two"]));
        assert_eq!(h["config"]["enabled"], json!(true));
    }

    #[test]
    fn inline_path_matcher_and_ordering() {
        // file_server is ordered after respond; a path matcher narrows the route.
        let r = routes("example.com {\n  respond /api* \"hi\"\n  respond \"fallback\"\n}");
        let handlers = &r[0]["handle"][0]["routes"];
        // The /api* route should come before the catch-all (more specific path).
        assert_eq!(handlers[0]["match"][0]["path"], json!(["/api*"]));
        assert_eq!(handlers[1].get("match"), None);
    }

    #[test]
    fn path_sort_trims_only_one_trailing_wildcard_like_caddy() {
        let r = routes(
            r#"example.com {
  respond /a** "double"
  respond /ab* "ab"
}"#,
        );
        let handlers = &r[0]["handle"][0]["routes"];
        assert_eq!(handlers[0]["match"][0]["path"], json!(["/a**"]));
        assert_eq!(handlers[1]["match"][0]["path"], json!(["/ab*"]));
    }

    #[test]
    fn vars_routes_with_equal_specificity_reverse_like_caddy() {
        let r = routes(
            r#"example.com {
  vars first one
  vars second two
  respond "{http.vars.first}-{http.vars.second}"
}"#,
        );
        let handlers = &r[0]["handle"][0]["routes"][0]["handle"];
        assert_eq!(handlers[0], json!({"handler": "vars", "second": "two"}));
        assert_eq!(handlers[1], json!({"handler": "vars", "first": "one"}));
    }

    #[test]
    fn tls_matcher_adapts() {
        let r = routes(
            r#"example.com {
  @secure tls
  @early tls early_data
  respond @secure ok
  respond @early early
}"#,
        );
        let handlers = &r[0]["handle"][0]["routes"];
        assert_eq!(handlers[0]["match"][0]["tls"], json!({}));
        assert_eq!(
            handlers[1]["match"][0]["tls"],
            json!({"handshake_complete": false})
        );
    }

    #[test]
    fn tls_matcher_rejects_invalid_option() {
        let err = adapt_err(
            r#"example.com {
  @bad tls no
  respond @bad ok
}"#,
        );
        assert!(err.contains("unrecognized option 'no'"), "{err}");
    }

    #[test]
    fn file_matcher_adapts_caddyfile_syntax() {
        let r = routes(
            r#"example.com {
  @exists file /index.html {
    root /srv/site
    try_files {path} {path}/index.html
    try_policy first_exist_fallback
    split_path .php .cgi
  }
  rewrite @exists {file_match.relative}
}"#,
        );
        let matcher = &r[0]["handle"][0]["routes"][0]["match"][0]["file"];
        assert_eq!(matcher["root"], "/srv/site");
        assert_eq!(
            matcher["try_files"],
            json!([
                "/index.html",
                "{http.request.uri.path}",
                "{http.request.uri.path}/index.html"
            ])
        );
        assert_eq!(matcher["try_policy"], "first_exist_fallback");
        assert_eq!(matcher["split_path"], json!([".php", ".cgi"]));
    }

    #[test]
    fn file_matcher_without_try_files_keeps_caddy_default() {
        let r = routes(
            r#"example.com {
  @exists file {
    root /srv/site
  }
  respond @exists ok
}"#,
        );
        let matcher = &r[0]["handle"][0]["routes"][0]["match"][0]["file"];
        assert_eq!(matcher["root"], "/srv/site");
        assert!(matcher.get("try_files").is_none());
    }

    #[test]
    fn file_matcher_empty_try_files_uses_accumulated_files_like_caddy() {
        let r = routes(
            r#"example.com {
  @exists file /index.html {
    try_files
  }
  respond @exists ok
}"#,
        );
        let matcher = &r[0]["handle"][0]["routes"][0]["match"][0]["file"];
        assert_eq!(matcher["try_files"], json!(["/index.html"]));

        let err = adapt_err(
            r#"example.com {
  @bad file {
    try_files
  }
  respond @bad ok
}"#,
        );
        assert!(err.contains("wrong argument count"), "{err}");
    }

    #[test]
    fn file_matcher_rejects_unknown_subdirective() {
        let err = adapt_err(
            r#"example.com {
  @bad file {
    nope value
  }
  respond @bad ok
}"#,
        );
        assert!(err.contains("unrecognized subdirective: nope"), "{err}");
    }

    #[test]
    fn global_order_changes_directive_sorting() {
        let r = routes(
            r#"{
  order respond before header
}
example.com {
  header X-Test yes
  respond ok
}"#,
        );
        let handlers = r[0]["handle"][0]["routes"][0]["handle"].as_array().unwrap();
        assert_eq!(handlers[0]["handler"], "static_response");
        assert_eq!(handlers[1]["handler"], "headers");
    }

    #[test]
    fn global_order_does_not_sort_route_blocks() {
        let r = routes(
            r#"{
  order respond before header
}
example.com {
  route {
    header X-Test yes
    respond ok
  }
}"#,
        );
        let route_handlers = r[0]["handle"][0]["routes"][0]["handle"][0]["routes"][0]["handle"]
            .as_array()
            .unwrap();
        assert_eq!(route_handlers[0]["handler"], "headers");
        assert_eq!(route_handlers[1]["handler"], "static_response");
    }

    #[test]
    fn global_order_handle_path_uses_raw_order_key() {
        let r = routes(
            r#"{
  order handle_path last
}
example.com {
  respond ok
  handle_path /api/* {
    respond api
  }
}"#,
        );
        let site_routes = r[0]["handle"][0]["routes"].as_array().unwrap();
        assert_eq!(site_routes[0]["match"][0]["path"], json!(["/api/*"]));
        assert_eq!(site_routes[0]["handle"][0]["handler"], "subroute");
        assert_eq!(site_routes[1]["handle"][0]["handler"], "static_response");
    }

    #[test]
    fn global_order_handle_controls_handle_path_routes() {
        let r = routes(
            r#"{
  order handle last
}
example.com {
  respond ok
  handle_path /api/* {
    respond api
  }
}"#,
        );
        let site_routes = r[0]["handle"][0]["routes"].as_array().unwrap();
        assert_eq!(site_routes[0]["handle"][0]["handler"], "static_response");
        assert_eq!(site_routes[1]["match"][0]["path"], json!(["/api/*"]));
        assert_eq!(site_routes[1]["handle"][0]["handler"], "subroute");
    }

    #[test]
    fn global_order_rejects_unknown_position() {
        let err = adapt_err(
            r#"{
  order respond sideways header
}
example.com {
  respond ok
}"#,
        );
        assert!(err.contains("unknown positional 'sideways'"), "{err}");
    }

    #[test]
    fn global_order_rejects_unknown_directive() {
        let err = adapt_err(
            r#"{
  order not_a_directive first
}
example.com {
  respond ok
}"#,
        );
        assert!(
            err.contains("not_a_directive is not a registered directive"),
            "{err}"
        );
    }

    #[test]
    fn global_order_rejects_missing_target_directive() {
        let err = adapt_err(
            r#"{
  order respond before not_a_directive
}
example.com {
  respond ok
}"#,
        );
        assert!(
            err.contains("directive 'not_a_directive' not found"),
            "{err}"
        );
    }

    #[test]
    fn servers_trusted_proxy_options_lower_to_server_json() {
        let (v, _) = adapt_full(
            r#"{
  servers {
    trusted_proxies static private_ranges 203.0.113.0/24
    trusted_proxies_strict
    trusted_proxies_unix
    client_ip_headers X-Forwarded-For CF-Connecting-IP
  }
}
example.com {
  respond ok
}"#,
        );
        let srv = &v["apps"]["http"]["servers"]["srv0"];
        assert_eq!(
            srv["trusted_proxies"],
            json!({"source": "static", "ranges": ["private_ranges", "203.0.113.0/24"]})
        );
        assert_eq!(srv["trusted_proxies_strict"], 1);
        assert_eq!(srv["trusted_proxies_unix"], true);
        assert_eq!(
            srv["client_ip_headers"],
            json!(["X-Forwarded-For", "CF-Connecting-IP"])
        );
    }

    #[test]
    fn servers_protocols_and_max_header_size_validate_like_caddy() {
        let (v, _) = adapt_full(
            r#"{
  servers {
    protocols h1 h2 h2c h3
    max_header_size 10kb
  }
}
example.com {
  respond ok
}"#,
        );
        let srv = &v["apps"]["http"]["servers"]["srv0"];
        assert_eq!(srv["protocols"], json!(["h1", "h2", "h2c", "h3"]));
        assert_eq!(srv["max_header_bytes"], 10_000);

        for (input, expected) in [
            (
                r#"{
  servers {
    protocols h1 h1
  }
}
example.com {
  respond ok
}"#,
                "protocol h1 specified more than once",
            ),
            (
                r#"{
  servers {
    protocols tls1.3
  }
}
example.com {
  respond ok
}"#,
                "unknown protocol 'tls1.3': expected h1, h2, h2c, or h3",
            ),
            (
                r#"{
  servers {
    protocols {
      h1
    }
  }
}
example.com {
  respond ok
}"#,
                "wrong argument count",
            ),
            (
                r#"{
  servers {
    max_header_size nope
  }
}
example.com {
  respond ok
}"#,
                "parsing max_header_size",
            ),
        ] {
            let err = adapt_err(input);
            assert!(err.contains(expected), "{err}");
        }
    }

    #[test]
    fn servers_client_ip_headers_reject_duplicates_and_blocks_like_caddy() {
        for (input, expected) in [
            (
                r#"{
  servers {
    client_ip_headers X-Forwarded-For X-Forwarded-For
  }
}
example.com {
  respond ok
}"#,
                "client IP header X-Forwarded-For specified more than once",
            ),
            (
                r#"{
  servers {
    client_ip_headers {
      X-Forwarded-For
    }
  }
}
example.com {
  respond ok
}"#,
                "wrong argument count",
            ),
        ] {
            let err = adapt_err(input);
            assert!(err.contains(expected), "{err}");
        }
    }

    #[test]
    fn servers_reject_unknown_options_like_caddy() {
        let err = adapt_err(
            r#"{
  servers {
    unknown on
  }
}
example.com {
  respond ok
}"#,
        );
        assert!(
            err.contains("unrecognized servers option 'unknown'"),
            "{err}"
        );
    }

    #[test]
    fn servers_metrics_rejects_unknown_suboptions_like_caddy() {
        let err = adapt_err(
            r#"{
  servers {
    metrics {
      unknown
    }
  }
}
example.com {
  respond ok
}"#,
        );
        assert!(
            err.contains("unrecognized metrics option 'unknown'"),
            "{err}"
        );
    }

    #[test]
    fn current_global_options_are_accepted_outside_ebpf_surface() {
        let (_, warnings) = adapt_full(
            r#"{
  storage_check off
  storage_clean_interval off
  renew_interval 10m
  ocsp_interval 5m
  acme_ca_root /tmp/root.pem
  ocsp_stapling off
  cert_lifetime 24h
  tls_resolvers 1.1.1.1
  renewal_window_ratio 0.5
  pki {
    ca local {
      name "Local CA"
    }
  }
  events {
    on cert_obtained exec echo ok
  }
  storage file_system /tmp/caddy-data
  acme_dns
  acme_eab {
    key_id kid
    mac_key secret
  }
  cert_issuer acme
  on_demand_tls {
    ask https://example.com/ask
  }
  preferred_chains {
    root_common_name "Root CA"
  }
  dns route53 {
    region us-east-1
  }
  ech public.example {
    dns route53 {
      region us-east-1
    }
  }
}
example.com {
  respond ok
}"#,
        );

        for option in [
            "storage_check",
            "storage_clean_interval",
            "renew_interval",
            "ocsp_interval",
            "acme_ca_root",
            "ocsp_stapling",
            "cert_lifetime",
            "tls_resolvers",
            "renewal_window_ratio",
            "pki",
            "events",
            "storage",
            "acme_dns",
            "cert_issuer",
            "on_demand_tls",
            "preferred_chains",
            "dns",
            "ech",
        ] {
            assert!(
                warnings.iter().any(|w| {
                    w.contains(&format!("global option '{option}'"))
                        && w.contains("outside zeroserve")
                }),
                "{option}: {warnings:?}"
            );
        }
        assert!(
            !warnings.iter().any(|w| w.contains("unrecognized")),
            "{warnings:?}"
        );
    }

    #[test]
    fn unsupported_global_options_validate_caddyfile_shape_like_caddy() {
        let (_, warnings) = adapt_full(
            r#"{
  admin 127.0.0.1:2020 {
    origins localhost
    enforce_origin
  }
  auto_https disable_redirects ignore_loaded_certs
  default_bind 127.0.0.1 {
    protocols h1 h2
  }
  storage_check off
  storage_clean_interval 1h
  email admin@example.com
  renewal_window_ratio 0.5
  tls_resolvers 1.1.1.1 8.8.8.8
  ocsp_stapling off
}
example.com {
  respond ok
}"#,
        );
        for option in [
            "admin",
            "auto_https",
            "default_bind",
            "storage_check",
            "storage_clean_interval",
            "renewal_window_ratio",
            "tls_resolvers",
            "ocsp_stapling",
        ] {
            assert!(
                warnings.iter().any(|w| {
                    w.contains(&format!("global option '{option}'"))
                        && w.contains("outside zeroserve")
                }),
                "{option}: {warnings:?}"
            );
        }

        for (input, expected) in [
            (
                r#"{
  admin 192.0.2.1:2019 127.0.0.1:2019
}
example.com {
  respond ok
}"#,
                "wrong argument count",
            ),
            (
                r#"{
  admin off {
    origins localhost
  }
}
example.com {
  respond ok
}"#,
                "No more option is allowed after turning off admin config",
            ),
            (
                r#"{
  auto_https typo
}
example.com {
  respond ok
}"#,
                "auto_https must be one of",
            ),
            (
                r#"{
  storage_check on
}
example.com {
  respond ok
}"#,
                "storage_check must be 'off'",
            ),
            (
                r#"{
  email a b
}
example.com {
  respond ok
}"#,
                "unexpected argument 'b'",
            ),
            (
                r#"{
  renewal_window_ratio 1.5
}
example.com {
  respond ok
}"#,
                "renewal_window_ratio must be between 0 and 1",
            ),
            (
                r#"{
  tls_resolvers
}
example.com {
  respond ok
}"#,
                "wrong argument count",
            ),
            (
                r#"{
  ocsp_stapling on
}
example.com {
  respond ok
}"#,
                "invalid argument 'on'",
            ),
            (
                r#"{
  default_bind {
    nope
  }
}
example.com {
  respond ok
}"#,
                "unknown subdirective: nope",
            ),
            (
                r#"{
  events {
    bogus cert_obtained exec echo ok
  }
}
example.com {
  respond ok
}"#,
                "wrong argument count",
            ),
            (
                r#"{
  events {
    on cert_obtained
  }
}
example.com {
  respond ok
}"#,
                "wrong argument count",
            ),
            (
                r#"{
  pki {
    bogus
  }
}
example.com {
  respond ok
}"#,
                "unrecognized pki option 'bogus'",
            ),
            (
                r#"{
  pki {
    ca local {
      bogus yes
    }
  }
}
example.com {
  respond ok
}"#,
                "unrecognized pki ca option 'bogus'",
            ),
            (
                r#"{
  pki {
    ca local {
      root {
        bogus yes
      }
    }
  }
}
example.com {
  respond ok
}"#,
                "unrecognized pki ca root option 'bogus'",
            ),
            (
                r#"{
  pki {
    ca local {
      renewal_window_ratio 1.5
    }
  }
}
example.com {
  respond ok
}"#,
                "renewal_window_ratio must be a number in (0, 1], got 1.5",
            ),
            (
                r#"{
  metrics {
    bogus
  }
}
example.com {
  respond ok
}"#,
                "unrecognized servers option 'bogus'",
            ),
            (
                r#"{
  log {
    hostnames example.com
  }
}
example.com {
  respond ok
}"#,
                "hostnames is not allowed in the log global options",
            ),
            (
                r#"{
  log default
  log default
}
example.com {
  respond ok
}"#,
                "duplicate global log option for: default",
            ),
            (
                r#"{
  log {
    sampling {
      first nope
    }
  }
}
example.com {
  respond ok
}"#,
                "failed to parse first",
            ),
            (
                r#"{
  log one two
}
example.com {
  respond ok
}"#,
                "wrong argument count",
            ),
            (
                r#"{
  storage
}
example.com {
  respond ok
}"#,
                "wrong argument count",
            ),
            (
                r#"{
  dns
}
example.com {
  respond ok
}"#,
                "wrong argument count",
            ),
            (
                r#"{
  acme_eab key_id kid
}
example.com {
  respond ok
}"#,
                "wrong argument count",
            ),
            (
                r#"{
  acme_eab {
    unknown value
  }
}
example.com {
  respond ok
}"#,
                "unrecognized parameter 'unknown'",
            ),
            (
                r#"{
  on_demand_tls
}
example.com {
  respond ok
}"#,
                "expected at least one config parameter for on_demand_tls",
            ),
            (
                r#"{
  on_demand_tls {
    interval 1m
  }
}
example.com {
  respond ok
}"#,
                "the on_demand_tls 'interval' option is no longer supported",
            ),
            (
                r#"{
  on_demand_tls {
    ask https://example.com/one
    permission module
  }
}
example.com {
  respond ok
}"#,
                "on-demand TLS permission module (or 'ask') already specified",
            ),
            (
                r#"{
  preferred_chains smallest {
    any_common_name Root
  }
}
example.com {
  respond ok
}"#,
                "No more options are accepted when using the 'smallest' option",
            ),
            (
                r#"{
  preferred_chains
}
example.com {
  respond ok
}"#,
                "No options for preferred_chains received",
            ),
            (
                r#"{
  preferred_chains {
    any_common_name Root
    root_common_name Other
  }
}
example.com {
  respond ok
}"#,
                "Can't set root_common_name when any_common_name is already set",
            ),
            (
                r#"{
  ech {
    dns route53
  }
}
example.com {
  respond ok
}"#,
                "wrong argument count",
            ),
            (
                r#"{
  ech public.example {
    unknown
  }
}
example.com {
  respond ok
}"#,
                "ech: unrecognized subdirective 'unknown'",
            ),
        ] {
            let err = adapt_err(input);
            assert!(err.contains(expected), "{err}");
        }
    }

    #[test]
    fn handle_errors_status_matchers_sort_before_fallback_like_caddy() {
        let errors = error_routes(
            r#"example.com {
  error /hidden* "Not found" 404
  error /internal* "Internal" 500
  handle_errors {
    respond "fallback"
  }
  handle_errors 5xx {
    respond "5xx"
  }
  handle_errors 4xx {
    respond "4xx"
  }
}"#,
        );
        let site_error_routes = &errors[0]["handle"][0]["routes"];
        assert_eq!(
            site_error_routes[0]["match"][0]["expression"],
            "{http.error.status_code} >= 400 && {http.error.status_code} <= 499"
        );
        assert_eq!(
            site_error_routes[0]["handle"][0]["routes"][0]["handle"][0]["body"],
            "4xx"
        );
        assert_eq!(
            site_error_routes[1]["match"][0]["expression"],
            "{http.error.status_code} >= 500 && {http.error.status_code} <= 599"
        );
        assert_eq!(
            site_error_routes[1]["handle"][0]["routes"][0]["handle"][0]["body"],
            "5xx"
        );
        assert!(site_error_routes[2].get("match").is_none());
        assert_eq!(
            site_error_routes[2]["handle"][0]["routes"][0]["handle"][0]["body"],
            "fallback"
        );
    }

    #[test]
    fn global_port_options_validate_like_caddy() {
        let (v, _warnings) = adapt_full(
            r#"{
  http_port 8080
  https_port 8443
}
example.com {
  respond ok
}"#,
        );
        let http = &v["apps"]["http"];
        assert_eq!(http["http_port"], 8080);
        assert_eq!(http["https_port"], 8443);

        for (input, expected) in [
            (
                r#"{
  http_port nope
}
example.com {
  respond ok
}"#,
                "converting port 'nope' to integer value",
            ),
            (
                r#"{
  https_port 8443 extra
}
example.com {
  respond ok
}"#,
                "unexpected argument 'extra'",
            ),
            (
                r#"{
  http_port
}
example.com {
  respond ok
}"#,
                "missing http_port",
            ),
        ] {
            let err = adapt_err(input);
            assert!(err.contains(expected), "{err}");
        }
    }

    #[test]
    fn global_options_reject_unknown_like_caddy() {
        let err = adapt_err(
            r#"{
  not_a_global_option on
}
example.com {
  respond ok
}"#,
        );
        assert!(
            err.contains("unrecognized global option: not_a_global_option"),
            "{err}"
        );
    }

    #[test]
    fn global_matcher_definitions_error_like_caddy() {
        let err = adapt_err(
            r#"@foo {
  path /foo
}

handle {
  respond "should not work"
}"#,
        );
        assert!(
            err.contains(
                "request matchers may not be defined globally, they must be in a site block; found @foo"
            ),
            "{err}"
        );
    }

    #[test]
    fn global_filesystem_option_adapts_to_caddy_filesystems_app() {
        let (v, warnings) = adapt_full(
            r#"{
  filesystem local disk /srv
}
example.com {
  respond ok
}"#,
        );
        assert!(
            warnings
                .iter()
                .any(|w| w.contains("global option 'filesystem'")),
            "{warnings:?}"
        );
        assert_eq!(
            v["apps"]["caddy.filesystems"]["filesystems"][0]["name"],
            "local"
        );
        assert_eq!(
            v["apps"]["caddy.filesystems"]["filesystems"][0]["file_system"]["backend"],
            "disk"
        );
    }

    #[test]
    fn current_servers_options_lower_to_ignored_server_json() {
        let (v, warnings) = adapt_full(
            r#"{
  servers :443 {
    name app
    keepalive_interval 30s
    keepalive_idle 2m
    keepalive_count 3
    enable_full_duplex
    strict_sni_host insecure_off
    log_credentials
    trace
    0rtt off
    metrics {
      per_host
    }
    listener_wrappers {
      proxy_protocol
    }
  }
}
example.com {
  respond ok
}"#,
        );

        let srv = &v["apps"]["http"]["servers"]["app"];
        assert_eq!(srv["keepalive_interval"], 30_000_000_000_i64);
        assert_eq!(srv["keepalive_idle"], 120_000_000_000_i64);
        assert_eq!(srv["keepalive_count"], 3);
        assert_eq!(srv["enable_full_duplex"], true);
        assert_eq!(srv["strict_sni_host"], false);
        assert_eq!(srv["logs"]["should_log_credentials"], true);
        assert_eq!(srv["logs"]["trace"], true);
        assert_eq!(srv["allow_0rtt"], false);
        assert!(
            warnings.iter().any(|w| w.contains("servers.name")),
            "{warnings:?}"
        );
        assert!(
            warnings
                .iter()
                .any(|w| w.contains("servers listener address ':443'")),
            "{warnings:?}"
        );
        assert!(
            warnings.iter().any(|w| w.contains("servers.metrics")),
            "{warnings:?}"
        );
        assert!(
            warnings
                .iter()
                .any(|w| w.contains("servers.listener_wrappers")),
            "{warnings:?}"
        );
    }

    #[test]
    fn current_servers_name_requires_listener_address_like_caddy() {
        let err = adapt_err(
            r#"{
  servers {
    name app
  }
}
example.com {
  respond ok
}"#,
        );
        assert!(
            err.contains("cannot set a name for a server without a listener address"),
            "{err}"
        );
    }

    #[test]
    fn current_servers_timeouts_adapt_multiple_entries() {
        let (v, _warnings) = adapt_full(
            r#"{
  servers {
    timeouts {
      read_body 1s
      read_header 2s
      write 3s
      idle 4s
    }
  }
}
example.com {
  respond ok
}"#,
        );

        let srv = &v["apps"]["http"]["servers"]["srv0"];
        assert_eq!(srv["read_timeout"], 1_000_000_000_i64);
        assert_eq!(srv["read_header_timeout"], 2_000_000_000_i64);
        assert_eq!(srv["write_timeout"], 3_000_000_000_i64);
        assert_eq!(srv["idle_timeout"], 4_000_000_000_i64);
    }

    #[test]
    fn current_servers_timeouts_reject_unknown_options_like_caddy() {
        let err = adapt_err(
            r#"{
  servers {
    timeouts {
      unknown 1s
    }
  }
}
example.com {
  respond ok
}"#,
        );
        assert!(
            err.contains("unrecognized timeouts option 'unknown'"),
            "{err}"
        );
    }

    #[test]
    fn servers_trusted_proxies_requires_source() {
        let err = adapt_err(
            r#"{
  servers {
    trusted_proxies
  }
}
example.com {
  respond ok
}"#,
        );
        assert!(
            err.contains("trusted_proxies expects an IP range source module name"),
            "{err}"
        );
    }

    #[test]
    fn map_rejects_placeholder_shorthand_destination_conflict() {
        let err = adapt_err(
            r#"example.com {
  map {path} {http.request.uri.path} {
    /foo /bar
  }
}"#,
        );
        assert!(
            err.contains("destination {path} conflicts with a Caddyfile placeholder shorthand"),
            "{err}"
        );
    }

    #[test]
    fn map_accepts_user_placeholder_destination() {
        let r = routes(
            r#"example.com {
  map {path} {mapped} {
    /foo /bar
  }
  respond {mapped}
}"#,
        );
        let h = &r[0]["handle"][0]["routes"][0]["handle"][0];
        assert_eq!(h["handler"], "map");
        assert_eq!(h["destinations"], json!(["{mapped}"]));
    }

    #[test]
    fn redir_becomes_static_response() {
        let r = routes("example.com {\n  redir https://example.org{uri} permanent\n}");
        let h = &r[0]["handle"][0]["routes"][0]["handle"][0];
        assert_eq!(h["handler"], "static_response");
        assert_eq!(h["status_code"], 301);
        assert_eq!(
            h["headers"]["Location"],
            json!(["https://example.org{http.request.uri}"])
        );
    }

    #[test]
    fn redir_html_becomes_static_html_response() {
        let r = routes("example.com {\n  redir https://example.org/a?b=<tag> html\n}");
        let h = &r[0]["handle"][0]["routes"][0]["handle"][0];
        assert_eq!(h["handler"], "static_response");
        assert_eq!(h["status_code"], 200);
        assert_eq!(
            h["headers"]["Content-Type"],
            json!(["text/html; charset=utf-8"])
        );
        assert!(h["headers"].get("Location").is_none(), "{h:?}");
        assert!(
            h["body"]
                .as_str()
                .is_some_and(|body| body.contains("https://example.org/a?b=&lt;tag&gt;")),
            "{h:?}"
        );
    }

    #[test]
    fn handle_path_strips_prefix() {
        let r = routes("example.com {\n  handle_path /api/* {\n    respond ok\n  }\n}");
        // The site route matches the path and wraps a subroute whose first route
        // strips the prefix, followed by the handled routes.
        let outer = &r[0]["handle"][0]["routes"][0];
        assert_eq!(outer["match"][0]["path"], json!(["/api/*"]));
        let inner = &outer["handle"][0];
        assert_eq!(inner["handler"], "subroute");
        assert_eq!(inner["routes"][0]["handle"][0]["handler"], "rewrite");
        assert_eq!(inner["routes"][0]["handle"][0]["strip_path_prefix"], "/api");
        assert_eq!(
            inner["routes"][1]["handle"][0]["handler"],
            "static_response"
        );
    }

    #[test]
    fn uri_query_adapts_inline_operation() {
        let r = routes("example.com {\n  uri query mode compiled\n}");
        let h = &r[0]["handle"][0]["routes"][0]["handle"][0];
        assert_eq!(h["handler"], "rewrite");
        assert_eq!(
            h["query"],
            json!({"set": [{"key": "mode", "val": "compiled"}]})
        );
    }

    #[test]
    fn uri_query_adapts_block_operations() {
        let r = routes(
            r#"example.com {
  uri query {
    old>new
    +extra 1
    -gone
    * raw cooked
  }
}"#,
        );
        let h = &r[0]["handle"][0]["routes"][0]["handle"][0];
        assert_eq!(h["query"]["rename"], json!([{"key": "old", "val": "new"}]));
        assert_eq!(h["query"]["add"], json!([{"key": "extra", "val": "1"}]));
        assert_eq!(h["query"]["delete"], json!(["gone"]));
        assert_eq!(
            h["query"]["replace"],
            json!([{"key": "*", "search_regexp": "raw", "replace": "cooked"}])
        );
    }

    #[test]
    fn uri_query_rename_ignores_extra_split_fields_like_caddy() {
        let r = routes("example.com {\n  uri query old>new>ignored\n}");
        let h = &r[0]["handle"][0]["routes"][0]["handle"][0];
        assert_eq!(h["query"]["rename"], json!([{"key": "old", "val": "new"}]));
    }

    #[test]
    fn uri_query_rejects_mixed_args_and_block() {
        let err = adapt_err(
            r#"example.com {
  uri query mode compiled {
    -gone
  }
}"#,
        );
        assert!(
            err.contains("Cannot specify uri query rewrites in both argument and block"),
            "{err}"
        );
    }

    #[test]
    fn uri_rejects_unknown_operation_like_caddy() {
        let err = adapt_err(
            r#"example.com {
  uri unknown target
}"#,
        );
        assert!(
            err.contains("unrecognized URI manipulation 'unknown'"),
            "{err}"
        );
    }

    #[test]
    fn fs_adapts_as_vars_and_rejects_extra_args() {
        let r = routes("example.com {\n  fs default\n}");
        let h = &r[0]["handle"][0]["routes"][0]["handle"][0];
        assert_eq!(h, &json!({"handler": "vars", "fs": "default"}));

        let err = adapt_err("example.com {\n  fs default extra\n}");
        assert!(err.contains("wrong argument count"), "{err}");
    }

    #[test]
    fn file_server_adapts_etag_file_extensions() {
        let r = routes(
            r#"example.com {
  file_server {
    etag_file_extensions .html .json
  }
}"#,
        );
        let h = &r[0]["handle"][0]["routes"][0]["handle"][0];
        assert_eq!(h["handler"], "file_server");
        assert_eq!(h["etag_file_extensions"], json!([".html", ".json"]));
    }

    #[test]
    fn file_server_precompressed_adapts_module_map_like_caddy() {
        let r = routes(
            r#"example.com {
  file_server {
    precompressed
  }
}"#,
        );
        let h = &r[0]["handle"][0]["routes"][0]["handle"][0];
        assert_eq!(h["precompressed_order"], json!(["br", "zstd", "gzip"]));
        assert_eq!(
            h["precompressed"],
            json!({"br": {}, "zstd": {}, "gzip": {}})
        );

        let err = adapt_err(
            r#"example.com {
  file_server {
    precompressed nope
  }
}"#,
        );
        assert!(
            err.contains(
                "getting module named 'http.precompressed.nope': module not registered: http.precompressed.nope"
            ),
            "{err}"
        );
    }

    #[test]
    fn file_server_browse_sort_subdirectives_append() {
        let r = routes(
            r#"example.com {
  file_server {
    browse {
      sort name asc
      sort time desc
    }
  }
}"#,
        );
        let h = &r[0]["handle"][0]["routes"][0]["handle"][0];
        assert_eq!(h["browse"]["sort"], json!(["name", "asc", "time", "desc"]));
    }

    #[test]
    fn file_server_hides_caddyfile_like_caddy() {
        let (v, _) = adapt_full("example.com {\n  file_server\n}");
        let h = &v["apps"]["http"]["servers"]["srv0"]["routes"][0]["handle"][0]["routes"][0]["handle"]
            [0];
        assert_eq!(h["hide"], json!(["./Caddyfile"]));

        let (v, _) = adapt(
            r#"example.com {
  file_server {
    hide secret.txt
  }
}"#,
            "conf/site/Caddyfile",
        )
        .unwrap();
        let h = &v["apps"]["http"]["servers"]["srv0"]["routes"][0]["handle"][0]["routes"][0]["handle"]
            [0];
        assert_eq!(h["hide"], json!(["secret.txt", "conf/site/Caddyfile"]));

        let (v, _) = adapt(
            r#"example.com {
  file_server {
    hide Caddyfile
  }
}"#,
            "Caddyfile",
        )
        .unwrap();
        let h = &v["apps"]["http"]["servers"]["srv0"]["routes"][0]["handle"][0]["routes"][0]["handle"]
            [0];
        assert_eq!(h["hide"], json!(["Caddyfile"]));

        let (v, _) = adapt(
            r#"example.com {
  file_server {
    hide conf/*/Caddyfile
  }
}"#,
            "conf/site/Caddyfile",
        )
        .unwrap();
        let h = &v["apps"]["http"]["servers"]["srv0"]["routes"][0]["handle"][0]["routes"][0]["handle"]
            [0];
        assert_eq!(h["hide"], json!(["conf/*/Caddyfile"]));
    }

    #[test]
    fn file_server_hides_imported_caddyfiles_like_caddy() {
        let root =
            std::env::temp_dir().join(format!("zeroserve-caddy-import-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        let main = root.join("Caddyfile");
        let imported = root.join("imported.caddy");
        fs::write(&imported, "root /srv\n").unwrap();
        let input = r#"example.com {
  import imported.caddy
  file_server
}"#;
        let result = adapt(input, main.to_str().unwrap());
        let _ = fs::remove_dir_all(&root);
        let (v, _) = result.unwrap();
        let h = first_handler(&v, "file_server").expect("file_server handler");
        assert_eq!(
            h["hide"],
            json!([
                main.to_string_lossy().replace('\\', "/"),
                imported.to_string_lossy().replace('\\', "/")
            ])
        );
    }

    #[test]
    fn file_imported_snippets_are_available_like_caddy() {
        let root = std::env::temp_dir().join(format!(
            "zeroserve-caddy-import-snippet-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(root.join("testdata")).unwrap();
        let main = root.join("Caddyfile");
        fs::write(
            root.join("testdata").join("snippet.conf"),
            "(test) {\n  reverse_proxy {\n    {block}\n  }\n}\n",
        )
        .unwrap();
        let input = r#"{
  admin off
  auto_https off
}

import testdata/snippet.conf

:8080 {
  import test {
    this_is_nonsense
  }
}"#;
        let result = adapt(input, main.to_str().unwrap());
        let _ = fs::remove_dir_all(&root);
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("unrecognized subdirective this_is_nonsense"),
            "{err}"
        );
    }

    #[test]
    fn file_server_rejects_caddyfile_duplicate_and_extra_args() {
        for (input, expected) in [
            (
                r#"example.com {
  file_server browse {
    browse
  }
}"#,
                "browsing is already configured",
            ),
            (
                r#"example.com {
  file_server {
    fs default
    fs default
  }
}"#,
                "file system already specified",
            ),
            (
                r#"example.com {
  file_server {
    pass_thru extra
  }
}"#,
                "wrong argument count",
            ),
            (
                r#"example.com {
  file_server {
    fs default extra
  }
}"#,
                "unknown subdirective 'extra'",
            ),
            (
                r#"example.com {
  file_server {
    status 200 extra
  }
}"#,
                "unknown subdirective 'extra'",
            ),
            (
                r#"example.com {
  file_server {
    browse template.html extra
  }
}"#,
                "unknown subdirective 'extra'",
            ),
            (
                r#"example.com {
  file_server {
    browse {
      reveal_symlinks extra
    }
  }
}"#,
                "unknown subdirective 'extra'",
            ),
            (
                r#"example.com {
  file_server {
    browse {
      sort unknown
    }
  }
}"#,
                "unknown sort option 'unknown'",
            ),
        ] {
            let err = adapt_err(input);
            assert!(err.contains(expected), "{err}");
        }
    }

    #[test]
    fn reverse_proxy_upstreams() {
        let r = routes("example.com {\n  reverse_proxy localhost:8080 localhost:8081\n}");
        let h = &r[0]["handle"][0]["routes"][0]["handle"][0];
        assert_eq!(h["handler"], "reverse_proxy");
        assert_eq!(
            h["upstreams"],
            json!([{"dial": "localhost:8080"}, {"dial": "localhost:8081"}])
        );
    }

    #[test]
    fn reverse_proxy_portless_upstreams_match_caddy() {
        let r = routes(
            r#"whoami.example.com {
  reverse_proxy whoami
}

app.example.com {
  reverse_proxy app:80
}

unix.example.com {
  reverse_proxy unix//path/to/socket
}"#,
        );

        let routes = r.as_array().expect("routes array");
        let dial_for = |host: &str| {
            routes
                .iter()
                .find(|route| route["match"][0]["host"][0] == host)
                .map(|route| {
                    route["handle"][0]["routes"][0]["handle"][0]["upstreams"][0]["dial"].clone()
                })
                .expect("host route")
        };

        assert_eq!(dial_for("whoami.example.com"), json!("whoami:80"));
        assert_eq!(dial_for("app.example.com"), json!("app:80"));
        assert_eq!(dial_for("unix.example.com"), json!("unix//path/to/socket"));
    }

    #[test]
    fn reverse_proxy_expands_upstream_port_ranges() {
        let r = routes("example.com {\n  reverse_proxy http://localhost:8001-8003\n}");
        let h = &r[0]["handle"][0]["routes"][0]["handle"][0];
        assert_eq!(
            h["upstreams"],
            json!([
                {"dial": "localhost:8001"},
                {"dial": "localhost:8002"},
                {"dial": "localhost:8003"},
            ])
        );
    }

    #[test]
    fn reverse_proxy_rejects_url_upstream_components() {
        for addr in [
            "http://localhost/",
            "http://localhost/path",
            "http://localhost?x=1",
            "http://localhost#frag",
        ] {
            let err = adapt_err(&format!("example.com {{\n  reverse_proxy {addr}\n}}"));
            assert!(
                err.contains(
                    "for now, URLs for proxy upstreams only support scheme, host, and port components"
                ),
                "{addr}: {err}"
            );
        }
    }

    #[test]
    fn reverse_proxy_lowers_dynamic_upstreams() {
        let r = routes(
            r#"example.com {
  reverse_proxy {
    dynamic multi {
      srv example.com {
        service http
        proto tcp
        refresh 30s
        resolvers 1.1.1.1 8.8.8.8
        dial_timeout 2s
        dial_fallback_delay 100ms
        grace_period 5s
      }
      a api.example.com 8443 {
        refresh 1m
        versions ipv4 ipv6
        dial_fallback_delay -1s
      }
    }
  }
}"#,
        );
        let dynamic = &r[0]["handle"][0]["routes"][0]["handle"][0]["dynamic_upstreams"];
        assert_eq!(dynamic["source"], "multi");
        assert_eq!(dynamic["sources"][0]["source"], "srv");
        assert_eq!(dynamic["sources"][0]["name"], "example.com");
        assert_eq!(dynamic["sources"][0]["service"], "http");
        assert_eq!(dynamic["sources"][0]["proto"], "tcp");
        assert_eq!(dynamic["sources"][0]["refresh"], 30_000_000_000_i64);
        assert_eq!(
            dynamic["sources"][0]["resolver"]["addresses"],
            json!(["1.1.1.1", "8.8.8.8"])
        );
        assert_eq!(dynamic["sources"][0]["dial_timeout"], 2_000_000_000_i64);
        assert_eq!(
            dynamic["sources"][0]["dial_fallback_delay"],
            100_000_000_i64
        );
        assert_eq!(dynamic["sources"][0]["grace_period"], 5_000_000_000_i64);
        assert_eq!(dynamic["sources"][1]["source"], "a");
        assert_eq!(dynamic["sources"][1]["name"], "api.example.com");
        assert_eq!(dynamic["sources"][1]["port"], "8443");
        assert_eq!(dynamic["sources"][1]["refresh"], 60_000_000_000_i64);
        assert_eq!(
            dynamic["sources"][1]["versions"],
            json!({"ipv4": true, "ipv6": true})
        );
        assert_eq!(
            dynamic["sources"][1]["dial_fallback_delay"],
            -1_000_000_000_i64
        );
    }

    #[test]
    fn reverse_proxy_rejects_invalid_dynamic_upstreams() {
        let duplicate = adapt_err(
            r#"example.com {
  reverse_proxy {
    dynamic a api.example.com {
      name other.example.com
    }
  }
}"#,
        );
        assert!(
            duplicate.contains("a name has already been specified"),
            "{duplicate}"
        );

        let unknown = adapt_err(
            r#"example.com {
  reverse_proxy {
    dynamic unknown
  }
}"#,
        );
        assert!(
            unknown.contains("unrecognized dynamic upstream source 'unknown'"),
            "{unknown}"
        );
    }

    #[test]
    fn reverse_proxy_trusted_proxies_and_runtime_fields() {
        let r = routes(
            r#"example.com {
  reverse_proxy localhost:8080 {
    trusted_proxies private_ranges 203.0.113.0/24
    request_buffers unlimited
    response_buffers 2KiB
    stream_buffer_size 4KiB
    stream_timeout 5s
    stream_close_delay 250ms
    flush_interval 1s
    verbose_logs
  }
}"#,
        );
        let h = &r[0]["handle"][0]["routes"][0]["handle"][0];
        assert_eq!(
            h["trusted_proxies"],
            json!([
                "192.168.0.0/16",
                "172.16.0.0/12",
                "10.0.0.0/8",
                "127.0.0.1/8",
                "fd00::/8",
                "::1",
                "203.0.113.0/24"
            ])
        );
        assert_eq!(h["request_buffers"], -1);
        assert_eq!(h["response_buffers"], 2048);
        assert_eq!(h["stream_buffer_size"], 4096);
        assert_eq!(h["stream_timeout"], 5_000_000_000_i64);
        assert_eq!(h["stream_close_delay"], 250_000_000_i64);
        assert_eq!(h["flush_interval"], 1_000_000_000_i64);
        assert_eq!(h["verbose_logs"], true);
    }

    #[test]
    fn reverse_proxy_accepts_bare_integer_runtime_durations_like_caddy() {
        let r = routes(
            r#"example.com {
  reverse_proxy localhost:8080 {
    flush_interval 10
    stream_timeout 20
    stream_close_delay 30
  }
}"#,
        );
        let h = &r[0]["handle"][0]["routes"][0]["handle"][0];
        assert_eq!(h["flush_interval"], 10);
        assert_eq!(h["stream_timeout"], 20);
        assert_eq!(h["stream_close_delay"], 30);
    }

    #[test]
    fn reverse_proxy_rejects_duplicate_verbose_logs() {
        let err = adapt_err(
            r#"example.com {
  reverse_proxy localhost:8080 {
    verbose_logs
    verbose_logs
  }
}"#,
        );
        assert!(err.contains("verbose_logs already specified"), "{err}");
    }

    #[test]
    fn reverse_proxy_lowers_retry_timing_controls() {
        let r = routes(
            r#"example.com {
  reverse_proxy localhost:8080 {
    lb_retries 3
    lb_try_duration 5s
    lb_try_interval 250ms
  }
}"#,
        );
        let lb = &r[0]["handle"][0]["routes"][0]["handle"][0]["load_balancing"];
        assert_eq!(lb["retries"], 3);
        assert_eq!(lb["try_duration"], 5_000_000_000_i64);
        assert_eq!(lb["try_interval"], 250_000_000_i64);
    }

    #[test]
    fn reverse_proxy_lowers_selection_policy_args() {
        let r = routes(
            r#"example.com {
  reverse_proxy localhost:8080 {
    lb_policy weighted_round_robin 5 0 2
  }
}"#,
        );
        let policy =
            &r[0]["handle"][0]["routes"][0]["handle"][0]["load_balancing"]["selection_policy"];
        assert_eq!(
            policy,
            &json!({"policy": "weighted_round_robin", "weights": [5, 0, 2]})
        );

        let r = routes(
            r#"example.com {
  reverse_proxy localhost:8080 {
    lb_policy random_choose 3
  }
}"#,
        );
        let policy =
            &r[0]["handle"][0]["routes"][0]["handle"][0]["load_balancing"]["selection_policy"];
        assert_eq!(policy, &json!({"policy": "random_choose", "choose": 3}));
    }

    #[test]
    fn reverse_proxy_lowers_selection_policy_fallbacks() {
        let r = routes(
            r#"example.com {
  reverse_proxy localhost:8080 {
    lb_policy header X-Tenant {
      fallback first
    }
  }
}"#,
        );
        let policy =
            &r[0]["handle"][0]["routes"][0]["handle"][0]["load_balancing"]["selection_policy"];
        assert_eq!(
            policy,
            &json!({"policy": "header", "field": "X-Tenant", "fallback": {"policy": "first"}})
        );

        let r = routes(
            r#"example.com {
  reverse_proxy localhost:8080 {
    lb_policy cookie sticky secret {
      max_age 10s
      fallback random_choose 2
    }
  }
}"#,
        );
        let policy =
            &r[0]["handle"][0]["routes"][0]["handle"][0]["load_balancing"]["selection_policy"];
        assert_eq!(
            policy,
            &json!({
                "policy": "cookie",
                "name": "sticky",
                "secret": "secret",
                "max_age": 10_000_000_000_i64,
                "fallback": {"policy": "random_choose", "choose": 2}
            })
        );
    }

    #[test]
    fn reverse_proxy_rejects_invalid_selection_policy_args() {
        let err = adapt_err(
            r#"example.com {
  reverse_proxy localhost:8080 {
    lb_policy weighted_round_robin 1 -1
  }
}"#,
        );
        assert!(
            err.contains("invalid weight value '-1': weight should be non-negative"),
            "{err}"
        );

        let err = adapt_err(
            r#"example.com {
  reverse_proxy localhost:8080 {
    lb_policy random extra
  }
}"#,
        );
        assert!(err.contains("wrong argument count"), "{err}");

        let err = adapt_err(
            r#"example.com {
  reverse_proxy localhost:8080 {
    lb_policy unknown
  }
}"#,
        );
        assert!(
            err.contains("unrecognized selection policy 'unknown'"),
            "{err}"
        );
    }

    #[test]
    fn reverse_proxy_rejects_invalid_retry_count() {
        let err = adapt_err(
            r#"example.com {
  reverse_proxy localhost:8080 {
    lb_retries not-a-number
  }
}"#,
        );
        assert!(
            err.contains("bad lb_retries number 'not-a-number'"),
            "{err}"
        );
    }

    #[test]
    fn reverse_proxy_lowers_retry_matchers() {
        let r = routes(
            r#"example.com {
  reverse_proxy localhost:8080 {
    lb_retry_match method GET
    lb_retry_match {
      path /api/*
      header X-Retry yes
    }
  }
}"#,
        );
        let retry_match =
            &r[0]["handle"][0]["routes"][0]["handle"][0]["load_balancing"]["retry_match"];
        let retry_match = retry_match.as_array().expect("retry_match array");
        assert_eq!(retry_match.len(), 2);
        assert_eq!(retry_match[0]["method"], json!(["GET"]));
        assert_eq!(retry_match[1]["path"], json!(["/api/*"]));
        assert_eq!(retry_match[1]["header"]["X-Retry"], json!(["yes"]));
    }

    #[test]
    fn reverse_proxy_rejects_invalid_retry_matcher() {
        let err = adapt_err(
            r#"example.com {
  reverse_proxy localhost:8080 {
    lb_retry_match unsupported foo
  }
}"#,
        );
        assert!(err.contains("failed to parse lb_retry_match"), "{err}");
    }

    #[test]
    fn reverse_proxy_lowers_passive_health_checks() {
        let r = routes(
            r#"example.com {
  reverse_proxy localhost:8080 {
    max_fails 3
    fail_duration 10s
    unhealthy_request_count 7
    unhealthy_status 5xx 404
    unhealthy_latency 250ms
  }
}"#,
        );
        let passive = &r[0]["handle"][0]["routes"][0]["handle"][0]["health_checks"]["passive"];
        assert_eq!(passive["max_fails"], 3);
        assert_eq!(passive["fail_duration"], 10_000_000_000_i64);
        assert_eq!(passive["unhealthy_request_count"], 7);
        assert_eq!(passive["unhealthy_status"], json!([5, 404]));
        assert_eq!(passive["unhealthy_latency"], 250_000_000_i64);
    }

    #[test]
    fn reverse_proxy_rejects_invalid_passive_health_count() {
        let err = adapt_err(
            r#"example.com {
  reverse_proxy localhost:8080 {
    max_fails nope
  }
}"#,
        );
        assert!(err.contains("invalid maximum fail count 'nope'"), "{err}");
    }

    #[test]
    fn reverse_proxy_lowers_active_health_checks() {
        let r = routes(
            r#"example.com {
  reverse_proxy localhost:8080 {
    health_uri /health?ready=1
    health_upstream health.example.com:9443
    health_headers {
      Host health.example.com
      X-Empty
    }
    health_method POST
    health_request_body ping
    health_interval 30s
    health_timeout 5s
    health_status 2xx
    health_body ok
    health_follow_redirects
    health_passes 2
    health_fails 3
  }
}"#,
        );
        let active = &r[0]["handle"][0]["routes"][0]["handle"][0]["health_checks"]["active"];
        assert_eq!(active["uri"], "/health?ready=1");
        assert_eq!(active["upstream"], "health.example.com:9443");
        assert_eq!(active["headers"]["Host"], json!(["health.example.com"]));
        assert_eq!(active["headers"]["X-Empty"], json!([""]));
        assert_eq!(active["method"], "POST");
        assert_eq!(active["body"], "ping");
        assert_eq!(active["interval"], 30_000_000_000_i64);
        assert_eq!(active["timeout"], 5_000_000_000_i64);
        assert_eq!(active["expect_status"], 2);
        assert_eq!(active["expect_body"], "ok");
        assert_eq!(active["follow_redirects"], true);
        assert_eq!(active["passes"], 2);
        assert_eq!(active["fails"], 3);
    }

    #[test]
    fn reverse_proxy_health_headers_append_repeated_fields_like_caddy() {
        let r = routes(
            r#"example.com {
  reverse_proxy localhost:8080 {
    health_headers {
      X-Check one two
      X-Check three
      X-Empty
      X-Empty blank
    }
  }
}"#,
        );
        let active = &r[0]["handle"][0]["routes"][0]["handle"][0]["health_checks"]["active"];
        assert_eq!(active["headers"]["X-Check"], json!(["one", "two", "three"]));
        assert_eq!(active["headers"]["X-Empty"], json!(["", "blank"]));
    }

    #[test]
    fn reverse_proxy_rejects_health_port_after_health_upstream() {
        let err = adapt_err(
            r#"example.com {
  reverse_proxy localhost:8080 {
    health_upstream health.example.com:9443
    health_port 8081
  }
}"#,
        );
        assert!(
            err.contains("the 'health_port' subdirective is ignored if 'health_upstream' is used"),
            "{err}"
        );
    }

    #[test]
    fn reverse_proxy_transport_http_adapts_tls_and_runtime_fields() {
        let r = routes(
            r#"example.com {
  reverse_proxy https://backend.example {
    transport http {
      tls
      tls_renegotiation once
      read_timeout 5s
      local_address 192.0.2.10
      proxy_protocol v2
      forward_proxy_url http://proxy.example:8080
      max_conns_per_host 32
      resolvers 1.1.1.1 8.8.8.8
      keepalive 2m
      keepalive_interval 30s
      keepalive_idle_conns 100
      keepalive_idle_conns_per_host 20
    }
  }
}"#,
        );
        let h = &r[0]["handle"][0]["routes"][0]["handle"][0];
        assert_eq!(h["transport"]["protocol"], "http");
        assert_eq!(h["transport"]["tls"], json!({"renegotiation": "once"}));
        assert_eq!(h["transport"]["read_timeout"], 5_000_000_000_i64);
        assert_eq!(h["transport"]["local_address"], "192.0.2.10");
        assert_eq!(h["transport"]["proxy_protocol"], "v2");
        assert_eq!(
            h["transport"]["network_proxy"],
            json!({"from": "url", "url": "http://proxy.example:8080"})
        );
        assert_eq!(h["transport"]["max_conns_per_host"], 32);
        assert_eq!(
            h["transport"]["resolver"],
            json!({"addresses": ["1.1.1.1", "8.8.8.8"]})
        );
        assert_eq!(
            h["transport"]["keep_alive"],
            json!({
                "idle_timeout": 120_000_000_000_i64,
                "probe_interval": 30_000_000_000_i64,
                "max_idle_conns": 100,
                "max_idle_conns_per_host": 20
            })
        );
    }

    #[test]
    fn reverse_proxy_transport_http_scalar_options_ignore_extra_args_like_caddy() {
        let r = routes(
            r#"example.com {
  reverse_proxy https://backend.example {
    transport http {
      tls_server_name backend.example ignored
      tls_renegotiation once ignored
      tls_timeout 10s ignored
      read_buffer 4KiB ignored
      write_buffer 8KiB ignored
      max_response_header 16KiB ignored
      read_timeout 5s ignored
      write_timeout 6s ignored
      dial_timeout 7s ignored
      dial_fallback_delay 8s ignored
      response_header_timeout 9s ignored
      expect_continue_timeout 10s ignored
      proxy_protocol v2 ignored
      forward_proxy_url http://proxy.example:8080 ignored
      max_conns_per_host 32 ignored
      local_address 192.0.2.10 ignored
    }
  }
}"#,
        );
        let h = &r[0]["handle"][0]["routes"][0]["handle"][0];
        assert_eq!(
            h["transport"]["tls"],
            json!({
                "server_name": "backend.example",
                "renegotiation": "once",
                "handshake_timeout": 10_000_000_000_i64
            })
        );
        assert_eq!(h["transport"]["read_buffer_size"], 4096);
        assert_eq!(h["transport"]["write_buffer_size"], 8192);
        assert_eq!(h["transport"]["max_response_header_size"], 16384);
        assert_eq!(h["transport"]["read_timeout"], 5_000_000_000_i64);
        assert_eq!(h["transport"]["write_timeout"], 6_000_000_000_i64);
        assert_eq!(h["transport"]["dial_timeout"], 7_000_000_000_i64);
        assert_eq!(h["transport"]["dial_fallback_delay"], 8_000_000_000_i64);
        assert_eq!(h["transport"]["response_header_timeout"], 9_000_000_000_i64);
        assert_eq!(
            h["transport"]["expect_continue_timeout"],
            10_000_000_000_i64
        );
        assert_eq!(h["transport"]["proxy_protocol"], "v2");
        assert_eq!(
            h["transport"]["network_proxy"],
            json!({"from": "url", "url": "http://proxy.example:8080"})
        );
        assert_eq!(h["transport"]["max_conns_per_host"], 32);
        assert_eq!(h["transport"]["local_address"], "192.0.2.10");
    }

    #[test]
    fn reverse_proxy_transport_http_adapts_keepalive_off() {
        let r = routes(
            r#"example.com {
  reverse_proxy localhost:8080 {
    transport http {
      keepalive off
    }
  }
}"#,
        );
        let h = &r[0]["handle"][0]["routes"][0]["handle"][0];
        assert_eq!(h["transport"]["keep_alive"], json!({"enabled": false}));
    }

    #[test]
    fn reverse_proxy_transport_http_keepalive_ignores_extra_args_like_caddy() {
        let r = routes(
            r#"example.com {
  reverse_proxy localhost:8080 {
    transport http {
      keepalive off ignored
    }
  }
}"#,
        );
        let h = &r[0]["handle"][0]["routes"][0]["handle"][0];
        assert_eq!(h["transport"]["keep_alive"], json!({"enabled": false}));

        let r = routes(
            r#"example.com {
  reverse_proxy localhost:8080 {
    transport http {
      keepalive 2m ignored
    }
  }
}"#,
        );
        let h = &r[0]["handle"][0]["routes"][0]["handle"][0];
        assert_eq!(
            h["transport"]["keep_alive"],
            json!({"idle_timeout": 120_000_000_000_i64})
        );
    }

    #[test]
    fn reverse_proxy_transport_http_keepalive_options_ignore_extra_args_like_caddy() {
        let r = routes(
            r#"example.com {
  reverse_proxy localhost:8080 {
    transport http {
      keepalive_interval 30s ignored
      keepalive_idle_conns 100 ignored
      keepalive_idle_conns_per_host 20 ignored
    }
  }
}"#,
        );
        let h = &r[0]["handle"][0]["routes"][0]["handle"][0];
        assert_eq!(
            h["transport"]["keep_alive"],
            json!({
                "probe_interval": 30_000_000_000_i64,
                "max_idle_conns": 100,
                "max_idle_conns_per_host": 20
            })
        );
    }

    #[test]
    fn reverse_proxy_transport_http_compression_matches_caddy_leniency() {
        let r = routes(
            r#"example.com {
  reverse_proxy localhost:8080 {
    transport http {
      compression off
    }
  }
}"#,
        );
        let h = &r[0]["handle"][0]["routes"][0]["handle"][0];
        assert_eq!(h["transport"]["compression"], false);

        for input in [
            r#"example.com {
  reverse_proxy localhost:8080 {
    transport http {
      compression
    }
  }
}"#,
            r#"example.com {
  reverse_proxy localhost:8080 {
    transport http {
      compression on
    }
  }
}"#,
        ] {
            let r = routes(input);
            let h = &r[0]["handle"][0]["routes"][0]["handle"][0];
            assert!(h["transport"].get("compression").is_none(), "{h}");
        }

        let r = routes(
            r#"example.com {
  reverse_proxy localhost:8080 {
    transport http {
      compression off ignored
    }
  }
}"#,
        );
        let h = &r[0]["handle"][0]["routes"][0]["handle"][0];
        assert_eq!(h["transport"]["compression"], false);
    }

    #[test]
    fn reverse_proxy_transport_http_compression_unknown_extra_args_are_ignored() {
        let r = routes(
            r#"example.com {
  reverse_proxy localhost:8080 {
    transport http {
      compression on ignored
    }
  }
}"#,
        );
        let h = &r[0]["handle"][0]["routes"][0]["handle"][0];
        assert!(h["transport"].get("compression").is_none(), "{h}");
    }

    #[test]
    fn reverse_proxy_transport_http_adapts_network_proxy_url() {
        let r = routes(
            r#"example.com {
  reverse_proxy localhost:8080 {
    transport http {
      network_proxy url http://proxy.example:8080
    }
  }
}"#,
        );
        let h = &r[0]["handle"][0]["routes"][0]["handle"][0];
        assert_eq!(
            h["transport"]["network_proxy"],
            json!({"from": "url", "url": "http://proxy.example:8080"})
        );
    }

    #[test]
    fn reverse_proxy_transport_http_rejects_invalid_scalar_options() {
        let bad_proxy_protocol = adapt_err(
            r#"example.com {
  reverse_proxy localhost:8080 {
    transport http {
      proxy_protocol v3
    }
  }
}"#,
        );
        assert!(
            bad_proxy_protocol.contains("invalid proxy protocol version 'v3'"),
            "{bad_proxy_protocol}"
        );

        let bad_idle_spelling = adapt_err(
            r#"example.com {
  reverse_proxy localhost:8080 {
    transport http {
      max_idle_conns_per_host 20
    }
  }
}"#,
        );
        assert!(
            bad_idle_spelling.contains("unrecognized http transport subdirective"),
            "{bad_idle_spelling}"
        );
    }

    #[test]
    fn reverse_proxy_non_http_transport_block_is_consumed() {
        let r = routes(
            r#"example.com {
  reverse_proxy localhost:9000 {
    transport fastcgi {
      root /srv/app
    }
  }
}"#,
        );
        let h = &r[0]["handle"][0]["routes"][0]["handle"][0];
        assert_eq!(h["transport"], json!({"protocol": "fastcgi"}));
    }

    #[test]
    fn reverse_proxy_fastcgi_transport_adapts_split_path() {
        let r = routes(
            r#"example.com {
  reverse_proxy *.php 127.0.0.1:9000 {
    transport fastcgi {
      split .php .php5
    }
  }
}"#,
        );
        let h = &r[0]["handle"][0]["routes"][0]["handle"][0];
        assert_eq!(
            h["transport"],
            json!({"protocol": "fastcgi", "split_path": [".php", ".php5"]})
        );
    }

    #[test]
    fn forward_auth_lowers_to_reverse_proxy_shortcut() {
        let r = routes(
            r#"example.com {
  forward_auth /private/* auth-gateway:9091 {
    uri /authenticate?redirect=https://auth.example.com
    copy_headers Remote-User Remote-Email>X-User
  }
  respond ok
}"#,
        );
        let route = &r[0]["handle"][0]["routes"][0];
        assert_eq!(route["match"][0]["path"], json!(["/private/*"]));
        let h = &route["handle"][0];
        assert_eq!(h["handler"], "reverse_proxy");
        assert_eq!(h["upstreams"], json!([{"dial": "auth-gateway:9091"}]));
        assert_eq!(h["rewrite"]["method"], "GET");
        assert_eq!(
            h["rewrite"]["uri"],
            "/authenticate?redirect=https://auth.example.com"
        );
        assert_eq!(
            h["headers"]["request"]["set"]["X-Forwarded-Method"],
            json!(["{http.request.method}"])
        );
        assert_eq!(
            h["headers"]["request"]["set"]["X-Forwarded-Uri"],
            json!(["{http.request.uri}"])
        );
        let responses = h["handle_response"].as_array().unwrap();
        assert_eq!(responses.len(), 1);
        assert_eq!(responses[0]["match"]["status_code"], json!([2]));
        let routes = responses[0]["routes"].as_array().unwrap();
        assert_eq!(routes[0]["handle"][0]["handler"], "vars");
        assert_eq!(
            routes[1]["handle"][0]["request"]["delete"],
            json!(["X-User"])
        );
        assert_eq!(
            routes[2]["match"][0]["not"][0]["vars"]["{http.reverse_proxy.header.Remote-Email}"],
            json!([""])
        );
        assert_eq!(
            routes[2]["handle"][0]["request"]["set"]["X-User"],
            json!(["{http.reverse_proxy.header.Remote-Email}"])
        );
        assert_eq!(
            routes[3]["handle"][0]["request"]["delete"],
            json!(["Remote-User"])
        );
        assert_eq!(
            routes[4]["handle"][0]["request"]["set"]["Remote-User"],
            json!(["{http.reverse_proxy.header.Remote-User}"])
        );
    }

    #[test]
    fn forward_auth_reverse_proxy_rewrite_overrides_auth_uri() {
        let r = routes(
            r#"example.com {
  forward_auth auth-gateway:9091 {
    rewrite /override
    uri /authenticate
  }
}"#,
        );
        let h = &r[0]["handle"][0]["routes"][0]["handle"][0];
        assert_eq!(h["rewrite"]["uri"], "/override");
    }

    #[test]
    fn push_adapts_resources_and_headers() {
        let r = routes(
            r#"example.com {
  push {
    GET /app.js
    HEAD /style.css
    /image.png
    headers {
      X-Push yes
      +X-Trace trace
      -X-Drop
    }
  }
  respond ok
}"#,
        );
        let h = &r[0]["handle"][0]["routes"][0]["handle"][0];
        assert_eq!(h["handler"], "push");
        assert_eq!(
            h["resources"],
            json!([
                {"method": "GET", "target": "/app.js"},
                {"method": "HEAD", "target": "/style.css"},
                {"target": "/image.png"}
            ])
        );
        assert_eq!(h["headers"]["set"]["X-Push"], json!(["yes"]));
        assert_eq!(h["headers"]["add"]["X-Trace"], json!(["trace"]));
        assert_eq!(h["headers"]["delete"], json!(["X-Drop"]));
    }

    #[test]
    fn push_treats_same_line_block_tokens_as_resources_like_caddy() {
        let r = routes(
            r#"example.com {
  push {
    /a /b
    GET /c /d
  }
}"#,
        );
        let h = &r[0]["handle"][0]["routes"][0]["handle"][0];
        assert_eq!(
            h["resources"],
            json!([
                {"target": "/a"},
                {"target": "/b"},
                {"method": "GET", "target": "/c"},
                {"target": "/d"}
            ])
        );
    }

    #[test]
    fn intercept_adapts_response_handlers() {
        let r = routes(
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
        );
        let h = &r[0]["handle"][0]["routes"][0]["handle"][0];
        assert_eq!(h["handler"], "intercept");
        let responses = h["handle_response"].as_array().unwrap();
        assert_eq!(responses.len(), 2);
        assert_eq!(responses[0]["match"]["status_code"], json!([201]));
        assert_eq!(
            responses[0]["match"]["headers"]["X-Origin"],
            json!(["app*"])
        );
        assert_eq!(responses[0]["status_code"], 202);
        assert_eq!(
            responses[1]["routes"][0]["handle"][0]["response"]["set"]["X-Intercept"],
            json!(["yes"])
        );
    }

    #[test]
    fn intercept_rejects_removed_handle_response_status_args() {
        let err = adapt_err(
            r#"example.com {
  intercept {
    handle_response @created 202 {
      header X-Intercept yes
    }
  }
}"#,
        );
        assert!(err.contains("Use 'replace_status' instead"), "{err}");
    }

    #[test]
    fn reverse_proxy_handle_response_routes() {
        let r = routes(
            r#"example.com {
  reverse_proxy localhost:8080 {
    @ok {
      status 2xx 304
      header X-Origin ok*
    }
    handle_response {
      header X-Fallback yes
    }
    handle_response @ok {
      copy_response_headers {
        include X-Origin
      }
      header X-Matched yes
    }
    replace_status @ok 299
  }
}"#,
        );
        let h = &r[0]["handle"][0]["routes"][0]["handle"][0];
        let responses = h["handle_response"].as_array().unwrap();
        assert_eq!(responses.len(), 3);
        // Matched response handlers stay before catch-all handlers, preserving
        // relative order within those two partitions.
        assert_eq!(responses[0]["match"]["status_code"], json!([2, 304]));
        assert_eq!(responses[0]["match"]["headers"]["X-Origin"], json!(["ok*"]));
        assert_eq!(responses[0]["routes"][0]["handle"][0]["handler"], "headers");
        assert_eq!(
            responses[0]["routes"][0]["handle"][1]["handler"],
            "copy_response_headers"
        );
        assert_eq!(responses[1]["status_code"], 299);
        assert_eq!(responses[1]["match"]["status_code"], json!([2, 304]));
        assert!(responses[2].get("match").is_none());
        assert_eq!(
            responses[2]["routes"][0]["handle"][0]["response"]["set"]["X-Fallback"],
            json!(["yes"])
        );
    }

    #[test]
    fn reverse_proxy_response_matchers_support_single_line_syntax() {
        let r = routes(
            r#"example.com {
  reverse_proxy localhost:8080 {
    @ok status 2xx 304
    replace_status @ok 299
  }
}"#,
        );
        let h = &r[0]["handle"][0]["routes"][0]["handle"][0];
        let responses = h["handle_response"].as_array().unwrap();
        assert_eq!(responses[0]["match"]["status_code"], json!([2, 304]));
        assert_eq!(responses[0]["status_code"], 299);
    }

    #[test]
    fn response_header_matchers_canonicalize_value_fields_like_caddy() {
        let r = routes(
            r#"example.com {
  reverse_proxy localhost:8080 {
    @matched {
      header x-origin ok
      header !x-missing
    }
    replace_status @matched 204
  }
}"#,
        );
        let h = &r[0]["handle"][0]["routes"][0]["handle"][0];
        let matcher = &h["handle_response"][0]["match"]["headers"];
        assert_eq!(matcher["X-Origin"], json!(["ok"]));
        assert_eq!(matcher["x-missing"], Value::Null);
    }

    #[test]
    fn copy_response_is_rejected_as_body_copy_surface() {
        for input in [
            r#"example.com {
  reverse_proxy localhost:8080 {
    handle_response {
      copy_response {
        status 299
      }
    }
  }
}"#,
            r#"example.com {
  reverse_proxy localhost:8080 {
    handle_response {
      copy_response 299
    }
  }
}"#,
        ] {
            let err = adapt_err(input);
            assert!(
                err.contains("copy_response handler copies upstream response bodies"),
                "{err}"
            );
        }
    }

    #[test]
    fn copy_response_headers_match_caddy_leniency() {
        let r = routes(
            r#"example.com {
  reverse_proxy localhost:8080 {
    handle_response {
      copy_response_headers {
        include
        include A
        include B C
      }
      copy_response_headers {
        exclude
        exclude X
      }
    }
  }
}"#,
        );
        let handlers = r[0]["handle"][0]["routes"][0]["handle"][0]["handle_response"][0]["routes"]
            [0]["handle"]
            .as_array()
            .unwrap();
        assert_eq!(
            handlers[0],
            json!({"handler": "copy_response_headers", "include": ["A", "B", "C"]})
        );
        assert_eq!(
            handlers[1],
            json!({"handler": "copy_response_headers", "exclude": ["X"]})
        );
    }

    #[test]
    fn encode_defaults_to_zstd_and_gzip() {
        let r = routes(
            r#"example.com {
  encode
}"#,
        );
        let h = &r[0]["handle"][0]["routes"][0]["handle"][0];
        assert_eq!(h["handler"], "encode");
        assert_eq!(h["prefer"], json!(["zstd", "gzip"]));
        assert_eq!(h["encodings"], json!({"zstd": {}, "gzip": {}}));
    }

    #[test]
    fn encode_adapts_encoder_options_and_response_matchers() {
        let r = routes(
            r#"example.com {
  encode {
    zstd {
      level best
      disable_checksum
    }
    gzip 6
    minimum_length 128
    match {
      status 2xx 304
      header Content-Type text/*
      header !X-Present
    }
  }
}"#,
        );
        let h = &r[0]["handle"][0]["routes"][0]["handle"][0];
        assert_eq!(h["handler"], "encode");
        assert_eq!(h["prefer"], json!(["zstd", "gzip"]));
        assert_eq!(
            h["encodings"],
            json!({"zstd": {"level": "best", "checksum": false}, "gzip": {"level": 6}})
        );
        assert_eq!(h["minimum_length"], 128);
        assert_eq!(h["match"]["status_code"], json!([2, 304]));
        assert_eq!(h["match"]["headers"]["Content-Type"], json!(["text/*"]));
        assert_eq!(h["match"]["headers"]["X-Present"], Value::Null);
    }

    #[test]
    fn encode_response_matcher_repeated_status_lines_append_like_caddy() {
        let r = routes(
            r#"example.com {
  encode {
    match {
      status 2xx
      status 304
    }
  }
}"#,
        );
        let h = &r[0]["handle"][0]["routes"][0]["handle"][0];
        assert_eq!(h["handler"], "encode");
        assert_eq!(h["match"]["status_code"], json!([2, 304]));
    }

    #[test]
    fn response_matcher_header_requires_value_unless_negated_like_caddy() {
        let err = adapt(
            r#"example.com {
  header {
    match {
      header X-Present
    }
    X-Test yes
  }
}"#,
            "Caddyfile",
        )
        .unwrap_err()
        .to_string();
        assert!(
            err.contains("malformed header matcher: expected both field and value"),
            "{err}"
        );

        let r = routes(
            r#"example.com {
  header {
    match {
      header !X-Present
    }
    X-Test yes
  }
}"#,
        );
        let h = &r[0]["handle"][0]["routes"][0]["handle"][0];
        assert_eq!(
            h["response"]["require"]["headers"]["X-Present"],
            Value::Null
        );
    }

    #[test]
    fn response_matcher_repeated_headers_overwrite_and_append_like_caddy() {
        let r = routes(
            r#"example.com {
  header {
    match {
      header !X-Present
      header X-Present yes
      header X-Present no
    }
    X-Test yes
  }
}"#,
        );
        let h = &r[0]["handle"][0]["routes"][0]["handle"][0];
        assert_eq!(
            h["response"]["require"]["headers"]["X-Present"],
            json!(["yes", "no"])
        );

        let r = routes(
            r#"example.com {
  header {
    match {
      header X-Present yes
      header !X-Present
    }
    X-Test yes
  }
}"#,
        );
        let h = &r[0]["handle"][0]["routes"][0]["handle"][0];
        assert_eq!(
            h["response"]["require"]["headers"]["X-Present"],
            Value::Null
        );
    }

    #[test]
    fn encode_gzip_ignores_extra_args_like_caddy() {
        let r = routes(
            r#"example.com {
  encode {
    gzip 6 ignored
  }
}"#,
        );
        let h = &r[0]["handle"][0]["routes"][0]["handle"][0];
        assert_eq!(h["handler"], "encode");
        assert_eq!(h["prefer"], json!(["gzip"]));
        assert_eq!(h["encodings"], json!({"gzip": {"level": 6}}));
    }

    #[test]
    fn encode_rejects_unknown_encoder_modules_like_caddy() {
        for input in [
            r#"example.com {
  encode br
}"#,
            r#"example.com {
  encode {
    minimum_length 512 extra
  }
}"#,
        ] {
            let err = adapt_err(input);
            assert!(
                err.contains("module not registered: http.encoders."),
                "{err}"
            );
        }
    }

    #[test]
    fn templates_rejects_body_rewrite_surface() {
        let err = adapt_err(
            r#"example.com {
  templates /docs/* {
    mime text/html text/markdown
    between [[ ]]
    root /srv/www
    extensions {
    }
  }
}"#,
        );
        assert!(
            err.contains("templates handler rewrites response bodies"),
            "{err}"
        );
    }

    #[test]
    fn templates_rejects_unregistered_extension_modules_like_caddy() {
        let err = adapt_err(
            r#"example.com {
  templates {
    extensions {
      sprig
    }
  }
}"#,
        );
        assert!(
            err.contains("module not registered: http.handlers.templates.functions.sprig"),
            "{err}"
        );
    }

    #[test]
    fn templates_still_ignores_unknown_subdirectives_before_rejecting_surface() {
        let err = adapt_err(
            r#"example.com {
  templates {
    unknown value
  }
}"#,
        );
        assert!(
            err.contains("templates handler rewrites response bodies"),
            "{err}"
        );
    }

    #[test]
    fn metrics_adapts_runtime_handler_config() {
        let r = routes(
            r#"example.com {
  metrics /metrics {
    disable_openmetrics
  }
}"#,
        );
        assert_eq!(
            r[0]["handle"][0]["routes"][0]["match"][0]["path"],
            json!(["/metrics"])
        );
        let h = &r[0]["handle"][0]["routes"][0]["handle"][0];
        assert_eq!(h["handler"], "metrics");
        assert_eq!(h["disable_openmetrics"], true);
    }

    #[test]
    fn metrics_disable_openmetrics_rejects_extra_args_like_caddy() {
        let err = adapt_err(
            r#"example.com {
  metrics {
    disable_openmetrics ignored tokens
  }
}"#,
        );
        assert!(err.contains("wrong argument count"), "{err}");
    }

    #[test]
    fn acme_server_adapts_runtime_handler_config() {
        let (v, _) = adapt_full(
            r#"example.com {
  acme_server /.well-known/acme/* {
    ca local
    lifetime 24h
    resolvers 1.1.1.1:53 8.8.8.8:53
    challenges http-01 dns-01
    allow_wildcard_names
    allow {
      domains example.com *.example.com
      ip_ranges 10.0.0.0/8
    }
    deny {
      domains bad.example
    }
    sign_with_root
  }
}"#,
        );
        assert_eq!(
            v["apps"]["pki"]["certificate_authorities"]["local"],
            json!({})
        );
        let r = v["apps"]["http"]["servers"]["srv0"]["routes"]
            .as_array()
            .unwrap();
        assert_eq!(
            r[0]["handle"][0]["routes"][0]["match"][0]["path"],
            json!(["/.well-known/acme/*"])
        );
        let h = &r[0]["handle"][0]["routes"][0]["handle"][0];
        assert_eq!(h["handler"], "acme_server");
        assert_eq!(h["ca"], "local");
        assert_eq!(h["lifetime"], 86_400_000_000_000_i64);
        assert_eq!(h["resolvers"], json!(["1.1.1.1:53", "8.8.8.8:53"]));
        assert_eq!(h["challenges"], json!(["http-01", "dns-01"]));
        assert_eq!(h["policy"]["allow_wildcard_names"], true);
        assert_eq!(
            h["policy"]["allow"],
            json!({"domains": ["example.com", "*.example.com"], "ip_ranges": ["10.0.0.0/8"]})
        );
        assert_eq!(h["policy"]["deny"], json!({"domains": ["bad.example"]}));
        assert_eq!(h["sign_with_root"], true);
    }

    #[test]
    fn acme_server_rule_sets_report_labeled_unknown_subdirectives_like_caddy() {
        let err = adapt_err(
            r#"example.com {
  acme_server {
    allow {
      unknown value
    }
  }
}"#,
        );
        assert!(
            err.contains("unrecognized 'allow' subdirective: unknown"),
            "{err}"
        );
    }

    #[test]
    fn acme_server_ca_side_effect_applies_in_named_routes_like_caddy() {
        let (v, _) = adapt_full(
            r#"&(acme) {
acme_server {
  ca named
}
}

example.com {
  invoke acme
}"#,
        );
        assert_eq!(
            v["apps"]["pki"]["certificate_authorities"]["named"],
            json!({})
        );
        assert_eq!(
            v["apps"]["http"]["servers"]["srv0"]["routes"][0]["handle"][0]["routes"][0]["handle"]
                [0]["name"],
            "acme"
        );
    }

    #[test]
    fn acme_server_appends_repeated_lists_like_caddy() {
        let r = routes(
            r#"example.com {
  acme_server {
    challenges
    challenges http-01
    challenges dns-01 tls-alpn-01
    allow {
      domains a.example
      domains b.example c.example
      ip_ranges 10.0.0.0/8
      ip_ranges 192.168.0.0/16
    }
    deny {
      domains bad1.example
      domains bad2.example
    }
  }
}"#,
        );
        let h = &r[0]["handle"][0]["routes"][0]["handle"][0];
        assert_eq!(h["challenges"], json!(["http-01", "dns-01", "tls-alpn-01"]));
        assert_eq!(
            h["policy"]["allow"],
            json!({
                "domains": ["a.example", "b.example", "c.example"],
                "ip_ranges": ["10.0.0.0/8", "192.168.0.0/16"]
            })
        );
        assert_eq!(
            h["policy"]["deny"]["domains"],
            json!(["bad1.example", "bad2.example"])
        );

        let r = routes("example.com {\n  acme_server {\n    challenges\n  }\n}");
        let h = &r[0]["handle"][0]["routes"][0]["handle"][0];
        assert!(h.get("challenges").is_none(), "{h}");

        let err = adapt_err(
            r#"example.com {
  acme_server {
    allow_wildcard_names extra
  }
}"#,
        );
        assert!(
            err.contains("unrecognized ACME server directive: extra"),
            "{err}"
        );
    }

    #[test]
    fn invoke_adapts_named_routes() {
        let (v, _) = adapt_full(
            r#"&(shared) {
  header X-Shared yes
}

example.com {
  invoke shared
}"#,
        );
        let srv = &v["apps"]["http"]["servers"]["srv0"];
        assert_eq!(
            srv["named_routes"]["shared"]["handle"][0]["response"]["set"]["X-Shared"],
            json!(["yes"])
        );
        let h = &srv["routes"][0]["handle"][0]["routes"][0]["handle"][0];
        assert_eq!(h, &json!({"handler": "invoke", "name": "shared"}));
    }

    #[test]
    fn php_fastcgi_adapts_common_shortcut_routes() {
        let r = routes(
            r#"example.com {
  php_fastcgi localhost:9000 {
    root /srv/app
    env FOO bar
  }
}"#,
        );
        let routes = r[0]["handle"][0]["routes"].as_array().unwrap();
        assert_eq!(
            routes[0]["match"][0]["file"]["try_files"],
            json!(["{http.request.uri.path}/index.php"])
        );
        assert_eq!(routes[0]["handle"][0]["handler"], "static_response");
        assert_eq!(routes[0]["handle"][0]["status_code"], 308);
        assert_eq!(
            routes[1]["match"][0]["file"]["try_files"],
            json!([
                "{http.request.uri.path}",
                "{http.request.uri.path}/index.php",
                "index.php"
            ])
        );
        assert_eq!(routes[1]["handle"][0]["handler"], "rewrite");
        assert_eq!(routes[2]["match"][0]["path"], json!(["*.php"]));
        let proxy = &routes[2]["handle"][0];
        assert_eq!(proxy["handler"], "reverse_proxy");
        assert_eq!(proxy["upstreams"], json!([{"dial": "localhost:9000"}]));
        assert_eq!(proxy["transport"]["protocol"], "fastcgi");
        assert_eq!(proxy["transport"]["split_path"], json!([".php"]));
        assert_eq!(proxy["transport"]["root"], "/srv/app");
        assert_eq!(proxy["transport"]["env"], json!({"FOO": "bar"}));
    }

    #[test]
    fn php_fastcgi_split_extensions_match_caddy_fallback_policy() {
        let r = routes(
            r#"example.com {
  php_fastcgi localhost:9000 {
    split .php .php5
    index index.php5
  }
}"#,
        );
        let routes = r[0]["handle"][0]["routes"].as_array().unwrap();
        assert_eq!(
            routes[1]["match"][0]["file"]["try_files"],
            json!([
                "{http.request.uri.path}",
                "{http.request.uri.path}/index.php5",
                "index.php5"
            ])
        );
        assert_eq!(
            routes[1]["match"][0]["file"]["try_policy"],
            "first_exist_fallback"
        );
        let proxy = &routes[2]["handle"][0];
        assert_eq!(proxy["transport"]["split_path"], json!([".php", ".php5"]));
    }

    #[test]
    fn php_fastcgi_passes_trusted_proxies_to_reverse_proxy() {
        let r = routes(
            r#"example.com {
  php_fastcgi localhost:9000 {
    trusted_proxies private_ranges 203.0.113.0/24
  }
}"#,
        );
        let proxy = &r[0]["handle"][0]["routes"][2]["handle"][0];
        assert_eq!(proxy["handler"], "reverse_proxy");
        let ranges = proxy["trusted_proxies"].as_array().unwrap();
        assert!(ranges.contains(&json!("10.0.0.0/8")));
        assert!(ranges.contains(&json!("203.0.113.0/24")));
    }

    #[test]
    fn php_fastcgi_passes_runtime_controls_to_reverse_proxy() {
        let r = routes(
            r#"example.com {
  php_fastcgi localhost:9000 {
    request_buffers unlimited
    response_buffers 2KiB
    stream_buffer_size 4KiB
    stream_timeout 5s
    stream_close_delay 250ms
    flush_interval 1s
    verbose_logs
  }
}"#,
        );
        let proxy = &r[0]["handle"][0]["routes"][2]["handle"][0];
        assert_eq!(proxy["request_buffers"], -1);
        assert_eq!(proxy["response_buffers"], 2048);
        assert_eq!(proxy["stream_buffer_size"], 4096);
        assert_eq!(proxy["stream_timeout"], 5_000_000_000_i64);
        assert_eq!(proxy["stream_close_delay"], 250_000_000_i64);
        assert_eq!(proxy["flush_interval"], 1_000_000_000_i64);
        assert_eq!(proxy["verbose_logs"], true);
    }

    #[test]
    fn php_fastcgi_passes_load_balancing_to_reverse_proxy() {
        let r = routes(
            r#"example.com {
  php_fastcgi localhost:9000 {
    lb_policy random_choose 2
    lb_retries 3
    lb_try_duration 5s
    lb_try_interval 250ms
    lb_retry_match {
      method GET
    }
  }
}"#,
        );
        let proxy = &r[0]["handle"][0]["routes"][2]["handle"][0];
        let lb = &proxy["load_balancing"];
        assert_eq!(
            lb["selection_policy"],
            json!({"policy": "random_choose", "choose": 2})
        );
        assert_eq!(lb["retries"], 3);
        assert_eq!(lb["try_duration"], 5_000_000_000_i64);
        assert_eq!(lb["try_interval"], 250_000_000_i64);
        assert_eq!(lb["retry_match"], json!([{"method": ["GET"]}]));
    }

    #[test]
    fn php_fastcgi_passes_health_checks_to_reverse_proxy() {
        let r = routes(
            r#"example.com {
  php_fastcgi localhost:9000 {
    health_uri /health
    health_method POST
    health_request_body ping
    health_status 2xx
    health_interval 5s
    health_timeout 250ms
    health_follow_redirects
    health_passes 2
    health_fails 3
    health_headers {
      X-Check one two
    }
    max_fails 4
    fail_duration 10s
    unhealthy_request_count 5
    unhealthy_status 5xx 429
    unhealthy_latency 2s
  }
}"#,
        );
        let health = &r[0]["handle"][0]["routes"][2]["handle"][0]["health_checks"];
        assert_eq!(
            health["active"],
            json!({
                "uri": "/health",
                "method": "POST",
                "body": "ping",
                "expect_status": 2,
                "interval": 5_000_000_000_i64,
                "timeout": 250_000_000_i64,
                "follow_redirects": true,
                "passes": 2,
                "fails": 3,
                "headers": {"X-Check": ["one", "two"]}
            })
        );
        assert_eq!(
            health["passive"],
            json!({
                "max_fails": 4,
                "fail_duration": 10_000_000_000_i64,
                "unhealthy_request_count": 5,
                "unhealthy_status": [5, 429],
                "unhealthy_latency": 2_000_000_000_i64
            })
        );
    }

    #[test]
    fn php_fastcgi_health_headers_append_repeated_fields_like_caddy() {
        let r = routes(
            r#"example.com {
  php_fastcgi localhost:9000 {
    health_headers {
      X-Check one
      X-Check two three
      X-Empty
    }
  }
}"#,
        );
        let health = &r[0]["handle"][0]["routes"][2]["handle"][0]["health_checks"];
        assert_eq!(
            health["active"]["headers"]["X-Check"],
            json!(["one", "two", "three"])
        );
        assert_eq!(health["active"]["headers"]["X-Empty"], json!([""]));
    }

    #[test]
    fn php_fastcgi_passes_response_handlers_to_reverse_proxy() {
        let r = routes(
            r#"example.com {
  php_fastcgi localhost:9000 {
    @bad status 5xx
    replace_status @bad 502
    handle_response {
      header X-Upstream-Handled yes
    }
  }
}"#,
        );
        let proxy = &r[0]["handle"][0]["routes"][2]["handle"][0];
        assert_eq!(
            proxy["handle_response"],
            json!([
                {
                    "match": {"status_code": [5]},
                    "status_code": 502
                },
                {
                    "routes": [{
                        "handle": [{
                            "handler": "headers",
                            "response": {"set": {"X-Upstream-Handled": ["yes"]}}
                        }]
                    }]
                }
            ])
        );
    }

    #[test]
    fn php_fastcgi_passes_method_rewrite_to_reverse_proxy() {
        let r = routes(
            r#"example.com {
  php_fastcgi localhost:9000 {
    method GET
    rewrite /backend{uri}
  }
}"#,
        );
        let proxy = &r[0]["handle"][0]["routes"][2]["handle"][0];
        assert_eq!(
            proxy["rewrite"],
            json!({"method": "GET", "uri": "/backend{http.request.uri}"})
        );
    }

    #[test]
    fn php_fastcgi_passes_dynamic_upstreams_to_reverse_proxy() {
        let r = routes(
            r#"example.com {
  php_fastcgi {
    dynamic a example.test 9000 {
      versions ipv4
      refresh 5s
    }
  }
}"#,
        );
        let proxy = &r[0]["handle"][0]["routes"][2]["handle"][0];
        assert_eq!(proxy["upstreams"], json!([]));
        assert_eq!(
            proxy["dynamic_upstreams"],
            json!({
                "source": "a",
                "name": "example.test",
                "port": "9000",
                "versions": {"ipv4": true},
                "refresh": 5_000_000_000_i64
            })
        );
    }

    #[test]
    fn php_fastcgi_rejects_duplicate_dynamic_and_transport_override() {
        let duplicate = adapt_err(
            r#"example.com {
  php_fastcgi localhost:9000 {
    dynamic a example.test
    dynamic a other.test
  }
}"#,
        );
        assert!(
            duplicate.contains("dynamic upstreams already specified"),
            "{duplicate}"
        );

        let transport = adapt_err(
            r#"example.com {
  php_fastcgi localhost:9000 {
    transport http
  }
}"#,
        );
        assert!(
            transport.contains("transport already specified"),
            "{transport}"
        );
    }

    #[test]
    fn try_files_lowers_to_file_matcher_rewrites() {
        let r = routes(
            r#"example.com {
  try_files {path} /index.php?{query}&p={path} =404 {
    policy first_exist_fallback
  }
}"#,
        );
        let routes = r[0]["handle"][0]["routes"].as_array().unwrap();
        assert_eq!(routes.len(), 3);
        assert_eq!(routes[0]["group"], routes[1]["group"]);
        assert_eq!(routes[1]["group"], routes[2]["group"]);
        assert_eq!(
            routes[0]["match"][0]["file"]["try_files"],
            json!(["{http.request.uri.path}"])
        );
        assert_eq!(
            routes[0]["match"][0]["file"]["try_policy"],
            "first_exist_fallback"
        );
        assert_eq!(
            routes[0]["handle"][0]["uri"],
            "{http.matchers.file.relative}"
        );
        assert_eq!(
            routes[1]["match"][0]["file"]["try_files"],
            json!(["/index.php"])
        );
        assert_eq!(
            routes[1]["handle"][0]["uri"],
            "{http.matchers.file.relative}?{http.request.uri.query}&p={http.request.uri.path}"
        );
        assert_eq!(routes[2]["match"][0]["file"]["try_files"], json!(["=404"]));
    }

    #[test]
    fn try_files_single_route_is_not_grouped_like_caddy() {
        let r = routes(
            r#"example.com {
  try_files {path} /index.html
}"#,
        );
        let routes = r[0]["handle"][0]["routes"].as_array().unwrap();
        assert_eq!(routes.len(), 1);
        assert!(routes[0].get("group").is_none(), "{routes:?}");
        assert_eq!(
            routes[0]["match"][0]["file"]["try_files"],
            json!(["{http.request.uri.path}", "/index.html"])
        );
    }

    #[test]
    fn try_files_ignores_unknown_subdirectives_like_caddy() {
        let r = routes(
            r#"example.com {
  try_files {path} /index.html {
    unsupported value
  }
}"#,
        );
        let routes = r[0]["handle"][0]["routes"].as_array().unwrap();
        assert_eq!(routes.len(), 1);
        assert_eq!(
            routes[0]["match"][0]["file"]["try_files"],
            json!(["{http.request.uri.path}", "/index.html"])
        );
    }

    #[test]
    fn header_ops() {
        let r = routes("example.com {\n  header {\n    X-Foo bar\n    -X-Bar\n  }\n}");
        let h = &r[0]["handle"][0]["routes"][0]["handle"][0];
        assert_eq!(h["handler"], "headers");
        assert_eq!(h["response"]["set"]["X-Foo"], json!(["bar"]));
        assert_eq!(h["response"]["delete"], json!(["X-Bar"]));
        assert_eq!(h["response"]["deferred"], json!(true));
    }

    #[test]
    fn header_field_suffix_trims_only_one_colon_like_caddy() {
        let r = routes(
            r#"example.com {
  header {
    X-Test:: ok
  }
  request_header X-Req:: ok
}"#,
        );
        let handlers = r[0]["handle"][0]["routes"][0]["handle"].as_array().unwrap();
        assert_eq!(handlers[0]["response"]["set"]["X-Test:"], json!(["ok"]));
        assert_eq!(handlers[1]["request"]["set"]["X-Req:"], json!(["ok"]));
    }

    #[test]
    fn header_match_response_matcher_adapts() {
        let r = routes(
            r#"example.com {
  header {
    match {
      status 2xx 304
      header X-Origin ok*
    }
    X-Matched yes
  }
}"#,
        );
        let h = &r[0]["handle"][0]["routes"][0]["handle"][0];
        assert_eq!(h["handler"], "headers");
        assert_eq!(h["response"]["set"]["X-Matched"], json!(["yes"]));
        assert_eq!(h["response"]["require"]["status_code"], json!([2, 304]));
        assert_eq!(
            h["response"]["require"]["headers"]["X-Origin"],
            json!(["ok*"])
        );
    }

    #[test]
    fn header_match_response_matcher_supports_single_line_syntax() {
        let r = routes(
            r#"example.com {
  header {
    match status 3xx
    X-Matched yes
  }
}"#,
        );
        let h = &r[0]["handle"][0]["routes"][0]["handle"][0];
        assert_eq!(h["response"]["require"]["status_code"], json!([3]));
    }

    #[test]
    fn log_append_adapts_as_observability_handler() {
        let r = routes("example.com {\n  log_append /admin* <route admin\n  respond ok\n}");
        let routes = r[0]["handle"][0]["routes"].as_array().unwrap();
        assert_eq!(routes[0]["match"][0]["path"], json!(["/admin*"]));
        let h = &routes[0]["handle"][0];
        assert_eq!(h["handler"], "log_append");
        assert_eq!(h["key"], "route");
        assert_eq!(h["value"], "admin");
        assert_eq!(h["early"], true);
    }

    #[test]
    fn site_log_is_accepted_outside_ebpf_surface() {
        let (v, warnings) = adapt_full(
            r#"example.com {
  log access {
    hostnames api.example.com
    output stdout
    format console
    level info
    sampling {
      interval 10s
      first 5
      thereafter 100
    }
  }
  respond ok
}"#,
        );
        assert!(warnings.iter().any(|w| w.contains("site log directive")));
        let h = &v["apps"]["http"]["servers"]["srv0"]["routes"][0]["handle"][0]["routes"][0]["handle"]
            [0];
        assert_eq!(h["handler"], "static_response");
    }

    #[test]
    fn site_log_accepts_nested_format_append_outside_ebpf_surface() {
        let (v, warnings) = adapt_full(
            r#"example.com {
  log {
    output stdout
    format append {
      fields {
        svc peekaping:gateway
      }
      wrap json {
        time_format iso8601
        message_key msg
      }
    }
    level info
  }
  respond ok
}"#,
        );
        assert!(warnings.iter().any(|w| w.contains("site log directive")));
        let h = &v["apps"]["http"]["servers"]["srv0"]["routes"][0]["handle"][0]["routes"][0]["handle"]
            [0];
        assert_eq!(h["handler"], "static_response");
    }

    #[test]
    fn site_log_rejects_global_only_subdirectives() {
        let err = adapt_err(
            r#"example.com {
  log {
    include http.log.access.default
  }
}"#,
        );
        assert!(
            err.contains("include is not allowed in the log directive"),
            "{err}"
        );
    }

    #[test]
    fn site_bind_and_tls_are_accepted_outside_ebpf_surface() {
        let (v, warnings) = adapt_full(
            r#"example.com {
  bind 127.0.0.1 {
    protocols h1 h2
  }
  tls internal {
    protocols tls1.2 tls1.3
    client_auth {
      mode require_and_verify
      trusted_leaf_cert_file client.pem
    }
    on_demand
  }
  respond ok
}"#,
        );
        assert!(warnings.iter().any(|w| w.contains("site bind directive")));
        assert!(warnings.iter().any(|w| w.contains("site tls directive")));
        let h = &v["apps"]["http"]["servers"]["srv0"]["routes"][0]["handle"][0]["routes"][0]["handle"]
            [0];
        assert_eq!(h["handler"], "static_response");
    }

    #[test]
    fn acme_options_produce_tls_automation_policies() {
        let (v, _) = adapt_full(
            r#"{
  email admin@example.com
  acme_ca https://acme.example/dir
  acme_eab {
    key_id kid-1
    mac_key bWFjLXNlY3JldA
  }
}
example.com {
  respond ok
}
internal.example {
  tls internal
  respond ok
}"#,
        );
        let policies = v["apps"]["tls"]["automation"]["policies"]
            .as_array()
            .expect("automation policies");
        let acme = policies
            .iter()
            .find_map(|p| {
                p["issuers"]
                    .as_array()?
                    .iter()
                    .find(|i| i["module"] == "acme")
            })
            .expect("acme issuer");
        assert_eq!(acme["email"], "admin@example.com");
        assert_eq!(acme["ca"], "https://acme.example/dir");
        assert_eq!(acme["external_account"]["key_id"], "kid-1");
        assert_eq!(acme["external_account"]["mac_key"], "bWFjLXNlY3JldA");
        let internal = policies
            .iter()
            .find(|p| {
                p["issuers"]
                    .as_array()
                    .is_some_and(|is| is.iter().any(|i| i["module"] == "internal"))
            })
            .expect("internal policy");
        assert_eq!(internal["subjects"][0], "internal.example");
    }

    #[test]
    fn site_tls_email_produces_acme_issuer() {
        let (v, _) = adapt_full(
            r#"example.com {
  tls me@example.com
  respond ok
}"#,
        );
        let policies = v["apps"]["tls"]["automation"]["policies"]
            .as_array()
            .expect("automation policies");
        assert!(policies.iter().any(|p| {
            p["issuers"].as_array().is_some_and(|is| {
                is.iter()
                    .any(|i| i["module"] == "acme" && i["email"] == "me@example.com")
            })
        }));
    }

    #[test]
    fn conflicting_site_acme_settings_are_rejected() {
        let err = adapt_err(
            r#"a.example {
  tls a@example.com
  respond ok
}
b.example {
  tls b@example.com
  respond ok
}"#,
        );
        assert!(err.contains("conflicting ACME email"), "{err}");

        let ca_conflict = adapt_err(
            r#"{
  acme_ca https://ca-one.example/dir
}
a.example {
  tls {
    ca https://ca-two.example/dir
  }
  respond ok
}"#,
        );
        assert!(ca_conflict.contains("conflicting ACME ca"), "{ca_conflict}");
    }

    #[test]
    fn site_tls_off_emits_automatic_https_skip() {
        let (v, _) = adapt_full(
            r#"{
  email admin@example.com
}
a.example {
  respond ok
}
b.example {
  tls off
  respond ok
}"#,
        );
        let skip = &v["apps"]["http"]["servers"]["srv0"]["automatic_https"]["skip"];
        assert_eq!(skip, &json!(["b.example"]));
        // `tls off` must not contribute an ACME issuer.
        let policies = v["apps"]["tls"]["automation"]["policies"]
            .as_array()
            .expect("automation policies");
        assert!(policies.iter().all(|p| {
            p["issuers"]
                .as_array()
                .is_none_or(|is| is.iter().all(|i| i["module"] != "internal"))
        }));
    }

    #[test]
    fn no_tls_app_without_acme_config() {
        let (v, _) = adapt_full(
            r#"example.com {
  respond ok
}"#,
        );
        assert!(v["apps"].get("tls").is_none(), "{v}");
    }

    #[test]
    fn site_tls_rejects_invalid_shape() {
        let naked = adapt_err("example.com {\n  tls\n}");
        assert!(naked.contains("wrong argument count"), "{naked}");

        let bad_single_arg = adapt_err("example.com {\n  tls not-an-email\n}");
        assert!(
            bad_single_arg.contains(
                "single argument must be 'internal', 'force_automate', 'off', or an email address"
            ),
            "{bad_single_arg}"
        );

        let (_, dns_warnings) = adapt_full(
            r#"example.com {
  tls {
    dns cloudflare token
  }
}"#,
        );
        assert!(
            dns_warnings
                .iter()
                .any(|w| w.contains("ignoring tls 'dns cloudflare'")),
            "{dns_warnings:?}"
        );

        let bad_protocol = adapt_err(
            r#"example.com {
  tls {
    protocols tls1.2 tls1.4
  }
}"#,
        );
        assert!(
            bad_protocol.contains("wrong protocol name or protocol not supported: 'tls1.4'"),
            "{bad_protocol}"
        );

        let bad_cipher = adapt_err(
            r#"example.com {
  tls {
    ciphers TLS_FAKE
  }
}"#,
        );
        assert!(
            bad_cipher
                .contains("wrong cipher suite name or cipher suite not supported: 'TLS_FAKE'"),
            "{bad_cipher}"
        );

        let bad_curve = adapt_err(
            r#"example.com {
  tls {
    curves fakecurve
  }
}"#,
        );
        assert!(
            bad_curve.contains("Wrong curve name or curve not supported: 'fakecurve'"),
            "{bad_curve}"
        );

        let extra_ca = adapt_err(
            r#"example.com {
  tls {
    ca https://ca.example extra
  }
}"#,
        );
        assert!(extra_ca.contains("wrong argument count"), "{extra_ca}");

        let missing_dns_provider = adapt_err(
            r#"example.com {
  tls {
    resolvers 1.1.1.1
  }
}"#,
        );
        assert!(
            missing_dns_provider
                .contains("setting DNS challenge options [resolvers] requires a DNS provider"),
            "{missing_dns_provider}"
        );

        let bad_duration = adapt_err(
            r#"example.com {
  tls {
    propagation_delay nope
  }
}"#,
        );
        assert!(
            bad_duration.contains("invalid propagation_delay duration nope"),
            "{bad_duration}"
        );

        let unknown = adapt_err(
            r#"example.com {
  tls internal {
    bogus yes
  }
}"#,
        );
        assert!(unknown.contains("unknown subdirective: bogus"), "{unknown}");
    }

    #[test]
    fn site_tls_accepts_caddy_edge_shapes() {
        let (v, warnings) = adapt_full(
            r#"{
  acme_dns
}

example.com {
  tls {
    protocols tls1.2 tls1.3 ignored
    ciphers
    curves
    load
    resolvers 1.1.1.1
    propagation_timeout -1
  }
  respond ok
}"#,
        );
        assert!(
            warnings
                .iter()
                .any(|w| w.contains("global option 'acme_dns'"))
        );
        assert!(warnings.iter().any(|w| w.contains("site tls directive")));
        let h = &v["apps"]["http"]["servers"]["srv0"]["routes"][0]["handle"][0]["routes"][0]["handle"]
            [0];
        assert_eq!(h["handler"], "static_response");
    }

    #[test]
    fn site_tls_client_auth_validates_like_caddy() {
        let (v, warnings) = adapt_full(
            r#"example.com {
  tls {
    client_auth ignored {
      trust_pool inline certdata
      verifier leaf
    }
  }
  respond ok
}"#,
        );
        assert!(warnings.iter().any(|w| w.contains("site tls directive")));
        assert_eq!(
            v["apps"]["http"]["servers"]["srv0"]["tls_connection_policies"][0]["client_authentication"]
                ["ca"]["trusted_ca_certs"],
            json!(["certdata"])
        );
        assert_eq!(
            v["apps"]["http"]["servers"]["srv0"]["tls_connection_policies"][0]["match"]["sni"],
            json!(["example.com"])
        );
        let h = &v["apps"]["http"]["servers"]["srv0"]["routes"][0]["handle"][0]["routes"][0]["handle"]
            [0];
        assert_eq!(h["handler"], "static_response");

        let (v, _) = adapt_full(
            r#"example.com {
  tls {
    client_auth {
      mode require_and_verify
      trusted_ca_cert_file /tmp/client-ca.pem
    }
  }
  respond ok
}"#,
        );
        assert_eq!(
            v["apps"]["http"]["servers"]["srv0"]["tls_connection_policies"][0]["client_authentication"]
                ["ca"]["trusted_ca_cert_files"],
            json!(["/tmp/client-ca.pem"])
        );

        let mode_extra = adapt_err(
            r#"example.com {
  tls {
    client_auth {
      mode require extra
    }
  }
}"#,
        );
        assert!(mode_extra.contains("wrong argument count"), "{mode_extra}");

        let unknown = adapt_err(
            r#"example.com {
  tls {
    client_auth {
      bogus yes
    }
  }
}"#,
        );
        assert!(
            unknown.contains("unknown subdirective for client_auth: bogus"),
            "{unknown}"
        );

        let unknown_trust_pool = adapt_err(
            r#"example.com {
  tls {
    client_auth {
      trust_pool leaf certdata
    }
  }
}"#,
        );
        assert!(
            unknown_trust_pool.contains("module not registered: tls.ca_pool.source.leaf"),
            "{unknown_trust_pool}"
        );

        let unknown_verifier = adapt_err(
            r#"example.com {
  tls {
    client_auth {
      verifier bogus
    }
  }
}"#,
        );
        assert!(
            unknown_verifier.contains("module not registered: tls.client_auth.verifier.bogus"),
            "{unknown_verifier}"
        );

        let conflict = adapt_err(
            r#"example.com {
  tls {
    client_auth {
      trusted_ca_cert certdata
      trust_pool inline certdata
    }
  }
}"#,
        );
        assert!(
            conflict.contains(
                "cannot specify both 'trust_pool' and 'trusted_ca_cert' or 'trusted_ca_cert_file'"
            ),
            "{conflict}"
        );
    }

    #[test]
    fn tracing_adapts_as_observability_handler() {
        let r = routes(
            r#"example.com {
  tracing {
    span request-{http.request.method}
    span_attributes {
      route {http.request.uri.path}
      tenant example
    }
  }
  respond ok
}"#,
        );
        let h = &r[0]["handle"][0]["routes"][0]["handle"][0];
        assert_eq!(h["handler"], "tracing");
        assert_eq!(h["span"], "request-{http.request.method}");
        assert_eq!(
            h["span_attributes"],
            json!({
                "route": "{http.request.uri.path}",
                "tenant": "example"
            })
        );
    }

    #[test]
    fn tracing_emits_default_span_like_caddy_json() {
        let r = routes(
            r#"example.com {
  tracing
  respond ok
}"#,
        );
        let h = &r[0]["handle"][0]["routes"][0]["handle"][0];
        assert_eq!(h["handler"], "tracing");
        assert_eq!(h["span"], "");

        let r = routes(
            r#"example.com {
  tracing {
    span_attributes {
      route path
    }
  }
  respond ok
}"#,
        );
        let h = &r[0]["handle"][0]["routes"][0]["handle"][0];
        assert_eq!(h["span"], "");
        assert_eq!(h["span_attributes"], json!({"route": "path"}));
    }

    #[test]
    fn tracing_rejects_span_attributes_arguments_like_caddy() {
        let err = adapt_err(
            r#"example.com {
  tracing {
    span_attributes unexpected {
      route path
    }
  }
}"#,
        );
        assert!(err.contains("wrong argument count"), "{err}");
    }

    #[test]
    fn basic_auth_adapts_as_authentication_handler() {
        let r = routes(
            r#"example.com {
  basic_auth /admin/* argon2id "Admin Area" {
    alice $argon2id$v=19$m=47104,t=1,p=1$salt$hash
    bob $argon2id$v=19$m=47104,t=1,p=1$salt2$hash2
  }
  respond ok
}"#,
        );
        let route = &r[0]["handle"][0]["routes"][0];
        assert_eq!(route["match"][0]["path"], json!(["/admin/*"]));
        let h = &route["handle"][0];
        assert_eq!(h["handler"], "authentication");
        let provider = &h["providers"]["http_basic"];
        assert_eq!(provider["hash"]["algorithm"], "argon2id");
        assert_eq!(provider["hash_cache"], json!({}));
        assert_eq!(provider["realm"], "Admin Area");
        assert_eq!(
            provider["accounts"],
            json!([
                {"username": "alice", "password": "$argon2id$v=19$m=47104,t=1,p=1$salt$hash"},
                {"username": "bob", "password": "$argon2id$v=19$m=47104,t=1,p=1$salt2$hash2"}
            ])
        );
    }

    #[test]
    fn basic_auth_missing_password_matches_caddy_error() {
        let err = adapt_err(
            r#"example.com {
  basic_auth {
    alice
  }
}"#,
        );
        assert!(
            err.contains("username and password cannot be empty or missing"),
            "{err}"
        );
    }

    #[test]
    fn basicauth_warns_and_defaults_to_bcrypt() {
        let (v, warnings) = adapt_full(
            r#"example.com {
  basicauth {
    alice $2a$14$hashed
  }
}"#,
        );
        assert!(warnings.iter().any(|w| w.contains("basicauth")));
        let h = &v["apps"]["http"]["servers"]["srv0"]["routes"][0]["handle"][0]["routes"][0]["handle"]
            [0];
        assert_eq!(h["handler"], "authentication");
        assert_eq!(h["providers"]["http_basic"]["hash"]["algorithm"], "bcrypt");
        assert_eq!(h["providers"]["http_basic"]["hash_cache"], json!({}));
    }

    #[test]
    fn log_skip_and_log_name_adapt_as_vars() {
        let (v, warnings) = adapt_full(
            "example.com {\n  log_skip /hidden*\n  skip_log /legacy*\n  log_name access_a access_b\n  respond ok\n}",
        );
        assert!(warnings.iter().any(|w| w.contains("skip_log")));
        let r = v["apps"]["http"]["servers"]["srv0"]["routes"].clone();
        let routes = r[0]["handle"][0]["routes"].as_array().unwrap();
        let mut saw_hidden = false;
        let mut saw_legacy = false;
        let mut saw_names = false;
        for route in routes {
            let handler = &route["handle"][0];
            if route["match"][0]["path"] == json!(["/hidden*"]) {
                assert_eq!(handler["handler"], "vars");
                assert_eq!(handler["log_skip"], true);
                saw_hidden = true;
            } else if route["match"][0]["path"] == json!(["/legacy*"]) {
                assert_eq!(handler["handler"], "vars");
                assert_eq!(handler["log_skip"], true);
                saw_legacy = true;
            } else if handler["access_logger_names"] == json!(["access_a", "access_b"]) {
                saw_names = true;
            }
        }
        assert!(saw_hidden && saw_legacy && saw_names);
    }

    #[test]
    fn log_skip_rejects_blocks_like_caddy() {
        let err = adapt_err(
            r#"example.com {
  log_skip {
    anything
  }
}"#,
        );
        assert!(
            err.contains("log_skip directive does not accept blocks"),
            "{err}"
        );
    }

    #[test]
    fn log_name_without_names_adapts_null_like_caddy() {
        let r = routes("example.com {\n  log_name\n  respond ok\n}");
        let handler = &r[0]["handle"][0]["routes"][0]["handle"][0];
        assert_eq!(handler["handler"], "vars");
        assert_eq!(handler["access_logger_names"], Value::Null);
    }

    #[test]
    fn bare_single_site_no_host_matcher() {
        // No host key -> catch-all; single block & no host matcher -> not wrapped.
        let r = routes(":8080\nrespond ok");
        assert_eq!(r[0]["handle"][0]["handler"], "static_response");
    }

    #[test]
    fn bare_known_directive_site_address_errors_like_caddy() {
        let err = adapt_err("handle\n\nrespond \"should not work\"");
        assert!(
            err.contains(
                "parsed 'handle' as a site address, but it is a known directive; directives must appear in a site block"
            ),
            "{err}"
        );
    }

    #[test]
    fn explicit_http_directive_like_hostname_is_valid_like_caddy() {
        let r = routes(
            r#"http://handle {
  file_server
}"#,
        );
        assert_eq!(r[0]["match"][0]["host"], json!(["handle"]));
        let h = &r[0]["handle"][0]["routes"][0]["handle"][0];
        assert_eq!(h["handler"], "file_server");
    }

    #[test]
    fn duplicate_site_keys_on_same_listener_error_like_caddy() {
        let err = adapt_err(
            r#":8080 {
  respond "one"
}

:8080 {
  respond "two"
}"#,
        );
        assert!(err.contains("ambiguous site definition: :8080"), "{err}");
    }

    #[test]
    fn duplicate_site_keys_on_different_listeners_are_not_ambiguous() {
        let v = adapt_full(
            r#"http://example.com {
  respond "http"
}

https://example.com {
  respond "https"
}"#,
        )
        .0;
        let servers = v["apps"]["http"]["servers"].as_object().unwrap();
        assert_eq!(servers.len(), 2);
    }

    #[test]
    fn mixed_scheme_site_block_pairs_each_listener_like_caddy() {
        let v = adapt_full(
            r#"abcdef {
  respond "abcdef"
}
abcdefg {
  respond "abcdefg"
}
abc {
  respond "abc"
}
abcde, http://abcde {
  respond "abcde"
}"#,
        )
        .0;

        let servers = v["apps"]["http"]["servers"].as_object().unwrap();
        assert_eq!(servers["srv0"]["listen"], json!([":443"]));
        assert_eq!(
            servers["srv0"]["routes"][2]["match"][0]["host"],
            json!(["abcde"])
        );
        assert_eq!(servers["srv1"]["listen"], json!([":80"]));
        assert_eq!(
            servers["srv1"]["routes"][0]["match"][0]["host"],
            json!(["abcde"])
        );
    }

    #[test]
    fn server_names_and_site_bind_shape_listeners_like_caddy() {
        let v = adapt_full(
            r#"{
  servers :443 {
    name https
  }
  servers :8000 {
    name app1
  }
  servers :8001 {
    name app2
  }
  servers 123.123.123.123:8002 {
    name bind-server
  }
}

example.com {
}
:8000 {
}
:8001, :8002 {
}
:8002 {
  bind 123.123.123.123 222.222.222.222
}"#,
        )
        .0;

        let servers = v["apps"]["http"]["servers"].as_object().unwrap();
        assert_eq!(servers["https"]["listen"], json!([":443"]));
        assert_eq!(servers["app1"]["listen"], json!([":8000"]));
        assert_eq!(servers["app2"]["listen"], json!([":8001"]));
        assert_eq!(
            servers["bind-server"]["listen"],
            json!(["123.123.123.123:8002", "222.222.222.222:8002"])
        );
        assert_eq!(servers["srv4"]["listen"], json!([":8002"]));
        assert!(servers["app1"].get("routes").is_none());
    }

    #[test]
    fn catch_all_site_blocks_preserve_source_order_like_caddy() {
        let r = routes(
            r#":80/a {
  respond "a"
}
:80/b {
  respond "b"
}"#,
        );
        assert_eq!(r[0]["match"][0]["path"], json!(["/a"]));
        assert_eq!(r[1]["match"][0]["path"], json!(["/b"]));
    }
}
