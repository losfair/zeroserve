use std::{path::PathBuf, sync::Arc, time::Duration};

use anyhow::{Result, anyhow, bail};

use crate::{
    bpf_compiler::EbpfCompiler,
    cli::{Cli, ListenAddr},
};

pub struct StaticConfig {
    pub http_addr: ListenAddr,
    pub tls_addr: Option<ListenAddr>,
    pub tar_path: PathBuf,
    /// When set (the `--caddy` flow), the site is served from this in-memory
    /// tarball rather than read from `tar_path`. `tar_path` then points at the
    /// source Caddyfile for diagnostics.
    pub caddy_tarball: Option<Arc<Vec<u8>>>,
    pub plugin_paths: Vec<PathBuf>,
    pub plugin_dir_paths: Vec<PathBuf>,
    pub cert_path: Option<PathBuf>,
    pub key_path: Option<PathBuf>,
    pub cert_dir_path: Option<PathBuf>,
    pub ech_key_path: Option<PathBuf>,
    pub reload_signal_file: Option<PathBuf>,
    pub index_file: String,
    pub chunk_size: usize,
    pub try_html: bool,
    pub expose_filesystem: bool,
    pub disable_request_logging: bool,
    pub enable_proxy_protocol: bool,
    pub disable_ns_isolation: bool,
    pub enable_netns_isolation: bool,
    pub threads: usize,
    pub preempt_timer_interval: Duration,
    pub sqpoll_idle_ms: Option<u32>,
    pub debug_proxy_protocol_disable_fast_path: bool,
    pub max_buffered_body_size: usize,
    pub max_request_external_memory_footprint: u64,
    pub max_rate_limit_buckets: usize,
    pub script_code_size_limit: usize,
    pub ebpf_require_static_region_analysis: bool,
    pub validate_hostnames: Vec<String>,
    pub ebpf_compiler: EbpfCompiler,
    #[cfg(feature = "iroh-proxy")]
    pub iroh_proxy: bool,
    #[cfg(feature = "iroh-proxy")]
    pub iroh_secret_key: Option<PathBuf>,
    #[cfg(feature = "iroh-proxy")]
    pub iroh_disable_networking: bool,
}

impl TryFrom<Cli> for StaticConfig {
    type Error = anyhow::Error;

    fn try_from(cli: Cli) -> Result<Self> {
        // async-ebpf requires the JIT code zone to be a non-zero multiple of
        // 64 KiB that fits in u32; validate here so it fails as a CLI error
        // instead of a loader panic.
        if cli.script_code_size_limit_kb % 64 != 0 {
            bail!("--script-code-size-limit-kb must be a multiple of 64");
        }
        let script_code_size_limit = cli
            .script_code_size_limit_kb
            .checked_mul(1024)
            .filter(|limit| u32::try_from(*limit).is_ok())
            .ok_or_else(|| anyhow!("--script-code-size-limit-kb is too large"))?;
        let http_addr = cli.addr;
        let tls_requested = cli.tls_addr.is_some()
            || cli.cert.is_some()
            || cli.key.is_some()
            || cli.cert_dir.is_some();
        let (tls_addr, cert_path, key_path, cert_dir_path) = if tls_requested {
            let tls_addr = cli
                .tls_addr
                .ok_or_else(|| anyhow!("--tls-addr is required when enabling TLS"))?;

            if let Some(cert_dir) = cli.cert_dir.clone() {
                (Some(tls_addr), None, None, Some(cert_dir))
            } else if cli.caddy.is_some() && cli.cert.is_none() && cli.key.is_none() {
                // `--caddy` without explicit cert flags: certificates come from
                // the Caddyfile's TLS policies, selected per connection by the
                // generated eBPF TLS section.
                (Some(tls_addr), None, None, None)
            } else {
                let cert = cli
                    .cert
                    .clone()
                    .ok_or_else(|| anyhow!("--cert is required when enabling TLS"))?;
                let key = cli
                    .key
                    .clone()
                    .ok_or_else(|| anyhow!("--key is required when enabling TLS"))?;
                (Some(tls_addr), Some(cert), Some(key), None)
            }
        } else {
            (None, None, None, None)
        };

        let ech_key_path = match cli.ech_key {
            Some(path) => {
                if !tls_requested {
                    return Err(anyhow!(
                        "--ech-key requires TLS to be enabled (provide --tls-addr with --cert/--key or --cert-dir)"
                    ));
                }
                Some(path)
            }
            None => None,
        };

        let index_file = if cli.index.is_empty() {
            crate::DEFAULT_INDEX.to_string()
        } else {
            cli.index
        };

        // In the `--caddy` flow there is no SITE_TAR; the source Caddyfile path
        // stands in for `tar_path` diagnostics. The in-memory tarball itself is
        // attached by the caller via `caddy_tarball`.
        let tar_path = cli.tarball.or_else(|| cli.caddy.clone()).ok_or_else(|| {
            anyhow!("SITE_TAR is required unless a standalone output mode is used")
        })?;

        Ok(Self {
            http_addr,
            tls_addr,
            tar_path,
            caddy_tarball: None,
            plugin_paths: cli.plugin,
            plugin_dir_paths: cli.plugin_dir,
            cert_path,
            key_path,
            cert_dir_path,
            ech_key_path,
            reload_signal_file: cli.reload_signal_file,
            index_file,
            chunk_size: cli.chunk_size.max(1024),
            try_html: cli.try_html,
            // The `--caddy` flow serves a Caddyfile that can reference absolute
            // host filesystem roots (e.g. `root * /var/www`), so expose-filesystem
            // is always forced on for it (a warning is logged at startup).
            expose_filesystem: cli.expose_filesystem || cli.caddy.is_some(),
            disable_request_logging: cli.disable_request_logging,
            enable_proxy_protocol: cli.enable_proxy_protocol,
            disable_ns_isolation: cli.disable_ns_isolation,
            threads: cli.threads,
            preempt_timer_interval: Duration::from_millis(cli.preempt_timer_interval_ms as u64),
            sqpoll_idle_ms: cli.sqpoll_idle_ms,
            enable_netns_isolation: cli.enable_netns_isolation,
            debug_proxy_protocol_disable_fast_path: cli.debug_proxy_protocol_disable_fast_path,
            max_buffered_body_size: cli.max_buffered_body_size_kb * 1024,
            max_request_external_memory_footprint: (cli.max_request_external_memory_footprint_kb
                * 1024) as u64,
            max_rate_limit_buckets: cli.max_rate_limit_buckets,
            script_code_size_limit,
            ebpf_require_static_region_analysis: cli.ebpf_require_static_region_analysis,
            validate_hostnames: cli.validate_hostnames,
            ebpf_compiler: cli.ebpf_compiler,
            #[cfg(feature = "iroh-proxy")]
            iroh_proxy: cli.iroh_proxy,
            #[cfg(feature = "iroh-proxy")]
            iroh_secret_key: cli.iroh_secret_key,
            #[cfg(feature = "iroh-proxy")]
            iroh_disable_networking: cli.iroh_disable_networking,
        })
    }
}
