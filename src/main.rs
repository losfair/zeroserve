mod acme;
mod boringtls;
mod bpf_compiler;
mod caddy_compile;
mod caddy_file;
mod caddy_run;
mod caddyfile;
mod cli;
mod config;
mod ech;
mod helpers;
mod http;
mod hupwatch;
mod ja4;
mod json;
mod logging;
mod oidc;
mod pack;
mod pool;
mod ratelimit;
mod reload;
mod script;
mod script_compile;
mod server;
mod shared;
mod site;
mod thread_pool;
mod tinycc;
mod tls;

use std::io::Write;
use std::net::TcpListener;
use std::os::fd::FromRawFd;
use std::rc::Rc;
use std::sync::{Arc, mpsc as std_mpsc};

use crate::cli::ListenAddr;

use anyhow::{Context, Result};
use clap::Parser;
use futures::channel::mpsc;
use monoio::{IoUringDriver, RuntimeBuilder};
use nix::mount::MsFlags;
use socket2::{Domain, Protocol, Socket, Type};

use crate::reload::SighupBlocked;
use crate::{
    cli::Cli,
    config::StaticConfig,
    hupwatch::HupWatcher,
    logging::spawn_file_logger,
    pack::USER_MANUAL,
    reload::{ReloadRequest, spawn_coordinator, worker_reload_loop},
    script::{ScriptRuntime, ScriptRuntimeConfig},
    script_compile::ZEROSERVE_H,
    server::amain,
    shared::SharedState,
    site::Site,
    tls::load_tls_if_configured,
};

pub const SERVER_HEADER: &str = "zeroserve";
pub const DEFAULT_INDEX: &str = "index.html";

/// Decides whether `source` is a Caddy JSON config (vs a native Caddyfile).
/// A filename hint takes precedence; otherwise we rely on the fact that a Caddy
/// JSON config always parses as a JSON object whereas a Caddyfile never does
/// (e.g. `{ http_port 80 }` is not valid JSON).
pub(crate) fn is_caddy_json(source: &str, path: &std::path::Path) -> bool {
    let name = path
        .file_name()
        .map(|s| s.to_string_lossy().to_lowercase())
        .unwrap_or_default();
    if name == "caddyfile" || name.ends_with(".caddyfile") || name.ends_with(".caddy") {
        return false;
    }
    if name.ends_with(".json") {
        return true;
    }
    serde_json::from_str::<serde_json::Value>(source)
        .map(|v| v.is_object())
        .unwrap_or(false)
}

fn main() -> Result<()> {
    let args = Cli::parse();
    if args.dump_sdk {
        let mut out = std::io::stdout().lock();
        out.write_all(ZEROSERVE_H)?;
        out.flush()?;
        return Ok(());
    }
    if args.manual {
        let mut out = std::io::stdout().lock();
        out.write_all(USER_MANUAL.as_bytes())?;
        out.flush()?;
        return Ok(());
    }
    if let Some(caddyfile_path) = args.adapt_caddyfile.as_ref() {
        let source = std::fs::read_to_string(caddyfile_path)
            .with_context(|| format!("failed to read {}", caddyfile_path.display()))?;
        let name = caddyfile_path.to_string_lossy();
        let (json, warnings) = caddyfile::adapt_to_string(&source, &name)
            .with_context(|| format!("failed to adapt {}", caddyfile_path.display()))?;
        for warning in &warnings {
            eprintln!("warning: {warning}");
        }
        let mut out = std::io::stdout().lock();
        out.write_all(json.as_bytes())?;
        out.write_all(b"\n")?;
        out.flush()?;
        return Ok(());
    }
    if let Some(config_path) = args.caddy_compile.as_ref() {
        let source = std::fs::read_to_string(config_path)
            .with_context(|| format!("failed to read {}", config_path.display()))?;
        // Auto-detect: a Caddy JSON config parses as a JSON object; a native
        // Caddyfile does not. Adapt the Caddyfile to JSON first, then compile.
        let json_source = if is_caddy_json(&source, config_path) {
            source
        } else {
            let name = config_path.to_string_lossy();
            let (json, warnings) = caddyfile::adapt_to_string(&source, &name)
                .with_context(|| format!("failed to adapt {}", config_path.display()))?;
            for warning in &warnings {
                eprintln!("warning: {warning}");
            }
            json
        };
        let (generated, warnings) = caddy_compile::compile_caddy_json_collecting(&json_source)
            .with_context(|| format!("failed to compile {}", config_path.display()))?;
        for warning in &warnings {
            eprintln!("warning: {warning}");
        }
        let mut out = std::io::stdout().lock();
        out.write_all(generated.as_bytes())?;
        out.flush()?;
        return Ok(());
    }
    if args.gen_ech_key {
        let public_name = args
            .ech_public_name
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("--gen-ech-key requires --ech-public-name"))?;
        ech::keygen::run(public_name)?;
        return Ok(());
    }
    if let Some(pack_root) = args.pack.as_ref() {
        pack::pack_site(pack_root, args.ebpf_compiler)?;
        return Ok(());
    }
    // The `--caddy` flow builds the entire site up front, while a writable
    // filesystem is still available for the compiler output scratch file
    // (before namespace isolation).
    let caddy_tarball = match args.caddy.as_ref() {
        Some(path) => {
            eprintln!(
                "warning: --caddy forces expose-filesystem on; generated middleware \
                 may read absolute host filesystem roots referenced by the Caddyfile"
            );
            let bytes = caddy_run::build_caddy_tarball(path, args.ebpf_compiler)
                .with_context(|| format!("failed to build site from {}", path.display()))?;
            eprintln!(
                "built in-memory caddy site from {} ({} bytes)",
                path.display(),
                bytes.len()
            );
            Some(Arc::new(bytes))
        }
        None => None,
    };
    let mut config = StaticConfig::try_from(args)?;
    config.caddy_tarball = caddy_tarball;
    let config = Arc::new(config);

    let fdlimit =
        rlimit::increase_nofile_limit(1048576).with_context(|| "failed to raise fd limit")?;
    eprintln!("fd limit {}", fdlimit);

    let threads = config.threads;

    // One listener per worker. This must happen before namespace isolation and
    // capability dropping so sockets bind in the caller's network namespace and
    // privileged ports remain possible.
    let http_listeners = create_worker_listeners(&config.http_addr, threads)
        .with_context(|| format!("failed to create HTTP listeners for {}", config.http_addr))?;
    let tls_listeners: Vec<Option<TcpListener>> = match &config.tls_addr {
        Some(addr) => create_worker_listeners(addr, threads)
            .with_context(|| format!("failed to create TLS listeners for {}", addr))?
            .into_iter()
            .map(Some)
            .collect(),
        None => (0..threads).map(|_| None).collect(),
    };

    // Build the reverse-proxy TLS client now, before namespace isolation turns
    // /etc into an empty tmpfs — the CA bundle must be read while it's still on
    // disk. Best-effort: HTTP proxying and serving still work without it; only
    // HTTPS upstreams would fail.
    match boringtls::init_client_from_system_roots() {
        Ok(()) => {}
        Err(err) => eprintln!("warning: {err}"),
    }

    if !config.disable_ns_isolation {
        setup_ns_isolation(&config).with_context(
            || "failed to set up namespace isolation (set --disable-ns-isolation to disable)",
        )?;

        let resolv_conf = std::fs::read("/etc/resolv.conf").ok();

        nix::mount::mount(
            None::<&str>,
            "/etc",
            Some("tmpfs"),
            MsFlags::empty(),
            None::<&str>,
        )
        .with_context(|| "failed to mount virtual /etc")?;

        if let Some(x) = &resolv_conf {
            std::fs::write("/etc/resolv.conf", x)
                .with_context(|| "failed to write /etc/resolv.conf in tmpfs")?;
        }

        drop_all_capabilities().with_context(|| "failed to drop capabilities")?;

        if let Err(err) = rlimit::Resource::NPROC.set(1024, 1024) {
            eprintln!("failed to restrict nproc: {:?}", err);
        }

        eprintln!(
            "isolation: ns_user=y, ns_net={}, ns_mount=y; caps, nproc",
            if config.enable_netns_isolation {
                "y"
            } else {
                "n"
            }
        );
    }

    // Block SIGHUP early before spawning any threads
    let sighup_blocked = SighupBlocked::new();

    let plugin_sites = load_plugin_sites(&config)?;
    let site = Arc::new(caddy_run::load_site(&config)?);
    let site_origin = if config.caddy_tarball.is_some() {
        format!("in-memory caddy site ({})", config.tar_path.display())
    } else {
        config.tar_path.display().to_string()
    };
    eprintln!(
        "loaded {} entries from {} ({} bytes)",
        site.total_entries, site_origin, site.total_bytes
    );

    // When `--acme-dir` is set, create the ACME runtime first so its shared
    // certificate registry can be wired into the TLS acceptor (TLS-ALPN-01
    // challenges and per-SNI live certificates are resolved through it).
    let acme_runtime = config.acme_dir.as_ref().map(|dir| {
        // Hostnames already covered by `--cert-dir` are served from there and
        // excluded from ACME provisioning.
        let cert_dir_names = config
            .cert_dir_path
            .as_deref()
            .map(tls::cert_dir_dns_names)
            .unwrap_or_default();
        acme::AcmeRuntime::new(dir.clone(), cert_dir_names)
    });
    let acme_certs = acme_runtime.as_ref().map(|a| a.certs());

    let tls_runtime = load_tls_if_configured(&config, acme_certs)?;
    if tls_runtime.is_some() {
        eprintln!("TLS enabled");
    }
    if acme_runtime.is_some() {
        eprintln!("ACME enabled (TLS-ALPN-01)");
    }

    eprintln!(
        "async preemption timer interval: {:?}",
        config.preempt_timer_interval
    );

    let file_logger = spawn_file_logger().with_context(|| "failed to spawn file logger")?;
    let shared = Arc::new(SharedState::new(
        config.clone(),
        site,
        plugin_sites,
        tls_runtime,
        acme_runtime,
        file_logger,
    ));

    // One reload channel per worker. The coordinator stages reloads on these:
    // the first worker acts as the canary, the rest are notified only after it
    // succeeds.
    #[allow(clippy::type_complexity)]
    let (reload_txs, reload_rxs): (
        Vec<mpsc::UnboundedSender<ReloadRequest>>,
        Vec<mpsc::UnboundedReceiver<ReloadRequest>>,
    ) = (0..threads).map(|_| mpsc::unbounded()).unzip();

    // The coordinator owns reload + rate-limit cleanup on its own thread.
    spawn_coordinator(shared.clone(), reload_txs, sighup_blocked)?;

    // Report the kernel-resolved addresses so `--addr 127.0.0.1:0` callers
    // (e.g. the e2e suite) can learn the actual port from this line.
    let http_local = http_listeners[0]
        .local_addr()
        .with_context(|| "failed to resolve bound HTTP listener address")?;
    eprintln!(
        "listening on http://{} ({} worker thread(s))",
        http_local, threads
    );
    if config.tls_addr.is_some() {
        let tls_local = tls_listeners[0]
            .as_ref()
            .expect("tls_addr implies TLS listeners")
            .local_addr()
            .with_context(|| "failed to resolve bound TLS listener address")?;
        eprintln!("listening on https://{}", tls_local);
    }

    let mut handles = Vec::with_capacity(threads);
    let (startup_tx, startup_rx) = std_mpsc::channel();
    for (i, ((http_listener, tls_listener), reload_rx)) in http_listeners
        .into_iter()
        .zip(tls_listeners)
        .zip(reload_rxs)
        .enumerate()
    {
        let shared = shared.clone();
        let config = config.clone();
        let startup_tx = startup_tx.clone();
        let handle = std::thread::Builder::new()
            .name(format!("worker-{i}"))
            .spawn(move || {
                if let Err(err) = run_worker(
                    i,
                    config,
                    shared,
                    http_listener,
                    tls_listener,
                    reload_rx,
                    startup_tx,
                ) {
                    eprintln!("worker {i} exited with error: {err:?}");
                }
            })
            .with_context(|| format!("failed to spawn worker thread {i}"))?;
        handles.push(handle);
    }
    drop(startup_tx);

    for _ in 0..threads {
        let (i, result) = startup_rx
            .recv()
            .with_context(|| "worker startup channel closed before all workers initialized")?;
        if let Err(err) = result {
            return Err(anyhow::anyhow!("worker {i} failed to start: {err}"));
        }
    }

    for handle in handles {
        let _ = handle.join();
    }
    Ok(())
}

/// Run a single worker: build a dedicated monoio runtime, create this thread's
/// own eBPF `ScriptRuntime`, compile its scripts, and serve its listeners. Each
/// worker is fully isolated — programs are pinned to this thread and never
/// shared.
fn run_worker(
    worker_id: usize,
    config: Arc<StaticConfig>,
    shared: Arc<SharedState>,
    http_listener: TcpListener,
    tls_listener: Option<TcpListener>,
    reload_rx: mpsc::UnboundedReceiver<ReloadRequest>,
    startup_tx: std_mpsc::Sender<(usize, Result<(), String>)>,
) -> Result<()> {
    let mut urb = io_uring::IoUring::builder();
    urb.setup_single_issuer();
    if let Some(ms) = config.sqpoll_idle_ms {
        urb.setup_sqpoll(ms);
    }

    RuntimeBuilder::<IoUringDriver>::new()
        .enable_timer()
        .uring_builder(urb)
        .build()
        .expect("zeroserve: failed to build io_uring runtime")
        .block_on(async move {
            // SAFETY: GlobalEnv::new() is idempotent (Once-guarded) and
            // init_thread() sets up this thread's preemption watcher; both are
            // safe to call once per worker thread.
            let script_runtime = unsafe {
                ScriptRuntime::new(ScriptRuntimeConfig {
                    preempt_timer_interval: config.preempt_timer_interval,
                    max_memory_footprint: config.max_request_external_memory_footprint,
                    expose_filesystem: config.expose_filesystem,
                    code_size_limit: config.script_code_size_limit,
                    require_static_region_analysis: config.ebpf_require_static_region_analysis,
                })
            };
            let script_runtime = Rc::new(script_runtime);

            // Per-worker hangup watcher (spawns its task on this runtime).
            let hup = HupWatcher::new();
            pool::install_hup_watcher(hup.clone());

            let sites = shared.collect_sites();
            let scripts = match script_runtime.load_scripts_from_sites(&sites).await {
                Ok(scripts) => scripts,
                Err(err) => {
                    let err = err.context("failed to load scripts");
                    let _ = startup_tx.send((worker_id, Err(format!("{err:?}"))));
                    return Err(err);
                }
            };
            script_runtime.install_scripts(scripts);
            let _ = startup_tx.send((worker_id, Ok(())));

            // ACME provisioning is process-wide: run it once, on worker 0. Read
            // the domain set from the site's `zeroserve.init.acme_config`
            // section and spawn the provisioning/renewal task.
            if worker_id == 0 {
                if let Some(acme) = shared.acme.clone() {
                    let site = shared.site.load_full();
                    match script_runtime.run_init_section(site, "acme_config").await {
                        Ok(entries) => match acme::AcmeConfig::merge(&entries) {
                            Ok(Some(cfg)) => {
                                eprintln!("acme: managing {} domain(s)", cfg.domains.len());
                                monoio::spawn(acme.run(cfg));
                            }
                            Ok(None) => eprintln!(
                                "acme: acme_config requested no domains; nothing to provision"
                            ),
                            Err(err) => eprintln!("acme: invalid acme_config: {err:#}"),
                        },
                        Err(err) => {
                            eprintln!("acme: running acme_config init section failed: {err:#}")
                        }
                    }
                }
            }

            monoio::spawn(worker_reload_loop(script_runtime.clone(), reload_rx));

            amain(shared, script_runtime, hup, http_listener, tls_listener).await
        })
}

fn load_plugin_sites(config: &StaticConfig) -> Result<Vec<Arc<Site>>> {
    let mut sites = Vec::with_capacity(config.plugin_paths.len() + config.plugin_dir_paths.len());
    for plugin_path in &config.plugin_paths {
        let site = Arc::new(Site::load_path(
            plugin_path,
            config.max_rate_limit_buckets,
            config.ebpf_compiler,
        )?);
        eprintln!(
            "loaded {} entries from plugin {} ({} bytes)",
            site.total_entries,
            plugin_path.display(),
            site.total_bytes
        );
        sites.push(site);
    }
    for plugin_dir in &config.plugin_dir_paths {
        let site = Arc::new(Site::load_directory(
            plugin_dir,
            config.max_rate_limit_buckets,
            config.ebpf_compiler,
        )?);
        eprintln!(
            "loaded {} entries from plugin directory {} ({} bytes)",
            site.total_entries,
            plugin_dir.display(),
            site.total_bytes
        );
        sites.push(site);
    }
    Ok(sites)
}

fn setup_ns_isolation(config: &StaticConfig) -> anyhow::Result<()> {
    unsafe {
        let uid = libc::getuid();
        let gid = libc::getgid();

        let mut flags = libc::CLONE_NEWUSER | libc::CLONE_NEWNS;
        if config.enable_netns_isolation {
            flags |= libc::CLONE_NEWNET;
        }

        if libc::unshare(flags) != 0 {
            return Err(anyhow::Error::from(std::io::Error::last_os_error()).context("unshare"));
        }
        std::fs::write("/proc/self/uid_map", format!("0 {} 1\n", uid))
            .with_context(|| "write uid_map")?;
        std::fs::write("/proc/self/setgroups", "deny\n").with_context(|| "write setgroups")?;
        std::fs::write("/proc/self/gid_map", format!("0 {} 1\n", gid))
            .with_context(|| "write gid_map")?;
    }
    Ok(())
}

/// Create one listener per worker thread for the given address.
///
/// For a bound socket address, each worker gets its own `SO_REUSEPORT` socket so
/// the kernel hash-balances incoming connections across the workers. For an
/// inherited file descriptor (e.g. systemd socket activation) the single socket
/// cannot be re-bound, so each worker receives its own `dup`'d descriptor and
/// the kernel hands each accepted connection to exactly one worker.
fn create_worker_listeners(addr: &ListenAddr, count: usize) -> Result<Vec<TcpListener>> {
    match addr {
        ListenAddr::Socket(socket_addr) => {
            let mut listeners = Vec::with_capacity(count);
            for _ in 0..count {
                let socket = Socket::new(
                    Domain::for_address(*socket_addr),
                    Type::STREAM,
                    Some(Protocol::TCP),
                )?;
                socket.set_reuse_address(true)?;
                socket.set_reuse_port(true)?;
                socket.set_nonblocking(true)?;
                socket.bind(&(*socket_addr).into())?;
                socket.listen(1024)?;
                listeners.push(socket.into());
            }
            Ok(listeners)
        }
        ListenAddr::Fd(fd) => {
            let mut listeners = Vec::with_capacity(count);
            for _ in 0..count {
                // SAFETY: the caller guarantees `fd` is a valid listening socket
                // (socket activation). dup gives each worker an independent
                // descriptor referencing the same underlying socket.
                let duped = unsafe { libc::dup(*fd) };
                if duped < 0 {
                    return Err(std::io::Error::last_os_error())
                        .with_context(|| format!("failed to dup inherited fd {fd}"));
                }
                let listener = unsafe { TcpListener::from_raw_fd(duped) };
                listener.set_nonblocking(true)?;
                listeners.push(listener);
            }
            Ok(listeners)
        }
    }
}

pub fn drop_all_capabilities() -> Result<(), caps::errors::CapsError> {
    use caps::CapSet;

    // Order matters: clear Bounding/Ambient first while we may still have CAP_SETPCAP.
    caps::clear(None, CapSet::Bounding)?;
    caps::clear(None, CapSet::Ambient)?;

    // Then clear the traditional POSIX sets.
    caps::clear(None, CapSet::Inheritable)?;
    caps::clear(None, CapSet::Permitted)?;
    caps::clear(None, CapSet::Effective)?;

    Ok(())
}
