use std::{
    os::fd::RawFd,
    rc::Rc,
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::{Context, Result};
use futures::{StreamExt, channel::mpsc};

use crate::{script::ScriptRuntime, shared::SharedState, site::Site, tls::load_tls_if_configured};

pub struct SighupBlocked {
    // Used by Linux signalfd creation; on BSD the blocked set is process-wide
    // and the kqueue EVFILT_SIGNAL path does not need the stored mask.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    mask: libc::sigset_t,
}

impl SighupBlocked {
    pub fn new() -> Self {
        let mut mask: libc::sigset_t = unsafe { core::mem::zeroed() };
        unsafe {
            libc::sigemptyset(&mut mask);
            libc::sigaddset(&mut mask, libc::SIGHUP);
            libc::sigprocmask(libc::SIG_BLOCK, &mask, core::ptr::null_mut());
        }
        Self { mask }
    }
}

/// A request handed to a worker telling it to recompile its eBPF programs from a
/// freshly loaded set of sites. The canary worker is given a `reply` channel so
/// the coordinator can wait for its result before committing the reload to the
/// rest of the fleet.
pub struct ReloadRequest {
    pub sites: Vec<Arc<Site>>,
    pub reply: Option<std::sync::mpsc::Sender<Result<(), String>>>,
}

/// How often the coordinator wakes to poll the reload signal file and run the
/// periodic rate-limit cleanup. A SIGHUP wakes it immediately via the platform
/// signal wait fd (signalfd on Linux, kqueue EVFILT_SIGNAL elsewhere).
const COORDINATOR_TICK: Duration = Duration::from_secs(1);
/// How often expired rate-limit buckets are swept from the (shared) current site.
const RATE_LIMIT_CLEANUP_INTERVAL: Duration = Duration::from_secs(60);
/// How long to wait for the canary worker to validate a reload before giving up
/// and aborting it (leaving the previous configuration in place).
const CANARY_RELOAD_TIMEOUT: Duration = Duration::from_secs(30);

/// Spawn the coordinator: a single dedicated OS thread (no event loop) that owns
/// all process-global background duties — reacting to reload triggers and
/// periodically cleaning up rate-limit state.
///
/// A reload is staged, not broadcast: the coordinator loads the new assets from
/// disk once, asks a single canary worker to recompile against them, and only if
/// the canary succeeds does it commit the new shared assets and notify the
/// remaining workers. A canary failure aborts the reload with nothing changed.
pub fn spawn_coordinator(
    shared: Arc<SharedState>,
    worker_txs: Vec<mpsc::UnboundedSender<ReloadRequest>>,
    sighup_blocked: SighupBlocked,
) -> Result<()> {
    let sfd = create_sighup_wait_fd(&sighup_blocked).context("failed to create SIGHUP wait fd")?;

    std::thread::Builder::new()
        .name("coordinator".into())
        .spawn(move || coordinator_loop(shared, worker_txs, sfd))
        .context("failed to spawn coordinator thread")?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn create_sighup_wait_fd(sighup_blocked: &SighupBlocked) -> std::io::Result<RawFd> {
    let sfd = unsafe { libc::signalfd(-1, &sighup_blocked.mask, libc::SFD_CLOEXEC) };
    if sfd < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(sfd)
    }
}

#[cfg(not(target_os = "linux"))]
fn create_sighup_wait_fd(_sighup_blocked: &SighupBlocked) -> std::io::Result<RawFd> {
    // SIGHUP is already blocked process-wide via sigprocmask. On BSD, a kqueue
    // EVFILT_SIGNAL note fires when a (blocked) signal is posted, without
    // installing a handler — the closest equivalent to Linux signalfd. Unlike
    // signalfd it neither reports signals that were already pending when the
    // knote was registered nor dequeues them from the pending set;
    // coordinator_loop sweeps the pending set every tick to cover both.
    let kq = unsafe { libc::kqueue() };
    if kq < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let flags = unsafe { libc::fcntl(kq, libc::F_GETFD) };
    if flags >= 0 {
        let _ = unsafe { libc::fcntl(kq, libc::F_SETFD, flags | libc::FD_CLOEXEC) };
    }
    let mut kev = libc::kevent {
        ident: libc::SIGHUP as _,
        filter: libc::EVFILT_SIGNAL,
        flags: (libc::EV_ADD | libc::EV_CLEAR) as _,
        fflags: 0,
        data: 0,
        udata: std::ptr::null_mut(),
    };
    let ret = unsafe { libc::kevent(kq, &mut kev, 1, std::ptr::null_mut(), 0, std::ptr::null()) };
    if ret < 0 {
        let err = std::io::Error::last_os_error();
        unsafe {
            libc::close(kq);
        }
        return Err(err);
    }
    Ok(kq)
}

#[cfg(target_os = "linux")]
fn drain_sighup_wait_fd(sfd: RawFd) {
    // Drain the signalfd so it doesn't stay readable.
    let mut buf = [0u8; std::mem::size_of::<libc::signalfd_siginfo>()];
    unsafe {
        libc::read(sfd, buf.as_mut_ptr().cast(), buf.len());
    }
}

/// Consume a pending (blocked) SIGHUP, if any, and report whether one was
/// taken. kqueue's EVFILT_SIGNAL only fires for signals posted *after* the
/// knote is registered, so a SIGHUP that arrived between the early process-wide
/// block in main() and coordinator startup (site/TLS loading happens in
/// between) would otherwise be silently lost — Linux signalfd is
/// level-triggered against the pending set and has no such hole. Sweeping every
/// tick also keeps consumed SIGHUPs from sitting in the pending set forever
/// (nothing else ever dequeues them on BSD).
#[cfg(not(target_os = "linux"))]
fn take_pending_sighup() -> bool {
    unsafe {
        let mut pending: libc::sigset_t = core::mem::zeroed();
        if libc::sigpending(&mut pending) != 0 {
            return false;
        }
        if libc::sigismember(&pending, libc::SIGHUP) != 1 {
            return false;
        }
        // SIGHUP is pending and blocked, so sigwait dequeues it and returns
        // immediately.
        let mut set: libc::sigset_t = core::mem::zeroed();
        libc::sigemptyset(&mut set);
        libc::sigaddset(&mut set, libc::SIGHUP);
        let mut sig: libc::c_int = 0;
        libc::sigwait(&set, &mut sig) == 0
    }
}

#[cfg(not(target_os = "linux"))]
fn drain_sighup_wait_fd(kq: RawFd) {
    // Consume the pending EVFILT_SIGNAL event(s).
    let mut events: [libc::kevent; 4] = unsafe { std::mem::zeroed() };
    let ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    unsafe {
        libc::kevent(
            kq,
            std::ptr::null(),
            0,
            events.as_mut_ptr(),
            events.len() as _,
            &ts,
        );
    }
}

fn coordinator_loop(
    shared: Arc<SharedState>,
    mut worker_txs: Vec<mpsc::UnboundedSender<ReloadRequest>>,
    sfd: RawFd,
) -> ! {
    let signal_file = shared.config.reload_signal_file.clone();
    let mut last_file_contents = signal_file.as_ref().and_then(|p| std::fs::read(p).ok());
    let mut last_cleanup = Instant::now();

    loop {
        let mut should_reload = false;

        // Block until SIGHUP arrives on the wait fd or the tick elapses.
        let mut pfd = libc::pollfd {
            fd: sfd,
            events: libc::POLLIN,
            revents: 0,
        };
        let ret = unsafe { libc::poll(&mut pfd, 1, COORDINATOR_TICK.as_millis() as libc::c_int) };
        if ret > 0 && (pfd.revents & libc::POLLIN) != 0 {
            drain_sighup_wait_fd(sfd);
            should_reload = true;
        } else if ret < 0 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() != Some(libc::EINTR) {
                eprintln!("coordinator poll failed: {err:?}");
            }
        }

        // Sweep the pending set: catches a SIGHUP that predates the kqueue
        // registration (invisible to EVFILT_SIGNAL) and dequeues signals the
        // kqueue path never consumes.
        #[cfg(not(target_os = "linux"))]
        if take_pending_sighup() {
            should_reload = true;
        }

        // Poll the reload signal file for content changes.
        if let Some(path) = &signal_file {
            if let Ok(contents) = std::fs::read(path) {
                if last_file_contents.as_ref() != Some(&contents) {
                    last_file_contents = Some(contents);
                    should_reload = true;
                }
            }
        }

        if should_reload {
            if let Err(err) = perform_reload(&shared, &mut worker_txs) {
                eprintln!("reload failed: {err:?}");
            }
        }

        if last_cleanup.elapsed() >= RATE_LIMIT_CLEANUP_INTERVAL {
            shared.site.load().rate_limit_manager.cleanup_expired();
            last_cleanup = Instant::now();
        }
    }
}

/// Load the new assets from disk (once), validate them on the canary worker, and
/// — only on success — commit them to the shared state and roll out to the
/// remaining workers.
fn perform_reload(
    shared: &Arc<SharedState>,
    worker_txs: &mut [mpsc::UnboundedSender<ReloadRequest>],
) -> Result<()> {
    eprintln!("reloading plugin, site, and TLS assets");

    // Filesystem work happens exactly once, here on the coordinator thread.
    let mut plugin_sites =
        Vec::with_capacity(shared.config.plugin_paths.len() + shared.config.plugin_dir_paths.len());
    for plugin_path in &shared.config.plugin_paths {
        plugin_sites.push(Arc::new(
            Site::load_path(
                plugin_path,
                shared.config.max_rate_limit_buckets,
                shared.config.ebpf_compiler,
            )
            .with_context(|| format!("failed to reload plugin {}", plugin_path.display()))?,
        ));
    }
    for plugin_dir in &shared.config.plugin_dir_paths {
        plugin_sites.push(Arc::new(
            Site::load_directory(
                plugin_dir,
                shared.config.max_rate_limit_buckets,
                shared.config.ebpf_compiler,
            )
            .with_context(|| {
                format!("failed to reload plugin directory {}", plugin_dir.display())
            })?,
        ));
    }
    let site = Arc::new(
        crate::caddy_run::reload_site(&shared.config).with_context(|| "failed to reload site")?,
    );
    // Rebuild the TLS runtime against the *existing* ACME certificate registry
    // so already-issued certificates keep being served across the reload.
    let acme_certs = shared.acme.as_ref().map(|a| a.certs());
    let tls_result = load_tls_if_configured(&shared.config, acme_certs);

    // The ordered sites every worker compiles: plugins first, then the main site.
    let sites: Vec<Arc<Site>> = plugin_sites
        .iter()
        .cloned()
        .chain(std::iter::once(site.clone()))
        .collect();

    let Some((canary_tx, rest)) = worker_txs.split_first_mut() else {
        // No workers to notify (shouldn't happen: thread count is >= 1).
        return Ok(());
    };

    // Stage 1: validate the new assets on the canary worker and wait for it.
    let (reply_tx, reply_rx) = std::sync::mpsc::channel();
    let canary_req = ReloadRequest {
        sites: sites.clone(),
        reply: Some(reply_tx),
    };
    if canary_tx.unbounded_send(canary_req).is_err() {
        eprintln!("canary worker is gone; aborting reload");
        return Ok(());
    }
    match reply_rx.recv_timeout(CANARY_RELOAD_TIMEOUT) {
        Ok(Ok(())) => {}
        Ok(Err(err)) => {
            eprintln!("canary reload failed, aborting (previous config kept): {err}");
            return Ok(());
        }
        Err(err) => {
            eprintln!("canary reload did not complete in time, aborting: {err}");
            return Ok(());
        }
    }

    // Stage 2: canary succeeded — commit the shared assets, then notify the rest.
    shared.plugin_sites.store(Arc::new(plugin_sites));
    shared.site.store(site);
    shared.file_logger.invalidate();
    match tls_result {
        Ok(runtime_opt) => {
            let tls_present = runtime_opt.is_some();
            shared.tls.store(runtime_opt.map(Arc::new));
            if tls_present {
                eprintln!("reloaded TLS configuration");
            }
        }
        Err(err) => eprintln!("TLS reload failed (keeping previous TLS): {err:?}"),
    }

    for tx in rest.iter_mut() {
        let _ = tx.unbounded_send(ReloadRequest {
            sites: sites.clone(),
            reply: None,
        });
    }

    if shared.config.caddy_tarball.is_some() {
        eprintln!(
            "rebuilt caddy site from {}",
            shared.config.tar_path.display()
        );
    } else {
        eprintln!("reloaded tarball {}", shared.config.tar_path.display());
    }
    for plugin_path in &shared.config.plugin_paths {
        eprintln!("reloaded plugin {}", plugin_path.display());
    }
    for plugin_dir in &shared.config.plugin_dir_paths {
        eprintln!("reloaded plugin directory {}", plugin_dir.display());
    }
    eprintln!("canary validated; rolled out to all workers");
    Ok(())
}

/// Per-worker reload loop. Awaits reload requests from the coordinator and
/// recompiles this thread's eBPF programs from the sites carried in the request,
/// installing them into this worker's `ScriptRuntime`. Programs are pinned to
/// the current thread, so each worker compiles independently. If the request is
/// the canary's, the outcome is reported back so the coordinator can decide
/// whether to roll the reload out to the rest of the fleet.
pub async fn worker_reload_loop(
    script_runtime: Rc<ScriptRuntime>,
    mut reload_rx: mpsc::UnboundedReceiver<ReloadRequest>,
) {
    while let Some(req) = reload_rx.next().await {
        let result = match script_runtime.load_scripts_from_sites(&req.sites).await {
            Ok(scripts) => {
                script_runtime.install_scripts(scripts);
                Ok(())
            }
            Err(err) => {
                eprintln!("worker reload: script recompilation failed: {err:?}");
                Err(format!("{err:?}"))
            }
        };
        if let Some(reply) = req.reply {
            let _ = reply.send(result);
        }
    }
}
