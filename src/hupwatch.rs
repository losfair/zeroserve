use std::{
    collections::HashMap,
    os::fd::RawFd,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

#[cfg(target_os = "linux")]
use std::{io::ErrorKind, os::fd::FromRawFd};

use futures::{StreamExt, channel::mpsc};
#[cfg(target_os = "linux")]
use monoio::net::UnixStream;
use parking_lot::Mutex;

/// A hook registration. The generation token ties the hook to one specific
/// `wait()` call so that an event harvested for a closed fd can never fire the
/// hook of a newer connection that recycled the same fd number.
struct Hook {
    generation: usize,
    tx: mpsc::Sender<()>,
}

pub struct HupWatcher {
    /// Platform watch fd: epoll on Linux, kqueue on BSD.
    watch_fd: RawFd,
    hooks: Mutex<HashMap<RawFd, Hook>>,
    next_generation: AtomicUsize,
}

impl HupWatcher {
    pub fn new() -> Arc<Self> {
        #[cfg(target_os = "linux")]
        {
            let efd = unsafe { create_watch_fd() };
            if efd < 0 {
                panic!("hupwatch create: {:?}", std::io::Error::last_os_error());
            }
            let efile = &*Box::leak(Box::new(unsafe {
                UnixStream::from_std(std::os::unix::net::UnixStream::from_raw_fd(efd)).unwrap()
            }));
            let me = Arc::new(Self {
                watch_fd: efd,
                hooks: Mutex::new(HashMap::new()),
                next_generation: AtomicUsize::new(0),
            });
            monoio::spawn(watcher_epoll(efile, me.clone()));
            me
        }

        #[cfg(not(target_os = "linux"))]
        {
            // The kqueue cannot be polled from the runtime itself (registering
            // a kqueue fd with monoio/mio's RW interest returns EINVAL), so a
            // dedicated thread blocks on kevent and completes hooks directly:
            // futures-mpsc senders are Send, and waking a monoio task from a
            // foreign thread is supported (the reload coordinator relies on
            // the same property).
            let kq = unsafe { create_watch_fd() };
            if kq < 0 {
                panic!("hupwatch create: {:?}", std::io::Error::last_os_error());
            }
            let me = Arc::new(Self {
                watch_fd: kq,
                hooks: Mutex::new(HashMap::new()),
                next_generation: AtomicUsize::new(0),
            });
            {
                let me = me.clone();
                std::thread::Builder::new()
                    .name("hupwatch".into())
                    .spawn(move || unsafe { kqueue_thread(me) })
                    .expect("spawn hupwatch thread");
            }
            me
        }
    }

    pub fn wait(
        self: &Arc<Self>,
        fd: RawFd,
    ) -> std::io::Result<impl Future<Output = ()> + Unpin + 'static> {
        let (tx, rx) = mpsc::channel(1);
        let generation = self.next_generation.fetch_add(1, Ordering::Relaxed);
        unsafe {
            self.hooks.lock().insert(fd, Hook { generation, tx });
            if let Err(err) = register_hup(self.watch_fd, fd, generation) {
                remove_hook_if_generation(self, fd, generation);
                return Err(err);
            }
        }

        struct G(Arc<HupWatcher>, RawFd, usize, mpsc::Receiver<()>);
        impl Drop for G {
            fn drop(&mut self) {
                remove_hook_if_generation(&self.0, self.1, self.2);
            }
        }
        let mut g = G(self.clone(), fd, generation, rx);

        Ok(Box::pin(async move {
            let _ = g.3.next().await;
        }))
    }
}

/// Remove the hook for `fd` only if it still belongs to `generation` — a later
/// `wait()` on a recycled fd number must not lose its own hook.
fn remove_hook_if_generation(w: &HupWatcher, fd: RawFd, generation: usize) {
    let mut hooks = w.hooks.lock();
    if hooks.get(&fd).is_some_and(|h| h.generation == generation) {
        hooks.remove(&fd);
    }
}

#[cfg(target_os = "linux")]
async fn watcher_epoll(efile: &UnixStream, w: Arc<HupWatcher>) -> ! {
    const MAX_EVENTS: usize = 10;

    let mut events: [libc::epoll_event; MAX_EVENTS] = unsafe { core::mem::zeroed() };
    loop {
        efile.readable(false).await.expect("hupwatch: efd wait");
        let nfds = unsafe { libc::epoll_wait(w.watch_fd, events.as_mut_ptr(), MAX_EVENTS as _, 0) };
        if nfds < 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() == ErrorKind::Interrupted {
                continue;
            }
            panic!("hupwatch: epoll_wait: {:?}", err);
        }
        for i in 0..nfds {
            let fd = events[i as usize].u64 as RawFd;
            let hook = w.hooks.lock().remove(&fd);
            if let Some(mut hook) = hook {
                let _ = hook.tx.try_send(());
            }
        }
    }
}

#[cfg(not(target_os = "linux"))]
unsafe fn kqueue_thread(w: Arc<HupWatcher>) -> ! {
    const MAX_EVENTS: usize = 32;
    let mut events: [libc::kevent; MAX_EVENTS] = unsafe { std::mem::zeroed() };
    loop {
        let nfds = unsafe {
            libc::kevent(
                w.watch_fd,
                std::ptr::null(),
                0,
                events.as_mut_ptr(),
                MAX_EVENTS as _,
                std::ptr::null(), // block indefinitely
            )
        };
        if nfds < 0 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            // panic=abort in release: takes the process down rather than
            // leaving hangup detection silently dead.
            panic!("hupwatch kevent: {err:?}");
        }
        for i in 0..nfds {
            let ev = &events[i as usize];
            // Mirror Linux EPOLLHUP/EPOLLRDHUP: only peer hangup / error.
            // Ordinary readability (on kernels that ignore NOTE_LOWAT) is
            // skipped WITHOUT disarming — the registration is EV_CLEAR, not
            // one-shot, so a later real hangup still fires.
            let flags = ev.flags as i16;
            if flags & (libc::EV_EOF as i16 | libc::EV_ERROR as i16) == 0 {
                continue;
            }
            let fd = ev.ident as RawFd;
            let generation = ev.udata as usize;
            let hook = {
                let mut hooks = w.hooks.lock();
                // The generation check drops events harvested for an fd that
                // was closed and recycled before this thread got to them.
                if hooks.get(&fd).is_some_and(|h| h.generation == generation) {
                    hooks.remove(&fd)
                } else {
                    None
                }
            };
            if let Some(mut hook) = hook {
                let _ = hook.tx.try_send(());
            }
        }
    }
}

#[cfg(target_os = "linux")]
unsafe fn create_watch_fd() -> RawFd {
    unsafe { libc::epoll_create1(libc::EPOLL_CLOEXEC) }
}

#[cfg(target_os = "linux")]
unsafe fn register_hup(efd: RawFd, fd: RawFd, _generation: usize) -> std::io::Result<()> {
    let mut ev = libc::epoll_event {
        events: (libc::EPOLLHUP | libc::EPOLLRDHUP | libc::EPOLLET | libc::EPOLLONESHOT) as _,
        u64: fd as _,
    };
    let mut ret = unsafe { libc::epoll_ctl(efd, libc::EPOLL_CTL_ADD, fd, &mut ev) };
    if ret < 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::EEXIST) {
        // The fd is still in the interest list from an earlier one-shot
        // registration that was abandoned without firing (e.g. a proxy
        // connection taken from the pool and later pooled again); re-arm it.
        ret = unsafe { libc::epoll_ctl(efd, libc::EPOLL_CTL_MOD, fd, &mut ev) };
    }
    if ret < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(not(target_os = "linux"))]
unsafe fn create_watch_fd() -> RawFd {
    let kq = unsafe { libc::kqueue() };
    if kq >= 0 {
        let flags = unsafe { libc::fcntl(kq, libc::F_GETFD) };
        if flags >= 0 {
            let _ = unsafe { libc::fcntl(kq, libc::F_SETFD, flags | libc::FD_CLOEXEC) };
        }
    }
    kq
}

#[cfg(not(target_os = "linux"))]
unsafe fn register_hup(kq: RawFd, fd: RawFd, generation: usize) -> std::io::Result<()> {
    // Watch for read-side EOF / hangup on the connection fd.
    //
    // kqueue has no hangup-only read filter, so the registration must not be
    // one-shot: EV_ONESHOT deletes the knote when the event is delivered to
    // userspace regardless of what userspace does with it, so ordinary request
    // data (no EV_EOF) would permanently disarm hangup detection. EV_CLEAR
    // keeps the knote armed edge-triggered instead. NOTE_LOWAT with an
    // unreachably high watermark suppresses wakeups for ordinary data on
    // kernels that honor it; the EOF/error condition bypasses the watermark.
    //
    // The generation rides in udata so the harvesting thread can tell this
    // registration apart from an older one on a recycled fd number (EV_ADD on
    // an existing ident/filter pair updates the knote in place).
    let mut kev = libc::kevent {
        ident: fd as _,
        filter: libc::EVFILT_READ,
        flags: (libc::EV_ADD | libc::EV_CLEAR) as _,
        fflags: libc::NOTE_LOWAT as _,
        data: i32::MAX as _,
        udata: generation as _,
    };
    let ret = unsafe { libc::kevent(kq, &mut kev, 1, std::ptr::null_mut(), 0, std::ptr::null()) };
    if ret < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}
