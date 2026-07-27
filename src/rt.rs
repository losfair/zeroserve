//! Platform runtime helpers.
//!
//! Linux uses monoio's io_uring driver; other platforms use the legacy
//! (epoll/kqueue) driver.

use std::io;

use monoio::RuntimeBuilder;

#[cfg(target_os = "linux")]
pub type InnerDriver = monoio::IoUringDriver;
#[cfg(not(target_os = "linux"))]
pub type InnerDriver = monoio::LegacyDriver;

/// Runtime with timers enabled (the common case for workers).
pub type Runtime = monoio::Runtime<monoio::time::TimeDriver<InnerDriver>>;

/// Build a monoio runtime with timers enabled.
///
/// `sqpoll_idle_ms` is honored only on Linux (io_uring SQPOLL).
pub fn build_runtime(sqpoll_idle_ms: Option<u32>) -> io::Result<Runtime> {
    #[cfg(target_os = "linux")]
    {
        let mut urb = io_uring::IoUring::builder();
        urb.setup_single_issuer();
        if let Some(ms) = sqpoll_idle_ms {
            urb.setup_sqpoll(ms);
        }
        RuntimeBuilder::<monoio::IoUringDriver>::new()
            .enable_timer()
            .uring_builder(urb)
            .build()
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = sqpoll_idle_ms;
        RuntimeBuilder::<monoio::LegacyDriver>::new()
            .enable_timer()
            .build()
    }
}
