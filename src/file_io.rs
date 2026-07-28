//! Positional file reads that do not block the worker event loop.
//!
//! On Linux, `monoio::fs::File` submits reads through io_uring and is truly
//! asynchronous. On other platforms monoio's legacy (kqueue) driver executes
//! file ops synchronously on the runtime thread — file fds are created with
//! `SharedFd::new_without_register`, so `read_at` degrades to an inline
//! blocking `pread` and a disk wait stalls every connection on that worker.
//! kqueue cannot make regular-file reads asynchronous and OpenBSD has neither
//! io_uring nor POSIX AIO, so the fallback `File` here runs blocking `pread`
//! on the process-global `FILE_TP` thread pool instead, mirroring the subset
//! of the `monoio::fs::File` API used by the serving path.

#[cfg(target_os = "linux")]
pub use monoio::fs::File;

#[cfg(not(target_os = "linux"))]
pub use fallback::File;

#[cfg(not(target_os = "linux"))]
mod fallback {
    use std::{io, os::fd::AsRawFd, path::Path, sync::Arc};

    use futures::channel::oneshot;
    use monoio::buf::IoBufMut;

    use crate::thread_pool::FILE_TP;

    /// Thread-pool-backed positional file handle. Cheap to clone via
    /// `try_clone` + `from_std` like its monoio counterpart; the inner handle
    /// is shared with in-flight pool tasks so the fd stays open while a read
    /// is running even if the request future is dropped.
    pub struct File {
        inner: Arc<std::fs::File>,
    }

    impl File {
        pub fn from_std(file: std::fs::File) -> io::Result<File> {
            Ok(File {
                inner: Arc::new(file),
            })
        }

        pub async fn open(path: impl AsRef<Path>) -> io::Result<File> {
            let path = path.as_ref().to_owned();
            run(move || std::fs::File::open(path))
                .await
                .and_then(Self::from_std)
        }

        pub async fn metadata(&self) -> io::Result<std::fs::Metadata> {
            let file = self.inner.clone();
            run(move || file.metadata()).await
        }

        pub async fn read_at<T: IoBufMut + Send + 'static>(
            &self,
            mut buf: T,
            pos: u64,
        ) -> monoio::BufResult<usize, T> {
            let file = self.inner.clone();
            run(move || {
                let len = buf.bytes_total();
                let res = pread(&file, buf.write_ptr(), len, pos);
                if let Ok(n) = res {
                    unsafe { buf.set_init(n) };
                }
                (res, buf)
            })
            .await
        }

        /// Fill the whole buffer, looping inside a single pool task so a
        /// short read does not pay another cross-thread round trip. Matches
        /// monoio's `read_exact_at`: EOF before the buffer is full is
        /// `UnexpectedEof`.
        pub async fn read_exact_at<T: IoBufMut + Send + 'static>(
            &self,
            mut buf: T,
            pos: u64,
        ) -> monoio::BufResult<(), T> {
            let file = self.inner.clone();
            run(move || {
                let len = buf.bytes_total();
                let ptr = buf.write_ptr();
                let mut read = 0;
                while read < len {
                    match pread(
                        &file,
                        unsafe { ptr.add(read) },
                        len - read,
                        pos + read as u64,
                    ) {
                        Ok(0) => {
                            return (
                                Err(io::Error::new(
                                    io::ErrorKind::UnexpectedEof,
                                    "failed to fill whole buffer",
                                )),
                                buf,
                            );
                        }
                        Ok(n) => read += n,
                        Err(e) => return (Err(e), buf),
                    }
                }
                unsafe { buf.set_init(len) };
                (Ok(()), buf)
            })
            .await
        }
    }

    /// Run `f` on the file pool and await its result. If the awaiting future
    /// is dropped mid-read, the pool task still completes and the buffer is
    /// discarded there — same lifecycle as an abandoned io_uring op.
    async fn run<R, F>(f: F) -> R
    where
        F: FnOnce() -> R + Send + 'static,
        R: Send + 'static,
    {
        let (tx, rx) = oneshot::channel();
        FILE_TP.spawn(move || {
            let _ = tx.send(f());
        });
        rx.await.expect("file I/O pool dropped a task")
    }

    fn pread(file: &std::fs::File, ptr: *mut u8, len: usize, pos: u64) -> io::Result<usize> {
        loop {
            let n = unsafe {
                libc::pread(
                    file.as_raw_fd(),
                    ptr as *mut libc::c_void,
                    len,
                    pos as libc::off_t,
                )
            };
            if n >= 0 {
                return Ok(n as usize);
            }
            let err = io::Error::last_os_error();
            if err.kind() != io::ErrorKind::Interrupted {
                return Err(err);
            }
        }
    }
}
