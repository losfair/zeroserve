use std::{collections::HashMap, path::PathBuf, sync::mpsc};

#[cfg(not(target_os = "linux"))]
use std::{collections::hash_map::Entry, io::Write};

use monoio::buf::IoBuf;

/// Write a line to stderr from a worker task.
///
/// On Linux this submits an io_uring write against a thread-local stderr fd so
/// the worker never blocks on a slow/full pipe. Elsewhere the line is handed to
/// a dedicated stderr writer thread (like the file logger below): a blocking
/// `write(2)` on the worker would freeze the whole single-threaded event loop
/// whenever the stderr consumer stalls and the pipe fills, and monoio's
/// `write_all_at(…, 0)` is pwrite-based — the wrong primitive for non-seekable
/// fds on BSD.
pub async fn async_log(msg: impl IoBuf) {
    #[cfg(target_os = "linux")]
    {
        use std::{os::fd::AsFd, rc::Rc};

        use monoio::fs::File;

        thread_local! {
            static STDERR: Rc<File> = Rc::new(File::from_std(
                std::fs::File::from(
                    std::io::stderr().as_fd().try_clone_to_owned()
                        .expect("failed to clone stderr")
                )).unwrap());
        }
        let stderr = STDERR.with(|x| x.clone());
        // Offset is ignored for pipes/ttys under Linux io_uring/pwrite; this is
        // the historical zeroserve path and keeps logging off the worker's
        // critical path.
        let _ = stderr.write_all_at(msg, 0).await;
    }

    #[cfg(not(target_os = "linux"))]
    {
        use std::sync::{OnceLock, mpsc::SyncSender};

        static STDERR_TX: OnceLock<SyncSender<Vec<u8>>> = OnceLock::new();
        let tx = STDERR_TX.get_or_init(|| {
            let (tx, rx) = std::sync::mpsc::sync_channel::<Vec<u8>>(4096);
            std::thread::Builder::new()
                .name("stderr-logger".into())
                .spawn(move || {
                    let mut stderr = std::io::stderr();
                    while let Ok(msg) = rx.recv() {
                        let _ = stderr.write_all(&msg);
                    }
                })
                .expect("failed to spawn stderr logger thread");
            tx
        });

        let ptr = msg.read_ptr();
        let len = msg.bytes_init();
        if len == 0 {
            return;
        }
        let bytes = unsafe { std::slice::from_raw_parts(ptr, len) }.to_vec();
        // Bounded channel + try_send: if the stderr sink is wedged the line is
        // dropped instead of stalling the worker's event loop.
        let _ = tx.try_send(bytes);
    }
}

#[derive(Clone)]
pub struct FileLogSender {
    tx: mpsc::Sender<FileLogCommand>,
}

enum FileLogCommand {
    Write { path: PathBuf, msg: Vec<u8> },
    Invalidate,
}

impl FileLogSender {
    pub fn write(&self, path: PathBuf, msg: Vec<u8>) {
        let _ = self.tx.send(FileLogCommand::Write { path, msg });
    }

    pub fn invalidate(&self) {
        let _ = self.tx.send(FileLogCommand::Invalidate);
    }
}

pub fn spawn_file_logger() -> std::io::Result<FileLogSender> {
    let (tx, rx) = mpsc::channel();
    std::thread::Builder::new()
        .name("file-logger".into())
        .spawn(move || run_file_logger(rx))
        .map_err(std::io::Error::other)?;
    Ok(FileLogSender { tx })
}

#[cfg(target_os = "linux")]
fn run_file_logger(rx: mpsc::Receiver<FileLogCommand>) {
    // Dedicated io_uring runtime: each drained batch is submitted as
    // concurrent writes (one submission amortized over the whole batch,
    // cross-file parallelism preserved). `write_all_at(…, 0)` is pwrite-based,
    // which on Linux still appends when O_APPEND is set.
    use std::rc::Rc;

    use futures::future::join_all;
    use monoio::fs::File;

    let mut urb = io_uring::IoUring::builder();
    urb.setup_single_issuer();
    let mut runtime = monoio::RuntimeBuilder::<monoio::IoUringDriver>::new()
        .uring_builder(urb)
        .build()
        .expect("zeroserve: failed to build file logger io_uring runtime");
    runtime.block_on(async move {
        let mut files = HashMap::<PathBuf, Rc<File>>::new();
        while let Ok(command) = rx.recv() {
            let mut commands = vec![command];
            while let Ok(command) = rx.try_recv() {
                commands.push(command);
            }

            let mut writes = Vec::new();
            for command in commands {
                match command {
                    FileLogCommand::Write { path, msg } => match cached_file(&mut files, path) {
                        Ok(file) => writes.push(async move { file.write_all_at(msg, 0).await.0 }),
                        Err(err) => eprintln!("file logger open failed: {err:?}"),
                    },
                    FileLogCommand::Invalidate => {
                        files.clear();
                    }
                }
            }
            for result in join_all(writes).await {
                if let Err(err) = result {
                    eprintln!("file logger write failed: {err:?}");
                }
            }
        }
    });
}

#[cfg(not(target_os = "linux"))]
fn run_file_logger(rx: mpsc::Receiver<FileLogCommand>) {
    // Dedicated OS thread: use blocking std writes on an O_APPEND fd.
    //
    // The io_uring path above uses `write_all_at(…, 0)` (pwrite). On Linux the
    // kernel still appends when O_APPEND is set; on OpenBSD/POSIX pwrite
    // ignores O_APPEND and would overwrite the file from offset 0. `write(2)`
    // honors O_APPEND everywhere. Doing this on a dedicated thread keeps
    // workers non-blocking on every platform.
    let mut files = HashMap::<PathBuf, std::fs::File>::new();
    while let Ok(command) = rx.recv() {
        let mut commands = vec![command];
        while let Ok(command) = rx.try_recv() {
            commands.push(command);
        }

        for command in commands {
            match command {
                FileLogCommand::Write { path, msg } => match cached_file(&mut files, path) {
                    Ok(file) => {
                        if let Err(err) = file.write_all(&msg) {
                            eprintln!("file logger write failed: {err:?}");
                        }
                    }
                    Err(err) => eprintln!("file logger open failed: {err:?}"),
                },
                FileLogCommand::Invalidate => {
                    files.clear();
                }
            }
        }
    }
}

#[cfg(target_os = "linux")]
fn cached_file(
    files: &mut HashMap<PathBuf, std::rc::Rc<monoio::fs::File>>,
    path: PathBuf,
) -> std::io::Result<std::rc::Rc<monoio::fs::File>> {
    use std::rc::Rc;

    if let Some(file) = files.get(&path) {
        return Ok(file.clone());
    }
    let file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)?;
    let file = Rc::new(monoio::fs::File::from_std(file)?);
    files.insert(path, file.clone());
    Ok(file)
}

#[cfg(not(target_os = "linux"))]
fn cached_file(
    files: &mut HashMap<PathBuf, std::fs::File>,
    path: PathBuf,
) -> std::io::Result<&mut std::fs::File> {
    match files.entry(path) {
        Entry::Occupied(entry) => Ok(entry.into_mut()),
        Entry::Vacant(entry) => {
            let file = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(entry.key())?;
            Ok(entry.insert(file))
        }
    }
}
