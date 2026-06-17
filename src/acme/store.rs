//! On-disk persistence for ACME state under `--acme-dir`: the account key and
//! per-domain certificate/key PEMs. File reads and writes go through monoio's
//! async filesystem APIs so the provisioning/renewal task never blocks the
//! io_uring event loop; only the advisory `flock` helpers use `std::fs`, since
//! they acquire a lock on a descriptor rather than transferring file contents.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow};
use boring::asn1::Asn1Time;
use boring::x509::X509;
use nix::errno::Errno;
use nix::fcntl::{Flock, FlockArg};

use super::jose::AccountKey;

/// Renew when the leaf certificate expires within this many days.
const RENEW_WITHIN_DAYS: u32 = 30;

pub struct Store {
    root: PathBuf,
}

/// Map a domain (possibly a wildcard) to a safe single path component.
fn dir_name(domain: &str) -> String {
    domain.replace('*', "_wildcard_")
}

/// Lowercased, path-safe file name for a published challenge key authorization.
pub(crate) fn challenge_file_name(name: &str) -> String {
    dir_name(&name.to_ascii_lowercase())
}

/// Read and parse the account key at `path`, or `Ok(None)` if it does not exist.
async fn read_account_key(path: &Path) -> Result<Option<AccountKey>> {
    match monoio::fs::read(path).await {
        Ok(pem) => Ok(Some(AccountKey::from_pem(&pem)?)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => {
            Err(anyhow::Error::from(e).context(format!("reading account key {}", path.display())))
        }
    }
}

impl Store {
    pub async fn open(root: &Path) -> Result<Self> {
        monoio::fs::create_dir_all(root)
            .await
            .with_context(|| format!("creating ACME directory {}", root.display()))?;
        Ok(Self {
            root: root.to_path_buf(),
        })
    }

    fn account_key_path(&self) -> PathBuf {
        self.root.join("account.key")
    }

    fn cert_dir(&self, domain: &str) -> PathBuf {
        self.root.join("certs").join(dir_name(domain))
    }

    /// Last-modified time of `domain`'s stored certificate, if present. Used to
    /// detect certificates (re)issued by another process sharing this directory.
    pub async fn cert_mtime(&self, domain: &str) -> Option<std::time::SystemTime> {
        monoio::fs::metadata(self.cert_dir(domain).join("cert.pem"))
            .await
            .ok()?
            .modified()
            .ok()
    }

    /// Try to take an exclusive advisory (`flock`) lock on `path` without
    /// blocking, creating the lock file if needed. `Some` guard means it was
    /// acquired (released on guard drop or process exit); `None` means another
    /// process holds it. Non-blocking so callers can retry cooperatively (yield
    /// to the event loop) instead of stalling the thread in the syscall.
    ///
    /// This opens the descriptor with `std::fs` because the lock lives on the
    /// descriptor itself (held by the returned [`Flock`] guard); no file content
    /// is read or written here, so there is nothing to offload to io_uring.
    pub fn try_lock(&self, path: &Path) -> Result<Option<Flock<fs::File>>> {
        let file = fs::OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false)
            .open(path)
            .with_context(|| format!("opening lock file {}", path.display()))?;
        match Flock::lock(file, FlockArg::LockExclusiveNonblock) {
            Ok(guard) => Ok(Some(guard)),
            // EAGAIN (== EWOULDBLOCK on Linux): another process holds the lock.
            Err((_, Errno::EAGAIN)) => Ok(None),
            Err((_, errno)) => Err(anyhow!("locking {}: {errno}", path.display())),
        }
    }

    /// Try to take the per-domain provisioning lock without blocking. `Some`
    /// guard means we may provision `domain`; `None` means another process holds
    /// it (and is provisioning), so we should skip.
    pub async fn try_lock_domain(&self, domain: &str) -> Result<Option<Flock<fs::File>>> {
        let dir = self.cert_dir(domain);
        monoio::fs::create_dir_all(&dir)
            .await
            .with_context(|| format!("creating cert directory {}", dir.display()))?;
        self.try_lock(&dir.join(".provision.lock"))
    }

    /// The exclusive lock guarding first-time account-key creation.
    pub fn account_key_lock_path(&self) -> PathBuf {
        self.root.join("account.key.lock")
    }

    fn challenges_dir(&self) -> PathBuf {
        self.root.join("challenges")
    }

    /// Publish the TLS-ALPN-01 key authorization for `identifier` so any process
    /// sharing this `--acme-dir` can answer the CA's validation handshake (which,
    /// with SO_REUSEPORT, may land on a process other than the one provisioning).
    pub async fn write_challenge(&self, identifier: &str, key_authorization: &str) -> Result<()> {
        let dir = self.challenges_dir();
        monoio::fs::create_dir_all(&dir)
            .await
            .with_context(|| format!("creating challenges directory {}", dir.display()))?;
        write_atomic(
            &dir.join(challenge_file_name(identifier)),
            key_authorization.as_bytes(),
            0o644,
        )
        .await
    }

    pub async fn remove_challenge(&self, identifier: &str) {
        let _ =
            monoio::fs::remove_file(self.challenges_dir().join(challenge_file_name(identifier)))
                .await;
    }

    /// The persisted ACME account key, or `Ok(None)` if none exists yet.
    pub async fn read_account_key(&self) -> Result<Option<AccountKey>> {
        read_account_key(&self.account_key_path()).await
    }

    /// Generate and persist a new account key. The caller must hold the
    /// account-key lock and have re-checked that none exists, so racing
    /// processes converge on a single account key.
    pub async fn create_account_key(&self) -> Result<AccountKey> {
        let path = self.account_key_path();
        let key = AccountKey::generate()?;
        write_atomic(&path, &key.to_pem()?, 0o600).await?;
        eprintln!("acme: generated new account key at {}", path.display());
        Ok(key)
    }

    /// The stored certificate chain + key PEM for `domain`, if present.
    pub async fn load_cert(&self, domain: &str) -> Option<(Vec<u8>, Vec<u8>)> {
        let dir = self.cert_dir(domain);
        let cert = monoio::fs::read(dir.join("cert.pem")).await.ok()?;
        let key = monoio::fs::read(dir.join("key.pem")).await.ok()?;
        Some((cert, key))
    }

    /// Persist `domain`'s certificate and key. The caller holds the per-domain
    /// provisioning lock (so no other process writes concurrently), and the
    /// atomic temp-then-rename keeps any concurrent reader from seeing a partial
    /// file — so no separate write lock is needed here.
    pub async fn save_cert(&self, domain: &str, cert_pem: &[u8], key_pem: &[u8]) -> Result<()> {
        let dir = self.cert_dir(domain);
        monoio::fs::create_dir_all(&dir)
            .await
            .with_context(|| format!("creating cert directory {}", dir.display()))?;
        write_atomic(&dir.join("cert.pem"), cert_pem, 0o644)
            .await
            .with_context(|| format!("writing certificate for {domain}"))?;
        write_atomic(&dir.join("key.pem"), key_pem, 0o600)
            .await
            .with_context(|| format!("writing private key for {domain}"))?;
        Ok(())
    }

    /// Whether `domain` needs a (re)issued certificate: no cert on disk, an
    /// unparseable one, or one expiring within the renewal window.
    pub async fn needs_renewal(&self, domain: &str) -> bool {
        let Some((cert_pem, _)) = self.load_cert(domain).await else {
            return true;
        };
        match cert_expires_within(&cert_pem, RENEW_WITHIN_DAYS) {
            Ok(needs) => needs,
            Err(e) => {
                eprintln!("acme: cannot read stored certificate for {domain}: {e:#}; will renew");
                true
            }
        }
    }
}

/// True if the leaf certificate's `notAfter` is within `days` from now.
fn cert_expires_within(cert_pem: &[u8], days: u32) -> Result<bool> {
    let chain = X509::stack_from_pem(cert_pem).context("parsing stored certificate")?;
    let leaf = chain
        .into_iter()
        .next()
        .context("stored certificate chain is empty")?;
    let threshold = Asn1Time::days_from_now(days).context("computing renewal threshold")?;
    // notAfter < now+days  =>  expires within the window.
    Ok(leaf
        .not_after()
        .compare(&threshold)
        .context("comparing certificate expiry")?
        == std::cmp::Ordering::Less)
}

/// Atomically write `data` to `path` with permission `mode`: write a temp file
/// in the same directory, flush it to disk, then `rename` it over `path`.
/// `rename` is atomic on a single filesystem, so a concurrent reader (which does
/// not take the write lock) sees either the old or the new *complete* file,
/// never a partially written one — important on shared storage. All I/O runs
/// through monoio so it stays off the event-loop thread.
async fn write_atomic(path: &Path, data: &[u8], mode: u32) -> Result<()> {
    use std::sync::atomic::{AtomicU64, Ordering};

    static TMP_SEQ: AtomicU64 = AtomicU64::new(0);

    let dir = path
        .parent()
        .ok_or_else(|| anyhow!("{} has no parent directory", path.display()))?;
    let file_name = path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| anyhow!("invalid path {}", path.display()))?;
    let seq = TMP_SEQ.fetch_add(1, Ordering::Relaxed);
    let tmp = dir.join(format!(".{file_name}.tmp.{}.{seq}", std::process::id()));

    let result = async {
        let mut opts = monoio::fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(mode);
        }
        #[cfg(not(unix))]
        let _ = mode;
        let file = opts
            .open(&tmp)
            .await
            .with_context(|| format!("creating temp file {}", tmp.display()))?;
        let (res, _) = file.write_all_at(data.to_vec(), 0).await;
        res.with_context(|| format!("writing {}", tmp.display()))?;
        // Flush data to disk before the rename so a crash can't leave the
        // renamed file pointing at unwritten blocks. Closing surfaces any
        // deferred write error.
        file.sync_all()
            .await
            .with_context(|| format!("syncing {}", tmp.display()))?;
        file.close()
            .await
            .with_context(|| format!("closing {}", tmp.display()))?;
        monoio::fs::rename(&tmp, path)
            .await
            .with_context(|| format!("renaming {} -> {}", tmp.display(), path.display()))?;
        Ok::<(), anyhow::Error>(())
    }
    .await;

    if result.is_err() {
        let _ = monoio::fs::remove_file(&tmp).await;
    } else {
        // Best-effort: persist the directory entry for the rename.
        if let Ok(dir_file) = monoio::fs::File::open(dir).await {
            let _ = dir_file.sync_all().await;
            let _ = dir_file.close().await;
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Run an async test body on a dedicated monoio runtime. `#[monoio::test]`
    /// can't be used (it cfg-gates on the crate's `iouring` feature, which
    /// zeroserve doesn't define), so build the runtime explicitly.
    fn block_on<F: std::future::Future>(fut: F) -> F::Output {
        monoio::RuntimeBuilder::<monoio::IoUringDriver>::new()
            .enable_timer()
            .build()
            .unwrap()
            .block_on(fut)
    }

    #[test]
    fn account_key_is_persisted_and_reused() {
        block_on(async {
            let dir = std::env::temp_dir().join(format!("zs-acme-store-{}", std::process::id()));
            let _ = fs::remove_dir_all(&dir);
            let store = Store::open(&dir).await.unwrap();
            assert!(store.read_account_key().await.unwrap().is_none());
            let k1 = store.create_account_key().await.unwrap();
            let k2 = store.read_account_key().await.unwrap().unwrap();
            assert_eq!(k1.thumbprint().unwrap(), k2.thumbprint().unwrap());
            assert!(store.needs_renewal("example.com").await, "no cert yet");
            fs::remove_dir_all(&dir).unwrap();
        });
    }

    #[test]
    fn save_cert_round_trips_atomically() {
        block_on(async {
            let dir =
                std::env::temp_dir().join(format!("zs-acme-cert-{}-{:?}", std::process::id(), "x"));
            let _ = fs::remove_dir_all(&dir);
            let store = Store::open(&dir).await.unwrap();
            store
                .save_cert("example.com", b"cert-bytes", b"key-bytes")
                .await
                .unwrap();
            let (cert, key) = store.load_cert("example.com").await.unwrap();
            assert_eq!(cert, b"cert-bytes");
            assert_eq!(key, b"key-bytes");
            let domain_dir = dir.join("certs").join("example.com");

            // Atomic writes leave no temp files behind, and apply the right modes.
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                for entry in fs::read_dir(&domain_dir).unwrap() {
                    let name = entry.unwrap().file_name();
                    assert!(
                        !name.to_string_lossy().contains(".tmp."),
                        "leftover temp file {name:?}"
                    );
                }
                let key_mode = fs::metadata(domain_dir.join("key.pem"))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777;
                assert_eq!(key_mode, 0o600, "key.pem must be private");
                let cert_mode = fs::metadata(domain_dir.join("cert.pem"))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777;
                assert_eq!(cert_mode, 0o644);
            }

            store
                .save_cert("other.example", b"c2", b"k2")
                .await
                .unwrap();
            assert_eq!(store.load_cert("other.example").await.unwrap().0, b"c2");
            fs::remove_dir_all(&dir).unwrap();
        });
    }

    #[test]
    fn try_lock_domain_is_single_flight() {
        block_on(async {
            let dir = std::env::temp_dir().join(format!("zs-acme-lock-{}", std::process::id()));
            let _ = fs::remove_dir_all(&dir);
            let store = Store::open(&dir).await.unwrap();

            let g1 = store.try_lock_domain("a.example").await.unwrap();
            assert!(g1.is_some(), "first acquire");
            // A second acquire of the same domain (separate fd) is denied.
            assert!(store.try_lock_domain("a.example").await.unwrap().is_none());
            // A different domain is independent.
            assert!(store.try_lock_domain("b.example").await.unwrap().is_some());
            drop(g1);
            // Released after the guard drops.
            assert!(store.try_lock_domain("a.example").await.unwrap().is_some());
            fs::remove_dir_all(&dir).unwrap();
        });
    }

    #[test]
    fn challenge_published_and_removed() {
        block_on(async {
            let dir = std::env::temp_dir().join(format!("zs-acme-chal-{}", std::process::id()));
            let _ = fs::remove_dir_all(&dir);
            let store = Store::open(&dir).await.unwrap();

            let file = dir
                .join("challenges")
                .join(challenge_file_name("Ch.Example"));
            store
                .write_challenge("Ch.Example", "tok.thumb")
                .await
                .unwrap();
            // Stored under the lowercased name with the exact key authorization.
            assert_eq!(fs::read_to_string(&file).unwrap(), "tok.thumb");
            store.remove_challenge("ch.example").await;
            assert!(!file.exists());
            fs::remove_dir_all(&dir).unwrap();
        });
    }

    #[test]
    fn cert_mtime_tracks_writes() {
        block_on(async {
            let dir = std::env::temp_dir().join(format!("zs-acme-mtime-{}", std::process::id()));
            let _ = fs::remove_dir_all(&dir);
            let store = Store::open(&dir).await.unwrap();
            assert!(store.cert_mtime("example.com").await.is_none());
            store.save_cert("example.com", b"c", b"k").await.unwrap();
            assert!(store.cert_mtime("example.com").await.is_some());
            fs::remove_dir_all(&dir).unwrap();
        });
    }
}
