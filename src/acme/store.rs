//! On-disk persistence for ACME state under `--acme-dir`: the account key and
//! per-domain certificate/key PEMs. Plain blocking `std::fs` — this is touched
//! only at startup and during the (infrequent) renewal cycle.

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

/// Acquire an exclusive advisory (`flock`) lock on `lock_path`, creating the
/// lock file if needed. The lock is held until the returned guard is dropped
/// and is released automatically if the process exits, making account-key and
/// per-domain certificate writes safe across multiple zeroserve processes that
/// share one `--acme-dir` (e.g. replicas on shared storage). The lock is
/// fine-grained — a separate lock file per resource (the account key, and each
/// domain) — so unrelated writes never contend.
fn lock_exclusive(lock_path: &Path) -> Result<Flock<fs::File>> {
    let file = fs::OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(false)
        .open(lock_path)
        .with_context(|| format!("opening ACME lock file {}", lock_path.display()))?;
    Flock::lock(file, FlockArg::LockExclusive)
        .map_err(|(_, errno)| anyhow!("locking {}: {errno}", lock_path.display()))
}

/// Read and parse the account key at `path`, or `Ok(None)` if it does not exist.
fn read_account_key(path: &Path) -> Result<Option<AccountKey>> {
    match fs::read(path) {
        Ok(pem) => Ok(Some(AccountKey::from_pem(&pem)?)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => {
            Err(anyhow::Error::from(e).context(format!("reading account key {}", path.display())))
        }
    }
}

impl Store {
    pub fn open(root: &Path) -> Result<Self> {
        fs::create_dir_all(root)
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
    pub fn cert_mtime(&self, domain: &str) -> Option<std::time::SystemTime> {
        fs::metadata(self.cert_dir(domain).join("cert.pem"))
            .ok()?
            .modified()
            .ok()
    }

    /// Try to take the per-domain provisioning lock without blocking. `Some`
    /// guard means we may provision `domain`; `None` means another process holds
    /// it (and is provisioning), so we should skip. Released on guard drop / exit.
    pub fn try_lock_domain(&self, domain: &str) -> Result<Option<Flock<fs::File>>> {
        let dir = self.cert_dir(domain);
        fs::create_dir_all(&dir)
            .with_context(|| format!("creating cert directory {}", dir.display()))?;
        let file = fs::OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false)
            .open(dir.join(".provision.lock"))
            .with_context(|| format!("opening provision lock for {domain}"))?;
        match Flock::lock(file, FlockArg::LockExclusiveNonblock) {
            Ok(guard) => Ok(Some(guard)),
            // EAGAIN (== EWOULDBLOCK on Linux): another process holds the lock.
            Err((_, Errno::EAGAIN)) => Ok(None),
            Err((_, errno)) => Err(anyhow!("locking provision lock for {domain}: {errno}")),
        }
    }

    fn challenges_dir(&self) -> PathBuf {
        self.root.join("challenges")
    }

    /// Publish the TLS-ALPN-01 key authorization for `identifier` so any process
    /// sharing this `--acme-dir` can answer the CA's validation handshake (which,
    /// with SO_REUSEPORT, may land on a process other than the one provisioning).
    pub fn write_challenge(&self, identifier: &str, key_authorization: &str) -> Result<()> {
        let dir = self.challenges_dir();
        fs::create_dir_all(&dir)
            .with_context(|| format!("creating challenges directory {}", dir.display()))?;
        write_atomic(
            &dir.join(challenge_file_name(identifier)),
            key_authorization.as_bytes(),
            0o644,
        )
    }

    pub fn remove_challenge(&self, identifier: &str) {
        let _ = fs::remove_file(self.challenges_dir().join(challenge_file_name(identifier)));
    }

    /// Load the ACME account key, generating and persisting one on first use.
    /// Creation is serialized across processes by an exclusive lock and a
    /// re-check, so racing instances converge on a single account key.
    pub fn load_or_create_account_key(&self) -> Result<AccountKey> {
        let path = self.account_key_path();
        if let Some(key) = read_account_key(&path)? {
            return Ok(key);
        }
        let _lock = lock_exclusive(&self.root.join("account.key.lock"))?;
        // Another process may have created the key before we took the lock.
        if let Some(key) = read_account_key(&path)? {
            return Ok(key);
        }
        let key = AccountKey::generate()?;
        write_atomic(&path, &key.to_pem()?, 0o600)?;
        eprintln!("acme: generated new account key at {}", path.display());
        Ok(key)
    }

    /// The stored certificate chain + key PEM for `domain`, if present.
    pub fn load_cert(&self, domain: &str) -> Option<(Vec<u8>, Vec<u8>)> {
        let dir = self.cert_dir(domain);
        let cert = fs::read(dir.join("cert.pem")).ok()?;
        let key = fs::read(dir.join("key.pem")).ok()?;
        Some((cert, key))
    }

    pub fn save_cert(&self, domain: &str, cert_pem: &[u8], key_pem: &[u8]) -> Result<()> {
        let dir = self.cert_dir(domain);
        fs::create_dir_all(&dir)
            .with_context(|| format!("creating cert directory {}", dir.display()))?;
        // Per-domain lock: concurrent writers for the same domain serialize;
        // different domains never contend.
        let _lock = lock_exclusive(&dir.join(".lock"))?;
        // Atomic writes so a concurrent reader never sees a partial cert/key.
        write_atomic(&dir.join("cert.pem"), cert_pem, 0o644)
            .with_context(|| format!("writing certificate for {domain}"))?;
        write_atomic(&dir.join("key.pem"), key_pem, 0o600)
            .with_context(|| format!("writing private key for {domain}"))?;
        Ok(())
    }

    /// Whether `domain` needs a (re)issued certificate: no cert on disk, an
    /// unparseable one, or one expiring within the renewal window.
    pub fn needs_renewal(&self, domain: &str) -> bool {
        let Some((cert_pem, _)) = self.load_cert(domain) else {
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
/// never a partially written one — important on shared storage.
fn write_atomic(path: &Path, data: &[u8], mode: u32) -> Result<()> {
    use std::io::Write;
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

    let result = (|| {
        let mut opts = fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(mode);
        }
        #[cfg(not(unix))]
        let _ = mode;
        let mut file = opts
            .open(&tmp)
            .with_context(|| format!("creating temp file {}", tmp.display()))?;
        file.write_all(data)
            .with_context(|| format!("writing {}", tmp.display()))?;
        // Flush data to disk before the rename so a crash can't leave the
        // renamed file pointing at unwritten blocks.
        file.sync_all()
            .with_context(|| format!("syncing {}", tmp.display()))?;
        fs::rename(&tmp, path)
            .with_context(|| format!("renaming {} -> {}", tmp.display(), path.display()))?;
        Ok(())
    })();

    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    } else {
        // Best-effort: persist the directory entry for the rename.
        if let Ok(dir_file) = fs::File::open(dir) {
            let _ = dir_file.sync_all();
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn account_key_is_persisted_and_reused() {
        let dir = std::env::temp_dir().join(format!("zs-acme-store-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let store = Store::open(&dir).unwrap();
        let k1 = store.load_or_create_account_key().unwrap();
        let k2 = store.load_or_create_account_key().unwrap();
        assert_eq!(k1.thumbprint().unwrap(), k2.thumbprint().unwrap());
        assert!(store.needs_renewal("example.com"), "no cert yet");
        // The account-key lock file was created alongside the key.
        assert!(dir.join("account.key.lock").exists());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn save_cert_round_trips_and_holds_a_per_domain_lock() {
        let dir =
            std::env::temp_dir().join(format!("zs-acme-cert-{}-{:?}", std::process::id(), "x"));
        let _ = fs::remove_dir_all(&dir);
        let store = Store::open(&dir).unwrap();
        store
            .save_cert("example.com", b"cert-bytes", b"key-bytes")
            .unwrap();
        let (cert, key) = store.load_cert("example.com").unwrap();
        assert_eq!(cert, b"cert-bytes");
        assert_eq!(key, b"key-bytes");
        // A fine-grained per-domain lock file lives in the domain directory.
        let domain_dir = dir.join("certs").join("example.com");
        assert!(domain_dir.join(".lock").exists());

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

        // Re-acquiring the same lock after the guard drops succeeds (the lock is
        // released when the guard is dropped), and a second domain is independent.
        drop(lock_exclusive(&dir.join("certs").join("example.com").join(".lock")).unwrap());
        store.save_cert("other.example", b"c2", b"k2").unwrap();
        assert_eq!(store.load_cert("other.example").unwrap().0, b"c2");
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn try_lock_domain_is_single_flight() {
        let dir = std::env::temp_dir().join(format!("zs-acme-lock-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let store = Store::open(&dir).unwrap();

        let g1 = store.try_lock_domain("a.example").unwrap();
        assert!(g1.is_some(), "first acquire");
        // A second acquire of the same domain (separate fd) is denied.
        assert!(store.try_lock_domain("a.example").unwrap().is_none());
        // A different domain is independent.
        assert!(store.try_lock_domain("b.example").unwrap().is_some());
        drop(g1);
        // Released after the guard drops.
        assert!(store.try_lock_domain("a.example").unwrap().is_some());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn challenge_published_and_removed() {
        let dir = std::env::temp_dir().join(format!("zs-acme-chal-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let store = Store::open(&dir).unwrap();

        let file = dir
            .join("challenges")
            .join(challenge_file_name("Ch.Example"));
        store.write_challenge("Ch.Example", "tok.thumb").unwrap();
        // Stored under the lowercased name with the exact key authorization.
        assert_eq!(fs::read_to_string(&file).unwrap(), "tok.thumb");
        store.remove_challenge("ch.example");
        assert!(!file.exists());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn cert_mtime_tracks_writes() {
        let dir = std::env::temp_dir().join(format!("zs-acme-mtime-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let store = Store::open(&dir).unwrap();
        assert!(store.cert_mtime("example.com").is_none());
        store.save_cert("example.com", b"c", b"k").unwrap();
        assert!(store.cert_mtime("example.com").is_some());
        fs::remove_dir_all(&dir).unwrap();
    }
}
