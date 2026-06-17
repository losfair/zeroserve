//! On-disk persistence for ACME state under `--acme-dir`: the account key and
//! per-domain certificate/key PEMs. Plain blocking `std::fs` — this is touched
//! only at startup and during the (infrequent) renewal cycle.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow};
use boring::asn1::Asn1Time;
use boring::x509::X509;
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
        write_private(&path, &key.to_pem()?)?;
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
        fs::write(dir.join("cert.pem"), cert_pem)
            .with_context(|| format!("writing certificate for {domain}"))?;
        write_private(&dir.join("key.pem"), key_pem)?;
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

#[cfg(unix)]
fn write_private(path: &Path, data: &[u8]) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("creating {}", path.display()))?;
    file.write_all(data)
        .with_context(|| format!("writing {}", path.display()))?;
    Ok(())
}

#[cfg(not(unix))]
fn write_private(path: &Path, data: &[u8]) -> Result<()> {
    fs::write(path, data).with_context(|| format!("writing {}", path.display()))
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
        assert!(dir.join("certs").join("example.com").join(".lock").exists());

        // Re-acquiring the same lock after the guard drops succeeds (the lock is
        // released when the guard is dropped), and a second domain is independent.
        drop(lock_exclusive(&dir.join("certs").join("example.com").join(".lock")).unwrap());
        store.save_cert("other.example", b"c2", b"k2").unwrap();
        assert_eq!(store.load_cert("other.example").unwrap().0, b"c2");
        fs::remove_dir_all(&dir).unwrap();
    }
}
