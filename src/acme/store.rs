//! On-disk persistence for ACME state under `--acme-dir`: the account key and
//! per-domain certificate/key PEMs. Plain blocking `std::fs` — this is touched
//! only at startup and during the (infrequent) renewal cycle.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use boring::asn1::Asn1Time;
use boring::x509::X509;

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
    pub fn load_or_create_account_key(&self) -> Result<AccountKey> {
        let path = self.account_key_path();
        if path.exists() {
            let pem = fs::read(&path)
                .with_context(|| format!("reading account key {}", path.display()))?;
            return AccountKey::from_pem(&pem);
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
    Ok(leaf.not_after().compare(&threshold).context("comparing certificate expiry")?
        == std::cmp::Ordering::Less)
}

#[cfg(unix)]
fn write_private(path: &Path, data: &[u8]) -> Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    use std::io::Write;
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
        fs::remove_dir_all(&dir).unwrap();
    }
}
