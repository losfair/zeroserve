//! Automatic certificate management over ACME (RFC 8555) with TLS-ALPN-01
//! validation (RFC 8737).
//!
//! The set of domains is read from the site's `zeroserve.init.acme_config` eBPF
//! section (see [`config`]). [`AcmeRuntime`] holds the shared certificate state
//! and, on worker 0, drives provisioning and renewal. Obtained certificates are
//! persisted under `--acme-dir` and served per-SNI by the TLS accept path.

mod challenge;
mod client;
pub mod config;
mod http;
mod jose;
mod store;

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::Result;
use boring::ssl::SslContext;

use crate::boringtls::dns_name_matches;

pub use config::AcmeConfig;

use challenge::{build_challenge_context, context_from_pem};
use client::AcmeClient;
use store::Store;

/// How often to attempt provisioning / renewal (a failed domain is retried at
/// this cadence, not the faster sync one).
const RENEWAL_INTERVAL: Duration = Duration::from_secs(12 * 3600);
/// How often to reload the live store from `--acme-dir`, so certificates issued
/// by a sibling process are picked up promptly.
const CERT_SYNC_INTERVAL: Duration = Duration::from_secs(60);

/// Shared certificate state consulted during the TLS handshake by every worker.
/// `live` maps an SNI to its serving context; `challenges` maps an identifier to
/// a transient TLS-ALPN-01 validation context while an order is in flight.
pub struct SharedCerts {
    live: Mutex<HashMap<String, SslContext>>,
    challenges: Mutex<HashMap<String, SslContext>>,
    /// `<acme-dir>/challenges`: key authorizations published by sibling
    /// processes that share this `--acme-dir`, so any process can answer a
    /// TLS-ALPN-01 validation handshake regardless of which one is provisioning.
    challenge_dir: Option<PathBuf>,
}

impl SharedCerts {
    fn new(challenge_dir: Option<PathBuf>) -> Self {
        Self {
            live: Mutex::new(HashMap::new()),
            challenges: Mutex::new(HashMap::new()),
            challenge_dir,
        }
    }

    fn insert_live(&self, domain: &str, ctx: SslContext) {
        self.live
            .lock()
            .expect("acme live certs poisoned")
            .insert(domain.to_ascii_lowercase(), ctx);
    }

    /// The serving context for `sni`, matching an exact domain or a `*.parent`
    /// wildcard certificate.
    pub fn live_for_sni(&self, sni: &str) -> Option<SslContext> {
        let map = self.live.lock().expect("acme live certs poisoned");
        let sni = sni.to_ascii_lowercase();
        if let Some(ctx) = map.get(&sni) {
            return Some(ctx.clone());
        }
        if let Some((_, parent)) = sni.split_once('.') {
            if let Some(ctx) = map.get(&format!("*.{parent}")) {
                return Some(ctx.clone());
            }
        }
        None
    }

    fn insert_challenge(&self, identifier: &str, ctx: SslContext) {
        self.challenges
            .lock()
            .expect("acme challenge certs poisoned")
            .insert(identifier.to_ascii_lowercase(), ctx);
    }

    fn remove_challenge(&self, identifier: &str) {
        self.challenges
            .lock()
            .expect("acme challenge certs poisoned")
            .remove(&identifier.to_ascii_lowercase());
    }

    /// The TLS-ALPN-01 validation context for `sni`, if a challenge is pending —
    /// either locally (in-memory) or published on disk by a sibling process
    /// sharing this `--acme-dir` (read on demand only for `acme-tls/1`
    /// handshakes, which are rare). Lets any process answer the CA's validation.
    pub fn challenge_for_sni(&self, sni: &str) -> Option<SslContext> {
        let sni = sni.to_ascii_lowercase();
        if let Some(ctx) = self
            .challenges
            .lock()
            .expect("acme challenge certs poisoned")
            .get(&sni)
            .cloned()
        {
            return Some(ctx);
        }
        // Cross-process fallback: a sibling published the key authorization.
        let dir = self.challenge_dir.as_ref()?;
        let path = dir.join(store::challenge_file_name(&sni));
        let key_authorization = std::fs::read_to_string(path).ok()?;
        build_challenge_context(&sni, &key_authorization).ok()
    }
}

/// Process-wide ACME state. Created at startup (so its [`SharedCerts`] can be
/// wired into the TLS runtime) and driven by [`AcmeRuntime::run`] on worker 0.
pub struct AcmeRuntime {
    acme_dir: PathBuf,
    certs: Arc<SharedCerts>,
    /// DNS SAN patterns of `--cert-dir` certificates. A domain covered here is
    /// served from `--cert-dir` and never acquired over ACME.
    cert_dir_names: Vec<String>,
}

impl AcmeRuntime {
    pub fn new(acme_dir: PathBuf, cert_dir_names: Vec<String>) -> Arc<Self> {
        let certs = Arc::new(SharedCerts::new(Some(acme_dir.join("challenges"))));
        Arc::new(Self {
            acme_dir,
            certs,
            cert_dir_names,
        })
    }

    pub fn certs(&self) -> Arc<SharedCerts> {
        self.certs.clone()
    }

    /// Whether `--cert-dir` already provides a certificate for `domain`.
    fn covered_by_cert_dir(&self, domain: &str) -> bool {
        self.cert_dir_names
            .iter()
            .any(|name| dns_name_matches(name, domain))
    }

    /// Drive ACME on worker 0: keep the live certificate store in sync with the
    /// `--acme-dir` (picking up certificates issued by sibling processes that
    /// share it), and provision/renew certificates this process is responsible
    /// for. Loops forever. Intended to be spawned once.
    pub async fn run(self: Arc<Self>, config: AcmeConfig) {
        let store = match Store::open(&self.acme_dir) {
            Ok(store) => store,
            Err(e) => {
                eprintln!(
                    "acme: cannot open --acme-dir {}: {e:#}",
                    self.acme_dir.display()
                );
                return;
            }
        };

        // mtimes of certificates already loaded into the live store, so we only
        // rebuild a context when a (possibly sibling-written) file changes.
        let mut loaded: HashMap<String, std::time::SystemTime> = HashMap::new();
        let mut next_provision = std::time::Instant::now();
        loop {
            // Pick up certificates (re)issued by any process, including siblings.
            self.sync_live_certs(&store, &config, &mut loaded);

            if std::time::Instant::now() >= next_provision {
                if let Err(e) = self.provision_cycle(&store, &config).await {
                    eprintln!("acme: provisioning cycle error: {e:#}");
                }
                next_provision = std::time::Instant::now() + RENEWAL_INTERVAL;
            }
            monoio::time::sleep(CERT_SYNC_INTERVAL).await;
        }
    }

    /// Reload into the live store any certificate whose file changed since we
    /// last loaded it (initial load, local renewal, or a sibling process's
    /// issuance/renewal). Skips `--cert-dir`-covered domains.
    fn sync_live_certs(
        &self,
        store: &Store,
        config: &AcmeConfig,
        loaded: &mut HashMap<String, std::time::SystemTime>,
    ) {
        for domain in &config.domains {
            if self.covered_by_cert_dir(domain) {
                continue;
            }
            let Some(mtime) = store.cert_mtime(domain) else {
                continue;
            };
            if loaded.get(domain) == Some(&mtime) {
                continue;
            }
            if let Some((cert_pem, key_pem)) = store.load_cert(domain) {
                match context_from_pem(&cert_pem, &key_pem) {
                    Ok(ctx) => {
                        self.certs.insert_live(domain, ctx);
                        loaded.insert(domain.clone(), mtime);
                    }
                    Err(e) => {
                        eprintln!(
                            "acme: ignoring unreadable stored certificate for {domain}: {e:#}"
                        )
                    }
                }
            }
        }
    }

    async fn provision_cycle(&self, store: &Store, config: &AcmeConfig) -> Result<()> {
        let pending: Vec<String> = config
            .domains
            .iter()
            .filter(|d| !self.covered_by_cert_dir(d) && store.needs_renewal(d))
            .cloned()
            .collect();
        if pending.is_empty() {
            return Ok(());
        }

        let key = store.load_or_create_account_key()?;
        let client = AcmeClient::connect(
            key,
            &config.directory_url,
            config.contact.as_deref(),
            config.eab.as_ref(),
        )
        .await?;

        for domain in pending {
            if let Err(e) = self.provision_domain(store, &client, &domain).await {
                eprintln!("acme: failed to provision {domain}: {e:#}");
            }
        }
        Ok(())
    }

    async fn provision_domain(
        &self,
        store: &Store,
        client: &AcmeClient,
        domain: &str,
    ) -> Result<()> {
        // Single-flight across processes: if a sibling holds the per-domain lock
        // it is already provisioning, so skip and let `sync_live_certs` adopt its
        // certificate.
        let Some(_lock) = store.try_lock_domain(domain)? else {
            return Ok(());
        };
        // Re-check under the lock: a sibling may have finished just before us.
        if !store.needs_renewal(domain) {
            return Ok(());
        }
        eprintln!("acme: provisioning certificate for {domain}");

        let domains = [domain.to_string()];
        let order = client.new_order(&domains).await?;

        for authz_url in &order.authorizations {
            let challenge = client.tls_alpn_challenge(authz_url).await?;
            let ctx = build_challenge_context(&challenge.identifier, &challenge.key_authorization)?;
            self.certs.insert_challenge(&challenge.identifier, ctx);
            // Publish the key authorization so any process (the CA's validation
            // handshake may land on a sibling via SO_REUSEPORT) can answer it.
            store.write_challenge(&challenge.identifier, &challenge.key_authorization)?;

            // Always tear the challenge down, whether validation succeeds or not.
            let result = async {
                client
                    .signal_challenge_ready(&challenge.challenge_url)
                    .await?;
                client.poll_authorization(authz_url).await
            }
            .await;
            self.certs.remove_challenge(&challenge.identifier);
            store.remove_challenge(&challenge.identifier);
            result?;
        }

        let key_pem = client.finalize(&order, &domains).await?;
        let cert_url = client.poll_order_certificate(&order).await?;
        let cert_pem = client.download_certificate(&cert_url).await?;
        store.save_cert(domain, &cert_pem, &key_pem)?;

        let ctx = context_from_pem(&cert_pem, &key_pem)?;
        self.certs.insert_live(domain, ctx);
        eprintln!("acme: obtained certificate for {domain}");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn challenge_served_from_sibling_published_on_disk() {
        let dir = std::env::temp_dir().join(format!("zs-acme-xchal-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let store = Store::open(&dir).unwrap();

        // A process whose SharedCerts has no in-memory challenge still serves the
        // TLS-ALPN-01 cert when a sibling published the key authorization on disk.
        let certs = SharedCerts::new(Some(dir.join("challenges")));
        assert!(certs.challenge_for_sni("acme.example").is_none());
        store
            .write_challenge("acme.example", "token.thumbprint")
            .unwrap();
        assert!(
            certs.challenge_for_sni("acme.example").is_some(),
            "should serve the on-disk challenge"
        );

        store.remove_challenge("acme.example");
        assert!(certs.challenge_for_sni("acme.example").is_none());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn no_challenge_dir_means_no_cross_process_lookup() {
        let certs = SharedCerts::new(None);
        assert!(certs.challenge_for_sni("acme.example").is_none());
    }
}
