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

pub use config::AcmeConfig;

use challenge::{build_challenge_context, context_from_pem};
use client::AcmeClient;
use store::Store;

/// How often the renewal loop re-checks certificate expiry.
const RENEWAL_INTERVAL: Duration = Duration::from_secs(12 * 3600);

/// Shared certificate state consulted during the TLS handshake by every worker.
/// `live` maps an SNI to its serving context; `challenges` maps an identifier to
/// a transient TLS-ALPN-01 validation context while an order is in flight.
#[derive(Default)]
pub struct SharedCerts {
    live: Mutex<HashMap<String, SslContext>>,
    challenges: Mutex<HashMap<String, SslContext>>,
}

impl SharedCerts {
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

    /// The TLS-ALPN-01 validation context for `sni`, if a challenge is pending.
    pub fn challenge_for_sni(&self, sni: &str) -> Option<SslContext> {
        self.challenges
            .lock()
            .expect("acme challenge certs poisoned")
            .get(&sni.to_ascii_lowercase())
            .cloned()
    }
}

/// Process-wide ACME state. Created at startup (so its [`SharedCerts`] can be
/// wired into the TLS runtime) and driven by [`AcmeRuntime::run`] on worker 0.
pub struct AcmeRuntime {
    acme_dir: PathBuf,
    certs: Arc<SharedCerts>,
}

impl AcmeRuntime {
    pub fn new(acme_dir: PathBuf) -> Arc<Self> {
        Arc::new(Self {
            acme_dir,
            certs: Arc::new(SharedCerts::default()),
        })
    }

    pub fn certs(&self) -> Arc<SharedCerts> {
        self.certs.clone()
    }

    /// Load any persisted certificates for `config`, then provision missing ones
    /// and loop forever renewing before expiry. Intended to be spawned once.
    pub async fn run(self: Arc<Self>, config: AcmeConfig) {
        let store = match Store::open(&self.acme_dir) {
            Ok(store) => store,
            Err(e) => {
                eprintln!("acme: cannot open --acme-dir {}: {e:#}", self.acme_dir.display());
                return;
            }
        };

        // Serve already-issued certificates immediately on restart.
        for domain in &config.domains {
            if let Some((cert_pem, key_pem)) = store.load_cert(domain) {
                match context_from_pem(&cert_pem, &key_pem) {
                    Ok(ctx) => self.certs.insert_live(domain, ctx),
                    Err(e) => {
                        eprintln!("acme: ignoring unreadable stored certificate for {domain}: {e:#}")
                    }
                }
            }
        }

        loop {
            if let Err(e) = self.provision_cycle(&store, &config).await {
                eprintln!("acme: provisioning cycle error: {e:#}");
            }
            monoio::time::sleep(RENEWAL_INTERVAL).await;
        }
    }

    async fn provision_cycle(&self, store: &Store, config: &AcmeConfig) -> Result<()> {
        let pending: Vec<String> = config
            .domains
            .iter()
            .filter(|d| store.needs_renewal(d))
            .cloned()
            .collect();
        if pending.is_empty() {
            return Ok(());
        }
        eprintln!("acme: provisioning certificates for {pending:?}");

        let key = store.load_or_create_account_key()?;
        let client = AcmeClient::connect(
            key,
            &config.directory_url,
            config.contact.as_deref(),
            config.eab.as_ref(),
        )
        .await?;

        for domain in pending {
            match self.provision_domain(store, &client, &domain).await {
                Ok(()) => eprintln!("acme: obtained certificate for {domain}"),
                Err(e) => eprintln!("acme: failed to provision {domain}: {e:#}"),
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
        let domains = [domain.to_string()];
        let order = client.new_order(&domains).await?;

        for authz_url in &order.authorizations {
            let challenge = client.tls_alpn_challenge(authz_url).await?;
            let ctx =
                build_challenge_context(&challenge.identifier, &challenge.key_authorization)?;
            self.certs.insert_challenge(&challenge.identifier, ctx);

            // Always remove the challenge cert, whether validation succeeds or not.
            let result = async {
                client.signal_challenge_ready(&challenge.challenge_url).await?;
                client.poll_authorization(authz_url).await
            }
            .await;
            self.certs.remove_challenge(&challenge.identifier);
            result?;
        }

        let key_pem = client.finalize(&order, &domains).await?;
        let cert_url = client.poll_order_certificate(&order).await?;
        let cert_pem = client.download_certificate(&cert_url).await?;
        store.save_cert(domain, &cert_pem, &key_pem)?;

        let ctx = context_from_pem(&cert_pem, &key_pem)?;
        self.certs.insert_live(domain, ctx);
        Ok(())
    }
}
