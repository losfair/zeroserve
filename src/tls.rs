use std::{
    cell::{Cell, RefCell},
    collections::HashMap,
    fs,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

use anyhow::{Context, Result, anyhow, bail};
use boring::hpke::HpkeKey;
use boring::pkey::{PKey, Private};
use boring::ssl::{SslContext, SslEchKeys};
use boring::x509::X509;

use crate::acme::SharedCerts;
use crate::boringtls::{BoringAcceptor, ServerIdentity, build_identity_context, dns_name_matches};
use crate::config::StaticConfig;
use crate::ech::key::EchKeySet;

pub struct TlsRuntime {
    pub acceptor: BoringAcceptor,
    /// True when ECH keys are loaded (the listener still serves plain TLS too).
    pub ech_enabled: bool,
    /// The ECH public name to report as the outer SNI when ECH is accepted.
    /// `Some` only when all loaded configs share one public name (so it is
    /// unambiguous); `None` otherwise (zero or multiple distinct names).
    pub ech_public_name: Option<String>,
    /// True in the `--caddy` flow: the site's eBPF TLS section selects the
    /// certificate per connection via `zs_caddy_tls_certificate`.
    pub script_certificates: bool,
    /// Shared ACME certificate registry (`--acme-dir`). The handshake serves
    /// TLS-ALPN-01 challenge certificates from here and falls back to a live
    /// ACME certificate by SNI when no script selects one.
    pub acme_certs: Option<Arc<SharedCerts>>,
    /// Certificates preloaded from `--cert-dir` when ACME is also enabled. The
    /// per-connection selector serves a matching cert-dir certificate in
    /// preference to an ACME one, so a hostname covered by `--cert-dir` is never
    /// served (or acquired) over ACME. Each entry pairs a leaf's DNS SAN
    /// patterns with its serving context.
    cert_dir_contexts: Vec<(Vec<String>, SslContext)>,
    /// ECH keys to install on lazily built per-certificate contexts so they
    /// mirror the acceptor's own configuration.
    ssl_ech_keys: Option<SslEchKeys>,
    /// Script-selected certificate contexts, keyed by (cert path, key path).
    /// Loaded on the first handshake that selects them and held in memory for
    /// the runtime's lifetime — dropped wholesale when a hot reload rebuilds
    /// the runtime, like cached log file handles.
    cert_contexts: Mutex<HashMap<(String, String), SslContext>>,
}

impl TlsRuntime {
    /// Resolve the server context for a script-selected certificate/key path
    /// pair, loading and caching the handle on first use.
    pub fn certificate_context(&self, cert_path: &str, key_path: &str) -> Result<SslContext> {
        let key = (cert_path.to_string(), key_path.to_string());
        let mut cache = self
            .cert_contexts
            .lock()
            .expect("certificate context cache poisoned");
        if let Some(context) = cache.get(&key) {
            return Ok(context.clone());
        }
        let identity = ServerIdentity::from_paths(Path::new(cert_path), Path::new(key_path))?;
        let context = build_identity_context(&identity, self.ssl_ech_keys.as_ref())?;
        cache.insert(key, context.clone());
        eprintln!("loaded TLS certificate {cert_path} (key {key_path})");
        Ok(context)
    }

    /// The `--cert-dir` certificate whose DNS SANs cover `sni`, if any. Consulted
    /// before the ACME live store so `--cert-dir` certificates take precedence.
    pub fn cert_dir_context_for_sni(&self, sni: &str) -> Option<SslContext> {
        let sni = sni.to_ascii_lowercase();
        self.cert_dir_contexts
            .iter()
            .find(|(names, _)| names.iter().any(|name| dns_name_matches(name, &sni)))
            .map(|(_, ctx)| ctx.clone())
    }
}

/// Per-handshake certificate selection state, attached to the script execution
/// context while the eBPF TLS section runs during the handshake's certificate
/// pause. `zs_caddy_tls_certificate` resolves paths through `runtime` and
/// records the first successful selection in `chosen`.
pub struct TlsCertSelect {
    pub runtime: Arc<TlsRuntime>,
    pub chosen: RefCell<Option<SslContext>>,
    /// Set by `zs_caddy_tls_client_auth` during the pre-handshake TLS section
    /// run when this connection's SNI matches a `client_auth` policy: the
    /// acceptor then requests a client certificate for the handshake.
    pub request_client_cert: Cell<bool>,
}

pub fn load_tls_if_configured(
    config: &Arc<StaticConfig>,
    acme_certs: Option<Arc<SharedCerts>>,
) -> Result<Option<TlsRuntime>> {
    match &config.tls_addr {
        Some(_addr) => {
            // Load ECH keys first (if configured) so we can install them on the
            // context during construction.
            let ech_keys = match &config.ech_key_path {
                Some(path) => {
                    let set = EchKeySet::load(path)
                        .with_context(|| format!("loading ECH keys from {}", path.display()))?;
                    if set.pairs.is_empty() {
                        bail!("ECH key set is empty");
                    }
                    Some(set)
                }
                None => None,
            };

            let ech_enabled = ech_keys.is_some();

            // The distinct ECH public names. When a client connects to one of
            // these without a decryptable inner ClientHello and we hold no
            // certificate covering it, the acceptor transparently relays the
            // raw TLS connection to the real public-name server.
            let relay_public_names: Vec<String> = match &ech_keys {
                Some(set) => {
                    let mut names: Vec<String> = set
                        .pairs
                        .iter()
                        .map(|p| p.config.public_name.clone())
                        .collect();
                    names.sort_unstable();
                    names.dedup();
                    names
                }
                None => Vec::new(),
            };

            let ssl_ech_keys = match &ech_keys {
                Some(set) => Some(build_ssl_ech_keys(set)?),
                None => None,
            };
            let configure = |builder: &mut boring::ssl::SslContextBuilder| {
                if let Some(ech) = &ssl_ech_keys {
                    builder
                        .set_ech_keys(ech)
                        .map_err(|e| anyhow!("SSL_CTX_set1_ech_keys failed: {e}"))?;
                }
                Ok(())
            };

            // The per-connection script selector drives certificate selection
            // when ACME is enabled (it serves ACME challenge/live certs and the
            // cert-dir certificates preloaded below) or in the `--caddy` flow
            // without an explicit `--cert-dir` (the site's eBPF TLS section
            // chooses the cert). A `--cert-dir` alone uses static SNI selection.
            let acme_enabled = config.acme_dir.is_some();
            let caddy_script = config.caddy_tarball.is_some() && config.cert_dir_path.is_none();
            let script_certificates = acme_enabled || caddy_script;

            // When ACME and `--cert-dir` are combined, preload the directory's
            // certificates so the selector can prefer them over ACME.
            let mut cert_dir_contexts: Vec<(Vec<String>, SslContext)> = Vec::new();
            if acme_enabled && let Some(cert_dir) = &config.cert_dir_path {
                let identities = load_cert_dir(cert_dir).with_context(|| {
                    format!("loading TLS certificates from {}", cert_dir.display())
                })?;
                eprintln!(
                    "loaded {} cert-dir identity(s) from {} (preferred over ACME)",
                    identities.len(),
                    cert_dir.display()
                );
                for identity in &identities {
                    let context = build_identity_context(identity, ssl_ech_keys.as_ref())?;
                    cert_dir_contexts.push((identity.dns_names.clone(), context));
                }
            }

            let acceptor = if script_certificates {
                // `--cert`/`--key`, when given, become the default identity for
                // connections whose SNI matches no policy and no cert-dir/ACME
                // certificate.
                let default_identity =
                    match (config.cert_path.as_deref(), config.key_path.as_deref()) {
                        (Some(cert), Some(key)) => Some(ServerIdentity::from_paths(cert, key)?),
                        _ => None,
                    };
                BoringAcceptor::build_script_selected(
                    default_identity,
                    relay_public_names.clone(),
                    acme_certs.clone(),
                    configure,
                )?
            } else if let Some(cert_dir) = &config.cert_dir_path {
                let identities = load_cert_dir(cert_dir).with_context(|| {
                    format!("loading TLS certificates from {}", cert_dir.display())
                })?;
                eprintln!(
                    "loaded {} TLS certificate identity(s) from {}",
                    identities.len(),
                    cert_dir.display()
                );
                BoringAcceptor::build_with_identities(
                    identities,
                    relay_public_names.clone(),
                    configure,
                )?
            } else {
                let cert = config
                    .cert_path
                    .as_deref()
                    .ok_or_else(|| anyhow!("TLS certificate path missing"))?;
                let key = config
                    .key_path
                    .as_deref()
                    .ok_or_else(|| anyhow!("TLS private key path missing"))?;
                BoringAcceptor::build(cert, key, relay_public_names.clone(), configure)?
            };

            let mut ech_public_name = None;
            if let Some(set) = &ech_keys {
                use base64ct::Encoding as _;
                let list_b64 = base64ct::Base64::encode_string(&set.config_list_bytes());
                let mut names: Vec<&str> = set
                    .pairs
                    .iter()
                    .map(|p| p.config.public_name.as_str())
                    .collect();
                eprintln!(
                    "ECH enabled: {} key(s), public_name(s)={:?}; the TLS cert must cover each name. Publish ech=\"{}\"",
                    set.pairs.len(),
                    names,
                    list_b64
                );
                eprintln!(
                    "ECH relay enabled for public name(s) {:?}: connections to those names without a decryptable inner ClientHello and without a matching certificate will be transparently relayed to the real server on port 443",
                    relay_public_names
                );
                // Report the outer SNI only when it is unambiguous.
                names.sort_unstable();
                names.dedup();
                if let [single] = names.as_slice() {
                    ech_public_name = Some(single.to_string());
                }
            }

            Ok(Some(TlsRuntime {
                acceptor,
                ech_enabled,
                ech_public_name,
                script_certificates,
                acme_certs,
                cert_dir_contexts,
                ssl_ech_keys,
                cert_contexts: Mutex::new(HashMap::new()),
            }))
        }
        None => Ok(None),
    }
}

/// The DNS SAN patterns of every certificate in `--cert-dir`, used to exclude
/// already-covered hostnames from ACME provisioning. Returns an empty list when
/// the directory holds no usable certificate (errors are non-fatal here: the
/// TLS runtime build surfaces directory problems).
pub fn cert_dir_dns_names(dir: &Path) -> Vec<String> {
    match load_cert_dir(dir) {
        Ok(identities) => identities
            .into_iter()
            .flat_map(|identity| identity.dns_names)
            .collect(),
        Err(_) => Vec::new(),
    }
}

fn build_ssl_ech_keys(set: &EchKeySet) -> Result<SslEchKeys> {
    let mut ech = SslEchKeys::builder().map_err(|e| anyhow!("SSL_ECH_KEYS_new failed: {e}"))?;
    for pair in &set.pairs {
        // BoringSSL only ships an X25519 HPKE key constructor
        // (the `dhkem_p256_sha256` name is a boring misnomer —
        // its body uses EVP_hpke_x25519_hkdf_sha256), which
        // matches the suite our keygen emits.
        let key = HpkeKey::dhkem_p256_sha256(&pair.private_key).map_err(|e| {
            anyhow!(
                "invalid ECH HPKE key (config_id 0x{:02x}): {e}",
                pair.config.config_id
            )
        })?;
        // is_retry_config = true: advertise every loaded config
        // in `retry_configs` when a client offers a stale one.
        ech.add_key(true, &pair.config.encode(), key).map_err(|e| {
            anyhow!(
                "SSL_ECH_KEYS_add failed (config_id 0x{:02x}): {e}",
                pair.config.config_id
            )
        })?;
    }
    Ok(ech.build())
}

struct CertFile {
    path: PathBuf,
    certs: Vec<X509>,
}

struct KeyFile {
    path: PathBuf,
    key: PKey<Private>,
}

fn load_cert_dir(dir: &Path) -> Result<Vec<ServerIdentity>> {
    let mut paths = fs::read_dir(dir)
        .with_context(|| format!("reading TLS certificate directory {}", dir.display()))?
        .map(|entry| entry.map(|entry| entry.path()))
        .collect::<std::io::Result<Vec<_>>>()
        .with_context(|| format!("reading entries in {}", dir.display()))?;
    paths.sort();

    let mut cert_files = Vec::new();
    let mut key_files = Vec::new();
    for path in paths {
        let metadata = fs::metadata(&path)
            .with_context(|| format!("stat TLS directory entry {}", path.display()))?;
        if !metadata.is_file() {
            continue;
        }

        let data = fs::read(&path).with_context(|| format!("reading {}", path.display()))?;
        if let Ok(certs) = X509::stack_from_pem(&data) {
            if !certs.is_empty() {
                cert_files.push(CertFile {
                    path: path.clone(),
                    certs,
                });
            }
        }
        if let Ok(key) = PKey::private_key_from_pem(&data) {
            key_files.push(KeyFile {
                path: path.clone(),
                key,
            });
        }
    }

    if cert_files.is_empty() {
        bail!("no TLS certificate PEMs found in {}", dir.display());
    }
    if key_files.is_empty() {
        bail!("no TLS private key PEMs found in {}", dir.display());
    }

    let mut identities = Vec::new();
    for cert_file in cert_files {
        let leaf = cert_file
            .certs
            .into_iter()
            .next()
            .expect("cert files are non-empty");
        let public_key = leaf
            .public_key()
            .with_context(|| format!("reading public key from {}", cert_file.path.display()))?;
        let Some(key_file) = key_files
            .iter()
            .find(|key_file| public_key.public_eq(&key_file.key))
        else {
            eprintln!(
                "warning: no matching private key found for TLS certificate {}",
                cert_file.path.display()
            );
            continue;
        };
        identities.push(ServerIdentity::from_leaf(
            cert_file.path,
            key_file.path.clone(),
            leaf,
        ));
    }

    if identities.is_empty() {
        bail!(
            "no TLS certificate PEMs in {} matched any private key PEM",
            dir.display()
        );
    }
    Ok(identities)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cert_dir_matches_certificate_to_key_by_public_key() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"));
        let cert = root.join("certificate.pem");
        let key = root.join("key.pem");
        if !cert.exists() || !key.exists() {
            eprintln!("skipping: test cert/key not present");
            return;
        }

        let dir =
            std::env::temp_dir().join(format!("zeroserve-cert-dir-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir(&dir).unwrap();
        fs::copy(&cert, dir.join("02-cert.pem")).unwrap();
        fs::copy(&key, dir.join("01-key.pem")).unwrap();

        let identities = load_cert_dir(&dir).unwrap();
        assert_eq!(identities.len(), 1);

        fs::remove_dir_all(&dir).unwrap();
    }
}
