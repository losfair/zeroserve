//! BoringSSL-backed TLS for the server listener, driven sans-IO over monoio.
//!
//! BoringSSL has native server-side ECH (inner-ClientHello decryption, the
//! ServerHello.random acceptance signal, and `retry_configs` on rejection),
//! which rustls 0.23 does not expose. We drive boring's synchronous
//! `SslStream` over an in-memory BIO (`MemBridge`) and pump ciphertext between
//! that buffer and a monoio `TcpStream`, exposing monoio's owned-buffer
//! `AsyncReadRent`/`AsyncWriteRent` so the result is a drop-in for the old
//! `monoio_rustls::TlsStream` (the h1/h2 handlers are unchanged).
//!
//! No tokio: `boring` (unlike `tokio-boring`) has no async-runtime dependency.

use std::cmp::Ordering;
use std::future::Future;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};

use anyhow::{Context, Result, anyhow};
use boring::asn1::Asn1Time;
use boring::ex_data::Index;
use boring::ssl::{
    AlpnError, ClientHello, ErrorCode, HandshakeError, NameType, SelectCertError, Ssl,
    SslConnector, SslContext, SslContextBuilder, SslFiletype, SslMethod, SslStream,
    SslStreamBuilder, SslVerifyMode, SslVersion, select_next_proto,
};
use boring::x509::{X509, X509Ref};
use monoio::{
    BufResult,
    buf::{IoBuf, IoBufMut, IoVecBuf, IoVecBufMut},
    io::{AsyncReadRent, AsyncWriteRent, AsyncWriteRentExt},
};

use crate::ja4;

const READ_CHUNK: usize = 16 * 1024;
// Wire-format ALPN list the server offers, in preference order: h2, http/1.1.
const ALPN_WIRE: &[u8] = b"\x02h2\x08http/1.1";
static JA4_EX_INDEX: OnceLock<Index<Ssl, String>> = OnceLock::new();
// Set by the certificate-selection callback when a connection should be
// transparently relayed (ECH "don't stick out" fallback) instead of
// terminated. Holds the relay target (the cleartext outer SNI / ECH public
// name). The handshake is then deliberately aborted and `drive_handshake`
// recovers this marker plus the buffered ClientHello.
static RELAY_EX_INDEX: OnceLock<Index<Ssl, String>> = OnceLock::new();
// Per-connection certificate decision for script-selected acceptors. Absent
// while the decision is pending: the selection callback returns RETRY, the
// handshake pauses with PENDING_CERTIFICATE, and `drive_handshake` runs the
// async selector and stores its result here before resuming. `None` means the
// selector chose nothing (serve the default identity if one exists).
static CERT_SELECT_EX_INDEX: OnceLock<Index<Ssl, Option<SslContext>>> = OnceLock::new();

pub struct ServerIdentity {
    pub cert_path: PathBuf,
    pub key_path: PathBuf,
    leaf: X509,
    dns_names: Vec<String>,
}

impl ServerIdentity {
    pub fn from_paths(cert_path: &Path, key_path: &Path) -> Result<Self> {
        let cert_pem = std::fs::read(cert_path)
            .with_context(|| format!("reading cert chain {}", cert_path.display()))?;
        let certs = X509::stack_from_pem(&cert_pem)
            .with_context(|| format!("parsing cert chain {}", cert_path.display()))?;
        let leaf = certs
            .into_iter()
            .next()
            .ok_or_else(|| anyhow!("no certificate found in {}", cert_path.display()))?;
        Ok(Self::from_leaf(
            cert_path.to_path_buf(),
            key_path.to_path_buf(),
            leaf,
        ))
    }

    pub fn from_leaf(cert_path: PathBuf, key_path: PathBuf, leaf: X509) -> Self {
        let dns_names = dns_sans(&leaf);
        Self {
            cert_path,
            key_path,
            leaf,
            dns_names,
        }
    }
}

struct SelectableIdentity {
    context: Option<SslContext>,
    leaf: X509,
    dns_names: Vec<String>,
}

/// In-memory bridge that boring's `SslStream<S>` reads/writes synchronously.
/// `inbound` holds ciphertext received from the peer that the SSL state machine
/// has not consumed yet; `outbound` collects ciphertext the SSL produced that
/// we must still send to the peer.
struct MemBridge {
    inbound: Vec<u8>,
    inbound_pos: usize,
    outbound: Vec<u8>,
}

impl MemBridge {
    fn new() -> Self {
        Self {
            inbound: Vec::new(),
            inbound_pos: 0,
            outbound: Vec::new(),
        }
    }
}

impl Read for MemBridge {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let avail = &self.inbound[self.inbound_pos..];
        if avail.is_empty() {
            // No buffered ciphertext: tell BoringSSL to come back (WANT_READ).
            return Err(io::Error::from(io::ErrorKind::WouldBlock));
        }
        let n = avail.len().min(buf.len());
        buf[..n].copy_from_slice(&avail[..n]);
        self.inbound_pos += n;
        Ok(n)
    }
}

impl Write for MemBridge {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.outbound.extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// A built server TLS context. Cheap to clone (refcounted `SSL_CTX`).
#[derive(Clone)]
pub struct BoringAcceptor {
    ctx: SslContext,
}

/// The result of a server-side accept. Normally a negotiated TLS stream, but
/// when ECH is enabled and a client connects to one of the ECH public names
/// without a decryptable inner ClientHello (and we hold no certificate for that
/// public name), the handshake is not terminated here — instead the raw
/// connection is handed back for transparent relay to the real public-name
/// server. See `RELAY_EX_INDEX`.
pub enum AcceptOutcome<IO> {
    /// A negotiated TLS stream, ready for the h1/h2 handlers.
    Stream(BoringStream<IO>),
    /// Relay the raw TCP bytes to `target`. `prelude` is the verbatim
    /// ClientHello (and any other already-buffered) bytes that must be replayed
    /// to the upstream before splicing `io` in both directions.
    Relay {
        target: String,
        prelude: Vec<u8>,
        io: IO,
    },
}

impl BoringAcceptor {
    /// Build a server context from PEM cert + key files, offering h2/http1.1
    /// via ALPN. `configure` runs against the builder before it is finalized
    /// (used to install ECH keys).
    pub fn build(
        cert_path: &std::path::Path,
        key_path: &std::path::Path,
        relay_public_names: Vec<String>,
        configure: impl FnOnce(&mut SslContextBuilder) -> Result<()>,
    ) -> Result<Self> {
        let identity = ServerIdentity::from_paths(cert_path, key_path)?;
        let mut builder = SslContextBuilder::new(SslMethod::tls())
            .context("creating BoringSSL server context")?;
        configure_server_context(&mut builder, &identity)?;
        let dns_names = identity.dns_names.clone();
        builder.set_select_certificate_callback(move |mut client_hello| {
            record_ja4(&mut client_hello);
            if let Some(target) = relay_target(&client_hello, &relay_public_names, |sni| {
                dns_names.iter().any(|name| dns_name_matches(name, sni))
            }) {
                client_hello.ssl_mut().set_ex_data(relay_ex_index(), target);
                return Err(SelectCertError::ERROR);
            }
            Ok(())
        });
        configure(&mut builder)?;
        Ok(Self {
            ctx: builder.build(),
        })
    }

    /// Build a server acceptor from multiple certificate identities. The first
    /// non-expired identity is the default for clients without SNI; clients
    /// with SNI are switched to the first non-expired identity whose DNS SAN
    /// matches that SNI.
    pub fn build_with_identities(
        identities: Vec<ServerIdentity>,
        relay_public_names: Vec<String>,
        configure: impl Fn(&mut SslContextBuilder) -> Result<()>,
    ) -> Result<Self> {
        if identities.is_empty() {
            return Err(anyhow!("no TLS certificates loaded"));
        }

        let default_idx = identities
            .iter()
            .position(|identity| !cert_is_expired(&identity.leaf).unwrap_or(true))
            .ok_or_else(|| anyhow!("all TLS certificates are expired"))?;

        let mut alternate_contexts = Vec::with_capacity(identities.len().saturating_sub(1));
        for (idx, identity) in identities.iter().enumerate() {
            if idx == default_idx {
                continue;
            }
            let mut builder = SslContextBuilder::new(SslMethod::tls())
                .context("creating BoringSSL server context")?;
            configure_server_context(&mut builder, identity)?;
            configure(&mut builder)?;
            alternate_contexts.push((idx, builder.build()));
        }

        let choices: Vec<SelectableIdentity> = identities
            .iter()
            .enumerate()
            .map(|(idx, identity)| SelectableIdentity {
                context: alternate_contexts
                    .iter()
                    .find(|(context_idx, _)| *context_idx == idx)
                    .map(|(_, context)| context.clone()),
                leaf: identity.leaf.to_owned(),
                dns_names: identity.dns_names.clone(),
            })
            .collect();
        let choices = Arc::new(choices);

        let default_identity = &identities[default_idx];
        let mut builder = SslContextBuilder::new(SslMethod::tls())
            .context("creating BoringSSL server context")?;
        configure_server_context(&mut builder, default_identity)?;
        configure(&mut builder)?;
        builder.set_select_certificate_callback(move |mut client_hello| {
            record_ja4(&mut client_hello);

            let Some(sni) = client_hello
                .servername(NameType::HOST_NAME)
                .map(str::to_ascii_lowercase)
            else {
                return Ok(());
            };

            let Some(choice) = choices.iter().find(|choice| {
                !cert_is_expired(&choice.leaf).unwrap_or(true) && cert_matches_sni(choice, &sni)
            }) else {
                // No certificate covers this SNI. If it is an ECH public name
                // and ECH was not accepted, mark the connection for transparent
                // relay to the real public-name server rather than failing.
                if let Some(target) = relay_target(&client_hello, &relay_public_names, |_| false) {
                    client_hello.ssl_mut().set_ex_data(relay_ex_index(), target);
                }
                return Err(SelectCertError::ERROR);
            };

            if let Some(ctx) = &choice.context {
                client_hello
                    .ssl_mut()
                    .set_ssl_context(ctx)
                    .map_err(|_| SelectCertError::ERROR)?;
            }
            Ok(())
        });

        Ok(Self {
            ctx: builder.build(),
        })
    }

    /// Build a server acceptor whose certificate is chosen per connection by
    /// the site's eBPF TLS section (the `--caddy` flow). The selection
    /// callback pauses the handshake at the ClientHello (`RETRY`) until
    /// `drive_handshake` has run the async selector and recorded its decision
    /// in ex-data; the callback then installs the chosen context. When the
    /// selector chooses nothing, the optional default identity (from
    /// `--cert`/`--key`) serves the connection; with no default the handshake
    /// is rejected (or transparently relayed for ECH public names).
    pub fn build_script_selected(
        default_identity: Option<ServerIdentity>,
        relay_public_names: Vec<String>,
        configure: impl FnOnce(&mut SslContextBuilder) -> Result<()>,
    ) -> Result<Self> {
        let mut builder = SslContextBuilder::new(SslMethod::tls())
            .context("creating BoringSSL server context")?;
        configure_base_server_context(&mut builder)?;
        let default_dns_names = match &default_identity {
            Some(identity) => {
                install_server_identity(&mut builder, identity)?;
                identity.dns_names.clone()
            }
            None => Vec::new(),
        };
        let has_default = default_identity.is_some();
        builder.set_select_certificate_callback(move |mut client_hello| {
            record_ja4(&mut client_hello);
            let Some(decision) = client_hello.ssl().ex_data(cert_select_ex_index()).cloned() else {
                // First pass: pause the handshake until the script has chosen.
                return Err(SelectCertError::RETRY);
            };
            if let Some(ctx) = decision {
                client_hello
                    .ssl_mut()
                    .set_ssl_context(&ctx)
                    .map_err(|_| SelectCertError::ERROR)?;
                return Ok(());
            }
            // The script selected no certificate: fall back to the default
            // identity, or reject (relaying ECH public-name connections).
            if let Some(target) = relay_target(&client_hello, &relay_public_names, |sni| {
                default_dns_names
                    .iter()
                    .any(|name| dns_name_matches(name, sni))
            }) {
                client_hello.ssl_mut().set_ex_data(relay_ex_index(), target);
                return Err(SelectCertError::ERROR);
            }
            if has_default {
                return Ok(());
            }
            Err(SelectCertError::ERROR)
        });
        configure(&mut builder)?;
        Ok(Self {
            ctx: builder.build(),
        })
    }

    /// Perform the server-side TLS handshake over `io`, pumping records
    /// through the in-memory bridge.
    pub async fn accept<IO>(&self, io: IO) -> Result<AcceptOutcome<IO>>
    where
        IO: AsyncReadRent + AsyncWriteRent,
    {
        self.accept_with_cert_selector(io, reject_cert_selector)
            .await
    }

    /// Like `accept`, but for script-selected acceptors: when the handshake
    /// pauses for certificate selection, `selector` is run with the
    /// (lowercased) SNI and its decision resumes the handshake. `Ok(None)`
    /// falls back to the default identity; `Err` rejects the connection.
    pub async fn accept_with_cert_selector<IO, F, Fut>(
        &self,
        io: IO,
        selector: F,
    ) -> Result<AcceptOutcome<IO>>
    where
        IO: AsyncReadRent + AsyncWriteRent,
        F: FnOnce(Option<String>) -> Fut,
        Fut: Future<Output = Result<Option<SslContext>>>,
    {
        let ssl = Ssl::new(&self.ctx).context("Ssl::new")?;
        let mid = SslStreamBuilder::new(ssl, MemBridge::new()).setup_accept();
        drive_handshake(mid, io, selector).await
    }
}

/// Selector for acceptors that never pause for certificate selection (their
/// callbacks never return `RETRY`); reaching it indicates a logic error.
async fn reject_cert_selector(_sni: Option<String>) -> Result<Option<SslContext>> {
    Err(anyhow!(
        "TLS handshake paused for certificate selection on a static acceptor"
    ))
}

/// Decide whether a connection should be transparently relayed instead of
/// terminated. Returns the relay target (the cleartext outer SNI) when ECH was
/// *not* accepted (no decryptable inner ClientHello), the cleartext SNI is one
/// of the configured ECH public names, and `cert_covers` reports that none of
/// our certificates cover that name.
fn relay_target(
    client_hello: &ClientHello<'_>,
    relay_public_names: &[String],
    cert_covers: impl Fn(&str) -> bool,
) -> Option<String> {
    if relay_public_names.is_empty() {
        return None;
    }
    // ECH accepted means we decrypted the inner ClientHello and are serving the
    // protected name — never relay those.
    if client_hello.ssl().ech_accepted() {
        return None;
    }
    let sni = client_hello
        .servername(NameType::HOST_NAME)?
        .to_ascii_lowercase();
    if !relay_public_names
        .iter()
        .any(|name| name.eq_ignore_ascii_case(&sni))
    {
        return None;
    }
    if cert_covers(&sni) {
        return None;
    }
    Some(sni)
}

fn configure_server_context(
    builder: &mut SslContextBuilder,
    identity: &ServerIdentity,
) -> Result<()> {
    configure_base_server_context(builder)?;
    install_server_identity(builder, identity)
}

/// Server context settings shared by every acceptor variant: TLS 1.3 only,
/// h2/http1.1 ALPN, and optional client certificates (verification is done by
/// the script layer, not BoringSSL).
fn configure_base_server_context(builder: &mut SslContextBuilder) -> Result<()> {
    builder
        .set_min_proto_version(Some(SslVersion::TLS1_3))
        .context("setting minimum TLS version")?;
    builder
        .set_max_proto_version(Some(SslVersion::TLS1_3))
        .context("setting maximum TLS version")?;
    builder.set_alpn_select_callback(|_ssl, client| {
        select_next_proto(ALPN_WIRE, client).ok_or(AlpnError::NOACK)
    });
    builder.set_verify_callback(SslVerifyMode::PEER, |_, _| true);
    Ok(())
}

/// Build a standalone server context for `identity`, configured like the
/// acceptor's base context (plus ECH keys when given). Used for the contexts
/// that script-driven certificate selection installs via `set_ssl_context`.
pub fn build_identity_context(
    identity: &ServerIdentity,
    ech_keys: Option<&boring::ssl::SslEchKeys>,
) -> Result<SslContext> {
    let mut builder =
        SslContextBuilder::new(SslMethod::tls()).context("creating BoringSSL server context")?;
    configure_server_context(&mut builder, identity)?;
    if let Some(keys) = ech_keys {
        builder
            .set_ech_keys(keys)
            .map_err(|e| anyhow!("SSL_CTX_set1_ech_keys failed: {e}"))?;
    }
    Ok(builder.build())
}

fn install_server_identity(
    builder: &mut SslContextBuilder,
    identity: &ServerIdentity,
) -> Result<()> {
    builder
        .set_certificate_chain_file(&identity.cert_path)
        .with_context(|| format!("loading cert chain {}", identity.cert_path.display()))?;
    builder
        .set_private_key_file(&identity.key_path, SslFiletype::PEM)
        .with_context(|| format!("loading private key {}", identity.key_path.display()))?;
    builder.check_private_key().with_context(|| {
        format!(
            "certificate/key mismatch: {} and {}",
            identity.cert_path.display(),
            identity.key_path.display()
        )
    })?;
    Ok(())
}

fn record_ja4(client_hello: &mut ClientHello<'_>) {
    if let Some(fingerprint) = ja4::tls_client_fingerprint(client_hello.as_bytes()) {
        client_hello
            .ssl_mut()
            .set_ex_data(ja4_ex_index(), fingerprint);
    }
}

fn cert_is_expired(cert: &X509Ref) -> Result<bool> {
    let now = Asn1Time::days_from_now(0).context("creating ASN.1 current time")?;
    Ok(cert
        .not_after()
        .compare(&now)
        .context("comparing certificate expiry")?
        == Ordering::Less)
}

fn cert_matches_sni(choice: &SelectableIdentity, sni: &str) -> bool {
    choice
        .dns_names
        .iter()
        .any(|name| dns_name_matches(name, sni))
}

fn dns_sans(cert: &X509Ref) -> Vec<String> {
    cert.subject_alt_names()
        .map(|names| {
            names
                .iter()
                .filter_map(|name| name.dnsname().map(str::to_ascii_lowercase))
                .collect()
        })
        .unwrap_or_default()
}

fn dns_name_matches(pattern: &str, sni: &str) -> bool {
    let pattern = pattern.to_ascii_lowercase();
    let sni = sni.to_ascii_lowercase();

    if !pattern.contains('*') {
        return pattern == sni;
    }

    let Some(suffix) = pattern.strip_prefix("*.") else {
        return false;
    };
    let Some(prefix) = sni.strip_suffix(suffix) else {
        return false;
    };
    prefix.ends_with('.') && !prefix[..prefix.len() - 1].contains('.')
}

/// Drive a mid-handshake `SslStream` to completion over `io`, pumping records
/// through the in-memory bridge. Shared by the server `accept` and client
/// `connect` paths. `selector` resolves a script-driven certificate selection
/// pause (`PENDING_CERTIFICATE`); acceptors that never pause pass
/// `reject_cert_selector`.
async fn drive_handshake<IO, F, Fut>(
    mut mid: boring::ssl::MidHandshakeSslStream<MemBridge>,
    mut io: IO,
    selector: F,
) -> Result<AcceptOutcome<IO>>
where
    IO: AsyncReadRent + AsyncWriteRent,
    F: FnOnce(Option<String>) -> Fut,
    Fut: Future<Output = Result<Option<SslContext>>>,
{
    let mut selector = Some(selector);
    // Snapshot of the peer's first flight (the ClientHello on the server path),
    // taken from the first non-empty inbound read so it survives the handshake's
    // later consumption/compaction of the bridge. Used to recover the cleartext
    // outer SNI when ECH is accepted.
    let mut first_flight: Option<Vec<u8>> = None;
    let stream = loop {
        match mid.handshake() {
            Ok(mut s) => {
                // Flush the final handshake flight to the peer.
                flush_out(s.get_mut(), &mut io).await?;
                break s;
            }
            Err(HandshakeError::WouldBlock(mut m))
                if m.error().code() == ErrorCode::PENDING_CERTIFICATE =>
            {
                // The selection callback paused the handshake at the
                // ClientHello: run the certificate selector and record its
                // decision, then re-enter the handshake (no IO is pending —
                // the pause is internal to BoringSSL).
                let Some(selector) = selector.take() else {
                    return Err(anyhow!(
                        "TLS handshake paused for certificate selection twice"
                    ));
                };
                let sni = m
                    .ssl()
                    .servername(NameType::HOST_NAME)
                    .map(str::to_ascii_lowercase);
                let decision = selector(sni)
                    .await
                    .context("TLS certificate selection failed")?;
                m.ssl_mut().set_ex_data(cert_select_ex_index(), decision);
                mid = m;
            }
            Err(HandshakeError::WouldBlock(mut m)) => {
                flush_out(m.get_mut(), &mut io).await?;
                if !fill_in(m.get_mut(), &mut io).await? {
                    return Err(anyhow!("peer closed during TLS handshake"));
                }
                if first_flight.is_none() {
                    let inbound = &m.get_ref().inbound;
                    if !inbound.is_empty() {
                        first_flight = Some(inbound.clone());
                    }
                }
                mid = m;
            }
            Err(HandshakeError::Failure(m)) => {
                // The certificate-selection callback may have aborted the
                // handshake to request a transparent relay (ECH "don't stick
                // out" fallback). Recover the target and the verbatim bytes the
                // client already sent (the ClientHello), discarding any alert
                // BoringSSL queued so the client sees a clean relayed stream.
                if let Some(target) = m.ssl().ex_data(relay_ex_index()).cloned() {
                    let prelude = m.get_ref().inbound.clone();
                    return Ok(AcceptOutcome::Relay {
                        target,
                        prelude,
                        io,
                    });
                }
                return Err(anyhow!("TLS handshake failed: {}", m.error()));
            }
            Err(HandshakeError::SetupFailure(e)) => {
                return Err(anyhow!("TLS setup failed: {e}"));
            }
        }
    };
    // When ECH was accepted, the negotiated `servername()` is the decrypted
    // inner name; recover the cleartext outer SNI from the wire ClientHello.
    let outer_sni = if stream.ssl().ech_accepted() {
        first_flight.as_deref().and_then(outer_sni_from_record)
    } else {
        None
    };
    Ok(AcceptOutcome::Stream(BoringStream {
        ssl: stream,
        io,
        scratch: vec![0u8; READ_CHUNK],
        plaintext: vec![0u8; READ_CHUNK],
        shutdown_sent: false,
        outer_sni,
    }))
}

/// Parse the cleartext SNI from a buffered TLS handshake record holding a
/// ClientHello. The wire ClientHello is always the *outer* one (the inner is
/// encrypted inside the ECH extension), so this yields the public/outer name.
/// Returns `None` if the bytes are not a single self-contained ClientHello
/// record (e.g. fragmented across records) or carry no SNI.
fn outer_sni_from_record(record: &[u8]) -> Option<String> {
    // TLSPlaintext: type(1) = handshake(0x16), legacy_version(2), length(2),
    // then the handshake message fragment.
    if record.len() < 5 || record[0] != 0x16 {
        return None;
    }
    let len = u16::from_be_bytes([record[3], record[4]]) as usize;
    let fragment = record.get(5..5 + len)?;
    ja4::client_hello_sni(fragment)
}

/// Process-wide TLS client connector for the reverse proxy, built once at
/// startup (before namespace isolation wipes `/etc`).
static CLIENT: OnceLock<SslConnector> = OnceLock::new();

/// Common system CA bundle locations, in probe order.
const CA_BUNDLE_PATHS: &[&str] = &[
    "/etc/ssl/certs/ca-certificates.crt", // Debian/Ubuntu/Alpine
    "/etc/pki/tls/certs/ca-bundle.crt",   // RHEL/Fedora
    "/etc/ssl/cert.pem",                  // BSD/macOS/some musl
    "/etc/ssl/ca-bundle.pem",             // openSUSE
];

/// Build the reverse-proxy TLS client from the host's CA bundle. MUST be called
/// at startup *before* namespace isolation, because `set_ca_file` eagerly loads
/// the certificates into the context (a lazy CA *path* would later fail once
/// `/etc` is a tmpfs). Reverse-proxying to HTTPS upstreams fails if this wasn't
/// initialized.
pub fn init_client_from_system_roots() -> Result<()> {
    let bundle = CA_BUNDLE_PATHS
        .iter()
        .map(std::path::Path::new)
        .find(|p| p.exists())
        .ok_or_else(|| {
            anyhow!(
                "no system CA bundle found (looked in {:?}); HTTPS reverse-proxy upstreams will fail",
                CA_BUNDLE_PATHS
            )
        })?;
    let mut builder =
        SslConnector::builder(SslMethod::tls()).context("creating BoringSSL client context")?;
    builder
        .set_min_proto_version(Some(SslVersion::TLS1_3))
        .context("setting minimum TLS client version")?;
    builder
        .set_max_proto_version(Some(SslVersion::TLS1_3))
        .context("setting maximum TLS client version")?;
    builder
        .set_ca_file(bundle)
        .with_context(|| format!("loading CA bundle {}", bundle.display()))?;
    // Upstream proxy connections are HTTP/1.1.
    builder
        .set_alpn_protos(b"\x08http/1.1")
        .context("setting client ALPN")?;
    CLIENT
        .set(builder.build())
        .map_err(|_| anyhow!("TLS client already initialized"))?;
    Ok(())
}

/// Connect to an upstream over TLS, verifying its certificate chain against the
/// startup-loaded CA bundle and checking the hostname against `sni`.
pub async fn client_connect<IO>(io: IO, sni: &str) -> Result<BoringStream<IO>>
where
    IO: AsyncReadRent + AsyncWriteRent,
{
    let connector = CLIENT
        .get()
        .ok_or_else(|| anyhow!("TLS client not initialized (no system CA bundle at startup)"))?;
    // `into_ssl` sets SNI and enables hostname verification against `sni`.
    let ssl = connector
        .configure()
        .context("configuring TLS client")?
        .into_ssl(sni)
        .with_context(|| format!("invalid TLS server name {sni:?}"))?;
    let mut builder = SslStreamBuilder::new(ssl, MemBridge::new());
    builder.set_connect_state();
    match drive_handshake(builder.setup_connect(), io, reject_cert_selector).await? {
        AcceptOutcome::Stream(stream) => Ok(stream),
        // Relay is only ever requested by the server cert-selection callback;
        // the client path installs no such marker.
        AcceptOutcome::Relay { .. } => Err(anyhow!(
            "unexpected relay outcome during client TLS connect"
        )),
    }
}

/// Flush any ciphertext BoringSSL has queued in `bridge.outbound` to the socket.
async fn flush_out<IO: AsyncWriteRent>(bridge: &mut MemBridge, io: &mut IO) -> Result<()> {
    if bridge.outbound.is_empty() {
        return Ok(());
    }
    let out = std::mem::take(&mut bridge.outbound);
    let (res, _) = io.write_all(out).await;
    res.context("writing TLS records to socket")?;
    io.flush().await.context("flushing socket")?;
    Ok(())
}

/// Read one chunk of ciphertext from the socket into `bridge.inbound`.
/// Returns `Ok(false)` on EOF.
async fn fill_in<IO: AsyncReadRent>(bridge: &mut MemBridge, io: &mut IO) -> Result<bool> {
    let buf = vec![0u8; READ_CHUNK];
    let (res, buf) = io.read(buf).await;
    let n = res.context("reading TLS records from socket")?;
    if n == 0 {
        return Ok(false);
    }
    // Compact fully-consumed inbound before appending so it can't grow forever.
    if bridge.inbound_pos == bridge.inbound.len() {
        bridge.inbound.clear();
        bridge.inbound_pos = 0;
    }
    bridge.inbound.extend_from_slice(&buf[..n]);
    Ok(true)
}

/// A negotiated TLS stream. Implements monoio's owned-buffer I/O traits so it
/// slots into the existing h1/h2 handlers in place of `monoio_rustls::TlsStream`.
pub struct BoringStream<IO> {
    ssl: SslStream<MemBridge>,
    io: IO,
    scratch: Vec<u8>,
    plaintext: Vec<u8>,
    shutdown_sent: bool,
    /// The cleartext outer SNI parsed from the wire ClientHello, set only when
    /// ECH was accepted (BoringSSL replaces `servername()` with the decrypted
    /// inner name, so the public/outer name is otherwise unrecoverable).
    outer_sni: Option<String>,
}

impl<IO: std::os::fd::AsRawFd> std::os::fd::AsRawFd for BoringStream<IO> {
    fn as_raw_fd(&self) -> std::os::fd::RawFd {
        self.io.as_raw_fd()
    }
}

impl<IO> BoringStream<IO> {
    /// Negotiated ALPN protocol, if any (e.g. `b"h2"`).
    pub fn alpn_protocol(&self) -> Option<Vec<u8>> {
        self.ssl.ssl().selected_alpn_protocol().map(<[u8]>::to_vec)
    }

    /// Whether the client offered ECH and BoringSSL accepted it (decrypted the
    /// inner ClientHello and signaled acceptance). False for plain TLS and for
    /// ECH that was rejected / not offered.
    pub fn ech_accepted(&self) -> bool {
        self.ssl.ssl().ech_accepted()
    }

    /// TLS protocol version in Caddy placeholder form (e.g. `tls1.3`).
    pub fn caddy_tls_version(&self) -> String {
        let name = match self.ssl.ssl().version_str() {
            "SSLv3" => "ssl3.0",
            "TLSv1" => "tls1.0",
            "TLSv1.1" => "tls1.1",
            "TLSv1.2" => "tls1.2",
            "TLSv1.3" => "tls1.3",
            other => return other.to_string(),
        };
        name.to_string()
    }

    /// RFC-standard TLS cipher suite selected for this connection, if any.
    pub fn caddy_tls_cipher_suite(&self) -> Option<String> {
        self.ssl.ssl().current_cipher().map(|cipher| {
            cipher
                .standard_name()
                .unwrap_or_else(|| cipher.name())
                .to_string()
        })
    }

    /// Whether this TLS connection resumed a previous session.
    pub fn tls_session_reused(&self) -> bool {
        self.ssl.ssl().session_reused()
    }

    /// The SNI BoringSSL is serving. When ECH was accepted this is the inner
    /// (real, protected) server name; for plain TLS it is the cleartext SNI.
    pub fn server_name(&self) -> Option<String> {
        self.ssl
            .ssl()
            .servername(boring::ssl::NameType::HOST_NAME)
            .map(str::to_string)
    }

    /// The cleartext outer SNI (the ECH public name the client actually sent),
    /// recovered from the wire ClientHello. `Some` only when ECH was accepted on
    /// this connection and the name could be parsed; `None` otherwise.
    pub fn outer_server_name(&self) -> Option<String> {
        self.outer_sni.clone()
    }

    /// JA4 TLS client fingerprint computed from the ClientHello, if available.
    pub fn ja4_fingerprint(&self) -> Option<String> {
        self.ssl.ssl().ex_data(ja4_ex_index()).cloned()
    }

    /// DER-encoded leaf client certificate, if the peer presented one.
    pub fn peer_certificate_der(&self) -> Option<Vec<u8>> {
        self.ssl
            .ssl()
            .peer_certificate()
            .and_then(|cert| cert.to_der().ok())
    }

    /// DER-encoded peer certificate chain as sent by the client.
    pub fn peer_certificate_chain_der(&self) -> Vec<Vec<u8>> {
        self.ssl
            .ssl()
            .peer_cert_chain()
            .map(|chain| {
                chain
                    .iter()
                    .filter_map(|cert| cert.to_der().ok())
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default()
    }
}

fn ja4_ex_index() -> Index<Ssl, String> {
    *JA4_EX_INDEX.get_or_init(|| Ssl::new_ex_index::<String>().expect("SSL ex-data index"))
}

fn cert_select_ex_index() -> Index<Ssl, Option<SslContext>> {
    *CERT_SELECT_EX_INDEX
        .get_or_init(|| Ssl::new_ex_index::<Option<SslContext>>().expect("SSL ex-data index"))
}

fn relay_ex_index() -> Index<Ssl, String> {
    *RELAY_EX_INDEX.get_or_init(|| Ssl::new_ex_index::<String>().expect("SSL ex-data index"))
}

impl<IO: AsyncWriteRent> BoringStream<IO> {
    async fn flush_outbound(&mut self) -> io::Result<()> {
        if self.ssl.get_mut().outbound.is_empty() {
            return Ok(());
        }
        let out = std::mem::take(&mut self.ssl.get_mut().outbound);
        let (res, _) = self.io.write_all(out).await;
        res.map(|_| ())
    }
}

impl<IO: AsyncReadRent> BoringStream<IO> {
    async fn fill_inbound(&mut self) -> io::Result<bool> {
        let buf = std::mem::take(&mut self.scratch);
        let (res, buf) = self.io.read(buf).await;
        let n = match res {
            Ok(n) => n,
            Err(e) => {
                self.scratch = buf;
                return Err(e);
            }
        };
        if n == 0 {
            self.scratch = buf;
            return Ok(false);
        }
        let bridge = self.ssl.get_mut();
        if bridge.inbound_pos == bridge.inbound.len() {
            bridge.inbound.clear();
            bridge.inbound_pos = 0;
        }
        bridge.inbound.extend_from_slice(&buf[..n]);
        self.scratch = buf;
        Ok(true)
    }
}

fn ssl_io_error(e: &boring::ssl::Error) -> io::Error {
    io::Error::other(format!("boring ssl error: {e}"))
}

impl<IO: AsyncReadRent + AsyncWriteRent> AsyncReadRent for BoringStream<IO> {
    async fn read<T: IoBufMut>(&mut self, mut buf: T) -> BufResult<usize, T> {
        let cap = buf.bytes_total();
        if cap == 0 {
            return (Ok(0), buf);
        }
        let want = cap.min(self.scratch.len().max(READ_CHUNK));
        if self.plaintext.len() < want {
            self.plaintext.resize(want, 0);
        }
        loop {
            // Drain any records BoringSSL wants to send (e.g. session tickets,
            // key updates) before potentially blocking on a read.
            if let Err(e) = self.flush_outbound().await {
                return (Err(e), buf);
            }
            match self.ssl.ssl_read(&mut self.plaintext[..want]) {
                Ok(n) => {
                    unsafe {
                        let dst = buf.write_ptr();
                        dst.copy_from_nonoverlapping(self.plaintext.as_ptr(), n);
                        buf.set_init(n);
                    }
                    return (Ok(n), buf);
                }
                Err(e) => match e.code() {
                    ErrorCode::ZERO_RETURN => return (Ok(0), buf), // clean close_notify
                    ErrorCode::WANT_READ => match self.fill_inbound().await {
                        Ok(true) => continue,
                        Ok(false) => return (Ok(0), buf),
                        Err(err) => return (Err(err), buf),
                    },
                    ErrorCode::WANT_WRITE => {
                        if let Err(err) = self.flush_outbound().await {
                            return (Err(err), buf);
                        }
                        continue;
                    }
                    _ => return (Err(ssl_io_error(&e)), buf),
                },
            }
        }
    }

    async fn readv<T: IoVecBufMut>(&mut self, mut buf: T) -> BufResult<usize, T> {
        // Fill only the first iovec slot; the AsyncReadRent contract allows a
        // short read. This keeps the vectored path simple and correct.
        let (ptr, len) = {
            #[cfg(unix)]
            unsafe {
                let slots =
                    std::slice::from_raw_parts(buf.write_iovec_ptr(), buf.write_iovec_len());
                match slots.iter().find(|s| s.iov_len > 0) {
                    Some(s) => (s.iov_base.cast::<u8>(), s.iov_len),
                    None => (std::ptr::null_mut(), 0),
                }
            }
            #[cfg(not(unix))]
            {
                (std::ptr::null_mut::<u8>(), 0usize)
            }
        };
        if len == 0 {
            return (Ok(0), buf);
        }
        let tmp = vec![0u8; len];
        let (res, tmp) = self.read(tmp).await;
        match res {
            Ok(n) => {
                unsafe {
                    ptr.copy_from_nonoverlapping(tmp.as_ptr(), n);
                    buf.set_init(n);
                }
                (Ok(n), buf)
            }
            Err(e) => (Err(e), buf),
        }
    }
}

impl<IO: AsyncReadRent + AsyncWriteRent> AsyncWriteRent for BoringStream<IO> {
    async fn write<T: IoBuf>(&mut self, buf: T) -> BufResult<usize, T> {
        let data = unsafe { std::slice::from_raw_parts(buf.read_ptr(), buf.bytes_init()) };
        if data.is_empty() {
            return (Ok(0), buf);
        }
        // ssl_write normally consumes the caller's buffer synchronously. Only
        // allocate a retry buffer when BoringSSL asks us to perform socket I/O
        // before it can accept the plaintext.
        match self.ssl.ssl_write(data) {
            Ok(n) => {
                if let Err(e) = self.flush_outbound().await {
                    return (Err(e), buf);
                }
                return (Ok(n), buf);
            }
            Err(e) if !matches!(e.code(), ErrorCode::WANT_WRITE | ErrorCode::WANT_READ) => {
                return (Err(ssl_io_error(&e)), buf);
            }
            Err(_) => {}
        }
        let data = data.to_vec();
        loop {
            match self.ssl.ssl_write(&data) {
                Ok(n) => {
                    if let Err(e) = self.flush_outbound().await {
                        return (Err(e), buf);
                    }
                    return (Ok(n), buf);
                }
                Err(e) => match e.code() {
                    ErrorCode::WANT_WRITE => {
                        if let Err(err) = self.flush_outbound().await {
                            return (Err(err), buf);
                        }
                        continue;
                    }
                    ErrorCode::WANT_READ => match self.fill_inbound().await {
                        Ok(true) => continue,
                        Ok(false) => {
                            return (Err(io::Error::from(io::ErrorKind::UnexpectedEof)), buf);
                        }
                        Err(err) => return (Err(err), buf),
                    },
                    _ => return (Err(ssl_io_error(&e)), buf),
                },
            }
        }
    }

    async fn writev<T: IoVecBuf>(&mut self, buf: T) -> BufResult<usize, T> {
        let data = unsafe {
            #[cfg(unix)]
            {
                let iovs = std::slice::from_raw_parts(buf.read_iovec_ptr(), buf.read_iovec_len());
                let mut v = Vec::new();
                for iov in iovs {
                    v.extend_from_slice(std::slice::from_raw_parts(
                        iov.iov_base.cast::<u8>(),
                        iov.iov_len,
                    ));
                }
                v
            }
            #[cfg(not(unix))]
            {
                Vec::new()
            }
        };
        if data.is_empty() {
            return (Ok(0), buf);
        }
        let (res, _) = self.write(data).await;
        (res, buf)
    }

    async fn flush(&mut self) -> io::Result<()> {
        self.flush_outbound().await
    }

    async fn shutdown(&mut self) -> io::Result<()> {
        if !self.shutdown_sent {
            // Best-effort close_notify; ignore WANT_* and errors.
            let _ = self.ssl.shutdown();
            self.shutdown_sent = true;
            let _ = self.flush_outbound().await;
        }
        self.io.shutdown().await
    }
}

// SAFETY: read paths only touch `inbound`/`scratch` and write paths only touch
// `outbound`; the underlying `IO` is itself `Split`. The h1 handler uses the
// halves sequentially (read request, then write response), matching the prior
// `monoio_rustls::TlsStream` usage which made the same promise.
unsafe impl<IO: monoio::io::Split> monoio::io::Split for BoringStream<IO> {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dns_san_matching_handles_exact_and_single_label_wildcards() {
        assert!(dns_name_matches("example.com", "example.com"));
        assert!(dns_name_matches("*.example.com", "www.example.com"));
        assert!(dns_name_matches("*.example.com", "WWW.EXAMPLE.COM"));
        assert!(!dns_name_matches("*.example.com", "example.com"));
        assert!(!dns_name_matches("*.example.com", "a.b.example.com"));
        assert!(!dns_name_matches("w*.example.com", "www.example.com"));
    }

    // A localhost client+server TLS handshake driven entirely over monoio,
    // proving the WANT_READ/WANT_WRITE pump and record framing are correct.
    // `#[monoio::test]` can't be used here: it cfg-gates the test on the
    // *destination crate's* `iouring` feature, which zeroserve doesn't define,
    // so the test silently vanishes. Build the runtime explicitly instead.
    #[test]
    fn loopback_handshake_and_echo() {
        monoio::RuntimeBuilder::<monoio::IoUringDriver>::new()
            .enable_timer()
            .build()
            .unwrap()
            .block_on(loopback_handshake_and_echo_inner());
    }

    async fn loopback_handshake_and_echo_inner() {
        use boring::ssl::{SslConnector, SslVerifyMode};
        use monoio::net::{TcpListener, TcpStream};

        // Self-signed cert/key generated for 127.0.0.1 (the repo test pair).
        let cert = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("certificate.pem");
        let key = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("key.pem");
        if !cert.exists() || !key.exists() {
            eprintln!("skipping: test cert/key not present");
            return;
        }

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let acceptor = BoringAcceptor::build(&cert, &key, Vec::new(), |_| Ok(())).unwrap();

        let server = async move {
            let (sock, _) = listener.accept().await.unwrap();
            let mut tls = match acceptor.accept(sock).await.unwrap() {
                AcceptOutcome::Stream(s) => s,
                AcceptOutcome::Relay { .. } => panic!("unexpected relay outcome"),
            };
            let ja4 = tls.ja4_fingerprint().unwrap();
            assert!(ja4.starts_with('t'));
            assert_eq!(ja4.len(), 36);
            // Echo one message.
            let (r, buf) = tls.read(vec![0u8; 64]).await;
            let n = r.unwrap();
            let (w, _) = tls.write(buf[..n].to_vec()).await;
            w.unwrap();
            tls.flush().await.unwrap();
        };

        let client = async move {
            let sock = TcpStream::connect(addr).await.unwrap();
            let mut cfg = SslConnector::builder(SslMethod::tls()).unwrap();
            cfg.set_verify(SslVerifyMode::NONE);
            let cfg = cfg.build().configure().unwrap();
            // Drive the client over the same sans-IO bridge for the test.
            let ssl = cfg.into_ssl("localhost").unwrap();
            let mut mid = SslStreamBuilder::new(ssl, MemBridge::new());
            mid.set_connect_state();
            let mut io = sock;
            let mut mid = {
                let mut m = mid.setup_connect();
                loop {
                    match m.handshake() {
                        Ok(s) => break s,
                        Err(HandshakeError::WouldBlock(mut mm)) => {
                            flush_out(mm.get_mut(), &mut io).await.unwrap();
                            if !fill_in(mm.get_mut(), &mut io).await.unwrap() {
                                panic!("server closed during handshake");
                            }
                            m = mm;
                        }
                        Err(e) => panic!("client handshake failed: {e}"),
                    }
                }
            };
            // Send "ping" and read the echo using the same pump primitives.
            mid.ssl_write(b"ping").unwrap();
            flush_out(mid.get_mut(), &mut io).await.unwrap();
            let mut out = [0u8; 4];
            loop {
                match mid.ssl_read(&mut out) {
                    Ok(_) => break,
                    Err(e) if e.code() == ErrorCode::WANT_READ => {
                        flush_out(mid.get_mut(), &mut io).await.unwrap();
                        assert!(fill_in(mid.get_mut(), &mut io).await.unwrap());
                    }
                    Err(e) => panic!("client read failed: {e}"),
                }
            }
            assert_eq!(&out, b"ping");
        };

        monoio::join!(server, client);
    }

    // End-to-end ECH: a boring client offering a real ECHConfigList against our
    // boring server with the matching key. Asserts BOTH sides report ECH
    // accepted — the thing rustls could not do (no ServerHello acceptance
    // signal). This is the regression guard for server-side ECH.
    #[test]
    fn ech_accepted_end_to_end() {
        monoio::RuntimeBuilder::<monoio::IoUringDriver>::new()
            .enable_timer()
            .build()
            .unwrap()
            .block_on(ech_accepted_end_to_end_inner());
    }

    async fn ech_accepted_end_to_end_inner() {
        use crate::ech::config::{
            CipherSuite, EchConfig, HPKE_AEAD_AES_128_GCM, HPKE_KDF_HKDF_SHA256,
            HPKE_KEM_DHKEM_X25519, encode_list,
        };
        use boring::pkey::{Id, PKey};
        use boring::ssl::{SslConnector, SslEchKeys, SslVerifyMode};
        use monoio::net::{TcpListener, TcpStream};

        let cert = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("certificate.pem");
        let key = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("key.pem");
        if !cert.exists() || !key.exists() {
            eprintln!("skipping: test cert/key not present");
            return;
        }

        // Generate an X25519 HPKE keypair with boring and build a matching
        // ECHConfig (config_id 0x2a, the MTI suite).
        let pkey = PKey::generate(Id::X25519).unwrap();
        let priv_raw = {
            let mut b = vec![0u8; 32];
            let s = pkey.raw_private_key(&mut b).unwrap();
            s.to_vec()
        };
        let pub_raw = {
            let mut b = vec![0u8; 32];
            let s = pkey.raw_public_key(&mut b).unwrap();
            s.to_vec()
        };
        let config = EchConfig {
            config_id: 0x2a,
            kem_id: HPKE_KEM_DHKEM_X25519,
            public_key: pub_raw,
            cipher_suites: vec![CipherSuite {
                kdf_id: HPKE_KDF_HKDF_SHA256,
                aead_id: HPKE_AEAD_AES_128_GCM,
            }],
            maximum_name_length: 0,
            public_name: "public.example.com".into(),
        };
        let config_bytes = config.encode();
        let config_list = encode_list(&[config]);

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        // Configure relay for the public name *and* use a cert that does not
        // cover it: this is the real "don't stick out" deployment. A legitimate
        // ECH client must still be accepted and served (not relayed), proving
        // the cert-selection callback observes ECH acceptance + the inner SNI.
        let acceptor = BoringAcceptor::build(
            &cert,
            &key,
            vec!["public.example.com".to_string()],
            move |builder| {
                let mut keys = SslEchKeys::builder().unwrap();
                let hpke = boring::hpke::HpkeKey::dhkem_p256_sha256(&priv_raw).unwrap();
                keys.add_key(true, &config_bytes, hpke).unwrap();
                builder.set_ech_keys(&keys.build()).unwrap();
                Ok(())
            },
        )
        .unwrap();
        let expected_outer = "public.example.com";

        let server = async move {
            let (sock, _) = listener.accept().await.unwrap();
            match acceptor.accept(sock).await {
                Ok(AcceptOutcome::Stream(tls)) => {
                    // With ECH accepted, servername() must be the INNER name the
                    // client protected, not the public/outer name.
                    assert_eq!(tls.server_name().as_deref(), Some("secret.internal"));
                    // The cleartext OUTER SNI is recovered from the wire
                    // ClientHello (BoringSSL only exposes the inner name).
                    assert_eq!(tls.outer_server_name().as_deref(), Some(expected_outer));
                    Some(tls.ech_accepted())
                }
                Ok(AcceptOutcome::Relay { .. }) => {
                    eprintln!("server unexpectedly chose relay");
                    None
                }
                Err(e) => {
                    eprintln!("server accept error: {e:?}");
                    None
                }
            }
        };

        let client = async move {
            let mut io = TcpStream::connect(addr).await.unwrap();
            let mut cfg = SslConnector::builder(SslMethod::tls()).unwrap();
            cfg.set_verify(SslVerifyMode::NONE);
            let conf = cfg.build().configure().unwrap();
            // Inner (real) SNI is the protected name; outer becomes public_name.
            let mut ssl = conf.into_ssl("secret.internal").unwrap();
            ssl.set_ech_config_list(&config_list).unwrap();
            let mut mid = SslStreamBuilder::new(ssl, MemBridge::new()).setup_connect();
            loop {
                match mid.handshake() {
                    Ok(mut s) => {
                        // Flush the client's final flight (Finished) so the
                        // server can complete its handshake.
                        let _ = flush_out(s.get_mut(), &mut io).await;
                        break Some(s.ssl().ech_accepted());
                    }
                    Err(HandshakeError::WouldBlock(mut m)) => {
                        if let Err(e) = flush_out(m.get_mut(), &mut io).await {
                            eprintln!("client flush error: {e:?}");
                            break None;
                        }
                        match fill_in(m.get_mut(), &mut io).await {
                            Ok(true) => {}
                            Ok(false) => {
                                eprintln!("client: server closed during ECH handshake");
                                break None;
                            }
                            Err(e) => {
                                eprintln!("client fill error: {e:?}");
                                break None;
                            }
                        }
                        mid = m;
                    }
                    Err(e) => {
                        eprintln!("client ECH handshake failed: {e}");
                        break None;
                    }
                }
            }
        };

        let (server_ech, client_ech) = monoio::join!(server, client);
        assert_eq!(client_ech, Some(true), "client: ECH should be accepted");
        assert_eq!(server_ech, Some(true), "server: ECH should be accepted");
    }

    // A client connecting with the ECH public name as its cleartext SNI but no
    // decryptable inner ClientHello (here, plain TLS with no ECH at all), while
    // the server holds no certificate covering that name, must yield a Relay
    // outcome carrying the public name and the buffered ClientHello — the core
    // of the ECH "don't stick out" fallback.
    #[test]
    fn relay_when_outer_sni_uncovered_and_inner_undecryptable() {
        monoio::RuntimeBuilder::<monoio::IoUringDriver>::new()
            .enable_timer()
            .build()
            .unwrap()
            .block_on(relay_when_outer_sni_uncovered_and_inner_undecryptable_inner());
    }

    async fn relay_when_outer_sni_uncovered_and_inner_undecryptable_inner() {
        use boring::ssl::{SslConnector, SslVerifyMode};
        use monoio::net::{TcpListener, TcpStream};

        let cert = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("certificate.pem");
        let key = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("key.pem");
        if !cert.exists() || !key.exists() {
            eprintln!("skipping: test cert/key not present");
            return;
        }

        // The repo test cert covers 127.0.0.1/localhost, not this public name.
        let public_name = "public.example.com";
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let acceptor =
            BoringAcceptor::build(&cert, &key, vec![public_name.to_string()], |_| Ok(())).unwrap();

        let server = async move {
            let (sock, _) = listener.accept().await.unwrap();
            match acceptor.accept(sock).await {
                Ok(AcceptOutcome::Relay {
                    target, prelude, ..
                }) => Some((target, prelude)),
                Ok(AcceptOutcome::Stream(_)) => {
                    eprintln!("server unexpectedly terminated instead of relaying");
                    None
                }
                Err(e) => {
                    eprintln!("server accept error: {e:?}");
                    None
                }
            }
        };

        // The client only needs to emit its ClientHello; the server aborts the
        // handshake to relay, so no ServerHello ever comes back. The flushed
        // bytes stay queued in the kernel and are delivered to the server even
        // after the client returns and the socket is torn down.
        let client = async move {
            let mut io = TcpStream::connect(addr).await.unwrap();
            let mut cfg = SslConnector::builder(SslMethod::tls()).unwrap();
            cfg.set_verify(SslVerifyMode::NONE);
            let conf = cfg.build().configure().unwrap();
            let ssl = conf.into_ssl(public_name).unwrap();
            let mid = SslStreamBuilder::new(ssl, MemBridge::new()).setup_connect();
            if let Err(HandshakeError::WouldBlock(mut m)) = mid.handshake() {
                let _ = flush_out(m.get_mut(), &mut io).await;
            }
        };

        let (relayed, ()) = monoio::join!(server, client);
        let (target, prelude) = relayed.expect("server should choose relay");
        assert_eq!(target, public_name);
        assert!(
            !prelude.is_empty(),
            "relay prelude (ClientHello) must be present"
        );
        // A TLS 1.3 ClientHello record starts with handshake content type 0x16.
        assert_eq!(prelude[0], 0x16, "prelude should be a TLS handshake record");
    }
}
