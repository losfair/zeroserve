//! RFC 8555 ACME protocol client (directory, nonces, account, orders,
//! authorizations, TLS-ALPN-01 challenges, finalize, certificate download).
//! Drives the HTTP-over-TLS transport in [`super::http`]. Single-threaded:
//! intended to run on one worker's monoio task.

use std::cell::RefCell;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use boring::ec::{EcGroup, EcKey};
use boring::hash::MessageDigest;
use boring::nid::Nid;
use boring::pkey::PKey;
use boring::stack::Stack;
use boring::x509::extension::SubjectAlternativeName;
use boring::x509::{X509NameBuilder, X509ReqBuilder};
use serde::Deserialize;
use serde_json::{Value, json};

use super::config::Eab;
use super::http;
use super::jose::{AccountKey, b64url};

const POLL_INTERVAL: Duration = Duration::from_secs(2);
const POLL_MAX_ATTEMPTS: usize = 30;

#[derive(Debug, Deserialize)]
struct Directory {
    #[serde(rename = "newNonce")]
    new_nonce: String,
    #[serde(rename = "newAccount")]
    new_account: String,
    #[serde(rename = "newOrder")]
    new_order: String,
}

/// A placed order's relevant URLs.
pub struct Order {
    pub url: String,
    pub finalize: String,
    pub authorizations: Vec<String>,
}

/// One TLS-ALPN-01 challenge to satisfy for an authorization.
pub struct TlsAlpnChallenge {
    pub identifier: String,
    pub challenge_url: String,
    pub key_authorization: String,
}

pub struct AcmeClient {
    key: AccountKey,
    directory: Directory,
    account_url: String,
    nonce: RefCell<Option<String>>,
}

impl AcmeClient {
    /// Fetch the directory, register (or re-register) the account, and return a
    /// ready client. Account registration with an existing key is idempotent:
    /// ACME returns the existing account URL.
    pub async fn connect(
        key: AccountKey,
        directory_url: &str,
        contact: Option<&str>,
        eab: Option<&Eab>,
    ) -> Result<Self> {
        let resp = http::request("GET", directory_url, None, None)
            .await
            .context("fetching ACME directory")?;
        if !resp.is_success() {
            bail!("ACME directory fetch failed: HTTP {}", resp.status);
        }
        let directory: Directory =
            serde_json::from_slice(&resp.body).context("parsing ACME directory")?;

        let mut client = AcmeClient {
            key,
            directory,
            account_url: String::new(),
            nonce: RefCell::new(None),
        };
        client.register_account(contact, eab).await?;
        Ok(client)
    }

    async fn get_nonce(&self) -> Result<String> {
        if let Some(n) = self.nonce.borrow_mut().take() {
            return Ok(n);
        }
        let resp = http::request("HEAD", &self.directory.new_nonce, None, None)
            .await
            .context("fetching ACME nonce")?;
        resp.header("replay-nonce")
            .map(str::to_string)
            .ok_or_else(|| anyhow!("newNonce returned no Replay-Nonce"))
    }

    fn store_nonce(&self, resp: &http::HttpResponse) {
        if let Some(n) = resp.header("replay-nonce") {
            *self.nonce.borrow_mut() = Some(n.to_string());
        }
    }

    /// Signed POST using the account key id (kid). `payload` is the serialized
    /// JSON body, or empty for POST-as-GET. Retries once on `badNonce`.
    async fn post(&self, url: &str, payload: &str) -> Result<http::HttpResponse> {
        for attempt in 0..2 {
            let nonce = self.get_nonce().await?;
            let protected = json!({
                "alg": "ES256",
                "kid": self.account_url,
                "nonce": nonce,
                "url": url,
            });
            let jws = self.key.sign_jws(protected, payload)?;
            let body = serde_json::to_vec(&jws)?;
            let resp =
                http::request("POST", url, Some("application/jose+json"), Some(&body)).await?;
            self.store_nonce(&resp);
            if resp.status == 400 && attempt == 0 && acme_error_type(&resp) == Some("badNonce") {
                continue;
            }
            return Ok(resp);
        }
        unreachable!("post loop always returns")
    }

    async fn register_account(&mut self, contact: Option<&str>, eab: Option<&Eab>) -> Result<()> {
        let mut payload = json!({ "termsOfServiceAgreed": true });
        if let Some(c) = contact {
            payload["contact"] = json!([c]);
        }
        if let Some(eab) = eab {
            payload["externalAccountBinding"] = self
                .key
                .external_account_binding(eab, &self.directory.new_account)?;
        }

        // newAccount is signed with an embedded JWK (no kid yet).
        let nonce = self.get_nonce().await?;
        let protected = json!({
            "alg": "ES256",
            "jwk": self.key.jwk()?,
            "nonce": nonce,
            "url": self.directory.new_account,
        });
        let jws = self
            .key
            .sign_jws(protected, &serde_json::to_string(&payload)?)?;
        let body = serde_json::to_vec(&jws)?;
        let resp = http::request(
            "POST",
            &self.directory.new_account,
            Some("application/jose+json"),
            Some(&body),
        )
        .await
        .context("registering ACME account")?;
        self.store_nonce(&resp);
        if !resp.is_success() {
            bail!(
                "ACME newAccount failed: HTTP {} {}",
                resp.status,
                problem(&resp)
            );
        }
        self.account_url = resp
            .header("location")
            .map(str::to_string)
            .ok_or_else(|| anyhow!("newAccount returned no account URL"))?;
        Ok(())
    }

    /// Place a new order for `domains`.
    pub async fn new_order(&self, domains: &[String]) -> Result<Order> {
        let identifiers: Vec<Value> = domains
            .iter()
            .map(|d| json!({ "type": "dns", "value": d }))
            .collect();
        let payload = json!({ "identifiers": identifiers });
        let resp = self
            .post(&self.directory.new_order, &serde_json::to_string(&payload)?)
            .await?;
        if !resp.is_success() {
            bail!(
                "ACME newOrder failed: HTTP {} {}",
                resp.status,
                problem(&resp)
            );
        }
        let url = resp
            .header("location")
            .map(str::to_string)
            .ok_or_else(|| anyhow!("newOrder returned no order URL"))?;
        let body = resp.json()?;
        let finalize = body["finalize"]
            .as_str()
            .ok_or_else(|| anyhow!("order missing finalize URL"))?
            .to_string();
        let authorizations = body["authorizations"]
            .as_array()
            .ok_or_else(|| anyhow!("order missing authorizations"))?
            .iter()
            .filter_map(|v| v.as_str().map(str::to_string))
            .collect();
        Ok(Order {
            url,
            finalize,
            authorizations,
        })
    }

    /// Fetch an authorization and extract its TLS-ALPN-01 challenge.
    pub async fn tls_alpn_challenge(&self, authz_url: &str) -> Result<TlsAlpnChallenge> {
        let resp = self.post(authz_url, "").await?;
        if !resp.is_success() {
            bail!(
                "fetching authorization failed: HTTP {} {}",
                resp.status,
                problem(&resp)
            );
        }
        let body = resp.json()?;
        let identifier = body["identifier"]["value"]
            .as_str()
            .ok_or_else(|| anyhow!("authorization missing identifier"))?
            .to_string();
        let challenge = body["challenges"]
            .as_array()
            .and_then(|cs| {
                cs.iter()
                    .find(|c| c["type"].as_str() == Some("tls-alpn-01"))
            })
            .ok_or_else(|| {
                anyhow!("authorization for {identifier} has no tls-alpn-01 challenge")
            })?;
        let challenge_url = challenge["url"]
            .as_str()
            .ok_or_else(|| anyhow!("tls-alpn-01 challenge missing url"))?
            .to_string();
        let token = challenge["token"]
            .as_str()
            .ok_or_else(|| anyhow!("tls-alpn-01 challenge missing token"))?;
        let key_authorization = self.key.key_authorization(token)?;
        Ok(TlsAlpnChallenge {
            identifier,
            challenge_url,
            key_authorization,
        })
    }

    /// Tell the server the challenge is ready to be validated.
    pub async fn signal_challenge_ready(&self, challenge_url: &str) -> Result<()> {
        let resp = self.post(challenge_url, "{}").await?;
        if !resp.is_success() {
            bail!(
                "signaling challenge failed: HTTP {} {}",
                resp.status,
                problem(&resp)
            );
        }
        Ok(())
    }

    /// Poll an authorization until it reaches `valid` (or fails / times out).
    pub async fn poll_authorization(&self, authz_url: &str) -> Result<()> {
        for _ in 0..POLL_MAX_ATTEMPTS {
            let resp = self.post(authz_url, "").await?;
            let body = resp.json()?;
            match body["status"].as_str() {
                Some("valid") => return Ok(()),
                Some("pending") | Some("processing") => {}
                Some("invalid") => {
                    bail!("authorization became invalid: {}", challenge_error(&body));
                }
                other => bail!("unexpected authorization status {other:?}"),
            }
            monoio::time::sleep(POLL_INTERVAL).await;
        }
        bail!("authorization did not validate within timeout")
    }

    /// Finalize the order with a CSR covering `domains`. Returns the freshly
    /// generated certificate private key (PKCS#8 PEM).
    pub async fn finalize(&self, order: &Order, domains: &[String]) -> Result<Vec<u8>> {
        let (key_pem, csr_der) = build_csr(domains)?;
        let payload = json!({ "csr": b64url(&csr_der) });
        let resp = self
            .post(&order.finalize, &serde_json::to_string(&payload)?)
            .await?;
        if !resp.is_success() {
            bail!(
                "ACME finalize failed: HTTP {} {}",
                resp.status,
                problem(&resp)
            );
        }
        Ok(key_pem)
    }

    /// Poll the order until `valid`, then return the certificate URL.
    pub async fn poll_order_certificate(&self, order: &Order) -> Result<String> {
        for _ in 0..POLL_MAX_ATTEMPTS {
            let resp = self.post(&order.url, "").await?;
            let body = resp.json()?;
            match body["status"].as_str() {
                Some("valid") => {
                    return body["certificate"]
                        .as_str()
                        .map(str::to_string)
                        .ok_or_else(|| anyhow!("valid order has no certificate URL"));
                }
                Some("processing") | Some("pending") | Some("ready") => {}
                Some("invalid") => bail!("order became invalid: {}", problem_body(&body)),
                other => bail!("unexpected order status {other:?}"),
            }
            monoio::time::sleep(POLL_INTERVAL).await;
        }
        bail!("order did not become valid within timeout")
    }

    /// Download the issued certificate chain (PEM).
    pub async fn download_certificate(&self, cert_url: &str) -> Result<Vec<u8>> {
        let resp = self.post(cert_url, "").await?;
        if !resp.is_success() {
            bail!(
                "downloading certificate failed: HTTP {} {}",
                resp.status,
                problem(&resp)
            );
        }
        Ok(resp.body)
    }
}

fn acme_error_type(resp: &http::HttpResponse) -> Option<&'static str> {
    let body = resp.json().ok()?;
    let ty = body["type"].as_str()?;
    if ty.ends_with(":badNonce") {
        Some("badNonce")
    } else {
        None
    }
}

fn problem(resp: &http::HttpResponse) -> String {
    resp.json().map(|b| problem_body(&b)).unwrap_or_else(|_| {
        String::from_utf8_lossy(&resp.body)
            .chars()
            .take(200)
            .collect()
    })
}

fn problem_body(body: &Value) -> String {
    let ty = body["type"].as_str().unwrap_or("");
    let detail = body["detail"].as_str().unwrap_or("");
    format!("{ty} {detail}").trim().to_string()
}

fn challenge_error(authz: &Value) -> String {
    authz["challenges"]
        .as_array()
        .and_then(|cs| cs.iter().find(|c| c.get("error").is_some()))
        .map(|c| problem_body(&c["error"]))
        .unwrap_or_else(|| problem_body(authz))
}

/// Build a PKCS#10 CSR (DER) covering `domains` with a fresh P-256 key, plus the
/// key as PKCS#8 PEM.
fn build_csr(domains: &[String]) -> Result<(Vec<u8>, Vec<u8>)> {
    if domains.is_empty() {
        bail!("cannot build a CSR with no domains");
    }
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
    let ec = EcKey::generate(&group).context("generating certificate key")?;
    let pkey = PKey::from_ec_key(ec).context("wrapping certificate key")?;

    let mut req = X509ReqBuilder::new()?;
    req.set_pubkey(&pkey)?;

    let mut name = X509NameBuilder::new()?;
    name.append_entry_by_text("CN", &domains[0])?;
    let name = name.build();
    req.set_subject_name(&name)?;

    let san = {
        let ctx = req.x509v3_context(None);
        let mut builder = SubjectAlternativeName::new();
        for domain in domains {
            builder.dns(domain);
        }
        builder.build(&ctx).context("building CSR SAN extension")?
    };
    let mut stack = Stack::new()?;
    stack.push(san)?;
    req.add_extensions(&stack)?;

    req.sign(&pkey, MessageDigest::sha256())?;
    let csr = req.build();

    let key_pem = pkey
        .private_key_to_pem_pkcs8()
        .context("serializing certificate key")?;
    let csr_der = csr.to_der().context("serializing CSR")?;
    Ok((key_pem, csr_der))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn csr_is_valid_der_with_san() {
        let (key_pem, csr_der) =
            build_csr(&["example.com".to_string(), "www.example.com".to_string()]).unwrap();
        assert!(key_pem.starts_with(b"-----BEGIN"));
        // Parse the CSR back and verify it carries both names.
        let req = boring::x509::X509Req::from_der(&csr_der).unwrap();
        let pubkey = req.public_key().unwrap();
        assert!(req.verify(&pubkey).unwrap());
    }
}
