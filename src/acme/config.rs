//! Parsing and merging of the `zeroserve.init.acme_config` JSON returned by the
//! site's eBPF scripts into a single, validated [`AcmeConfig`].

use anyhow::{Result, bail};
use serde::Deserialize;

/// Default ACME directory: Let's Encrypt production.
pub const DEFAULT_DIRECTORY_URL: &str = "https://acme-v02.api.letsencrypt.org/directory";

/// External Account Binding credentials, as returned by a script's
/// `acme_config`. The `hmac_key` is base64url-encoded (the ACME convention).
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub struct Eab {
    pub kid: String,
    pub hmac_key: String,
}

/// The raw JSON shape a single `zeroserve.init.acme_config` section returns.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct AcmeConfigJson {
    #[serde(default)]
    domains: Vec<String>,
    #[serde(default)]
    contact: Option<String>,
    #[serde(default)]
    directory_url: Option<String>,
    #[serde(default)]
    eab: Option<Eab>,
}

/// The merged, validated ACME configuration driving provisioning.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AcmeConfig {
    /// Domains to obtain a certificate for, de-duplicated and lowercased. Each
    /// domain currently gets its own single-name certificate.
    pub domains: Vec<String>,
    pub contact: Option<String>,
    pub directory_url: String,
    pub eab: Option<Eab>,
}

/// Reject obviously invalid domain names before they reach the ACME server.
/// This is a syntactic guard, not a full RFC 1035 validator: it rules out
/// whitespace, control characters, schemes, ports, and paths.
fn validate_domain(domain: &str) -> Result<()> {
    if domain.is_empty() || domain.len() > 253 {
        bail!("invalid acme_config domain {domain:?}: empty or too long");
    }
    if domain.starts_with('.') || domain.ends_with('.') || domain.contains("..") {
        bail!("invalid acme_config domain {domain:?}: misplaced dot");
    }
    for label in domain.split('.') {
        if label.is_empty() || label.len() > 63 {
            bail!("invalid acme_config domain {domain:?}: bad label length");
        }
        let valid = label
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'*');
        if !valid || label.starts_with('-') || label.ends_with('-') {
            bail!("invalid acme_config domain {domain:?}: illegal characters");
        }
    }
    // A wildcard, if present, must be the entire leftmost label.
    if domain.contains('*') {
        let mut labels = domain.split('.');
        let first = labels.next().unwrap_or("");
        if first != "*" || domain.matches('*').count() != 1 {
            bail!("invalid acme_config domain {domain:?}: malformed wildcard");
        }
    }
    Ok(())
}

impl AcmeConfig {
    /// Merge the per-script `acme_config` values into one configuration.
    /// `entries` pairs each contributing script name with its returned JSON.
    /// Returns `Ok(None)` when no script asked for any domain (nothing to do).
    pub fn merge(entries: &[(String, serde_json::Value)]) -> Result<Option<AcmeConfig>> {
        let mut domains: Vec<String> = Vec::new();
        let mut contact: Option<String> = None;
        let mut directory_url: Option<String> = None;
        let mut eab: Option<Eab> = None;

        for (script, value) in entries {
            let parsed: AcmeConfigJson = serde_json::from_value(value.clone())
                .map_err(|e| anyhow::anyhow!("script '{script}' acme_config is invalid: {e}"))?;

            for domain in parsed.domains {
                let domain = domain.trim().to_ascii_lowercase();
                validate_domain(&domain).map_err(|e| anyhow::anyhow!("script '{script}': {e}"))?;
                if !domains.contains(&domain) {
                    domains.push(domain);
                }
            }

            if let Some(url) = parsed.directory_url {
                if let Some(existing) = &directory_url {
                    if existing != &url {
                        eprintln!(
                            "acme: script '{script}' overrides directory_url {existing:?} -> {url:?} (last wins)"
                        );
                    }
                }
                directory_url = Some(url);
            }

            if let Some(c) = parsed.contact {
                if let Some(existing) = &contact {
                    if existing != &c {
                        eprintln!(
                            "acme: script '{script}' overrides contact {existing:?} -> {c:?} (last wins)"
                        );
                    }
                }
                contact = Some(c);
            }

            if let Some(e) = parsed.eab {
                if eab.as_ref().is_some_and(|existing| existing != &e) {
                    eprintln!(
                        "acme: script '{script}' overrides external account binding (last wins)"
                    );
                }
                eab = Some(e);
            }
        }

        if domains.is_empty() {
            return Ok(None);
        }

        Ok(Some(AcmeConfig {
            domains,
            contact,
            directory_url: directory_url.unwrap_or_else(|| DEFAULT_DIRECTORY_URL.to_string()),
            eab,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn merges_and_dedups_domains_across_scripts() {
        let entries = vec![
            (
                "01.o".to_string(),
                json!({ "domains": ["Example.com", "www.example.com"] }),
            ),
            (
                "02.o".to_string(),
                json!({ "domains": ["example.com", "api.example.com"], "contact": "mailto:a@b.c" }),
            ),
        ];
        let cfg = AcmeConfig::merge(&entries).unwrap().unwrap();
        assert_eq!(
            cfg.domains,
            vec!["example.com", "www.example.com", "api.example.com"]
        );
        assert_eq!(cfg.contact.as_deref(), Some("mailto:a@b.c"));
        assert_eq!(cfg.directory_url, DEFAULT_DIRECTORY_URL);
    }

    #[test]
    fn no_domains_yields_none() {
        let entries = vec![("01.o".to_string(), json!({ "contact": "mailto:a@b.c" }))];
        assert!(AcmeConfig::merge(&entries).unwrap().is_none());
    }

    #[test]
    fn custom_directory_and_eab() {
        let entries = vec![(
            "01.o".to_string(),
            json!({
                "domains": ["example.com"],
                "directory_url": "https://acme-staging-v02.api.letsencrypt.org/directory",
                "eab": { "kid": "k1", "hmac_key": "aGVsbG8" }
            }),
        )];
        let cfg = AcmeConfig::merge(&entries).unwrap().unwrap();
        assert!(cfg.directory_url.contains("staging"));
        assert_eq!(cfg.eab.unwrap().kid, "k1");
    }

    #[test]
    fn rejects_invalid_domain() {
        let entries = vec![("01.o".to_string(), json!({ "domains": ["bad domain.com"] }))];
        assert!(AcmeConfig::merge(&entries).is_err());
    }

    #[test]
    fn rejects_unknown_field() {
        let entries = vec![(
            "01.o".to_string(),
            json!({ "domains": ["example.com"], "bogus": 1 }),
        )];
        assert!(AcmeConfig::merge(&entries).is_err());
    }
}
