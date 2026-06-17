//! TLS-ALPN-01 (RFC 8737) challenge certificate generation, plus a helper to
//! build a serving [`SslContext`] from in-memory certificate/key PEM.

use anyhow::{Context, Result, anyhow};
use boring::asn1::Asn1Time;
use boring::bn::{BigNum, MsbOption};
use boring::ec::{EcGroup, EcKey};
use boring::hash::MessageDigest;
use boring::nid::Nid;
use boring::pkey::PKey;
use boring::ssl::{
    AlpnError, SslContext, SslContextBuilder, SslMethod, SslVersion, select_next_proto,
};
use boring::x509::extension::SubjectAlternativeName;
use boring::x509::{X509, X509Extension, X509NameBuilder};

use super::jose::sha256;

/// The `id-pe-acmeIdentifier` extension OID (RFC 8737 §3).
const ACME_IDENTIFIER_OID: &str = "1.3.6.1.5.5.7.1.31";
/// Wire-format ALPN list for the challenge: only `acme-tls/1`.
const ACME_TLS_ALPN: &[u8] = b"\x0aacme-tls/1";
/// Wire-format ALPN list for live certificates: h2 then http/1.1.
const SERVER_ALPN: &[u8] = b"\x02h2\x08http/1.1";

fn hex_lower(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// Build the self-signed TLS-ALPN-01 challenge certificate for `identifier`,
/// carrying the critical `acmeIdentifier` extension holding
/// `SHA-256(key_authorization)`, together with its private key.
fn build_challenge_cert(
    identifier: &str,
    key_authorization: &str,
) -> Result<(X509, PKey<boring::pkey::Private>)> {
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
    let ec = EcKey::generate(&group).context("generating challenge key")?;
    let pkey = PKey::from_ec_key(ec).context("wrapping challenge key")?;

    let mut builder = X509::builder().context("creating challenge cert builder")?;
    builder.set_version(2)?;

    let mut serial = BigNum::new()?;
    serial.rand(159, MsbOption::MAYBE_ZERO, false)?;
    let serial = serial.to_asn1_integer()?;
    builder.set_serial_number(&serial)?;

    let mut name = X509NameBuilder::new()?;
    name.append_entry_by_text("CN", identifier)?;
    let name = name.build();
    builder.set_subject_name(&name)?;
    builder.set_issuer_name(&name)?;
    builder.set_pubkey(&pkey)?;
    let not_before = Asn1Time::days_from_now(0)?;
    let not_after = Asn1Time::days_from_now(7)?;
    builder.set_not_before(&not_before)?;
    builder.set_not_after(&not_after)?;

    // SubjectAltName: the identifier being validated.
    let san = {
        let ctx = builder.x509v3_context(None, None);
        SubjectAlternativeName::new()
            .dns(identifier)
            .build(&ctx)
            .context("building SAN extension")?
    };
    builder.append_extension(&san)?;

    // The critical acmeIdentifier extension: an OCTET STRING (tag 0x04, len 0x20)
    // wrapping SHA-256(key_authorization).
    let digest = sha256(key_authorization.as_bytes());
    let value = format!("critical,DER:0420{}", hex_lower(&digest));
    let acme_ext = X509Extension::new(None, None, ACME_IDENTIFIER_OID, &value)
        .context("building acmeIdentifier extension")?;
    builder.append_extension(&acme_ext)?;

    builder.sign(&pkey, MessageDigest::sha256())?;
    Ok((builder.build(), pkey))
}

/// Build the TLS-ALPN-01 challenge certificate for `identifier` and wrap it in
/// an `SslContext` that negotiates only the `acme-tls/1` ALPN. Served during the
/// CA's validation handshake.
pub fn build_challenge_context(identifier: &str, key_authorization: &str) -> Result<SslContext> {
    let (cert, pkey) = build_challenge_cert(identifier, key_authorization)?;

    let mut ctx = SslContextBuilder::new(SslMethod::tls()).context("challenge SSL context")?;
    ctx.set_min_proto_version(Some(SslVersion::TLS1_3))?;
    ctx.set_max_proto_version(Some(SslVersion::TLS1_3))?;
    ctx.set_certificate(&cert)?;
    ctx.set_private_key(&pkey)?;
    ctx.set_alpn_select_callback(|_ssl, client| {
        select_next_proto(ACME_TLS_ALPN, client).ok_or(AlpnError::NOACK)
    });
    Ok(ctx.build())
}

/// Build a serving `SslContext` from an in-memory certificate chain (leaf
/// first) and private key PEM. Negotiates the normal h2/http1.1 ALPN.
pub fn context_from_pem(cert_chain_pem: &[u8], key_pem: &[u8]) -> Result<SslContext> {
    let mut certs = X509::stack_from_pem(cert_chain_pem).context("parsing certificate chain")?;
    if certs.is_empty() {
        return Err(anyhow!("certificate chain is empty"));
    }
    let leaf = certs.remove(0);
    let key = PKey::private_key_from_pem(key_pem).context("parsing certificate private key")?;

    let mut ctx = SslContextBuilder::new(SslMethod::tls()).context("creating SSL context")?;
    ctx.set_min_proto_version(Some(SslVersion::TLS1_3))?;
    ctx.set_max_proto_version(Some(SslVersion::TLS1_3))?;
    ctx.set_certificate(&leaf)?;
    for extra in certs {
        ctx.add_extra_chain_cert(extra)?;
    }
    ctx.set_private_key(&key)?;
    ctx.check_private_key()
        .context("certificate/key mismatch")?;
    ctx.set_alpn_select_callback(|_ssl, client| {
        select_next_proto(SERVER_ALPN, client).ok_or(AlpnError::NOACK)
    });
    Ok(ctx.build())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::acme::jose::AccountKey;

    #[test]
    fn challenge_cert_carries_acme_identifier_digest() {
        let key = AccountKey::generate().unwrap();
        let key_auth = key.key_authorization("token-abc").unwrap();
        let (cert, _pkey) = build_challenge_cert("example.com", &key_auth).unwrap();

        // The DER of the cert must embed SHA-256(key_authorization).
        let digest = sha256(key_auth.as_bytes());
        let der = cert.to_der().unwrap();
        assert!(
            der.windows(digest.len()).any(|w| w == digest),
            "cert does not embed the key-authorization digest"
        );

        // And the public path builds a serving context without error.
        assert!(build_challenge_context("example.com", &key_auth).is_ok());
    }
}
