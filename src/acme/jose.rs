//! JOSE primitives for ACME: the ES256 account key, its public JWK and
//! thumbprint, JWS signing, and HMAC external account bindings. Built on
//! BoringSSL's EC/ECDSA so we reuse the crypto already linked into zeroserve.

use anyhow::{Context, Result, anyhow};
use base64ct::{Base64UrlUnpadded, Encoding};
use boring::bn::{BigNum, BigNumContext};
use boring::ec::{EcGroup, EcKey};
use boring::ecdsa::EcdsaSig;
use boring::nid::Nid;
use boring::pkey::{PKey, Private};
use hmac::{Hmac, Mac};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use super::config::Eab;

/// base64url-encode without padding (the ACME/JOSE convention).
pub fn b64url(data: &[u8]) -> String {
    Base64UrlUnpadded::encode_string(data)
}

/// base64url-decode, tolerating optional `=` padding.
pub fn b64url_decode(s: &str) -> Result<Vec<u8>> {
    let trimmed = s.trim_end_matches('=');
    Base64UrlUnpadded::decode_vec(trimmed).map_err(|e| anyhow!("invalid base64url: {e}"))
}

pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// Left-pad a big-endian integer to `width` bytes (P-256 coordinates and ECDSA
/// `r`/`s` are 32 bytes; BoringSSL strips leading zeroes).
fn pad_be(bytes: &[u8], width: usize) -> Vec<u8> {
    if bytes.len() >= width {
        return bytes.to_vec();
    }
    let mut out = vec![0u8; width - bytes.len()];
    out.extend_from_slice(bytes);
    out
}

/// An ACME account key: a P-256 EC key used to sign every JWS request.
pub struct AccountKey {
    pkey: PKey<Private>,
}

impl AccountKey {
    pub fn generate() -> Result<Self> {
        let group =
            EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).context("creating P-256 group")?;
        let ec = EcKey::generate(&group).context("generating EC account key")?;
        let pkey = PKey::from_ec_key(ec).context("wrapping account key")?;
        Ok(Self { pkey })
    }

    pub fn to_pem(&self) -> Result<Vec<u8>> {
        self.pkey
            .private_key_to_pem_pkcs8()
            .context("serializing account key")
    }

    pub fn from_pem(pem: &[u8]) -> Result<Self> {
        let pkey = PKey::private_key_from_pem(pem).context("parsing account key")?;
        Ok(Self { pkey })
    }

    fn ec(&self) -> Result<EcKey<Private>> {
        self.pkey.ec_key().context("account key is not an EC key")
    }

    /// The public JWK (`{"crv","kty","x","y"}`) for this account key.
    pub fn jwk(&self) -> Result<Value> {
        let (x, y) = self.public_coords()?;
        Ok(json!({
            "crv": "P-256",
            "kty": "EC",
            "x": b64url(&x),
            "y": b64url(&y),
        }))
    }

    fn public_coords(&self) -> Result<(Vec<u8>, Vec<u8>)> {
        let ec = self.ec()?;
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
        let mut ctx = BigNumContext::new()?;
        let mut x = BigNum::new()?;
        let mut y = BigNum::new()?;
        ec.public_key()
            .affine_coordinates_gfp(&group, &mut x, &mut y, &mut ctx)
            .context("extracting EC public coordinates")?;
        Ok((pad_be(&x.to_vec(), 32), pad_be(&y.to_vec(), 32)))
    }

    /// RFC 7638 JWK thumbprint (base64url SHA-256 of the canonical JWK).
    pub fn thumbprint(&self) -> Result<String> {
        let (x, y) = self.public_coords()?;
        // Canonical form: members in lexicographic order, no whitespace.
        let canonical = format!(
            "{{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"{}\",\"y\":\"{}\"}}",
            b64url(&x),
            b64url(&y)
        );
        Ok(b64url(&sha256(canonical.as_bytes())))
    }

    /// The ACME key authorization for a challenge `token`: `token.thumbprint`.
    pub fn key_authorization(&self, token: &str) -> Result<String> {
        Ok(format!("{token}.{}", self.thumbprint()?))
    }

    /// Sign one JWS request. `protected` is the protected header value (the
    /// caller supplies `alg`/`url`/`nonce` and either `jwk` or `kid`); `payload`
    /// is the already-serialized JSON body, or empty for POST-as-GET. Returns
    /// the flattened JWS JSON ACME expects.
    pub fn sign_jws(&self, protected: Value, payload: &str) -> Result<Value> {
        let protected_b64 = b64url(serde_json::to_string(&protected)?.as_bytes());
        let payload_b64 = if payload.is_empty() {
            String::new()
        } else {
            b64url(payload.as_bytes())
        };
        let signing_input = format!("{protected_b64}.{payload_b64}");
        let signature = self.es256(signing_input.as_bytes())?;
        Ok(json!({
            "protected": protected_b64,
            "payload": payload_b64,
            "signature": b64url(&signature),
        }))
    }

    fn es256(&self, signing_input: &[u8]) -> Result<Vec<u8>> {
        let digest = sha256(signing_input);
        let ec = self.ec()?;
        let sig = EcdsaSig::sign(&digest, &ec).context("ECDSA signing")?;
        let mut out = pad_be(&sig.r().to_vec(), 32);
        out.extend_from_slice(&pad_be(&sig.s().to_vec(), 32));
        Ok(out)
    }

    /// Build the `externalAccountBinding` object for `newAccount`: a nested JWS
    /// over this account's public JWK, signed with the EAB HMAC key (HS256).
    pub fn external_account_binding(&self, eab: &Eab, new_account_url: &str) -> Result<Value> {
        let protected = json!({ "alg": "HS256", "kid": eab.kid, "url": new_account_url });
        let protected_b64 = b64url(serde_json::to_string(&protected)?.as_bytes());
        let payload_b64 = b64url(serde_json::to_string(&self.jwk()?)?.as_bytes());
        let signing_input = format!("{protected_b64}.{payload_b64}");

        let key = b64url_decode(&eab.hmac_key)?;
        let mut mac = Hmac::<Sha256>::new_from_slice(&key)
            .map_err(|e| anyhow!("invalid EAB HMAC key: {e}"))?;
        mac.update(signing_input.as_bytes());
        let signature = mac.finalize().into_bytes();
        Ok(json!({
            "protected": protected_b64,
            "payload": payload_b64,
            "signature": b64url(&signature),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn account_key_roundtrips_through_pem() {
        let key = AccountKey::generate().unwrap();
        let pem = key.to_pem().unwrap();
        let reloaded = AccountKey::from_pem(&pem).unwrap();
        assert_eq!(key.thumbprint().unwrap(), reloaded.thumbprint().unwrap());
    }

    #[test]
    fn jwk_has_padded_32_byte_coords() {
        let key = AccountKey::generate().unwrap();
        let jwk = key.jwk().unwrap();
        let x = b64url_decode(jwk["x"].as_str().unwrap()).unwrap();
        let y = b64url_decode(jwk["y"].as_str().unwrap()).unwrap();
        assert_eq!(x.len(), 32);
        assert_eq!(y.len(), 32);
    }

    #[test]
    fn es256_signature_is_64_bytes_and_verifies() {
        let key = AccountKey::generate().unwrap();
        let jws = key
            .sign_jws(json!({ "alg": "ES256", "url": "u", "nonce": "n" }), "{}")
            .unwrap();
        let sig = b64url_decode(jws["signature"].as_str().unwrap()).unwrap();
        assert_eq!(sig.len(), 64);

        // Reconstruct the signing input and verify against the public key.
        let protected_b64 = jws["protected"].as_str().unwrap();
        let payload_b64 = jws["payload"].as_str().unwrap();
        let signing_input = format!("{protected_b64}.{payload_b64}");
        let digest = sha256(signing_input.as_bytes());
        let r = BigNum::from_slice(&sig[..32]).unwrap();
        let s = BigNum::from_slice(&sig[32..]).unwrap();
        let ecdsa = EcdsaSig::from_private_components(r, s).unwrap();
        let ec = key.ec().unwrap();
        assert!(ecdsa.verify(&digest, &ec).unwrap());
    }

    #[test]
    fn key_authorization_joins_token_and_thumbprint() {
        let key = AccountKey::generate().unwrap();
        let ka = key.key_authorization("tok123").unwrap();
        assert!(ka.starts_with("tok123."));
        assert_eq!(ka, format!("tok123.{}", key.thumbprint().unwrap()));
    }
}
