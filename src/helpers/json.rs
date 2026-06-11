use async_ebpf::program::HelperScope;
use boring::{
    hash::MessageDigest,
    x509::{X509, X509NameRef},
};

use crate::{
    json::JsonRef,
    script::{ScriptResponse, deref_and_write_cstr, read_utf8, with_ectx},
    shared::read_tar_entry,
};

pub fn h_json_parse(
    scope: &async_ebpf::program::HelperScope,
    data_ptr: u64,
    data_len: u64,
    _: u64,
    _: u64,
    _: u64,
) -> Result<u64, ()> {
    let data = scope.user_memory(data_ptr, data_len)?;
    with_ectx(scope, |ctx| {
        let data: serde_json::Value = match serde_json::from_slice(data) {
            Ok(x) => x,
            Err(_) => return Ok(-1i64 as u64),
        };
        ctx.alloc_memory_footprint(estimate_json_memory_usage(&data) as u64)?;
        let r = JsonRef::new(data);
        ctx.alloc_extobj(r)
    })
}

pub fn h_load_static_json(
    scope: &async_ebpf::program::HelperScope,
    path_ptr: u64,
    path_len: u64,
    _: u64,
    _: u64,
    _: u64,
) -> Result<u64, ()> {
    let path = match read_utf8(scope, path_ptr, path_len) {
        Ok(path) if !path.is_empty() => path.to_string(),
        _ => return Ok(-1i64 as u64),
    };
    let site = with_ectx(scope, |ctx| Ok(ctx.site.clone()))?;
    scope.post_task(async move {
        let result = async {
            let entry = site.entries.get(&path).cloned().ok_or(())?;
            let buf = read_tar_entry(entry, &site).await.map_err(|_| ())?;
            serde_json::from_slice::<serde_json::Value>(&buf).map_err(|_| ())
        }
        .await;
        move |scope: &HelperScope| match result {
            Ok(json) => with_ectx(scope, |ctx| {
                ctx.alloc_memory_footprint(estimate_json_memory_usage(&json) as u64)?;
                let r = JsonRef::new(json);
                ctx.alloc_extobj(r)
            }),
            Err(()) => Ok(-1i64 as u64),
        }
    });
    Ok(0)
}

pub fn h_load_file_metadata(
    scope: &async_ebpf::program::HelperScope,
    path_ptr: u64,
    path_len: u64,
    _: u64,
    _: u64,
    _: u64,
) -> Result<u64, ()> {
    let path = match read_utf8(scope, path_ptr, path_len) {
        Ok(path) if !path.is_empty() => path.to_string(),
        _ => return Ok(-1i64 as u64),
    };
    with_ectx(scope, |ctx| {
        let entry = match ctx.site.entries.get(&path) {
            Some(entry) => entry,
            None => return Ok(-1i64 as u64),
        };
        let json = serde_json::json!({
            "size": entry.size,
            "etag": entry.etag,
            "mtime": entry.mtime,
        });
        ctx.alloc_memory_footprint(estimate_json_memory_usage(&json) as u64)?;
        let r = JsonRef::new(json);
        ctx.alloc_extobj(r)
    })
}

/// Return a JSON object describing the current connection's transport state:
///
/// ```json
/// {
///   "tls": true,
///   "alpn": "h2",
///   "sni": { "inner": "secret.internal", "outer": "public.example.com" },
///   "ech": { "accepted": true },
///   "fingerprint": { "ja4": "t13d1516h2_8daaf6152771_e5627efa2ab1" }
/// }
/// ```
///
/// Fields:
/// - `tls`        — `true` when the request arrived over TLS.
/// - `tls_handshake_complete` — true when TLS is complete for this request.
/// - `alpn`       — negotiated ALPN protocol, or `null` if ALPN was not used.
/// - `sni`        — `{ "inner": string|null, "outer": string|null }`.
///     - `inner` is the server name BoringSSL is serving: the real, protected
///       name when ECH was accepted; the cleartext SNI for plain TLS.
///     - `outer` is the cleartext ECH public name when ECH was accepted on
///       this connection; `null` for plain TLS or rejected ECH.
/// - `ech`        — `null` when the server has no ECH keys loaded; otherwise an
///   object with `accepted` (bool): `true` means BoringSSL decrypted the inner
///   ClientHello and the real SNI is protected; `false` means ECH was not
///   accepted on this connection (client offered a stale/absent config and is
///   being served against the public-name certificate).
/// - `fingerprint` — TLS client fingerprints; currently `{ "ja4": string|null }`.
/// - `tls_client` — compact TLS peer certificate metadata:
///   `{ "certificate": object|null, "chain_fingerprints_sha256": string[] }`.
pub fn h_connection_info(
    scope: &async_ebpf::program::HelperScope,
    _: u64,
    _: u64,
    _: u64,
    _: u64,
    _: u64,
) -> Result<u64, ()> {
    with_ectx(scope, |ctx| {
        let json = {
            let request = ctx.request.borrow();
            let conn = &request.connection;
            let ech = match conn.ech_accepted {
                Some(accepted) => serde_json::json!({ "accepted": accepted }),
                None => serde_json::Value::Null,
            };
            let tls_client_cert = conn
                .tls_client_cert_der
                .as_ref()
                .and_then(|der| tls_client_cert_info(der));
            let tls_client_chain_fingerprints = conn
                .tls_client_chain_der
                .iter()
                .filter_map(|der| tls_cert_fingerprint_sha256(der))
                .collect::<Vec<_>>();
            serde_json::json!({
                "tls": conn.tls,
                "tls_handshake_complete": conn.tls_handshake_complete,
                "alpn": conn.alpn,
                "sni": {
                    "inner": conn.inner_sni,
                    "outer": conn.outer_sni,
                },
                "ech": ech,
                "fingerprint": {
                    "ja4": conn.tls_client_ja4,
                },
                "tls_client": {
                    "certificate": tls_client_cert,
                    "chain_fingerprints_sha256": tls_client_chain_fingerprints,
                },
            })
        };
        ctx.alloc_memory_footprint(estimate_json_memory_usage(&json) as u64)?;
        let r = JsonRef::new(json);
        ctx.alloc_extobj(r)
    })
}

fn tls_client_cert_info(der: &[u8]) -> Option<serde_json::Value> {
    let cert = X509::from_der(der).ok()?;
    Some(serde_json::json!({
        "fingerprint_sha256": tls_cert_fingerprint_sha256(der)?,
        "subject": x509_name_to_string(cert.subject_name()),
        "issuer": x509_name_to_string(cert.issuer_name()),
        "serial": cert
            .serial_number()
            .to_bn()
            .ok()?
            .to_hex_str()
            .ok()?
            .to_string(),
    }))
}

fn tls_cert_fingerprint_sha256(der: &[u8]) -> Option<String> {
    let cert = X509::from_der(der).ok()?;
    let digest = cert.digest(MessageDigest::sha256()).ok()?;
    Some(hex_lower(digest.as_ref()))
}

fn x509_name_to_string(name: &X509NameRef) -> String {
    name.entries()
        .map(|entry| {
            let key = entry.object().nid().short_name().unwrap_or("unknown");
            let value = entry
                .data()
                .as_utf8()
                .map(|value| value.to_string())
                .unwrap_or_else(|_| hex_lower(entry.data().as_slice()));
            format!("{key}={value}")
        })
        .collect::<Vec<_>>()
        .join(",")
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

pub fn h_json_reset(
    scope: &async_ebpf::program::HelperScope,
    idx: u64,
    _: u64,
    _: u64,
    _: u64,
    _: u64,
) -> Result<u64, ()> {
    with_ectx(scope, |ctx| {
        let root = ctx.extobj::<JsonRef>(idx)?.root();
        ctx.external_objects.insert(idx, Box::new(root));
        Ok(0)
    })
}

const INVALID_JSON_REF_ERROR: &str = "json reference is no longer valid";

pub fn h_json_get(
    scope: &async_ebpf::program::HelperScope,
    idx: u64,
    key_ptr: u64,
    key_len: u64,
    _: u64,
    _: u64,
) -> Result<u64, ()> {
    let key = scope.user_memory(key_ptr, key_len)?;
    let Ok(key) = std::str::from_utf8(key) else {
        return Ok(-1i64 as u64);
    };
    with_ectx(scope, |ctx| {
        let r = ctx.extobj::<JsonRef>(idx)?;
        let r = r
            .get(|x| match x {
                serde_json::Value::Object(x) => x.get(key),
                _ => None,
            })
            .inspect_err(|()| ctx.error = INVALID_JSON_REF_ERROR.into())?;
        let Some(r) = r else {
            return Ok(-1i64 as u64);
        };
        ctx.alloc_extobj(r)
    })
}

pub fn h_json_array_get(
    scope: &async_ebpf::program::HelperScope,
    idx: u64,
    array_index: u64,
    _: u64,
    _: u64,
    _: u64,
) -> Result<u64, ()> {
    with_ectx(scope, |ctx| {
        let r = ctx.extobj::<JsonRef>(idx)?;
        let r = r
            .get(|x| match x {
                serde_json::Value::Array(x) => x.get(array_index as usize),
                _ => None,
            })
            .inspect_err(|()| ctx.error = INVALID_JSON_REF_ERROR.into())?;
        let Some(r) = r else {
            return Ok(-1i64 as u64);
        };
        ctx.alloc_extobj(r)
    })
}

pub fn h_json_read_string(
    scope: &async_ebpf::program::HelperScope,
    idx: u64,
    out_ptr: u64,
    out_len: u64,
    _: u64,
    _: u64,
) -> Result<u64, ()> {
    with_ectx(scope, |ctx| {
        let r = ctx.extobj::<JsonRef>(idx)?;
        r.view(|x| match x {
            serde_json::Value::String(value) => {
                deref_and_write_cstr(scope, out_ptr, out_len, value)
            }
            _ => Ok(-1i64 as u64),
        })
        .inspect_err(|()| ctx.error = INVALID_JSON_REF_ERROR.into())?
    })
}

pub fn h_json_read_i64(
    scope: &async_ebpf::program::HelperScope,
    idx: u64,
    out_ptr: u64,
    out_len: u64,
    _: u64,
    _: u64,
) -> Result<u64, ()> {
    with_ectx(scope, |ctx| {
        let r = ctx.extobj::<JsonRef>(idx)?;
        let value = r
            .view(|x| match x {
                serde_json::Value::Number(value) => value.as_i64(),
                _ => None,
            })
            .inspect_err(|()| ctx.error = INVALID_JSON_REF_ERROR.into())?;
        let Some(value) = value else {
            return Ok(-1i64 as u64);
        };
        const VALUE_LEN: u64 = std::mem::size_of::<i64>() as u64;
        if out_len != VALUE_LEN {
            return Err(());
        }
        scope
            .user_memory_mut(out_ptr, out_len)?
            .copy_from_slice(&value.to_ne_bytes());
        Ok(VALUE_LEN)
    })
}

pub fn h_json_read_bool(
    scope: &async_ebpf::program::HelperScope,
    idx: u64,
    out_ptr: u64,
    out_len: u64,
    _: u64,
    _: u64,
) -> Result<u64, ()> {
    with_ectx(scope, |ctx| {
        let r = ctx.extobj::<JsonRef>(idx)?;
        let value = r
            .view(|x| match x {
                serde_json::Value::Bool(value) => Some(*value),
                _ => None,
            })
            .inspect_err(|()| ctx.error = INVALID_JSON_REF_ERROR.into())?;
        let Some(value) = value else {
            return Ok(-1i64 as u64);
        };
        const VALUE_LEN: u64 = 1;
        if out_len != VALUE_LEN {
            return Err(());
        }
        scope.user_memory_mut(out_ptr, out_len)?[0] = u8::from(value);
        Ok(VALUE_LEN)
    })
}

pub fn h_json_new_object(
    scope: &async_ebpf::program::HelperScope,
    _: u64,
    _: u64,
    _: u64,
    _: u64,
    _: u64,
) -> Result<u64, ()> {
    with_ectx(scope, |ctx| {
        let json = serde_json::Value::Object(serde_json::Map::new());
        ctx.alloc_memory_footprint(estimate_json_memory_usage(&json) as u64)?;
        let r = JsonRef::new(json);
        ctx.alloc_extobj(r)
    })
}

pub fn h_json_new_array(
    scope: &async_ebpf::program::HelperScope,
    _: u64,
    _: u64,
    _: u64,
    _: u64,
    _: u64,
) -> Result<u64, ()> {
    with_ectx(scope, |ctx| {
        let json = serde_json::Value::Array(Vec::new());
        ctx.alloc_memory_footprint(estimate_json_memory_usage(&json) as u64)?;
        let r = JsonRef::new(json);
        ctx.alloc_extobj(r)
    })
}

pub fn h_json_clone(
    scope: &async_ebpf::program::HelperScope,
    idx: u64,
    _: u64,
    _: u64,
    _: u64,
    _: u64,
) -> Result<u64, ()> {
    with_ectx(scope, |ctx| {
        let r = ctx.extobj::<JsonRef>(idx)?;
        let cloned = r
            .view(|x| x.clone())
            .inspect_err(|()| ctx.error = INVALID_JSON_REF_ERROR.into())?;
        ctx.alloc_memory_footprint(estimate_json_memory_usage(&cloned) as u64)?;
        let r = JsonRef::new(cloned);
        ctx.alloc_extobj(r)
    })
}

const JSON_TYPE_NULL: u64 = 0;
const JSON_TYPE_BOOL: u64 = 1;
const JSON_TYPE_NUMBER: u64 = 2;
const JSON_TYPE_STRING: u64 = 3;
const JSON_TYPE_ARRAY: u64 = 4;
const JSON_TYPE_OBJECT: u64 = 5;

pub fn h_json_type(
    scope: &async_ebpf::program::HelperScope,
    idx: u64,
    _: u64,
    _: u64,
    _: u64,
    _: u64,
) -> Result<u64, ()> {
    with_ectx(scope, |ctx| {
        let r = ctx.extobj::<JsonRef>(idx)?;
        r.view(|x| match x {
            serde_json::Value::Null => JSON_TYPE_NULL,
            serde_json::Value::Bool(_) => JSON_TYPE_BOOL,
            serde_json::Value::Number(_) => JSON_TYPE_NUMBER,
            serde_json::Value::String(_) => JSON_TYPE_STRING,
            serde_json::Value::Array(_) => JSON_TYPE_ARRAY,
            serde_json::Value::Object(_) => JSON_TYPE_OBJECT,
        })
        .inspect_err(|()| ctx.error = INVALID_JSON_REF_ERROR.into())
    })
}

pub fn h_json_len(
    scope: &async_ebpf::program::HelperScope,
    idx: u64,
    _: u64,
    _: u64,
    _: u64,
    _: u64,
) -> Result<u64, ()> {
    with_ectx(scope, |ctx| {
        let r = ctx.extobj::<JsonRef>(idx)?;
        r.view(|x| match x {
            serde_json::Value::Array(arr) => arr.len() as u64,
            serde_json::Value::Object(obj) => obj.len() as u64,
            serde_json::Value::String(s) => s.len() as u64,
            _ => -1i64 as u64,
        })
        .inspect_err(|()| ctx.error = INVALID_JSON_REF_ERROR.into())
    })
}

pub fn h_json_set(
    scope: &async_ebpf::program::HelperScope,
    idx: u64,
    key_ptr: u64,
    key_len: u64,
    value_idx: u64,
    _: u64,
) -> Result<u64, ()> {
    let key = scope.user_memory(key_ptr, key_len)?;
    let Ok(key) = std::str::from_utf8(key) else {
        return Ok(-1i64 as u64);
    };
    let key = key.to_string();
    with_ectx(scope, |ctx| {
        let value_ref = ctx.extobj::<JsonRef>(value_idx)?;
        let value = value_ref
            .view(|x| x.clone())
            .inspect_err(|()| ctx.error = INVALID_JSON_REF_ERROR.into())?;
        let r = ctx.extobj::<JsonRef>(idx)?;
        r.modify(|x| match x {
            serde_json::Value::Object(obj) => {
                obj.insert(key.clone(), value);
                Ok(0)
            }
            _ => Ok(-1i64 as u64),
        })
        .inspect_err(|()| ctx.error = INVALID_JSON_REF_ERROR.into())?
    })
}

pub fn h_json_remove(
    scope: &async_ebpf::program::HelperScope,
    idx: u64,
    key_ptr: u64,
    key_len: u64,
    _: u64,
    _: u64,
) -> Result<u64, ()> {
    let key = scope.user_memory(key_ptr, key_len)?;
    let Ok(key) = std::str::from_utf8(key) else {
        return Ok(-1i64 as u64);
    };
    with_ectx(scope, |ctx| {
        let r = ctx.extobj::<JsonRef>(idx)?;
        r.modify(|x| match x {
            serde_json::Value::Object(obj) => {
                if obj.remove(key).is_some() {
                    Ok(0)
                } else {
                    Ok(-1i64 as u64)
                }
            }
            _ => Ok(-1i64 as u64),
        })
        .inspect_err(|()| ctx.error = INVALID_JSON_REF_ERROR.into())?
    })
}

pub fn h_json_array_push(
    scope: &async_ebpf::program::HelperScope,
    idx: u64,
    value_idx: u64,
    _: u64,
    _: u64,
    _: u64,
) -> Result<u64, ()> {
    with_ectx(scope, |ctx| {
        let value_ref = ctx.extobj::<JsonRef>(value_idx)?;
        let value = value_ref
            .view(|x| x.clone())
            .inspect_err(|()| ctx.error = INVALID_JSON_REF_ERROR.into())?;
        let r = ctx.extobj::<JsonRef>(idx)?;
        r.modify(|x| match x {
            serde_json::Value::Array(arr) => {
                arr.push(value);
                Ok(arr.len() as u64)
            }
            _ => Ok(-1i64 as u64),
        })
        .inspect_err(|()| ctx.error = INVALID_JSON_REF_ERROR.into())?
    })
}

pub fn h_json_array_set(
    scope: &async_ebpf::program::HelperScope,
    idx: u64,
    array_index: u64,
    value_idx: u64,
    _: u64,
    _: u64,
) -> Result<u64, ()> {
    with_ectx(scope, |ctx| {
        let value_ref = ctx.extobj::<JsonRef>(value_idx)?;
        let value = value_ref
            .view(|x| x.clone())
            .inspect_err(|()| ctx.error = INVALID_JSON_REF_ERROR.into())?;
        let r = ctx.extobj::<JsonRef>(idx)?;
        r.modify(|x| match x {
            serde_json::Value::Array(arr) => {
                if let Some(elem) = arr.get_mut(array_index as usize) {
                    *elem = value;
                    Ok(0)
                } else {
                    Ok(-1i64 as u64)
                }
            }
            _ => Ok(-1i64 as u64),
        })
        .inspect_err(|()| ctx.error = INVALID_JSON_REF_ERROR.into())?
    })
}

pub fn h_json_set_string(
    scope: &async_ebpf::program::HelperScope,
    idx: u64,
    value_ptr: u64,
    value_len: u64,
    _: u64,
    _: u64,
) -> Result<u64, ()> {
    let value = scope.user_memory(value_ptr, value_len)?;
    let Ok(value) = std::str::from_utf8(value) else {
        return Ok(-1i64 as u64);
    };
    let value = value.to_string();
    with_ectx(scope, |ctx| {
        let r = ctx.extobj::<JsonRef>(idx)?;
        r.modify(|x| {
            *x = serde_json::Value::String(value);
            Ok(0)
        })
        .inspect_err(|()| ctx.error = INVALID_JSON_REF_ERROR.into())?
    })
}

pub fn h_json_set_i64(
    scope: &async_ebpf::program::HelperScope,
    idx: u64,
    value: u64,
    _: u64,
    _: u64,
    _: u64,
) -> Result<u64, ()> {
    let value = value as i64;
    with_ectx(scope, |ctx| {
        let r = ctx.extobj::<JsonRef>(idx)?;
        r.modify(|x| {
            *x = serde_json::Value::Number(serde_json::Number::from(value));
            Ok(0)
        })
        .inspect_err(|()| ctx.error = INVALID_JSON_REF_ERROR.into())?
    })
}

pub fn h_json_set_bool(
    scope: &async_ebpf::program::HelperScope,
    idx: u64,
    value: u64,
    _: u64,
    _: u64,
    _: u64,
) -> Result<u64, ()> {
    let value = value != 0;
    with_ectx(scope, |ctx| {
        let r = ctx.extobj::<JsonRef>(idx)?;
        r.modify(|x| {
            *x = serde_json::Value::Bool(value);
            Ok(0)
        })
        .inspect_err(|()| ctx.error = INVALID_JSON_REF_ERROR.into())?
    })
}

pub fn h_json_set_null(
    scope: &async_ebpf::program::HelperScope,
    idx: u64,
    _: u64,
    _: u64,
    _: u64,
    _: u64,
) -> Result<u64, ()> {
    with_ectx(scope, |ctx| {
        let r = ctx.extobj::<JsonRef>(idx)?;
        r.modify(|x| {
            *x = serde_json::Value::Null;
            Ok(0)
        })
        .inspect_err(|()| ctx.error = INVALID_JSON_REF_ERROR.into())?
    })
}

pub fn h_json_respond(
    scope: &async_ebpf::program::HelperScope,
    status: u64,
    idx: u64,
    _: u64,
    _: u64,
    _: u64,
) -> Result<u64, ()> {
    let status = u16::try_from(status).map_err(|_| ())?;
    with_ectx(scope, |ctx| {
        let r = ctx.extobj::<JsonRef>(idx)?;
        let body = r
            .view(|x| serde_json::to_vec(x))
            .inspect_err(|()| ctx.error = INVALID_JSON_REF_ERROR.into())?
            .map_err(|_| ())?;
        ctx.alloc_memory_footprint(body.len() as u64)?;
        ctx.metadata.borrow_mut().insert(
            "zs.response.header.content-type".to_string(),
            "application/json".to_string(),
        );
        ctx.response = Some(ScriptResponse {
            status,
            body,
            content_type: Some("application/json".to_string()),
            force_close: false,
            headers: Vec::new(),
        });
        Ok(0)
    })
}

pub fn h_req_body_json(
    scope: &async_ebpf::program::HelperScope,
    _: u64,
    _: u64,
    _: u64,
    _: u64,
    _: u64,
) -> Result<u64, ()> {
    let body_source = with_ectx(scope, |ctx| Ok(ctx.body_source.clone()))?;

    scope.post_task(async move {
        let result = body_source.read().await;
        move |scope: &HelperScope| match result {
            Ok(bytes) => {
                let data: serde_json::Value = match serde_json::from_slice(&bytes) {
                    Ok(x) => x,
                    Err(_) => return Ok(-1i64 as u64),
                };
                with_ectx(scope, |ctx| {
                    ctx.alloc_memory_footprint(estimate_json_memory_usage(&data) as u64)?;
                    ctx.alloc_extobj(JsonRef::new(data))
                })
            }
            Err(()) => Ok(-1i64 as u64),
        }
    });
    Ok(0)
}
pub(crate) fn estimate_json_memory_usage(root: &serde_json::Value) -> usize {
    use serde_json::Value;

    let mut total: usize = 0;
    let mut stack: Vec<&Value> = Vec::new();
    stack.push(root);

    while let Some(v) = stack.pop() {
        total += size_of::<Value>();

        match v {
            Value::Null | Value::Bool(_) | Value::Number(_) => {}

            Value::String(s) => {
                total += s.len();
            }

            Value::Array(a) => {
                for child in a.iter() {
                    stack.push(child);
                }
            }

            Value::Object(map) => {
                for (k, child) in map {
                    total += size_of::<String>() + k.len();
                    stack.push(child);
                }
            }
        }
    }

    total
}
