#ifndef ZEROSERVE_SDK_ZEROSERVE_H
#define ZEROSERVE_SDK_ZEROSERVE_H

#define ZS_STR(s) (s), zs_strlen((s))
#define ZS_STR_WITH_NULL(s) (s), (zs_strlen((s)) + 1)

typedef unsigned long long uint64_t;
typedef long long int64_t;
typedef unsigned int uint32_t;
typedef int int32_t;
typedef unsigned short uint16_t;
typedef short int16_t;
typedef unsigned char uint8_t;
typedef char int8_t;
typedef unsigned long size_t;
typedef long ssize_t;

#define ZS_SECTION(name) __attribute__((section(name)))
#define ZS_ENTRY ZS_SECTION("zeroserve.request")
#define ZS_TLS_ENTRY ZS_SECTION("zeroserve.tls")
#define ZS_INLINE __attribute__((always_inline))
/* Marks a definition that a given generated script may legitimately not
 * reference, suppressing clang's -Wunused-function. */
#define ZS_MAYBE_UNUSED __attribute__((unused))

/* Define a function callable from other scripts via
 * zs_call(script, ..., "<name>", ..., input). It is placed in the
 * "zeroserve.call.<name>" code section and receives the inbound JSON handle by
 * value through the user-named parameter, returning a JSON handle (or a
 * negative value to signal failure):
 *
 *   ZS_CALL_ENTRY(greet, input) {
 *     zs_s64 out = zs_json_new_object();
 *     zs_json_set_string(out, ZS_STR("hello"));
 *     return out;            // input is the caller's argument
 *   }
 */
#define ZS_CALL_ENTRY(name, input)                                             \
  static zs_s64 zs__call_body_##name(zs_s64 input);                            \
  ZS_SECTION("zeroserve.call." #name)                                          \
  zs_s64 zs__call_entry_##name(zs_s64 *zs__call_input) {                       \
    return zs__call_body_##name(*zs__call_input);                              \
  }                                                                            \
  static zs_s64 zs__call_body_##name(zs_s64 input)

/* Define an init hook placed in the "zeroserve.init.<name>" code section. It is
 * run once at load time (not per request), receives no input, and returns a
 * JSON handle describing configuration that the host reads back. A negative
 * return signals failure. Used, e.g., for ACME configuration:
 *
 *   ZS_INIT_ENTRY(acme_config) {
 *     zs_s64 cfg = zs_json_new_object();
 *     zs_s64 domains = zs_json_new_array();
 *     zs_s64 d = zs_json_new_object();
 *     zs_json_set_string(d, ZS_STR("example.com"));
 *     zs_json_array_push(domains, d);
 *     zs_json_set(cfg, ZS_STR("domains"), domains);
 *     return cfg;
 *   }
 */
#define ZS_INIT_ENTRY(name)                                                    \
  static zs_s64 zs__init_body_##name(void);                                    \
  ZS_SECTION("zeroserve.init." #name)                                          \
  zs_s64 zs__init_entry_##name(void) { return zs__init_body_##name(); }        \
  static zs_s64 zs__init_body_##name(void)
#define ZS_MIN(a, b) ((a) < (b) ? (a) : (b))
#define ZS_MAX(a, b) ((a) > (b) ? (a) : (b))

#define ZS_BASE64_STANDARD 0
#define ZS_BASE64_STANDARD_NO_PAD 1
#define ZS_BASE64_URL 2
#define ZS_BASE64_URL_NO_PAD 3

#define ZS_HEX_LOWERCASE 0
#define ZS_HEX_UPPERCASE 1

#define ZS_JSON_NULL 0
#define ZS_JSON_BOOL 1
#define ZS_JSON_NUMBER 2
#define ZS_JSON_STRING 3
#define ZS_JSON_ARRAY 4
#define ZS_JSON_OBJECT 5

typedef uint64_t zs_u64;
typedef int64_t zs_s64;
typedef uint32_t zs_u32;
typedef int32_t zs_s32;
typedef uint16_t zs_u16;
typedef int16_t zs_s16;
typedef uint8_t zs_u8;
typedef int8_t zs_s8;

extern zs_s64 zs_log(const char *msg, zs_u64 len);
extern zs_u64 zs_now_ms(void);
extern zs_s64 zs_version(char *out, zs_u64 out_len);
extern zs_s64 zs_env_get(const char *name, zs_u64 name_len, char *out,
                         zs_u64 out_len);
extern zs_s64 zs_getrandom(void *out, zs_u64 out_len);
extern zs_s64 zs_sha256(const void *data, zs_u64 data_len, void *out,
                        zs_u64 out_len);
extern zs_s64 zs_hmac_sha256(const void *key, zs_u64 key_len, const void *msg,
                             zs_u64 msg_len, void *out);
extern zs_s64 zs_base64_encode(const void *data, zs_u64 data_len, void *out,
                               zs_u64 out_len, zs_u64 encoding);
extern zs_s64 zs_base64_decode_in_place(void *buf, zs_u64 buf_len,
                                        zs_u64 encoding);
extern zs_s64 zs_hex_encode(const void *data, zs_u64 data_len, void *out,
                            zs_u64 out_len, zs_u64 case_flag);
extern zs_s64 zs_hex_decode_in_place(void *buf, zs_u64 buf_len);

extern zs_s64 zs_json_parse(const void *data, zs_u64 data_len);
extern zs_s64 zs_load_static_json(const char *path, zs_u64 path_len);
extern zs_s64 zs_load_file_metadata(const char *path, zs_u64 path_len);
extern zs_s64 zs_json_reset(zs_u64 json);
extern zs_s64 zs_json_get(zs_u64 json, const char *key, zs_u64 key_len);
extern zs_s64 zs_json_array_get(zs_u64 json, zs_u64 array_index);
extern zs_s64 zs_json_read_string(zs_u64 json, char *out, zs_u64 out_len);
extern zs_s64 zs_json_read_i64(zs_u64 json, void *out, zs_u64 out_len);
extern zs_s64 zs_json_read_bool(zs_u64 json, void *out, zs_u64 out_len);
extern zs_s64 zs_object_free(zs_u64 idx);

extern zs_s64 zs_json_new_object(void);
extern zs_s64 zs_json_new_array(void);
extern zs_s64 zs_json_clone(zs_u64 json);
extern zs_s64 zs_json_len(zs_u64 json);
extern zs_s64 zs_json_type(zs_u64 json);
extern zs_s64 zs_json_set(zs_u64 json, const char *key, zs_u64 key_len,
                          zs_u64 value_json);
extern zs_s64 zs_json_remove(zs_u64 json, const char *key, zs_u64 key_len);
extern zs_s64 zs_json_array_push(zs_u64 json, zs_u64 value_json);
extern zs_s64 zs_json_array_set(zs_u64 json, zs_u64 index, zs_u64 value_json);
extern zs_s64 zs_json_set_string(zs_u64 json, const char *value,
                                 zs_u64 value_len);
extern zs_s64 zs_json_set_i64(zs_u64 json, zs_s64 value);
extern zs_s64 zs_json_set_bool(zs_u64 json, zs_u64 value);
extern zs_s64 zs_json_set_null(zs_u64 json);
extern zs_s64 zs_json_respond(zs_u64 status, zs_u64 json);

/* Invoke another script's `zeroserve.call.<func>` entrypoint (defined with
 * ZS_CALL_ENTRY), passing a JSON handle and receiving one back. `script` names
 * the target script file (with or without the `.o` extension); `func` is the
 * exported call name. The input JSON is deep-copied into the callee, and its
 * returned JSON is copied back as a fresh handle in the caller's object table.
 *
 * Returns a new JSON object handle on success (free it with zs_object_free), or
 * -1 if the call could not be completed: unknown script or function, the callee
 * trapped or returned a negative handle, or the maximum call depth was reached.
 * The two string arguments pair naturally with ZS_STR:
 *
 *   zs_s64 reply = zs_call(ZS_STR("greeter"), ZS_STR("greet"), payload);
 */
extern zs_s64 zs_call(const char *script, zs_u64 script_len, const char *func,
                      zs_u64 func_len, zs_s64 json_handle);
/* Register a per-request response hook. The hook is a `ZS_CALL_ENTRY` function
 * that runs after response headers exist and before they are written to the
 * client. Pass an empty script name to target the current script. */
extern zs_s64 zs_res_hook(const char *script, zs_u64 script_len,
                          const char *func, zs_u64 func_len,
                          zs_s64 json_handle);
extern zs_s64 zs_res_hooks_clear(void);

extern zs_s64 zs_req_body_json(void);

extern zs_s64 zs_req_method(char *out, zs_u64 out_len);
extern zs_s64 zs_req_set_method(const char *method, zs_u64 method_len);
extern zs_s64 zs_caddy_rewrite_method(const char *method_template,
                                      zs_u64 method_template_len);
extern zs_s64 zs_req_path(char *out, zs_u64 out_len);
extern zs_s64 zs_req_normalized_path(char *out, zs_u64 out_len);
extern zs_s64 zs_caddy_path_regexp_subject(char *out, zs_u64 out_len);
extern zs_s64 zs_req_uri(char *out, zs_u64 out_len);
extern zs_s64 zs_req_set_uri(const char *uri, zs_u64 uri_len);
extern zs_s64 zs_req_query(char *out, zs_u64 out_len);
extern zs_s64 zs_caddy_rewrite_uri(const char *uri_template,
                                   zs_u64 uri_template_len);
extern zs_s64 zs_req_rewrite_uri(const char *ops_json, zs_u64 ops_json_len);
extern zs_s64 zs_req_rewrite_query(const char *ops_json, zs_u64 ops_json_len);
extern zs_s64 zs_req_scheme(char *out, zs_u64 out_len);
extern zs_s64 zs_req_proto_major(void);
extern zs_s64 zs_req_proto_minor(void);
extern zs_s64 zs_req_peer(char *out, zs_u64 out_len);
extern zs_s64 zs_req_is_tls(void);
extern zs_s64 zs_req_tls_handshake_complete(void);
extern zs_s64 zs_caddy_tls_certificate(const char *cert_path,
                                       zs_u64 cert_path_len,
                                       const char *key_path,
                                       zs_u64 key_path_len);
extern zs_s64 zs_caddy_tls_client_auth(const char *config_json,
                                       zs_u64 config_json_len);
extern zs_s64 zs_req_remote_ip_matches(const char *ranges_json,
                                       zs_u64 ranges_json_len);
extern zs_s64 zs_caddy_remote_ip_matches(const char *ranges_json,
                                         zs_u64 ranges_json_len);
extern zs_s64 zs_caddy_client_ip_matches(const char *config_json,
                                         zs_u64 config_json_len);
extern zs_s64 zs_caddy_vars_set(const char *vars_json, zs_u64 vars_json_len);
extern zs_s64 zs_caddy_vars_match(const char *vars_json, zs_u64 vars_json_len);
extern zs_s64 zs_caddy_vars_match_expanded_keys(const char *vars_json,
                                                zs_u64 vars_json_len);
extern zs_s64 zs_caddy_vars_regexp_match(const char *vars_json,
                                         zs_u64 vars_json_len);
extern zs_s64 zs_caddy_vars_regexp_match_expanded_keys(
    const char *vars_json, zs_u64 vars_json_len);
extern zs_s64 zs_caddy_map(const char *config_json, zs_u64 config_json_len);
extern zs_s64 zs_caddy_response_headers(const char *ops_json,
                                        zs_u64 ops_json_len);
/* Enable Caddy-compatible streaming response compression (the `encode`
 * handler). `config_json` is the normalized encode config (encodings, prefer,
 * minimum_length, match). The runtime negotiates the encoding from the
 * request's Accept-Encoding and compresses the response body. */
extern zs_s64 zs_caddy_encode(const char *config_json, zs_u64 config_json_len);
extern zs_s64 zs_caddy_path_match(const char *pattern, zs_u64 pattern_len);
/* Match the request path against NUL-separated patterns, in order; returns 1
 * on the first match. One call covers a whole `path` matcher list. */
extern zs_s64 zs_caddy_path_match_multi(const char *patterns,
                                        zs_u64 patterns_len);
extern zs_s64 zs_caddy_query_match(const char *name_template,
                                   zs_u64 name_template_len,
                                   const char *value_template,
                                   zs_u64 value_template_len);
extern zs_s64 zs_caddy_query_present(const char *name_template,
                                     zs_u64 name_template_len);
extern zs_s64 zs_caddy_query_empty(void);
extern zs_s64 zs_caddy_header_match(const char *name, zs_u64 name_len,
                                    const char *value_template,
                                    zs_u64 value_template_len);
extern zs_s64 zs_caddy_header_match_expanded(const char *name,
                                             zs_u64 name_len,
                                             const char *value_template,
                                             zs_u64 value_template_len);
extern zs_s64 zs_caddy_header_present(const char *name, zs_u64 name_len);
extern zs_s64 zs_caddy_header_present_expanded(const char *name,
                                               zs_u64 name_len);
extern zs_s64 zs_caddy_header_regexp_match(const char *name, zs_u64 name_len,
                                           const char *config_json,
                                           zs_u64 config_json_len);
extern zs_s64 zs_caddy_header_regexp_match_expanded(
    const char *name, zs_u64 name_len, const char *config_json,
    zs_u64 config_json_len);
extern zs_s64 zs_caddy_req_header_first_prefix(const char *name,
                                               zs_u64 name_len,
                                               const char *prefix,
                                               zs_u64 prefix_len);
extern zs_s64 zs_caddy_regex_match(const char *input, zs_u64 input_len,
                                   const char *config_json,
                                   zs_u64 config_json_len);
extern zs_s64 zs_caddy_expr_in(const char *input_template,
                               zs_u64 input_template_len,
                               const char *values_json, zs_u64 values_json_len);
extern zs_s64 zs_caddy_expr_eq(const char *left_template,
                               zs_u64 left_template_len,
                               const char *right_template,
                               zs_u64 right_template_len);
extern zs_s64 zs_caddy_file_match(const char *config_json,
                                  zs_u64 config_json_len);
extern zs_s64 zs_caddy_expand(const char *input, zs_u64 input_len, char *out,
                              zs_u64 out_len);
extern zs_s64 zs_caddy_expand_known(const char *input, zs_u64 input_len,
                                    char *out, zs_u64 out_len);
extern zs_s64 zs_caddy_respond(const char *status_template,
                               zs_u64 status_template_len,
                               const char *body_template,
                               zs_u64 body_template_len);
extern zs_s64 zs_caddy_respond_static(const char *status_template,
                                      zs_u64 status_template_len,
                                      const char *config_json,
                                      zs_u64 config_json_len);
extern zs_s64 zs_caddy_set_error(const char *status_template,
                                 zs_u64 status_template_len,
                                 const char *message_template,
                                 zs_u64 message_template_len);
extern zs_s64 zs_caddy_adopt_call_result(zs_u64 result_json);
extern zs_s64 zs_caddy_basic_auth(const char *config_json,
                                  zs_u64 config_json_len);
extern zs_s64 zs_caddy_reverse_proxy_url(const char *url_template,
                                         zs_u64 url_template_len, char *out,
                                         zs_u64 out_len);
extern zs_s64 zs_caddy_reverse_proxy_forwarded(const char *config_json,
                                               zs_u64 config_json_len);
extern zs_s64 zs_caddy_reverse_proxy_request_headers(const char *ops_json,
                                                     zs_u64 ops_json_len);
extern zs_s64 zs_caddy_reverse_proxy_rewrite(const char *config_json,
                                             zs_u64 config_json_len);

/* Return a JSON object handle describing the current connection's transport
 * state. Free with zs_object_free. The object has fields:
 *   "tls"     (bool)         - true if served over TLS
 *   "tls_handshake_complete" (bool) - true if TLS is complete
 *   "alpn"    (string|null)  - negotiated ALPN, e.g. "h2" / "http/1.1"
 *   "sni"     (object)       - { "inner": string|null, "outer": string|null }
 *   "ech"     (object|null)  - null when the server has no ECH keys loaded;
 *                              otherwise { "accepted": bool }
 *   "fingerprint" (object)   - { "ja4": string|null } for the TLS client JA4
 *                              fingerprint; null on plaintext connections
 *
 * "sni.inner" is the server name being served: the real, protected name when
 * ECH was accepted, or the cleartext SNI for plain TLS. "sni.outer" is the
 * cleartext ECH public name when ECH was accepted (null for plain TLS or
 * rejected ECH).
 *
 * "ech.accepted" is true when BoringSSL decrypted the client's Encrypted
 * Client Hello (the real SNI is protected). false means ECH was not accepted
 * on this connection (the client offered a stale/absent config and is being
 * served against the public-name certificate). On rejection BoringSSL returns
 * retry_configs to the client automatically.
 *
 * "fingerprint.ja4" is the JA4 TLS client fingerprint computed from the
 * ClientHello, for example "t13d1516h2_8daaf6152771_e5627efa2ab1".
 */
extern zs_s64 zs_connection_info(void);

extern zs_s64 zs_req_header(const char *name, zs_u64 name_len, char *out,
                            zs_u64 out_len);
extern zs_s64 zs_req_set_header(const char *name, zs_u64 name_len,
                                const char *value, zs_u64 value_len);
extern zs_s64 zs_req_append_header(const char *name, zs_u64 name_len,
                                   const char *value, zs_u64 value_len);
extern zs_s64 zs_req_delete_header(const char *pattern, zs_u64 pattern_len);
extern zs_s64 zs_req_replace_header(const char *op_json, zs_u64 op_json_len);
extern zs_s64 zs_req_query_param(const char *name, zs_u64 name_len, char *out,
                                 zs_u64 out_len);
extern zs_s64 zs_req_query_param_matches(const char *name, zs_u64 name_len,
                                         const char *value, zs_u64 value_len);
extern zs_s64 zs_req_body_limit(zs_u64 max_size);

extern zs_s64 zs_meta_get(const char *key, zs_u64 key_len, char *out,
                          zs_u64 out_len);
extern zs_s64 zs_meta_set(const char *key, zs_u64 key_len, const char *value,
                          zs_u64 value_len);
extern zs_s64 zs_res_replace_header(const char *op_json, zs_u64 op_json_len);
extern zs_s64 zs_res_status(void);
extern zs_s64 zs_res_set_status(zs_u64 status);
extern zs_s64 zs_res_header(const char *name, zs_u64 name_len, char *out,
                            zs_u64 out_len);
extern zs_s64 zs_res_continue_request(void);
extern zs_s64 zs_caddy_res_header_match(const char *name, zs_u64 name_len,
                                        const char *value, zs_u64 value_len);
extern zs_s64 zs_caddy_res_header_present(const char *name, zs_u64 name_len);
extern zs_s64 zs_caddy_copy_response_headers(const char *config_json,
                                             zs_u64 config_json_len);
extern zs_s64 zs_response_pending(void);
extern zs_s64 zs_response_clear(void);

/* Close the current request without writing any HTTP response. Terminal. */
extern zs_s64 zs_abort(void);
extern zs_s64 zs_respond(zs_u64 status, const void *body, zs_u64 body_len);

extern zs_s64 zs_reverse_proxy(const char *backend_url, zs_u64 backend_url_len);
/* Caddy-compatible file server helper. Returns:
 *   0 = handled current request
 *   1 = pass_thru miss; continue to the next handler
 *   2 = hard file-server error; Caddy error metadata has been populated
 */
extern zs_s64 zs_file_server(const char *config_json, zs_u64 config_json_len);

/* AWS SigV4 signing */

typedef struct {
  /* Credentials */
  const void *access_key;
  zs_u64 access_key_len;
  const void *secret_key;
  zs_u64 secret_key_len;

  /* Request metadata */
  const void *region;
  zs_u64 region_len;
  const void *service;
  zs_u64 service_len;
  const void *method;
  zs_u64 method_len;
  const void *uri;
  zs_u64 uri_len;

  /* Headers as JSON object handle */
  zs_u64 headers_json;

  /* Body hash: hex-encoded SHA256 or "UNSIGNED-PAYLOAD" */
  const void *body_hash;
  zs_u64 body_hash_len;

  /* Unix timestamp in milliseconds */
  zs_s64 timestamp_ms;

  /* Output buffer */
  void *out;
  zs_u64 out_len;
} zs_aws_v4_sign_params;

/* Generate AWS SigV4 Authorization header value (not including header name).
 * Returns the generated string length capped to out_len, or -1/-2 on error. If
 * out_len is 0, returns 0 without writing. The output is always null-terminated
 * if out_len > 0 and space permits. */
extern zs_s64
zs_aws_v4_authorization_header(const zs_aws_v4_sign_params *params,
                               zs_u64 params_len);

/* Generate AWS SigV4 pre-signed URL.
 * Returns the generated string length capped to out_len, or -1/-2 on error. If
 * out_len is 0, returns 0 without writing. The output is always null-terminated
 * if out_len > 0 and space permits.
 * The output is a URL path with query string containing the signature
 * parameters (X-Amz-Algorithm, X-Amz-Credential, X-Amz-Date, X-Amz-Expires,
 * X-Amz-SignedHeaders, X-Amz-Signature). */
extern zs_s64 zs_aws_v4_presigned_url(const zs_aws_v4_sign_params *params,
                                      zs_u64 params_len, zs_u64 expires_secs);

/* Rate limiting */

#define ZS_RATE_LIMIT_ALLOWED 0
#define ZS_RATE_LIMIT_EXCEEDED_SECOND 1
#define ZS_RATE_LIMIT_EXCEEDED_MINUTE 2
#define ZS_RATE_LIMIT_EXCEEDED_HOUR 3
#define ZS_RATE_LIMIT_EXCEEDED_BUCKET_LIMIT 4

/* Check rate limit for a key with per-second, per-minute, and per-hour limits.
 *
 * Arguments:
 *   key, key_len     - Arbitrary key bytes (e.g., IP address, API key, user ID)
 *   per_second       - Max requests per second (0 = unlimited)
 *   per_minute       - Max requests per minute (0 = unlimited)
 *   per_hour         - Max requests per hour (0 = unlimited)
 *
 * Returns:
 *   0 = allowed
 *   1 = per-second limit exceeded
 *   2 = per-minute limit exceeded
 *   3 = per-hour limit exceeded
 *   4 = bucket limit exceeded (too many unique keys)
 *  -1 = error (invalid parameters or key too long)
 *
 * Example:
 *   // Rate limit by IP: 10 req/s, 100 req/min, 1000 req/hour
 *   char peer[64];
 *   zs_req_peer(peer, sizeof(peer));
 *   int64_t result = zs_rate_limit(ZS_STR(peer), 10, 100, 1000);
 *   if (result == ZS_RATE_LIMIT_EXCEEDED_SECOND) {
 *       zs_respond(429, ZS_STR("{\"error\":\"rate limit exceeded\"}"));
 *   }
 */
extern zs_s64 zs_rate_limit(const void *key, zs_u64 key_len, zs_u64 per_second,
                            zs_u64 per_minute, zs_u64 per_hour);

/* OAuth2 / OIDC login (Authorization Code + PKCE)
 *
 * zeroserve acts as the OAuth2 client (Relying Party). The three flow steps map
 * to terminal helpers (they set the HTTP response, so the script should return
 * right after calling them):
 *
 *   - zs_oidc_begin_login: redirect an unauthenticated user to the IdP.
 *   - zs_oidc_handle_callback: handle the IdP redirect on your redirect_uri path.
 *   - zs_oidc_session_verify: check the session cookie on every other request.
 *   - zs_oidc_logout: clear the session.
 *
 * Configuration is passed as a JSON object handle (`cfg`), built with
 * zs_json_parse or zs_json_new_object + zs_json_set_string. Recognised keys:
 *
 *   "issuer"                 (string, optional)  - enables OIDC discovery
 *   "authorization_endpoint" (string, optional)  - overrides discovery
 *   "token_endpoint"         (string, optional)  - overrides discovery
 *   "client_id"              (string, required)
 *   "client_secret"          (string, required)
 *   "redirect_uri"           (string, required)  - must match the IdP config
 *   "scope"                  (string, optional)  - default "openid profile email"
 *   "cookie_secret"          (string, required)  - >= 16 bytes, keep STABLE
 *   "session_ttl_secs"       (number, optional)  - default 3600
 *
 * Provide either "issuer" (for discovery) or the two explicit endpoints
 * (explicit endpoints take precedence). Login state (PKCE verifier, CSRF state,
 * nonce) and the session are carried in sealed (encrypted + authenticated,
 * XChaCha20-Poly1305) cookies; there is no server-side session store. The
 * "cookie_secret" must stay stable across restarts/instances or existing
 * sessions are invalidated.
 *
 * NOTE: The id_token is fetched directly from the token endpoint over a
 * server-validated TLS connection, so per OIDC Core 3.1.3.7 its claims
 * (iss/aud/exp/nonce) are validated but its signature is NOT separately
 * verified against a JWKS.
 */

/* All four helpers below return `-1` on configuration errors (bad `cfg`
 * handle, missing client_id/redirect_uri, weak cookie_secret). `-1` is a
 * normal return value — the script keeps running and is expected to decide
 * what to do (e.g. respond 500, fall through to other middleware). The
 * runtime logs the underlying reason to stderr. */

/* Begin login: set the sealed state cookie and 302-redirect to the IdP.
 * `return_to` is stored and the user is sent back there after callback.
 * Terminal on success. Returns 0 on success, -1 on configuration error. */
extern zs_s64 zs_oidc_begin_login(zs_s64 cfg, const char *return_to,
                                  zs_u64 return_to_len);

/* Handle the IdP redirect: reads `code` and `state` from the current request,
 * validates state against the state cookie, exchanges the code (+PKCE verifier)
 * at the token endpoint, validates id_token claims, sets the sealed session
 * cookie, and 302-redirects to the stored return_to. Terminal on success.
 * Returns 0 on success, -1 on configuration error. A bad/missing state sets a
 * 400 and returns 0; a token-exchange failure sets a 502 and returns 0. */
extern zs_s64 zs_oidc_handle_callback(zs_s64 cfg);

/* Verify the session cookie on the current request. Returns a JSON object handle
 * of the identity claims (e.g. "sub", "email") on success, 0 if there is no
 * valid session, or -1 on configuration error. NOT terminal: the script decides
 * what to do (e.g. call zs_oidc_begin_login when 0). Free the handle with
 * zs_object_free. */
extern zs_s64 zs_oidc_session_verify(zs_s64 cfg);

/* Clear the session cookie. If `end_session_url` is non-empty, 302-redirect
 * there (e.g. the IdP end-session endpoint); otherwise respond 200. Terminal
 * on success. Returns 0 on success, -1 on configuration error. */
extern zs_s64 zs_oidc_logout(zs_s64 cfg, const char *end_session_url,
                             zs_u64 end_session_url_len);

/* strongSwan VICI helpers */

/* Query active strongSwan IKE_SAs and find the SA whose remote-host or
 * remote-vips contains `ip`. `ip` may be a plain IP, CIDR-like IP/prefix, or a
 * socket address such as the value returned by zs_req_peer().
 *
 * The VICI socket is server-controlled via $ZEROSERVE_VICI_SOCKET. If the
 * variable is unset, this helper is disabled and returns -1. The environment
 * value may be a path or unix:// URI.
 *
 * Returns a JSON object handle on match, 0 if no SA matches, or -1 on invalid
 * input / VICI errors. Free a returned handle with zs_object_free. The object
 * contains "identity" (same as "remote_eap_id"), "remote_id", "ike_name",
 * "uniqueid", "state", "local_host", "local_id", "remote_host",
 * "remote_vips", "matched_ip", and "matched_by".
 */
extern zs_s64 zs_vici_eap_identity_by_ip(const char *ip, zs_u64 ip_len);

extern void *zs_memcpy(void *dst, const void *src, size_t n);
extern int zs_memcmp(const void *a, const void *b, size_t n);
extern void *zs_memset(void *dst, int c, size_t n);

static __attribute__((unused)) ZS_INLINE char *
zs_strncpy(char *dst, const char *src, size_t n) {
  size_t i = 0;

  for (; i < n && src[i] != '\0'; i++)
    dst[i] = src[i];
  for (; i < n; i++)
    dst[i] = '\0';
  return dst;
}

static __attribute__((unused)) ZS_INLINE char *zs_strcpy(char *dst,
                                                         const char *src) {
  size_t i = 0;

  while (src[i] != '\0') {
    dst[i] = src[i];
    i++;
  }
  dst[i] = '\0';
  return dst;
}

static __attribute__((unused)) ZS_INLINE char *zs_stpcpy(char *dst,
                                                         const char *src) {
  size_t i = 0;

  while (src[i] != '\0') {
    dst[i] = src[i];
    i++;
  }
  dst[i] = '\0';
  return dst + i;
}

static __attribute__((unused)) ZS_INLINE int zs_strcmp(const char *a,
                                                       const char *b) {
  size_t i = 0;

  while (a[i] != '\0' && b[i] != '\0') {
    if (a[i] != b[i])
      return (int)(unsigned char)a[i] - (int)(unsigned char)b[i];
    i++;
  }
  return (int)(unsigned char)a[i] - (int)(unsigned char)b[i];
}

static __attribute__((unused)) ZS_INLINE int
zs_strncmp(const char *a, const char *b, size_t n) {
  for (size_t i = 0; i < n; i++) {
    if (a[i] != b[i])
      return (int)(unsigned char)a[i] - (int)(unsigned char)b[i];
    if (a[i] == '\0')
      return 0;
  }
  return 0;
}

static __attribute__((unused)) ZS_INLINE char *zs_strrchr(const char *s,
                                                          int c) {
  const char *last = 0;
  char target = (char)c;

  for (;;) {
    if (*s == target)
      last = s;
    if (*s == '\0')
      break;
    s++;
  }

  return (char *)last;
}

static __attribute__((unused)) ZS_INLINE size_t zs_strlen(const char *s) {
  size_t len = 0;

  while (s[len] != '\0')
    len++;
  return len;
}

static __attribute__((unused)) ZS_INLINE int
zs_utoa10(unsigned int value, char *out, size_t out_size) {
  /* Need at least 2 bytes for "0" + '\0' */
  if (!out || out_size < 2)
    return -1;

  /* Special case: value == 0 */
  if (value == 0) {
    out[0] = '0';
    out[1] = '\0';
    return 1;
  }

  /* First, count digits */
  unsigned int tmp = value;
  size_t digits = 0;
  while (tmp > 0) {
    tmp /= 10;
    digits++;
  }

  /* Ensure buffer can hold digits + null terminator */
  if (digits + 1 > out_size)
    return -1;

  /* Write digits from the end */
  out[digits] = '\0';
  size_t i = digits;
  while (value > 0) {
    unsigned int digit = value % 10;
    value /= 10;
    out[--i] = (char)('0' + digit);
  }

  return (int)digits;
}

#endif
