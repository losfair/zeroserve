# Zeroserve User Manual

## Overview

Zeroserve is a high-performance, scriptable HTTP server that uses `io_uring` and eBPF. It
serves a static website from a tarball, and optionally runs eBPF request scripts.
It supports HTTP, HTTPS, hot reload, a small templating pass for text responses, and
an opt-in reverse proxy from scripts.

## Quick start

Serve a prebuilt tarball:

```bash
zeroserve --addr 0.0.0.0:8080 site.tar
```

Package a directory into a tarball and serve it:

```bash
# Create a tarball from the current directory
zeroserve --pack . > site.tar

# Serve it
zeroserve --addr 0.0.0.0:8080 site.tar
```

## Packaging a site

Zeroserve expects a tarball whose root corresponds to the site root.
Use `--pack` to build one from a directory:

```bash
zeroserve --pack ./public > site.tar
```

Packaging notes:

- All regular files under the directory are added to the tarball.
- Request scripts live under `.zeroserve/scripts/`.
- Any `.c` file in `.zeroserve/scripts/` is compiled to an `.o` eBPF object.
  The resulting `.o` is included in the tarball and the `.c` is omitted.
- If a `.c` and `.o` share the same name, the `.o` is skipped in favor of recompiling.
- Script compilation requires `clang` and `llc` on your `PATH`.

If you want the SDK header without packing:

```bash
zeroserve --dump-sdk > zeroserve.h
```

## Compiling Caddy configs to a script

Zeroserve can compile the HTTP routing portion of a Caddy config into a
zeroserve request script. `--caddy-compile` accepts either a Caddy JSON
config or a native **Caddyfile** — the input format is auto-detected (a JSON
config parses as a JSON object; anything else is treated as a Caddyfile):

```bash
zeroserve --caddy-compile caddy.json  > .zeroserve/scripts/caddy.c
zeroserve --caddy-compile Caddyfile   > .zeroserve/scripts/caddy.c
zeroserve --pack ./public > site.tar
```

To skip the manual pack-and-run steps, `--caddy` performs the whole pipeline
(adapt → compile → in-memory site tarball → serve) in one shot, keeping the
generated middleware C and the tarball entirely in memory (memfd):

```bash
zeroserve --caddy Caddyfile --addr 0.0.0.0:8080
```

### Caddyfile support

When given a Caddyfile, zeroserve parses it (with an LALRPOP-based parser) and
adapts it to Caddy JSON before compiling, reproducing the output of Caddy's own
`caddyfile` adapter for the supported HTTP surface. Supported syntax includes:
global options blocks, snippets and `import` (snippets and file globs with
`{args[...]}` substitution), site addresses (scheme/host/port/path, comma lists,
brace-less single sites), named matchers (`@name`) and inline `/path`/`*`
matchers, heredocs, backtick/quoted strings, `{$ENV}` substitution, and
placeholder shorthands (e.g. `{path}`, `{header.X}`).

Supported directives map to the same handlers the JSON path supports: `respond`,
`error`, `abort`, `redir`, `header`/`request_header`, `rewrite`/`uri`/`method`,
`handle`/`handle_path`/`route`/`handle_errors`, `root`/`fs`/`vars`/`map`,
`basic_auth`/`basicauth`, `request_body`, `file_server`, and `reverse_proxy`
(common options). Directives
are ordered by Caddy's canonical directive order and wrapped in terminal
subroutes under each site's host/path matchers, exactly as Caddy does.

To inspect the adapter output without compiling, use `--adapt-caddyfile`:

```bash
zeroserve --adapt-caddyfile Caddyfile   # prints Caddy JSON to stdout
```

TLS/PKI/admin/automatic-HTTPS global options are accepted but reported as
warnings, since they live outside zeroserve's eBPF request-processing surface
(the same surface the JSON path documents below).

The generated script implements Caddy HTTP routes, matcher sets, route groups,
terminal routes, method/query/header/header-regexp/path-regexp/file/protocol/TLS/
remote-IP/vars/vars-regexp matchers, host matchers with Caddy-compatible IDNA
normalization, case-folding, port stripping, and label wildcards, case-folded path matchers with ordinary
`*` wildcards, and the Caddy handlers that map to zeroserve's script surface:
`static_response` including placeholder-expanded status/body and `abort`,
placeholder-expanded `vars`,
lazy `map`, `invoke` of server `named_routes`, `headers` request and response
add/set/delete/string/regex-replace operations including deferred response
`require` status/header matchers. Header operations expand Caddy placeholders in
header names/values; response `require` header matcher values are matched
literally, as in Caddy.
`rewrite.method`, `rewrite.uri`, `rewrite.strip_path_prefix`,
`rewrite.strip_path_suffix`, non-regex `rewrite.uri_substring`, and
`rewrite.path_regexp`, and `rewrite.query` rename/set/add/string/regex
replace/delete operations, nested
`subroute`, `file_server` over packed tar entries and, when
`--expose-filesystem` is set, absolute host-filesystem roots (`root`, `hide`, `index_names`,
`fs: "file"`/`fs: "default"` explicit filesystem mode,
`browse` listings including Caddy-shaped JSON responses, `sort`, `file_limit`,
and `reveal_symlinks`, `canonical_uris`,
placeholder-expanded `status_code`, `pass_thru`, byte-range responses, built-in `precompressed`
sidecars, `precompressed_order`, and `etag_file_extensions`),
`request_body.max_size`, and single-upstream `reverse_proxy` including
placeholder-expanded upstream dials, Caddy forwarded-header defaults,
and upstream request method/URI/query/path rewrites, upstream response status/header
placeholders, upstream latency placeholders, `handle_response` status replacement,
and request-mutating `handle_response.routes` flows such as `forward_auth`;
response-only reverse-proxy response routes, including `copy_response_headers`,
are rejected because Caddy represents them as replacement responses and
zeroserve intentionally does not implement Caddy response-body rewrite or
suppression compatibility. Authentication with the Caddy `http_basic` provider
using `bcrypt` or `argon2id` hashes is supported. For Caddy `intercept`,
`handle_response.status_code: 0` runs matching response routes and preserves
the generated response status; nonzero `intercept` status replacement is
ignored to match current Caddy behavior;
for `reverse_proxy`, `handle_response.status_code: 0` preserves the upstream
status and takes priority over any routes, matching Caddy's distinct handler
semantics.
Server `errors.routes`, including grouped error routes, and
`subroute.errors.routes` are supported for generated error responses from the
`error` handler, including
`http.error.status_code`, `http.error.status_text`, and `http.error.message`
placeholders.
Supported Caddy `tls.client_auth` policies are emitted into a separate
`zeroserve.tls` eBPF section which runs before normal HTTP request routing.
The supported modes are `require`, `verify_if_given`, and
`require_and_verify` with inline trusted CA certificates produced by Caddy JSON
or Caddyfile adaptation. Custom client-auth verifier modules and
trusted-leaf-only verification are rejected.
The Caddy `expression` matcher is supported for the request-matcher subset that
can be represented directly in generated middleware: boolean `&&`/`||`/`!`,
parentheses, string equality/inequality and string-list `in`, string
concatenation, and matcher macro calls for `method`, `path`, `path_regexp`,
`host`, `remote_ip`, `client_ip`, `protocol`, `header`, `header_regexp`,
`query`, `vars`, `vars_regexp`, and `file`. Full CEL evaluation, arithmetic,
dynamic values, comprehensions, request object access, and typed numeric/bool
placeholder comparisons are intentionally not emitted.
Listener, TLS,
certificate, automatic HTTPS, load balancing, HTTP/2 server push,
observability-only handlers (`log_append`, `tracing`), response-body handlers
(`encode`, `templates`, `copy_response`), Caddy body-inspection placeholders
(`{http.request.body}`, `{http.request.body_base64}`,
`{http.response.body}`, `{http.response.body_base64}`), metrics-serving handlers,
authentication providers other than `http_basic`, ACME handlers, full CEL expression evaluation,
body/certificate-derived placeholders, error-route `http.error.id`/`trace` placeholders,
dynamic `client_ip` trusted-proxy IP sources, TLS early-data matching,
request-body replacement/timeouts, reverse-proxy buffering, streaming lifetime
controls, retries, custom upstream TLS settings, file-server
custom browse templates, and non-default filesystem modules are intentionally
not emitted because they require runtime features outside
zeroserve's current eBPF-configurable surface. `reverse_proxy` with multiple
upstreams also fails compilation, since balancing across upstreams is not
exposed by zeroserve. Fields outside the request-processing surface, such as
listener binding and TLS termination settings, are ignored with warnings.
Site `log` directives with `output file <path>` are the supported exception:
generated middleware selects the Caddy access log file and zeroserve writes JSON
access records from a dedicated monoio/io_uring logging thread, but only when
the server is started with `--expose-filesystem`. Without that flag, Caddy file
logging is a no-op.
Unsupported HTTP features fail compilation instead of silently generating
different behavior.

Configuration that lives entirely outside the eBPF request-processing surface —
HTTP app listener defaults/shutdown timing (`http_port`, `https_port`,
`grace_period`, `shutdown_delay`), server listener binding (`listen`,
`listener_wrappers`, `packet_conn_wrappers`), TLS termination and certificates
(`tls_connection_policies`, `automatic_https`, and the top-level `tls`/`pki`
apps), connection transport tuning (`protocols`, `listen_protocols`, timeouts,
keepalive settings, `max_header_bytes`, `enable_full_duplex`), logging outside
supported file access logs, metrics (`metrics`), the `events` app, and a `reverse_proxy`
`load_balancing` policy on a single-upstream proxy (where it is a no-op), plus
reverse-proxy buffering and stream lifetime knobs —
cannot be observed or altered by a script. The compiler prints a
`warning: ignoring ...` line to stderr and continues, rather than failing, since
these fields are configured elsewhere when running zeroserve. The generated
script on stdout is unaffected, so redirecting it to a file keeps the warnings
visible on the terminal.
The `log_append` and `tracing` handlers are also ignored with warnings because
they only affect Caddy's access logging/tracing pipeline, not HTTP
request/response semantics.
The `push` handler is ignored with warnings because it creates HTTP/2 server
push side effects rather than modifying the eventual response.

## Running the server

Command synopsis:

```bash
zeroserve [OPTIONS] SITE_TAR
```

Key options:

- `--addr <ADDR>`: HTTP listen address (default `0.0.0.0:8080`). Accepts either
  `ip:port` to bind a new socket, or `fd:N` to use an inherited file descriptor.
- `--tls-addr <ADDR>`: HTTPS listen address (requires `--cert`/`--key` or
  `--cert-dir`).
  Accepts either `ip:port` or `fd:N`.
- `--cert <FILE>`: TLS certificate PEM.
- `--key <FILE>`: TLS private key PEM.
- `--cert-dir <DIR>`: Directory of TLS certificate PEMs and private key PEMs.
  Zeroserve matches keys to certificates automatically and selects certificates
  by SNI.
- `--ech-key <PATH>`: Path to an ECH key PEM file or directory of files.
  Requires TLS to be configured. See the ECH section below.
- `--gen-ech-key`: Generate a new ECH keypair and ECHConfig. Writes the PEM
  bundle to stdout and a base64 ECHConfigList to stderr. Requires
  `--ech-public-name`.
- `--caddy-compile <CONFIG>`: Compile a Caddy config's HTTP routes into a
  zeroserve eBPF C request script on stdout. Accepts a Caddy JSON config or a
  native Caddyfile (auto-detected). The output can be placed under
  `.zeroserve/scripts/` and compiled by `--pack`.
- `--caddy <CADDYFILE>`: Run a Caddyfile (or Caddy JSON) directly — adapt,
  compile, build an in-memory site tarball, and serve it, all in memory
  (memfd). Used in place of the `SITE_TAR` argument.
- `--adapt-caddyfile <CADDYFILE>`: Adapt a Caddyfile to Caddy JSON and print it
  to stdout (without compiling), for inspecting the adapter output.
- `--ech-public-name <NAME>`: Public DNS name to embed in a generated
  ECHConfig (used only with `--gen-ech-key`).
- `--index <NAME>`: Default document for directories (default `index.html`).
- `--try-html`: Try `<path>.html` when a request path is missing.
- `--expose-filesystem`: Allow generated Caddy middleware to read absolute host
  filesystem roots. Without this flag, Caddy `file` matchers and `file_server`
  handlers with absolute roots do not read the host filesystem.
- `--plugin <PLUGIN_TAR[,PLUGIN_TAR...]>`: Load scripts from one or more
  plugin tarballs before scripts from `SITE_TAR`. Plugin tarballs use the same
  layout as site tarballs; eBPF objects are read from `.zeroserve/scripts/*.o`.
- `--chunk-size <BYTES>`: Streaming chunk size for tar reads (default 65536).
- `--max-buffered-body-size-kb <KB>`: Maximum request body size in KB for script
  body reads via `zs_req_body_json` (default 256).
- `--max-request-external-memory-footprint-kb <KB>`: Maximum external memory
  footprint in KB per request for scripts (default 256).
- `--reload-signal-file <FILE>`: Poll a file and reload when its contents change.
- `--disable-request-logging`: Turn off per-request logs.
- `--enable-proxy-protocol`: Expect PROXY protocol v1 on each new connection.
- `--disable-ns-isolation`: Disable Linux namespace isolation.
- `--enable-netns-isolation`: Enable Linux network namespace isolation.
- `--preempt-timer-interval-ms <MS>`: Script preemption timer interval.
- `--sqpoll-idle-ms <MS>`: Enable io_uring sqpoll with idle timeout.
- `--validate-hostnames <HOSTNAMES>`: Comma-separated list of allowed hostnames.
  Requests with a non-matching `Host` header (or HTTP/2 `:authority`) receive a
  `421 Misdirected Request` response. Supports IPv4, IPv6 (bracket notation), and
  hostnames with optional ports (e.g., `example.com,api.example.com,[::1]`).
  Matching is case-insensitive and port numbers are stripped before comparison.

Examples:

```bash
# HTTP only
zeroserve --addr 0.0.0.0:8080 site.tar

# HTTP + HTTPS
zeroserve --addr 0.0.0.0:8080 \
  --tls-addr 0.0.0.0:8443 --cert certificate.pem --key key.pem \
  site.tar

# HTML fallback and PROXY protocol
zeroserve --try-html --enable-proxy-protocol site.tar

# Plugin scripts before site scripts
zeroserve --plugin auth.tar,headers.tar site.tar

# Socket activation (inherit pre-bound sockets)
zeroserve --addr fd:3 --tls-addr fd:4 --cert cert.pem --key key.pem site.tar

# Hostname validation (reject requests not matching allowed hostnames)
zeroserve --validate-hostnames example.com,www.example.com,[::1] site.tar
```

## Routing and file lookup

Zeroserve normalizes request paths (handles `.`/`..` and percent decoding) before lookup.
Lookup order:

- Direct match for the requested path.
- If the path is a directory (or looks like one), try `<path>/<index>`.
- Also tries `<path>/<index>` even without a trailing slash.
- If `--try-html` is enabled, try `<path>.html` when the path has no extension.

The default index document is `index.html`, configurable via `--index`.

## Hot reload

Zeroserve reloads the site tarball, scripts, and TLS configuration on:

- `SIGHUP` (for example: `killall -SIGHUP zeroserve`).
- Changes to `--reload-signal-file` (polled periodically, content-based).

This is useful for replacing the tarball and certificate in place without downtime.

## TLS

To enable HTTPS, provide a TLS address plus either a certificate/key pair or a
certificate directory. HTTPS supports TLS 1.3 only, with HTTP/2 via ALPN (h2)
and HTTP/1.1 fallback:

```bash
zeroserve --tls-addr 0.0.0.0:8443 --cert certificate.pem --key key.pem site.tar
```

With `--cert-dir`, zeroserve scans regular files in the directory, treats PEMs
with certificates as certificate chains, treats PEMs with private keys as keys,
and matches keys to certificates by public key. For SNI connections, it serves
the first non-expired certificate, in lexicographic path order, whose DNS SAN
matches the SNI; wildcard SANs match a single label. Reloading TLS assets uses
the same hot-reload mechanism as the tarball.

## Encrypted Client Hello (ECH)

Zeroserve terminates TLS with BoringSSL, which has native server-side support
for Encrypted Client Hello (draft-ietf-tls-esni / RFC 9460 HTTPS resource
records), so the inner SNI — the real hostname a client is reaching — never
appears in cleartext on the wire. The on-path observer only sees the public
"client-facing" name.

### Generate a keypair

```bash
zeroserve --gen-ech-key --ech-public-name www.example.com > ech.pem
```

`--gen-ech-key` writes a PEM bundle (one `ECH PRIVATE KEY` block and one
`ECH CONFIG` block) to stdout and prints a base64-encoded `ECHConfigList`
to stderr for publication. Put the printed value in the `ech=` parameter of
the destination's HTTPS DNS resource record. The TLS certificate served by
zeroserve must cover the chosen public name (its SAN must include
`www.example.com`).

### Run with ECH enabled

```bash
zeroserve --tls-addr 0.0.0.0:8443 --cert certificate.pem --key key.pem \
  --ech-key ech.pem site.tar
```

`--ech-key` accepts either a single PEM file (one or more `ECH PRIVATE KEY`
/ `ECH CONFIG` pairs concatenated) **or** a directory containing one or more
such files. Directory mode is convenient for rotation: drop a new key file
into the directory and send `SIGHUP` to load it alongside the existing keys.
Files starting with `.` are ignored; entries are loaded in sorted-filename
order; `config_id` collisions across pairs are rejected.

When ECH is enabled the server logs the combined `ech=` value and the list
of public names on startup and on each reload.

### Rotation

To rotate without downtime, generate a new pair and add it to the
`--ech-key` directory:

```bash
zeroserve --gen-ech-key --ech-public-name www.example.com > keys/02.pem
killall -SIGHUP zeroserve
```

Both old and new `ech=` values continue to decrypt successfully until the
old file is removed. Update the DNS HTTPS record with the new ECHConfigList
printed at reload, then after the DNS TTL has expired you can delete the
old key file and SIGHUP again.

### Reject behaviour

When a client offers an ECH extension whose `config_id` doesn't match any
loaded key, or when HPKE decryption fails, BoringSSL completes the handshake
against the **public-name** certificate and returns the current `retry_configs`
(every loaded ECHConfig) in the EncryptedExtensions. An ECH-aware client can
then retry immediately with a fresh config, so a stale DNS cache self-heals
within one extra handshake. Scripts can observe per-connection ECH status via
`zs_connection_info()` (the `ech.accepted` field).

### Transparent relay fallback ("don't stick out")

The reject behaviour above assumes the configured certificate covers the ECH
public name. If it does **not** — i.e. ECH is enabled but no loaded certificate
matches the public name — zeroserve cannot complete the handshake for that name.
In that case, when a client connects with the public name as its (cleartext)
outer SNI and there is **no decryptable inner ClientHello** (no ECH offered,
GREASE ECH, or a stale/undecryptable config), zeroserve transparently relays the
raw TLS connection to the real server for that public name on port 443.

The relay is byte-for-byte: the buffered ClientHello is replayed to the upstream
and both directions are then spliced, so the connection is indistinguishable
from a direct connection to the public name. This lets you point an ECH public
name at a genuine, separately-hosted domain (e.g. a large shared front-end)
without that domain's certificate, exactly as recommended by the ECH spec to
avoid "sticking out". Connections whose inner ClientHello *does* decrypt are
terminated normally and served the protected site; this fallback only applies to
the undecryptable case. It is enabled automatically whenever ECH is configured.

## Request scripting (eBPF)

Zeroserve can run eBPF programs on every request. Scripts are loaded from
`.zeroserve/scripts/*.o` inside plugin tarballs and the site tarball. Scripts in
plugins run first, in the order given to `--plugin`; scripts inside each tarball
run in sorted path order, followed by site scripts in sorted path order.

Flow and behavior:

- Each script must export a function in section `zeroserve.request`.
  Use the `ZS_ENTRY` macro to mark the entrypoint.
- Scripts run for every request.
- A per-request metadata map is shared across scripts.
- If a script calls `zs_respond`, its response is sent and later scripts are skipped.
- If a script calls `zs_reverse_proxy`, the request is proxied and later scripts are skipped.
- Script failures are logged but do not abort the chain.
- A script may also export `zeroserve.call.<name>` functions (via
  `ZS_CALL_ENTRY`) that other scripts invoke with `zs_call`; see
  "Inter-script calls" below.

### Entry point

```c
#include <zeroserve.h>

ZS_ENTRY
zs_u64 entry(void) {
  // ...
  return 0;
}
```

### Building scripts

Option A: let `--pack` compile `.c` sources automatically.

```bash
zeroserve --pack ./site > site.tar
```

Option B: compile manually.

```bash
clang -O2 -target bpf -emit-llvm -c input.c -o tmp.bc
llc -march=bpf -bpf-stack-size=4096 -mcpu=v3 -filetype=obj tmp.bc -o out.o
```

Put the `.o` files at `.zeroserve/scripts/` in the tarball.

### Plugin tarballs

Plugin tarballs use the same layout as site tarballs, but only their eBPF script
objects are loaded. Static file serving and helpers such as
`zs_load_static_json` read from the main site tarball.

```bash
zeroserve --plugin auth.tar,headers.tar site.tar
```

Hot reload reloads plugin tarballs, site scripts, site files, and TLS assets
together. If any plugin or site script fails to load during reload, Zeroserve
keeps serving the previous site and script chain.

### Helper API overview

Logging and time:

- `zs_log(msg, len)`
- `zs_now_ms()` returns milliseconds since the Unix epoch.
- `zs_env_get(name, name_len, out, out_len)` reads an environment variable.

Crypto and encoding:

- `zs_getrandom(out, out_len)` fills `out` with random bytes.
- `zs_sha256(data, data_len, out, out_len)` writes a 32-byte SHA-256 digest.
- `zs_hmac_sha256(key, key_len, msg, msg_len, out)` writes a 32-byte HMAC-SHA-256 digest.
- `zs_base64_encode(data, data_len, out, out_len, encoding)` encodes Base64.
- `zs_base64_decode_in_place(buf, buf_len, encoding)` decodes Base64 in place.
- `zs_hex_encode(data, data_len, out, out_len, case)` encodes binary data to hexadecimal.
- `zs_hex_decode_in_place(buf, buf_len)` decodes hexadecimal to binary in place.

AWS Signature Version 4:

- `zs_aws_v4_authorization_header(params, params_len)` generates an AWS SigV4
  Authorization header value. Takes a pointer to `zs_aws_v4_sign_params`
  and the struct size. Returns the number of characters written (excluding null
  terminator), or -1/-2 on error. If `params->out_len` is 0, returns the required
  buffer size without writing.

    The `zs_aws_v4_sign_params` struct fields:
    - `access_key`, `access_key_len`: AWS access key ID
    - `secret_key`, `secret_key_len`: AWS secret access key
    - `region`, `region_len`: AWS region (e.g., "us-east-1")
    - `service`, `service_len`: Service name (e.g., "s3", "execute-api")
    - `method`, `method_len`: HTTP method (e.g., "GET", "POST")
    - `uri`, `uri_len`: Request URI including path and optional query string
    - `headers_json`: JSON object handle with headers to sign
    - `body_hash`, `body_hash_len`: Hex-encoded SHA256, or "UNSIGNED-PAYLOAD"
    - `timestamp_ms`: Unix timestamp in milliseconds
    - `out`, `out_len`: Output buffer for the Authorization header value

- `zs_aws_v4_presigned_url(params, params_len, expires_secs)` generates an AWS SigV4
  pre-signed URL. Takes a pointer to `zs_aws_v4_sign_params`, the struct size, and the
  expiration time in seconds. Returns the number of characters written (excluding null
  terminator), or -1/-2 on error. If `params->out_len` is 0, returns the required
  buffer size without writing.

  The output is a URL path with query string containing the signature parameters
  (`X-Amz-Algorithm`, `X-Amz-Credential`, `X-Amz-Date`, `X-Amz-Expires`,
  `X-Amz-SignedHeaders`, `X-Amz-Signature`). The body is always treated as
  `UNSIGNED-PAYLOAD`.

  The `zs_aws_v4_sign_params` struct is shared with `zs_aws_v4_authorization_header`,
  but `body_hash` is ignored (always treated as `UNSIGNED-PAYLOAD`).

Rate limiting:

- `zs_rate_limit(key, key_len, per_second, per_minute, per_hour)` checks whether a
  request should be allowed based on rate limits for the given key. Returns:
  - `ZS_RATE_LIMIT_ALLOWED` (0) if the request is allowed
  - `ZS_RATE_LIMIT_EXCEEDED_SECOND` (1) if per-second limit exceeded
  - `ZS_RATE_LIMIT_EXCEEDED_MINUTE` (2) if per-minute limit exceeded
  - `ZS_RATE_LIMIT_EXCEEDED_HOUR` (3) if per-hour limit exceeded
  - `ZS_RATE_LIMIT_EXCEEDED_BUCKET_LIMIT` (4) if too many unique keys are being tracked
  - `-1` on error (invalid parameters or key too long, max 256 bytes)

  A limit of 0 means unlimited for that window. The key can be any arbitrary bytes,
  such as an IP address (`zs_req_peer`), API key, or user ID. Rate limit state is
  shared across all requests and persists across hot reloads.

  Example (rate limit by IP):
  ```c
  char peer[64];
  zs_req_peer(peer, sizeof(peer));
  int64_t result = zs_rate_limit(ZS_STR(peer), 10, 100, 1000);
  if (result == ZS_RATE_LIMIT_EXCEEDED_SECOND) {
      zs_respond(429, ZS_STR("{\"error\":\"rate limit exceeded\"}"));
      return 0;
  }
  ```

OAuth2 / OIDC login (Authorization Code + PKCE):

zeroserve can act as an OpenID Connect Relying Party to put an identity-provider
login in front of the site. There is no server-side session store: the transient
login state and the session are carried in sealed (encrypted + authenticated,
XChaCha20-Poly1305) cookies. Configuration is passed as a **JSON object handle**
(built with `zs_json_parse` or `zs_json_new_object`); recognised keys are
`issuer` (or explicit `authorization_endpoint`/`token_endpoint`), `client_id`,
`client_secret`, `redirect_uri`, optional `scope`, `cookie_secret` (>= 16 bytes,
**must stay stable across restarts** or all sessions are invalidated), and
optional `session_ttl_secs`.

All four helpers take the config JSON handle as their first argument.

- `zs_oidc_begin_login(cfg, return_to, return_to_len)` sets the state cookie and
  302-redirects to the IdP. After login the user returns to `return_to`. Terminal.
- `zs_oidc_handle_callback(cfg)` runs on your `redirect_uri` path. It validates
  the CSRF `state`, exchanges the `code` (with the PKCE verifier) at the token
  endpoint, validates the id_token claims, sets the session cookie, and redirects
  back to the stored `return_to`. Terminal (400 on bad state, 502 if the exchange
  fails).
- `zs_oidc_session_verify(cfg)` returns a JSON object handle of the identity
  claims when a valid session cookie is present, `0` if not, `<0` on error. Not
  terminal — free the handle with `zs_object_free`.
- `zs_oidc_logout(cfg, end_session_url, end_session_url_len)` clears the session
  cookie and (optionally) redirects to the IdP end-session URL. Terminal.

> The id_token is fetched directly from the token endpoint over a server-validated
> TLS connection, so per OIDC Core 3.1.3.7 its claims (`iss`/`aud`/`exp`/`nonce`)
> are validated but its signature is not separately checked against a JWKS.

strongSwan VICI:

- `zs_vici_eap_identity_by_ip(ip, ip_len)` queries strongSwan's VICI
  `list-sas` stream and returns a JSON object handle for the SA whose
  `remote-host` or `remote-vips` matches `ip`. The VICI socket is
  server-controlled via `$ZEROSERVE_VICI_SOCKET`; if the variable is unset,
  this helper is disabled and returns `-1`. The environment value may be a path
  or `unix://` URI.
  Returns `0` when no SA matches and `-1` on bad input or VICI errors. The JSON
  object includes `identity`/`remote_eap_id`, `remote_id`, `ike_name`,
  `uniqueid`, `state`, `remote_host`, `remote_vips`, `matched_ip`, and
  `matched_by`. Free the handle with `zs_object_free`.

Example (gate the whole site behind login):
```c
#include <zeroserve.h>

ZS_ENTRY
zs_u64 entry(void) {
    // Config as a JSON object. Keep cookie_secret stable and secret.
    zs_s64 cfg = zs_json_parse(ZS_STR(
        "{"
          "\"issuer\":\"https://accounts.example.com\","
          "\"client_id\":\"my-client-id\","
          "\"client_secret\":\"my-client-secret\","
          "\"redirect_uri\":\"https://app.example.com/callback\","
          "\"cookie_secret\":\"keep-this-secret-stable-please\""
        "}"));
    if (cfg < 0) { zs_respond(500, ZS_STR("config error")); return 0; }

    char path[256];
    zs_req_path(path, sizeof(path));

    if (zs_memcmp(path, "/callback", 9) == 0) {
        zs_oidc_handle_callback(cfg);
        return 0;
    }
    if (zs_memcmp(path, "/logout", 7) == 0) {
        zs_oidc_logout(cfg, ZS_STR("https://accounts.example.com/logout"));
        return 0;
    }

    zs_s64 session = zs_oidc_session_verify(cfg);
    if (session <= 0) {
        char uri[512];
        zs_req_uri(uri, sizeof(uri));
        zs_oidc_begin_login(cfg, ZS_STR(uri));  // 302 to the IdP
        return 0;
    }
    zs_object_free(session);
    return 0;  // authenticated: fall through to static serving
}
```

JSON parsing:

- `zs_json_parse(data, data_len)` parses JSON and returns a handle (-1 on failure).
- `zs_load_static_json(path, path_len)` reads the static file at `path` in the tarball,
  parses JSON, and returns a handle (-1 if missing or invalid JSON). The path is used
  verbatim (no normalization, index fallback, or `.html` try).
- `zs_load_file_metadata(path, path_len)` returns a JSON handle for a tarball entry
  with `{"size":...,"etag":...,"mtime":...}` (-1 if missing). The path is used verbatim.
- `zs_json_reset(json)` resets a handle back to the document root.
- `zs_json_get(json, key, key_len)` reads an object key and returns a handle (-1 if missing).
- `zs_json_array_get(handle, array_index)` takes an array index and returns a handle
  (-1 if missing, non-array).
- `zs_json_read_string(json, out, out_len)` writes a JSON string into `out`.
- `zs_json_read_i64(json, out, out_len)` writes an `i64` into `out`.
- `zs_json_read_bool(json, out, out_len)` writes `0` or `1` into `out`.
- `zs_object_free(handle)` releases a handle when you're done with it.

JSON creation and modification:

- `zs_json_new_object()` creates an empty JSON object `{}`; returns a handle.
- `zs_json_new_array()` creates an empty JSON array `[]`; returns a handle.
- `zs_json_clone(json)` deep-clones a JSON value into a new independent tree.
- `zs_json_len(json)` returns the length of an array, object, or string (-1 for other types).
- `zs_json_type(json)` returns the type code: `ZS_JSON_NULL` (0), `ZS_JSON_BOOL` (1),
  `ZS_JSON_NUMBER` (2), `ZS_JSON_STRING` (3), `ZS_JSON_ARRAY` (4), `ZS_JSON_OBJECT` (5).
- `zs_json_set(json, key, key_len, value_json)` sets a field on an object (value is cloned).
- `zs_json_remove(json, key, key_len)` removes a field from an object.
- `zs_json_array_push(json, value_json)` appends a cloned value to an array.
- `zs_json_array_set(json, index, value_json)` sets an element at an array index.
- `zs_json_set_string(json, value, value_len)` replaces the node with a string.
- `zs_json_set_i64(json, value)` replaces the node with an i64.
- `zs_json_set_bool(json, value)` replaces the node with a boolean.
- `zs_json_set_null(json)` replaces the node with null.

JSON response:

- `zs_json_respond(status, json)` serializes the JSON handle to a response body,
  sets `Content-Type: application/json`, and sends the response.

Inter-script calls:

- `zs_call(script, script_len, func, func_len, json_handle)` invokes another
  script's exported call function, passing a JSON handle and receiving one back.
  Returns a new JSON object handle (free it with `zs_object_free`), or `-1` if
  the call could not be completed: unknown script or function, the callee
  trapped or returned a negative handle, or the maximum call depth (8) was
  reached. `script` names the target script file with or without the `.o`
  extension.
- Expose a callable from a script with the `ZS_CALL_ENTRY(name, input)` macro.
  It places the function in the `zeroserve.call.<name>` code section and gives
  it the signature `zs_s64 on_call(zs_s64 input)` — it receives the inbound JSON
  handle by value through the user-named parameter and returns a JSON handle:

  ```c
  // greeter.c — callee; exposes greet, but no request entrypoint of its own.
  ZS_CALL_ENTRY(greet, input) {
    zs_s64 out = zs_json_new_object();
    zs_s64 value = zs_json_new_object();
    zs_json_set_string(value, ZS_STR("Hello!"));
    zs_json_set(out, ZS_STR("greeting"), value);
    zs_object_free(value);
    return out;
  }
  ```

  ```c
  // gateway.c — caller.
  ZS_ENTRY
  zs_u64 entry(void) {
    zs_s64 payload = zs_json_new_object();
    zs_s64 reply = zs_call(ZS_STR("greeter"), ZS_STR("greet"), payload);
    zs_object_free(payload);
    if (reply < 0) { zs_respond(502, ZS_STR("call failed\n")); return 0; }
    zs_json_respond(200, reply);
    zs_object_free(reply);
    return 0;
  }
  ```

  The JSON argument is deep-copied into the callee and its return value is copied
  back, so JSON handles are not shared across the call. The **request** and the
  **metadata map**, however, are shared by reference for the whole request: a
  callee's `zs_req_set_header`/`zs_req_set_uri` and `zs_meta_set` are visible to
  the caller and propagate out to the wire (including `zs.response.header.*`
  metadata). Response hooks registered with `zs_res_hook` also share the same
  metadata map. Each callee gets its own response/reverse-proxy slot and JSON
  object table. Calls may nest (a callee can `zs_call` again) up to a depth of 8;
  the whole chain is torn down immediately if the client disconnects. See
  `examples/call_gateway.c` and `examples/call_greeter.c`.

Request inspection:

- `zs_req_method`, `zs_req_path`, `zs_req_uri`, `zs_req_query`, `zs_req_scheme`, `zs_req_peer`
- `zs_req_normalized_path(out, out_len)` returns the cleaned decoded request
  path used by zeroserve static-file lookup.
- `zs_caddy_path_regexp_subject(out, out_len)` returns the decoded, cleaned
  request path used by Caddy `path_regexp` matching.
- `zs_req_proto_major()` and `zs_req_proto_minor()` return the HTTP protocol
  version numbers used by Caddy's `protocol` matcher.
- `zs_req_is_tls()` returns `1` for TLS requests. `zs_req_tls_handshake_complete()`
  returns `1` once TLS is complete for the current request; zeroserve currently
  only runs middleware after TCP TLS handshakes complete.
- `zs_req_header(name, name_len, out, out_len)`
- `zs_req_query_param(name, name_len, out, out_len)` returns the first decoded
  query value for `name`.
- `zs_req_query_param_matches(name, name_len, value, value_len)` returns `1`
  when any decoded query value for `name` equals `value`, or when `value` is
  `*` and the key is present.
- `zs_req_remote_ip_matches(ranges_json, ranges_json_len)` returns `1` when the
  current direct peer IP matches any IP or CIDR range in the JSON string array.
- `zs_caddy_remote_ip_matches(ranges_json, ranges_json_len)` expands each range
  as Caddy placeholders before matching the current direct peer IP.
- `zs_caddy_client_ip_matches(config_json, config_json_len)` resolves the Caddy
  client IP using Caddy's server-level `client_ip_headers`,
  `trusted_proxies_strict`, `trusted_proxies_unix`, and optional static
  `trusted_proxies`, then matches it against configured IP/CIDR ranges. Without
  static TCP trusted-proxy ranges, TCP requests use the direct peer IP while
  `trusted_proxies_unix` can still trust Unix-socket peers. The matcher ranges
  are expanded as Caddy placeholders.
- `zs_caddy_vars_match(vars_json, vars_json_len)` returns `1` when any Caddy
  `vars` matcher entry matches. Single-placeholder keys are resolved as
  placeholders, literal keys read values from `zs_caddy_vars_set`, and expected
  values are placeholder-expanded.
- `zs_caddy_path_match(pattern, pattern_len)` returns `1` when the current
  request path matches a Caddy path matcher pattern, including Caddy's
  case-insensitive matching, cleaned paths, glob syntax, and escaped `%`
  comparison behavior.
- `zs_caddy_query_match(name_template, name_template_len, value_template,
  value_template_len)` expands both templates as Caddy placeholders, then
  returns `1` when the decoded query key is present with the decoded value, or
  when the expanded value is `*` and the key is present.
- `zs_caddy_query_present(name_template, name_template_len)` expands the key
  template as Caddy placeholders and returns `1` when the decoded query key is
  present.
- `zs_caddy_query_empty()` returns `1` when Caddy's parsed query map is empty,
  matching an empty Caddy query matcher. Malformed query strings make Caddy
  query matchers return false, matching Go's `url.ParseQuery` path.
- `zs_caddy_header_match(name, name_len, value_template, value_template_len)`
  expands the allowed value template and evaluates Caddy request-header matcher
  semantics against every repeated value for `name`.
- `zs_caddy_header_present(name, name_len)` returns `1` when the request header
  exists. Generated header matchers use this for Caddy's empty-array
  present-header case and negate it for Caddy's `null` absent-header case.
- `zs_caddy_header_regexp_match(name, name_len, config_json, config_json_len)`
  evaluates a Caddy regex matcher config (`pattern`, optional `name`) against
  every repeated request-header value for `name` and stores captures on success.
- `zs_caddy_regex_match(input, input_len, config_json, config_json_len)`
  evaluates a Caddy regex matcher config (`pattern`, optional `name`) and stores
  numbered/named captures in metadata under `http.regexp...` keys.
- `zs_caddy_file_match(config_json, config_json_len)` evaluates a supported
  Caddy `file` matcher against the packed site or, when `--expose-filesystem`
  is set, an absolute host filesystem root and stores `http.matchers.file.relative`, `.absolute`, `.type`, and
  `.remainder` placeholders on success. If `root` is omitted, it uses
  `http.vars.root` and falls back to the packed site root when unset, matching
  Caddy's default. Static glob expansion is supported for packed-site roots and
  absolute host filesystem roots; `=status` error fallbacks produce that
  response status when reached.
- `zs_caddy_expand(input, input_len, out, out_len)` expands supported Caddy
  placeholders from the current request, response hook headers, shared
  metadata, regex captures, and Caddy vars. Supported request placeholders
  include method, scheme, host/port/hostport, host labels, local address
  host/port, request duration, request cookies, remote address host/port including
  `http.request.remote.host/<bits>` CIDR masks,
  URI/path/query with escaped variants, prefixed query, path
  file/dir/base/ext and indexed path segments, original method/URI/path/query
  state from before request mutation, protocol/protocol name, request UUID, and
  available TLS version, cipher suite, session resumption, ALPN/SNI/ECH state,
  including Caddy's always-true `http.request.tls.proto_mutual` on TLS requests.
  Caddy shutdown placeholders resolve to the inactive zeroserve state:
  `http.shutting_down=false` and an empty `http.time_until_shutdown`.
  Supported response placeholders include `http.response.header.*` while a
  response hook is running. Unknown placeholders expand to an empty string.
  Generated Caddy middleware rejects Caddy request/response body placeholders
  at compile time instead of inspecting or rewriting body contents.
- `zs_caddy_rewrite_uri(uri_template, uri_template_len)` expands a Caddy
  `rewrite.uri` template against the current request metadata, then updates the
  path, query, and fragment using Caddy's preservation rules. It is intended
  for generated Caddy middleware.
- `zs_caddy_respond(status_template, status_template_len, body_template,
  body_template_len)` expands Caddy placeholders in a static response status and
  body, applies Caddy's static-response content-type inference, and sets a
  terminal response. It is intended for generated Caddy request middleware and
  is not supported from response hooks.
- `zs_caddy_respond_static(status_template, status_template_len, config_json,
  config_json_len)` is the generated Caddy `static_response` helper. The config
  contains the body, headers, and close flag; headers are expanded before
  Caddy's implicit `Content-Type` decision.
- `zs_caddy_basic_auth(config_json, config_json_len)` implements generated
  Caddy `authentication.providers.http_basic` checks. It returns `1` when the
  current request is authenticated, sets `{http.auth.user.id}`, and returns `0`
  after setting Caddy 401 error metadata and `WWW-Authenticate` on failure.
- `zs_abort()` closes the current request without writing an HTTP response. It
  is terminal and is used for Caddy `static_response.abort`.
- `zs_caddy_map(config_json, config_json_len)` registers a lazy Caddy map
  provider for the current request. The config is Caddy's `map` handler JSON
  without the `handler` field; mapped placeholders are evaluated when later
  placeholder expansion asks for them.
- `zs_caddy_response_headers(ops_json, ops_json_len)` applies non-deferred
  Caddy `headers.response` operations to the current request's early response
  header map before a downstream handler creates the response.
- `zs_caddy_reverse_proxy_url(url_template, url_template_len, out, out_len)`
  expands a generated reverse-proxy backend URL template, stores
  `http.reverse_proxy.upstream.*` placeholders in metadata for subsequent
  header operations, and writes the expanded URL to `out`. The
  `upstream.address` and `upstream.hostport` placeholders use Caddy's dial
  hostport form with default ports, not the full proxy URL.
- `zs_caddy_reverse_proxy_forwarded(config_json, config_json_len)` applies
  Caddy reverse-proxy `X-Forwarded-*` preparation, including server-level static
  trusted proxies and handler `trusted_proxies` preservation rules. It is
  intended for generated Caddy middleware.
- `zs_caddy_reverse_proxy_request_headers(ops_json, ops_json_len)` applies
  Caddy reverse-proxy request header operations to the upstream request only,
  without mutating the live request seen by later response hooks.
- `zs_caddy_reverse_proxy_rewrite(config_json, config_json_len)` applies a
  supported Caddy reverse-proxy `rewrite` object to the upstream request only,
  without mutating the live request seen by later response hooks. It is intended
  for generated Caddy middleware.
- `zs_file_server(config_json, config_json_len)` registers a Caddy-compatible
  file-server response for the current request. It returns `0` when the request
  is handled, `1` for a `pass_thru` miss, and `2` for a hard file-server error;
  hard errors populate Caddy `http.error.*` metadata for generated error routes.
- `zs_req_body_limit(max_size)` lowers the per-request buffered body read limit
  and returns `1` if `Content-Length` is already larger than `max_size`.
- `zs_req_body_json()` parses the request body as JSON and returns a handle (-1 on failure).
- `zs_connection_info()` returns a JSON object handle describing the
  underlying connection: `{ "tls": bool, "tls_handshake_complete": bool,
  "alpn": string|null, "sni": {
  "inner": string|null, "outer": string|null }, "ech": null | { "accepted":
  bool }, "fingerprint": { "ja4": string|null } }`. `sni.inner` is the real
  (protected) server name when ECH was accepted, else the cleartext SNI;
  `sni.outer` is the ECH public name when ECH was accepted. `fingerprint.ja4`
  is the JA4 TLS client fingerprint computed from the ClientHello, or `null`
  on plaintext connections. Free with `zs_object_free`.

Request mutation:

- `zs_req_set_method(method, method_len)`
- `zs_caddy_rewrite_method(method_template, method_template_len)` expands a
  Caddy `rewrite.method` template, uppercases it, and applies it to the current
  request.
- `zs_req_set_uri(uri, uri_len)`
- `zs_req_set_header(name, name_len, value, value_len)`
  (pass `value_len = 0` to remove the header)
- `zs_req_append_header(name, name_len, value, value_len)`
- `zs_req_delete_header(pattern, pattern_len)` where `pattern` may be exact,
  prefix (`Foo*`), suffix (`*Foo`), contains (`*Foo*`), or `*` to clear all
  request headers.
- `zs_req_replace_header(op_json, op_json_len)` applies a supported Caddy
  header replacement object to request headers. `op_json` contains `name`,
  `search` or `search_regexp`, and `replace`.
- `zs_req_rewrite_query(ops_json, ops_json_len)` applies supported Caddy
  `rewrite.query` operations (`rename`, `set`, `add`, string `replace`, and
  `delete`) to the current request query string and re-encodes it.
- `zs_caddy_rewrite_uri(uri_template, uri_template_len)` applies a placeholder
  aware Caddy `rewrite.uri` template to the current request.
- `zs_req_rewrite_uri(ops_json, ops_json_len)` applies supported Caddy URI
  rewrite operations (`strip_path_prefix`, `strip_path_suffix`, and string
  `uri_substring`, and `path_regexp`) to the current request URI.
- `zs_caddy_vars_set(vars_json, vars_json_len)` stores supported Caddy `vars`
  handler values in the per-request metadata map, expanding placeholders in
  variable names and string values.

Metadata:

- `zs_meta_get(key, key_len, out, out_len)`
- `zs_meta_set(key, key_len, value, value_len)`

Metadata keys prefixed with `zs.response.header.` are applied as HTTP response
headers for all responses (static files, `zs_respond`, and reverse proxy).
Example: `zs_meta_set("zs.response.header.cache-control", ..., "no-store", ...)`.
Response hooks can also set these metadata keys before the final response head is
written.

Response hooks:

- `zs_res_hook(script, script_len, func, func_len, json_handle)` registers a
  `ZS_CALL_ENTRY(func, input)` function to run for the current request after
  response headers exist and before they are written. Pass an empty script name
  to target the current script.
- `zs_res_hooks_clear()` removes all response hooks registered so far for the
  current request. It does not clear a direct response; use
  `zs_response_clear()` for that.
- In a response hook, `zs_res_status()` returns the current response status,
  `zs_res_set_status(status)` changes the status, and `zs_res_header(name,
  name_len, out, out_len)` reads the current response header value.
- `zs_response_pending()` returns `1` when the current request script has
  already produced a direct response.
- `zs_response_clear()` clears a direct response produced by the current
  request script.
- In a response hook, `zs_caddy_res_header_match(name, name_len, value,
  value_len)` and `zs_caddy_res_header_present(name, name_len)` implement Caddy
  response-header matcher value and presence semantics across repeated headers.
  The allowed value is matched literally with Caddy's wildcard rules; response
  matchers do not expand placeholders.
- In a response hook, `zs_caddy_copy_response_headers(config_json,
  config_json_len)` copies headers from the original response header set using a
  Caddy `copy_response_headers`-style object with optional `include` or
  `exclude` arrays.
- In a response hook, `zs_res_replace_header(op_json, op_json_len)` applies a
  supported Caddy header replacement object to response headers. `op_json`
  contains `name`, `search` or `search_regexp`, and `replace`.
- In a response hook, `zs_res_continue_request()` suppresses the current
  response and asks the server to rerun request middleware with the same
  per-request metadata and request object. This is used by generated Caddy
  middleware for non-terminal reverse-proxy `handle_response` flows such as
  `forward_auth`.

Response/proxy:

- `zs_respond(status, body, body_len)`
- `zs_json_respond(status, json)` (auto-sets Content-Type to application/json)
- `zs_reverse_proxy(backend_url, backend_url_len)`
- `zs_file_server(config_json, config_json_len)` serves a static file response
  for the current request using supported Caddy file-server config JSON. A
  relative `root` resolves against the packed site tar; an absolute `root`
  resolves against the host filesystem only when `--expose-filesystem` is set.
  When `root` is omitted, `http.vars.root`
  is used with a packed-site-root fallback. Caddy placeholders are expanded in
  `fs`, `root`, `hide`, `index_names`, and `status_code` before selecting a file. `hide`
  entries use Caddy-style case-sensitive component/path glob matching. With
  `{"pass_thru": true}`, it returns `1` and leaves the request runnable when no
  file would be served; otherwise it returns `0` after selecting the
  file-server response. File responses suppress `ETag`/`Last-Modified`
  validators for Caddy's invalid modification times (Unix seconds `0` and
  `1`). Browse responses include `Last-Modified`, honor `If-Modified-Since`,
  and return Caddy's listing item array for `Accept: application/json`.

Helper notes:

- String helpers write C strings into the provided buffer.
- If `out_len = 0`, helpers return the required length.
- Binary helpers return the number of bytes written and do not NUL-terminate.
- `zs_sha256` requires `out_len` to be exactly 32 bytes.
- `zs_hmac_sha256` requires an output buffer of at least 32 bytes.
- `zs_base64_encode` needs an output buffer sized to the encoded length; use `out_len = 0` to query it.
- `zs_base64_decode_in_place` uses `buf_len` bytes of input (exclude any trailing NUL).
- `zs_hex_encode` outputs 2 hex characters per input byte; use `out_len = 0` to query the required length.
- `zs_hex_decode_in_place` requires an even `buf_len`; returns the decoded length or -1 on error.
- `zs_json_read_i64` writes a native-endian `i64`; `zs_json_read_bool` writes a single byte.
- Base64 `encoding` values: `ZS_BASE64_STANDARD` (0), `ZS_BASE64_STANDARD_NO_PAD` (1),
  `ZS_BASE64_URL` (2), `ZS_BASE64_URL_NO_PAD` (3).
- Hex `case` values: `ZS_HEX_LOWERCASE` (0), `ZS_HEX_UPPERCASE` (1).
- Header names are matched case-insensitively.
- `ZS_STR("literal")` expands to `(ptr, len)` using `zs_strlen`, which is handy for
  helpers that take a string pointer plus length; only use it with NUL-terminated
  strings and pass explicit lengths for binary or embedded-NUL data.
- `zs_req_body_json` reads the request body lazily (only when called) and caches the
  result for subsequent calls. The body is limited to 256KB by default (configurable
  via `--max-buffered-body-size-kb`); larger bodies return -1. Returns -1 for empty
  bodies or invalid JSON.

Examples:

- `examples/log_request.c` logs method and path.
- `examples/reverse_proxy.c` proxies `/api` to a backend.
- `examples/template.c` sets metadata for templating.
- `examples/health_response.c` returns a JSON health check.

**For a complete list of APIs, run `zeroserve --dump-sdk` to dump the SDK header.**

## Template substitution

When scripts set metadata, Zeroserve performs a simple template replacement on
static text responses. Any `<zs-meta>key</zs-meta>` placeholder (with optional
whitespace around the key) is replaced with the corresponding metadata value.

Rules:

- Only applies to HTML and XML MIME types.
- Only runs for static file responses, not `zs_respond` bodies.
- Unknown keys are removed.

Example:

```html
<h1>Hello <zs-meta>name</zs-meta></h1>
```

If a script does `zs_meta_set("name", ..., "Ada", ...)`, the response becomes:

```html
<h1>Hello Ada</h1>
```

## Reverse proxy behavior

`zs_reverse_proxy` takes a backend URL such as `http://127.0.0.1:9000` or
`https://api.example.com/v1?token=abc`.

Zeroserve will:

- Append the request path to the backend base path.
- Merge the backend query string with the request query string.
- Forward the request `Host` header unchanged; scripts may change or remove it with
  `zs_req_set_header`.
- Fill missing `X-Forwarded-For`, `X-Forwarded-Proto`, and `X-Forwarded-Host`
  headers for proxied requests. Generated Caddy reverse-proxy middleware applies
  configured reverse-proxy request header operations to the upstream request
  only, then applies Caddy's server-level and handler `trusted_proxies` rules to
  either replace untrusted forwarded values or preserve trusted values.
- Generated Caddy reverse-proxy middleware preserves `TE: trailers` on upstream
  requests while stripping other hop-by-hop headers, matching Caddy's proxy
  request preparation.
- Populate `http.reverse_proxy.status_code`, `http.reverse_proxy.status_text`,
  `http.reverse_proxy.header.*`, `http.reverse_proxy.upstream.latency`, and
  `http.reverse_proxy.upstream.latency_ms` placeholders from upstream response
  headers before response hooks run.

Only `http` and `https` backends are supported.

## Socket activation

Zeroserve supports socket activation, where a process manager (such as systemd)
pre-binds the listening sockets and passes them as inherited file descriptors.
Use `fd:N` syntax instead of `ip:port`:

```bash
zeroserve --addr fd:3 site.tar
```

This is useful for:

- Zero-downtime restarts (the socket stays open during process replacement).
- Running without elevated privileges (the parent binds privileged ports).
- Integration with systemd socket units.

Example systemd socket unit (`zeroserve.socket`):

```ini
[Socket]
ListenStream=80
ListenStream=443

[Install]
WantedBy=sockets.target
```

Example systemd service unit (`zeroserve.service`):

```ini
[Service]
ExecStart=/usr/bin/zeroserve --addr fd:3 --tls-addr fd:4 --cert /etc/certs/cert.pem --key /etc/certs/key.pem /var/www/site.tar
```

## Operational notes

- Request logging is enabled by default; disable with `--disable-request-logging`.
- `--enable-proxy-protocol` is required when running behind a TCP load balancer
  that speaks PROXY protocol v1.
- `--disable-ns-isolation` and `--enable-netns-isolation` are Linux-specific
  isolation controls; leave them default unless you know you need them.
- Long-running scripts are throttled; keep scripts fast and avoid busy loops.
- Static file responses include an `ETag`; packed-site defaults use a Blake3
  hash prefix, and Caddy file-server `etag_file_extensions` sidecars use the
  sidecar file's entity tag value. Matching `If-None-Match` requests receive
  `304 Not Modified`.

## Troubleshooting

- TLS startup errors: `--tls-addr` requires either `--cert` plus `--key`, or
  `--cert-dir`.
- `--pack expects a directory`: pass a directory path, not a file.
- `tarball ... does not contain any regular files`: ensure your site has files.
- Script compilation fails: verify `clang` and `llc` are on `PATH`.
