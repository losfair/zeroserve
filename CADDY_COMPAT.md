# Caddy Compatibility

This document records the current state of zeroserve's Caddy compatibility
layer. It is a practical compatibility target, not a claim that zeroserve is a
drop-in replacement for the full Caddy runtime.

## Scope

zeroserve can adapt supported Caddyfiles to Caddy JSON and can compile supported
Caddy HTTP JSON to a generated zeroserve eBPF/C middleware script. The generated
middleware runs in zeroserve's request-processing surface, so features outside
that surface are either ignored with warnings where they have no request effect,
or rejected when approximating them would be misleading.

Supported work is centered on HTTP request routing, matchers, header mutation,
URI rewriting, basic static responses, static file serving, selected reverse
proxy behavior, response hooks, variables, maps, and basic authentication.

## Entry Points

- `--caddy-compile <path>` compiles a Caddy JSON config, or a Caddyfile
  path which is first adapted to JSON, and writes generated C middleware to
  stdout.
- `--caddy <path>` runs a Caddyfile (or Caddy JSON) directly end to end:
  adapt -> compile -> in-memory site tarball -> serve. The generated
  middleware C and the resulting tarball live entirely in memory (memfd); no
  SITE_TAR argument is needed.
- Caddy-translated middleware uses the bundled `zeroserve_caddy.h` helper layer
  instead of emitting large helper implementations inline.
- Response processing hooks are registered through the `zs_call` mechanism and
  run during response processing for the current request.
- The metadata map is shared between request and response phases. Existing
  response-header-in-metadata-map behavior continues to work.

## Caddyfile Adapter

The adapter implements the supported directive set needed by the compiler and
tracks Caddy behavior for many parser and validation edge cases. Current covered
areas include:

- site address parsing, wildcard hosts, duplicate/ambiguous site validation, and
  known-directive-as-address diagnostics
- Caddy-like site block pairing by listener address, including mixed implicit
  HTTPS/explicit HTTP site keys, listener-specific `servers { name ... }`
  adapter output, site `bind` listener shaping, and server trusted-proxy
  option validation where it is outside the generated request middleware
  surface
- global options needed for directive ordering and filesystem definitions, with
  warnings or errors for unsupported runtime options
- imports, import globs, snippet registration from imported files, snippet
  arguments, `{block}`, `{blocks.name}`, named routes, and heredocs
- canonical route ordering for supported directives, including `handle`,
  `handle_path`, `route`, `handle_errors` status/fallback ordering, and named
  route invocation
- matcher syntax for path, method, host, header, query, vars, regexp, file,
  `not`, and supported expression forms
- directives including `respond`, `redir`, `map`, `vars`, `root`, `rewrite`,
  `uri`, `try_files`, `file_server`, `request_header`, `header`,
  `request_body`, `basic_auth`, `reverse_proxy`, `forward_auth`, `intercept`,
  `log`, `log_skip`, `bind`, `tls`, `metrics`, `acme_server`, and
  observability directives where relevant to validation, including nested
  access-log output/format option blocks accepted outside the generated
  request middleware surface
- real-world path-scoped `file_server /path/* browse` routes alongside default
  static file serving, path headers, and `handle_path` reverse proxying
- real-world multi-upstream routing with site `bind`, `handle_path` prefix
  stripping, browse static files, and `header_up` Host/request-header
  placeholder propagation
- real-world `header_regexp User-Agent` denylist matching from a published
  AI-bot Caddyfile snippet, validated with matched and non-matched requests
- real-world static docs negotiation with regexp-capture rewrites,
  trailing-slash redirects, markdown `Accept` handling, cache headers, and
  `handle_errors` fallback pages
- real-world route-scoped upload file serving alongside catch-all proxying,
  gzip encode, ignored access-log configuration, and status-specific
  `handle_errors` fallback for upstream connection failures
- reverse-proxy transport option adaptation for supported Caddyfile parsing
  shapes, including Caddy's `transport http` resolver object form and
  `compression off`; timeout and keepalive tuning is ignored with warnings by
  the compiler, while unsupported transport behavior that would change proxied
  request semantics is rejected
- reverse-proxy single-upstream load-balancing/retry Caddyfile options such as
  `lb_try_duration` and `lb_try_interval`, validated as ignored with warnings
  while preserving proxied request behavior
- reverse-proxy dynamic upstream Caddyfile adaptation, including signed
  Go-style duration values such as negative `dial_fallback_delay`; generated
  middleware still rejects dynamic upstream discovery as outside zeroserve's
  supported runtime surface
- PHP FastCGI shortcut and expanded-form adapter JSON shape, including
  Caddy-compatible split-path and fallback try-policy lowering; generated
  middleware still rejects FastCGI runtime transport as outside zeroserve's
  supported runtime surface

Unsupported Caddyfile directives or subdirectives should fail during adaptation
or compile with explicit diagnostics instead of silently generating incorrect
middleware.

## JSON Compiler

The JSON compiler supports these Caddy HTTP handlers in the generated
middleware:

- `static_response`
- `error`
- `headers`
- `rewrite`
- `request_body` for request size/time limits only
- `reverse_proxy` for supported single-request proxy behavior
- `intercept` for supported response-header/status hooks
- `file_server`
- `vars`
- `map`
- `invoke`
- `subroute`
- `authentication` with HTTP basic auth
- `encode` for gzip/zstd response compression
- `log_append` and `tracing` as validated no-op/ignored observability surfaces

The compiler validates unknown fields on supported handlers, routes, matchers,
servers, and apps where zeroserve has a modeled schema. This is intentional:
unrecognized Caddy JSON often means behavior zeroserve cannot reproduce.

## Runtime Behavior Implemented

Current generated middleware support includes:

- route matching and ordering for supported Caddy route structures
- request method, host, path, query, header, remote IP, client IP, regexp, file,
  vars, expression, and `not` matchers
- placeholder expansion for supported request, original request, regexp,
  variable, map, file matcher, reverse-proxy response-header, and error-status
  placeholders
- static responses, redirects, and Caddy-compatible redirect HTML bodies
- request header set/add/delete/replace
- response header set/add/delete/replace, including deferred response hooks and
  response matcher conditions
- URI/path/query rewrite operations, including set/add/delete/rename/replace
  query operations and regexp path replacement
- maps with defaults, literal mappings, regexp mappings, typed Caddyfile
  outputs, and multiple destinations
- basic auth with bcrypt and argon2id hashes, challenge responses, credential
  checks, and `{http.auth.user.id}`
- Caddy `tls.client_auth` policies for supported modes (`require`,
  `verify_if_given`, and `require_and_verify`) using inline trusted CA
  certificates from Caddy JSON/Caddyfile adaptation. Generated middleware emits
  a `zeroserve.tls` eBPF section which enforces the policy before normal HTTP
  request routing.
- file serving from packed tarball content and from configured filesystem roots
  only when zeroserve is started with `--expose-filesystem`
- Caddyfile/Caddy JSON access logging to `output file ...` targets, written by
  a dedicated monoio/io_uring logging thread when `--expose-filesystem` is
  enabled; without that flag, file logging is a no-op
- file-server options including root, hide, index names, status code,
  pass-thru, browse sort/file limit, sidecar ETags, and selected precompressed
  sidecar behavior
- Caddy `encode` response compression for gzip and zstd, including
  `Accept-Encoding` negotiation, minimum-length and response-matcher checks,
  `no-transform` handling, header mutation, buffered bodies, file bodies, and
  reverse-proxy bodies. Brotli and other encoder modules remain intentionally
  unsupported.
- conditional requests (`If-Match`, `If-None-Match`, `If-Modified-Since`,
  `If-Unmodified-Since`, `If-Range`) and single byte-range requests, matching
  Go's `net/http.ServeContent` semantics that Caddy's file server delegates to:
  RFC 7232 precondition precedence (`304`/`412`), suffix and open-ended ranges,
  `416` responses (`invalid range` with no `Content-Range`; `failed to overlap`
  with `bytes */N`), the empty-file and oversized-range special cases, and
  HTTP-date parsing that ignores the weekday like Go does
- error routes and `handle_errors` for supported error status handling
- reverse proxying to supported static or placeholder-expanded upstreams,
  selected request rewrite/header mutation including upstream method/URI
  rewrite with Caddy-compatible `GET`/`HEAD` request-body suppression,
  response-header hooks, response status replacement, Caddy's default upstream
  `Accept-Encoding: gzip` request header when the client request does not
  supply one, `transport http`
  `compression off` disabling that default, direct `502 Bad Gateway` fallback
  on upstream connection failure, connection-error fallback through
  `handle_errors`, and
  `forward_auth` copied-header behavior. Generic `reverse_proxy handle_response`
  routes that would suppress or replace the upstream response body are rejected
  rather than approximated.
- response hook registration and execution through `zs_call`

## Intentional Exclusions

zeroserve does not attempt to support Caddy compatibility features that require
body rewriting/copying or Caddy's full server runtime. In particular:

- no `Via` header injection or handling
- no Caddy request body rewriting
- no Caddy response body rewriting, response body copying, or response body
  suppression, including generic `reverse_proxy handle_response` response routes
- no `templates` or `copy_response` generated behavior
- no `encode` support for brotli or other encoders beyond gzip and zstd
- no `multipart/byteranges` responses: a request for multiple byte ranges is
  not served as a multipart body. Such requests have their `Range` header
  ignored and receive the full `200 OK` representation (which RFC 7233
  section 3.1 permits). Single-range requests are fully supported.
- no `zs_req_set_body`, `zs_res_set_body`, `zs_res_suppress_body`, or
  `zs_res_copy_body` APIs
- no generic `zs_res_set_header`, `zs_res_append_header`, or
  `zs_res_delete_header` APIs
- no TLS automation, listener management, certificate management, ACME server
  runtime, ECH, or PKI runtime behavior
- no custom Caddy `tls.client_auth` verifier modules or trusted-leaf-only
  client-auth behavior
- no Prometheus metrics serving
- no HTTP/2 server push; Caddy `push` handlers are validated and ignored with
  warnings because server push is outside the generated request middleware
  surface
- no PHP FastCGI runtime behavior
- no full Caddy logging/tracing runtime behavior beyond supported file access
  logs
- no advanced reverse-proxy load balancing, retry, health-check, dynamic
  upstream, or transport/TLS customization semantics
- no filesystem exposure unless `--expose-filesystem` is explicitly provided

Unsupported surfaces should be rejected or warned about clearly. They should not
be approximated in generated middleware.

## Validation State

Current validation combines Rust unit tests and Deno end-to-end tests. The most
important checks are:

- `cargo test --bin zeroserve caddyfile::adapter:: -- --nocapture`
- `cargo test --bin zeroserve caddy_compile::tests:: -- --nocapture`
- `cargo test --bin zeroserve server::caddy::tests:: -- --nocapture`
- `cargo test helpers::`
- `cargo build --release`
- `python3 tools/caddyfile_golden.py /tmp/caddy-fresh ./target/release/zeroserve testing/caddyfile_fixtures`
- `cd testing && deno test -A caddy_e2e_compare_test.ts`
- relevant focused tests in `testing/caddy_compile_test.ts`
- `cargo fmt --check`
- `git diff --check`

The live comparison tests start stock `caddy run` and zeroserve against generated
Caddyfiles, then compare actual HTTP responses for supported behavior. Several
cases are ported or adapted from `/mnt/jfs/caddy/caddytest/integration`,
including Caddy `encode` gzip/zstd negotiation, response-matcher gating, and
`Cache-Control: no-transform` behavior over real HTTP, plus Caddy integration
method, rewrite, URI query-operation, import/snippet block, reverse-proxy,
`forward_auth`, `intercept`, placeholder, and basic-auth fixtures with concrete
expected response bodies and headers, plus request-header mutation fixtures
with concrete mutated header response bodies, and Caddy upstream issue coverage
for deferred default response headers (`?Header`) preserving already-set
headers and for site-level/scoped response headers retained alongside
`handle` blocks. Ignored Caddy `push`,
`log_append`, and `tracing` handler fixtures assert compile warnings and
unchanged fallthrough response behavior. The suite also
includes localized real-world Caddyfiles from popular GitHub repositories for
supported conditional request-header propagation, file-matcher static-miss
proxy routing including Caddy's default upstream `Accept-Encoding: gzip`
behavior, Caddy docs-style reverse-proxy `transport http` `compression off`,
path-scoped reverse-proxy fallthrough, scoped `header_up` request-header
deletion before proxying, `header_down` Set-Cookie domain replacement using
request placeholders, trusted-proxy `client_ip` matcher resolution from
configured forwarding headers, `handle_path` prefix stripping before nested
file-server root resolution, SPA/static,
extension-fallback docs routing, Matrix delegation responses with CORS headers,
Ghost-style nested development gateway routing with strip-prefix rewrites,
upstream header mutation, and reverse-proxy connection-error fallback through
`handle_errors`,
Mastodon-style file/regexp matcher static routing and streaming/fallback
proxying, Immich-style multi-service `handle_path` proxy routing, Nextcloud
AIO-style routed app proxying with strip-prefix rewrites and upstream header
mutation, Directus-style path-scoped `try_files` fallbacks served by a global
file server, exact env/static/cache-header SPA gateway routing, host-gated
docs/landing redirects with ignored global server options, protected-file,
protected static-dashboard
fallback, public-bypass/protected-proxy basic-auth routing, snippet-import,
multi-host AI service proxy fanout, Netmaker-style multi-host proxy fanout
with broad security headers and WebSocket-style header-matcher no-upgrade
behavior, 3x-ui-style WebSocket-gated route proxying with forbidden fallback,
OpenMediaVault-style reverse-proxy response-header deletion,
Chibisafe-style upload `file_server pass_thru` routing before named API/docs
and default reverse proxies with upstream Host/request-header propagation,
Appsmith-style request-ID expression matcher/header normalization plus `/info`
rewrite-to-file serving and loading-page fallback,
API-and-SPA handle_path routing,
public/private proxy split, variable-derived
reverse-proxy header propagation, request-body-limited API/client proxy splits,
request-body-only `handle_path` branches falling through to a later shared
proxy snippet with header propagation, variable-derived proto and incoming
forwarded-for proxy header propagation,
multi-subpath AriaNg/File Browser/Rclone proxying with ignored transport
timeout/keepalive tuning, Freedium-style imported proxy snippets with ignored
single-upstream `lb_try_*` retry tuning, media-proxy/static front routing with
forwarded proxy headers, dotfile denial, and ignored streaming flush/timeout
fields asserted as warnings, multi-branch blog/admin proxy routing with URI
aliases and admin SPA fallback,
FreshRSS-style subfolder redirects and strip-prefix proxying with forwarded
prefix, host, and request header propagation,
Gitea-style explicit real-IP and forwarded-for reverse-proxy header
propagation,
PostHog-style CORS preflight handling, global CORS response headers,
path-specific proxy routing, and upstream CORS header deletion,
CORS static/media with `forward_auth`, query-driven media download headers on
served files and file-server misses, subpath SPA/proxy routing with Host-regexp
matcher shapes, generated admin-subpath redirect/fallback routing,
overlapping API `handle_path` rewrites with exact-route precedence and
regexp-cookie external redirects,
Authelia-style auth portal/protected-subpath `forward_auth` with copied and
request-header-propagated auth headers, Authelia-style explicit auth-check
reverse-proxy method/URI rewrites with upstream `GET` body suppression and
original-method/original-URI header propagation, Authentik-style route-wrapped
outpost bypass plus copied identity headers, multi-path gateway proxy
precedence, and API-proxy patterns, plus generated static-site templates with
clean URLs, hidden files, status-page error
handling, file-server error-route app-shell fallback, and published AI-bot
User-Agent regexp denylist matching, plus Pagefind-style docs redirects,
markdown negotiation, cache headers, and error pages, and Bonfire-style
route-scoped upload serving with `502` to `503` proxy-error fallback, plus
Caddy upstream issue coverage for repeated `handle_errors` app-shell serving
through `file_server { status 200 }`; those real-world
probes assert concrete expected status, body, and header behavior in addition
to comparing zeroserve against stock Caddy. The protected AriaNg fixture also
requires the generated middleware compiler to warn about ignored
`reverse_proxy.transport` timeout, keepalive, and connection-limit tuning before
it runs the real proxied-response comparison. Focused compiler tests separately
assert that real Caddyfile transport timeout and keepalive aliases adapt
successfully and emit ignore warnings at compile time. A generated Caddyfile
fixture now also validates those ignored transport tuning fields end to end
against stock Caddy, asserting both the compile warnings and the successful
proxied response.
The Caddyfile golden route-tree comparator normalizes zeroserve's internal
`caddy_access_log` handlers because Caddy stores access-log configuration
outside the request route tree; file access-log behavior is covered by Deno
runtime tests.
The current local reference was built fresh from `/home/user/caddy` at
`d3986f824d2e82310405d5ca520d61f3e2e701c9` for the latest comparison run.

## Known Incomplete Areas

The current implementation is intentionally narrower than Caddy. Remaining risk
is mostly in exact edge-case parity:

- broader Caddyfile parser/provisioning diagnostics
- long-tail global option/module validation
- uncommon route sorting and matcher combinations
- `try_files` candidates containing query strings: adaptation currently lowers
  them to file matcher plus rewrite routes, but a live comparison against Caddy
  issue #2891-style `try_files /test.php?{query}&p={path}` did not produce a
  supported parity fixture; stock Caddy returned a request error for the
  localized reverse-proxy route while zeroserve rewrote through to the upstream
- multi-range (`multipart/byteranges`) responses, which are intentionally
  unsupported (see Intentional Exclusions); single-range and conditional
  request handling is covered by live comparisons
- placeholder timing and unsupported placeholder diagnostics outside covered
  paths
- matcher-set-local dependencies where one matcher consumes regexp captures
  from another matcher in the same matcher map; fresh Caddy runs showed this can
  depend on Go map evaluation order, so live fixtures avoid relying on it
- deeper response-hook ordering interactions across proxy, file-server, and
  error-route boundaries
- reverse-proxy behavior beyond the supported single-request/header/status hook
  surface

These gaps are documented rather than hidden. Future compatibility work should
prefer Caddy's own fixtures from `/mnt/jfs/caddy/caddytest/integration` and
should keep unsupported body-rewrite/runtime features rejected.
