# Iroh Reverse Proxy Design

This note proposes adding an iroh-backed reverse-proxy transport to zeroserve.
The goal is to let a normal zeroserve route proxy HTTP requests to a remote
iroh endpoint identified by its key, while preserving the current script and
Caddy reverse-proxy surface.

## Research Summary

As of 2026-06-15, iroh is a Rust networking stack for authenticated,
end-to-end encrypted QUIC connections between endpoints. It handles direct
connectivity, NAT traversal, and relay fallback under the hood. The main
application object is an endpoint, and iroh recommends one endpoint per
application so outbound connections share connectivity state.

Every iroh endpoint has a cryptographic public identifier. Current iroh
documentation calls this an `EndpointID` in concept docs and `EndpointId` /
public key in Rust API docs; some ecosystem crates expose the same idea as a
node id. Connecting to a peer requires the peer key, enough addressing
information to reach it, and an ALPN string that selects the application
protocol on the resulting QUIC connection. Address lookup can make the key
alone sufficient by resolving relay URLs and direct addresses. Endpoint tickets
are serializable bundles of endpoint address information for cases where lookup
is not enough.

Iroh exposes QUIC streams after connection. Streams are cheap and multiplexed,
so the natural HTTP proxy mapping is one HTTP request per iroh bidirectional
stream on a long-lived iroh connection. Protocol handlers are selected by ALPN.

Relevant references:

- Iroh overview: https://docs.iroh.computer/what-is-iroh
- Endpoint concepts: https://docs.iroh.computer/concepts/endpoints
- Protocol and ALPN concepts: https://docs.iroh.computer/concepts/protocols
- Rust `iroh` crate docs: https://docs.rs/iroh/latest/iroh/
- Dumbpipe protocol source: https://github.com/n0-computer/dumbpipe

## Current Zeroserve Fit

The existing reverse-proxy path is intentionally simple and script-driven:

- Native scripts call `zs_reverse_proxy(url)` in `src/helpers/generic.rs`.
- Generated Caddy middleware emits `zs_reverse_proxy(...)` from
  `src/caddy_compile.rs`.
- Runtime proxying in `src/server.rs` parses the selected string with
  `parse_backend_target`, opens a backend transport with `connect_backend`, then
  runs the existing HTTP/1 proxy codec over TCP, TLS, or Unix sockets.
- `src/pool.rs` stores reusable backend HTTP/1 connections per worker thread.

That means iroh should be introduced as a backend transport selected by URL
scheme, not as a script helper. Scripts and generated Caddy code should continue
to choose a terminal proxy destination; Rust should decide how to dial it.

## User-Facing Shape

Add an optional iroh feature and a new upstream URL scheme:

```caddyfile
example.com {
  reverse_proxy iroh://<endpoint-key>
}
```

Native script use remains the same:

```c
zs_reverse_proxy(ZS_STR("iroh://<endpoint-key>"));
```

The URL grammar should allow:

- `iroh://<endpoint-key>`: dial by key using configured address lookup.
- `iroh://<endpoint-key>/<base-path>`: prepend a base path like existing HTTP
  upstream URLs.
- `?addr=<socket-addr>`: provide one or more direct addresses for dialing. This
  parameter is consumed by zeroserve and is not forwarded upstream.
- `iroh+ticket://<endpoint-ticket>` or `iroh://ticket/<encoded-ticket>`:
  optional ticket form when the operator has full endpoint addressing material.
- `?alpn=<name>`: optional future override for advanced interop; the first
  implementation uses dumbpipe's default ALPN.

The first implementation should require the remote endpoint to speak the chosen
HTTP-over-iroh protocol. "Any remote service on iroh by key" therefore means
any service that exposes HTTP over the agreed iroh ALPN, not arbitrary existing
iroh protocols such as blobs, docs, or gossip.

## Protocol

Use one iroh bidirectional stream per HTTP request. On each stream, zeroserve
writes the same HTTP/1.1 request head and body that it currently writes to TCP
backends, and reads an HTTP/1.1 response head and body back through an
incremental parser.

Recommended default ALPN:

```text
DUMBPIPEV0
```

Dumbpipe's default protocol requires the side that opens the bidirectional
stream to send the fixed handshake bytes `hello` before arbitrary stream data.
zeroserve then writes a normal HTTP/1.1 request and expects a normal HTTP/1.1
response. This keeps the runtime small and compatible with zeroserve's existing
proxy hooks, compression, body limits, WebSocket handling, and response
streaming without adding a third-party HTTP-over-iroh protocol crate.

## Runtime Architecture

Add a new module, `src/iroh_proxy.rs`, behind a Cargo feature such as
`iroh-proxy`.

Responsibilities:

- Own the single process-wide iroh endpoint.
- Persist or load an iroh secret key from a CLI-configured path, load a 64-hex
  secret key from `ZEROSERVE_IROH_SECRET_KEY`, or generate an ephemeral key when
  neither is configured.
- Create new secret-key files with `0600` permissions and tighten existing
  group/world-readable key files before reading them.
- Configure iroh address lookup and relay defaults.
- Dial a remote endpoint by key or ticket with the selected ALPN.
- Cache iroh connections by endpoint key.
- Open one bidirectional stream per proxied HTTP request.
- Write and parse HTTP/1 incrementally over the dumbpipe stream.

`src/server.rs` changes:

- Extend `BackendScheme` with `Iroh`.
- Extend `BackendTarget` with iroh target metadata: endpoint key or ticket,
  ALPN, and optional base path/query.
- Teach `parse_backend_target` to parse `iroh://...`.
- Teach `connect_backend` to return a new pooled connection variant for iroh
  streams, or split the existing function into "connection-backed" and
  "request-stream-backed" transports.

The important design choice is pooling. TCP/Unix pooling stores one reusable
HTTP/1 connection. Iroh should instead pool the QUIC connection and create a
fresh stream per request. That suggests this split:

- Keep `pool.rs` for TCP/TLS/Unix HTTP/1 backend connections.
- Add an iroh connection cache in `iroh_proxy.rs`.
- Do not return individual iroh streams to `pool.rs`.

This avoids corrupting HTTP/1 stream state across QUIC streams and fits iroh's
cheap-stream model.

## Tokio And Monoio Boundary

zeroserve runs on monoio. The iroh ecosystem currently assumes Tokio-style
async IO. The implementation should isolate that mismatch:

- Run an internal Tokio runtime on one or more background threads only when
  `iroh-proxy` is enabled.
- Use request-scoped channels to ask the iroh runtime to open a stream.
- Wrap each returned stream with a small adapter that presents monoio-compatible
  async read/write operations, or forward bytes through bounded channels if a
  direct adapter is not practical.

The direct adapter is preferred for throughput and backpressure. The channel
bridge is acceptable for the first implementation if it has bounded buffers,
propagates cancellation, and is covered by streaming-body tests.

The current implementation uses bounded runtime-neutral channels across the
monoio/Tokio boundary. It is streaming and waker-driven, not poll/sleep driven,
and the request upload and response download paths run concurrently. HTTP/1
WebSocket upgrades are tunneled as raw bytes after the upstream `101 Switching
Protocols` response.

## CLI And Configuration

Add CLI flags in `src/cli.rs`:

- `--iroh-proxy`: enable iroh reverse-proxy transport.
- `--iroh-secret-key <path>`: load or create a stable local iroh endpoint key
  containing 64 hex characters.
- `ZEROSERVE_IROH_SECRET_KEY`: optional 64-hex local endpoint secret key used
  when `--iroh-secret-key` is omitted.
- `--iroh-relay <url>`: optional relay override; default to iroh/N0 defaults.
- `--iroh-address-lookup <mode>`: default lookup mode for key-only dialing.
- `--iroh-alpn <value>`: default ALPN for `iroh://` upstreams.

When the feature is not compiled in or the runtime flag is disabled,
`iroh://...` should fail clearly at request time and during `--caddy-compile`
validation where possible.

## Caddy Compatibility

Caddy's `reverse_proxy` adapter already compiles to a single URL string. The
least invasive compatibility rule is:

- Allow `reverse_proxy iroh://<key>` as a zeroserve extension.
- Keep rejecting Caddy dynamic upstream discovery and advanced transport
  options for iroh, same as the existing constrained reverse-proxy surface.
- Record the extension in `CADDY_COMPAT.md` because stock Caddy does not have
  this upstream scheme.

`upstream_to_url` and reverse-proxy validation should accept `iroh://` only in
zeroserve's compiler/runtime. The generated C still calls `zs_reverse_proxy`;
no eBPF SDK change is required.

## Security Model

- The remote peer identity must be pinned to the key in the `iroh://` URL.
- Do not trust application-level headers from the remote peer beyond existing
  reverse-proxy behavior.
- Do not expose filesystem or local network access through iroh automatically.
  A companion "serve local HTTP over iroh" bridge must require an explicit local
  target URL.
- Preserve existing request-body limits and timeout behavior.
- Add explicit dial and response-header timeouts for iroh, because relay-backed
  paths can fail differently than local TCP.
- Bound queued iroh proxy commands and concurrent fetches so the background
  Tokio runtime applies backpressure under load.
- Log the authenticated remote key and whether the connection used relay or
  direct paths when iroh exposes that state.

## Testing Plan

Unit tests:

- Parse valid and invalid `iroh://` URLs.
- Confirm base path/query merging matches HTTP upstream behavior.
- Confirm pool keys and future iroh connection-cache keys include endpoint
  identity.
- Confirm Caddy compile accepts the zeroserve extension and rejects unsupported
  iroh transport options.

Integration tests:

- Start a test iroh HTTP service and proxy through zeroserve by key.
- Confirm base path/query merging for `iroh://<key>/<base>?addr=...&x=...`
  matches existing HTTP upstream behavior.
- Confirm response bodies stream incrementally through zeroserve instead of
  being collected before forwarding.
- Stream request bodies larger than the in-memory body limit.
- Exercise the request-body TooLarge path.
- Exercise HTTP/2 clients against the same iroh upstream.
- Verify WebSocket upgrade requests tunnel raw bytes after the `101` response.
- Kill the remote endpoint and verify zeroserve returns a gateway error without
  poisoning hot reload state.

Manual tests:

- Relay-only connectivity with direct UDP blocked.
- Key-only dialing through configured address lookup.
- Ticket dialing when address lookup is disabled.

## Open Questions

- Should future versions add an ALPN override, or keep the transport strictly
  dumbpipe-compatible?
- Which iroh address lookup mechanism should be enabled by default for server
  deployments?
- Should zeroserve also expose its own HTTP service over iroh, or only act as an
  iroh client for reverse proxying?
- Should `iroh://<key>` be available by default in binaries, or behind a
  separate release artifact/feature due to Tokio and dependency size?
- How should access logs represent iroh upstream latency and relay/direct path
  state?
- Should future versions expose more generic HTTP/1 upgrade tunneling beyond
  WebSocket-shaped upgrades?

## Proposed Milestones

1. Feature-gated parser and Caddy acceptance for `iroh://` upstreams, returning
   a clear "iroh proxy not enabled" runtime error.
2. Internal iroh endpoint manager and connection cache.
3. HTTP/1 request-per-bidirectional-stream proxying for non-upgrade requests.
4. Streaming body and HTTP/2 client coverage.
5. Optional companion bridge/example for exposing a local HTTP service over the
   dumbpipe-compatible iroh ALPN.
6. Broader upgrade/full-duplex coverage if tests show more protocol variants
   are needed beyond WebSocket-shaped upgrades.
