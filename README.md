# zeroserve

Zero-config, fast, scriptable `io_uring` HTTPS server.

`zeroserve` serves a website packaged as a single tarball, runs sandboxed eBPF
request scripts JIT-compiled to native code, and can
compile and serve a [Caddy](https://caddyserver.com/) config directly. It hot
reloads on `SIGHUP`, leaves no temporary files on disk, and hardens itself with
Linux namespaces and capability dropping.

## Highlights

- **`io_uring` end to end.** All network and disk I/O runs on the
  [`monoio`](https://github.com/bytedance/monoio) runtime, with a per-core
  worker thread and `SO_REUSEPORT` listeners.
- **Single-file sites.** A site is just a tarball. It is indexed at load time
  (path → byte range) and served directly via byte-range reads — no extraction,
  no temp files.
- **eBPF request scripting.** Inspect and rewrite requests, generate responses,
  reverse-proxy, rate-limit, do crypto, sign AWS SigV4 requests, and gate the
  site behind OAuth2/OIDC login - all from small eBPF scripts (written in C, or if you prefer, Rust)
  JIT-compiled to native code on load and executed per request.
  It's preferred to feed zeroserve tarballs with precompiled eBPF `.o` files,
  but it also accepts raw `.c` files - zeroserve has a built-in
  [tinycc with eBPF backend patch](https://github.com/losfair/tinycc/tree/ebpf)
  so it can compile C to eBPF on the fly.
- **Caddy compatibility.** Adapt a Caddyfile (or Caddy JSON) to a zeroserve
  script and serve it in one command. See [`CADDY_COMPAT.md`](CADDY_COMPAT.md).
- **Modern TLS.** TLS 1.3 via BoringSSL, SNI certificate selection from a directory,
  and Encrypted Client Hello (ECH) with key rotation and transparent relay
  fallback.
- **Hardened runtime.** Linux namespace isolation, capability dropping, and an
  explicit `--expose-filesystem` opt-in for any host filesystem access.

## Install

Docker:

```bash
docker run --rm -p 8080:8080 -v "$PWD/site.tar:/srv/site.tar:ro" \
  ghcr.io/losfair/zeroserve:0.2.11 --addr 0.0.0.0:8080 /srv/site.tar
```

Images are published to `ghcr.io/losfair/zeroserve` (multi-arch: `amd64`,
`arm64`).

Prebuilt binary from [GitHub releases](https://github.com/losfair/zeroserve/releases):

```bash
curl -fsSL "https://github.com/losfair/zeroserve/releases/download/v0.2.11/zeroserve-$(uname -m)-linux" \
  -o zeroserve && chmod +x zeroserve
```

Iroh-enabled release binaries are published with an `-iroh` suffix, for example
`zeroserve-x86_64-linux-iroh` and `zeroserve-aarch64-linux-iroh`.

From source (requires a recent stable Rust toolchain; Linux only):

```bash
cargo build --release --locked
# binary at target/release/zeroserve
```

> zeroserve is Linux-only because it relies on `io_uring`.

## Quick start

```bash
# Pack the current directory into a site tarball
zeroserve --pack ./public > site.tar

# Serve it over HTTP on :8080
zeroserve --addr 0.0.0.0:8080 site.tar
```

`--pack` walks the directory, adds every regular file, and compiles any
`.zeroserve/scripts/*.c` request script to an eBPF `.o` (the `.c` source is
omitted from the tarball).

## Usage

```bash
# HTTP only (default address is 0.0.0.0:8080)
zeroserve site.tar

# HTTP on :8080 and HTTPS on :8443
zeroserve --tls-addr 0.0.0.0:8443 --cert certificate.pem --key key.pem site.tar

# HTTPS with SNI certificate selection from a directory of PEMs
zeroserve --tls-addr 0.0.0.0:8443 --cert-dir /etc/zeroserve/certs site.tar

# Fall back to <path>.html when a request path is missing
zeroserve --try-html site.tar

# Honor PROXY protocol v1 (e.g. behind a TCP load balancer)
zeroserve --enable-proxy-protocol site.tar

# Reject requests whose Host/SNI is not in the allow-list (otherwise 421)
zeroserve --validate-hostnames example.com,www.example.com site.tar

# Run standalone eBPF scripts with no static files
zeroserve auth.c

# Run plugin scripts before the site's own scripts
zeroserve --plugin auth.c,metrics.o site.tar
zeroserve --plugin-dir ./plugins/auth site.tar

# Inherit a pre-bound socket (socket activation)
zeroserve --addr fd:3 site.tar

# Hot-reload tarball, certificates, and scripts in place
killall -SIGHUP zeroserve
```

Run `zeroserve --manual` to print the full embedded user manual (also in
[`docs/user_manual.md`](docs/user_manual.md)), and `zeroserve --help` for the
complete flag reference.

## Request scripting

Scripts live under `.zeroserve/scripts/` in the site directory and run in
filename order. Each is a C file using the SDK header
([`sdk/zeroserve.h`](sdk/zeroserve.h), also available via
`zeroserve --dump-sdk`):

```c
#include <zeroserve.h>

ZS_ENTRY
zs_u64 entry(void) {
  char path[64];
  zs_req_path(path, sizeof(path));

  if (zs_strcmp(path, "/health") == 0) {
    zs_meta_set(ZS_STR("zs.response.header.content-type"), ZS_STR("application/json"));
    zs_respond(200, ZS_STR("{\"status\":\"ok\"}\n"));
  }
  return 0;
}
```

Scripts are compiled to eBPF and JIT-executed per request inside a memory- and
time-bounded sandbox. The helper API covers request/response inspection and
mutation, response templating, logging and time, crypto and encoding
(SHA-256, HMAC, base64, hex, random), AWS SigV4 signing, rate limiting,
reverse proxy, OAuth2/OIDC login with sealed cookies, and strongSwan VICI
lookups. See the "Request scripting" section of the user manual for the full
helper reference, and [`examples/`](examples/) for runnable scripts.

> Generating scripts is easiest via the `zeroserve-script-create` workflow, or
> by hand against `sdk/zeroserve.h`.

## Script sandboxing: the pointer cage

Request scripts are compiled to eBPF and JIT-executed **in-process**, in the
same address space as the server. The pointer cage — provided by the
[async-ebpf](https://github.com/losfair/async-ebpf) runtime — is the memory
isolation boundary that makes this safe: a buggy or malicious script cannot read
or write any memory outside its own sandbox, no matter how it computes a pointer.

It works by confining every guest memory access to a fixed, power-of-two-sized
window of virtual memory:

- **Caged layout.** Each program gets one anonymous mapping, initially
  `PROT_NONE`, carved into a read/write **stack** region (per-invocation) and a
  read-only **data** region (the linked program image), separated and surrounded
  by **guard regions**. The guard sizes are randomized per program (ASLR-style),
  and the whole window is padded to a power of two with a one-page margin on each
  side to absorb the maximum load/store displacement.
- **Branchless pointer masking.** The JIT (a patched [uBPF](https://github.com/iovisor/ubpf))
  rewrites every load and store address to `(address & mask) + offset` before the
  native access, where `mask = window_size - 1` and `offset` is the window base.
  Because the window is a power of two, _any_ pointer — however the script
  arithmetic produced it — is forced back inside the cage. The transform is
  branchless, so there is no mis-speculatable path for a transient out-of-bounds
  read (Spectre-v1).
- **Guard pages catch escapes.** A masked pointer that lands in a guard region
  hits `PROT_NONE` memory and faults. A `SIGSEGV` handler translates the faulting
  native address back to a guest offset and turns it into a clean, contained
  program fault instead of a server crash or an escape.
- **Immutable code and data.** After linking, the data/code region is frozen to
  read-only (`mprotect`), and the JIT confines **all stores to the stack region**
  regardless of analysis hints — so a script can never modify its own code or the
  shared data region.

Static region analysis is layered on top as a _performance_ optimization (it
lets confidently-classified loads skip one of two region probes), but it is
explicitly **not** a security boundary — the JIT always retains a single-region
bounds check, so the cage holds even if the analysis is imprecise.

## Caddy compatibility

zeroserve can adapt and compile the HTTP-routing portion of a Caddy config —
either a native Caddyfile or Caddy JSON, auto-detected by content:

```bash
# Adapt → compile → in-memory site → serve, all in one shot
zeroserve --caddy Caddyfile --addr 0.0.0.0:8080

# Compile a Caddy config to a zeroserve script you can pack into a site
zeroserve --caddy-compile Caddyfile > .zeroserve/scripts/50-caddy.c

# Just adapt a Caddyfile to Caddy JSON and inspect it
zeroserve --adapt-caddyfile Caddyfile
```

Supported directives include `respond`/`error`/`abort`, `redir`,
`header`/`request_header`, `rewrite`/`uri`/`method`,
`handle`/`handle_path`/`route`/`handle_errors`, `root`/`fs`/`vars`/`map`,
`basic_auth`, `request_body`, `file_server`, and single-upstream
`reverse_proxy`, with matchers, route groups, response hooks, and
`tls.client_auth` policies. The full supported surface and known non-goals are
documented in [`CADDY_COMPAT.md`](CADDY_COMPAT.md).

## Encrypted Client Hello (ECH)

```bash
# Generate an ECH keypair + ECHConfig (PEM to stdout, DNS guidance to stderr)
zeroserve --gen-ech-key --ech-public-name ech.example.com > ech.pem

# Serve with ECH enabled (TLS must be configured)
zeroserve --tls-addr 0.0.0.0:8443 --cert-dir /etc/zeroserve/certs \
  --ech-key /etc/zeroserve/ech site.tar
```

`--ech-key` accepts a single PEM bundle or a directory of key files for rotation.
See the "Encrypted Client Hello" section of the user manual for the rotation,
rejection, and transparent-relay-fallback behaviors.

## Hot reload

Send `SIGHUP` (or point `--reload-signal-file` at a file whose contents change)
to reload the site tarball, TLS certificates, and scripts atomically. The last
known-good runtime state is preserved if a reload fails.

## Building and testing

```bash
cargo fmt --all --check       # verify formatting
cargo build --release --locked
cargo test --locked           # Rust unit tests

cd testing && deno test -A --parallel   # end-to-end tests (TypeScript/Deno)
```

The e2e suite launches `target/release/zeroserve`, so build the release binary
first. Scripting tests use the built-in tinycc backend by default; pass
`--ebpf-compiler clang` (and have `clang`/`llc` on `PATH`) to exercise the
clang path. Caddy comparison tests require a `caddy` binary (exposed via
`CADDY_BIN`).

## License

MIT — see [`LICENSE`](LICENSE).
