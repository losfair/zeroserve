# zeroserve

Zero-config, fast `io_uring`-based HTTPS server.

`zeroserve` serves a website packaged as a tarball, can run standalone eBPF
`.c`/`.o` scripts directly, and handles hot-reload via SIGHUP.

## Features

- Built-in TLS support
- All network and disk I/O use `io_uring`
- Clean - does not leave any temporary files on disk. Tarballs are indexed during loading (path -> byte-range), and served via byte-range reads on the tarball directly.
- Support for low-latency eBPF request processing middleware

## Dependencies

- `monoio`: the `io_uring` runtime
- `clap`: Argument parser (use derive macro)
- `monoio-rustls`: TLS server
- `tar`: Tarball handling

## Usage

```bash
# Serve HTTP on port 8080
zeroserve --addr 0.0.0.0:8080 site.tar

# Serve HTTP on port 8080, and HTTPS on port 8443
zeroserve --addr 0.0.0.0:8080 --tls-addr 0.0.0.0:8443 --cert certificate.pem --key key.pem site.tar

# Serve HTTPS with SNI certificate selection from a certificate directory
zeroserve --addr 0.0.0.0:8080 --tls-addr 0.0.0.0:8443 --cert-dir /etc/zeroserve/certs site.tar

# Fall back to <path>.html when a request path is missing
zeroserve --addr 0.0.0.0:8080 --try-html site.tar

# Honor PROXY protocol v1 headers (e.g. when behind a TCP load balancer)
zeroserve --enable-proxy-protocol site.tar

# Run standalone eBPF scripts directly
zeroserve --plugin auth.c app.o

# Hot-reload certificate, site tarball, or standalone eBPF scripts
killall -SIGHUP zeroserve
```

## Testing

End-to-end tests live in `testing/` and are written in TypeScript for Deno.

```bash
# Run all e2e tests
cd testing
deno test -A --parallel
```

The scripting tests use the builtin tinycc compiler by default. Pass
`--ebpf-compiler clang` to use clang/llc for `.zeroserve/scripts/*.c` and
generated `--caddy` middleware instead.
