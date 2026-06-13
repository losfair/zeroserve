#!/usr/bin/env python3
"""
Routing/matching benchmark for the Caddy-generated middleware.

Generates a synthetic Caddyfile with N virtual hosts (each with path routes and
a path_regexp route), starts `zeroserve --caddy` in the background, and drives
it with wrk against representative hosts:

  - first   : host that sorts first in the route chain (best case)
  - last    : host that sorts last (worst case: walks every host matcher)
  - last-re : regexp route on the last host (regex matching cost)
  - miss    : host that matches nothing (full walk, 200 {} fallback)

Thread budget (dev machine has 8 fast cores): server --threads 3, wrk -t2.

Usage:
  benchmark/routing/benchmark.py --label baseline [--sites 256] [--duration 3]

Results are printed as a table and appended as JSON lines to
benchmark/routing/results.jsonl with the given label.
"""

import argparse
import json
import os
import re
import signal
import ssl
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
BINARY = REPO / "target/release/zeroserve"
WORKDIR = Path("/tmp/zeroserve-bench-routing")
PORT = 18080
TLS_PORT = 18443
# Unused-but-bound HTTP port when benchmarking TLS (zeroserve --addr, Caddy
# http_port) so neither fights over PORT or tries :80.
HTTP_FALLBACK_PORT = 18079
# Shared HTTP upstream for --proxy mode (a 2-worker nginx).
BACKEND_PORT = 18090
BACKEND_BODY = "backend ok"
BACKEND_WORKERS = 2
CERT = WORKDIR / "bench-cert.pem"
KEY = WORKDIR / "bench-key.pem"
SERVER_THREADS = 3
WRK_THREADS = 2
WRK_CONNECTIONS = 64

# Set in main() when --tls / --proxy are given.
TLS = False
PROXY = False


def base_url(host: str) -> str:
    """Under TLS, connect by hostname so the client sends a proper SNI:
    zeroserve answers 421 when SNI is present but does not match the request
    Host (wrk puts the URL host — even an IP literal — into SNI). The bench
    hostnames must resolve to 127.0.0.1 via /etc/hosts; plain HTTP keeps
    IP connections with a Host header override."""
    if TLS:
        return f"https://{host}:{TLS_PORT}"
    return f"http://127.0.0.1:{PORT}"


def check_hosts_resolve(hosts):
    import socket

    missing = [h for h in hosts if not _resolves(h, socket)]
    if missing:
        entries = " ".join(missing)
        sys.exit(
            f"--tls needs these hostnames to resolve to 127.0.0.1 "
            f"(echo '127.0.0.1 {entries}' | sudo tee -a /etc/hosts): {entries}"
        )


def _resolves(host, socket) -> bool:
    try:
        return socket.gethostbyname(host) == "127.0.0.1"
    except OSError:
        return False


def insecure_ssl_context():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def ensure_cert():
    """Self-signed ECDSA P-256 wildcard cert covering every bench vhost.
    Clients connect by IP (no SNI), so zeroserve also gets this via --cert/--key
    as the no-SNI default; the Caddyfile's per-site `tls` directives use the
    same files."""
    if CERT.exists() and KEY.exists():
        return
    subprocess.run(
        [
            "openssl", "req", "-x509",
            "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
            "-keyout", str(KEY), "-out", str(CERT),
            "-days", "30", "-nodes",
            "-subj", "/CN=*.bench",
            "-addext", "subjectAltName=DNS:*.bench",
        ],
        check=True,
        capture_output=True,
    )


def gen_caddyfile(n_sites: int) -> str:
    """N vhosts; same-length hostnames so specificity sort keeps input order
    and host{n-1} is deterministically the last route. With --tls each site is
    https:// with an explicit `tls cert key` (also keeps stock Caddy from
    attempting ACME for .bench names)."""
    blocks = []
    for i in range(n_sites):
        host = f"host{i:04d}.bench"
        addr = (
            f"https://{host}:{TLS_PORT}" if TLS else f"http://{host}:{PORT}"
        )
        tls_line = f"\n    tls {CERT} {KEY}\n" if TLS else ""
        if PROXY:
            blocks.append(f"""\
{addr} {{{tls_line}
    reverse_proxy 127.0.0.1:{BACKEND_PORT}
}}
""")
            continue
        blocks.append(f"""\
{addr} {{{tls_line}
    @api path /api/*
    respond @api "api {i}" 200

    @item path_regexp item ^/items/([a-z0-9-]+)$
    respond @item "item {i}" 200

    handle /static/* {{
        respond "static {i}" 200
    }}

    respond "root {i}" 200
}}
""")
    return "\n".join(blocks)


def gen_backend_conf(workdir: Path) -> str:
    """The shared HTTP upstream for --proxy mode: a separate nginx instance
    that answers every request with a fixed 200. Sized so it is not the
    bottleneck (2 workers; proxy 3 + wrk 2 + backend 2 = 7 of 8 cores)."""
    tmp = workdir / "nginx-tmp"
    return f"""\
worker_processes {BACKEND_WORKERS};
pid {workdir}/nginx-backend.pid;
error_log {workdir}/nginx-backend-error.log warn;

events {{
    worker_connections 1024;
}}

http {{
    access_log off;
    keepalive_requests 1000000;
    client_body_temp_path {tmp}/backend-body;
    proxy_temp_path {tmp}/backend-proxy;
    fastcgi_temp_path {tmp}/backend-fastcgi;
    uwsgi_temp_path {tmp}/backend-uwsgi;
    scgi_temp_path {tmp}/backend-scgi;

    server {{
        listen {BACKEND_PORT} default_server;
        server_name _;
        return 200 "{BACKEND_BODY}";
    }}
}}
"""


def wait_backend_ready(timeout: float = 15.0):
    deadline = time.time() + timeout
    last_err = None
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(
                f"http://127.0.0.1:{BACKEND_PORT}/", timeout=1
            ) as resp:
                if resp.read().decode() == BACKEND_BODY:
                    return
        except Exception as e:  # noqa: BLE001
            last_err = e
            time.sleep(0.2)
    raise RuntimeError(f"backend did not become ready: {last_err}")


def gen_nginx_conf(n_sites: int, workdir: Path) -> str:
    """Equivalent nginx config: one server block per vhost. `^~` on the prefix
    locations mirrors Caddy's route order (the regex is never consulted for
    /api/* or /static/* requests), and a default_server returns the same empty
    200 as the Caddy fallback. keepalive_requests is raised so nginx does not
    recycle wrk's connections every 1000 requests."""
    tmp = workdir / "nginx-tmp"
    listen = f"{TLS_PORT} ssl" if TLS else f"{PORT}"
    ssl_conf = (
        f"    ssl_certificate {CERT};\n    ssl_certificate_key {KEY};\n"
        if TLS
        else ""
    )
    # Upstream keepalive matters for fairness: without it nginx opens a new
    # backend connection per request while Caddy and zeroserve pool theirs.
    upstream = (
        f"    upstream bench_backend {{\n"
        f"        server 127.0.0.1:{BACKEND_PORT};\n"
        f"        keepalive {WRK_CONNECTIONS};\n"
        f"    }}\n"
        if PROXY
        else ""
    )
    blocks = []
    for i in range(n_sites):
        host = f"host{i:04d}.bench"
        if PROXY:
            blocks.append(f"""\
    server {{
        listen {listen};
        server_name {host};
        location / {{
            proxy_pass http://bench_backend;
            proxy_http_version 1.1;
            proxy_set_header Connection "";
            proxy_set_header Host $host;
        }}
    }}
""")
            continue
        blocks.append(f"""\
    server {{
        listen {listen};
        server_name {host};
        location ^~ /api/ {{ return 200 "api {i}"; }}
        location ~ "^/items/([a-z0-9-]+)$" {{ return 200 "item {i}"; }}
        location ^~ /static/ {{ return 200 "static {i}"; }}
        location / {{ return 200 "root {i}"; }}
    }}
""")
    sites = "\n".join(blocks)
    return f"""\
worker_processes {SERVER_THREADS};
pid {workdir}/nginx.pid;
error_log {workdir}/nginx-error.log warn;

events {{
    worker_connections 1024;
}}

http {{
    access_log off;
    keepalive_requests 1000000;
    server_names_hash_max_size 4096;
    client_body_temp_path {tmp}/body;
    proxy_temp_path {tmp}/proxy;
    fastcgi_temp_path {tmp}/fastcgi;
    uwsgi_temp_path {tmp}/uwsgi;
    scgi_temp_path {tmp}/scgi;
{ssl_conf}{upstream}
    server {{
        listen {listen} default_server;
        server_name _;
        return 200 "";
    }}

{sites}}}
"""


def fetch(host: str, path: str, timeout: float) -> str:
    req = urllib.request.Request(
        f"{base_url(host)}{path}", headers={"Host": host}
    )
    kwargs = {"context": insecure_ssl_context()} if TLS else {}
    with urllib.request.urlopen(req, timeout=timeout, **kwargs) as resp:
        return resp.read().decode()


def wait_ready(host: str, timeout: float = 30.0):
    deadline = time.time() + timeout
    last_err = None
    while time.time() < deadline:
        try:
            fetch(host, "/", 1)
            return
        except Exception as e:  # noqa: BLE001
            last_err = e
            time.sleep(0.2)
    raise RuntimeError(f"server did not become ready: {last_err}")


def check_response(host: str, path: str, expect: str):
    body = fetch(host, path, 2)
    if body != expect:
        raise RuntimeError(
            f"unexpected response for {host}{path}: {body!r} != {expect!r}"
        )


def run_wrk(host: str, path: str, duration: int) -> dict:
    out = subprocess.run(
        [
            "wrk",
            f"-t{WRK_THREADS}",
            f"-c{WRK_CONNECTIONS}",
            f"-d{duration}s",
            "--latency",
            "-H",
            f"Host: {host}",
            f"{base_url(host)}{path}",
        ],
        capture_output=True,
        text=True,
    )
    if out.returncode != 0:
        raise RuntimeError(
            f"wrk failed for {host}{path} "
            f"(exit {out.returncode}): {out.stdout} {out.stderr}"
        )
    out = out.stdout
    # wrk counts error responses as completed requests; a misconfigured
    # scenario (e.g. SNI/Host mismatch -> 421) would otherwise "benchmark"
    # the server's error fast path.
    non2xx = re.search(r"Non-2xx or 3xx responses:\s+(\d+)", out)
    if non2xx:
        raise RuntimeError(
            f"wrk got {non2xx.group(1)} non-2xx responses for {host}{path}"
        )
    rps = float(re.search(r"Requests/sec:\s+([\d.]+)", out).group(1))
    p50 = re.search(r"50%\s+([\d.]+\w+)", out).group(1)
    p99 = re.search(r"99%\s+([\d.]+\w+)", out).group(1)
    return {"rps": rps, "p50": p50, "p99": p99}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--label", required=True)
    ap.add_argument("--sites", type=int, default=256)
    ap.add_argument("--duration", type=int, default=3)
    ap.add_argument("--runs", type=int, default=2)
    ap.add_argument(
        "--server",
        choices=["zeroserve", "caddy", "nginx"],
        default="zeroserve",
        help="serve the config with zeroserve, stock Caddy, or nginx",
    )
    ap.add_argument(
        "--caddy-binary",
        default=str(WORKDIR / "caddy-stock"),
        help="stock caddy binary for --server caddy",
    )
    ap.add_argument(
        "--tls",
        action="store_true",
        help="serve and load-test over HTTPS (self-signed *.bench cert)",
    )
    ap.add_argument(
        "--proxy",
        action="store_true",
        help="every vhost reverse-proxies to a shared HTTP nginx backend",
    )
    ap.add_argument(
        "--ebpf-compiler",
        choices=["tcc", "clang"],
        default="tcc",
        help="eBPF C compiler used by zeroserve --caddy",
    )
    args = ap.parse_args()

    global TLS, PROXY
    TLS = args.tls
    PROXY = args.proxy

    if args.server == "zeroserve" and not BINARY.exists():
        sys.exit(f"missing {BINARY}; run cargo build --release first")

    WORKDIR.mkdir(parents=True, exist_ok=True)
    if TLS:
        ensure_cert()
    suffix = f"{args.sites}"
    if PROXY:
        suffix += ".proxy"
    if TLS:
        suffix += ".tls"
    caddyfile = WORKDIR / f"Caddyfile.{suffix}"
    caddyfile.write_text(gen_caddyfile(args.sites))
    # Stock Caddy gets the same sites plus admin off, so repeated runs do not
    # fight over the admin port. GOMAXPROCS matches zeroserve's --threads.
    # Under --tls, also keep Caddy off :80 (http_port) and skip the
    # HTTP->HTTPS redirect listener.
    stock_global = "{\n    admin off\n"
    if TLS:
        # Clients connect by IP: urllib sends no SNI (default_sni), wrk sends
        # the IP literal as SNI (fallback_sni). Without these certmagic
        # refuses the handshake; zeroserve gets --cert/--key and nginx the
        # http-level default cert for the same reason. The literal `*.bench`
        # matters: the fallback identifier is looked up exactly against the
        # cert cache, which keys this cert by its SAN `*.bench`.
        stock_global += (
            f"    http_port {HTTP_FALLBACK_PORT}\n"
            "    auto_https disable_redirects\n"
            "    default_sni *.bench\n"
            "    fallback_sni *.bench\n"
        )
    stock_global += "}\n\n"
    caddyfile_stock = WORKDIR / f"Caddyfile.{suffix}.stock"
    caddyfile_stock.write_text(stock_global + gen_caddyfile(args.sites))

    first = "host0000.bench"
    last = f"host{args.sites - 1:04d}.bench"

    if TLS:
        check_hosts_resolve([first, last, "nomatch.bench"])

    scenarios = [
        ("first", first, "/api/x"),
        ("last", last, "/api/x"),
        ("last-re", last, "/items/abc-123"),
        ("miss", "nomatch.bench", "/api/x"),
    ]

    if args.server == "caddy":
        cmd = [
            args.caddy_binary,
            "run",
            "--config",
            str(caddyfile_stock),
            "--adapter",
            "caddyfile",
        ]
        env = {**os.environ, "GOMAXPROCS": str(SERVER_THREADS)}
    elif args.server == "nginx":
        nginx_conf = WORKDIR / f"nginx.{suffix}.conf"
        nginx_conf.write_text(gen_nginx_conf(args.sites, WORKDIR))
        (WORKDIR / "nginx-tmp").mkdir(exist_ok=True)
        cmd = [
            "nginx",
            "-c",
            str(nginx_conf),
            "-p",
            str(WORKDIR),
            "-g",
            "daemon off;",
        ]
        env = None
    else:
        cmd = [
            str(BINARY),
            "--caddy",
            str(caddyfile),
            "--ebpf-compiler",
            args.ebpf_compiler,
            "--threads",
            str(SERVER_THREADS),
            "--disable-request-logging",
        ]
        if TLS:
            # Clients connect by IP (wrk sends no SNI), so the wildcard cert
            # is also installed as the global no-SNI default; the per-site
            # `tls` directives still exercise SNI-based selection when present.
            cmd += [
                "--addr",
                f"127.0.0.1:{HTTP_FALLBACK_PORT}",
                "--tls-addr",
                f"127.0.0.1:{TLS_PORT}",
                "--cert",
                str(CERT),
                "--key",
                str(KEY),
            ]
        else:
            cmd += ["--addr", f"127.0.0.1:{PORT}"]
        env = None
    backend_proc = None
    if PROXY:
        backend_conf = WORKDIR / "nginx-backend.conf"
        backend_conf.write_text(gen_backend_conf(WORKDIR))
        (WORKDIR / "nginx-tmp").mkdir(exist_ok=True)
        backend_proc = subprocess.Popen(
            ["nginx", "-c", str(backend_conf), "-p", str(WORKDIR), "-g", "daemon off;"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        wait_backend_ready()

    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
        env=env,
    )
    results = {}
    try:
        wait_ready(first)
        # Sanity: routing must be correct before we measure it.
        if PROXY:
            check_response(first, "/api/x", BACKEND_BODY)
            check_response(last, "/api/x", BACKEND_BODY)
            check_response(last, "/items/abc-123", BACKEND_BODY)
            check_response(last, "/", BACKEND_BODY)
            check_response("nomatch.bench", "/api/x", "")
        else:
            check_response(first, "/api/x", "api 0")
            check_response(last, "/api/x", f"api {args.sites - 1}")
            check_response(last, "/items/abc-123", f"item {args.sites - 1}")
            check_response(last, "/static/a.css", f"static {args.sites - 1}")
            check_response(last, "/", f"root {args.sites - 1}")
            check_response("nomatch.bench", "/api/x", "")

        for name, host, path in scenarios:
            run_wrk(host, path, 1)  # warmup
            best = None
            for _ in range(args.runs):
                r = run_wrk(host, path, args.duration)
                if best is None or r["rps"] > best["rps"]:
                    best = r
            results[name] = best
            print(
                f"{name:8s} {host:18s} {path:16s} "
                f"{best['rps']:>12.0f} req/s  p50 {best['p50']:>8s}  p99 {best['p99']:>8s}"
            )
    finally:
        os.killpg(proc.pid, signal.SIGKILL)
        proc.wait()
        if backend_proc is not None:
            os.killpg(backend_proc.pid, signal.SIGKILL)
            backend_proc.wait()

    record = {
        "label": args.label,
        "server": args.server,
        "sites": args.sites,
        "duration": args.duration,
        "tls": TLS,
        "proxy": PROXY,
        "ebpf_compiler": args.ebpf_compiler if args.server == "zeroserve" else None,
        "results": results,
    }
    with open(Path(__file__).parent / "results.jsonl", "a") as f:
        f.write(json.dumps(record) + "\n")


if __name__ == "__main__":
    main()
