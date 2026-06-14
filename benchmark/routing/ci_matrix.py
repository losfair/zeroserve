#!/usr/bin/env python3
"""Run the small routing benchmark matrix used by CI.

Matrix:
  - N=8 sites
  - 2 server threads
  - 10ms zeroserve preemption interval
  - route-only and reverse-proxy modes
  - HTTP and HTTPS
  - zeroserve clang, zeroserve tcc, Caddy, nginx

The underlying benchmark.py still emits detailed per-run output. This wrapper
collects the JSON records and prints one Markdown table with throughput, p50,
p99, and peak serving RSS for every probe.
"""

import argparse
import json
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
BENCH = REPO / "benchmark/routing/benchmark.py"
PROBES = ["first", "last", "last-re", "miss"]
PAGE_KB = os.sysconf("SC_PAGE_SIZE") // 1024


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--duration", type=int, default=3)
    ap.add_argument("--runs", type=int, default=1)
    ap.add_argument("--caddy-binary", default=os.environ.get("CADDY_BIN", "caddy"))
    ap.add_argument("--nginx-binary", default="/usr/sbin/nginx")
    args = ap.parse_args()

    with tempfile.TemporaryDirectory(prefix="zeroserve-bench-ci-") as td:
        results_jsonl = Path(td) / "results.jsonl"
        records = run_matrix(args, results_jsonl)
        table = render_table(records)
        print("\n" + table)
        summary = os.environ.get("GITHUB_STEP_SUMMARY")
        if summary:
            with open(summary, "a") as f:
                f.write(table)
                f.write("\n")

    return 0


def run_matrix(args: argparse.Namespace, results_jsonl: Path) -> list[dict]:
    base = [
        sys.executable,
        str(BENCH),
        "--sites",
        "8",
        "--duration",
        str(args.duration),
        "--runs",
        str(args.runs),
        "--server-threads",
        "2",
        "--preempt-timer-interval-ms",
        "10",
        "--caddy-binary",
        args.caddy_binary,
        "--nginx-binary",
        args.nginx_binary,
        "--results-jsonl",
        str(results_jsonl),
    ]
    modes = [
        ("http", "route-only", []),
        ("http", "reverse-proxy", ["--proxy"]),
        ("https", "route-only", ["--tls"]),
        ("https", "reverse-proxy", ["--tls", "--proxy"]),
    ]
    servers = [
        ("zeroserve", "clang", ["--server", "zeroserve", "--ebpf-compiler", "clang"]),
        ("zeroserve", "tcc", ["--server", "zeroserve", "--ebpf-compiler", "tcc"]),
        ("caddy", "", ["--server", "caddy"]),
        ("nginx", "", ["--server", "nginx"]),
    ]

    records = []
    for protocol, mode, mode_args in modes:
        for server, compiler, server_args in servers:
            label_parts = ["ci", "n8", protocol, mode, server]
            if compiler:
                label_parts.append(compiler)
            label = "-".join(label_parts)
            cmd = base + ["--label", label] + mode_args + server_args
            print(f"\n==> {label}", flush=True)
            print(" ".join(cmd), flush=True)
            peak_rss_kb = run_with_memory(cmd, server)
            record = read_record(results_jsonl, label)
            record["_protocol"] = protocol
            record["_mode"] = mode
            record["_server_label"] = f"{server}-{compiler}" if compiler else server
            record["_serving_peak_rss_kb"] = peak_rss_kb
            record["_serving_peak_rss_mib"] = peak_rss_kb / 1024
            print(
                f"serving peak RSS: {record['_serving_peak_rss_mib']:.1f} MiB",
                flush=True,
            )
            records.append(record)
    return records


def run_with_memory(cmd: list[str], server: str) -> int:
    proc = subprocess.Popen(cmd, cwd=REPO)
    peak_rss_kb = 0
    while proc.poll() is None:
        peak_rss_kb = max(peak_rss_kb, serving_rss_kb(proc.pid, server))
        time.sleep(0.05)
    rc = proc.wait()
    if rc != 0:
        raise subprocess.CalledProcessError(rc, cmd)
    return peak_rss_kb


def serving_rss_kb(benchmark_pid: int, server: str) -> int:
    """Peak memory for the server being benchmarked.

    zeroserve and Caddy serve in their main process, so exclude transient
    helper/compiler children. nginx serves in master+worker processes, so count
    that subtree. In proxy mode the backend nginx is deliberately not counted.
    """
    children = children_map()
    total = 0
    seen = set()
    for root in front_roots(benchmark_pid, server, children):
        pids = {root} | descendants(root, children) if server == "nginx" else {root}
        for pid in pids:
            if pid in seen:
                continue
            seen.add(pid)
            total += rss_kb(pid)
    return total


def front_roots(
    benchmark_pid: int, server: str, children: dict[int, list[int]]
) -> list[int]:
    roots = []
    for pid in descendants(benchmark_pid, children):
        cmd = proc_cmdline(pid)
        if not cmd:
            continue
        if server == "zeroserve" and "target/release/zeroserve" in cmd:
            roots.append(pid)
        elif (
            server == "caddy"
            and "caddy" in Path(cmd.split()[0]).name
            and " run " in f" {cmd} "
            and "Caddyfile." in cmd
        ):
            roots.append(pid)
        elif (
            server == "nginx"
            and "/nginx.8" in cmd
            and "nginx-backend.conf" not in cmd
        ):
            roots.append(pid)
    return roots


def children_map() -> dict[int, list[int]]:
    children = {}
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        pid = int(entry.name)
        try:
            stat = (entry / "stat").read_text()
            rparen = stat.rfind(")")
            ppid = int(stat[rparen + 2 :].split()[1])
        except (OSError, ValueError, IndexError):
            continue
        children.setdefault(ppid, []).append(pid)
    return children


def descendants(root: int, children: dict[int, list[int]]) -> set[int]:
    out = set()
    stack = list(children.get(root, []))
    while stack:
        pid = stack.pop()
        if pid in out:
            continue
        out.add(pid)
        stack.extend(children.get(pid, []))
    return out


def proc_cmdline(pid: int) -> str:
    try:
        raw = Path(f"/proc/{pid}/cmdline").read_bytes()
    except OSError:
        return ""
    return raw.replace(b"\0", b" ").decode("utf-8", "replace").strip()


def rss_kb(pid: int) -> int:
    try:
        fields = Path(f"/proc/{pid}/statm").read_text().split()
        return int(fields[1]) * PAGE_KB
    except (OSError, ValueError, IndexError):
        return 0


def read_record(path: Path, label: str) -> dict:
    found = None
    with open(path) as f:
        for line in f:
            record = json.loads(line)
            if record["label"] == label:
                found = record
    if found is None:
        raise RuntimeError(f"benchmark record not found for label {label}")
    return found


def render_table(records: list[dict]) -> str:
    lines = [
        "# Routing Benchmark",
        "",
        "N=8, server threads=2, zeroserve preemption interval=10ms.",
        "Memory is peak serving RSS: zeroserve/Caddy process only, nginx master plus workers; proxy backend and transient compiler/helper children are excluded.",
        "",
        "| protocol | mode | server | probe | throughput | p50 | p99 | peak RSS |",
        "|---|---|---|---|---:|---:|---:|---:|",
    ]
    for record in records:
        for probe in PROBES:
            result = record["results"][probe]
            lines.append(
                "| {protocol} | {mode} | {server} | {probe} | {rps} req/s | {p50} | {p99} | {rss:.1f} MiB |".format(
                    protocol=record["_protocol"],
                    mode=record["_mode"],
                    server=record["_server_label"],
                    probe=probe,
                    rps=f"{result['rps']:,.0f}",
                    p50=result["p50"],
                    p99=result["p99"],
                    rss=record["_serving_peak_rss_mib"],
                )
            )
    return "\n".join(lines)


if __name__ == "__main__":
    raise SystemExit(main())
