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
and p99 for every probe.
"""

import argparse
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
BENCH = REPO / "benchmark/routing/benchmark.py"
PROBES = ["first", "last", "last-re", "miss"]


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
            subprocess.run(cmd, cwd=REPO, check=True)
            record = read_record(results_jsonl, label)
            record["_protocol"] = protocol
            record["_mode"] = mode
            record["_server_label"] = f"{server}-{compiler}" if compiler else server
            records.append(record)
    return records


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
        "",
        "| protocol | mode | server | probe | throughput | p50 | p99 |",
        "|---|---|---|---|---:|---:|---:|",
    ]
    for record in records:
        for probe in PROBES:
            result = record["results"][probe]
            lines.append(
                "| {protocol} | {mode} | {server} | {probe} | {rps} req/s | {p50} | {p99} |".format(
                    protocol=record["_protocol"],
                    mode=record["_mode"],
                    server=record["_server_label"],
                    probe=probe,
                    rps=f"{result['rps']:,.0f}",
                    p50=result["p50"],
                    p99=result["p99"],
                )
            )
    return "\n".join(lines)


if __name__ == "__main__":
    raise SystemExit(main())
