---
name: nmap-scan
description: "Scan ONE in-scope host with nmap: unprivileged TCP connect + service/version detection, structured JSON out. Refuses non-RFC1918 targets."
metadata: {"openclaw": {"emoji": "🛰️", "os": ["linux"], "requires": {"bins": ["nmap", "python3"]}}}
user-invocable: true
---
# nmap-scan
Real-tool recon for a single in-scope lab host using nmap. Use when you have a target IP/hostname and want open ports WITH service + version fingerprints (richer than a raw banner grab). The wrapper enforces an unprivileged connect scan and lab scope.

## Use when
- One target, and you want services identified (product/version), not just open/closed.
- Not for subnet sweeps or public hosts. One host per run.

## Run
Invoke: `python3 /workspace/skills/nmap-scan/scripts/nmap_scan.py <target> [--ports common|top:N|SPEC]`
- `<target>`: single IP or hostname. RFC1918 only; public refused unless `--allow-public` (needs operator authorization).
- `--ports`: `common` (nmap top 100, default), `top:N` (top N), or an nmap spec like `22,80,443` or `1-1024`.
- Output is JSON: `target`, `ip`, `host_status`, `open_count`, and per-port `{port, proto, service, product, version}`.

## Rules
- One host per invocation. Connect scan only (`-sT`), no OS detection, no NSE scripts.
- Stay in declared scope; do not pass `--allow-public` without authorization.
- Report the JSON summary (services + versions), not nmap's raw console output. Decide the next move from the product/version findings.

## Helper
- `scripts/nmap_scan.py` wraps `nmap -sT -sV -Pn`, applies an RFC1918 scope guard, and parses `-oX` XML to structured JSON. Stdlib + nmap only.
