---
name: recon-sweep
description: "Recon ONE in-scope host: bounded TCP connect-scan plus light banner grab. Stdlib Python only; refuses non-RFC1918 targets."
metadata: {"openclaw": {"emoji": "🔭", "os": ["linux"], "requires": {"bins": ["python3"]}}}
user-invocable: true
---
# recon-sweep
First-contact recon for a single in-scope lab host. Use to find open TCP ports and grab light service banners when you have a target IP and need to orient. Self-contained: stdlib Python, no nmap/ss/external tools, so it runs in the minimal sandbox.

## Use when
- You have ONE target IP/hostname in the lab and need an open-port + service picture.
- Not for sweeping ranges or public hosts. One host per run.

## Run
```bash
python3 scripts/recon_sweep.py <target> [--ports common|LIST] [--timeout 2.0] [--banner-bytes 256]
```
- `<target>`: single IP or hostname. Must be RFC1918 (private). Public targets are refused unless `--allow-public` is given with explicit authorization.
- `--ports`: `common` (curated ~37 ports, default) or an explicit list/range like `22,80,443,8000-8100`. Hard cap 1024 ports/run.
- Output is JSON: `target`, resolved `ip`, `ports_scanned`, `open_count`, and per-open-port `{port, service, banner}`.

## Rules
- One host per invocation. Do not loop it over a subnet.
- Stay in declared scope. The script refuses non-private targets by default; do not pass `--allow-public` without operator authorization.
- Report the JSON summary, not raw socket noise. Decide the next move from `open_count` + services.

## Helper
- `scripts/recon_sweep.py`: bounded TCP connect-scan (capped ports, capped workers, short timeouts) + passive banner read. Stdlib only, connect scan only.
