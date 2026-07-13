#!/usr/bin/env python3
"""nmap_scan.py - wrap nmap for ONE in-scope host: TCP connect + service/version scan, structured JSON.

Unprivileged connect scan (-sT -sV -Pn), no OS detection, no NSE. RFC1918-only unless --allow-public.
"""
import argparse
import ipaddress
import json
import shutil
import socket
import subprocess
import sys
import xml.etree.ElementTree as ET


def fail(msg):
    print(json.dumps({"error": msg}))
    sys.exit(1)


def main():
    ap = argparse.ArgumentParser(description="nmap connect+version scan for one in-scope host.")
    ap.add_argument("target", help="single IP or hostname (RFC1918 unless --allow-public)")
    ap.add_argument("--ports", default="common",
                    help="'common' (top 100), 'top:N', or an nmap spec e.g. 22,80,443 or 1-1024")
    ap.add_argument("--timing", default="4", help="nmap -T timing template 0-5")
    ap.add_argument("--allow-public", action="store_true",
                    help="OVERRIDE: permit non-private targets (requires authorization)")
    args = ap.parse_args()

    if not shutil.which("nmap"):
        fail("nmap not found in this environment")

    try:
        ip = socket.gethostbyname(args.target)
    except OSError as e:
        fail(f"cannot resolve {args.target}: {e}")

    if not args.allow_public and not ipaddress.ip_address(ip).is_private:
        fail(f"out-of-scope target {args.target} ({ip}) is not RFC1918; "
             f"pass --allow-public only with explicit authorization")

    cmd = ["nmap", "-sT", "-sV", "-Pn", f"-T{args.timing}", "-oX", "-"]
    if args.ports == "common":
        cmd += ["--top-ports", "100"]
    elif args.ports.startswith("top:"):
        cmd += ["--top-ports", args.ports.split(":", 1)[1]]
    else:
        cmd += ["-p", args.ports]
    cmd.append(args.target)

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
    except subprocess.TimeoutExpired:
        fail("nmap timed out (600s)")
    if not proc.stdout.strip():
        fail(f"nmap produced no output: {proc.stderr.strip()[:300]}")

    try:
        root = ET.fromstring(proc.stdout)
    except ET.ParseError as e:
        fail(f"could not parse nmap XML: {e}")

    host = root.find("host")
    status = "unknown"
    open_ports = []
    if host is not None:
        st = host.find("status")
        if st is not None:
            status = st.get("state", "unknown")
        for p in host.findall("./ports/port"):
            state_el = p.find("state")
            if state_el is None or state_el.get("state") != "open":
                continue
            svc = p.find("service")
            open_ports.append({
                "port": int(p.get("portid")),
                "proto": p.get("protocol", "tcp"),
                "service": svc.get("name", "") if svc is not None else "",
                "product": svc.get("product", "") if svc is not None else "",
                "version": svc.get("version", "") if svc is not None else "",
            })

    open_ports.sort(key=lambda d: d["port"])
    print(json.dumps({
        "target": args.target,
        "ip": ip,
        "host_status": status,
        "open_count": len(open_ports),
        "open_ports": open_ports,
    }, indent=2))


if __name__ == "__main__":
    main()
