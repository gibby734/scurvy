#!/usr/bin/env python3
"""recon_sweep.py - bounded TCP connect-scan + light banner grab for ONE in-scope host.

Stdlib only. Refuses public (non-RFC1918) targets unless --allow-public is set.
Bounded: capped port count, capped workers, short timeouts. Connect scan only.
"""
import argparse
import concurrent.futures as cf
import ipaddress
import json
import socket
import sys

COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 88, 110, 111, 135, 139, 143, 389, 443, 445,
    464, 636, 993, 995, 1433, 1521, 2049, 3268, 3269, 3306, 3389, 5060,
    5432, 5985, 5986, 6379, 8000, 8080, 8443, 9200, 11211, 27017,
]
MAX_PORTS = 1024
MAX_WORKERS = 100


def fail(msg):
    print(json.dumps({"error": msg}))
    sys.exit(1)


def parse_ports(spec):
    if spec == "common":
        return COMMON_PORTS
    ports = set()
    try:
        for part in spec.split(","):
            part = part.strip()
            if not part:
                continue
            if "-" in part:
                a, b = part.split("-", 1)
                ports.update(range(int(a), int(b) + 1))
            else:
                ports.add(int(part))
    except ValueError:
        fail(f"bad --ports value: {spec!r}")
    return sorted(p for p in ports if 1 <= p <= 65535)


def service_name(port):
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return ""


def probe(ip, port, timeout, banner_bytes):
    try:
        with socket.create_connection((ip, port), timeout=timeout) as s:
            banner = ""
            if banner_bytes > 0:
                try:
                    s.settimeout(timeout)
                    data = s.recv(banner_bytes)
                    banner = data.decode("latin-1", "replace").strip()
                except OSError:
                    banner = ""
            return {"port": port, "service": service_name(port), "banner": banner}
    except OSError:
        return None


def main():
    ap = argparse.ArgumentParser(description="Bounded TCP recon for one in-scope host.")
    ap.add_argument("target", help="single IP or hostname (RFC1918 unless --allow-public)")
    ap.add_argument("--ports", default="common",
                    help="'common' (default ~37 ports) or list/ranges e.g. 22,80,8000-8100")
    ap.add_argument("--timeout", type=float, default=2.0,
                    help="per-connection timeout (s); raise for targets across a firewall")
    ap.add_argument("--banner-bytes", type=int, default=256,
                    help="max banner bytes to read (0 disables banner grab)")
    ap.add_argument("--workers", type=int, default=64, help="concurrent connections")
    ap.add_argument("--allow-public", action="store_true",
                    help="OVERRIDE: permit non-private targets (requires authorization)")
    args = ap.parse_args()

    ports = parse_ports(args.ports)
    if not ports:
        fail("no valid ports to scan")
    if len(ports) > MAX_PORTS:
        fail(f"too many ports ({len(ports)} > {MAX_PORTS}); narrow the scan")

    try:
        ip = socket.gethostbyname(args.target)
    except OSError as e:
        fail(f"cannot resolve {args.target}: {e}")

    if not args.allow_public and not ipaddress.ip_address(ip).is_private:
        fail(f"out-of-scope target {args.target} ({ip}) is not RFC1918; "
             f"pass --allow-public only with explicit authorization")

    timeout = min(max(args.timeout, 0.05), 5.0)
    workers = min(max(args.workers, 1), MAX_WORKERS)
    banner_bytes = min(max(args.banner_bytes, 0), 2048)

    open_ports = []
    with cf.ThreadPoolExecutor(max_workers=workers) as ex:
        for res in ex.map(lambda p: probe(ip, p, timeout, banner_bytes), ports):
            if res:
                open_ports.append(res)
    open_ports.sort(key=lambda d: d["port"])

    print(json.dumps({
        "target": args.target,
        "ip": ip,
        "ports_scanned": len(ports),
        "open_count": len(open_ports),
        "open_ports": open_ports,
    }, indent=2))


if __name__ == "__main__":
    main()
