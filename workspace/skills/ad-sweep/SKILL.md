---
name: ad-sweep
description: "With a foothold domain credential, sweep the whole domain at breadth for misconfigurations and return a RANKED findings list: ADCS ESC templates, GPP cpasswords in SYSVOL, credentials in AD object descriptions, and dangerous ACLs over privileged groups. Wraps certipy-ad, NetExec (nxc), and bloodyad."
metadata: {"openclaw": {"emoji": "🗺️", "os": ["linux"], "requires": {"bins": ["certipy-ad", "nxc", "bloodyad", "python3"]}}}
user-invocable: true
---
# ad-sweep
The breadth skill. Once you hold any domain credential, run this to enumerate the entire attack surface in one pass and get back a short, ranked list of what is exploitable. It does the exhaustive, boring checks a human would skip and hands you only the anomalies that matter.

## Use when
- You have a valid domain credential (e.g. from `ad-foothold`) and want to find every path to privilege at once, not one at a time.
- One domain/DC per run.

## Run
Invoke: `python3 /workspace/skills/ad-sweep/scripts/ad_sweep.py <DC-ip> -u <user> -p <password>`
- Auto-discovers the domain (override with `--domain`).
- Output is JSON: `findings` (each with type, severity, technique, detail, and a `next` command), plus a `summary` of the actionable (critical/high) ones.

## What it checks
- **ADCS ESC** (certipy-ad find -vulnerable) -> ESC1..ESC16, ATT&CK **T1649**.
- **GPP cpassword** (nxc -M gpp_password) -> credentials in SYSVOL, **T1552.006**.
- **AD description secrets** (nxc ldap --users) -> credentials in object metadata, **T1552.001**.
- **Attack paths to Domain Admin** (bloodyad security-descriptor collection + graph analysis) -> any non-default principal that reaches DA via control ACEs (GenericAll / WriteDacl / WriteOwner), DCSync rights, or multi-hop chains, **T1098 / T1003.006**. Uses bloodyad rather than BloodHound because the standard collectors (bloodhound-python, nxc --bloodhound) fail to authenticate against a channel-binding-hardened DC.

## Rules
- RFC1918 targets only (`--allow-public` needs operator authorization).
- Report the ranked `summary`, then act on the highest-severity finding using its `next` command. Pursue one path to Domain Admin, then STOP and report (don't chase every finding unless told to continue).
- For ESC abuse on Server 2025, remember the cert needs the target SID (`-sid`, strong cert mapping / KB5014754).
- Each check is isolated; a skipped/failed check is reported as `info`, not a hard error.

## Helper
- `scripts/ad_sweep.py` orchestrates certipy-ad + nxc + bloodyad and aggregates a ranked JSON. Determinism in the skill, judgment to the model. Python stdlib + those three tools only.
