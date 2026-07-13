---
name: ad-foothold
description: "From only a target DC IP and no credentials, establish a first low-priv domain credential: discover the domain from the IP, enumerate valid users (Kerberos AS-REQ), then run a lockout-safe password spray. Wraps kerbrute + NetExec (nxc)."
metadata: {"openclaw": {"emoji": "⚓", "os": ["linux"], "requires": {"bins": ["kerbrute", "nxc", "python3"]}}}
user-invocable: true
---
# ad-foothold
The from-zero entry skill. Given nothing but the DC IP, get a foothold credential so the rest of the kill chain (e.g. `ad-loot`) can run. ATT&CK **T1589.002** (user enumeration) + **T1110.003** (password spraying).

## Use when
- You have a target IP and NO credentials, and need to establish initial access.
- One domain/DC per run.

## Run
Invoke: `python3 /workspace/skills/ad-foothold/scripts/ad_foothold.py <DC-ip>`
- Auto-discovers the domain/realm from the IP (override with `--domain`).
- Uses the bundled OSINT-style `wordlists/users.txt` and targeted `wordlists/passwords.txt` (override with `--userlist` / `--passlist`).
- Output is JSON: `domain`, `valid_users`, `creds_found`, `foothold` (the validated cred), and a `next` hint.

## Rules
- RFC1918 targets only (`--allow-public` needs operator authorization).
- **Lockout-safe by design:** sprays at most `--max-attempts-per-user` passwords per invocation (default 2, which stays under a 3/15/15 lockout policy), one password across all users per round, stops on first hit. Do NOT raise the cap or re-run rapidly: you will lock accounts and taint the run. If no cred is found and passwords remain, WAIT OUT the 15-minute lockout window before another round.
- On success, hand the `foothold` cred to **ad-loot** to hunt for escalation (the `next` field gives the exact command). Then stop and report once you confirm Domain Admin.
- Report the foothold (which user, how it was obtained), not the raw spray output.

## Helpers
- `scripts/ad_foothold.py` wraps `nxc smb` (domain discovery), `kerbrute userenum` (AS-REQ enumeration, does not touch the lockout counter), and `kerbrute passwordspray` (capped). kerbrute + nxc + Python stdlib only.
- `wordlists/users.txt`, `wordlists/passwords.txt` - editable seed lists. The user list models standard pre-engagement OSINT (gathered employee names); kerbrute validates which exist before any spray.
