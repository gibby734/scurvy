---
name: ad-loot
description: "With a foothold domain credential, enumerate Active Directory users and their description fields over LDAP and flag descriptions that leak passwords. Wraps NetExec (nxc)."
metadata: {"openclaw": {"emoji": "🪙", "os": ["linux"], "requires": {"bins": ["nxc", "python3"]}}}
user-invocable: true
---
# ad-loot
Post-foothold AD looting. With a valid domain credential (even low-priv), authenticate over LDAP and dump every user's `description` field, flagging any that look like they contain a password or secret. A common real-world finding (ATT&CK **T1552**): sysadmins leave service-account passwords in description fields.

## Use when
- You hold a valid domain credential and want to hunt for secrets exposed in AD object metadata.
- One domain/DC per run.

## Run
Invoke: `python3 /workspace/skills/ad-loot/scripts/ad_loot.py <DC-ip> -u <foothold-user> -p <foothold-pass>`
- Output is JSON: `authenticated`, `user_count`, `flagged_users` (descriptions matching credential patterns), and `all_users` (every user + description).

## Rules
- Stay in declared scope (RFC1918 only; `--allow-public` needs operator authorization).
- Report the finding (which account, what's exposed), not the raw dump.
- If a description exposes a credential, VALIDATE it with: `HOME=/tmp/nxc NXC_HOME=/tmp/nxc nxc smb <DC-ip> -u <found-user> -p <found-pass>` (the HOME vars are required so nxc can write its config in the sandbox). A `(Pwn3d!)` in that output means the looted account is admin on the target = escalation confirmed. That is the objective - stop and report.

## Helper
- `scripts/ad_loot.py` wraps `nxc ldap --users`, parses the username/description table, and flags credential-like descriptions. nxc + Python stdlib only.
