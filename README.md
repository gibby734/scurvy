# ☠️ Scurvy

**Scurvy** is an autonomous offensive-security (red-team) agent built for **Hull** (codename *Davy Jones Domain*), a contained, instrumented AI purple-teaming research lab. It runs on the [OpenClaw](https://github.com/) agent framework as the tool-calling vehicle, driving a small local model against an isolated Active Directory domain and leaving a clean, reproducible log of every action.

This repository is the **agent definition** — its identity/doctrine workspace files plus the custom AD tradecraft skills. It is a research and portfolio artifact.

> ### ⚠️ Authorized-use notice
> Scurvy is designed and used **only against targets inside a contained, sanctioned lab** (an isolated AD domain on a dedicated VLAN, no real-world victim). Every bundled skill enforces an **RFC1918-only scope guard** and refuses public targets unless explicitly overridden with authorization. The password-spray skill is **lockout-safe by design**. Do not point these tools at systems you are not explicitly authorized to test. The skills wrap standard, already-public offensive-security tools (NetExec, Impacket, Certipy, kerbrute, bloodyAD, nmap); the value here is the agent doctrine, orchestration, and safety guards, not novel exploits.

## What's here

```
workspace/                 # the OpenClaw agent workspace (~/.openclaw/workspace/)
  SOUL.md                  # who Scurvy is + operating doctrine (the core prompt)
  AGENTS.md                # operating instructions / rules of engagement
  IDENTITY.md              # name, vibe, emoji
  USER.md                  # the operator profile
  TOOLS.md                 # lab-specific environment + target notes
  MEMORY.md                # long-term memory (curated durable facts)
  HEARTBEAT.md             # periodic-poll config (kept empty = off)
  README.md                # note on the workspace mirror / source of truth
  skills/                  # custom, on-domain tradecraft skills
    ad-foothold/           # from a DC IP + no creds -> first low-priv credential
    ad-sweep/              # authenticated breadth sweep -> ranked attack paths to DA
    ad-loot/               # dump AD user descriptions, flag leaked credentials
    nmap-scan/             # single-host service/version recon (nmap wrapper)
    recon-sweep/           # stdlib-only bounded TCP connect scan + banner grab
```

## The agent, briefly

Scurvy is handed only a target IP. Its doctrine (`workspace/SOUL.md`) walks a fixed entry sequence:

1. **`ad-foothold`** — discover the domain from the IP, enumerate valid users (Kerberos AS-REQ), run a lockout-safe spray → a first low-priv credential.
2. **`ad-sweep`** — with that credential, sweep the whole domain in one pass and return a ranked list of the exploitable surface: ADCS ESC templates, GPP cpasswords in SYSVOL, secrets in AD object metadata, and full ACL/DCSync attack paths to Domain Admin.
3. Chain the findings, walk one path to Domain Admin, **stop cleanly on the first confirmation**, and report the path with evidence.

The log is the deliverable: one tool call per turn, every action deliberate, reproducible, and explained in a line.

## Skills

| Skill | Purpose | Wraps | ATT&CK |
|-------|---------|-------|--------|
| `ad-foothold` | From-zero foothold: domain discovery + user enum + lockout-safe spray | kerbrute, NetExec | T1589.002, T1110.003 |
| `ad-sweep`    | Authenticated breadth sweep → ranked findings + paths to DA | certipy-ad, NetExec, bloodyAD | T1649, T1552.006, T1552.001, T1098, T1003.006 |
| `ad-loot`     | Dump AD user `description` fields, flag leaked creds | NetExec | T1552.001 |
| `nmap-scan`   | Single-host connect + service/version scan → JSON | nmap | — |
| `recon-sweep` | Stdlib-only bounded TCP connect scan + banner grab | (none) | — |

Each skill has a `SKILL.md` describing when/how to use it and a Python helper under `scripts/`. All are `python3 <script> <target> [...]`, RFC1918-guarded, and emit structured JSON.

## Runtime

Scurvy runs under OpenClaw: the gateway drives the agent loop, tool actions execute in a Docker sandbox (a Kali-based image with the offensive toolchain preinstalled), and the sandbox is network-bounded to the lab segment. The `workspace/` directory maps to the agent's OpenClaw workspace; skills resolve at `/workspace/skills/<name>/` inside the sandbox (hence the invoke paths in each `SKILL.md`).
