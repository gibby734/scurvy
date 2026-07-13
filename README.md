# Scurvy

Scurvy is an OpenClaw agent equipped with red-teaming tools, having the automation and agentic reasoning driven by the OpenClaw agent, which can utilize classic AD tooling to compromise entire AD systems.

An autonomous Active Directory red-teaming agent. Given only a target IP, it works a fixed sequence to reach Domain Admin and reports the path with evidence.

Runs on the OpenClaw agent framework: the agent loop drives custom skills inside a sandbox, one tool call per turn.

Scurvy is not meant to be an all-powerful red-teaming solution, but a copilot to automate penetration tasks achieving much faster attacks, accurately. 

> Authorized testing only. Every skill enforces an RFC1918-only scope guard and refuses public targets without an explicit override. The spray skill is lockout-safe by design.

## How it works

1. `ad-foothold` — from a DC IP and no credentials: discover the domain, enumerate valid users, run a lockout-safe spray for a first low-priv credential.
2. `ad-sweep` — with that credential, sweep the domain and return ranked findings: ADCS ESC templates, GPP cpasswords, secrets in AD object metadata, and ACL/DCSync paths to Domain Admin.
3. Walk one path to Domain Admin, stop on the first confirmation, report.

## Layout

```
workspace/
  SOUL.md AGENTS.md IDENTITY.md USER.md TOOLS.md MEMORY.md HEARTBEAT.md
  skills/
    ad-foothold/   from-zero foothold (kerbrute, NetExec)
    ad-sweep/      breadth sweep + paths to DA (certipy-ad, NetExec, bloodyAD)
    ad-loot/       dump AD descriptions, flag leaked creds (NetExec)
    nmap-scan/     single-host service/version scan (nmap)
    recon-sweep/   stdlib-only TCP connect scan + banner grab
```

`workspace/` maps to the OpenClaw agent workspace; skills resolve at `/workspace/skills/<name>/` in the sandbox. Each skill has a `SKILL.md` and a Python helper that emits structured JSON.
