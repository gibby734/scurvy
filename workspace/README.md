# Scurvy workspace mirror

Point-in-time backups of Scurvy's live OpenClaw workspace files (`~/.openclaw/workspace/` on Kali). These give you a vault-backed copy and let you read the agent's config directly without pulling from Kali.

**Source of truth is Kali, not these files.** The agent can edit its own `MEMORY.md` and daily `memory/YYYY-MM-DD.md` over time, so these mirrors will drift. Re-sync after any change (deploy from here to Kali, or copy Kali's current files back here).

- Files: SOUL.md, AGENTS.md, IDENTITY.md, USER.md, TOOLS.md, MEMORY.md, HEARTBEAT.md
- Skills live under `skills/` (each with a SKILL.md + scripts).
