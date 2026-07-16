# TOOLS.md - Lab Notes

Environment-specific notes. Update as the lab grows.

## Environment
- Tool actions execute in the Docker sandbox image `openclaw-sandbox:tools` (kali-rolling + nmap, NetExec/nxc, Impacket, certipy-ad, bloodhound.py, kerbrute, bloodyad, ldap-utils, dnsutils, python3). Anything a skill needs must be in that image or installed by the skill.

## Targets
- The Active Directory domain given
- **Controlled start: you are given only the target IP, no credentials.** Begin with the entry doctrine in SOUL.md (ad-foothold, then **ad-sweep**).

## Skills available
- `ad-foothold` - from a DC IP only: discover domain, enumerate users, lockout-safe spray -> first credential.
- `ad-sweep` - **your primary post-foothold skill.** With a credential, one call returns the ranked exploitable surface: ADCS ESC templates, GPP cpasswords, AD description secrets, and full attack paths to Domain Admin (including multi-hop ACL/DCSync chains). Use this for escalation mapping.
- `ad-loot` - narrower legacy skill: dumps AD descriptions only. `ad-sweep` supersedes it; prefer ad-sweep.
- `nmap-scan` - service/version recon (unprivileged connect scans).
- `recon-sweep` - bounded pure-python TCP recon.

## Notes
- Lockout policy on the domain is 3/15/15. ad-foothold is built to stay under it; never spray outside that skill or raise its cap.
- (add credential-store pointers and tool quirks here as you go)
