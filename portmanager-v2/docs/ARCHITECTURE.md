# Architecture — PM2-SPEC-001

## Specification
Contract: **PM2-SPEC-001 v1.0.0, 2026-10-09**.
The full Persian specification is maintained as
`PortManager_V2_Implementation_Roadmap_FA.md` in the originating planning artifact;
the concise, self-contained phase checklist is in `docs/PROGRESS.md`.
No unfinished feature may pretend to be working.

## Source baselines (frozen)
- V1: `smorad3363/assistant-vps@64842968c85f85afdad4e11c3ed4adfce65f5d22`
- V1 original installer blob: `3a2e58a1f6899e5e692aedd3dfba2121e0420cf7`
- V1 compressed payload blob: `c0b04f712f872b63c77ab0c25ee7d709563a888e`
- DDS Tunnel: `azavaxhuman/IPTABLE-Tunnel-multi-port@73fe935e86b8ae74fb83901c2624204fdf6e664d`
- DDS tunnel.sh blob: `fae4ee1ba9488636cf591642cf0e4fdf8267479f`

## Non-negotiable ownership boundaries
- V1: `/usr/local/bin/portmanager`, `/etc/portmanager`,
  `/var/lib/portmanager`, existing root cron and `PORTMANAGER_ACCT`.
- V2: `/usr/local/bin/portmanager2`, `/opt/portmanager2`,
  `/etc/portmanager2`, `/var/lib/portmanager2`,
  `/var/log/portmanager2`, `portmanager2-*` units.
- **No mutation of V1 state, `iptables-persistent`, `rules.v4`,
  foreign iptables chains or foreign qdiscs.**
- Never flush whole iptables tables, set default firewall policies, or delete a
  qdisc without verified V2 ownership.
- Use a named V2 chain ownership manifest and fail closed on conflicts; no
  destructive installer-time NAT changes.
- Network functionality is IPv4 NAT forwarding, *not an encrypted VPN*.

## Baseline audit
V1 installer downloads a gzip+base64 Bash payload, validates `bash -n`,
and installs `/usr/local/bin/portmanager`. V1 main script owns
`PORTMANAGER_ACCT` in mangle and uses `conntrack --ctorigdstport`/
`--ctorigsrcport`; sample/reapply is via root cron. Its limiter deletes
and rebuilds root and ingress qdisc on the chosen interface, therefore V2
2.0 must not apply traffic shaping. The legacy DDS script's
`Flush all iptables rules` action is **not imported**.

## Rollout
Phase 0: audit, baselines, ownership contract and resume checkpoint.
Phase 1: V1 alias; independent, fail-closed V2 bootstrap and CLI; no NAT.
Phase 2: schema, per-tunnel IPv4 NAT, conflict preflight and rollback.
Phase 3: all-except management protections and timed confirm.
Phase 4: conntrack accounting, SQLite and TUI.
Phase 5: tc-conflict detection; in 2.0 limit modifications remain unsupported.
Phase 6: acceptance AT-001..040 across nft/legacy Ubuntu/Debian before release.
Phase 7: 2.1.x shaping ONLY after exclusive qdisc ownership tests.

See `docs/PROGRESS.md` for the latest verified state.
