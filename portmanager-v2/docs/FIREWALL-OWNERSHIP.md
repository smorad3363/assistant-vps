# Firewall ownership and non-interference

Planned V2 chains only: `nat/PM2_NAT_PRE`, `nat/PM2_NAT_POST`,
`filter/PM2_FORWARD`, `mangle/PM2_ACCOUNT`. One verified hook per parent,
annotated `pm2:<uuid>:<purpose>` rules. **Not yet implemented in phase 1.**

Safety design:
1. Check interface/listening IP, SSH/admin ports, existing listeners and
   overlapping NAT rules, including legacy DDS and other managers.
2. Reject uncertain backend, owner, chain or firewall-manager conflicts.
3. Lock mutating operations; snapshot config and owned rules, stage changes.
4. Apply only V2-owned rules; on failure restore only V2-owned manifest.
5. For all-except/management-impacting changes require 120-second rollback
   watchdog and explicit `confirm <change-id>`.
6. No global `iptables -F`, `iptables -P`, `iptables-save > rules.v4`,
   `iptables-restore` without owned scope, or foreign `tc qdisc del`.
7. Never assert that a kernel resource belongs to V2 merely because its name
   resembles a V2 resource; verify the ownership manifest.
8. V1 may replace its own qdisc; V2 2.0 does not apply shaping.

Phase 1 installs **no** iptables rules, hooks, policy changes, qdiscs, cron
jobs or systemd units. The V2 CLI returns E_UNSUPPORTED for tunnel mutation.
