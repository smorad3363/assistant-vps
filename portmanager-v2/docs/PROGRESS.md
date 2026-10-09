# Port Manager V2 — checkpoint for any AI contributor

**Last verified CI evidence:** 2026-10-09,
[GitHub Actions 37960307468](https://github.com/smorad3363/assistant-vps/actions/runs/37960307468),
source SHA `ac6655379fb370ad4b7d7933f361e98cf78d1ba1`. All 9 jobs passed,
including 48 unit tests on each Python 3.10/3.12, real V1/V2 installed on
an ephemeral Ubuntu 24.04 VM, and real 120-second watchdog expiry.
This document was updated **after** that verified SHA; re-check the
latest HEAD's workflow before claiming a green final commit.

**Branch:** `feat/portmanager-v2-roadmap`; draft
[PR #1](https://github.com/smorad3363/assistant-vps/pull/1).
**Base/stable V1 master SHA:** `64842968c85f85afdad4e11c3ed4adfce65f5d22`.
**Spec:** `docs/PM2-SPEC-001.fa.md` — normative v1.0.0.
**V2 version:** `2.0.0-dev.1`, not a production release.
**Release decision:** `master` untouched and PR remains DRAFT until
acceptance gates A–F and user testing complete.

## Implementation status

- [x] Phase 0 — original V1 frozen; upstream comparison and ownership contract.
- [x] Phase 1 core — V1 alias, isolated V2 pinned installer, SHA256 inventory,
  root-owned config, safe uninstall, own systemd units; actual V1 coexistence
  tested on a disposable Ubuntu 24.04 VM. Destructive purge/other systems pending.
- [x] Phase 2 core — IPv4 TCP/UDP DNAT + MASQUERADE/SNAT and FORWARD/ACCOUNT,
  collision detection, CRUD, atomic config/state with journal; 3-namespace
  end-to-end round trips and simulated rule loss/restore passed.
- [x] Phase 3 core — all-except requiring explicit SSH fallback exclusion,
  actual listener audit, 120s watchdog, confirm, manual rollback, and actual
  120s automatic expiry in a clean Ubuntu VM; broader SSH lockout tests pending.
- [x] Phase 4 core — SQLite counters (reset-safe epochs), 1h/24h/7d reports,
  live rates, terminal menu, backups, audit logs; positive up/down network
  bytes and 48 Python tests in CI. Long-term load/retention not verified.
- [x] Phase 5 2.0 contract — no V2 tc modification; shaping postponed to 2.1.
- [ ] Phase 6 — expanded fault injection, full VM reboot, test purge and
  legacy backend; verify admin/SSH continuity and user acceptance. Gate F BLOCKED.
- [ ] Phase 7 — V2 2.1 qdisc limits/quotas (never part of 2.0 rollout).

## Current latest acceptance evidence

- [Run 37960307468](https://github.com/smorad3363/assistant-vps/actions/runs/37960307468):
  9/9 jobs green at `ac665537...`; 48 unit tests each on Python
  3.10 and 3.12, shellcheck/Bash/SHA256, no V1 file changes.
- Real original V1 install plus new alias: same binary, preserved V1 cron,
  V1 accounting chain, data fingerprints and tc state across V2 lifecycle.
- Networkns: TCP 443→8443 and UDP 2053→2053 with return path; upload/download
  bytes positive with interval coverage; idempotent apply and removal of own
  hooks; all-except forward and confirmation; rollback-pending manual path.
- Networkns reestablishes verified V2-owned chains after simulated kernel
  rule loss (not equivalent to rebooting Ubuntu).
- Optional V2 systemd timer and restore units enabled, operated and removed
  cleanly; disabled by default at initial install.
- Real `systemd-run --on-active=120s` expires and removes protected journal.
- Pending failed kernel rollback retains journal (unit regression test).
- Safety: no global iptables flush/restore, no root qdisc modifications,
  source names `PM2_*`, no V1 binary/cron overwrite.

## Open risks and acceptance work remaining

1. **P0 until verified:** Full guest reboot of a VM with actual active
   TCP/UDP tunnels, with V1 installed, then verify V2 restoration and V1
   fingerprints. Simulated netfilter loss alone does not pass this gate.
2. **P0 until verified:** Deliberate SSH port change/all-except failure,
   access loss and real watchdog restore using a *separate console*, including
   restoration when rebooted within the confirmation window.
3. **P1:** Validate iptables-legacy versus iptables-nft, UFW/firewalld,
   Docker/custom NAT collision rejection; never auto-flush foreign chains.
4. **P1:** Privileged failure injection: partial multi-table apply, reload
   failure, corrupt journals, full purge with installed V1 and permission
   changes; preserve V1 and recovery evidence.
5. **P1:** Long-lived telemetry under counter resets, large sample history,
   retention rotation and date-window boundaries; evaluate need to implement
   rollups/cleanup before calling reporting stable.
6. **P1:** Bounded 120s timer lifecycle: survive process crash/reboot, locking
   contention and disk failures; check exactly what happens if root network
   manager restarts or boot restore fires before timer.
7. Gate F: user acceptance on sacrificial VPS/snapshot, release notes,
   approval and **only then** selective merge to master, retaining unchanged
   original V1 command; V2 must remain a separate install URL.

See [TEST-MATRIX.md](TEST-MATRIX.md) for claims versus evidence and
[OPERATOR-TEST-FA.md](OPERATOR-TEST-FA.md) for reproducible test steps.

## Recovery instructions for the next AI

1. Read this file and `docs/PM2-SPEC-001.fa.md`; get actual current head SHA,
   draft PR state and **latest** Actions runs (not the historical green run).
2. Inspect `portmanager-v2/manifest.sha256` and update checksums for every
   modified/new file. Run SHA256 verification, ShellCheck and Python 3.10/3.12.
3. Check V1 diff against frozen base is empty, and original V1 URL unchanged.
4. Fix failing CI before expanding features. Run isolated TCP/UDP, rollback
   and coexistence jobs; do NOT test privileged NAT on the user's VPS.
5. Complete the outstanding P0 then P1 acceptance checks (above). Record
   actual run URLs, commit SHAs and acceptance IDs, not assumed passes.
6. Keep draft PR unmerged until Gate F. Avoid changing unrelated or stable V1
   paths; if blocked on final user-only network test, make an explicit handoff.

## Known hazards

R01 legacy global iptables flush — prohibited. R02 V1 qdisc ownership —
never override. R03 NFT/legacy or Docker/UFW hooks — reject uncertain state.
R04 SSH/management port captures — protect even when running on an alternate
port. R05 counter direction/epochs — verify. R06 symlink/ownership/rollback
— fail closed and preserve the journal on ambiguous outcomes.
