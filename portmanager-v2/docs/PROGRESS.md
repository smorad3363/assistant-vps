# Port Manager V2 — checkpoint for any AI contributor

## 2026-10-09 — Default V2 `portmanager` and reversible V1 cut-over (PR #2)

User specifically requires:
- Same original one-line installer with no arg: V2 becomes **`portmanager`** (while `portmanager2` remains an alias).
- Same original installer piped through `sudo bash -s -- v1`: switches to the original V1, not parallel V1+V2 installations.
- Existing V1 installation upgrades into V2 without discarding V1 backups/settings, with option to downgrade exactly to previous V1.
- `sudo bash v1` is not valid for piped installers.

Implementation:
- New `pm2/migration.py`: fail-closed preflight; recognizes only original V1
  binary (and V2-owned alias), snapshots SHA256 archived V1 executable under
  `/var/lib/portmanager2/legacy-v1/`, preserves V1 config/data and exact
  root crontab entries, disables only verified V1 `sample/apply` jobs and
  atomically replaces the public `portmanager` command with V2.
  V1 iptables and tc rules deliberately survive migration (no network break).
- Original V1 restoration in `portmanager-v1/install.sh`: before uninstalling
  V2 it verifies the preserved archive and rejects enabled V2 tunnels;
  refuses unknown aliases; safely removes only V2-owned network/services via
  `portmanager2 uninstall --yes`; restores exact archived V1 binary + old
  cron jobs. V2 config/data remain preserved for later reupgrade.
- `pm2/cli.py`: V2 uninstall removes its owned public symlink only and
  prevents `--purge` if a V1 archive exists.
- `pm2/shaping.py`: recognizes V2 primary command symlink (not treated as
  active V1) and detects live V1 HTB 1: qdisc after migration, rejecting
  conflicting shaping without silently deleting legacy tc.
- CI: unit `test_migration.py`, ephemeral V1->V2->V1 router, lifecycle,
  destructive purge protection, real TC and namespace tests.

**IMPORTANT:** This cut-over is about selecting the app executable and
disabling old cron. It does not automatically convert old V1 rate policies
to V2's configuration or delete old kernel firewall/tc rules. An operator
must review those for real server migration. A V1 rollback with any enabled
V2 tunnels is refused to prevent dropping SSH or service access.
This is a safety boundary, not an implementation bug.

Release gate: 13 GitHub jobs at the exact final head SHA must pass. PR #2
should merge to master only after the matching head's CI is green; future
changes require revalidation.


## 2026-10-09 — New version-router and 2.1 RC release candidate

User has explicitly changed installer requirements:
- **SAME ORIGINAL URL** `master/portmanager-dashboard/install.sh`
  executes V2 when piped to `sudo bash`.
- Explicit original V1 from SAME URL uses `| sudo bash -s -- v1`.
  `sudo bash v1` is technically impossible to use as piped-script option:
  Bash opens a file named `v1` rather than reading stdin.
- `portmanager-v1/legacy-install.sh` is a byte-for-byte snapshot of the
  frozen installer at original repository base SHA. The compressed V1 script
  under `portmanager-dashboard/portmanager.sh.gz.b64` remains unchanged.
- `portmanager-v1/install.sh` delegates to the snapshot and refuses V1
  installation when V2-owned tc shaping state is active.
- The original `portmanager-dashboard/install.sh` on the development branch
  is now an explicit 2-way shell dispatcher, but `master` is unchanged
  **until PR #1 is merged**. CI route tests are required before merge.
- `pm2/shaping.py` adds real per-port scheduled `tc clsact` ingress
  policing for upload and egress policing for download, each resolved to a
  single active V2 tunnel interface. Uses `pm2/limit_windows.py` for
  weekdays, IANA timezone, cross-midnight and DST logic.
- V2 shaping **rejects V1 installation, unknown clsact/foreign filters and
  journal conflicts**. It never deletes a root qdisc or flushes firewall
  tables. The 1-minute V2 sampler timer is enabled on schedule installation.
- CLI: `limits schedule-preview`, `schedule-install`, `schedule-list`,
  `schedule-apply`, plus text menu 05 for interactive schedule entries.
- Uninstall removes only owned V2 clsact filters after kernel ownership
  verification. Tunnel edits are blocked while enabled V2 timed schedules
  refer to that config, preventing stale scheduled filters.
- Version bump: `2.1.0-rc.1`. **Do NOT call it stable until tests pass.**

**Pending P0 tests:** latest commit manifest and CI (including actual
`tc-police-scheduled-ephemeral` job); full guest reboot with live SSH plus
real multi-host traffic and time-based shape under realistic load have not
been independently demonstrated. A disposable VPS with independent console
and snapshot is required to claim production readiness.


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

## Watchdog scheduling bug and mitigation (2026-10-09)

- **Reproduced intermittent 120s deadline violation** in
  [run 37961808849](https://github.com/smorad3363/assistant-vps/actions/runs/37961808849):
  the transient `systemd-run --on-active=120s` default `AccuracySec=1min`
  can coalesce execution up to ~60 additional seconds. In a 130s timeout
  test, the rollback journal was still present.
- **Fix:** set `--timer-property=AccuracySec=1s` explicitly in
  `pm2/guard.py`. The 130s test now dumps transient timer status/journal
  on a miss and unit tests assert explicit timing properties. **Latest CI
  rerun is required before this mitigation can be marked PASS.**
- Even with tighter accuracy, timers cannot provide a hard real-time
  guarantee under a suspended/offline/unresponsive machine. Keep reboot
  and SSH disconnect cases as P0 until independently tested.

## Current latest acceptance evidence

- [Run 37960307468](https://github.com/smorad3363/assistant-vps/actions/runs/37960307468):
  9/9 jobs green at `ac665537...`; 48 unit tests each on Python
  3.10 and 3.12, shellcheck/Bash/SHA256, no V1 file changes.
- Real original V1 install plus new alias: same binary, preserved V1 cron,
  V1 accounting chain, data fingerprints and tc state across V2 lifecycle.
- `v1-reinstall-v2-purge` (run 37961638987): V1 reinstalled with V2
  present; V2 purged via pseudo-terminal and explicit confirmation; V1
  executable, cron, accounting chain and qdisc fingerprints remained intact.
  AT-007 and AT-032 passed on disposable Ubuntu 24.04 runner.
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

## 2026-10-09: Debian V1 CPU regression and requested 2.1 scheduling

- User observed all 4 cores at 100% on an active Debian host immediately
  after selecting V1 Live `measure window 1s`; screenshot also displayed
  `ksoftirqd`, Xray and sing-box. **CPU causation not proven solely by image.**
- Frozen V1 source audit (run 37963364961) confirms `liverows` calls
  `ensure_rules` on every refresh. Each call discovers ports via
  `ss`, `iptables-save` and `ip6tables-save`, checks chain ownership
  via repeated `iptables` commands and *can rebuild* entire accounting
  chain when ports change. This is unnecessarily expensive for 1-second
  viewing; per-packet mangle costs may persist even after closing Live.
- **V1 installation and original binary are untouched.** New optional
  `portmanager-v1/perf/fast_live.py` reads only existing V1 counters,
  skips rule discovery/recreation, clamps refresh >=2s and defaults 5s.
  GitHub V1 read-only audit CI run 37963898105 passed **6 pure unit tests**;
  live Debian CPU effect is **NOT TESTED** and needs measured before/after.
- A new pure `pm2/limit_windows.py` backend supports scheduled per-port
  policy validation/evaluation: weekday, timezone, overnight, DST,
  overlap and preview-only JSON. Tests and example plan added.
  **This does NOT enforce bandwidth in V2 2.0.0.** Real 2.1 qdisc
  ownership-based enforcement is still a separate work item; see
  [ADR-0003](ADR-0003-SCHEDULED-LIMITS.md).
- Requested extra acceptance IDs: AT-041..050, with 047..050
  requiring real scheduling + qdisc ownership and VM tests.

## Live per-port graph (latest 2026-10-09 change)

- Implemented `pm2/port_graph.py`, `graph --refresh N --window 10m`
  and interactive menu option 04. A single per-refresh read-only
  `iptables-save -c -t mangle` snapshot powers real per-original-port
  TCP/UDP throughput, configurable 2..60s refresh, rolling time-weighted
  600-second averages, ASCII/Unicode sparkline history, reset-safe deltas,
  bounded SQLite retention and load-aware refresh backoff.
- Shows existing V1 `PORTMANAGER_ACCT` original monitor ports **without
  editing V1** as well as V2's own `PM2_ACCOUNT` tunnel ports.
- All-except rules are explicitly labelled `ALL*` aggregated because
  single-port conntrack tags are not present; no invented per-port stats.
- Added `tests/unit/test_port_graph.py` (11 cases) and namespace
  TCP/UDP graph assertions in GitHub Actions. First failing SQLite window
  boundary test was fixed. A second V1 parser exclusion error was fixed;
  validate **the latest HEAD run**, not previous runs, before release.
- **NEXT:** confirm 10/10 green CI at latest HEAD, then perform user
  acceptance on disposable Debian VPS/snapshot. Time-scheduled `tc`
  enforcement still requires version 2.1 ownership-safe backend.

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
   failure, corrupt journals and permission changes; preserve V1 and recovery
   evidence. Purge with installed V1 now tested on an isolated Ubuntu runner.
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
