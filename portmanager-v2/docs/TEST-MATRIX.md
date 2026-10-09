# Acceptance/test gates — Port Manager V2, 2026-10-09

Normative source: [PM2-SPEC-001](PM2-SPEC-001.fa.md).
Automated evidence: [run 37960307468](https://github.com/smorad3363/assistant-vps/actions/runs/37960307468)
at commit `ac6655379fb370ad4b7d7933f361e98cf78d1ba1`.
**All nine jobs passed:** static/unit Python 3.10/3.12 (48 tests), V1 alias,
V2 bootstrap, real V1+V2 coexistence, networkns TCP+UDP, activated V2 systemd,
120-second automatic rollback watchdog, and VM-isolated failure/integrity checks.

| Gate | Status | Evidence/remaining work |
| --- | --- | --- |
| A — V1 frozen, manifest, Bash, ShellCheck, Python | PASS | CI checks, V1 path diff |
| B — CLI/config/systemd unit tests | PASS | 48 unit tests on Python 3.10/3.12 |
| AT-001 original V1 installer, AT-002 alias | PASS (Ubuntu 24.04 VM) | Real V1 and V1 alias invoked separately |
| AT-003 V2 install/doctor/version, AT-005 reinstall | PASS (Ubuntu VM) | Root install and idempotence |
| AT-004/006 real V1+V2 install/uninstall | PASS (Ubuntu VM) | V1 binary/data/cron/accounting/tc fingerprints unchanged |
| AT-007 purge with V1 present | PASS (ephemeral Ubuntu VM) | `v1-reinstall-v2-purge`, run 37961638987; interactive PTY confirmation, V1 checksums unchanged |
| AT-008..021 network/SSH-specific variants | PARTIAL | TCP+UDP, SNAT, reverse return, all-except and confirm tested; not exhaustive |
| AT-022 dry-run no mutation | PARTIAL | Tunnel preview/installer dry run, not all error injections |
| AT-023..027 reporting/shaping | PARTIAL | Two real samples, positive upload/download/rates; shaping deliberately unsupported |
| AT-028..040 failure/reboot/compatibility | PARTIAL | AT-032 V1 reinstall passed on run 37961638987; unit tamper, networkns kernel-rule reset+restore, real 120s timer; full OS reboot/legacy backend unsupported |
| C — NAT/SSH safety | PARTIAL | Isolated network success; real SSH port-change/lockout safety still unverified |
| D — V1/V2 coexistence | PASS on fresh Ubuntu runner | Other distributions, long-lived V1 configs still unverified |
| E — failure injection and reboot | PARTIAL | Simulated rule loss works; full reboot and true loss-of-connectivity need VM |
| F — publication gate | BLOCKED | User acceptance, remaining AT IDs, explicit release review |

Additional acceptance evidence: [run 37961638987](https://github.com/smorad3363/assistant-vps/actions/runs/37961638987)
(`v1-reinstall-v2-purge`): original V1 reinstalled with V2 present, then
V2 interactive `--purge` removed only V2 paths and preserved V1 executable,
root cron, mangle accounting chain and tc state.

**Scope of claims matters.** Successful GitHub jobs do **not** prove V2 safe
on an arbitrary active VPS with Docker, UFW, custom SSH ports or `tc` shaping.
Do not mark a full reboot, legacy iptables, IPv6, high-load soak, automatic
rollback after real SSH loss, or destructive purge PASS until observed.
Never merge to `master` while Gate F is blocked.
