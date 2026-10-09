# Port Manager V2 — resumable implementation checkpoint

**Branch:** `feat/portmanager-v2-roadmap` (base `64842968c85f85afdad4e11c3ed4adfce65f5d22`).
**Draft PR:** https://github.com/smorad3363/assistant-vps/pull/1
**Contract:** PM2-SPEC-001 v1.0.0 (2026-10-09).
**Stable V1:** do not edit `portmanager-dashboard/**`.
**Release state:** development; **DO NOT deploy on production**.

## Implementation phases
- [x] Phase 0 — pinned baseline/source audit and ownership model documented.
- [ ] Phase 1 — V1 alias, independent V2 installer/bootstrap and CLI have been
      committed; completing CI, installer tests and VM coexistence validation.
- [ ] Phase 2 — IPv4 DNAT/SNAT, strict ownership, CRUD and rollback.
- [ ] Phase 3 — all-except, port/SSH guard, 120-second rollback.
- [ ] Phase 4 — sampling, live dashboard, SQLite reports.
- [ ] Phase 5 — qdisc detector, limits E_CONFLICT/E_UNSUPPORTED.
- [ ] Phase 6 — VM/netns gate A–F, release v2.0.0 to master.
- [ ] Phase 7 — 2.1 shaping/quota after stable release.

## Phase 1 decisions
- V1 new URL is a thin wrapper around the original unchanged master installer.
- `portmanager2` is a separate Python stdlib CLI, not a rewritten V1.
- Development VERSION uses SemVer prerelease suffix, not 2.0.0 stable.
- Unimplemented features return E_UNSUPPORTED, never fake success.
- V2 bootstrap is intentionally non-network-mutating.
- Neither existing V1 path nor V1 crontab is written by V2.
- Installer must pin archive to resolved full GitHub commit SHA, verify SHA256
  manifest, and provide atomic release activation and rollback.

## Resumption instructions for any assistant
1. Fetch this file, `docs/ARCHITECTURE.md`, `docs/FIREWALL-OWNERSHIP.md`,
   source files and README **from this branch**; check current branch HEAD and
   open PR before modifying code. Compare to PM2-SPEC-001.
2. Check `portmanager-dashboard/**` diff from frozen base is **empty**.
3. Continue the earliest incomplete phase and record commits and tests here.
4. Update this file at every meaningful checkpoint; preserve acceptance IDs.
5. Do not merge development PR to master until all mandatory gates pass.
6. A missing privileged VM test must be marked **NOT TESTED**, not passed.

## Testing status as of 2026-10-09

- GitHub Actions includes a frozen-V1 diff check, Bash syntax, SHA256 manifest,
  Python compilation, isolated CLI unit tests and ShellCheck.
- A CI unit assertion originally rejected the harmless `iptables-restore`
  *dependency name* and was corrected to detect execution instead.
- CI static/unit passed on Python 3.10 and 3.12 at commit
  `1a70eaaa6d908d2166bb0f22702e02eb1eb051ed`.
- Installer smoke on a disposable GitHub Ubuntu 24.04 VM caught a real
  **reinstall bug**: `/var/lib/portmanager2` initially lacked `owner.json`.
  Fixed in commit `3bb9f501e74b1e8b5e5237e7bacdab4a5779b312`.
- **PASSED:** workflow https://github.com/smorad3363/assistant-vps/actions/runs/37932900700
  on commit `5d013af223b1f0b399bd1c0437bc092224517f43`.
  Python 3.10 / 3.12 static+unit, Bash parsing, ShellCheck, SHA256 integrity,
  frozen-V1 diff, and disposable Ubuntu 24.04 VM install/reinstall/dry-run
  uninstall/uninstall all passed.
- A CI permission assumption was fixed: after uninstall, root-private V2
  config remains present (verify with `sudo test -f`, not ordinary user).
- No V1 installation/coexistence test has run yet. Do **not** count
  AT-001..AT-007 as fully passed.
- Phase 1 remaining: systemd lifecycle implementation/testing, V1 alias
  equivalence test with frozen V1, full coexistence/fingerprint verification.
- All actual `iptables`, systemd, reboot, root install/uninstall and V1/V2
  coexistence tests are still **NOT TESTED** on an isolated VM.
- No phase 2, 3, 4 or 5 network functionality should be described as working.
- Resumption: check fresh workflow runs for the current HEAD and fix failures.

## Mandatory test matrix
AT-001..AT-007 installs/coexistence; AT-008..AT-022 NAT/safety/rollback;
AT-023..AT-027 accounting/tc; AT-028..AT-040 failures/compatibility.
No privileged VM/netns result has been verified yet.

## Known risk register
R01 critical: DDS legacy globally flushes iptables (do not copy).
R02 critical: V1 `tc` root/ingress replacement (limit V2 2.0 is no-op).
R03 high: mixed nft/legacy and foreign NAT hooks (fail closed).
R04 high: SSH/admin listener capture by all-except (mandatory exclusions).
R05 high: incorrect SNAT/conntrack direction accounting.
R06 high: destructive reinstall/uninstall (strict path ownership).
