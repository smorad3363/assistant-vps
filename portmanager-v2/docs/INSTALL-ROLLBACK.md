# Phase 1 installation, disabled services and recovery

This page applies to **2.0.0-dev.1** on the development branch; V2 is not ready
for production forwarding. No NAT, filter, qdisc, root cron or sysctl changes
are performed by the V2 development installer.

## Three version routes

- Legacy V1 (unchanged): `master/portmanager-dashboard/install.sh`
- New V1 alias: `master/portmanager-v1/install.sh` (delegates to legacy)
- New V2: `master/portmanager-v2/install.sh` **only after release approval**.

To test development V2 on a disposable VM, check out the development branch and
use its `install.sh` with `PORTMANAGER2_REF=<full SHA>`. The installer resolves
the commit, fetches one archive for that SHA, verifies checksums, stages a
release, atomically points `current` at it, and installs **three disabled**
systemd units. Never run prerelease code on your production VPS.

The service files have dedicated names:
- `portmanager2-restore.service`
- `portmanager2-sample.service`
- `portmanager2-sample.timer`

All are **intentionally disabled and inactive** until their engines are
complete. The restore/sample services have `ConditionPathExists` guards for
marker files that Phase 1 never creates. Do not enable them manually.

## Independent ownership

- V1 original binary/data/cron, `PORTMANAGER_ACCT` and V1 `tc` are untouched.
- V2 unit files: `/etc/systemd/system/portmanager2-*`.
- V2 unit ownership is recorded in `/etc/portmanager2/systemd-owner.json`,
  including a SHA256 for **each** installed unit.
- Before replacement/removal V2 checks the entire unit inventory and requires
  `disabled` / `inactive` states. If units changed externally, stop with
  `E_CONFLICT`: there is **no** force flag.
- Installer and `uninstall` coordinate using
  `/run/lock/portmanager2.lock` (nonblocking, exit 9 for conflict).
- Root-owned V2 config/data are mode 0700; files are 0600.

## Supported recovery

- `portmanager2 doctor --json` is read-only and reports service drift.
- `portmanager2 uninstall --dry-run` previews affected paths.
- `sudo portmanager2 uninstall --yes` checks unit ownership, removes owned
  disabled units + launcher + V2 releases. Config/data are **retained**.
- `sudo portmanager2 uninstall --purge` requires additional **interactive**
  confirmation for V2 config/data/logs.
- A modified or enabled V2 unit blocks uninstall; restore the exact
  package-owned unit or investigate external management first. Never
  automatically delete or disable foreign units.
- If systemctl daemon-reload fails during unit changes, V2 attempts to restore
  prior unit bytes and marker. If rollback also fails, it returns
  `E_ROLLBACK` and requires manual diagnosis. Do not report success.
- V2 does not auto-reset `ip_forward` or roll back the global firewall.

## Remaining tests before release

The isolated GitHub Ubuntu 24.04 VM tests cover bootstrap install, repeat
install, dry-run uninstall and uninstall. Test complete V1 installation,
boot/reboot restore, firewall changes and network namespace integration
**separately** before releasing any forwarding feature.
