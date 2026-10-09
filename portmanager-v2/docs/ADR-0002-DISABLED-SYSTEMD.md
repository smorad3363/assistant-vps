# ADR-0002 — Install systemd units disabled in prerelease

Accepted 2026-10-09.

The normative PM2-SPEC-001 requires a boot restore service and 60-second
sample timer in stable 2.0.0. Their engines do **not** exist in Phase 1.
Publishing enabled units that execute `restore` or `sample` today would
report errors on boot or pretend to do something useful.

**Decision:** installer ships all three dedicated units, records SHA256
fingerprints in `/etc/portmanager2/systemd-owner.json`, then runs
`systemctl daemon-reload`. No `enable` or `start` is allowed yet.
Restore and sample services additionally have `ConditionPathExists` guards;
Phase 1 does not create those marker files. Operators MUST NOT enable the
units manually. Uninstaller removes verified, disabled/inactive units only.

Transition: enabling restore is gated by Phase 2 rollback/restore tests;
enabling the sampler timer is gated by Phase 4 accounting tests. At these
transitions this ADR must be replaced with an ownership-aware enable/disable
procedure and VM reboot evidence. The final 2.0.0 must meet the stable spec.
