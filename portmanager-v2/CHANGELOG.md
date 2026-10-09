# Changelog

## 2.0.0-dev.1 — 2026-10-09 (unreleased)
### Added
- Independent development CLI and read-only doctor/status.
- Three disabled systemd unit templates with SHA256 ownership verification.
- Nonblocking V2-only mutation lock and unit lifecycle rollback on reload failure.
- Complete authoritative Persian implementation specification, shipped in repo.
- CI regression tests for owned/foreign/tampered/masked systemd units and the
  V1 alias, plus real V2 installer smoke tests on ephemeral Ubuntu.
- New V1 installation alias pointing to original installer.
- Ownership boundaries, resumable development checklist and audits.
### Security
- No NAT/iptables/tc mutations or unsupported network features in bootstrap.
- Uninstaller refuses to remove enabled, modified or foreign unit files.
- Reinstall preserves V2 config and does not duplicate owned units.
- Conservative V2 uninstall limited to recognized ownership paths.
### Known limitations
- Phase 1 only. **No tunnel management or real-world traffic monitoring yet.**
- Missing privileged VM, Ubuntu/Debian and coexistence test evidence.
