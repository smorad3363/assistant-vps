# Changelog

## 2.0.0-dev.1 — 2026-10-09 (unreleased)
### Added
- Independent development CLI and read-only doctor/status.
- New V1 installation alias pointing to original installer.
- Ownership boundaries, resumable development checklist and audits.
### Security
- No NAT/iptables/tc mutations or unsupported network features in bootstrap.
- Conservative V2 uninstall limited to recognized ownership paths.
### Known limitations
- Phase 1 only. **No tunnel management or real-world traffic monitoring yet.**
- Missing privileged VM, Ubuntu/Debian and coexistence test evidence.
