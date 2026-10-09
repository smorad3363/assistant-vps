# ADR-0001 — Explicit prerelease during incomplete implementation

**Accepted:** 2026-10-09

Specification requests stable 2.0.0 after phases 0..6 but feature-complete
behavior is not yet implemented. During phases 1..5, `VERSION` therefore
uses valid SemVer `2.0.0-dev.1`. This makes `--version` truthful and prevents
a bootstrap-only artifact from being mistaken for stable 2.0.0.

No repository-wide `master` install path is published by this branch.
Stable 2.0.0 is gated on VM integration acceptance AT-001..AT-040.
