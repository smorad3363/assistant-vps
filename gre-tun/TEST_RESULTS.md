# Test results - 0.2.1-dev

Date: 2026-10-17. Host: Debian 13 (trixie), x86_64, no CAP_NET_ADMIN, no nft binary.

- Frozen contract + package schema tests: PASS when source SHA256SUMS matches this release.
- Python unit tests: see runner output in release build; these are offline-only.
- GRE peers, real TCP/UDP payload, firewall coexistence, tc/IFB caps: NOT RUN.
- Crash injection, independent guard, scoping, real uninstall: NOT RUN.
- Ubuntu 22.04 and 24.04, reboot, foreign sentinels, 16-tunnel scale: NOT RUN.

No deployment, PASS status, throughput or production guarantee is inferred from the offline test suite.
