# Implementation status

Date: 2026-10-17
Contract: 1.0.0
Development application: 0.1.0-dev
Release ready: **NO**

| Area | Status |
|---|---|
| Frozen specification, menu strings, schemas, reference behavior | Included / offline tests pass |
| Atomic, lock-protected desired-state JSON storage | Implemented / offline tests |
| First-run host role, GRE pair identity, parser, peer GT1 setup token | Preview implemented / offline tests |
| Local port mapping input (`5445:5454`) and cap input | Preview implemented / offline tests |
| CLI menu, read-only status, bounded NOT RUN diagnostic reports | Preview implemented / offline tests |
| Stable installer entry point and safe source code refresh | Implemented / syntax checks; no Ubuntu VM install test |
| Atomic live GRE, underlay route and nftables forwarding | **NOT IMPLEMENTED** |
| Bidirectional tc/IFB shaping with per-forward aggregate limits | **NOT IMPLEMENTED** |
| Persistent SQLite metering and 1h/24h accounting | **NOT IMPLEMENTED** |
| Journal + systemd-run rollback + ownership-safe uninstall | **NOT IMPLEMENTED** |
| Live Ubuntu 22.04/24.04 with actual traffic and reboot | **NOT RUN** |
| New dedicated GitHub repository | Blocked: linked GitHub connector cannot create a repository |

Do not install this build as a production replacement. The preview systemd service cannot change networking.
