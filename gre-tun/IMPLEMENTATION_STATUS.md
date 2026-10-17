# GRE Tunnel Manager implementation status

Date: 2026-10-17. Contract: 1.0.0. App: 0.2.0-dev.

**NOT production ready.** This environment runs Debian 13 without CAP_NET_ADMIN; it cannot prove real tunnel forwarding, firewall rule syntax on the actual target kernel, tc shaping or reboot recovery.

| Component | Status |
|---|---|
| Peer token, port parsing, menu contracts, atomic config | Offline tested |
| Forward edits and local toggle/delete | Implemented; kernel behavior NOT RUN |
| GRE interface/policy rule/nft renderer | Prototype only, live lab gate required |
| Existing firewall detection | Conservative refusal, not full compatibility |
| SQLite rolling 1h/24h accounting | Offline-tested partial implementation |
| Background stats sampler | Implemented; real counters NOT RUN |
| Current per-forward 2s speed | Not implemented |
| Upload/download HTB/IFB bandwidth caps | Not implemented; nonzero cap refuses apply |
| Crash-safe journal + independently armed rollback | Not implemented |
| Production-safe owned uninstall | Not implemented |
| Automatic boot reconciliation/repair | Not implemented |
| Ubuntu 22.04/24.04 two-host and four-tunnel integration | NOT RUN |
| Stable command, source integrity, app-file refresh | Offline tested; target Ubuntu installation NOT RUN |
| New standalone repository | Github connector cannot create repository; deployed under `smorad3363/assistant-vps/gre-tun` |

Never call this build a functional completed tunnel manager. The installer is non-activating and preserving user data by design.
