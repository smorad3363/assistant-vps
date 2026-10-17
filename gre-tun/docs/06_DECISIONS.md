# Frozen decisions and scope protection

| Decision | Frozen value / rationale |
|---|---|
| Deployment | Fresh install on both endpoints; no migration or legacy takeover |
| CLI | gre-tun; exactly four top-level actions and Exit |
| Implementation | Python standard library core + small Bash install/launcher |
| Network backend | Native nftables + iproute2; one implementation path |
| Statistics | SQLite, 60-second persisted intervals, 1h/24h rolling windows |
| Current speed | Two monotonic counter observations, about two seconds apart |
| Caps | Per logical forward and direction; aggregate clients; shared Both |
| Limits UI | Separate upload/download integers, 0=Unlimited |
| Forward input | PORT or LISTEN:TARGET; comma batches; no target-port prompt |
| Local public addresses | Explicit exact IP, eligible on the tunnel's selected WAN |
| Roles | Iran/Foreign label only; no asymmetric feature restrictions |
| Remote setup | Bounded GT1 data token; manual copy/paste, no SSH credential collection |
| Address conflict | Deterministic candidates, machine-generated retry response |
| Accounted traffic | Logical L3 forwarding counters, not NAT counters or provider bill |
| Existing connections | Only affected identity flushed for mapping edits/removal |
| Existing network tools | Read-only conflict checks; never blanket disable/delete |
| Watchdog | Structural reconciliation, no ping-triggered reset loop |
| Tests | Bounded by default; real load tests only in isolated build lab |
| Source addresses | Synthetic examples only; never copied from the old chat |
| Uninstall | One keep-data question; local owned resources only |
| Reproducibility | Frozen behavior/text/contracts; immutable release for identical code |

No product behavior can be replaced by the old script merely because a function already exists there. Do not introduce special treatment for ports 6111/51820 or any real IP. Do not add dashboards, automatic failover, Telegram, a web API, extra main-menu items, or a user-facing settings labyrinth.

For unresolved low-level implementation details, preserve the contract, use the target platforms' native tools, document the selected method, and prove it in integration tests. If a defined architecture cannot meet a safety or correctness invariant, report the exact conflict and a minimal proposed revision instead of silently switching backends. This does not authorize leaving ordinary implementation work unfinished.
