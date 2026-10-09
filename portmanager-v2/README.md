# Port Manager V2 — Tunnel Edition (`2.0.0-dev.1`)

**Development / pre-release. Not yet approved for production.**
V2 is a separate IPv4 NAT port-forwarding tool, **not an encrypted VPN**.
No source files under `portmanager-dashboard/**` (stable V1) are changed.

## Version separation (after PR acceptance)

| Installer | Destination | Role |
| --- | --- | --- |
| `master/portmanager-dashboard/install.sh` | V1 / `portmanager` | **Original URL stays unchanged** |
| `master/portmanager-v1/install.sh` | V1 / `portmanager` | New alias to original V1 |
| `master/portmanager-v2/install.sh` | V2 / `portmanager2` | Separate V2; valid **only once PR merges** |

The current V2 code is available **only on** the protected-in-review
`feat/portmanager-v2-roadmap` development branch. Do not try the V2 master URL
before release. Full instructions to clone a pinned commit, test and uninstall
on a disposable VM: [راهنمای آزمون فارسی](docs/OPERATOR-TEST-FA.md).

## Implemented in the development branch

- Strict IPv4 tunnel CRUD, TCP/UDP individual port mappings, and `all-except`
  with explicit acknowledgment, existing-listener inspection and reserved SSH
  fallback port 22.
- V2-only `PM2_*` NAT, filter, mangle and accounting chains (no global flush);
  conntrack scoped SNAT and bidirectional forwarding.
- Full read-only previews, SHA256 file ownership, safety checks for V1 and
  foreign rules, undo journal and rollback on recognized failures.
- Dangerous binding/all-except changes: prearmed 120-second `systemd-run`
  rollback and a unique confirmation ID. A failed/unknown rollback preserves
  recovery evidence instead of pretending success.
- SQLite sampling, upload/download reports for 1h/24h/7d, live rates,
  separate JSON audit log, config backups, and a text-based tunnel manager.
- Optional `systemd` V2-only restore + minute sampler services. **They are
  disabled by default** and require explicit installer opt-in. No V1 cron
  installation and no V1 `tc` changes.
- V2-only IPv4 `sysctl.d` forwarding drop-in; uninstall never turns off a
  possibly shared live `net.ipv4.ip_forward`.
- Shaping and quotas are intentionally out of scope for V2 2.0; planned for
  2.1 and must not overwrite any existing `tc` qdisc.
- A **read-only scheduled-limit preview** is implemented in
  `pm2/limit_windows.py`, including weekdays, IANA timezone, overnight
  windows, overlap rejection and DST handling. **It does not actually throttle
  traffic in 2.0**. 2.1 enforcement must prove exclusive qdisc ownership.
  See [scheduled-limit ADR](docs/ADR-0003-SCHEDULED-LIMITS.md).

## Useful CLI (after installing on a disposable VM)

```bash
portmanager2                        # text menu on a TTY
portmanager2 help
portmanager2 doctor --json
portmanager2 tunnel list --json
portmanager2 tunnel create --dry-run --name test --listen-ip 192.0.2.11 --interface eth0 --protocol tcp --mode ports --mapping 443:8443 --target-ip 198.51.100.10
portmanager2 tunnel check --json
portmanager2 report --window 1h --json
portmanager2 backup list
portmanager2 limits list --json     # enforcement unavailable/2.1
portmanager2 limits schedule-preview --file examples/scheduled-limits.example.json --at 2026-10-12T20:00:00Z --json  # read-only
sudo portmanager2 uninstall --dry-run
sudo portmanager2 uninstall --yes   # retains V2 config/data
```

Current evidence: [GitHub Actions run 37960307468](https://github.com/smorad3363/assistant-vps/actions/runs/37960307468)
passed static/unit (48 tests per Python), real V1/V2 coexistence, networkns
TCP+UDP round trip, guard rollback and 120s timer, and activated systemd on
fresh GitHub Ubuntu VMs. **A full guest reboot, real multi-host reliability,
IPv6 behavior, legacy iptables and user acceptance are still not certified.**

V1 users seeing CPU spikes after `portmanager live 1` can consult the
[read-only V1 profiler and lower-overhead viewer](../portmanager-v1/perf/README.fa.md).
V1's original installer and executable remain frozen.

See [PM2-SPEC-001](docs/PM2-SPEC-001.fa.md),
[progress checkpoint](docs/PROGRESS.md),
[test matrix](docs/TEST-MATRIX.md), [CLI contract](docs/CLI.md) and
[operator test guide](docs/OPERATOR-TEST-FA.md). PR must remain draft until
all release gates pass.
