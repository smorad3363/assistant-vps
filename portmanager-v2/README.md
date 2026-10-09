# oort Manager V2 — Tunnel Edition (`2.1.0-rc.5`)

oort Manager V2 has its own binary (`portmanager2`), configuration, firewall
chains, SQLite accounting database and optional services. It does not alter
the original V1 executable or compressed V1 payload.

## One shared installer URL (after merging this branch)

**Default V2:**

```bash
curl -fsSL https://raw.githubusercontent.com/smorad3363/assistant-vps/master/portmanager-dashboard/install.sh | sudo bash
```

**Explicit V1:**

```bash
curl -fsSL https://raw.githubusercontent.com/smorad3363/assistant-vps/master/portmanager-dashboard/install.sh | sudo bash -s -- v1
```

`sudo bash v1` is not valid for piped script arguments. Use `-s -- v1`.
See [version router guide](docs/RELEASE-ROUTER.fa.md).

## Small live-screen and existing-rules fix (2.1.0-rc.5)

- Reference-style live terminal: separate download/upload cards with
  current Mbps, peak, sampled average and session total; a clean per-port
  10m/1h/8h/24h table and small footer.
- A clearly labelled **OTHER / UNKNOWN ~** row estimates directional
  interface bytes not accounted for by displayed port rules. This is
  **not an exact per-port attribution**: NAT, bridges and overlapping
  counters can make interface and port totals incomparable.
- The edit/delete menu shows **already existing NAT rules**, including
  unmanaged/legacy ones, read-only. V2-only managed tunnel rules can be
  changed; unknown Docker/UFW/external rules are never deleted by the menu.
- The same cyan-bordered compact menu cards are used for Home, IPtables
  and Configuration.

## Included features

- **Fixed-screen live terminal dashboard (curses):** single-screen real-time redraw on Debian/Ubuntu without spilling each interval into SSH scrollback. Default shows busiest active ports only, terminal-height bounded, with 10m/1h/8h/24h averages. Keys: `q` or `Esc` to choose a port, `a` show idle ports, `+/-` refresh seconds, arrows to scroll. JSON/once modes stay plain text.
- **Simple V1-inspired menu:** only [1] Live & speed limits, [2] IPTABLES & tunnels,
  [3] Edit/remove configurations. No IDs or iptables syntax required.
- **No more false “0 traffic” assumption:** autodetect TCP/UDP IPv4 local sockets
  with bounded, owned, temporary mangle counters when V2/V1 lack per-port
  accounting; always show real aggregate interface traffic separately.
- 10m / 1h / 8h / 24h time-weighted per-port averages, sorted from highest
  observed 10-minute utilization. History is retained for up to 24 hours **of
  actual collected samples**, not fabricated while viewer is closed.
- Select a displayed port after Ctrl+C to apply/edit/remove an always-on or
  hourly timed limit; choose ALL for a **single aggregate IPv4 limit** over
  an explicitly shown interface (including SSH). No global iptables flush.


- TCP/UDP IPv4 NAT tunnels, individual port forwarding or all-except mode.
- Protected all-except/management binding changes with timed rollback and
  explicit confirmation identifier; no blanket firewall flush.
- Live per-port 10-minute time-weighted moving-average sparklines, read-only
  V1 and V2 accounting, selectable refresh 2–60 seconds and CPU-aware backoff.
- SQLite 1h/24h/7d reporting, root-only backups, CLI and text menu.
- **V2-only timed port limits:** `tc clsact` flower policing for a tunnel's
  inbound upload and outbound download using IANA timezone, week days and
  HH:MM start/end. A minute systemd timer reconciles desired limits.
- All tc shaping operations are isolated to V2-owned clsact. If V1 or a
  foreign clsact is present, V2 rejects the limiter with `E_CONFLICT`.
  A limiter here is drop/policing, not HTB queued shaping.
- V2 installer checks SHA256 manifest, pins a commit and maintains release
  ownership markers. V1 remains separately installed and executable.

### Terminal monitor

```bash
sudo portmanager2
sudo portmanager2 graph --refresh 5 --window 10m
sudo portmanager2 graph --refresh 10 --all-ports
sudo portmanager2 report --window 24h --json
```

### Time-based bandwidth limits

Choose option 05 in `sudo portmanager2` for a validated schedule wizard.
Or use the [JSON example](examples/scheduled-limits.example.json):

```bash
sudo portmanager2 limits schedule-preview --file /path/to/schedules.json --json
sudo portmanager2 limits schedule-install --file /path/to/schedules.json --json
sudo portmanager2 limits schedule-list
sudo portmanager2 limits schedule-apply
```

Scheduling requires an enabled V2 `ports` tunnel and **no V1 installation**.
The schedule-install command activates V2's own sample timer. Policing may
drop excess packets, so test on a disposable VPS before production. Deleting
V2 removes only its recorded clsact filters after ownership preflight.

## Release status

This is a **release candidate**, not a production guarantee. Automated CI
tests exercise Debian 12 userspace, Ubuntu networking with isolated
namespaces, firewall rollback and tc filters; a complete guest reboot
with real SSH loss, custom Docker rules and production performance must still
be qualified by an operator with snapshot and alternate console.

[Detailed specification](docs/PM2-SPEC-001.fa.md) ·
[Time-window rate limits](docs/ADR-0003-SCHEDULED-LIMITS.md) ·
[Graph guide](docs/LIVE-PORT-GRAPH-FA.md) ·
[Operator test guide](docs/OPERATOR-TEST-FA.md) ·
[Progress checkpoint](docs/PROGRESS.md).
