"""Bounded, CPU-aware, per-original-port live traffic graph.

One read-only iptables-save -c -t mangle snapshot per refresh. Never discovers
ports on each refresh, never adds firewall rules or changes tc. History persists
for 10 minutes across viewer restarts in the existing V2-owned SQLite DB.
"""
from collections import defaultdict
from contextlib import nullcontext
import json
import math
import os
import shutil
import sqlite3
import sys
import time

from . import accounting, auto_monitor, config, sampler, transaction
from .errors import PM2Error

WINDOW = 600
# A 10-minute history OF the trailing 10-minute moving average needs
# 20 minutes of underlying samples, not just the last 10 minutes.
RETENTION = 86400 + WINDOW + 60
PERIODS = {"10m": 600, "1h": 3600, "8h": 28800, "24h": 86400}
SPARK = "▁▂▃▄▅▆▇█"


def refresh_interval(requested, rule_count, snapshot_cost):
    if not 2 <= requested <= 60:
        raise PM2Error("E_VALIDATION", "Refresh must be between 2 and 60 seconds")
    floor = 10 if rule_count >= 1000 else 5 if rule_count >= 400 else 2
    if snapshot_cost >= 0.75:
        floor = max(floor, math.ceil(snapshot_cost * 5))
    return min(60, max(requested, floor))


def port_labels(tunnels):
    """Ports configured on enabled V2 tunnels, not arbitrary system sockets."""
    labels = {}
    for t in tunnels:
        if not t["enabled"]:
            continue
        ports = ([row["listen_port"] for row in t["mapping"]]
                 if t["mode"] == "ports" else [0])
        for proto in t["protocols"]:
            for port in ports:
                labels[(t["id"], proto, port)] = t["name"]
    return labels


def add_v1_labels(labels, snapshot, tunnel_filter=None):
    """Frozen V1 accounting chain is read only and can share this graph."""
    if tunnel_filter not in (None, "v1"):
        return labels
    for tid, proto, _direction, port in snapshot:
        if tid == "v1" and port is not None:
            labels.setdefault((tid, proto, port), "V1 monitored")
    return labels


def key_from_counter(raw):
    """Normalize (tunnel,proto,direction,original_port|None) counter keys."""
    if len(raw) != 4:
        raise PM2Error("E_VALIDATION", "Expected per-port V2 accounting counters")
    tid, proto, direction, port = raw
    if direction not in ("up", "down") or proto not in ("tcp", "udp", "all"):
        raise PM2Error("E_VALIDATION", "Invalid V2 graph counter key")
    if port is not None and not 1 <= port <= 65535:
        raise PM2Error("E_VALIDATION", "Invalid original port")
    return tid, proto, direction, 0 if port is None else port


def deltas(before, after, elapsed, labels):
    """Reset-safe Mbit/s; first-seen or reset counters yield zero."""
    if elapsed <= 0:
        raise PM2Error("E_VALIDATION", "Elapsed sample interval must be positive")
    rates = {key: {"up": 0.0, "down": 0.0} for key in labels}
    for raw, value in after.items():
        tid, proto, direction, port = key_from_counter(raw)
        key = (tid, proto, port)
        if key not in labels:
            continue
        old = before.get(raw)
        diff = max(0, value - old) if old is not None and value >= old else 0
        rates[key][direction] += diff * 8 / elapsed / 1_000_000
    return rates


def weighted(history, now, window=WINDOW):
    """Time-weighted rolling 10-minute mean, with honest coverage fraction."""
    cutoff = now - window
    used = 0.0
    up = down = 0.0
    for end, duration, u, d in history:
        # A historical moving-average point cannot use a sample that had
        # not completed at that point in time (avoid look-ahead bias).
        if end > now:
            continue
        overlap = end - max(end - duration, cutoff)
        overlap = max(0.0, min(duration, overlap))
        if overlap > 0:
            used += overlap
            up += u * overlap
            down += d * overlap
    if used <= 0:
        return {"up": None, "down": None, "coverage": 0.0}
    return {"up": up / used, "down": down / used,
            "coverage": min(used, window)}


def sparkline(history, now, direction, buckets=24, window=WINDOW):
    """History OF trailing 10-minute averages (not raw bucket rates).

    The previous ten minutes of chart endpoints require up to twenty minutes
    of raw counter intervals to compute each endpoint's honest 600s mean.
    """
    bucket_size = window / buckets
    points = []
    for i in range(buckets):
        end = now - window + (i + 1) * bucket_size
        rolling = weighted(history, end, window)
        points.append(rolling[direction])
    maxval = max((x for x in points if x is not None), default=0)
    return "".join(" " if x is None else
                   SPARK[min(7, int((x / maxval) * 7))] if maxval else SPARK[0]
                   for x in points)


def init_history(db):
    db.execute("""CREATE TABLE IF NOT EXISTS port_live_samples (
        sample_end REAL NOT NULL,
        tunnel_id TEXT NOT NULL,
        protocol TEXT NOT NULL,
        listen_port INTEGER NOT NULL,
        duration_seconds REAL NOT NULL,
        up_mbps REAL NOT NULL,
        down_mbps REAL NOT NULL,
        PRIMARY KEY (sample_end,tunnel_id,protocol,listen_port)
    )""")
    db.execute("CREATE INDEX IF NOT EXISTS idx_pm2_port_live_time ON port_live_samples(sample_end)")
    db.execute("""CREATE TABLE IF NOT EXISTS port_live_minutes (
        bucket_end REAL NOT NULL, tunnel_id TEXT NOT NULL,
        protocol TEXT NOT NULL, listen_port INTEGER NOT NULL,
        duration_seconds REAL NOT NULL, up_mbps REAL NOT NULL,
        down_mbps REAL NOT NULL,
        PRIMARY KEY(bucket_end,tunnel_id,protocol,listen_port)
    )""")
    db.execute("CREATE INDEX IF NOT EXISTS idx_pm2_port_minutes_time ON port_live_minutes(bucket_end)")


def record(db, timestamp, elapsed, rates):
    if elapsed <= 0:
        raise PM2Error("E_VALIDATION", "Invalid live sample duration")
    init_history(db)
    with db:
        for (tid, proto, port), row in rates.items():
            db.execute(
                "INSERT OR REPLACE INTO port_live_samples VALUES(?,?,?,?,?,?,?)",
                (timestamp, tid, proto, port, elapsed, row["up"], row["down"]))
        # Keep exact 5-second resolution for recent 20m. Older complete
        # minutes are compressed to one weighted row so 24h history does not
        # require scanning ~1 million raw records on every 5-second redraw.
        compact_before = (int((timestamp - 1200) // 60)) * 60
        older = db.execute(
            "SELECT CAST(sample_end/60 AS INTEGER)*60+60 AS bucket_end,"
            "tunnel_id,protocol,listen_port,SUM(duration_seconds),"
            "SUM(up_mbps*duration_seconds),SUM(down_mbps*duration_seconds) "
            "FROM port_live_samples WHERE sample_end < ? "
            "GROUP BY bucket_end,tunnel_id,protocol,listen_port",
            (compact_before,)).fetchall()
        for bucket, tid, proto, port, duration, up_total, down_total in older:
            if duration:
                db.execute(
                    "INSERT OR REPLACE INTO port_live_minutes VALUES(?,?,?,?,?,?,?)",
                    (bucket, tid, proto, port, duration,
                     up_total / duration, down_total / duration))
        db.execute("DELETE FROM port_live_samples WHERE sample_end < ?",
                   (compact_before,))
        db.execute("DELETE FROM port_live_minutes WHERE bucket_end < ?",
                   (timestamp - RETENTION - 60,))


def history(db, timestamp, labels):
    """Bounded 24h minutes + exact recent raw samples, no full-day raw scans."""
    init_history(db)
    series = defaultdict(list)
    cutoff = timestamp - RETENTION
    raw = db.execute(
        "SELECT sample_end,tunnel_id,protocol,listen_port,duration_seconds,"
        "up_mbps,down_mbps FROM port_live_samples "
        "WHERE sample_end >= ? AND sample_end <= ? ORDER BY sample_end",
        (cutoff, timestamp))
    for end, tid, proto, port, duration, up, down in raw:
        key = (tid, proto, port)
        if key in labels:
            series[key].append((end, duration, up, down))
    minute_rows = db.execute(
        "SELECT bucket_end,tunnel_id,protocol,listen_port,duration_seconds,"
        "up_mbps,down_mbps FROM port_live_minutes "
        "WHERE bucket_end >= ? AND bucket_end <= ? ORDER BY bucket_end",
        (cutoff, timestamp))
    for end, tid, proto, port, duration, up, down in minute_rows:
        key = (tid, proto, port)
        if key in labels:
            series[key].append((end, duration, up, down))
    for key in series:
        series[key].sort(key=lambda item: item[0])
    return series


def frame(labels, rates, histories, timestamp, top=20, active_only=True):
    """Structured graph data, source of truth for terminal or JSON output."""
    result = []
    for key, name in labels.items():
        data = histories.get(key, [])
        avg = weighted(data, timestamp)
        avgs = {period: weighted(data, timestamp, seconds)
                for period, seconds in PERIODS.items()}
        recent = rates.get(key, {"up": 0.0, "down": 0.0})
        # Active means transferred bytes during the last rolling 10m, not
        # merely an open TCP listener/advertised port.
        moving = any((up > 0 or down > 0) and end > timestamp - WINDOW
                     for end, _, up, down in data)
        if active_only and not moving:
            continue
        tid, proto, port = key
        result.append({
            "tunnel_id": tid, "name": name, "protocol": proto,
            "listen_port": port if port else None,
            "scope": ("v1_monitored_port" if tid == "v1" else
                      "original_port" if port else "all_except_aggregate"),
            "now_up_mbps": recent["up"], "now_down_mbps": recent["down"],
            "avg10m_up_mbps": avg["up"], "avg10m_down_mbps": avg["down"],
            "coverage_seconds": round(avg["coverage"], 2),
            "averages": {
                period: {"up_mbps": stat["up"], "down_mbps": stat["down"],
                         "coverage_seconds": round(stat["coverage"], 2),
                         "requested_seconds": PERIODS[period]}
                for period, stat in avgs.items()
            },
            "graph_up": sparkline(data, timestamp, "up"),
            "graph_down": sparkline(data, timestamp, "down"),
        })
    result.sort(key=lambda x: (-((x["avg10m_up_mbps"] or 0) +
                                      (x["avg10m_down_mbps"] or 0)),
                               -(x["now_up_mbps"] + x["now_down_mbps"]), x["listen_port"] or 0))
    return {"timestamp_utc": timestamp, "window_seconds": WINDOW,
            "rows": result[:top], "active_rows": len(result),
            "refresh_is_read_only": True,
            "all_except_note": "All-except without mapping has aggregate counters only"}


def render(data, requested, effective, rules):
    """Compact colorful V1-style terminal dashboard without extra prompts."""
    interactive = sys.stdout.isatty() and os.environ.get("NO_COLOR") is None
    def c(code, value):
        return f"\x1b[{code}m{value}\x1b[0m" if interactive else str(value)
    width = max(72, min(shutil.get_terminal_size((100, 28)).columns, 116))
    print(c("96;1", "╔" + "═" * (width - 2) + "╗"))
    title = "  PORT MANAGER  •  LIVE PORTS  •  10-MIN TRAFFIC  "
    print(c("96;1", "║" + title.center(width - 2)[:width-2] + "║"))
    print(c("96;1", "╚" + "═" * (width - 2) + "╝"))
    print(f"  {c('92;1', '● LIVE')}  refresh {effective:g}s"
          + (f"  {c('93', '(CPU-safe adjusted)')}" if effective != requested else "")
          + f"  │  {rules} counter rules")
    links = data.get("interfaces", [])
    if links:
        for row in links[:2]:
            print(f"  {c('96', row['interface'][:14]):14}  "
                  f"{c('92', '↑')} {row['tx_mbps']:8.1f} Mb/s   "
                  f"{c('94', '↓')} {row['rx_mbps']:8.1f} Mb/s  "
                  + c("90", "(whole interface)"))
    print(c("90", "  " + "─" * (width - 4)))
    print(c("90", "  Ranked by measured 10m usage | avg10m / 1h / 8h / 24h"))
    if not data["rows"]:
        count = data.get("auto_discovered_ports", 0)
        if count:
            print(c("93", f"  Detected {count} local TCP/UDP ports; "
                         "waiting for attributed IPv4 traffic..."))
        else:
            print(c("93", "  No per-port counters. Interface traffic above is still real."))
            print("  Monitor discovers listening TCP/UDP ports automatically.")
        print(c("90", "  Whole-interface traffic cannot honestly be attributed to a port."))
    else:
        for row in data["rows"]:
            port = str(row["listen_port"]) if row["listen_port"] is not None else "ALL"
            up = row["now_up_mbps"]
            down = row["now_down_mbps"]
            avg_u = row["avg10m_up_mbps"]
            avg_d = row["avg10m_down_mbps"]
            name = (str(row["name"])[:16] + " ") if row["name"] else ""
            print(f"  {c('97;1', row['protocol'].upper() + ':' + port)} "
                  f"{c('90', name)} "
                  f"↑ {c('92;1', f'{up:.1f}')}  ↓ {c('94;1', f'{down:.1f}')} Mb/s"
                  f"  [10m avg ↑ {avg_u:.1f} ↓ {avg_d:.1f}]"
                  if avg_u is not None and avg_d is not None else
                  f"  {c('97;1', row['protocol'].upper() + ':' + port)}  "
                  f"↑ {up:.1f} ↓ {down:.1f} Mb/s (warming up)")
            stats = row.get("averages", {})
            parts = []
            for period in ("10m", "1h", "8h", "24h"):
                item = stats.get(period, {})
                mean = (item.get("up_mbps") or 0) + (item.get("down_mbps") or 0)
                coverage = item.get("coverage_seconds", 0)
                parts.append(f"{period}: {mean:.1f}" if coverage else f"{period}: --")
            print("    " + "  ".join(parts) + " Mb/s")
            print(f"    {c('92', '↑')} {c('92', row['graph_up'])}")
            print(f"    {c('94', '↓')} {c('94', row['graph_down'])}")
    print(c("90", "  " + "─" * (width - 4)))
    print(c("90", "  Graph = 10-minute rolling average  •  Ctrl+C returns to menu"))
    sys.stdout.flush()


def watch(refresh=5, tunnel=None, top=20, active_only=True,
          once=False, json_mode=False, on_frame=None):
    """Auto-detect Xray/Sing-box local TCP/UDP ports if no managed rules exist.

    Reuse existing V2/V1 counters as-is. Only if *none* exist, enable up
    to 24 temporary, counter-only IPv4 rules owned by this viewer. No tc,
    NAT, ACCEPT or DROP action and no V1 state change. Interface rates are
    always measured separately from /proc/net/dev for visibility when no
    port can be attributed.
    """
    if not 2 <= refresh <= 60 or not 1 <= top <= 100:
        raise PM2Error("E_VALIDATION", "Refresh 2..60 seconds, top 1..100")
    if os.geteuid() != 0:
        raise PM2Error("E_PERMISSION", "Reading kernel mangle counters requires root")
    cfg = config.load(transaction.CONFIG)
    labels = port_labels(cfg["tunnels"])
    if tunnel:
        labels = {key: value for key, value in labels.items() if key[0] == tunnel}
    db = sampler.connect()
    try:
        t0 = time.monotonic()
        before = accounting.counters(by_port=True, include_v1=True)
        labels = add_v1_labels(labels, before, tunnel)
        # V2 used to show "0 rules" for a busy Debian/Xray host with no
        # configured tunnel. Explicitly collect local listening ports then.
        # We do not run ss every N seconds or indiscriminately track 65k ports.
        use_auto = not labels and tunnel is None
        monitor = auto_monitor.AutoMonitor() if use_auto else nullcontext()
        try:
            with monitor as session:
                if use_auto:
                    labels.update({("auto", proto, port): "Local service"
                                   for proto, port in session.ports})
                    t0 = time.monotonic()
                    before = accounting.counters(by_port=True, include_v1=True,
                                                 include_probe=True)
                net_before = auto_monitor.interface_counters()
                sample_cost = time.monotonic() - t0
                interval = refresh_interval(refresh, len(before), sample_cost)
                next_reload = time.time() + 30
                while True:
                    try:
                        time.sleep(interval)
                        t1 = time.monotonic()
                        after = accounting.counters(by_port=True, include_v1=True,
                                                    include_probe=use_auto)
                        net_after = auto_monitor.interface_counters()
                        labels = add_v1_labels(labels, after, tunnel)
                        t2 = time.monotonic()
                        elapsed = max(0.001, t2 - t0)
                        effective = refresh_interval(refresh, len(after), t2 - t1)
                        now = time.time()
                        rates = deltas(before, after, elapsed, labels)
                        record(db, now, elapsed, rates)
                        result = frame(labels, rates, history(db, now, labels),
                                       now, top=top, active_only=active_only)
                        result["interfaces"] = auto_monitor.interface_rates(
                            net_before, net_after, elapsed)[:5]
                        result.update({"requested_refresh_seconds": refresh,
                                       "effective_refresh_seconds": interval,
                                       "rule_count": len(after),
                                       "auto_discovered_ports": len(session.ports) if use_auto else 0,
                                       "port_coverage": "selected_ipv4_listening_ports"
                                       if use_auto else "configured_monitor_rules"})
                        if on_frame is not None:
                            on_frame(result)
                        if json_mode:
                            print(json.dumps(result, sort_keys=True), flush=True)
                        else:
                            if sys.stdout.isatty() and not once:
                                print("\x1b[2J\x1b[H", end="")
                            render(result, refresh, interval, len(after))
                        if once:
                            return 0
                        before, net_before, t0, interval = after, net_after, t2, effective
                        if not use_auto and now >= next_reload:
                            cfg = config.load(transaction.CONFIG)
                            labels = port_labels(cfg["tunnels"])
                            if tunnel:
                                labels = {key: v for key, v in labels.items()
                                          if key[0] == tunnel}
                            labels = add_v1_labels(labels, after, tunnel)
                            next_reload = now + 30
                    except KeyboardInterrupt:
                        print("\nLive monitor stopped; owned temporary counters cleaned.")
                        return 130
        except BlockingIOError as exc:
            raise PM2Error("E_LOCKED", "Another live monitor is already running") from exc
    finally:
        db.close()
