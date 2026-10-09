"""Bounded, CPU-aware, per-original-port live traffic graph.

One read-only iptables-save -c -t mangle snapshot per refresh. Never discovers
ports on each refresh, never adds firewall rules or changes tc. History persists
for 10 minutes across viewer restarts in the existing V2-owned SQLite DB.
"""
from collections import defaultdict
import json
import math
import os
import shutil
import sqlite3
import sys
import time

from . import accounting, config, sampler, transaction
from .errors import PM2Error

WINDOW = 600
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


def key_from_counter(raw):
    """Normalize (tunnel,proto,direction,original_port|None) counter keys."""
    if len(raw) != 4:
        raise PM2Error("E_VALIDATION", "Expected per-port V2 accounting counters")
    tid, proto, direction, port = raw
    if direction not in ("up", "down") or proto not in ("tcp", "udp"):
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
        overlap = min(end, now) - max(end - duration, cutoff)
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
    """Draw trailing 10 minutes of sampled throughput, gaps remain blank."""
    bucket_size = window / buckets
    points = []
    for i in range(buckets):
        start = now - window + i * bucket_size
        end = start + bucket_size
        num = den = 0.0
        for stamp, duration, up, down in history:
            overlap = max(0.0, min(stamp, end) - max(stamp - duration, start))
            if overlap > 0:
                num += (up if direction == "up" else down) * overlap
                den += overlap
        points.append(num / den if den else None)
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


def record(db, timestamp, elapsed, rates):
    if elapsed <= 0:
        raise PM2Error("E_VALIDATION", "Invalid live sample duration")
    init_history(db)
    with db:
        for (tid, proto, port), row in rates.items():
            db.execute(
                "INSERT OR REPLACE INTO port_live_samples VALUES(?,?,?,?,?,?,?)",
                (timestamp, tid, proto, port, elapsed, row["up"], row["down"]))
        # Bounded history: only trailing 10 minutes, retain records overlapping
        # a bucket at the cutoff, and do not accumulate forever.
        db.execute("DELETE FROM port_live_samples WHERE sample_end < ?",
                   (timestamp - WINDOW - 60,))


def history(db, timestamp, labels):
    init_history(db)
    series = defaultdict(list)
    for end, tid, proto, port, duration, up, down in db.execute(
        "SELECT sample_end,tunnel_id,protocol,listen_port,duration_seconds,"
        "up_mbps,down_mbps FROM port_live_samples "
        "WHERE sample_end >= ? AND sample_end <= ? ORDER BY sample_end",
        (timestamp - WINDOW, timestamp)):
        key = (tid, proto, port)
        if key in labels:
            series[key].append((end, duration, up, down))
    return series


def frame(labels, rates, histories, timestamp, top=20, active_only=True):
    """Structured graph data, source of truth for terminal or JSON output."""
    result = []
    for key, name in labels.items():
        data = histories.get(key, [])
        avg = weighted(data, timestamp)
        recent = rates.get(key, {"up": 0.0, "down": 0.0})
        # Active means transferred bytes during the last rolling 10m, not
        # merely an open TCP listener/advertised port.
        moving = any(up > 0 or down > 0 for _, _, up, down in data)
        if active_only and not moving:
            continue
        tid, proto, port = key
        result.append({
            "tunnel_id": tid, "name": name, "protocol": proto,
            "listen_port": port if port else None,
            "scope": "original_port" if port else "all_except_aggregate",
            "now_up_mbps": recent["up"], "now_down_mbps": recent["down"],
            "avg10m_up_mbps": avg["up"], "avg10m_down_mbps": avg["down"],
            "coverage_seconds": round(avg["coverage"], 2),
            "graph_up": sparkline(data, timestamp, "up"),
            "graph_down": sparkline(data, timestamp, "down"),
        })
    result.sort(key=lambda x: -(x["now_up_mbps"] + x["now_down_mbps"]))
    return {"timestamp_utc": timestamp, "window_seconds": WINDOW,
            "rows": result[:top], "active_rows": len(result),
            "refresh_is_read_only": True,
            "all_except_note": "All-except without mapping has aggregate counters only"}


def render(data, requested, effective, rules):
    width = max(65, min(shutil.get_terminal_size((90, 28)).columns, 140))
    print(f"PORT MANAGER 2 | LIVE PORTS | 10m rolling graph | "
          f"refresh {effective:g}s (requested {requested:g}s) | {rules} rules")
    print("Last 10 minutes: left=oldest, right=latest; "
          "UP=outbound, DOWN=inbound; units Mbit/s")
    if not data["rows"]:
        print("No port traffic yet. Use --all-ports to show idle configured ports.")
    for row in data["rows"]:
        port = str(row["listen_port"]) if row["listen_port"] is not None else "ALL*"
        avgup = "-" if row["avg10m_up_mbps"] is None else f"{row['avg10m_up_mbps']:.3f}"
        avgdown = "-" if row["avg10m_down_mbps"] is None else f"{row['avg10m_down_mbps']:.3f}"
        print(f"\n{row['name'][:18]:18} {row['protocol']:3} :{port:<5} "
              f"NOW U:{row['now_up_mbps']:.2f} D:{row['now_down_mbps']:.2f} "
              f"AVG10m U:{avgup} D:{avgdown} "
              f"[coverage {row['coverage_seconds']:.0f}/600s]")
        print(f"  U {row['graph_up']}\n  D {row['graph_down']}")
    if any(x["listen_port"] is None for x in data["rows"]):
        print("* All-except counts are aggregate, not individual destination ports.")


def watch(refresh=5, tunnel=None, top=20, active_only=True,
          once=False, json_mode=False):
    """One reader; CPU-adaptive refresh, bounded SQLite history and no mutations."""
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
        before = accounting.counters(by_port=True)
        cost = time.monotonic() - t0
        interval = refresh_interval(refresh, len(before), cost)
        while True:
            try:
                time.sleep(interval)
                t1 = time.monotonic()
                after = accounting.counters(by_port=True)
                t2 = time.monotonic()
                elapsed = max(0.001, t2 - t0)
                effective = refresh_interval(refresh, len(after), t2 - t1)
                now = time.time()
                # Use actual monotonic elapsed rather than assuming requested
                # interval is the effective elapsed time.
                rates = deltas(before, after, elapsed, labels)
                record(db, now, elapsed, rates)
                result = frame(labels, rates, history(db, now, labels),
                               now, top=top, active_only=active_only)
                result.update({"requested_refresh_seconds": refresh,
                               "effective_refresh_seconds": interval,
                               "rule_count": len(after)})
                if json_mode:
                    print(json.dumps(result, sort_keys=True), flush=True)
                else:
                    if sys.stdout.isatty() and not once:
                        print("\x1b[2J\x1b[H", end="")
                    render(result, refresh, interval, len(after))
                if once:
                    return 0
                before, t0, interval = after, t2, effective
                # A tunnel may be added/removed while viewing. Refresh the
                # tiny JSON config at most once per 30 seconds.
                if "next_reload" not in locals() or now >= next_reload:
                    cfg = config.load(transaction.CONFIG)
                    labels = port_labels(cfg["tunnels"])
                    if tunnel:
                        labels = {key: v for key, v in labels.items()
                                  if key[0] == tunnel}
                    next_reload = now + 30
            except KeyboardInterrupt:
                print("\nGraph stopped. No firewall/tc changes.")
                return 130
    finally:
        db.close()
