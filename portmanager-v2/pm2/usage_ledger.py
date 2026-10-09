"""Durable per-port byte ledger and conservative time-window usage reports.

A successful sample stores *integer counter deltas*, not averaged Mbps.
When a requested endpoint cuts through a sample, its bytes are POSSIBLE,
not known: precise intra-interval timestamps do not exist. No invented
backfill and no cross-port provider billing claim.
"""
from collections import defaultdict
from datetime import datetime, timezone
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError
import re
import sqlite3
from .errors import PM2Error
from . import sampler


def init(db):
    db.execute("""CREATE TABLE IF NOT EXISTS pm2_port_byte_intervals (
      start_utc REAL NOT NULL, end_utc REAL NOT NULL,
      tunnel_id TEXT NOT NULL, protocol TEXT NOT NULL,
      listen_port INTEGER NOT NULL,
      upload_bytes INTEGER NOT NULL, download_bytes INTEGER NOT NULL,
      PRIMARY KEY(end_utc, tunnel_id, protocol, listen_port)
    )""")
    db.execute("""CREATE INDEX IF NOT EXISTS idx_pm2_byte_report
      ON pm2_port_byte_intervals(start_utc, end_utc, protocol, listen_port)""")
    db.execute("""CREATE TABLE IF NOT EXISTS pm2_port_byte_boot (
      id INTEGER PRIMARY KEY CHECK(id=1), boot_id TEXT NOT NULL
    )""")


def boot_id():
    try:
        from pathlib import Path
        value = Path("/proc/sys/kernel/random/boot_id").read_text(
            encoding="ascii").strip()
    except OSError:
        return None
    return value if re.fullmatch(r"[0-9a-f-]{36}", value) else None


def baseline_matches(db, current_boot):
    if current_boot is None:
        return False
    row = db.execute("SELECT boot_id FROM pm2_port_byte_boot WHERE id=1").fetchone()
    return bool(row and row[0] == current_boot)


def remember_boot(db, current_boot):
    if current_boot is None:
        db.execute("DELETE FROM pm2_port_byte_boot")
    else:
        db.execute("INSERT OR REPLACE INTO pm2_port_byte_boot VALUES(1,?)",
                   (current_boot,))


def record(db, intervals):
    """Called inside collector's transaction. Intervals are prevalidated."""
    init(db)
    for start, end, tid, proto, port, up, down in intervals:
        if (not 0 <= start < end or not 0 <= up or not 0 <= down or
                not 0 <= port <= 65535 or proto not in ("tcp", "udp", "all")):
            raise PM2Error("E_VALIDATION", "Invalid byte-ledger interval")
        db.execute("""INSERT OR IGNORE INTO pm2_port_byte_intervals
          (start_utc,end_utc,tunnel_id,protocol,listen_port,upload_bytes,download_bytes)
          VALUES (?,?,?,?,?,?,?)""", (start, end, tid, proto, port, up, down))


def parse_datetime(value, tz_name):
    """Explicit timezone prevents silent server-UTC versus Tehran mistakes."""
    try:
        zone = ZoneInfo(tz_name)
        parsed = datetime.strptime(value, "%Y-%m-%d %H:%M")
        local = parsed.replace(tzinfo=zone)
        utc = local.astimezone(timezone.utc)
        # Reject nonexistent local time, e.g. daylight-saving forward gap.
        if utc.astimezone(zone).replace(tzinfo=None) != parsed:
            raise ValueError("Nonexistent local time")
        return utc.timestamp()
    except (ValueError, ZoneInfoNotFoundError, KeyError) as exc:
        raise PM2Error("E_VALIDATION",
                       "Use YYYY-MM-DD HH:MM and a valid IANA timezone",
                       {"time": value, "timezone": tz_name}) from exc


def _rank(source):
    return 0 if source not in ("auto", "v1") else 1 if source == "v1" else 2


def _union_seconds(ranges):
    if not ranges:
        return 0.0
    ordered = sorted(ranges)
    left, right = ordered[0]
    total = 0.0
    for a, b in ordered[1:]:
        if a > right:
            total += right - left
            left, right = a, b
        else:
            right = max(right, b)
    return total + right - left


def summarize(intervals, start, end):
    """Return LOWER/UPPER bounds, never bill partial samples as exact bytes.

    Same timestamp/port from V2, V1 or auto are alternative measurements
    of potentially identical traffic, not independent billable usage.
    Prefer V2, then V1, then auto for exactly coincident sample windows.
    """
    picked = {}
    overlap_sources = set()
    for a, b, source, proto, port, up, down in intervals:
        if proto not in ("tcp", "udp") or port <= 0:
            continue   # all-except aggregates cannot be assigned to a port
        if not (a < b and b > start and a < end):
            continue
        key = (a, b, proto, port)
        candidate = (source, int(up), int(down))
        if key in picked:
            overlap_sources.add((proto, port))
            if _rank(source) < _rank(picked[key][0]):
                picked[key] = candidate
        else:
            picked[key] = candidate

    grouped = defaultdict(list)
    for (a, b, proto, port), (source, up, down) in picked.items():
        grouped[(proto, port)].append((a, b, source, up, down))
    results = []
    for (proto, port), records in grouped.items():
        low_up = low_down = extra_up = extra_down = 0
        windows = []
        sources = set()
        for a, b, source, up, down in records:
            windows.append((max(start, a), min(end, b)))
            sources.add(source)
            if start <= a and b <= end:
                low_up += up
                low_down += down
            else:
                extra_up += up
                extra_down += down
        covered = _union_seconds(windows)
        results.append({
            "protocol": proto, "port": port, "sources": sorted(sources),
            "upload_bytes_lower": low_up, "download_bytes_lower": low_down,
            "upload_bytes_upper": low_up + extra_up,
            "download_bytes_upper": low_down + extra_down,
            "total_bytes_lower": low_up + low_down,
            "total_bytes_upper": low_up + low_down + extra_up + extra_down,
            "boundary_uncertain_bytes": extra_up + extra_down,
            "covered_seconds": round(min(covered, end - start), 2),
            "missing_seconds": round(max(0, end - start - covered), 2),
            "overlapping_sources": (proto, port) in overlap_sources or len(sources) > 1
        })
    results.sort(key=lambda x: (-x["total_bytes_lower"], x["port"], x["protocol"]))
    return results


def report(from_time, to_time, tz_name="UTC", port=None, protocol=None):
    start, end = parse_datetime(from_time, tz_name), parse_datetime(to_time, tz_name)
    if end <= start or end - start > 366 * 86400:
        raise PM2Error("E_VALIDATION", "End must be after start; maximum range is 366 days")
    if port is not None and (type(port) is not int or not 1 <= port <= 65535):
        raise PM2Error("E_VALIDATION", "Port must be 1..65535")
    if protocol not in (None, "tcp", "udp"):
        raise PM2Error("E_VALIDATION", "Protocol must be tcp or udp")
    db = sampler.connect()
    try:
        init(db)
        sql = ("""SELECT start_utc,end_utc,tunnel_id,protocol,listen_port,
                         upload_bytes,download_bytes
                  FROM pm2_port_byte_intervals
                  WHERE end_utc > ? AND start_utc < ?""")
        values = [start, end]
        if port is not None:
            sql += " AND listen_port=?"
            values.append(port)
        if protocol is not None:
            sql += " AND protocol=?"
            values.append(protocol)
        rows = db.execute(sql, values).fetchall()
        grouped = summarize(rows, start, end)
        note = [
            "IPv4 monitored ports only; IPv6, unmatched ports and traffic of other networks may be absent.",
            "Counters are per original TCP/UDP port; NAT/bridges and overlapping sources may double-count across ports.",
            "Intervals crossing requested endpoints have unknown intra-minute distribution; lower/upper bounds are shown.",
            "A missing interval is NOT zero traffic. This is not a provider billing reconciliation.",
            "Only data sampled after this byte ledger was enabled are available; older Mbps graphs are not billing data.",
            "At most 24 auto-detected ports are continuously tracked, plus separate managed counters."
        ]
        if any(x["missing_seconds"] > 1 or x["boundary_uncertain_bytes"] > 0
               or x["overlapping_sources"] for x in grouped):
            note.insert(0, "CAUTION: incomplete coverage, boundary uncertainty, or overlapping counters")
        if not rows:
            note.insert(0, "No recorded byte intervals for this period. Never interpret as zero usage.")
        return {
            "from": from_time, "to": to_time, "timezone": tz_name,
            "interval_seconds": end - start, "ports": grouped,
            "all_port_sum_bytes_lower": sum(x["total_bytes_lower"] for x in grouped),
            "all_port_sum_bytes_upper": sum(x["total_bytes_upper"] for x in grouped),
            "intervals_read": len(rows), "warnings": note,
            "not_provider_billable": True,
        }
    except sqlite3.DatabaseError as exc:
        raise PM2Error("E_APPLY", "Cannot read per-port traffic ledger") from exc
    finally:
        db.close()


def format_bytes(amount):
    return f"{amount / (1024 ** 3):.4f} GiB ({amount / 1e9:.4f} GB)"


def pretty(result):
    from datetime import timedelta
    lines = [
        f'PER-PORT USAGE  {result["from"]} → {result["to"]}  ({result["timezone"]})',
        "Measured integer bytes | complete intervals LOWER bound | includes boundary UPPER bound",
        "PORT          ↓ Download lower .. upper        ↑ Upload lower .. upper    Missing"
    ]
    for item in result["ports"]:
        lines.append(
            f'{item["protocol"].upper()}:{item["port"]:<6} '
            f'{item["download_bytes_lower"]/1e9:8.4f} .. {item["download_bytes_upper"]/1e9:8.4f} GB   '
            f'{item["upload_bytes_lower"]/1e9:8.4f} .. {item["upload_bytes_upper"]/1e9:8.4f} GB   '
            f'{item["missing_seconds"]/60:.0f} min'
        )
    if not result["ports"]:
        lines.append("No recorded per-port intervals in this time window.")
    lines.extend(["", "Lower = complete samples; Upper includes unknown portions of boundary samples.",
                  "Missing = no measured coverage. This is not the provider's billed total.",
                  "Do not add NIC/interface sums to port totals."])
    return "\n".join(lines)
