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

# Keep only the latest two weeks of measured consumption records.
RETENTION_DAYS = 14
RETENTION_SECONDS = RETENTION_DAYS * 86400


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


def prune(db, now):
    """Remove expired consumption intervals; called on each minute tick.

    Use the END of the interval as the retention key so an interval never
    becomes partially represented by accidental truncation of its bytes.
    Deleted SQLite pages are reused; db size stabilizes instead of growing
    without a time limit. Database snapshots/backups are separate.
    """
    init(db)
    cutoff = float(now) - RETENTION_SECONDS
    cursor = db.execute(
        "DELETE FROM pm2_port_byte_intervals WHERE end_utc <= ?", (cutoff,))
    return cursor.rowcount


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
    candidates = defaultdict(list)
    for a, b, source, proto, port, up, down in intervals:
        if proto not in ("tcp", "udp", "all") or port <= 0:
            continue
        if a < b and b > start and a < end:
            candidates[(proto, port)].append((a, b, source, int(up), int(down)))

    grouped = {}
    overlap_sources = set()
    # Different chains can count the same forwarded bytes. Prefer one
    # authoritative source per overlapped timespan, even if their sample
    # boundaries differ by a fraction of a second. We conservatively
    # exclude the second whole interval rather than sum duplicate bytes.
    for key, rows in candidates.items():
        chosen = []
        for row in sorted(rows, key=lambda x: (_rank(x[2]), x[0], x[1])):
            if any(row[0] < accepted[1] and accepted[0] < row[1]
                   for accepted in chosen):
                overlap_sources.add(key)
                continue
            chosen.append(row)
        grouped[key] = sorted(chosen)
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
        bounds = db.execute(
            "SELECT MIN(start_utc), MAX(end_utc) FROM pm2_port_byte_intervals"
        ).fetchone()
        ledger_first, ledger_last = bounds if bounds else (None, None)
        # The previous counter baseline is retained independently. It is
        # diagnostic only: first baseline does not imply measured bytes.
        baseline = db.execute(
            "SELECT MAX(sampled_at) FROM pm2_history_health"
        ).fetchone() if db.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='pm2_history_health'"
        ).fetchone() else None
        grouped = summarize(rows, start, end)
        note = [
            "IPv4 monitored ports only; IPv6, unmatched ports and traffic of other networks may be absent.",
            "Counters are per original TCP/UDP port (or legacy combined-protocol counter). NAT/bridges can overlap; no combined billable total is asserted.",
            "Intervals crossing requested endpoints have unknown intra-minute distribution; lower/upper bounds are shown.",
            "A missing interval is NOT zero traffic. This is not a provider billing reconciliation.",
            "Only data sampled after this byte ledger was enabled are available; older Mbps graphs are not billing data.",
            "Raw per-port byte records older than 14 days are deleted automatically on the next successful sample.",
            "Up to 64 autodetected or forwarded ports are tracked, plus managed ports; other ports may be absent."
        ]
        if any(x["missing_seconds"] > 1 or x["boundary_uncertain_bytes"] > 0
               or x["overlapping_sources"] for x in grouped):
            note.insert(0, "CAUTION: incomplete coverage, boundary uncertainty, or overlapping counters")
        if not rows:
            note.insert(0, "No recorded byte intervals for this period. Never interpret as zero usage.")
            if ledger_first is not None:
                note.insert(1, "Recorded data exists outside the requested range; choose a time within the available history.")
            elif baseline and baseline[0] is not None:
                note.insert(1, "Sampler has a baseline but no complete interval stored. Wait for another successful timer run.")
            else:
                note.insert(1, "No background sampler baseline is recorded; check portmanager2-sample.timer/service.")
        return {
            "from": from_time, "to": to_time, "timezone": tz_name,
            "interval_seconds": end - start, "ports": grouped,
            "intervals_read": len(rows),
            "retention_days": RETENTION_DAYS,
            "first_recorded_utc": ledger_first,
            "latest_recorded_utc": ledger_last,
            "last_sampler_baseline_utc": baseline[0] if baseline else None,
            "warnings": note,
            "not_provider_billable": True,
        }
    except sqlite3.DatabaseError as exc:
        raise PM2Error("E_APPLY", "Cannot read per-port traffic ledger") from exc
    finally:
        db.close()


def format_bytes(amount):
    return f"{amount / (1024 ** 3):.4f} GiB ({amount / 1e9:.4f} GB)"


def to_csv(result):
    """Spreadsheet-compatible read-only export; one row per measured port."""
    import csv
    from io import StringIO
    out = StringIO(newline="")
    writer = csv.writer(out)
    writer.writerow(["from", "to", "timezone", "protocol", "port",
                     "download_bytes_lower", "download_bytes_upper",
                     "upload_bytes_lower", "upload_bytes_upper",
                     "missing_seconds", "boundary_uncertain_bytes",
                     "overlapping_sources", "not_provider_billable"])
    for row in result["ports"]:
        writer.writerow([
            result["from"], result["to"], result["timezone"],
            row["protocol"], row["port"],
            row["download_bytes_lower"], row["download_bytes_upper"],
            row["upload_bytes_lower"], row["upload_bytes_upper"],
            row["missing_seconds"], row["boundary_uncertain_bytes"],
            row["overlapping_sources"], True
        ])
    return out.getvalue()


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
