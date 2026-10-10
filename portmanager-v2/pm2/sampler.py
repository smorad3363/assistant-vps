"""Per-tunnel SQLite v1 accounting with reset-safe monotonic deltas."""
import json
import os
from pathlib import Path
import sqlite3
import time
from . import accounting, config
from .errors import PM2Error

DB = Path(os.environ.get("PM2_DATA", "/var/lib/portmanager2")) / "traffic.sqlite3"
CONFIG = Path(os.environ.get("PM2_ETC", "/etc/portmanager2")) / "config.json"


def connect():
    if DB.is_symlink():
        raise PM2Error("E_CONFLICT", "Refusing symlinked V2 traffic database")
    if not DB.parent.is_dir():
        raise PM2Error("E_DEPENDENCY", "V2 data directory is unavailable")
    prev = os.umask(0o077)
    try:
        db = sqlite3.connect(DB, timeout=5)
    finally:
        os.umask(prev)
    db.execute("PRAGMA journal_mode=WAL")
    db.execute("PRAGMA busy_timeout=5000")
    db.executescript("""
        CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY);
        CREATE TABLE IF NOT EXISTS tunnels (id TEXT PRIMARY KEY, name TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS samples (
          timestamp_utc INTEGER NOT NULL, tunnel_id TEXT NOT NULL,
          protocol TEXT NOT NULL, direction TEXT NOT NULL,
          total_bytes INTEGER NOT NULL, delta_bytes INTEGER NOT NULL,
          counter_epoch INTEGER NOT NULL, interval_seconds REAL NOT NULL,
          PRIMARY KEY(timestamp_utc, tunnel_id, protocol, direction)
        );
        CREATE TABLE IF NOT EXISTS daily_rollups (
          day_utc TEXT NOT NULL, tunnel_id TEXT NOT NULL,
          upload_bytes INTEGER NOT NULL DEFAULT 0,
          download_bytes INTEGER NOT NULL DEFAULT 0,
          PRIMARY KEY(day_utc,tunnel_id)
        );
        CREATE TABLE IF NOT EXISTS events (
          timestamp_utc INTEGER NOT NULL, level TEXT NOT NULL,
          event_code TEXT NOT NULL, message TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS samples_latest (
          tunnel_id TEXT NOT NULL, protocol TEXT NOT NULL,
          direction TEXT NOT NULL, last_time INTEGER NOT NULL,
          total_bytes INTEGER NOT NULL, counter_epoch INTEGER NOT NULL,
          PRIMARY KEY(tunnel_id,protocol,direction)
        );
        INSERT OR IGNORE INTO schema_migrations(version) VALUES(1);
    """)
    return db


def sample(now=None, values=None):
    if os.geteuid():
        raise PM2Error("E_PERMISSION", "Traffic sampling requires root")
    cfg = config.load(CONFIG)
    values = accounting.counters() if values is None else values
    timestamp = int(time.time() if now is None else now)
    db = connect()
    entries = 0
    try:
        with db:
            for t in cfg["tunnels"]:
                db.execute("INSERT OR REPLACE INTO tunnels(id,name) VALUES(?,?)",
                           (t["id"], t["name"]))
            for (tid, proto, direction), total in values.items():
                if total < 0:
                    raise PM2Error("E_VALIDATION", "Negative byte counter")
                row = db.execute(
                    "SELECT last_time,total_bytes,counter_epoch FROM samples_latest "
                    "WHERE tunnel_id=? AND protocol=? AND direction=?",
                    (tid, proto, direction)).fetchone()
                if row is None:
                    delta, epoch, interval = 0, 0, 0.0
                elif total < row[1]:
                    delta, epoch, interval = 0, row[2] + 1, max(0, timestamp-row[0])
                else:
                    delta, epoch, interval = total-row[1], row[2], max(0, timestamp-row[0])
                db.execute(
                    "INSERT OR REPLACE INTO samples VALUES(?,?,?,?,?,?,?,?)",
                    (timestamp, tid, proto, direction, total, delta, epoch, interval))
                db.execute(
                    "INSERT INTO samples_latest VALUES(?,?,?,?,?,?) ON CONFLICT "
                    "(tunnel_id,protocol,direction) DO UPDATE SET last_time=excluded.last_time,"
                    "total_bytes=excluded.total_bytes,counter_epoch=excluded.counter_epoch",
                    (tid, proto, direction, timestamp, total, epoch))
                entries += 1
            # The old V2 per-tunnel sample table also grows without a cap.
            # Retain the same 14-day window as per-port byte accounting.
            db.execute("DELETE FROM samples WHERE timestamp_utc <= ?",
                       (timestamp - 14 * 86400,))
    finally:
        db.close()
    return {"timestamp_utc": timestamp, "samples_written": entries}


def report(window):
    if window not in ("1h", "24h", "7d"):
        raise PM2Error("E_VALIDATION", "Window must be 1h, 24h or 7d")
    seconds = {"1h": 3600, "24h": 86400, "7d": 604800}[window]
    if not DB.is_file():
        return {"window": window, "coverage_seconds": 0,
                "upload_bytes": 0, "download_bytes": 0,
                "upload_mbps": None, "download_mbps": None, "tunnels": []}
    db = connect()
    try:
        cutoff = int(time.time()) - seconds
        rows = db.execute(
            "SELECT tunnel_id,direction,SUM(delta_bytes),SUM(interval_seconds) "
            "FROM samples WHERE timestamp_utc >= ? GROUP BY tunnel_id,direction",
            (cutoff,)).fetchall()
        totals, coverage = {}, 0
        for tid, direction, bytes_total, span in rows:
            t = totals.setdefault(tid, {"id": tid, "upload_bytes": 0,
                                        "download_bytes": 0})
            t["upload_bytes" if direction == "up" else "download_bytes"] += bytes_total
            coverage = max(coverage, min(int(span), seconds))
        combined_up = sum(x["upload_bytes"] for x in totals.values())
        combined_down = sum(x["download_bytes"] for x in totals.values())
        return {
            "window": window, "coverage_seconds": coverage,
            "upload_bytes": combined_up, "download_bytes": combined_down,
            "upload_mbps": (combined_up * 8 / coverage / 1_000_000) if coverage else None,
            "download_mbps": (combined_down * 8 / coverage / 1_000_000) if coverage else None,
            "tunnels": sorted(totals.values(), key=lambda t: t["id"])
        }
    except sqlite3.DatabaseError as exc:
        raise PM2Error("E_APPLY", "Traffic database read failed") from exc
    finally:
        db.close()
