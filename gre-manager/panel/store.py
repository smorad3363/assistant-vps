"""Atomic profiles, bounded SQLite telemetry, sessions, and portable backups."""
import contextlib
import copy
import errno
import fcntl
import hashlib
import hmac
import io
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import sqlite3
import tempfile
import time
import uuid
import zipfile

from .model import DEFAULTS, PanelError

MIB = 1024 * 1024
MIN_FREE_BYTES = 512 * MIB
WAL_HEADROOM = 4 * MIB
MAX_BACKUP_BYTES = 32 * MIB
SAMPLE_BATCH = 8192
BACKUP_POLICY = ("backup_keep", "backup_limit_mib")
BACKUP_NAME = re.compile(r"backup-[0-9]{8}-[0-9]{6}\.zip")
INSTALL_BACKUP_NAME = re.compile(r"install-[0-9]{8}-[0-9]{6}-[0-9]+")
TRAFFIC_SCHEMA = """
    CREATE TABLE IF NOT EXISTS samples(at INTEGER NOT NULL,identity TEXT NOT NULL,port TEXT NOT NULL,up INTEGER NOT NULL,down INTEGER NOT NULL,PRIMARY KEY(at,identity,port));
    CREATE TABLE IF NOT EXISTS totals(identity TEXT NOT NULL,port TEXT NOT NULL,up INTEGER NOT NULL,down INTEGER NOT NULL,PRIMARY KEY(identity,port));
"""


class Paths:
    def __init__(self, home=None):
        home = home or os.environ.get("GRE_PANEL_HOME")
        self.etc = Path(home) / "etc" if home else Path("/etc/gremgr")
        self.var = Path(home) / "var" if home else Path("/var/lib/gremgr")
        self.run = Path(home) / "run" if home else Path("/run/gremgr")
        self.install_lock = Path(home) / "install.lock" if home else Path("/run/lock/gremgr-install.lock")
        self.config = self.etc / "panel.json"
        self.db = self.var / "panel.sqlite3"
        self.socket = self.run / "control.sock"
        self.backups = self.var / "backups"
        self.staged_backup = self.backups / ".settings-backup.zip"
        self.ssh = self.etc / "ssh"
        self.tls = self.etc / "tls"
        for p in (self.etc, self.var, self.run, self.backups, self.ssh, self.tls):
            p.mkdir(parents=True, exist_ok=True, mode=0o700)


def atomic_write(path, writer, mode="w"):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, temporary = tempfile.mkstemp(dir=path.parent, prefix=".write-")
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, mode) as out:
            writer(out)
            out.flush()
            os.fsync(out.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def atomic_json(path, data):
    def write(out):
        json.dump(data, out, ensure_ascii=False, indent=2, allow_nan=False)
        out.write("\n")
    atomic_write(path, write)


def file_size(path):
    try:
        return path.stat().st_size
    except FileNotFoundError:
        return 0


def disk_full(error):
    return getattr(error, "sqlite_errorname", None) == "SQLITE_FULL" or str(error) == "database or disk is full"


def prune_install_backups(current):
    """Retire old installer snapshots after preserving the rollback in use."""
    current = Path(current)
    previous = sorted((path for path in current.parent.iterdir()
                       if path != current and INSTALL_BACKUP_NAME.fullmatch(path.name)
                       and not path.is_symlink() and path.is_dir()), reverse=True)
    used, kept = 0, 0
    for snapshot in [current, *previous]:
        size = sum(file_size(path) for path in snapshot.iterdir() if not path.is_symlink() and path.is_file())
        if snapshot != current and (kept >= 3 or used + size > MAX_BACKUP_BYTES):
            shutil.rmtree(snapshot)
        else:
            used += size
            kept += 1


def password_hash(password):
    if len(str(password)) < 12 or len(str(password)) > 256:
        raise PanelError("Use a password of 12..256 characters.", "password")
    salt = secrets.token_hex(16)
    digest = hashlib.scrypt(str(password).encode(), salt=bytes.fromhex(salt), n=16384, r=8, p=1).hex()
    return f"scrypt${salt}${digest}"


def check_password(password, stored):
    try:
        method, salt, expected = stored.split("$")
        if method != "scrypt" or len(str(password)) > 256:
            return False
        actual = hashlib.scrypt(str(password).encode(), salt=bytes.fromhex(salt), n=16384, r=8, p=1).hex()
        return hmac.compare_digest(actual, expected)
    except (ValueError, TypeError):
        return False


def topology_node_id(paths):
    # The peer-only agent can share the same identity before the panel exists.
    with contextlib.closing(sqlite3.connect(paths.db, timeout=15)) as db, db:
        db.execute("CREATE TABLE IF NOT EXISTS secrets(key TEXT PRIMARY KEY,value TEXT NOT NULL)")
        key = "topology.node_id"
        db.execute("INSERT OR IGNORE INTO secrets VALUES(?,?)", (key, uuid.uuid4().hex))
        node_id = db.execute("SELECT value FROM secrets WHERE key=?", (key,)).fetchone()[0]
    os.chmod(paths.db, 0o600)
    return node_id


class Store:
    def __init__(self, paths=None):
        self.paths = paths or Paths()
        if not self.paths.config.exists():
            atomic_json(self.paths.config, {"schema": 1, "web_enabled": True, "settings": copy.deepcopy(DEFAULTS), "connections": [], "servers": []})
        with self.database() as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS secrets(key TEXT PRIMARY KEY,value TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS sessions(token TEXT PRIMARY KEY,csrf TEXT NOT NULL,expires REAL NOT NULL);
                CREATE TABLE IF NOT EXISTS attempts(peer TEXT PRIMARY KEY,failures INTEGER NOT NULL,last REAL NOT NULL);
                CREATE TABLE IF NOT EXISTS events(id INTEGER PRIMARY KEY,at REAL NOT NULL,kind TEXT NOT NULL,message TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS jobs(id TEXT PRIMARY KEY,status TEXT NOT NULL,progress INTEGER NOT NULL,message TEXT NOT NULL,result TEXT,created REAL NOT NULL);
            """ + TRAFFIC_SCHEMA + """
                CREATE TABLE IF NOT EXISTS cursors(identity TEXT NOT NULL,port TEXT NOT NULL,epoch TEXT NOT NULL,up INTEGER NOT NULL,down INTEGER NOT NULL,at REAL NOT NULL,PRIMARY KEY(identity,port));
                CREATE INDEX IF NOT EXISTS sample_time ON samples(at);
            """)
        os.chmod(self.paths.db, 0o600)

    @contextlib.contextmanager
    def database(self):
        db = sqlite3.connect(self.paths.db, timeout=15)
        db.row_factory = sqlite3.Row
        try:
            if db.execute("PRAGMA page_count").fetchone()[0] == 0:
                db.execute("PRAGMA auto_vacuum=INCREMENTAL")
            db.execute("PRAGMA journal_mode=WAL")
            db.execute("PRAGMA wal_autocheckpoint=512")
            db.execute(f"PRAGMA journal_size_limit={WAL_HEADROOM}")
            with db:
                yield db
        finally:
            db.close()

    def config(self):
        data = json.loads(self.paths.config.read_text())
        if data.get("schema") != 1:
            raise PanelError("Unsupported configuration schema.")
        data["settings"] = dict(DEFAULTS, **data["settings"])
        return data

    def topology_node_id(self):
        return topology_node_id(self.paths)

    def interrupt_jobs(self):
        with self.database() as db:
            db.execute("UPDATE jobs SET status='interrupted',message='Service restarted before the operation completed.' WHERE status IN ('queued','running')")

    def save(self, data):
        atomic_json(self.paths.config, data)

    def secret(self, key, value=None):
        with self.database() as db:
            if value is not None:
                db.execute("INSERT OR REPLACE INTO secrets VALUES(?,?)", (key, value))
            row = db.execute("SELECT value FROM secrets WHERE key=?", (key,)).fetchone()
        return row[0] if row else None

    def set_password(self, value):
        self.secret("password", password_hash(value))
        with self.database() as db:
            db.execute("DELETE FROM sessions")

    def login(self, username, password, peer):
        now = time.time()
        with self.database() as db:
            row = db.execute("SELECT * FROM attempts WHERE peer=?", (peer,)).fetchone()
            if row and row["failures"] >= 8 and now - row["last"] < 300:
                raise PanelError("Too many login attempts. Try again in five minutes.", "rate_limit")
            good = check_password(password, self.secret("password") or "")
            good = hmac.compare_digest(str(username).encode(), self.config()["settings"]["username"].encode()) and good
            if not good:
                failures = row["failures"] + 1 if row and now - row["last"] < 300 else 1
                db.execute("INSERT OR REPLACE INTO attempts VALUES(?,?,?)", (peer, failures, now))
            else:
                db.execute("DELETE FROM attempts WHERE peer=?", (peer,))
                token, csrf = secrets.token_urlsafe(32), secrets.token_urlsafe(24)
                db.execute("INSERT INTO sessions VALUES(?,?,?)", (hashlib.sha256(token.encode()).hexdigest(), csrf, now + 12 * 3600))
        if not good:
            raise PanelError("Incorrect username or password.", "auth")
        return {"token": token, "csrf": csrf}

    def session(self, token, csrf=None):
        digest = hashlib.sha256(str(token or "").encode()).hexdigest()
        with self.database() as db:
            row = db.execute("SELECT * FROM sessions WHERE token=? AND expires>?", (digest, time.time())).fetchone()
        if not row:
            raise PanelError("Please sign in.", "auth")
        if csrf is not None and not hmac.compare_digest(str(csrf).encode(), row["csrf"].encode()):
            raise PanelError("The request token expired. Reload the page.", "csrf")
        return dict(row)

    def logout(self, token):
        with self.database() as db:
            db.execute("DELETE FROM sessions WHERE token=?", (hashlib.sha256(str(token).encode()).hexdigest(),))

    def event(self, kind, message):
        with self.database() as db:
            db.execute("INSERT INTO events(at,kind,message) VALUES(?,?,?)", (time.time(), kind, message[:1000]))
            db.execute("DELETE FROM events WHERE id NOT IN (SELECT id FROM events ORDER BY id DESC LIMIT 1000)")

    def events(self):
        with self.database() as db:
            return [dict(x) for x in db.execute("SELECT * FROM events ORDER BY id DESC LIMIT 30")]

    def job(self, identity, status=None, progress=0, message="", result=None):
        with self.database() as db:
            if status is not None:
                db.execute("INSERT INTO jobs VALUES(?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET status=excluded.status,progress=excluded.progress,message=excluded.message,result=excluded.result", (identity, status, progress, message[:1000], json.dumps(result) if result is not None else None, time.time()))
                db.execute("DELETE FROM jobs WHERE id NOT IN (SELECT id FROM jobs ORDER BY created DESC LIMIT 100)")
            row = db.execute("SELECT * FROM jobs WHERE id=?", (identity,)).fetchone()
        if not row:
            raise PanelError("Operation not found.", "not_found")
        output = dict(row)
        output["result"] = json.loads(output["result"]) if output["result"] else None
        return output

    def sample(self, counters, epoch, now=None):
        now = time.time() if now is None else now
        if not counters:
            return {}
        free = shutil.disk_usage(self.paths.var).free
        if free < WAL_HEADROOM:
            return {}
        budget = self.config()["settings"]["telemetry_limit_mib"] * MIB - WAL_HEADROOM
        used = self.telemetry_bytes()
        if used >= budget and file_size(self.paths.db.with_name(self.paths.db.name + "-wal")) >= WAL_HEADROOM:
            return {}
        history = free >= MIN_FREE_BYTES and used < budget
        try:
            return self._save_sample(counters, epoch, now, budget if history else 0)
        except sqlite3.OperationalError as error:
            if not disk_full(error):
                raise
            # The bounded history transaction rolled back. Preserve counters if
            # there is still space for the smaller state-only transaction.
            if history:
                try:
                    return self._save_sample(counters, epoch, now, 0)
                except sqlite3.OperationalError as retry:
                    if not disk_full(retry):
                        raise
            return {}

    def _save_sample(self, counters, epoch, now, history_budget):
        rates = {}
        with self.database() as db:
            if history_budget:
                page = db.execute("PRAGMA page_size").fetchone()[0]
                db.execute(f"PRAGMA max_page_count={history_budget // page}")
            for (identity, port), (up, down) in counters.items():
                previous = db.execute("SELECT * FROM cursors WHERE identity=? AND port=?", (identity, port)).fetchone()
                same = previous and previous["epoch"] == epoch
                du = max(0, up - previous["up"]) if same and up >= previous["up"] else up
                dd = max(0, down - previous["down"]) if same and down >= previous["down"] else down
                elapsed = max(0.001, now - previous["at"]) if same else 0
                rates[(identity, port)] = {"up": du * 8 / elapsed if elapsed else 0, "down": dd * 8 / elapsed if elapsed else 0}
                db.execute("INSERT INTO totals VALUES(?,?,?,?) ON CONFLICT(identity,port) DO UPDATE SET up=up+excluded.up,down=down+excluded.down", (identity, port, du, dd))
                if history_budget:
                    db.execute("INSERT INTO samples VALUES(?,?,?,?,?) ON CONFLICT(at,identity,port) DO UPDATE SET up=up+excluded.up,down=down+excluded.down", (int(now // 60) * 60, identity, port, du, dd))
                db.execute("INSERT OR REPLACE INTO cursors VALUES(?,?,?,?,?,?)", (identity, port, epoch, up, down, now))
        return rates

    def stats(self, identity=None, hours=24):
        clauses, args = (" AND identity=?", [identity]) if identity else ("", [])
        now = time.time()
        with self.database() as db:
            totals = [dict(x) for x in db.execute("SELECT * FROM totals WHERE 1=1" + clauses, args)]
            # Times are stored in UTC; the browser labels them in the configured zone.
            points = [dict(x) for x in db.execute("SELECT (at/300)*300 AS at,SUM(up) AS up,SUM(down) AS down FROM samples WHERE port='all' AND at>=?" + clauses + " GROUP BY (at/300) ORDER BY at", [now - hours * 3600] + args)]
            series = [dict(x) for x in db.execute("SELECT (at/300)*300 AS at,identity,SUM(up) AS up,SUM(down) AS down FROM samples WHERE port='all' AND at>=?" + clauses + " GROUP BY (at/300),identity ORDER BY at", [now - hours * 3600] + args)]
            from datetime import datetime
            from zoneinfo import ZoneInfo
            midnight = datetime.fromtimestamp(now, ZoneInfo("Asia/Tehran")).replace(hour=0, minute=0, second=0, microsecond=0).timestamp()
            by_day = [dict(x) for x in db.execute("SELECT identity,SUM(up) AS up,SUM(down) AS down FROM samples WHERE port='all' AND at>=?" + clauses + " GROUP BY identity", [midnight] + args)]
        if identity is None:
            from collections import defaultdict
            kinds = {c["id"]: c["kind"] for c in self.config()["connections"]}
            grouped = defaultdict(lambda: [0, 0])
            for row in series:
                kind = kinds.get(row["identity"])
                if kind:
                    grouped[(row["at"], kind)][0] += row["up"]
                    grouped[(row["at"], kind)][1] += row["down"]
            series = [dict(at=at, kind=kind, up=values[0], down=values[1]) for (at, kind), values in sorted(grouped.items())]
        return {"totals": totals, "points": points, "series": series, "today": by_day}

    def telemetry_bytes(self):
        files = [self.paths.db.with_name(self.paths.db.name + suffix) for suffix in ("", "-wal", "-shm")]
        return sum(map(file_size, files)) + file_size(self.paths.var / "v2-host-metrics.json")

    def backup_files(self):
        return sorted((p for p in self.paths.backups.glob("backup-*.zip")
                       if BACKUP_NAME.fullmatch(p.name) and not p.is_symlink() and p.is_file()), reverse=True)

    def storage(self, settings):
        return {"telemetry_bytes": self.telemetry_bytes(), "telemetry_limit": settings["telemetry_limit_mib"] * MIB,
                "backup_bytes": sum(map(file_size, self.backup_files())) + file_size(self.paths.staged_backup),
                "backup_limit": settings["backup_limit_mib"] * MIB,
                "free_bytes": shutil.disk_usage(self.paths.var).free, "free_reserve": MIN_FREE_BYTES}

    def prune(self, settings=None):
        settings = settings or self.config()["settings"]
        free = shutil.disk_usage(self.paths.var).free
        if free < WAL_HEADROOM:
            return
        # Leave room for a WAL checkpoint and filesystem allocations before
        # history reaches the displayed limit.
        target = settings["telemetry_limit_mib"] * MIB - 2 * WAL_HEADROOM
        pressure = self.telemetry_bytes() > target or free < MIN_FREE_BYTES
        with self.database() as db:
            if pressure:
                _, pending, checkpointed = db.execute("PRAGMA wal_checkpoint(PASSIVE)").fetchone()
                if pending > checkpointed:
                    return
            db.execute("DELETE FROM samples WHERE rowid IN (SELECT rowid FROM samples WHERE at<? ORDER BY at LIMIT ?)",
                       (time.time() - settings["retention_days"] * 86400, SAMPLE_BATCH))
            db.execute("DELETE FROM sessions WHERE expires<?", (time.time(),))
            db.execute("DELETE FROM attempts WHERE last<?", (time.time() - 3600,))
            db.commit()
            if pressure:
                self._reclaim_history(db, target, free)
            else:
                db.execute("PRAGMA incremental_vacuum(100)").fetchall()

    def _reclaim_history(self, db, target, free):
        page = db.execute("PRAGMA page_size").fetchone()[0]
        pages = db.execute("PRAGMA page_count").fetchone()[0]
        reclaimable = db.execute("PRAGMA freelist_count").fetchone()[0]
        if (pages - reclaimable) * page > target or (free < MIN_FREE_BYTES and reclaimable * page < WAL_HEADROOM):
            db.execute("DELETE FROM samples WHERE rowid IN (SELECT rowid FROM samples ORDER BY at LIMIT ?)", (SAMPLE_BATCH,))
            db.commit()
        if db.execute("PRAGMA auto_vacuum").fetchone()[0]:
            db.execute("PRAGMA incremental_vacuum(1024)").fetchall()
        elif (db.execute("PRAGMA freelist_count").fetchone()[0] and
              shutil.disk_usage(self.paths.var).free >= MIN_FREE_BYTES + 2 * self.telemetry_bytes()):
            # A legacy database needs a rebuild before it can return free pages.
            db.execute("PRAGMA auto_vacuum=INCREMENTAL")
            db.execute("VACUUM")
        db.execute("PRAGMA wal_checkpoint(PASSIVE)").fetchone()

    def backup(self, max_bytes=MAX_BACKUP_BYTES):
        config = json.dumps(self.config(), ensure_ascii=False).encode()
        manifest = json.dumps({"schema": 1, "version": "1.0.0", "created": time.time(), "credentials": "excluded"})
        db_budget = min(max_bytes, MAX_BACKUP_BYTES) - len(config) - 65536
        available = shutil.disk_usage(self.paths.var).free
        if db_budget < 65536 or available < WAL_HEADROOM:
            raise PanelError("Insufficient space for a restorable backup.", "storage")
        include_history = available >= MIN_FREE_BYTES
        db_budget = min(db_budget, available // 4)
        with tempfile.TemporaryDirectory(dir=self.paths.var) as directory:
            destination = Path(directory) / "telemetry.sqlite3"
            with self.database() as source, contextlib.closing(sqlite3.connect(destination)) as target:
                target.executescript(TRAFFIC_SCHEMA)
                page = target.execute("PRAGMA page_size").fetchone()[0]
                target.execute(f"PRAGMA max_page_count={db_budget // page}")
                source.execute("BEGIN")
                try:
                    with target:
                        target.executemany("INSERT INTO totals VALUES(?,?,?,?)",
                                           source.execute("SELECT identity,port,up,down FROM totals"))
                except sqlite3.OperationalError as error:
                    if not disk_full(error):
                        raise
                    raise PanelError("The archive limit is too small for the saved traffic totals.", "storage") from error
                if include_history:
                    rows = source.execute("SELECT at,identity,port,up,down FROM samples ORDER BY at DESC,identity DESC,port DESC")
                    while batch := rows.fetchmany(512):
                        try:
                            with target:
                                target.executemany("INSERT INTO samples VALUES(?,?,?,?,?)", batch)
                        except sqlite3.OperationalError as error:
                            if not disk_full(error):
                                raise
                            break
            buffer = io.BytesIO()
            with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
                archive.writestr("manifest.json", manifest)
                archive.writestr("config.json", config)
                archive.write(destination, "telemetry.sqlite3")
            content = buffer.getvalue()
            if len(content) > min(max_bytes, MAX_BACKUP_BYTES):
                raise PanelError("The archive exceeds the backup size limit.", "storage")
            return content

    @staticmethod
    def read_backup(content):
        if len(content) > MAX_BACKUP_BYTES:
            raise PanelError("Backup is too large.")
        try:
            with zipfile.ZipFile(io.BytesIO(content)) as archive:
                if set(archive.namelist()) != {"manifest.json", "config.json", "telemetry.sqlite3"} or sum(x.file_size for x in archive.infolist()) > 128 * 1024 * 1024:
                    raise PanelError("Invalid backup archive.")
                manifest = json.loads(archive.read("manifest.json"))
                config = json.loads(archive.read("config.json"))
                telemetry = archive.read("telemetry.sqlite3")
                if manifest.get("schema") != 1 or config.get("schema") != 1:
                    raise PanelError("Unsupported backup schema.")
                return config, telemetry
        except (zipfile.BadZipFile, KeyError, ValueError, OSError) as error:
            raise PanelError("The backup could not be read.") from error

    def automatic_backup(self, settings=None, *, stage=False):
        with (self.paths.var / "backup.lock").open("a") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            settings = settings or self.config()["settings"]
            limit = settings["backup_limit_mib"] * MIB
            content = self.backup(limit)
            if shutil.disk_usage(self.paths.backups).free < len(content) + 65536:
                raise PanelError("Insufficient space for a restorable backup.", "storage")
            filename = self.paths.staged_backup if stage else self._backup_path()
            try:
                atomic_write(filename, lambda out: out.write(content), "wb")
            except OSError as error:
                if error.errno != errno.ENOSPC:
                    raise
                raise PanelError("Insufficient space for a restorable backup.", "storage") from error
            if not stage:
                self._rotate_backups(filename, settings)
            return filename.name

    def _backup_path(self):
        return self.paths.backups / (time.strftime("backup-%Y%m%d-%H%M%S", time.gmtime()) + ".zip")

    def finish_settings_backup(self, settings):
        staged = self.paths.staged_backup
        if not staged.is_file():
            return
        with (self.paths.var / "backup.lock").open("a") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            with zipfile.ZipFile(staged) as archive:
                previous = json.loads(archive.read("config.json"))["settings"]
            if all(previous[key] == settings[key] for key in BACKUP_POLICY):
                staged.unlink()
                return
            filename = self._backup_path()
            staged.replace(filename)
            self._rotate_backups(filename, settings)

    def _rotate_backups(self, filename, settings):
        limit = settings["backup_limit_mib"] * MIB
        used, kept = file_size(filename), 1
        for old in self.backup_files():
            if old == filename:
                continue
            size = file_size(old)
            if kept >= settings["backup_keep"] or used + size > limit:
                old.unlink(missing_ok=True)
            else:
                used += size
                kept += 1
