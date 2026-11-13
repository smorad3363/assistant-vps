"""Atomic profiles, bounded SQLite telemetry, sessions, and portable backups."""
import contextlib
import copy
import hashlib
import hmac
import io
import json
import os
from pathlib import Path
import secrets
import sqlite3
import tempfile
import time
import zipfile

from .model import DEFAULTS, PanelError


class Paths:
    def __init__(self, home=None):
        home = home or os.environ.get("GRE_PANEL_HOME")
        self.etc = Path(home) / "etc" if home else Path("/etc/gremgr")
        self.var = Path(home) / "var" if home else Path("/var/lib/gremgr")
        self.run = Path(home) / "run" if home else Path("/run/gremgr")
        self.config = self.etc / "panel.json"
        self.db = self.var / "panel.sqlite3"
        self.socket = self.run / "control.sock"
        self.backups = self.var / "backups"
        self.ssh = self.etc / "ssh"
        self.tls = self.etc / "tls"
        for p in (self.etc, self.var, self.run, self.backups, self.ssh, self.tls):
            p.mkdir(parents=True, exist_ok=True, mode=0o700)


def atomic_json(path, data):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, temporary = tempfile.mkstemp(dir=path.parent, prefix=".write-")
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w") as out:
            json.dump(data, out, ensure_ascii=False, indent=2, allow_nan=False)
            out.write("\n")
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
                CREATE TABLE IF NOT EXISTS samples(at INTEGER NOT NULL,identity TEXT NOT NULL,port TEXT NOT NULL,up INTEGER NOT NULL,down INTEGER NOT NULL,PRIMARY KEY(at,identity,port));
                CREATE TABLE IF NOT EXISTS totals(identity TEXT NOT NULL,port TEXT NOT NULL,up INTEGER NOT NULL,down INTEGER NOT NULL,PRIMARY KEY(identity,port));
                CREATE TABLE IF NOT EXISTS cursors(identity TEXT NOT NULL,port TEXT NOT NULL,epoch TEXT NOT NULL,up INTEGER NOT NULL,down INTEGER NOT NULL,at REAL NOT NULL,PRIMARY KEY(identity,port));
                CREATE INDEX IF NOT EXISTS sample_time ON samples(at);
            """)
        os.chmod(self.paths.db, 0o600)

    @contextlib.contextmanager
    def database(self):
        db = sqlite3.connect(self.paths.db, timeout=15)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA journal_mode=WAL")
        db.execute("PRAGMA busy_timeout=15000")
        try:
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
        rates = {}
        with self.database() as db:
            for (identity, port), (up, down) in counters.items():
                previous = db.execute("SELECT * FROM cursors WHERE identity=? AND port=?", (identity, port)).fetchone()
                same = previous and previous["epoch"] == epoch
                du = max(0, up - previous["up"]) if same and up >= previous["up"] else up
                dd = max(0, down - previous["down"]) if same and down >= previous["down"] else down
                elapsed = max(0.001, now - previous["at"]) if same else 0
                rates[(identity, port)] = {"up": du * 8 / elapsed if elapsed else 0, "down": dd * 8 / elapsed if elapsed else 0}
                db.execute("INSERT INTO totals VALUES(?,?,?,?) ON CONFLICT(identity,port) DO UPDATE SET up=up+excluded.up,down=down+excluded.down", (identity, port, du, dd))
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

    def prune(self):
        with self.database() as db:
            db.execute("DELETE FROM samples WHERE at<?", (time.time() - self.config()["settings"]["retention_days"] * 86400,))
            db.execute("DELETE FROM sessions WHERE expires<?", (time.time(),))
            db.execute("DELETE FROM attempts WHERE last<?", (time.time() - 3600,))
            db.execute("PRAGMA incremental_vacuum(100)")

    def backup(self):
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "telemetry.sqlite3"
            with self.database() as source:
                target = sqlite3.connect(destination)
                try:
                    source.backup(target)
                    target.execute("PRAGMA secure_delete=ON")
                    target.execute("DELETE FROM sessions")
                    target.execute("DELETE FROM attempts")
                    target.execute("DELETE FROM secrets")
                    target.commit()
                    target.execute("VACUUM")
                finally:
                    target.close()
            buffer = io.BytesIO()
            with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
                archive.writestr("manifest.json", json.dumps({"schema": 1, "version": "1.0.0", "created": time.time(), "credentials": "excluded"}))
                archive.writestr("config.json", json.dumps(self.config(), ensure_ascii=False))
                archive.write(destination, "telemetry.sqlite3")
            return buffer.getvalue()

    @staticmethod
    def read_backup(content):
        if len(content) > 32 * 1024 * 1024:
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

    def automatic_backup(self):
        filename = self.paths.backups / (time.strftime("backup-%Y%m%d-%H%M%S", time.gmtime()) + ".zip")
        filename.write_bytes(self.backup())
        os.chmod(filename, 0o600)
        keep = self.config()["settings"]["backup_keep"]
        for old in sorted(self.paths.backups.glob("backup-*.zip"), reverse=True)[keep:]:
            old.unlink()
        return filename.name
