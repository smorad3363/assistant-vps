"""Serialized jobs, durable rollback journals and the authenticated API."""
import base64
from collections import defaultdict
import concurrent.futures
import contextlib
import copy
import fcntl
import json
import ipaddress
import os
from pathlib import Path
import re
import secrets
import socket
import sqlite3
import tempfile
import threading
import time
import uuid

from . import __version__
from .agent import read_peers
from .engine import Engine, discovered_ssh_ports, gre_for, run
from .model import PanelError, connection, resolve, settings_update, validate_conflicts
from .remote import Remote, server_metadata
from .store import Store, atomic_json, check_password


class Controller:
    def __init__(self, store=None, engine=None, remote=None):
        self.store = store or Store()
        self.paths = self.store.paths
        self.engine = engine or Engine(self.paths)
        self.remote = remote or Remote(self.paths)
        self.lock = threading.RLock()
        self.executor = concurrent.futures.ThreadPoolExecutor(max_workers=1, thread_name_prefix="network-job")
        self.rates, self.health, self.failures = {}, {}, {}
        self.last_sample, self.last_probe, self.last_backup = 0, 0, 0
        self.live_counters, self.live_epoch, self.last_persist = {}, None, 0
        self.pending = self.paths.etc / "pending.json"
        self.stats_cache, self.stats_cached_at = None, 0

    def adopt(self):
        """Import saved Iran pair profiles without touching live interfaces."""
        cfg = self.store.config()
        changed = False
        seen = {x["id"] for x in cfg["connections"]}
        for path in (self.paths.etc / "pairs").glob("*.json"):
            old = json.loads(path.read_text())
            if old.get("role") != "iran" or old.get("id") in seen:
                continue
            ports = old["ports"]
            mapped = {} if ports == "all" else {str(p): d for p, d in ports if p != d}
            item = {"id": old["id"], "kind": "gre", "name": old["outer_peer"],
                    "listen_ip": old["service_ip"], "outer_local": old["outer_local"],
                    "target_host": old["outer_peer"], "resolved_ip": old["outer_peer"],
                    "ports": "all" if ports == "all" else ",".join(str(x[0]) for x in ports),
                    "target_port": None, "port_map": mapped, "protocols": ["tcp", "udp"],
                    "enabled": True, "exclude_ports": [], "upload_mbps": 0, "download_mbps": 0,
                    "port_limits": {}, "monitor_ports": [], "mtu": old["mtu"], "mtu_mode": "manual",
                    "service_ip": old["outer_peer"], "server_id": "", "legacy_pair": old}
            cfg["connections"].append(item)
            changed = True
        if changed:
            self.store.save(cfg)
            self.store.event("info", "Existing GRE pairs imported without changing live tunnels.")

    def combined(self, cfg):
        result = copy.deepcopy(cfg)
        result["connections"] += read_peers(self.paths)
        return result

    def collect(self, persist=True):
        counters, epoch = self.engine.counters()
        now = time.time()
        fallback = self.store.sample(counters, epoch, now) if persist else {}
        if persist:
            self.last_persist = now
        # Read counters every second; persist durable history every five seconds.
        # Network transactions still flush before changing the counter epoch.
        elapsed = now - self.last_sample
        if elapsed >= .8 or epoch != self.live_epoch:
            self.rates = {}
            for key, values in counters.items():
                before = self.live_counters.get(key)
                if before is not None and epoch == self.live_epoch:
                    delta = [max(0, value - previous) for value, previous in zip(values, before)]
                    self.rates[key] = dict(zip(("up", "down"), (v * 8 / max(.001, elapsed) for v in delta)))
                else:
                    self.rates[key] = fallback.get(key, {"up": 0, "down": 0})
            self.live_counters, self.live_epoch, self.last_sample = copy.deepcopy(counters), epoch, now

    def allocate_gre(self, updated, previous):
        if not any(c["kind"] == "gre" and c.get("enabled", True) for c in updated["connections"]):
            return
        servers = {s["id"]: s for s in updated["servers"]}
        local = self.engine.routes()
        remote = {}
        old = {c["id"]: c for c in previous["connections"]}
        reserved = {c["id"]: ipaddress.ip_network(gre_for(old[c["id"]])["local_tun"] + "/30", strict=False)
                    for c in updated["connections"] if c["kind"] == "gre"
                    and c["id"] in old and old[c["id"]]["kind"] == "gre" and gre_for(old[c["id"]])["id"] == gre_for(c)["id"]}
        for c in updated["connections"]:
            if c["kind"] != "gre" or not c.get("enabled", True):
                continue
            before = old.get(c["id"])
            if before and before["kind"] == "gre" and before.get("enabled", True) and gre_for(before)["id"] == gre_for(c)["id"]:
                c["gre_slot"] = before.get("gre_slot", 0)
                continue
            server = servers.get(c["server_id"])
            if server and server["id"] not in remote:
                remote[server["id"]] = self.remote.call(server, {"action": "status"})
            status = remote.get(c["server_id"], {})
            profiles = sorted((p for p in status.get("pair_profiles", []) if p["gre_id"] == gre_for(c)["id"]),
                              key=lambda p: p.get("enabled", True), reverse=True)
            profile = profiles[0] if profiles else None
            fixed = bool(profile and profile.get("enabled", True))
            start = profile.get("slot", 0) if fixed else c.get("gre_slot", 0)
            routes = local + status.get("routes", [])
            blocked = [ipaddress.ip_network(r["dst"], strict=False) for r in routes
                       if r.get("dev") != gre_for(c)["tunnel"]]
            blocked += [ipaddress.ip_network(p["private_subnet"], strict=False) for p in status.get("pair_profiles", [])
                        if p["gre_id"] != gre_for(c)["id"] and p.get("private_subnet")]
            blocked += [n for identity, n in reserved.items() if identity != c["id"]]
            pool = ipaddress.ip_network("10.240.0.0/12")
            origin = int(pool.network_address)
            intervals = sorted((max(0, (int(n.network_address)-origin)//4), min(262143, (int(n.broadcast_address)-origin)//4))
                               for n in blocked if n.overlaps(pool))
            c["gre_slot"] = start
            preferred = (int(ipaddress.ip_address(gre_for(c)["local_tun"]))-origin)//4
            def available(first, last):
                if first > last:
                    return None
                index = first
                for lo, hi in intervals:
                    if hi < index:
                        continue
                    if lo > index:
                        break
                    index = hi + 1
                    if index > last:
                        return None
                return index
            chosen = available(preferred, preferred if fixed else 262143)
            if chosen is None and not fixed:
                chosen = available(0, preferred-1)
            if chosen is None:
                raise PanelError("No free private GRE subnet was found on both endpoints.", "route_conflict")
            c["gre_slot"] = (start + chosen - preferred) % 262144
            reserved[c["id"]] = ipaddress.ip_network(gre_for(c)["local_tun"] + "/30", strict=False)

    def submit(self, operation, payload):
        identity = uuid.uuid4().hex[:16]
        self.store.job(identity, "queued", 0, "Queued")

        def perform():
            self.store.job(identity, "running", 5, "Checking configuration")
            try:
                with self.lock, open(self.paths.etc / "network.lock", "a") as lock:
                    fcntl.flock(lock, fcntl.LOCK_EX)
                    if self.pending.exists() and operation not in ("server.connect", "backup.create", "connection.probe"):
                        raise PanelError("A previous change is being recovered. Wait for recovery to finish.", "recovering")
                    result = self.operation(operation, payload, lambda p, m: self.store.job(identity, "running", p, m))
                self.store.job(identity, "done", 100, "Completed", result)
            except Exception as error:
                message = str(error)[:800]
                self.store.event("error", message)
                self.store.job(identity, "failed", 100, message,
                               {"code": getattr(error, "code", "system"), "field": getattr(error, "field", None)})

        self.executor.submit(perform)
        return {"job": identity}

    @staticmethod
    def remote_changes(previous, updated):
        before = {x["id"]: x for x in previous["connections"] if x["kind"] == "gre"}
        after = {x["id"]: x for x in updated["connections"] if x["kind"] == "gre"}
        changes = defaultdict(list)
        for identity in before.keys() | after.keys():
            old, new = before.get(identity), after.get(identity)
            if old == new:
                continue
            # Unedited imported pairs need no SSH takeover merely to update UI settings.
            if old and old.get("server_id") and (not new or old["server_id"] != new.get("server_id")):
                changes[old["server_id"]].append((old, True))
            if new and new.get("server_id") and (new.get("enabled") or old and old.get("enabled") and old.get("server_id") == new.get("server_id")):
                changes[new["server_id"]].append((new, False))
            elif new and old and new.get("enabled") and new != old and new.get("legacy_pair"):
                allowed = {"name", "enabled", "upload_mbps", "download_mbps", "monitor_ports", "port_limits", "exclude_ports"}
                if any(old.get(k) != new.get(k) for k in set(old) | set(new) if k not in allowed):
                    raise PanelError("Connect the foreign SSH server before changing this imported GRE route.", "ssh_key")
        return changes

    def transaction(self, updated, progress=lambda p, m: None, measure_mtu=True):
        previous = self.store.config()
        measurements = set()
        if measure_mtu:
            for c in updated["connections"]:
                old = next((x for x in previous["connections"] if x["id"] == c["id"]), None)
                if c["kind"] == "gre" and c["enabled"] and c["mtu_mode"] == "auto" and (
                        old is None or old.get("resolved_ip") != c["resolved_ip"] or old.get("mtu_mode") != "auto"):
                    # Probe with both endpoints at the ceiling, then subtract
                    # headroom once. Probing the saved reduced MTU shrinks it
                    # again on every restore or manual-to-auto transition.
                    c["mtu"] = updated["settings"]["mtu"]
                    measurements.add(c["id"])
        validate_conflicts(updated["connections"], updated["settings"])
        self.allocate_gre(updated, previous)
        self.engine.preflight(self.combined(updated))
        self.collect()
        self.store.automatic_backup()
        journal = {"previous": previous, "updated": updated, "remote": [], "phase": "prepare", "created": time.time()}
        atomic_json(self.pending, journal)
        servers = {x["id"]: x for x in previous["servers"] + updated["servers"]}
        try:
            progress(20, "Preparing foreign servers")
            for server_id, changes in self.remote_changes(previous, updated).items():
                if server_id not in servers:
                    raise PanelError("The foreign SSH server is missing.", "server")
                reply = self.remote.batch(servers[server_id], changes)
                journal["remote"].append({"server": server_id, "transaction": reply["transaction"]})
                atomic_json(self.pending, journal)
            progress(50, "Applying scoped network rules")
            self.collect()
            self.engine.apply(self.combined(updated), self.combined(previous))
            progress(65, "Checking GRE and MTU")
            for c in updated["connections"]:
                old = next((x for x in previous["connections"] if x["id"] == c["id"]), None)
                if c["kind"] != "gre" or not c["enabled"] or old == c:
                    continue
                if c.get("server_id"):
                    health = self.engine.probe(c)
                    self.health[c["id"]] = health
                    if health["gre"] is not True:
                        raise PanelError("The GRE peer did not respond. Previous settings have been restored.", "gre_probe")
                    if c["id"] in measurements:
                        c["mtu"] = self.engine.choose_mtu(c, updated["settings"]["mtu"])
            # Keep both sides at the measured MTU. The first stage used the ceiling.
            self.collect()
            self.engine.apply(self.combined(updated), self.combined(updated))
            self.engine.retire_legacy(self.combined(updated))
            self.store.save(updated)
            self.stats_cache = None
            journal["updated"], journal["phase"] = updated, "commit"
            atomic_json(self.pending, journal)
            progress(85, "Committing both endpoints")
            for entry in journal["remote"]:
                self.remote.call(servers[entry["server"]], {"action": "commit", "transaction": entry["transaction"]})
            # If MTU auto-selection reduced the ceiling, a second peer transaction
            # records that same final MTU durably without stopping the interface.
            for server_id, changes in self.remote_changes(previous, updated).items():
                reply = self.remote.batch(servers[server_id], changes)
                self.remote.call(servers[server_id], {"action": "commit", "transaction": reply["transaction"]})
            self.pending.unlink()
            self.store.event("success", "Network configuration saved; owned rules restored automatically at boot.")
            self.collect()
        except Exception:
            self.recover()
            raise

    def recover(self):
        if not self.pending.exists():
            return True
        journal = json.loads(self.pending.read_text())
        old, new = journal["previous"], journal["updated"]
        servers = {x["id"]: x for x in old["servers"] + new["servers"]}
        ok = True
        for item in journal["remote"]:
            try:
                self.remote.call(servers[item["server"]], {"action": "rollback", "transaction": item["transaction"]})
            except Exception:
                ok = False
        # Also restores endpoints whose commit was acknowledged before a crash.
        for server_id, changes in self.remote_changes(new, old).items():
            try:
                reply = self.remote.batch(servers[server_id], changes)
                self.remote.call(servers[server_id], {"action": "commit", "transaction": reply["transaction"]})
            except Exception:
                ok = False
        with contextlib.suppress(Exception):
            self.collect()
        self.engine.apply(self.combined(old), self.combined(new))
        self.store.save(old)
        if ok:
            self.pending.unlink()
            self.store.event("warning", "Previous network settings restored after an unsuccessful change.")
        else:
            self.store.event("warning", "Local rollback completed; foreign recovery will retry. Uncommitted foreign changes have a rollback timer.")
        return ok

    def operation(self, operation, payload, progress):
        cfg = self.store.config()
        if operation == "server.connect":
            progress(20, "Checking SSH host keys and credentials")
            identity = str(payload.get("id", ""))
            previous = next((x for x in cfg["servers"] if x["id"] == identity), None)
            if identity and previous is None:
                raise PanelError("Foreign server not found.", "not_found")
            credentials = {key: payload[key] for key in ("host", "port", "username", "name", "password", "private_key") if key in payload}
            if resolve(credentials.get("host", "")) in self.engine.interfaces():
                raise PanelError("The foreign server must be a different host.", "loop")
            if previous and (self.paths.ssh / (identity + ".pub")).is_file():
                credentials["_revoke_key"] = (self.paths.ssh / (identity + ".pub")).read_text()
            server = self.remote.connect(credentials)
            if previous:
                temporary = server["id"]
                for suffix in ("", ".pub", ".known"):
                    source = self.paths.ssh / (temporary + suffix)
                    if source.exists():
                        os.replace(source, self.paths.ssh / (identity + suffix))
                server["id"] = identity
                cfg["servers"] = [server if x["id"] == identity else x for x in cfg["servers"]]
                if self.pending.exists():
                    journal = json.loads(self.pending.read_text())
                    for key in ("previous", "updated"):
                        journal[key]["servers"] = [server if x["id"] == identity else x for x in journal[key]["servers"]]
                    atomic_json(self.pending, journal)
            else:
                cfg["servers"].append(server)
            for c in cfg["connections"]:
                if c["kind"] != "gre" or c.get("server_id") or not c.get("legacy_pair"):
                    continue
                if c["resolved_ip"] not in server.get("addresses", [server["resolved_ip"]]):
                    continue
                profile = next((p for p in server.get("service_profiles", []) if p["gre_id"] == gre_for(c)["id"]), None)
                if profile:
                    c["service_ip"], c["server_id"] = profile["service_ip"], server["id"]
            self.store.save(cfg)
            self.store.event("success", "Foreign server connected with a restricted management key.")
            return {"server": server["id"]}
        if operation == "server.delete":
            identity = str(payload.get("id", ""))
            if any(x.get("server_id") == identity for x in cfg["connections"]):
                raise PanelError("This server is still used by a GRE connection.", "in_use")
            return self.cleanup_server(identity)
        if operation in ("connection.save", "connection.delete", "connection.toggle", "connection.probe"):
            identity = payload.get("id")
            previous = next((x for x in cfg["connections"] if x["id"] == identity), None)
            if identity and previous is None:
                raise PanelError("Connection not found.", "not_found")
            if operation == "connection.probe":
                self.health[identity] = self.engine.probe(previous)
                return self.health[identity]
            if operation == "connection.save":
                item = connection(payload, cfg["settings"], previous)
                if item["kind"] == "gre" and not any(x["id"] == item["server_id"] for x in cfg["servers"]):
                    raise PanelError("Connect a foreign server first.", "server")
                cfg["connections"] = [x for x in cfg["connections"] if x["id"] != item["id"]] + [item]
            elif operation == "connection.toggle":
                previous["enabled"] = not previous["enabled"]
            else:
                cfg["connections"] = [x for x in cfg["connections"] if x["id"] != identity]
            self.transaction(cfg, progress)
            result = {"id": item["id"] if operation == "connection.save" else identity}
            if operation == "connection.delete" and previous["kind"] == "gre" and previous.get("server_id"):
                server_id = previous["server_id"]
                if not any(c.get("server_id") == server_id for c in cfg["connections"]):
                    progress(92, "Cleaning unused foreign helper")
                    result["cleanup"] = self.cleanup_server(server_id)
            return result
        if operation == "settings.save":
            previous = copy.deepcopy(cfg["settings"])
            cfg["settings"] = settings_update(previous, payload)
            with contextlib.suppress(PanelError):
                cfg["settings"]["ssh_ports"] = sorted(set(cfg["settings"]["ssh_ports"] + discovered_ssh_ports()))
            if cfg["settings"]["port"] != previous["port"]:
                with socket.socket() as probe:
                    # Match HTTPServer's reuse behavior: TIME_WAIT from a
                    # previous panel port must not look like a live listener.
                    probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                    try:
                        probe.bind(("0.0.0.0", cfg["settings"]["port"]))
                    except OSError:
                        raise PanelError("The panel port is already in use.", "port_in_use", "port")
                cfg["settings"]["reserved_ports"] = sorted(set(cfg["settings"]["reserved_ports"] + [previous["port"]]))
            self.transaction(cfg, progress)
            if cfg["settings"]["port"] != previous["port"]:
                atomic_json(self.paths.etc / "web-pending.json", {"previous": previous, "deadline": time.time() + 120})
                self.schedule_web_restart()
            return {"port": cfg["settings"]["port"], "reconnect": cfg["settings"]["port"] != previous["port"]}
        if operation == "backup.create":
            return {"filename": self.store.automatic_backup()}
        if operation == "backup.restore":
            incoming, telemetry = self.store.read_backup(base64.b64decode(payload.get("content", ""), validate=True))
            # Management identity and bind/TLS settings stay local during restore.
            incoming["settings"] = settings_update(cfg["settings"], incoming["settings"])
            incoming["settings"]["port"] = cfg["settings"]["port"]
            incoming["settings"]["username"] = cfg["settings"]["username"]
            incoming["settings"]["ssh_ports"] = sorted(set(incoming["settings"]["ssh_ports"] + cfg["settings"]["ssh_ports"]))
            incoming["servers"] = [server_metadata(s) for s in incoming["servers"]]
            if len(incoming["servers"]) > 128 or len({s["id"] for s in incoming["servers"]}) != len(incoming["servers"]):
                raise PanelError("Invalid foreign server list in backup.")
            normalized = []
            for c in incoming["connections"]:
                c = copy.deepcopy(c)
                mapping = payload.get("address_map", {})
                if not isinstance(mapping, dict):
                    raise PanelError("Invalid address mapping.")
                c["listen_ip"] = mapping.get(c["listen_ip"], c["listen_ip"])
                if c.get("outer_local"):
                    c["outer_local"] = mapping.get(c["outer_local"], c["outer_local"])
                if c["kind"] == "gre" and not (self.paths.ssh / c.get("server_id", "missing")).is_file():
                    c["enabled"] = False
                normalized.append(connection(c, incoming["settings"], c))
            incoming["connections"] = normalized
            # Validate the database before any network state is changed.
            self.validate_telemetry(telemetry)
            self.transaction(incoming, progress, measure_mtu=False)
            self.restore_telemetry(telemetry)
            return {"paused_gre": sum(x["kind"] == "gre" and not x["enabled"] for x in normalized)}
        if operation == "tls.save":
            import ssl
            cert, key = str(payload.get("certificate", "")), str(payload.get("key", ""))
            if len(cert) > 131072 or len(key) > 32768:
                raise PanelError("Certificate files are too large.")
            with tempfile.TemporaryDirectory(dir=self.paths.tls) as directory:
                cp, kp = Path(directory) / "cert.pem", Path(directory) / "key.pem"
                cp.write_text(cert)
                kp.write_text(key)
                os.chmod(kp, 0o600)
                try:
                    ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER).load_cert_chain(cp, kp)
                except (ssl.SSLError, OSError) as error:
                    raise PanelError("The TLS certificate and private key do not match.", "certificate") from error
                for source, name in ((cp, "cert.pem"), (kp, "key.pem")):
                    destination = self.paths.tls / name
                    if destination.exists():
                        destination.replace(destination.with_suffix(".previous"))
                    source.replace(destination)
                    os.chmod(destination, 0o640)
                self.publish_web_config(cfg)
                from .certificates import status, save
                automation = status(self.paths)
                automation.update(enabled=False, status="manual")
                save(self.paths, automation)
            self.schedule_web_restart()
            return {}
        if operation == "tls.auto":
            from .certificates import configure, save
            automation = configure(self.store)
            automation.update(enabled=True, status="pending", error="")
            save(self.paths, automation)
            run("systemctl", "start", "--no-block", "gremgr-certificate.service")
            return {"scheduled": True}
        if operation == "update":
            run("systemd-run", "--quiet", "--unit=gremgr-update-" + uuid.uuid4().hex[:8], "--on-active=3s", "--timer-property=AccuracySec=1s",
                "/bin/bash", "/opt/gremgr/current/install.sh", "--update-only")
            self.store.event("info", "Update scheduled. The management services will restart after package verification.")
            return {"scheduled": True}
        raise PanelError("Unsupported operation.")

    def cleanup_server(self, identity):
        cfg = self.store.config()
        server = next((s for s in cfg["servers"] if s["id"] == identity), None)
        if not server or not re.fullmatch(r"[0-9a-f]{10}", identity):
            raise PanelError("Foreign server not found.", "not_found")
        public = self.paths.ssh / (identity + ".pub")
        try:
            if not public.is_file():
                raise PanelError("Reconnect this server before cleaning the foreign installation.", "ssh_key")
            result = self.remote.call(server, {"action": "cleanup", "username": server["username"], "key": public.read_text()})
        except Exception as error:
            server["cleanup_pending"] = True
            self.store.save(cfg)
            self.store.event("warning", "Foreign cleanup pending; retry from the server list.")
            raise PanelError("The tunnel was removed, but foreign cleanup is pending. Reconnect an older helper or retry from Settings.", "cleanup_pending") from error
        cfg["servers"] = [s for s in cfg["servers"] if s["id"] != identity]
        self.store.save(cfg)
        for suffix in ("", ".pub", ".known"):
            (self.paths.ssh / (identity + suffix)).unlink(missing_ok=True)
        self.store.event("success", "Unused foreign management connection removed safely.")
        return result

    def restore_telemetry(self, raw):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "restore.sqlite3"
            path.write_bytes(raw)
            try:
                db = sqlite3.connect("file:" + str(path) + "?mode=ro", uri=True)
                db.set_progress_handler(lambda: 1 if time.monotonic() - started > 10 else 0, 10000)
                started = time.monotonic()
                if db.execute("PRAGMA quick_check").fetchone()[0] != "ok":
                    raise PanelError("Backup telemetry is corrupt.")
                for name in ("samples", "totals"):
                    if db.execute("SELECT type FROM sqlite_master WHERE name=?", (name,)).fetchone()[0] != "table":
                        raise PanelError("Invalid telemetry table.")
                with self.store.database() as target:
                    for table, columns in (("totals", "identity,port,up,down"), ("samples", "at,identity,port,up,down")):
                        target.execute("DELETE FROM " + table)
                        placeholders = ",".join("?" for _ in columns.split(","))
                        cursor = db.execute("SELECT " + columns + " FROM " + table)
                        while rows := cursor.fetchmany(1000):
                            target.executemany("INSERT INTO " + table + " VALUES(" + placeholders + ")", rows)
                    target.execute("DELETE FROM cursors")
                db.close()
            except (sqlite3.Error, TypeError, IndexError) as error:
                raise PanelError("Backup telemetry could not be restored.") from error

    @staticmethod
    def validate_telemetry(raw):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "check.sqlite3"
            path.write_bytes(raw)
            db = sqlite3.connect("file:" + str(path) + "?mode=ro", uri=True)
            started = time.monotonic()
            db.set_progress_handler(lambda: int(time.monotonic() - started > 10), 10000)
            try:
                if db.execute("PRAGMA quick_check").fetchone()[0] != "ok":
                    raise PanelError("Backup telemetry is corrupt.")
                for table, columns in (("totals", "identity,port,up,down"), ("samples", "identity,port,up,down,at")):
                    found = db.execute("SELECT type FROM sqlite_master WHERE name=?", (table,)).fetchone()
                    if not found or found[0] != "table":
                        raise PanelError("Invalid telemetry table.")
                    keys = "identity,port" if table == "totals" else "at,identity,port"
                    if db.execute("SELECT 1 FROM " + table + " GROUP BY " + keys + " HAVING COUNT(*)>1 LIMIT 1").fetchone():
                        raise PanelError("Duplicate telemetry records in backup.")
                    for index, row in enumerate(db.execute("SELECT " + columns + " FROM " + table)):
                        if index > 2000000 or not re.fullmatch(r"[0-9a-f]{10}", str(row[0])) or not re.fullmatch(r"all|[0-9]{1,5}", str(row[1])) or any(not isinstance(n, int) or not 0 <= n <= 2**63-1 for n in row[2:]):
                            raise PanelError("Invalid telemetry data.")
            except sqlite3.Error as error:
                raise PanelError("Backup telemetry could not be read.") from error
            finally:
                db.close()

    def publish_web_config(self, cfg=None):
        cfg = cfg or self.store.config()
        destination = self.paths.run / "web.json"
        self.paths.run.chmod(0o750)
        import grp
        import shutil
        try:
            gid = grp.getgrnam("gremgr").gr_gid
        except KeyError:
            gid = os.getgid()
        for name in ("cert.pem", "key.pem"):
            source = self.paths.tls / name
            if source.exists():
                target = self.paths.run / name
                shutil.copyfile(source, target)
                os.chmod(target, 0o640)
                if os.geteuid() == 0:
                    os.chown(target, 0, gid)
        atomic_json(destination, {"port": cfg["settings"]["port"], "bind": cfg["settings"]["bind"],
                                  "tls": cfg["settings"]["tls"], "certificate": str(self.paths.run / "cert.pem"),
                                  "key": str(self.paths.run / "key.pem")})
        os.chmod(destination, 0o640)
        if os.geteuid() == 0:
            os.chown(destination, 0, gid)

    def schedule_web_restart(self):
        self.publish_web_config()
        run("systemd-run", "--quiet", "--unit=gremgr-web-reload-" + uuid.uuid4().hex[:8], "--on-active=2s", "--timer-property=AccuracySec=1s",
            "/bin/systemctl", "restart", "gremgr-web.service")

    def state(self, session):
        cfg = self.store.config()
        if self.stats_cache is None or time.time() - self.stats_cached_at >= 30:
            self.stats_cache = self.store.stats()
            self.stats_cached_at = time.time()
        for c in cfg["connections"]:
            c["rate"] = self.rates.get((c["id"], "all"), {"up": 0, "down": 0})
            c["port_rates"] = {p: rate for (identity, p), rate in self.rates.items() if identity == c["id"] and p != "all"}
            c["health"] = self.health.get(c["id"])
            c["adopted"] = bool(c.pop("legacy_pair", None))
            c["measured_ports"] = sorted(int(p) for identity, p in self.rates if identity == c["id"] and p != "all")
        for s in cfg["servers"]:
            s["key_ready"] = (self.paths.ssh / s["id"]).is_file()
        try:
            addresses = self.engine.interfaces()
        except PanelError:
            addresses = {}
        from .certificates import status
        return dict(cfg, version=__version__, csrf=session["csrf"], addresses=addresses, certificate=status(self.paths),
                    stats=self.stats_cache, events=self.store.events(), sampled_at=self.last_sample,
                    recovering=self.pending.exists(), backups=[p.name for p in sorted(self.paths.backups.glob("backup-*.zip"), reverse=True)])

    def request(self, route, payload, token=None, csrf=None, peer="local"):
        if route == "login":
            return self.store.login(payload.get("username", ""), payload.get("password", ""), peer)
        session = self.store.session(token, None if route in ("state", "live", "stats", "job", "backup.download") else csrf or "")
        if route == "auth.check":
            return {}
        if route == "state":
            return self.state(session)
        if route == "live":
            with self.lock:
                return {"sampled_at": self.last_sample, "connections": [
                    {"id": c["id"], "rate": self.rates.get((c["id"], "all"), {"up": 0, "down": 0}),
                     "port_rates": {p: rate for (identity, p), rate in self.rates.items() if identity == c["id"] and p != "all"}}
                    for c in self.store.config()["connections"]]}
        if route == "stats":
            return self.store.stats(payload.get("id"), min(24 * 30, max(1, int(payload.get("hours", 24)))))
        if route == "job":
            return self.store.job(str(payload.get("id", "")))
        if route == "logout":
            self.store.logout(token)
            return {}
        if route == "password":
            if not check_password(payload.get("current", ""), self.store.secret("password") or ""):
                raise PanelError("The current password is incorrect.", "auth")
            self.store.set_password(payload.get("password", ""))
            return {}
        if route == "web.confirm":
            pending = self.paths.etc / "web-pending.json"
            if pending.exists() and payload.get("port") == self.store.config()["settings"]["port"]:
                pending.unlink()
            return {}
        if route == "backup.download":
            name = str(payload.get("filename", ""))
            if not re.fullmatch(r"backup-[0-9]{8}-[0-9]{6}\.zip", name):
                raise PanelError("Invalid backup name.")
            path = self.paths.backups / name
            if not path.is_file():
                raise PanelError("Backup not found.", "not_found")
            return {"content": base64.b64encode(path.read_bytes()).decode(), "filename": name}
        if route == "backup.preview":
            config, _ = self.store.read_backup(base64.b64decode(payload.get("content", ""), validate=True))
            return {"connections": len(config["connections"]), "servers": len(config["servers"]),
                    "addresses": sorted({x["listen_ip"] for x in config["connections"]})}
        if route in {"connection.save", "connection.delete", "connection.toggle", "connection.probe", "server.connect", "server.delete", "settings.save", "backup.create", "backup.restore", "tls.save", "tls.auto", "update"}:
            return self.submit(route, copy.deepcopy(payload))
        raise PanelError("Endpoint not found.", "not_found")

    def tick(self):
        if not self.lock.acquire(blocking=False):
            return
        try:
            now = time.time()
            if self.pending.exists():
                self.recover()
            self.collect(persist=now - self.last_persist >= 5)
            pending = self.paths.etc / "web-pending.json"
            if pending.exists():
                rollback = json.loads(pending.read_text())
                if now > rollback["deadline"]:
                    cfg = self.store.config()
                    previous = copy.deepcopy(cfg)
                    cfg["settings"] = rollback["previous"]
                    self.engine.apply(self.combined(cfg), self.combined(previous))
                    self.store.save(cfg)
                    pending.unlink()
                    self.schedule_web_restart()
                    self.store.event("warning", "Panel port change rolled back because access was not confirmed.")
            cfg = self.store.config()
            if now - self.last_probe > 60:
                self.last_probe = now
                for c in cfg["connections"]:
                    if not c.get("enabled") or c["kind"] != "gre":
                        continue
                    status = self.engine.probe(c)
                    self.health[c["id"]] = status
                    self.failures[c["id"]] = 0 if status["gre"] else self.failures.get(c["id"], 0) + 1
                    if cfg["settings"]["watchdog"] and self.failures[c["id"]] == 3:
                        with open(self.paths.etc / "network.lock", "a") as lock:
                            fcntl.flock(lock, fcntl.LOCK_EX)
                            self.collect()
                            self.engine.apply(self.combined(cfg), self.combined(cfg))
                        self.store.event("warning", "Owned GRE state refreshed after three failed checks; VPN services were not restarted.")
            if now - self.last_backup > 86400:
                self.store.prune()
                self.store.automatic_backup()
                self.last_backup = now
        finally:
            self.lock.release()
