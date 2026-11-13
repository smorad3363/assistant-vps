"""Explicit loopback-only development fixture. Never used by systemd services."""
import argparse
import copy
import json
import os
from pathlib import Path
import tempfile
import threading
import time
import uuid

from .controller import Controller
from .model import connection
from .store import Paths, Store
from .web import serve


class DemoEngine:
    def __init__(self):
        self.current = None
        self.epoch = "demo"
        self.amount = 0

    def interfaces(self): return {"192.0.2.10": "demo0", "192.0.2.11": "demo0"}
    def preflight(self, cfg): return self.interfaces()
    def apply(self, cfg, previous=None): self.current = copy.deepcopy(cfg)
    def retire_legacy(self, cfg): pass
    def choose_mtu(self, c, ceiling): return min(1380, ceiling)
    def counters(self):
        self.amount += 1000000
        return ({(c["id"], "all"): [self.amount, self.amount * 4] for c in (self.current or {}).get("connections", []) if c["enabled"]}, self.epoch)
    def probe(self, c): return {"checked": time.time(), "gre": True if c["kind"] == "gre" else None, "tcp": True, "udp": None, "latency_ms": 68.4, "loss_percent": 0}


class DemoRemote:
    def __init__(self, paths): self.paths = paths
    def connect(self, data):
        identity = uuid.uuid4().hex[:10]
        (self.paths.ssh / identity).write_text("DEMO ONLY")
        return {"id": identity, "host": data["host"], "resolved_ip": "203.0.113.20", "username": data.get("username", "root"), "port": int(data.get("port", 22)), "name": data.get("name") or data["host"], "fingerprints": ["SHA256:DEMO-ONLY"], "key_ready": True}
    def batch(self, server, changes): return {"transaction": uuid.uuid4().hex[:16]}
    def call(self, server, request): return {}


class LocalBackend:
    def __init__(self, controller): self.controller = controller
    def request(self, *args, **kwargs):
        try: return {"ok": True, "result": self.controller.request(*args, **kwargs)}
        except Exception as error: return {"ok": False, "error": str(error), "code": getattr(error, "code", "system"), "field": getattr(error, "field", None)}


class DemoController(Controller):
    def schedule_web_restart(self): pass
    def operation(self, operation, payload, progress):
        if operation == "update": return {"scheduled": True}
        return super().operation(operation, payload, progress)


def seed(store, controller):
    cfg = store.config()
    server = controller.remote.connect({"name": "آلمان · فرانکفورت", "host": "de.example.com"})
    cfg["servers"] = [server]
    for payload in [
        {"kind": "gre", "name": "آلمان · مسیر اصلی", "listen_ip": "192.0.2.10", "target_host": "203.0.113.20", "ports": "all", "exclude_ports": [1000, 443], "server_id": server["id"], "upload_mbps": 200, "download_mbps": 200},
        {"kind": "gre", "name": "فنلاند · مسیر دوم", "listen_ip": "192.0.2.11", "target_host": "203.0.113.21", "ports": "51820-51821", "server_id": server["id"], "mtu": 1380, "mtu_mode": "manual"},
        {"kind": "direct", "name": "اوپن‌وی‌پی‌ان", "listen_ip": "192.0.2.10", "target_host": "203.0.113.30", "ports": "1000", "protocols": ["udp"]},
        {"kind": "direct", "name": "انتقال سرویس وب", "listen_ip": "192.0.2.10", "target_host": "203.0.113.31", "ports": "443", "target_port": 8443, "enabled": False}
    ]:
        item = connection(payload, cfg["settings"])
        cfg["connections"].append(item)
        controller.health[item["id"]] = controller.engine.probe(item)
    store.save(cfg)
    controller.engine.apply(cfg)
    now = time.time()
    for i in range(120):
        counters = {(x["id"], "all"): [int((i+1)*1800000*(1+(i%7)/10)), int((i+1)*7000000*(1+(i%5)/10))] for x in cfg["connections"]}
        store.sample(counters, "seed", now-7200+i*60)
    store.event("info", "Existing GRE pairs imported without changing live tunnels.")
    store.event("success", "Network configuration saved; owned rules restored automatically at boot.")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=8877)
    parser.add_argument("--seed", action="store_true")
    parser.add_argument("--home")
    args = parser.parse_args()
    home = args.home or tempfile.mkdtemp(prefix="gremgr-demo-")
    paths = Paths(home)
    store = Store(paths)
    store.set_password(os.environ.get("GRE_PANEL_PASSWORD", "Demo-Panel-2026!"))
    controller = DemoController(store, DemoEngine(), DemoRemote(paths))
    if args.seed and not store.config()["connections"]: seed(store, controller)
    controller.collect()
    def sample():
        while True:
            time.sleep(5)
            with controller.lock: controller.collect()
    threading.Thread(target=sample, daemon=True).start()
    print(f"Development fixture only: http://127.0.0.1:{args.port}", flush=True)
    serve({"bind": "127.0.0.1", "port": args.port, "tls": False}, LocalBackend(controller))


if __name__ == "__main__": main()
