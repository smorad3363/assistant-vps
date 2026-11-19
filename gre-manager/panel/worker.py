"""Privileged Unix-socket daemon. Only authenticated, allowlisted operations."""
import contextlib
import grp
import json
import os
import signal
import socketserver
import threading

from .controller import Controller
from .model import PanelError
from .transactions import fingerprint
from .v2_forwarding import with_ssh_protection
from .v2_health import Watchdog
from .v2_resources import HostSampler

MAX_REQUEST = 48 * 1024 * 1024


class Handler(socketserver.StreamRequestHandler):
    def handle(self):
        try:
            raw = self.rfile.readline(MAX_REQUEST + 1)
            if len(raw) > MAX_REQUEST:
                raise PanelError("Request is too large.")
            request = json.loads(raw)
            result = self.server.controller.request(str(request.get("route", "")), request.get("payload", {}),
                                                     request.get("token"), request.get("csrf"), str(request.get("peer", "local")))
            reply = {"ok": True, "result": result}
        except Exception as error:
            reply = {"ok": False, "error": str(error)[:800], "code": getattr(error, "code", "system"), "field": getattr(error, "field", None)}
        self.wfile.write(json.dumps(reply, ensure_ascii=False, allow_nan=False).encode() + b"\n")


class Server(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True


def main():
    if os.geteuid() != 0:
        raise SystemExit("The network worker requires root.")
    controller = Controller()
    controller.store.interrupt_jobs()
    with open(controller.paths.etc / "network.lock", "a") as lock:
        import fcntl
        fcntl.flock(lock, fcntl.LOCK_EX)
        controller.adopt()
        controller.collect()
        controller.recover()
        cfg = controller.store.config()
        controller.engine.apply(controller.combined(cfg), controller.combined(cfg))
        controller.engine.retire_legacy(controller.combined(cfg))
    controller.publish_web_config()
    controller.paths.socket.unlink(missing_ok=True)
    server = Server(str(controller.paths.socket), Handler)
    server.controller = controller
    os.chmod(controller.paths.socket, 0o660)
    os.chown(controller.paths.socket, 0, grp.getgrnam("gremgr").gr_gid)
    stop = threading.Event()

    def management(record, member):
        node = member["node_id"]
        if not member["managed"] or record["owner"] != controller.v2_agent.node_id:
            return None
        if node == controller.v2_agent.node_id:
            return True
        operations = controller.v2_coordinator.journal.read()["operations"].values()
        change = next((op["change"] for op in operations if op["phase"] == "committed" and
                       op["change"]["group_id"] == record["group"]["id"] and
                       op["change"]["expected_revision"] + 1 == record["revision"]), None)
        if not change:
            return None
        try:
            reply = controller.v2_coordinator._response(node, "status", change, fingerprint(change))
            healthy = reply["phase"] == "committed" and reply["revision"] == record["revision"]
            observations = reply.get("health", {})
            if healthy and isinstance(observations, dict):
                controller.v2_remote_health[(record["group"]["id"], node)] = observations
            return healthy
        except (PanelError, OSError, KeyError):
            return False

    monitor = Watchdog(controller.v2_agent, lambda: with_ssh_protection(controller.store.config(), controller.paths),
                       controller.engine.run, management)
    threading.Thread(target=monitor.serve, args=(stop, lambda error: controller.store.event(
        "error", "V2 health checks: " + error[:550])), daemon=True).start()

    sampler = HostSampler(controller.paths)

    def timer():
        while not stop.is_set():
            try:
                controller.tick()
                sampler.snapshot()
            except Exception as error:
                controller.store.event("error", "Background check: " + str(error)[:600])
            stop.wait(1)

    threading.Thread(target=timer, daemon=True).start()

    def shutdown(signum, frame):
        stop.set()
        threading.Thread(target=server.shutdown, daemon=True).start()

    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)
    try:
        server.serve_forever()
    finally:
        stop.set()
        server.server_close()
        controller.executor.shutdown(wait=True, cancel_futures=True)
        controller.v2_executor.shutdown(wait=True, cancel_futures=True)
        with contextlib.suppress(Exception):
            controller.collect()


if __name__ == "__main__":
    main()
