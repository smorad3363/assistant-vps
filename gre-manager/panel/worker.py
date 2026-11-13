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
    controller.adopt()
    with open(controller.paths.etc / "network.lock", "a") as lock:
        import fcntl
        fcntl.flock(lock, fcntl.LOCK_EX)
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

    def timer():
        while not stop.is_set():
            try:
                controller.tick()
            except Exception as error:
                controller.store.event("error", "Background check: " + str(error)[:600])
            stop.wait(5)

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
        with contextlib.suppress(Exception):
            controller.collect()


if __name__ == "__main__":
    main()
