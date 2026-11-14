"""Noninteractive installation/diagnostic commands. Management lives in the UI."""
import argparse
import contextlib
import json
import os
import secrets
import sys

from . import __version__
from .controller import Controller
from .engine import discovered_ssh_ports, run
from .store import Store


def main():
    parser = argparse.ArgumentParser(description="GRE Manager web panel; no interactive Bash menus.")
    parser.add_argument("command", choices=["init", "status", "recover", "reset-password"], nargs="?", default="status")
    parser.add_argument("--port", type=int, default=None)
    args = parser.parse_args()
    if os.geteuid() != 0 and not os.environ.get("GRE_PANEL_HOME"):
        raise SystemExit("Run with sudo/root.")
    store = Store()
    cfg = store.config()
    if args.command == "init":
        if not store.secret("password"):
            cfg["settings"]["username"] = os.environ.get("GRE_PANEL_USERNAME") or "admin_" + secrets.token_hex(4)
        if args.port is not None:
            from .model import integer
            cfg["settings"]["port"] = integer(args.port, 1024, 65535, "port")
        with contextlib.suppress(Exception):
            cfg["settings"]["ssh_ports"] = sorted(set(cfg["settings"]["ssh_ports"] + discovered_ssh_ports()))
        store.save(cfg)
        if not store.secret("password"):
            password = os.environ.get("GRE_PANEL_PASSWORD") or secrets.token_urlsafe(18)
            store.set_password(password)
            # First-install credentials are printed once, never sent to journald.
            print("Username: " + cfg["settings"]["username"])
            print("Password: " + password)
    elif args.command == "reset-password":
        password = os.environ.get("GRE_PANEL_PASSWORD") or secrets.token_urlsafe(18)
        store.set_password(password)
        print("Username: " + cfg["settings"]["username"])
        print("Password: " + password)
    elif args.command == "recover":
        import fcntl
        controller = Controller(store)
        with open(store.paths.etc / "network.lock", "a") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            controller.recover()
    else:
        print("GRE Manager " + __version__)
        print("Manage all connections in the web panel:")
    hostname = cfg["settings"].get("hostname") or "SERVER_IP"
    print(f"https://{hostname}:{cfg['settings']['port']}")


if __name__ == "__main__":
    main()
