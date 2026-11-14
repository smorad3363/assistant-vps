"""Root-only forced-command peer helper; no listening management port."""
import contextlib
import fcntl
import json
import os
from pathlib import Path
import re
import sys
import time
import uuid

from .engine import Engine, pair_values, run
from . import __version__
from .model import DEFAULTS, PanelError, address, integer
from .store import Paths, atomic_json


def validate_peer(data):
    if not isinstance(data, dict) or not re.fullmatch(r"[0-9a-f]{10}", str(data.get("id", ""))):
        raise PanelError("Invalid peer ID.")
    g = data.get("gre", {})
    local, remote = address(g.get("outer_local", "")), address(g.get("outer_peer", ""))
    expected = pair_values(local, remote)
    if local == remote or any(g.get(key) != value for key, value in expected.items()):
        raise PanelError("The GRE identity does not match its endpoints.")
    expected["mtu"] = integer(g.get("mtu"), 576, 1476, "mtu")
    return {"id": data["id"], "kind": "peer", "gre": expected,
            "service_ip": address(data.get("service_ip", "")), "enabled": bool(data.get("enabled", True))}


def read_peers(paths):
    path = paths.etc / "peers.json"
    if path.exists():
        return json.loads(path.read_text())
    peers = []
    for original in (paths.etc / "pairs").glob("*.json"):
        c = json.loads(original.read_text())
        if c.get("role") == "foreign":
            g = pair_values(c["outer_local"], c["outer_peer"])
            g["mtu"] = c["mtu"]
            peers.append({"id": c["id"], "kind": "peer", "gre": g, "enabled": True, "service_ip": c["service_ip"]})
    return peers


def combined(paths, peers):
    path = paths.config
    config = json.loads(path.read_text()) if path.exists() else {"settings": dict(DEFAULTS), "connections": []}
    config["connections"] = config["connections"] + peers
    return config


def recover(paths, transaction, engine):
    if not re.fullmatch(r"[0-9a-f]{16}", transaction):
        raise PanelError("Invalid transaction ID.")
    path = paths.etc / "transactions" / (transaction + ".json")
    if not path.exists():
        return
    snapshot = json.loads(path.read_text())
    current = read_peers(paths)
    engine.apply(combined(paths, snapshot["previous"]), combined(paths, current))
    atomic_json(paths.etc / "peers.json", snapshot["previous"])
    path.unlink()


def action(paths, request, engine=None):
    engine = engine or Engine(paths)
    # Reconcile expired leases even if a rollback unit failed or was killed.
    # Active leases retain their full commit window.
    for pending in (paths.etc / "transactions").glob("*.json"):
        if json.loads(pending.read_text()).get("deadline", 0) <= time.time():
            recover(paths, pending.stem, engine)
    peers = read_peers(paths)
    operation = request.get("action")
    if operation == "status":
        return {"version": __version__, "addresses": engine.interfaces(), "peers": len(peers),
                "pair_profiles": [{"gre_id": x["gre"]["id"], "service_ip": x["service_ip"], "mtu": x["gre"]["mtu"]} for x in peers]}
    if operation == "revoke-key":
        import pwd
        import tempfile
        username = str(request.get("username", ""))
        parts = str(request.get("key", "")).split()
        if not re.fullmatch(r"[a-z_][a-z0-9_-]{0,31}", username) or len(parts) < 2 or len(parts[1]) > 4096:
            raise PanelError("Invalid management public key.")
        path = Path(pwd.getpwnam(username).pw_dir) / ".ssh" / "authorized_keys"
        content = path.read_text()
        filtered = "".join(line + "\n" for line in content.splitlines() if not (parts[1] in line and "gremgr-peer" in line and "command=" in line))
        stat = path.stat()
        fd, temporary = tempfile.mkstemp(dir=path.parent, prefix=".gremgr-key-")
        try:
            os.fchmod(fd, 0o600)
            os.fchown(fd, stat.st_uid, stat.st_gid)
            with os.fdopen(fd, "w") as out:
                out.write(filtered)
                out.flush()
                os.fsync(out.fileno())
            os.replace(temporary, path)
        finally:
            if os.path.exists(temporary): os.unlink(temporary)
        return {"revoked": True}
    if operation == "prepare":
        changes = request.get("changes", [{"peer": request.get("peer"), "remove": request.get("remove", False)}])
        if not isinstance(changes, list) or not 1 <= len(changes) <= 128:
            raise PanelError("Invalid peer changes.")
        changes = [(validate_peer(x.get("peer")), bool(x.get("remove"))) for x in changes]
        identity = uuid.uuid4().hex[:16]
        directory = paths.etc / "transactions"
        directory.mkdir(mode=0o700, exist_ok=True)
        # Do not stack uncommitted network transactions from separate controllers.
        if list(directory.glob("*.json")):
            raise PanelError("Another peer change is still awaiting commit.", "busy")
        snapshot = {"previous": peers, "deadline": time.time() + 120}
        path = directory / (identity + ".json")
        atomic_json(path, snapshot)
        updated = list(peers)
        for peer, remove in changes:
            updated = [x for x in updated if x["id"] != peer["id"]]
            if not remove:
                updated.append(peer)
        try:
            run("systemd-run", "--quiet", "--unit=gremgr-peer-rollback-" + identity, "--on-active=120s", "--timer-property=AccuracySec=1s",
                "/usr/local/sbin/gremgr-peer", "--recover", identity)
            engine.apply(combined(paths, updated), combined(paths, peers))
            atomic_json(paths.etc / "peers.json", updated)
            engine.retire_legacy(combined(paths, updated))
        except Exception:
            with contextlib.suppress(Exception):
                recover(paths, identity, engine)
            raise
        return {"transaction": identity, "addresses": engine.interfaces()}
    if operation in ("commit", "rollback"):
        identity = str(request.get("transaction", ""))
        if not re.fullmatch(r"[0-9a-f]{16}", identity):
            raise PanelError("Invalid transaction ID.")
        if operation == "rollback":
            recover(paths, identity, engine)
        else:
            (paths.etc / "transactions" / (identity + ".json")).unlink(missing_ok=True)
        run("systemctl", "stop", "gremgr-peer-rollback-" + identity + ".timer", check=False)
        return {"committed": operation == "commit"}
    raise PanelError("Unsupported peer operation.")


def main():
    if os.geteuid() != 0:
        raise SystemExit("Run the peer helper as root.")
    paths = Paths()
    with open(paths.etc / "network.lock", "a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        engine = Engine(paths)
        if sys.argv[1:] == ["--restore"]:
            for pending in (paths.etc / "transactions").glob("*.json"):
                recover(paths, pending.stem, engine)
            engine.apply(combined(paths, read_peers(paths)))
            return
        if len(sys.argv) == 3 and sys.argv[1] == "--recover":
            recover(paths, sys.argv[2], engine)
            return
        raw = sys.stdin.buffer.read(1048577)
        if len(raw) > 1048576:
            raise PanelError("Peer request is too large.")
        result = action(paths, json.loads(raw), engine)
        print(json.dumps({"ok": True, "result": result}))


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print(json.dumps({"ok": False, "error": str(error)[:800], "code": getattr(error, "code", "peer")}))
        sys.exit(1)
