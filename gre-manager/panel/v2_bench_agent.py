"""Bounded benchmark leases and an isolated test link for each direction."""
from contextlib import ExitStack
import fcntl
import json
import os
from pathlib import Path
import re
import secrets
import shlex
import signal
import sys
import time

from .engine import Engine
from .model import DEFAULTS, PanelError, address, integer
from .store import Paths, atomic_json, topology_node_id
from .transactions import fingerprint, identity
from .v2_benchmark import open_receiver, receive, send
from .v2_drivers import driver_for
from .v2_forwarding import gre_link
from .v2_resources import boot_id

METHODS = ("gre", "ipip")
MAX_SECONDS = 300
MAX_RATE = 12_500_000
MAX_BYTES = 1_000_000_000
ACTIVE = {"reserved", "starting", "ready", "active"}
LEASE_FIELDS = ("job_id", "method", "direction", "nodes", "first", "second", "seconds", "rate", "budget")


def policy(paths):
    try:
        limits = json.loads(paths.config.read_text())["settings"].get("v2_limits", {})
    except FileNotFoundError:
        limits = {}
    listed = [max(1, int(value * 125_000)) for value in limits.values() if value]
    return {"max_seconds": MAX_SECONDS, "rate": min([MAX_RATE, *listed]), "bytes": MAX_BYTES}


def key_for(payload):
    return fingerprint([identity(payload.get("job_id")), payload.get("method"), payload.get("direction")])[:24]


def record_file(paths, key):
    if not re.fullmatch(r"[a-f0-9]{24}", key):
        raise PanelError("Invalid benchmark operation ID.", "identity")
    return paths.var / "v2-bench-agent" / (key + ".json")


def load(path):
    try:
        return json.loads(path.read_text())
    except FileNotFoundError:
        return None


def observed(task):
    return {field: task[field] for field in ("phase", "port", "receipt", "error", "cleaned", "node_id", "task_key") if field in task}


def validate(payload, engine, paths):
    details = policy(paths)
    nodes = payload.get("nodes")
    if not isinstance(nodes, list) or len(nodes) != 2:
        raise PanelError("Choose two different benchmark nodes.", "participant")
    nodes = [identity(node) for node in nodes]
    here, other = address(payload.get("first")), address(payload.get("second"))
    local = topology_node_id(paths)
    if local not in nodes or nodes[0] == nodes[1] or here == other:
        raise PanelError("Choose two different benchmark endpoints.", "participant")
    side = nodes.index(local)
    if (here, other)[side] not in engine.interfaces():
        raise PanelError("The benchmark source address is unavailable on this node.", "local_ip")
    direction, method = payload.get("direction"), payload.get("method")
    if direction not in (0, 1) or type(direction) is not int or method not in METHODS:
        raise PanelError("This test method or direction is unavailable.", "method")
    return {"job_id": identity(payload.get("job_id")), "method": method, "direction": direction,
            "local": (here, other)[side], "remote": (other, here)[side], "side": side,
            "receiver": side != direction, "nodes": nodes, "first": here, "second": other,
            "seconds": integer(payload.get("seconds"), 1, details["max_seconds"] // 2, "duration_s"),
            "rate": integer(payload.get("rate"), 1, details["rate"], "rate"),
            "budget": integer(payload.get("budget"), 1, details["bytes"], "budget")}


def configure(paths, engine, owner, action, payload):
    node_id = topology_node_id(paths)
    if action == "benchmark/capabilities":
        return {"node_id": node_id, "addresses": sorted(engine.interfaces()),
                "methods": [method for method in METHODS if engine.run("modprobe", "-nq", driver_for({"method": method}).module,
                                                                        check=False).returncode == 0], **policy(paths)}
    if not isinstance(payload, dict) or action not in {"benchmark/offer", "benchmark/start", "benchmark/status", "benchmark/cancel"}:
        raise PanelError("Unsupported benchmark action.", "benchmark")
    key = key_for(payload)
    file = record_file(paths, key)
    task = load(file)
    if task and task["owner"] != owner:
        raise PanelError("This benchmark belongs to another owner.", "owner")
    now = time.time()
    if task and (task["phase"] not in ACTIVE or task["boot"] != boot_id() or task["expires"] < now) and not task.get("cleaned"):
        cleanup(paths, key, engine)
        task = load(file)
    if action == "benchmark/status":
        if task and task["phase"] in ACTIVE and (task["boot"] != boot_id() or task["expires"] < now):
            return dict(observed(task), phase="interrupted")
        return observed(task) if task else {"phase": "unknown", "cleaned": True, "node_id": node_id, "task_key": key}
    if action == "benchmark/cancel":
        if task and task["phase"] == "reserved":
            task.pop("approval", None)
            atomic_json(file, dict(task, phase="cancelled"))
        elif task and task["phase"] in ACTIVE:
            file.with_suffix(".stop").touch()
        return {"phase": "stopping" if task else "unknown"}
    cooked = validate(payload, engine, paths)
    digest = fingerprint([owner, {name: cooked[name] for name in LEASE_FIELDS}])
    if task:
        if digest != task["digest"]:
            raise PanelError("This benchmark operation already has other settings.", "idempotency")
        if action == "benchmark/offer" and task["phase"] == "reserved" and task["expires"] > now and task["boot"] == boot_id():
            return dict(observed(task), approval=task["approval"])
        if action == "benchmark/start" and task["phase"] != "reserved":
            return observed(task)
    elif action == "benchmark/start":
        raise PanelError("Both nodes must approve the benchmark before starting.", "auth")
    if action == "benchmark/start":
        return launch(paths, engine, file, task, payload, now)
    if task:
        raise PanelError("The benchmark approval expired. Start a new job.", "expired")
    family = []
    for candidate in file.parent.glob("*.json"):
        peer = load(candidate)
        if peer and peer["boot"] == boot_id() and peer["expires"] >= now and peer["phase"] in ACTIVE:
            if (peer["owner"], peer["request"]["job_id"]) != (owner, cooked["job_id"]):
                raise PanelError("Another benchmark is active on this host.", "busy")
            family.append(peer["request"])
        elif peer and not peer.get("cleaned"):
            cleanup(paths, candidate.stem, engine)
            if not load(candidate).get("cleaned"):
                raise PanelError("A previous benchmark is still removing its own resources.", "cleanup_pending")
        elif peer and peer["expires"] < now - 86400:
            candidate.unlink(missing_ok=True)
            candidate.with_suffix(".stop").unlink(missing_ok=True)
    limits = policy(paths)
    if (len(family) >= len(METHODS) or sum(item["rate"] for item in family) + cooked["rate"] > limits["rate"]
            or sum(item["budget"] for item in family) + cooked["budget"] > limits["bytes"]):
        raise PanelError("This benchmark exceeds the shared host budget.", "rate_limit")
    expires = int(now) + 50
    approval = {"node_id": node_id, "task_key": key, "digest": digest,
                "nonce": secrets.token_hex(32), "expires": expires}
    task = {"owner": owner, "request": cooked, "phase": "reserved", "boot": boot_id(), "cleaned": True,
            "node_id": node_id, "task_key": key, "expires": expires, "digest": digest, "approval": approval}
    atomic_json(file, task)
    return dict(observed(task), approval=approval)


def launch(paths, engine, file, task, payload, now):
    cooked = task["request"]
    approvals = payload.get("approvals")
    if (not isinstance(approvals, list) or len(approvals) != 2 or task["boot"] != boot_id() or task["expires"] <= now
            or any(not valid_approval(approval, node, task, now) for node, approval in zip(cooked["nodes"], approvals))
            or approvals[cooked["side"]] != task["approval"]):
        raise PanelError("The two approved endpoints did not agree on this benchmark lease.", "auth")
    cooked["secret"] = fingerprint([task["digest"], *(approval["nonce"] for approval in approvals)])
    cooked["port"] = None if cooked["receiver"] else integer(payload.get("port"), 1024, 65535, "port")
    task.update(phase="starting", expires=now + cooked["seconds"] + 55, cleaned=False)
    task.pop("approval", None)
    atomic_json(file, task)
    try:
        flags = ["--setenv=PYTHONPATH=" + str(Path(__file__).resolve().parent.parent)]
        if home := os.environ.get("GRE_PANEL_HOME"):
            flags.append("--setenv=GRE_PANEL_HOME=" + home)
        key = task["task_key"]
        command = [sys.executable, "-m", "panel.v2_bench_agent", key]
        cleanup = "--property=ExecStopPost=" + shlex.join([*command, "--cleanup"])
        engine.run("systemd-run", "--quiet", "--collect", "--unit=gremgr-bench-" + key,
                   "--property=RuntimeMaxSec=" + str(cooked["seconds"] + 50), cleanup, *flags, *command)
    except PanelError:
        atomic_json(file, dict(task, phase="failed", error="launch"))
        raise
    return observed(task)


def valid_approval(value, node, task, now):
    return (isinstance(value, dict) and value.get("node_id") == node and value.get("digest") == task["digest"]
            and value.get("task_key") == task["task_key"] and type(value.get("expires")) is int
            and 0 < value["expires"] - now <= 60 and isinstance(value.get("nonce"), str)
            and re.fullmatch(r"[a-f0-9]{64}", value["nonce"]))


def exact_rule(engine, args):
    engine.run("iptables", "-w", "5", "-I", "INPUT", "1", *args)


def test_link(owner, request):
    local, remote = request["first"], request["second"]
    scope = fingerprint([owner, request["job_id"], request["direction"]])[:32]
    return gre_link(scope, {"ip": local}, {"method": request["method"], "service_ip": remote}, receiving=bool(request["side"]))


def pending_for_owner(paths, owner=None):
    return any((owner is None or task["owner"] == owner) and
               (not task.get("cleaned") or task["phase"] in ACTIVE and task["expires"] > time.time())
               for file in (paths.var / "v2-bench-agent").glob("*.json") if (task := load(file)))


def cleanup(paths, key, engine, outcome=None):
    file = record_file(paths, key)
    task = load(file)
    if not task or task.get("cleaned"):
        return
    failures = []
    with (paths.etc / "kernel-apply.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        try:
            output = engine.run("iptables-save", "-t", "filter").stdout
            for line in output.splitlines():
                if line.startswith("-A INPUT ") and "gmpbench:" + key in line:
                    rule = shlex.split(line)
                    if "--comment" in rule and rule[rule.index("--comment") + 1] == "gmpbench:" + key:
                        try:
                            engine.run("iptables", "-w", "5", "-D", *rule[1:])
                        except PanelError:
                            failures.append("rule")
        except (PanelError, OSError):
            failures.append("firewall")
        try:
            engine.remove_gre(test_link(task["owner"], task["request"]))
        except (PanelError, OSError):
            failures.append("device")
    file.with_suffix(".stop").unlink(missing_ok=True)
    if outcome:
        task.update(outcome)
    elif task["phase"] in ACTIVE:
        task["phase"] = "interrupted"
    task.pop("approval", None)
    task["request"].pop("secret", None)
    task["cleaned"] = not failures
    if failures:
        task["error"] = "cleanup_pending"
    elif task.get("error") == "cleanup_pending":
        task.pop("error")
    atomic_json(file, task)


def carrier_filter(link):
    rule = driver_for(link).firewall(link)
    if link.get("method", "gre") == "gre":
        size = "0>>22&0x3C"
        match = f"{size}@0&0xF000FFFF=0x20000800 && {size}@4=0x{link['key']:08x}"
        rule += ["-m", "u32", "--u32", match]
    return rule


def execute(paths, key, engine=None):
    file = record_file(paths, key)
    task = load(file)
    if not task or task["phase"] != "starting" or task["boot"] != boot_id():
        return
    engine = engine or Engine(paths)
    request = task["request"]
    link = test_link(task["owner"], request)
    token = bytes.fromhex(request["secret"])
    label = ["-m", "comment", "--comment", "gmpbench:" + key, "-j", "ACCEPT"]
    stop = False

    def terminate(*_):
        nonlocal stop
        stop = True

    def cancelled():
        return stop or file.with_suffix(".stop").exists()

    def change(**values):
        task.update(values)
        atomic_json(file, task)

    signal.signal(signal.SIGTERM, terminate)
    signal.signal(signal.SIGINT, terminate)
    try:
        with ExitStack() as owned:
            with (paths.etc / "kernel-apply.lock").open("a") as lock:
                fcntl.flock(lock, fcntl.LOCK_EX)
                interfaces = engine.preflight({"settings": DEFAULTS, "connections": [], "v2_devices": [link]})
                if request["method"] == "ipip":
                    observed_links = json.loads(engine.run("ip", "-j", "-d", "link", "show", "type", "ipip").stdout)
                    for row in observed_links:
                        data = row.get("linkinfo", {}).get("info_data", {})
                        if "UP" in row.get("flags", []) and (data.get("local") in (None, "0.0.0.0")
                                                             or data.get("remote") in (None, "0.0.0.0")):
                            raise PanelError("An active wildcard IPIP interface already uses this host.", "device_conflict")
                engine.ensure_gre(link, interfaces)
                exact_rule(engine, ["-i", interfaces[request["local"]], "-s", request["remote"], "-d", request["local"],
                                    *carrier_filter(link), *label])
            incoming = ["-i", link["tunnel"], "-s", link["peer_tun"], "-d", link["local_tun"], "-p", "tcp"]
            if request["receiver"]:
                listener = owned.enter_context(open_receiver(link["local_tun"], link["tunnel"]))
                port = listener.getsockname()[1]
                exact_rule(engine, [*incoming, "--dport", str(port), *label])
                change(phase="ready", port=port)
                receipt = receive(listener, link["peer_tun"], token, request["seconds"], request["budget"],
                                  lambda value: change(phase="active", receipt=value), cancelled)
                outcome = {"phase": "done" if receipt else "failed", "receipt": receipt,
                           "error": None if receipt else "no_peer"}
            else:
                exact_rule(engine, [*incoming, "--sport", str(request["port"]), "-m", "conntrack", "--ctstate", "ESTABLISHED", *label])
                change(phase="active")
                send(link["local_tun"], link["peer_tun"], request["port"], token, request["seconds"], request["rate"],
                     request["budget"], device=link["tunnel"], cancelled=cancelled)
                outcome = {"phase": "done"}
    except (PanelError, OSError, ValueError) as error:
        outcome = {"phase": "failed", "error": getattr(error, "code", "path_unavailable")}
    cleanup(paths, key, engine, outcome)


if __name__ == "__main__":
    paths = Paths()
    if sys.argv[2:] == ["--cleanup"]:
        cleanup(paths, sys.argv[1], Engine(paths))
    else:
        execute(paths, sys.argv[1])
