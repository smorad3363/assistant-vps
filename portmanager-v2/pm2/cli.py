"""Fail-closed development CLI; no network mutations in phase 1.

Future feature commands are deliberately unavailable until their safety tests
are complete. Never silently 'succeed' at a tunnel or bandwidth mutation.
"""

import argparse
import contextlib
import errno
import fcntl
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time
import uuid

from . import VERSION
from .errors import PM2Error
from . import services, tunnels, sampler, persistence, bandwidth, dashboard, firewall
from . import config as safe_config
from . import backup, guard, logbook, live, forwarding, limit_windows, port_graph, shaping


ETC = Path(os.environ.get("PM2_ETC", "/etc/portmanager2"))
DATA = Path(os.environ.get("PM2_DATA", "/var/lib/portmanager2"))
OPT = Path(os.environ.get("PM2_OPT", "/opt/portmanager2"))
LOG = Path(os.environ.get("PM2_LOG", "/var/log/portmanager2"))
BIN = Path(os.environ.get("PM2_BIN", "/usr/local/bin/portmanager2"))
V1_BIN = Path("/usr/local/bin/portmanager")
PRIMARY_V2 = "/opt/portmanager2/current/bin/portmanager2"
REQUIRED = ("python3", "ip", "iptables", "iptables-save", "iptables-restore", "ss", "tc")
PREFIX = "portmanager2-"
LOCK = Path("/run/lock/portmanager2.lock")


@contextlib.contextmanager
def mutation_lock(wait=False):
    """Coordinate V2 writers; watchdog may wait for a bounded 180 seconds."""
    try:
        fd = os.open(LOCK, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    except OSError as exc:
        raise PM2Error("E_APPLY", "Cannot open V2 mutation lock") from exc
    try:
        deadline = time.monotonic() + 180 if wait else time.monotonic()
        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError as exc:
                if not wait or time.monotonic() >= deadline:
                    raise PM2Error("E_LOCKED", "Another Port Manager V2 operation is running") from exc
                time.sleep(1)
        yield
    finally:
        os.close(fd)



def response(ok, code, message, details, json_mode):
    """Print one stable machine-readable JSON object or a short text result."""
    payload = {
        "ok": ok,
        "code": code,
        "message": message,
        "details": details,
        "request_id": str(uuid.uuid4()),
    }
    if json_mode:
        print(json.dumps(payload, ensure_ascii=False, sort_keys=True))
    else:
        stream = sys.stdout if ok else sys.stderr
        print(f"[{code}] {message}", file=stream)
        if details:
            print(json.dumps(details, ensure_ascii=False, indent=2), file=stream)


def read_json(path):
    try:
        with path.open("r", encoding="utf-8") as handle:
            return json.load(handle)
    except FileNotFoundError:
        return None
    except PermissionError as exc:
        raise PM2Error("E_PERMISSION", f"Cannot read {path}") from exc
    except (ValueError, OSError) as exc:
        raise PM2Error("E_VALIDATION", f"Invalid state file: {path}") from exc


def owner_check():
    owner = read_json(ETC / "owner.json")
    if not isinstance(owner, dict) or owner.get("product") != "portmanager2":
        raise PM2Error("E_CONFLICT", "Unrecognized or missing V2 ownership marker")
    return owner


def _backend():
    if not shutil.which("iptables"):
        return None
    try:
        result = subprocess.run(
            ["iptables", "--version"], check=False, capture_output=True,
            text=True, timeout=3
        )
    except (OSError, subprocess.TimeoutExpired):
        return "unknown"
    return result.stdout.strip() or result.stderr.strip() or "unknown"


def doctor():
    """Read-only preflight. Unknown values are explicit, never guessed."""
    missing = [item for item in REQUIRED if not shutil.which(item)]
    config = read_json(ETC / "config.json")
    state = read_json(DATA / "state.json")
    owner = read_json(ETC / "owner.json")
    try:
        units = services.preflight()
        unit_state = ("installed_active" if units and units.get("activation") == "active"
                      else "installed_disabled" if units else "not_installed")
        unit_error = None
    except PM2Error as exc:
        unit_state = "conflict"
        unit_error = exc.message
    kernel_ownership = "unknown_no_privilege"
    kernel_drift = None
    if isinstance(state, dict):
        try:
            firewall.check_inventory(firewall.snapshot(), state.get("firewall", {}))
            kernel_ownership = "verified"
            kernel_drift = False
        except PM2Error as exc:
            kernel_ownership = "conflict_or_unreadable"
            kernel_drift = {"code": exc.code, "message": exc.message}
    try:
        forwarding_state = forwarding.preflight()
    except PM2Error as exc:
        forwarding_state = {"unknown": exc.code}
    return {
        "development": True,
        "v1_installed": V1_BIN.is_file() and not V1_BIN.is_symlink(),
        "dependencies_missing": missing,
        "iptables_backend": _backend(),
        "config_schema": config.get("schema_version") if isinstance(config, dict) else None,
        "active_tunnels": sum(bool(x.get("enabled")) for x in config.get("tunnels", []) if isinstance(x, dict)) if isinstance(config, dict) and isinstance(config.get("tunnels"), list) else None,
        "owner_valid": isinstance(owner, dict) and owner.get("product") == "portmanager2",
        "state_present": isinstance(state, dict),
        "network_rules_supported": not missing and _backend() not in (None, "unknown"),
        "iptables_ownership": kernel_ownership,
        "qdisc_ownership": "V2 does not manage tc (V1/foreign qdiscs preserved)",
        "cron_v1": "not_checked",
        "systemd_units": unit_state,
        "systemd_conflict": unit_error,
        "ip_forward": forwarding_state,
        "drift": kernel_drift,
    }


def status():
    config = read_json(ETC / "config.json")
    if config is not None and (
        not isinstance(config, dict) or config.get("schema_version") != 1
    ):
        raise PM2Error("E_UNSUPPORTED", "Unrecognized V2 config schema")
    return {
        "version": VERSION,
        "release_status": "development_bootstrap",
        "tunnel_engine": "development_phase2_network_engine",
        "tunnels": len(config.get("tunnels", [])) if config else 0,
        "generation": config.get("generation", 0) if config else 0,
        "v1_installed": V1_BIN.exists(),
        "v1_integrity_verified": False,  # independent VM/CI validation still required
    }


def limit_list():
    return bandwidth.list_limits()


def uninstall(args):
    """Remove only recognized V2 paths. No iptables, tc or V1 mutations."""
    if os.geteuid() != 0 and not args.dry_run:
        raise PM2Error("E_PERMISSION", "Uninstall requires root")
    owner_check()
    service_marker = services.preflight()
    if guard._read() is not None:
        raise PM2Error("E_CONFLICT", "Pending guarded change must be confirmed/rolled back before uninstall")
    if BIN.is_symlink():
        if os.readlink(BIN) != "/opt/portmanager2/current/bin/portmanager2":
            raise PM2Error("E_CONFLICT", "Unrecognized portmanager2 launcher")
    elif BIN.exists():
        raise PM2Error("E_CONFLICT", "portmanager2 binary is not our symlink")
    marker = read_json(OPT / ".owner.json")
    if not isinstance(marker, dict) or marker.get("product") != "portmanager2":
        raise PM2Error("E_CONFLICT", "Unrecognized V2 release directory")
    current = OPT / "current"
    if current.is_symlink():
        resolved = current.resolve()
        if OPT / "releases" not in resolved.parents:
            raise PM2Error("E_CONFLICT", "V2 release pointer escapes expected directory")
    elif current.exists():
        raise PM2Error("E_CONFLICT", "V2 release pointer is not a symlink")
    forward_info = forwarding.preflight()
    paths = [str(BIN), str(OPT)]
    primary_owned = V1_BIN.is_symlink() and os.readlink(V1_BIN) == PRIMARY_V2
    if primary_owned:
        paths.append(str(V1_BIN))
    if forward_info["dropin_owned"]:
        paths.append(str(forwarding.DROPIN))
    if service_marker is not None:
        paths += [str(services.SYSTEMD / name) for name in services.UNIT_NAMES]
        paths.append(str(services.MARKER))
    if args.purge:
        # A user asking to remove V2 must not unknowingly destroy their only
        # archived V1 recovery binary/cron. Keep the archive unless it was
        # separately restored or manually and intentionally backed up.
        legacy = DATA / "legacy-v1" / "archive.json"
        if legacy.exists() or legacy.is_symlink():
            raise PM2Error("E_CONFLICT", "V1 rollback archive exists; refusing V2 purge. Use uninstall --yes without --purge.")
        paths += [str(ETC), str(DATA), str(LOG)]
    runtime_file = DATA / "state.json"
    if runtime_file.exists() or runtime_file.is_symlink():
        runtime = read_json(runtime_file)
        if not isinstance(runtime, dict):
            raise PM2Error("E_CONFLICT", "Unrecognized V2 firewall state")
        owned = runtime.get("firewall", {})
        firewall.check_inventory(firewall.snapshot(), owned)
    elif (ETC / "config.json").exists():
        raise PM2Error("E_CONFLICT", "Missing V2 firewall inventory; uninstall blocked")
    else:
        runtime, owned = None, {}
    shaper_state = shaping.state_load()
    if shaper_state["interfaces"]:
        paths.append("V2-owned tc clsact on: " + ",".join(shaper_state["interfaces"]))
    if args.dry_run:
        return {"would_remove": paths,
                "would_remove_owned_chains": [chain for table, chain in firewall.ORDER
                                             if chain in owned.get(table, {})],
                "v1_untouched": True}
    if not args.yes:
        if not sys.stdin.isatty():
            raise PM2Error("E_VALIDATION", "Interactive confirmation required or pass --yes")
        if input("Type REMOVE-V2 to uninstall: ").strip() != "REMOVE-V2":
            raise PM2Error("E_VALIDATION", "Uninstall cancelled")
    if args.purge:
        if any(path.is_symlink() for path in (ETC, DATA, LOG)):
            raise PM2Error("E_CONFLICT", "Refusing to purge a symlinked V2 data path")
        if not sys.stdin.isatty():
            raise PM2Error("E_VALIDATION", "Purge requires an additional interactive confirmation")
        if input("Type PURGE-V2-DATA to delete V2 data: ").strip() != "PURGE-V2-DATA":
            raise PM2Error("E_VALIDATION", "Purge cancelled")
    # Remove exact V2-owned police filters before deleting V2's executable.
    # Unknown / drifted clsact state aborts; never flush foreign qdiscs.
    shaping.remove_owned()
    # Remove owned firewall rules *before* deleting the executable. Fail closed.
    new_inventory = owned
    if any(owned.get(table) for table in firewall.CHAINS):
        new_inventory = firewall.reconcile(
            {chain: [] for _, chain in firewall.ORDER}, owned)
    try:
        services.remove()
    except PM2Error:
        if new_inventory != owned:
            try:
                firewall.reconcile(
                    {chain: list(owned.get(table, {}).get(chain, []))
                     for table, chain in firewall.ORDER}, new_inventory)
            except PM2Error as exc:
                raise PM2Error("E_ROLLBACK", "Cannot restore V2-owned rules after unit error") from exc
        raise
    if runtime is not None and new_inventory != owned:
        retained = dict(runtime, firewall=new_inventory, applied_generation=-1)
        safe_config.atomic_json(runtime_file, retained)
    forwarding.remove_dropin()
    if BIN.is_symlink():
        BIN.unlink()
    if primary_owned:
        # Only remove the V2-owned public alias. Leave a restored regular
        # V1 executable and all archived V1 config/data completely untouched.
        if not V1_BIN.is_symlink() or os.readlink(V1_BIN) != PRIMARY_V2:
            raise PM2Error("E_CONFLICT", "Public command alias changed during uninstall")
        V1_BIN.unlink()
    shutil.rmtree(OPT)
    if args.purge:
        for path in (ETC, DATA, LOG):
            if path.is_symlink():
                raise PM2Error("E_CONFLICT", f"Refusing to follow symlink: {path}")
            if path.exists():
                shutil.rmtree(path)
    return {"removed": paths, "v1_untouched": True}


def parser():
    p = argparse.ArgumentParser(
        prog="portmanager2",
        description="Port Manager V2 — IPv4 tunnel and per-port live monitoring (development)"
    )
    p.add_argument("--version", action="version", version=VERSION)
    sub = p.add_subparsers(dest="command")
    sub.add_parser("help")
    for name in ("doctor", "status"):
        sub.add_parser(name).add_argument("--json", action="store_true")
    tunnel = sub.add_parser("tunnel")
    tunnel.add_argument("operation", nargs="?")
    tunnel.add_argument("args", nargs=argparse.REMAINDER)
    limits = sub.add_parser("limits")
    limits.add_argument("operation", nargs="?")
    limits.add_argument("args", nargs=argparse.REMAINDER)
    rem = sub.add_parser("uninstall")
    rem.add_argument("--purge", action="store_true")
    rem.add_argument("--yes", action="store_true")
    rem.add_argument("--dry-run", action="store_true")
    report = sub.add_parser("report")
    report.add_argument("--window", choices=("1h", "24h", "7d"), required=True)
    report.add_argument("--json", action="store_true")
    live_parser = sub.add_parser("live")
    live_parser.add_argument("--interval", type=int, default=5)
    live_parser.add_argument("--tunnel")
    live_parser.add_argument("--top", type=int, default=20)
    live_parser.add_argument("--all-ports", action="store_true")
    live_parser.add_argument("--once", action="store_true")
    live_parser.add_argument("--json", action="store_true")
    graph_parser = sub.add_parser("graph", help="Live per-port graphs, rolling 10-minute average")
    graph_parser.add_argument("--refresh", type=int, default=5, help="2..60 seconds")
    graph_parser.add_argument("--window", choices=("10m",), default="10m")
    graph_parser.add_argument("--tunnel")
    graph_parser.add_argument("--top", type=int, default=20)
    graph_parser.add_argument("--all-ports", action="store_true")
    graph_parser.add_argument("--once", action="store_true")
    graph_parser.add_argument("--json", action="store_true")
    logs_parser = sub.add_parser("logs")
    logs_parser.add_argument("--lines", type=int, default=100)
    for name in ("sample", "restore", "backup", "confirm", "rollback-pending"):
        cmd = sub.add_parser(name)
        cmd.add_argument("args", nargs=argparse.REMAINDER)
    return p


def main(argv=None):
    p = parser()
    args = p.parse_args(argv)
    if args.command is None:
        return dashboard.menu() if sys.stdin.isatty() else (p.print_help() or 0)
    if args.command == "help":
        p.print_help()
        return 0
    json_mode = bool(getattr(args, "json", False)) or (
        getattr(args, "args", []) and "--json" in args.args
    )
    try:
        if args.command == "doctor":
            data = doctor()
            response(True, "OK", "Read-only development diagnostics", data, json_mode)
        elif args.command == "status":
            response(True, "OK", "Development bootstrap status", status(), json_mode)
        elif args.command == "tunnel":
            details = tunnels.handle(args.operation, args.args, mutation_lock)
            if args.operation in ("create", "update", "enable", "disable", "delete", "apply") and not details.get("dry_run"):
                logbook.record("TUNNEL_" + args.operation.upper(), generation=details.get("generation"))
            response(True, "OK", "Tunnel operation complete", details, json_mode)
        elif args.command == "limits":
            if args.operation == "list":
                saved = shaping.schedule_load()
                state = shaping.state_load()
                response(True, "OK", "Managed clsact bandwidth policies", {
                    "supported": True, "policies": saved["policies"],
                    "active_filters": len(state["filters"]),
                    "limitations": "No V1 or foreign clsact coexistence; disabled without systemd sampler"
                }, json_mode)
            elif args.operation == "schedule-list":
                saved = shaping.schedule_load()
                state = shaping.state_load()
                response(True, "OK", "Scheduled per-port limits", {
                    "policies": saved["policies"], "active_filters": state["filters"]
                }, json_mode)
            elif args.operation == "schedule-install":
                lp = argparse.ArgumentParser(prog="portmanager2 limits schedule-install")
                lp.add_argument("--file", required=True)
                lp.add_argument("--json", action="store_true")
                opts = lp.parse_args(args.args)
                with mutation_lock():
                    details = shaping.install_schedule(opts.file)
                    result = shaping.reconcile()
                    if details["saved"]:
                        services.activate()
                    details.update(result)
                response(True, "OK", "Schedule installed and minute reconciliation activated", details, json_mode or opts.json)
            elif args.operation == "schedule-apply":
                with mutation_lock():
                    details = shaping.reconcile()
                response(True, "OK", "Scheduled port limits reconciled", details, json_mode)

            elif args.operation == "schedule-preview":
                lp = argparse.ArgumentParser(prog="portmanager2 limits schedule-preview")
                lp.add_argument("--file", required=True)
                lp.add_argument("--at")
                lp.add_argument("--json", action="store_true")
                opts = lp.parse_args(args.args)
                preview = limit_windows.preview_json_file(opts.file, opts.at)
                response(True, "OK", "Read-only 2.1 schedule preview; no shaping applied",
                         preview, json_mode or opts.json)
            elif args.operation in ("set", "remove", "schedule-add", "schedule-remove"):
                bandwidth.mutation()
            else:
                raise PM2Error("E_VALIDATION", "Unknown limits command")
        elif args.command == "confirm":
            if not args.args:
                raise PM2Error("E_VALIDATION", "confirm requires change UUID")
            with mutation_lock():
                payload = guard.confirm(args.args[0])
            response(True, "OK", "Protected change confirmed", payload, json_mode)
        elif args.command == "rollback-pending":
            if not args.args:
                raise PM2Error("E_VALIDATION", "rollback-pending requires change UUID")
            with mutation_lock(wait=True):
                payload = guard.rollback(args.args[0])
            response(True, "OK", "Protected change rolled back", payload, json_mode)
        elif args.command == "sample":
            with mutation_lock():
                payload = sampler.sample()
                payload["shaping"] = shaping.reconcile()
            logbook.record("TRAFFIC_SAMPLED")
            response(True, "OK", "Traffic counters sampled", payload, json_mode)
        elif args.command == "restore":
            with mutation_lock():
                payload = persistence.restore()
                payload["shaping"] = shaping.reconcile(allow_kernel_reset=True)
            response(True, "OK", "V2-owned rules reconciled after reboot", payload, json_mode)
        elif args.command == "backup":
            argv = args.args or []
            operation = argv[0] if argv else None
            if operation == "list":
                details = backup.list_backups()
            elif operation == "create":
                with mutation_lock():
                    details = backup.create()
            elif operation == "restore" and len(argv) >= 2:
                dry_run = "--dry-run" in argv
                with mutation_lock() if not dry_run else contextlib.nullcontext():
                    details = backup.restore(argv[1], dry_run)
            else:
                raise PM2Error("E_VALIDATION", "Usage: backup create|list|restore <id> [--dry-run]")
            response(True, "OK", "Backup operation completed", details, json_mode)
        elif args.command == "report":
            payload = sampler.report(args.window)
            response(True, "OK", "Traffic report", payload, json_mode)
        elif args.command in ("live", "graph"):
            return port_graph.watch(
                refresh=args.interval if args.command == "live" else args.refresh,
                tunnel=args.tunnel, top=args.top, active_only=not args.all_ports,
                once=args.once or not sys.stdout.isatty(),
                json_mode=args.json,
            )
        elif args.command == "logs":
            for line in logbook.tail(args.lines):
                print(line)
        elif args.command == "uninstall":
            if args.dry_run:
                details = uninstall(args)
            else:
                with mutation_lock():
                    details = uninstall(args)
            response(True, "OK", "V2 removed" if not args.dry_run else "Uninstall preview",
                     details, json_mode)
        else:
            raise PM2Error(
                "E_UNSUPPORTED",
                "This command is unavailable in the development bootstrap. No system changes were made.",
                {"phase": "phase_1", "command": args.command}
            )
        return 0
    except PM2Error as exc:
        response(False, exc.code, exc.message, exc.details, json_mode)
        return exc.exit_code
    except (OSError, ValueError) as exc:
        response(False, "E_APPLY", "Filesystem operation failed", {"error": str(exc)}, json_mode)
        return 6


if __name__ == "__main__":
    sys.exit(main())
