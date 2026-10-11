"""Stable V2 tunnel CLI: list/show/create/update/enable/disable/delete/apply/check."""
import argparse
import json
import os
import sys
from . import config, firewall, transaction, guard, shaping
from .errors import PM2Error
from .validation import make_tunnel


def _arguments(operation, argv):
    parser = argparse.ArgumentParser(prog=f"portmanager2 tunnel {operation}")
    if operation in ("show", "update", "enable", "disable", "delete"):
        parser.add_argument("id")
    if operation in ("create", "update"):
        for name in ("name", "listen-ip", "interface", "protocol", "mode",
                     "target-ip"):
            parser.add_argument("--" + name, required=True)
        parser.add_argument("--mapping")
        parser.add_argument("--exclude")
        parser.add_argument("--ack-all-ports", action="store_true")
    if operation in ("create", "update", "enable", "disable", "delete", "apply"):
        parser.add_argument("--dry-run", action="store_true")
    if operation == "delete":
        parser.add_argument("--yes", action="store_true")
    if operation in ("list", "show", "check"):
        parser.add_argument("--json", action="store_true")
    try:
        return parser.parse_args(argv)
    except SystemExit as exc:
        raise PM2Error("E_VALIDATION", "Invalid tunnel command arguments") from exc


def _proposal(operation, cfg, args):
    tunnel_list = list(cfg["tunnels"])
    if operation == "create":
        item = make_tunnel(name=args.name, listen_ip=args.listen_ip,
                           interface=args.interface, protocol=args.protocol,
                           mode=args.mode, mapping=args.mapping,
                           exclude=args.exclude, target_ip=args.target_ip,
                           ack_all_ports=args.ack_all_ports)
        tunnel_list.append(item)
    elif operation == "update":
        old = config.get(tunnel_list, args.id)
        item = make_tunnel(ident=args.id, enabled=old["enabled"],
                           name=args.name, listen_ip=args.listen_ip,
                           interface=args.interface, protocol=args.protocol,
                           mode=args.mode, mapping=args.mapping,
                           exclude=args.exclude, target_ip=args.target_ip,
                           ack_all_ports=args.ack_all_ports)
        tunnel_list = [item if t["id"] == args.id else t for t in tunnel_list]
    elif operation in ("enable", "disable"):
        old = config.get(tunnel_list, args.id)
        item = dict(old, enabled=operation == "enable")
        tunnel_list = [item if t["id"] == args.id else t for t in tunnel_list]
    elif operation == "delete":
        config.get(tunnel_list, args.id)
        tunnel_list = [t for t in tunnel_list if t["id"] != args.id]
    from .validation import validate_collection
    validate_collection(tunnel_list)
    return config.replace(cfg, tunnel_list)


def handle(operation, argv, lock):
    if operation not in ("list", "show", "create", "update", "enable",
                         "disable", "delete", "apply", "check"):
        raise PM2Error("E_VALIDATION", "Unknown tunnel operation",
                       {"operation": operation})
    args = _arguments(operation, argv)
    if operation == "list":
        return {"tunnels": config.load(transaction.CONFIG)["tunnels"]}
    if operation == "show":
        cfg = config.load(transaction.CONFIG)
        return {"tunnel": config.get(cfg["tunnels"], args.id)}
    if operation == "check":
        cfg, runtime = transaction.state()
        try:
            if guard._read() is not None:
                raise PM2Error("E_CONFLICT", "Protected change awaits confirmation")
            report = transaction.preflight(cfg, runtime, allow_protected=True)
            public = {key: value for key, value in report.items()
                      if not key.startswith("_")}
            return {"safe": True, **public}
        except PM2Error as exc:
            return {"safe": False, "code": exc.code, "reason": exc.message}
    if operation == "apply":
        if args.dry_run:
            cfg, runtime = transaction.state()
            return {"dry_run": True, "rules": firewall.compile_rules(cfg)}
        with lock():
            cfg = config.load(transaction.CONFIG)
            if guard._read() is not None:
                raise PM2Error("E_CONFLICT", "Protected change pending; confirm or rollback first")
            return transaction.apply(cfg)
    with lock() if not args.dry_run else _null():
        cfg = config.load(transaction.CONFIG)
        candidate = _proposal(operation, cfg, args)
        if args.dry_run:
            return {"dry_run": True, "candidate": candidate,
                    "owned_rules": firewall.compile_rules(candidate)}
        if operation in ("update", "enable", "disable", "delete") and candidate != cfg:
            # Avoid stale live tc filters matching an old port/interface if a
            # scheduled policy remains configured. Require explicit schedule
            # removal before changing a tunnel's network binding.
            schedules = shaping.schedule_load()
            if any(p["enabled"] for p in schedules["policies"]):
                raise PM2Error("E_CONFLICT",
                               "Remove V2 port schedules before changing tunnel bindings")
        if os.geteuid():
            raise PM2Error("E_PERMISSION", "Tunnel mutations require root")
        if operation == "delete" and not args.yes:
            # Scripted CLI requires a flag, never an unexpected stdin prompt.
            # Interactive Ports menu already passes --yes on deliberate Delete.
            raise PM2Error("E_VALIDATION", "Pass --yes to delete a V2 tunnel")
        if guard.risky(cfg, candidate):
            return guard.apply(candidate)
        if guard._read() is not None:
            raise PM2Error("E_CONFLICT", "Protected change pending; confirm or rollback first")
        return transaction.apply(candidate)


class _null:
    def __enter__(self):
        return None
    def __exit__(self, *_):
        return False
