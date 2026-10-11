"""Guarded, exact-match editor for manually maintained IPv4 NAT DNAT targets.

No arbitrary flush, no adoption of Docker/UFW/V2 rules. Systemd schedules a
120-second rollback BEFORE any external rule is changed. Changes use a
per-chain numbered iptables -R command (no global iptables-restore).
"""
import ipaddress
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time
import uuid

from . import config, system_rules
from .discovery import run
from .errors import PM2Error

JOURNAL = Path(os.environ.get("PM2_DATA", "/var/lib/portmanager2")) / "foreign-nat-edit.json"
TIMEOUT = 120
_RESERVED = ("PM2_", "DOCKER", "CNI-", "KUBE-", "ufw", "firewalld", "LIBVIRT", "NETAVARK")


def _unit(ident):
    return "portmanager2-foreign-nat-" + ident


def parse_destination(value):
    match = re.fullmatch(r"([0-9.]+)(?::([0-9]{1,5}))?", value.strip())
    if not match:
        raise PM2Error("E_VALIDATION", "Enter IPv4 or IPv4:destination-port")
    try:
        address = ipaddress.IPv4Address(match.group(1))
    except ipaddress.AddressValueError as exc:
        raise PM2Error("E_VALIDATION", "Invalid destination IPv4") from exc
    if address.is_loopback or address.is_multicast or address.is_unspecified:
        raise PM2Error("E_VALIDATION", "Unroutable destination IPv4")
    if match.group(2) and not 1 <= int(match.group(2)) <= 65535:
        raise PM2Error("E_VALIDATION", "Destination port must be 1..65535")
    return str(address) + (":" + str(int(match.group(2))) if match.group(2) else "")


def editable(rule):
    """Only user-style directly placed DNAT rules, never third-party chains."""
    if rule.get("target") != "DNAT" or rule.get("owned"):
        return False
    if rule.get("chain") not in ("PREROUTING", "OUTPUT"):
        return False
    args = rule.get("argv", ())
    if not args or "-j" not in args or "--to-destination" not in args:
        return False
    if any(str(a).startswith(_RESERVED) for a in args):
        return False
    if any(prefix.lower() in str(a).lower() for prefix in
           ("docker", "kube-", "ufw-", "cni-", "firewalld", "pm2:") for a in args):
        return False
    return True


def replacement(rule, destination, source_port=None):
    if not editable(rule):
        raise PM2Error("E_CONFLICT",
                       "This rule is managed by another application or is not editable DNAT")
    args = list(rule["argv"])
    at = args.index("--to-destination")
    args[at + 1] = parse_destination(destination)
    if source_port is not None:
        if "--dport" not in args or not str(rule["port"]).isdecimal():
            raise PM2Error("E_UNSUPPORTED",
                           "Only existing single source ports can be changed here")
        if not str(source_port).isdecimal() or not 1 <= int(source_port) <= 65535:
            raise PM2Error("E_VALIDATION", "Source port must be 1..65535")
        args[args.index("--dport") + 1] = str(int(source_port))
    return args[2:]  # iptables -R CHAIN NUMBER receives args after -A CHAIN


def _snapshot():
    raw = run(["iptables-save", "-t", "nat"], timeout=15)
    return system_rules.parse_nat(raw, limit=None)


def _matching(snapshot, entry, expected):
    row = next((r for r in snapshot if r["chain"] == entry["chain"] and
                r["line_number"] == entry["line_number"]), None)
    return row is not None and row["argv"][2:] == expected


def _read():
    if JOURNAL.is_symlink():
        raise PM2Error("E_CONFLICT", "Foreign NAT edit journal is an unsafe symlink")
    if not JOURNAL.exists():
        return None
    try:
        record = json.loads(JOURNAL.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise PM2Error("E_CONFLICT", "Foreign NAT journal is unreadable") from exc
    if (not isinstance(record, dict) or
            record.get("product") != "portmanager2-foreign-nat"
            or not isinstance(record.get("changes"), list)
            or not isinstance(record.get("ident"), str)):
        raise PM2Error("E_CONFLICT", "Unknown foreign NAT journal")
    return record


def _schedule(ident):
    try:
        completed = subprocess.run([
            "systemd-run", "--quiet", "--collect",
            "--unit", _unit(ident), "--on-active=120s",
            "--timer-property=AccuracySec=1s",
            "--setenv=PYTHONPATH=/opt/portmanager2/current",
            "/usr/bin/python3", "-m", "pm2.nat_editor", "rollback", ident,
        ], capture_output=True, text=True, timeout=15, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise PM2Error("E_DEPENDENCY", "Rollback timer unavailable") from exc
    if completed.returncode:
        raise PM2Error("E_APPLY", "Cannot arm foreign NAT rollback watchdog",
                       {"error": completed.stderr[-240:]})


def _cancel(ident):
    try:
        result = subprocess.run(["systemctl", "stop", _unit(ident) + ".timer"],
                                capture_output=True, text=True, timeout=15, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise PM2Error("E_APPLY", "Cannot cancel rollback watchdog") from exc
    if result.returncode:
        raise PM2Error("E_APPLY", "Rollback watchdog cancellation failed",
                       {"error": result.stderr[-240:]})


def _replace(entry, args):
    run(["iptables", "-w", "5", "-t", "nat", "-R",
         entry["chain"], str(entry["line_number"]), *args], timeout=15)


def apply(members, destination, source_port=None):
    """Caller MUST hold Port Manager mutation lock; returns confirmation token."""
    if os.geteuid() != 0:
        raise PM2Error("E_PERMISSION", "Editing NAT requires root")
    if _read() is not None:
        raise PM2Error("E_CONFLICT", "Confirm or recover the previous NAT edit first")
    from . import guard, transaction
    if guard._read() is not None or transaction.PENDING.exists():
        raise PM2Error("E_CONFLICT", "Finish the current guarded V2 change first")
    target = parse_destination(destination)
    if not members or len(members) > 2:
        raise PM2Error("E_VALIDATION", "Select one or a TCP/UDP pair")
    original = _snapshot()
    changes = []
    for member in members:
        if not editable(member):
            raise PM2Error("E_CONFLICT", "Only manual PREROUTING/OUTPUT DNAT is editable")
        ident = {"chain": member["chain"], "line_number": member["line_number"]}
        if not _matching(original, ident, member["argv"][2:]):
            raise PM2Error("E_CONFLICT", "NAT rule changed since it was displayed; reload list")
        after = replacement(member, target, source_port)
        changes.append({**ident, "old": member["argv"][2:], "new": after})
    if len({(r["chain"], r["line_number"]) for r in changes}) != len(changes):
        raise PM2Error("E_VALIDATION", "Duplicate source rule")
    if all(item["old"] == item["new"] for item in changes):
        return {"changed": False}
    ident = str(uuid.uuid4())
    record = {"product": "portmanager2-foreign-nat", "ident": ident,
              "deadline": time.time() + TIMEOUT, "changes": changes}
    config.atomic_json(JOURNAL, record)
    try:
        _schedule(ident)
    except Exception:
        JOURNAL.unlink(missing_ok=True)
        raise
    # Journal + running systemd rollback timer exist BEFORE any -R.
    # On partial failures leave the journal and watchdog to repair.
    try:
        for change in changes:
            if not _matching(_snapshot(), change, change["old"]):
                raise PM2Error("E_CONFLICT", "NAT rules drifted while editing; watchdog armed")
            _replace(change, change["new"])
    except Exception:
        # Restore any already-changed half of a TCP/UDP pair immediately.
        # If restore fails, retain the journal and armed timer for recovery.
        try:
            rollback(ident)
        except Exception:
            pass
        raise
    return {"changed": True, "pending_confirmation": ident,
            "rollback_after_seconds": TIMEOUT}


def rollback(ident):
    record = _read()
    if record is None:
        return {"changed": False}
    if record["ident"] != ident:
        raise PM2Error("E_CONFLICT", "Foreign NAT rollback token mismatch")
    # Compare-and-swap: never overwrite a third-party concurrent change.
    current = _snapshot()
    for change in reversed(record["changes"]):
        if _matching(current, change, change["old"]):
            continue
        if not _matching(current, change, change["new"]):
            raise PM2Error("E_CONFLICT", "Rule changed externally; cannot safely roll back",
                           {"chain": change["chain"], "line": change["line_number"]})
        _replace(change, change["old"])
        current = _snapshot()
    JOURNAL.unlink()
    return {"rolled_back": ident}


def confirm(ident):
    record = _read()
    if record is None or record["ident"] != ident:
        raise PM2Error("E_CONFLICT", "No matching pending NAT edit")
    if time.time() >= record["deadline"]:
        raise PM2Error("E_CONFLICT", "Rollback confirmation window expired")
    current = _snapshot()
    if any(not _matching(current, change, change["new"])
           for change in record["changes"]):
        raise PM2Error("E_CONFLICT", "Edited NAT rules were changed; cannot confirm")
    _cancel(ident)
    JOURNAL.unlink()
    return {"confirmed": ident}


if __name__ == "__main__":
    if len(sys.argv) != 3 or sys.argv[1] != "rollback":
        raise SystemExit("usage: python -m pm2.nat_editor rollback UUID")
    from .cli import mutation_lock
    with mutation_lock(wait=True):
        print(rollback(sys.argv[2]))
