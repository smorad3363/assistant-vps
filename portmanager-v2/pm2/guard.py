"""120-second fail-safe, explicit confirmation for high-risk IPv4 NAT changes.

The watchdog is scheduled *before* applying risky rules, not afterwards.
A durable V2-only journal permits rollback even when CLI/SSH is interrupted.
"""
import os
from pathlib import Path
import subprocess
import time
import uuid

from . import config, firewall, transaction
from .errors import PM2Error

PROTECTED = Path(os.environ.get("PM2_DATA", "/var/lib/portmanager2")) / "protected.json"
TIMEOUT = 120


def risky(before, after):
    """Any all-except or change to an existing listener binding is high risk."""
    if any(x["enabled"] and x["mode"] == "all-except" for x in after["tunnels"]):
        return True
    old_by_id = {x["id"]: x for x in before["tunnels"]}
    for t in after["tunnels"]:
        old = old_by_id.get(t["id"])
        if old is not None and (
                old["listen_ip"] != t["listen_ip"] or
                old["interface"] != t["interface"]):
            return True
    # Removing an all-except tunnel or a protected listener is also a change.
    after_ids = {x["id"] for x in after["tunnels"]}
    return any(x["enabled"] and x["mode"] == "all-except" and x["id"] not in after_ids
               for x in before["tunnels"])


def _systemctl(args):
    try:
        result = subprocess.run(["systemctl", *args], timeout=12,
                                capture_output=True, text=True, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise PM2Error("E_DEPENDENCY", "systemd command unavailable") from exc
    return result


def _timer(ident):
    return "portmanager2-rollback-" + ident


def _schedule(ident):
    unit = _timer(ident)
    try:
        result = subprocess.run([
            "systemd-run", "--quiet", "--collect",
            "--unit", unit, "--on-active=120s",
            "/usr/local/bin/portmanager2", "rollback-pending", ident
        ], timeout=15, capture_output=True, text=True, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise PM2Error("E_DEPENDENCY", "Cannot create systemd rollback watchdog") from exc
    if result.returncode:
        raise PM2Error("E_APPLY", "Could not schedule timed rollback",
                       {"stderr": result.stderr[-350:]})
    return unit


def _cancel(ident):
    result = _systemctl(["stop", _timer(ident) + ".timer"])
    if result.returncode:
        raise PM2Error("E_APPLY", "Cannot cancel rollback timer",
                       {"stderr": result.stderr[-350:]})


def _read():
    if PROTECTED.is_symlink():
        raise PM2Error("E_CONFLICT", "Protected transaction is symlinked")
    if not PROTECTED.exists():
        return None
    try:
        import json
        item = json.loads(PROTECTED.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise PM2Error("E_CONFLICT", "Invalid protected rollback record") from exc
    if not isinstance(item, dict) or item.get("product") != "portmanager2":
        raise PM2Error("E_CONFLICT", "Unknown protected rollback record")
    return item


def apply(candidate):
    """Schedule bounded watchdog first, then run journaled network apply.

    Caller must hold the V2 mutation lock for the entire operation.
    """
    if os.geteuid():
        raise PM2Error("E_PERMISSION", "Guarded apply requires root")
    if _read() is not None:
        raise PM2Error("E_CONFLICT", "Previous protected change not confirmed")
    original, runtime = transaction.state()
    # Validate and catch all irreversible conflicts before timer installation.
    transaction.preflight(candidate, runtime, allow_protected=True)
    ident = str(uuid.uuid4())
    old = {"product": "portmanager2", "change_id": ident,
           "created_at": time.time(), "expires_at": time.time() + TIMEOUT,
           "original_config": original, "original_state": runtime,
           "desired_generation": candidate["generation"]}
    config.atomic_json(PROTECTED, old)
    scheduled = False
    try:
        _schedule(ident)
        scheduled = True
        result = transaction.apply(candidate, allow_protected=True)
    except Exception:
        if scheduled:
            # Keep the timer and journal as fail-safe if anything is uncertain.
            raise
        PROTECTED.unlink(missing_ok=True)
        raise
    return {**result, "pending_confirmation": ident, "rollback_after_seconds": TIMEOUT}


def confirm(ident):
    if os.geteuid():
        raise PM2Error("E_PERMISSION", "Confirm requires root")
    value = _read()
    if value is None or value.get("change_id") != ident:
        raise PM2Error("E_VALIDATION", "No matching unconfirmed V2 change")
    if time.time() >= value["expires_at"]:
        raise PM2Error("E_CONFLICT", "Confirmation window has expired")
    current, runtime = transaction.state()
    if runtime.get("applied_generation") != value["desired_generation"]:
        raise PM2Error("E_CONFLICT", "Protected change generation drift")
    firewall.check_inventory(firewall.snapshot(), runtime.get("firewall", {}))
    # If cancel fails, timer must remain active; do not prematurely confirm.
    _cancel(ident)
    PROTECTED.unlink()
    return {"confirmed": ident, "generation": current["generation"]}


def rollback(ident):
    """V2-only watchdog rollback. Caller holds lock, not global firewall lock."""
    if os.geteuid():
        raise PM2Error("E_PERMISSION", "Timed rollback requires root")
    value = _read()
    if value is None:
        return {"changed": False, "reason": "already_confirmed"}
    if value.get("change_id") != ident:
        raise PM2Error("E_CONFLICT", "Watchdog change-id mismatch")
    old_conf = value["original_config"]
    old_state = value["original_state"]
    current, runtime = transaction.state()
    now_rules = firewall.snapshot()
    current_inv = runtime.get("firewall", {})
    # Refuse unknown/foreign ownership, even during watchdog rollback.
    firewall.check_inventory(now_rules, current_inv)
    previous_rules = {chain: list(old_state.get("firewall", {}).get(table, {}).get(chain, []))
                      for table, chain in firewall.ORDER}
    restored_inv = firewall.reconcile(previous_rules, current_inv)
    restored = dict(old_state, firewall=restored_inv,
                    applied_generation=old_conf["generation"],
                    desired_generation=old_conf["generation"])
    try:
        config.atomic_json(transaction.STATE, restored)
        config.atomic_json(transaction.CONFIG, old_conf)
    except Exception as exc:
        raise PM2Error("E_ROLLBACK", "Kernel restored but config recovery failed",
                       {"error": str(exc)}) from exc
    PROTECTED.unlink()
    return {"changed": True, "rolled_back": ident, "generation": old_conf["generation"]}
