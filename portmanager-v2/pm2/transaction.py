"""Durable V2-only apply transaction; never restores a global iptables snapshot."""
import os
from pathlib import Path

from . import config, discovery, firewall
from .errors import PM2Error

CONFIG = Path(os.environ.get("PM2_ETC", "/etc/portmanager2")) / "config.json"
STATE = Path(os.environ.get("PM2_DATA", "/var/lib/portmanager2")) / "state.json"
PENDING = Path(os.environ.get("PM2_DATA", "/var/lib/portmanager2")) / "pending.json"


def state():
    item = config.load(CONFIG)
    try:
        import json
        runtime = json.loads(STATE.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise PM2Error("E_VALIDATION", "V2 apply state missing or corrupt") from exc
    if not isinstance(runtime, dict):
        raise PM2Error("E_VALIDATION", "V2 runtime state is invalid")
    return item, runtime


def preflight(candidate, runtime, allow_protected=False):
    """All checks occur before kernel mutation."""
    from .validation import validate_collection
    validate_collection(candidate["tunnels"])
    if PENDING.exists() or PENDING.is_symlink():
        raise PM2Error("E_CONFLICT", "Incomplete V2 pending transaction; manual recovery required")
    if any(t["enabled"] and t["mode"] == "all-except" for t in candidate["tunnels"]) and not allow_protected:
        raise PM2Error("E_CONFLICT", "All-except requires an armed 120-second rollback watchdog")
    report = discovery.audit(candidate["tunnels"])
    original_backend = runtime.get("backend")
    if original_backend is not None and original_backend != report["backend"]:
        raise PM2Error("E_CONFLICT", "iptables backend changed; no V2 mutation allowed")
    if not discovery.forwarding_enabled() and any(t["enabled"] for t in candidate["tunnels"]):
        raise PM2Error("E_CONFLICT", "IPv4 forwarding disabled; enable it in isolated test/managed sysctl first")
    inventory = runtime.get("firewall", {})
    firewall.check_inventory(firewall.snapshot(), inventory)
    return report


def apply(candidate, allow_protected=False):
    """Root-only, requires caller holding V2 global mutation lock."""
    if os.geteuid():
        raise PM2Error("E_PERMISSION", "Applying V2 tunnels requires root")
    original, runtime = state()
    report = preflight(candidate, runtime, allow_protected=allow_protected)
    if candidate == original and runtime.get("applied_generation") == original["generation"]:
        return {"changed": False, "generation": original["generation"], **report}
    previous = runtime.get("firewall", {})
    compiled = firewall.compile_rules(candidate)
    journal = {"product": "portmanager2", "original_generation": original["generation"],
               "desired_generation": candidate["generation"], "previous_firewall": previous}
    config.atomic_json(PENDING, journal)
    applied = None
    completed = False
    rollback_completed = False
    try:
        applied = firewall.reconcile(compiled, previous)
        next_state = dict(runtime)
        next_state.update({
            "firewall": applied, "backend": report["backend"],
            "desired_generation": candidate["generation"],
            "applied_generation": candidate["generation"],
            "last_error": None,
        })
        # Save new state then candidate config; failure -> attempt owned rollback.
        config.atomic_json(STATE, next_state)
        config.atomic_json(CONFIG, candidate)
        completed = True
    except Exception as exc:
        try:
            if applied is not None:
                firewall.reconcile({chain: list(previous.get(table, {}).get(chain, []))
                                    for table, chain in firewall.ORDER}, applied)
            config.atomic_json(STATE, runtime)
            config.atomic_json(CONFIG, original)
            rollback_completed = True
        except Exception as rollback_exc:
            raise PM2Error("E_ROLLBACK", "Failed to restore transaction state",
                           {"cause": str(exc), "rollback": str(rollback_exc)}) from rollback_exc
        if isinstance(exc, PM2Error):
            raise
        raise PM2Error("E_APPLY", "Tunnel transaction failed", {"error": str(exc)}) from exc
    finally:
        # Do not erase recovery evidence if we cannot know rollback succeeded.
        if (completed or rollback_completed) and not PENDING.is_symlink():
            PENDING.unlink(missing_ok=True)
    return {"changed": True, "generation": candidate["generation"],
            "tunnels": len(candidate["tunnels"]), **report}
