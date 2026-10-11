"""Durable V2-only apply transaction; never restores a global iptables snapshot."""
import os
from pathlib import Path

from . import config, discovery, firewall, forwarding
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
    if (PENDING.parent / "foreign-nat-edit.json").exists():
        raise PM2Error("E_CONFLICT",
                       "Foreign NAT edit awaits confirmation/rollback; retry afterwards")
    if not allow_protected and (PENDING.parent / "protected.json").exists():
        raise PM2Error("E_CONFLICT", "Unconfirmed high-risk change; confirm or rollback first")
    if any(t["enabled"] and t["mode"] == "all-except" for t in candidate["tunnels"]) and not allow_protected:
        raise PM2Error("E_CONFLICT", "All-except requires an armed 120-second rollback watchdog")
    report = discovery.audit(candidate["tunnels"])
    original_backend = runtime.get("backend")
    if original_backend is not None and original_backend != report["backend"]:
        raise PM2Error("E_CONFLICT", "iptables backend changed; no V2 mutation allowed")
    forward_info = forwarding.preflight()
    report["forwarding_activation_required"] = (
        not forward_info["forwarding_enabled"] and
        any(t["enabled"] for t in candidate["tunnels"])
    )
    inventory = runtime.get("firewall", {})
    kernel = firewall.snapshot()
    actual_inventory, missing = firewall.repairable_inventory(kernel, inventory)
    if missing:
        # Internal baseline used by apply(); only intact, exactly-matching PM2
        # chains are eligible. Missing chains can be rebuilt, partial/drifted
        # chains already raised above.
        report["repair_missing_firewall"] = True
        report["_repair_previous_firewall"] = actual_inventory
        report["missing_owned_chains"] = [chain for _, chain in missing]
    else:
        report["repair_missing_firewall"] = False
    return report


def apply(candidate, allow_protected=False):
    """Root-only, requires caller holding V2 global mutation lock."""
    if os.geteuid():
        raise PM2Error("E_PERMISSION", "Applying V2 tunnels requires root")
    original, runtime = state()
    already_committed = (candidate == original and
                         runtime.get("applied_generation") == original["generation"])
    # A confirmed all-except configuration must be re-checkable/idempotent.
    # The verified owned inventory still enforces actual kernel safety.
    report = preflight(candidate, runtime, allow_protected=allow_protected or already_committed)
    # Reconcile legacy single-address rules to the complete set of verified
    # addresses even when the saved tunnel configuration itself is unchanged.
    # Keep the preflight and inventory checks before changing any rules.
    saved_previous = runtime.get("firewall", {})
    repairing_missing = bool(report.get("repair_missing_firewall"))
    repair_previous = report.pop("_repair_previous_firewall", None)
    # During repair, rollback to the exact intact subset that was really in
    # the kernel before mutation, not to stale state entries for missing chains.
    previous = (repair_previous if isinstance(repair_previous, dict) else {}
                ) if repairing_missing else saved_previous
    if repairing_missing:
        rollback_runtime = dict(runtime, firewall=previous)
    else:
        rollback_runtime = runtime
    compiled = firewall.compile_rules(candidate, report.get("interface_ips"))
    if already_committed and firewall.matches_compiled_inventory(compiled, previous):
        return {"changed": False, "generation": original["generation"], **report}
    journal = {"product": "portmanager2", "original_generation": original["generation"],
               "desired_generation": candidate["generation"], "previous_firewall": previous,
               "repair_missing_firewall": repairing_missing}
    config.atomic_json(PENDING, journal)
    applied = None
    completed = False
    rollback_completed = False
    try:
        if report["forwarding_activation_required"]:
            forwarding.activate()
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
            if isinstance(exc, PM2Error) and exc.code == "E_ROLLBACK":
                # The firewall engine explicitly says kernel recovery failed.
                # Never overwrite the evidence or report the kernel as safe.
                raise exc
            if applied is not None:
                firewall.reconcile({chain: list(previous.get(table, {}).get(chain, []))
                                    for table, chain in firewall.ORDER}, applied)
            config.atomic_json(STATE, rollback_runtime)
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
            "tunnels": len(candidate["tunnels"]),
            "repaired_missing_firewall": repairing_missing, **report}
