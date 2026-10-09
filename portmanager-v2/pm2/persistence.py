"""Boot-only idempotent recovery of V2-owned rules.

All unexpected *partial* states fail closed; never repair a foreign firewall.
"""
import json
import os

from . import config, discovery, firewall, transaction
from .errors import PM2Error


def restore():
    if os.geteuid():
        raise PM2Error("E_PERMISSION", "Boot restore requires root")
    cfg, current = transaction.state()
    if transaction.PENDING.exists():
        raise PM2Error("E_CONFLICT", "Incomplete V2 apply: manual recovery needed")
    from . import guard
    pending = guard._read()
    if pending is not None:
        return guard.rollback(pending["change_id"])
    inventory = current.get("firewall", {})
    expected_backend = current.get("backend")
    backend = discovery.backend()
    if expected_backend and expected_backend != backend:
        raise PM2Error("E_CONFLICT", "iptables backend changed since previous apply")
    current_rules = firewall.snapshot()
    owned_names = [
        (table, chain)
        for table, chain in firewall.ORDER
        if ["-N", chain] in current_rules[table]
    ]
    if owned_names:
        firewall.check_inventory(current_rules, inventory)
        return {"changed": False, "reason": "already_present",
                "generation": cfg["generation"]}
    if not any(inventory.get(t) for t in firewall.CHAINS):
        if not cfg["tunnels"] or not any(x["enabled"] for x in cfg["tunnels"]):
            return {"changed": False, "reason": "no_active_tunnels"}
        raise PM2Error("E_CONFLICT", "No recorded kernel ownership inventory")
    report = discovery.audit(cfg["tunnels"])
    if not discovery.forwarding_enabled():
        raise PM2Error("E_CONFLICT", "IPv4 forwarding disabled at boot")
    expected = firewall.compile_rules(cfg)
    actual = firewall.reconcile(expected, {})  # kernel explicitly empty
    updated = dict(current, firewall=actual, backend=backend,
                   applied_generation=cfg["generation"],
                   desired_generation=cfg["generation"])
    config.atomic_json(transaction.STATE, updated)
    return {"changed": True, "reason": "post_boot_owned_restore",
            "generation": cfg["generation"], **report}
