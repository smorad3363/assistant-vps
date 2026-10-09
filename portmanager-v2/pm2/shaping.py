"""Opt-in, root-only timed ingress/egress police filters on V2-owned clsact.

Never deletes/replaces a root qdisc, never edits V1 tc state. Refuses to
attach when V1 is installed, a foreign clsact exists or filter ownership drifts.
No silent fallback: if traffic-control capabilities are absent, reject.
"""
import json
import os
from pathlib import Path
import re
from datetime import datetime, timezone

from . import config, limit_windows, transaction
from .discovery import run
from .errors import PM2Error

SCHEDULE = Path(os.environ.get("PM2_ETC", "/etc/portmanager2")) / "schedules.json"
STATE = Path(os.environ.get("PM2_DATA", "/var/lib/portmanager2")) / "shaping.json"
PENDING = Path(os.environ.get("PM2_DATA", "/var/lib/portmanager2")) / "shaping-pending.json"
_V1 = Path("/usr/local/bin/portmanager")
_MAIN_V2 = "/opt/portmanager2/current/bin/portmanager2"
_LEGACY_ARCHIVE = Path("/var/lib/portmanager2/legacy-v1/archive.json")


def legacy_conflict():
    """A V2-owned primary symlink is NOT a live V1 installation."""
    if _V1.is_symlink() and os.readlink(_V1) == _MAIN_V2:
        # A migrated V1 might have live HTB 1: root rules until reboot or
        # controlled migration. Never silently compound V1 and V2 limits.
        if _LEGACY_ARCHIVE.exists():
            try:
                qs = _tc_json(["qdisc", "show"])
            except PM2Error:
                raise PM2Error("E_CONFLICT", "Cannot inspect archived V1 tc state")
            if any(row.get("kind") == "htb" and str(row.get("handle", "")).startswith("1:")
                   for row in qs):
                raise PM2Error("E_CONFLICT", "Legacy V1 HTB qdisc remains active; review before enabling V2 limits")
        return False
    return _V1.exists() or _V1.is_symlink()
_IFACE = re.compile(r"^[A-Za-z0-9_.:-]{1,15}$")


def _safe(path):
    if path.is_symlink():
        raise PM2Error("E_CONFLICT", "Unsafe shaping symlink", {"path": str(path)})


def schedule_load():
    _safe(SCHEDULE)
    if not SCHEDULE.exists():
        return {"schema_version": 1, "policies": []}
    try:
        data = json.loads(SCHEDULE.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise PM2Error("E_CONFLICT", "Unreadable or malformed schedule plan") from exc
    if type(data) is not dict or set(data) != {"schema_version", "policies"} or data["schema_version"] != 1:
        raise PM2Error("E_VALIDATION", "Unsupported schedule schema")
    limit_windows.validate(data["policies"])
    return data


def state_load():
    _safe(STATE)
    if not STATE.exists():
        return {"product": "portmanager2", "interfaces": [], "filters": []}
    try:
        value = json.loads(STATE.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise PM2Error("E_CONFLICT", "Shaping state cannot be decoded") from exc
    if (type(value) is not dict or set(value) != {"product", "interfaces", "filters"} or
            value["product"] != "portmanager2" or type(value["interfaces"]) is not list or
            type(value["filters"]) is not list):
        raise PM2Error("E_CONFLICT", "Shaping owner record has an unknown schema")
    for iface in value["interfaces"]:
        _iface(iface)
    return value


def _iface(value):
    if not isinstance(value, str) or not _IFACE.fullmatch(value):
        raise PM2Error("E_VALIDATION", "Invalid shaping interface", {"interface": value})
    return value


def _tc(argv):
    return run(["tc", *argv])


def _tc_json(argv):
    try:
        return json.loads(_tc(["-j", *argv]))
    except (ValueError, TypeError) as exc:
        raise PM2Error("E_DEPENDENCY", "tc JSON support is required") from exc


def desired_filters(plan, tunnels, at=None):
    limit_windows.validate(plan["policies"])
    when = at or datetime.now(timezone.utc)
    wanted = limit_windows.evaluate(plan["policies"], when)["would_apply"]
    # Resolve a port+protocol to exactly one active V2 original listener.
    bindings = {}
    for t in tunnels:
        if not t["enabled"] or t["mode"] != "ports":
            continue
        for mapping in t["mapping"]:
            for proto in t["protocols"]:
                key = (mapping["listen_port"], proto)
                if key in bindings and bindings[key] != t["interface"]:
                    raise PM2Error("E_CONFLICT", "Scheduled port bound to multiple interfaces")
                bindings[key] = _iface(t["interface"])
    filters = []
    # Global matchall and per-port police on the same interface can interfere
    # and produce unexpected combined drops. Refuse any such combination.
    global_ifaces = {p.get("interface") for p in plan["policies"]
                     if p["enabled"] and p["port"] == 0}
    if any(p["enabled"] and p["port"] != 0 and
           (p.get("interface") in global_ifaces or
            any(bindings.get((p["port"], proto)) in global_ifaces
                for proto in p["protocol"].split(",")))
           for p in plan["policies"]):
        raise PM2Error("E_CONFLICT", "Remove individual port limits before setting an all-ports limit on same interface")
    for item in wanted:
        for proto in (("all",) if item["port"] == 0 else item["protocol"].split(",")):
            key = (item["port"], proto)
            iface = item.get("interface") or bindings.get(key)
            if iface is None:
                raise PM2Error("E_CONFLICT", "Limit requires active V2 tunnel or explicit network interface",
                               {"port": item["port"], "protocol": proto})
            iface = _iface(iface)
            bound = bindings.get(key)
            if bound is not None and bound != iface:
                raise PM2Error("E_CONFLICT", "Explicit interface conflicts with tunnel listener interface")
            for direction, rate_key in (("ingress", "upload_mbps"), ("egress", "download_mbps")):
                rate = item[rate_key]
                if rate:
                    filters.append({"iface": iface, "proto": proto,
                                    "port": item["port"], "direction": direction,
                                    "mbps": rate})
    filters.sort(key=lambda x: (x["iface"], x["direction"], x["proto"], x["port"]))
    if len(filters) > 500:
        raise PM2Error("E_VALIDATION", "Too many traffic police filters")
    # Kernel priority is bounded 1..65535, unique per managed interface/direction.
    for i, item in enumerate(filters):
        item["pref"] = 41000 + i
    return filters


def _kernel(iface):
    qdiscs = _tc_json(["qdisc", "show", "dev", iface])
    clsact = any(q.get("kind") == "clsact" for q in qdiscs)
    filters = {}
    for direction in ("ingress", "egress"):
        rows = _tc_json(["filter", "show", "dev", iface, direction])
        concrete = []
        for row in rows:
            if row.get("kind") not in ("flower", "matchall"):
                raise PM2Error("E_CONFLICT", "Foreign tc filter in V2-controlled clsact",
                               {"interface": iface, "direction": direction})
            # iproute2 emits one bare flower descriptor followed by a second
            # fully-qualified descriptor for the *same* filter priority.
            # Only the concrete (keys + actions) entry is a separate filter.
            options = row.get("options")
            if isinstance(options, dict) and (options.get("keys") or options.get("actions")):
                concrete.append(row)
            elif not isinstance(options, dict) and row.get("pref") is not None:
                continue
            else:
                raise PM2Error("E_CONFLICT", "Unexpected incomplete flower filter")
        filters[direction] = concrete
    return clsact, filters


def preflight(before, desired, allow_kernel_reset=False, allow_v1_cleanup=False):
    _safe(PENDING)
    if PENDING.exists():
        raise PM2Error("E_CONFLICT", "Unconfirmed shaping mutation; preserve recovery journal")
    if not allow_v1_cleanup and legacy_conflict():
        raise PM2Error("E_CONFLICT", "V1 installation may own tc; V2 shaping cannot coexist")
    known = set(before["interfaces"])
    by_iface = {x["iface"] for x in desired} | known
    for iface in by_iface:
        _iface(iface)
        clsact, existing = _kernel(iface)
        if clsact and iface not in known:
            raise PM2Error("E_CONFLICT", "Foreign clsact qdisc present", {"interface": iface})
        if not clsact and iface in known and not allow_kernel_reset:
            raise PM2Error("E_CONFLICT", "Previously owned clsact disappeared")
        for direction, rows in existing.items():
            expected = {f["pref"]: f for f in before["filters"]
                        if f["iface"] == iface and f["direction"] == direction}
            actual = {}
            for r in rows:
                pref = r.get("pref")
                if isinstance(pref, str) and pref.isdecimal():
                    pref = int(pref)
                if type(pref) is not int or pref in actual:
                    raise PM2Error("E_CONFLICT", "Ambiguous tc filter priority",
                                   {"row": str(r)[:250]})
                actual[pref] = r
            if clsact and set(actual) != set(expected):
                raise PM2Error("E_CONFLICT", "Foreign or missing tc filter detected",
                               {"interface": iface, "direction": direction})
            for pref, row in actual.items():
                expected_f = expected[pref]
                keys = row.get("options", {}).get("keys", {})
                if expected_f["port"] == 0:
                    if row.get("kind") != "matchall":
                        raise PM2Error("E_CONFLICT", "Global limit filter changed")
                else:
                    portkey = "dst_port" if direction == "ingress" else "src_port"
                    if row.get("kind") != "flower" or str(keys.get(portkey)) != str(expected_f["port"]) or str(keys.get("ip_proto")) not in (
                        expected_f["proto"], str({"tcp": 6, "udp": 17}[expected_f["proto"]])):
                        raise PM2Error("E_CONFLICT", "V2 tc filter match drift",
                                       {"interface": iface, "pref": pref})
                actions = row.get("options", {}).get("actions", [])
                if not any(a.get("kind") == "police" for a in actions if isinstance(a, dict)):
                    raise PM2Error("E_CONFLICT", "V2 tc filter police action drift",
                                   {"interface": iface, "pref": pref})


def _filter_add(f):
    prefix = ["filter", "add", "dev", f["iface"], f["direction"], "protocol", "ip",
              "pref", str(f["pref"])]
    if f["port"] == 0:
        prefix.append("matchall")
    else:
        field = "dst_port" if f["direction"] == "ingress" else "src_port"
        prefix += ["flower", "ip_proto", f["proto"], field, str(f["port"])]
    _tc(prefix + ["action", "police", "rate", f'{f["mbps"]}mbit',
                  "burst", "256kb", "conform-exceed", "drop"])


def _filter_delete(f):
    _tc(["filter", "del", "dev", f["iface"], f["direction"],
         "protocol", "ip", "pref", str(f["pref"]),
         "matchall" if f["port"] == 0 else "flower"])


def reconcile(at=None, allow_kernel_reset=False):
    """Called under the existing V2 global writer lock. Zero work when idle."""
    if os.geteuid():
        raise PM2Error("E_PERMISSION", "Shaping mutations require root")
    plan = schedule_load()
    before = state_load()
    cfg = config.load(transaction.CONFIG)
    desired = desired_filters(plan, cfg["tunnels"], at)
    if not desired and not before["interfaces"]:
        _safe(PENDING)
        if PENDING.exists():
            raise PM2Error("E_CONFLICT", "Incomplete shaping journal requires recovery")
        return {"changed": False, "active_filters": 0}
    preflight(before, desired, allow_kernel_reset=allow_kernel_reset)
    target_ifaces = sorted({x["iface"] for x in desired} | set(before["interfaces"]))
    missing = ({iface for iface in before["interfaces"] if not _kernel(iface)[0]}
               if allow_kernel_reset else set())
    if desired == before["filters"] and not missing:
        return {"changed": False, "active_filters": len(desired)}
    journal = {"product": "portmanager2", "before": before,
               "desired": desired, "interfaces": target_ifaces}
    config.atomic_json(PENDING, journal)
    created, added, removed = [], [], []
    try:
        for iface in target_ifaces:
            owned = iface in before["interfaces"]
            clsact, _ = _kernel(iface)
            if not clsact and not owned:
                _tc(["qdisc", "add", "dev", iface, "clsact"])
                created.append(iface)
            elif not clsact and allow_kernel_reset:
                _tc(["qdisc", "add", "dev", iface, "clsact"])
                created.append(iface)
        for f in before["filters"]:
            if f["iface"] not in missing:
                _filter_delete(f)
                removed.append(f)
        for f in desired:
            _filter_add(f)
            added.append(f)
        committed = {"product": "portmanager2",
                     "interfaces": target_ifaces, "filters": desired}
        config.atomic_json(STATE, committed)
        PENDING.unlink()
        return {"changed": True, "active_filters": len(desired)}
    except Exception as exc:
        try:
            for f in reversed(added):
                _filter_delete(f)
            for f in removed:
                _filter_add(f)
            for iface in created:
                # Only remove qdiscs created by this transaction, after
                # confirmed V2 filter cleanup.
                _tc(["qdisc", "del", "dev", iface, "clsact"])
            config.atomic_json(STATE, before)
            PENDING.unlink()
        except Exception as rollback_error:
            raise PM2Error("E_ROLLBACK", "Shaping rollback uncertain; pending journal kept",
                           {"error": str(rollback_error)[:200]}) from exc
        raise PM2Error("E_APPLY", "Shaping failed, previous policy restored",
                       {"error": str(exc)[:200]}) from exc


def install_schedule(path):
    if os.geteuid():
        raise PM2Error("E_PERMISSION", "Schedule writes require root")
    source = Path(path)
    _safe(source)
    if not source.is_file():
        raise PM2Error("E_VALIDATION", "Schedule JSON file is unavailable")
    try:
        data = json.loads(source.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise PM2Error("E_VALIDATION", "Invalid schedule JSON") from exc
    if type(data) is not dict or set(data) != {"schema_version", "policies"} or data["schema_version"] != 1:
        raise PM2Error("E_VALIDATION", "Schedule schema_version must be 1")
    limit_windows.validate(data["policies"])
    # A disabled or future-dated plan still needs isolated V2-only tc ownership.
    if data["policies"] and legacy_conflict():
        raise PM2Error("E_CONFLICT", "V1 is installed; V2 cannot safely manage its tc")
    cfg = config.load(transaction.CONFIG)
    # Validate all scheduled bindings in advance, even if none active right now.
    for item in data["policies"]:
        if not item["enabled"]:
            continue
        if item.get("interface") is not None:
            _iface(item["interface"])
            # An interface name can be validated syntactically, but the
            # actual kernel existence/ownership must be verified before apply.
            continue
        if not any(t["enabled"] and t["mode"] == "ports" and
                   item["port"] in {row["listen_port"] for row in t["mapping"]} and
                   set(item["protocol"].split(",")).issubset(set(t["protocols"]))
                   for t in cfg["tunnels"]):
            raise PM2Error("E_CONFLICT", "Schedule requires enabled V2 tunnel or explicit interface",
                           {"id": item["id"], "port": item["port"]})
    _safe(SCHEDULE)
    config.atomic_json(SCHEDULE, data)
    return {"saved": len(data["policies"]), "enforcement": "requires_active_V2_systemd_timer"}


def remove_owned():
    """Uninstall-only cleanup: preserve foreign tc and V1; fail closed on drift."""
    before = state_load()
    if not before["interfaces"]:
        return {"changed": False}
    preflight(before, [], allow_v1_cleanup=True)
    # Temporarily bypass V1-presence restriction *only for removing exact
    # recorded owner filters* during uninstall. Never add new filters.
    _safe(PENDING)
    if PENDING.exists():
        raise PM2Error("E_CONFLICT", "Unconfirmed shaping transaction")
    for iface in before["interfaces"]:
        clsact, rows = _kernel(iface)
        if not clsact:
            raise PM2Error("E_CONFLICT", "Missing owned clsact at uninstall")
        for direction in ("ingress", "egress"):
            wanted = {x["pref"] for x in before["filters"]
                      if x["iface"] == iface and x["direction"] == direction}
            got = {r.get("pref") for r in rows[direction]}
            if wanted != got:
                raise PM2Error("E_CONFLICT", "Foreign tc filter prevents shaping removal")
    for f in before["filters"]:
        _filter_delete(f)
    for iface in before["interfaces"]:
        _tc(["qdisc", "del", "dev", iface, "clsact"])
    config.atomic_json(STATE, {"product": "portmanager2", "interfaces": [], "filters": []})
    return {"changed": True}
