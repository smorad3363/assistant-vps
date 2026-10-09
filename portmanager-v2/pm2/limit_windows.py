"""Pure time-of-day port-limit scheduling engine. No tc mutations in V2 2.0.

Scheduling is a 2.1 proposal with offline evaluation only. A future qdisc
adapter MUST prove exclusive V2 ownership and fail on V1/foreign qdisc drift
before changing rates; never execute a stored policy with the 2.0 backend.
"""
from datetime import datetime, timezone
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError
import ipaddress
import json
import re

from .errors import PM2Error

MAX_POLICIES = 64
MINUTES_WEEK = 10080
CLOCK = re.compile(r"^(?:[01]\d|2[0-3]):[0-5]\d$")
ZONE = re.compile(r"^[A-Za-z0-9_+./-]{1,80}$")


def invalid(message, **details):
    raise PM2Error("E_VALIDATION", message, details)


def minute(value):
    if not isinstance(value, str) or not CLOCK.fullmatch(value):
        invalid("Expected 24-hour HH:MM clock", clock=value)
    hour, minute_ = map(int, value.split(":"))
    return hour * 60 + minute_


def timezone_for(name):
    if not isinstance(name, str) or not ZONE.fullmatch(name) or ".." in name:
        invalid("Expected a valid IANA timezone", timezone=name)
    try:
        return ZoneInfo(name)
    except (ZoneInfoNotFoundError, KeyError, ValueError) as exc:
        invalid("Unknown IANA timezone; install distro tzdata", timezone=name)


def _rate(value, label):
    if type(value) is not int or not 0 <= value <= 100000:
        invalid("Rate must be integer Mbit/s from 0 (unlimited) to 100000",
                field=label, value=value)
    return value


def validate(policies):
    """Canonical JSON records, no hidden field rewriting or clock surprises."""
    if type(policies) is not list or len(policies) > MAX_POLICIES:
        invalid("Schedule collection must be a list of at most 64 policies")
    ids = set()
    weekly_occupancy = {}
    port_timezones = {}
    for rule in policies:
        if not isinstance(rule, dict):
            invalid("Schedule record must be an object")
        required = {"id", "port", "protocol", "timezone", "days", "start",
                    "end", "download_mbps", "upload_mbps", "enabled"}
        permitted = required | {"interface"}
        if not required.issubset(set(rule)) or not set(rule).issubset(permitted):
            invalid("Unexpected/missing scheduling fields",
                    unexpected=sorted(set(rule)-permitted),
                    missing=sorted(required-set(rule)))
        rid = rule["id"]
        if not isinstance(rid, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,32}", rid):
            invalid("Invalid schedule ID")
        if rid in ids:
            invalid("Duplicate schedule ID", id=rid)
        ids.add(rid)
        p = rule["port"]
        if type(p) is not int or not 0 <= p <= 65535:
            invalid("Port must be 0 (all interface traffic) or 1..65535", id=rid)
        iface = rule.get("interface")
        if iface is not None and (not isinstance(iface, str) or
                not re.fullmatch(r"[a-zA-Z0-9_.:-]{1,15}", iface)):
            invalid("Invalid interface for bandwidth policy", id=rid)
        if p == 0 and iface is None:
            invalid("All-port bandwidth limit requires an explicit interface", id=rid)
        protocol = rule["protocol"]
        if protocol not in ("tcp", "udp", "tcp,udp"):
            invalid("Protocol must be tcp, udp or tcp,udp", id=rid)
        if p == 0 and protocol != "tcp,udp":
            invalid("Global rate needs protocol=tcp,udp (covers interface IPv4)", id=rid)
        timezone_for(rule["timezone"])
        days = rule["days"]
        if (not isinstance(days, list) or not days or
                any(type(day) is not int or not 0 <= day <= 6 for day in days) or
                days != sorted(set(days))):
            invalid("days must be sorted unique ISO weekdays 0=Mon..6=Sun", id=rid)
        start, end = minute(rule["start"]), minute(rule["end"])
        _rate(rule["download_mbps"], "download_mbps")
        _rate(rule["upload_mbps"], "upload_mbps")
        if type(rule["enabled"]) is not bool:
            invalid("enabled must be a boolean", id=rid)
        if not rule["enabled"]:
            continue
        # Collision is exact in each local calendar week for rules sharing
        # same port and timezone. It is unsafe to compose overlapping zones.
        protos = ("tcp", "udp") if protocol == "tcp,udp" else (protocol,)
        for proto in protos:
            key = (p, proto)
            other_timezone = port_timezones.setdefault(key, rule["timezone"])
            if other_timezone != rule["timezone"]:
                raise PM2Error("E_CONFLICT",
                               "Different timezone policies on same port/protocol require explicit migration",
                               {"id": rid, "other_timezone": other_timezone})
        duration = (end - start) % 1440 or 1440   # equal clocks mean 24 hours
        for proto in protos:
            for d in days:
                for offset in range(duration):
                    position = (d * 1440 + start + offset) % MINUTES_WEEK
                    key = (p, proto, position)
                    other = weekly_occupancy.get(key)
                    if other is not None:
                        raise PM2Error("E_CONFLICT",
                                       "Time-window overlap on same port/protocol",
                                       {"id": rid, "other": other, "minute_of_week": position})
                    weekly_occupancy[key] = rid
    return True


def matches(rule, instant):
    """Evaluate a UTC instant against local clock and start-day semantics."""
    if not rule["enabled"]:
        return False
    tz = timezone_for(rule["timezone"])
    local = instant.astimezone(tz)
    now = local.hour * 60 + local.minute
    start, end = minute(rule["start"]), minute(rule["end"])
    elapsed = (end - start) % 1440 or 1440
    if elapsed == 1440:
        return local.weekday() in rule["days"]
    if start < end:
        return local.weekday() in rule["days"] and start <= now < end
    # A midnight crossing belongs to the day when it began.
    if now >= start:
        return local.weekday() in rule["days"]
    return now < end and (local.weekday()-1) % 7 in rule["days"]


def evaluate(policies, at=None):
    validate(policies)
    when = at or datetime.now(timezone.utc)
    if when.tzinfo is None:
        invalid("Evaluation timestamp must include UTC offset")
    active = []
    for item in policies:
        if matches(item, when):
            active.append({
                "id": item["id"], "port": item["port"], "protocol": item["protocol"],
                "download_mbps": item["download_mbps"],
                "upload_mbps": item["upload_mbps"], "timezone": item["timezone"],
                "interface": item.get("interface")
            })
    return {"at_utc": when.astimezone(timezone.utc).isoformat(),
            "would_apply": sorted(active, key=lambda x: (x["port"], x["id"])),
            "network_mutation": False,
            "backend": "preview_only_unavailable_until_v2_1"}


def preview_json_file(path, utc_timestamp=None):
    """Pure offline preview of a user-owned JSON schedule plan."""
    from pathlib import Path
    target = Path(path)
    if target.is_symlink() or not target.is_file():
        invalid("Schedule preview path must be a regular non-symlink file")
    try:
        source = json.loads(target.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        invalid("Invalid schedule JSON preview")
    if type(source) is not dict or set(source) != {"schema_version", "policies"} or source["schema_version"] != 1:
        invalid("Schedule JSON must contain schema_version=1 and policies")
    try:
        when = (datetime.fromisoformat(utc_timestamp.replace("Z", "+00:00"))
                if utc_timestamp is not None else datetime.now(timezone.utc))
    except (TypeError, AttributeError, ValueError) as exc:
        raise PM2Error("E_VALIDATION", "Invalid ISO 8601 --at timestamp") from exc
    return evaluate(source["policies"], when)
