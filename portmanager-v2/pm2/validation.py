"""Strict IPv4 tunnel schema and collision checks. Pure, no host modifications."""
import ipaddress
import re
import uuid

from .errors import PM2Error

MAX_TUNNELS = 100
MAX_RULES = 512
MAX_EXCLUDES = 1024
_NAME = re.compile(r"^[a-zA-Z0-9_-]{1,64}$")
_IFACE = re.compile(r"^[a-zA-Z0-9_.:@-]{1,15}$")


def error(message, **details):
    raise PM2Error("E_VALIDATION", message, details)


def ip4(value, field, *, target=False):
    try:
        addr = ipaddress.IPv4Address(value)
    except (ipaddress.AddressValueError, TypeError):
        error("Invalid IPv4 address", field=field, value=str(value))
    if not addr.is_global and not addr.is_private:
        error("Forbidden IPv4 address", field=field, value=str(value))
    if addr.is_loopback or addr.is_multicast or addr.is_unspecified or addr.is_link_local or addr.is_reserved:
        error("Unsafe IPv4 address", field=field, value=str(value))
    # Private targets are valid only if discovery later verifies a route.
    return str(addr)


def port(value):
    if isinstance(value, bool):
        error("Port must be an integer from 1 to 65535", value=value)
    try:
        if not str(value).isdigit():
            raise ValueError()
        n = int(value)
    except (ValueError, TypeError):
        error("Invalid port", value=str(value))
    if not 1 <= n <= 65535:
        error("Port outside 1..65535", value=n)
    return n


def csv_ports(value):
    if not isinstance(value, str) or not value:
        error("Exclude list must be nonempty")
    values = [port(s) for s in value.split(",")]
    if len(values) != len(set(values)):
        error("Duplicate exclude port")
    if len(values) > MAX_EXCLUDES:
        error("Too many exclusions", maximum=MAX_EXCLUDES)
    return sorted(values)


def mappings(value):
    if not isinstance(value, str) or not value:
        error("Mappings are required for ports mode")
    entries = []
    for raw in value.split(","):
        entry = raw.strip()
        if entry.count(":") > 1 or not entry:
            error("Use 5555 or 5555:6666, comma-separated", value=raw)
        if ":" in entry:
            a, b = (part.strip() for part in entry.split(":"))
        else:
            a = b = entry
        entries.append({"listen_port": port(a), "target_port": port(b)})
    if len({x["listen_port"] for x in entries}) != len(entries):
        error("Duplicate listen port")
    if len(entries) > MAX_RULES:
        error("Too many mappings", maximum=MAX_RULES)
    return sorted(entries, key=lambda x: x["listen_port"])


def protocols(value):
    if value == "tcp":
        return ["tcp"]
    if value == "udp":
        return ["udp"]
    if value == "tcp,udp":
        return ["tcp", "udp"]
    error("Protocol must be tcp, udp or tcp,udp", value=str(value))


def make_tunnel(*, name, listen_ip, interface, protocol, mode,
                target_ip, mapping=None, exclude=None, ack_all_ports=False,
                ident=None, enabled=True):
    if not isinstance(name, str) or not _NAME.fullmatch(name):
        error("Name must be 1..64 ASCII letters, digits, _ or -", field="name")
    if not isinstance(interface, str) or not _IFACE.fullmatch(interface) or interface.startswith("-"):
        error("Invalid interface", field="interface", value=str(interface))
    source = ip4(listen_ip, "listen_ip")
    target = ip4(target_ip, "target_ip", target=True)
    if source == target:
        error("Target and listening addresses must differ")
    prots = protocols(protocol)
    if mode == "ports":
        if exclude is not None:
            error("exclude may not be combined with ports mode")
        pairs = mappings(mapping)
        exceptions = []
    elif mode == "all-except":
        if mapping is not None:
            error("mapping may not be combined with all-except")
        if not ack_all_ports:
            error("All-except requires --ack-all-ports")
        exceptions = csv_ports(exclude)
        if 22 not in exceptions:
            error("All-except must exclude SSH fallback port 22")
        pairs = []
    else:
        error("mode must be ports or all-except", value=str(mode))
    if ident is None:
        ident = str(uuid.uuid4())
    else:
        try:
            if uuid.UUID(ident).version != 4:
                raise ValueError()
        except (ValueError, TypeError, AttributeError):
            error("Invalid tunnel UUIDv4")
    return {
        "id": ident, "name": name, "enabled": bool(enabled), "mode": mode,
        "listen_ip": source, "interface": interface, "protocols": prots,
        "mapping": pairs, "exclude": exceptions, "target_ip": target
    }


def collides(left, right):
    """Overlap of original listen tuples; all-except accounts for exceptions."""
    if left["interface"] != right["interface"] or left["listen_ip"] != right["listen_ip"]:
        return False
    if not set(left["protocols"]) & set(right["protocols"]):
        return False
    if left["mode"] == right["mode"] == "ports":
        return bool({x["listen_port"] for x in left["mapping"]} &
                    {x["listen_port"] for x in right["mapping"]})
    if left["mode"] == right["mode"] == "all-except":
        return True  # at most 1024 exclusions cannot partition entire port space
    specific = left if left["mode"] == "ports" else right
    wildcard = right if specific is left else left
    return any(x["listen_port"] not in wildcard["exclude"] for x in specific["mapping"])


def validate_collection(tunnels):
    if not isinstance(tunnels, list) or len(tunnels) > MAX_TUNNELS:
        error("Too many tunnels or invalid collection", maximum=MAX_TUNNELS)
    names, ids, count = set(), set(), 0
    for i, row in enumerate(tunnels):
        if not isinstance(row, dict):
            error("Invalid tunnel entry", index=i)
        try:
            p = ",".join(row["protocols"])
            expected = make_tunnel(
                ident=row["id"], name=row["name"], enabled=row["enabled"],
                listen_ip=row["listen_ip"], interface=row["interface"],
                protocol=p, mode=row["mode"], target_ip=row["target_ip"],
                mapping=",".join(f'{m["listen_port"]}:{m["target_port"]}' for m in row["mapping"])
                if row["mode"] == "ports" else None,
                exclude=",".join(str(x) for x in row["exclude"])
                if row["mode"] == "all-except" else None,
                ack_all_ports=row["mode"] == "all-except",
            )
        except (KeyError, TypeError, AttributeError) as exc:
            error("Malformed tunnel entry", index=i, exception=str(exc))
        if row != expected:
            error("Tunnel must use canonical schema", index=i)
        if row["id"] in ids or row["name"].lower() in names:
            error("Duplicate tunnel ID or case-insensitive name", index=i)
        ids.add(row["id"])
        names.add(row["name"].lower())
        if row["enabled"]:
            count += len(row["protocols"]) * (
                len(row["mapping"]) if row["mode"] == "ports" else 1
            )
    if count > MAX_RULES:
        error("Active mapping/protocol limit reached", maximum=MAX_RULES)
    enabled = [t for t in tunnels if t["enabled"]]
    for i, left in enumerate(enabled):
        for right in enabled[i + 1:]:
            if collides(left, right):
                raise PM2Error("E_CONFLICT", "Overlapping active tunnel listen tuple",
                               {"left": left["id"], "right": right["id"]})
    return True
