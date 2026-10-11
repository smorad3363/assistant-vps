"""Detect only overlapping foreign NAT forwarding rules; never change their ownership."""
import ipaddress
import shlex

TARGETS = frozenset({"DNAT", "REDIRECT", "NETMAP"})
PORT_FLAGS = ("--dport", "--dports", "--destination-port", "--destination-ports")


def _argument(args, flags):
    for flag in flags:
        if flag in args:
            index = args.index(flag)
            return args[index + 1] if index + 1 < len(args) else None
    return None


def _range(part):
    part = part.strip()
    sep = ":" if ":" in part else "-" if "-" in part else None
    bits = part.split(sep, 1) if sep else [part, part]
    try:
        begin, end = (int(value) if value else (1 if index == 0 else 65535)
                      for index, value in enumerate(bits))
    except ValueError:
        return None
    return (begin, end) if 1 <= begin <= end <= 65535 else None


def _ports_overlap(selector, tunnel):
    if selector is None:
        return True
    ranges = [_range(part) for part in selector.split(",")]
    if any(item is None for item in ranges):
        return True  # Unknown syntax: fail closed, not silently bypass.
    if tunnel["mode"] == "ports":
        return any(low <= pair["listen_port"] <= high
                   for low, high in ranges for pair in tunnel["mapping"])
    excluded = set(tunnel["exclude"])
    return any(high - low + 1 > sum(low <= port <= high for port in excluded)
               for low, high in ranges)


def _matches(args, tunnel):
    if "!" in args:
        return True
    device = _argument(args, ("-i", "--in-interface"))
    if device and not device.endswith("+") and device != tunnel["interface"]:
        return False
    proto = _argument(args, ("-p", "--protocol"))
    if proto and proto not in ("all", "0") and proto not in tunnel["protocols"]:
        return False
    destination = _argument(args, ("-d", "--destination"))
    if destination:
        try:
            if ipaddress.ip_address(tunnel["listen_ip"]) not in ipaddress.ip_network(
                    destination, strict=False):
                return False
        except ValueError:
            return True
    port = _argument(args, PORT_FLAGS)
    if port is None and any(flag in args for flag in ("--sports", "--sport", "--ports")):
        return True
    return _ports_overlap(port, tunnel)


def find_conflicts(snapshot, tunnels):
    """Return relevant foreign DNAT rules and the tunnel they might intercept."""
    conflicts = []
    for line in snapshot.splitlines():
        if not line.startswith("-A "):
            continue
        try:
            args = shlex.split(line)
        except ValueError:
            continue
        if len(args) < 4 or args[1] == "PM2_NAT_PRE":
            continue
        if _argument(args, ("-j", "--jump")) not in TARGETS:
            continue
        for tunnel in tunnels:
            if tunnel.get("enabled") and _matches(args, tunnel):
                conflicts.append({"rule": line[:500], "tunnel": tunnel["name"]})
                break
    return conflicts
