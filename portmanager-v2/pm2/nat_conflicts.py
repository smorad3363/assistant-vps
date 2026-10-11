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


def _same_destination_forward(args, tunnel):
    """A later DDS-like DNAT may coexist if its forwarding is identical.

    Different destinations/port remaps on a different host IPv4 must not be
    silently stolen when an existing V2 port expands to all assigned IPv4s.
    """
    if "!" in args or _argument(args, ("-j", "--jump")) != "DNAT":
        return False
    dest = _argument(args, ("--to-destination",))
    if not dest:
        return False
    if ":" in dest:
        address, port_text = dest.rsplit(":", 1)
        if not port_text.isdecimal():
            return False
        target_port = int(port_text)
    else:
        address, target_port = dest, None
    if address != tunnel["target_ip"]:
        return False
    if tunnel["mode"] == "all-except":
        return target_port is None
    selected = _argument(args, PORT_FLAGS)
    intervals = ([_range(x) for x in selected.split(",")]
                 if selected else [(1, 65535)])
    if any(r is None for r in intervals):
        return False
    matching = [m for m in tunnel["mapping"]
                if any(lo <= m["listen_port"] <= hi for lo, hi in intervals)]
    return bool(matching) and all(
        m["target_port"] == (target_port if target_port is not None
                              else m["listen_port"]) for m in matching)


def blocking_conflicts(snapshot, tunnels):
    """Respect NAT hook order and prevent shadowing different existing routes.

    The V2 hook is inserted before other PREROUTING rules. Earlier foreign
    DNAT rules can intercept V2; later ones may be shadowed by multi-IP V2.
    Later identical DDS-style mappings are allowed, but different targets
    must be flagged before mutating the kernel.
    """
    entries = []
    by_chain = {}
    for line in snapshot.splitlines():
        if not line.startswith("-A "):
            continue
        try:
            args = shlex.split(line)
        except ValueError:
            continue
        if len(args) < 4:
            continue
        by_chain.setdefault(args[1], []).append((line, args))
        if args[1] == "PREROUTING":
            entries.append((line, args))
    hook_at = next((i for i, (_, args) in enumerate(entries)
                    if _argument(args, ("-j", "--jump")) == "PM2_NAT_PRE"),
                   0)
    risky = []

    def intercepts(args, tunnel, before, seen, depth=0):
        if depth > 8 or "!" in args:
            return True
        if not _matches(args, tunnel):
            return False
        target = _argument(args, ("-j", "--jump"))
        if target in TARGETS:
            return before or not _same_destination_forward(args, tunnel)
        if target in by_chain and target != "PM2_NAT_PRE":
            if target in seen:
                return True
            next_seen = seen | {target}
            return any(intercepts(child, tunnel, before, next_seen, depth+1)
                       for _, child in by_chain[target])
        return False

    for i, (line, args) in enumerate(entries):
        if _argument(args, ("-j", "--jump")) == "PM2_NAT_PRE":
            continue
        before = i < hook_at
        for tunnel in tunnels:
            if tunnel.get("enabled") and intercepts(args, tunnel, before, set()):
                risky.append({"rule": line[:500], "tunnel": tunnel["name"]})
                break
    return risky
