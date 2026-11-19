"""Validation and local listener claims for the v2 topology."""
from collections import defaultdict
import re

from .model import DEFAULTS, PanelError, address, bandwidth_limits, connection, integer, port_ranges, ranges_for
from .transactions import identity, overlaps
from .v2_drivers import DRIVERS, wireguard_public_key
from .v2_forwarding import segments


def enabled(value):
    if type(value) is not bool:
        raise PanelError("The enabled flag must be true or false.", field="enabled")
    return value


def l2tpv2_settings(value):
    if not isinstance(value, dict) or set(value) != {"lac", "ingress", "destination"} or value["lac"] not in ("ingress", "destination"):
        raise PanelError("Select the LAC role and configure both L2TPv2 endpoints.", field="l2tpv2")
    cooked = {"lac": value["lac"]}
    for side in ("ingress", "destination"):
        endpoint = value[side]
        if not isinstance(endpoint, dict) or set(endpoint) != {"port", "credential"}:
            raise PanelError("Provide a UDP port and local credential reference for each end.", field="l2tpv2")
        name = endpoint["credential"]
        if not isinstance(name, str) or not re.fullmatch(r"[a-zA-Z0-9_-]{1,48}", name):
            raise PanelError("Use a local PPP credential name of up to 48 letters, digits, dashes or underscores.", field="credential")
        cooked[side] = {"port": integer(endpoint["port"], 1024, 65535, "port"), "credential": name}
    return cooked


def listener_profile(listener, settings, service_ip):
    keys = ("protocols", "ports", "target_port", "port_map", "exclude_ports", "port_limits")
    profile = {key: listener[key] for key in keys if key in listener}
    return connection(
        dict(profile, kind="direct", listen_ip=listener["ip"], target_host=service_ip),
        settings, resolver=lambda ip: ip,
    )


def link_settings(raw):
    if not isinstance(raw, dict) or set(raw) - {"ingress", "destination"}:
        raise PanelError("Configure GRE link settings on either side.", field="link_settings")
    result = {}
    for side, values in raw.items():
        if not isinstance(values, dict) or set(values) - {"mtu", "mss", "mss_mode"}:
            raise PanelError("Provide MTU and MSS settings for the link.", field="link_settings")
        mode = values.get("mss_mode", "mtu")
        if mode not in ("mtu", "pmtu", "manual", "off"):
            raise PanelError("Choose an MSS mode.", field="mss_mode")
        settings = {"mss_mode": mode}
        if "mtu" in values:
            settings["mtu"] = integer(values["mtu"], 576, 1476, "mtu")
        if mode == "manual":
            settings["mss"] = integer(values.get("mss"), 64, 1436, "mss")
        result[side] = settings
    return result


def wireguard_settings(raw):
    if not isinstance(raw, dict):
        raise PanelError("Configure both WireGuard peers.", field="wireguard")
    result = {"keepalive": integer(raw.get("keepalive", 25), 0, 65535, "keepalive")}
    for side in ("ingress", "destination"):
        peer = raw.get(side)
        if not isinstance(peer, dict):
            raise PanelError("Set the public key and UDP port on each host.", field="wireguard")
        result[side] = {"public_key": wireguard_public_key(peer.get("public_key")),
                        "port": integer(peer.get("port"), 1024, 65535, "port")}
    if result["ingress"]["public_key"] == result["destination"]["public_key"]:
        raise PanelError("WireGuard requires a distinct public key for each endpoint.", field="wireguard")
    return result


def normalize_group(raw):
    if not isinstance(raw, dict):
        raise PanelError("Provide a topology group.")
    name = str(raw.get("name", "")).strip()
    if not name or len(name) > 80 or any(ord(char) < 32 for char in name):
        raise PanelError("Use a group name of 1..80 characters.", field="name")
    selection = raw.get("selection", "weighted")
    if selection not in ("weighted", "failover", "single"):
        raise PanelError("Invalid member selection policy.", field="selection")
    listeners = raw.get("listeners")
    if not isinstance(listeners, list) or not 1 <= len(listeners) <= 128:
        raise PanelError("Provide 1..128 listeners.")
    result = {"id": identity(raw.get("id"), group=True), "name": name, "selection": selection,
              "enabled": enabled(raw.get("enabled", True)), "listeners": []}
    if "limits" in raw:
        result["limits"] = bandwidth_limits(raw["limits"])
    neutral = dict(DEFAULTS, port=22)
    used = set()
    edges = defaultdict(set)
    for listener in listeners:
        if not isinstance(listener, dict):
            raise PanelError("Invalid listener.")
        listener_id, ingress = identity(listener.get("id")), identity(listener.get("node_id"))
        listen_ip = address(listener.get("ip", ""))
        outer_ip = address(listener.get("outer_ip") or listen_ip)
        if listener_id in used:
            raise PanelError("Duplicate listener or member ID.", "identity")
        used.add(listener_id)
        members = listener.get("members")
        if not isinstance(members, list) or not 1 <= len(members) <= 128:
            raise PanelError("Provide 1..128 members per listener.")
        if selection == "single" and len(members) != 1:
            raise PanelError("Single-member selection needs one member.")
        normalized_members = []
        for member in members:
            if not isinstance(member, dict):
                raise PanelError("Invalid member.")
            member_id = identity(member.get("id"))
            if member_id in used:
                raise PanelError("Duplicate listener or member ID.", "identity")
            used.add(member_id)
            method = member.get("method")
            managed = enabled(member.get("managed", method != "direct"))
            egress = identity(member.get("node_id"))
            if not isinstance(method, str) or method not in {"direct", *DRIVERS} or (method != "direct" and not managed):
                raise PanelError("An unmanaged destination needs direct forwarding.")
            if managed:
                edges[ingress].add(egress)
            service_ip = address(member.get("service_ip", ""))
            target_outer = address(member.get("outer_ip") or service_ip) if method in DRIVERS else None
            is_enabled = enabled(member.get("enabled", True))
            draining = enabled(member.get("draining", False))
            if target_outer == outer_ip or method == "direct" and service_ip == listen_ip:
                raise PanelError("A member must use a different destination endpoint.", "loop")
            if draining and not is_enabled:
                raise PanelError("A stopped member cannot be draining.", "state")
            normalized_members.append({
                "id": member_id, "method": method, "managed": managed, "node_id": egress,
                "service_ip": service_ip, "outer_ip": target_outer,
                "mtu": integer(member.get("mtu", 1280), 576, 1476, "mtu") if method in DRIVERS else None,
                "weight": integer(member.get("weight", 1), 1, 1000, "weight"),
                "priority": integer(member.get("priority", 0), 0, 1000, "priority"),
                "enabled": is_enabled, "draining": draining,
            })
            if "limits" in member:
                normalized_members[-1]["limits"] = bandwidth_limits(member["limits"])
            if "link_settings" in member:
                if method not in DRIVERS:
                    raise PanelError("Set link MTU and MSS on a tunnel member.", field="link_settings")
                normalized_members[-1]["link_settings"] = link_settings(member["link_settings"])
            if method == "ipip":
                normalized_members[-1]["ttl"] = integer(member.get("ttl", 64), 0, 255, "ttl")
            if method == "vxlan":
                parameters = member.get("vxlan")
                if not isinstance(parameters, dict) or set(parameters) - {"vni", "port"}:
                    raise PanelError("Set the VNI and optional UDP port for this VXLAN link.", field="vxlan")
                normalized_members[-1]["vxlan"] = {"vni": integer(parameters.get("vni"), 1, 16777215, "vni"),
                                                   "port": integer(parameters.get("port", 4789), 1, 65535, "port")}
            if method == "wireguard":
                normalized_members[-1]["wireguard"] = wireguard_settings(member.get("wireguard"))
            if method == "l2tpv2":
                normalized_members[-1]["l2tpv2"] = l2tpv2_settings(member.get("l2tpv2"))
            if method == "gretap":
                settings = member.get("gretap", {})
                if not isinstance(settings, dict) or set(settings) - {"key"}:
                    raise PanelError("Configure the optional GRETAP key.", field="gretap")
                normalized_members[-1]["gretap"] = ({"key": integer(settings["key"], 1, 4294967295, "key")}
                                                       if "key" in settings else {})
        first = normalized_members[0]
        profile = listener_profile(dict(listener, ip=listen_ip), neutral, first["service_ip"])
        result["listeners"].append({
            "id": listener_id, "node_id": ingress, "ip": profile["listen_ip"], "outer_ip": outer_ip,
            "ports": profile["ports"], "protocols": profile["protocols"],
            "exclude_ports": profile["exclude_ports"], "port_map": profile["port_map"],
            "target_port": profile["target_port"], "members": normalized_members,
        })
        if listener.get("watch_link") is not None:
            result["listeners"][-1]["watch_link"] = enabled(listener["watch_link"])
        if "limits" in listener:
            result["listeners"][-1]["limits"] = bandwidth_limits(listener["limits"])
        if "port_limits" in listener:
            result["listeners"][-1]["port_limits"] = profile["port_limits"]
        probe = listener.get("probe")
        if probe is not None:
            if not isinstance(probe, dict) or probe.get("protocol") not in profile["protocols"]:
                raise PanelError("Choose a protocol the listener forwards.", "probe", "protocol")
            port = integer(probe.get("port"), 1, 65535, "port")
            if not any(lo <= port <= hi for lo, hi in port_ranges(profile["ports"])) or port in profile["exclude_ports"]:
                raise PanelError("The health probe needs a forwarded listening port.", "probe", "port")
            request, response = probe.get("request"), probe.get("response")
            if not all(isinstance(value, str) and 0 < len(value.encode()) <= 512 for value in (request, response)):
                raise PanelError("Set bounded request and expected response text for the service.", "probe")
            result["listeners"][-1]["probe"] = {"protocol": probe["protocol"], "port": port,
                                                  "request": request, "response": response}
    if len(used) > 1024:
        raise PanelError("Use at most 1024 listeners and members per group.")
    # Remove sinks repeatedly in this bounded graph. Remaining edges form a cycle.
    remaining = {node: set(targets) for node, targets in edges.items()}
    while remaining:
        sinks = {target for targets in remaining.values() for target in targets} - remaining.keys()
        if not sinks:
            raise PanelError("The managed forwarding graph has a cycle.", "cycle")
        remaining = {node: targets - sinks for node, targets in remaining.items() if targets - sinks}
    return result


def managed_nodes(group):
    nodes = set()
    if group:
        for listener in group["listeners"]:
            nodes.add(listener["node_id"])
            nodes.update(member["node_id"] for member in listener["members"] if member["managed"])
    return nodes


def local_claims(change, node_id, config, addresses):
    raw = change.get("group")
    if raw is None:
        return []
    group = normalize_group(raw)
    if group != raw or group["id"] != change["group_id"]:
        raise PanelError("The group does not match the planned representation.", "group")
    if not (managed_nodes(group) | {change["owner"]}).issubset(change["participants"]):
        raise PanelError("A managed node is missing from the operation.", "participant")
    if not group["enabled"]:
        return []
    settings = dict(DEFAULTS, **config.get("settings", {}))
    protected = {22, settings["port"], *settings["ssh_ports"], *settings["reserved_ports"]}
    claims = []
    for listener in group["listeners"]:
        for member in listener["members"]:
            if member["enabled"] and member["managed"] and member["node_id"] == node_id:
                if member["method"] in DRIVERS and member["outer_ip"] not in addresses:
                    raise PanelError("The tunnel destination address is unavailable on this node.", "local_ip")
                if member["method"] in DRIVERS and protected.intersection([listener["target_port"], *listener["port_map"].values()]):
                    raise PanelError("The translated destination uses a protected port.", "reserved", "port_map")
                if member["method"] == "direct" and member["service_ip"] in addresses and "tcp" in listener["protocols"]:
                    if config.get("ssh_discovery_error"):
                        raise PanelError(config["ssh_discovery_error"], "ssh_discovery", "ssh_ports")
                    targets = ((target, target) if target else (lo, hi)
                               for lo, hi, target in segments(listener, dict(DEFAULTS, port=22)))
                    if any(lo <= port <= hi for lo, hi in targets for port in protected):
                        raise PanelError("Exclude the managed direct destination's protected ports or change the mapping.",
                                         "reserved", "port_map")
        if listener["node_id"] != node_id:
            continue
        if listener["ip"] not in addresses:
            raise PanelError("The listener address is unavailable on this node.", "listen_ip")
        if any(member["enabled"] and member["method"] in DRIVERS for member in listener["members"]) and listener["outer_ip"] not in addresses:
            raise PanelError("The tunnel source address is unavailable on this node.", "local_ip")
        profile = listener_profile(listener, settings, listener["members"][0]["service_ip"])
        incoming = [(listener["ip"], proto, lo, hi) for proto in listener["protocols"]
                    for lo, hi in ranges_for(profile, settings)]
        if overlaps(claims, incoming):
            raise PanelError("Two listeners in this group overlap.", "overlap")
        claims.extend(incoming)
    for legacy in config.get("connections", []):
        if legacy.get("enabled", True):
            existing = [(legacy["listen_ip"], proto, lo, hi) for proto in legacy["protocols"]
                        for lo, hi in ranges_for(legacy, settings)]
            if overlaps(claims, existing):
                raise PanelError("Listener overlaps legacy route " + legacy["id"] + ".", "overlap")
    return claims


def participant_order(group, nodes):
    edges = defaultdict(set)
    if group:
        for listener in group["listeners"]:
            edges[listener["node_id"]].update(member["node_id"] for member in listener["members"] if member["managed"])
    pending = set(nodes)
    order = []
    while pending:
        ready = sorted(node for node in pending if not edges[node] & pending)
        order.extend(ready)
        pending.difference_update(ready)
    return order
