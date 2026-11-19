"""Translate v2 listener groups into scoped, conntrack-preserving Linux rules."""
import hashlib
import ipaddress
import json

from .model import DEFAULTS, PanelError, ranges_for, subtract
from .store import atomic_json, topology_node_id
from .transactions import Journal, fingerprint
from .v2_drivers import DRIVERS, driver_for, local_wireguard_key
from .v2_resources import boot_id

LINK_PROBE_PROTOCOL = 253
BOOT_ID = boot_id()


def gre_link(owner, listener, member, receiving=False):
    source = listener.get("outer_ip") or listener["ip"]
    target = member.get("outer_ip") or member["service_ip"]
    mtu = member.get("mtu") or 1280
    method = member["method"]
    base = f"{owner}|{source}|{target}|{member['service_ip']}"
    identity_input = f"{base}|{mtu}" if method == "gre" else f"{method}|{base}"
    if method == "wireguard":
        identity_input += "|" + member["id"]
    settings_key = member.get("gretap", {}).get("key") if method == "gretap" else None
    if settings_key:
        identity_input += "|" + str(settings_key)
    if method in ("vxlan", "geneve"):
        settings = member[method]
        identity_input += f"|{settings['vni']}|{settings['port']}"
    identity = hashlib.sha256(identity_input.encode()).hexdigest()
    start = int(ipaddress.IPv4Address("10.224.0.0")) + 4 * (int(identity[12:20], 16) % 262144)
    addresses = [str(ipaddress.IPv4Address(start + offset)) for offset in (1, 2)]
    if receiving:
        source, target = target, source
        addresses.reverse()
    parameters = member.get("link_settings", {}).get("destination" if receiving else "ingress", {})
    extra = {}
    if method in ("vxlan", "geneve"):
        extra = {"vni": settings["vni"], "listen_port": settings["port"]}
    if method == "wireguard":
        settings = member["wireguard"]
        here, there = ("destination", "ingress") if receiving else ("ingress", "destination")
        extra = {"public_key": settings[here]["public_key"], "peer_public_key": settings[there]["public_key"],
                 "listen_port": settings[here]["port"], "peer_port": settings[there]["port"],
                 "keepalive": 0 if receiving else settings["keepalive"]}
    return {
        "id": identity[:10], "tunnel": {"gre": "g2-", "ipip": "i2-", "wireguard": "w2-", "vxlan": "v2-",
                                       "gretap": "t2-", "geneve": "n2-"}[method] + identity[:12],
        "outer_local": source, "outer_peer": target, "local_tun": addresses[0],
        "peer_tun": addresses[1], "key": settings_key or int(identity[20:28], 16) or 1, "mtu": parameters.get("mtu", mtu),
        **({"mss_mode": parameters["mss_mode"], "mss": parameters.get("mss")} if parameters else {}),
        **({"method": method, "ttl": member.get("ttl", 64)} if method != "gre" else {}),
        **extra,
    }


def segments(listener, settings):
    mappings = {int(port): target for port, target in listener["port_map"].items()}
    effective = ranges_for(listener, settings)
    individual = set(mappings) | {int(port) for port in listener.get("port_limits", {})}
    split = [(port, port, mappings.get(port, listener["target_port"])) for port in sorted(individual)
             if any(lo <= port <= hi for lo, hi in effective)]
    return split + [(lo, hi, listener["target_port"]) for lo, hi in subtract(effective, individual)]


def active_members(listener, selection):
    eligible = [member for member in listener["members"]
                if member["enabled"] and not member.get("draining") and member.get("available", True)]
    if not eligible:
        return []
    priority = min(member["priority"] for member in eligible)
    tier = sorted((member for member in eligible if member["priority"] == priority), key=lambda member: member["id"])
    return tier if selection == "weighted" else tier[:1]


def checks_admission(listener, member):
    return "probe" in listener or (listener.get("watch_link", False) and member["method"] in DRIVERS)


def health_signature(owner, listener, member):
    path = [listener.get(key) for key in ("id", "node_id", "ip", "outer_ip", "ports", "exclude_ports", "port_map",
                                          "target_port", "protocols", "probe", "watch_link")]
    peer = [member.get(key) for key in ("id", "node_id", "service_ip", "method", "outer_ip", "mtu", "enabled")]
    if member["method"] in ("wireguard", "vxlan", "gretap", "geneve"):
        peer.append(member[member["method"]])
    return fingerprint([owner, path, peer])


def topology_views(config, state, node_id, *, paths=None, require_keys_for=None):
    listeners, devices, receivers = [], {}, {}
    policies = {}
    unavailable = {}
    local_key = None
    key_read = False
    routes = {}
    settings = dict(DEFAULTS, **config["settings"])

    def usable_member(listener, group, member):
        nonlocal key_read, local_key
        method = member["method"]
        if (not paths or group["id"] == require_keys_for or method not in ("wireguard", "geneve")
                or not (member["enabled"] or member.get("draining"))):
            return member
        side = "ingress" if listener["node_id"] == node_id else "destination" if member["node_id"] == node_id else None
        if side is None:
            return member
        from .engine import run
        if method == "wireguard":
            if not key_read:
                try:
                    local_key = local_wireguard_key(paths, run)
                except (PanelError, OSError):
                    pass
                key_read = True
            if local_key == member["wireguard"][side]["public_key"]:
                return member
            problem = "wireguard_key"
        else:
            link = gre_link(group["id"], listener, member, receiving=side == "destination")
            key = link["outer_peer"], link["listen_port"]
            if key not in routes:
                try:
                    routes[key] = driver_for(link).preferred_source(link, run)[0]
                except (PanelError, OSError, ValueError):
                    routes[key] = None
            if routes[key] == link["outer_local"]:
                return member
            problem = "geneve_route"
        unavailable[group["id"] + ":" + member["id"]] = problem
        return dict(member, enabled=False, draining=False)

    def reconcile_link(link, group_id, staged):
        name = link["tunnel"]
        settings = (link["mtu"], link.get("mss_mode", "mtu"), link.get("mss"), link.get("ttl", 64))
        if name in policies:
            old, claimed, owner, prepared = policies[name]
            if claimed != settings and (owner != group_id or prepared == staged):
                raise PanelError("Groups sharing a GRE link must agree on the local MTU and MSS.", "link_policy", "link_settings")
            return old
        policies[name] = (link, settings, group_id, staged)
        return link

    def add_group(owner, group, staged):
        if not group or not group["enabled"]:
            return
        for listener in group["listeners"]:
            if paths:
                listener = dict(listener, members=[usable_member(listener, group, member) for member in listener["members"]])
            ingress = listener["node_id"] == node_id
            if ingress and not staged:
                if "probe" in listener or listener.get("watch_link"):
                    observed = state.get("health", {})
                    members = []
                    for member in listener["members"]:
                        sample = observed.get(group["id"] + ":" + member["id"], {})
                        verified = (sample.get("boot_id") == BOOT_ID and sample.get("path") == health_signature(owner, listener, member)
                                    and sample.get("available", False))
                        members.append(dict(member, available=verified or not checks_admission(listener, member)))
                    listener = dict(listener, members=members)
                listeners.append((group, owner, listener))
            for member in listener["members"]:
                if member["method"] not in DRIVERS or not (member["enabled"] or member.get("draining")):
                    continue
                receiving = member["node_id"] == node_id
                if not ingress and not receiving:
                    continue
                gre = reconcile_link(gre_link(owner, listener, member, receiving), group["id"], staged)
                if ingress:
                    devices[gre["tunnel"]] = gre
                if receiving:
                    peer = receivers.setdefault(gre["tunnel"], {
                        "id": gre["id"], "kind": "peer", "enabled": True, "gre": gre,
                        "service_ip": member["service_ip"], "v2_ports": {"tcp": [], "udp": []},
                    })
                    # Use the mapped service ports, excluding management access
                    # on this receiving host. The ingress enforces its own list.
                    protected = {22, settings["port"], *settings["ssh_ports"], *settings["reserved_ports"]}
                    targets = [(target, target) if target else (lo, hi)
                               for lo, hi, target in segments(listener, dict(DEFAULTS, port=22))]
                    for proto in listener["protocols"]:
                        peer["v2_ports"][proto].extend(subtract(targets, protected))

    for record in state["groups"].values():
        if record["active"]:
            add_group(record["owner"], record["group"], False)
    for record in state["operations"].values():
        if record["phase"] == "prepared" and record.get("change"):
            add_group(record["owner"], record["change"]["group"], True)
    return dict(config, settings=settings, connections=[*config["connections"], *receivers.values()],
                v2_listeners=listeners, v2_devices=list(devices.values()), v2_driver_unavailable=unavailable)


def installed_topology(paths, config):
    if "v2_listeners" in config:
        return config
    state = Journal(paths.var / "v2-participant.json").read()
    if not state["groups"] and not state["operations"]:
        return config
    return topology_views(with_ssh_protection(config, paths, remember=True), state, topology_node_id(paths), paths=paths)


def with_ssh_protection(config, paths=None, *, remember=False):
    from .engine import discovered_ssh_ports

    settings = dict(DEFAULTS, **config["settings"])
    cache = paths.var / "ssh-ports.json" if paths else None
    error = None
    try:
        observed = discovered_ssh_ports()
    except PanelError as exc:
        error = str(exc)
        observed = json.loads(cache.read_text()) if cache and cache.exists() else []
    else:
        if remember and cache:
            atomic_json(cache, observed)
    settings["ssh_ports"] = sorted(set(settings["ssh_ports"] + observed))
    return dict(config, settings=settings, ssh_discovery_error=error)


def require_ssh_protection(config, previous=None):
    error = config.get("ssh_discovery_error")
    if not error:
        return
    def incoming(view):
        items = []
        for group, owner, listener in view.get("v2_listeners", []):
            if "tcp" in listener["protocols"]:
                members = [{key: value for key, value in m.items() if key != "available"} for m in listener.get("members", [])]
                items.append((group.get("selection") if group else None, owner, dict(listener, members=members)))
        return items

    def receiving(view):
        return {(peer["gre"]["tunnel"], peer["service_ip"], lo, hi)
                for peer in view.get("connections", [])
                for lo, hi in peer.get("v2_ports", {}).get("tcp", [])}

    previous = previous or {}
    if any(item not in incoming(previous) for item in incoming(config)) or receiving(config) - receiving(previous):
        raise PanelError(error, "ssh_discovery", "ssh_ports")


def format_port(low, high):
    return str(low) if low == high else f"{low}:{high}"


def mss_rules(add, link, local_service=None):
    mode = link.get("mss_mode", "mtu")
    if mode == "off":
        return
    target = ["--clamp-mss-to-pmtu"] if mode == "pmtu" else ["--set-mss", link["mss"] if mode == "manual" else link["mtu"] - 40]
    for interface_flag in ("-i", "-o"):
        add("mangle", "GMP_MSS", interface_flag, link["tunnel"], "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN",
            "-j", "TCPMSS", *target)
    if local_service:
        add("mangle", "GMP_MSS_LOCAL", "-o", link["tunnel"], "-s", local_service, "-d", link["peer_tun"],
            "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN", "-j", "TCPMSS", *target)


def traffic_caps(config, group, listener, members, direction, port):
    """Keep a shared bucket at every layer and explicitly apportion group budgets by ingress."""
    nodes = {row["node_id"] for row in group["listeners"]}
    id_group = group["id"]
    id_listener = listener["id"]
    caps = [
        ("host", config["settings"].get("v2_limits", {}).get(direction, 0)),
        ("group:" + id_group, group.get("limits", {}).get(direction, 0) / len(nodes)),
        ("listener:" + id_group + ":" + id_listener, listener.get("limits", {}).get(direction, 0)),
    ]
    capped = [(member["id"], member["limits"][direction]) for member in members if member.get("limits", {}).get(direction)]
    if capped:
        member_id, speed = min(capped, key=lambda pair: pair[1])
        caps.append(("member:" + id_group + ":" + member_id, speed))
    if port:
        caps.append(("port:" + id_group + ":" + id_listener + ":" + port, listener.get("port_limits", {}).get(port, {}).get(direction, 0)))
    for scope, speed in reversed(caps):
        if speed:
            yield hashlib.sha256(f"v2 limit {scope} {direction} {speed}".encode()).hexdigest()[:18], speed


def add_receiver_rules(add, peer, interfaces, settings):
    gre = peer["gre"]
    device, remote, service = gre["tunnel"], gre["peer_tun"], peer["service_ip"]
    mss_rules(add, gre, service if service in interfaces else None)
    add("filter", "GMP_INPUT", "-i", device, "-s", remote, "-d", gre["local_tun"], "-p", LINK_PROBE_PROTOCOL, "-j", "ACCEPT")
    protected = {22, settings["port"], *settings["ssh_ports"], *settings["reserved_ports"]}
    session_ports = subtract([(1, 65535)], protected)
    for proto, ports in peer["v2_ports"].items():
        incoming = ["-i", device, "-s", remote]
        tracked = ["-m", "conntrack", "--ctstate", "DNAT"]
        established = ["-m", "conntrack", "--ctstate", "ESTABLISHED", "--ctdir", "ORIGINAL",
                       "--ctorigdst", gre["local_tun"]]
        # Conntrack remembers the translated port for a live session when a mapping changes.
        for low, high in session_ports:
            session = [*incoming, "-d", service, "-p", proto, "--dport", format_port(low, high), *established, *tracked]
            add("filter", "GMP_INPUT", *session, "-j", "ACCEPT")
            add("filter", "GMP_FWD", *session, "-j", "ACCEPT")
        add("filter", "GMP_FWD", "-o", device, "-d", remote, "-s", service, "-p", proto,
            "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT")
        for low, high in sorted(set(ports)):
            match = ["-p", proto, "--dport", format_port(low, high)]
            add("nat", "GMP_PRE", *incoming, "-d", gre["local_tun"], *match, "-j", "DNAT", "--to-destination", service)
            add("filter", "GMP_INPUT", *incoming, "-d", service, *match, *tracked, "-j", "ACCEPT")
            add("filter", "GMP_FWD", *incoming, "-d", service, *match, *tracked, "-j", "ACCEPT")
            if service not in interfaces:
                add("nat", "GMP_POST", "-s", remote, "-d", service, *match, *tracked, "-j", "MASQUERADE")
            elif proto == "udp":
                add("nat", "GMP_LOCAL", *incoming, "-d", service, *match,
                    "-m", "multiport", "!", "--dports", "500,4500",
                    "-m", "policy", "--dir", "in", "--pol", "none", *tracked,
                    "-j", "SNAT", "--to-source", gre["local_tun"])


def add_listener_rules(add, config, interfaces, limit):
    links_seen = set()
    for group, owner, listener in config.get("v2_listeners", []):
        wan = interfaces[listener["ip"]]
        active = active_members(listener, group["selection"])
        targets = {}
        path_members = {}
        for member in listener["members"]:
            if not member["enabled"] and not member.get("draining"):
                continue
            gre = gre_link(owner, listener, member) if member["method"] in DRIVERS else None
            targets[member["id"]] = (gre["peer_tun"] if gre else member["service_ip"], gre)
            destination, link = targets[member["id"]]
            path_members.setdefault((destination, link["tunnel"] if link else ""), []).append(member)
            if gre and gre["tunnel"] not in links_seen:
                links_seen.add(gre["tunnel"])
                add("filter", "GMP_INPUT", "-i", interfaces[gre["outer_local"]], "-s", gre["outer_peer"],
                    "-d", gre["outer_local"], *driver_for(gre).firewall(gre), "-j", "ACCEPT")
                add("filter", "GMP_INPUT", "-i", gre["tunnel"], "-s", gre["peer_tun"], "-d", gre["local_tun"],
                    "-p", LINK_PROBE_PROTOCOL, "-j", "ACCEPT")
                mss_rules(add, gre)
            probe = listener.get("probe")
            if probe:
                origin = gre["local_tun"] if gre else listener["ip"]
                endpoint = gre["peer_tun"] if gre else member["service_ip"]
                target = listener["port_map"].get(str(probe["port"]), listener["target_port"] or probe["port"])
                device = ["-i", gre["tunnel"]] if gre else []
                add("filter", "GMP_INPUT", *device, "-s", endpoint, "-d", origin, "-p", probe["protocol"],
                    "--sport", target, "-m", "conntrack", "--ctstate", "ESTABLISHED", "--ctdir", "REPLY", "-j", "ACCEPT")
        for proto in listener["protocols"]:
            for low, high, translated in segments(listener, config["settings"]):
                port = format_port(low, high)
                selector = ["-i", wan, "-d", listener["ip"], "-p", proto, "--dport", port]
                weight_left = sum(member["weight"] for member in active)
                for member in active:
                    destination, _ = targets[member["id"]]
                    destination += ":" + str(translated) if translated else ""
                    weight = member["weight"]
                    draw = ["-m", "statistic", "--mode", "random", "--probability", f"{weight / weight_left:.11f}"] if weight < weight_left else []
                    add("nat", "GMP_PRE", *selector, *draw, "-j", "DNAT", "--to-destination", destination)
                    weight_left -= weight
                if not active:
                    add("nat", "GMP_PRE", *selector, "-j", "ACCEPT")
                tracked = ["-p", proto, "-m", "conntrack", "--ctstate", "DNAT", "--ctorigdst", listener["ip"],
                           "--ctorigdstport", port]
                routes = {(ip, item["tunnel"] if item else ""): item for ip, item in targets.values()}
                for (destination, gre), link in sorted(routes.items()):
                    send = ["-o", gre] if link else []
                    receive = ["-i", gre] if link else []
                    snat = ["-j", "SNAT", "--to-source", link["local_tun"]] if link else ["-j", "MASQUERADE"]
                    add("nat", "GMP_POST", "-d", destination, *tracked, *send, *snat)
                    for flow, marker, direction in (
                        (["-i", wan, "-d", destination, *send], "ORIGINAL", "up"),
                        (["-o", wan, "-s", destination, *receive], "REPLY", "down"),
                    ):
                        rule = [*flow, *tracked, "--ctdir", marker]
                        if direction == "up" and config.get("v2_conntrack_busy"):
                            add("filter", "GMP_FWD", *rule, "-m", "conntrack", "--ctstate", "NEW", "!", "--ctstatus",
                                "CONFIRMED", "-j", "DROP")
                        exact_port = str(low) if low == high else None
                        for bucket, speed in traffic_caps(config, group, listener, path_members[(destination, gre)], direction, exact_port):
                            limit(rule, bucket, direction, speed, minimum=1)
                        add("filter", "GMP_FWD", *rule, "-m", "comment",
                            "--comment", f"gmpanel:{group['id']}:all:{direction}", "-j", "ACCEPT")
