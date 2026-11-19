"""Translate v2 listener groups into scoped, conntrack-preserving Linux rules."""
import hashlib
import ipaddress

from .model import DEFAULTS, ranges_for, subtract
from .store import topology_node_id
from .transactions import Journal


def gre_link(owner, listener, member, receiving=False):
    source, target = listener["outer_ip"], member["outer_ip"]
    identity = hashlib.sha256(f"{owner}|{source}|{target}|{member['service_ip']}|{member['mtu']}".encode()).hexdigest()
    start = int(ipaddress.IPv4Address("10.224.0.0")) + 4 * (int(identity[12:20], 16) % 262144)
    addresses = [str(ipaddress.IPv4Address(start + offset)) for offset in (1, 2)]
    if receiving:
        source, target = target, source
        addresses.reverse()
    return {
        "id": identity[:10], "tunnel": "g2-" + identity[:12],
        "outer_local": source, "outer_peer": target, "local_tun": addresses[0],
        "peer_tun": addresses[1], "key": int(identity[20:28], 16) or 1, "mtu": member["mtu"],
    }


def segments(listener, settings):
    mappings = {int(port): target for port, target in listener["port_map"].items()}
    effective = ranges_for(listener, settings)
    mapped = [(port, port, target) for port, target in sorted(mappings.items())
              if any(lo <= port <= hi for lo, hi in effective)]
    return mapped + [(lo, hi, listener["target_port"]) for lo, hi in subtract(effective, mappings)]


def active_members(listener, selection):
    eligible = [member for member in listener["members"] if member["enabled"] and not member["draining"]]
    if not eligible:
        return []
    priority = min(member["priority"] for member in eligible)
    tier = sorted((member for member in eligible if member["priority"] == priority), key=lambda member: member["id"])
    return tier if selection == "weighted" else tier[:1]


def topology_views(config, state, node_id):
    listeners, devices, receivers = [], {}, {}
    settings = dict(DEFAULTS, **config["settings"])

    def add_group(owner, group, staged):
        if not group or not group["enabled"]:
            return
        for listener in group["listeners"]:
            ingress = listener["node_id"] == node_id
            if ingress and not staged:
                listeners.append((group, owner, listener))
            for member in listener["members"]:
                if member["method"] != "gre" or not (member["enabled"] or member["draining"]):
                    continue
                receiving = member["node_id"] == node_id
                if not ingress and not receiving:
                    continue
                gre = gre_link(owner, listener, member, receiving)
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
                v2_listeners=listeners, v2_devices=list(devices.values()))


def installed_topology(paths, config):
    if "v2_listeners" in config:
        return config
    state = Journal(paths.var / "v2-participant.json").read()
    if not state["groups"] and not state["operations"]:
        return config
    return topology_views(config, state, topology_node_id(paths))


def format_port(low, high):
    return str(low) if low == high else f"{low}:{high}"


def add_receiver_rules(add, peer, interfaces):
    gre = peer["gre"]
    device, remote, service = gre["tunnel"], gre["peer_tun"], peer["service_ip"]
    for proto, ports in peer["v2_ports"].items():
        for low, high in sorted(set(ports)):
            match = ["-p", proto, "--dport", format_port(low, high)]
            incoming = ["-i", device, "-s", remote]
            tracked = ["-m", "conntrack", "--ctstate", "DNAT"]
            add("nat", "GMP_PRE", *incoming, "-d", gre["local_tun"], *match, "-j", "DNAT", "--to-destination", service)
            add("filter", "GMP_INPUT", *incoming, "-d", service, *match, *tracked, "-j", "ACCEPT")
            add("filter", "GMP_FWD", *incoming, "-d", service, *match, *tracked, "-j", "ACCEPT")
            add("filter", "GMP_FWD", "-o", device, "-d", remote, "-s", service, "-p", proto,
                "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT")
            if service not in interfaces:
                add("nat", "GMP_POST", "-s", remote, "-d", service, *match, *tracked, "-j", "MASQUERADE")
            elif proto == "udp":
                add("nat", "GMP_LOCAL", *incoming, "-d", service, *match,
                    "-m", "multiport", "!", "--dports", "500,4500",
                    "-m", "policy", "--dir", "in", "--pol", "none", *tracked,
                    "-j", "SNAT", "--to-source", gre["local_tun"])


def add_listener_rules(add, config, interfaces):
    for group, owner, listener in config.get("v2_listeners", []):
        wan = interfaces[listener["ip"]]
        active = active_members(listener, group["selection"])
        targets = {}
        for member in listener["members"]:
            if not member["enabled"] and not member["draining"]:
                continue
            gre = gre_link(owner, listener, member) if member["method"] == "gre" else None
            targets[member["id"]] = (gre["peer_tun"] if gre else member["service_ip"], gre)
            if gre:
                add("filter", "GMP_INPUT", "-i", interfaces[gre["outer_local"]], "-s", gre["outer_peer"],
                    "-d", gre["outer_local"], "-p", "gre", "-j", "ACCEPT")
                for interface_flag in ("-i", "-o"):
                    add("mangle", "GMP_MSS", interface_flag, gre["tunnel"], "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN",
                        "-j", "TCPMSS", "--set-mss", gre["mtu"] - 40)
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
                        add("filter", "GMP_FWD", *flow, *tracked, "--ctdir", marker, "-m", "comment",
                            "--comment", f"gmpanel:{group['id']}:all:{direction}", "-j", "ACCEPT")
