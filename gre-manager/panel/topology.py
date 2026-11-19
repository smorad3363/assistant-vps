"""Project schema-1 forwarding and receiver profiles into the v2 model."""
import uuid

from . import __version__
from .engine import gre_for
from .model import DEFAULTS, ranges_for


def legacy_topology(config, peers, node_id, addresses, ready_servers):
    settings = dict(DEFAULTS, **config["settings"])
    reserved = sorted({22, settings["port"], *settings["ssh_ports"], *settings["reserved_ports"]})
    namespace = uuid.UUID(node_id)
    nodes = {}
    links = {}
    groups = []
    receivers = []

    def identifier(resource, identity):
        return uuid.uuid5(namespace, f"{resource}:{identity}").hex

    def unmanaged(host, ip):
        identity = identifier("unmanaged", host)
        node = nodes.setdefault(identity, {
            "id": identity, "access": "unmanaged", "hostname": host,
            "addresses": [], "management_port": None,
        })
        if ip not in node["addresses"]:
            node["addresses"].append(ip)
        return identity

    def gre_link(peer_id, gre, requested_mtu):
        # Both endpoints stay explicit even when their effective MTU is the same.
        # Paused profiles may retain a different MTU for the same pair and slot.
        identity = identifier("gre", f"{peer_id}:{gre['id']}:{gre.get('slot', 0)}:{requested_mtu}:{gre['mtu']}")
        links.setdefault(identity, {
            "id": identity, "method": "gre", "settings_version": 1, "family": 4,
            "pair_id": gre["id"], "key": gre["key"], "slot": gre.get("slot", 0),
            "endpoints": [
                {"node_id": current, "outer_ip": gre[outer], "inner_ip": gre[inner],
                 "interface": gre["tunnel"], "requested": {"mtu": requested_mtu},
                 "effective": {"mtu": gre["mtu"]}}
                for current, outer, inner in (
                    (node_id, "outer_local", "local_tun"), (peer_id, "outer_peer", "peer_tun")
                )
            ],
        })
        return identity

    local_addresses = set(addresses)
    for server in config["servers"]:
        identity = server["id"]
        nodes[identity] = {
            "id": identity, "access": "ssh", "hostname": server["host"],
            "addresses": sorted({server["resolved_ip"], *server.get("addresses", [])}),
            "management_port": server["port"], "requires_connection": identity not in ready_servers,
        }

    for item in config["connections"]:
        identity = item["id"]
        local_addresses.add(item["listen_ip"])
        target = item["resolved_ip"]
        enabled = item.get("enabled", True)
        server_id = item.get("server_id")
        peer_id = server_id if server_id in nodes else unmanaged(item["target_host"], target)
        link_id = None
        needs_connection = False
        service_ip = target
        if item["kind"] == "gre":
            gre = gre_for(item)
            requested_mtu = settings["mtu"] if item.get("mtu_mode") == "auto" else gre["mtu"]
            local_addresses.add(gre["outer_local"])
            link_id = gre_link(peer_id, gre, requested_mtu)
            service_ip = item.get("service_ip", target)
            needs_connection = server_id not in ready_servers
        listener = {
            "id": identifier("listener", identity), "node_id": node_id, "ip": item["listen_ip"],
            "ports": item["ports"], "protocols": item["protocols"],
            "exclude_ports": item.get("exclude_ports", []),
            "effective_ranges": [list(bounds) for bounds in ranges_for(item, settings)],
            "port_map": item.get("port_map", {}), "target_port": item.get("target_port"),
            "members": [{
                "id": identifier("member", identity), "node_id": peer_id, "link_id": link_id,
                "method": item["kind"], "service_ip": service_ip, "weight": 1, "priority": 0,
                "enabled": enabled, "requires_connection": needs_connection,
            }],
        }
        groups.append({
            "id": identity, "name": item["name"], "owner": node_id, "revision": 0,
            "enabled": enabled, "selection": "single", "health_policy": "legacy",
            "listeners": [listener], "traffic_id": identity,
            "limits": {"up": item.get("upload_mbps", 0), "down": item.get("download_mbps", 0),
                       "ports": item.get("port_limits", {})},
            "monitor_ports": item.get("monitor_ports", []),
        })

    for peer in peers:
        gre = peer["gre"]
        local_addresses.update((gre["outer_local"], peer["service_ip"]))
        peer_id = unmanaged(gre["outer_peer"], gre["outer_peer"])
        receivers.append({
            "id": peer["id"], "owner": peer_id, "link_id": gre_link(peer_id, gre, gre["mtu"]),
            "service_ip": peer["service_ip"], "enabled": peer.get("enabled", True),
        })

    nodes[node_id] = {
        "id": node_id, "access": "local", "addresses": sorted(local_addresses),
        "management_port": settings["port"], "version": __version__,
    }
    for node in nodes.values():
        node["addresses"].sort()
    return {
        "schema": 2, "local_node_id": node_id,
        "nodes": sorted(nodes.values(), key=lambda node: node["id"]),
        "links": sorted(links.values(), key=lambda link: link["id"]),
        "groups": sorted(groups, key=lambda group: group["id"]),
        "receivers": sorted(receivers, key=lambda receiver: receiver["id"]),
        "host_policy": {"owner": node_id, "revision": 0, "protected_ports": reserved},
    }
