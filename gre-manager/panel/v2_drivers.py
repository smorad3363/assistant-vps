"""Kernel transport parameters shared by provisioning and rule compilation."""
from dataclasses import dataclass
import ipaddress


@dataclass(frozen=True)
class IPTunnel:
    method: str
    module: str
    protocol: str
    keyed: bool = False

    def create(self, link, interface):
        key = ["key", link["key"]] if self.keyed else []
        return ["ip", "tunnel", "add", link["tunnel"], "mode", self.method, "local", link["outer_local"], "remote",
                link["outer_peer"], *key, "ttl", link.get("ttl", 64), "dev", interface]

    def marker(self, link):
        return None if self.keyed else "gremgr:v2:" + link["id"]

    def owns(self, link, row):
        info = row.get("linkinfo", {})
        data = info.get("info_data", {})
        if (info.get("info_kind"), data.get("local"), data.get("remote")) != (
                self.method, link["outer_local"], link["outer_peer"]):
            return False
        if not self.keyed:
            return row.get("ifalias") == self.marker(link)
        key = data.get("ikey", 0)
        if isinstance(key, str):
            key = int(ipaddress.IPv4Address(key)) if "." in key else int(key)
        return key == link["key"]

    def refresh(self, link, info, interface):
        if not self.keyed and info.get("info_data", {}).get("ttl", 0) != link.get("ttl", 64):
            command = self.create(link, interface)
            command[2] = "change"
            return command
        return None

    def delete(self, link):
        return ["ip", "tunnel", "del", link["tunnel"]]

    def firewall(self, link):
        return ["-p", self.protocol]


class Vxlan:
    method = module = "vxlan"
    overhead = 50

    def create(self, link, interface):
        return ["ip", "link", "add", "dev", link["tunnel"], "type", self.method, "id", link["vni"],
                "local", link["outer_local"], "remote", link["outer_peer"], "dstport", link["listen_port"],
                "dev", interface, "nolearning"]

    def marker(self, link):
        return "gremgr:v2:" + link["id"]

    def owns(self, link, row):
        info = row.get("linkinfo", {})
        data = info.get("info_data", {})
        return (info.get("info_kind") == self.method and row.get("ifalias") == self.marker(link)
                and (data.get("id"), data.get("local"), data.get("remote"), data.get("port")) ==
                (link["vni"], link["outer_local"], link["outer_peer"], link["listen_port"]))

    def refresh(self, link, info, interface):
        return None

    def delete(self, link):
        return ["ip", "link", "del", "dev", link["tunnel"]]

    def firewall(self, link):
        return ["-p", "udp", "--dport", link["listen_port"]]


DRIVERS = {"gre": IPTunnel("gre", "ip_gre", "gre", True), "ipip": IPTunnel("ipip", "ipip", "4"), "vxlan": Vxlan()}


def driver_for(link):
    return DRIVERS[link.get("method", "gre")]
