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

    def owns(self, link, info):
        data = info.get("info_data", {})
        if (info.get("info_kind"), data.get("local"), data.get("remote")) != (
                self.method, link["outer_local"], link["outer_peer"]):
            return False
        if not self.keyed:
            return True
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


DRIVERS = {"gre": IPTunnel("gre", "ip_gre", "gre", True), "ipip": IPTunnel("ipip", "ipip", "4")}


def driver_for(link):
    return DRIVERS[link.get("method", "gre")]
