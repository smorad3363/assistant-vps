"""Kernel transport parameters shared by provisioning and rule compilation."""
from dataclasses import dataclass
import base64
import fcntl
import ipaddress
import json
import re
import os
import tempfile

from .model import PanelError
from .v2_l2tp import L2TPv3


def gre_key(value):
    if isinstance(value, str) and "." in value:
        return int(ipaddress.IPv4Address(value))
    return int(value)


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
        return gre_key(data.get("ikey", 0)) == link["key"]

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


class GreTap(IPTunnel):
    staged_marker = True

    def create(self, link, interface):
        return ["ip", "link", "add", "dev", link["tunnel"], "type", self.method,
                "local", link["outer_local"], "remote", link["outer_peer"], "key", link["key"], "ttl", 64, "dev", interface]

    def marker(self, link):
        return "gremgr:v2:" + link["id"]

    def owns(self, link, row):
        return (row.get("ifalias") == self.marker(link) and super().owns(link, row)
                and gre_key(row["linkinfo"]["info_data"].get("okey", 0)) == link["key"])

    def delete(self, link):
        return ["ip", "link", "del", "dev", link["tunnel"]]

    def firewall(self, link):
        header = "0>>22&0x3C"
        match = f"{header}@0&0xF000FFFF=0x20006558 && {header}@4=0x{link['key']:08x}"
        return ["-p", self.protocol, "-m", "u32", "--u32", match]


class Sit(IPTunnel):
    def create(self, link, interface):
        return ["ip", "link", "add", "dev", link["tunnel"], "alias", self.marker(link), "type", self.method,
                "local", link["outer_local"], "remote", link["outer_peer"], "ttl", 64, "dev", interface]

    def refresh(self, link, info, interface):
        return None

    def delete(self, link):
        return ["ip", "link", "del", "dev", link["tunnel"]]


def ipv6_enabled(run):
    result = run("sysctl", "-n", "net.ipv6.conf.all.disable_ipv6", "net.ipv6.conf.default.disable_ipv6", check=False)
    return result.returncode == 0 and result.stdout.split() == ["0", "0"]


def wireguard_public_key(value):
    try:
        decoded = base64.b64decode(value, validate=True)
        if len(decoded) == 32 and any(decoded) and base64.b64encode(decoded).decode() == value:
            return value
    except (TypeError, ValueError):
        pass
    raise PanelError("Provide a valid WireGuard public key.", field="public_key")


def local_wireguard_key(paths, run, create=False):
    """Keep the host private key on disk locally. Return only its public key."""
    secret = paths.etc / "wireguard.key"
    if create:
        with secret.with_suffix(".lock").open("a") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            if not secret.exists():
                key = run("wg", "genkey").stdout.strip()
                with tempfile.NamedTemporaryFile(mode="w", dir=paths.etc, prefix=".wg-key-", delete=False) as staged:
                    try:
                        staged.write(key + "\n")
                        staged.flush()
                        os.fsync(staged.fileno())
                        os.replace(staged.name, secret)
                    finally:
                        if os.path.exists(staged.name):
                            os.unlink(staged.name)
    if not secret.is_file():
        raise PanelError("Generate the WireGuard public key on this host first.", "wireguard_key")
    if secret.stat().st_mode & 0o077:
        raise PanelError("The local WireGuard key must be accessible only to its owner.", "wireguard_key")
    return wireguard_public_key(run("wg", "pubkey", input=secret.read_text()).stdout.strip())


class WireGuard:
    method = module = "wireguard"

    def create(self, link, interface):
        return ["ip", "link", "add", "dev", link["tunnel"], "type", "wireguard"]

    def marker(self, link):
        return "gremgr:v2:" + link["id"]

    def owns(self, link, row):
        return row.get("linkinfo", {}).get("info_kind") == self.method and row.get("ifalias") == self.marker(link)

    def refresh(self, link, info, interface):
        return None

    def delete(self, link):
        return ["ip", "link", "del", "dev", link["tunnel"]]

    def firewall(self, link):
        return ["-p", "udp", "--dport", link["listen_port"]]

    def configure(self, link, paths, run):
        name = link["tunnel"]
        peers = run("wg", "show", name, "peers").stdout.split()
        if any(peer != link["peer_public_key"] for peer in peers):
            raise PanelError("A different WireGuard peer already owns this managed interface.", "device_conflict")
        run("wg", "set", name, "private-key", paths.etc / "wireguard.key", "listen-port", link["listen_port"],
            "peer", link["peer_public_key"], "endpoint", f"{link['outer_peer']}:{link['peer_port']}",
            "allowed-ips", link["peer_tun"] + "/32", "persistent-keepalive", link["keepalive"])


class Vxlan:
    method = module = "vxlan"
    staged_marker = True
    overhead = 50

    def create(self, link, interface):
        return ["ip", "link", "add", "dev", link["tunnel"], "type", self.method, "id", link["vni"],
                "local", link["outer_local"], "remote", link["outer_peer"], "dstport", link["listen_port"],
                "dev", interface, "nolearning"]

    def inspect(self, run, name=None):
        selector = ("dev", name) if name else ("type", self.method)
        result = run("ip", "-j", "-d", "link", "show", *selector, check=not name)
        if result.returncode:
            return []
        try:
            return json.loads(result.stdout)
        except json.JSONDecodeError:
            # Some distribution builds print a plaintext VXLAN flag in detailed JSON.
            plain = run("ip", "-o", "-d", "link", "show", *selector).stdout
            basic = json.loads(run("ip", "-j", "link", "show", *selector).stdout)
            details = {}
            for line in plain.splitlines():
                index = re.match(r"\s*(\d+):", line)
                data = re.search(r"(?:\\\s+|\s{2,})" + self.method + r"\s+id\s+(\d+)\b(.*)", line)
                if not index or not data:
                    continue
                attrs = {"id": int(data[1]), "learning": "nolearning" not in data[2].split()}
                for option, key in (("local", "local"), ("remote", "remote"), ("dev", "link"), ("dstport", "port")):
                    match = re.search(r"(?:^|\s)" + option + r"\s+(\S+)", data[2])
                    if match:
                        attrs[key] = int(match[1]) if option == "dstport" else match[1]
                details[int(index[1])] = attrs
            for row in basic:
                if row["ifindex"] in details:
                    row["linkinfo"] = {"info_kind": self.method, "info_data": details[row["ifindex"]]}
                elif not name:
                    raise PanelError(f"The installed iproute2 could not describe an existing {self.method.upper()} interface.", "device_conflict")
            return basic

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


class Geneve(Vxlan):
    method = module = "geneve"

    def create(self, link, interface):
        return ["ip", "link", "add", "dev", link["tunnel"], "type", self.method, "id", link["vni"],
                "remote", link["outer_peer"], "dstport", link["listen_port"]]

    def owns(self, link, row):
        info = row.get("linkinfo", {})
        data = info.get("info_data", {})
        return (info.get("info_kind") == self.method and row.get("ifalias") == self.marker(link)
                and (data.get("id"), data.get("remote"), data.get("port")) == (link["vni"], link["outer_peer"], link["listen_port"]))

    def preferred_source(self, link, run):
        rows = json.loads(run("ip", "-j", "-4", "route", "get", link["outer_peer"], "ipproto", "udp",
                              "dport", link["listen_port"]).stdout)
        route = rows[0] if rows else {}
        return route.get("prefsrc"), route.get("dev")


DRIVERS = {"gre": IPTunnel("gre", "ip_gre", "gre", True), "ipip": IPTunnel("ipip", "ipip", "4"), "wireguard": WireGuard(), "vxlan": Vxlan(),
           "gretap": GreTap("gretap", "ip_gre", "gre", True), "geneve": Geneve(), "l2tpv3": L2TPv3(), "sit": Sit("sit", "sit", "41")}


def driver_for(link):
    return DRIVERS[link.get("method", "gre")]
