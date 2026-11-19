"""Kernel transport parameters shared by provisioning and rule compilation."""
from dataclasses import dataclass
import base64
import fcntl
import ipaddress
import os
import tempfile

from .model import PanelError


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


DRIVERS = {"gre": IPTunnel("gre", "ip_gre", "gre", True), "ipip": IPTunnel("ipip", "ipip", "4"), "wireguard": WireGuard()}


def driver_for(link):
    return DRIVERS[link.get("method", "gre")]
