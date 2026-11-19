"""Linux TAP adapter for the EoIP GRE version 1 wire format."""
from contextlib import suppress
import errno
import fcntl
import ipaddress
import json
import os
from pathlib import Path
import select
import socket
import struct
import sys
import time

from .model import PanelError
from .store import atomic_json

GRE_PROTOCOL = 47
EOIP_PREFIX = struct.pack("!HH", 0x2001, 0x6400)
TUNSETIFF = 0x400454CA
IFF_EXCLUSIVE_TAP = 0x8000 | 0x1000 | 0x0002


def encode_frame(tunnel_id, frame):
    return EOIP_PREFIX + struct.pack("!H", len(frame)) + struct.pack("<H", tunnel_id) + frame


def decode_frame(packet, local, peer, tunnel_id, maximum):
    if len(packet) < 28 or packet[0] >> 4 != 4 or packet[9] != GRE_PROTOCOL:
        return None
    outer_size = (packet[0] & 15) * 4
    end = int.from_bytes(packet[2:4], "big")
    if not 20 <= outer_size <= end - 8 or end != len(packet) or packet[12:20] != peer + local:
        return None
    header = packet[outer_size:outer_size + 8]
    size = int.from_bytes(header[4:6], "big")
    if (header[:4] != EOIP_PREFIX or int.from_bytes(header[6:8], "little") != tunnel_id
            or not 14 <= size <= maximum or outer_size + 8 + size != end):
        return None
    return packet[outer_size + 8:end]


class EoIP:
    method, module = "eoip", "tun"
    overhead = 42

    @staticmethod
    def marker(link):
        return "gremgr:v2:" + link["id"]

    def owns(self, link, row):
        return row.get("ifalias") == self.marker(link) and row.get("link_type") == "ether"

    def firewall(self, link):
        locator = "0>>22&0x3C"
        wire_id = int.from_bytes(link["eoip_id"].to_bytes(2, "little"), "big")
        return ["-p", "gre", "-m", "u32", "--u32", f"{locator}@0=0x20016400 && {locator}@4&0xFFFF=0x{wire_id:04x}"]

    @staticmethod
    def settings(paths, link):
        return paths.var / "eoip" / (link["tunnel"] + ".json")

    @staticmethod
    def unit(link):
        return "gremgr-eoip-" + link["id"] + ".service"

    @staticmethod
    def description(link):
        return "GRE Manager EoIP link " + link["tunnel"]

    def status(self, link, run):
        result = run("systemctl", "show", self.unit(link), "--property=LoadState,ActiveState,Description,Transient", check=False)
        properties = dict(line.split("=", 1) for line in result.stdout.splitlines() if "=" in line)
        if properties.get("LoadState") == "not-found":
            return {}
        if result.returncode or properties.get("Transient") != "yes" or properties.get("Description") != self.description(link):
            raise PanelError("A different service uses the EoIP link unit name.", "device_conflict", "eoip")
        return properties

    def check(self, links, interfaces, run):
        if run("modprobe", "-nq", self.module, check=False).returncode:
            raise PanelError("Enable Linux TUN/TAP support before creating an EoIP link.", "method", "eoip")
        identities = {}
        for link in links:
            identity = link["outer_local"], link["outer_peer"], link["eoip_id"]
            if identities.setdefault(identity, link["tunnel"]) != link["tunnel"]:
                raise PanelError("Choose a different EoIP ID for this endpoint pair.", "device_conflict", "eoip")
            device = interfaces.get(link["outer_local"])
            if not device:
                raise PanelError("The selected EoIP source address is unavailable.", "local_ip", "outer_ip")
            outer = json.loads(run("ip", "-j", "link", "show", "dev", device).stdout)[0]
            if link["mtu"] + self.overhead > outer["mtu"]:
                raise PanelError("Lower the EoIP MTU to fit the underlay.", "link_policy", "mtu")
            self.status(link, run)

    def configure(self, link, paths, interface, row, run):
        record = self.settings(paths, link)
        source = str(Path(__file__).resolve().parents[1])
        desired = dict(link, interface=interface, source=source)
        status = self.status(link, run)
        if row and (not status or not self.owns(link, row)):
            raise PanelError("A different interface uses the EoIP link name.", "device_conflict", "eoip")
        if (row and status.get("ActiveState") == "active" and record.is_file()
                and json.loads(record.read_text()) == desired):
            return
        if status:
            run("systemctl", "stop", self.unit(link))
        atomic_json(record, desired)
        run("systemd-run", "--quiet", "--collect", "--unit=" + self.unit(link), "--description=" + self.description(link),
            "--property=Type=notify", "--property=TimeoutStartSec=12", "--property=Restart=on-failure",
            "--property=RestartSec=3", "--property=WorkingDirectory=" + source,
            sys.executable, "-m", "panel.v2_eoip", str(record))
        deadline = time.monotonic() + 8
        while time.monotonic() < deadline:
            observed = run("ip", "-j", "link", "show", "dev", link["tunnel"], check=False)
            if observed.returncode == 0 and any(self.owns(link, row) and "UP" in row.get("flags", [])
                                               for row in json.loads(observed.stdout)):
                return
            time.sleep(.15)
        raise PanelError("The EoIP service did not keep its managed TAP interface up.", "method", "eoip")

    def remove(self, link, paths, run):
        if self.status(link, run):
            run("systemctl", "stop", self.unit(link))
        self.settings(paths, link).unlink(missing_ok=True)


def ready():
    address = os.environ.get("NOTIFY_SOCKET")
    if address:
        if address.startswith("@"):
            address = "\0" + address[1:]
        with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as notification:
            notification.sendto(b"READY=1", address)


def send_frame(carrier, endpoint, tunnel_id, frame):
    try:
        carrier.sendto(encode_frame(tunnel_id, frame), endpoint)
    except OSError as error:
        if error.errno not in (errno.EAGAIN, errno.EWOULDBLOCK, errno.ECONNREFUSED, errno.EMSGSIZE,
                               errno.EPROTONOSUPPORT, errno.EHOSTUNREACH, errno.ENETUNREACH):
            raise


def run_link(link):
    from .engine import run

    local, peer = [ipaddress.IPv4Address(link[field]).packed for field in ("outer_local", "outer_peer")]
    name, tunnel_id = link["tunnel"], link["eoip_id"]
    endpoint = (link["outer_peer"], 0)
    maximum = link["mtu"] + 18
    run("modprobe", "tun", check=False)
    tap = os.open("/dev/net/tun", os.O_RDWR | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        fcntl.ioctl(tap, TUNSETIFF, struct.pack("16sH", name.encode(), IFF_EXCLUSIVE_TAP).ljust(40, b"\0"))
        run("ip", "link", "set", "dev", name, "alias", EoIP.marker(link))
        run("ip", "addr", "replace", link["local_tun"] + "/30", "dev", name)
        run("ip", "link", "set", "dev", name, "mtu", link["mtu"], "up")
        run("sysctl", "-qw", "net.ipv4.conf." + name + ".rp_filter=2")
        with socket.socket(socket.AF_INET, socket.SOCK_RAW, GRE_PROTOCOL) as carrier:
            carrier.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, link["interface"].encode() + b"\0")
            carrier.bind((link["outer_local"], 0))
            # An unconnected raw socket avoids asynchronous ICMP errors while
            # the other agent is still committing its end of the link.
            carrier.setblocking(False)
            ready()
            next_keepalive = 0.0
            while True:
                now = time.monotonic()
                if now >= next_keepalive:
                    send_frame(carrier, endpoint, tunnel_id, b"")
                    next_keepalive = now + 3
                readable, _, _ = select.select([carrier, tap], [], [], max(0, next_keepalive - now))
                if carrier in readable:
                    with suppress(BlockingIOError, ConnectionRefusedError):
                        frame = decode_frame(carrier.recv(65535), local, peer, tunnel_id, maximum)
                        if frame:
                            os.write(tap, frame)
                if tap in readable:
                    with suppress(BlockingIOError, ConnectionRefusedError):
                        frame = os.read(tap, maximum + 1)
                        if 14 <= len(frame) <= maximum:
                            send_frame(carrier, endpoint, tunnel_id, frame)
    finally:
        os.close(tap)


if __name__ == "__main__":
    run_link(json.loads(Path(sys.argv[1]).read_text()))
