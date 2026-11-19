"""Manage a static Ethernet L2TPv3 session and its dedicated UDP tunnel."""
import contextlib
import json

from .model import PanelError
from .store import atomic_json


class L2TPv3:
    method, module = "l2tpv3", "l2tp_eth"

    def marker(self, link):
        return "gremgr:v2:" + link["id"]

    def firewall(self, link):
        offset = "0>>22&0x3C"
        match = f"{offset}@8&0x800F0000=0x00030000 && {offset}@12=0x{link['session_id']:08x}"
        return ["-p", "udp", "--sport", link["peer_port"], "--dport", link["listen_port"], "-m", "u32", "--u32", match]

    def owns(self, link, row):
        return row.get("ifalias") == self.marker(link) and row.get("link_type") == "ether"

    @staticmethod
    def journal(paths, link):
        return paths.var / "l2tpv3" / (link["tunnel"] + ".json")

    def expected(self, link):
        return {"tunnel_id": link["tunnel_id"], "encap": "UDP", "local": link["outer_local"], "peer": link["outer_peer"],
                "peer_tunnel": link["peer_tunnel_id"], "local_port": link["listen_port"], "peer_port": link["peer_port"]}

    @staticmethod
    def session(link):
        return {"session_id": link["session_id"], "tunnel_id": link["tunnel_id"], "peer_session_id": link["peer_session_id"],
                "peer_tunnel_id": link["peer_tunnel_id"], "interface": link["tunnel"]}

    def receipt(self, link, phase="ready"):
        return {"id": link["id"], "tunnel": self.expected(link), "session": self.session(link), "phase": phase}

    def phase(self, paths, link):
        try:
            observed = json.loads(self.journal(paths, link).read_text())
        except (OSError, ValueError):
            return None
        if not isinstance(observed, dict):
            return None
        phase = observed.get("phase", "ready")
        if phase in ("pending", "ready", "removing") and dict(observed, phase=phase) == self.receipt(link, phase):
            return phase

    @staticmethod
    def device(link, run):
        result = run("ip", "-j", "-d", "link", "show", "dev", link["tunnel"], check=False)
        rows = json.loads(result.stdout) if result.returncode == 0 else []
        return rows[0] if rows else None

    def session_owned(self, link, phase, run):
        row = self.device(link, run)
        if not row or row.get("ifname") != link["tunnel"] or row.get("link_type") != "ether":
            return False
        return self.owns(link, row) or (phase == "pending" and not row.get("ifalias"))

    @staticmethod
    def reads(run, kind, allow_empty=False):
        result = run("ip", "-j", "l2tp", "show", kind, check=False)
        if result.returncode:
            if allow_empty and "genl family" in result.stderr.lower():
                return []
            raise PanelError("The installed iproute2 could not inspect static L2TPv3.", "method", "l2tpv3")
        return json.loads(result.stdout)

    @staticmethod
    def matches(expected, observed):
        return all(observed.get(key) == value for key, value in expected.items())

    def check(self, links, interfaces, paths, run):
        if not links:
            return
        if run("modprobe", "-nq", self.module, check=False).returncode:
            raise PanelError("Static L2TPv3 needs the Linux Ethernet pseudowire module.", "method", "l2tpv3")
        tunnels = self.reads(run, "tunnel", allow_empty=True)
        sessions = self.reads(run, "session", allow_empty=True)
        ids, session_ids, ports = {}, {}, {}
        for link in links:
            phase = self.phase(paths, link)
            if link["outer_local"] not in interfaces:
                raise PanelError("The L2TPv3 source address is unavailable.", "local_ip", "outer_ip")
            for claims, field in ((ids, "tunnel_id"), (session_ids, "session_id"), (ports, "listen_port")):
                if claims.setdefault(link[field], link["tunnel"]) != link["tunnel"]:
                    raise PanelError("Choose a separate L2TPv3 tunnel ID, session ID and local UDP port.", "device_conflict", field)
            for row in tunnels:
                if row.get("tunnel_id") == link["tunnel_id"] or row.get("local_port") == link["listen_port"]:
                    if not phase or not self.matches(self.expected(link), row):
                        raise PanelError("A different L2TP tunnel uses this ID or port.", "device_conflict", "l2tpv3")
            for row in sessions:
                if row.get("session_id") == link["session_id"] or row.get("interface") == link["tunnel"]:
                    if not phase or not self.matches(self.session(link), row) or not self.session_owned(link, phase, run):
                        raise PanelError("A different L2TP session uses this ID.", "device_conflict", "l2tpv3")
        kernel_ports = {row.get("local_port") for row in tunnels}
        for line in run("ss", "-H", "-una").stdout.splitlines():
            fields = line.split()
            port = fields[3].rsplit(":", 1)[-1] if len(fields) > 3 else ""
            if port.isdecimal() and int(port) in ports.keys() - kernel_ports:
                raise PanelError("An existing UDP socket already uses the L2TPv3 port.", "device_conflict", "port")

    def configure(self, link, paths, run):
        run("modprobe", "l2tp_netlink", check=False)
        phase = self.phase(paths, link)
        tunnels = self.reads(run, "tunnel")
        sessions = self.reads(run, "session")
        current = next((row for row in tunnels if row.get("tunnel_id") == link["tunnel_id"]), None)
        existing = next((row for row in sessions if row.get("session_id") == link["session_id"]), None)
        if current and (not phase or not self.matches(self.expected(link), current)):
            raise PanelError("L2TPv3 tunnel ownership changed before apply.", "device_conflict")
        if existing and (not phase or not self.matches(self.session(link), existing) or not self.session_owned(link, phase, run)):
            raise PanelError("L2TPv3 session ownership changed before apply.", "device_conflict")
        if not existing:
            if self.device(link, run):
                raise PanelError("A different interface uses the L2TPv3 device name.", "device_conflict")
            atomic_json(self.journal(paths, link), self.receipt(link, "pending"))
        if not current:
            run("ip", "l2tp", "add", "tunnel", "tunnel_id", link["tunnel_id"], "peer_tunnel_id", link["peer_tunnel_id"],
                "encap", "udp", "local", link["outer_local"], "remote", link["outer_peer"], "udp_sport", link["listen_port"],
                "udp_dport", link["peer_port"])
        if not existing:
            try:
                run("ip", "l2tp", "add", "session", "tunnel_id", link["tunnel_id"], "session_id", link["session_id"],
                    "peer_session_id", link["peer_session_id"], "name", link["tunnel"])
            except PanelError:
                if not current:
                    with contextlib.suppress(PanelError):
                        self.remove(link, paths, run)
                raise
        run("ip", "link", "set", "dev", link["tunnel"], "alias", self.marker(link))
        atomic_json(self.journal(paths, link), self.receipt(link))

    def remove(self, link, paths, run):
        phase = self.phase(paths, link)
        if not phase:
            return
        existing = next((row for row in self.reads(run, "tunnel", allow_empty=True) if row.get("tunnel_id") == link["tunnel_id"]), None)
        if not existing:
            self.journal(paths, link).unlink(missing_ok=True)
            return
        if not self.matches(self.expected(link), existing):
            return
        sessions = [row for row in self.reads(run, "session") if row.get("tunnel_id") == link["tunnel_id"]]
        ours = next((row for row in sessions if self.matches(self.session(link), row)), None)
        if ours:
            if not self.session_owned(link, phase, run):
                return
            if phase != "pending":
                phase = "removing"
                atomic_json(self.journal(paths, link), self.receipt(link, phase))
            run("ip", "l2tp", "del", "session", "tunnel_id", link["tunnel_id"], "session_id", link["session_id"])
            sessions = [row for row in self.reads(run, "session") if row.get("tunnel_id") == link["tunnel_id"]]
        if not sessions and phase in ("pending", "removing"):
            run("ip", "l2tp", "del", "tunnel", "tunnel_id", link["tunnel_id"])
            self.journal(paths, link).unlink(missing_ok=True)
