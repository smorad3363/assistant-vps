"""Run an isolated xl2tpd/pppd instance for a managed L2TPv2 link."""
import hashlib
import ipaddress
import json
import re
import shutil
import stat

from .model import PanelError
from .store import atomic_json


class L2TPv2:
    method, module = "l2tpv2", "ppp_generic"

    def available(self, run):
        return shutil.which("xl2tpd") and shutil.which("pppd") and not run("modprobe", "-nq", self.module, check=False).returncode

    def firewall(self, link):
        return ["-p", "udp", "--sport", link["peer_port"], "--dport", link["listen_port"]]

    @staticmethod
    def credential(paths, name):
        if not re.fullmatch(r"[a-zA-Z0-9_-]{1,48}", name):
            raise PanelError("Choose a valid local PPP credential name.", "ppp_credential", "credential")
        file = paths.etc / "ppp-credentials" / name
        try:
            info = file.lstat()
            if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077 or info.st_uid != 0 or info.st_size > 129:
                raise OSError()
            secret = file.read_text().strip()
            if not re.fullmatch(r"[a-f0-9]{64}", secret):
                raise ValueError()
        except (OSError, ValueError) as error:
            raise PanelError("Provide the local root-owned PPP credential with mode 0600 and a 32-byte hex secret.",
                             "ppp_credential", "credential") from error
        return secret

    @staticmethod
    def unit(link):
        return "gremgr-ppp-" + link["id"] + ".service"

    @staticmethod
    def description(link):
        return "GRE Manager L2TPv2 link " + link["tunnel"]

    def profile(self, paths, link):
        return paths.var / "l2tpv2" / link["tunnel"]

    def status(self, link, run):
        result = run("systemctl", "show", self.unit(link), "--property=LoadState,ActiveState,Description,Transient,MainPID", check=False)
        properties = dict(line.split("=", 1) for line in result.stdout.splitlines() if "=" in line)
        if properties.get("LoadState") == "not-found":
            return {}
        if result.returncode or properties.get("Transient") != "yes" or properties.get("Description") != self.description(link):
            raise PanelError("A different systemd service uses the PPP link unit name.", "device_conflict", "l2tpv2")
        return properties

    def check(self, links, interfaces, paths, run):
        if not self.available(run):
            raise PanelError("Install xl2tpd and ppp and enable the Linux PPP kernel module on both hosts.", "method", "l2tpv2")
        ports = {}
        sockets = run("ss", "-H", "-lunp").stdout.splitlines()
        routes = json.loads(run("ip", "-j", "-4", "route", "show", "table", "all").stdout)
        for link in links:
            self.credential(paths, link["credential"])
            if ports.setdefault(link["listen_port"], link["tunnel"]) != link["tunnel"]:
                raise PanelError("Use a dedicated UDP port for each L2TPv2 link.", "device_conflict", "port")
            status = self.status(link, run)
            pid = status.get("MainPID", "0")
            for line in sockets:
                fields = line.split()
                endpoint = fields[3].rsplit(":", 1)[-1] if len(fields) > 3 else ""
                if endpoint == str(link["listen_port"]) and f"pid={pid}," not in line:
                    raise PanelError("A different UDP socket uses the L2TPv2 port.", "device_conflict", "port")
            if not status and run("ip", "link", "show", "dev", link["tunnel"], check=False).returncode == 0:
                raise PanelError("A different interface uses the PPP link name.", "device_conflict", "l2tpv2")
            inner = ipaddress.IPv4Network(link["local_tun"] + "/30", strict=False)
            for route in routes:
                target = route.get("dst")
                if target and target != "default" and route.get("dev") != link["tunnel"]:
                    if inner.overlaps(ipaddress.IPv4Network(target, strict=False)):
                        raise PanelError("The private PPP subnet overlaps an existing route.", "route_conflict", "l2tpv2")

    def configure(self, link, paths, run):
        directory = self.profile(paths, link)
        secret = self.credential(paths, link["credential"])
        profile_id = hashlib.sha256(json.dumps(link, sort_keys=True).encode() + secret.encode()).hexdigest()
        status = self.status(link, run)
        marker = directory / "profile.json"
        if status and status.get("ActiveState") in ("active", "activating") and marker.exists():
            if json.loads(marker.read_text()) == profile_id:
                return
        if status:
            run("systemctl", "stop", self.unit(link))
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        private = directory / "ppp"
        private.mkdir(mode=0o700, exist_ok=True)
        global_options = f"[global]\nlisten-addr = {link['outer_local']}\nport = {link['listen_port']}\naccess control = yes\n"
        local, peer = link["local_tun"], link["peer_tun"]
        local_name, peer_name = ("gremgr-lac", "gremgr-lns") if link["lac"] else ("gremgr-lns", "gremgr-lac")
        ppp_options = (f"ifname {link['tunnel']}\nname {local_name}\nremotename {peer_name}\n{local}:{peer}\n"
                       f"mtu {link['mtu']}\nmru {link['mtu']}\nnoipdefault\nnodefaultroute\n"
                       "require-mschap-v2\nrefuse-pap\nnoipv6\nlcp-echo-interval 5\nlcp-echo-failure 3\n")
        if link["lac"]:
            role = (f"[lac gremgr]\nlns = {link['outer_peer']}:{link['peer_port']}\nname = {local_name}\n"
                    "autodial = yes\nredial = yes\nredial timeout = 3\n")
        else:
            role = (f"[lns default]\nlac = {link['outer_peer']} - {link['outer_peer']}\nip range = {peer} - {peer}\n"
                    f"local ip = {local}\nname = {local_name}\nrequire authentication = yes\nrequire chap = yes\nrefuse pap = yes\n")
        (directory / "xl2tpd.conf").write_text(global_options + role + "length bit = yes\npppoptfile = /etc/ppp/gremgr-options\n")
        (private / "options").write_text("")
        (private / "gremgr-options").write_text(ppp_options)
        chap = private / "chap-secrets"
        chap.touch(mode=0o600, exist_ok=True)
        chap.write_text(f"{local_name} {peer_name} {secret} {peer}\n{peer_name} {local_name} {secret} {peer}\n")
        atomic_json(marker, profile_id)
        run("modprobe", self.module, check=False)
        run("systemd-run", "--quiet", "--collect", "--unit=" + self.unit(link), "--description=" + self.description(link),
            "--property=Type=exec", "--property=Restart=on-failure", "--property=RestartSec=3s",
            "--property=BindReadOnlyPaths=" + str(private) + ":/etc/ppp", "--property=UMask=0077",
            shutil.which("xl2tpd") or "xl2tpd", "-D", "-c", str(directory / "xl2tpd.conf"),
            "-p", str(directory / "daemon.pid"), "-C", str(directory / "control"))

    def remove(self, link, paths, run):
        if self.status(link, run):
            run("systemctl", "stop", self.unit(link))
        directory = self.profile(paths, link)
        if directory.exists():
            shutil.rmtree(directory)
