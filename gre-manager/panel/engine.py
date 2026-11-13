"""Owned GRE devices and scoped Netfilter rules. Never restores a host firewall."""
from collections import defaultdict
import contextlib
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import time
import uuid

from .model import PanelError, address, ranges_for, subtract
from .store import atomic_json

CHAINS = {"nat": ["GMP_PRE", "GMP_POST"], "filter": ["GMP_FWD", "GMP_INPUT", "GMP_COUNT"], "mangle": ["GMP_MSS"]}
HOOKS = [("nat", "PREROUTING", "GMP_PRE"), ("nat", "POSTROUTING", "GMP_POST"),
         ("filter", "FORWARD", "GMP_FWD"), ("filter", "INPUT", "GMP_INPUT"), ("mangle", "FORWARD", "GMP_MSS")]


def run(*args, check=True, timeout=20, input=None):
    try:
        result = subprocess.run([str(x) for x in args], input=input, capture_output=True, text=True,
                                timeout=timeout, env=dict(os.environ, LC_ALL="C"))
    except (OSError, subprocess.TimeoutExpired) as error:
        raise PanelError("A required system command failed or timed out.", "system") from error
    if check and result.returncode:
        # Never include stdin: remote provisioning and key material use it.
        raise PanelError((result.stderr or result.stdout or "Network command failed.").strip()[-800:], "network")
    return result


def pair_values(local, remote):
    digest = hashlib.sha256("|".join(sorted((local, remote))).encode()).hexdigest()
    index = int(digest[:6], 16) % (16 * 16384)
    network = ipaddress.IPv4Network((int(ipaddress.IPv4Address("10.240.0.0")) + index * 4, 30))
    hosts = list(map(str, network.hosts()))
    if ipaddress.IPv4Address(local) > ipaddress.IPv4Address(remote):
        hosts.reverse()
    return {"id": digest[:10], "tunnel": "gmp-" + digest[:10], "local_tun": hosts[0], "peer_tun": hosts[1],
            "key": int(digest[:8], 16) or 1, "outer_local": local, "outer_peer": remote}


def local_addresses():
    data = json.loads(run("ip", "-j", "-4", "addr", "show").stdout)
    return {a["local"]: row["ifname"] for row in data for a in row.get("addr_info", []) if a.get("scope") != "host"}


def discovered_ssh_ports():
    result = run("sshd", "-T", check=False)
    return sorted({int(x.split()[1]) for x in result.stdout.splitlines() if re.fullmatch(r"port [0-9]+", x)}) or [22]


def gre_for(c):
    local = c.get("outer_local", c["listen_ip"])
    remote = c["resolved_ip"]
    result = pair_values(local, remote)
    result["mtu"] = c["mtu"]
    return result


def match_port(low, high):
    return str(low) if low == high else f"{low}:{high}"


def monitored(c, settings):
    explicit = c.get("monitor_ports", []) + [int(x) for x in c.get("port_limits", {})]
    ranges = ranges_for(c, settings)
    # Specific port lists are individually counted; wide ranges remain grouped
    # until the operator selects ports to monitor. Never adds 65k firewall rules.
    if sum(hi - lo + 1 for lo, hi in ranges) <= 128:
        explicit += [p for lo, hi in ranges for p in range(lo, hi + 1)]
    return sorted({p for p in explicit if any(lo <= p <= hi for lo, hi in ranges)})


def build_rules(config, interfaces, docker_udp=False):
    tables = {table: {name: [] for name in names} for table, names in CHAINS.items()}

    def add(table, chain, *args):
        tables[table][chain].append(list(map(str, args)))

    def tag(identity, port, direction):
        return ["-m", "comment", "--comment", f"gmpanel:{identity}:{port}:{direction}"]

    # ACCEPT in nat terminates this hook, including any older broad DNAT rule
    # after our dispatcher. RETURN alone would not protect panel/SSH access.
    protected = sorted(set(config["settings"]["ssh_ports"] + config["settings"]["reserved_ports"] + [22, config["settings"]["port"]]))
    panel_enabled = config.get("web_enabled", any(x["kind"] != "peer" for x in config["connections"]))
    protected_ips = set(interfaces) if panel_enabled else {x["listen_ip"] for x in config["connections"] if x["kind"] != "peer"}
    for ip in sorted(protected_ips):
        for proto in ("tcp", "udp"):
            for p in protected:
                add("nat", "GMP_PRE", "-i", interfaces[ip], "-d", ip, "-p", proto, "--dport", p, "-j", "ACCEPT")
        if panel_enabled:
            add("filter", "GMP_INPUT", "-i", interfaces[ip], "-d", ip, "-p", "tcp", "--dport", config["settings"]["port"], "-j", "ACCEPT")

    def limiter(base, identity, direction, speed, port="all"):
        if not speed:
            return
        # Byte-rate policing is confined to this flow. No host qdisc is replaced.
        per_second = max(1000, int(speed * 1000000 / 8))
        burst = max(16384, min(100000000, per_second // 5))
        rate_name = f"gm{identity}{direction[0]}{port}"[:30]
        add("filter", "GMP_FWD", *base, "-m", "hashlimit", "--hashlimit-above", f"{per_second}b/s",
            "--hashlimit-burst", str(burst), "--hashlimit-name", rate_name, "--hashlimit-htable-expire", "1000",
            "-j", "DROP")

    for c in config["connections"]:
        if not c.get("enabled", True):
            continue
        identity = c["id"]
        if c["kind"] == "peer":
            g = c["gre"]
            t, peer = g["tunnel"], g["peer_tun"]
            wan = interfaces[g["outer_local"]]
            add("filter", "GMP_INPUT", "-i", wan, "-s", g["outer_peer"], "-d", g["outer_local"], "-p", "gre", "-j", "ACCEPT")
            add("filter", "GMP_INPUT", "-i", t, "-s", peer, "-d", g["local_tun"], "-p", "icmp", "-j", "ACCEPT")
            for proto in ("tcp", "udp"):
                incoming = ["-i", t, "-s", peer, "-d", g["local_tun"], "-p", proto]
                if docker_udp and proto == "udp" and c["service_ip"] in interfaces:
                    add("nat", "GMP_PRE", *incoming, "--dport", "51820", "-j", "DOCKER")
                add("nat", "GMP_PRE", *incoming, "-j", "DNAT", "--to-destination", c["service_ip"])
                add("filter", "GMP_INPUT", "-i", t, "-s", peer, "-d", c["service_ip"], "-p", proto,
                    "-m", "conntrack", "--ctstate", "DNAT", "-j", "ACCEPT")
                add("filter", "GMP_FWD", "-i", t, "-s", peer, "-p", proto, "-m", "conntrack", "--ctstate", "DNAT", "-j", "ACCEPT")
                add("filter", "GMP_FWD", "-o", t, "-d", peer, "-p", proto, "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT")
                if c["service_ip"] not in interfaces:
                    add("nat", "GMP_POST", "-s", peer, "-d", c["service_ip"], "-p", proto,
                        "-m", "conntrack", "--ctstate", "DNAT", "-j", "MASQUERADE")
            continue

        wan = interfaces[c["listen_ip"]]
        if c["kind"] == "gre":
            g = gre_for(c)
            dest, device = g["peer_tun"], g["tunnel"]
            add("filter", "GMP_INPUT", "-i", interfaces[g["outer_local"]], "-s", g["outer_peer"], "-d", g["outer_local"], "-p", "gre", "-j", "ACCEPT")
            add("filter", "GMP_INPUT", "-i", device, "-s", dest, "-d", g["local_tun"], "-p", "icmp", "-j", "ACCEPT")
        else:
            dest, device = c["resolved_ip"], None
        mapped = {int(p): int(d) for p, d in c.get("port_map", {}).items()}
        segments = [(p, p, d) for p, d in sorted(mapped.items())]
        segments += [(lo, hi, c.get("target_port")) for lo, hi in subtract(ranges_for(c, config["settings"]), mapped)]
        for proto in c["protocols"]:
            for low, high, target_port in segments:
                destination = dest + (":" + str(target_port) if target_port else "")
                add("nat", "GMP_PRE", "-i", wan, "-d", c["listen_ip"], "-p", proto, "--dport", match_port(low, high),
                    "-m", "comment", "--comment", f"gmpanel:{identity}", "-j", "DNAT", "--to-destination", destination)
                conn = ["-p", proto, "-m", "conntrack", "--ctstate", "DNAT", "--ctorigdst", c["listen_ip"], "--ctorigdstport", match_port(low, high)]
                for direction, original in (("up", True), ("down", False)):
                    base = [*conn, "--ctdir", "ORIGINAL" if original else "REPLY"]
                    base += ["-i" if original else "-o", wan]
                    if device:
                        base += ["-o" if original else "-i", device]
                    else:
                        base += ["-d" if original else "-s", dest]
                    for port, values in c.get("port_limits", {}).items():
                        if low <= int(port) <= high:
                            pbase = [*base, "-m", "conntrack", "--ctorigdstport", port]
                            limiter(pbase, identity, direction, values[direction], port)
                    limiter(base, identity, direction, c["upload_mbps"] if original else c["download_mbps"])
                    add("filter", "GMP_FWD", *base, "-j", "GMP_COUNT")
                    add("filter", "GMP_FWD", *base, *tag(identity, "all", direction), "-j", "ACCEPT")
                    for port in monitored(c, config["settings"]):
                        if low <= port <= high:
                            add("filter", "GMP_COUNT", *base, "-m", "conntrack", "--ctorigdstport", port,
                                *tag(identity, str(port), direction), "-j", "RETURN")
            post = ["-d", dest, "-p", proto, "-m", "conntrack", "--ctstate", "DNAT", "--ctorigdst", c["listen_ip"]]
            # Constrain by original input port too: two rules can share a target.
            for low, high in ranges_for(c, config["settings"]):
                suffix = ["-m", "conntrack", "--ctorigdstport", match_port(low, high)]
                if device:
                    add("nat", "GMP_POST", *post, *suffix, "-o", device, "-j", "SNAT", "--to-source", g["local_tun"])
                else:
                    add("nat", "GMP_POST", *post, *suffix, "-j", "MASQUERADE")
        if device:
            for switch in ("-i", "-o"):
                add("mangle", "GMP_MSS", switch, device, "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN",
                    "-j", "TCPMSS", "--set-mss", c["mtu"] - 40)
    return tables


class Engine:
    def __init__(self, paths, runner=run):
        self.paths, self.run = paths, runner
        self.epoch_file = paths.run / "counter-epoch"

    def interfaces(self):
        rows = json.loads(self.run("ip", "-j", "-4", "addr", "show").stdout)
        return {x["local"]: row["ifname"] for row in rows for x in row.get("addr_info", []) if x.get("scope") != "host"}

    def preflight(self, config):
        interfaces = self.interfaces()
        for c in config["connections"]:
            if not c.get("enabled", True):
                continue
            local = c["gre"]["outer_local"] if c["kind"] == "peer" else c["listen_ip"]
            if local not in interfaces or (c["kind"] == "gre" and c.get("outer_local", local) not in interfaces):
                raise PanelError("The selected local IP is not assigned to this server.", "local_ip", "listen_ip")
            if c["kind"] == "direct" and c["resolved_ip"] in interfaces:
                raise PanelError("A direct destination cannot be the input server itself.", "loop")
        existing = self.run("iptables-save", "-t", "nat").stdout
        for line in existing.splitlines():
            if not line.startswith("-A PREROUTING ") or "-j DNAT" not in line or "gmpanel:" in line:
                continue
            if any("gmp:" + c.get("legacy_pair", {}).get("id", "__none__") in line for c in config["connections"]):
                continue
            parts = shlex.split(line)
            destination = parts[parts.index("-d") + 1] if "-d" in parts else None
            for c in config["connections"]:
                if not c.get("enabled", True) or c["kind"] == "peer":
                    continue
                if destination and ipaddress.IPv4Address(c["listen_ip"]) not in ipaddress.IPv4Network(destination, strict=False):
                    continue
                if "-p" in parts and parts[parts.index("-p") + 1] not in c["protocols"]:
                    continue
                # Broad or unparseable external rules are conservatively conflicts.
                raw = parts[parts.index("--dport") + 1] if "--dport" in parts else parts[parts.index("--dports") + 1] if "--dports" in parts else "1:65535"
                try:
                    ext = []
                    for item in raw.split(","):
                        p = item.split(":")
                        ext.append((int(p[0]), int(p[-1])))
                    overlap = any(max(a, x) <= min(b, y) for a, b in ranges_for(c, config["settings"]) for x, y in ext)
                except ValueError:
                    overlap = True
                if overlap:
                    raise PanelError("An existing external port forward overlaps this connection. Migrate it explicitly first.", "external_conflict")
        return interfaces

    def ensure_gre(self, g, interfaces):
        self.run("modprobe", "ip_gre", check=False)
        current = self.run("ip", "-j", "-d", "link", "show", g["tunnel"], check=False)
        if current.returncode == 0:
            details = json.loads(current.stdout)[0].get("linkinfo", {})
            data = details.get("info_data", {})
            key = data.get("ikey", 0)
            if isinstance(key, str):
                key = int(ipaddress.IPv4Address(key)) if "." in key else int(key)
            if details.get("info_kind") != "gre" or data.get("local") != g["outer_local"] or data.get("remote") != g["outer_peer"] or key != g["key"]:
                raise PanelError("Another program owns this GRE interface.", "device_conflict")
        else:
            for route in json.loads(self.run("ip", "-j", "-4", "route", "show").stdout):
                if route.get("dst") not in (None, "default") and ipaddress.IPv4Address(g["local_tun"]) in ipaddress.IPv4Network(route["dst"], strict=False):
                    raise PanelError("The private GRE subnet overlaps an existing route.", "route_conflict")
            self.run("ip", "tunnel", "add", g["tunnel"], "mode", "gre", "local", g["outer_local"], "remote", g["outer_peer"], "key", g["key"], "ttl", "64", "dev", interfaces[g["outer_local"]])
        self.run("ip", "addr", "replace", g["local_tun"] + "/30", "dev", g["tunnel"])
        self.run("ip", "link", "set", "dev", g["tunnel"], "mtu", g["mtu"], "up")
        self.run("sysctl", "-qw", "net.ipv4.conf." + g["tunnel"] + ".rp_filter=2")

    def docker_udp(self):
        result = self.run("iptables", "-w", "10", "-t", "nat", "-S", "DOCKER", check=False)
        return result.returncode == 0 and any("-p udp" in x and "--dport 51820" in x and "-j DNAT" in x for x in result.stdout.splitlines())

    def restore_owned(self, tables):
        for table, chains in tables.items():
            # --noflush plus explicit own-chain flush keeps all unrelated state.
            for name in chains:
                self.run("iptables", "-w", "10", "-t", table, "-N", name, check=False)
            lines = ["*" + table]
            lines += ["-F " + name for name in chains]
            for name, rules in chains.items():
                lines += ["-A " + name + " " + shlex.join(rule) for rule in rules]
            lines.append("COMMIT")
            self.run("iptables-restore", "-w", "10", "--noflush", input="\n".join(lines) + "\n")
        for table, parent, own in HOOKS:
            prefix = ("iptables", "-w", "10", "-t", table)
            if self.run(*prefix, "-C", parent, "-m", "comment", "--comment", "gmpanel:hook", "-j", own, check=False).returncode:
                self.run(*prefix, "-I", parent, "1", "-m", "comment", "--comment", "gmpanel:hook", "-j", own)
        self.epoch_file.write_text(uuid.uuid4().hex)

    def apply(self, config, previous=None):
        interfaces = self.preflight(config)
        previous = previous or dict(config, connections=[])
        old_gre = {g["tunnel"]: g for g in self.gre_devices(previous)}
        try:
            for g in self.gre_devices(config):
                self.ensure_gre(g, interfaces)
            if any(x.get("enabled", True) for x in config["connections"]):
                self.run("sysctl", "-qw", "net.ipv4.ip_forward=1")
            self.restore_owned(build_rules(config, interfaces, self.docker_udp()))
        except Exception:
            with contextlib.suppress(Exception):
                for g in old_gre.values():
                    self.ensure_gre(g, interfaces)
                self.restore_owned(build_rules(previous, interfaces, self.docker_udp()))
            for g in self.gre_devices(config):
                if g["tunnel"] not in old_gre:
                    self.remove_gre(g)
            raise
        wanted = {g["tunnel"] for g in self.gre_devices(config)}
        for name, g in old_gre.items():
            if name not in wanted:
                self.remove_gre(g)

    @staticmethod
    def gre_devices(config):
        for c in config["connections"]:
            if c.get("enabled", True) and c["kind"] in ("gre", "peer"):
                yield c["gre"] if c["kind"] == "peer" else gre_for(c)

    def remove_gre(self, g):
        # Verify ownership even on deletion. Never deletes an arbitrary name.
        current = self.run("ip", "-j", "-d", "link", "show", g["tunnel"], check=False)
        if current.returncode:
            return
        details = json.loads(current.stdout)[0].get("linkinfo", {})
        data = details.get("info_data", {})
        key = data.get("ikey", 0)
        if isinstance(key, str):
            key = int(ipaddress.IPv4Address(key)) if "." in key else int(key)
        if details.get("info_kind") == "gre" and data.get("local") == g["outer_local"] and data.get("remote") == g["outer_peer"] and key == g["key"]:
            self.run("ip", "tunnel", "del", g["tunnel"])

    def retire_legacy(self, config):
        """Adopt only matching pair profiles, after their replacement is active."""
        for g in self.gre_devices(config):
            path = self.paths.etc / "pairs" / (g["id"] + ".json")
            if not path.exists():
                continue
            saved = json.loads(path.read_text())
            if saved.get("outer_local") != g["outer_local"] or saved.get("outer_peer") != g["outer_peer"]:
                continue
            backup = self.paths.etc / "pairs" / "backups" / (g["id"] + "-panel-adopted.json")
            backup.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            # Removing the profile first makes legacy ExecStop refuse operation,
            # so stopping its unit cannot remove the still-active GRE device.
            os.replace(path, backup)
            unit = "gremgr-pair@" + g["id"] + ".service"
            self.run("systemctl", "disable", unit, check=False)
            self.run("systemctl", "stop", unit, check=False)
            self.run("systemctl", "reset-failed", unit, check=False)
            for table in ("nat", "filter", "mangle"):
                current = self.run("iptables-save", "-t", table).stdout
                for line in current.splitlines():
                    if not line.startswith("-A "):
                        continue
                    tokens = shlex.split(line)
                    if "--comment" not in tokens:
                        continue
                    comment = tokens[tokens.index("--comment") + 1]
                    if comment.startswith("gmp:" + g["id"] + ":"):
                        self.run("iptables", "-w", "10", "-t", table, "-D", *tokens[1:], check=False)

    def counters(self):
        raw = self.run("iptables-save", "-c", "-t", "filter", check=False)
        result = defaultdict(lambda: [0, 0])
        for line in raw.stdout.splitlines():
            counts = re.match(r"\[(\d+):(\d+)\] -A GMP_(?:FWD|COUNT) ", line)
            label = re.search(r"gmpanel:([a-f0-9]{10}):(all|[0-9]+):(up|down)", line)
            if counts and label:
                result[(label[1], label[2])][0 if label[3] == "up" else 1] += int(counts[2])
        epoch = self.epoch_file.read_text().strip() if self.epoch_file.exists() else "initial"
        return dict(result), epoch

    def probe(self, c):
        health = {"checked": time.time(), "gre": None, "tcp": None, "udp": None, "latency_ms": None,
                  "message": "UDP needs an application response; an open UDP socket alone is not proof."}
        if not c.get("enabled", True):
            return dict(health, message="Connection is paused.")
        if c["kind"] == "gre":
            g = gre_for(c)
            result = self.run("ping", "-n", "-I", g["tunnel"], "-c", "3", "-W", "2", g["peer_tun"], check=False, timeout=10)
            health["gre"] = result.returncode == 0
            rtt = re.search(r"= [\d.]+/([\d.]+)/", result.stdout)
            loss = re.search(r"([\d.]+)% packet loss", result.stdout)
            health["latency_ms"] = float(rtt[1]) if rtt else None
            health["loss_percent"] = float(loss[1]) if loss else None
            health["mtu"] = c["mtu"]
        if "tcp" in c["protocols"] and c["ports"] != "all":
            import socket
            port = c.get("target_port") or ranges_for(c, {"ssh_ports": [], "reserved_ports": [], "port": 0})[0][0]
            target = c.get("service_ip", c["resolved_ip"])
            try:
                with socket.create_connection((target, port), timeout=3):
                    health["tcp"] = True
            except OSError:
                health["tcp"] = False
        return health

    def choose_mtu(self, c, ceiling):
        g = gre_for(c)
        # A small successful probe alone is not enough. Test full payloads;
        # cap the result and retain headroom instead of maximizing path capacity.
        for candidate in sorted({min(ceiling, x) for x in (1400, 1380, 1360, 1320, 1280)}, reverse=True):
            result = self.run("ping", "-n", "-I", g["tunnel"], "-M", "do", "-s", candidate - 28, "-c", "3", "-W", "2", g["peer_tun"], check=False, timeout=10)
            if result.returncode == 0 and "0% packet loss" in result.stdout:
                return max(576, candidate - 20)
        raise PanelError("The GRE MTU probe failed. Check protocol 47 and both endpoints.", "gre_probe")
