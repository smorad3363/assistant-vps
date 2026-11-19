"""Owned GRE devices and scoped Netfilter rules. Never restores a host firewall."""
from collections import defaultdict
import contextlib
import fcntl
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import shlex
import subprocess
import time
import uuid

from .model import PanelError, address, ranges_for, subtract
from .store import atomic_json
from .v2_drivers import driver_for, gre_key, ipv6_enabled, local_wireguard_key
from .v2_forwarding import add_listener_rules, add_receiver_rules, installed_topology, require_ssh_protection
from .v2_resources import admission_pressure, pressure_file

CHAINS = {"nat": ["GMP_PRE", "GMP_POST", "GMP_LOCAL"], "filter": ["GMP_FWD", "GMP_INPUT", "GMP_COUNT"],
          "mangle": ["GMP_MSS", "GMP_MSS_LOCAL"]}
HOOKS = [("nat", "PREROUTING", "GMP_PRE"), ("nat", "POSTROUTING", "GMP_POST"), ("nat", "INPUT", "GMP_LOCAL"),
         ("filter", "FORWARD", "GMP_FWD"), ("filter", "INPUT", "GMP_INPUT"), ("mangle", "FORWARD", "GMP_MSS"),
         ("mangle", "OUTPUT", "GMP_MSS_LOCAL")]


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


def pair_values(local, remote, slot=0):
    digest = hashlib.sha256("|".join(sorted((local, remote))).encode()).hexdigest()
    index = (int(digest[:6], 16) + slot) % (16 * 16384)
    network = ipaddress.IPv4Network((int(ipaddress.IPv4Address("10.240.0.0")) + index * 4, 30))
    hosts = list(map(str, network.hosts()))
    if ipaddress.IPv4Address(local) > ipaddress.IPv4Address(remote):
        hosts.reverse()
    result = {"id": digest[:10], "tunnel": "gmp-" + digest[:10], "local_tun": hosts[0], "peer_tun": hosts[1],
              "key": int(digest[:8], 16) or 1, "outer_local": local, "outer_peer": remote}
    if slot:
        result["slot"] = slot
    return result


def local_addresses():
    data = json.loads(run("ip", "-j", "-4", "addr", "show").stdout)
    return {a["local"]: row["ifname"] for row in data for a in row.get("addr_info", []) if a.get("scope") != "host"}


def discovered_ssh_ports():
    def probe(*args):
        with contextlib.suppress(PanelError):
            result = run(*args, check=False, timeout=5)
            if result.returncode == 0 and (args[0] != "ss" or not result.stderr):
                return result.stdout
        return None

    def port(value):
        number = value.rsplit(":", 1)[-1]
        if re.fullmatch(r"[0-9]{1,5}", number) and 1 <= int(number) <= 65535:
            ports.add(int(number))

    ports = set()
    config = probe("sshd", "-T") or ""
    for line in config.splitlines():
        fields = line.split()
        if len(fields) == 2 and fields[0] in ("port", "listenaddress"):
            port(fields[1])
    connection = os.environ.get("SSH_CONNECTION", "").split()
    if len(connection) == 4:
        port(connection[3])

    listening = probe("ss", "-H", "-ltnp")
    sockets = probe("systemctl", "list-sockets", "--no-legend", "--no-pager", "--plain")
    systemd_listener = False
    for line in (listening or "").splitlines():
        fields = line.split()
        if len(fields) < 5:
            continue
        owners = " ".join(fields[5:])
        if re.search(r'\("(?:sshd(?:-session)?|dropbear)",', owners):
            port(fields[3])
        systemd_listener |= '("systemd",' in owners
    for line in (sockets or "").splitlines():
        fields = line.split()
        if len(fields) > 1 and any(re.fullmatch(r"(?:ssh|sshd|dropbear)(?:@\S*)?\.(?:socket|service)", f)
                                   for f in fields[1:]):
            port(fields[0])
    if listening is None or (systemd_listener and sockets is None):
        raise PanelError("Could not verify the host's SSH listeners. Check sshd, ss and systemd before applying.",
                         "ssh_discovery", "ssh_ports")
    return sorted(ports)


def gre_for(c):
    local = c.get("outer_local", c["listen_ip"])
    remote = c["resolved_ip"]
    result = pair_values(local, remote, c.get("gre_slot", 0))
    result["mtu"] = c["mtu"]
    return result


def restore_token(value):
    """Render an argument for iptables-restore's double-quoted rules format."""
    if value and not any(letter.isspace() or letter in '\"\\' for letter in value):
        return value
    return '"' + value.replace('\\', '\\\\').replace('"', '\\"') + '"'


def match_port(low, high):
    return str(low) if low == high else f"{low}:{high}"


def udp_carrier_matches(rule, link, interface=None):
    protocol = ("ipv6", "41") if link.get("family") == 6 else ("udp", "17")
    if "-p" in rule:
        position = rule.index("-p")
        if (rule[position + 1] in (*protocol, "all", "0")) == (rule[position - 1] == "!"):
            return False
    if interface and "-i" in rule:
        position = rule.index("-i")
        selector = rule[position + 1]
        matches = interface.startswith(selector[:-1]) if selector.endswith("+") else interface == selector
        if matches == (rule[position - 1] == "!"):
            return False
    for flag, name in (("-s", "outer_peer"), ("-d", "outer_local")):
        if flag in rule:
            position = rule.index(flag)
            network = ipaddress.IPv4Network(rule[position + 1], strict=False)
            if (ipaddress.IPv4Address(link[name]) in network) == (rule[position - 1] == "!"):
                return False
    for flag in ("--dport", "--dports"):
        if flag not in rule:
            continue
        if "listen_port" not in link:
            return False
        try:
            position = rule.index(flag)
            ranges = [tuple(int(port) for port in value.split(":")) for value in rule[position + 1].split(",")]
            matches = any(ports[0] <= link["listen_port"] <= ports[-1] for ports in ranges)
            if matches == (rule[position - 1] == "!"):
                return False
        except ValueError:
            pass
    return True


def external_carrier_forward(rules, link, interface):
    chains = defaultdict(list)
    for line in rules.splitlines():
        if line.startswith("-A "):
            fields = shlex.split(line)
            chains[fields[1]].append(fields[2:])
    visited, pending = {"GMP_PRE"}, ["PREROUTING"]
    while pending:
        chain = pending.pop()
        if chain in visited:
            continue
        visited.add(chain)
        for rule in chains[chain]:
            jump = next((rule[rule.index(flag) + 1] for flag in ("-j", "-g") if flag in rule), None)
            if not jump or not udp_carrier_matches(rule, link, interface):
                continue
            if jump in ("DNAT", "REDIRECT", "NETMAP"):
                return True
            if jump in chains:
                pending.append(jump)
    return False


def monitored(c, settings):
    explicit = c.get("monitor_ports", []) + [int(x) for x in c.get("port_limits", {})] + [int(x) for x in c.get("port_map", {})]
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
    protected_ips.update(listener["ip"] for _, _, listener in config.get("v2_listeners", []))
    for ip in sorted(protected_ips):
        for proto in ("tcp", "udp"):
            for p in protected:
                add("nat", "GMP_PRE", "-i", interfaces[ip], "-d", ip, "-p", proto, "--dport", p, "-j", "ACCEPT")
        if panel_enabled:
            add("filter", "GMP_INPUT", "-i", interfaces[ip], "-d", ip, "-p", "tcp", "--dport", config["settings"]["port"], "-j", "ACCEPT")
    for link in Engine.gre_devices(config):
        if "listen_port" in link or link.get("family") == 6:
            add("nat", "GMP_PRE", "-i", interfaces[link["outer_local"]], "-s", link["outer_peer"],
                "-d", link["outer_local"], *driver_for(link).firewall(link), "-j", "ACCEPT")
        if link.get("family") == 6:
            add("filter", "GMP_INPUT", "-i", interfaces[link["outer_local"]], "-s", link["outer_peer"],
                "-d", link["outer_local"], *driver_for(link).firewall(link), "-j", "ACCEPT")

    def limiter(base, identity, direction, speed, port="all", minimum=1000):
        if not speed:
            return
        # Byte-rate policing is confined to this flow. No host qdisc is replaced.
        per_second = max(minimum, int(speed * 1000000 / 8))
        # Older xt_hashlimit rounds the encoded rate up before checking the
        # burst. Leave room for that quantization while keeping the same rate.
        burst = max(2048, per_second + 1024)
        rate_name = f"gm{identity}{direction[0]}{port}"[:30]
        add("filter", "GMP_FWD", *base, "-m", "hashlimit", "--hashlimit-above", f"{per_second}b/s",
            "--hashlimit-burst", str(burst) + "b", "--hashlimit-name", rate_name, "--hashlimit-htable-expire", "1000",
            "-j", "DROP")

    for c in config["connections"]:
        if not c.get("enabled", True):
            continue
        identity = c["id"]
        if c["kind"] == "peer":
            g = c["gre"]
            t, peer = g["tunnel"], g["peer_tun"]
            wan = interfaces[g["outer_local"]]
            add("filter", "GMP_INPUT", "-i", wan, "-s", g["outer_peer"], "-d", g["outer_local"],
                *driver_for(g).firewall(g), "-j", "ACCEPT")
            add("filter", "GMP_INPUT", "-i", t, "-s", peer, "-d", g["local_tun"], "-p", "icmp", "-j", "ACCEPT")
            if "v2_ports" in c:
                add_receiver_rules(add, c, interfaces, config["settings"])
                continue
            for proto in ("tcp", "udp"):
                incoming = ["-i", t, "-s", peer, "-d", g["local_tun"], "-p", proto]
                if docker_udp and proto == "udp" and c["service_ip"] in interfaces:
                    add("nat", "GMP_PRE", *incoming, "--dport", "51820", "-j", "DOCKER")
                add("nat", "GMP_PRE", *incoming, "-j", "DNAT", "--to-destination", c["service_ip"])
                add("filter", "GMP_INPUT", "-i", t, "-s", peer, "-d", c["service_ip"], "-p", proto,
                    "-m", "conntrack", "--ctstate", "DNAT", "-j", "ACCEPT")
                if proto == "udp" and c["service_ip"] in interfaces:
                    add("filter", "GMP_INPUT", "-i", t, "-s", peer, "-d", c["service_ip"], "-p", "udp",
                        "--dport", "1701", "-m", "policy", "--dir", "in", "--pol", "ipsec", "-j", "ACCEPT")
                    # The owned GRE local route prefers the service IP below.
                    # INPUT SNAT to that GRE address lets wildcard UDP replies
                    # select the service source and match the tracked DNAT tuple.
                    # IKE/NAT-T uses explicit source addressing. Rewriting its
                    # peer to our own local GRE address breaks transport-mode
                    # XFRM selectors. Decrypted IPsec payloads must also retain
                    # their authenticated endpoints and ports.
                    add("nat", "GMP_LOCAL", "-i", t, "-s", peer, "-d", c["service_ip"], "-p", "udp",
                        "-m", "multiport", "!", "--dports", "500,4500",
                        "-m", "policy", "--dir", "in", "--pol", "none",
                        "-m", "conntrack", "--ctstate", "DNAT", "-j", "SNAT", "--to-source", g["local_tun"])
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
    add_listener_rules(add, config, interfaces, limiter)
    return tables


class Engine:
    def __init__(self, paths, runner=run):
        self.paths, self.run = paths, runner
        self.epoch_file = paths.run / "counter-epoch"

    def interfaces(self):
        rows = json.loads(self.run("ip", "-j", "-4", "addr", "show").stdout)
        return {x["local"]: row["ifname"] for row in rows for x in row.get("addr_info", []) if x.get("scope") != "host"}

    def routes(self):
        return [{"dst": x["dst"], "dev": x.get("dev", "")} for x in
                json.loads(self.run("ip", "-j", "-4", "route", "show", "table", "all").stdout)
                if x.get("dst") and x["dst"] != "default"]

    def clear_owned(self):
        """Used only after the peer confirms no panel, peers or other managers remain."""
        for table, hook, chain in HOOKS:
            while self.run("iptables", "-w", "5", "-t", table, "-C", hook, "-j", chain, check=False).returncode == 0:
                self.run("iptables", "-w", "5", "-t", table, "-D", hook, "-j", chain)
        for table, chains in CHAINS.items():
            present = [chain for chain in chains if self.run("iptables", "-w", "5", "-t", table, "-S", chain, check=False).returncode == 0]
            for chain in present:
                self.run("iptables", "-w", "5", "-t", table, "-F", chain)
            for chain in reversed(present):
                self.run("iptables", "-w", "5", "-t", table, "-X", chain)

    def check_udp_overlays(self, links, interfaces):
        if not links:
            return
        method = links[0]["method"]
        name = method.upper()
        identifiers, ports, devices = {}, set(), {}
        for link in links:
            interface = interfaces.get(link["outer_local"])
            if not interface:
                raise PanelError(f"The configured {name} source address is unavailable.", "local_ip", "outer_ip")
            if method == "geneve":
                if driver_for(link).preferred_source(link, self.run) != (link["outer_local"], interface):
                    raise PanelError("Select the source address and interface used by the route to the GENEVE endpoint.", "route", "outer_ip")
            if interface not in devices:
                devices[interface] = json.loads(self.run("ip", "-j", "link", "show", "dev", interface).stdout)[0]
            if link["mtu"] + driver_for(link).overhead > devices[interface]["mtu"]:
                raise PanelError(f"Lower the {name} MTU for this underlay interface.", "link_policy", "mtu")
            peer = link["outer_peer"] if method == "geneve" else None
            identity = link["listen_port"], link["vni"], peer
            if identifiers.setdefault(identity, link)["tunnel"] != link["tunnel"]:
                raise PanelError(f"Two {name} links use the same endpoint, VNI and UDP port.", "device_conflict", "vni")
            ports.add(link["listen_port"])
        kernel_ports = set()
        for row in driver_for(links[0]).inspect(self.run):
            data = row.get("linkinfo", {}).get("info_data", {})
            port = data.get("port")
            if port not in ports:
                continue
            peer = data.get("remote") if method == "geneve" else None
            expected = identifiers.get((port, data.get("id"), peer))
            if expected and (row.get("ifname") != expected["tunnel"] or not self.owns_link(expected, row)):
                raise PanelError(f"An existing {name} interface uses the requested VNI and UDP port.", "device_conflict", "vni")
            if method == "vxlan" and expected and (data.get("link") != interfaces[expected["outer_local"]] or data.get("learning") is not False):
                raise PanelError("The VXLAN underlay or learning setting was changed outside the panel.", "device_conflict", "outer_ip")
            managed = expected and self.owns_link(expected, row)
            if not managed and not row.get("ifalias", "").startswith("gremgr:v2:"):
                raise PanelError(f"An existing {name} interface already uses this UDP port.", "device_conflict", "port")
            kernel_ports.add(port)
        unused = ports - kernel_ports
        if unused:
            for row in self.run("ss", "-H", "-una").stdout.splitlines():
                fields = row.split()
                port = fields[3].rsplit(":", 1)[-1] if len(fields) > 3 else ""
                if port.isdecimal() and int(port) in unused:
                    raise PanelError(f"An existing UDP socket already uses the {name} port.", "device_conflict", "port")

    def check_wireguard(self, links, interfaces):
        if not links:
            return
        local_key = local_wireguard_key(self.paths, self.run)
        ports = {}
        for link in links:
            if local_key != link["public_key"]:
                raise PanelError("The public key does not match this WireGuard host.", "wireguard_key")
            route = json.loads(self.run("ip", "-j", "-4", "route", "get", link["outer_peer"]).stdout)[0]
            if (route.get("prefsrc"), route.get("dev")) != (link["outer_local"], interfaces.get(link["outer_local"])):
                raise PanelError("Select the source address and interface used by the route to the WireGuard endpoint.", "route", "outer_ip")
            if ports.setdefault(link["listen_port"], link["tunnel"]) != link["tunnel"]:
                raise PanelError("Two WireGuard links cannot share this UDP port.", "device_conflict")
            known = self.run("wg", "show", link["tunnel"], "peers", check=False)
            if known.returncode == 0 and any(key != link["peer_public_key"] for key in known.stdout.split()):
                raise PanelError("Pause this group before replacing its WireGuard peer key.", "device_conflict", "public_key")
        claimed = set()
        for row in self.run("wg", "show", "all", "listen-port").stdout.splitlines():
            fields = row.split()
            if len(fields) != 2 or not fields[1].isdecimal():
                continue
            port = int(fields[1])
            if port in ports:
                if ports[port] != fields[0]:
                    raise PanelError("An existing WireGuard interface already listens on this UDP port.", "device_conflict")
                claimed.add(port)
        for row in self.run("ss", "-H", "-lun").stdout.splitlines():
            fields = row.split()
            if len(fields) < 4:
                continue
            port = fields[3].rsplit(":", 1)[-1]
            if port.isdecimal() and int(port) in ports.keys() - claimed:
                raise PanelError("An existing UDP socket already listens on the WireGuard port.", "device_conflict", "port")

    def preflight(self, config):
        interfaces = self.interfaces()
        forwarding = list(config["connections"])
        for _, _, listener in config.get("v2_listeners", []):
            if any(member["method"] == "direct" and member["service_ip"] in interfaces for member in listener["members"]):
                raise PanelError("A direct destination cannot be the input server itself.", "loop")
            forwarding.append(dict(listener, listen_ip=listener["ip"], kind="v2"))
        for g in config.get("v2_devices", []):
            if g["outer_local"] not in interfaces:
                raise PanelError("The selected tunnel outer address is unavailable on this node.", "local_ip")
        unkeyed_pairs, keyed_pairs, vxlan, wg_links, geneve, l2tp = {}, {}, [], [], [], []
        for link in self.gre_devices(config):
            if (method := link.get("method")) in ("ipip", "sit"):
                pair = link["outer_local"], link["outer_peer"]
                if unkeyed_pairs.setdefault(method, {}).setdefault(pair, link)["tunnel"] != link["tunnel"]:
                    raise PanelError(f"{method.upper()} cannot distinguish two tunnels with the same outer addresses.", "device_conflict")
            if link.get("method") == "vxlan":
                vxlan.append(link)
            if link.get("method") == "geneve":
                geneve.append(link)
            if link.get("method") == "wireguard":
                wg_links.append(link)
            if link.get("method") == "l2tpv3":
                l2tp.append(link)
            if link.get("method") == "gretap":
                key = link["outer_local"], link["outer_peer"], link["key"]
                if keyed_pairs.setdefault(key, link)["tunnel"] != link["tunnel"]:
                    raise PanelError("Choose a different GRETAP key for this endpoint pair.", "device_conflict", "key")
        if "sit" in unkeyed_pairs and not ipv6_enabled(self.run):
            raise PanelError("Enable IPv6 on this host and new interfaces before creating a SIT link.", "ipv6_disabled", "sit")
        for method, pairs in unkeyed_pairs.items():
            inspected = self.run("ip", "-j", "-d", "link", "show", "type", method, check=False)
            if inspected.returncode == 0:
                for row in json.loads(inspected.stdout):
                    data = row.get("linkinfo", {}).get("info_data", {})
                    link = pairs.get((data.get("local"), data.get("remote")))
                    if link and (row.get("ifname") != link["tunnel"] or not self.owns_link(link, row)):
                        raise PanelError(f"An existing {method.upper()} interface uses the requested outer addresses.", "device_conflict")
        if keyed_pairs:
            observed = self.run("ip", "-j", "-d", "link", "show", "type", "gretap").stdout
            for row in json.loads(observed):
                data = row.get("linkinfo", {}).get("info_data", {})
                link = keyed_pairs.get((data.get("local"), data.get("remote"), gre_key(data.get("ikey", 0))))
                if link and (row.get("ifname") != link["tunnel"] or not self.owns_link(link, row)):
                    raise PanelError("An existing GRETAP interface uses that endpoint pair and key.", "device_conflict", "key")
        self.check_udp_overlays(vxlan, interfaces)
        self.check_udp_overlays(geneve, interfaces)
        self.check_wireguard(wg_links, interfaces)
        if l2tp:
            driver_for(l2tp[0]).check(l2tp, interfaces, self.paths, self.run)
        carriers = [*vxlan, *wg_links, *geneve, *l2tp]
        transports = {}
        for link in carriers:
            if transports.setdefault(link["listen_port"], link["method"]) != link["method"]:
                raise PanelError("Different UDP tunnel types require separate ports on this node.", "device_conflict", "port")
        for c in forwarding:
            if not c.get("enabled", True):
                continue
            local = c["gre"]["outer_local"] if c["kind"] == "peer" else c["listen_ip"]
            if local not in interfaces or (c["kind"] == "gre" and c.get("outer_local", local) not in interfaces):
                raise PanelError("The selected local IP is not assigned to this server.", "local_ip", "listen_ip")
            if c["kind"] == "direct" and c["resolved_ip"] in interfaces:
                raise PanelError("A direct destination cannot be the input server itself.", "loop")
        existing = self.run("iptables-save", "-t", "nat").stdout
        for link in [*carriers, *unkeyed_pairs.get("sit", {}).values()]:
            if external_carrier_forward(existing, link, interfaces[link["outer_local"]]):
                raise PanelError("An external port forward already handles this tunnel endpoint.", "external_conflict", "port")
        for line in existing.splitlines():
            if not line.startswith("-A PREROUTING ") or "-j DNAT" not in line or "gmpanel:" in line:
                continue
            if any("gmp:" + c.get("legacy_pair", {}).get("id", "__none__") in line for c in config["connections"]):
                continue
            parts = shlex.split(line)
            destination = parts[parts.index("-d") + 1] if "-d" in parts else None
            for c in forwarding:
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
        driver = driver_for(g)
        interface = interfaces[g["outer_local"]]
        v6 = g.get("family") == 6
        subnet = ipaddress.ip_interface(g["local_tun"] + "/" + str(g.get("prefix_length", 30)))
        self.run("modprobe", driver.module, check=False)
        row = self.inspect_link(g, driver)
        if not row:
            routes = ["ip", "-j", "-6", "route", "show", "table", "all"] if v6 else ["ip", "-j", "-4", "route", "show"]
            for route in json.loads(self.run(*routes).stdout):
                destination = route.get("dst")
                if destination in (None, "default"):
                    continue
                existing = ipaddress.ip_network(destination, strict=False)
                if (subnet.network.overlaps(existing) if v6 else subnet.ip in existing):
                    raise PanelError("The private tunnel subnet overlaps an existing route.", "route_conflict")
        if driver.method == "l2tpv3":
            driver.configure(g, self.paths, self.run)
        else:
            self.ensure_ip_link(g, driver, interface, row)
        if driver.method == "wireguard":
            driver.configure(g, self.paths, self.run)
        addr = ["ip", "-6", "addr"] if v6 else ["ip", "addr"]
        self.run(*addr, "replace", str(subnet), "dev", g["tunnel"])
        self.run("ip", "link", "set", "dev", g["tunnel"], "mtu", g["mtu"], "up")
        if not v6:
            self.run("sysctl", "-qw", "net.ipv4.conf." + g["tunnel"] + ".rp_filter=2")

    def ensure_ip_link(self, g, driver, interface, row):
        stage = self.staging_path(g) if getattr(driver, "staged_marker", False) else None
        if row:
            if not self.owns_link(g, row):
                raise PanelError("Another program owns this tunnel interface.", "device_conflict")
            if stage:
                if not row.get("ifalias"):
                    self.run("ip", "link", "set", "dev", g["tunnel"], "alias", driver.marker(g))
                stage.unlink(missing_ok=True)
            refresh = driver.refresh(g, row.get("linkinfo", {}), interface)
            if refresh:
                self.run(*refresh)
        else:
            create = driver.create(g, interface)
            if stage:
                suffix = secrets.token_hex(5)
                mac = "02:" + ":".join(suffix[i:i + 2] for i in range(0, len(suffix), 2))
                atomic_json(stage, {"id": g["id"], "mac": mac})
                position = create.index("type")
                create[position:position] = ["address", mac]
            self.run(*create)
            marker = driver.marker(g)
            if marker:
                try:
                    self.run("ip", "link", "set", "dev", g["tunnel"], "alias", marker)
                except PanelError:
                    with contextlib.suppress(PanelError):
                        self.run(*driver.delete(g))
                    raise
            if stage:
                stage.unlink(missing_ok=True)

    def staging_path(self, link):
        return self.paths.var / "link-staging" / (link["tunnel"] + ".json")

    def owns_link(self, link, row):
        driver = driver_for(link)
        if driver.owns(link, row):
            return True
        if row.get("ifalias") or not getattr(driver, "staged_marker", False):
            return False
        try:
            saved = json.loads(self.staging_path(link).read_text())
        except (OSError, ValueError):
            return False
        return (saved.get("id") == link["id"] and saved.get("mac") == row.get("address")
                and bool(saved.get("mac")) and driver.owns(link, dict(row, ifalias=driver.marker(link))))

    def inspect_link(self, link, driver):
        if driver.method in ("vxlan", "geneve"):
            rows = driver.inspect(self.run, link["tunnel"])
        else:
            result = self.run("ip", "-j", "-d", "link", "show", link["tunnel"], check=False)
            rows = json.loads(result.stdout) if result.returncode == 0 else []
        return rows[0] if rows else None

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
                # iptables-restore parses a rules file, not a shell command.
                lines += ["-A " + name + " " + " ".join(map(restore_token, rule)) for rule in rules]
            lines.append("COMMIT")
            self.run("iptables-restore", "-w", "10", "--noflush", input="\n".join(lines) + "\n")
        for table, parent, own in HOOKS:
            prefix = ("iptables", "-w", "10", "-t", table)
            if self.run(*prefix, "-C", parent, "-m", "comment", "--comment", "gmpanel:hook", "-j", own, check=False).returncode:
                self.run(*prefix, "-I", parent, "1", "-m", "comment", "--comment", "gmpanel:hook", "-j", own)
        self.epoch_file.write_text(uuid.uuid4().hex)

    def apply(self, config, previous=None):
        with (self.paths.etc / "kernel-apply.lock").open("a") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            return self._apply(config, previous)

    def _apply(self, config, previous):
        previous = installed_topology(self.paths, previous) if previous is not None else None
        config = installed_topology(self.paths, config)
        marker = pressure_file(self.paths)
        was_busy = marker.exists()
        busy = admission_pressure(config["settings"], was_busy)
        config = dict(config, v2_conntrack_busy=busy)
        require_ssh_protection(config, previous)
        interfaces = self.preflight(config)
        previous = previous or dict(config, connections=[], v2_listeners=[], v2_devices=[])
        previous = dict(previous, v2_conntrack_busy=was_busy)
        old_gre = {g["tunnel"]: g for g in self.gre_devices(previous)}
        try:
            for g in self.gre_devices(config):
                self.ensure_gre(g, interfaces)
            self.sync_reply_routes(config, interfaces)
            if config.get("v2_listeners") or any(x.get("enabled", True) for x in config["connections"]):
                self.run("sysctl", "-qw", "net.ipv4.ip_forward=1")
            self.restore_owned(build_rules(config, interfaces, self.docker_udp()))
        except Exception:
            with contextlib.suppress(Exception):
                for g in old_gre.values():
                    self.ensure_gre(g, interfaces)
                self.sync_reply_routes(previous, interfaces)
                self.restore_owned(build_rules(previous, interfaces, self.docker_udp()))
            for g in self.gre_devices(config):
                if g["tunnel"] not in old_gre:
                    self.remove_gre(g)
            raise
        wanted = {g["tunnel"] for g in self.gre_devices(config)}
        retired = dict(old_gre)
        for snapshot in (previous, config):
            retired.update((link["tunnel"], link) for link in snapshot.get("v2_unavailable_devices", []))
        for name, g in retired.items():
            if name not in wanted:
                self.remove_gre(g)
        if busy:
            marker.touch()
        else:
            marker.unlink(missing_ok=True)

    def sync_reply_routes(self, config, interfaces):
        for c in config["connections"]:
            if c["kind"] != "peer" or not c.get("enabled", True):
                continue
            g = c["gre"]
            source = c["service_ip"] if c["service_ip"] in interfaces else g["local_tun"]
            # Changes only the host route created for our own GRE address.
            # Public service-address routes and the default route are untouched.
            self.run("ip", "route", "replace", "local", g["local_tun"] + "/32", "dev", g["tunnel"],
                     "table", "local", "src", source, "proto", "kernel")
            # IPsec transport-mode replies retain their real GRE peer rather
            # than INPUT SNAT. A wildcard L2TP socket must select the service
            # source so its reply matches the authenticated XFRM selector.
            self.run("ip", "route", "replace", g["peer_tun"] + "/32", "dev", g["tunnel"],
                     "src", source, "proto", "static")

    @staticmethod
    def gre_devices(config):
        yield from config.get("v2_devices", [])
        for c in config["connections"]:
            if c.get("enabled", True) and c["kind"] in ("gre", "peer"):
                yield c["gre"] if c["kind"] == "peer" else gre_for(c)

    def remove_gre(self, g):
        # Verify ownership even on deletion. Never deletes an arbitrary name.
        driver = driver_for(g)
        if driver.method == "l2tpv3":
            driver.remove(g, self.paths, self.run)
            return
        row = self.inspect_link(g, driver)
        if row and self.owns_link(g, row):
            self.run(*driver.delete(g))
            if getattr(driver, "staged_marker", False):
                self.staging_path(g).unlink(missing_ok=True)

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
            label = re.search(r"gmpanel:([a-f0-9]{32}|[a-f0-9]{10}):(all|[0-9]+):(up|down)", line)
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
