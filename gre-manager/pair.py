#!/usr/bin/env python3
"""Role-aware GRE setup; configuration is kept outside application updates."""
import contextlib
import fcntl
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import sys
import tempfile
import time

VERSION = "0.2.1"
ROOT = Path(os.environ.get("GRE_PAIR_CONFIG_DIR", "/etc/gremgr/pairs"))
BIN = "/usr/local/sbin/gremgr-pair"


def run(*args, check=True, quiet=False):
    return subprocess.run(list(map(str, args)), check=check, text=True,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE)


def ipv4(value):
    address = ipaddress.IPv4Address(value)
    if address.is_unspecified or address.is_multicast or address.is_loopback:
        raise ValueError("Use a non-loopback unicast IPv4 address.")
    return str(address)


def parse_ports(value):
    value = re.sub(r"\s+", "", value).lower()
    if value == "all":
        return "all"
    if not value or value.startswith(",") or value.endswith(","):
        raise ValueError("Enter all or ports such as 80,443,8080:80.")
    result = {}
    for item in value.split(","):
        if not re.fullmatch(r"[0-9]{1,5}(?::[0-9]{1,5})?", item):
            raise ValueError("Invalid port mapping: " + item)
        parts = list(map(int, item.split(":")))
        source, target = parts[0], parts[-1]
        if not all(1 <= x <= 65535 for x in (source, target)):
            raise ValueError("Ports must be between 1 and 65535.")
        if source == 22:
            raise ValueError("Input port 22 is reserved for local SSH.")
        if source in result:
            raise ValueError("Duplicate input port: " + str(source))
        result[source] = target
    return [[p, result[p]] for p in sorted(result)]


def pair_values(local, peer):
    digest = hashlib.sha256("|".join(sorted((local, peer))).encode()).hexdigest()
    index = int(digest[:6], 16) % (16 * 16384)
    network = ipaddress.IPv4Network((int(ipaddress.IPv4Address("10.240.0.0")) + index * 4, 30))
    hosts = list(map(str, network.hosts()))
    if ipaddress.IPv4Address(local) > ipaddress.IPv4Address(peer):
        hosts.reverse()
    return digest[:10], "gmp-" + digest[:10], hosts[0], hosts[1], int(digest[:8], 16) or 1


def load(identity):
    if not re.fullmatch(r"[0-9a-f]{10}", identity):
        raise ValueError("Invalid pair ID.")
    cfg = json.loads((ROOT / (identity + ".json")).read_text())
    validate(cfg)
    return cfg


def validate(c):
    for key in ("outer_local", "outer_peer", "service_ip", "local_tun", "peer_tun"):
        ipv4(c[key])
    expected = pair_values(c["outer_local"], c["outer_peer"])
    if c["outer_local"] == c["outer_peer"] or tuple(c[k] for k in ("id", "tunnel", "local_tun", "peer_tun", "key")) != expected:
        raise ValueError("Pair identity or tunnel addresses do not match the endpoints.")
    if c["role"] not in ("iran", "foreign") or not re.fullmatch(r"[a-zA-Z0-9_.-]{1,15}", c["wan"]):
        raise ValueError("Invalid role or WAN interface.")
    if not isinstance(c["mtu"], int) or not 576 <= c["mtu"] <= 1476:
        raise ValueError("Invalid GRE MTU.")
    ports = c["ports"]
    if ports != "all":
        if not isinstance(ports, list) or not ports:
            raise ValueError("A nonempty port list is required.")
        normalized = parse_ports(",".join(f"{p}:{d}" for p, d in ports))
        if normalized != ports:
            raise ValueError("Port mappings are not normalized.")


def rules(c):
    """Return exact owned rules. Mapping is performed once, on Iran ingress."""
    w, t, local, peer = c["wan"], c["tunnel"], c["local_tun"], c["peer_tun"]
    tag = "gmp:" + c["id"]
    result = []
    def add(table, chain, *args):
        result.append((table, chain, list(args)))
    add("filter", "INPUT", "-i", w, "-s", c["outer_peer"], "-d", c["outer_local"], "-p", "gre", "-m", "comment", "--comment", tag + ":outer", "-j", "ACCEPT")
    add("filter", "INPUT", "-i", t, "-s", peer, "-d", local, "-p", "icmp", "-m", "comment", "--comment", tag + ":probe", "-j", "ACCEPT")
    if c["role"] == "iran":
        for proto in ("tcp", "udp"):
            mappings = [(None, None)] if c["ports"] == "all" else c["ports"]
            for source, target in mappings:
                match = ["!", "--dport", "22"] if source is None else ["--dport", str(source)]
                dest = peer if target is None else f"{peer}:{target}"
                add("nat", "PREROUTING", "-i", w, "-d", c["service_ip"], "-p", proto, *match, "-m", "comment", "--comment", tag + ":dnat", "-j", "DNAT", "--to-destination", dest)
            add("nat", "POSTROUTING", "-o", t, "-d", peer, "-p", proto, "-m", "conntrack", "--ctstate", "DNAT", "-m", "comment", "--comment", tag + ":snat", "-j", "SNAT", "--to-source", local)
            add("filter", "FORWARD", "-i", w, "-o", t, "-d", peer, "-p", proto, "-m", "conntrack", "--ctstate", "DNAT", "-m", "comment", "--comment", tag + ":forward", "-j", "ACCEPT")
        add("filter", "FORWARD", "-i", t, "-o", w, "-s", peer, "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-m", "comment", "--comment", tag + ":return", "-j", "ACCEPT")
        for direction in ("-i", "-o"):
            add("mangle", "FORWARD", direction, t, "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN", "-m", "comment", "--comment", tag + ":mss", "-j", "TCPMSS", "--set-mss", str(c["mtu"] - 40))
    else:
        for proto in ("tcp", "udp"):
            add("nat", "PREROUTING", "-i", t, "-s", peer, "-d", local, "-p", proto, "-m", "comment", "--comment", tag + ":receive", "-j", "DNAT", "--to-destination", c["service_ip"])
            add("filter", "INPUT", "-i", t, "-s", peer, "-d", c["service_ip"], "-p", proto, "-m", "conntrack", "--ctstate", "DNAT", "-m", "comment", "--comment", tag + ":input", "-j", "ACCEPT")
    return result


def change_rules(c, up):
    for table, chain, args in rules(c):
        prefix = ["iptables", "-w", "10", "-t", table]
        exists = run(*prefix, "-C", chain, *args, check=False).returncode == 0
        if up and not exists:
            run(*prefix, "-I", chain, "1", *args)
        elif not up:
            while exists:
                run(*prefix, "-D", chain, *args)
                exists = run(*prefix, "-C", chain, *args, check=False).returncode == 0


def docker_wireguard_rule(c):
    """Narrow bridge between GRE ingress and Docker's published WG UDP port."""
    if c["role"] != "foreign":
        return None
    return [
        "-i", c["tunnel"], "-s", c["peer_tun"] + "/32",
        "-d", c["local_tun"] + "/32", "-p", "udp", "--dport", "51820",
        "-m", "comment", "--comment", "gmp:" + c["id"] + ":docker-wg",
        "-j", "DOCKER",
    ]


def sync_docker_wireguard(c, enable=True):
    """Restore the Docker DNAT path; never alter other ports or Docker rules."""
    args = docker_wireguard_rule(c)
    if args is None:
        return
    prefix = ("iptables", "-w", "10", "-t", "nat")
    published = run(*prefix, "-S", "DOCKER", check=False)
    # Docker may start after GRE; the periodic sync retries harmlessly.
    if published.returncode != 0:
        return
    active = any(
        "-p udp" in line and "--dport 51820" in line
        and "-j DNAT" in line and "--to-destination " in line
        for line in published.stdout.splitlines()
    )
    present = run(*prefix, "-C", "PREROUTING", *args, check=False).returncode == 0
    if not enable or not active:
        if present:
            run(*prefix, "-D", "PREROUTING", *args)
        return
    rules_now = run(*prefix, "-S", "PREROUTING").stdout.splitlines()
    first = next((line for line in rules_now if line.startswith("-A PREROUTING ")), "")
    if present and ("gmp:" + c["id"] + ":docker-wg") in first:
        return
    if present:
        run(*prefix, "-D", "PREROUTING", *args)
    run(*prefix, "-I", "PREROUTING", "1", *args)


def owned_device(c, device):
    details = json.loads(device.stdout)[0].get("linkinfo", {})
    data = details.get("info_data", {})
    key = data.get("ikey", 0)
    if isinstance(key, str):
        key = int(ipaddress.IPv4Address(key)) if "." in key else int(key)
    return details.get("info_kind") == "gre" and data.get("local") == c["outer_local"] and data.get("remote") == c["outer_peer"] and key == c["key"]


def up(c):
    run("modprobe", "ip_gre", check=False)
    device = run("ip", "-j", "-d", "link", "show", c["tunnel"], check=False)
    if device.returncode == 0:
        if not owned_device(c, device):
            raise ValueError("An unowned or different tunnel uses this interface name.")
    else:
        run("ip", "tunnel", "add", c["tunnel"], "mode", "gre", "local", c["outer_local"], "remote", c["outer_peer"], "key", c["key"], "ttl", "64", "dev", c["wan"])
    run("ip", "addr", "replace", c["local_tun"] + "/30", "dev", c["tunnel"])
    run("ip", "link", "set", c["tunnel"], "mtu", c["mtu"], "up")
    # Loose validation supports multi-homed hosts without disabling source checks globally.
    run("sysctl", "-qw", f"net.ipv4.conf.{c['tunnel']}.rp_filter=2")
    if c["role"] == "iran":
        run("sysctl", "-qw", "net.ipv4.ip_forward=1")
    change_rules(c, True)
    sync_docker_wireguard(c)


def down(c):
    sync_docker_wireguard(c, False)
    change_rules(c, False)
    device = run("ip", "-j", "-d", "link", "show", c["tunnel"], check=False)
    if device.returncode == 0:
        if not owned_device(c, device):
            raise ValueError("Refusing to delete an unowned tunnel interface.")
        run("ip", "tunnel", "del", c["tunnel"])


def save(path, data):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, name = tempfile.mkstemp(prefix=".pair-", dir=path.parent)
    try:
        with os.fdopen(fd, "w") as out:
            out.write(json.dumps(data, indent=2) + "\n")
            out.flush()
            os.fsync(out.fileno())
        os.replace(name, path)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def ask(label, default=""):
    answer = input(label + (f" [{default}]" if default else "") + ": ").strip()
    return answer or default


def status(c):
    print(f"{c['id']} {c['role']} | {c['outer_local']} -> {c['outer_peer']} | service {c['service_ip']}")
    print("TCP+UDP ports:", c["ports"], "| Iran input port 22 always stays local.")
    result = run("ping", "-n", "-I", c["tunnel"], "-c", "3", "-W", "2", c["peer_tun"], check=False)
    print(result.stdout.strip() or result.stderr.strip())
    print("GRE peer: VERIFIED" if result.returncode == 0 else "GRE peer: NOT VERIFIED (configure/check the other server)")
    return result.returncode


def conflicts(c, legacy=None):
    wanted = None if c["ports"] == "all" else {p for p, _ in c["ports"]}
    for path in ROOT.glob("*.json"):
        other = json.loads(path.read_text())
        if other["id"] == c["id"]:
            continue
        if {other["local_tun"], other["peer_tun"]} & {c["local_tun"], c["peer_tun"]}:
            raise ValueError("Inner subnet collision with another saved pair.")
        if c["role"] == other["role"] == "iran" and c["service_ip"] == other["service_ip"]:
            occupied = None if other["ports"] == "all" else {p for p, _ in other["ports"]}
            if wanted is None or occupied is None or wanted & occupied:
                raise ValueError("Input ports overlap another saved pair; edit that pair first.")
    # A separately managed active deployment must not silently be shadowed.
    current = run("iptables-save", "-t", "nat").stdout
    for line in current.splitlines():
        if legacy and "gre-ir-fi:" in line:
            continue
        if line.startswith("-A PREROUTING ") and "-j DNAT" in line and ("-d " + c["service_ip"] + "/32") in line and "gmp:" not in line and c["role"] == "iran":
            raise ValueError("Existing port forwards on this IP are managed by another tool. Keep them or remove/migrate them explicitly before setup.")


def legacy_config():
    path = Path("/etc/gre-ir-fi.conf")
    if not path.exists() or run("systemctl", "is-enabled", "gre-ir-fi.service", check=False).returncode != 0:
        return None
    values = {}
    for line in path.read_text().splitlines():
        if line.strip() and not line.startswith("#"):
            key, value = line.split("=", 1)
            values[key] = shlex.split(value)[0]
    return dict(role="iran" if values["ROLE"] == "iran" else "foreign",
                outer_local=values["OUTER_LOCAL"], outer_peer=values["OUTER_REMOTE"],
                service_ip=values["LOCAL_PUBLIC"], ports="all")


def configure():
    print(f"GRE pair wizard {VERSION} | TCP + UDP | SSH input 22 protected")
    legacy = legacy_config()
    profiles = list(ROOT.glob("*.json"))
    defaults = json.loads(profiles[0].read_text()) if len(profiles) == 1 else legacy or {}
    role = ask("Role: 1 Iran / 2 Foreign", {"iran": "1", "foreign": "2"}.get(defaults.get("role"), ""))
    role = {"1": "iran", "2": "foreign", "iran": "iran", "foreign": "foreign"}.get(role.lower())
    if not role:
        raise ValueError("Choose 1 or 2.")
    # Read route data only; no external IP lookup or third-party download.
    route = json.loads(run("ip", "-j", "-4", "route", "get", "1.1.1.1").stdout)[0]
    detected = route.get("prefsrc", route.get("src", ""))
    local = ipv4(ask("Local GRE IPv4 (can differ from service IP)", defaults.get("outer_local", detected)))
    peer = ipv4(ask("Other server GRE public IPv4", defaults.get("outer_peer", "")))
    if local == peer:
        raise ValueError("Local and peer endpoints must differ.")
    addresses = json.loads(run("ip", "-j", "-4", "addr", "show").stdout)
    interfaces = {a["local"]: row["ifname"] for row in addresses for a in row["addr_info"]}
    if local not in interfaces:
        raise ValueError("Local GRE IPv4 must be assigned to this server.")
    identity, tunnel, inside, remote, key = pair_values(local, peer)
    path = ROOT / (identity + ".json")
    previous = load(identity) if path.exists() else None
    if previous and previous["role"] != role:
        raise ValueError("Existing pair has a different role; do not swap roles accidentally.")
    service = ipv4(ask("Iran listen IPv4" if role == "iran" else "Local destination/service IPv4", previous["service_ip"] if previous else defaults.get("service_ip", detected)))
    if service not in interfaces:
        raise ValueError("Service IPv4 must be assigned to this server.")
    if role == "iran":
        old_ports = previous["ports"] if previous else "all"
        default = old_ports if old_ports == "all" else ",".join(f"{p}:{d}" for p, d in old_ports)
        ports = parse_ports(ask("Ports: all OR 80,443,8080:80 (input:output)", default))
    else:
        print("Foreign receives tunneled traffic only. Select ports/mappings on Iran.")
        ports = "all"
    cfg = dict(id=identity, tunnel=tunnel, role=role, outer_local=local, outer_peer=peer,
               service_ip=service, wan=interfaces[local], local_tun=inside, peer_tun=remote,
               key=key, mtu=previous["mtu"] if previous else 1400, ports=ports)
    validate(cfg)
    migrating = legacy if legacy and all(cfg[k] == legacy[k] for k in ("role", "outer_local", "outer_peer", "service_ip")) else None
    conflicts(cfg, migrating)
    unit = "gremgr-pair@" + identity + ".service"
    if previous:
        backup = ROOT / "backups" / (identity + "-" + str(time.time_ns()) + ".json")
        save(backup, previous)
    else:
        if run("ip", "link", "show", tunnel, check=False).returncode == 0:
            raise ValueError("Tunnel interface already exists without a saved profile.")
        # Do not steal a pre-existing route owned by a different application.
        for row in json.loads(run("ip", "-j", "-4", "route", "show").stdout):
            if row.get("dst") not in (None, "default") and ipaddress.IPv4Address(inside) in ipaddress.IPv4Network(row["dst"], strict=False):
                raise ValueError("Selected inner subnet overlaps an existing route.")
    enabled_before = run("systemctl", "is-enabled", unit, check=False).returncode == 0
    active_before = run("systemctl", "is-active", unit, check=False).returncode == 0
    legacy_active = migrating and run("systemctl", "is-active", "gre-ir-fi.service", check=False).returncode == 0
    try:
        if migrating:
            save(ROOT / "backups" / ("gre-ir-fi-" + str(time.time_ns()) + ".json"), migrating)
            run("systemctl", "disable", "--now", "gre-ir-fi.service")
        if previous:
            run("systemctl", "stop", unit)
            down(previous)
        save(path, cfg)
        run("systemctl", "enable", "--now", unit)
    except BaseException:
        # Unit stop can fail when ExecStart failed; exact rule cleanup is still needed.
        run("systemctl", "stop", unit, check=False)
        with contextlib.suppress(Exception):
            down(cfg)
        if previous:
            save(path, previous)
            if active_before:
                run("systemctl", "start", unit, check=False)
            if not enabled_before:
                run("systemctl", "disable", unit, check=False)
        else:
            path.unlink(missing_ok=True)
            run("systemctl", "disable", unit, check=False)
        if migrating:
            run("systemctl", "enable", "gre-ir-fi.service", check=False)
            if legacy_active:
                run("systemctl", "start", "gre-ir-fi.service", check=False)
        raise
    print("Saved. Enabled at boot. Pair ID:", identity)
    print(f"On the other server use local GRE {peer} and peer GRE {local}.")
    print("Status: gremgr-pair status " + identity)
    print("Configure the other server too; local setup alone does not prove connectivity.")
    status(cfg)


def main():
    if os.geteuid() != 0:
        raise ValueError("Run with sudo/root.")
    ROOT.mkdir(parents=True, exist_ok=True, mode=0o700)
    args = sys.argv[1:]
    if args == ["--version"]:
        print(VERSION)
        return
    if not args or args == ["wizard"]:
        if not sys.stdin.isatty():
            with open("/dev/tty") as tty:
                sys.stdin = tty
                with open(ROOT / ".lock", "a") as lock:
                    fcntl.flock(lock, fcntl.LOCK_EX)
                    configure()
        else:
            with open(ROOT / ".lock", "a") as lock:
                fcntl.flock(lock, fcntl.LOCK_EX)
                configure()
        return
    if args == ["list"]:
        for path in sorted(ROOT.glob("*.json")):
            c = load(path.stem)
            print(c["id"], c["role"], c["outer_local"], "->", c["outer_peer"], "ports:", c["ports"])
        return
    if args == ["docker-sync-all"]:
        for path in sorted(ROOT.glob("*.json")):
            identity = path.stem
            with open(ROOT / (identity + ".lock"), "a") as lock:
                fcntl.flock(lock, fcntl.LOCK_EX)
                sync_docker_wireguard(load(identity))
        return
    if len(args) != 2 or args[0] not in ("up", "down", "status", "docker-sync"):
        raise ValueError("Usage: gremgr-pair [wizard|list|up ID|down ID|status ID]")
    identity = args[1]
    # Per-pair locks serialize boot, manual recovery and timer operations.
    if not re.fullmatch(r"[0-9a-f]{10}", identity):
        raise ValueError("Invalid pair ID.")
    with open(ROOT / (identity + ".lock"), "a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        c = load(identity)
        if args[0] == "status":
            sys.exit(status(c))
        if args[0] == "docker-sync":
            sync_docker_wireguard(c)
        else:
            (up if args[0] == "up" else down)(c)


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, subprocess.CalledProcessError, KeyboardInterrupt) as exc:
        details = exc.stderr.strip() if isinstance(exc, subprocess.CalledProcessError) else str(exc)
        print("ERROR:", details, file=sys.stderr)
        sys.exit(1)
