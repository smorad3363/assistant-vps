"""Conservative read-only Linux IPv4 preflight."""
import json
import ipaddress
import re
import shutil
import subprocess
from .errors import PM2Error
from . import nat_conflicts


def run(argv, *, allowed=(0,), timeout=8):
    try:
        result = subprocess.run(argv, check=False, capture_output=True,
                                text=True, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise PM2Error("E_DEPENDENCY", "Network command unavailable",
                       {"program": argv[0]}) from exc
    if result.returncode not in allowed:
        raise PM2Error("E_DEPENDENCY", "Network command failed",
                       {"program": argv[0], "stderr": result.stderr[-400:]})
    return result.stdout


def backend():
    output = run(["iptables", "--version"])
    if "nf_tables" in output:
        return "nf_tables"
    if "legacy" in output:
        return "legacy"
    raise PM2Error("E_UNSUPPORTED", "Unrecognized iptables backend")


def audit(tunnels):
    for name in ("ip", "iptables", "iptables-save", "ss", "sysctl"):
        if not shutil.which(name):
            raise PM2Error("E_DEPENDENCY", f"Missing {name}")
    # systemctl reflects the *host* manager even inside ip netns exec.
    # Only its *actual hooks/chains in this network namespace* are relevant.
    kernel_rules = run(["iptables-save"])
    if shutil.which("systemctl"):
        for service in ("ufw", "firewalld"):
            status = run(["systemctl", "is-active", service],
                         allowed=(0, 1, 3, 4)).strip()
            signature = "ufw-" if service == "ufw" else "firewalld"
            if status == "active" and signature in kernel_rules.lower():
                raise PM2Error("E_CONFLICT", "External firewall manager owns active rules",
                               {"service": service})
    raw = json.loads(run(["ip", "-j", "-4", "addr", "show"]))
    interfaces = {}
    all_ips = set()
    for item in raw:
        ips = {a["local"] for a in item.get("addr_info", [])
               if a.get("family") == "inet"}
        interfaces[item["ifname"]] = (item.get("flags", []), ips)
        all_ips |= ips
    # A legacy V2 listen_ip is the interface anchor, not the only address
    # receiving public port traffic. The reference tunnel accepts ingress to
    # all IPv4 addresses assigned to the selected external interface.
    # Expand strictly to actual, routable host addresses; never target
    # arbitrary forwarded traffic or addresses on other NICs.
    interface_ips = {}
    for tunnel in (item for item in tunnels if item["enabled"]):
        flags, assigned = interfaces.get(tunnel["interface"], ([], set()))
        if "UP" not in flags or tunnel["listen_ip"] not in assigned:
            raise PM2Error("E_CONFLICT", "Listening interface/IPv4 is not UP",
                           {"interface": tunnel["interface"], "ip": tunnel["listen_ip"]})
        accepted = []
        for value in assigned:
            address = ipaddress.IPv4Address(value)
            if (not address.is_loopback and not address.is_link_local and
                    not address.is_unspecified and not address.is_multicast and
                    not address.is_reserved):
                accepted.append(value)
        addresses = sorted(accepted, key=ipaddress.IPv4Address)
        if not addresses or len(addresses) > 32:
            raise PM2Error("E_CONFLICT", "Invalid or too many IPv4s on ingress interface",
                           {"interface": tunnel["interface"], "count": len(addresses)})
        interface_ips[tunnel["interface"]] = addresses

    effective_tunnels = [
        dict(t, listen_ip=address)
        for t in tunnels if t["enabled"]
        for address in interface_ips[t["interface"]]
    ]
    foreign_nat = run(["iptables-save", "-t", "nat"])
    collisions = nat_conflicts.blocking_conflicts(foreign_nat, effective_tunnels)
    if collisions:
        raise PM2Error(
            "E_CONFLICT",
            "Existing NAT forwarding overlaps the requested port; inspect all iptables rules",
            {"rule": collisions[0]["rule"], "tunnel": collisions[0]["tunnel"],
             "conflict_count": len(collisions)})
    listening = []
    for line in run(["ss", "-H", "-lntu"]).splitlines():
        fields = line.split()
        if len(fields) < 5:
            continue
        proto = ("tcp" if fields[0].startswith("tcp") else
                 "udp" if fields[0].startswith("udp") else None)
        if proto is None:
            continue
        try:
            ip, number = fields[4].rsplit(":", 1)
            listening.append((proto, ip.strip("[]"), int(number)))
        except ValueError:
            continue
    for tunnel in (t for t in tunnels if t["enabled"]):
        if tunnel["target_ip"] in all_ips:
            raise PM2Error("E_CONFLICT", "Target IP belongs to local host")
        route = json.loads(run(["ip", "-j", "-4", "route", "get", tunnel["target_ip"]]))
        if not route or route[0].get("dev") in (None, "lo") or route[0].get("type") == "local":
            raise PM2Error("E_CONFLICT", "Target IPv4 route would loop back")
        ports = ({m["listen_port"] for m in tunnel["mapping"]} if tunnel["mode"] == "ports"
                 else None)
        for proto, ip, number in listening:
            if proto not in tunnel["protocols"] or ip not in (
                    "*", "0.0.0.0", "::", *interface_ips[tunnel["interface"]]):
                continue
            conflict = number in ports if ports is not None else number not in tunnel["exclude"]
            if conflict:
                raise PM2Error("E_CONFLICT", "Local listening socket would be intercepted",
                               {"protocol": proto, "port": number})
    return {"backend": backend(), "listeners_checked": len(listening),
            "interface_ips": interface_ips}


def forwarding_enabled():
    return run(["sysctl", "-n", "net.ipv4.ip_forward"]).strip() == "1"
