"""Read-only discovery of existing NAT forwarding rules, including legacy.

This intentionally never imports, modifies or deletes foreign iptables
rules. Unmanaged rules may belong to Docker, UFW, V1, or another tunnel.
"""
import re
import shlex

from .discovery import run

_TARGETS = {"DNAT", "REDIRECT", "SNAT", "MASQUERADE"}
_PORT = re.compile(r"^[0-9]{1,5}(?::[0-9]{1,5})?$")


def parse_nat(text, limit=20):
    rows = []
    for line in text.splitlines():
        if not line.startswith("-A "):
            continue
        try:
            args = shlex.split(line)
        except ValueError:
            continue
        if len(args) < 4 or "-j" not in args:
            continue
        try:
            target = args[args.index("-j") + 1]
        except IndexError:
            continue
        if target not in _TARGETS:
            continue
        chain = args[1]
        proto = args[args.index("-p") + 1] if "-p" in args and args.index("-p") + 1 < len(args) else "any"
        port = args[args.index("--dport") + 1] if "--dport" in args and args.index("--dport") + 1 < len(args) else "ALL"
        if port != "ALL" and not _PORT.fullmatch(port):
            port = "multiple"
        dest = ""
        for option in ("--to-destination", "--to-ports", "--to-source"):
            if option in args and args.index(option) + 1 < len(args):
                dest = args[args.index(option) + 1]
                break
        interface = "-"
        for flag in ("-i", "-o"):
            if flag in args and args.index(flag) + 1 < len(args):
                interface = args[args.index(flag) + 1]
                break
        rows.append({"chain": chain, "protocol": proto, "port": port,
                     "target": target, "destination": dest or "-",
                     "interface": interface,
                     "source": "iptables (read-only)"})
    return rows[:limit]


def detect_nat(limit=20):
    """Absence of permission/dependency is displayed, not mistaken for no rules."""
    try:
        output = run(["iptables-save", "-t", "nat"], timeout=12)
    except (OSError, Exception) as exc:
        return [], "Could not inspect existing NAT rules: " + str(exc)[:140]
    return parse_nat(output, limit), None
