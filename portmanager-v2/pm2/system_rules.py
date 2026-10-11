"""NAT rule inspection and lossless TCP/UDP display grouping.

A group contains at most one TCP and one UDP rule with identical other
selectors. Grouping never changes order, ownership, or kernel rules.
"""
import re
import shlex
from collections import defaultdict

from .discovery import run

_TARGETS = {"DNAT", "REDIRECT", "SNAT", "MASQUERADE"}
_PORT = re.compile(r"^[0-9]{1,5}(?::[0-9]{1,5})?$")


def _get(args, *flags, default=None):
    for flag in flags:
        if flag in args:
            pos = args.index(flag)
            return args[pos + 1] if pos + 1 < len(args) else default
    return default


def parse_nat(text, limit=20):
    rows, counts = [], defaultdict(int)
    for raw in text.splitlines():
        if not raw.startswith("-A "):
            continue
        try:
            args = shlex.split(raw)
        except ValueError:
            continue
        if len(args) < 4 or "-j" not in args:
            continue
        chain = args[1]
        counts[chain] += 1  # iptables -R chain line number, NOT list row index
        target = _get(args, "-j")
        if target not in _TARGETS:
            continue
        proto = _get(args, "-p", "--protocol", default="any")
        port = _get(args, "--dport", "--dports", default="ALL")
        if port != "ALL" and not _PORT.fullmatch(port):
            port = "multiple" if "," not in port else port
        dest = _get(args, "--to-destination", "--to-ports",
                    "--to-source", default="-")
        interface = _get(args, "-i", "-o", default="-")
        owned = chain.startswith("PM2_") or any(
            token.startswith("pm2:") for token in args)
        rows.append({
            "chain": chain, "protocol": proto, "port": port, "target": target,
            "destination": dest, "interface": interface,
            "source": "Port Manager V2" if owned else "iptables (read-only)",
            "owned": owned, "raw": raw, "argv": args,
            "line_number": counts[chain],
        })
        if limit is not None and len(rows) >= limit:
            break
    return rows


def _group_key(rule):
    """Ignore protocol ONLY; retain every other match, action and comment."""
    args = rule.get("argv")
    if not args:
        return (rule["chain"], rule["target"], rule["port"],
                rule["destination"], rule.get("interface", "-"))
    out = []
    i = 0
    while i < len(args):
        if args[i] in ("-p", "--protocol") and i + 1 < len(args) and (
                args[i + 1] in ("tcp", "udp")):
            i += 2
            continue
        if args[i] == "-m" and i + 1 < len(args) and (
                args[i + 1] in ("tcp", "udp")):
            i += 2
            continue
        out.append(args[i])
        i += 1
    return tuple(out)


def group_nat(rows):
    """Pair matching TCP and UDP without swallowing duplicate rule copies."""
    groups = []
    waiting = {}
    for rule in rows:
        protocol = rule["protocol"]
        if protocol not in ("tcp", "udp"):
            groups.append({**rule, "members": [rule]})
            continue
        key = _group_key(rule)
        opposite = "udp" if protocol == "tcp" else "tcp"
        # Pair only a single counterpart; a third duplicate stays visible.
        candidate = waiting.pop((key, opposite), None)
        if candidate is None:
            group = {**rule, "members": [rule]}
            groups.append(group)
            waiting[(key, protocol)] = group
        else:
            candidate["members"].append(rule)
            candidate["protocol"] = "tcp+udp"
            # Keep raw member identities; this aggregated row is presentation.
    return groups


def detect_nat(limit=2000, grouped=False):
    """Read-only. Error is never treated as an empty or successful scan."""
    try:
        output = run(["iptables-save", "-t", "nat"], timeout=15)
    except Exception as exc:
        return [], "Could not inspect existing NAT rules: " + str(exc)[:160]
    rows = parse_nat(output, limit)
    return (group_nat(rows) if grouped else rows), None


def detect_all():
    """All IPv4 tables, builtin policies and foreign chains (read-only)."""
    try:
        output = run(["iptables-save"], timeout=20)
    except Exception as exc:
        return [], "Could not inspect IPv4 iptables rules: " + str(exc)[:160]
    return [line for line in output.splitlines()
            if line.startswith(("*", ":", "-A ", "-I ", "-N ", "-P ", "COMMIT"))], None
