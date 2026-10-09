"""Read-only V2 conntrack counters, optionally split by ORIGINAL destination port."""
import re
import shlex

from .discovery import run
from .errors import PM2Error

_COUNTER = re.compile(r"^\[(\d+):(\d+)\]$")
_COMMENT = re.compile(r"^pm2:([a-f0-9-]{36}):(up|down)$")


def parse_counters(output, by_port=False):
    """Parse one iptables-save -c -t mangle snapshot.

    Existing default returns (tunnel_id, proto, direction) -> bytes, preserving
    SQLite sampler compatibility. by_port=True exposes the conntrack original
    destination port; all-except aggregate rules have a None port.
    """
    data = {}
    for line in output.splitlines():
        if "PM2_ACCOUNT" not in line or "-A" not in line:
            continue
        args = shlex.split(line)
        if "-A" not in args:
            continue
        index = args.index("-A")
        if index + 1 >= len(args) or args[index + 1] != "PM2_ACCOUNT":
            continue
        counted = next((x for x in args if _COUNTER.fullmatch(x)), None)
        if counted is None:
            raise PM2Error("E_CONFLICT", "Missing mangle packet/byte counters")
        if "--comment" not in args:
            raise PM2Error("E_CONFLICT", "V2 accounting rule missing owner label")
        i = args.index("--comment")
        if i + 1 >= len(args):
            raise PM2Error("E_CONFLICT", "Truncated V2 accounting comment")
        owner = _COMMENT.fullmatch(args[i + 1])
        if owner is None:
            raise PM2Error("E_CONFLICT", "Unrecognized V2 accounting owner")
        tunnel_id, direction = owner.groups()
        if "-p" not in args:
            raise PM2Error("E_CONFLICT", "Unrecognized accounting protocol")
        proto = args[args.index("-p") + 1]
        if proto not in ("tcp", "udp"):
            raise PM2Error("E_CONFLICT", "Invalid V2 accounting protocol")
        original_port = None
        if "--ctorigdstport" in args:
            at = args.index("--ctorigdstport")
            try:
                original_port = int(args[at + 1])
            except (IndexError, ValueError) as exc:
                raise PM2Error("E_CONFLICT", "Malformed ORIGINAL port counter") from exc
            if not 1 <= original_port <= 65535:
                raise PM2Error("E_CONFLICT", "Out-of-range original port")
        number = int(_COUNTER.fullmatch(counted).group(2))
        key = ((tunnel_id, proto, direction, original_port) if by_port
               else (tunnel_id, proto, direction))
        data[key] = data.get(key, 0) + number
    return data


def counters(by_port=False):
    # One read-only kernel snapshot, not one iptables call per monitored port.
    output = run(["iptables-save", "-c", "-t", "mangle"])
    return parse_counters(output, by_port=by_port)
