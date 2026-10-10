"""Read-only V2 conntrack counters, optionally split by ORIGINAL destination port."""
import re
import shlex

from .discovery import run
from .errors import PM2Error

_COUNTER = re.compile(r"^\[(\d+):(\d+)\]$")
_COMMENT = re.compile(r"^pm2:([a-f0-9-]{36}):(up|down)$")
_V1_COMMENT = re.compile(r"^pm-(ul|dl):([0-9]{1,5})$")
_PROBE_COMMENT = re.compile(r"^pm2view:(tcp|udp):(\d{1,5}):(up|down)$")
_HIST_COMMENT = re.compile(r"^pm2hist:(tcp|udp):(\d{1,5}):(up|down)$")


def parse_counters(output, by_port=False, include_v1=False, include_probe=False, include_history=False):
    """Parse one iptables-save -c -t mangle snapshot.

    Existing default returns (tunnel_id, proto, direction) -> bytes, preserving
    SQLite sampler compatibility. by_port=True exposes the conntrack original
    destination port; all-except aggregate rules have a None port.
    """
    data = {}
    for line in output.splitlines():
        if "-A" not in line or not ("PM2_ACCOUNT" in line or
                (include_v1 and by_port and "PORTMANAGER_ACCT" in line) or
                (include_probe and by_port and "PM2_VIEW_" in line) or
                (include_history and by_port and "PM2_HIST_" in line)):
            continue
        args = shlex.split(line)
        if "-A" not in args:
            continue
        index = args.index("-A")
        if index + 1 >= len(args):
            continue
        chain = args[index + 1]
        if chain not in ("PM2_ACCOUNT", "PORTMANAGER_ACCT", "PM2_VIEW_RX", "PM2_VIEW_TX",
                          "PM2_HIST_RX", "PM2_HIST_TX"):
            continue
        if chain in ("PM2_HIST_RX", "PM2_HIST_TX") and not (by_port and include_history):
            continue
        if chain in ("PM2_VIEW_RX", "PM2_VIEW_TX") and not (by_port and include_probe):
            continue
        if chain == "PORTMANAGER_ACCT" and not (include_v1 and by_port):
            continue
        counted = next((x for x in args if _COUNTER.fullmatch(x)), None)
        if counted is None:
            raise PM2Error("E_CONFLICT", "Missing mangle packet/byte counters")
        if "--comment" not in args:
            raise PM2Error("E_CONFLICT", "V2 accounting rule missing owner label")
        i = args.index("--comment")
        if i + 1 >= len(args):
            raise PM2Error("E_CONFLICT", "Truncated V2 accounting comment")
        if chain in ("PM2_HIST_RX", "PM2_HIST_TX"):
            match = _HIST_COMMENT.fullmatch(args[i + 1])
            if not match:
                raise PM2Error("E_CONFLICT", "Unrecognized background port history label")
            proto, port, direction = match.groups()
            if direction != ("down" if chain == "PM2_HIST_RX" else "up"):
                raise PM2Error("E_CONFLICT", "Background history direction mismatch")
            key = ("auto", proto, direction, int(port))
            data[key] = data.get(key, 0) + int(_COUNTER.fullmatch(counted).group(2))
            continue
        if chain in ("PM2_VIEW_RX", "PM2_VIEW_TX"):
            match = _PROBE_COMMENT.fullmatch(args[i + 1])
            if not match:
                raise PM2Error("E_CONFLICT", "Unrecognized automatic port accounting label")
            proto, port, direction = match.groups()
            if direction != ("down" if chain == "PM2_VIEW_RX" else "up"):
                raise PM2Error("E_CONFLICT", "Automatic port counter direction mismatch")
            data[("auto", proto, direction, int(port))] = int(_COUNTER.fullmatch(counted).group(2))
            continue
        if chain == "PORTMANAGER_ACCT":
            v1 = _V1_COMMENT.fullmatch(args[i + 1])
            if v1 is None:
                # Other V1 accounting rules should not block read-only V2.
                continue
            direction = "up" if v1.group(1) == "ul" else "down"
            original_port = int(v1.group(2))
            if not 1 <= original_port <= 65535:
                continue
            proto = args[args.index("-p") + 1] if "-p" in args else "all"
            if proto not in ("tcp", "udp"):
                proto = "all"
            key = ("v1", proto, direction, original_port)
            data[key] = data.get(key, 0) + int(_COUNTER.fullmatch(counted).group(2))
            continue
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


def counters(by_port=False, include_v1=False, include_probe=False, include_history=False):
    # One read-only kernel snapshot, not one iptables call per monitored port.
    output = run(["iptables-save", "-c", "-t", "mangle"])
    return parse_counters(output, by_port=by_port, include_v1=include_v1,
                          include_probe=include_probe, include_history=include_history)
