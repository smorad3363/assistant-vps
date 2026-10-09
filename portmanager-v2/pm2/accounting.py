"""Read V2-only conntrack-aware iptables mangle counters."""
import re
import shlex
from .discovery import run
from .errors import PM2Error

_COUNTER = re.compile(r"^\[(\d+):(\d+)\]$")
_COMMENT = re.compile(r"^pm2:([a-f0-9-]{36}):(up|down)$")


def counters():
    output = run(["iptables-save", "-c", "-t", "mangle"])
    data = {}
    for line in output.splitlines():
        args = shlex.split(line)
        # iptables-save -c may print counter token before "-A".
        if "-A" not in args:
            continue
        index = args.index("-A")
        if index + 1 >= len(args) or args[index + 1] != "PM2_ACCOUNT":
            continue
        match = next((s for s in args if _COUNTER.fullmatch(s)), None)
        if match is None:
            raise PM2Error("E_CONFLICT", "Missing mangle rule counters")
        index = args.index("--comment") if "--comment" in args else -1
        if index < 0 or index + 1 >= len(args):
            raise PM2Error("E_CONFLICT", "Unnamed V2 mangle rule")
        tagged = _COMMENT.fullmatch(args[index + 1])
        if not tagged:
            raise PM2Error("E_CONFLICT", "Unrecognized V2 accounting owner")
        ident, direction = tagged.groups()
        proto = args[args.index("-p") + 1] if "-p" in args else None
        if proto not in ("tcp", "udp"):
            raise PM2Error("E_CONFLICT", "Unrecognized accounting protocol")
        count = int(_COUNTER.fullmatch(match).group(2))
        key = (ident, proto, direction)
        data[key] = data.get(key, 0) + count
    return data
