"""Temporary, exact-owner, IPv4 per-socket-port accounting for V1-style viewer.

No DNAT, ACCEPT, DROP, tc or system service. Counter-only rules in two
exclusively named mangle chains, with exact matching owner hooks. Select at
most 24 listening ports, prioritizing established connections. All changes
are removed on exit; a subsequent viewer can validate and reclaim stale
rules after a hard kill. Never flush global tables or touch V1 chains.
"""
import fcntl
import os
import re
import shlex
import subprocess
from pathlib import Path

from .discovery import run
from .errors import PM2Error

CHAINS = {"down": ("PREROUTING", "PM2_VIEW_RX", "ORIGINAL"),
          "up": ("POSTROUTING", "PM2_VIEW_TX", "REPLY")}
HOOK_COMMENT = "pm2view:hook"
MAX_PORTS = 24
LOCK_FILE = Path("/run/lock/portmanager2-view.lock")
_COMMENT = re.compile(r"^pm2view:(tcp|udp):(\d{1,5}):(up|down)$")


def parse_listeners(text):
    """IPv4 TCP/UDP bound listeners. Wildcard includes IPv4 but ::1 does not."""
    found = set()
    for line in text.splitlines():
        fields = line.split()
        if len(fields) < 5:
            continue
        proto = ("tcp" if fields[0].startswith("tcp") else
                 "udp" if fields[0].startswith("udp") else None)
        if not proto:
            continue
        address = fields[4]
        if ":" not in address:
            continue
        host, number = address.rsplit(":", 1)
        try:
            port = int(number)
        except ValueError:
            continue
        if not 1 <= port <= 65535:
            continue
        if host in ("127.0.0.1", "::1", "[::1]") or host.startswith("127."):
            continue
        # IPv6-only bound sockets are not counted by this IPv4 backend.
        if ":" in host and host not in ("[::]", "::"):
            continue
        found.add((proto, port))
    return found


def parse_established(text):
    counts = {}
    for line in text.splitlines():
        fields = line.split()
        # ss -H -tn state established: Recv-Q Send-Q Local:Port Peer:Port
        if len(fields) < 4:
            continue
        # With -H and "state established" ss may emit either
        # ESTAB 0 0 local peer or 0 0 local peer (state column omitted).
        local = fields[3] if fields[0].upper() in ("ESTAB", "ESTABLISHED") and len(fields) >= 5 else fields[2]
        if ":" not in local:
            continue
        try:
            port = int(local.rsplit(":", 1)[1])
        except ValueError:
            continue
        counts[port] = counts.get(port, 0) + 1
    return counts


def discover(existing=()):
    existing = set(existing)
    listeners = parse_listeners(run(["ss", "-H", "-lntu"], timeout=12))
    try:
        busy = parse_established(run(["ss", "-H", "-tn", "state", "established"], timeout=12))
    except PM2Error:
        busy = {}
    ports = [key for key in listeners if key not in existing]
    ports.sort(key=lambda p: (-busy.get(p[1], 0), p[1], p[0]))
    return ports[:MAX_PORTS]


def interface_counters(path=Path("/proc/net/dev")):
    """Host interface summary, explicitly NOT attributed to a socket port."""
    totals = {}
    for line in path.read_text(encoding="ascii").splitlines()[2:]:
        if ":" not in line:
            continue
        name, data = line.split(":", 1)
        name = name.strip()
        values = data.split()
        if name != "lo" and len(values) >= 16:
            totals[name] = (int(values[0]), int(values[8]))
    return totals


def interface_rates(old, new, elapsed):
    result = []
    for name, (rx, tx) in new.items():
        if name not in old or elapsed <= 0:
            continue
        rx0, tx0 = old[name]
        result.append({"interface": name,
                       "rx_mbps": max(0, rx - rx0) * 8 / elapsed / 1e6 if rx >= rx0 else 0,
                       "tx_mbps": max(0, tx - tx0) * 8 / elapsed / 1e6 if tx >= tx0 else 0})
    result.sort(key=lambda x: -(x["rx_mbps"] + x["tx_mbps"]))
    return result


def _ipt(*args):
    return run(["iptables", "-w", "3", "-t", "mangle", *args], timeout=15)


def _rules(chain):
    try:
        return _ipt("-S", chain).splitlines()
    except PM2Error:
        return None


def _expected_hook(builtin, chain):
    return ("-A", builtin, "-m", "comment", "--comment", HOOK_COMMENT, "-j", chain)


def _valid_counter(line, chain, direction):
    args = shlex.split(line)
    if len(args) != 14 or args[:2] != ["-A", chain]:
        return False
    # Netfilter canonical order may differ between nft and legacy backends;
    # enforce *all* non-dynamic semantics and forbid any packet target.
    if "-j" in args or "-g" in args or "--dport" in args:
        return False
    # Exact rule signature avoids ever deleting unrelated service rules.
    if args[2:6] not in (["-p", "tcp", "-m", "conntrack"],
                         ["-p", "udp", "-m", "conntrack"]):
        return False
    if args[6] != "--ctdir" or args[8] != "--ctorigdstport" or args[10:13] != ["-m", "comment", "--comment"]:
        return False
    try:
        proto = args[args.index("-p") + 1]
        owner = args[args.index("--comment") + 1]
        ct = args[args.index("--ctdir") + 1]
        port = int(args[args.index("--ctorigdstport") + 1])
    except (IndexError, ValueError):
        return False
    match = _COMMENT.fullmatch(owner)
    return bool(match and match.group(1) == proto and
                int(match.group(2)) == port and match.group(3) == direction and
                ct == CHAINS[direction][2] and
                proto in ("tcp", "udp") and 1 <= port <= 65535)


def _inspect():
    """Fail closed if any chain/hook belongs to somebody else."""
    present = []
    for direction, (builtin, chain, _) in CHAINS.items():
        rules = _rules(chain)
        all_builtins = _rules(builtin)
        if all_builtins is None:
            raise PM2Error("E_DEPENDENCY", "Cannot inspect mangle base chain")
        hooks = [shlex.split(l) for l in all_builtins
                 if l.startswith("-A ") and ("PM2_VIEW_" in l or HOOK_COMMENT in l)]
        expected = list(_expected_hook(builtin, chain))
        if hooks and (len(hooks) != 1 or hooks[0] != expected):
            raise PM2Error("E_CONFLICT", "Unknown or modified live counter hook",
                           {"chain": chain})
        if rules is None:
            if hooks:
                raise PM2Error("E_CONFLICT", "Orphaned monitor hook")
            continue
        if not all(_valid_counter(x, chain, direction) for x in rules if x.startswith("-A ")):
            raise PM2Error("E_CONFLICT", "Foreign rule in owned live monitor chain",
                           {"chain": chain})
        present.append((builtin, chain, bool(hooks)))
    return present


def _clear_owned():
    for builtin, chain, hooked in _inspect():
        if hooked:
            _ipt("-D", builtin, "-m", "comment", "--comment", HOOK_COMMENT, "-j", chain)
        _ipt("-F", chain)  # ONLY OUR EXACT-VERIFIED PRIVATE CHAIN
        _ipt("-X", chain)


def _install(ports):
    _clear_owned()
    try:
        for direction, (builtin, chain, ctdir) in CHAINS.items():
            _ipt("-N", chain)
            for proto, port in ports:
                _ipt("-A", chain, "-p", proto, "-m", "conntrack",
                     "--ctdir", ctdir, "--ctorigdstport", str(port),
                     "-m", "comment", "--comment", f"pm2view:{proto}:{port}:{direction}")
            _ipt("-I", builtin, "1", "-m", "comment", "--comment",
                 HOOK_COMMENT, "-j", chain)
    except Exception:
        _clear_owned()
        raise


class AutoMonitor:
    def __init__(self, existing=()):
        self.existing = existing
        self.lock = None
        self.ports = []

    def __enter__(self):
        if os.geteuid():
            raise PM2Error("E_PERMISSION", "Auto port monitoring requires root")
        fd = os.open(LOCK_FILE, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.lock = fd
            self.ports = discover(self.existing)
            if self.ports:
                _install(self.ports)
            else:
                # Clean validated stale hooks, even if no socket remains.
                _clear_owned()
        except Exception:
            os.close(fd)
            self.lock = None
            raise
        return self

    def __exit__(self, exc_type, exc, tb):
        try:
            if self.lock is not None:
                _clear_owned()
        finally:
            if self.lock is not None:
                os.close(self.lock)
                self.lock = None
        return False
