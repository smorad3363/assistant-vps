"""Minute-scale persistent per-port history, independent of the live terminal.

Only touches two explicitly owned, counter-only mangle chains. An active
systemd sample timer calls collect() every minute. A live viewer may read
these counters without owning or resetting them.
"""
from pathlib import Path
import os
import re
import shlex
import time

from . import accounting, auto_monitor, config, sampler, transaction, port_graph
from .errors import PM2Error

CHAINS = {"down": ("PREROUTING", "PM2_HIST_RX", "ORIGINAL"),
          "up": ("POSTROUTING", "PM2_HIST_TX", "REPLY")}
HOOK = "pm2hist:hook"
LABEL = re.compile(r"^pm2hist:(tcp|udp):([1-9][0-9]{0,4}):(up|down)$")
MAX_PORTS = auto_monitor.MAX_PORTS


def _rule_ports(line, chain, direction):
    """Return a verified rule's (protocol, port), or reject foreign content."""
    try:
        args = shlex.split(line)
        if args[:2] != ["-A", chain]:
            return None
        tokens = args[2:]
        if len(tokens) % 2:
            return None
        fields = {}
        for i in range(0, len(tokens), 2):
            key, value = tokens[i:i + 2]
            if key not in ("-p", "-m", "--ctdir", "--ctorigdstport", "--comment"):
                return None
            fields.setdefault(key, []).append(value)
        if any(len(fields.get(k, [])) != 1 for k in
               ("-p", "--ctdir", "--ctorigdstport", "--comment")):
            return None
        proto = fields["-p"][0]
        modules = fields.get("-m", [])
        if (proto not in ("tcp", "udp") or
                not {"conntrack", "comment"}.issubset(modules) or
                len(modules) > 3 or
                any(m not in ("conntrack", "comment", proto) for m in modules)):
            return None
        label = LABEL.fullmatch(fields["--comment"][0])
        if not label or (label.group(1), label.group(3)) != (proto, direction):
            return None
        port = int(label.group(2))
        if (not 1 <= port <= 65535 or
                fields["--ctorigdstport"][0] != str(port) or
                fields["--ctdir"][0] != CHAINS[direction][2]):
            return None
        return proto, port
    except (ValueError, IndexError):
        return None


def _inspect():
    found, groups = [], {}
    for direction, (builtin, chain, _) in CHAINS.items():
        rules = auto_monitor._rules(chain)
        parent = auto_monitor._rules(builtin)
        if parent is None:
            raise PM2Error("E_DEPENDENCY", "Cannot inspect netfilter mangle hooks")
        expected = ["-A", builtin, "-m", "comment", "--comment", HOOK,
                    "-j", chain]
        hooks = []
        for line in parent:
            if HOOK in line or ("-j " + chain) in line:
                try:
                    hooks.append(shlex.split(line))
                except ValueError as exc:
                    raise PM2Error("E_CONFLICT", "Malformed history hook") from exc
        if hooks and (len(hooks) != 1 or hooks[0] != expected):
            raise PM2Error("E_CONFLICT", "Unexpected history hook", {"chain": chain})
        if rules is None:
            if hooks:
                raise PM2Error("E_CONFLICT", "History hook with missing owned chain")
            found.append((builtin, chain, False, False))
            groups[direction] = set()
            continue
        ports = set()
        for line in rules:
            if not line.startswith("-A "):
                continue
            key = _rule_ports(line, chain, direction)
            if key is None or key in ports:
                raise PM2Error("E_CONFLICT", "Foreign or duplicate history rule",
                               {"chain": chain})
            ports.add(key)
        if ports and not hooks:
            raise PM2Error("E_CONFLICT", "History rules missing owned hook")
        found.append((builtin, chain, bool(hooks), True))
        groups[direction] = ports
    if groups["down"] != groups["up"]:
        raise PM2Error("E_CONFLICT", "History counter directions do not agree")
    return found, groups["down"]


def _clear(owned):
    for builtin, chain, hooked, present in owned:
        if not present:
            continue
        if hooked:
            auto_monitor._ipt("-D", builtin, "-m", "comment", "--comment",
                              HOOK, "-j", chain)
        auto_monitor._ipt("-F", chain)
        auto_monitor._ipt("-X", chain)


def _install(ports, inspected):
    old, _ = inspected
    _clear(old)
    try:
        for direction, (builtin, chain, ctdir) in CHAINS.items():
            auto_monitor._ipt("-N", chain)
            for proto, port in sorted(ports):
                auto_monitor._ipt("-A", chain, "-p", proto,
                                  "-m", "conntrack", "--ctdir", ctdir,
                                  "--ctorigdstport", str(port),
                                  "-m", "comment", "--comment",
                                  f"pm2hist:{proto}:{port}:{direction}")
            auto_monitor._ipt("-I", builtin, "1", "-m", "comment",
                              "--comment", HOOK, "-j", chain)
    except Exception:
        # Cleanup only if all the new rules still pass ownership verification.
        _clear(_inspect()[0])
        raise


def _schema(db):
    port_graph.init_history(db)
    db.execute("""CREATE TABLE IF NOT EXISTS pm2_history_last (
        protocol TEXT NOT NULL, listen_port INTEGER NOT NULL,
        direction TEXT NOT NULL, total_bytes INTEGER NOT NULL,
        sampled_at REAL NOT NULL,
        PRIMARY KEY(protocol,listen_port,direction)
    )""")
    db.execute("""CREATE TABLE IF NOT EXISTS pm2_history_health (
        id INTEGER PRIMARY KEY CHECK(id=1), sampled_at REAL NOT NULL
    )""")


def healthy(db=None, timestamp=None):
    """Do not adopt abandoned persistent hooks when its timer has stopped."""
    own = db is None
    if own:
        try:
            db = sampler.connect()
        except PM2Error:
            return False
    try:
        _schema(db)
        row = db.execute("SELECT sampled_at FROM pm2_history_health WHERE id=1").fetchone()
        return bool(row and 0 <= (time.time() if timestamp is None else timestamp)
                    - row[0] < 180)
    finally:
        if own:
            db.close()


def active_ports():
    """Return ports only from completely verified owned hooks."""
    inspected, ports = _inspect()
    if not all(row[2] for row in inspected):
        return []
    return sorted(ports)


def _history_counters():
    snapshot = accounting.counters(by_port=True, include_history=True)
    return {(proto, port, direction): n
            for (tid, proto, direction, port), n in snapshot.items()
            if tid == "auto" and port}


def _tracked_elsewhere():
    present = accounting.counters(by_port=True, include_v1=True)
    known = set()
    for tid, proto, _direction, port in present:
        if port:
            if proto == "all":
                known.update((("tcp", port), ("udp", port)))
            else:
                known.add((proto, port))
    cfg = config.load(transaction.CONFIG)
    for tid, proto, port in port_graph.port_labels(cfg["tunnels"]):
        if port:
            known.add((proto, port))
    return known


def collect(timestamp=None):
    """Store one bounded, reset-safe counter interval per minute.

    First run or any missed interval > 120s re-baselines without claiming
    monitoring coverage during the gap. Historical samples survive reboots.
    """
    if os.geteuid():
        raise PM2Error("E_PERMISSION", "Persistent history requires root")
    now = time.time() if timestamp is None else float(timestamp)
    db = sampler.connect()
    try:
        _schema(db)
        inspected = _inspect()
        current_ports = inspected[1]
        valid_old = current_ports and all(row[2] for row in inspected[0])
        current = _history_counters() if valid_old else {}
        previous = {(proto, port, direction): (total, end)
                    for proto, port, direction, total, end in db.execute(
                        "SELECT protocol, listen_port, direction, total_bytes, sampled_at "
                        "FROM pm2_history_last")}
        rates = {}
        for proto, port in sorted(current_ports):
            old_down = previous.get((proto, port, "down"))
            old_up = previous.get((proto, port, "up"))
            down_total = current.get((proto, port, "down"))
            up_total = current.get((proto, port, "up"))
            if not old_down or not old_up or down_total is None or up_total is None:
                continue
            elapsed = now - max(old_down[1], old_up[1])
            if not 0 < elapsed <= 120 or down_total < old_down[0] or up_total < old_up[0]:
                continue
            rates[("auto", proto, port)] = {
                "down": (down_total - old_down[0]) * 8 / elapsed / 1e6,
                "up": (up_total - old_up[0]) * 8 / elapsed / 1e6}
        if rates:
            # One interval per direction/port; weighted averages use the
            # *actual* interval length and never invent coverage in outages.
            elapsed = now - max(previous[(proto, port, "down")][1]
                                for _tid, proto, port in rates)
            port_graph.record(db, now, elapsed, rates)
        try:
            wanted = set(auto_monitor.discover(existing=_tracked_elsewhere()))
        except PM2Error:
            # A transient ss failure cannot reset previously owned counters.
            wanted = current_ports
        if wanted != current_ports or not valid_old:
            _install(wanted, inspected)
            current = _history_counters() if wanted else {}
        with db:
            db.execute("DELETE FROM pm2_history_last")
            for (proto, port, direction), count in current.items():
                db.execute("INSERT INTO pm2_history_last VALUES(?,?,?,?,?)",
                           (proto, port, direction, count, now))
            db.execute("INSERT OR REPLACE INTO pm2_history_health VALUES(1,?)",
                       (now,))
        return {"monitored_ports": len(wanted), "samples_written": len(rates),
                "history_active": True, "sampled_at": now}
    finally:
        db.close()
