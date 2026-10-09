"""Short, beginner-friendly, V1-inspired terminal UI with safe backend reuse."""
import json
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

from .errors import PM2Error
from . import config, guard, limit_windows, port_graph, services, shaping, transaction, tunnels, system_rules


def _paint(code, text):
    return f"\033[{code}m{text}\033[0m" if os.isatty(1) and not os.getenv("NO_COLOR") else text


def _ask(label, default=None):
    suffix = f" [{default}]" if default is not None else ""
    try:
        answer = input(f"  {label}{suffix}: ").strip()
    except (KeyboardInterrupt, EOFError):
        return None
    return answer or default


def _confirm(label):
    return (_ask(label + " (y/N)", "n") or "").lower() == "y"


def _clear_screen():
    """Redraw one screen per navigation step; no accumulated SSH scrollback."""
    if os.isatty(1) and os.getenv("TERM", "").lower() not in ("", "dumb"):
        print("\033[2J\033[H", end="", flush=True)


def _title(subtitle):
    _clear_screen()
    _ui_header(subtitle.upper())


def _options(*choices):
    """One compact card style for tunnel, edit and limit submenus."""
    width = 60
    print(_paint("90", "  ╭" + "─" * width + "╮"))
    for choice in choices:
        print("  " + _paint("90", "│") +
              _paint("96;1" if choice.startswith("[1]") else "97", "  " + choice.ljust(width - 2)[:width - 2]) +
              _paint("90", "│"))
    print(_paint("90", "  ╰" + "─" * width + "╯"))


def _network_defaults():
    """Prefer real VPS Ethernet to optional WARP/WireGuard default routing."""
    from .discovery import run
    out = run(["ip", "-4", "route", "get", "1.1.1.1"], timeout=5).split()
    if "dev" not in out or "src" not in out:
        raise PM2Error("E_DEPENDENCY", "Cannot discover default interface and local IPv4")
    dev, src = out[out.index("dev") + 1], out[out.index("src") + 1]
    try:
        rows = json.loads(run(["ip", "-j", "-4", "addr", "show", "scope", "global"],
                              timeout=5))
        physical = []
        for row in rows:
            name = row.get("ifname", "")
            if not re.match(r"^(eth|ens|enp|eno)[0-9a-z_.-]*$", name):
                continue
            for address in row.get("addr_info", []):
                if address.get("family") == "inet" and address.get("local"):
                    physical.append((name, address["local"]))
        if physical:
            if dev in {p[0] for p in physical}:
                return next(p for p in physical if p[0] == dev)
            return sorted(physical, key=lambda item: (item[0] != "eth0", item[0]))[0]
    except (PM2Error, ValueError, TypeError, KeyError):
        pass
    return dev, src


def _protected_ssh_ports():
    """Use common SSH port plus detected sshd listeners; never guess one alone."""
    protected = {22}
    try:
        from .discovery import run
        raw = run(["ss", "-H", "-ltnp"], timeout=5)
        for line in raw.splitlines():
            if "sshd" not in line:
                continue
            fields = line.split()
            if len(fields) < 5 or ":" not in fields[4]:
                continue
            value = fields[4].rsplit(":", 1)[1]
            if value.isdecimal() and 1 <= int(value) <= 65535:
                protected.add(int(value))
    except PM2Error:
        pass
    return ",".join(str(p) for p in sorted(protected))


def _mutate(operation, argv):
    from .cli import mutation_lock
    preview = tunnels.handle(operation, [*argv, "--dry-run"], mutation_lock)
    print(_paint("93", "  Review change to Port Manager-owned tunnel configuration"))
    if not _confirm("Apply?"):
        return
    if operation == "delete":
        argv = [*argv, "--yes"]
    result = tunnels.handle(operation, argv, mutation_lock)
    if result.get("pending_confirmation"):
        pending = result["pending_confirmation"]
        print(_paint("93", "  IMPORTANT: SSH rollback guard armed (120 seconds)."))
        if _confirm("Still connected and keep the change?"):
            with mutation_lock():
                guard.confirm(pending)
        else:
            print("  Change will roll back automatically; do not close SSH.")
    print(_paint("92", "  ✓ Done"))


def _tunnel_wizard(old=None, all_ports=False):
    try:
        iface, ip = _network_defaults()
    except PM2Error as err:
        print(f"  Interface autodetection failed: {err.message}")
        return
    name_default = old["name"] if old else f"tunnel-{len(config.load(transaction.CONFIG)['tunnels'])+1}"
    name = _ask("Name", name_default)
    if name is None:
        return
    target = _ask("Destination server IPv4", old["target_ip"] if old else None)
    if not target:
        return
    listen_ip = old["listen_ip"] if old else ip
    device = old["interface"] if old else iface
    is_all = (old["mode"] == "all-except") if old else all_ports
    print(_paint("90", f"  Incoming interface {device} / local IP {listen_ip}"))
    argv = ([old["id"]] if old else []) + [
        "--name", name, "--interface", device, "--listen-ip", listen_ip,
        "--target-ip", target,
        "--protocol", ",".join(old["protocols"]) if old else "tcp,udp",
        "--mode", "all-except" if is_all else "ports"
    ]
    if is_all:
        existing = ",".join(str(p) for p in old["exclude"]) if old else _protected_ssh_ports()
        excludes = _ask("Protected SSH/admin ports (never tunnel)", existing)
        if excludes is None:
            return
        argv += ["--exclude", excludes, "--ack-all-ports"]
        print(_paint("91", "  CAUTION: all-except forwarding can disrupt SSH."))
    else:
        if old and old["mapping"]:
            preserved = ",".join(f'{p["listen_port"]}:{p["target_port"]}' for p in old["mapping"])
            mapping = _ask("Port pairs incoming:destination", preserved)
        else:
            port_in = _ask("Incoming port")
            port_out = _ask("Destination port", port_in)
            if not port_in or not port_out:
                return
            mapping = f"{port_in}:{port_out}"
        if not mapping:
            return
        argv += ["--mapping", mapping]
    _mutate("update" if old else "create", argv)



# Read-only, reference-style port configuration screen. Network operations
# stay in the existing tunnel/transaction functions; UI only renders data.
def _ui_width():
    import shutil
    return max(46, min(138, shutil.get_terminal_size((118, 30)).columns - 2))


def _ui_clean(value):
    # Protect terminal output against control characters in names/rule values.
    return "".join(c if c >= " " and c != "\x7f" else "?" for c in str(value))


def _ui_cut(value, width):
    import unicodedata
    value = _ui_clean(value)
    used = 0
    result = ""
    for char in value:
        size = 0 if unicodedata.combining(char) else (
            2 if unicodedata.east_asian_width(char) in ("W", "F") else 1)
        if used + size > width:
            return result[:-1] + "…" if result else ""
        result += char
        used += size
    return result


def _ui_len(value):
    import unicodedata
    raw = re.sub(r"\x1b\[[0-9;]*m", "", value)
    return sum(0 if unicodedata.combining(c) else (
        2 if unicodedata.east_asian_width(c) in ("W", "F") else 1) for c in raw)


def _ui_line(text="", width=None):
    width = width or _ui_width()
    usable = width - 4
    # Display text can contain our own ANSI styling; truncate fields first.
    extra = max(0, usable - _ui_len(text))
    print(_paint("96", "║") + " " + text + " " * extra +
          " " + _paint("96", "║"))


def _ui_edge(kind, width=None):
    width = width or _ui_width()
    left, right = {"top": ("╔", "╗"), "bottom": ("╚", "╝"),
                   "rule": ("╟", "╢")}[kind]
    print(_paint("96", left + ("═" if kind != "rule" else "─") *
                 (width - 2) + right))


def _ui_header(page):
    from . import VERSION
    import socket
    width = _ui_width()
    label = f" ◆  PORT MANAGER  │  {page}"
    host = _ui_cut(socket.gethostname(), 18)
    right = f"● ONLINE  │  {_ui_cut(VERSION, 18)}  │  {host}"
    room = width - 4
    if len(label) + len(right) + 1 > room:
        right = f"● ONLINE  │  {_ui_cut(VERSION, 12)}"
    gap = max(1, room - len(label) - len(right))
    print()
    _ui_edge("top", width)
    _ui_line(_paint("96;1", label) + " " * gap + _paint("92;1", right), width)
    _ui_edge("bottom", width)
    from .auto_monitor import interface_counters
    try:
        detected = interface_counters()
        interface = f"ALL ({len(detected)})" if detected else "none detected"
    except (OSError, ValueError):
        interface = "unknown"
    _ui_edge("top", width)
    status = (" Interfaces: " + _paint("92;1", interface) +
              "   │   View: " + _paint("93", "all ports / rules") +
              "   │   Mode: " + _paint("92;1", "interactive"))
    if _ui_len(status) > width - 4:
        status = " Interfaces: " + _paint("92;1", interface) + "  │  Interactive"
    _ui_line(status, width)
    _ui_edge("bottom", width)


def _ui_actions(*choices):
    width = _ui_width()
    _ui_edge("top", width)
    for index, (hotkey, label) in enumerate(choices):
        marker = _paint("96;1", f"[{hotkey}]")
        pointer = _paint("96;1", " ›") if index == 0 else "  "
        content = f"  {marker}   " + _ui_cut(label, width - 20)
        if index == 0:
            content = _paint("96", "▸ ") + content
        else:
            content = "  " + content
        _ui_line(content + " " * max(0, width - 5 - _ui_len(content) - 2) +
                 pointer, width)
    _ui_edge("bottom", width)
    print(_paint("90", "  0 Back    │    number + Enter Select    │    r Refresh"))


def _ui_header_row(width):
    if width >= 105:
        return "  #  CHAIN         PROTO:PORT      ACTION   TARGET                        IFACE        OWNER"
    if width >= 79:
        return "  #  CHAIN          PROTO:PORT       ACTION    TARGET / IFACE"
    return "  #   PROTO:PORT  →  TARGET / IFACE"


def _ui_record(index, chain, proto, action, destination, external=True, interface="-"):
    width = _ui_width()
    chain = _ui_clean(chain)
    proto = _ui_clean(proto)
    action = _ui_clean(action)
    destination = _ui_clean(destination)
    iface = _ui_clean(interface)
    if width >= 105:
        row = (f" {index:>2}  " + _paint("93", "●") + " " +
               f"{_ui_cut(chain, 12):<12}  " +
               _paint("96;1", f"{_ui_cut(proto, 13):<13}") + "  " +
               f"{_ui_cut(action, 7):<7}  " +
               _paint("95;1", f"{_ui_cut(destination, 28):<28}") + "  " +
               f"{_ui_cut(iface, 11):<11}  " +
               _paint("90", "[external]" if external else "[managed]"))
    elif width >= 79:
        row = (f" {index:>2}  " + _paint("93", "●") + " " +
               f"{_ui_cut(chain, 13):<13}  " +
               _paint("96;1", f"{_ui_cut(proto, 13):<13}") + "  " +
               f"{_ui_cut(action, 7):<7}  " +
               _paint("95;1", _ui_cut(destination + " [" + iface + "]",
                                     max(12, width - 58))))
    else:
        row = (f" {index:>2}  " + _paint("93", "●") + "  " +
               _paint("96;1", _ui_cut(proto, 14)) + " → " +
               _paint("95;1", _ui_cut(destination + " [" + iface + "]",
                                     max(10, width - 31))))
    _ui_line(row)


def _list_tunnels():
    width = _ui_width()
    cfg = config.load(transaction.CONFIG)
    items = cfg["tunnels"]
    rules, error = system_rules.detect_nat(limit=200)
    _ui_edge("top", width)
    _ui_line(_paint("96;1", " ▤  EXISTING FIREWALL CONFIGURATION"))
    _ui_line(_paint("90", "    Port Manager tunnels and existing NAT rules (system-wide view)"))
    _ui_edge("rule", width)
    if items:
        _ui_line(_paint("96;1", " ── PORT MANAGER CREATED TUNNELS ──"))
        for i, t in enumerate(items, 1):
            ports = ("ALL except " + ",".join(map(str, t["exclude"]))
                     if t["mode"] == "all-except" else
                     ",".join(f'{p["listen_port"]}→{p["target_port"]}'
                              for p in t["mapping"]))
            name = _ui_cut(t.get("name", "tunnel"), 20)
            dest = _ui_cut(t.get("target_ip", "?"), 32)
            state = _paint("92;1", "● ACTIVE") if t["enabled"] else _paint("90", "○ DISABLED")
            _ui_line(f"  {i:>2}. " + _paint("96;1", name) + "  " +
                     _paint("97", _ui_cut(ports, max(10, width - 65))) +
                     "  → " + _paint("95;1", dest) + "  " + state)
    else:
        _ui_line(_paint("97", f"  {len(items)} tunnels created here  |  {len(rules)} existing NAT rules detected"))
    _ui_line("")
    _ui_line(_paint("96;1", " ── EXISTING FIREWALL RULES ──"))
    _ui_line(_paint("90", _ui_cut(_ui_header_row(width), width - 5)))
    _ui_edge("rule", width)
    if rules:
        for i, rule in enumerate(rules, 1):
            _ui_record(i, rule["chain"],
                       f'{rule["protocol"]}:{rule["port"]}',
                       rule["target"], rule["destination"],
                       interface=rule.get("interface", "-"))
    elif error:
        _ui_line(_paint("93", "  " + _ui_cut(error, width - 8)))
    else:
        _ui_line(_paint("90", "  No existing NAT forwarding rules found."))
    _ui_line("")
    _ui_line(_paint("90", _ui_cut(
        "  External rules: read-only until verified import. Never auto-delete Docker/UFW rules.",
        width - 6)))
    _ui_edge("bottom", width)
    return items


def _ui_ports_intro():
    width = _ui_width()
    _ui_edge("top", width)
    _ui_line(_paint("96;1", " ▤  PORT FORWARDING & TUNNELS"))
    _ui_line("  Create or manage TCP/UDP port mappings without editing iptables by hand.")
    _ui_line(_paint("90", _ui_cut(
        "  Existing external NAT rules remain untouched. Changes to V2 require confirmation.",
        width - 7)))
    _ui_edge("bottom", width)


def _delete_all():
    from .cli import mutation_lock
    from . import shaping
    current = config.load(transaction.CONFIG)
    if not current["tunnels"]:
        return
    if any(p["enabled"] for p in shaping.schedule_load()["policies"]):
        raise PM2Error("E_CONFLICT", "Remove active speed-limit policies before deleting tunnels")
    print(_paint("91", "  Remove only Port Manager-created tunnels. External rules stay untouched."))
    if not _confirm("Delete every V2 tunnel?"):
        return
    with mutation_lock():
        current = config.load(transaction.CONFIG)
        if guard._read() is not None:
            raise PM2Error("E_CONFLICT", "Pending guarded tunnel change")
        proposed = config.replace(current, [])
        if guard.risky(current, proposed):
            result = guard.apply(proposed)
        else:
            result = transaction.apply(proposed)
        if result.get("pending_confirmation"):
            if _confirm("Keep the change after checking SSH?"):
                guard.confirm(result["pending_confirmation"])
            else:
                print("  Pending 120s rollback; network change not confirmed.")
    print(_paint("92", "  ✓ Tunnel removal requested"))


def _inspect_existing_rule():
    """Foreign NAT rules are viewable, but must not be modified blindly."""
    while True:
        _title("EXISTING RULES")
        rules, error = system_rules.detect_nat(limit=200)
        if error:
            print(_paint("93", "  " + error))
            _ask("Enter to return")
            return
        _ui_edge("top")
        _ui_line(f"  {len(rules)} NAT rules found  |  read-only inspection")
        for index, rule in enumerate(rules, 1):
            _ui_line("  " + _ui_cut(
                f"[{index}] {rule['chain']}  {rule['protocol']}:{rule['port']} "
                f"→ {rule['target']} {rule['destination']}", _ui_width() - 8))
        _ui_line("")
        _ui_line(_paint("93", _ui_cut(
            "  Editing a Docker/UFW/legacy rule without ownership validation can disconnect the VPS.",
            _ui_width() - 8)))
        _ui_edge("bottom")
        selected = _ask("Rule number to inspect / 0 Back", "0")
        if selected in ("0", None):
            return
        if not selected.isdecimal() or not 1 <= int(selected) <= len(rules):
            continue
        rule = rules[int(selected) - 1]
        _title("RULE DETAILS")
        _ui_edge("top")
        for key in ("chain", "protocol", "port", "target", "destination", "interface", "source"):
            _ui_line(f"  {key.upper():<16} {_ui_cut(rule.get(key, '-'), _ui_width() - 26)}")
        _ui_line("")
        _ui_line(_paint("93", "  Existing rule: inspect only; safe import is not configured."))
        _ui_edge("bottom")
        _ask("Enter to continue")


def _manage():
    while True:
        _title("CONFIG")
        items = _list_tunnels()
        _ui_actions(("1", "Edit / Delete Port Manager tunnel"),
                    ("2", "Delete ALL Port Manager tunnels"),
                    ("3", "Inspect existing external NAT rules"),
                    ("0", "Back"))
        choice = _ask("Select", "0")
        if choice in ("0", None):
            return
        if choice and choice.lower() == "r":
            continue
        if choice == "3":
            _inspect_existing_rule()
            continue
        if choice == "2":
            _delete_all()
            continue
        if choice != "1":
            continue
        if not items:
            _title("CONFIG")
            _ui_edge("top")
            _ui_line("  No tunnels created by Port Manager in this installation.")
            _ui_line("  Existing firewall rules are shown in option [3].")
            _ui_edge("bottom")
            _ask("Enter to continue")
            continue
        value = _ask("Tunnel number")
        if not value or not value.isdecimal() or not 1 <= int(value) <= len(items):
            continue
        selected = items[int(value) - 1]
        _title("EDIT TUNNEL")
        _ui_actions(("1", "Edit tunnel"), ("2", "Delete tunnel"), ("0", "Back"))
        action = _ask("Select", "0")
        if action == "1":
            _tunnel_wizard(selected)
        elif action == "2":
            _mutate("delete", [selected["id"]])


def _tunnel_page():
    while True:
        _title("PORTS")
        _list_tunnels()
        _ui_actions(("1", "New port to IP tunnel"),
                    ("2", "Tunnel ALL ports (protect SSH)"),
                    ("3", "Edit / Delete managed tunnel"),
                    ("4", "Inspect all system NAT rules"),
                    ("0", "Back"))
        choice = _ask("Select", "0")
        if choice in ("0", None):
            return
        if choice and choice.lower() == "r":
            continue
        if choice == "1":
            _title("NEW PORT")
            _tunnel_wizard()
        elif choice == "2":
            _title("ALL PORTS")
            _tunnel_wizard(all_ports=True)
        elif choice == "3":
            _manage()
        elif choice == "4":
            _inspect_existing_rule()


def _persist_policy(plan):
    from .cli import mutation_lock
    from . import config as safe_config
    limit_windows.validate(plan["policies"])
    with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8",
                                     dir=str(shaping.SCHEDULE.parent),
                                     prefix=".pm2-easy-", suffix=".json",
                                     delete=False) as tmp:
        path = Path(tmp.name)
        json.dump(plan, tmp)
    try:
        with mutation_lock():
            before = shaping.schedule_load()
            shaping.install_schedule(path)
            try:
                result = shaping.reconcile()
                if plan["policies"]:
                    services.activate()
            except Exception as exc:
                if isinstance(exc, PM2Error) and exc.code == "E_ROLLBACK":
                    raise
                safe_config.atomic_json(shaping.SCHEDULE, before)
                raise
        print(_paint("92", f"  ✓ Limits saved, active filters: {result['active_filters']}"))
    finally:
        path.unlink(missing_ok=True)


def _limit(port, interface, proto="tcp,udp"):
    if not interface:
        print(_paint("93", "  No network interface found; cannot apply a traffic cap."))
        return
    plan = shaping.schedule_load()
    mine = [p for p in plan["policies"] if p["port"] == port and
            (p.get("interface") == interface or not p.get("interface"))]
    title = "ALL interface IPv4 traffic" if port == 0 else f"port {port}"
    _title("SPEED LIMIT")
    _ui_edge("top")
    _ui_line(f"  Speed limit: {title} on {interface}")
    _ui_line(_paint("93", "  Requires an explicit confirmation before changing tc."))
    _ui_edge("bottom")
    if mine:
        for p in mine:
            print(f"   {p['id']}: ↓{p['download_mbps']} ↑{p['upload_mbps']} Mb/s "
                  f"{p['start']}-{p['end']}")
    _ui_actions(("1", "Set or edit speed limit"), ("2", "Remove limit"), ("0", "Back"))
    choice = _ask("Select", "0")
    if choice in ("0", None):
        return
    if choice == "2":
        if not mine:
            print("  No limit configured.")
            return
        if _confirm("Remove configured limit(s)?"):
            plan["policies"] = [p for p in plan["policies"] if p not in mine]
            _persist_policy(plan)
        return
    if choice != "1":
        return
    speed = _ask("Maximum speed in Mbit/s (same ↓/↑)", "20")
    if not speed or not speed.isdecimal() or not 1 <= int(speed) <= 100000:
        print("  Use a whole number from 1 to 100000.")
        return
    timing = _ask("[1] Always   [2] Certain hours", "1")
    if timing not in ("1", "2"):
        return
    if timing == "2":
        start = _ask("Start HH:MM", "18:00")
        end = _ask("End HH:MM", "02:00")
        zone = _ask("Timezone", "Asia/Tehran")
        if not start or not end or not zone:
            return
    else:
        start, end, zone = "00:00", "00:00", "UTC"
    ident = ("all" if port == 0 else f"p{port}") + "-" + re.sub(r"[^a-zA-Z0-9_-]", "-", interface)
    plan["policies"] = [p for p in plan["policies"] if p not in mine]
    plan["policies"].append({
        "id": ident[:32], "port": port,
        "protocol": "tcp,udp" if port == 0 else proto,
        "interface": interface, "timezone": zone,
        "days": [0, 1, 2, 3, 4, 5, 6], "start": start, "end": end,
        "download_mbps": int(speed), "upload_mbps": int(speed), "enabled": True
    })
    if port == 0:
        print(_paint("91", "  WARNING: ALL IPv4 traffic on this interface, including SSH, can be slowed/dropped."))
        if not _confirm("Confirm interface-wide rate policing?"):
            return
    _persist_policy(plan)


def _resolve_port_interface(row, links, chosen="ALL"):
    """Pick ingress NIC for a selected port without prompting unnecessarily.

    Port counters are not per-interface, so resolve from an explicit user NIC,
    owned tunnel configuration, foreign NAT -i binding, or physical VPS route.
    Never silently choose docker0 merely because it appears among interfaces.
    """
    names = {str(link.get("interface", "")) for link in links}
    # Tab/arrow-selected NIC is an intentional manual override of ALL view.
    if chosen and chosen != "ALL" and chosen in names:
        return chosen
    port = row.get("listen_port")
    proto = row.get("protocol")
    owner = row.get("tunnel_id")
    if not port or proto not in ("tcp", "udp"):
        return None
    if owner not in ("auto", "v1", None):
        cfg = config.load(transaction.CONFIG)
        for tunnel in cfg["tunnels"]:
            if tunnel["id"] == owner:
                iface = tunnel.get("interface")
                return iface if iface in names else None

    # Foreign NAT may explicitly bind packets to one incoming NIC (-i).
    rules, error = system_rules.detect_nat(limit=200)
    if not error:
        matches = {rule.get("interface") for rule in rules
                   if rule.get("chain") == "PREROUTING"
                   and rule.get("target") in ("DNAT", "REDIRECT")
                   and rule.get("protocol") == proto
                   and str(rule.get("port")) == str(port)
                   and rule.get("interface") not in (None, "-", "")}
        if len(matches) > 1:
            return None  # conflicting interfaces: require explicit choice
        if len(matches) == 1:
            iface = next(iter(matches))
            return iface if iface in names else None

    # No explicit -i: choose the primary physical VPS NIC; unlike choosing
    # links[0], this cannot select docker0 merely due to naming/sort order.
    try:
        iface, _address = _network_defaults()
        if iface in names and iface != "lo" and not iface.startswith(
                ("docker", "veth", "br-", "virbr")):
            return iface
    except (PM2Error, OSError, ValueError):
        pass
    physical = [name for name in names
                if re.match(r"^(eth|ens|enp|eno)[0-9a-z_.-]*$", name)]
    if len(physical) == 1:
        return physical[0]
    return None  # still ambiguous: fail closed before offering manual choice


def _choose_limit_interface(links):
    """A global overview cannot be passed to tc as a real network interface."""
    choices = [str(link["interface"]) for link in links]
    if not choices:
        print(_paint("93", "  No network interfaces detected."))
        return None
    if len(choices) == 1:
        return choices[0]
    _title("CHOOSE INTERFACE")
    _ui_edge("top")
    _ui_line("  Select one actual interface before applying speed limits.")
    _ui_line(_paint("93", "  ALL is a display mode, not a Linux network interface."))
    for index, name in enumerate(choices, 1):
        _ui_line(f"  [{index}] " + _ui_cut(name, _ui_width() - 12))
    _ui_edge("bottom")
    choice = _ask("Interface number / 0 Back", "0")
    if choice and choice.isdecimal() and 1 <= int(choice) <= len(choices):
        return choices[int(choice) - 1]
    return None


def _live():
    # Live opens directly in the fixed-screen UI; +/- changes refresh.
    latest = {}
    picked = {}
    def capture(frame):
        latest.clear()
        latest.update(frame)
    def choose(row, interface):
        # Store a read-only selection; actual traffic shaping is requested
        # only after curses/monitor contexts have safely unwound.
        picked.update({"row": row, "interface": interface})
    result = port_graph.watch(refresh=5, top=100, active_only=False,
                              on_frame=capture, on_select=choose)
    if not latest:
        return
    links = latest.get("interfaces", [])
    default_iface = links[0]["interface"] if links else None
    if picked:
        row = picked["row"]
        if row is None:
            iface = picked["interface"]
            if iface == "ALL":
                iface = _choose_limit_interface(links)
            if iface:
                _limit(0, iface)
            return
        selected_port = row.get("listen_port")
        if not selected_port:
            print(_paint("93", "  Aggregate row selected. Use g for whole-interface limit."))
            return
        selected_interface = picked["interface"]
    elif result == 0:
        # Esc returns without changing limits. Ctrl+C retains manual fallback.
        return
    else:
        _title("SELECT PORT")
        print("\n  Enter a port shown in Live, or ALL for the entire interface.")
        print("  [0] Return without changes")
        selected = _ask("Port / ALL", "0")
        if not selected or selected == "0":
            return
        if selected.upper() == "ALL":
            interface = _choose_limit_interface(links)
            if interface:
                _limit(0, interface)
            return
        if not selected.isdecimal() or not 1 <= int(selected) <= 65535:
            return
        selected_port = int(selected)
        matching = [x for x in latest["rows"] if x["listen_port"] == selected_port]
        if not matching:
            print("  Port not in the displayed list; no change made.")
            return
        row = matching[0]
        selected_interface = "ALL" if len(links) > 1 else default_iface
    # AUTO when Live is on ALL; honor an explicitly selected NIC if any.
    interface = _resolve_port_interface(row, links, selected_interface)
    if not interface:
        print(_paint("93", "  Interface ambiguous; choose one manually."))
        interface = _choose_limit_interface(links)
    if not interface:
        return
    proto = row["protocol"] if row["protocol"] in ("tcp", "udp") else "tcp,udp"
    _limit(selected_port, interface, proto)


def menu():
    if not os.isatty(0):
        raise PM2Error("E_VALIDATION", "Interactive Port Manager requires a terminal")
    while True:
        _title("HOME")
        _ui_actions(("1", "● LIVE TRAFFIC & SPEED LIMITS"),
                    ("2", "◆ PORTS / IPTABLES / TUNNELS"),
                    ("3", "✎ EDIT / DELETE CONFIGURATIONS"),
                    ("0", "Exit"))
        choice = _ask("Select", "0")
        if choice in ("0", None):
            _clear_screen()
            return 0
        try:
            if choice == "1":
                _live()
            elif choice == "2":
                _tunnel_page()
            elif choice == "3":
                _manage()
        except PM2Error as exc:
            print(_paint("91", f"  {exc.code}: {exc.message}"))
            _ask("Enter to continue")
        except (OSError, ValueError) as exc:
            print(_paint("91", f"  Invalid input: {str(exc)[:140]}"))
            _ask("Enter to continue")
