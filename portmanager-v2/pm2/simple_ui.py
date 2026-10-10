"""Short, beginner-friendly, V1-inspired terminal UI with safe backend reuse."""
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from .errors import PM2Error
from . import config, guard, limit_windows, port_graph, services, shaping, transaction, tunnels, system_rules, usage_ledger


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


def _title(subtitle, compact=False):
    _clear_screen()
    _ui_header(subtitle.upper(), compact=compact)


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
    print(_paint("93", "  Check the changes before saving this port connection."))
    if not _confirm("Apply?"):
        return
    if operation == "delete":
        argv = [*argv, "--yes"]
    result = tunnels.handle(operation, argv, mutation_lock)
    if result.get("pending_confirmation"):
        pending = result["pending_confirmation"]
        print(_paint("93", "  Keep this SSH window open for 2 minutes while the change is checked."))
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
    name_default = old["name"] if old else f"port-link-{len(config.load(transaction.CONFIG)['tunnels'])+1}"
    name = _ask("Name for this port connection", name_default)
    if name is None:
        return
    target = _ask("Send traffic to this IP address", old["target_ip"] if old else None)
    if not target:
        return
    listen_ip = old["listen_ip"] if old else ip
    device = old["interface"] if old else iface
    is_all = (old["mode"] == "all-except") if old else all_ports
    print(_paint("90", f"  Using network {device} on this server ({listen_ip})"))
    argv = ([old["id"]] if old else []) + [
        "--name", name, "--interface", device, "--listen-ip", listen_ip,
        "--target-ip", target,
        "--protocol", ",".join(old["protocols"]) if old else "tcp,udp",
        "--mode", "all-except" if is_all else "ports"
    ]
    if is_all:
        existing = ",".join(str(p) for p in old["exclude"]) if old else _protected_ssh_ports()
        excludes = _ask("Ports to keep unchanged (SSH/admin)", existing)
        if excludes is None:
            return
        argv += ["--exclude", excludes, "--ack-all-ports"]
        print(_paint("91", "  Warning: forwarding almost all ports can break remote login."))
    else:
        if old and old["mapping"]:
            preserved = ",".join(f'{p["listen_port"]}:{p["target_port"]}' for p in old["mapping"])
            mapping = _ask("Port pairs on this server:destination", preserved)
        else:
            port_in = _ask("Port on this server")
            port_out = _ask("Port on destination server", port_in)
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


def _ui_header(page, compact=False):
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
    if compact:
        return
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


def _ui_actions(*choices, selected=0):
    """Shared menu: the highlighted arrow is a real keyboard selection."""
    width = _ui_width()
    _ui_edge("top", width)
    for index, (hotkey, label) in enumerate(choices):
        chosen = index == selected
        text = "  " + f"[{hotkey}] " + _ui_cut(label, width - 17)
        inner_width = width - 8
        content = ("▶ " if chosen else "  ") + text
        content += " " * max(0, inner_width - _ui_len(content))
        if chosen:
            content = _paint("96;1", content)  # contrast-friendly; no solid background
        else:
            content = _paint("97", content)
        _ui_line(content, width)
    _ui_edge("bottom", width)
    print(_paint("90", "  ↑↓ Move   │   Enter Choose   │   0 / Esc Back   │   Number + Enter"))


def _menu_key(choices, selected, shortcuts=()):
    """Read one action directly from an interactive SSH terminal.

    The tty is always restored, including on Ctrl+C, EOF and exceptions.
    Digits require Enter (so a typed newline never leaks to the next screen).
    """
    import select
    import termios
    import tty
    fd = sys.stdin.fileno()
    previous = termios.tcgetattr(fd)
    typed = ""
    try:
        tty.setcbreak(fd)
        while True:
            char = os.read(fd, 1)
            if not char:
                return "0"
            if char == b"\x03":  # Ctrl+C
                return "0"
            if char == b"\x1b":
                seq = b""
                if select.select([fd], [], [], 0.05)[0]:
                    seq = os.read(fd, 1)
                    if seq in (b"[", b"O"):
                        while len(seq) < 12 and select.select([fd], [], [], 0.05)[0]:
                            nxt = os.read(fd, 1)
                            seq += nxt
                            if nxt in b"~ABCDHF":
                                break
                if seq.endswith(b"A"):
                    selected = (selected - 1) % len(choices)
                elif seq.endswith(b"B"):
                    selected = (selected + 1) % len(choices)
                else:
                    return "0"
                typed = ""
                _repaint_actions(choices, selected, typed)
                continue
            if char in (b"\r", b"\n"):
                if typed:
                    available = {key for key, _ in choices}
                    result = typed if typed in available else None
                    if result is None:
                        typed = ""
                        _repaint_actions(choices, selected, typed)
                        continue
                    return result
                return choices[selected][0]
            if char in (b"\x7f", b"\x08"):
                typed = typed[:-1]
                _draw_menu_prompt(choices, selected, typed)
                continue
            if char in (b"r", b"R") and not typed:
                return "r"
            if char in (b"q", b"Q") and not typed:
                return "0"
            # Letter shortcuts are used for actions that share a screen
            # with numeric day/port choices; they must never shadow a day.
            if char.isalpha() and not typed:
                letter = char.decode("ascii").lower()
                if letter in {key.lower() for key, _ in choices} or letter in shortcuts:
                    return letter
                continue
            if char.isdigit():
                typed = (typed + char.decode("ascii"))[-5:]
                _draw_menu_prompt(choices, selected, typed)
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, previous)
        print()


def _draw_menu_prompt(choices, selected, typed):
    default = choices[selected][0]
    sys.stdout.write("\r\x1b[2K" + _paint("96;1", "  Choose") +
                     f" [{default}]: {typed}")
    sys.stdout.flush()


def _repaint_actions(choices, selected, typed):
    # Cursor is on the prompt line just below the (n + 3)-line menu.
    sys.stdout.write("\r\x1b[2K" + f"\x1b[{len(choices) + 3}A\x1b[J")
    sys.stdout.flush()
    _ui_actions(*choices, selected=selected)
    _draw_menu_prompt(choices, selected, typed)


def _choose(*choices, selected=0, shortcuts=()):
    """Universal navigation for all on-screen options, with safe pipe fallback."""
    if not choices:
        return "0"
    keys = [key for key, _ in choices] + list(shortcuts)
    if len(set(keys)) != len(keys):
        raise ValueError("Menu shortcuts must be unique")
    selected = max(0, min(selected, len(choices) - 1))
    _ui_actions(*choices, selected=selected)
    if not (os.isatty(0) and os.isatty(1) and sys.stdin.isatty() and
            sys.stdout.isatty() and
            os.getenv("TERM", "").lower() not in ("", "dumb")):
        return _ask("Choose option", "0")
    try:
        _draw_menu_prompt(choices, selected, "")
        return _menu_key(choices, selected, shortcuts=shortcuts)
    except (OSError, ValueError, ImportError):
        # Nonstandard terminal: provide an ordinary numeric choice.
        print()
        return _ask("Choose option", "0")


def _pick_row(title, rows, describe):
    """Browse any length of port/rule list with bounded terminal-height pages."""
    if not rows:
        return None
    size = max(3, min(7, shutil.get_terminal_size((100, 28)).lines - 13))
    page = 0
    while True:
        start = page * size
        window = rows[start:start + size]
        _title(title)
        _ui_edge("top")
        _ui_line(f"  {len(rows)} results  |  Page {page + 1} of {(len(rows) + size - 1) // size}")
        _ui_line("  Use ↑↓ and Enter, or type a number and Enter.")
        _ui_edge("bottom")
        choices = [(str(i + 1), _ui_cut(describe(item),
                                       _ui_width() - 20))
                   for i, item in enumerate(window)]
        if page:
            choices.append(("8", "Previous page"))
        if start + size < len(rows):
            choices.append(("9", "Next page"))
        choices.append(("0", "Go back"))
        action = _choose(*choices)
        if action in ("0", None):
            return None
        if action == "8" and page:
            page -= 1
        elif action == "9" and start + size < len(rows):
            page += 1
        elif action == "r":
            continue
        elif action and action.isdecimal() and 1 <= int(action) <= len(window):
            return window[int(action) - 1]


def _ui_header_row(width):
    if width >= 105:
        return "  #  DIRECTION     PORT          ACTION      DESTINATION                    NETWORK      CREATED BY"
    if width >= 79:
        return "  #  DIRECTION      PORT             ACTION     DESTINATION"
    return "  #  PORT  →  DESTINATION"


def _ui_record(index, chain, proto, action, destination, external=True, interface="-"):
    width = _ui_width()
    direction = {"PREROUTING": "Incoming", "POSTROUTING": "Outgoing",
                 "OUTPUT": "Local out"}.get(chain, chain)
    operation = {"DNAT": "Forward", "REDIRECT": "Local", "SNAT": "Change IP",
                 "MASQUERADE": "Share IP"}.get(action, action)
    proto = _ui_clean(proto)
    destination = _ui_clean(destination)
    iface = _ui_clean(interface)
    owner = "Other app" if external else "This app"
    if width >= 105:
        row = (f" {index:>2}  " + _paint("93", "●") + " " +
               f"{_ui_cut(direction, 12):<12}  " +
               _paint("96;1", f"{_ui_cut(proto, 13):<13}") + "  " +
               f"{_ui_cut(operation, 10):<10}  " +
               _paint("95;1", f"{_ui_cut(destination, 28):<28}") + "  " +
               f"{_ui_cut(iface, 11):<11}  " +
               _paint("90", _ui_cut(owner, 11)))
    elif width >= 79:
        row = (f" {index:>2}  " + _paint("93", "●") + " " +
               f"{_ui_cut(direction, 13):<13}  " +
               _paint("96;1", f"{_ui_cut(proto, 15):<15}") + "  " +
               f"{_ui_cut(operation, 9):<9}  " +
               _paint("95;1", _ui_cut(destination, max(12, width - 57))))
    else:
        row = (f" {index:>2}  " + _paint("93", "●") + "  " +
               _paint("96;1", _ui_cut(proto, 14)) + " → " +
               _paint("95;1", _ui_cut(destination, max(10, width - 23))))
    _ui_line(row)


def _list_tunnels():
    width = _ui_width()
    cfg = config.load(transaction.CONFIG)
    items = cfg["tunnels"]
    rules, error = system_rules.detect_nat(limit=200)
    # Keep the action menu on-screen even with hundreds of port rules.
    height = shutil.get_terminal_size((100, 28)).lines
    budget = max(4, min(10, height - 18))
    saved_preview = min(len(items), max(2, budget // 2))
    rules_preview = max(2, budget - saved_preview)
    _ui_edge("top", width)
    _ui_line(_paint("96;1", " ▤  PORTS AND CONNECTIONS ON THIS SERVER"))
    _ui_line(_paint("90", "    See where your ports send traffic. Nothing changes on this page."))
    _ui_edge("rule", width)
    if items:
        _ui_line(_paint("96;1", " ── PORT CONNECTIONS SAVED HERE ──"))
        for i, t in enumerate(items[:saved_preview], 1):
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
        if len(items) > saved_preview:
            _ui_line(_paint("90", f"  + {len(items) - saved_preview} more saved connections; choose Change / Remove to browse"))
    else:
        _ui_line(_paint("97", f"  {len(items)} saved connections  |  {len(rules)} existing network rules"))
    _ui_line("")
    _ui_line(_paint("96;1", " ── OTHER EXISTING PORT RULES ──"))
    _ui_line(_paint("90", _ui_cut(_ui_header_row(width), width - 5)))
    _ui_edge("rule", width)
    if rules:
        for i, rule in enumerate(rules[:rules_preview], 1):
            _ui_record(i, rule["chain"],
                       f'{rule["protocol"]}:{rule["port"]}',
                       rule["target"], rule["destination"],
                       interface=rule.get("interface", "-"))
        if len(rules) > rules_preview:
            _ui_line(_paint("90", f"  + {len(rules) - rules_preview} more rules; choose See existing port rules to browse"))
    elif error:
        _ui_line(_paint("93", "  " + _ui_cut(error, width - 8)))
    else:
        _ui_line(_paint("90", "  No existing NAT forwarding rules found."))
    _ui_line("")
    _ui_line(_paint("90", _ui_cut(
        "  Other apps may own these rules (read-only). View them safely here.",
        width - 6)))
    _ui_edge("bottom", width)
    return items


def _ui_ports_intro():
    width = _ui_width()
    _ui_edge("top", width)
    _ui_line(_paint("96;1", " ▤  PORT FORWARDING"))
    _ui_line("  Send traffic arriving on a port to another server.")
    _ui_line(_paint("90", _ui_cut(
        "  Other apps\x27 network rules are kept safe. Changes need confirmation.",
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
    print(_paint("91", "  Remove saved port connections? Other apps will not be changed."))
    if not _confirm("Remove ALL saved port connections?"):
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
    print(_paint("92", "  ✓ Saved connection removal requested"))


def _inspect_existing_rule():
    """Existing rules are browseable, never silently adopted or changed."""
    while True:
        rules, error = system_rules.detect_nat(limit=200)
        if error:
            _title("EXISTING PORTS")
            _ui_edge("top")
            _ui_line(_paint("93", "  Cannot read existing port rules right now."))
            _ui_line(_ui_cut(error, _ui_width() - 8))
            _ui_edge("bottom")
            _ask("Press Enter to return")
            return
        if not rules:
            _title("EXISTING PORTS")
            _ui_edge("top")
            _ui_line("  No existing port rules found.")
            _ui_edge("bottom")
            _ask("Press Enter to return")
            return
        rule = _pick_row(
            "EXISTING PORTS", rules,
            lambda item: (f'{item["protocol"]}:{item["port"]} '
                          f'→ {item["destination"]}  ({item["target"]})'))
        if rule is None:
            return
        _title("PORT DETAILS")
        _ui_edge("top")
        columns = (("Port", f'{rule["protocol"]}:{rule["port"]}'),
                   ("Direction", "Incoming" if rule["chain"] == "PREROUTING"
                    else "Outgoing" if rule["chain"] == "POSTROUTING"
                    else rule["chain"]),
                   ("Action", {"DNAT": "Forward to destination",
                               "REDIRECT": "Handle on this server",
                               "SNAT": "Change outgoing IP",
                               "MASQUERADE": "Use this server's IP"}.get(
                                   rule["target"], rule["target"])),
                   ("Destination", rule["destination"]),
                   ("Network", rule.get("interface", "-")))
        for label, value in columns:
            _ui_line(f"  {label:<14} {_ui_cut(value, _ui_width() - 24)}")
        _ui_line("")
        _ui_line(_paint("93", "  Rule from another app: view only for safety."))
        _ui_edge("bottom")
        _choose(("0", "Back to port list"))



def _manage():
    while True:
        _title("MY PORTS")
        items = _list_tunnels()
        choice = _choose(("1", "Change or remove a saved port"),
                         ("2", "Remove all saved port connections"),
                         ("3", "See other existing port rules"),
                         ("0", "Back to previous menu"))
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
            _title("MY PORTS")
            _ui_edge("top")
            _ui_line("  No port connections saved in this app yet.")
            _ui_line("  You can still see existing ports with option [3].")
            _ui_edge("bottom")
            _ask("Enter to continue")
            continue
        selected = _pick_row(
            "SAVED PORT CONNECTIONS", items,
            lambda item: (f'{item.get("name", "Connection")}  → '
                          f'{item.get("target_ip", "?")}'))
        if selected is None:
            continue
        _title("EDIT PORT")
        action = _choose(("1", "Change this port connection"),
                         ("2", "Remove this port connection"),
                         ("0", "Go back"))
        if action == "1":
            _tunnel_wizard(selected)
        elif action == "2":
            _mutate("delete", [selected["id"]])


def _tunnel_page():
    while True:
        _title("PORTS")
        _list_tunnels()
        choice = _choose(("1", "Forward a port to another server"),
                         ("2", "Forward almost all ports (advanced)"),
                         ("3", "Change or remove a saved port"),
                         ("4", "See other existing port rules"),
                         ("0", "Back to home"))
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
    _ui_line(f"  Selected: {title}  |  Network: {interface}")
    _ui_line(_paint("93", "  Nothing changes until you save the new speed setting."))
    _ui_edge("bottom")
    if mine:
        for p in mine:
            print(f"   {p['id']}: ↓{p['download_mbps']} ↑{p['upload_mbps']} Mb/s "
                  f"{p['start']}-{p['end']}")
    choice = _choose(("1", "Set or change speed"),
                     ("2", "Remove the speed limit"),
                     ("0", "Go back"))
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
    speed = _ask("Max download and upload speed (Mbps)", "20")
    if not speed or not speed.isdecimal() or not 1 <= int(speed) <= 100000:
        print("  Use a whole number from 1 to 100000.")
        return
    _title("WHEN TO LIMIT SPEED")
    timing = _choose(("1", "All day, every day"),
                     ("2", "Only at certain hours"),
                     ("0", "Cancel"))
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
    _title("CHOOSE NETWORK")
    _ui_edge("top")
    _ui_line("  More than one network matches. Choose the one to limit.")
    _ui_line(_paint("93", "  Your choice affects only this network."))
    for index, name in enumerate(choices, 1):
        _ui_line(f"  [{index}] " + _ui_cut(name, _ui_width() - 12))
    _ui_edge("bottom")
    choice = _ask("Network number / 0 Back", "0")
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
        print(_paint("93", "  Could not identify one network for this port."))
        interface = _choose_limit_interface(links)
    if not interface:
        return
    proto = row["protocol"] if row["protocol"] in ("tcp", "udp") else "tcp,udp"
    _limit(selected_port, interface, proto)


def _usage_amount(lower, upper):
    """Compact GB labels; sub-0.01 GB measurements are never shown as zero."""
    def short(byte_count):
        if byte_count == 0:
            return "0"
        if 0 < byte_count < 10_000_000:
            return "<0.01"
        return f"{byte_count / 1e9:.2f}"
    lo, hi = short(lower), short(upper)
    if lower == upper:
        return lo
    return f"{lo}–{hi}" if lo != hi else f"{lo}~"


def _usage_row(label, item, wide=True, date=None):
    """Fixed-width columns; no text/background color may obscure a value."""
    down = _usage_amount(item["download_bytes_lower"],
                         item["download_bytes_upper"])
    up = _usage_amount(item["upload_bytes_lower"],
                       item["upload_bytes_upper"])
    covered = item.get("covered_seconds")
    coverage = f"{covered / 60:.0f}m recorded" if covered is not None else (
        f'{item.get("missing_seconds", 0) / 60:.0f}m gap')
    if wide:
        prefix = f"  {date:<11} " if date is not None else "  "
        return (f"{prefix}{label:<12}"
                f"  {down:>18}  {up:>18}  {coverage}")
    prefix = f"  {date}  " if date is not None else "  "
    return (f"{prefix}{label}\n"
            f"    ↓ Download: {down} GB   |   ↑ Upload: {up} GB\n"
            f"    {coverage}")


_BIG_DIGITS = {
    "0": ("███", "█ █", "█ █", "█ █", "███"),
    "1": (" ██", "  █", "  █", "  █", "███"),
    "2": ("███", "  █", "███", "█  ", "███"),
    "3": ("███", "  █", "███", "  █", "███"),
    "4": ("█ █", "█ █", "███", "  █", "  █"),
    "5": ("███", "█  ", "███", "  █", "███"),
    "6": ("███", "█  ", "███", "█ █", "███"),
    "7": ("███", "  █", "  █", "  █", "  █"),
    "8": ("███", "█ █", "███", "█ █", "███"),
    "9": ("███", "█ █", "███", "  █", "███"),
    ".": ("   ", "   ", "   ", "   ", " █ "),
    "-": ("   ", "   ", "███", "   ", "   "),
}


def _usage_big_digits(text):
    """Five-terminal-row digits, no special fonts or terminal extensions."""
    glyphs = [_BIG_DIGITS.get(char, _BIG_DIGITS["-"])
              for char in str(text)]
    return [" ".join(glyph[i] for glyph in glyphs) for i in range(5)]


def _usage_hero(label, data, width):
    """One compact, high-contrast totals display; never equate missing with 0."""
    iface = data.get("interface") if data else None
    known = bool(data and data.get("has_samples"))
    _ui_line(_paint("97;1", f"  {label}") +
             _paint("90", f"  ·  {iface}" if iface else ""))
    if not known:
        _ui_line(_paint("93;1", "  NOT RECORDED") +
                 _paint("90", "   Traffic before logging started is unknown."))
        return
    down_lo, down_hi = data["download_bytes_lower"], data["download_bytes_upper"]
    up_lo, up_hi = data["upload_bytes_lower"], data["upload_bytes_upper"]
    dl, ul = down_lo / 1e9, up_lo / 1e9
    wide = (width >= 99 and
            shutil.get_terminal_size((110, 34)).lines >= 36)
    if wide:
        col = (width - 12) // 2
        _ui_line("  " + _paint("92;1", "↓ DOWNLOAD".ljust(col)) +
                 _paint("96;1", "↑ UPLOAD"))
        down_art = _usage_big_digits(f"{dl:.2f}")
        up_art = _usage_big_digits(f"{ul:.2f}")
        for i in range(5):
            _ui_line("  " + _paint("92;1", down_art[i].ljust(col)) +
                     _paint("96;1", up_art[i]))
        _ui_line("  " + _paint("92;1", "GB".ljust(col)) +
                 _paint("96;1", "GB"))
    else:
        _ui_line("  " + _paint("92;1", f"↓ DOWNLOAD   {dl:.2f} GB"))
        _ui_line("  " + _paint("96;1", f"↑ UPLOAD     {ul:.2f} GB"))
    if down_lo != down_hi or up_lo != up_hi:
        _ui_line(_paint("93",
            "  Partial sample: ↓ " +
            _usage_amount(down_lo, down_hi) + " GB  |  ↑ " +
            _usage_amount(up_lo, up_hi) + " GB"))
    total = down_lo + up_lo
    _ui_line("  " + _paint("93;1", f"↓ + ↑  {total/1e9:.2f} GB recorded") +
             _paint("90", "    (both directions, not the provider bill)"))
    covered = data.get("covered_seconds", 0)
    _ui_line(_paint("90", f"  Measured {covered/60:.0f} minutes. "
               "Gaps are unknown—not zero."))


def _usage_day_label(day, width):
    """Day list: one recognizable line, never merge day and port views."""
    network = day.get("server") or {}
    if network.get("has_samples"):
        dl = _usage_amount(network["download_bytes_lower"],
                           network["download_bytes_upper"])
        ul = _usage_amount(network["upload_bytes_lower"],
                           network["upload_bytes_upper"])
        # The network is measured independently and is never a sum of ports.
        total_lo = network["download_bytes_lower"] + network["upload_bytes_lower"]
        total_hi = network["download_bytes_upper"] + network["upload_bytes_upper"]
        total = _usage_amount(total_lo, total_hi)
        label = (f'{day["date"]:<12}   '
                 f'↓ {dl:>12} GB     ↑ {ul:>12} GB     '
                 f'TOTAL {total:>12} GB')
        return _ui_cut(label, max(15, width - 19))
    if day.get("ports"):
        return _ui_cut(
            f'{day["date"]}   Ports recorded · server total unavailable',
            max(15, width - 19))
    return f'{day["date"]}   No recordings (unknown)'


def _usage_cross_date(result):
    """Daily bytes for all monitored ports, on one screen with pagination."""
    all_days = list(reversed(result.get("daily", [])))
    port_names = sorted({
        (item["protocol"], item["port"])
        for day in all_days for item in day.get("ports", [])
    }, key=lambda key: (
        -sum(item["download_bytes_lower"] + item["upload_bytes_lower"]
             for day in all_days for item in day.get("ports", [])
             if (item["protocol"], item["port"]) == key),
        key[0], key[1]))
    filter_port = None
    page = 0
    while True:
        width = _ui_width()
        screen_rows = shutil.get_terminal_size((118, 34)).lines
        page_size = max(4, min(15, screen_rows - 17))
        entries = []
        if filter_port is None:
            for day in all_days:
                observed = sorted(day.get("ports", []),
                                  key=lambda item: -(
                                      item["download_bytes_lower"] +
                                      item["upload_bytes_lower"]))
                for item in observed:
                    entries.append((day["date"], item))
                if not observed:
                    entries.append((day["date"], None))
        else:
            for day in all_days:
                entry = next((item for item in day.get("ports", [])
                              if (item["protocol"], item["port"]) == filter_port), None)
                entries.append((day["date"], entry))
        max_page = max(0, (len(entries) - 1) // page_size)
        page = min(page, max_page)
        _title("PORT CONSUMPTION BY DATE", compact=True)
        _ui_edge("top")
        label = (f"{filter_port[0].upper()}:{filter_port[1]}"
                 if filter_port else "ALL MONITORED PORTS")
        _ui_line(_paint("97;1", f"  {label}") +
                 _paint("90", f"  ·  {result.get('timezone', 'Asia/Tehran')}  ·  past 14 days"))
        _ui_line(_paint("90", "  Values = recorded GB; unknown days are not zero usage."))
        if filter_port is not None:
            selected = next((item for item in result.get("ports", [])
                             if (item["protocol"], item["port"]) == filter_port), None)
            if selected is not None:
                down = _usage_amount(selected["download_bytes_lower"],
                                     selected["download_bytes_upper"])
                up = _usage_amount(selected["upload_bytes_lower"],
                                   selected["upload_bytes_upper"])
                both = _usage_amount(
                    selected["download_bytes_lower"] + selected["upload_bytes_lower"],
                    selected["download_bytes_upper"] + selected["upload_bytes_upper"])
                _ui_line(_paint("93;1", "  RECORDED PERIOD TOTAL") +
                         f"  ↓ {down} GB   ↑ {up} GB   BOTH {both} GB")
        _ui_line(_paint("90",
                 "  F: filter by port / ALL    9: next page    8: previous page"))
        _ui_edge("rule")
        if width >= 104:
            _ui_line(_paint("96;1",
                f"  {'DATE':<12} {'PORT':<11} {'↓ DOWNLOAD GB':>15}"
                f"  {'↑ UPLOAD GB':>15}  {'TOTAL GB':>15}  MEASURED"))
        else:
            _ui_line(_paint("96;1",
                "  DATE  /  PORT      ↓ DOWNLOAD GB    ↑ UPLOAD GB    TOTAL"))
        displayed = entries[page * page_size:(page + 1) * page_size]
        for date, item in displayed:
            if item is None:
                _ui_line(_paint("93", f"  {date}   NO RECORD (unknown)"))
                continue
            port_label = f'{item["protocol"].upper()}:{item["port"]}'
            down = _usage_amount(item["download_bytes_lower"],
                                 item["download_bytes_upper"])
            up = _usage_amount(item["upload_bytes_lower"],
                               item["upload_bytes_upper"])
            both = _usage_amount(
                item["download_bytes_lower"] + item["upload_bytes_lower"],
                item["download_bytes_upper"] + item["upload_bytes_upper"])
            measured = f'{item.get("covered_seconds", 0)/60:.0f}m'
            if width >= 104:
                _ui_line("  " + f"{date:<12} {port_label:<11} " +
                         _paint("92;1", f"{down:>15}") + "  " +
                         _paint("96;1", f"{up:>15}") + "  " +
                         _paint("93;1", f"{both:>15}") +
                         _paint("90", f"  {measured}"))
            else:
                _ui_line("  " + f"{date}  {port_label:<10} " +
                         _paint("92;1", f"↓{down}") + " " +
                         _paint("96;1", f"↑{up}") + " " +
                         _paint("93;1", f"Σ{both}"))
        if not entries:
            _ui_line(_paint("93;1", "  No port byte samples recorded for this range."))
        _ui_edge("bottom")
        print(_paint("90", f"  Page {page+1}/{max_page+1}  ·  {len(entries)} day/port entries"))
        print(_paint("90",
            "  Port counters may overlap due to NAT; do not add ports to estimate the server bill."))
        choices = []
        if page > 0:
            choices.append(("8", "Previous page"))
        if page < max_page:
            choices.append(("9", "Next page"))
        choices.append(("0", "Back"))
        action = _choose(*choices, shortcuts=("f",))
        if action == "8" and page > 0:
            page -= 1
        elif action == "9" and page < max_page:
            page += 1
        elif action == "f":
            raw = _ask("Port number (ALL to show all)", "ALL")
            if raw is None:
                continue
            if raw.strip().upper() == "ALL":
                filter_port = None
            elif raw.strip().isdecimal() and 1 <= int(raw) <= 65535:
                number = int(raw)
                matching = [key for key in port_names if key[1] == number]
                if not matching:
                    _ui_line(_paint("93",
                        f"  Port {number} has no stored data in this range."))
                    _ask("Enter to return")
                    continue
                filter_port = matching[0]
            else:
                _ui_line(_paint("93", "  Enter a port from 1–65535 or ALL."))
                _ask("Enter to return")
                continue
            page = 0
        else:
            return


def _usage_detail(result, day=None):
    """One selected day -> only its per-port table; Esc returns to day list."""
    rows = day["ports"] if day is not None else result["ports"]
    network = day.get("server") if day is not None else result.get("server")
    label = day["date"] if day is not None else "SELECTED PERIOD"
    page = 0
    while True:
        width = _ui_width()
        terminal_rows = shutil.get_terminal_size((110, 34)).lines
        uses_big_figures = width >= 99 and terminal_rows >= 36
        # Budget for compact header, 5-row figure, table labels and menu.
        reserved_rows = 29 if uses_big_figures else 23
        max_rows = max(1, min(12, terminal_rows - reserved_rows))
        max_page = max(0, (len(rows) - 1) // max_rows)
        page = min(page, max_page)
        _title("PORTS · " + label, compact=True)
        _ui_edge("top")
        _usage_hero("SERVER TRAFFIC", network, width)
        _ui_edge("rule")
        _ui_line(_paint("97;1", "  PORT BREAKDOWN") +
                 _paint("90", f"   ·   {len(rows)} monitored ports"))
        if width >= 94:
            _ui_line(_paint("96;1",
                f"  {'PORT':<13}  {'↓ DOWNLOAD (GB)':>18}  {'↑ UPLOAD (GB)':>18}   MEASURED"))
        else:
            _ui_line(_paint("96;1", "  PORT     ↓ DOWNLOAD  |  ↑ UPLOAD"))
        shown = rows[page * max_rows:(page + 1) * max_rows]
        if not shown:
            _ui_line(_paint("93;1",
                "  No port samples for this date. Usage is unknown, not 0 GB."))
        for item in shown:
            name = f'{item["protocol"].upper()}:{item["port"]}'
            down = _usage_amount(item["download_bytes_lower"],
                                 item["download_bytes_upper"])
            up = _usage_amount(item["upload_bytes_lower"],
                               item["upload_bytes_upper"])
            mins = item.get("covered_seconds", 0) / 60
            if width >= 94:
                line = (f"  {name:<13}  " +
                        _paint("92;1", f"{down:>18}") + "  " +
                        _paint("96;1", f"{up:>18}") +
                        _paint("90", f"   {mins:.0f}m"))
                _ui_line(line)
            else:
                _ui_line(_paint("97;1", f"  {name}") + "  " +
                         _paint("92;1", f"↓ {down} GB") + "  " +
                         _paint("96;1", f"↑ {up} GB"))
        _ui_edge("bottom")
        if len(rows) > max_rows:
            print(_paint("90", f"  Page {page+1}/{max_page+1}"))
        print(_paint("90",
            "  Port amounts can overlap due to forwarding; don't add them for billing."))
        buttons = []
        if page > 0:
            buttons.append(("8", "Previous ports"))
        if page < max_page:
            buttons.append(("9", "Next ports"))
        print(_paint("90", "  P: compare each port's consumption across dates"))
        buttons.append(("0", "Back to days"))
        action = _choose(*buttons, shortcuts=("p",))
        if action == "8" and page > 0:
            page -= 1
        elif action == "9" and page < max_page:
            page += 1
        elif action == "p":
            _usage_cross_date(result)
        else:
            return


def _usage_report(custom=False):
    """Home [4] goes directly to a 14-day date chooser with no questions."""
    zone_name = "Asia/Tehran"
    port = None
    if custom:
        _title("REPORT SETTINGS", compact=True)
        _ui_edge("top")
        _ui_line("  Change dates or choose one port. Press Enter for defaults.")
        _ui_edge("bottom")
        zone_name = _ask("Time zone", zone_name)
        if not zone_name:
            return
    try:
        zone = ZoneInfo(zone_name)
    except (ZoneInfoNotFoundError, KeyError, ValueError):
        print("  Unknown time zone. Try Asia/Tehran or UTC.")
        _ask("Enter to return")
        return
    now = datetime.now(zone).replace(second=0, microsecond=0)
    start = (now - timedelta(days=13)).replace(hour=0, minute=0).strftime(
        "%Y-%m-%d %H:%M")
    end = now.strftime("%Y-%m-%d %H:%M")
    if custom:
        start = _ask("From date/time (YYYY-MM-DD HH:MM)", start)
        end = _ask("Until date/time (YYYY-MM-DD HH:MM)", end)
        chosen_port = _ask("Port (ALL = all ports)", "ALL")
        if start is None or end is None or chosen_port is None:
            return
        if chosen_port.upper() != "ALL":
            if not chosen_port.isdecimal() or not 1 <= int(chosen_port) <= 65535:
                print("  Enter ALL or a port between 1 and 65535.")
                return
            port = int(chosen_port)
    result = usage_ledger.report(start, end, zone_name, port=port)
    days = list(reversed(result.get("daily", [])))
    page = 0
    while True:
        width = _ui_width()
        page_size = max(3, min(7, shutil.get_terminal_size((110, 34)).lines - 15))
        max_page = max(0, (len(days) - 1) // page_size)
        page = min(page, max_page)
        _title("TRAFFIC BY DAY", compact=True)
        _ui_edge("top")
        _ui_line(_paint("97;1", "  CHOOSE A DAY") +
                 _paint("90", f"  ·  last 14 days  ·  {zone_name}"))
        _ui_line("  " + _paint("92;1", "↓ DOWNLOAD") +
                 "     " + _paint("96;1", "↑ UPLOAD") +
                 "     " + _paint("93;1", "TOTAL (↓ + ↑)") +
                 _paint("90", "   ·   GB on main network interface"))
        _ui_line(_paint("93",
            "  Unknown days show NO DATA; zero is never assumed."))
        summary = result.get("server") or {}
        if summary.get("has_samples"):
            summed_dl = _usage_amount(summary["download_bytes_lower"],
                                      summary["download_bytes_upper"])
            summed_ul = _usage_amount(summary["upload_bytes_lower"],
                                      summary["upload_bytes_upper"])
            summed_total = _usage_amount(
                summary["download_bytes_lower"] + summary["upload_bytes_lower"],
                summary["download_bytes_upper"] + summary["upload_bytes_upper"])
            _ui_line("  " + _paint("97;1", "PERIOD TOTAL") +
                     f"  ↓ {summed_dl} GB   ↑ {summed_ul} GB   " +
                     _paint("93;1", f"TOTAL {summed_total} GB"))
        _ui_line(_paint("90",
            "  Enter: one day   P: port traffic by date   S: settings   T: range"))
        _ui_edge("bottom")
        chunk = days[page * page_size:(page + 1) * page_size]
        choices = [(str(i + 1), _usage_day_label(day, width))
                   for i, day in enumerate(chunk)]
        if page > 0:
            choices.append(("8", "← Newer days"))
        if page < max_page:
            choices.append(("9", "Older days →"))
        choices.append(("0", "Back to home"))
        action = _choose(*choices, shortcuts=("s", "t", "p"))
        if action and action.isdecimal() and 1 <= int(action) <= len(chunk):
            _usage_detail(result, chunk[int(action) - 1])
        elif action == "8" and page > 0:
            page -= 1
        elif action == "9" and page < max_page:
            page += 1
        elif action == "s":
            return _usage_report(custom=True)
        elif action == "t":
            _usage_detail(result)
        elif action == "p":
            _usage_cross_date(result)
        elif action == "r":
            result = usage_ledger.report(start, end, zone_name, port=port)
            days = list(reversed(result.get("daily", [])))
        else:
            return



def menu():
    if not os.isatty(0):
        raise PM2Error("E_VALIDATION", "Interactive Port Manager requires a terminal")
    while True:
        _title("HOME")
        choice = _choose(("1", "See live traffic and control speed"),
                         ("2", "View and forward ports"),
                         ("3", "Change or remove port connections"),
                         ("4", "Daily port traffic (download / upload)"),
                         ("0", "Exit Port Manager"))
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
            elif choice == "4":
                _usage_report()
        except PM2Error as exc:
            print(_paint("91", f"  {exc.code}: {exc.message}"))
            _ask("Enter to continue")
        except (OSError, ValueError) as exc:
            print(_paint("91", f"  Invalid input: {str(exc)[:140]}"))
            _ask("Enter to continue")
