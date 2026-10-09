"""Short, beginner-friendly, V1-inspired terminal UI with safe backend reuse."""
import json
import os
import re
import subprocess
import tempfile
from pathlib import Path

from .errors import PM2Error
from . import config, guard, limit_windows, port_graph, services, shaping, transaction, tunnels


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


def _title(subtitle):
    print("\n" + _paint("96;1", "╔════════════════════════════════════════════════╗"))
    print(_paint("96;1", "║") + _paint("97;1", "       ✦  PORT MANAGER  ✦  " + subtitle[:19].ljust(19))
          + _paint("96;1", "║"))
    print(_paint("96;1", "╚════════════════════════════════════════════════╝"))


def _network_defaults():
    """Use configured default-route dev/src, not an invented interface/IP."""
    from .discovery import run
    out = run(["ip", "-4", "route", "get", "1.1.1.1"], timeout=5).split()
    if "dev" not in out or "src" not in out:
        raise PM2Error("E_DEPENDENCY", "Cannot discover default interface and local IPv4")
    return out[out.index("dev") + 1], out[out.index("src") + 1]


def _mutate(operation, argv):
    from .cli import mutation_lock
    preview = tunnels.handle(operation, [*argv, "--dry-run"], mutation_lock)
    print(_paint("93", "  Review change to V2-owned tunnel configuration"))
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
    argv = ([old["id"]] if old else []) + [
        "--name", name, "--interface", device, "--listen-ip", listen_ip,
        "--target-ip", target, "--protocol", "tcp,udp",
        "--mode", "all-except" if is_all else "ports"
    ]
    if is_all:
        existing = ",".join(str(p) for p in old["exclude"]) if old else "22"
        excludes = _ask("Protected SSH/admin ports (never tunnel)", existing)
        if excludes is None:
            return
        argv += ["--exclude", excludes, "--ack-all-ports"]
        print(_paint("91", "  CAUTION: all-except forwarding can disrupt SSH."))
    else:
        if old and old["mapping"]:
            first = old["mapping"][0]
            d_in, d_out = str(first["listen_port"]), str(first["target_port"])
        else:
            d_in, d_out = None, None
        port_in = _ask("Incoming port", d_in)
        port_out = _ask("Destination port", d_out or port_in)
        if not port_in or not port_out:
            return
        argv += ["--mapping", f"{port_in}:{port_out}"]
    _mutate("update" if old else "create", argv)


def _list_tunnels():
    cfg = config.load(transaction.CONFIG)
    items = cfg["tunnels"]
    for i, t in enumerate(items, 1):
        ports = "ALL except " + ",".join(map(str, t["exclude"])) if t["mode"] == "all-except" else (
            ",".join(f'{p["listen_port"]}→{p["target_port"]}' for p in t["mapping"]))
        print(f"  {i}. {_paint('92' if t['enabled'] else '90', t['name'][:18])}"
              f"  {ports[:25]}  → {t['target_ip']}  {'●' if t['enabled'] else '○'}")
    if not items:
        print("  No tunnels yet.")
    return items


def _delete_all():
    from .cli import mutation_lock
    from . import shaping
    current = config.load(transaction.CONFIG)
    if not current["tunnels"]:
        return
    if any(p["enabled"] for p in shaping.schedule_load()["policies"]):
        raise PM2Error("E_CONFLICT", "Remove active speed-limit policies before deleting tunnels")
    print(_paint("91", "  Remove ALL V2 tunnels only; other firewall chains remain untouched."))
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


def _manage():
    while True:
        _title("CONFIG")
        items = _list_tunnels()
        print("  [1] Edit / Delete a tunnel   [2] Delete ALL   [0] Back")
        choice = _ask("Select", "0")
        if choice in ("0", None):
            return
        if choice == "2":
            _delete_all()
            continue
        if choice != "1" or not items:
            continue
        value = _ask("Tunnel number")
        if not value or not value.isdecimal() or not 1 <= int(value) <= len(items):
            continue
        selected = items[int(value) - 1]
        action = _ask("[1] Edit   [2] Delete   [0] Back", "0")
        if action == "1":
            _tunnel_wizard(selected)
        elif action == "2":
            _mutate("delete", [selected["id"]])


def _tunnel_page():
    while True:
        _title("IPTABLES")
        print("  [1] New port → IP tunnel")
        print("  [2] Tunnel ALL ports (protect SSH)")
        print("  [3] Edit / Delete current tunnels")
        print("  [0] Back")
        choice = _ask("Select", "0")
        if choice in ("0", None):
            return
        if choice == "1":
            _tunnel_wizard()
        elif choice == "2":
            _tunnel_wizard(all_ports=True)
        elif choice == "3":
            _manage()


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
    print(f"\n  Speed limit: {title} on {interface}")
    if mine:
        for p in mine:
            print(f"   {p['id']}: ↓{p['download_mbps']} ↑{p['upload_mbps']} Mb/s "
                  f"{p['start']}-{p['end']}")
    choice = _ask("[1] Set / Edit   [2] Remove limit   [0] Back", "0")
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


def _live():
    _title("LIVE")
    refresh = _ask("Refresh every N seconds", "5")
    if not refresh or not refresh.isdecimal() or not 2 <= int(refresh) <= 60:
        print("  Refresh must be 2..60 seconds.")
        return
    latest = {}
    def capture(frame):
        latest.clear()
        latest.update(frame)
    print(_paint("90", "  Graph starts now. Ctrl+C opens port selection and limits."))
    port_graph.watch(refresh=int(refresh), top=24, active_only=False, on_frame=capture)
    if not latest:
        return
    items = [r for r in latest["rows"] if r["listen_port"]]
    links = latest.get("interfaces", [])
    default_iface = links[0]["interface"] if links else None
    print("\n  Select a visible port number to limit, or ALL for the entire interface.")
    print("  [0] Return without changes")
    selected = _ask("Port / ALL", "0")
    if not selected or selected == "0":
        return
    if selected.upper() == "ALL":
        _limit(0, default_iface)
        return
    if not selected.isdecimal() or not 1 <= int(selected) <= 65535:
        return
    selected_port = int(selected)
    matching = [x for x in items if x["listen_port"] == selected_port]
    if not matching:
        print("  Port not in the displayed list; no change made.")
        return
    # The tracked traffic may be auto-local, V1, or a V2 tunnel. Use the
    # actual configured interface for a V2 tunnel where possible.
    row = matching[0]
    interface = default_iface
    if row["tunnel_id"] not in ("auto", "v1"):
        cfg = config.load(transaction.CONFIG)
        for t in cfg["tunnels"]:
            if t["id"] == row["tunnel_id"]:
                interface = t["interface"]
                break
    proto = row["protocol"] if row["protocol"] in ("tcp", "udp") else "tcp,udp"
    _limit(selected_port, interface, proto)


def menu():
    if not os.isatty(0):
        raise PM2Error("E_VALIDATION", "Interactive Port Manager requires a terminal")
    while True:
        _title("HOME")
        print("  [1] " + _paint("92;1", "LIVE & SPEED LIMITS"))
        print("  [2] " + _paint("96;1", "IPTABLES / TUNNELS"))
        print("  [3] " + _paint("93;1", "EDIT / DELETE CONFIGS"))
        print("  [0] Exit")
        choice = _ask("Select", "0")
        if choice in ("0", None):
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
        except (OSError, ValueError) as exc:
            print(_paint("91", f"  Invalid input: {str(exc)[:140]}"))
