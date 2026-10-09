"""Portable, ANSI-free interactive terminal manager (Ctrl+C -> exit 130).

Every mutation calls the same validated/transactional CLI engine. The TUI
never writes iptables, configuration or V1 resources itself.
"""
import json
import shutil
import sys
from . import sampler
from .errors import PM2Error

MAIN = (
    ("01", "Network Dashboard"),
    ("02", "Tunnel Management"),
    ("03", "Port Mapping"),
    ("04", "Live Traffic Monitor"),
    ("05", "Bandwidth Limits"),
    ("06", "Traffic Reports"),
    ("07", "Firewall & Diagnostics"),
    ("08", "Backup & Restore"),
    ("09", "Settings / About"),
    ("00", "Exit"),
)


def _ask(prompt, default=None):
    suffix = f" [{default}]" if default is not None else ""
    try:
        text = input(f"{prompt}{suffix}: ").strip()
    except EOFError:
        return None
    if text in ("0", "00"):
        return None
    return text if text else default


def _show_tunnels():
    from . import config, transaction
    current = config.load(transaction.CONFIG)
    print(f"\nTunnels: {len(current['tunnels'])} | Generation {current['generation']}")
    for t in current["tunnels"]:
        mappings = ",".join(f"{m['listen_port']}:{m['target_port']}"
                            for m in t["mapping"])
        detail = mappings if t["mode"] == "ports" else f"except {len(t['exclude'])} ports"
        print(f" {t['id']}  {t['name']}  "
              f"{'ON' if t['enabled'] else 'OFF'}  "
              f"{t['listen_ip']}/{t['interface']} -> {t['target_ip']}  "
              f"{','.join(t['protocols'])}  {detail}")
    return current["tunnels"]


def _preview_and_apply(operation, argv):
    from . import guard, tunnels
    from .cli import mutation_lock
    try:
        preview = tunnels.handle(operation, [*argv, "--dry-run"], mutation_lock)
        candidate = preview["candidate"]
        print("\nPREVIEW — no changes applied yet:")
        print(json.dumps(candidate, indent=2, ensure_ascii=False))
        if _ask("Type APPLY to proceed") != "APPLY":
            print("Cancelled without changes.")
            return
        if operation == "delete":
            argv.append("--yes")
        result = tunnels.handle(operation, argv, mutation_lock)
        print(json.dumps(result, indent=2, ensure_ascii=False))
        pending = result.get("pending_confirmation")
        if pending:
            print("\nDANGER: automatic rollback within 120 seconds unless confirmed.")
            print(f"Change ID: {pending}")
            if _ask("Type CONFIRM to keep the new rules") == "CONFIRM":
                with mutation_lock():
                    confirmed = guard.confirm(pending)
                print("Confirmed:", confirmed)
            else:
                print("Not confirmed. Rollback watchdog remains armed.")
    except PM2Error as error:
        print(f"[{error.code}] {error.message}")
        if error.details:
            print(json.dumps(error.details, ensure_ascii=False))


def _wizard(old=None):
    print("\nAdd / replace tunnel; type 0 at a prompt to cancel.")
    required = ("name", "interface", "listen-ip", "mode", "protocol", "target-ip")
    defaults = {}
    if old:
        defaults = {
            "name": old["name"], "interface": old["interface"],
            "listen-ip": old["listen_ip"], "mode": old["mode"],
            "protocol": ",".join(old["protocols"]), "target-ip": old["target_ip"],
            "mapping": ",".join(f"{m['listen_port']}:{m['target_port']}"
                                for m in old["mapping"]),
            "exclude": ",".join(map(str, old["exclude"]))
        }
    values = {}
    for field in required:
        value = _ask(field, defaults.get(field))
        if value is None:
            return
        values[field] = value
    kind = values["mode"]
    if kind not in ("ports", "all-except"):
        print("Only 'ports' or 'all-except' is supported.")
        return
    additional = "mapping" if kind == "ports" else "exclude"
    value = _ask(additional, defaults.get(additional))
    if value is None:
        return
    values[additional] = value
    argv = [old["id"]] if old else []
    for key in required:
        argv.extend(["--" + key, values[key]])
    argv.extend(["--" + additional, values[additional]])
    if kind == "all-except":
        argv.append("--ack-all-ports")
    _preview_and_apply("update" if old else "create", argv)


def _tunnel_page():
    while True:
        print("\nTunnel Management: [1] List [2] Add [3] Edit "
              "[4] Enable [5] Disable [6] Delete [0] Back")
        choice = _ask("Choice")
        if choice is None:
            return
        if choice == "1":
            _show_tunnels()
        elif choice == "2":
            _wizard()
        elif choice in ("3", "4", "5", "6"):
            from . import config, transaction
            tunnel_id = _ask("Exact tunnel UUID")
            if tunnel_id is None:
                continue
            try:
                old = config.get(config.load(transaction.CONFIG)["tunnels"], tunnel_id)
                if choice == "3":
                    _wizard(old)
                else:
                    operation = {"4": "enable", "5": "disable", "6": "delete"}[choice]
                    _preview_and_apply(operation, [tunnel_id])
            except PM2Error as e:
                print(f"[{e.code}] {e.message}")
        else:
            print("Invalid selection")


def _reports():
    for window in ("1h", "24h", "7d"):
        report = sampler.report(window)
        up = report["upload_bytes"]
        down = report["download_bytes"]
        print(f"  {window:>3}: UP {up:,} bytes  DOWN {down:,} bytes"
              f"  coverage {report['coverage_seconds']}s")


def _backup_page():
    from . import backup
    print("\nBackups: [1] List [2] Create [0] Back")
    choice = _ask("Choice")
    if choice is None:
        return
    if choice == "1":
        print(backup.list_backups())
    elif choice == "2":
        if _ask("Type BACKUP") == "BACKUP":
            print(backup.create())


def _live_graph():
    from . import port_graph
    raw = _ask("Refresh seconds (2..60)", "5")
    if raw is None:
        return
    try:
        seconds = int(raw)
        if not 2 <= seconds <= 60:
            print("Refresh must be 2..60 seconds")
            return
        print("10-minute rolling graph: active ports only, Ctrl+C to return.")
        port_graph.watch(refresh=seconds, top=20, active_only=True)
    except ValueError:
        print("Refresh must be a whole number between 2 and 60.")


def _limits_page():
    """Schedule wizard reuses the same CLI-owned validation/rollback backend."""
    from . import shaping, limit_windows, services
    from .cli import mutation_lock
    import tempfile
    from pathlib import Path
    while True:
        print("\nTimed limits: [1] List [2] Add [3] Remove [4] Apply now [0] Back")
        choice = _ask("Choice")
        if choice is None:
            return
        try:
            plan = shaping.schedule_load()
            if choice == "1":
                for item in plan["policies"]:
                    print(f" {item['id']}: :{item['port']} {item['protocol']} "
                          f"{item['start']}-{item['end']} {item['timezone']} "
                          f"weekdays {item['days']} upload {item['upload_mbps']} "
                          f"download {item['download_mbps']} Mbit/s")
                continue
            if choice == "4":
                with mutation_lock():
                    print(shaping.reconcile())
                continue
            if choice == "2":
                fields = {
                    "id": _ask("Policy ID (ASCII)"),
                    "port": _ask("Listen port 1..65535"),
                    "protocol": _ask("Protocol tcp/udp/tcp,udp", "tcp,udp"),
                    "timezone": _ask("IANA timezone", "Asia/Tehran"),
                    "days": _ask("Weekdays 0=Mon .. 6=Sun (comma separated)", "0,1,2,3,4,5,6"),
                    "start": _ask("Start HH:MM", "18:00"),
                    "end": _ask("End HH:MM (next day if earlier)", "02:00"),
                    "upload_mbps": _ask("Upload Mbit/s (0 = unlimited)", "10"),
                    "download_mbps": _ask("Download Mbit/s (0 = unlimited)", "20"),
                }
                if any(x is None for x in fields.values()):
                    continue
                new = {"id": fields["id"], "port": int(fields["port"]),
                       "protocol": fields["protocol"], "timezone": fields["timezone"],
                       "days": sorted(set(int(d.strip()) for d in fields["days"].split(","))),
                       "start": fields["start"], "end": fields["end"],
                       "upload_mbps": int(fields["upload_mbps"]),
                       "download_mbps": int(fields["download_mbps"]),
                       "enabled": True}
                plan["policies"].append(new)
            elif choice == "3":
                ident = _ask("Exact policy ID")
                if ident is None:
                    continue
                old_count = len(plan["policies"])
                plan["policies"] = [p for p in plan["policies"] if p["id"] != ident]
                if len(plan["policies"]) == old_count:
                    print("No matching policy.")
                    continue
            else:
                print("Unknown selection")
                continue
            limit_windows.validate(plan["policies"])
            print("\nProposed schedule:\n", json.dumps(plan, indent=2))
            if _ask("Type APPLY to save") != "APPLY":
                continue
            # Reuse installer validation rather than editing the file outside
            # the privileged transaction lock.
            with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8",
                                             prefix=".pm2-sched-", suffix=".json",
                                             dir=shaping.SCHEDULE.parent,
                                             delete=False) as tmp:
                filename = Path(tmp.name)
                json.dump(plan, tmp)
            try:
                with mutation_lock():
                    result = shaping.install_schedule(filename)
                    result.update(shaping.reconcile())
                    if plan["policies"]:
                        services.activate()
                print(result)
            finally:
                filename.unlink(missing_ok=True)
        except (PM2Error, ValueError, OSError) as error:
            print(f"Schedule rejected: {error}")


def _doctor():
    from . import cli
    print(json.dumps(cli.doctor(), indent=2, ensure_ascii=False))


def menu():
    """Only three user-facing choices. Keep validated CLI backend intact."""
    from .simple_ui import menu as friendly_menu
    return friendly_menu()
