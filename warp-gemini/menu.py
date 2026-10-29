#!/usr/bin/env python3
"""Gemini WARP menu for Debian/Ubuntu nodes, including optional Marzban Node overlay."""
import datetime
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path("/opt/warp-gemini")
CONFIG = Path("/var/lib/master/warp-gemini.json")
COMPOSE = Path("/opt/master/docker-compose.yml")
OVERRIDE = Path("/opt/master/docker-compose.override.yml")
WRAPPER = HERE / "xray-wrapper.py"
RAW_WRAPPER = "https://github.com/smorad3363/assistant-vps/raw/refs/heads/master/warp-gemini/xray-wrapper.py"
DEFAULTS = [
    "domain:gemini.google.com",
    "domain:aistudio.google.com",
    "domain:generativelanguage.googleapis.com",
    "domain:aisandbox-pa.googleapis.com",
    "domain:alkalimakersuite-pa.clients6.google.com",
]
TRACE = "https://www.cloudflare.com/cdn-cgi/trace"

def run(args, timeout=25, capture=False, check=False):
    p = subprocess.run(args, text=True, stdout=subprocess.PIPE if capture else None,
                       stderr=subprocess.STDOUT if capture else None, timeout=timeout, check=check)
    return p.stdout or "" if capture else p.returncode

def init():
    if CONFIG.is_file():
        data = json.loads(CONFIG.read_text())
        if isinstance(data.get("domains"), list) and isinstance(data.get("port"), int):
            return data
        raise RuntimeError("Invalid config file; refusing overwrite: " + str(CONFIG))
    data = {"enabled": True, "port": 40000, "ipv4_only": True, "sniff_2053": False, "domains": DEFAULTS}
    save(data, initial=True)
    return data

def save(data, initial=False):
    CONFIG.parent.mkdir(parents=True, exist_ok=True)
    if CONFIG.exists() and not initial:
        backup = CONFIG.with_suffix(".json.bak")
        shutil.copy2(CONFIG, backup)
    tmp = CONFIG.with_name(CONFIG.name + ".tmp")
    tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n")
    os.chmod(tmp, 0o600)
    os.replace(tmp, CONFIG)

def domain(value):
    v = value.strip().lower()
    if not v:
        raise ValueError("Empty domain")
    if not v.startswith(("domain:", "full:")):
        v = "domain:" + v
    name = v.split(":", 1)[1]
    if len(name) > 253 or not re.fullmatch(r"[a-z0-9-]+(?:\.[a-z0-9-]+)+", name):
        raise ValueError("Invalid domain: " + v)
    if any(len(label) > 63 or label.startswith("-") or label.endswith("-") for label in name.split(".")):
        raise ValueError("Invalid hostname label")
    return v

def trace(proxy=False, ipv4=False):
    args = ["curl", "-fsS", "--connect-timeout", "5", "--max-time", "15"]
    if proxy:
        if ipv4:
            args += ["-4", "--socks5", "127.0.0.1:40000"]
        else:
            args += ["--socks5-hostname", "127.0.0.1:40000"]
    else:
        args.append("-4")
    args += [TRACE]
    r = run(args, timeout=19, capture=True)
    return {k: v for k, v in (line.split("=", 1) for line in r.splitlines() if "=" in line) if k in ("ip", "loc", "warp", "colo")}

def status():
    print("\n== WARP ==")
    print(run(["warp-cli", "--accept-tos", "status"], capture=True).strip())
    for label, use_proxy, ipv4 in [("DIRECT IPv4", False, True), ("WARP default", True, False), ("WARP IPv4", True, True)]:
        try:
            values = trace(use_proxy, ipv4)
            print(f"{label}: IP={values.get('ip','?')} Location={values.get('loc','?')} Colo={values.get('colo','?')} warp={values.get('warp','?')}")
        except Exception as e:
            print(f"{label}: FAILED ({e})")
    print("\n== Marzban Node overlay ==")
    print("Wrapper:", "installed" if WRAPPER.is_file() else "missing")
    print("Compose override:", "present" if OVERRIDE.is_file() else "not installed")
    print("Routing enabled:", init()["enabled"])
    print("Saved domains:", len(init()["domains"]))
    print("Selected Gemini backend port:", init()["port"])
    if Path("/opt/warp-gemini/wgcf-isolated/wireproxy.conf").is_file():
        wgcf_status()
    print("IPv4-only Gemini routing:", init().get("ipv4_only", True))
    print("Sniffing on Trojan 2053:", init().get("sniff_2053", False))
    print("Google/Gemini 2053 test enabled:", init().get("google_2053_full_route", False))
    if COMPOSE.exists():
        print("Node:", run(["docker", "ps", "--filter", "name=^/master$", "--format", "{{.Status}}"], capture=True).strip() or "not running")
    live()
    print("Host default route:")
    print(run(["ip", "-4", "route", "get", "1.1.1.1"], capture=True).splitlines()[0])


def live():
    """Read the actual Xray memfd configuration without exposing users/keys."""
    settings = init()
    found = False
    for folder in Path("/proc").iterdir():
        if not folder.name.isdigit():
            continue
        try:
            if (folder / "comm").read_text().strip() != "xray":
                continue
            for fd in (folder / "fd").iterdir():
                if "memfd:xray-warp-config" not in os.readlink(fd):
                    continue
                with open(fd, encoding="utf-8") as stream:
                    cfg = json.load(stream)
                found = True
                outbound = next((x for x in cfg.get("outbounds", []) if x.get("tag") == "warp-gemini"), None)
                rule = next((x for x in cfg.get("routing", {}).get("rules", [])
                             if x.get("outboundTag") == "warp-gemini" and not x.get("inboundTag")), None)
                active = list(rule.get("domain", [])) if rule else []
                print("\n== LIVE XRAY ROUTING ==")
                print("Xray PID:", folder.name)
                print("WARP outbound:", "active" if outbound else "disabled")
                sock = next((x for x in cfg.get("outbounds", []) if x.get("tag") == "warp-gemini-socks" or (x.get("tag") == "warp-gemini" and x.get("protocol") == "socks")), None)
                servers = sock.get("settings", {}).get("servers", []) if sock else []
                live_port = servers[0].get("port") if servers else None
                print("Live WARP SOCKS5 port:", live_port)
                print("Saved backend matches live:", settings.get("port", 40000) == live_port)

                print("Live IPv4-only via Freedom:", bool(outbound and outbound.get("protocol") == "freedom" and outbound.get("settings", {}).get("domainStrategy") == "ForceIPv4"))
                inbound2053 = next((x for x in cfg.get("inbounds", []) if "2053" in str(x.get("port","")).split(",")), None)
                print("Live Sniffing 2053:", bool(inbound2053 and inbound2053.get("sniffing", {}).get("enabled")))
                if outbound and settings.get("ipv4_only", True) != (outbound.get("protocol") == "freedom"):
                    print("NOTE: Saved IPv4 preference not yet applied. Use option 9.")
                test_rule = next((x for x in cfg.get("routing", {}).get("rules", [])
                    if x.get("outboundTag") == "warp-gemini" and x.get("inboundTag") and
                    "domain:google.com" in x.get("domain", [])), None)
                print("Live Google full-route scoped test:", "2053 only" if test_rule else "off")
                if settings.get("google_2053_full_route", False) != bool(test_rule):
                    print("NOTE: Saved 2053 test differs from live. Apply via option 9.")
                print("Current live domain rules:")
                for x in active:
                    print("  -", x)
                saved = list(settings["domains"]) if settings.get("enabled", True) else []
                print("Saved config matches live:", saved == active)
                if saved != active:
                    print("NOTE: Edits are saved but not yet applied. Use option 9.")
                return
        except (PermissionError, FileNotFoundError, OSError, ValueError, json.JSONDecodeError):
            continue
    if not found:
        print("No live managed Xray configuration found. Node may be disconnected or overlay inactive.")

def show():
    d = init()
    print(f"\nEnabled: {d['enabled']} | SOCKS port: {d['port']} | domains: {len(d['domains'])}")
    print("IPv4-only WARP destinations:", d.get("ipv4_only", True))
    print("Sniffing on Trojan 2053:", d.get("sniff_2053", False))
    print("Google/Gemini single egress on 2053:", d.get("google_2053_full_route", False))
    print("Applied only after node recreation/restart; edits on disk do NOT change running Xray.")
    for i, item in enumerate(d["domains"], 1):
        print(f" {i:2}. {item}")

def add():
    d = init()
    print("Enter one or more hostnames separated by commas (default suffix match).")
    print("Use full:example.com for exact host matching.")
    vals = input("Domains: ").replace("\n", ",").split(",")
    for value in vals:
        if value.strip():
            try:
                v = domain(value)
                if v not in d["domains"]:
                    d["domains"].append(v)
                    print("+", v)
                else:
                    print("Already present:", v)
            except ValueError as exc:
                print("SKIPPED:", exc)
    save(d)
    print("Saved. Use 'Apply routing' to activate changes.")

def remove():
    d = init()
    show()
    raw = input("Enter numbers (e.g. 2,3) or one exact entry: ").strip()
    if not raw:
        return
    if re.fullmatch(r"[0-9, ]+", raw):
        indexes = {int(x) for x in raw.replace(" ", ",").split(",") if x}
        if any(i < 1 or i > len(d["domains"]) for i in indexes):
            print("Invalid index; no changes.")
            return
        d["domains"] = [v for i, v in enumerate(d["domains"], 1) if i not in indexes]
    else:
        v = domain(raw)
        if v not in d["domains"]:
            print("Not found.")
            return
        d["domains"].remove(v)
    save(d)
    print("Saved. Apply routing to activate changes.")

def enabled():
    d = init()
    d["enabled"] = not d["enabled"]
    save(d)
    print("Overlay routing enabled:", d["enabled"])
    print("Apply routing to activate.")

def toggle_google_2053():
    d = init()
    d["google_2053_full_route"] = not d.get("google_2053_full_route", False)
    save(d)
    print("2053 test: route Google auth + Gemini via one WARP egress:", d["google_2053_full_route"])
    print("Port 2096 and all other inbounds are unchanged.")
    print("Saved. Use option 9 to apply (recreates Marzban Node).")

def toggle_ipv4():
    d = init()
    d["ipv4_only"] = not d.get("ipv4_only", True)
    save(d)
    print("IPv4-only destinations:", d["ipv4_only"])
    print("Saved. Apply routing (option 9) to activate.")

def toggle_sniff_2053():
    d = init()
    d["sniff_2053"] = not d.get("sniff_2053", False)
    save(d)
    print("Trojan 2053 Sniffing:", d["sniff_2053"])
    print("Saved. Apply routing (option 9) to activate.")

def rotate():
    print("\nWARP IP is assigned by Cloudflare. Reconnect cannot guarantee a new IP/country.")
    try:
        before = trace(True, ipv4=True)
        print("IPv4 Before:", before)
    except Exception as e:
        print("Before: unavailable:", e)
    ans = input("Disconnect and reconnect only WARP? (yes/no): ").strip().lower()
    if ans != "yes":
        return
    run(["warp-cli", "--accept-tos", "disconnect"], timeout=20)
    run(["warp-cli", "--accept-tos", "connect"], timeout=20)
    for i in range(15):
        try:
            after = trace(True, ipv4=True)
            if after.get("warp") in ("on", "plus"):
                print("IPv4 After:", after)
                return
        except Exception:
            pass
        __import__("time").sleep(2)
    print("No healthy WARP response yet. Check service with warp-cli status.")

def tests():
    for name, url in [
        ("Gemini", "https://gemini.google.com/app"),
        ("AI Studio", "https://aistudio.google.com/"),
        ("Gemini API reachability (404 may be normal)", "https://generativelanguage.googleapis.com/"),
    ]:
        print("\n", name, url)
        for label in ("DIRECT IPv4", "WARP default", "WARP IPv4"):
            cmd = ["curl", "-sSL", "-o", "/dev/null", "-w", "%{http_code} / %{time_total}s",
                   "--connect-timeout", "5", "--max-time", "18"]
            if label == "WARP default":
                cmd += ["--socks5-hostname", "127.0.0.1:40000"]
            elif label == "WARP IPv4":
                cmd += ["-4", "--socks5", "127.0.0.1:40000"]
            else:
                cmd += ["-4"]
            try:
                print(label + ":", run(cmd + [url], timeout=22, capture=True).strip())
            except Exception as exc:
                print(label, "ERROR:", exc)
    print("\nHTTP success does not prove authenticated Gemini chats will work.")

def install_integration():
    if not COMPOSE.is_file():
        print("No known Marzban Node Compose file at", COMPOSE)
        return False
    if OVERRIDE.exists():
        if WRAPPER.is_file() and "warp-xray" in OVERRIDE.read_text():
            print("WARP overlay Compose file already installed.")
            return True
        print("An unrelated Compose override exists. Refusing to overwrite:", OVERRIDE)
        return False
    HERE.mkdir(parents=True, exist_ok=True)
    raw = HERE / "xray-wrapper.py"
    if not raw.exists():
        try:
            run(["curl", "-fsSL", "--max-time", "30", RAW_WRAPPER, "-o", str(raw)], timeout=35, check=True)
        except Exception as e:
            print("Wrapper download error:", e)
            return False
        os.chmod(raw, 0o755)
    if not init()["domains"]:
        print("No domains. Add at least one first.")
        return False
    cfg = """services:
  marzban-node:
    environment:
      XRAY_EXECUTABLE_PATH: /usr/local/bin/warp-xray
    volumes:
      - /opt/warp-gemini/xray-wrapper.py:/usr/local/bin/warp-xray:ro
"""
    OVERRIDE.write_text(cfg)
    try:
        run(["docker", "compose", "-f", str(COMPOSE), "-f", str(OVERRIDE), "config", "--quiet"], timeout=15, check=True)
    except Exception:
        OVERRIDE.unlink(missing_ok=True)
        print("Compose validation failed. No changes applied.")
        return False
    print("Overlay configured in", OVERRIDE)
    print("No running services changed; select Apply routing to activate.")
    return True

def apply():
    if not install_integration():
        return
    d = init()
    print("WARNING: This operation will briefly disconnect ALL clients on this Marzban Node.")
    print("Marzban should reconnect and repopulate inbounds/users from the master.")
    print("Routing:", "WARP" if d["enabled"] else "DIRECT", "| domains:", len(d["domains"]))
    ans = input("Type APPLY to recreate marzban-node now: ").strip()
    if ans != "APPLY":
        print("Cancelled; saved configuration remains on disk.")
        return
    run(["docker", "compose", "-f", str(COMPOSE), "-f", str(OVERRIDE),
         "up", "-d", "--no-deps", "--force-recreate", "marzban-node"], timeout=100, check=True)
    print("Container recreation submitted. Marzban master must reconnect the node.")
    print("Check node status and test a VPN client after reconnecting.")

def wgcf_status():
    print("\n== Isolated WGCF WireProxy ==")
    print("Service:", run(["systemctl", "is-active", "warp-gemini-wgcf-proxy.service"], capture=True).strip())
    try:
        raw = run(["curl", "-4fsS", "--socks5", "127.0.0.1:40001", "--connect-timeout", "5", "--max-time", "15",
                   TRACE], timeout=19, capture=True)
        values = {k: v for k, v in (line.split("=", 1) for line in raw.splitlines() if "=" in line)
                  if k in ("ip", "loc", "warp", "colo")}
        print("WireGuard SOCKS5:", values)
        print("Healthy:", values.get("warp") in ("on", "plus") and ":" not in values.get("ip", ""))
    except Exception as exc:
        print("WireGuard SOCKS5 unavailable:", exc)
    print("Selected Gemini backend:", init()["port"])

def wgcf_install():
    installer = "/usr/local/bin/wgcf-wireproxy-install"
    if not Path(installer).is_file():
        print("Installer is missing. Re-run the permanent install command.")
        return
    print("Installs separate WGCF + WireProxy on 127.0.0.1:40001.")
    print("Does NOT change the host default route, Docker, Xray or Marzban.")
    choice = input("Type INSTALL to continue: ").strip()
    if choice != "INSTALL":
        return
    subprocess.run([installer, "install"], check=False)

def backend_switch():
    d = init()
    print("Current Gemini SOCKS5 backend:", d["port"])
    print("1) Official Cloudflare WARP MASQUE (port 40000)")
    print("2) Isolated WGCF WireProxy (port 40001)")
    choice = input("Choose 1/2: ").strip()
    if choice not in ("1", "2"):
        print("Cancelled.")
        return
    port = 40000 if choice == "1" else 40001
    try:
        output = run(["curl", "-4fsS", "--socks5", f"127.0.0.1:{port}",
                      "--connect-timeout", "5", "--max-time", "15", TRACE],
                     timeout=19, capture=True)
        if "warp=on" not in output and "warp=plus" not in output:
            print("Backend is not healthy. No changes saved.")
            return
    except Exception as exc:
        print("Backend unreachable; no changes saved.", exc)
        return
    if d["port"] == port:
        print("Already selected. Check live routing using option 11.")
        return
    d["port"] = port
    save(d)
    print("Backend preference saved:", port)
    print("IMPORTANT: Use option 9 to apply (temporarily disconnects node clients).")

def health_check():
    p = "/usr/local/bin/warp-health"
    if not Path(p).is_file():
        print("Health monitor not installed. Re-run the permanent installer.")
        return
    subprocess.run([p, "check"], check=False)

def health_report():
    p = "/usr/local/bin/warp-health"
    if not Path(p).is_file():
        print("Health monitor not installed. Re-run the permanent installer.")
        return
    subprocess.run([p, "report"], check=False)
    print("\nHealth timer:", run(["systemctl", "is-active", "warp-gemini-health.timer"], capture=True).strip())
    print("Read-only monitoring: does not rotate WARP IP or change Xray.")

def diagnose():
    print("== Memory ==")
    run(["free", "-h"])
    print("== Xray ==")
    run(["ps", "-C", "xray", "-o", "pid,stat,etime,%cpu,rss,nlwp"])
    print("== Sockets ==")
    run(["ss", "-s"])
    print("== Recent OOM ==")
    run(["journalctl", "-k", "--since", "1 day ago", "--no-pager", "-g", "Killed process"])
    print("== WARP ==")
    status()

def main():
    if os.geteuid() != 0:
        sys.exit("Run sudo warp-menu")
    if len(sys.argv) > 1:
        actions = {"status": status, "domains": show, "test": tests, "diagnose": diagnose, "integrate": install_integration, "live": live, "wgcf-status": wgcf_status, "health": health_check, "health-report": health_report}
        action = actions.get(sys.argv[1])
        if action:
            action()
            return
        sys.exit("Available: status, domains, test, diagnose, integrate")
    init()
    while True:
        print("""
======== GEMINI WARP MANAGER ========
 1) Show routed domains / current settings
 2) Add domain(s)
 3) Remove domain(s)
 4) Enable/disable WARP routing in Xray
 5) Show direct IP, WARP IP and health
 6) Reconnect WARP / attempt new exit IP
 7) Test Gemini and AI Studio over both routes
 8) Install per-node Xray integration (no restart)
 9) Apply routing changes (brief node interruption)
10) Diagnostics
11) Verify live Xray routing and domain rules
12) Toggle IPv4-only destinations through WARP
13) Toggle domain Sniffing for Trojan 2053
14) Install/check isolated WGCF WireProxy
15) Choose Gemini WARP backend (40000 or 40001)
16) Show isolated WireGuard proxy status/IP
17) Toggle single-egress Google/Gemini test for port 2053 only
18) Run WARP and Gemini health check now
19) Show last health report and monitor timer
 0) Exit
=====================================""")
        choice = input("Choose: ").strip()
        try:
            actions = {
                "1": show, "2": add, "3": remove, "4": enabled,
                "5": status, "6": rotate, "7": tests, "8": install_integration,
                "9": apply, "10": diagnose, "11": live,
                "12": toggle_ipv4, "13": toggle_sniff_2053,
                "14": wgcf_install, "15": backend_switch, "16": wgcf_status,
                "17": toggle_google_2053,
                "18": health_check, "19": health_report,
            }
            if choice == "0":
                return
            fn = actions.get(choice)
            fn() if fn else print("Invalid choice.")
        except KeyboardInterrupt:
            print("\nCancelled.")
        except Exception as exc:
            print("ERROR:", exc)

if __name__ == "__main__":
    main()
