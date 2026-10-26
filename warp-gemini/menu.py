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
RAW_WRAPPER = "https://raw.githubusercontent.com/smorad3363/assistant-vps/master/warp-gemini/xray-wrapper.py"
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
    data = {"enabled": True, "port": 40000, "domains": DEFAULTS}
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

def trace(proxy=False):
    args = ["curl", "-fsS", "--connect-timeout", "5", "--max-time", "15"]
    if proxy:
        args += ["--socks5-hostname", "127.0.0.1:40000"]
    if not proxy:
        args.append("-4")
    args += [TRACE]
    r = run(args, timeout=19, capture=True)
    return {k: v for k, v in (line.split("=", 1) for line in r.splitlines() if "=" in line) if k in ("ip", "loc", "warp", "colo")}

def status():
    print("\n== WARP ==")
    print(run(["warp-cli", "--accept-tos", "status"], capture=True).strip())
    for label, use_proxy in [("DIRECT", False), ("WARP SOCKS5", True)]:
        try:
            values = trace(use_proxy)
            print(f"{label}: IP={values.get('ip','?')} Location={values.get('loc','?')} Colo={values.get('colo','?')} warp={values.get('warp','?')}")
        except Exception as e:
            print(f"{label}: FAILED ({e})")
    print("\n== Marzban Node overlay ==")
    print("Wrapper:", "installed" if WRAPPER.is_file() else "missing")
    print("Compose override:", "present" if OVERRIDE.is_file() else "not installed")
    print("Routing enabled:", init()["enabled"])
    print("Saved domains:", len(init()["domains"]))
    if COMPOSE.exists():
        print("Node:", run(["docker", "ps", "--filter", "name=^/master$", "--format", "{{.Status}}"], capture=True).strip() or "not running")
    print("Host default route:")
    print(run(["ip", "-4", "route", "get", "1.1.1.1"], capture=True).splitlines()[0])

def show():
    d = init()
    print(f"\nEnabled: {d['enabled']} | SOCKS port: {d['port']} | domains: {len(d['domains'])}")
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

def rotate():
    print("\nWARP IP is assigned by Cloudflare. Reconnect cannot guarantee a new IP/country.")
    try:
        before = trace(True)
        print("Before:", before)
    except Exception as e:
        print("Before: unavailable:", e)
    ans = input("Disconnect and reconnect only WARP? (yes/no): ").strip().lower()
    if ans != "yes":
        return
    run(["warp-cli", "--accept-tos", "disconnect"], timeout=20)
    run(["warp-cli", "--accept-tos", "connect"], timeout=20)
    for i in range(15):
        try:
            after = trace(True)
            if after.get("warp") in ("on", "plus"):
                print("After:", after)
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
        for proxy in (False, True):
            cmd = ["curl", "-sSL", "-o", "/dev/null", "-w", "%{http_code} / %{time_total}s",
                   "--connect-timeout", "5", "--max-time", "18"]
            if proxy:
                cmd += ["--socks5-hostname", "127.0.0.1:40000"]
            try:
                print("WARP:  " if proxy else "DIRECT:", run(cmd + [url], timeout=22, capture=True).strip())
            except Exception as exc:
                print("ERROR:", exc)
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
        actions = {"status": status, "domains": show, "test": tests, "diagnose": diagnose, "integrate": install_integration}
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
 0) Exit
=====================================""")
        choice = input("Choose: ").strip()
        try:
            actions = {
                "1": show, "2": add, "3": remove, "4": enabled,
                "5": status, "6": rotate, "7": tests, "8": install_integration,
                "9": apply, "10": diagnose,
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
