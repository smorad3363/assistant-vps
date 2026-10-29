#!/usr/bin/env python3
"""Read-only health monitor of the two local WARP SOCKS5 egresses.

Network success is NOT proof of authenticated Gemini chat eligibility.
No WARP reconnects, IP rotations, Docker restarts, nftables or Xray changes.
"""
import datetime
import ipaddress
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path("/var/lib/warp-gemini")
STATE = ROOT / "health.json"
HISTORY = ROOT / "history.jsonl"
CONFIG = Path("/var/lib/master/warp-gemini.json")
TRACE = "https://www.cloudflare.com/cdn-cgi/trace"
GEMINI = "https://gemini.google.com/app"
PORTS = (40000, 40001)

def cmd(args, timeout=22):
    try:
        p = subprocess.run(args, capture_output=True, text=True,
                           errors="replace", timeout=timeout, check=False)
        return p.returncode, p.stdout, p.stderr[:200]
    except (OSError, subprocess.TimeoutExpired) as e:
        return 255, "", str(e)[:200]

def trace(port=None):
    args = ["curl", "-4fsS", "--connect-timeout", "5", "--max-time", "12"]
    if port is not None:
        args += ["--socks5", f"127.0.0.1:{port}"]
    rc, output, err = cmd(args + [TRACE], 17)
    attrs = {}
    for line in output.splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            if k in ("ip", "loc", "warp", "colo"):
                attrs[k] = v.strip()
    ip = attrs.get("ip", "")
    try:
        attrs["ip_version"] = ipaddress.ip_address(ip).version
    except ValueError:
        attrs["ip_version"] = None
    attrs["proxy_healthy"] = bool(rc == 0 and attrs.get("warp") in ("on", "plus") and attrs["ip_version"] == 4) if port is not None else rc == 0
    if rc != 0:
        attrs["error"] = err or f"curl exit {rc}"
    return attrs

def gemini_probe(port):
    # Download at most 256 KiB so unexpected large responses cannot grow memory.
    with tempfile.TemporaryDirectory(prefix="wg-health-") as td:
        body = Path(td) / "body"
        args = ["curl", "-4sSL", "--connect-timeout", "5", "--max-time", "15",
                "--max-filesize", "262144", "-o", str(body), "-w",
                "%{http_code}|%{url_effective}", "--socks5", f"127.0.0.1:{port}", GEMINI]
        rc, out, err = cmd(args, 19)
        fields = out.strip().split("|", 1)
        code = int(fields[0]) if fields and fields[0].isdigit() else 0
        url = fields[1] if len(fields) == 2 else ""
        page = (body.read_bytes()[:262144].decode("utf-8", "replace").lower() if body.exists() else "")
        patterns = [
            "our systems have detected unusual traffic",
            "gemini isn't available in this country",
            "gemini isn't currently supported",
            "gemini is not available in your country",
            "not supported in your country"
        ]
        detected = next((p for p in patterns if p in page), None)
        blocked = (code in (403, 429) or "/sorry/" in url.lower() or detected is not None)
        return {"http_code": code, "transport_ok": rc == 0,
                "block_signal": bool(blocked),
                "signal": detected or (f"HTTP {code}" if code in (403, 429) else "google-sorry" if "/sorry/" in url.lower() else None),
                "error": err if rc not in (0, 63) else None,
                "account_chat_tested": False}

def read_config():
    try:
        c = json.loads(CONFIG.read_text())
        p = int(c.get("port", 40000))
        return p if p in PORTS else 40000
    except (ValueError, OSError):
        return 40000

def snapshot():
    now = datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")
    selected = read_config()
    direct = trace()
    backends = {str(p): trace(p) for p in PORTS}
    p = backends[str(selected)]
    google = gemini_probe(selected) if p.get("proxy_healthy") else {
        "http_code": 0, "transport_ok": False,
        "block_signal": None, "signal": "selected WARP proxy unavailable",
        "account_chat_tested": False}
    ip0 = backends["40000"].get("ip")
    ip1 = backends["40001"].get("ip")
    return {"time_utc": now, "selected_port": selected,
            "direct": direct, "proxies": backends,
            "same_exit_ipv4": bool(ip0 and ip1 and ip0 == ip1),
            "gemini_public_page": google,
            "interpretation": "Network-level preflight only; authenticated Gemini chat cannot be verified without the user's session."}

def save(current):
    ROOT.mkdir(parents=True, exist_ok=True)
    os.chmod(ROOT, 0o700)
    prior = {}
    if STATE.is_file():
        try:
            prior = json.loads(STATE.read_text())
        except (ValueError, OSError):
            pass
    temp = STATE.with_suffix(".tmp")
    temp.write_text(json.dumps(current, ensure_ascii=True, indent=2) + "\n")
    os.chmod(temp, 0o600)
    os.replace(temp, STATE)
    def signature(x):
        p = x.get("proxies", {})
        return (x.get("selected_port"),
                tuple((k, p.get(k, {}).get("ip"), p.get(k, {}).get("proxy_healthy")) for k in ("40000", "40001")),
                x.get("gemini_public_page", {}).get("http_code"),
                x.get("gemini_public_page", {}).get("block_signal"))
    if not HISTORY.exists() or signature(current) != signature(prior):
        if HISTORY.is_file() and HISTORY.stat().st_size > 1000000:
            HISTORY.rename(ROOT / "history.previous.jsonl")
        with HISTORY.open("a") as f:
            f.write(json.dumps(current, separators=(",", ":")) + "\n")
        os.chmod(HISTORY, 0o600)

def display(x):
    print("Checked UTC:", x.get("time_utc", "unknown"))
    print("Selected Xray backend:", x.get("selected_port", "?"))
    print("Direct IPv4:", x.get("direct", {}).get("ip", "?"))
    for p in PORTS:
        data = x.get("proxies", {}).get(str(p), {})
        print(f"WARP SOCKS5 {p}: IP={data.get('ip','?')}, country={data.get('loc','?')}, warp={data.get('warp','?')}, network_healthy={data.get('proxy_healthy',False)}")
    print("Same WARP IPv4 exit:", x.get("same_exit_ipv4", "?"))
    gp = x.get("gemini_public_page", {})
    print("Gemini unauthenticated HTTP:", gp.get("http_code", "?"),
          "blocked_signal:", gp.get("block_signal"),
          "reason:", gp.get("signal") or "-")
    print("Authenticated Gemini chat: NOT TESTED by this monitor")
    print("Auto IP rotation and backend changes: DISABLED (read-only monitoring)")
    print("History:", HISTORY)

def main():
    if os.geteuid() != 0:
        raise SystemExit("Run as root.")
    action = sys.argv[1] if len(sys.argv) > 1 else "report"
    if action == "check":
        x = snapshot()
        save(x)
        display(x)
    elif action == "report":
        if not STATE.is_file():
            print("No saved report. Run: sudo warp-health check")
            raise SystemExit(1)
        display(json.loads(STATE.read_text()))
    else:
        raise SystemExit("Usage: warp-health [check|report]")

if __name__ == "__main__":
    main()
