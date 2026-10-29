#!/usr/local/bin/python3
"""Exec wrapper for Marzban Node Xray; applies an additive per-node WARP SOCKS5 overlay.

The original Xray binary remains untouched. All non-run invocations pass through.
Linux memfd keeps the generated configuration off disk and retains the Xray PID/signal semantics.
"""
import json
import os
import sys

XRAY = "/usr/local/bin/xray"
SETTINGS = "/var/lib/marzban-node/warp-gemini.json"
DEFAULT_TAG = "warp-gemini"

def transform(cfg, settings):
    if not settings.get("enabled", True):
        return cfg
    domains = settings.get("domains", [])
    if not domains:
        return cfg
    port = int(settings.get("port", 40000))
    if not 1024 <= port <= 65535:
        raise ValueError("invalid WARP SOCKS5 port")
    if not isinstance(cfg.get("outbounds"), list):
        raise ValueError("Xray config lacks outbounds")
    if any(o.get("tag") in (DEFAULT_TAG, DEFAULT_TAG + "-socks") for o in cfg["outbounds"]):
        raise ValueError("WARP outbound tag collision")
    rules = cfg.setdefault("routing", {}).setdefault("rules", [])
    if not isinstance(rules, list):
        raise ValueError("Xray routing.rules is not a list")
    for entry in domains:
        if not isinstance(entry, str) or not entry.startswith(("domain:", "full:")):
            raise ValueError("invalid domain entry: " + str(entry))
    # A plain SOCKS outbound lets the SOCKS server select IPv6 for a hostname.
    # On Xray 25.3.x, targetStrategy alone does not reliably constrain this.
    # Freedom with ForceIPv4 resolves A records first, then chains to SOCKS5.
    if settings.get("ipv4_only", True):
        cfg["outbounds"].append({
            "tag": DEFAULT_TAG,
            "protocol": "freedom",
            "settings": {"domainStrategy": "ForceIPv4"},
            "proxySettings": {"tag": DEFAULT_TAG + "-socks"}
        })
        cfg["outbounds"].append({
            "tag": DEFAULT_TAG + "-socks",
            "protocol": "socks",
            "settings": {"servers": [{"address": "127.0.0.1", "port": port}]}
        })
    else:
        cfg["outbounds"].append({
            "tag": DEFAULT_TAG,
            "protocol": "socks",
            "settings": {"servers": [{"address": "127.0.0.1", "port": port}]}
        })

    if settings.get("sniff_2053", False):
        for inbound in cfg.get("inbounds", []):
            ports = [p.strip() for p in str(inbound.get("port", "")).split(",")]
            if "2053" in ports and inbound.get("protocol") == "trojan":
                sniff = inbound.get("sniffing") or {}
                sniff["enabled"] = True
                sniff["destOverride"] = ["http", "tls"]
                inbound["sniffing"] = sniff

    rule = {
        "type": "field",
        "domain": domains,
        "outboundTag": DEFAULT_TAG
    }
    # Marzban Node inserts API_INBOUND routing at position zero.
    # Preserve it so its TLS API is never accidentally captured by WARP.
    idx = 1 if rules and "API_INBOUND" in rules[0].get("inboundTag", []) else 0
    if settings.get("google_2053_full_route", False):
        # A/B test: only clients on the Trojan 2053 inbound use a single
        # WARP egress for Google, including Gemini authentication / assets.
        tags = [
            inbound.get("tag") for inbound in cfg.get("inbounds", [])
            if inbound.get("tag") and inbound.get("protocol") == "trojan"
            and "2053" in [p.strip() for p in str(inbound.get("port", "")).split(",")]
        ]
        if not tags:
            raise ValueError("Google 2053 test requested but no Trojan inbound exists on port 2053")
        rules.insert(idx, {
            "type": "field",
            "inboundTag": tags,
            "domain": [
                "domain:google.com",
                "domain:googleapis.com",
                "domain:googleusercontent.com",
                "domain:gstatic.com"
            ],
            "outboundTag": DEFAULT_TAG
        })
        idx += 1
    rules.insert(idx, rule)
    return cfg

def main():
    args = sys.argv[1:]
    if not args or args[0] != "run" or "stdin:" not in args:
        os.execv(XRAY, [XRAY] + args)

    config_raw = sys.stdin.buffer.read()
    try:
        cfg = json.loads(config_raw)
        with open(SETTINGS, encoding="utf-8") as f:
            settings = json.load(f)
        patched = transform(cfg, settings)
        config_raw = json.dumps(patched, ensure_ascii=True, separators=(",", ":")).encode()
    except FileNotFoundError:
        # No settings means pass-through: all traffic stays on original Marzban route.
        pass
    except Exception as exc:
        # Fail closed to original Xray configuration: don't interrupt a production node.
        print("[warp-gemini] overlay skipped: " + repr(exc), file=sys.stderr, flush=True)

    fd = os.memfd_create("xray-warp-config", flags=0)
    os.write(fd, config_raw)
    os.lseek(fd, 0, os.SEEK_SET)
    os.set_inheritable(fd, True)
    new_args = [a if a != "stdin:" else "/proc/self/fd/" + str(fd) for a in args]
    os.execv(XRAY, [XRAY] + new_args + ["-format", "json"])

if __name__ == "__main__":
    main()
