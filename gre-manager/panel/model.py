"""Validated, versioned configuration shared by the UI and privileged helpers."""
import copy
import ipaddress
import re
import socket
import uuid


class PanelError(ValueError):
    def __init__(self, message, code="invalid", field=None):
        super().__init__(message)
        self.code, self.field = code, field


DEFAULTS = {
    "port": 8787, "bind": "0.0.0.0", "tls": True,
    "ssh_ports": [22], "reserved_ports": [], "mtu": 1400,
    "retention_days": 30, "backup_keep": 7, "watchdog": True,
    "timezone": "Asia/Tehran", "hostname": "", "username": "admin",
}


def integer(value, low, high, field):
    try:
        if isinstance(value, bool) or int(value) != float(value):
            raise ValueError()
        n = int(value)
    except (ValueError, TypeError, OverflowError):
        raise PanelError("Enter a whole number.", field=field)
    if not low <= n <= high:
        raise PanelError(f"Value must be between {low} and {high}.", field=field)
    return n


def address(value):
    try:
        ip = ipaddress.IPv4Address(str(value))
    except ipaddress.AddressValueError:
        raise PanelError("Enter an IPv4 address.", field="listen_ip")
    if ip.is_unspecified or ip.is_multicast or ip.is_loopback or str(ip) == "255.255.255.255":
        raise PanelError("Use a unicast server address.")
    return str(ip)


def hostname(value):
    value = str(value).strip().rstrip(".")
    try:
        return address(value)
    except PanelError:
        pass
    try:
        value = value.encode("idna").decode("ascii").lower()
    except UnicodeError:
        raise PanelError("Invalid hostname.", field="target_host")
    if len(value) > 253 or not re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?", value):
        raise PanelError("Use an IP or a hostname without a scheme or port.", field="target_host")
    if value.replace(".", "").isdigit() or any(not x or len(x) > 63 or x[0] == "-" or x[-1] == "-" for x in value.split(".")):
        raise PanelError("Invalid hostname.", field="target_host")
    return value


def resolve(value):
    value = hostname(value)
    try:
        return address(value)
    except PanelError:
        pass
    try:
        ips = sorted({address(x[4][0]) for x in socket.getaddrinfo(value, None, socket.AF_INET, socket.SOCK_STREAM)})
    except (OSError, PanelError):
        raise PanelError("The destination hostname could not be resolved.", "dns", "target_host")
    if not ips:
        raise PanelError("No IPv4 destination was found.", "dns")
    return ips[0]


def port_list(value):
    if isinstance(value, str):
        value = [x.strip() for x in value.split(",") if x.strip()]
    if not isinstance(value, list) or len(value) > 128:
        raise PanelError("Invalid port list.")
    return sorted({integer(x, 1, 65535, "ports") for x in value})


def port_ranges(value):
    text = re.sub(r"\s+", "", str(value)).lower()
    if text == "all":
        return [(1, 65535)]
    result = []
    if not text or len(text) > 2048:
        raise PanelError("Enter ports, ranges, or all.", field="ports")
    for item in text.split(","):
        if not re.fullmatch(r"[0-9]{1,5}(?:-[0-9]{1,5})?", item):
            raise PanelError("Use ports such as 443,8080-8090.", field="ports")
        parts = item.split("-")
        start, end = integer(parts[0], 1, 65535, "ports"), integer(parts[-1], 1, 65535, "ports")
        if start > end:
            raise PanelError("The port range is reversed.", field="ports")
        result.append((start, end))
    merged = []
    for start, end in sorted(result):
        if merged and start <= merged[-1][1] + 1:
            merged[-1] = (merged[-1][0], max(end, merged[-1][1]))
        else:
            merged.append((start, end))
    if len(merged) > 64:
        raise PanelError("Use at most 64 port ranges.", field="ports")
    return merged


def subtract(ranges, excluded):
    result = []
    for low, high in ranges:
        start = low
        for p in sorted(set(excluded)):
            if start <= p <= high:
                if start < p:
                    result.append((start, p - 1))
                start = p + 1
        if start <= high:
            result.append((start, high))
    return result


def ranges_for(c, settings):
    reserved = set(settings["ssh_ports"] + settings["reserved_ports"] + [22, settings["port"]])
    reserved.update(c.get("exclude_ports", []))
    return subtract(port_ranges(c["ports"]), reserved)


def rate(value):
    try:
        n = float(value or 0)
    except (ValueError, TypeError):
        raise PanelError("Enter a speed in Mbps.", field="speed")
    if not 0 <= n <= 100000 or (n and n < 0.008):
        raise PanelError("Speed must be zero (unlimited) or 0.008..100000 Mbps.", field="speed")
    return round(n, 3)


def connection(data, settings, previous=None, resolver=resolve):
    if not isinstance(data, dict):
        raise PanelError("Invalid connection.")
    kind = data.get("kind", previous.get("kind") if previous else "direct")
    if kind not in ("gre", "direct"):
        raise PanelError("Choose GRE or direct forwarding.")
    identity = previous["id"] if previous else uuid.uuid4().hex[:10]
    if not re.fullmatch(r"[0-9a-f]{10}", identity):
        raise PanelError("Invalid connection ID.")
    name = str(data.get("name", "")).strip() or ("GRE" if kind == "gre" else "Direct")
    if len(name) > 80 or any(ord(x) < 32 for x in name):
        raise PanelError("Use a name of up to 80 characters.", field="name")
    protocols = data.get("protocols", ["tcp", "udp"])
    if not isinstance(protocols, list) or not protocols or set(protocols) - {"tcp", "udp"}:
        raise PanelError("Choose TCP and/or UDP.", field="protocols")
    ports = str(data.get("ports", "all")).strip().lower()
    parsed = port_ranges(ports)
    target_port = data.get("target_port")
    target_port = None if target_port in (None, "", 0, "0") else integer(target_port, 1, 65535, "target_port")
    if target_port and (len(parsed) != 1 or parsed[0][0] != parsed[0][1]):
        raise PanelError("Port translation needs one input port.", field="target_port")
    host = hostname(data.get("target_host", ""))
    resolved = resolver(host)
    result = dict(id=identity, kind=kind, name=name, listen_ip=address(data.get("listen_ip", "")),
                  target_host=host, resolved_ip=resolved, target_port=target_port,
                  ports=ports, protocols=sorted(set(protocols)), enabled=bool(data.get("enabled", True)),
                  exclude_ports=port_list(data.get("exclude_ports", [])),
                  upload_mbps=rate(data.get("upload_mbps", 0)), download_mbps=rate(data.get("download_mbps", 0)),
                  monitor_ports=port_list(data.get("monitor_ports", [])),
                  port_limits={}, port_map={})
    mappings = data.get("port_map", previous.get("port_map", {}) if previous and ports == previous["ports"] else {})
    if isinstance(mappings, str):
        try:
            entries = [x.strip().split(":") for x in mappings.split(",") if x.strip()]
            if len({int(x[0]) for x in entries}) != len(entries):
                raise ValueError()
            mappings = dict(entries)
        except ValueError:
            raise PanelError("Use port mappings such as 8080:80,8443:443.", field="port_map")
    if not isinstance(mappings, dict) or len(mappings) > 128:
        raise PanelError("Invalid port mappings.", field="port_map")
    for p, destination in mappings.items():
        p = integer(p, 1, 65535, "port_map")
        if str(p) in result["port_map"]:
            raise PanelError("Duplicate mapped input port.", field="port_map")
        if not any(lo <= p <= hi for lo, hi in ranges_for(result, settings)):
            raise PanelError("Mapped input ports must belong to this connection.", field="port_map")
        result["port_map"][str(p)] = integer(destination, 1, 65535, "port_map")
    if not ranges_for(result, settings):
        raise PanelError("All selected ports are reserved for management.", "reserved", "ports")
    reserved = set(settings["ssh_ports"] + settings["reserved_ports"] + [22, settings["port"]])
    if ports != "all" and any(lo <= p <= hi for lo, hi in parsed for p in reserved):
        raise PanelError("The selected ports include a protected management port.", "reserved", "ports")
    limits = data.get("port_limits", {})
    if not isinstance(limits, dict) or len(limits) > 128:
        raise PanelError("Invalid port speed limits.")
    for p, values in limits.items():
        p = integer(p, 1, 65535, "ports")
        if not isinstance(values, dict) or not any(lo <= p <= hi for lo, hi in ranges_for(result, settings)):
            raise PanelError("The limited port must belong to this connection.")
        result["port_limits"][str(p)] = {"up": rate(values.get("up")), "down": rate(values.get("down"))}
    if kind == "gre":
        result.update(mtu=integer(data.get("mtu", settings["mtu"]), 576, 1476, "mtu"),
                      gre_slot=integer(data.get("gre_slot", previous.get("gre_slot", 0) if previous else 0), 0, 262143, "gre_slot"),
                      mtu_mode=data.get("mtu_mode", "auto"),
                      service_ip=address(data.get("service_ip") or resolved),
                      outer_local=address(data.get("outer_local") or result["listen_ip"]),
                      server_id=str(data.get("server_id", "")))
        if result["mtu_mode"] not in ("auto", "manual"):
            raise PanelError("Invalid MTU mode.")
        if result["listen_ip"] == resolved:
            raise PanelError("The GRE endpoints must differ.")
        if not re.fullmatch(r"[0-9a-f]{10}", result["server_id"]) and (result["enabled"] or result["server_id"]):
            raise PanelError("Connect a foreign server first.", "server", "server_id")
    if previous:
        for key in ("legacy_pair", "migration", "gre", "health"):
            if key in previous:
                result[key] = copy.deepcopy(previous[key])
    return result


def validate_conflicts(items, settings):
    if len({x["id"] for x in items}) != len(items):
        raise PanelError("Duplicate connection IDs.")
    active = [x for x in items if x.get("enabled", True)]
    if len(items) > 128:
        raise PanelError("Use at most 128 connections.")
    for index, a in enumerate(active):
        for b in active[index + 1:]:
            if a["kind"] == b["kind"] == "gre" and (a.get("outer_local", a["listen_ip"]), a["resolved_ip"]) == (b.get("outer_local", b["listen_ip"]), b["resolved_ip"]):
                raise PanelError("Edit the existing GRE connection to this server.", "gre_exists")
            if a["listen_ip"] != b["listen_ip"] or not set(a["protocols"]) & set(b["protocols"]):
                continue
            if any(max(al, bl) <= min(ah, bh) for al, ah in ranges_for(a, settings) for bl, bh in ranges_for(b, settings)):
                raise PanelError(f"Input ports overlap: {a['name']} / {b['name']}.", "overlap", "ports")


def settings_update(old, data):
    result = copy.deepcopy(old)
    if not isinstance(data, dict):
        raise PanelError("Invalid settings.")
    for key, lo, hi in (("port", 1024, 65535), ("mtu", 576, 1476), ("retention_days", 1, 365), ("backup_keep", 1, 30)):
        if key in data:
            result[key] = integer(data[key], lo, hi, key)
    for key in ("ssh_ports", "reserved_ports"):
        if key in data:
            result[key] = port_list(data[key])
    if "watchdog" in data:
        result["watchdog"] = bool(data["watchdog"])
    if "hostname" in data:
        result["hostname"] = hostname(data["hostname"]) if data["hostname"] else ""
    if "username" in data:
        if not re.fullmatch(r"[A-Za-z0-9_.-]{3,40}", str(data["username"])):
            raise PanelError("Use a 3..40 character login name.")
        result["username"] = data["username"]
    return result
