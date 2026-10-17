"""Frozen, side-effect-free contracts. This module never changes networking."""
from __future__ import annotations

import base64
import hashlib
import ipaddress
import json
import re
from decimal import Decimal, ROUND_HALF_UP
from pathlib import Path

CONTRACT_VERSION = "1.0.0"
POOL = ipaddress.IPv4Network("10.240.0.0/12")
MAX_ID = 4095


class ContractError(ValueError):
    def __init__(self, code: str, detail: str = ""):
        self.code = code
        self.detail = detail
        super().__init__(f"{code}: {detail}" if detail else code)


def _int(value, minimum=0, maximum=None):
    if isinstance(value, bool) or not isinstance(value, int):
        raise ContractError("E_DATA", "Expected an integer.")
    if value < minimum or (maximum is not None and value > maximum):
        raise ContractError("E_DATA", "Integer outside the allowed range.")
    return value


def parse_ports(text: str) -> list[dict[str, int]]:
    if not isinstance(text, str) or not text.strip(" \t"):
        raise ContractError("E_REQUIRED")
    if len(text) > 2048 or "\n" in text or "\r" in text:
        raise ContractError("E_PORT_FORMAT")
    tokens = text.split(",")
    if len(tokens) > 256:
        raise ContractError("E_PORT_BATCH")
    output, seen = [], set()
    for raw in tokens:
        token = raw.strip(" \t")
        if not re.fullmatch(r"[0-9]+(?:[ \t]*:[ \t]*[0-9]+)?", token):
            raise ContractError("E_PORT_FORMAT", token)
        pieces = token.split(":")
        listen = int(pieces[0].strip(" \t"), 10)
        target = int(pieces[-1].strip(" \t"), 10)
        if not 1 <= listen <= 65535 or not 1 <= target <= 65535:
            raise ContractError("E_PORT_RANGE", token)
        if listen in seen:
            raise ContractError("E_PORT_DUPLICATE", str(listen))
        seen.add(listen)
        output.append({"listen_port": listen, "target_port": target})
    return output


def parse_limit(text: str, current: int = 0) -> int:
    _int(current, 0, 100000)
    value = text.strip(" \t").lower()
    if value == "":
        return current
    if value == "unlimited":
        return 0
    if not re.fullmatch(r"[0-9]+", value) or len(value) > 6:
        raise ContractError("E_LIMIT")
    result = int(value, 10)
    if result > 100000:
        raise ContractError("E_LIMIT")
    return result


def canonical_json(value) -> bytes:
    return json.dumps(value, ensure_ascii=True, sort_keys=True,
                      separators=(",", ":"), allow_nan=False).encode("utf-8")


def pair_identity(first: str, second: str) -> dict:
    try:
        a, b = sorted([ipaddress.IPv4Address(first), ipaddress.IPv4Address(second)], key=int)
    except (ipaddress.AddressValueError, ValueError):
        raise ContractError("E_IP") from None
    if a == b:
        raise ContractError("E_PEER_SELF")
    for addr in (a, b):
        if addr.is_loopback or addr.is_multicast or addr.is_unspecified or int(addr) == 0xFFFFFFFF:
            raise ContractError("E_IP")
    digest = hashlib.sha256(f"{a}|{b}".encode("ascii")).digest()
    return {"outer_a": str(a), "outer_b": str(b), "pair_id": digest.hex()[:16],
            "key": int.from_bytes(digest[:4], "big") or 1,
            "start_slot": int.from_bytes(digest[4:8], "big") % (POOL.num_addresses // 4)}


def candidate_cidrs(first: str, second: str, occupied=(), count: int = 16) -> list[str]:
    _int(count, 1, 16)
    identity = pair_identity(first, second)
    try:
        exclusions = [ipaddress.IPv4Network(x, strict=False) for x in occupied]
    except ValueError:
        raise ContractError("E_DATA", "Invalid occupied network.") from None
    exclusions = [n for n in exclusions if n.prefixlen != 0]
    result = []
    slots = POOL.num_addresses // 4
    for offset in range(slots):
        slot = (identity["start_slot"] + offset) % slots
        network = ipaddress.IPv4Network((int(POOL.network_address) + slot * 4, 30))
        if not any(network.overlaps(old) for old in exclusions):
            result.append(str(network))
            if len(result) == count:
                return result
    raise ContractError("E_ADDRESS_CONFLICT")


def inside_addresses(cidr: str, local_outer: str, peer_outer: str) -> dict:
    identity = pair_identity(local_outer, peer_outer)
    try:
        network = ipaddress.IPv4Network(cidr, strict=True)
    except ValueError:
        raise ContractError("E_DATA", "Invalid inside subnet.") from None
    if network.prefixlen != 30 or not network.subnet_of(POOL):
        raise ContractError("E_DATA", "Inside subnet is outside the reserved pool.")
    local_low = str(ipaddress.IPv4Address(local_outer)) == identity["outer_a"]
    return {"local_inner": str(network.network_address + (1 if local_low else 2)),
            "peer_inner": str(network.network_address + (2 if local_low else 1))}


def resource_ids(tunnel_id: int, forward_id: int = 1) -> dict:
    _int(tunnel_id, 1, MAX_ID)
    _int(forward_id, 1, MAX_ID)
    mark = 0x47000000 | (tunnel_id << 12) | forward_id
    return {"tunnel_label": f"T{tunnel_id:04d}", "forward_label": f"P{forward_id:04d}",
            "gre_if": f"gtn{tunnel_id}", "ifb_if": f"gti{tunnel_id}",
            "route_table": 45000 + tunnel_id, "rule_priority": 30000 + tunnel_id,
            "underlay_rule_priority": 20000 + tunnel_id,
            "mark": f"0x{mark:08x}",
            "route_mark": f"0x{(0x47000000 | tunnel_id << 12):08x}/0xfffff000",
            "upload_class": f"1:{forward_id:x}", "download_class": f"2:{forward_id:x}",
            "upload_leaf": f"{0x1000 + forward_id:x}:",
            "download_leaf": f"{0x2000 + forward_id:x}:"}


def validate_peer(payload: dict) -> None:
    expected = {"schema_version", "kind", "pair_id", "outer_a", "outer_b", "key", "mtu",
                "candidates", "selected_index", "revision", "rejected_cidrs"}
    if not isinstance(payload, dict) or set(payload) != expected:
        raise ContractError("E_CODE")
    if payload["schema_version"] != 1 or isinstance(payload["schema_version"], bool):
        raise ContractError("E_CODE")
    if payload["kind"] not in ("setup", "conflict"):
        raise ContractError("E_CODE")
    identity = pair_identity(payload["outer_a"], payload["outer_b"])
    for key in ("outer_a", "outer_b", "pair_id", "key"):
        if payload[key] != identity[key]:
            raise ContractError("E_CODE")
    _int(payload["key"], 1, 0xFFFFFFFF)
    _int(payload["mtu"], 1280, 1400)
    _int(payload["revision"], 1, 2147483647)
    candidates = payload["candidates"]
    if not isinstance(candidates, list) or not 1 <= len(candidates) <= 16:
        raise ContractError("E_CODE")
    if any(not isinstance(n, str) for n in candidates) or len(set(candidates)) != len(candidates):
        raise ContractError("E_CODE")
    for cidr in candidates:
        inside_addresses(cidr, payload["outer_a"], payload["outer_b"])
    _int(payload["selected_index"], 0, len(candidates) - 1)
    rejected = payload["rejected_cidrs"]
    if not isinstance(rejected, list) or any(n not in candidates for n in rejected):
        raise ContractError("E_CODE")
    if len(set(rejected)) != len(rejected):
        raise ContractError("E_CODE")
    if payload["kind"] == "setup" and rejected:
        raise ContractError("E_CODE")
    if payload["kind"] == "conflict" and rejected != candidates:
        raise ContractError("E_CODE")


def encode_peer(payload: dict) -> str:
    validate_peer(payload)
    raw = canonical_json(payload)
    if len(raw) > 6000:
        raise ContractError("E_CODE")
    body = base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")
    token = "GT1." + body + "." + hashlib.sha256(raw).hexdigest()
    if len(token) > 8192:
        raise ContractError("E_CODE")
    return token


def _unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ContractError("E_CODE")
        result[key] = value
    return result


def decode_peer(token: str) -> dict:
    if not isinstance(token, str):
        raise ContractError("E_CODE")
    token = token.strip(" \t")
    if len(token) > 8192 or not re.fullmatch(r"GT1\.[A-Za-z0-9_-]+\.[0-9a-f]{64}", token):
        raise ContractError("E_CODE")
    _, encoded, checksum = token.split(".")
    try:
        raw = base64.b64decode(encoded + "=" * (-len(encoded) % 4), altchars=b"-_", validate=True)
        if len(raw) > 6000 or hashlib.sha256(raw).hexdigest() != checksum:
            raise ContractError("E_CODE")
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_pairs,
                           parse_constant=lambda _: (_ for _ in ()).throw(ContractError("E_CODE")))
        validate_peer(value)
        if encode_peer(value) != token:
            raise ContractError("E_CODE")
        return value
    except (ValueError, TypeError, KeyError, UnicodeError, RecursionError):
        raise ContractError("E_CODE") from None


def _two(value: Decimal) -> str:
    return format(value.quantize(Decimal("0.01"), rounding=ROUND_HALF_UP), ".2f")


def format_volume(byte_count: int | None) -> str:
    if byte_count is None:
        return "N/A"
    _int(byte_count)
    divisor, suffix = (1000000000, "GB") if byte_count >= 1000000000 else (1000000, "MB")
    return f"{_two(Decimal(byte_count) / Decimal(divisor))} {suffix}"


def counter_delta(previous: int, current: int, same_epoch: bool = True) -> int | None:
    _int(previous)
    _int(current)
    return current - previous if same_epoch and current >= previous else None


def current_mbps(previous: int, current: int, elapsed_ms: int, same_epoch=True) -> str | None:
    _int(elapsed_ms)
    delta = counter_delta(previous, current, same_epoch)
    if delta is None or not 1000 <= elapsed_ms <= 10000:
        return None
    return _two(Decimal(delta) * 8 * 1000 / Decimal(elapsed_ms) / 1000000)


def rolling_window(samples: list[dict], now_ms: int, window_seconds: int) -> dict:
    _int(now_ms)
    _int(window_seconds, 1)
    start = now_ms - window_seconds * 1000
    up = down = Decimal(0)
    coverage = 0
    prior_end = None
    for sample in sorted(samples, key=lambda row: row["start_ms"]):
        left = _int(sample["start_ms"])
        right = _int(sample["end_ms"])
        upload = _int(sample["upload_bytes"])
        download = _int(sample["download_bytes"])
        if right <= left or (prior_end is not None and left < prior_end):
            raise ContractError("E_SAMPLE", "Invalid or overlapping intervals.")
        prior_end = right
        overlap = max(0, min(right, now_ms) - max(left, start))
        if overlap:
            coverage += overlap
            fraction = Decimal(overlap) / Decimal(right - left)
            up += Decimal(upload) * fraction
            down += Decimal(download) * fraction
    result = {"as_of_ms": now_ms, "window_seconds": window_seconds,
              "coverage_ms": coverage, "status": "empty",
              "upload_bytes": None, "download_bytes": None, "total_bytes": None,
              "avg_upload_mbps": None, "avg_download_mbps": None}
    if coverage:
        result["status"] = "complete" if coverage == window_seconds * 1000 else "partial"
        result["upload_bytes"] = int(up.quantize(Decimal(1), rounding=ROUND_HALF_UP))
        result["download_bytes"] = int(down.quantize(Decimal(1), rounding=ROUND_HALF_UP))
        result["total_bytes"] = result["upload_bytes"] + result["download_bytes"]
        result["avg_upload_mbps"] = _two(up * 8 * 1000 / Decimal(coverage) / 1000000)
        result["avg_download_mbps"] = _two(down * 8 * 1000 / Decimal(coverage) / 1000000)
    return result


def render_menu(name: str, enabled: bool = True, root: Path | None = None) -> str:
    root = root or Path(__file__).resolve().parents[1]
    strings = json.loads((root / "contracts/ui.en.json").read_text(encoding="utf-8"))
    menus = json.loads((root / "contracts/menus.json").read_text(encoding="utf-8"))
    menu = menus[name]
    lines = [strings[menu["title"]], ""]
    for item in menu["items"]:
        key = item["text"]
        if "text_disabled" in item and not enabled:
            key = item["text_disabled"]
        lines.append(f'{item["key"]}) {strings[key]}')
    lines += ["", f'0) {strings[menu["zero"]]}', "", strings[menu["prompt"]]]
    return "\n".join(lines) + "\n"
