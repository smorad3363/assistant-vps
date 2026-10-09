"""Ownership-checked, fail-closed systemd unit lifecycle (phase 1).

Units are installed but intentionally NOT enabled or started until the
restoration and sampling engines pass their network acceptance tests.
No root crontab, iptables, V1 resource or qdisc is modified.
"""

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import uuid

from .errors import PM2Error


UNIT_NAMES = (
    "portmanager2-restore.service",
    "portmanager2-sample.service",
    "portmanager2-sample.timer",
)
SOURCE = Path(__file__).resolve().parents[1] / "systemd"
SYSTEMD = Path("/etc/systemd/system")
MARKER = Path("/etc/portmanager2/systemd-owner.json")


def digest(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def _check_root():
    if os.geteuid():
        raise PM2Error("E_PERMISSION", "Systemd unit maintenance requires root")


def _run(args):
    try:
        result = subprocess.run(
            ["systemctl", *args], capture_output=True, text=True,
            timeout=15, check=False
        )
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError) as exc:
        raise PM2Error("E_DEPENDENCY", "systemctl unavailable or timed out") from exc
    return result


def _reload():
    result = _run(["daemon-reload"])
    if result.returncode:
        raise PM2Error(
            "E_APPLY", "systemd daemon-reload failed",
            {"stderr": result.stderr[-500:]}
        )


def _atomic(path: Path, content: bytes, mode: int):
    temp = path.parent / f".pm2-{uuid.uuid4().hex}.tmp"
    try:
        fd = os.open(
            temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            mode
        )
        with os.fdopen(fd, "wb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temp, mode)
        os.replace(temp, path)
        fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    finally:
        if temp.exists():
            temp.unlink()


def _read_marker():
    if MARKER.is_symlink():
        raise PM2Error("E_CONFLICT", "systemd ownership marker is a symlink")
    if not MARKER.exists():
        return None
    try:
        value = json.loads(MARKER.read_text(encoding="utf-8"))
    except (ValueError, OSError) as exc:
        raise PM2Error("E_CONFLICT", "Invalid V2 systemd ownership marker") from exc
    if not isinstance(value, dict) or value.get("product") != "portmanager2" or (
        value.get("schema_version") != 1
    ):
        raise PM2Error("E_CONFLICT", "Unrecognized systemd ownership marker")
    units = value.get("units")
    if not isinstance(units, dict) or set(units) != set(UNIT_NAMES):
        raise PM2Error("E_CONFLICT", "Invalid V2 unit inventory")
    if any(not isinstance(v, str) or len(v) != 64 for v in units.values()):
        raise PM2Error("E_CONFLICT", "Invalid V2 unit fingerprints")
    return value


def preflight():
    """Verify *all* files before any removal, replacement or daemon reload."""
    marker = _read_marker()
    for name in UNIT_NAMES:
        path = SYSTEMD / name
        if path.is_symlink():
            raise PM2Error("E_CONFLICT", f"Refusing symlinked unit: {name}")
        if marker is None:
            if path.exists():
                raise PM2Error("E_CONFLICT", f"Unowned unit exists: {name}")
            continue
        if not path.is_file():
            raise PM2Error("E_CONFLICT", f"Owned unit missing: {name}")
        if digest(path.read_bytes()) != marker["units"][name]:
            raise PM2Error("E_CONFLICT", f"Owned unit modified externally: {name}")
        for kind in ("is-enabled", "is-active"):
            try:
                res = _run([kind, name])
            except PM2Error:
                raise
            # systemctl is-enabled returns 0 for enabled and static aliases;
            # static units (sample.service) must not be treated as active.
            val = res.stdout.strip()
            if kind == "is-enabled" and val not in ("disabled", "static", "indirect"):
                raise PM2Error("E_CONFLICT", f"V2 unit is not safely disabled ({val}): {name}")
            if kind == "is-active" and val != "inactive":
                raise PM2Error("E_CONFLICT", f"V2 unit is not inactive ({val}): {name}")
    return marker


def _restore(snapshots):
    for path, original in snapshots.items():
        if original is None:
            if path.exists():
                path.unlink()
        else:
            _atomic(path, original, 0o600 if path == MARKER else 0o644)
    _reload()


def _change(operation: str):
    _check_root()
    if not SYSTEMD.is_dir() or not MARKER.parent.is_dir():
        raise PM2Error("E_DEPENDENCY", "Systemd or Port Manager V2 config directory unavailable")
    old = preflight()
    if operation == "remove" and old is None:
        return {"units": [], "changed": False, "enabled": False}
    contents = {}
    if operation == "install":
        for name in UNIT_NAMES:
            path = SOURCE / name
            if not path.is_file() or path.is_symlink():
                raise PM2Error("E_DEPENDENCY", f"Missing systemd source unit: {name}")
            contents[name] = path.read_bytes()
    if operation == "install" and old is not None and all(
        old["units"][name] == digest(contents[name]) for name in UNIT_NAMES
    ):
        return {"units": list(UNIT_NAMES), "changed": False, "enabled": False}
    paths = [SYSTEMD / n for n in UNIT_NAMES] + [MARKER]
    snapshots = {path: path.read_bytes() if path.is_file() else None for path in paths}
    try:
        if operation == "install":
            for name, content in contents.items():
                path = SYSTEMD / name
                if snapshots[path] != content:
                    _atomic(path, content, 0o644)
            marker = {
                "product": "portmanager2",
                "schema_version": 1,
                "units": {name: digest(contents[name]) for name in UNIT_NAMES},
                "activation": "disabled_until_engine_release",
            }
            _atomic(MARKER, (json.dumps(marker, sort_keys=True) + "\n").encode(), 0o600)
        else:
            for name in UNIT_NAMES:
                (SYSTEMD / name).unlink()
            MARKER.unlink()
        _reload()
    except Exception as exc:
        try:
            _restore(snapshots)
        except Exception as rollback_exc:
            raise PM2Error(
                "E_ROLLBACK", "systemd unit rollback failed",
                {"operation": operation, "error": str(exc), "rollback_error": str(rollback_exc)}
            ) from rollback_exc
        if isinstance(exc, PM2Error):
            raise
        raise PM2Error(
            "E_APPLY", f"systemd unit {operation} failed",
            {"error": str(exc)}
        ) from exc
    return {"units": list(UNIT_NAMES), "changed": True, "enabled": False}


def install():
    return _change("install")


def remove():
    return _change("remove")


def main():
    if len(sys.argv) != 2 or sys.argv[1] not in ("install", "remove"):
        print("Usage: python3 -m pm2.services install|remove", file=sys.stderr)
        return 2
    try:
        result = install() if sys.argv[1] == "install" else remove()
        print(json.dumps(result, sort_keys=True))
        return 0
    except PM2Error as exc:
        print(f"[{exc.code}] {exc.message}", file=sys.stderr)
        return exc.exit_code


if __name__ == "__main__":
    sys.exit(main())
