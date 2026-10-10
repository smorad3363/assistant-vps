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
FLAGS = (MARKER.parent / "enable-restore", MARKER.parent / "enable-sample")
FLAG_BYTES = b"portmanager2-owned-activation\\n"


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
    if value.get("activation") not in ("disabled_until_engine_release", "active"):
        raise PM2Error("E_CONFLICT", "Unrecognized or transitional unit activation state")
    units = value.get("units")
    if not isinstance(units, dict) or set(units) != set(UNIT_NAMES):
        raise PM2Error("E_CONFLICT", "Invalid V2 unit inventory")
    if any(not isinstance(v, str) or len(v) != 64 for v in units.values()):
        raise PM2Error("E_CONFLICT", "Invalid V2 unit fingerprints")
    return value


def preflight():
    """Verify *all* files before any removal, replacement or daemon reload."""
    marker = _read_marker()
    for flag in FLAGS:
        if flag.is_symlink():
            raise PM2Error("E_CONFLICT", "Symlinked V2 activation flag")
        if flag.exists() and flag.read_bytes() != FLAG_BYTES:
            raise PM2Error("E_CONFLICT", "Unknown V2 activation flag owner")
    if marker is not None:
        active = marker["activation"] == "active"
        if active and not all(f.is_file() for f in FLAGS):
            raise PM2Error("E_CONFLICT", "Enabled V2 service missing owned activation flag")
        if not active and any(f.exists() for f in FLAGS):
            raise PM2Error("E_CONFLICT", "Disabled V2 service has stale activation flags")
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
            active = marker["activation"] == "active"
            if kind == "is-enabled":
                expected = (
                    ("enabled",) if active and name != "portmanager2-sample.service"
                    else ("disabled", "static", "indirect")
                )
                if val not in expected:
                    raise PM2Error("E_CONFLICT", f"Unexpected V2 enable state ({val}): {name}")
            if kind == "is-active":
                expected = "active" if active and name == "portmanager2-sample.timer" else "inactive"
                # A timer-triggered oneshot can legitimately be in "failed"
                # after its last invocation; it is still the exact owned unit
                # verified above, so that result cannot mean a foreign unit.
                # Preserve the error in systemd/journald and warn visibly,
                # while allowing verified upgrades that may repair the cause.
                recoverable_sample_failure = (
                    marker["activation"] == "active"
                    and name == "portmanager2-sample.service"
                    and val == "failed"
                )
                if val != expected and not recoverable_sample_failure:
                    raise PM2Error("E_CONFLICT", f"Unexpected V2 runtime state ({val}): {name}")
                if recoverable_sample_failure:
                    print("[portmanager2] WARNING: sampler service previously failed; "
                          "install can continue, but check its journal: "
                          "journalctl -u portmanager2-sample.service -n 60 --no-pager",
                          file=sys.stderr)
    return marker


def _restore(snapshots):
    for path, original in snapshots.items():
        if original is None:
            if path.exists():
                path.unlink()
        else:
            _atomic(path, original, 0o600 if path == MARKER or path in FLAGS else 0o644)
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
        return {"units": list(UNIT_NAMES), "changed": False,
                "enabled": old["activation"] == "active"}
    if operation == "install" and old is not None and old["activation"] == "active":
        raise PM2Error("E_CONFLICT", "Upgrade changing enabled units must use an explicit safe lifecycle")
    paths = [SYSTEMD / n for n in UNIT_NAMES] + [MARKER] + list(FLAGS)
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
            if old is not None and old["activation"] == "active":
                for action in (["disable", "--now", "portmanager2-sample.timer"],
                               ["disable", "portmanager2-restore.service"]):
                    result = _run(action)
                    if result.returncode:
                        raise PM2Error("E_APPLY", "Could not disable owned V2 unit",
                                       {"command": action, "stderr": result.stderr[-350:]})
            for flag in FLAGS:
                if flag.exists():
                    flag.unlink()
            for name in UNIT_NAMES:
                (SYSTEMD / name).unlink()
            MARKER.unlink()
        _reload()
    except Exception as exc:
        try:
            _restore(snapshots)
            if old is not None and old.get("activation") == "active":
                _run(["enable", "portmanager2-restore.service"])
                _run(["enable", "--now", "portmanager2-sample.timer"])
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
    return {"units": list(UNIT_NAMES), "changed": True,
            "enabled": old is not None and old.get("activation") == "active" and operation != "remove"}


def activate():
    """Explicitly opt in to persistence after VM-qualified network release.

    Installs only V2 systemd entries; no changes to cron, iptables or V1.
    Caller must hold the V2 global lock.
    """
    _check_root()
    old = preflight()
    if old is None:
        raise PM2Error("E_DEPENDENCY", "Install V2 units before activation")
    if old["activation"] == "active":
        return {"enabled": True, "changed": False}
    pending = dict(old, activation="enabling")
    _atomic(MARKER, (json.dumps(pending, sort_keys=True) + "\n").encode(), 0o600)
    try:
        for flag in FLAGS:
            if flag.exists():
                raise PM2Error("E_CONFLICT", "Unexpected preexisting activation flag")
            _atomic(flag, FLAG_BYTES, 0o600)
        for action in (["enable", "portmanager2-restore.service"],
                       ["enable", "--now", "portmanager2-sample.timer"]):
            result = _run(action)
            if result.returncode:
                raise PM2Error("E_APPLY", "Could not activate owned service",
                               {"command": action, "stderr": result.stderr[-350:]})
        finished = dict(old, activation="active")
        _atomic(MARKER, (json.dumps(finished, sort_keys=True) + "\n").encode(), 0o600)
    except Exception:
        try:
            _run(["disable", "--now", "portmanager2-sample.timer"])
            _run(["disable", "portmanager2-restore.service"])
            for flag in FLAGS:
                if flag.is_file() and flag.read_bytes() == FLAG_BYTES:
                    flag.unlink()
            _atomic(MARKER, (json.dumps(old, sort_keys=True) + "\n").encode(), 0o600)
        except Exception as rollback:
            raise PM2Error("E_ROLLBACK", "Could not restore original V2 unit activation") from rollback
        raise
    return {"enabled": True, "changed": True}


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
