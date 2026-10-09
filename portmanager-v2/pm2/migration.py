"""Safe, reversible command cut-over from original Port Manager V1 to V2.

This module ONLY manages the command alias, a byte-for-byte archive of the V1
executable and precisely identified V1 cron entries. It intentionally DOES NOT
flush V1 firewall rules, remove tc qdiscs, or mutate V1 config/data.
It must run as the LAST installer step after V2 is validated and owns its units.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile

from .errors import PM2Error

BIN = Path("/usr/local/bin/portmanager")
V2_TARGET = "/opt/portmanager2/current/bin/portmanager2"
ARCHIVE = Path("/var/lib/portmanager2/legacy-v1")
MARKER = ARCHIVE / "archive.json"
FROZEN = ARCHIVE / "portmanager.v1"
_CRON_V1 = re.compile(r"(?<![\w/.-])(?:/usr/local/bin/)?portmanager\s+(?:sample|apply)(?=\s|$)")
_CRON_ANY = re.compile(r"(?<![\w/.-])(?:/usr/local/bin/)?portmanager(?=\s|$)")


def _fail(message):
    raise PM2Error("E_CONFLICT", message)


def _digest(data):
    return hashlib.sha256(data).hexdigest()


def _read_cron():
    p = subprocess.run(["crontab", "-l"], capture_output=True, text=True,
                       timeout=12, check=False)
    if p.returncode == 0:
        return p.stdout
    if p.returncode == 1 and (
        "no crontab" in p.stderr.lower() or
        (not p.stderr.strip() and not p.stdout.strip())
    ):
        return ""
    raise PM2Error("E_DEPENDENCY", "Cannot read root crontab safely",
                   {"stderr": p.stderr[-200:]})


def _write_cron(text):
    p = subprocess.run(["crontab", "-"], input=text, text=True,
                       capture_output=True, timeout=12, check=False)
    if p.returncode:
        raise PM2Error("E_APPLY", "Cannot replace root cron entries safely",
                       {"stderr": p.stderr[-200:]})


def _split_cron(text):
    keep, removed = [], []
    for line in text.splitlines(keepends=True):
        if not line.lstrip().startswith("#") and _CRON_V1.search(line):
            removed.append(line)
        elif not line.lstrip().startswith("#") and _CRON_ANY.search(line):
            _fail("Unexpected legacy portmanager cron command; manual migration required")
        else:
            keep.append(line)
    return "".join(keep), removed


def _validate_current():
    if BIN.is_symlink():
        if os.readlink(BIN) == V2_TARGET:
            return "v2"
        _fail("Another program owns /usr/local/bin/portmanager symlink")
    if not BIN.exists():
        return "absent"
    if not BIN.is_file():
        _fail("Unknown active /usr/local/bin/portmanager file type")
    data = BIN.read_bytes()
    if not data.startswith(b"#!") or b"PORTMANAGER_ACCT" not in data:
        _fail("Existing portmanager is not a recognized original V1 binary")
    return "v1"


def _load_marker():
    if MARKER.is_symlink() or ARCHIVE.is_symlink():
        _fail("Unsafe legacy archive symlink")
    if not MARKER.exists():
        return None
    try:
        value = json.loads(MARKER.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise PM2Error("E_CONFLICT", "Corrupted legacy archive marker") from exc
    if (type(value) is not dict or value.get("product") != "portmanager2-v1-archive" or
            not isinstance(value.get("sha256"), str)):
        _fail("Unknown legacy archive marker")
    if not FROZEN.is_file() or FROZEN.is_symlink():
        _fail("Missing/untrusted V1 executable archive")
    if _digest(FROZEN.read_bytes()) != value["sha256"]:
        _fail("V1 archive checksum differs from recorded original")
    return value


def _atomic_bytes(path, data, mode=0o600):
    if path.is_symlink():
        _fail(f"Refusing to overwrite symlink: {path}")
    fd, temp_name = tempfile.mkstemp(prefix=".pm2-archive-", dir=str(path.parent))
    temp = Path(temp_name)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temp, mode)
        os.replace(temp, path)
    finally:
        temp.unlink(missing_ok=True)


def _link_v2():
    temp = BIN.parent / f".portmanager.v2-install.{os.getpid()}"
    if temp.exists() or temp.is_symlink():
        _fail("Unexpected temporary command link exists")
    try:
        os.symlink(V2_TARGET, temp)
        os.replace(temp, BIN)
    finally:
        temp.unlink(missing_ok=True)


def preflight():
    mode = _validate_current()
    if mode == "v1":
        if not shutil.which("crontab"):
            raise PM2Error("E_DEPENDENCY", "cron/crontab required for legacy upgrade")
        _split_cron(_read_cron())
    marker = _load_marker()
    if mode == "v1" and marker and _digest(BIN.read_bytes()) != marker["sha256"]:
        _fail("A different V1 binary is active; archive must be reconciled manually")
    if mode == "v2" and not Path(V2_TARGET).is_file():
        _fail("V2 alias points to a missing executable")
    return {"active": mode, "archive_exists": marker is not None,
            "would_change_kernel": False}


def activate():
    if os.geteuid():
        raise PM2Error("E_PERMISSION", "Version cutover must run as root")
    result = preflight()
    mode = result["active"]
    if mode == "v2":
        return {"changed": False, "active": "v2",
                "archive_exists": result["archive_exists"]}
    original_cron, revised_cron, changed_cron = None, None, False
    old_data = None
    old_mode = None
    try:
        if mode == "v1":
            old_data = BIN.read_bytes()
            old_mode = BIN.stat().st_mode & 0o777
            original_cron = _read_cron()
            revised_cron, removed = _split_cron(original_cron)
            if not ARCHIVE.exists():
                ARCHIVE.mkdir(mode=0o700, parents=False)
            if ARCHIVE.is_symlink() or not ARCHIVE.is_dir():
                _fail("Legacy archive is not a private directory")
            os.chmod(ARCHIVE, 0o700)
            if not MARKER.exists():
                if FROZEN.exists() or FROZEN.is_symlink():
                    _fail("Unowned legacy backup already exists")
                _atomic_bytes(FROZEN, old_data, old_mode)
                _atomic_bytes(MARKER, json.dumps({
                    "product": "portmanager2-v1-archive",
                    "sha256": _digest(old_data),
                    "binary_mode": old_mode,
                    "original_cron": original_cron,
                    "disabled_cron": removed,
                }, indent=2).encode())
            if original_cron != revised_cron:
                # Stop V1's minute sampler / reboot apply BEFORE alias switch.
                if _read_cron() != original_cron:
                    _fail("Root crontab changed concurrently; refusing cutover")
                _write_cron(revised_cron)
                changed_cron = True
        _link_v2()
        if subprocess.run([str(BIN), "--version"], capture_output=True,
                          text=True, timeout=12).returncode:
            raise PM2Error("E_APPLY", "V2 primary launcher failed smoke test")
        return {"changed": True, "active": "v2",
                "legacy_archived": mode == "v1",
                "old_cron_disabled": changed_cron,
                "archive": str(ARCHIVE) if mode == "v1" else None,
                "kernel_untouched": True}
    except Exception:
        # Restore prior public command and exact root cron if anything failed.
        if old_data is not None:
            _atomic_bytes(BIN, old_data, old_mode)
        elif mode == "absent" and BIN.is_symlink() and os.readlink(BIN) == V2_TARGET:
            BIN.unlink()
        if changed_cron:
            _write_cron(original_cron)
        raise


def restore_archived_cron():
    """Run after the original V1 installer finishes during explicit rollback.

    Leave non-V1 entries from the current root crontab in place; reinstate the
    saved V1 jobs only if they are missing. Never overwrite concurrent jobs.
    """
    marker = _load_marker()
    if not marker:
        return False
    old = marker.get("disabled_cron", [])
    if not isinstance(old, list) or any(not isinstance(x, str) for x in old):
        _fail("Corrupt legacy cron archive")
    current = _read_cron()
    entries = current.splitlines(keepends=True)
    existing = set(entries)
    missing = [line for line in old if line not in existing]
    if not missing:
        return False
    if _read_cron() != current:
        _fail("Root crontab changed concurrently during V1 restore")
    _write_cron(current + ("" if not current or current.endswith("\n") else "\n")
                + "".join(missing))
    return True


def main():
    command = sys.argv[1] if len(sys.argv) > 1 else "preflight"
    try:
        if command == "preflight":
            print(json.dumps(preflight()))
        elif command == "activate":
            print(json.dumps(activate()))
        elif command == "restore-cron":
            print(json.dumps({"restored": restore_archived_cron()}))
        else:
            raise PM2Error("E_VALIDATION", "Invalid migration action")
    except PM2Error as exc:
        print(f"{exc.code}: {exc.message}", file=sys.stderr)
        return 5
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
