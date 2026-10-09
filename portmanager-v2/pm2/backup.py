"""Versioned V2-only configuration backups and preview-first restore."""
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
from datetime import datetime, timezone

from . import config, transaction
from .errors import PM2Error


BASE = Path(os.environ.get("PM2_DATA", "/var/lib/portmanager2")) / "backups"
_ID = re.compile(r"^\d{8}T\d{6}Z-[a-f0-9]{8}$")


def create():
    if os.geteuid():
        raise PM2Error("E_PERMISSION", "Creating root-owned backups requires root")
    current, runtime = transaction.state()
    if BASE.is_symlink():
        raise PM2Error("E_CONFLICT", "Backup directory must not be a symlink")
    BASE.mkdir(mode=0o700, parents=True, exist_ok=True)
    ident = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + secrets.token_hex(4)
    directory = BASE / ident
    directory.mkdir(mode=0o700)
    payload = json.dumps(
        {"schema_version": 1, "config": current, "kernel_owner_inventory": runtime.get("firewall", {})},
        sort_keys=True, ensure_ascii=False
    ).encode()
    digest = hashlib.sha256(payload).hexdigest()
    path = directory / "backup.json"
    path.write_bytes(payload)
    os.chmod(path, 0o600)
    (directory / "sha256").write_text(digest + "\n")
    os.chmod(directory / "sha256", 0o600)
    return {"id": ident, "sha256": digest}


def list_backups():
    if not BASE.exists():
        return {"backups": []}
    if BASE.is_symlink():
        raise PM2Error("E_CONFLICT", "Backup directory must not be a symlink")
    return {"backups": sorted(
        [p.name for p in BASE.iterdir() if p.is_dir() and not p.is_symlink() and _ID.fullmatch(p.name)]
    )}


def restore(ident, dry_run=False):
    if not _ID.fullmatch(ident):
        raise PM2Error("E_VALIDATION", "Invalid backup identifier")
    directory = BASE / ident
    if directory.is_symlink() or not directory.is_dir():
        raise PM2Error("E_VALIDATION", "Unknown or unsafe backup path")
    data = directory / "backup.json"
    checksum = directory / "sha256"
    if data.is_symlink() or checksum.is_symlink():
        raise PM2Error("E_CONFLICT", "Backup content is symlinked")
    raw = data.read_bytes()
    if hashlib.sha256(raw).hexdigest() != checksum.read_text().strip():
        raise PM2Error("E_CONFLICT", "Backup checksum does not match")
    payload = json.loads(raw)
    if not isinstance(payload, dict) or payload.get("schema_version") != 1:
        raise PM2Error("E_UNSUPPORTED", "Unknown backup schema")
    candidate = payload["config"]
    from .validation import validate_collection
    validate_collection(candidate["tunnels"])
    original, _ = transaction.state()
    prepared = config.replace(original, candidate["tunnels"])
    if dry_run:
        return {"dry_run": True, "candidate": prepared, "backup_id": ident}
    return transaction.apply(prepared)
