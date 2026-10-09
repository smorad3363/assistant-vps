"""Root-owned structured V2 logs without packet payloads or client IP addresses."""
import json
import os
from pathlib import Path
from datetime import datetime, timezone

from .errors import PM2Error

PATH = Path(os.environ.get("PM2_LOG", "/var/log/portmanager2")) / "portmanager2.log"


def record(event, *, level="INFO", code="OK", generation=None):
    if os.geteuid() != 0 or not PATH.parent.is_dir() or PATH.is_symlink():
        return
    data = {
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "level": level, "component": "pm2", "event_code": event,
        "code": code, "generation": generation
    }
    fd = os.open(PATH, os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW, 0o600)
    try:
        os.write(fd, (json.dumps(data, sort_keys=True) + "\n").encode())
    finally:
        os.close(fd)


def tail(lines=100):
    if type(lines) is not int or not 1 <= lines <= 500:
        raise PM2Error("E_VALIDATION", "--lines must be from 1 to 500")
    if PATH.is_symlink():
        raise PM2Error("E_CONFLICT", "V2 log path is symlinked")
    if not PATH.exists():
        return []
    try:
        with PATH.open("r", encoding="utf-8") as file:
            # Avoid unbounded reads from a large log file.
            from collections import deque
            return [line.rstrip("\n") for line in deque(file, maxlen=lines)]
    except OSError as exc:
        raise PM2Error("E_PERMISSION", "Cannot read V2 logs") from exc
