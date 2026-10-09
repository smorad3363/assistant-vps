"""Root-owned versioned configuration with atomic durable replacement."""
import json
import os
from pathlib import Path
import tempfile

from .errors import PM2Error
from .validation import validate_collection


def load(path):
    try:
        value = json.loads(Path(path).read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise PM2Error("E_VALIDATION", "V2 config is missing; install V2 first") from exc
    except (OSError, ValueError) as exc:
        raise PM2Error("E_VALIDATION", "Cannot parse V2 config", {"error": str(exc)}) from exc
    if not isinstance(value, dict) or value.get("schema_version") != 1:
        raise PM2Error("E_UNSUPPORTED", "Unsupported V2 configuration schema")
    if type(value.get("generation")) is not int or value["generation"] < 0:
        raise PM2Error("E_VALIDATION", "Invalid configuration generation")
    if set(value) != {"schema_version", "generation", "tunnels"}:
        raise PM2Error("E_VALIDATION", "Unknown V2 configuration fields")
    validate_collection(value["tunnels"])
    return value


def atomic_json(path, value):
    """fsync file and parent before returning; caller serializes using V2 lock."""
    path = Path(path)
    if path.is_symlink() or not path.parent.is_dir() or path.parent.is_symlink():
        raise PM2Error("E_CONFLICT", "Config location is not an owned regular path")
    data = (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode()
    name = None
    try:
        fd, name = tempfile.mkstemp(prefix=".pm2-", dir=str(path.parent))
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(name, path)
        name = None
        fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    except OSError as exc:
        raise PM2Error("E_APPLY", "Unable to persist V2 configuration", {"error": str(exc)}) from exc
    finally:
        if name is not None:
            Path(name).unlink(missing_ok=True)


def get(tunnels, ident):
    for t in tunnels:
        if t["id"] == ident:
            return t
    raise PM2Error("E_VALIDATION", "Unknown tunnel UUID", {"tunnel_id": ident})


def replace(config, tunnels):
    validate_collection(tunnels)
    return {"schema_version": 1, "generation": config["generation"] + 1,
            "tunnels": tunnels}
