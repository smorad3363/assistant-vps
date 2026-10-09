"""Own IPv4 forwarding sysctl drop-in without touching foreign sysctl files."""
import os
from pathlib import Path

from . import discovery
from .errors import PM2Error

DROPIN = Path("/etc/sysctl.d/91-portmanager2-forward.conf")
BODY = b"# Managed only by Port Manager V2\nnet.ipv4.ip_forward=1\n"


def preflight():
    if DROPIN.is_symlink():
        raise PM2Error("E_CONFLICT", "Unsafe forwarding symlink")
    if DROPIN.exists() and DROPIN.read_bytes() != BODY:
        raise PM2Error("E_CONFLICT", "Unknown owner of V2 sysctl file")
    return {"forwarding_enabled": discovery.forwarding_enabled(),
            "dropin_owned": DROPIN.is_file() and DROPIN.read_bytes() == BODY}


def activate():
    """Call only after full NAT preflight and user-initiated apply.

    Does not turn off forwarding during uninstall/rollback; other services
    might depend on it by then.
    """
    if os.geteuid():
        raise PM2Error("E_PERMISSION", "IPv4 forwarding activation requires root")
    info = preflight()
    if info["forwarding_enabled"]:
        return {"changed": False, **info}
    if not DROPIN.parent.is_dir():
        raise PM2Error("E_DEPENDENCY", "Missing sysctl.d directory")
    created = False
    if not DROPIN.exists():
        try:
            fd = os.open(DROPIN, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)
            with os.fdopen(fd, "wb") as stream:
                stream.write(BODY)
                stream.flush()
                os.fsync(stream.fileno())
            created = True
        except OSError as exc:
            raise PM2Error("E_APPLY", "Unable to create owned forwarding drop-in") from exc
    try:
        discovery.run(["sysctl", "-w", "net.ipv4.ip_forward=1"])
    except PM2Error:
        if created and DROPIN.read_bytes() == BODY:
            DROPIN.unlink()
        raise
    return {"changed": True, "dropin_owned": True, "forwarding_enabled": True}


def remove_dropin():
    """Leave live ip_forward unchanged, remove only exact owned configuration."""
    info = preflight()
    if info["dropin_owned"]:
        DROPIN.unlink()
        return {"removed_dropin": True, "live_forwarding_left_unchanged": True}
    return {"removed_dropin": False, "live_forwarding_left_unchanged": True}
