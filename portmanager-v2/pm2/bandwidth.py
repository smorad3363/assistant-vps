"""Version 2.0 never changes root, ingress or other tc qdiscs."""
import os
import shutil
from .discovery import run
from .errors import PM2Error


def list_limits():
    return {"supported": False, "reason": "planned_for_2.1", "limits": []}


def mutation():
    # Detect an existing V1 even when it uses the same network interface.
    if os.path.exists("/usr/local/bin/portmanager"):
        raise PM2Error("E_CONFLICT", "Port Manager V1 owns potential tc limits")
    if shutil.which("tc"):
        lines = run(["tc", "qdisc", "show"]).splitlines()
        non_default = [x for x in lines if not any(
            (" " + name + " ") in x for name in ("noqueue", "fq_codel", "pfifo_fast", "mq"))]
        if non_default:
            raise PM2Error("E_CONFLICT", "Foreign qdisc exists; no V2 traffic shaping")
    raise PM2Error("E_UNSUPPORTED", "V2 shaping is planned for version 2.1.x")
