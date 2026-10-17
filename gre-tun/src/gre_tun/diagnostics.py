"""Bounded read-only structural diagnostics."""
from datetime import datetime,timezone
import json
import subprocess
from .config import read

def status():
    c=read()
    if not c:return {"contract_version":"1.0.0","config_revision":0,"tunnels":[],"forwards":[],"service":"Unconfigured","pending_transaction":False}
    return {"contract_version":"1.0.0","config_revision":c["config_revision"],
            "tunnels":[{"id":f"T{t['id']:04d}","peer_ip":t["peer_ip"],"state":"Not applied"} for t in c["tunnels"]],
            "forwards":[{"id":f"P{f['id']:04d}","listen_port":f["listen_port"],"state":"Not applied"} for f in c["forwards"]],
            "service":"Development preview","pending_transaction":False}

def test(tunnel_id=None):
    c=read()
    targets=[t for t in (c or {}).get("tunnels",[]) if tunnel_id is None or t["id"]==tunnel_id]
    if not targets:return []
    return [{"contract_version":"1.0.0","test_id":f"TEST-{t['id']:04d}",
             "timestamp_utc":datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
             "tunnel_id":f"T{t['id']:04d}","structure":"NOT RUN",
             "reachability":"NOT RUN","result":"UNVERIFIED","log_path":None} for t in targets]
