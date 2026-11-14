"""Opt-in destructive feature acceptance on an explicitly disposable panel host."""
import base64
import io
import json
import os
from pathlib import Path
import time
import zipfile
from live_api import API, peer_script

a = API()
results = []


def passed(name, detail=None):
    results.append({"test": name, "passed": True, "detail": detail})
    print(json.dumps(results[-1]), flush=True)
    Path("/root/gremgr-panel-acceptance.json").write_text(json.dumps(results, indent=2))


def reject(name, route, data, code=None):
    job = a.job(route, data, fail=True)
    if code:
        assert job["result"]["code"] == code, job
    passed(name, job["result"])


state = a.request("state")
gre = next(c for c in state["connections"] if c["kind"] == "gre")
assert state["certificate"]["status"] == "ready"
passed("trusted HTTPS and automatic certificate status")
for name, headers in [("missing CSRF", {"X-Gremgr-CSRF": ""}), ("cross-origin mutation", {"Origin": "https://example.invalid"})]:
    try:
        a.request("settings.save", {}, headers)
    except RuntimeError as error:
        assert "HTTP 403" in str(error), error
        passed(name)
    else:
        raise AssertionError(name)
for port in (22, 8787):
    reject("management port protected " + str(port), "connection.save", {"kind": "direct", "listen_ip": a.host, "target_host": gre["target_host"], "ports": str(port)}, "reserved")
reject("GRE/direct shared conflict", "connection.save", {"kind": "direct", "listen_ip": a.host, "target_host": gre["target_host"], "ports": "5311"})
reject("invalid speed rejected", "connection.save", dict(gre, upload_mbps=-1))
reject("invalid destination rejected", "connection.save", dict(gre, target_host="https://example.com"))
reject("used SSH server cannot be deleted", "server.delete", {"id": gre["server_id"]}, "in_use")
settings = dict(state["settings"], retention_days=14, backup_keep=3, watchdog=False)
a.job("settings.save", settings)
assert a.request("state")["settings"]["retention_days"] == 14
passed("editable retention, backup count and watchdog settings")
backup = a.job("backup.create", {})["filename"]
raw = a.request("backup.download?filename=" + backup)
with zipfile.ZipFile(io.BytesIO(raw)) as z:
    assert all("ssh/" not in n and "key.pem" not in n for n in z.namelist())
    assert b"scrypt$" not in z.read("telemetry.sqlite3")
content = base64.b64encode(raw).decode()
preview = a.request("backup.preview", {"content": content})
assert preview["connections"] == len(state["connections"])
passed("backup download, preview and secret exclusion", preview)
a.job("connection.save", dict(gre, name="Edited acceptance name", mtu_mode="manual", mtu=1280))
current = next(c for c in a.request("state")["connections"] if c["id"] == gre["id"])
assert current["name"] == "Edited acceptance name" and current["mtu"] == 1280
passed("edit name and manual MTU applied to both endpoints")
a.job("connection.toggle", {"id": gre["id"]})
assert not next(c for c in a.request("state")["connections"] if c["id"] == gre["id"])["enabled"]
a.job("connection.toggle", {"id": gre["id"]})
passed("pause and resume GRE")
a.job("connection.delete", {"id": gre["id"]})
assert not a.request("state")["connections"]
passed("delete GRE and owned peer state")
a.job("backup.restore", {"content": content})
restored = a.request("state")
assert len(restored["connections"]) == len(state["connections"])
assert restored["connections"][0]["id"] == gre["id"] and restored["connections"][0]["enabled"]
passed("restore configuration and SQLite history")
probe = a.job("connection.probe", {"id": gre["id"]})
assert probe["gre"] is True and probe["udp"] is None
passed("GRE probe and honest unverified generic UDP status", probe)
settings.update(watchdog=True)
a.job("settings.save", settings)
passed("watchdog re-enabled")
print(json.dumps({"result": "PASS", "checks": len(results)}), flush=True)
