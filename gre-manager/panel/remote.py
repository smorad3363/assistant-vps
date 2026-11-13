"""SSH bootstrap with pinned host keys and a forced-command management key."""
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import tempfile
import uuid

from .engine import run
from .model import PanelError, address, hostname, integer, resolve


def server_metadata(data):
    if not isinstance(data, dict) or not re.fullmatch(r"[0-9a-f]{10}", str(data.get("id", ""))):
        raise PanelError("Invalid foreign server ID.")
    user = str(data.get("username", ""))
    if not re.fullmatch(r"[a-z_][a-z0-9_-]{0,31}", user):
        raise PanelError("Invalid SSH user.")
    return {"id": data["id"], "username": user, "port": integer(data.get("port"), 1, 65535, "port"),
            "host": hostname(data.get("host", "")), "resolved_ip": address(data.get("resolved_ip", "")),
            "name": str(data.get("name", ""))[:80],
            "fingerprints": [str(x)[:128] for x in data.get("fingerprints", [])[:10]]}

BOOTSTRAP = r'''
import base64,json,os,pathlib,subprocess,sys
if os.geteuid()!=0: raise SystemExit("Root or passwordless sudo is required for initial setup.")
payload=json.load(sys.stdin)
base=pathlib.Path('/opt/gremgr-peer/panel');base.mkdir(parents=True,exist_ok=True,mode=0o755)
for name,content in payload['files'].items():
 if name not in ('__init__.py','model.py','store.py','engine.py','agent.py'): raise SystemExit('Invalid package')
 p=base/name;p.write_bytes(base64.b64decode(content));p.chmod(0o644)
wrapper=pathlib.Path('/usr/local/sbin/gremgr-peer')
wrapper.write_text('#!/bin/sh\ncd /opt/gremgr-peer\nexec /usr/bin/python3 -m panel.agent "$@"\n');wrapper.chmod(0o755)
user=payload['username']
import pwd
home=pathlib.Path(pwd.getpwnam(user).pw_dir);ssh=home/'.ssh';ssh.mkdir(mode=0o700,exist_ok=True)
command='/usr/local/sbin/gremgr-peer' if user=='root' else 'sudo -n /usr/local/sbin/gremgr-peer'
key='restrict,command="'+command+'" '+payload['public_key'].strip()+'\n'
auth=ssh/'authorized_keys';old=auth.read_text() if auth.exists() else ''
if payload['public_key'].split()[1] not in old: auth.write_text(old+('' if not old or old.endswith('\n') else '\n')+key)
auth.chmod(0o600)
record=pwd.getpwnam(user);os.chown(ssh,record.pw_uid,record.pw_gid);os.chown(auth,record.pw_uid,record.pw_gid)
if user!='root':
 p=pathlib.Path('/etc/sudoers.d/gremgr-peer');p.write_text(user+' ALL=(root) NOPASSWD: /usr/local/sbin/gremgr-peer\n');p.chmod(0o440)
 subprocess.run(['visudo','-cf',str(p)],check=True,stdout=subprocess.DEVNULL)
unit=pathlib.Path('/etc/systemd/system/gremgr-peer.service')
unit.write_text('[Unit]\nDescription=GRE Manager peer restore\nWants=network-online.target\nAfter=network-online.target\n[Service]\nType=oneshot\nExecStart=/usr/local/sbin/gremgr-peer --restore\nRemainAfterExit=yes\n[Install]\nWantedBy=multi-user.target\n')
subprocess.run(['systemctl','daemon-reload'],check=True)
subprocess.run(['systemctl','enable','gremgr-peer.service'],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
print(json.dumps({'ok':True}))
'''


class Remote:
    def __init__(self, paths):
        self.paths = paths

    def _options(self, server, key):
        server = server_metadata(server)
        return ["ssh", "-T", "-p", str(server["port"]), "-i", str(key),
                "-o", "IdentitiesOnly=yes", "-o", "StrictHostKeyChecking=yes",
                "-o", "UserKnownHostsFile=" + str(self.paths.ssh / (server["id"] + ".known")),
                "-o", "ConnectTimeout=10", "-o", "ServerAliveInterval=10", "-o", "ServerAliveCountMax=3",
                server["username"] + "@" + server["resolved_ip"]]

    def connect(self, data):
        host = hostname(data.get("host", ""))
        user = str(data.get("username", "root"))
        if not re.fullmatch(r"[a-z_][a-z0-9_-]{0,31}", user):
            raise PanelError("Invalid SSH user.", field="username")
        server = {"id": uuid.uuid4().hex[:10], "host": host, "resolved_ip": resolve(host),
                  "port": integer(data.get("port", 22), 1, 65535, "port"), "username": user,
                  "name": str(data.get("name", "")).strip()[:80] or host}
        scanned = run("ssh-keyscan", "-T", "8", "-p", server["port"], server["resolved_ip"], check=False, timeout=30)
        lines = [line for line in scanned.stdout.splitlines() if line and not line.startswith("#")]
        if not lines:
            raise PanelError("The foreign SSH service did not respond.", "ssh")
        known = self.paths.ssh / (server["id"] + ".known")
        known.write_text("\n".join(lines) + "\n")
        os.chmod(known, 0o600)
        key = self.paths.ssh / server["id"]
        run("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", key)
        fingerprints = []
        for line in lines:
            parts = line.split()
            if len(parts) >= 3:
                fingerprints.append("SHA256:" + base64.b64encode(hashlib.sha256(base64.b64decode(parts[2])).digest()).decode().rstrip("="))
        server["fingerprints"] = fingerprints
        server["key_ready"] = True
        bundle = {}
        for name in ("__init__.py", "model.py", "store.py", "engine.py", "agent.py"):
            bundle[name] = base64.b64encode((Path(__file__).parent / name).read_bytes()).decode()
        content = json.dumps({"files": bundle, "username": user, "public_key": key.with_suffix(".pub").read_text()})
        try:
            with tempfile.TemporaryDirectory(dir=self.paths.ssh) as temporary:
                initial_key = Path(temporary) / "initial"
                private = str(data.get("private_key", "")).strip()
                if private:
                    initial_key.write_text(private + "\n")
                    os.chmod(initial_key, 0o600)
                options = self._options(server, initial_key if private else key)
                command = ("" if user == "root" else "sudo -n ") + "python3 -c " + shlex.quote(BOOTSTRAP)
                password = str(data.get("password", ""))
                if password:
                    if "\n" in password or len(password) > 1024:
                        raise PanelError("Invalid SSH password.", "ssh")
                    read_fd, write_fd = os.pipe()
                    try:
                        os.write(write_fd, password.encode() + b"\n")
                        os.close(write_fd)
                        write_fd = -1
                        result = subprocess.run(["sshpass", "-d", str(read_fd), *options, command],
                                                input=content, text=True, capture_output=True, pass_fds=(read_fd,), timeout=90)
                    finally:
                        os.close(read_fd)
                        if write_fd >= 0:
                            os.close(write_fd)
                else:
                    result = run(*options[:-1], "-o", "BatchMode=yes", options[-1], command, input=content, check=False, timeout=90)
                if result.returncode:
                    raise PanelError("SSH setup failed. Check the credentials and root/passwordless sudo access.", "ssh")
            self.call(server, {"action": "status"})
        except Exception:
            for path in (key, key.with_suffix(".pub"), known):
                path.unlink(missing_ok=True)
            raise
        return server

    def call(self, server, request, timeout=90):
        server = server_metadata(server)
        key = self.paths.ssh / server["id"]
        if not key.exists():
            raise PanelError("Reconnect this foreign server; its private key is not present.", "ssh_key")
        args = self._options(server, key)
        result = run(*args[:-1], "-o", "BatchMode=yes", args[-1], input=json.dumps(request), check=False, timeout=timeout)
        if result.returncode:
            raise PanelError("The foreign SSH operation failed. Its previous configuration is retained or rolled back automatically.", "ssh")
        try:
            response = json.loads(result.stdout)
        except ValueError:
            raise PanelError("The foreign helper returned an invalid response.", "ssh")
        if not response.get("ok"):
            raise PanelError(response.get("error", "The foreign setup failed."), response.get("code", "ssh"))
        return response.get("result", {})

    def prepare(self, server, connection, remove=False):
        from .engine import gre_for, pair_values
        gre = gre_for(connection)
        foreign = pair_values(gre["outer_peer"], gre["outer_local"])
        foreign["mtu"] = connection["mtu"]
        return self.call(server, {"action": "prepare", "remove": remove,
                                 "peer": {"id": connection["id"], "kind": "peer", "gre": foreign,
                                          "enabled": connection.get("enabled", True), "service_ip": connection["service_ip"]}})

    def batch(self, server, changes):
        from .engine import gre_for, pair_values
        entries = []
        for c, remove in changes:
            g = gre_for(c)
            foreign = pair_values(g["outer_peer"], g["outer_local"])
            foreign["mtu"] = c["mtu"]
            entries.append({"peer": {"id": c["id"], "kind": "peer", "gre": foreign,
                                     "enabled": c.get("enabled", True), "service_ip": c["service_ip"]}, "remove": remove})
        return self.call(server, {"action": "prepare", "changes": entries})
