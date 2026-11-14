"""Explicit live-test API/SSH client. Credentials never belong in the repository."""
import http.client
import json
import os
from pathlib import Path
import re
import ssl
import subprocess
import time


class API:
    def __init__(self, port=8787):
        self.port, self.cookie, self.csrf = port, "", ""
        self.host = os.environ["GRE_PANEL_TEST_HOST"]
        saved = Path("/root/gremgr-test-login.json")
        if saved.exists():
            credentials = json.loads(saved.read_text())
        else:
            text = Path("/root/gremgr-install.log").read_text()
            credentials = {"username": re.search(r"Username: (\S+)", text)[1], "password": re.search(r"Password: (\S+)", text)[1]}
        self.request("login", credentials)

    def request(self, route, payload=None, headers=None):
        conn = http.client.HTTPSConnection(self.host, self.port, timeout=35, context=ssl.create_default_context())
        h = {"Content-Type": "application/json", "Cookie": self.cookie, "X-Gremgr-CSRF": self.csrf, "Origin": f"https://{self.host}:{self.port}"}
        h.update(headers or {})
        conn.request("GET" if payload is None else "POST", "/api/" + route, None if payload is None else json.dumps(payload), h)
        response = conn.getresponse(); body = response.read(); cookie = response.getheader("Set-Cookie")
        if cookie:
            self.cookie = cookie.split(";")[0]
        conn.close()
        if response.status >= 400:
            raise RuntimeError(f"HTTP {response.status}: {body.decode()}")
        if route.startswith("backup.download"):
            return body
        data = json.loads(body)
        if route == "login":
            self.csrf = data["csrf"]
        return data

    def job(self, route, payload, fail=False):
        job = self.request(route, payload)["job"]
        for _ in range(300):
            try:
                result = self.request("job?id=" + job)
            except OSError:
                time.sleep(1)
                continue
            except RuntimeError as error:
                if "HTTP 503" not in str(error):
                    raise
                time.sleep(1)
                continue
            if result["status"] in ("done", "failed", "interrupted"):
                if fail:
                    assert result["status"] == "failed", result
                    return result
                if result["status"] != "done":
                    raise RuntimeError(json.dumps(result))
                return result.get("result", {})
            time.sleep(1)
        raise TimeoutError(route)


def peer_script(code, timeout=480):
    config = json.loads(Path("/etc/gremgr/panel.json").read_text())
    server = config["servers"][0]
    read_fd, write_fd = os.pipe()
    os.write(write_fd, os.environ["LAB_PEER_PASSWORD"].encode() + b"\n"); os.close(write_fd)
    try:
        result = subprocess.run(["sshpass", "-d", str(read_fd), "ssh", "-T", "-p", str(server["port"]),
                                 "-o", "StrictHostKeyChecking=yes", "-o", "UserKnownHostsFile=/etc/gremgr/ssh/" + server["id"] + ".known",
                                 "-o", "PubkeyAuthentication=no", "root@" + server["resolved_ip"], "python3 -"],
                                pass_fds=(read_fd,), input=code, text=True, capture_output=True, timeout=timeout)
    finally:
        os.close(read_fd)
    if result.returncode:
        raise RuntimeError(result.stderr[-3000:] + result.stdout[-1000:])
    return result.stdout
