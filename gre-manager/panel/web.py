"""Unprivileged HTTPS facade and static UI. Contains no network mutation code."""
import argparse
import base64
from http import cookies
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import mimetypes
import os
from pathlib import Path
import socket
import ssl
from urllib.parse import parse_qs, urlsplit

MAX_REQUEST = 48 * 1024 * 1024
STATIC = Path(__file__).parent / "static"
GET_ROUTES = {"state", "live", "stats", "job", "backup.download"}
POST_ROUTES = {"login", "logout", "password", "web.confirm", "backup.preview", "connection.save", "connection.delete", "connection.toggle", "connection.probe", "server.connect", "server.delete", "settings.save", "backup.create", "backup.restore", "tls.save", "tls.auto", "update"}


class RPC:
    def __init__(self, path):
        self.path = str(path)

    def request(self, route, payload, token=None, csrf=None, peer="local"):
        request = json.dumps(dict(route=route, payload=payload, token=token, csrf=csrf, peer=peer)).encode() + b"\n"
        with socket.socket(socket.AF_UNIX) as sock:
            sock.settimeout(30)
            sock.connect(self.path)
            sock.sendall(request)
            with sock.makefile("rb") as incoming:
                return json.loads(incoming.readline(MAX_REQUEST + 1))


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "GRE-Manager"
    sys_version = ""

    def log_message(self, format, *args):
        # Do not log URLs, request bodies, credentials or cookies.
        pass

    def setup(self):
        super().setup()
        self.connection.settimeout(30)

    def reply(self, status, content, content_type="application/json; charset=utf-8", extra=None):
        if isinstance(content, (dict, list)):
            content = json.dumps(content, ensure_ascii=False, allow_nan=False).encode()
        if isinstance(content, str):
            content = content.encode()
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(content)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
        if self.server.secure:
            self.send_header("Strict-Transport-Security", "max-age=86400")
        for key, value in (extra or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(content)

    def token(self):
        jar = cookies.SimpleCookie()
        try:
            jar.load(self.headers.get("Cookie", ""))
            return jar["gremgr_session"].value if "gremgr_session" in jar else None
        except cookies.CookieError:
            return None

    def do_GET(self):
        path = urlsplit(self.path)
        if path.path.startswith("/api/"):
            route = path.path[5:]
            if route not in GET_ROUTES:
                return self.reply(404, {"error": "Not found", "code": "not_found"})
            payload = {key: values[-1] for key, values in parse_qs(path.query).items()}
            return self.api(route, payload)
        names = {"/": "index.html", "/index.html": "index.html", "/app.js": "app.js", "/style.css": "style.css", "/favicon.svg": "favicon.svg"}
        if path.path not in names:
            return self.reply(404, {"error": "Not found", "code": "not_found"})
        file = STATIC / names[path.path]
        content_type = mimetypes.guess_type(file.name)[0] or "application/octet-stream"
        self.reply(200, file.read_bytes(), content_type + ("; charset=utf-8" if content_type.startswith("text/") or content_type == "application/javascript" else ""))

    def do_POST(self):
        path = urlsplit(self.path).path
        route = path[5:] if path.startswith("/api/") else ""
        if route not in POST_ROUTES:
            self.close_connection = True
            return self.reply(404, {"error": "Not found", "code": "not_found"})
        origin = self.headers.get("Origin")
        expected = ("https://" if self.server.secure else "http://") + self.headers.get("Host", "")
        if origin and origin != expected:
            self.close_connection = True
            return self.reply(403, {"error": "Origin mismatch", "code": "csrf"})
        if self.headers.get("Content-Type", "").split(";")[0] != "application/json" or self.headers.get("Transfer-Encoding"):
            self.close_connection = True
            return self.reply(400, {"error": "JSON required", "code": "invalid"})
        if route != "login":
            try:
                check = self.server.backend.request("auth.check", {}, self.token(), self.headers.get("X-Gremgr-CSRF"), self.client_address[0])
            except (OSError, ValueError):
                check = {"ok": False, "code": "unavailable", "error": "Management service is restarting."}
            if not check.get("ok"):
                self.close_connection = True
                return self.reply(401 if check.get("code") == "auth" else 403, check)
        try:
            length = int(self.headers.get("Content-Length", "-1"))
            maximum = MAX_REQUEST if route in ("backup.restore", "backup.preview") else 4096 if route == "login" else 262144
            if not 0 <= length <= maximum:
                raise ValueError()
            payload = json.loads(self.rfile.read(length))
            if not isinstance(payload, dict):
                raise ValueError()
        except (ValueError, OSError):
            self.close_connection = True
            return self.reply(400, {"error": "Invalid request", "code": "invalid"})
        self.api(route, payload)

    def api(self, route, payload):
        try:
            reply = self.server.backend.request(route, payload, self.token(), self.headers.get("X-Gremgr-CSRF"), self.client_address[0])
        except (OSError, ValueError):
            return self.reply(503, {"error": "Management service is restarting. Try again shortly.", "code": "unavailable"})
        if not reply.get("ok"):
            code = reply.get("code", "invalid")
            return self.reply(401 if code == "auth" else 403 if code == "csrf" else 429 if code == "rate_limit" else 400, reply)
        result = reply["result"]
        extra = {}
        if route == "login":
            token = result.pop("token")
            extra["Set-Cookie"] = "gremgr_session=" + token + "; HttpOnly; SameSite=Strict; Path=/; Max-Age=43200" + ("; Secure" if self.server.secure else "")
        elif route == "logout":
            extra["Set-Cookie"] = "gremgr_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0" + ("; Secure" if self.server.secure else "")
        elif route == "backup.download":
            return self.reply(200, base64.b64decode(result["content"]), "application/zip", {"Content-Disposition": 'attachment; filename="' + result["filename"] + '"'})
        self.reply(200, result, extra=extra)


def serve(config, backend, ready=None):
    server = ThreadingHTTPServer((config["bind"], config["port"]), Handler)
    server.daemon_threads = True
    server.backend = backend
    server.secure = config.get("tls", True)
    if server.secure:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(config["certificate"], config["key"])
        server.socket = context.wrap_socket(server.socket, server_side=True)
    elif config["bind"] not in ("127.0.0.1", "::1"):
        raise SystemExit("Unencrypted management is restricted to loopback.")
    if ready:
        ready(server)
    try:
        server.serve_forever()
    finally:
        server.server_close()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", default="/run/gremgr/web.json")
    args = parser.parse_args()
    config = json.loads(Path(args.config).read_text())
    serve(config, RPC(Path(args.config).parent / "control.sock"))


if __name__ == "__main__":
    main()
