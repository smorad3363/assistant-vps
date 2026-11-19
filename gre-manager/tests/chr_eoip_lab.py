"""Use a disposable RouterOS CHR guest as the peer of the Linux EoIP adapter."""
from contextlib import ExitStack
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import sys
import threading
import time

import pexpect

LINUX = "198.51.100.1"
ROUTER = "198.51.100.2"
INNER_LINUX = "10.254.199.1"
INNER_ROUTER = "10.254.199.2"
PROMPT = r"\[[\w-]+@[^\]\r\n]+\][\x1b\[\d;m ]*>"
PAYLOAD = "gremgr-eoip-chr-payload"


def run(*args):
    return subprocess.run(args, check=True, text=True, capture_output=True, timeout=25).stdout


class Router:
    def __init__(self, guest):
        self.guest = guest
        self.password = ""

    def login(self):
        self.guest.expect(r"(?i)login\s*:", timeout=160)
        self.guest.send("admin\r")
        self.guest.expect(r"(?i)password\s*:")
        self.guest.send(self.password + "\r")
        for _ in range(6):
            event = self.guest.expect([PROMPT, r"(?i)do you want to see.*license", r"(?i)new password[^:\r\n]*[:>]",
                                       r"(?i)repeat password[^:\r\n]*[:>]"])
            if event == 0:
                return
            if event == 1:
                self.guest.send("n\r")
                continue
            if not self.password:
                self.password = "C1!" + secrets.token_hex(12)
            self.guest.send(self.password + "\r")
        raise AssertionError("RouterOS did not present its operational CLI prompt.")

    def call(self, command):
        self.guest.send(command + "\r")
        self.guest.expect(PROMPT)
        return self.guest.before

    def fetch(self):
        log = self.call(f"/tool/fetch url=http://{INNER_LINUX}:25244/payload output=user")
        assert PAYLOAD in log, log[-350:]


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.client_address[0] != INNER_ROUTER or self.path != "/payload":
            self.send_error(404)
            return
        self.send_response(200)
        self.end_headers()
        self.wfile.write(PAYLOAD.encode())

    def log_message(self, *_):
        pass


def main(image, directory):
    assert os.environ.get("GITHUB_ACTIONS") == "true" and os.geteuid() == 0
    directory = Path(directory)
    tap = "gmchr" + secrets.token_hex(3)
    device = "gm-eoip-lab"
    record = directory / "linux-link.json"
    record.write_text(json.dumps({"id": "chrfixture", "tunnel": device, "mtu": 1280, "eoip_id": 22411,
                                  "outer_local": LINUX, "outer_peer": ROUTER, "local_tun": INNER_LINUX, "interface": tap}))
    assert ipaddress.ip_address(ROUTER).is_private
    with ExitStack() as cleanup:
        run("ip", "tuntap", "add", "dev", tap, "mode", "tap")
        cleanup.callback(run, "ip", "link", "del", "dev", tap)
        run("ip", "addr", "add", LINUX + "/24", "dev", tap)
        run("ip", "link", "set", "dev", tap, "up")
        add = ("-i", tap, "-s", ROUTER, "-d", LINUX, "-p", "gre", "-j", "ACCEPT")
        run("iptables", "-w", "5", "-I", "INPUT", "1", *add)
        cleanup.callback(run, "iptables", "-w", "5", "-D", "INPUT", *add)
        linux = subprocess.Popen([sys.executable, "-m", "panel.v2_eoip", str(record)])

        def stop_linux():
            if linux.poll() is None:
                linux.terminate()
            linux.wait(timeout=10)

        cleanup.callback(stop_linux)
        guest = pexpect.spawn("qemu-system-x86_64", ["-machine", "accel=kvm:tcg", "-m", "768", "-smp", "2", "-display", "none",
            "-serial", "stdio", "-monitor", "none", "-drive", f"file={image},format=raw,if=virtio", "-netdev",
            f"tap,id=wan,ifname={tap},script=no,downscript=no", "-device", "virtio-net-pci,netdev=wan"], timeout=35, encoding="utf-8",
            codec_errors="replace", env=dict(os.environ, TERM="dumb"))
        cleanup.callback(guest.close, True)
        router = Router(guest)
        try:
            router.login()
            version = router.call(":put [/system/resource/get version]")
            assert re.search(r"7\.25\.1(?:\s|\()", version), version[-250:]
            router.call(f"/ip/address/add address={ROUTER}/24 interface=ether1")
            router.call(f"/interface/eoip/add name=gm-eoip remote-address={LINUX} local-address={ROUTER} tunnel-id=22411 mtu=1280")
            router.call(f"/ip/address/add address={INNER_ROUTER}/30 interface=gm-eoip")
            with ThreadingHTTPServer((INNER_LINUX, 25244), Handler) as service:
                control = threading.Thread(target=service.serve_forever, daemon=True)
                control.start()
                try:
                    router.fetch()
                    run("ping", "-c", "2", "-W", "4", "-I", device, INNER_ROUTER)
                    guest.send("/system/reboot\r")
                    guest.expect(r"(?i)reboot[^\r\n]*(?:\[y/N\]|\[Y/n\])")
                    guest.send("y\r")
                    time.sleep(5)
                    router.login()
                    router.fetch()
                    run("ping", "-c", "2", "-W", "4", "-I", device, INNER_ROUTER)
                finally:
                    service.shutdown()
                    control.join(timeout=5)
            print("PASS: Linux EoIP and RouterOS CHR 7.25.1 exchanged actual HTTP payload and ICMP before and after RouterOS reboot.")
        except Exception:
            diagnostic = (guest.before or "")[-2500:]
            if router.password:
                diagnostic = diagnostic.replace(router.password, "[redacted]")
            print(diagnostic, file=sys.stderr)
            raise


if __name__ == "__main__":
    main(*sys.argv[1:])
