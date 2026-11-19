"""Real namespace traffic for v2 GRE/direct groups and established sessions."""
from collections import Counter
import copy
import json
import os
from pathlib import Path
import select
import socket
import socketserver
import subprocess
import sys
import threading
import uuid

from panel.engine import Engine
from panel.model import DEFAULTS
from panel.store import Paths, atomic_json
from panel.v2_config import normalize_group
from panel.v2_forwarding import topology_views


def command(*args, **kwargs):
    return subprocess.run(args, check=True, text=True, timeout=30, **kwargs)


def namespace(name, action, *args):
    return ["ip", "netns", "exec", name, sys.executable, __file__, action, *map(str, args)]


def serve(address, marker):
    class TCP(socketserver.BaseRequestHandler):
        def handle(self):
            while data := self.request.recv(256):
                self.request.sendall(marker + data)

    class UDP(socketserver.BaseRequestHandler):
        def handle(self):
            data, sock = self.request
            sock.sendto(marker + data, self.client_address)

    tcp = socketserver.ThreadingTCPServer((address, 5000), TCP)
    udp = socketserver.UDPServer((address, 5000), UDP)
    threading.Thread(target=udp.serve_forever, daemon=True).start()
    print("ready", flush=True)
    tcp.serve_forever()


def exchange(sock, payload):
    sock.sendall(payload)
    answer = sock.recv(256)
    assert answer[1:] == payload, answer
    return answer[:1].decode()


def sample(address, number, udp=False):
    result = Counter()
    kind = socket.SOCK_DGRAM if udp else socket.SOCK_STREAM
    for case in range(number):
        with socket.socket(socket.AF_INET, kind) as sock:
            sock.settimeout(3)
            sock.connect((address, 5100))
            result[exchange(sock, str(case).encode())] += 1
    print(json.dumps(result), flush=True)


def hold(address):
    with socket.create_connection((address, 5100), timeout=5) as sock:
        print(exchange(sock, b"before"), flush=True)
        assert sys.stdin.readline() == "continue\n"
        print(exchange(sock, b"after"), flush=True)


def render(home, node, with_panel):
    paths = Paths(home)
    empty = {"groups": {}, "operations": {}}
    current = json.load(sys.stdin)
    prior = paths.var / "lab-v2.json"
    previous = json.loads(prior.read_text()) if prior.exists() else empty
    config = {"settings": dict(DEFAULTS, ssh_ports=[22, 6111]), "connections": [], "web_enabled": with_panel}
    Engine(paths).apply(topology_views(config, current, node), topology_views(config, previous, node))
    atomic_json(prior, current)


def receive_line(process):
    if not select.select([process.stdout], [], [], 10)[0]:
        raise TimeoutError("The namespace fixture did not respond.")
    line = process.stdout.readline().strip()
    if not line:
        raise RuntimeError("The namespace fixture exited without a response.")
    return line


def lab(root):
    assert os.geteuid() == 0
    assert os.readlink("/proc/self/ns/net") != os.readlink("/proc/1/ns/net")
    nodes = {"gm-ir": ("192.0.2.10", uuid.uuid4().hex)}
    services = []
    for index in range(4):
        name, outside = f"gm-v2d{index}", f"192.0.2.{41 + index}"
        nodes[name] = outside, uuid.uuid4().hex
        services.append(name)
    owner = nodes["gm-ir"][1]
    processes, namespaces = [], []
    group_id = uuid.uuid4().hex

    def listener(source, targets, method, weights):
        address, node = nodes[source]
        return {
            "id": uuid.uuid4().hex, "ip": address, "node_id": node, "ports": "5100", "port_map": {"5100": 5000},
            "members": [
                {"id": uuid.uuid4().hex, "node_id": nodes[target][1], "service_ip": nodes[target][0],
                 "method": method, "weight": weight}
                for target, weight in zip(targets, weights)
            ],
        }

    def apply(listeners):
        group = normalize_group({"id": group_id, "name": "Namespace acceptance", "listeners": listeners})
        state = {"groups": {group_id: {"active": True, "owner": owner, "group": group}}, "operations": {}}
        for name, (_, node) in nodes.items():
            command(*namespace(name, "render", Path(root) / name, node, int(name == "gm-ir")), input=json.dumps(state))

    def exchanges(name, count, proto="tcp"):
        return json.loads(command(*namespace("gm-client", "sample", nodes[name][0], count, proto),
                                  capture_output=True).stdout)

    try:
        for index, name in enumerate(services):
            address, _ = nodes[name]
            link = f"v-v2d{index}"
            command("ip", "netns", "add", name)
            namespaces.append(name)
            command("ip", "link", "add", link, "type", "veth", "peer", "name", "eth0", "netns", name)
            command("ip", "link", "set", link, "master", "gm-br")
            command("ip", "link", "set", link, "up")
            command("ip", "-n", name, "link", "set", "lo", "up")
            command("ip", "-n", name, "link", "set", "eth0", "up")
            command("ip", "-n", name, "addr", "add", address + "/24", "dev", "eth0")
            command("ip", "netns", "exec", name, "iptables", "-P", "INPUT", "DROP")
            for proto in ("tcp", "udp"):
                command("ip", "netns", "exec", name, "iptables", "-A", "INPUT", "-s", "192.0.2.0/24",
                        "-p", proto, "--dport", "5000", "-j", "ACCEPT")
            process = subprocess.Popen(namespace(name, "serve", address, index), text=True, stdout=subprocess.PIPE)
            processes.append(process)
            assert receive_line(process) == "ready"

        apply([listener("gm-ir", services, "gre", [1, 1, 1, 1])])
        for proto in ("tcp", "udp"):
            counts = exchanges("gm-ir", 96, proto)
            assert set(counts) == {"0", "1", "2", "3"}, (proto, counts)
            print(f"v2 GRE mapped {proto} payloads reached four independent destinations: {counts}", flush=True)

        direct = listener("gm-ir", services[:2], "direct", [1, 3])
        apply([direct])
        counts = exchanges("gm-ir", 1000)
        assert 700 <= counts.get("1", 0) <= 800, counts
        print(f"v2 direct weighted 1:3 across 1000 connections: {counts}", flush=True)

        client = subprocess.Popen(namespace("gm-client", "hold", nodes["gm-ir"][0]), text=True,
                                  stdin=subprocess.PIPE, stdout=subprocess.PIPE)
        processes.append(client)
        previous = receive_line(client)
        draining = copy.deepcopy(direct)
        draining["members"][int(previous)]["draining"] = True
        apply([draining])
        assert exchanges("gm-ir", 40) == {str(1 - int(previous)): 40}
        client.stdin.write("continue\n")
        client.stdin.flush()
        assert receive_line(client) == previous
        assert client.wait(timeout=10) == 0
        print("v2 draining kept the established TCP session while all new flows moved.", flush=True)

        sources = ["gm-ir", *services[1:]]
        apply([listener(source, services[:1], "gre", [1]) for source in sources])
        for source in sources:
            for proto in ("tcp", "udp"):
                assert exchanges(source, 4, proto) == {"0": 4}
        print("v2 four ingress hosts reached a shared mapped GRE service.", flush=True)
    finally:
        for process in processes:
            if process.poll() is None:
                process.terminate()
            process.wait(timeout=5)
        for name in reversed(namespaces):
            command("ip", "netns", "del", name)


if __name__ == "__main__":
    action, *args = sys.argv[1:]
    if action == "lab":
        lab(*args)
    elif action == "render":
        render(args[0], args[1], bool(int(args[2])))
    elif action == "serve":
        serve(args[0], args[1].encode())
    elif action == "sample":
        sample(args[0], int(args[1]), args[2] == "udp")
    elif action == "hold":
        hold(*args)
