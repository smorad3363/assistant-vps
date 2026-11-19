"""Real namespace traffic for v2 GRE/direct groups and established sessions."""
from collections import Counter
from contextlib import ExitStack, suppress
import copy
import json
import os
from pathlib import Path
import secrets
import select
import signal
import socket
import socketserver
import subprocess
import sys
import threading
import time
import uuid

from panel.engine import Engine
from panel.model import DEFAULTS
from panel.store import Paths, atomic_json, topology_node_id
from panel.v2_bench_agent import boot_id as benchmark_boot_id, execute as execute_benchmark, key_for, record_file, test_link, validate
from panel.v2_benchmark import SECOND, direction_lengths, report
from panel.v2_config import normalize_group
from panel.v2_drivers import driver_for
from panel.v2_forwarding import topology_views, with_ssh_protection
from panel.v2_forwarding import BOOT_ID, gre_link, health_signature
from panel.v2_health import Watchdog, link_responses, transition


def command(*args, **kwargs):
    return subprocess.run(args, check=True, text=True, timeout=30, **kwargs)


def namespace(name, action, *args):
    return ["ip", "netns", "exec", name, sys.executable, __file__, action, *map(str, args)]


def serve(address, marker, port):
    class TCP(socketserver.BaseRequestHandler):
        def handle(self):
            while data := self.request.recv(256):
                self.request.sendall(b"ready" if data == b"gremgr-health" else marker + data)

    class UDP(socketserver.BaseRequestHandler):
        def handle(self):
            data, sock = self.request
            sock.sendto(b"ready" if data == b"gremgr-health" else marker + data, self.client_address)

    family = socket.AF_INET6 if ":" in address else socket.AF_INET

    class TCPServer(socketserver.ThreadingTCPServer):
        address_family = family

    class UDPServer(socketserver.UDPServer):
        address_family = family

    tcp = TCPServer((address, port), TCP)
    udp = UDPServer((address, port), UDP)
    threading.Thread(target=udp.serve_forever, daemon=True).start()
    print("ready", flush=True)
    tcp.serve_forever()


def exchange(sock, payload):
    sock.sendall(payload)
    answer = sock.recv(256)
    assert answer[1:] == payload, answer
    return answer[:1].decode()


def sample(address, number, udp=False, port=5100, source_start=None):
    result = Counter()
    kind = socket.SOCK_DGRAM if udp else socket.SOCK_STREAM
    family = socket.AF_INET6 if ":" in address else socket.AF_INET
    for case in range(number):
        with socket.socket(family, kind) as sock:
            sock.settimeout(3)
            if source_start is not None:
                sock.bind(("", source_start + case))
            sock.connect((address, port))
            result[exchange(sock, str(case).encode())] += 1
    print(json.dumps(result), flush=True)


def hold(address):
    with socket.create_connection((address, 5100), timeout=5) as sock:
        print(exchange(sock, b"before"), flush=True)
        assert sys.stdin.readline() == "continue\n"
        print(exchange(sock, b"after"), flush=True)


def aggregate_udp(address):
    with ExitStack() as stack:
        sockets = [stack.enter_context(socket.socket(socket.AF_INET, socket.SOCK_DGRAM)) for _ in range(96)]
        for sock in sockets:
            sock.connect((address, 5100))
            sock.setblocking(False)
        markers = set()
        payload = b"x" * 1024
        total = 0
        started = time.monotonic()
        sent = 0
        while time.monotonic() - started < 7:
            with suppress(BlockingIOError):
                sockets[sent % len(sockets)].send(payload)
            sent += 1
            readable = select.select(sockets, [], [], .001)[0]
            for ready in readable:
                with suppress(BlockingIOError):
                    answer = ready.recv(2048)
                    assert answer[1:] == payload
                    markers.add(answer[:1].decode())
                    if time.monotonic() - started >= 3:
                        total += len(answer)
            time.sleep(.0006)
        print(json.dumps({"bytes": total, "members": sorted(markers)}), flush=True)


def render(home, node, with_panel, crash=None):
    paths = Paths(home)
    empty = {"groups": {}, "operations": {}}
    current = json.load(sys.stdin)
    prior = paths.var / "lab-v2.json"
    previous = json.loads(prior.read_text()) if prior.exists() else empty
    config = with_ssh_protection({"settings": dict(DEFAULTS, ssh_ports=[22, 6111]),
                                  "connections": [], "web_enabled": with_panel})
    from panel.engine import run

    def execute(*args, **kwargs):
        result = run(*args, **kwargs)
        created = args[:3] == ("ip", "link", "add") and "type" in args and args[args.index("type") + 1] == crash
        if crash and (created or (crash == "l2tpv3" and args[:4] == ("ip", "l2tp", "add", "session"))):
            os.kill(os.getpid(), signal.SIGKILL)
        return result

    Engine(paths, execute).apply(topology_views(config, current, node, paths=paths), topology_views(config, previous, node, paths=paths))
    atomic_json(prior, current)


def receive_line(process):
    if not select.select([process.stdout], [], [], 10)[0]:
        raise TimeoutError("The namespace fixture did not respond.")
    line = process.stdout.readline().strip()
    if not line:
        raise RuntimeError("The namespace fixture exited without a response.")
    return line


def stop_process(process):
    try:
        with suppress(ProcessLookupError):
            os.killpg(process.pid, signal.SIGTERM)
        try:
            process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            with suppress(ProcessLookupError):
                os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=5)
    finally:
        for stream in (process.stdin, process.stdout, process.stderr):
            if stream:
                stream.close()


def start_process(stack, args, **kwargs):
    process = subprocess.Popen(args, start_new_session=True, text=True, **kwargs)
    stack.callback(stop_process, process)
    return process


def ssh_client(stack, root, name, address, port):
    root.mkdir(parents=True)
    for key in ("user", "host"):
        command("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", root / key)
    sshd = root / "sshd.conf"
    sshd.write_text(f"ListenAddress {address}:{port}\nHostKey {root}/host\nPidFile {root}/sshd.pid\n"
                    f"AuthorizedKeysFile {root}/user.pub\nPermitRootLogin prohibit-password\n"
                    "PasswordAuthentication no\nKbdInteractiveAuthentication no\nUsePAM no\nStrictModes no\nLogLevel VERBOSE\n")
    pinned = root / "known_hosts"
    pinned.write_text(f"[{address}]:{port} " + (root / "host.pub").read_text())
    command("ip", "netns", "exec", name, "iptables", "-A", "INPUT", "-p", "tcp", "--dport", str(port), "-j", "ACCEPT")
    start_process(stack, ["ip", "netns", "exec", name, "/usr/sbin/sshd", "-D", "-e", "-f", sshd])
    client = ["ip", "netns", "exec", "gm-client", "ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=2", "-o",
              "StrictHostKeyChecking=yes", "-o", f"UserKnownHostsFile={pinned}", "-o", "IdentitiesOnly=yes",
              "-i", root / "user", "-p", str(port), f"root@{address}"]
    for _ in range(12):
        ready = subprocess.run([*client, "printf ready"], capture_output=True, text=True, timeout=8)
        if ready.returncode == 0 and ready.stdout == "ready":
            return client
        time.sleep(.2)
    raise RuntimeError(f"Unable to reach namespace SSH fixture: {ready.stderr}")


def bench_child(home, owner):
    paths = Paths(home)
    payload = json.load(sys.stdin)
    engine = Engine(paths)
    key = key_for(payload)
    request = dict(validate(payload, engine, paths), secret=payload["secret"], port=payload.get("port"))
    atomic_json(record_file(paths, key), {"phase": "starting", "boot": benchmark_boot_id(), "owner": owner,
                                         "expires": time.time() + payload["seconds"] + 40, "request": request})
    execute_benchmark(paths, key, engine)


def bench_acceptance(stack, root, left, right, addresses):
    hosts = [left, right]
    homes = [Path(root) / ("bench-" + host) for host in hosts]
    paths = [Paths(home) for home in homes]
    node_ids = [topology_node_id(item) for item in paths]

    def launch(side, payload):
        process = start_process(stack, namespace(hosts[side], "bench-child", homes[side], node_ids[0]), stdin=subprocess.PIPE)
        process.stdin.write(json.dumps(payload))
        process.stdin.close()
        return process

    for method, duration in (("gre", 2), ("ipip", 3), ("sit", 3)):
        receipts = []
        job_id = uuid.uuid4().hex
        for direction, seconds in enumerate(direction_lengths(duration)):
            sender, receiver = direction, 1 - direction
            payload = {"job_id": job_id, "method": method, "direction": direction, "nodes": node_ids,
                       "first": addresses[0], "second": addresses[1], "seconds": seconds, "budget": 800_000,
                       "rate": 200_000, "secret": secrets.token_hex(32)}
            key = key_for(payload)
            receiving = launch(receiver, payload)
            record = record_file(paths[receiver], key)
            deadline = time.monotonic() + 12
            status = {}
            while time.monotonic() < deadline:
                if record.exists():
                    status = json.loads(record.read_text())
                    if status["phase"] == "ready":
                        break
                if receiving.poll() is not None:
                    break
                time.sleep(.03)
            assert status.get("phase") == "ready", status.get("error")
            sending = launch(sender, dict(payload, port=status["port"]))
            assert receiving.wait(timeout=seconds + 8) == 0 and sending.wait(timeout=5) == 0
            final = json.loads(record.read_text())
            result = final.get("receipt")
            assert final["phase"] == "done" and final["cleaned"] and result and result["reason"] == "finished", final.get("error")
            assert result["elapsed_ns"] == seconds * SECOND and 130_000 < result["received_bytes"] <= seconds * 200_000, result
            receipts.append(result)
            link = test_link(node_ids[0], final["request"])["tunnel"]
            for host in hosts:
                assert subprocess.run(["ip", "-n", host, "link", "show", link], capture_output=True).returncode != 0
                rules = command("ip", "netns", "exec", host, "iptables-save", "-t", "filter", capture_output=True).stdout
                assert "gmpbench:" + key not in rules
                if method == "sit":
                    rules = command("ip", "netns", "exec", host, "ip6tables-save", "-t", "filter", capture_output=True).stdout
                    assert "gmpbench:" + key not in rules
        results = report(*receipts)
        assert results["finished"] and results["received_bytes"] == sum(item["received_bytes"] for item in receipts)
        print(f"v2 {method.upper()} benchmark proved {duration} seconds of real directional TCP and selective cleanup: {results['received_bytes']} bytes.", flush=True)


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
    group_id = uuid.uuid4().hex
    next_udp_source = 20000

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

    def apply(listeners, health=None, selection="weighted", limits=None):
        group = normalize_group({"id": group_id, "name": "Namespace acceptance", "listeners": listeners,
                                 "selection": selection, **({"limits": limits} if limits else {})})
        state = {"groups": {group_id: {"active": True, "revision": 1, "owner": owner, "group": group}},
                 "operations": {}, "health": health or {}}
        for name, (_, node) in nodes.items():
            command(*namespace(name, "render", Path(root) / name, node, int(name == "gm-ir")), input=json.dumps(state))
        return group["listeners"][0]

    def exchanges(name, count, proto="tcp", port=5100):
        nonlocal next_udp_source
        source = []
        if proto == "udp":
            # Old UDP tuples intentionally keep their previous destination across revisions.
            source = [next_udp_source]
            next_udp_source += count
        return json.loads(command(*namespace("gm-client", "sample", nodes[name][0], count, proto, port, *source),
                                  capture_output=True).stdout)

    with ExitStack() as mounts, ExitStack() as processes:
        for index, name in enumerate(services):
            address, _ = nodes[name]
            link = f"v-v2d{index}"
            command("ip", "netns", "add", name)
            mounts.callback(command, "ip", "netns", "del", name)
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
            process = start_process(processes, namespace(name, "serve", address, index, 5000), stdout=subprocess.PIPE)
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

        client = start_process(processes, namespace("gm-client", "hold", nodes["gm-ir"][0]),
                               stdin=subprocess.PIPE, stdout=subprocess.PIPE)
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

        first_target = services[0]
        previous_map = listener("gm-ir", [first_target], "gre", [1])
        apply([previous_map])
        old = start_process(processes, namespace("gm-client", "hold", nodes["gm-ir"][0]),
                            stdin=subprocess.PIPE, stdout=subprocess.PIPE)
        assert receive_line(old) == "0"
        replacement = start_process(processes, namespace(first_target, "serve", nodes[first_target][0], "M", 6000),
                                    stdout=subprocess.PIPE)
        assert receive_line(replacement) == "ready"
        next_map = copy.deepcopy(previous_map)
        next_map["port_map"]["5100"] = 6000
        apply([next_map])
        assert exchanges("gm-ir", 8) == {"M": 8}
        old.stdin.write("continue\n")
        old.stdin.flush()
        assert receive_line(old) == "0"
        assert old.wait(timeout=10) == 0
        print("v2 GRE remapping preserved the old TCP connection and sent new traffic to port 6000.", flush=True)

        Path("/run/sshd").mkdir(exist_ok=True, mode=0o755)
        ssh_commands = [ssh_client(processes, Path(root) / f"ssh-{host}", host, nodes[host][0], port)
                        for host, port in [("gm-ir", 23351), (first_target, 34471)]]
        sessions = [start_process(processes, [*args, "cat"], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
                    for args in ssh_commands]
        for session in sessions:
            session.stdin.write("before\n")
            session.stdin.flush()
            assert receive_line(session) == "before"
        all_ports = dict(next_map, ports="all")
        for routes in ([all_ports], [next_map]):
            apply(routes)
            assert exchanges("gm-ir", 4) == {"M": 4}
            for args, session in zip(ssh_commands, sessions):
                assert command(*args, "printf fresh", capture_output=True).stdout == "fresh"
                session.stdin.write("after\n")
                session.stdin.flush()
                assert receive_line(session) == "after"
        print("v2 all-port forwarding and rollback kept established and new SSH sessions on both custom ports.", flush=True)

        route = listener("gm-ir", services[:2], "gre", [1, 1])
        route["members"][1]["priority"] = 1
        route["probe"] = {"protocol": "tcp", "port": 5100, "request": "gremgr-health", "response": "ready"}
        compiled = apply([route], selection="failover")
        for target, member in zip(services, compiled["members"]):
            link = gre_link(owner, compiled, member, receiving=True)
            responder = start_process(processes, namespace(target, "link-respond", json.dumps(link)), stdout=subprocess.PIPE)
            assert receive_line(responder) == "ready"
        for host in ("gm-ir", *services[:2]):
            command("ip", "netns", "exec", host, "iptables", "-I", "INPUT", "1", "-p", "icmp", "-j", "DROP")

        evidence = {}

        def probe(position, time_value):
            member = compiled["members"][position]
            sample = json.loads(command(*namespace("gm-ir", "health", owner, json.dumps(compiled), position),
                                        capture_output=True).stdout)
            identity = group_id + ":" + member["id"]
            evidence[identity] = dict(transition(evidence.get(identity), sample, time_value), revision=1,
                                      path=health_signature(owner, compiled, member), boot_id=BOOT_ID)
            return sample

        for index in (0, 1):
            observation = probe(index, 0)
            assert observation["service"] is True and observation["link"] is True and observation["icmp"] is False, observation
        apply([route], evidence, "failover")
        assert exchanges("gm-ir", 3) == {"0": 3}
        block = ("INPUT", "-i", gre_link(owner, compiled, compiled["members"][0], True)["tunnel"],
                 "-p", "tcp", "--dport", "5000", "-j", "DROP")
        command("ip", "netns", "exec", first_target, "iptables", "-I", *block)
        for elapsed in (5, 10, 15):
            observation = probe(0, elapsed)
            assert observation["link"] is True and observation["service"] is False, observation
        apply([route], evidence, "failover")
        assert exchanges("gm-ir", 3) == {"1": 3}
        command("ip", "netns", "exec", first_target, "iptables", "-D", *block)
        for elapsed in (20, 25, 30, 50):
            assert probe(0, elapsed)["service"] is True
            apply([route], evidence, "failover")
            assert exchanges("gm-ir", 3) == ({"1": 3} if elapsed < 50 else {"0": 3})
        print("v2 payload health separated ICMP and service failure, failed over and returned after the stability window.", flush=True)

        weighted = listener("gm-ir", services, "direct", [1, 1, 1, 1])
        for direction in ("up", "down"):
            apply([weighted], limits={direction: 1})
            measured = json.loads(command(*namespace("gm-client", "aggregate", nodes["gm-ir"][0]), capture_output=True).stdout)
            assert set(measured["members"]) == {"0", "1", "2", "3"}, measured
            assert 210000 < measured["bytes"] < 610000, (direction, measured)
            print(f"v2 four destinations shared the 1 Mbps {direction} aggregate: {measured['bytes']} bytes over 4 seconds.", flush=True)

        ipip = listener("gm-ir", [first_target], "ipip", [1])
        command("ip", "netns", "exec", "gm-ir", "ip", "tunnel", "add", "gm-other-ipip", "mode", "ipip",
                "local", nodes["gm-ir"][0], "remote", nodes[services[-1]][0])
        ipip["members"][0]["ttl"] = 43
        normalized = apply([ipip])
        link = gre_link(owner, normalized, normalized["members"][0])
        for host in ("gm-ir", first_target):
            details = json.loads(command("ip", "-n", host, "-j", "-d", "link", "show", link["tunnel"], capture_output=True).stdout)[0]
            assert details["linkinfo"]["info_kind"] == "ipip", details
            assert details["linkinfo"]["info_data"]["ttl"] == 43, details
        for proto in ("tcp", "udp"):
            assert exchanges("gm-ir", 6, proto) == {"0": 6}
        ipip["members"][0]["ttl"] = 55
        apply([ipip])
        for host in ("gm-ir", first_target):
            details = json.loads(command("ip", "-n", host, "-j", "-d", "link", "show", link["tunnel"], capture_output=True).stdout)[0]
            assert details["linkinfo"]["info_data"]["ttl"] == 55, details
        assert exchanges("gm-ir", 6) == {"0": 6}
        apply([weighted])
        for host in ("gm-ir", first_target):
            assert subprocess.run(["ip", "-n", host, "link", "show", link["tunnel"]], capture_output=True).returncode != 0
        command("ip", "-n", "gm-ir", "link", "show", "gm-other-ipip", stdout=subprocess.DEVNULL)
        print("v2 IPIP carried TCP and UDP through both endpoints, changed TTL and removed only the owned device.", flush=True)

        sit = listener("gm-ir", [first_target], "sit", [1])
        sit.update(ports="all", port_map={}, protocols=[])
        sit["members"][0]["sit"] = {"ingress": "fd34:5d09:ee5::1/64", "destination": "fd34:5d09:ee5::2/64"}
        command("ip", "-n", "gm-ir", "link", "add", "gm-foreign-sit", "type", "sit", "local", nodes["gm-ir"][0],
                "remote", nodes[services[-1]][0])
        staged = normalize_group({"id": group_id, "name": "SIT prepare", "listeners": [sit]})
        plan = {"groups": {}, "operations": {"prepared": {"phase": "prepared", "owner": owner, "change": {"group": staged}}}}
        pending = gre_link(owner, staged["listeners"][0], staged["listeners"][0]["members"][0])
        for host in ("gm-ir", first_target):
            command(*namespace(host, "render", Path(root) / host, nodes[host][1], int(host == "gm-ir")), input=json.dumps(plan))
            assert subprocess.run(["ip", "-n", host, "link", "show", pending["tunnel"]], capture_output=True).returncode != 0
        compiled = apply([sit])
        link = gre_link(owner, compiled, compiled["members"][0])
        endpoint = link["peer_tun"]
        echo = start_process(processes, namespace(first_target, "serve", endpoint, "6", 25244), stdout=subprocess.PIPE)
        assert receive_line(echo) == "ready"
        for proto in ("tcp", "udp"):
            observed = command(*namespace("gm-ir", "sample", endpoint, 6, proto, 25244), capture_output=True).stdout
            assert json.loads(observed) == {"6": 6}, observed
        for host, inner in (("gm-ir", link["local_tun"]), (first_target, endpoint)):
            device = json.loads(command("ip", "-n", host, "-j", "-d", "link", "show", link["tunnel"], capture_output=True).stdout)[0]
            assert device["linkinfo"]["info_kind"] == "sit" and device["ifalias"] == "gremgr:v2:" + link["id"], device
            ipv6 = json.loads(command("ip", "-n", host, "-j", "-6", "addr", "show", "dev", link["tunnel"], capture_output=True).stdout)
            assert any(a["local"] == inner and a["prefixlen"] == 64 for a in ipv6[0]["addr_info"]), ipv6
        stop_process(echo)
        ipv6_default = ("ip", "netns", "exec", "gm-ir", "sysctl", "-qw", "net.ipv6.conf.default.disable_ipv6=")
        command(*ipv6_default[:-1], ipv6_default[-1] + "1")
        apply([weighted])
        command(*ipv6_default[:-1], ipv6_default[-1] + "0")
        for host in ("gm-ir", first_target):
            assert subprocess.run(["ip", "-n", host, "link", "show", link["tunnel"]], capture_output=True).returncode != 0
        command("ip", "-n", "gm-ir", "link", "show", "gm-foreign-sit", stdout=subprocess.DEVNULL)
        print("v2 SIT reserved without installing, carried IPv6 TCP and UDP, and removed only the owned device with IPv6 disabled.", flush=True)
        bench_acceptance(processes, root, "gm-ir", first_target, [nodes["gm-ir"][0], nodes[first_target][0]])

        l2 = listener("gm-ir", [first_target], "gretap", [1])
        l2["members"][0]["gretap"] = {"key": 224411}
        command("ip", "-n", "gm-ir", "link", "add", "gm-foreign-tap", "type", "gretap", "local",
                nodes["gm-ir"][0], "remote", nodes[first_target][0], "key", "224412")
        command("ip", "-n", first_target, "link", "add", "gm-foreign-tap", "type", "gretap", "local",
                nodes[first_target][0], "remote", nodes["gm-ir"][0], "key", "224412")
        for host, overlay in (("gm-ir", "10.254.250.1"), (first_target, "10.254.250.2")):
            command("ip", "-n", host, "addr", "add", overlay + "/30", "dev", "gm-foreign-tap")
            command("ip", "-n", host, "link", "set", "gm-foreign-tap", "up")
        group = normalize_group({"id": group_id, "name": "Interrupted GRETAP creation", "listeners": [l2]})
        state = {"groups": {group_id: {"active": True, "owner": owner, "group": group}}, "operations": {}}
        crashed = subprocess.run(namespace("gm-ir", "render", Path(root) / "gm-ir", owner, 1, "gretap"),
                                 input=json.dumps(state), capture_output=True, text=True, timeout=30)
        assert crashed.returncode == -signal.SIGKILL, crashed.stderr
        compiled = apply([l2])
        link = gre_link(owner, compiled, compiled["members"][0])
        assert not (Path(root) / "gm-ir" / "var" / "link-staging" / (link["tunnel"] + ".json")).exists()
        subprocess.run(["ip", "netns", "exec", "gm-ir", "ping", "-c", "1", "-w", "2", "-I", "gm-foreign-tap",
                        "10.254.250.2"], capture_output=True, timeout=5)
        foreign = json.loads(command("ip", "-n", "gm-ir", "-j", "neigh", "show", "dev", "gm-foreign-tap",
                                     capture_output=True).stdout)
        assert not any(item.get("lladdr") for item in foreign), foreign
        for proto in ("tcp", "udp"):
            assert exchanges("gm-ir", 6, proto) == {"0": 6}
        for host in ("gm-ir", first_target):
            info = json.loads(command("ip", "-n", host, "-j", "-d", "link", "show", link["tunnel"], capture_output=True).stdout)[0]
            assert info["link_type"] == "ether" and info["linkinfo"]["info_kind"] == "gretap", info
            neighbors = json.loads(command("ip", "-n", host, "-j", "neigh", "show", "dev", link["tunnel"],
                                           capture_output=True).stdout)
            assert any(item.get("lladdr") for item in neighbors), neighbors
        apply([weighted])
        for host in ("gm-ir", first_target):
            assert subprocess.run(["ip", "-n", host, "link", "show", link["tunnel"]], capture_output=True).returncode != 0
        command("ip", "-n", "gm-ir", "link", "show", "gm-foreign-tap", stdout=subprocess.DEVNULL)
        print("v2 GRETAP two-sided Ethernet learned the peer MAC and carried isolated TCP/UDP without touching the foreign device.", flush=True)


        first = listener("gm-ir", [first_target], "vxlan", [1])
        second = listener("gm-ir", [first_target], "vxlan", [1])
        second.update(ports="5200", port_map={"5200": 6000})
        for route, vni in ((first, 172), (second, 274)):
            route["members"][0]["vxlan"] = {"vni": vni, "port": 34789}
        command("ip", "-n", "gm-ir", "link", "add", "gm-foreign-vx", "type", "vxlan", "id", "172", "local",
                nodes["gm-ir"][0], "remote", nodes[first_target][0], "dstport", "34790", "dev", "eth0")
        conflict = copy.deepcopy(second)
        conflict["members"][0]["vxlan"]["port"] = 34790
        candidate = normalize_group({"id": group_id, "name": "Foreign VXLAN", "listeners": [conflict]})
        state = {"groups": {group_id: {"active": True, "owner": owner, "group": candidate}}, "operations": {}}
        rejected = subprocess.run(namespace("gm-ir", "render", Path(root) / "gm-ir", owner, 1), input=json.dumps(state),
                                  capture_output=True, text=True, timeout=30)
        assert rejected.returncode and "already uses this UDP port" in rejected.stderr, rejected.stderr
        apply([first, second])
        links = []
        for route, marker, port in ((first, "0", 5100), (second, "M", 5200)):
            member = route["members"][0]
            link = gre_link(owner, route, member)
            links.append(link["tunnel"])
            for host in ("gm-ir", first_target):
                def inside(*args, check=True):
                    return subprocess.run(["ip", "netns", "exec", host, *args], capture_output=True, text=True, check=check)

                info = driver_for(link).inspect(inside, link["tunnel"])[0]["linkinfo"]
                attrs = info["info_data"]
                assert info["info_kind"] == "vxlan" and attrs["id"] == member["vxlan"]["vni"], info
                assert attrs["port"] == 34789 and attrs["local"] == nodes[host][0], info
                assert attrs["remote"] == nodes[first_target if host == "gm-ir" else "gm-ir"][0], info
                assert attrs["link"] == "eth0" and attrs["learning"] is False, info
            for proto in ("tcp", "udp"):
                assert exchanges("gm-ir", 6, proto, port=port) == {marker: 6}
        apply([first])
        for host in ("gm-ir", first_target):
            command("ip", "-n", host, "link", "show", links[0], stdout=subprocess.DEVNULL)
            assert subprocess.run(["ip", "-n", host, "link", "show", links[1]], capture_output=True).returncode != 0
        assert exchanges("gm-ir", 6) == {"0": 6}
        command("ip", "-n", "gm-ir", "link", "show", "gm-foreign-vx", stdout=subprocess.DEVNULL)
        print("v2 independent unicast VXLAN VNIs verified their kernel settings, TCP/UDP round trips, and selective removal.", flush=True)

        geneve = listener("gm-ir", [first_target], "geneve", [1])
        geneve.update(ports="5300", port_map={"5300": 6000})
        geneve["members"][0]["geneve"] = {"vni": 98345, "port": 36081}
        second_peer = listener("gm-ir", [services[1]], "geneve", [1])
        second_peer.update(ports="5340", port_map={"5340": 5000})
        second_peer["members"][0]["geneve"] = dict(geneve["members"][0]["geneve"])
        apply([first, geneve, second_peer])
        geneve_link = gre_link(owner, geneve, geneve["members"][0])
        for host in ("gm-ir", first_target):
            settings = json.loads(command("ip", "-n", host, "-j", "-d", "link", "show", geneve_link["tunnel"],
                                          capture_output=True).stdout)[0]["linkinfo"]
            assert settings["info_kind"] == "geneve", settings
            assert settings["info_data"]["id"] == 98345 and settings["info_data"]["port"] == 36081, settings
        for proto in ("tcp", "udp"):
            assert exchanges("gm-ir", 6, proto, port=5300) == {"M": 6}
            assert exchanges("gm-ir", 6, proto, port=5340) == {"1": 6}
            assert exchanges("gm-ir", 6, proto, port=5100) == {"0": 6}
        command("ip", "-n", "gm-ir", "addr", "add", "192.0.2.199/32", "dev", "eth0")
        command("ip", "-n", "gm-ir", "route", "replace", nodes[first_target][0] + "/32", "dev", "eth0", "src", "192.0.2.199")
        apply([first])
        command("ip", "-n", "gm-ir", "route", "del", nodes[first_target][0] + "/32", "dev", "eth0")
        command("ip", "-n", "gm-ir", "addr", "del", "192.0.2.199/32", "dev", "eth0")
        for host in ("gm-ir", first_target):
            assert subprocess.run(["ip", "-n", host, "link", "show", geneve_link["tunnel"]], capture_output=True).returncode != 0
        assert exchanges("gm-ir", 6) == {"0": 6}
        print("v2 GENEVE carried two peers, cleaned up after preferred-route loss and preserved the independent VXLAN path.", flush=True)

        l2tp = listener("gm-ir", [first_target], "l2tpv3", [1])
        l2tp["members"][0]["l2tpv3"] = {"ingress": {"tunnel_id": 21701, "session_id": 21711, "port": 37001},
                                      "destination": {"tunnel_id": 21702, "session_id": 21712, "port": 37002}}
        group = normalize_group({"id": group_id, "name": "Interrupted L2TPv3 creation", "listeners": [l2tp]})
        state = {"groups": {group_id: {"active": True, "owner": owner, "group": group}}, "operations": {}}
        crashed = subprocess.run(namespace("gm-ir", "render", Path(root) / "gm-ir", owner, 1, "l2tpv3"),
                                 input=json.dumps(state), capture_output=True, text=True, timeout=30)
        assert crashed.returncode == -signal.SIGKILL, crashed.stderr
        normalized = apply([l2tp])
        member = normalized["members"][0]
        for (host, local_ip, peer_ip, local_id, peer_id), receiving in (
                (("gm-ir", "198.19.200.1", "198.19.200.2", 21911, 21912), False),
                ((first_target, "198.19.200.2", "198.19.200.1", 21912, 21911), True)):
            link = gre_link(owner, normalized, member, receiving=receiving)
            prefix = ["ip", "netns", "exec", host]
            command(*prefix, "ip", "l2tp", "add", "session", "tunnel_id", str(link["tunnel_id"]), "session_id", str(local_id),
                    "peer_session_id", str(peer_id), "name", "gm-adjacent-v3")
            command(*prefix, "ip", "addr", "add", local_ip + "/30", "dev", "gm-adjacent-v3")
            command(*prefix, "ip", "link", "set", "gm-adjacent-v3", "up")
            carrier = driver_for(link).firewall(dict(link, session_id=local_id))
            command(*prefix, "iptables", "-A", "INPUT", "-i", "eth0", "-s", link["outer_peer"],
                    "-d", link["outer_local"], *map(str, carrier), "-j", "ACCEPT")
            command(*prefix, "iptables", "-A", "INPUT", "-i", "gm-adjacent-v3", "-s", peer_ip, "-d", local_ip,
                    "-p", "tcp", "-j", "ACCEPT")
        adjacent = start_process(processes, namespace(first_target, "serve", "198.19.200.2", "L", 5699), stdout=subprocess.PIPE)
        assert receive_line(adjacent) == "ready"
        for proto in ("tcp", "udp"):
            assert exchanges("gm-ir", 5, proto) == {"0": 5}
        apply([weighted])
        neighbor = json.loads(command(*namespace("gm-ir", "sample", "198.19.200.2", 5, "tcp", 5699), capture_output=True).stdout)
        assert neighbor == {"L": 5}
        apply([l2tp])
        link = gre_link(owner, normalized, member)
        prefix = ("ip", "netns", "exec", "gm-ir")
        tunnel, session = str(link["tunnel_id"]), str(link["session_id"])
        command(*prefix, "ip", "l2tp", "del", "session", "tunnel_id", tunnel, "session_id", session)
        command(*prefix, "ip", "l2tp", "add", "session", "tunnel_id", tunnel, "session_id", session,
                "peer_session_id", str(link["peer_session_id"]), "name", link["tunnel"])
        command(*prefix, "ip", "link", "set", "dev", link["tunnel"], "alias", "outside-gremgr")
        apply([weighted])
        foreign = json.loads(command(*prefix, "ip", "-j", "link", "show", "dev", link["tunnel"], capture_output=True).stdout)
        assert foreign[0]["ifalias"] == "outside-gremgr", foreign
        assert json.loads(command(*namespace("gm-ir", "sample", "198.19.200.2", 5, "tcp", 5699), capture_output=True).stdout) == {"L": 5}
        print("v2 L2TPv3 recovered interrupted creation, carried TCP/UDP and preserved neighboring and foreign sessions.", flush=True)
        wg = listener("gm-ir", [first_target], "wireguard", [1])
        sides = {}
        for name, host, port in (("ingress", "gm-ir", 35379), ("destination", first_target, 35389)):
            public = command(*namespace(host, "wg-key", Path(root) / host), capture_output=True).stdout.strip()
            sides[name] = {"public_key": public, "port": port}
        wg["members"][0]["wireguard"] = dict(sides, keepalive=5)
        command("ip", "netns", "exec", first_target, "ip", "link", "add", "gm-existing-wg", "type", "wireguard")
        sentinel = ["ip", "netns", "exec", first_target, "wg"]
        command(*sentinel, "set", "gm-existing-wg", "listen-port", "35390")
        command("ip", "-n", first_target, "link", "set", "gm-existing-wg", "up")
        conflicting = copy.deepcopy(wg)
        conflicting["members"][0]["wireguard"]["destination"]["port"] = 35390
        revision = normalize_group({"id": group_id, "name": "WireGuard conflict", "listeners": [conflicting]})
        candidate = {"groups": {group_id: {"active": True, "owner": owner, "group": revision}}, "operations": {}}
        rejected = subprocess.run(namespace(first_target, "render", Path(root) / first_target, nodes[first_target][1], 0),
                                  input=json.dumps(candidate), capture_output=True, text=True, timeout=30)
        assert rejected.returncode and "already listens on this UDP port" in rejected.stderr, rejected.stderr
        compiled_wg = apply([wg])
        link = gre_link(owner, compiled_wg, compiled_wg["members"][0])
        remote_link = gre_link(owner, compiled_wg, compiled_wg["members"][0], receiving=True)
        responder = start_process(processes, namespace(first_target, "link-respond", json.dumps(remote_link)), stdout=subprocess.PIPE)
        assert receive_line(responder) == "ready"
        deadline = time.monotonic() + 14
        while True:
            response = command(*namespace("gm-ir", "link-probe", json.dumps(link)), capture_output=True).stdout.strip()
            handshakes = [command("ip", "netns", "exec", host, "wg", "show", link["tunnel"], "latest-handshakes",
                                  capture_output=True).stdout.split() for host in ("gm-ir", first_target)]
            if response == "true" and all(len(row) == 2 and int(row[-1]) > 0 for row in handshakes):
                break
            if time.monotonic() >= deadline:
                for host in ("gm-ir", first_target):
                    command("ip", "netns", "exec", host, "iptables", "-nvL", "GMP_INPUT")
                    for field in ("endpoints", "latest-handshakes", "transfer"):
                        command("ip", "netns", "exec", host, "wg", "show", link["tunnel"], field)
                raise AssertionError("WireGuard did not negotiate a handshake at both endpoints.")
            time.sleep(.2)
        for proto in ("tcp", "udp"):
            assert exchanges("gm-ir", 6, proto) == {"0": 6}
        apply([weighted])
        assert command(*sentinel, "show", "gm-existing-wg", "listen-port", capture_output=True).stdout.strip() == "35390"
        for host in ("gm-ir", first_target):
            assert subprocess.run(["ip", "-n", host, "link", "show", link["tunnel"]], capture_output=True).returncode != 0
        print("v2 WireGuard proved the handshake and TCP/UDP payload in both namespaces. A separate interface survived removal.", flush=True)


if __name__ == "__main__":
    action, *args = sys.argv[1:]
    if action == "lab":
        lab(*args)
    elif action == "render":
        render(args[0], args[1], bool(int(args[2])), args[3] if len(args) > 3 else None)
    elif action == "serve":
        serve(args[0], args[1].encode(), int(args[2]))
    elif action == "sample":
        sample(args[0], int(args[1]), args[2] == "udp", int(args[3]) if len(args) > 3 else 5100,
               int(args[4]) if len(args) > 4 else None)
    elif action == "hold":
        hold(*args)
    elif action == "aggregate":
        aggregate_udp(*args)
    elif action == "link-respond":
        link = json.loads(args[0])
        print("ready", flush=True)
        link_responses(lambda: {(link["local_tun"], link["peer_tun"]): link}, threading.Event())
    elif action == "link-probe":
        from panel.v2_health import link_probe

        print(json.dumps(link_probe(json.loads(args[0]))))
    elif action == "health":
        from panel.engine import run

        listener = json.loads(args[1])
        watchdog = Watchdog(None, None, run)
        print(json.dumps(watchdog.measure({"owner": args[0]}, listener, listener["members"][int(args[2])])))
    elif action == "bench-child":
        bench_child(*args)
    elif action == "wg-key":
        from panel.engine import run
        from panel.v2_drivers import local_wireguard_key

        print(local_wireguard_key(Paths(args[0]), run, create=True))
