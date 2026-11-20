"""Observe the configured path locally and change only new-flow eligibility."""
from concurrent.futures import ThreadPoolExecutor
from contextlib import suppress
import copy
import errno
import fcntl
import os
import select
import socket
import threading
import time

from .model import PanelError, ranges_for
from .v2_drivers import DRIVERS
from .v2_forwarding import LINK_PROBE_PROTOCOL, checks_admission, gre_link, health_signature, topology_views
from .v2_resources import admission_pressure, boot_id, pressure_file

PROBE_REQUEST = b"gremgr2?"
PROBE_REPLY = b"gremgr2!"
TIMEOUT = 2
INTERVAL = 5
PARALLEL = 8
PATH_DOWN = {errno.ENODEV, errno.ENETDOWN, errno.ENETUNREACH, errno.EADDRNOTAVAIL, errno.EHOSTUNREACH}


def transition(previous, sample, now):
    """Three real failures withdraw admission. Three stable successes restore it."""
    previous = previous or {}
    result = dict(sample, successes=0, failures=0, since=None, available=previous.get("available", False))
    service = sample.get("admission", sample["service"])
    if service is True:
        result["successes"] = previous.get("successes", 0) + 1
        result["since"] = previous.get("since") if previous.get("successes") else now
        if not previous.get("verified") or (result["successes"] >= 3 and now - result["since"] >= 30):
            result["available"] = True
            result["verified"] = True
    elif service is False:
        result["failures"] = previous.get("failures", 0) + 1
        if result["failures"] >= 3:
            result["available"] = False
    result.setdefault("verified", previous.get("verified", False))
    return result


def bound_socket(link, kind, protocol=0, source=None):
    sock = socket.socket(socket.AF_INET, kind, protocol)
    try:
        sock.settimeout(TIMEOUT)
        if link:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, link["tunnel"].encode() + b"\0")
            sock.bind((link["local_tun"], 0))
        elif source:
            sock.bind((source, 0))
        return sock
    except OSError:
        sock.close()
        raise


def inner_packet(packet):
    if len(packet) < 20 or packet[0] >> 4 != 4:
        return None, b""
    return socket.inet_ntoa(packet[16:20]), packet[(packet[0] & 15) * 4:]


def link_probe(link):
    try:
        with bound_socket(link, socket.SOCK_RAW, LINK_PROBE_PROTOCOL) as sock:
            nonce = os.urandom(16)
            local, remote = link["local_tun"], link["peer_tun"]
            sock.sendto(PROBE_REQUEST + nonce, (remote, 0))
            deadline = time.monotonic() + TIMEOUT
            while time.monotonic() < deadline:
                sock.settimeout(max(.001, deadline - time.monotonic()))
                packet, source = sock.recvfrom(2048)
                destination, payload = inner_packet(packet)
                if source[0] == remote and destination == local and payload == PROBE_REPLY + nonce:
                    return True
    except TimeoutError:
        return False
    except OSError as error:
        return False if error.errno in PATH_DOWN else None
    return False


def link_responses(links, stop):
    """Echo nonces only between the known endpoints of installed GRE links."""
    with suppress(OSError), socket.socket(socket.AF_INET, socket.SOCK_RAW, LINK_PROBE_PROTOCOL) as listener:
        while not stop.is_set():
            if not select.select([listener], [], [], .5)[0]:
                continue
            packet, source = listener.recvfrom(2048)
            local, data = inner_packet(packet)
            link = links().get((local, source[0]))
            if not link or not data.startswith(PROBE_REQUEST) or len(data) != len(PROBE_REQUEST) + 16:
                continue
            with suppress(OSError), bound_socket(link, socket.SOCK_RAW, LINK_PROBE_PROTOCOL) as reply:
                reply.sendto(PROBE_REPLY + data[len(PROBE_REQUEST):], (source[0], 0))


def service_probe(host, port, definition, link, source=None):
    udp = definition["protocol"] == "udp"
    request = definition["request"].encode()
    response = definition["response"].encode()
    try:
        sock = bound_socket(link, socket.SOCK_DGRAM if udp else socket.SOCK_STREAM, source=source)
    except OSError as error:
        return False if link and error.errno in PATH_DOWN else None
    try:
        with sock:
            deadline = time.monotonic() + TIMEOUT
            sock.connect((host, port))
            sock.settimeout(max(.001, deadline - time.monotonic()))
            sock.sendall(request)
            if udp:
                return sock.recv(len(response) + 1) == response
            received = b""
            while len(received) < len(response) and time.monotonic() < deadline:
                sock.settimeout(max(.001, deadline - time.monotonic()))
                part = sock.recv(len(response) - len(received))
                if not part:
                    break
                received += part
            return received == response
    except OSError:
        return False


class Watchdog:
    def __init__(self, participant, config, run, management=None, clock=time.time):
        self.participant, self.config, self.run = participant, config, run
        self.management, self.clock = management, clock
        self.peer_links = {}
        self.offset = 0
        self.boot_id = boot_id()
        self.management_pool = None
        self.management_lock = threading.Lock()
        self.management_checks = {}
        self.driver_unavailable = {}

    def management_state(self, record, member):
        if self.management_pool is None or not member["managed"]:
            return None
        key = record["group"]["id"], record["revision"], member["node_id"]
        with self.management_lock:
            now = self.clock()
            for identity, (started, future) in list(self.management_checks.items()):
                if future.done() and now - started >= 30:
                    del self.management_checks[identity]
            sample = self.management_checks.get(key)
            if sample:
                future = sample[1]
                return future.result() if future.done() else None
            if sum(not future.done() for _, future in self.management_checks.values()) < 4:
                self.management_checks[key] = (now, self.management_pool.submit(self.management, record, member))
        return None

    def measure(self, record, listener, member):
        link = gre_link(record["owner"], listener, member) if member["method"] in DRIVERS else None
        ping = None
        if link:
            with suppress(PanelError):
                ping = self.run("ping", "-n", "-I", link["tunnel"], "-W", "1", "-c", "1", link["peer_tun"],
                                check=False, timeout=2).returncode == 0
        service = None
        probe = listener.get("probe")
        if probe:
            target = listener["port_map"].get(str(probe["port"]), listener["target_port"] or probe["port"])
            host = link["peer_tun"] if link else member["service_ip"]
            service = service_probe(host, target, probe, link, source=listener["ip"])
        link_state = (True if service else link_probe(link)) if link and member["method"] != "sit" else None
        management = self.management_state(record, member)
        return {"management": management, "link": link_state, "service": service, "icmp": ping,
                "admission": service if probe else link_state,
                "checked": self.clock(), "reason": "service_probe" if probe else "link_probe" if link_state is not None else "no_service_probe"}

    def paths(self, state):
        targets, peers = {}, {}
        local = self.participant.node_id
        for group_id, record in state["groups"].items():
            group = record["group"]
            if not record["active"] or not group["enabled"]:
                continue
            for listener in group["listeners"]:
                for member in listener["members"]:
                    if not member["enabled"]:
                        continue
                    if listener["node_id"] == local:
                        targets[group_id + ":" + member["id"]] = (record, listener, member)
                    if member["node_id"] == local and member["method"] in DRIVERS and member["method"] != "sit":
                        link = gre_link(record["owner"], listener, member, receiving=True)
                        peers[(link["local_tun"], link["peer_tun"])] = link
        return targets, peers

    def round(self, pool):
        snapshot = self.participant.journal.read()
        targets, self.peer_links = self.paths(snapshot)
        if self.management_pool:
            for record in snapshot["groups"].values():
                if record["active"] and record["owner"] == self.participant.node_id:
                    for listener in record["group"]["listeners"]:
                        if listener["node_id"] != self.participant.node_id:
                            self.management_state(record, {"node_id": listener["node_id"], "managed": True})
        keys = sorted(targets)
        selected = (keys[self.offset:] + keys[:self.offset])[:PARALLEL]
        self.offset = (self.offset + PARALLEL) % len(keys) if keys else 0
        settings = self.config()["settings"]

        def check(target):
            record, listener, member = target
            probe = listener.get("probe")
            if probe and not any(lo <= probe["port"] <= hi for lo, hi in ranges_for(listener, settings)):
                return {"checked": self.clock(), "service": None, "link": None, "management": None,
                        "icmp": None, "reason": "protected_probe_port"}
            return self.measure(record, listener, member)

        samples = dict(zip(selected, pool.map(check, (targets[k] for k in selected))))
        with self.participant.network_lock.open("a") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            self.publish(samples, targets)

    def publish(self, samples, targets):
        with self.participant.journal.edit() as state:
            current, _ = self.paths(state)
            before = copy.deepcopy(state)
            health = state.setdefault("health", {})
            config = self.config()
            settings = config["settings"]
            unavailable = topology_views(dict(config, connections=config.get("connections", [])), state, self.participant.node_id,
                                         paths=self.participant.paths)["v2_driver_unavailable"]
            was_busy = pressure_file(self.participant.paths).exists()
            changed = admission_pressure(settings, was_busy) != was_busy or unavailable != self.driver_unavailable
            for key in list(health):
                if key not in current:
                    del health[key]
            for key, sample in samples.items():
                if current.get(key) != targets[key]:
                    continue
                record, listener, member = targets[key]
                previous = health.get(key, {})
                path = health_signature(record["owner"], listener, member)
                if previous.get("path") != path or previous.get("boot_id") != self.boot_id:
                    previous = {}
                following = transition(previous, sample, self.clock())
                health[key] = dict(following, path=path, revision=record["revision"], boot_id=self.boot_id)
                if checks_admission(listener, member) and previous.get("available", False) != following["available"]:
                    changed = True
            if changed:
                self.participant.materialize(state, before)
                self.driver_unavailable = unavailable

    def serve(self, stop, report):
        threading.Thread(target=link_responses, args=(lambda: self.peer_links, stop), daemon=True).start()
        with ThreadPoolExecutor(max_workers=PARALLEL) as pool, ThreadPoolExecutor(max_workers=4) as control:
            self.management_pool = control if self.management else None
            while not stop.is_set():
                started = time.monotonic()
                try:
                    self.round(pool)
                except (PanelError, OSError, ValueError) as error:
                    report(str(error))
                stop.wait(max(.1, INTERVAL - (time.monotonic() - started)))
