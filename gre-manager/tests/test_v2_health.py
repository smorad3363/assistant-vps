"""Health evidence and gating with independent management and ICMP failures."""
from concurrent.futures import ThreadPoolExecutor
import copy
import random
import socket
import tempfile
import threading
import unittest

from panel.engine import build_rules
from panel.model import DEFAULTS
from panel.store import Paths
from panel.transactions import Participant
from panel.v2_config import normalize_group
from panel.v2_forwarding import active_members, topology_views
from panel.v2_health import Watchdog, service_probe, transition
from test_v2_forwarding import data, key


def sample(service, now):
    return {"checked": now, "service": service, "link": True, "icmp": False, "management": False}


class WatchdogTests(unittest.TestCase):
    def test_application_response_is_required_for_tcp_and_udp(self):
        for kind, protocol in ((socket.SOCK_STREAM, "tcp"), (socket.SOCK_DGRAM, "udp")):
            with self.subTest(protocol=protocol), socket.socket(socket.AF_INET, kind) as server:
                server.bind(("127.0.0.1", 0))
                server.settimeout(4)
                if protocol == "tcp":
                    server.listen()

                def respond():
                    if protocol == "udp":
                        message, peer = server.recvfrom(16)
                        server.sendto(b"ok-" + message, peer)
                    else:
                        client, _ = server.accept()
                        with client:
                            client.sendall(b"ok-" + client.recv(16))

                service = threading.Thread(target=respond)
                service.start()
                self.assertTrue(service_probe("127.0.0.1", server.getsockname()[1],
                                             {"protocol": protocol, "request": "nonce", "response": "ok-nonce"}, None))
                service.join(4)
                self.assertFalse(service.is_alive())

    def test_unknown_and_other_failures_do_not_count_as_service_failures(self):
        previous = transition({}, sample(True, 0), 0)
        rng = random.Random(7921)
        for now in range(1, 400):
            reading = sample(rng.choice([True, None]), now)
            previous = transition(previous, reading, now)
            self.assertTrue(previous["available"])
            self.assertEqual(previous["failures"], 0)
            self.assertIs(previous["management"], False)
            self.assertIs(previous["icmp"], False)

    def test_priority_admission_counts_real_payload_and_keeps_return_filters(self):
        group = data([{"id": key(index + 10), "node_id": key(index + 20), "method": "gre",
                       "service_ip": "203.0.113." + str(index + 20), "priority": index}
                      for index in range(2)])
        group["selection"] = "failover"
        group["listeners"][0]["probe"] = {"protocol": "tcp", "port": 5100, "request": "probe", "response": "ok"}
        self.assertEqual(normalize_group(group), group)
        config = {"settings": DEFAULTS, "connections": [], "web_enabled": True}
        interfaces = {"192.0.2.10": "eth0", "192.0.2.11": "eth0"}
        now, results = [0], [True, True]
        applications = []
        with tempfile.TemporaryDirectory() as root, ThreadPoolExecutor(max_workers=2) as pool:
            participant = Participant(Paths(root), key(3), lambda _: [],
                                      materialize=lambda state, previous: applications.append(copy.deepcopy(state)))
            with participant.journal.edit() as saved:
                saved["groups"][group["id"]] = {"active": True, "revision": 2, "owner": key(3), "group": group}
            watchdog = Watchdog(participant, lambda: config, None, clock=lambda: now[0])
            watchdog.measure = lambda r, l, m: sample(results[m["priority"]], now[0])

            def selected():
                state = participant.journal.read()
                view = topology_views(config, state, key(3))
                _, _, compiled = view["v2_listeners"][0]
                return [m["priority"] for m in active_members(compiled, group["selection"])], build_rules(view, interfaces)

            self.assertEqual(selected()[0], [])
            watchdog.round(pool)
            priorities, before = selected()
            self.assertEqual(priorities, [0])
            replies = [rule for rule in before["filter"]["GMP_INPUT"] if "--ctdir" in rule]
            self.assertEqual(len(replies), 2)
            self.assertTrue(all("REPLY" in rule and "ESTABLISHED" in rule and "5000" in rule for rule in replies))
            results[0] = False
            for moment in (5, 10):
                now[0] = moment
                watchdog.round(pool)
                self.assertEqual(selected()[0], [0])
            now[0] = 15
            watchdog.round(pool)
            priorities, after = selected()
            self.assertEqual(priorities, [1])
            self.assertEqual(before["filter"]["GMP_FWD"], after["filter"]["GMP_FWD"])
            results[1] = False
            results[0] = True
            for moment in (20, 25, 30):
                now[0] = moment
                watchdog.round(pool)
            self.assertEqual(selected()[0], [])
            now[0] = 50
            watchdog.round(pool)
            self.assertEqual(selected()[0], [0])
            self.assertEqual(len(applications), 4)
