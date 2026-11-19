"""Real HTTPS pairing and deterministic distributed decision failures."""
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
import http.client
import json
from pathlib import Path
import random
import ssl
import subprocess
import tempfile
import threading
import time
import unittest
import uuid

from panel.controller import Controller
from panel.demo import DemoEngine, DemoRemote, LocalBackend
from panel.model import PanelError
from panel.store import Paths, Store
from panel.transactions import Coordinator, Participant, overlaps
from panel.v2_config import normalize_group
from panel.web import Handler, ThreadingHTTPServer


def operation(owner, nodes):
    return dict(id=uuid.uuid4().hex, group_id=uuid.uuid4().hex, owner=owner,
                participants=nodes, expected_revision=0, group={})


class TransactionsTest(unittest.TestCase):
    def setUp(self):
        root = tempfile.TemporaryDirectory()
        self.addCleanup(root.cleanup)
        self.paths = Paths(Path(root.name) / "coordinator")
        self.nodes = [uuid.uuid4().hex for _ in range(4)]
        self.roots = {key: Paths(Path(root.name) / key) for key in self.nodes}
        self.change = operation(self.nodes[0], self.nodes)

    def send(self, node, action, change):
        participant = Participant(self.roots[node], node, lambda change: [("192.0.2.10", "tcp", 5000, 5100)])
        return participant.request(change["owner"], action, change)

    def test_missing_fourth_participant_aborts_all_after_restart(self):
        missing = self.nodes[-1]

        def offline(node, action, change):
            if node == missing:
                raise OSError("disconnected")
            return self.send(node, action, change)

        coordinator = Coordinator(self.paths, offline)
        coordinator.enqueue(self.change)
        job = coordinator.advance(self.change["id"])
        self.assertEqual(job["phase"], "aborting")
        self.assertEqual(job["decision"], "abort")
        for node in self.nodes[:-1]:
            self.assertEqual(self.send(node, "status", self.change)["phase"], "aborted")

        recovered = Coordinator(self.paths, self.send)
        job = recovered.advance(self.change["id"])
        self.assertEqual(job["phase"], "aborted")
        self.assertEqual(recovered.enqueue(self.change), job)
        self.assertEqual(self.send(missing, "prepare", self.change)["phase"], "aborted")
        for node in self.nodes:
            self.assertFalse(Participant(self.roots[node], node, None).journal.read()["groups"])

    def test_lost_commit_response_replays_the_real_receipt(self):
        missing = self.nodes[-1]

        def lost(node, action, change):
            result = self.send(node, action, change)
            if node == missing and action == "commit":
                raise OSError("response lost after commit")
            return result

        coordinator = Coordinator(self.paths, lost)
        coordinator.plan(self.change)
        coordinator.enqueue(self.change)
        job = coordinator.advance(self.change["id"])
        self.assertEqual(job["phase"], "committing")
        self.assertEqual(job["decision"], "commit")
        self.assertEqual(self.send(missing, "status", self.change)["revision"], 1)
        job = Coordinator(self.paths, self.send).advance(self.change["id"])
        self.assertEqual(job["phase"], "committed")

        stale = dict(self.change, id=uuid.uuid4().hex)
        with self.assertRaisesRegex(PanelError, "revision"):
            coordinator.plan(stale)
        with self.assertRaisesRegex(PanelError, "already in use"):
            coordinator.enqueue(dict(self.change, expected_revision=1))

    def test_expired_prepare_does_not_count_as_a_commit(self):
        node = self.nodes[0]
        now = time.time()
        participant = Participant(self.roots[node], node, lambda change: [], clock=lambda: now)
        participant.request(node, "prepare", self.change)
        now += 130
        self.assertEqual(participant.request(node, "status", self.change)["phase"], "expired")
        self.assertFalse(participant.journal.read()["groups"])

    def test_revisions_and_claims_are_reserved_atomically(self):
        node = self.nodes[0]
        first, second = self.change, dict(self.change, id=uuid.uuid4().hex, group_id=uuid.uuid4().hex)

        def prepare(change):
            try:
                return self.send(node, "prepare", change)["phase"]
            except PanelError as error:
                return error.code

        with ThreadPoolExecutor(max_workers=2) as executor:
            self.assertCountEqual(executor.map(prepare, (first, second)), ["prepared", "reserved"])
        reserved = next(item for item in (first, second) if self.send(node, "status", item)["phase"] == "prepared")
        self.send(node, "commit", reserved)
        with self.assertRaisesRegex(PanelError, "another owner"):
            self.send(node, "prepare", dict(reserved, id=uuid.uuid4().hex, owner=self.nodes[1], expected_revision=1))

    def test_removed_node_can_rejoin_at_a_newer_revision(self):
        owner, receiver = self.nodes[:2]
        coordinator = Coordinator(self.paths, self.send)
        original = dict(self.change, participants=[owner, receiver])
        changes = [
            original,
            dict(original, id=uuid.uuid4().hex, expected_revision=1, departing=[receiver]),
            dict(original, id=uuid.uuid4().hex, expected_revision=2, participants=[owner]),
            dict(original, id=uuid.uuid4().hex, expected_revision=3, joining=[receiver]),
        ]
        for change in changes:
            coordinator.plan(change)
            coordinator.enqueue(change)
            self.assertEqual(coordinator.advance(change["id"])["phase"], "committed")
        group = Participant(self.roots[receiver], receiver, None).journal.read()["groups"][original["group_id"]]
        self.assertEqual(group["revision"], 4)
        self.assertTrue(group["active"])

    def test_generated_range_intersections_match_the_set_oracle(self):
        rng = random.Random(2205100)
        node_ip = "192.0.2.10"
        for case in range(256):
            a, b = sorted(rng.sample(range(1, 40), 2))
            c, d = sorted(rng.sample(range(1, 40), 2))
            transport = rng.choice(("tcp", "udp"))
            with self.subTest(case=case):
                expected = transport == "tcp" and bool(set(range(a, b + 1)) & set(range(c, d + 1)))
                self.assertEqual(overlaps([(node_ip, "tcp", a, b)], [(node_ip, transport, c, d)]), expected)


class HTTPClient:
    def __init__(self, controller):
        self.controller = controller
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        self.context.check_hostname = False
        self.context.verify_mode = ssl.CERT_NONE
        self.cookie, self.csrf = "", ""

    def call(self, path, payload=None):
        with closing(http.client.HTTPSConnection("localhost", self.port, timeout=6, context=self.context)) as conn:
            conn.request("GET" if payload is None else "POST", "/api/" + path,
                         None if payload is None else json.dumps(payload),
                         {"Content-Type": "application/json", "Cookie": self.cookie, "X-Gremgr-CSRF": self.csrf})
            response = conn.getresponse()
            if response.getheader("Set-Cookie"):
                self.cookie = response.getheader("Set-Cookie").split(";")[0]
            result = json.loads(response.read())
            return response.status, result

    def login(self):
        status, result = self.call("login", {"username": "admin", "password": "fixture-password-2026"})
        if status != 200:
            raise AssertionError(result)
        self.csrf = result["csrf"]


class HTTPSPairingTest(unittest.TestCase):
    def panel(self, root):
        paths = Paths(root)
        store = Store(paths)
        store.set_password("fixture-password-2026")
        controller = Controller(store, DemoEngine(), DemoRemote(paths))
        self.addCleanup(controller.executor.shutdown, wait=True)
        self.addCleanup(controller.v2_executor.shutdown, wait=True)
        client = HTTPClient(controller)
        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        server.backend, server.secure = LocalBackend(controller), True
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        certificate, key = paths.run / "cert.pem", paths.run / "key.pem"
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                        "-subj", "/CN=localhost", "-keyout", key, "-out", certificate],
                       check=True, capture_output=True)
        context.load_cert_chain(certificate, key)
        server.socket = context.wrap_socket(server.socket, server_side=True)
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        client.port = server.server_port
        cfg = store.config()
        cfg["settings"]["port"] = client.port
        store.save(cfg)
        client.login()
        return client

    def test_two_panels_pair_plan_commit_and_revoke(self):
        with tempfile.TemporaryDirectory() as directory:
            a = self.panel(Path(directory) / "a")
            b = self.panel(Path(directory) / "b")
            owner = a.controller.v2_agent.node_id
            status, invite = b.call("v2/pairing.invite", {"host": "localhost", "owner": owner})
            self.assertEqual(status, 200, invite)
            self.assertEqual(b.call("v2/agent.exchange", {"owner": uuid.uuid4().hex,
                             "target": invite["node_id"], "code": invite["code"]})[0], 401)
            status, pin_error = a.call("v2/pairing.connect", dict(invite, fingerprint="a" * 64))
            self.assertEqual((status, pin_error["code"]), (400, "fingerprint"))
            status, pair = a.call("v2/pairing.connect", invite)
            self.assertEqual((status, pair["node_id"]), (200, invite["node_id"]))
            self.assertEqual(a.call("v2/pairing.connect", invite)[0], 401)

            self.assertEqual(b.call("v2/pairing.invite", {"host": "localhost", "owner": owner})[0], 400)
            group_id = uuid.uuid4().hex
            request = {"id": uuid.uuid4().hex, "group_id": group_id, "expected_revision": 0,
                       "group": {"id": group_id, "name": "Acceptance", "listeners": [{
                           "id": uuid.uuid4().hex, "node_id": owner, "ip": "192.0.2.10", "ports": "5100",
                           "port_map": {"5100": 5000}, "members": [{
                               "id": uuid.uuid4().hex, "node_id": invite["node_id"],
                               "method": "gre", "service_ip": "192.0.2.11",
                           }],
                       }]}}
            status, queued = a.call("v2/plan", request)
            self.assertEqual(status, 200, queued)
            for _ in range(100):
                status, plan_job = a.call("v2/jobs?id=" + queued["job"])
                self.assertEqual(status, 200, plan_job)
                if plan_job["status"] in ("done", "failed"):
                    break
                time.sleep(0.02)
            self.assertEqual(plan_job["status"], "done", plan_job)
            plan = plan_job["result"]
            status, job = a.call("v2/apply", dict(request, digest=plan["digest"]))
            self.assertEqual(status, 200, job)
            a.controller.v2_future.result(timeout=8)
            status, completed = a.call("v2/jobs?id=" + job["id"])
            self.assertEqual((status, completed["phase"]), (200, "committed"))
            for panel in (a, b):
                status, groups = panel.call("v2/groups")
                self.assertEqual(status, 200, groups)
                group, = groups
                self.assertEqual((group["owner"], group["revision"]), (owner, 1))
                self.assertEqual(group["group"], normalize_group(request["group"]))
            with self.assertRaises(PanelError) as conflict:
                config = a.controller.store.config()
                config["settings"]["reserved_ports"] = [5100]
                a.controller.check_v2_reservations(config)
            self.assertEqual(conflict.exception.code, "in_use")
            self.assertEqual(b.call("v2/pairing.revoke", {"node_id": owner})[0], 200)
            with self.assertRaises(PanelError) as rejected:
                a.controller.v2_access.call(invite["node_id"], "status", a.controller.v2_change(request))
            self.assertEqual(rejected.exception.code, "auth")
