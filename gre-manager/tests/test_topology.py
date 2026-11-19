"""Migration invariants for schema-1 data and independent peer state."""
from concurrent.futures import ThreadPoolExecutor
import random
import tempfile
import unittest
import uuid

from panel.controller import Controller
from panel.demo import DemoEngine, DemoRemote
from panel.engine import gre_for, pair_values
from panel.model import connection
from panel.store import Paths, Store, atomic_json
from panel.topology import legacy_topology


class TopologyTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.store = Store(Paths(directory.name))
        self.controller = Controller(self.store, DemoEngine(), DemoRemote(self.store.paths))
        self.addCleanup(self.controller.executor.shutdown, wait=True)

    def test_node_identity_is_durable_and_created_once_across_callers(self):
        with ThreadPoolExecutor(max_workers=6) as pool:
            ids = list(pool.map(lambda _: self.store.topology_node_id(), range(16)))
        self.assertEqual(len(set(ids)), 1)
        self.assertEqual(Store(self.store.paths).topology_node_id(), ids[0])
        self.assertEqual(uuid.UUID(ids[0]).version, 4)

    def test_generated_legacy_profiles_keep_exact_ports_and_state(self):
        seed = 2105100
        rng = random.Random(seed)
        cfg = self.store.config()
        cfg["settings"].update(ssh_ports=[22, 6111], reserved_ports=[2096])
        for index in range(128):
            ports = sorted(rng.sample(range(20000, 65000), 4))
            direct = connection({
                "name": f"Route {index}", "listen_ip": f"192.0.2.{index + 10}", "target_host": "203.0.113.10",
                "ports": "all" if index % 2 == 0 else ",".join(map(str, ports)),
                "exclude_ports": [ports[1]], "port_map": {str(ports[0]): rng.randint(1, 65535)},
                "enabled": rng.choice((True, False)), "upload_mbps": rng.randint(1, 100),
            }, cfg["settings"])
            cfg["connections"].append(direct)
        node = self.store.topology_node_id()
        topology = legacy_topology(cfg, (), node, (), set())
        original = {item["id"]: item for item in cfg["connections"]}
        with self.subTest(seed=seed):
            self.assertEqual(len(topology["groups"]), 128)
            self.assertEqual(len(topology["nodes"]), 2)
            self.assertCountEqual(topology["host_policy"]["protected_ports"], [22, 2096, 6111, 8787])
            for group in topology["groups"]:
                item = original[group["id"]]
                listener, = group["listeners"]
                member, = listener["members"]
                self.assertEqual(group["owner"], node)
                self.assertEqual(group["traffic_id"], item["id"])
                self.assertEqual(member["enabled"], item["enabled"])
                self.assertEqual(listener["port_map"], item["port_map"])
                self.assertEqual(group["limits"]["up"], item["upload_mbps"])
                self.assertTrue(all(
                    all(not low <= p <= high for low, high in listener["effective_ranges"])
                    for p in [22, 2096, 6111, 8787, *item["exclude_ports"]]
                ))
            cfg["connections"].reverse()
            self.assertEqual(legacy_topology(cfg, (), node, (), set()), topology)

    def test_pair_profiles_and_agent_receivers_preserve_gre_identity(self):
        paths = self.store.paths
        local, remote = "192.0.2.10", "203.0.113.10"
        pair = dict(pair_values(local, remote), mtu=1320, role="iran", service_ip="192.0.2.11",
                    ports=[[3300, 3000], [5100, 5000]])
        other = dict(pair_values(local, "203.0.113.11"), mtu=1380, role="foreign", service_ip=local)
        for profile in (pair, other):
            atomic_json(paths.etc / "pairs" / (profile["id"] + ".json"), profile)
        before = paths.config.read_bytes()
        topology = self.controller.topology()
        group, = topology["groups"]
        self.assertEqual(group["id"], pair["id"])
        listener, = group["listeners"]
        self.assertEqual(listener["ip"], pair["service_ip"])
        self.assertEqual(listener["port_map"], {"3300": 3000, "5100": 5000})
        member, = listener["members"]
        self.assertTrue(member["requires_connection"])
        link = next(item for item in topology["links"] if item["id"] == member["link_id"])
        self.assertEqual(link["key"], pair["key"])
        self.assertEqual(link["endpoints"][0]["interface"], pair["tunnel"])
        self.assertEqual(link["endpoints"][0]["inner_ip"], pair["local_tun"])
        self.assertEqual(link["endpoints"][0]["effective"]["mtu"], 1320)
        receiver, = topology["receivers"]
        self.assertEqual(receiver["id"], other["id"])
        self.assertEqual(paths.config.read_bytes(), before)

        self.controller.adopt()
        (paths.etc / "pairs" / (other["id"] + ".json")).unlink()
        self.controller.adopt()
        self.assertEqual(self.controller.topology(), topology)
        live, = self.store.config()["connections"]
        self.assertEqual(gre_for(live)["key"], pair["key"])

        peer = {"id": "abcdef1234", "kind": "peer", "gre": dict(pair_values(local, remote, 12), mtu=1280),
                "enabled": False, "service_ip": local}
        atomic_json(paths.etc / "peers.json", [peer])
        adopted_peer, = self.controller.topology()["receivers"]
        self.assertEqual(adopted_peer["id"], peer["id"])
        self.assertFalse(adopted_peer["enabled"])

    def test_paused_profile_cannot_overwrite_an_active_links_mtu(self):
        cfg = self.store.config()
        server = self.controller.remote.connect({"host": "203.0.113.20"})
        cfg["servers"] = [server]
        payload = dict(kind="gre", listen_ip="192.0.2.10", target_host=server["resolved_ip"],
                       server_id=server["id"], ports="5100", mtu_mode="manual")
        active = connection(dict(payload, mtu=1400), cfg["settings"])
        paused = connection(dict(payload, mtu=1280, enabled=False), cfg["settings"])
        cfg["connections"] = [paused, active]
        node = self.store.topology_node_id()
        topology = legacy_topology(cfg, (), node, (), {server["id"]})
        links = {link["id"]: link for link in topology["links"]}
        by_group = {
            group["id"]: links[group["listeners"][0]["members"][0]["link_id"]]["endpoints"][0]["effective"]["mtu"]
            for group in topology["groups"]
        }
        self.assertEqual(by_group, {active["id"]: 1400, paused["id"]: 1280})
        cfg["connections"].reverse()
        self.assertEqual(legacy_topology(cfg, (), node, (), {server["id"]}), topology)
