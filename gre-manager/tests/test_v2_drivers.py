"""Kernel command and ownership contracts for v2 tunnel drivers."""
import copy
import random
import tempfile
import unittest

from panel.engine import Engine, build_rules
from panel.model import DEFAULTS, PanelError
from panel.store import Paths
from panel.v2_config import normalize_group
from panel.v2_drivers import driver_for
from panel.v2_forwarding import gre_link, topology_views
from test_v2_forwarding import data, key


class DriverTests(unittest.TestCase):
    def test_existing_gre_keeps_its_key_and_command(self):
        group = data([{"id": key(4), "node_id": key(5), "method": "gre", "service_ip": "203.0.113.20"}])
        listener = group["listeners"][0]
        link = gre_link(key(3), listener, listener["members"][0])
        driver = driver_for(link)
        self.assertEqual(driver.create(link, "eth1"), ["ip", "tunnel", "add", link["tunnel"], "mode", "gre",
                                                        "local", "192.0.2.11", "remote", "203.0.113.20",
                                                        "key", link["key"], "ttl", 64, "dev", "eth1"])
        self.assertTrue(driver.owns(link, {"linkinfo": {"info_kind": "gre", "info_data": {"local": link["outer_local"],
                                                     "remote": link["outer_peer"], "ikey": str(link["key"])}}}))

    def test_ipip_reverses_endpoints_and_rejects_unowned_devices(self):
        rng = random.Random(404)
        for _ in range(40):
            group = data([{"id": key(4), "node_id": key(5), "method": "ipip",
                           "service_ip": f"203.0.113.{rng.randint(1, 254)}", "ttl": rng.randint(0, 255)}])
            listener = group["listeners"][0]
            member = listener["members"][0]
            source = gre_link(key(3), listener, member)
            target = gre_link(key(3), listener, member, receiving=True)
            self.assertEqual(group, normalize_group(group))
            self.assertEqual(source["local_tun"], target["peer_tun"])
            self.assertEqual(source["outer_local"], target["outer_peer"])
            driver = driver_for(source)
            self.assertNotIn("key", driver.create(source, "eth1"))
            self.assertEqual(driver.firewall(source), ["-p", "4"])
            info = {"info_kind": "ipip", "info_data": {"local": source["outer_local"], "remote": source["outer_peer"],
                                                     "ttl": (member["ttl"] + 1) % 256}}
            self.assertFalse(driver.owns(source, {"linkinfo": info}))
            row = {"linkinfo": info, "ifalias": driver.marker(source)}
            self.assertTrue(driver.owns(source, row))
            self.assertIn("change", driver.refresh(source, info, "eth1"))
            info["info_kind"] = "gre"
            self.assertFalse(driver.owns(source, row))

    def test_unkeyed_endpoint_collision_is_rejected(self):
        original = data([{"id": key(4), "node_id": key(5), "method": "ipip", "service_ip": "203.0.113.20",
                          "outer_ip": "203.0.113.21"}])
        duplicate = copy.deepcopy(original)
        duplicate["id"] = key(8)
        duplicate["listeners"][0]["members"][0]["service_ip"] = "203.0.113.22"
        state = {"groups": {group["id"]: {"active": True, "owner": key(3), "group": group}
                            for group in (original, duplicate)}, "operations": {}}
        view = topology_views({"settings": DEFAULTS, "connections": []}, state, key(3))
        with tempfile.TemporaryDirectory() as root:
            engine = Engine(Paths(root))
            engine.interfaces = lambda: {"192.0.2.10": "eth0", "192.0.2.11": "eth1"}
            with self.assertRaisesRegex(PanelError, "same outer addresses"):
                engine.preflight(view)
        compiled = build_rules(view, {"192.0.2.10": "eth0", "192.0.2.11": "eth1"})["filter"]["GMP_INPUT"]
        self.assertTrue(any(["-p", "4"] == rule[-4:-2] for rule in compiled))
